#include "shellcode.h"
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <signal.h>

#define RENEF_PAYLOAD_PATH "/data/local/tmp/libagent.so"

#ifdef __linux__
#include <elf.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#else
// ELF definitions for non-Linux platforms (macOS, etc.)
// These are needed for parsing Android ELF binaries from the host

#include <cstdint>

#define EI_NIDENT 16
#define ELFMAG "\177ELF"
#define SELFMAG 4

typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef int64_t Elf64_Sxword;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Section;

typedef struct {
  unsigned char e_ident[EI_NIDENT];
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry;
  Elf64_Off e_phoff;
  Elf64_Off e_shoff;
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct {
  Elf64_Word sh_name;
  Elf64_Word sh_type;
  Elf64_Xword sh_flags;
  Elf64_Addr sh_addr;
  Elf64_Off sh_offset;
  Elf64_Xword sh_size;
  Elf64_Word sh_link;
  Elf64_Word sh_info;
  Elf64_Xword sh_addralign;
  Elf64_Xword sh_entsize;
} Elf64_Shdr;

typedef struct {
  Elf64_Word st_name;
  unsigned char st_info;
  unsigned char st_other;
  Elf64_Section st_shndx;
  Elf64_Addr st_value;
  Elf64_Xword st_size;
} Elf64_Sym;

// Program header (used by find_code_cave).
typedef struct {
  Elf64_Word p_type;
  Elf64_Word p_flags;
  Elf64_Off p_offset;
  Elf64_Addr p_vaddr;
  Elf64_Addr p_paddr;
  Elf64_Xword p_filesz;
  Elf64_Xword p_memsz;
  Elf64_Xword p_align;
} Elf64_Phdr;

#ifndef PT_LOAD
#define PT_LOAD 1
#endif
#ifndef PF_X
#define PF_X 1
#endif

#endif // __linux__

#ifndef __NR_memfd_create
#if defined(__aarch64__) || defined(__arm64__)
#define __NR_memfd_create 279
#elif defined(__arm__)
#define __NR_memfd_create 385
#elif defined(__x86_64__)
#define __NR_memfd_create 319
#elif defined(__i386__)
#define __NR_memfd_create 356
#endif
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#if defined(__aarch64__) || defined(__arm64__)
static const char *LIBC_PATHS[] = {
    "/apex/com.android.runtime/lib64/bionic/libc.so", // Android 10+
    "/system/lib64/libc.so",                          // Android 8-9
    nullptr};
static const char *LIBDL_PATHS[] = {
    "/apex/com.android.runtime/lib64/bionic/libdl.so", "/system/lib64/libdl.so",
    nullptr};
#elif defined(__arm__)
static const char *LIBC_PATHS[] = {
    "/apex/com.android.runtime/lib/bionic/libc.so", "/system/lib/libc.so",
    nullptr};
static const char *LIBDL_PATHS[] = {
    "/apex/com.android.runtime/lib/bionic/libdl.so", "/system/lib/libdl.so",
    nullptr};
#elif defined(__x86_64__) || defined(__amd64__)
static const char *LIBC_PATHS[] = {
    "/apex/com.android.runtime/lib64/bionic/libc.so", "/system/lib64/libc.so",
    nullptr};
static const char *LIBDL_PATHS[] = {
    "/apex/com.android.runtime/lib64/bionic/libdl.so", "/system/lib64/libdl.so",
    nullptr};
#elif defined(__i386__) || defined(__i686__)
static const char *LIBC_PATHS[] = {
    "/apex/com.android.runtime/lib/bionic/libc.so", "/system/lib/libc.so",
    nullptr};
static const char *LIBDL_PATHS[] = {
    "/apex/com.android.runtime/lib/bionic/libdl.so", "/system/lib/libdl.so",
    nullptr};
#else
#error "Unsupported architecture. Please compile for ARM or x86."
#endif

// Find the actual path of a library by checking multiple locations
static const char *resolve_lib_path(const char **paths) {
  for (int i = 0; paths[i] != nullptr; i++) {
    if (access(paths[i], R_OK) == 0) {
      return paths[i];
    }
  }
  return nullptr;
}

static bool copy_file(const char *src, const char *dst) {
  int src_fd = open(src, O_RDONLY);
  if (src_fd < 0)
    return false;

  int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (dst_fd < 0) {
    close(src_fd);
    return false;
  }

  char buf[8192];
  ssize_t n;
  while ((n = read(src_fd, buf, sizeof(buf))) > 0) {
    if (write(dst_fd, buf, n) != n) {
      close(src_fd);
      close(dst_fd);
      unlink(dst);
      return false;
    }
  }

  close(src_fd);
  close(dst_fd);
  return n == 0;
}

bool write_memory(int pid, uintptr_t addr, const std::vector<uint8_t> &data) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", pid);

  int fd = open(path, O_RDWR);
  if (fd < 0) {
    std::cerr << "Failed to open " << path << "\n";
    return false;
  }

  ssize_t written = pwrite(fd, data.data(), data.size(), addr);
  close(fd);

  if (written != (ssize_t)data.size()) {
    std::cerr << "Write failed: " << written << "/" << data.size()
              << " bytes\n";
    return false;
  }

  return true;
}

std::vector<uint8_t> read_memory(int pid, uintptr_t addr, size_t size) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", pid);

  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    return {};
  }

  std::vector<uint8_t> buf(size);
  ssize_t bytes_read = pread(fd, buf.data(), size, addr);
  close(fd);

  if (bytes_read != (ssize_t)size) {
    return {};
  }

  return buf;
}

uintptr_t find_symbol(const char *lib_path, const char *symbol_name) {
  int fd = open(lib_path, O_RDONLY);
  if (fd < 0) {
    std::cerr << "  ✗ Cannot open " << lib_path << "\n";
    return 0;
  }

  struct stat st;
  if (fstat(fd, &st) < 0) {
    close(fd);
    return 0;
  }

  void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);

  if (map == MAP_FAILED) {
    return 0;
  }

  uintptr_t result = 0;
  auto *ehdr = static_cast<Elf64_Ehdr *>(map);

  // Verify ELF magic
  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
    munmap(map, st.st_size);
    return 0;
  }

  auto *shdr = reinterpret_cast<Elf64_Shdr *>(static_cast<uint8_t *>(map) +
                                              ehdr->e_shoff);

  Elf64_Shdr *dynsym = nullptr;
  Elf64_Shdr *dynstr = nullptr;
  Elf64_Shdr *symtab = nullptr;
  Elf64_Shdr *strtab = nullptr;

  Elf64_Shdr *shstrtab = &shdr[ehdr->e_shstrndx];
  const char *shstrtab_data =
      static_cast<const char *>(map) + shstrtab->sh_offset;

  for (int i = 0; i < ehdr->e_shnum; i++) {
    const char *name = shstrtab_data + shdr[i].sh_name;
    if (strcmp(name, ".dynsym") == 0)
      dynsym = &shdr[i];
    else if (strcmp(name, ".dynstr") == 0)
      dynstr = &shdr[i];
    else if (strcmp(name, ".symtab") == 0)
      symtab = &shdr[i];
    else if (strcmp(name, ".strtab") == 0)
      strtab = &shdr[i];
  }

  if (dynsym && dynstr) {
    auto *sym = reinterpret_cast<Elf64_Sym *>(static_cast<uint8_t *>(map) +
                                              dynsym->sh_offset);
    const char *str = static_cast<const char *>(map) + dynstr->sh_offset;
    size_t sym_count = dynsym->sh_size / sizeof(Elf64_Sym);

    for (size_t i = 0; i < sym_count; i++) {
      if (sym[i].st_name && sym[i].st_value != 0) {
        if (strcmp(str + sym[i].st_name, symbol_name) == 0) {
          result = sym[i].st_value;
          goto done;
        }
      }
    }
  }

  if (!result && symtab && strtab) {
    auto *sym = reinterpret_cast<Elf64_Sym *>(static_cast<uint8_t *>(map) +
                                              symtab->sh_offset);
    const char *str = static_cast<const char *>(map) + strtab->sh_offset;
    size_t sym_count = symtab->sh_size / sizeof(Elf64_Sym);

    for (size_t i = 0; i < sym_count; i++) {
      if (sym[i].st_name && sym[i].st_value != 0) {
        if (strcmp(str + sym[i].st_name, symbol_name) == 0) {
          result = sym[i].st_value;
          goto done;
        }
      }
    }
  }

done:
  munmap(map, st.st_size);
  return result;
}

uintptr_t find_library_base(int pid, const char *lib_name) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);

  FILE *fp = fopen(path, "r");
  if (!fp)
    return 0;

  char line[512];
  while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, lib_name)) {
      char *end;
      uintptr_t addr = strtoul(line, &end, 16);
      fclose(fp);
      return addr;
    }
  }

  fclose(fp);
  return 0;
}

uintptr_t find_libc_base(int pid) { return find_library_base(pid, "libc.so"); }

int create_memfd_from_file(const char *so_path) {
  int fd = open(so_path, O_RDONLY);
  if (fd < 0) {
    std::cerr << "  ✗ Failed to open SO file: " << so_path << "\n";
    return -1;
  }

  struct stat st;
  if (fstat(fd, &st) < 0) {
    std::cerr << "  ✗ Failed to stat SO file\n";
    close(fd);
    return -1;
  }
  size_t file_size = st.st_size;

  int memfd = syscall(__NR_memfd_create, "", MFD_CLOEXEC);
  if (memfd < 0) {
    std::cerr << "  ✗ memfd_create failed (errno: " << errno << ")\n";
    close(fd);
    return -1;
  }

  char buf[8192];
  ssize_t total_written = 0;
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0) {
    ssize_t written = write(memfd, buf, n);
    if (written != n) {
      std::cerr << "  ✗ Failed to write to memfd\n";
      close(fd);
      close(memfd);
      return -1;
    }
    total_written += written;
  }

  close(fd);

  if (total_written != (ssize_t)file_size) {
    std::cerr << "  ✗ Size mismatch: " << total_written << " != " << file_size
              << "\n";
    close(memfd);
    return -1;
  }

  std::cout << "  ✓ memfd created (fd=" << memfd << ", size=" << file_size
            << "B)\n";
  return memfd;
}


// ---------------------------------------------------------------------------
// Code-cave injection
//
// The original scheme writes the whole stage-1 shellcode (196 bytes) over
// the beginning of malloc() and later writes the original bytes back.
// Every thread that calls malloc() meanwhile loops INSIDE those bytes
// waiting for the lock, and the restore is only safe if all of them have
// been moved back to malloc+0 first. That was done by time: write `b .`
// at malloc+0, sleep 30ms, restore. A thread that simply does not get
// scheduled during those 30ms (seen live: a low-priority "Jit thread
// pool" thread, and once the main thread, during a busy app start)
// resumes in the middle of the restored, original malloc() with the wrong
// registers -> SIGSEGV around malloc+44. Nothing short of knowing every
// thread's PC makes a multi-instruction restore safe, and that needs
// ptrace.
//
// So do not put more than ONE instruction into malloc(). Stage 1 goes into
// unused zero padding after the end of libc's executable segment (same
// mapping, so within reach of a plain `B`), and malloc+0 becomes a single
// `B cave`. A one-word write is atomic for the threads executing it, in
// both directions. Waiting threads loop inside the cave; when injection is
// done their loop slots are rewritten to `B malloc`, which is correct no
// matter when - or how late - each of them runs again. No sleeps, no
// timing assumptions.
// ---------------------------------------------------------------------------

static uint32_t arm64_b(uintptr_t from, uintptr_t to) {
  int64_t delta = (int64_t)to - (int64_t)from;
  return 0x14000000u | (uint32_t)((delta >> 2) & 0x03FFFFFF);
}

static std::vector<uint8_t> le32_words(const std::vector<uint32_t> &words) {
  std::vector<uint8_t> out(words.size() * 4);
  memcpy(out.data(), words.data(), out.size());
  return out;
}

// Returns the address of `need` unused (zero) bytes located after the end
// of the executable PT_LOAD segment that contains `near_addr`, still
// inside the same executable mapping of the target. 0 if there is none.
static uintptr_t find_code_cave(int pid, const char *lib_path,
                                uintptr_t lib_base, uintptr_t near_addr,
                                size_t need) {
  // 1) End of the executable segment, from the ELF program headers.
  uint64_t seg_end_vaddr = 0;
  {
    int fd = open(lib_path, O_RDONLY);
    if (fd < 0) return 0;
    Elf64_Ehdr eh;
    if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh) ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_phentsize != sizeof(Elf64_Phdr)) {
      close(fd);
      return 0;
    }
    uint64_t rel = near_addr - lib_base;
    for (int i = 0; i < eh.e_phnum; i++) {
      Elf64_Phdr ph;
      if (pread(fd, &ph, sizeof(ph), eh.e_phoff + (off_t)i * sizeof(ph)) !=
          (ssize_t)sizeof(ph))
        break;
      if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X) && rel >= ph.p_vaddr &&
          rel < ph.p_vaddr + ph.p_memsz) {
        seg_end_vaddr = ph.p_vaddr + ph.p_memsz;
        break;
      }
    }
    close(fd);
  }
  if (!seg_end_vaddr) return 0;

  // 2) The executable mapping that contains near_addr.
  uintptr_t map_start = 0, map_end = 0;
  {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps) return 0;
    char line[512];
    while (fgets(line, sizeof(line), maps)) {
      unsigned long long s = 0, e = 0;
      char perms[8] = {0};
      if (sscanf(line, "%llx-%llx %7s", &s, &e, perms) != 3) continue;
      if (near_addr >= s && near_addr < e && perms[2] == 'x') {
        map_start = (uintptr_t)s;
        map_end = (uintptr_t)e;
        break;
      }
    }
    fclose(maps);
  }
  if (!map_end) return 0;

  // Leave a 16-byte gap after the last real instruction.
  uintptr_t cave = lib_base + ((seg_end_vaddr + 15) & ~(uint64_t)15) + 16;
  if (cave < map_start || cave + need > map_end) return 0;

  // Must really be unused: all zero bytes right now.
  auto cur = read_memory(pid, cave, need);
  if (cur.size() != need) return 0;
  for (uint8_t b : cur) {
    if (b != 0) return 0;
  }
  return cave;
}

// Pre-lock part of stage 1 = its first 6 instructions (spin-lock on the
// shared variable). A thread can only be inside these while it has NOT
// taken the lock, i.e. while it has not touched sp or saved anything, so
// sending it back to malloc+0 from any of the six slots is always correct.
static const size_t STAGE1_PRELOCK_WORDS = 6;

static std::vector<uint8_t> cave_back_to_malloc(uintptr_t cave,
                                                uintptr_t malloc_addr) {
  std::vector<uint32_t> words;
  for (size_t i = 0; i < STAGE1_PRELOCK_WORDS; i++) {
    words.push_back(arm64_b(cave + i * 4, malloc_addr));
  }
  return le32_words(words);
}

static void restore_cave_later(int pid, uintptr_t cave,
                               std::vector<uint8_t> expected_head,
                               std::vector<uint8_t> original) {
  auto task = [pid, cave, expected_head, original]() {
    // By now every thread that was parked in the cave has been sent back
    // to malloc() the moment it ran. The delay is not what makes that
    // safe (the `B malloc` slots are); it only decides how long the
    // padding stays modified before it is put back to zeros.
    std::this_thread::sleep_for(std::chrono::seconds(5));
    // Same process, same cave contents we left? (pid may be gone/reused.)
    auto now = read_memory(pid, cave, expected_head.size());
    if (now != expected_head) return;
    write_memory(pid, cave, original);
  };
#ifdef BUILD_STANDALONE_AGENT
  task(); // the standalone injector exits right after inject() returns
#else
  std::thread(task).detach();
#endif
}

static bool inject_via_code_cave(int pid, uintptr_t malloc_addr,
                                 uintptr_t timezone_addr, uintptr_t cave,
                                 const std::vector<uint8_t> &stage1,
                                 const std::vector<uint8_t> &stage2,
                                 const char *so_path) {
  std::cout << "  ✓ Code cave: 0x" << std::hex << cave << std::dec << " ("
            << stage1.size() << "B, single-instruction malloc patch)\n";

  std::cout << "[4/7] Backing up original memory...\n";
  auto malloc_backup = read_memory(pid, malloc_addr, 4);
  auto cave_backup = read_memory(pid, cave, stage1.size());
  auto timezone_backup = read_memory(pid, timezone_addr, 8);
  if (malloc_backup.size() != 4 || cave_backup.size() != stage1.size() ||
      timezone_backup.size() != 8) {
    std::cerr << " Failed to backup memory\n";
    return false;
  }
  std::cout << "  ✓ Backup complete\n";

  auto back_to_malloc = cave_back_to_malloc(cave, malloc_addr);

  // Undo for every failure path below. Order matters: malloc first (one
  // atomic word), then release anyone parked in the cave, then the lock
  // variable (a zero lock byte must never be visible while a thread could
  // still take the lock).
  auto rollback = [&]() {
    write_memory(pid, malloc_addr, malloc_backup);
    write_memory(pid, cave, back_to_malloc);
    write_memory(pid, timezone_addr, timezone_backup);
    restore_cave_later(pid, cave, back_to_malloc, cave_backup);
  };

  std::cout << "[5/7] Injecting stage 1 shellcode...\n";
  std::vector<uint8_t> zero(8, 0);
  if (!write_memory(pid, timezone_addr, zero)) {
    std::cerr << " Failed to zero timezone\n";
    return false;
  }
  if (!write_memory(pid, cave, stage1)) {
    std::cerr << " Failed to write stage1 into the code cave\n";
    write_memory(pid, timezone_addr, timezone_backup);
    return false;
  }
  // Only now make it reachable: one word at malloc+0.
  if (!write_memory(pid, malloc_addr, le32_words({arm64_b(malloc_addr, cave)}))) {
    std::cerr << " Failed to patch malloc\n";
    write_memory(pid, cave, cave_backup);
    write_memory(pid, timezone_addr, timezone_backup);
    return false;
  }
  std::cout << "  ✓ Stage1 injected\n";

  std::cout << "[6/7] Waiting for malloc() trigger...\n";
  uintptr_t new_map = 0;
  int timeout_counter = 0;
  const int MAX_TIMEOUT = 30000;

  char kill_cmd[256];
  snprintf(kill_cmd, sizeof(kill_cmd), "kill -10 %d 2>/dev/null", pid); // SIGUSR1 → GC
  system(kill_cmd);
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  std::cout << "  → Trigger signals sent\n";

  while (true) {
    std::this_thread::sleep_for(std::chrono::milliseconds(3));
    auto data = read_memory(pid, timezone_addr, 8);
    if (data.size() == 8) {
      uint64_t val = 0;
      memcpy(&val, data.data(), 8);
      if ((val & 0x1) && (val & 0xFFFFFFFFFFFFFFF0)) {
        new_map = val & 0xFFFFFFFFFFFFFFF0;
        break;
      }
    }
    if (++timeout_counter > MAX_TIMEOUT) {
      std::cerr << " Timeout waiting for malloc trigger\n";
      rollback();
      return false;
    }
  }
  std::cout << "  ✓ Triggered! New map: 0x" << std::hex << new_map << std::dec << "\n";

  std::cout << "[7/7] Finalizing injection...\n";

  // (a) malloc() is whole again - one atomic word. From here on new
  //     callers run the real function. This has to happen BEFORE stage 2
  //     starts: stage 2 calls dlopen(), and the library's constructors
  //     call malloc() themselves on the very thread that holds the lock.
  if (!write_memory(pid, malloc_addr, malloc_backup)) {
    std::cerr << "Failed to restore malloc\n";
    rollback();
    return false;
  }

  // (b) Release the threads waiting for the lock in the cave: each of the
  //     six pre-lock slots now branches to malloc+0. The lock holder is
  //     past these slots by definition (it published the map address).
  if (!write_memory(pid, cave, back_to_malloc)) {
    std::cerr << "Warning: Failed to release waiters in the code cave\n";
  }

  // (c) Only after (b): the lock variable gets its real value back. No
  //     thread can reach the lock test anymore, so a zero byte here cannot
  //     hand the lock to a second thread.
  if (!write_memory(pid, timezone_addr, timezone_backup)) {
    std::cerr << "Warning: Failed to restore timezone\n";
  }

  // (d) Stage 2 into the new map. The lock holder is spinning on the first
  //     word (`b .`), so write everything else first and that word last -
  //     it must not start executing a half-written stage 2.
  if (stage2.size() <= 4) {
    std::cerr << "Invalid stage2\n";
    return false;
  }
  std::vector<uint8_t> stage2_tail(stage2.begin() + 4, stage2.end());
  std::vector<uint8_t> stage2_head(stage2.begin(), stage2.begin() + 4);
  if (!write_memory(pid, new_map + 4, stage2_tail) ||
      !write_memory(pid, new_map, stage2_head)) {
    std::cerr << "Failed to write stage2\n";
    return false;
  }
  std::cout << "  ✓ Stage2 written to new map\n";

  // (e) The cave goes back to zeros later; until then it holds only
  //     `B malloc` slots (plus the now unreachable rest of stage 1).
  restore_cave_later(pid, cave, back_to_malloc, cave_backup);
  std::cout << "  ✓ Original functions restored\n";

  std::cout << "\n Injection complete! Loaded: " << so_path << "\n";
  return true;
}

bool inject(int pid, const char *so_path) {
  std::cout << "=== RENEF Injection ===\n";
  std::cout << "Target PID: " << pid << "\n";
  std::cout << "Payload: " << so_path << "\n\n";

  uintptr_t agent_base = find_library_base(pid, "libagent.so");
  if (agent_base != 0) {
    std::cout << "  ✓ Agent already loaded at 0x" << std::hex << agent_base
              << std::dec << ", skipping injection\n";
    return true;
  }

  std::cout << "[1/7] Finding libc base...\n";
  uintptr_t libc_base = find_libc_base(pid);
  if (!libc_base) {
    std::cerr << " Failed to find libc base\n";
    return false;
  }
  std::cout << "  ✓ 0x" << std::hex << libc_base << std::dec << "\n";

  std::cout << "[2/7] Finding symbols...\n";

  const char *libc_path = resolve_lib_path(LIBC_PATHS);
  const char *libdl_path = resolve_lib_path(LIBDL_PATHS);

  if (!libc_path) {
    std::cerr << "  ✗ Cannot find libc.so on this device\n";
    return false;
  }
  if (!libdl_path) {
    std::cerr << "  ✗ Cannot find libdl.so on this device\n";
    return false;
  }

  std::cout << "  → Using libc: " << libc_path << "\n";
  std::cout << "  → Using libdl: " << libdl_path << "\n";

  uintptr_t malloc_offset = find_symbol(libc_path, "malloc");
  uintptr_t timezone_offset = find_symbol(libc_path, "timezone");
  uintptr_t dlopen_offset = find_symbol(libdl_path, "dlopen");

  if (!malloc_offset || !timezone_offset || !dlopen_offset) {
    std::cerr << "  ✗ Failed to find symbols (malloc=" << std::hex
              << malloc_offset << ", timezone=" << timezone_offset
              << ", dlopen=" << dlopen_offset << ")\n"
              << std::dec;
    return false;
  }

  uintptr_t libdl_base = find_library_base(pid, "libdl.so");
  if (!libdl_base) {
    std::cerr << " Failed to find libdl.so\n";
    return false;
  }

  uintptr_t malloc_addr = libc_base + malloc_offset;
  uintptr_t timezone_addr = libc_base + timezone_offset;
  uintptr_t dlopen_addr = libdl_base + dlopen_offset;

  std::cout << "  ✓ malloc: 0x" << std::hex << malloc_addr << std::dec << "\n";
  std::cout << "  ✓ dlopen: 0x" << std::hex << dlopen_addr << std::dec << "\n";

  bool is_legacy_android = (strstr(libc_path, "/apex/") == nullptr);
  if (is_legacy_android) {
    std::cout << "  → Legacy Android detected (pre-10), using direct dlopen\n";
  }

  std::cout << "[3/7] Preparing payload...\n";
  char final_path[64];
  bool using_temp_file = false;

  if (strcmp(so_path, RENEF_PAYLOAD_PATH) == 0) {
    strncpy(final_path, so_path, sizeof(final_path) - 1);
    std::cout << "  ✓ Using payload directly: " << so_path << "\n";
  } else if (copy_file(so_path, RENEF_PAYLOAD_PATH)) {
    strncpy(final_path, RENEF_PAYLOAD_PATH, sizeof(final_path) - 1);
    using_temp_file = true;
    std::cout << "  ✓ Payload copied to temp path\n";
  } else {
    std::cerr << "  ⚠ Failed to copy, using original path\n";
    strncpy(final_path, so_path, sizeof(final_path) - 1);
  }
  final_path[sizeof(final_path) - 1] = '\0';

  if (is_legacy_android) {
    // === Android 9 and below: Single-stage (direct dlopen from libc) ===
    // On older Android, dlopen from anonymous mmap'd memory fails due to
    // linker namespace restrictions. Stage 1 calls dlopen directly from
    // libc's address space (malloc hook) to bypass this.

    auto stage1 = shellcode::arm64_stage1_direct_dlopen(timezone_addr, dlopen_addr);
    std::cout << "  ✓ Stage1 (direct): " << stage1.size() << "B\n";

    std::cout << "[4/7] Backing up original memory...\n";
    auto malloc_backup = read_memory(pid, malloc_addr, stage1.size());
    auto timezone_backup = read_memory(pid, timezone_addr, 8);
    if (malloc_backup.empty() || timezone_backup.empty()) {
      std::cerr << " Failed to backup memory\n";
      return false;
    }
    std::cout << "  ✓ Backup complete\n";

    std::cout << "[5/7] Injecting shellcode...\n";
    std::vector<uint8_t> zero(8, 0);
    if (!write_memory(pid, timezone_addr, zero)) {
      std::cerr << " Failed to zero timezone\n";
      return false;
    }
    if (!write_memory(pid, malloc_addr, stage1)) {
      std::cerr << " Failed to write stage1\n";
      write_memory(pid, timezone_addr, timezone_backup);
      return false;
    }
    std::cout << "  ✓ Stage1 injected\n";

    std::cout << "[6/7] Waiting for malloc() trigger...\n";
    int timeout_counter = 0;
    const int MAX_TIMEOUT = 30000;

    // Try multiple signals to maximize chance of hitting malloc:
    // SIGUSR1 (10): ART GC trigger — works for app processes
    // SIGQUIT (3):  ART thread dump — calls malloc heavily, works for Zygote
    char kill_cmd[256];
    snprintf(kill_cmd, sizeof(kill_cmd), "kill -10 %d 2>/dev/null", pid);
    system(kill_cmd);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    snprintf(kill_cmd, sizeof(kill_cmd), "kill -3 %d 2>/dev/null", pid);
    system(kill_cmd);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    // If target is Zygote (has only 1 thread and is in ppoll), launch a cold
    // app in parallel to force Zygote to process a fork request and call malloc.
    char check_cmd[256];
    snprintf(check_cmd, sizeof(check_cmd),
             "cat /proc/%d/status 2>/dev/null | grep -q 'Threads:\\s*1' && "
             "cat /proc/%d/comm 2>/dev/null | grep -q zygote", pid, pid);
    if (system(check_cmd) == 0) {
      std::cout << "  → Target is Zygote, forcing fork via monkey...\n";
      // Launch any app via monkey to force Zygote to fork (and call malloc)
      system("monkey -p com.google.android.contacts 1 >/dev/null 2>&1 &");
    }
    std::cout << "  → Trigger signals sent\n";

    bool dlopen_ok = false;
    while (true) {
      std::this_thread::sleep_for(std::chrono::milliseconds(3));
      auto data = read_memory(pid, timezone_addr, 8);
      if (data.size() != 8) {
        timeout_counter++;
        if (timeout_counter > MAX_TIMEOUT) {
          std::cerr << " Timeout waiting for malloc trigger\n";
          write_memory(pid, malloc_addr, malloc_backup);
          write_memory(pid, timezone_addr, timezone_backup);
          return false;
        }
        continue;
      }

      uint64_t val = 0;
      memcpy(&val, data.data(), 8);

      if (val != 0) {
        dlopen_ok = (val > 1);
        if (!dlopen_ok) {
          // Android 9 quirk: dlopen may return NULL but library is still loaded
          // (constructors run before namespace check fails)
          // Verify by checking /proc/pid/maps
          uintptr_t agent_base = find_library_base(pid, "libagent.so");
          if (agent_base != 0) {
            std::cout << "  → dlopen returned NULL but library loaded at 0x"
                      << std::hex << agent_base << std::dec << "\n";
            dlopen_ok = true;
          }
        }
        break;
      }

      timeout_counter++;
      if (timeout_counter > MAX_TIMEOUT) {
        std::cerr << " Timeout waiting for malloc trigger\n";
        write_memory(pid, malloc_addr, malloc_backup);
        write_memory(pid, timezone_addr, timezone_backup);
        return false;
      }
    }
    std::cout << "  ✓ Triggered! dlopen " << (dlopen_ok ? "succeeded" : "failed") << "\n";

    std::cout << "[7/7] Restoring original functions...\n";

    auto loop = shellcode::arm64_infinite_loop();
    if (!write_memory(pid, malloc_addr, loop)) {
      std::cerr << "Failed to write infinite loop\n";
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    if (!write_memory(pid, malloc_addr, malloc_backup)) {
      std::cerr << "Warning: Failed to restore malloc\n";
    }
    if (!write_memory(pid, timezone_addr, timezone_backup)) {
      std::cerr << "Warning: Failed to restore timezone\n";
    }

    // Send SIGUSR2 to flush I-cache on main thread.
    // On Android 9, /proc/pid/mem writes don't invalidate I-cache,
    // so the main thread may still execute stale infinite loop from cache.
    // The agent installs a SIGUSR2 handler that calls __builtin___clear_cache.
    kill(pid, SIGUSR2);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::cout << "  ✓ Original functions restored\n";

    std::cout << "\n Injection " << (dlopen_ok ? "complete" : "FAILED")
              << "! Loaded: " << so_path << "\n";
    return dlopen_ok;

  } else {
    auto stage2 = shellcode::arm64_stage2_dlopen_linjector(
        dlopen_addr, final_path, malloc_addr);
    auto stage1 =
        shellcode::arm64_stage1_linjector_exact(timezone_addr, stage2.size());
    std::cout << "  ✓ Stage1: " << stage1.size() << "B, Stage2: " << stage2.size()
              << "B\n";

    // Preferred path - stage 1 in a code cave, malloc()
    // patched with a single branch. Falls back to the original in-place
    // scheme below only when libc has no usable padding after its text.
    uintptr_t cave = find_code_cave(pid, libc_path, libc_base, malloc_addr, stage1.size());
    // Escape hatch: RENEF_NO_CODE_CAVE=1 in renef_server's environment
    // forces the original in-place scheme (also used to measure it).
    if (getenv("RENEF_NO_CODE_CAVE")) {
      cave = 0;
    }
    if (cave) {
      return inject_via_code_cave(pid, malloc_addr, timezone_addr, cave, stage1, stage2, so_path);
    }
    std::cout << "  ⚠ No code cave after libc text, using in-place malloc patch\n";

    std::cout << "[4/7] Backing up original memory...\n";
    auto malloc_backup = read_memory(pid, malloc_addr, stage1.size());
    auto timezone_backup = read_memory(pid, timezone_addr, 8);
    if (malloc_backup.empty() || timezone_backup.empty()) {
      std::cerr << " Failed to backup memory\n";
      return false;
    }
    std::cout << "  ✓ Backup complete\n";

    std::cout << "[5/7] Injecting stage 1 shellcode...\n";
    std::vector<uint8_t> zero(8, 0);
    if (!write_memory(pid, timezone_addr, zero)) {
      std::cerr << " Failed to zero timezone\n";
      return false;
    }
    if (!write_memory(pid, malloc_addr, stage1)) {
      std::cerr << " Failed to write stage1\n";
      write_memory(pid, timezone_addr, timezone_backup);
      return false;
    }
    std::cout << "  ✓ Stage1 injected\n";

    std::cout << "[6/7] Waiting for malloc() trigger...\n";
    uintptr_t new_map = 0;
    int timeout_counter = 0;
    const int MAX_TIMEOUT = 30000;

    char kill_cmd[256];
    snprintf(kill_cmd, sizeof(kill_cmd), "kill -10 %d 2>/dev/null",
             pid); // SIGUSR1 → GC
    system(kill_cmd);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    std::cout << "  → Trigger signals sent\n";

    while (true) {
      std::this_thread::sleep_for(std::chrono::milliseconds(3));
      auto data = read_memory(pid, timezone_addr, 8);
      if (data.size() != 8) {
        timeout_counter++;
        if (timeout_counter > MAX_TIMEOUT) {
          std::cerr << " Timeout waiting for malloc trigger\n";
          write_memory(pid, malloc_addr, malloc_backup);
          write_memory(pid, timezone_addr, timezone_backup);
          return false;
        }
        continue;
      }

      uint64_t val = 0;
      memcpy(&val, data.data(), 8);

      if ((val & 0x1) && (val & 0xFFFFFFFFFFFFFFF0)) {
        new_map = val & 0xFFFFFFFFFFFFFFF0;
        break;
      }

      timeout_counter++;
      if (timeout_counter > MAX_TIMEOUT) {
        std::cerr << " Timeout waiting for malloc trigger\n";
        write_memory(pid, malloc_addr, malloc_backup);
        write_memory(pid, timezone_addr, timezone_backup);
        return false;
      }
    }
    std::cout << "  ✓ Triggered! New map: 0x" << std::hex << new_map << std::dec
              << "\n";

    std::cout << "[7/7] Finalizing injection...\n";

    if (!write_memory(pid, new_map, stage2)) {
      std::cerr << "Failed to write stage2\n";
      return false;
    }
    std::cout << "  ✓ Stage2 written to new map\n";

    auto loop = shellcode::arm64_infinite_loop();
    if (!write_memory(pid, malloc_addr, loop)) {
      std::cerr << "Failed to write infinite loop\n";
      return false;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    if (!write_memory(pid, malloc_addr, malloc_backup)) {
      std::cerr << "Warning: Failed to restore malloc\n";
    }
    if (!write_memory(pid, timezone_addr, timezone_backup)) {
      std::cerr << "Warning: Failed to restore timezone\n";
    }
    std::cout << "  ✓ Original functions restored\n";

    std::cout << "\n Injection complete! Loaded: " << so_path << "\n";
    return true;
  }
}

#ifdef BUILD_STANDALONE_AGENT
int main(int argc, char **argv) {
  int pid;
  const char *so_path;

  if (argc == 2) {
    pid = atoi(argv[1]);
    so_path = DEFAULT_PAYLOAD_PATH;
  } else if (argc == 3) {
    pid = atoi(argv[1]);
    so_path = argv[2];
  } else {
    std::cerr << "Usage: " << argv[0] << " <PID> [SO_PATH]\n";
    std::cerr << "  Default payload: " << DEFAULT_PAYLOAD_PATH << "\n";
    return 1;
  }

  if (inject(pid, so_path)) {
    return 0;
  } else {
    return 1;
  }
}
#endif

