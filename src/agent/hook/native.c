#include <agent/hook.h>
#include <agent/globals.h>
#include <agent/output_queue.h>
#include <agent/proc.h>
#include <agent/lua_thread.h>

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sched.h>
#include <dlfcn.h>
#include <link.h>
#include <android/dlext.h>
#include <elf.h>
#include <capstone/capstone.h>

// Reentrancy guard: prevents infinite recursion when a hooked function
// (e.g. __android_log_print, strlen, fopen) is called from inside the
// hook handler itself (via LOGI, verbose_log, etc.)
//
// This flag is NOT a `__thread` variable. On Android a
// `__thread` access in a dlopen()ed library is emulated TLS: a call to
// __emutls_get_address(), which itself calls pthread_getspecific(), and on
// first use pthread_once()/pthread_mutex_lock()/malloc() - and a contended
// mutex ends in a futex wait that bionic issues through the exported
// syscall() function. So with any of those hooked, merely READING the flag
// that is supposed to stop recursion re-entered the hook handler. Excluding
// calls made from libagent.so by return address (check_hook_reentrant) does
// not help here: the hooked function is called by libc, on our behalf.
// Found live: hooking syscall() killed the target with a SIGSEGV that left
// no tombstone (unbounded recursion on whatever thread hit it first).
//
// The flag therefore lives in a small lock-free table keyed by the thread
// pointer (tpidr_el0): one `mrs`, a hash, a compare - no libc, no TLS
// machinery. Every other thread-local in this file is only ever touched
// while the flag is already set, so their emulated-TLS lookups are safe.
#define HOOK_GUARD_SLOTS 4096 /* power of two; live threads + churn */

typedef struct {
    uintptr_t tp;   /* thread pointer owning this slot, 0 = free */
    int flag;

    /* All other per-thread hook state lives here too, for the same reason
     * as the flag: the handler runs on arbitrary threads in arbitrary
     * contexts - including from INSIDE malloc() when an allocator-internal
     * function is hooked - and a first-time emulated-TLS access allocates
     * (__emutls_get_address -> malloc). Found live with syscall() hooked:
     * a thread that entered the hook from scudo's lock slow path did its
     * first `__thread` access, re-entered malloc(), and deadlocked the
     * allocator against the thread running a Lua callback. */
    int handler_depth;        /* >0 while inside generic_hook_handler's normal path */
    int cur_hook_plus1;       /* current hook index + 1 (0 = none) */
    int agent_lua_depth;      /* lua_vm_lock nesting on this thread */
    int agent_lua_saved;      /* guard value to restore at the outermost unlock */
    uint64_t replace_retval;  /* result of an Interceptor.replace callback */
    void* jni_env;            /* JNIEnv* of the hooked call (x0) */
    uintptr_t caller_fp;      /* frame record of the hooked function's caller */
    uintptr_t caller_lr;
} HookGuardSlot;

static HookGuardSlot g_hook_guard_slots[HOOK_GUARD_SLOTS];

static inline uintptr_t hook_guard_thread_pointer(void) {
    uintptr_t tp;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tp));
    return tp;
}

// Slot of the calling thread, claiming a free one on first use. A thread
// pointer is unique among live threads; when a thread exits and a later one
// reuses the same address it simply inherits the slot (flag is 0 again by
// then: every set is paired with a reset on the same thread). NULL only if
// all slots are taken - callers then treat the thread as guarded, i.e.
// hooks are bypassed on it rather than risking recursion.
static HookGuardSlot* hook_guard_slot(void) {
    uintptr_t tp = hook_guard_thread_pointer();
    size_t h = (size_t)(((uint64_t)(tp >> 4) * 0x9E3779B97F4A7C15ULL) >> 52) & (HOOK_GUARD_SLOTS - 1);
    for (size_t probe = 0; probe < HOOK_GUARD_SLOTS; probe++) {
        HookGuardSlot* slot = &g_hook_guard_slots[(h + probe) & (HOOK_GUARD_SLOTS - 1)];
        uintptr_t cur = __atomic_load_n(&slot->tp, __ATOMIC_ACQUIRE);
        if (cur == tp) return slot;
        if (cur == 0) {
            uintptr_t expected = 0;
            if (__atomic_compare_exchange_n(&slot->tp, &expected, tp, false,
                                            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                return slot;
            }
            if (expected == tp) return slot;
        }
    }
    return NULL;
}

// State of the calling thread. Never NULL: if the table is full the thread
// shares one dummy record - it is treated as permanently guarded (see
// hook_guard_get), so nothing on the handler's normal path ever uses it.
static HookGuardSlot g_hook_guard_overflow;

static inline HookGuardSlot* hook_thread_state(void) {
    HookGuardSlot* slot = hook_guard_slot();
    return slot ? slot : &g_hook_guard_overflow;
}

static inline int hook_guard_get(void) {
    HookGuardSlot* slot = hook_guard_slot();
    return slot ? slot->flag : 1;
}

static inline void hook_guard_set(int value) {
    HookGuardSlot* slot = hook_guard_slot();
    if (slot) slot->flag = value;
}

// Return value produced by an Interceptor.replace callback, read back by
// generic_hook_handler when hook_logger signals replace mode (returns 1).
// Thread-local: each thread carries its own in-flight replacement result.
#define g_replace_retval (hook_thread_state()->replace_retval)

uint64_t get_replace_retval(void) {
    return g_replace_retval;
}

// Per-call JNIEnv*, thread-local. `g_current_jni_env`
// (globals.c, process-wide) serves a DIFFERENT role -- the agent-init env
// captured once on the agent's own command/eval thread, which
// install_lua_java_hook() (below) reads to register Java hooks, including
// from deferred_poll_thread (a different thread, which must still see it --
// so that global must stay global). This thread-local one is the OTHER
// role: hook_logger() sets it from x0 on the APP thread that just triggered
// a hook, and log_return_value() reads it back on that SAME thread shortly
// after, to build a jstring for an onLeave return override. JNIEnv* is only
// valid on the thread that obtained it, so sharing one global between two
// app threads hooking concurrently let thread B's log_return_value() call
// NewStringUTF with thread A's JNIEnv* -- undefined behavior in ART,
// matching the reported "freeze/crash under concurrent hooks" symptom.
#define g_hook_call_jni_env (*(JNIEnv**)&hook_thread_state()->jni_env)
#include <capstone/arm64.h>

HookInfo g_hooks[MAX_HOOKS];
int g_hook_count = 0;

// Per-thread, in the guard table (see HookGuardSlot). Read-only view; the
// single writer is set_current_hook_index().
#define g_current_hook_index (hook_thread_state()->cur_hook_plus1 - 1)

// The caller frame of the hooked function, for Thread.backtrace() inside a
// callback. Shadow the emulated-TLS variables of the same name declared in
// lua_thread.h (still used by the strace handler) for everything below.
#define g_hook_caller_fp (hook_thread_state()->caller_fp)
#define g_hook_caller_lr (hook_thread_state()->caller_lr)

uintptr_t hook_current_caller_fp(void) { return hook_thread_state()->caller_fp; }
uintptr_t hook_current_caller_lr(void) { return hook_thread_state()->caller_lr; }

// Native hook onEnter/onLeave/replace callbacks below use the process-wide
// recursive g_lua_vm_mutex (lua_vm_lock/lua_vm_unlock, see globals.h) rather
// than a private mutex here. Previously this file had its own non-shared
// g_lua_mutex, java.c had a *separate* g_java_lua_mutex, and the normal
// script-exec path (engine.c lua_engine_load_script/_load_file) took no lock
// at all — three independent/missing locks guarding the same lua_State. That
// let a normal script execution and a hot native hook callback run Lua code
// concurrently on the same lua_State from different threads, which is the
// root cause of a SIGSEGV seen on a device.

int change_page_protection(void* addr, int prot) {
    void* page = PAGE_START(addr);
    if (mprotect(page, PAGE_SIZE, prot) != 0) {
        LOGE("mprotect failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

uint32_t create_branch_insn(void* from, void* to) {
    int64_t offset = (int64_t)to - (int64_t)from;
    offset >>= 2;
    return 0x14000000 | (offset & 0x03FFFFFF);
}

void* allocate_trampoline(size_t size) {
    size_t aligned_size = ALIGN_UP(size, PAGE_SIZE);
    void* mem = mmap(NULL, aligned_size,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        LOGE("mmap failed: %s", strerror(errno));
        return NULL;
    }
    return mem;
}

// On real devices, security-hardened system libraries
// (confirmed: libcrypto.so, in the segment covering EVP_CipherInit_ex)
// map part of their .text as Execute-Only Memory (XOM: PROT_EXEC without
// PROT_READ, e.g. "--xp" in /proc/self/maps). A plain memcpy()/direct
// read of such a page SIGSEGVs (SEGV_ACCERR) unconditionally - the CPU
// enforces this at the hardware/MMU level regardless of our own process
// being the page's owner. Reads of the target function's own bytes (for
// Capstone disassembly, and for building the trampoline's copied
// prologue) must go through the same privileged path the write side of
// this file already uses for writing hook bytes into such pages:
// /proc/self/mem, whose pread()/pwrite() go through the kernel's
// mem_rw() handler (the same mechanism ptrace PEEKTEXT/POKETEXT uses),
// which is not subject to the mapping's own PROT_READ/PROT_WRITE bits.
static bool safe_read_target_bytes(void* addr, uint8_t* buf, size_t len) {
    int fd = agent_open_self_mem(O_RDONLY);
    if (fd >= 0) {
        ssize_t n = pread(fd, buf, len, (off_t)(uintptr_t)addr);
        close(fd);
        if (n == (ssize_t)len) {
            return true;
        }
        LOGE("safe_read_target_bytes: pread failed (%zd): %s", n, strerror(errno));
    } else {
        LOGE("safe_read_target_bytes: open(/proc/self/mem) failed: %s", strerror(errno));
    }
    // Fall back to a direct read for ordinary (non-XOM) pages, in case
    // /proc/self/mem is ever unavailable (e.g. a hardened SELinux
    // policy blocking self-access) - this still works for the common
    // case, and only XOM pages specifically need the path above.
    memcpy(buf, addr, len);
    return true;
}

size_t disassemble_instructions(void* addr, void** insn_out, size_t min_bytes) {
    csh handle;
    size_t count;
    cs_insn** out = (cs_insn**)insn_out;
    uint8_t code_buf[16];

    if (min_bytes > sizeof(code_buf)) {
        LOGE("disassemble_instructions: min_bytes %zu exceeds buffer", min_bytes);
        return 0;
    }
    if (!safe_read_target_bytes(addr, code_buf, sizeof(code_buf))) {
        LOGE("disassemble_instructions: failed to read target bytes at %p", addr);
        return 0;
    }

    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        LOGE("cs_open failed");
        return 0;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(handle, code_buf, sizeof(code_buf), (uint64_t)addr, 0, out);
    if (count == 0) {
        LOGE("cs_disasm failed");
        cs_close(&handle);
        return 0;
    }

    size_t total_bytes = 0;
    for (size_t i = 0; i < count && total_bytes < min_bytes; i++) {
        total_bytes += (*out)[i].size;
    }

    cs_close(&handle);
    return total_bytes;
}

bool is_pc_relative(void* insn_ptr) {
    cs_insn* insn = (cs_insn*)insn_ptr;

    switch (insn->id) {
        case ARM64_INS_ADRP:
        case ARM64_INS_ADR:
        case ARM64_INS_B:
        case ARM64_INS_BL:
        case ARM64_INS_CBZ:
        case ARM64_INS_CBNZ:
        case ARM64_INS_TBZ:
        case ARM64_INS_TBNZ:
            return true;

        case ARM64_INS_LDR:
            if (insn->detail->arm64.op_count == 2) {
                cs_arm64_op *op = &insn->detail->arm64.operands[1];
                if (op->type == ARM64_OP_MEM && op->mem.base == ARM64_REG_INVALID) {
                    return true;
                }
            }
            return false;

        default:
            return false;
    }
}

// --- Dynamic PLT/GOT resolution via dl_iterate_phdr ---

struct got_scan_ctx {
    const char* sym_name;       // Symbol name to find (e.g. "memcpy")
    const char* caller_lib;     // Optional: only patch this library's GOT
    void* hook_func;            // The hook thunk to redirect to
    HookInfo* hook_info;        // Where to store patched GOT entries
    void* original_func;        // The resolved original function address
    void* target_addr;          // Optional: also match slots already bound to this address
};

static int got_scan_callback(struct dl_phdr_info *info, size_t size, void *data) {
    struct got_scan_ctx *ctx = (struct got_scan_ctx *)data;

    // Skip entries with no name (vdso, main executable)
    if (!info->dlpi_name || strlen(info->dlpi_name) == 0) {
        return 0;
    }

    // If caller_lib is specified, only scan matching libraries
    // caller_lib can be a single name or comma-separated list
    if (ctx->caller_lib && strlen(ctx->caller_lib) > 0) {
        // "*" wildcard — scan all libraries
        if (strcmp(ctx->caller_lib, "*") != 0) {
            bool match = false;
            char callers_copy[1024];
            strncpy(callers_copy, ctx->caller_lib, sizeof(callers_copy) - 1);
            callers_copy[sizeof(callers_copy) - 1] = '\0';

            char* saveptr = NULL;
            char* token = strtok_r(callers_copy, ",", &saveptr);
            while (token) {
                if (strstr(info->dlpi_name, token)) {
                    match = true;
                    break;
                }
                token = strtok_r(NULL, ",", &saveptr);
            }
            if (!match) return 0;
        }
    } else {
        // No caller specified — should not reach here for PLT/GOT
        return 0;
    }

    ElfW(Addr) base = info->dlpi_addr;

    // Find PT_DYNAMIC segment
    const ElfW(Dyn)* dyn = NULL;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = (const ElfW(Dyn)*)(base + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }

    if (!dyn) return 0;

    // Extract dynamic entries
    ElfW(Addr) jmprel_addr = 0;
    size_t pltrelsz = 0;
    ElfW(Addr) symtab_addr = 0;
    ElfW(Addr) strtab_addr = 0;

    for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_JMPREL:   jmprel_addr  = d->d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrelsz     = d->d_un.d_val; break;
            case DT_SYMTAB:   symtab_addr  = d->d_un.d_ptr; break;
            case DT_STRTAB:   strtab_addr  = d->d_un.d_ptr; break;
        }
    }

    if (!jmprel_addr || !symtab_addr || !strtab_addr || pltrelsz == 0) {
        return 0;
    }

    // On Android, d_ptr values may be relative offsets (not relocated by linker).
    // Detect this: if the value is smaller than the module base, it's relative.
    if (jmprel_addr < base)  jmprel_addr  += base;
    if (symtab_addr < base)  symtab_addr  += base;
    if (strtab_addr < base)  strtab_addr  += base;

    const ElfW(Rela)* jmprel = (const ElfW(Rela)*)jmprel_addr;
    const ElfW(Sym)* symtab  = (const ElfW(Sym)*)symtab_addr;
    const char* strtab       = (const char*)strtab_addr;

    size_t rela_count = pltrelsz / sizeof(ElfW(Rela));

    verbose_log("Scanning GOT of %s (%zu relocation entries)", info->dlpi_name, rela_count);

    for (size_t i = 0; i < rela_count; i++) {
        unsigned long sym_idx = ELF64_R_SYM(jmprel[i].r_info);
        const char* name = strtab + symtab[sym_idx].st_name;

        void** got_addr = (void**)(base + jmprel[i].r_offset);

        // Match by name, or by the address the slot is already bound to.
        // The second rule covers aliases: dladdr() reports bionic's openat
        // as "openat64", but callers import it as "openat", so a name-only
        // match finds nothing. Android binds GOT slots at load time
        // (BIND_NOW), so the slot value is the real function address.
        bool by_name = strcmp(name, ctx->sym_name) == 0;
        bool by_addr = !by_name && ctx->target_addr != NULL && *got_addr == ctx->target_addr;

        if (by_name || by_addr) {

            LOGI("Found GOT entry for '%s' (imported as '%s') in %s at %p (current value: %p)",
                 ctx->sym_name, name, info->dlpi_name, got_addr, *got_addr);

            int idx = ctx->hook_info->data.plt_got.patched_count;
            if (idx >= 64) {
                LOGW("Maximum GOT patches reached (64)");
                return 1;
            }

            ctx->hook_info->data.plt_got.got_entries[idx] = got_addr;
            ctx->hook_info->data.plt_got.original_funcs[idx] = *got_addr;
            if (idx == 0) {
                ctx->original_func = *got_addr;
            }

            // Count the
            // entry BEFORE the GOT slot is rewritten, so a thread that goes
            // through the freshly patched slot already finds
            // original_funcs[0] published (patched_count > 0) instead of
            // getting a NULL "original" back from get_hook_trampoline().
            ctx->hook_info->data.plt_got.patched_count++;

            void* new_val = ctx->hook_func;
            int got_fd = agent_open_self_mem(O_RDWR);
            if (got_fd >= 0) {
                pwrite(got_fd, &new_val, sizeof(void*), (off_t)(uintptr_t)got_addr);
                close(got_fd);
            } else {
                if (change_page_protection(got_addr, PROT_READ | PROT_WRITE) != 0) {
                    LOGE("Failed to change GOT page protection for %p", got_addr);
                    ctx->hook_info->data.plt_got.patched_count--;
                    continue;
                }
                *got_addr = ctx->hook_func;
            }

            LOGI("Patched GOT entry at %p: %p -> %p",
                 got_addr, ctx->hook_info->data.plt_got.original_funcs[idx], ctx->hook_func);
        }
    }

    return 0;
}

// PLT/GOT hook by SYMBOL NAME: patches every matching JUMP_SLOT entry in the
// GOT of `caller_lib` (same matching rules as install_plt_got_hook). Needed
// for symbols that cannot be resolved to an address from here - e.g. the
// linker-private __loader_dlopen that only libdl.so imports.
static int install_plt_got_hook_impl(const char* sym_name, void* target_addr, void* hook_func,
                                     HookInfo* hook_info, const char* caller_lib) {
    // Initialize hook_info for PLT/GOT
    hook_info->type = HOOK_PLT_GOT;
    hook_info->data.plt_got.patched_count = 0;
    hook_info->data.plt_got.hook_func = hook_func;

    // Scan loaded modules for GOT entries matching the symbol
    struct got_scan_ctx ctx = {
        .sym_name = sym_name,
        .caller_lib = caller_lib,
        .hook_func = hook_func,
        .hook_info = hook_info,
        .original_func = NULL,
        .target_addr = target_addr
    };

    dl_iterate_phdr(got_scan_callback, &ctx);

    if (hook_info->data.plt_got.patched_count == 0) {
        LOGE("No GOT entries found for symbol '%s'", sym_name);
        return -1;
    }

    LOGI("PLT/GOT hook installed: %d GOT entries patched for '%s'",
         hook_info->data.plt_got.patched_count, sym_name);

    return 0;
}

int install_plt_got_hook_by_name(const char* sym_name, void* hook_func, HookInfo* hook_info, const char* caller_lib) {
    return install_plt_got_hook_impl(sym_name, NULL, hook_func, hook_info, caller_lib);
}

int install_plt_got_hook(void* target_func, void* hook_func, HookInfo* hook_info, const char* caller_lib) {
    LOGI("Installing PLT/GOT hook: target=%p hook=%p", target_func, hook_func);

    // Resolve symbol name via dladdr
    Dl_info dl_info;
    if (!dladdr(target_func, &dl_info) || !dl_info.dli_sname) {
        LOGE("dladdr failed: cannot resolve symbol name for %p", target_func);
        return -1;
    }

    LOGI("Resolved symbol: %s (from %s)", dl_info.dli_sname, dl_info.dli_fname);

    return install_plt_got_hook_impl(dl_info.dli_sname, target_func, hook_func, hook_info, caller_lib);
}

// A PC-relative
// instruction (ADRP/ADR/LDR-literal/B/CBZ/CBNZ/...) copied VERBATIM into
// the trampoline computes its target relative to the TRAMPOLINE's own
// address once it executes there - not the original function's. This
// was previously only logged as a warning (is_pc_relative() below) and
// copied anyway, which is the actual mechanism behind a class of
// "unexplained" crashes: confirmed via disassembly that bionic's real
// __strncmp_aarch64 (what `strncmp` resolves to post-IFUNC) has `cbz x2,
// +0x1ac` as its SECOND instruction (within the copied 16 bytes) - when
// that lands in a ~32-byte trampoline, it branches into the trampoline's
// own zero-filled, never-written tail, i.e. executing 0x00000000, which
// is architecturally UNDEFINED -> SIGILL. This exactly matches the observed
// tombstone: fault at trampoline_base+0x1ac, SIGILL/ILL_ILLOPC. An
// async-hook crash (SIGSEGV writing through a garbage pointer) is the
// same root cause via a different instruction class: integrityHeartbeat's
// `adrp x8, <counter's page>` computed relative to the TRAMPOLINE's
// address instead of the original function's, pointing nowhere near the
// real global.
//
// Fixed by relocating each PC-relative instruction in the copied
// prologue into a position-independent equivalent before it's written
// into the trampoline, instead of copying it verbatim.

// Emits MOVZ + up to 3 MOVK instructions that materialize an arbitrary
// 64-bit absolute value into register `rd`, with no PC-relative
// dependency. Always emits at least the MOVZ (1-4 words).
static size_t emit_load_abs64(uint32_t rd, uint64_t value, uint32_t* out) {
    size_t n = 0;
    uint32_t parts[4] = {
        (uint32_t)(value & 0xFFFF),
        (uint32_t)((value >> 16) & 0xFFFF),
        (uint32_t)((value >> 32) & 0xFFFF),
        (uint32_t)((value >> 48) & 0xFFFF),
    };
    out[n++] = 0xD2800000 | (parts[0] << 5) | rd;              // MOVZ rd, #parts[0]
    if (parts[1]) out[n++] = 0xF2A00000 | (parts[1] << 5) | rd; // MOVK rd, #parts[1], LSL#16
    if (parts[2]) out[n++] = 0xF2C00000 | (parts[2] << 5) | rd; // MOVK rd, #parts[2], LSL#32
    if (parts[3]) out[n++] = 0xF2E00000 | (parts[3] << 5) | rd; // MOVK rd, #parts[3], LSL#48
    return n;
}

// X16 ("IP0") is the architecturally-designated scratch register for
// exactly this purpose (indirect-branch veneers) - safe to clobber here
// regardless of what the original instruction was, since by the time we
// reach this sequence the original instruction's own semantics (the
// register it tested, if any) have already been evaluated.
static size_t emit_abs_branch(uint64_t target, uint32_t* out) {
    size_t n = emit_load_abs64(16, target, out);
    out[n++] = 0xD61F0200; // BR X16
    return n;
}

// Relocates ONE PC-relative instruction (raw 32-bit encoding, originally
// at `orig_pc`) into an equivalent, position-independent sequence
// written to `out` (caller-provided buffer, >= 6 words). Returns the
// number of words written, or 0 if this is a PC-relative form we don't
// know how to relocate (BL, TBZ/TBNZ, FP/SIMD literal loads) - the
// caller must then refuse to install the hook rather than copy it
// verbatim and risk the exact class of crash this function exists to
// prevent.
static size_t relocate_pc_relative(uint32_t raw, uint64_t orig_pc, uint32_t* out) {
    // ADR / ADRP: bits[28:24] == 10000; bit31 selects ADR(0)/ADRP(1).
    if ((raw & 0x1F000000) == 0x10000000) {
        bool is_adrp = (raw >> 31) & 1;
        uint32_t rd = raw & 0x1F;
        uint32_t immlo = (raw >> 29) & 0x3;
        uint32_t immhi = (raw >> 5) & 0x7FFFF;
        int64_t imm21 = (int64_t)((immhi << 2) | immlo);
        if (imm21 & (1LL << 20)) imm21 -= (1LL << 21);

        uint64_t target = is_adrp
            ? (orig_pc & ~0xFFFULL) + ((uint64_t)imm21 << 12)
            : orig_pc + (uint64_t)imm21;

        return emit_load_abs64(rd, target, out);
    }

    // LDR (literal): bits[29:27]==011, bits[25:24]==00 (opc/V free).
    if ((raw & 0x3B000000) == 0x18000000) {
        uint32_t opc = (raw >> 30) & 0x3;
        uint32_t V = (raw >> 26) & 0x1;
        if (V || opc == 3) return 0; // FP/SIMD dest or reserved/PRFM - not handled

        uint32_t rt = raw & 0x1F;
        int64_t imm19 = (int64_t)((raw >> 5) & 0x7FFFF);
        if (imm19 & (1LL << 18)) imm19 -= (1LL << 19);
        uint64_t lit_addr = orig_pc + (uint64_t)(imm19 * 4);

        size_t n = emit_load_abs64(rt, lit_addr, out);
        if (opc == 1) {
            out[n++] = 0xF9400000 | (rt << 5) | rt; // LDR Xrt, [Xrt]
        } else if (opc == 2) {
            out[n++] = 0xB9800000 | (rt << 5) | rt; // LDRSW Xrt, [Xrt]
        } else {
            out[n++] = 0xB9400000 | (rt << 5) | rt; // LDR Wrt, [Xrt]
        }
        return n;
    }

    // B (unconditional): bits[30:26]==00101, bit31 selects B(0)/BL(1).
    if ((raw & 0x7C000000) == 0x14000000) {
        bool is_bl = (raw >> 31) & 1;
        if (is_bl) return 0; // BL in a prologue's first few instructions - not handled
        int64_t imm26 = (int64_t)(raw & 0x3FFFFFF);
        if (imm26 & (1LL << 25)) imm26 -= (1LL << 26);
        uint64_t target = orig_pc + (uint64_t)(imm26 * 4);
        return emit_abs_branch(target, out);
    }

    // CBZ/CBNZ: bits[30:25]==011010 (sf, op free).
    if ((raw & 0x7E000000) == 0x34000000) {
        uint32_t sf = (raw >> 31) & 1;
        uint32_t op = (raw >> 24) & 1; // 0=CBZ, 1=CBNZ
        uint32_t rt = raw & 0x1F;
        int64_t imm19 = (int64_t)((raw >> 5) & 0x7FFFF);
        if (imm19 & (1LL << 18)) imm19 -= (1LL << 19);
        uint64_t target = orig_pc + (uint64_t)(imm19 * 4);

        // Invert the condition to skip over an absolute-jump sequence:
        //   CBNZ/CBZ rt, +6   (inverted: if condition is FALSE, skip)
        //   <emit_abs_branch(target)>   (up to 5 words)
        // "+6" = this instruction + the 5-word absolute jump that follows.
        //
        // The skip distance MUST be computed from what emit_abs_branch()
        // actually emitted: it is 2..5 words, not always 5 (MOVK is only
        // emitted for non-zero 16-bit chunks, and a normal userspace
        // address has a zero top chunk -> 4 words). A hard-coded "+6" then
        // skipped one instruction too many on the fall-through path, i.e.
        // silently dropped the ORIGINAL instruction that follows the
        // CBZ/CBNZ (found live: bionic strncpy starts `cbz x2,..; sub x8,
        // x2,#1` - the `sub` was skipped, x8 stayed garbage, SIGSEGV in the
        // zero-fill tail).
        size_t n_abs = emit_abs_branch(target, &out[1]);
        uint32_t inv_op = 1 - op;
        uint32_t skip = (uint32_t)(n_abs + 1);
        out[0] = (sf << 31) | (0x1A << 25) | (inv_op << 24) | ((skip & 0x7FFFF) << 5) | rt;
        return n_abs + 1;
    }

    // B.cond: bits[31:24]==01010100 (fixed), bit4==0.
    // Confirmed live necessary: Android 9 emulator's bionic strcmp()
    // prologue uses `b.ne` here where later Android versions' bionic
    // builds use a different instruction sequence - without this, the
    // hook correctly refused to install (safe) but couldn't actually
    // hook strcmp() on that OS version.
    if ((raw & 0xFF000010) == 0x54000000) {
        uint32_t cond = raw & 0xF;
        int64_t imm19 = (int64_t)((raw >> 5) & 0x7FFFF);
        if (imm19 & (1LL << 18)) imm19 -= (1LL << 19);
        uint64_t target = orig_pc + (uint64_t)(imm19 * 4);

        // Same technique as CBZ/CBNZ: invert the condition (flip bit 0,
        // standard AArch64 condition-code pairing) to skip over an
        // absolute-jump sequence instead.
        // Skip distance computed from the real emitted length - see the
        // CBZ/CBNZ case above for why a fixed "+6" was wrong.
        size_t n_abs = emit_abs_branch(target, &out[1]);
        uint32_t inv_cond = cond ^ 1;
        uint32_t skip = (uint32_t)(n_abs + 1);
        out[0] = 0x54000000 | ((skip & 0x7FFFF) << 5) | inv_cond;
        return n_abs + 1;
    }

    // TBZ/TBNZ, BL - not handled, caller refuses the hook.
    return 0;
}

// --- Near veneers ---
//
// A 16-byte slot `LDR X16,#8 ; BR X16 ; <abs64 thunk>` placed within the
// +-128MB reach of an AArch64 `B`, so the patch written over the target
// can be that single 4-byte `B veneer` (see install_trampoline_hook for
// why that matters). Slots are bump-allocated out of RWX pages that are
// mapped into free gaps of the address space near the target and are never
// unmapped: a reverted hook only leaks its 16-byte slot.
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define NEAR_BRANCH_RANGE ((uintptr_t)0x7F00000) // 127MB, margin below the +-128MB limit
#define NEAR_VENEER_SIZE 16
#define MAX_NEAR_PAGES 64

typedef struct {
    uintptr_t base;
    size_t size;
    size_t used;
} NearPage;

static NearPage g_near_pages[MAX_NEAR_PAGES];
static int g_near_page_count = 0;

static bool within_near_range(uintptr_t a, uintptr_t b) {
    uintptr_t d = (a > b) ? (a - b) : (b - a);
    return d < NEAR_BRANCH_RANGE;
}

// Maps one fresh RWX page into a free gap within range of `target`.
static NearPage* map_near_page(uintptr_t target) {
    if (g_near_page_count >= MAX_NEAR_PAGES) return NULL;

    long psz = sysconf(_SC_PAGESIZE);
    uintptr_t page = (psz > 0) ? (uintptr_t)psz : PAGE_SIZE;

    uintptr_t range_lo = (target > NEAR_BRANCH_RANGE) ? (target - NEAR_BRANCH_RANGE) : page;
    uintptr_t range_hi = target + NEAR_BRANCH_RANGE - page; // highest usable page start
    range_lo = (range_lo + page - 1) & ~(page - 1);
    range_hi &= ~(page - 1);

    // Candidate page addresses: for every free gap that intersects the
    // range, the page in it closest to the target.
    uintptr_t cand[16];
    int ncand = 0;

    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return NULL;
    char line[512];
    uintptr_t prev_end = 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long long s = 0, e = 0;
        if (sscanf(line, "%llx-%llx", &s, &e) != 2) continue;
        uintptr_t gap_start = (prev_end + page - 1) & ~(page - 1);
        uintptr_t gap_end = (uintptr_t)s & ~(page - 1);
        prev_end = (uintptr_t)e;
        if (gap_end < gap_start + page) continue; // no whole free page here

        uintptr_t lo = (gap_start > range_lo) ? gap_start : range_lo;
        uintptr_t hi = ((gap_end - page) < range_hi) ? (gap_end - page) : range_hi;
        if (lo > hi) continue;

        uintptr_t pick = (target <= lo) ? lo : hi; // target is mapped, so never inside the gap
        if (ncand < 16) {
            cand[ncand++] = pick;
        } else {
            // keep the 16 closest
            int worst = 0;
            for (int i = 1; i < 16; i++) {
                uintptr_t dw = (cand[worst] > target) ? cand[worst] - target : target - cand[worst];
                uintptr_t di = (cand[i] > target) ? cand[i] - target : target - cand[i];
                if (di > dw) worst = i;
            }
            uintptr_t dw = (cand[worst] > target) ? cand[worst] - target : target - cand[worst];
            uintptr_t dp = (pick > target) ? pick - target : target - pick;
            if (dp < dw) cand[worst] = pick;
        }
    }
    fclose(maps);

    // Try closest first.
    for (int n = 0; n < ncand; n++) {
        int best = -1;
        uintptr_t best_d = 0;
        for (int i = 0; i < ncand; i++) {
            if (cand[i] == 0) continue;
            uintptr_t d = (cand[i] > target) ? cand[i] - target : target - cand[i];
            if (best < 0 || d < best_d) { best = i; best_d = d; }
        }
        if (best < 0) break;
        uintptr_t addr = cand[best];
        cand[best] = 0;

        void* mem = mmap((void*)addr, page, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (mem == MAP_FAILED) continue;
        // Kernels without MAP_FIXED_NOREPLACE treat the address as a hint
        // and may place the page elsewhere - only usable if still in range.
        if (!within_near_range((uintptr_t)mem, target) ||
            !within_near_range((uintptr_t)mem + page, target)) {
            munmap(mem, page);
            continue;
        }
        NearPage* np = &g_near_pages[g_near_page_count++];
        np->base = (uintptr_t)mem;
        np->size = page;
        np->used = 0;
        LOGI("Mapped near-veneer page at %p for target %p", mem, (void*)target);
        return np;
    }
    return NULL;
}

// Returns a veneer that jumps to `dest`, reachable from `target` with a
// plain `B`, or NULL if no memory could be obtained in range.
static void* alloc_near_veneer(uintptr_t target, void* dest) {
    NearPage* np = NULL;
    for (int i = 0; i < g_near_page_count; i++) {
        NearPage* p = &g_near_pages[i];
        if (p->used + NEAR_VENEER_SIZE > p->size) continue;
        if (within_near_range(p->base, target) && within_near_range(p->base + p->size, target)) {
            np = p;
            break;
        }
    }
    if (!np) np = map_near_page(target);
    if (!np) return NULL;

    uint32_t* v = (uint32_t*)(np->base + np->used);
    np->used += NEAR_VENEER_SIZE;
    v[0] = 0x58000050;              // LDR X16, #8
    v[1] = 0xD61F0200;              // BR  X16
    *(uint64_t*)(&v[2]) = (uint64_t)dest;
    __builtin___clear_cache((char*)v, (char*)v + NEAR_VENEER_SIZE);
    return v;
}

// True if `addr` lies in a mapping with execute permission.
static bool address_is_executable(uintptr_t addr) {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return true; // cannot tell - do not block hooking on that
    char line[512];
    bool found = false, exec = false;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long long s = 0, e = 0;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &s, &e, perms) != 3) continue;
        if (addr >= s && addr < e) {
            found = true;
            exec = (perms[2] == 'x');
            break;
        }
    }
    fclose(maps);
    return found && exec;
}

int install_trampoline_hook(void* target_func, void* hook_func, HookInfo* hook_info) {
    LOGI("Installing trampoline hook: target=%p hook=%p", target_func, hook_func);

    // A library's export table also lists DATA objects
    // (environ, stdout, sys_signame, __malloc_hook, ...). Their bytes are
    // not code, but four arbitrary bytes very often still decode as some
    // instruction - so with the single-instruction patch a "hook" on such
    // a symbol would install and overwrite the variable itself (found
    // live: hooking libc's `environ` rewrote half of the pointer, and the
    // next getenv() crashed). Only executable memory can be hooked.
    if (!address_is_executable((uintptr_t)target_func)) {
        LOGE("Cannot hook %p: not in executable memory (a data symbol, not a function?)",
             target_func);
        return -1;
    }

    cs_insn* insn = NULL;
    size_t decoded_bytes = disassemble_instructions(target_func, (void**)&insn, 16);
    if (decoded_bytes == 0) {
        LOGE("Failed to disassemble target function");
        return -1;
    }
    size_t decoded_count = decoded_bytes / 4;

    // Prefer a 4-byte patch (a single `B veneer`, veneer
    // allocated within +-128MB of the target) over the 16-byte absolute
    // jump. Overwriting 16 bytes is unsafe whenever another thread is
    // executing - or is PARKED - inside those bytes. That is the normal
    // state of affairs for syscall wrappers (`mov x8,#nr ; svc #0 ; ...`):
    // a thread blocked in read()/nanosleep()/epoll_pwait() resumes at
    // func+8, which a 16-byte patch has just turned into the 8-byte address
    // literal (found live: SIGILL at nanosleep+8 on RenderThread, and at
    // pwrite64+8 on the installing thread itself, whose own
    // /proc/self/mem pwrite() was the call being patched). A 4-byte patch
    // replaces only the first instruction with one atomic word write, so no
    // thread can ever be "inside" the patch. It also makes short functions
    // (>= 1 instruction) hookable.
    void* veneer = alloc_near_veneer((uintptr_t)target_func, hook_func);
    size_t bytes_to_copy = veneer ? 4 : 16;

    if (veneer) {
        LOGI("Using 4-byte near-branch patch (veneer at %p)", veneer);
    } else {
        LOGW("No free memory within +-128MB of %p, falling back to the 16-byte patch", target_func);
    }

    if (decoded_bytes < bytes_to_copy) {
        LOGE("Cannot safely hook %p: only %zu decodable bytes at the target "
             "(need %zu) - not code, or the function is too small",
             target_func, decoded_bytes, bytes_to_copy);
        cs_free(insn, decoded_count);
        return -1;
    }

    size_t insn_count = bytes_to_copy / 4;

    // 16-byte fallback only: the first 16 bytes must be four instructions
    // that all belong to THIS function, that nothing in them branches back
    // into, and that no thread can be parked inside. Otherwise the patch
    // silently overwrites the next function / a branch target / a syscall
    // return address and the process later executes the 8-byte address
    // literal as code. Refuse with a clear reason instead.
    if (!veneer) {
        uint64_t patch_start = (uint64_t)target_func;
        uint64_t patch_end = patch_start + 16;
        uint64_t cond_branch_past = 0; // furthest conditional-branch target seen so far

        for (size_t i = 0; i < insn_count; i++) {
            cs_insn* in = &insn[i];
            cs_arm64* a = &in->detail->arm64;
            uint64_t in_addr = patch_start + i * 4;

            if (in->id == ARM64_INS_SVC) {
                LOGE("Cannot safely hook %p with a 16-byte patch: syscall wrapper "
                     "(svc at offset %zu) - a thread blocked in this syscall would "
                     "resume inside the patch. Use PLT/GOT mode (caller=...) instead",
                     target_func, i * 4);
                cs_free(insn, decoded_count);
                return -1;
            }

            bool is_imm_branch = (in->id == ARM64_INS_B || in->id == ARM64_INS_BL ||
                                  in->id == ARM64_INS_CBZ || in->id == ARM64_INS_CBNZ ||
                                  in->id == ARM64_INS_TBZ || in->id == ARM64_INS_TBNZ);
            bool is_cond = (in->id == ARM64_INS_CBZ || in->id == ARM64_INS_CBNZ ||
                            in->id == ARM64_INS_TBZ || in->id == ARM64_INS_TBNZ ||
                            (in->id == ARM64_INS_B && a->cc != ARM64_CC_INVALID &&
                             a->cc != ARM64_CC_AL && a->cc != ARM64_CC_NV));

            if (is_imm_branch && a->op_count > 0 &&
                a->operands[a->op_count - 1].type == ARM64_OP_IMM) {
                uint64_t tgt = (uint64_t)a->operands[a->op_count - 1].imm;
                if (tgt > patch_start && tgt < patch_end) {
                    LOGE("Cannot safely hook %p: instruction at offset %zu (%s %s) "
                         "branches into the 16 bytes the hook overwrites",
                         target_func, i * 4, in->mnemonic, in->op_str);
                    cs_free(insn, decoded_count);
                    return -1;
                }
                if (is_cond && tgt >= patch_end && tgt > cond_branch_past) {
                    cond_branch_past = tgt;
                }
            }

            bool is_terminator = (in->id == ARM64_INS_RET || in->id == ARM64_INS_RETAA ||
                                  in->id == ARM64_INS_RETAB || in->id == ARM64_INS_BR ||
                                  in->id == ARM64_INS_BRAA || in->id == ARM64_INS_BRAAZ ||
                                  in->id == ARM64_INS_BRAB || in->id == ARM64_INS_BRABZ ||
                                  in->id == ARM64_INS_UDF || in->id == ARM64_INS_BRK ||
                                  (in->id == ARM64_INS_B && !is_cond));

            // A terminator before the 4th instruction means the function may
            // end here; the remaining patched bytes are only known to be
            // part of it if an earlier conditional branch jumps past them.
            if (is_terminator && i + 1 < insn_count && cond_branch_past <= in_addr) {
                LOGE("Cannot safely hook %p: function ends after %zu bytes (%s %s), "
                     "shorter than the 16-byte hook patch",
                     target_func, (i + 1) * 4, in->mnemonic, in->op_str);
                cs_free(insn, decoded_count);
                return -1;
            }
        }
    }

    // The trampoline returns into the function body with an indirect
    // branch through a scratch register. X16 by default; if a relocated
    // instruction itself writes X16 (its value must survive into the body)
    // use X17 instead. The hook entry path (veneer/thunk) clobbers both, so
    // an instruction that READS either before writing it cannot be hooked.
    bool writes_x16 = false, writes_x17 = false;
    for (size_t i = 0; i < insn_count; i++) {
        cs_arm64* a = &insn[i].detail->arm64;
        bool reads16 = false, reads17 = false, wr16 = false, wr17 = false;
        for (int k = 0; k < a->op_count; k++) {
            cs_arm64_op* op = &a->operands[k];
            if (op->type == ARM64_OP_REG) {
                bool is16 = (op->reg == ARM64_REG_X16 || op->reg == ARM64_REG_W16);
                bool is17 = (op->reg == ARM64_REG_X17 || op->reg == ARM64_REG_W17);
                bool rd = (op->access & CS_AC_READ) || !(op->access & CS_AC_WRITE);
                bool wr = (op->access & CS_AC_WRITE) != 0;
                if (is16) { reads16 |= rd; wr16 |= wr; }
                if (is17) { reads17 |= rd; wr17 |= wr; }
            } else if (op->type == ARM64_OP_MEM) {
                if (op->mem.base == ARM64_REG_X16 || op->mem.index == ARM64_REG_X16) reads16 = true;
                if (op->mem.base == ARM64_REG_X17 || op->mem.index == ARM64_REG_X17) reads17 = true;
            }
        }
        if ((reads16 && !writes_x16) || (reads17 && !writes_x17)) {
            LOGE("Cannot safely hook %p: instruction at offset %zu (%s %s) reads "
                 "x16/x17, which the hook entry path clobbers",
                 target_func, i * 4, insn[i].mnemonic, insn[i].op_str);
            cs_free(insn, decoded_count);
            return -1;
        }
        writes_x16 |= wr16;
        writes_x17 |= wr17;
    }
    if (writes_x16 && writes_x17) {
        LOGE("Cannot safely hook %p: the first %zu bytes set both x16 and x17, "
             "no scratch register left to return into the function", target_func, bytes_to_copy);
        cs_free(insn, decoded_count);
        return -1;
    }
    uint32_t back_reg = writes_x16 ? 17 : 16;

    // Build the trampoline's prologue instruction-by-instruction,
    // relocating any PC-relative instruction instead of copying it
    // verbatim (see the comment above relocate_pc_relative()). Sourced
    // from Capstone's own captured bytes (insn[i].bytes), already safely
    // read via disassemble_instructions()'s safe_read_target_bytes() -
    // no second read of target_func needed here.
    uint32_t prologue[32]; // worst case per instruction: 6 words (CBZ/CBNZ); 4 instructions max
    size_t prologue_words = 0;
    for (size_t i = 0; i < insn_count; i++) {
        uint32_t raw;
        memcpy(&raw, insn[i].bytes, sizeof(raw));
        uint64_t orig_pc = (uint64_t)target_func + i * 4;

        if (is_pc_relative(&insn[i])) {
            size_t n = relocate_pc_relative(raw, orig_pc, &prologue[prologue_words]);
            if (n == 0) {
                LOGE("Cannot safely hook %p: unrelocatable PC-relative instruction "
                     "at offset %zu (%s %s)",
                     target_func, i * 4, insn[i].mnemonic, insn[i].op_str);
                cs_free(insn, decoded_count);
                return -1;
            }
            LOGW("Relocated PC-relative instruction at offset %zu (%s %s) into "
                 "%zu position-independent instruction(s)",
                 i * 4, insn[i].mnemonic, insn[i].op_str, n);
            prologue_words += n;
        } else {
            prologue[prologue_words++] = raw;
        }
    }

    size_t prologue_size = prologue_words * 4;
    size_t trampoline_size = prologue_size + 16;
    void* trampoline = allocate_trampoline(trampoline_size);
    if (!trampoline) {
        LOGE("Failed to allocate trampoline");
        cs_free(insn, decoded_count);
        return -1;
    }

    memcpy(trampoline, prologue, prologue_size);

    LOGI("Wrote %zu relocated/copied bytes (from %zu original bytes) to trampoline at %p",
         prologue_size, bytes_to_copy, trampoline);

    void* return_addr = (void*)((uintptr_t)target_func + bytes_to_copy);
    void* branch_location = (void*)((uintptr_t)trampoline + prologue_size);

    uint32_t* branch_insns = (uint32_t*)branch_location;
    branch_insns[0] = 0x58000040 | back_reg;          // LDR X<back_reg>, #8
    branch_insns[1] = 0xD61F0000 | (back_reg << 5);   // BR  X<back_reg>
    *(uint64_t*)(&branch_insns[2]) = (uint64_t)return_addr;

    LOGI("Added branch back: from %p to %p (via x%u)", branch_location, return_addr, back_reg);

    __builtin___clear_cache((char*)trampoline, (char*)((uintptr_t)trampoline + trampoline_size));

    // Original (unmodified) instruction words, for uninstall/revert -
    // straight from Capstone's own captured bytes, NOT from `trampoline`
    // (which may now hold relocated/expanded instructions rather than a
    // 1:1 copy, whenever any original instruction was PC-relative).
    uint32_t orig_words[4] = {0, 0, 0, 0};
    for (size_t i = 0; i < insn_count && i < 4; i++) {
        memcpy(&orig_words[i], insn[i].bytes, sizeof(uint32_t));
    }
    for (size_t i = 0; i < 4; i++) {
        hook_info->data.trampoline.original_insn[i] = orig_words[i];
    }

    // Publish the complete hook record BEFORE the target is
    // patched. The instant the patch lands, any other thread can enter the
    // thunk -> generic_hook_handler -> get_hook_trampoline(); if
    // type/trampoline_addr were still unset at that point (they used to be
    // assigned only after the write, with a logcat call in between) the
    // handler did `blr NULL` - the pc=0 SIGSEGV seen when installing many
    // hooks on hot libc functions in a multi-threaded target.
    hook_info->data.trampoline.target_addr = target_func;
    hook_info->data.trampoline.trampoline_addr = trampoline;
    hook_info->data.trampoline.hook_addr = hook_func;
    hook_info->data.trampoline.original_size = bytes_to_copy;
    hook_info->type = HOOK_TRAMPOLINE;

    uint8_t hook_bytes[16];
    uint32_t* hb = (uint32_t*)hook_bytes;
    if (veneer) {
        int64_t delta = (int64_t)((uintptr_t)veneer - (uintptr_t)target_func);
        hb[0] = 0x14000000 | (uint32_t)((delta >> 2) & 0x03FFFFFF); // B veneer
    } else {
        hb[0] = 0x58000050;
        hb[1] = 0xd61f0200;
        *(uint64_t*)(&hb[2]) = (uint64_t)hook_func;
    }

    bool wrote_via_proc_mem = false;
    int mem_fd = agent_open_self_mem(O_RDWR);
    if (mem_fd >= 0) {
        ssize_t written = pwrite(mem_fd, hook_bytes, bytes_to_copy, (off_t)(uintptr_t)target_func);
        close(mem_fd);
        if (written != (ssize_t)bytes_to_copy) {
            LOGE("pwrite failed (%zd): %s, falling back to mprotect", written, strerror(errno));
            goto mprotect_fallback;
        }
        LOGI("Wrote hook via /proc/self/mem (no mprotect)");
        wrote_via_proc_mem = true;
    } else {
        mprotect_fallback:
        if (change_page_protection(target_func, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            LOGE("Failed to change target page protection");
            hook_info->data.trampoline.trampoline_addr = NULL;
            munmap(trampoline, ALIGN_UP(trampoline_size, PAGE_SIZE));
            cs_free(insn, decoded_count);
            return -1;
        }
        memcpy(target_func, hook_bytes, bytes_to_copy);
        LOGI("Wrote hook via mprotect fallback");
    }

    // On an Execute-Only page, even a plain
    // *read* is blocked at the MMU level - and __builtin___clear_cache's
    // "dc cvau"/"ic ivau" cache-maintenance-by-VA instructions are
    // subject to the SAME data-side permission check, so calling it on
    // target_func here reliably SIGSEGVs (confirmed via tombstone:
    // "Cause: execute-only (no-read) memory access error") even though
    // the write itself just succeeded via /proc/self/mem. That kernel
    // write path (mem_rw() -> access_remote_vm(), the same mechanism
    // ptrace POKETEXT uses) already performs its own icache invalidation
    // for the written range as part of the remote-write - unlike a
    // direct userspace store, it doesn't need a userspace cache flush
    // behind it. Only the mprotect-fallback path (a real userspace
    // store, and the page is now genuinely readable/writable/executable)
    // still needs the explicit flush.
    if (!wrote_via_proc_mem) {
        __builtin___clear_cache((char*)target_func, (char*)((uintptr_t)target_func + bytes_to_copy));
    }

    cs_free(insn, decoded_count);

    LOGI("Trampoline hook installed: target=%p trampoline=%p patch=%zu bytes",
         target_func, trampoline, bytes_to_copy);
    return 0;
}

int uninstall_hook(int hook_id) {
    if (hook_id < 0 || hook_id >= g_hook_count) {
        LOGE("Invalid hook ID: %d", hook_id);
        return -1;
    }

    HookInfo* hook = &g_hooks[hook_id];

    if (hook->type == HOOK_TRAMPOLINE) {
        if (hook->data.trampoline.target_addr == NULL) {
            LOGI("Hook %d already uninstalled", hook_id);
            return 0;
        }

        void* target = hook->data.trampoline.target_addr;

        if (change_page_protection(target, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            LOGE("Failed to change page protection for unhook");
            return -1;
        }

        // Restore exactly what the install overwrote: 4 bytes for a
        // near-branch patch, 16 for the absolute-jump fallback.
        size_t restore_size = hook->data.trampoline.original_size;
        if (restore_size != 4 && restore_size != 16) restore_size = 16;

        uint32_t* target_insns = (uint32_t*)target;
        for (size_t i = 0; i < restore_size / 4; i++) {
            target_insns[i] = hook->data.trampoline.original_insn[i];
        }

        __builtin___clear_cache((char*)target, (char*)((uintptr_t)target + restore_size));

        // Do NOT unmap the trampoline or clear
        // trampoline_addr. Other threads can be anywhere between the
        // (just removed) patch and the end of the hook right now: in the
        // thunk, in generic_hook_handler about to ask for this hook's
        // trampoline, or executing the trampoline itself. Unmapping it /
        // returning NULL for it crashed exactly those threads (found live:
        // ~half of all detaches with 127 hooks on hot libc functions ended
        // in SIGSEGV or a frozen main thread). The trampoline stays valid
        // forever - it is the original instruction plus a jump back, which
        // is correct with or without the patch - at the cost of one leaked
        // page per removed hook. target_addr == NULL is the "uninstalled"
        // marker.
        hook->data.trampoline.target_addr = NULL;

    } else if (hook->type == HOOK_PLT_GOT) {
        if (hook->data.plt_got.patched_count == 0) {
            LOGI("Hook %d already uninstalled", hook_id);
            return 0;
        }

        for (int i = 0; i < hook->data.plt_got.patched_count; i++) {
            void** got_entry = hook->data.plt_got.got_entries[i];
            if (!got_entry) continue;

            if (change_page_protection(got_entry, PROT_READ | PROT_WRITE) != 0) {
                LOGE("Failed to change GOT page protection for uninstall (entry %d)", i);
                continue;
            }

            *got_entry = hook->data.plt_got.original_funcs[i];
            __builtin___clear_cache((char*)got_entry, (char*)got_entry + sizeof(void*));
            hook->data.plt_got.got_entries[i] = NULL;
        }

        hook->data.plt_got.patched_count = 0;
        // Thunk intentionally left mapped, and original_funcs[0] left in
        // place, for threads still on their way through this hook (see the
        // trampoline case above).
    }

    // uninstall_hook() is reached from the "unhook"/"unhook all" command on
    // the connection thread, outside any script's lua_pcall — it must take
    // the VM lock itself before touching the Lua registry, since a hook
    // callback on another app thread may be mid-dispatch on this hook right
    // now.
    if (g_lua_engine && (hook->lua_onEnter_ref != LUA_NOREF || hook->lua_onLeave_ref != LUA_NOREF ||
                          hook->lua_replace_ref != LUA_NOREF)) {
        lua_vm_lock();
        lua_State* L = lua_engine_get_state(g_lua_engine);
        if (L) {
            if (hook->lua_onEnter_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, hook->lua_onEnter_ref);
            }
            if (hook->lua_onLeave_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, hook->lua_onLeave_ref);
            }
            // This was missing before -- a replace-hook's
            // callback ref (is_replace=1, onEnter/onLeave both LUA_NOREF)
            // was never released on uninstall, leaking one Lua registry
            // slot per Interceptor.replace() call that got unhooked.
            if (hook->lua_replace_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, hook->lua_replace_ref);
            }
        }
        // Cleared while still holding the VM lock: a thread already inside
        // the handler takes this lock before it reads the refs, so it
        // either ran its callback before this point or sees "no callback"
        // and just calls the original.
        hook->lua_onEnter_ref = LUA_NOREF;
        hook->lua_onLeave_ref = LUA_NOREF;
        hook->lua_replace_ref = LUA_NOREF;
        hook->is_replace = 0;
        lua_vm_unlock();
    }

    hook->lua_onEnter_ref = LUA_NOREF;
    hook->lua_onLeave_ref = LUA_NOREF;
    hook->lua_replace_ref = LUA_NOREF;
    hook->logical_target_addr = NULL;
    hook->is_async = 0;

    LOGI("Hook %d uninstalled", hook_id);
    return 0;
}

// Interceptor.revert(lib, offset). Resolves (lib_name,
// offset) to an absolute address exactly like install_lua_hook/
// install_lua_replace do, then finds whichever installed slot (trampoline
// or PLT/GOT -- logical_target_addr is set for both) matches that address
// and reverts it via the existing uninstall_hook().
int interceptor_revert(const char* lib_name, uintptr_t offset) {
    uintptr_t base = (uintptr_t)find_library_base(lib_name);
    if (base == 0) {
        LOGE("Interceptor.revert: library %s not loaded", lib_name);
        return -1;
    }

    void* target_addr = (void*)(base + offset);

    for (int i = 0; i < g_hook_count; i++) {
        if (g_hooks[i].logical_target_addr == target_addr) {
            LOGI("Interceptor.revert: found hook #%d for %s+0x%lx", i, lib_name, offset);
            return uninstall_hook(i);
        }
    }

    LOGE("Interceptor.revert: no installed hook found at %s+0x%lx", lib_name, offset);
    return -1;
}

int uninstall_all_hooks(void) {
    int count = 0;
    for (int i = 0; i < g_hook_count; i++) {
        bool is_installed = false;

        if (g_hooks[i].type == HOOK_TRAMPOLINE) {
            is_installed = (g_hooks[i].data.trampoline.target_addr != NULL);
        } else if (g_hooks[i].type == HOOK_PLT_GOT) {
            is_installed = (g_hooks[i].data.plt_got.patched_count > 0);
        }

        if (is_installed && uninstall_hook(i) == 0) {
            count++;
        }
    }
    LOGI("Uninstalled %d hooks", count);
    return count;
}

static void init_agent_text_range(void);

void* create_hook_thunk(int hook_index) {
    // Every hook gets a thunk before its target is patched, so this is the
    // one place that guarantees the agent's own text range is known before
    // any handler can run (see check_hook_reentrant()).
    init_agent_text_range();

    void* thunk = mmap(NULL, PAGE_SIZE,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (thunk == MAP_FAILED) {
        LOGE("Failed to allocate thunk");
        return NULL;
    }

    uint32_t* code = (uint32_t*)thunk;

    code[0] = 0xD2800011 | ((hook_index & 0xFFFF) << 5);

    code[1] = 0x58000070;

    code[2] = 0xD61F0200;

    code[3] = 0xD503201F;

    *(uint64_t*)(&code[4]) = (uint64_t)generic_hook_handler;

    __builtin___clear_cache((char*)thunk, (char*)thunk + 32);

    LOGI("Created thunk at %p for hook index %d", thunk, hook_index);
    return thunk;
}

// ============================================================
// Deferred hooks: installed automatically when a library loads
// ============================================================

typedef struct {
    char lib_name[128];
    uintptr_t offset;
    int onEnter_ref;
    int onLeave_ref;
    int replace_ref;   // Interceptor.replace callback, or LUA_NOREF for a plain hook
    char caller_lib[128];
    bool active;
    bool is_async;      // carried through to the real install once the library loads
} PendingHook;

// Bumped proportionally with MAX_HOOKS (globals.h).
#define MAX_PENDING_HOOKS 64
static PendingHook g_pending_hooks[MAX_PENDING_HOOKS];
static int g_pending_hook_count = 0;
static bool g_dlopen_hooked = false;

// Hook installation is reachable from three threads - the
// script/command thread (hook()/Interceptor.replace), the deferred poll
// thread, and whichever app thread just returned from dlopen (the dlopen event
// path). Nothing serialised them: found live, the event path and the poll
// thread both saw the same pending hook as still active and both installed
// it, claiming the same g_hooks slot and patching the same function twice.
// One recursive mutex covers every path that touches g_hooks/g_hook_count
// or the pending-hook table.
static pthread_mutex_t g_hook_install_mutex;
static pthread_once_t g_hook_install_mutex_once = PTHREAD_ONCE_INIT;

static void init_hook_install_mutex(void) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_hook_install_mutex, &attr);
    pthread_mutexattr_destroy(&attr);
}

static void hook_install_lock(void) {
    pthread_once(&g_hook_install_mutex_once, init_hook_install_mutex);
    pthread_mutex_lock(&g_hook_install_mutex);
}

static void hook_install_unlock(void) {
    pthread_mutex_unlock(&g_hook_install_mutex);
}

static void try_install_pending_hooks(void);
static void try_install_pending_hooks_impl(bool from_dlopen_event);

// Bounded backoff instead of an unconditional busy-spin.
// A plain sched_yield() loop with no sleep pins one CPU core at 100% for
// as long as ANY pending hook's target library hasn't loaded yet -- on a
// low-core/thermal-throttled device this starves the scheduler enough that
// even unrelated, already-installed hooks appear to "freeze" (the reported
// "pooling" symptom), and if the script typo'd a library name that never
// loads, the thread spins forever and never gives it back.
//
// Fix: keep the pure busy-spin ONLY for the first short window (the race
// this thread exists to win -- catching the gap between dlopen() returning
// and the very first call into the freshly-loaded library -- is won or
// lost within microseconds, so any sleep at all during that window risks
// missing it). After that window, back off exponentially (usleep, capped),
// and give up entirely after an overall deadline so a bad library name
// can't leak a spinning thread forever.
#define DEFERRED_BUSY_SPIN_ITERS 2000      // pure sched_yield(), no sleep
#define DEFERRED_BACKOFF_START_US 1000     // 1ms
#define DEFERRED_BACKOFF_CAP_US 50000      // 50ms ceiling
#define DEFERRED_TIMEOUT_SECONDS 45        // give up after this long

static void* deferred_poll_thread(void* arg) {
    (void)arg;
    hook_mark_agent_thread();
    LOGI("[deferred] Poll thread started (busy-spin %d iters, then backoff, %ds timeout)",
         DEFERRED_BUSY_SPIN_ITERS, DEFERRED_TIMEOUT_SECONDS);

    struct timespec start_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);

    int iter = 0;
    useconds_t backoff_us = DEFERRED_BACKOFF_START_US;

    while (1) {
        bool all_done = true;
        for (int i = 0; i < g_pending_hook_count; i++) {
            if (g_pending_hooks[i].active) {
                all_done = false;
                break;
            }
        }
        if (all_done) {
            LOGI("[deferred] All pending hooks installed, poll thread exiting");
            return NULL;
        }

        try_install_pending_hooks();

        if (iter < DEFERRED_BUSY_SPIN_ITERS) {
            iter++;
            sched_yield(); // narrow-race window: no sleep yet
        } else {
            struct timespec now_ts;
            clock_gettime(CLOCK_MONOTONIC, &now_ts);
            long elapsed_s = now_ts.tv_sec - start_ts.tv_sec;
            if (elapsed_s >= DEFERRED_TIMEOUT_SECONDS) {
                LOGE("[deferred] Timed out after %ds waiting for pending hook target "
                     "librar(y/ies) to load -- giving up, poll thread exiting "
                     "(check the library name passed to hook())", DEFERRED_TIMEOUT_SECONDS);
                for (int i = 0; i < g_pending_hook_count; i++) {
                    if (g_pending_hooks[i].active) {
                        LOGE("[deferred]   still pending: %s", g_pending_hooks[i].lib_name);
                        g_pending_hooks[i].active = false;
                    }
                }
                return NULL;
            }
            usleep(backoff_us);
            if (backoff_us < DEFERRED_BACKOFF_CAP_US) {
                backoff_us *= 2;
                if (backoff_us > DEFERRED_BACKOFF_CAP_US) backoff_us = DEFERRED_BACKOFF_CAP_US;
            }
        }
    }
}

static void start_deferred_poll(void) {
    if (g_dlopen_hooked) return;
    g_dlopen_hooked = true;

    pthread_t tid;
    pthread_create(&tid, NULL, deferred_poll_thread, NULL);
    pthread_detach(tid);
    LOGI("[deferred] Started library load watcher (busy-wait)");
}

// Event-driven complement to the poll thread above. PLT/GOT-
// hooks dlopen AND android_dlopen_ext (plain C functions, not Lua
// callbacks -- this is agent-internal plumbing, not new Lua API surface)
// across every loaded library's GOT so we get notified the instant either
// one returns, instead of only finding out on the poll thread's next tick.
//
// Both symbols are hooked because live testing on a real device (Android
// 15/API 35) found plain dlopen() is essentially never used for a real
// app's own native library loading -- java.lang.System.load()/loadLibrary()
// go through ART's native loader, which always calls android_dlopen_ext()
// (the linker-namespace-aware variant) instead, specifically because of
// per-APK linker namespace isolation (introduced Android 7+). Hooking only
// dlopen, as this started out, fired zero times across a full passive
// Settings-startup window and zero times for a java.lang.System.load() call
// that DID successfully load a test library -- confirmed via a
// before/after /proc/<pid>/maps diff -- while the poll thread still caught
// it a tick later. android_dlopen_ext is the one that actually matters.
//
// Still not a full replacement for the poll thread: any load path neither
// symbol goes through (there probably isn't one left on this ABI, but
// nothing guarantees that for every OEM/Android version) falls back to it.
//
// This used to hook libdl's public dlopen()/android_dlopen_ext() in
// every library's GOT and call the original FROM HERE. Those two wrappers
// do nothing but capture their own return address and hand it to the
// linker as the "caller", which the linker uses to pick the linker
// NAMESPACE the library is searched in. Called from this function the
// caller became libagent.so, so every namespace-sensitive load in the
// process was looked up in the wrong namespace. Found live on a Mali
// device: with a pending (deferred) hook registered under --pause, the GPU
// driver's android_dlopen_ext("mapper.mediatek.so") resolved wrongly,
// "Failed to locate stable-C mapper library", and RenderThread abort()ed
// inside libGLES_mali.so ~1s after spawn.
//
// Hook one level down instead: the linker entry points libdl.so forwards
// to, which take the caller address as an explicit ARGUMENT. Passing that
// argument through unchanged keeps namespace resolution exactly as it was;
// only libdl.so's own two GOT slots are patched.
static HookInfo g_dlopen_hook_info;
static HookInfo g_dlopen_ext_hook_info;
static bool g_dlopen_event_hook_installed = false;

typedef void* (*loader_dlopen_fn)(const char*, int, const void*);
typedef void* (*loader_dlopen_ext_fn)(const char*, int, const android_dlextinfo*, const void*);

static void* dlopen_event_hook(const char* filename, int flags, const void* caller_addr) {
    // Read the original straight from the hook record: it is published
    // before the GOT slot is rewritten, so there is no window in
    // which this hook is reachable but the original is still unknown.
    loader_dlopen_fn real = (loader_dlopen_fn)g_dlopen_hook_info.data.plt_got.original_funcs[0];
    void* result = real(filename, flags, caller_addr);
    if (result) {
        LOGI("[deferred] dlopen(\"%s\") returned, checking pending hooks (event path)",
             filename ? filename : "(null)");
        // Runs on whatever thread called dlopen() -- the same thread that's
        // about to make the very first call into the newly-loaded library,
        // so this is exactly the race the poll thread exists to win, just
        // won synchronously instead of by polling.
        try_install_pending_hooks_impl(true);
    }
    return result;
}

static void* dlopen_ext_event_hook(const char* filename, int flags, const android_dlextinfo* extinfo,
                                   const void* caller_addr) {
    loader_dlopen_ext_fn real = (loader_dlopen_ext_fn)g_dlopen_ext_hook_info.data.plt_got.original_funcs[0];
    void* result = real(filename, flags, extinfo, caller_addr);
    if (result) {
        LOGI("[deferred] android_dlopen_ext(\"%s\") returned, checking pending hooks (event path)",
             filename ? filename : "(null)");
        try_install_pending_hooks_impl(true);
    }
    return result;
}

static void install_dlopen_event_hook(void) {
    if (g_dlopen_event_hook_installed) return;
    g_dlopen_event_hook_installed = true;

    memset(&g_dlopen_hook_info, 0, sizeof(g_dlopen_hook_info));
    if (install_plt_got_hook_by_name("__loader_dlopen", (void*)dlopen_event_hook,
                                     &g_dlopen_hook_info, "libdl.so") == 0) {
        LOGI("[deferred] dlopen event hook installed, %d GOT entries patched",
             g_dlopen_hook_info.data.plt_got.patched_count);
    } else {
        LOGE("[deferred] Failed to install dlopen event hook -- falling back "
             "to poll-only for plain dlopen");
    }

    memset(&g_dlopen_ext_hook_info, 0, sizeof(g_dlopen_ext_hook_info));
    if (install_plt_got_hook_by_name("__loader_android_dlopen_ext", (void*)dlopen_ext_event_hook,
                                     &g_dlopen_ext_hook_info, "libdl.so") == 0) {
        LOGI("[deferred] android_dlopen_ext event hook installed, %d GOT entries patched",
             g_dlopen_ext_hook_info.data.plt_got.patched_count);
    } else {
        LOGE("[deferred] Failed to install android_dlopen_ext event hook -- "
             "falling back to poll-only for it");
    }
}

static void try_install_pending_hooks_impl(bool from_dlopen_event) {
    if (from_dlopen_event) {
        // The dlopen event path can run while this thread still owns the
        // linker's global lock (a library constructor calling dlopen()
        // from inside an outer dlopen). Installing needs that linker lock
        // too (dl_iterate_phdr), so the poll/script thread takes "install
        // mutex, then linker lock" - blocking here would be the opposite
        // order. Found live: poll thread held the install mutex waiting
        // for the linker lock, this thread held the linker lock waiting
        // for the install mutex, and the app's later
        // System.loadLibrary() never returned. If someone else is
        // installing right now, leave it to them (the poll thread is the
        // documented fallback for every load this path misses).
        pthread_once(&g_hook_install_mutex_once, init_hook_install_mutex);
        if (pthread_mutex_trylock(&g_hook_install_mutex) != 0) {
            return;
        }
    } else {
        hook_install_lock();
    }
    // This runs on arbitrary app threads (event path). Hold the hook
    // reentrancy guard while installing: a hooked function reached from
    // here would otherwise wait for the Lua VM lock while this thread owns
    // the install mutex - the script thread takes those two in the
    // opposite order (VM lock, then hook()).
    int saved_guard = hook_guard_get();
    hook_guard_set(1);
    for (int i = 0; i < g_pending_hook_count; i++) {
        PendingHook* ph = &g_pending_hooks[i];
        if (!ph->active) continue;

        uintptr_t base = (uintptr_t)find_library_base(ph->lib_name);
        if (base == 0) continue;

        LOGI("[deferred] Library %s now loaded at 0x%lx, installing hook at +0x%lx",
             ph->lib_name, base, ph->offset);

        // Install the hook now
        ph->active = false;
        const char* caller = ph->caller_lib[0] ? ph->caller_lib : NULL;
        if (ph->replace_ref != LUA_NOREF) {
            install_lua_replace(ph->lib_name, ph->offset, ph->replace_ref, caller);
        } else {
            install_lua_hook(ph->lib_name, ph->offset,
                            ph->onEnter_ref, ph->onLeave_ref, caller, ph->is_async);
        }
    }
    hook_guard_set(saved_guard);
    hook_install_unlock();
}

static void try_install_pending_hooks(void) {
    try_install_pending_hooks_impl(false);
}

static bool add_pending_hook(const char* lib_name, uintptr_t offset,
                             int onEnter_ref, int onLeave_ref,
                             int replace_ref,
                             const char* caller_lib, bool is_async) {
    if (g_pending_hook_count >= MAX_PENDING_HOOKS) {
        LOGE("[deferred] Maximum pending hooks reached");
        return false;
    }

    PendingHook* ph = &g_pending_hooks[g_pending_hook_count++];
    strncpy(ph->lib_name, lib_name, sizeof(ph->lib_name) - 1);
    ph->offset = offset;
    ph->onEnter_ref = onEnter_ref;
    ph->onLeave_ref = onLeave_ref;
    ph->replace_ref = replace_ref;
    ph->is_async = is_async;
    if (caller_lib) {
        strncpy(ph->caller_lib, caller_lib, sizeof(ph->caller_lib) - 1);
    } else {
        ph->caller_lib[0] = '\0';
    }
    ph->active = true;

    // Try to catch the load event-driven; the poll thread stays on as
    // the fallback either way (see install_dlopen_event_hook's comment).
    install_dlopen_event_hook();
    start_deferred_poll();

    LOGI("[deferred] Pending hook registered: %s+0x%lx (will install on load)",
         lib_name, offset);
    return true;
}

// ============================================================
// Async/fire-and-forget hooks
// ============================================================
//
// Measured before it was optimized: a synchronous onEnter
// hook -- full g_lua_vm_mutex acquisition + a Lua table alloc + pcall --
// costs real, measurable overhead per call that's pure waste for a hook
// that only observes args and never modifies them (the common pentest
// "count/log every call" case). This mode moves that cost off the
// calling thread entirely: hook_logger() just copies 8 registers + a
// timestamp into a bounded ring buffer and returns immediately, letting
// the original function proceed with no added latency from the Lua
// side at all. A single dedicated consumer thread drains the buffer
// periodically and runs the real onEnter callback there, under the
// normal VM lock -- slow Lua code in the callback no longer has any way
// to show up as latency in the hooked function's caller.
//
// Deliberately a bounded SPINLOCK-protected ring, not a from-scratch
// lock-free MPSC queue: multiple hook-firing threads (producers) can
// enqueue concurrently, one consumer thread drains, and the critical
// section under the lock is just a few field copies -- a handful of
// nanoseconds, negligible contention cost even under real concurrency --
// while staying trivially easy to reason about correct, which a hand-
// rolled lock-free ring would not be. This trade favors
// verifiable correctness over the last few nanoseconds.
//
// A full ring drops the new event (counted in g_async_dropped) rather
// than blocking the hot path -- the whole point of "fire-and-forget" is
// that the hooked function's caller never waits on Lua for any reason.
#define ASYNC_RING_SIZE 4096 // must be a power of 2 (wrap via bitmask)

typedef struct {
    int hook_index;
    uint64_t args[8];
    uint64_t timestamp_ns;
} AsyncHookEvent;

static AsyncHookEvent g_async_ring[ASYNC_RING_SIZE];
static volatile int g_async_lock = 0;      // trivial spinlock: 0=free, 1=held
static uint32_t g_async_head = 0;          // next slot to write (producer side, under lock)
static uint32_t g_async_tail = 0;          // next slot to drain (consumer side, under lock)
static uint64_t g_async_dropped = 0;       // ring-full count, under lock (rarely touched)
static uint64_t g_async_dropped_logged = 0; // last value we LOGE'd, to only log on change
static bool g_async_consumer_started = false;
static pthread_mutex_t g_async_start_mutex = PTHREAD_MUTEX_INITIALIZER;

#define ASYNC_DRAIN_BATCH_MAX 256 // bound one consumer tick's local copy + Lua-call time

static inline void async_spin_lock(void) {
    int expected = 0;
    while (!__atomic_compare_exchange_n(&g_async_lock, &expected, 1, false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        expected = 0;
        sched_yield();
    }
}

static inline void async_spin_unlock(void) {
    __atomic_store_n(&g_async_lock, 0, __ATOMIC_RELEASE);
}

// Called from hook_logger() (the hot path) -- must stay as fast as
// possible. No Lua, no libc calls beyond clock_gettime.
static void async_enqueue(int hook_index, uint64_t* regs) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    async_spin_lock();
    uint32_t next_head = (g_async_head + 1) & (ASYNC_RING_SIZE - 1);
    if (next_head == (g_async_tail & (ASYNC_RING_SIZE - 1))) {
        g_async_dropped++;
        async_spin_unlock();
        return;
    }
    AsyncHookEvent* slot = &g_async_ring[g_async_head];
    slot->hook_index = hook_index;
    memcpy(slot->args, regs, sizeof(slot->args));
    slot->timestamp_ns = now_ns;
    g_async_head = next_head;
    async_spin_unlock();
}

static void* async_consumer_thread(void* arg) {
    (void)arg;
    hook_mark_agent_thread();
    LOGI("[async] Consumer thread started");

    AsyncHookEvent batch[ASYNC_DRAIN_BATCH_MAX];

    while (1) {
        int batch_count = 0;

        async_spin_lock();
        while (g_async_tail != g_async_head && batch_count < ASYNC_DRAIN_BATCH_MAX) {
            batch[batch_count++] = g_async_ring[g_async_tail];
            g_async_tail = (g_async_tail + 1) & (ASYNC_RING_SIZE - 1);
        }
        uint64_t dropped_now = g_async_dropped;
        async_spin_unlock();

        if (dropped_now != g_async_dropped_logged) {
            LOGE("[async] Ring buffer full, %llu event(s) dropped so far -- "
                 "consumer can't keep up with this hook's call rate",
                 (unsigned long long)dropped_now);
            g_async_dropped_logged = dropped_now;
        }

        if (batch_count > 0 && g_lua_engine) {
            lua_vm_lock();
            lua_State* L = lua_engine_get_state(g_lua_engine);
            if (L) {
                for (int i = 0; i < batch_count; i++) {
                    AsyncHookEvent* ev = &batch[i];
                    if (ev->hook_index < 0 || ev->hook_index >= g_hook_count) continue;
                    HookInfo* hook = &g_hooks[ev->hook_index];
                    if (hook->lua_onEnter_ref == LUA_NOREF) continue;

                    lua_rawgeti(L, LUA_REGISTRYINDEX, hook->lua_onEnter_ref);
                    lua_newtable(L);
                    for (int a = 0; a < 8; a++) {
                        lua_pushinteger(L, (lua_Integer)ev->args[a]);
                        lua_rawseti(L, -2, a);
                    }
                    if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                        LOGE("[async] onEnter callback failed (hook #%d): %s",
                             ev->hook_index, lua_tostring(L, -1));
                        lua_pop(L, 1);
                    }
                }
            }
            lua_vm_unlock();
        }

        // Fire-and-forget doesn't promise low latency, just "off the hot
        // path" -- a short poll interval is the simplest correct choice
        // here (no condvar/semaphore wake-up plumbing to get wrong).
        usleep(batch_count > 0 ? 1000 : 5000); // 1ms if busy, 5ms if idle
    }
    return NULL;
}

static void start_async_consumer(void) {
    pthread_mutex_lock(&g_async_start_mutex);
    if (!g_async_consumer_started) {
        g_async_consumer_started = true;
        pthread_t tid;
        pthread_create(&tid, NULL, async_consumer_thread, NULL);
        pthread_detach(tid);
    }
    pthread_mutex_unlock(&g_async_start_mutex);
}

// ============================================================

static bool install_lua_hook_unlocked(const char* lib_name, uintptr_t offset, int onEnter_ref, int onLeave_ref, const char* caller_lib, bool is_async) {
    LOGI("Installing Lua hook: %s+0x%lx", lib_name, offset);

    uintptr_t base = (uintptr_t)find_library_base(lib_name);
    if (base == 0) {
        LOGI("Library %s not loaded yet, deferring hook", lib_name);
        return add_pending_hook(lib_name, offset, onEnter_ref, onLeave_ref, LUA_NOREF, caller_lib, is_async);
    }

    uintptr_t target_addr = base + offset;
    LOGI("Hook target address: 0x%lx", target_addr);

    if (g_hook_count >= MAX_HOOKS) {
        LOGE("Maximum hooks reached");
        return false;
    }

    int hook_index = g_hook_count;
    HookInfo* hook_info = &g_hooks[hook_index];
    hook_info->lua_onEnter_ref = onEnter_ref;
    hook_info->lua_onLeave_ref = onLeave_ref;
    hook_info->lua_replace_ref = LUA_NOREF;
    hook_info->is_replace = 0;
    hook_info->is_async = is_async ? 1 : 0;
    hook_info->hook_index = hook_index;
    hook_info->logical_target_addr = (void*)target_addr;
    hook_info->hits = 0;

    if (is_async) {
        start_async_consumer();
    }

    void* thunk = create_hook_thunk(hook_index);
    if (!thunk) {
        LOGE("Failed to create hook thunk");
        return false;
    }
    hook_info->thunk_addr = thunk;

    int result = -1;
    if (caller_lib && strlen(caller_lib) > 0) {
        LOGI("Using PLT/GOT hooking method (caller: %s)", caller_lib);
        result = install_plt_got_hook((void*)target_addr, thunk, hook_info, caller_lib);
    } else {
        LOGI("Using trampoline hooking method");
        result = install_trampoline_hook((void*)target_addr, thunk, hook_info);
    }

    if (result != 0) {
        LOGE("Failed to install hook");
        munmap(thunk, PAGE_SIZE);
        return false;
    }

    g_hook_count++;

    LOGI("Lua hook #%d installed (type=%s, onEnter=%d, onLeave=%d, async=%d)",
         hook_index,
         (caller_lib && strlen(caller_lib) > 0) ? "PLT/GOT" : "Trampoline",
         onEnter_ref, onLeave_ref, hook_info->is_async);
    return true;
}

// Interceptor.replace: install a hook that runs `replace_ref` INSTEAD of the
// original. Mirrors install_lua_hook but marks the slot as a replace hook and
// leaves onEnter/onLeave unset. The callback's return value becomes the call's
// return; the original can still be reached via NativeFunction(addr) (reentrant).
static bool install_lua_replace_unlocked(const char* lib_name, uintptr_t offset, int replace_ref, const char* caller_lib) {
    LOGI("Installing Lua replace: %s+0x%lx", lib_name, offset);

    uintptr_t base = (uintptr_t)find_library_base(lib_name);
    if (base == 0) {
        LOGI("Library %s not loaded yet, deferring replace", lib_name);
        // Async never applies to replace hooks (the callback's
        // return value becomes the call's result -- there's no way to be
        // "fire and forget" about that).
        return add_pending_hook(lib_name, offset, LUA_NOREF, LUA_NOREF, replace_ref, caller_lib, false);
    }

    uintptr_t target_addr = base + offset;
    LOGI("Replace target address: 0x%lx", target_addr);

    if (g_hook_count >= MAX_HOOKS) {
        LOGE("Maximum hooks reached");
        return false;
    }

    int hook_index = g_hook_count;
    HookInfo* hook_info = &g_hooks[hook_index];
    hook_info->lua_onEnter_ref = LUA_NOREF;
    hook_info->lua_onLeave_ref = LUA_NOREF;
    hook_info->lua_replace_ref = replace_ref;
    hook_info->is_replace = 1;
    hook_info->hook_index = hook_index;
    hook_info->logical_target_addr = (void*)target_addr;
    hook_info->hits = 0;

    void* thunk = create_hook_thunk(hook_index);
    if (!thunk) {
        LOGE("Failed to create hook thunk");
        return false;
    }
    hook_info->thunk_addr = thunk;

    int result = -1;
    if (caller_lib && strlen(caller_lib) > 0) {
        result = install_plt_got_hook((void*)target_addr, thunk, hook_info, caller_lib);
    } else {
        result = install_trampoline_hook((void*)target_addr, thunk, hook_info);
    }

    if (result != 0) {
        LOGE("Failed to install replace hook");
        munmap(thunk, PAGE_SIZE);
        return false;
    }

    g_hook_count++;
    LOGI("Lua replace #%d installed (replace_ref=%d)", hook_index, replace_ref);
    return true;
}

// Public entry points: serialised against the deferred poll thread and the
// dlopen event path (see g_hook_install_mutex).
bool install_lua_hook(const char* lib_name, uintptr_t offset, int onEnter_ref, int onLeave_ref, const char* caller_lib, bool is_async) {
    hook_install_lock();
    bool ok = install_lua_hook_unlocked(lib_name, offset, onEnter_ref, onLeave_ref, caller_lib, is_async);
    hook_install_unlock();
    return ok;
}

bool install_lua_replace(const char* lib_name, uintptr_t offset, int replace_ref, const char* caller_lib) {
    hook_install_lock();
    bool ok = install_lua_replace_unlocked(lib_name, offset, replace_ref, caller_lib);
    hook_install_unlock();
    return ok;
}

// Check reentrancy and return trampoline address for bypass.
// Returns NULL if not reentrant (normal path), or trampoline addr to skip handler.
// Address the handler must call to run the ORIGINAL function of hook
// `hook_index`. Takes the index explicitly (it lives in the handler's own
// stack frame) instead of reading the thread-local g_current_hook_index:
// that TLS value belongs to the OUTERMOST hook currently being processed
// on this thread and must not be consulted or overwritten for a nested one.
void* get_hook_trampoline(int hook_index) {
    if (hook_index < 0 || hook_index >= MAX_HOOKS) {
        return NULL;
    }
    HookInfo* hook = &g_hooks[hook_index];

    if (hook->type == HOOK_TRAMPOLINE) {
        return hook->data.trampoline.trampoline_addr;
    } else if (hook->type == HOOK_PLT_GOT) {
        // Not gated on patched_count: original_funcs[0] is published before
        // the first GOT slot is patched and stays valid after uninstall,
        // for threads that are still inside the hook at that moment.
        return hook->data.plt_got.original_funcs[0];
    }
    return NULL;
}

// --- "Calls made by the agent itself are never hooked" ---
//
// libagent.so (the agent glue, the statically linked Lua VM, Capstone,
// compiler-rt's __emutls_get_address, ...) calls plenty of libc itself:
// malloc/realloc/free, memcpy, strlen, pthread_mutex_lock,
// pthread_getspecific, write, ... If the user hooks one of those, the
// agent's OWN calls used to enter the hook handler too. Two consequences,
// both found live while bulk-hooking libc exports:
//   - Unbounded recursion -> "stack pointer is not in a rw map" SIGSEGV:
//     the handler's very first step reads a `__thread` variable, which on
//     Android is emulated TLS (__emutls_get_address -> pthread_getspecific
//     / malloc). With one of those hooked, reading the reentrancy guard
//     re-entered the handler before the guard could be consulted.
//   - Lua VM re-entered from the middle of its own internals (e.g. its
//     allocator calling a hooked realloc), i.e. callbacks running on a VM
//     that is not at a safe point.
// The fix does not depend on any libc/TLS service: a call whose RETURN
// ADDRESS lies inside libagent.so's own executable segment is forwarded
// straight to the original function. The only exceptions are the two call
// sites NativeFunction uses (native_call8 / native_call_ext): a script
// calling a hooked function through NativeFunction is an explicit request
// to exercise the hook, and it happens at a safe lua_CFunction boundary.
static uintptr_t g_agent_text_start = 0;
static uintptr_t g_agent_text_end = 0;

extern const char native_call8_ret[] __attribute__((visibility("hidden")));
extern const char native_call_ext_ret[] __attribute__((visibility("hidden")));

static int agent_text_range_cb(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size; (void)data;
    uintptr_t self = (uintptr_t)&generic_hook_handler;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr)* ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X)) continue;
        uintptr_t start = (uintptr_t)info->dlpi_addr + ph->p_vaddr;
        uintptr_t end = start + ph->p_memsz;
        if (self >= start && self < end) {
            g_agent_text_start = start;
            g_agent_text_end = end;
            return 1;
        }
    }
    return 0;
}

// Must have run before the first thunk becomes reachable (create_hook_thunk
// calls it), so the handler never observes a half-initialised range.
static void init_agent_text_range(void) {
    if (g_agent_text_end != 0) return;
    dl_iterate_phdr(agent_text_range_cb, NULL);
    if (g_agent_text_end == 0) {
        LOGE("Could not determine libagent.so's own text range; "
             "agent-originated calls will not be excluded from hooks");
    } else {
        LOGI("Agent text range: %p-%p", (void*)g_agent_text_start, (void*)g_agent_text_end);
    }
}

// --- "The agent's own Lua execution is never hooked either" ---
//
// The return-address test above only covers libc functions libagent.so
// calls DIRECTLY. Lua/agent internals also reach hooked functions
// INDIRECTLY, with libc as the immediate caller (found live: every
// tostring(i) -> snprintf -> bionic vfprintf -> free(): with free() hooked,
// the hook's Lua callback ran on the very VM that was in the middle of
// formatting a number - 20000 times in a 20000-iteration loop). A Lua VM
// may only be re-entered at a lua_CFunction boundary, never from inside
// its own internals.
//
// So: while a thread holds the Lua VM lock outside of a native hook
// handler (running a script / exec / rpc, a Java-hook callback, the async
// consumer, ...), the reentrancy guard is held and every hooked function it
// reaches is bypassed. The guard is lifted only for the explicit outbound
// calls a script makes into the target - NativeFunction and Java method
// invocations (hook_outcall_begin/end) - because there the user IS asking
// to run target code, hooks included, and those are safe lua_CFunction
// boundaries.
#define g_agent_lua_depth (hook_thread_state()->agent_lua_depth)
#define g_agent_lua_saved (hook_thread_state()->agent_lua_saved)
#define g_hook_handler_depth (hook_thread_state()->handler_depth)

void hook_agent_lua_enter(void) {
    // Guard first, thread-locals second (see the note on the guard table).
    int prev = hook_guard_get();
    hook_guard_set(1);
    if (g_agent_lua_depth++ == 0) {
        g_agent_lua_saved = prev;
    }
}

void hook_agent_lua_leave(void) {
    if (g_agent_lua_depth > 0 && --g_agent_lua_depth == 0) {
        hook_guard_set(g_agent_lua_saved);
    }
}

// Threads the agent itself creates (command/script handler, output writer,
// deferred-hook poller, async consumer) hold the guard for their whole
// lifetime. Found live: with pthread_mutex_unlock() hooked, the output
// writer thread's pthread_cond_wait() -> (libc-internal) pthread_mutex_unlock
// entered the hook while still owning the output-queue mutex and then
// waited for the Lua VM lock; the script thread, which held the VM lock,
// was waiting for that same queue mutex in print() -> a permanent deadlock.
// Agent threads never need to observe hooks on their own housekeeping; the
// outcall window below still lets a script's explicit calls trigger them.
void hook_mark_agent_thread(void) {
    hook_guard_set(1);
    g_agent_lua_saved = 1;
}

// Outbound call from a script into the target. Inside a native hook's own
// callback the guard must STAY held: that is what makes calling the hooked
// address from its callback reach the original function instead of
// recursing into the hook (the Interceptor.replace "call original" idiom).
int hook_outcall_begin(void) {
    int prev = hook_guard_get();
    // g_hook_handler_depth is a __thread variable: only read it while the
    // guard is held, and lift the guard as the very last step.
    hook_guard_set(1);
    int in_handler = (g_hook_handler_depth != 0);
    hook_guard_set(in_handler ? prev : 0);
    return prev;
}

void hook_outcall_end(int prev) {
    hook_guard_set(prev);
}

void* check_hook_reentrant(int hook_index, uintptr_t caller_lr) {
    // Agent-originated call: bypass WITHOUT touching any thread-local state
    // (see the block comment above - reading TLS here is what recursed).
    if (caller_lr >= g_agent_text_start && caller_lr < g_agent_text_end &&
        caller_lr != (uintptr_t)native_call8_ret &&
        caller_lr != (uintptr_t)native_call_ext_ret) {
        return get_hook_trampoline(hook_index);
    }

    HookGuardSlot* guard = hook_guard_slot();
    if (guard == NULL || guard->flag) {
        // Reentrant: return trampoline so handler can be bypassed.
        //
        // This used to do `g_current_hook_index = hook_index`
        // first. That clobbered the index of the OUTER hook still being
        // processed on this thread (its onEnter callback, or its original
        // function, is what made this nested call), so the outer handler
        // went on to call the NESTED hook's trampoline with its own
        // arguments and to fire the nested hook's onLeave instead of its
        // own. The bypass never needed the TLS value in the first place.
        return get_hook_trampoline(hook_index);
    }
    guard->flag = 1;
    g_hook_handler_depth++;
    return NULL;
}

// Frame layout (416 bytes below the x29/x30 frame record):
//   [sp+0   .. sp+128)  q0-q7   FP/SIMD argument registers, later reused
//                               for the FP/SIMD result registers q0-q3
//   [sp+128 .. sp+360)  x0-x28  == `saved_regs` handed to hook_logger()
//                               (so saved_regs[36]/[37] are still the
//                               frame record: caller's x29/x30)
//   [sp+384]  hook index (x17 from the thunk)
//   [sp+392]  trampoline address
//   [sp+400]  integer result (x0)
//   [sp+408]  second integer result word (x1)
//
// q0-q7 and x1 were not preserved at all. The C code this
// handler calls (hook_logger, the Lua VM, log_return_value) uses FP/SIMD
// registers freely, so a hooked function received garbage in its float/
// double arguments (found live: ldexp(1.5, 4) returned 0.0 instead of 24.0
// once hooked) and callers of functions returning float/double or a
// 16-byte value could get a clobbered result.
__attribute__((naked)) void generic_hook_handler(void) {
    __asm__ __volatile__(
        "stp x29, x30, [sp, #-16]!\n"
        "mov x29, sp\n"
        "sub sp, sp, #416\n"

        // Save FP/SIMD argument registers and all integer regs FIRST
        // (before any C call)
        "stp q0, q1, [sp, #0]\n"
        "stp q2, q3, [sp, #32]\n"
        "stp q4, q5, [sp, #64]\n"
        "stp q6, q7, [sp, #96]\n"

        "str x17, [sp, #384]\n"

        "stp x0, x1, [sp, #128]\n"
        "stp x2, x3, [sp, #144]\n"
        "stp x4, x5, [sp, #160]\n"
        "stp x6, x7, [sp, #176]\n"
        "stp x8, x9, [sp, #192]\n"
        "stp x10, x11, [sp, #208]\n"
        "stp x12, x13, [sp, #224]\n"
        "stp x14, x15, [sp, #240]\n"
        "stp x16, x17, [sp, #256]\n"
        "stp x18, x19, [sp, #272]\n"
        "stp x20, x21, [sp, #288]\n"
        "stp x22, x23, [sp, #304]\n"
        "stp x24, x25, [sp, #320]\n"
        "stp x26, x27, [sp, #336]\n"
        "stp x28, xzr, [sp, #352]\n"

        // Check reentrancy BEFORE any logging
        "ldr x0, [sp, #384]\n"       // x0 = hook_index
        "ldr x1, [sp, #424]\n"       // x1 = caller's return address (x30 saved at entry)
        "bl check_hook_reentrant\n"
        "cbnz x0, .Lreentrant_bypass\n" // if non-NULL, skip handler

        // Normal path: run hook handler
        "ldr x0, [sp, #384]\n"
        "bl set_current_hook_index\n"

        "add x0, sp, #128\n"         // saved_regs
        "bl hook_logger\n"
        "cbnz x0, .Lskip_original\n"   // replace mode: don't call the original

        // Resolve the trampoline from the hook index kept
        // in THIS frame, not from thread-local state.
        "ldr x0, [sp, #384]\n"
        "bl get_hook_trampoline\n"
        "str x0, [sp, #392]\n"

        // Arguments exactly as the caller passed them (onEnter may have
        // rewritten the integer ones in saved_regs).
        "ldp q0, q1, [sp, #0]\n"
        "ldp q2, q3, [sp, #32]\n"
        "ldp q4, q5, [sp, #64]\n"
        "ldp q6, q7, [sp, #96]\n"
        "ldp x0, x1, [sp, #128]\n"
        "ldp x2, x3, [sp, #144]\n"
        "ldp x4, x5, [sp, #160]\n"
        "ldp x6, x7, [sp, #176]\n"
        "ldp x8, x9, [sp, #192]\n"

        "ldr x16, [sp, #392]\n"

        "blr x16\n"
        "b .Lafter_original\n"

        ".Lskip_original:\n"
        "bl get_replace_retval\n"      // x0 = value returned by the replace cb

        ".Lafter_original:\n"
        // Keep every result register across onLeave: x0 (may be replaced
        // by onLeave), x1 (second word of a 16-byte result), q0-q3.
        "stp q0, q1, [sp, #0]\n"
        "stp q2, q3, [sp, #32]\n"
        "str x1, [sp, #408]\n"
        // Re-assert this frame's hook index before onLeave
        // runs, so it can never fire a different hook's callback.
        "str x0, [sp, #400]\n"
        "ldr x0, [sp, #384]\n"
        "bl set_current_hook_index\n"
        "ldr x0, [sp, #400]\n"
        "bl log_return_value\n"        // returns the (possibly replaced) x0

        "ldr x1, [sp, #408]\n"
        "ldp q0, q1, [sp, #0]\n"
        "ldp q2, q3, [sp, #32]\n"

        "add sp, sp, #416\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n"

        // Reentrant bypass: skip handler, go straight to trampoline
        ".Lreentrant_bypass:\n"
        "str x0, [sp, #392]\n"       // store trampoline addr

        "ldp q0, q1, [sp, #0]\n"
        "ldp q2, q3, [sp, #32]\n"
        "ldp q4, q5, [sp, #64]\n"
        "ldp q6, q7, [sp, #96]\n"
        "ldp x0, x1, [sp, #128]\n"
        "ldp x2, x3, [sp, #144]\n"
        "ldp x4, x5, [sp, #160]\n"
        "ldp x6, x7, [sp, #176]\n"
        "ldp x8, x9, [sp, #192]\n"

        "ldr x16, [sp, #392]\n"

        "add sp, sp, #416\n"
        "ldp x29, x30, [sp], #16\n"
        "br x16\n"                    // tail-call trampoline (no blr — don't return here)
    );
}

void set_current_hook_index(int index) {
    hook_thread_state()->cur_hook_plus1 = index + 1;
}

// hook_logger()/log_return_value() run on
// EVERY hook invocation, on WHATEVER thread calls the hooked function -
// including short-stack system/binder worker threads already deep into
// their own call chain. Even after trimming verbose_log()'s own local
// buffer, a THREAD with little stack left can still overflow just from
// the call overhead of reaching it (confirmed via two separate
// tombstones: one inside verbose_log's old local buffer, one inside
// __android_log_vprint's OWN internal property-lookup call chain once
// that buffer was removed - "stack pointer is not in a rw map; likely
// due to stack overflow" either way). These calls are debug-only
// (print-on-every-call tracing) and provide no runtime behavior - skip
// the call entirely (not just the formatting inside verbose_log) when
// verbose mode is off, so this hot path doesn't touch the logging
// machinery's stack footprint at all in the common case.
#define VLOG(...) do { if (g_verbose_mode) verbose_log(__VA_ARGS__); } while (0)

// --- Bounded wait for the Lua VM in native hook callbacks ---
//
// A hooked function can be called while its caller holds a lock the Lua
// side needs as well. Found live with a hook on syscall(): bionic issues
// every futex wait through it, including scudo's, so a thread inside
// malloc() - holding an allocator lock - entered the hook and waited for
// the Lua VM, while the thread that owned the VM was in a callback waiting
// for that same allocator lock to allocate a Lua object. Neither could
// proceed; the app froze. The same applies to anything libc calls inside a
// critical section (mmap/munmap/madvise from the allocator, ...).
//
// There is no way to see that from here, so a callback never waits for the
// VM without a bound. If the VM is not available in time the callback is
// skipped for THIS call and the original function runs untouched - which
// is what releases the other lock and lets the VM owner continue. Skips
// are counted and reported; for functions like these the async hook mode
// (no VM lock on the calling thread) is the right tool.
#define HOOK_CALLBACK_LOCK_TIMEOUT_MS 500

static volatile unsigned long g_hook_cb_skipped = 0;
static volatile long g_hook_cb_skip_reported_at = 0;

static bool hook_callback_lock(void) {
    if (lua_vm_lock_timed(HOOK_CALLBACK_LOCK_TIMEOUT_MS)) {
        return true;
    }

    unsigned long total = __atomic_add_fetch(&g_hook_cb_skipped, 1, __ATOMIC_RELAXED);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long last = __atomic_load_n(&g_hook_cb_skip_reported_at, __ATOMIC_RELAXED);
    if (now.tv_sec - last >= 2 &&
        __atomic_compare_exchange_n(&g_hook_cb_skip_reported_at, &last, (long)now.tv_sec, false,
                                    __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        char msg[256];
        int n = snprintf(msg, sizeof(msg),
                         "[renef] %lu hook callback(s) skipped: Lua VM busy for >%dms "
                         "(hooked function is called under a lock the script also needs; "
                         "use an async hook for it)\n",
                         total, HOOK_CALLBACK_LOCK_TIMEOUT_MS);
        if (n > 0) {
            LOGW("%s", msg);
            output_queue_push(msg, (size_t)n);
        }
    }
    return false;
}

int hook_logger(uint64_t* saved_regs) {
    uint64_t x0 = saved_regs[0];
    uint64_t x1 = saved_regs[1];
    uint64_t x2 = saved_regs[2];
    uint64_t x3 = saved_regs[3];
    uint64_t x4 = saved_regs[4];
    uint64_t x5 = saved_regs[5];
    uint64_t x6 = saved_regs[6];
    uint64_t x7 = saved_regs[7];

    if (x0 != 0) {
        g_hook_call_jni_env = (JNIEnv*)x0;
    }

    VLOG("=== HOOK #%d: Function Called ===", g_current_hook_index);
    VLOG("  x0-x3: 0x%llx 0x%llx 0x%llx 0x%llx",
         (unsigned long long)x0, (unsigned long long)x1,
         (unsigned long long)x2, (unsigned long long)x3);

    VLOG("  [DEBUG] g_lua_engine=%p, hook_index=%d", g_lua_engine, g_current_hook_index);

    g_hook_caller_fp = saved_regs[36];
    g_hook_caller_lr = saved_regs[37];

    if (g_current_hook_index >= 0 && g_lua_engine) {
        HookInfo* hook = &g_hooks[g_current_hook_index];

        __atomic_add_fetch(&hook->hits, 1, __ATOMIC_RELAXED);

        // Interceptor.replace: run the replacement callback with the args and
        // use its return value; the original function is NOT called (the asm
        // handler skips the trampoline when we return 1). The callback may still
        // invoke the original itself via NativeFunction(addr) — that re-enters
        // the hook and the reentrancy guard runs the original.
        if (hook->is_replace && hook->lua_replace_ref != LUA_NOREF && hook_callback_lock()) {
            uint64_t rv = 0;
            lua_State* L = lua_engine_get_state(g_lua_engine);
            if (L) {
                lua_rawgeti(L, LUA_REGISTRYINDEX, hook->lua_replace_ref);
                lua_newtable(L);
                uint64_t params[] = {x0, x1, x2, x3, x4, x5, x6, x7};
                for (int i = 0; i < 8; i++) {
                    lua_pushinteger(L, params[i]);
                    lua_rawseti(L, -2, i);
                }
                if (lua_pcall(L, 1, 1, 0) == LUA_OK) {
                    if (lua_isinteger(L, -1) || lua_isnumber(L, -1)) {
                        rv = (uint64_t)lua_tointeger(L, -1);
                    } else if (lua_isboolean(L, -1)) {
                        rv = lua_toboolean(L, -1) ? 1 : 0;
                    }
                    // nil / other -> rv stays 0
                    lua_pop(L, 1);
                } else {
                    LOGE("replace callback failed: %s", lua_tostring(L, -1));
                    lua_pop(L, 1);
                }
            }
            lua_vm_unlock();
            g_replace_retval = rv;
            g_hook_caller_fp = 0;
            g_hook_caller_lr = 0;
            return 1;  // tell the handler to skip the original
        }

        VLOG("  [DEBUG] onEnter_ref=%d (NOREF=%d)", hook->lua_onEnter_ref, LUA_NOREF);

        // Fire-and-forget path. Skips g_lua_vm_mutex and the
        // Lua call entirely on this (the hooked function's calling) thread --
        // async_enqueue() is just a few field copies under a short spinlock.
        // The real onEnter call happens later, on async_consumer_thread.
        if (hook->is_async && hook->lua_onEnter_ref != LUA_NOREF) {
            async_enqueue(g_current_hook_index, saved_regs);
            g_hook_caller_fp = 0;
            g_hook_caller_lr = 0;
            return 0; // normal path: call the original, no Lua involved here
        }

        if (hook->lua_onEnter_ref != LUA_NOREF && hook_callback_lock()) {
            lua_State* L = lua_engine_get_state(g_lua_engine);
            VLOG("  [DEBUG] lua_State=%p", L);
            if (L) {
                lua_rawgeti(L, LUA_REGISTRYINDEX, hook->lua_onEnter_ref);
                lua_newtable(L);

                uint64_t params[] = {x0, x1, x2, x3, x4, x5, x6, x7};

                for (int i = 0; i < 8; i++) {
                    lua_pushinteger(L, params[i]);
                    lua_rawseti(L, -2, i);
                }

                lua_pushvalue(L, -1);
                int args_ref = luaL_ref(L, LUA_REGISTRYINDEX);

                VLOG("  [DEBUG] Calling lua_pcall...");
                if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                    LOGE("onEnter callback failed: %s", lua_tostring(L, -1));
                    lua_pop(L, 1);
                } else {
                    VLOG("  [DEBUG] lua_pcall succeeded");

                    lua_rawgeti(L, LUA_REGISTRYINDEX, args_ref);
                    for (int i = 0; i < 8; i++) {
                        lua_rawgeti(L, -1, i);
                        if (lua_isinteger(L, -1)) {
                            uint64_t new_val = (uint64_t)lua_tointeger(L, -1);
                            if (new_val != saved_regs[i]) {
                                VLOG("  Arg %d modified: 0x%llx -> 0x%llx", i,
                                    (unsigned long long)saved_regs[i], (unsigned long long)new_val);
                                saved_regs[i] = new_val;
                            }
                        }
                        lua_pop(L, 1);
                    }
                    lua_pop(L, 1);
                }

                luaL_unref(L, LUA_REGISTRYINDEX, args_ref);
            }
            lua_vm_unlock();
        }
    } else {
        VLOG("  [DEBUG] Skipped: engine=%p, index=%d", g_lua_engine, g_current_hook_index);
    }

    g_hook_caller_fp = 0;
    g_hook_caller_lr = 0;
    // Note: don't reset the reentrancy guard here — log_return_value still needs it
    return 0;  // normal path: call the original
}

uint64_t log_return_value(uint64_t ret_val) {
    VLOG("=== HOOK: Function Returned ===");
    VLOG("  x0 (return): 0x%llx (%lld)", (unsigned long long)ret_val, (long long)ret_val);

    uintptr_t my_fp;
    __asm__ volatile("mov %0, x29" : "=r"(my_fp));
    uintptr_t handler_fp = *(uintptr_t*)my_fp;
    g_hook_caller_fp = *(uintptr_t*)handler_fp;
    g_hook_caller_lr = *(uintptr_t*)(handler_fp + 8);

    if (g_current_hook_index >= 0 && g_lua_engine) {
        HookInfo* hook = &g_hooks[g_current_hook_index];

        if (hook->lua_onLeave_ref != LUA_NOREF && hook_callback_lock()) {
            lua_State* L = lua_engine_get_state(g_lua_engine);
            if (L) {
                lua_rawgeti(L, LUA_REGISTRYINDEX, hook->lua_onLeave_ref);
                lua_pushinteger(L, ret_val);

                if (lua_pcall(L, 1, 1, 0) == LUA_OK) {
                    if (lua_isnil(L, -1)) {
                    } else if (lua_istable(L, -1)) {
                        lua_getfield(L, -1, "__jni_type");
                        if (lua_isstring(L, -1)) {
                            const char* jni_type = lua_tostring(L, -1);
                            lua_pop(L, 1);
                            lua_getfield(L, -1, "value");

                            if (strcmp(jni_type, "string") == 0 && lua_isstring(L, -1)) {
                                const char* str_value = lua_tostring(L, -1);
                                if (g_hook_call_jni_env && str_value) {
                                    jstring new_str = (*g_hook_call_jni_env)->NewStringUTF(g_hook_call_jni_env, str_value);
                                    ret_val = (uint64_t)new_str;
                                    VLOG("  Modified to jstring: \"%s\"", str_value);
                                }
                            } else if (strcmp(jni_type, "int") == 0 || strcmp(jni_type, "long") == 0) {
                                ret_val = (uint64_t)lua_tointeger(L, -1);
                                VLOG("  Modified to %s: %lld", jni_type, (long long)ret_val);
                            } else if (strcmp(jni_type, "boolean") == 0) {
                                ret_val = lua_toboolean(L, -1) ? 1 : 0;
                                VLOG("  Modified to boolean: %s", ret_val ? "true" : "false");
                            }
                            lua_pop(L, 1);
                        } else {
                            lua_pop(L, 1);
                        }
                    } else if (lua_isinteger(L, -1) || lua_isnumber(L, -1)) {
                        ret_val = (uint64_t)lua_tointeger(L, -1);
                        VLOG("  Modified to: 0x%llx", (unsigned long long)ret_val);
                    }
                    lua_pop(L, 1);
                } else {
                    LOGE("onLeave callback failed: %s", lua_tostring(L, -1));
                    lua_pop(L, 1);
                }
            }
            lua_vm_unlock();
        }
    }

    g_hook_caller_fp = 0;
    g_hook_caller_lr = 0;
    if (g_hook_handler_depth > 0) g_hook_handler_depth--;
    hook_guard_set(0);  // Reset guard at the very end of hook processing
    return ret_val;
}

void* get_current_trampoline(void) {
    if (g_current_hook_index >= 0) {
        return get_hook_trampoline(g_current_hook_index);
    }
    return NULL;
}

// Invoke a native function from C/Lua with up to 8 integer/pointer args.
// AAPCS64: on entry x0=fn, x1=args. We stash them in x9/x10 before clobbering
// x0-x7 with the argument array, then branch. The callee's return (x0) survives
// the epilogue untouched. Args beyond 8 and floating-point regs are not handled.
__attribute__((naked)) uint64_t native_call8(void* fn, uint64_t* args) {
    __asm__ __volatile__(
        "stp x29, x30, [sp, #-16]!\n"
        "mov x29, sp\n"
        "mov x9, x0\n"                 // x9  = fn
        "mov x10, x1\n"                // x10 = args
        "ldp x0, x1, [x10, #0]\n"
        "ldp x2, x3, [x10, #16]\n"
        "ldp x4, x5, [x10, #32]\n"
        "ldp x6, x7, [x10, #48]\n"
        "blr x9\n"
        // Return site whitelisted in check_hook_reentrant(): a hooked
        // function called from here (a script's NativeFunction call) must
        // still run its hook, unlike every other call made by libagent.so.
        ".globl native_call8_ret\n"
        ".hidden native_call8_ret\n"
        "native_call8_ret:\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n"
    );
}

// Same idea as native_call8, extended
// with the AAPCS64 floating-point register file (d0-d7), which ARM64
// counts completely independently from x0-x7 -- a float/double argument
// never consumes an integer register slot and vice versa, so the two
// argument arrays are filled by the caller according to each argument's
// DECLARED type, not its position. `fret_out` always receives the
// callee's d0 on return, whether or not the call actually returns a
// float/double -- harmless when it doesn't (the real integer/pointer
// result is still x0, returned normally), and lets the Lua side read a
// float or double result without a second call variant.
//
// A `float` argument/return occupies only the low 32 bits of its D
// register slot per AAPCS64 (upper 32 bits unspecified) -- the caller
// (native_function_call, api_hook.c) is responsible for writing/reading
// just those 4 bytes for "float" vs. the full 8 for "double".
//
// Still unsupported, same as v1 and not attempted here: more than 8
// integer or more than 8 float/double arguments (the AAPCS64 stack-
// passing case) and struct-by-value args/returns.
__attribute__((naked)) uint64_t native_call_ext(void* fn, uint64_t* iargs, double* fargs, double* fret_out) {
    __asm__ __volatile__(
        // 32 bytes: 16 for the saved frame, 16 for fret_out (needs a slot
        // that survives the call -- x9-x15 are AAPCS64 caller-saved/
        // temporary, so stashing fret_out in x12 across `blr` is NOT safe:
        // the callee (sinf/pow/whatever) is free to clobber it, and on a
        // real device this crashed with a SIGSEGV writing through
        // whatever garbage the callee left in x12. Round-tripping through
        // the stack instead, like x29/x30, is the correct fix.
        "stp x29, x30, [sp, #-32]!\n"
        "mov x29, sp\n"
        "mov x9, x0\n"                 // x9  = fn
        "mov x10, x1\n"                // x10 = iargs
        "mov x11, x2\n"                // x11 = fargs
        "str x3, [sp, #16]\n"          // fret_out, parked across the call
        "ldp x0, x1, [x10, #0]\n"
        "ldp x2, x3, [x10, #16]\n"
        "ldp x4, x5, [x10, #32]\n"
        "ldp x6, x7, [x10, #48]\n"
        "ldp d0, d1, [x11, #0]\n"
        "ldp d2, d3, [x11, #16]\n"
        "ldp d4, d5, [x11, #32]\n"
        "ldp d6, d7, [x11, #48]\n"
        "blr x9\n"
        // Whitelisted return site, see native_call8_ret / check_hook_reentrant().
        ".globl native_call_ext_ret\n"
        ".hidden native_call_ext_ret\n"
        "native_call_ext_ret:\n"
        "ldr x12, [sp, #16]\n"         // reload fret_out -- do NOT trust it survived in a register
        "str d0, [x12]\n"
        "ldp x29, x30, [sp], #32\n"
        "ret\n"
    );
}

bool install_lua_java_hook(const char* class_name, const char* method_name,
                           const char* signature, int onEnter_ref, int onLeave_ref) {
    if (!g_current_jni_env) {
        LOGE("JNIEnv not available for Java hook");
        return false;
    }

    int result = install_java_hook(g_current_jni_env,
                                   class_name,
                                   method_name,
                                   signature,
                                   onEnter_ref,
                                   onLeave_ref);
    return result >= 0;
}
