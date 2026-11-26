#include <stdarg.h>
#include <time.h>
#include <agent/output_queue.h>
#include <agent/hook_java.h>
#include <agent/globals.h>
#include <agent/agent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <elf.h>
#include <fcntl.h>

// Not in the NDK's elf.h; standard GNU extension tag, same value on every
// toolchain (glibc, bionic, LLVM, binutils).
#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef5
#endif

JavaHookInfo g_java_hooks[MAX_JAVA_HOOKS];
int g_java_hook_count = 0;

static int g_api_level = 0;
static ArtMethodOffsets g_offsets = {0};
static bool g_java_hook_initialized = false;
static pthread_mutex_t g_java_hook_mutex = PTHREAD_MUTEX_INITIALIZER;

// Java onEnter/onLeave callbacks below take the process-wide recursive
// g_lua_vm_mutex (lua_vm_lock/lua_vm_unlock, globals.h) instead of a private
// mutex. This used to be a separate g_java_lua_mutex, distinct from native.c's
// own g_lua_mutex and unrelated to the (previously unlocked) script-exec path
// in engine.c — three locks/non-locks guarding one shared lua_State. Sharing
// one recursive lock here closes that gap and keeps supporting nested hook
// callbacks (parent calling child) on the same thread.

// Thread-local hook call stack for tracking nested calls
#define MAX_HOOK_CALL_DEPTH 16
typedef struct {
    int hook_indices[MAX_HOOK_CALL_DEPTH];
    int depth;
} HookCallStack;

static __thread HookCallStack g_hook_call_stack = {{0}, 0};

static __thread int g_current_java_hook_index = -1;

static void* g_interpreter_bridge = NULL;

static uint64_t nativized_method_stub(void) {
    int hook_index = g_current_java_hook_index;
    if (hook_index >= 0 && hook_index < g_java_hook_count) {
        JavaHookInfo* hook = &g_java_hooks[hook_index];
        if (hook->has_stored_return) {
            LOGI("nativized_method_stub returning stored value: 0x%llx",
                 (unsigned long long)hook->stored_return_value);
            return hook->stored_return_value;
        }
    }
    LOGW("nativized_method_stub: no stored return value, returning 0");
    return 0;
}


int get_android_api_level(void) {
    if (g_api_level > 0) {
        return g_api_level;
    }

    char sdk_ver[PROP_VALUE_MAX];
    if (__system_property_get("ro.build.version.sdk", sdk_ver) > 0) {
        g_api_level = atoi(sdk_ver);
    } else {
        g_api_level = 29;
        LOGW("Failed to detect API level, defaulting to %d", g_api_level);
    }

    LOGI("Detected Android API level: %d", g_api_level);
    return g_api_level;
}

static void* elf_find_symbol(const char* lib_path, uintptr_t load_addr, const char* symbol_name) {
    int fd = open(lib_path, O_RDONLY);
    if (fd < 0) return NULL;

    off_t file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    void* map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (map == MAP_FAILED) return NULL;

    void* result = NULL;
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)map;

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        goto cleanup;
    }

    Elf64_Phdr* phdr = (Elf64_Phdr*)((uint8_t*)map + ehdr->e_phoff);
    uintptr_t first_load_vaddr = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            first_load_vaddr = phdr[i].p_vaddr;
            break;
        }
    }

    uintptr_t load_bias = load_addr - first_load_vaddr;

    Elf64_Shdr* shdr = (Elf64_Shdr*)((uint8_t*)map + ehdr->e_shoff);
    Elf64_Shdr* shstrtab = &shdr[ehdr->e_shstrndx];
    const char* shstrtab_data = (const char*)map + shstrtab->sh_offset;

    Elf64_Shdr* dynsym_shdr = NULL;
    Elf64_Shdr* dynstr_shdr = NULL;
    Elf64_Shdr* symtab_shdr = NULL;
    Elf64_Shdr* strtab_shdr = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char* name = shstrtab_data + shdr[i].sh_name;
        if (strcmp(name, ".dynsym") == 0) dynsym_shdr = &shdr[i];
        else if (strcmp(name, ".dynstr") == 0) dynstr_shdr = &shdr[i];
        else if (strcmp(name, ".symtab") == 0) symtab_shdr = &shdr[i];
        else if (strcmp(name, ".strtab") == 0) strtab_shdr = &shdr[i];
    }

    if (dynsym_shdr && dynstr_shdr) {
        Elf64_Sym* symtab = (Elf64_Sym*)((uint8_t*)map + dynsym_shdr->sh_offset);
        const char* strtab = (const char*)map + dynstr_shdr->sh_offset;
        size_t sym_count = dynsym_shdr->sh_size / sizeof(Elf64_Sym);

        for (size_t i = 0; i < sym_count; i++) {
            const char* name = strtab + symtab[i].st_name;
            if (strcmp(name, symbol_name) == 0 && symtab[i].st_value != 0) {
                result = (void*)(load_bias + symtab[i].st_value);
                LOGI("ELF: Found %s in .dynsym at %p", symbol_name, result);
                goto cleanup;
            }
        }
    }

    if (!result && symtab_shdr && strtab_shdr) {
        Elf64_Sym* symtab = (Elf64_Sym*)((uint8_t*)map + symtab_shdr->sh_offset);
        const char* strtab = (const char*)map + strtab_shdr->sh_offset;
        size_t sym_count = symtab_shdr->sh_size / sizeof(Elf64_Sym);

        for (size_t i = 0; i < sym_count; i++) {
            const char* name = strtab + symtab[i].st_name;
            if (strcmp(name, symbol_name) == 0 && symtab[i].st_value != 0) {
                result = (void*)(load_bias + symtab[i].st_value);
                LOGI("ELF: Found %s in .symtab at %p", symbol_name, result);
                goto cleanup;
            }
        }
    }

cleanup:
    munmap(map, file_size);
    return result;
}

static void* elf_find_symbol_containing(const char* lib_path, uintptr_t load_addr,
                                         const char* pattern, char* found_name, size_t found_name_size) {
    int fd = open(lib_path, O_RDONLY);
    if (fd < 0) return NULL;

    off_t file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    void* map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (map == MAP_FAILED) return NULL;

    void* result = NULL;
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)map;

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        goto cleanup;
    }

    Elf64_Phdr* phdr = (Elf64_Phdr*)((uint8_t*)map + ehdr->e_phoff);
    uintptr_t first_load_vaddr = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            first_load_vaddr = phdr[i].p_vaddr;
            break;
        }
    }

    uintptr_t load_bias = load_addr - first_load_vaddr;

    Elf64_Shdr* shdr = (Elf64_Shdr*)((uint8_t*)map + ehdr->e_shoff);
    Elf64_Shdr* shstrtab = &shdr[ehdr->e_shstrndx];
    const char* shstrtab_data = (const char*)map + shstrtab->sh_offset;

    Elf64_Shdr* dynsym_shdr = NULL;
    Elf64_Shdr* dynstr_shdr = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char* name = shstrtab_data + shdr[i].sh_name;
        if (strcmp(name, ".dynsym") == 0) dynsym_shdr = &shdr[i];
        else if (strcmp(name, ".dynstr") == 0) dynstr_shdr = &shdr[i];
    }

    if (dynsym_shdr && dynstr_shdr) {
        Elf64_Sym* symtab = (Elf64_Sym*)((uint8_t*)map + dynsym_shdr->sh_offset);
        const char* strtab = (const char*)map + dynstr_shdr->sh_offset;
        size_t sym_count = dynsym_shdr->sh_size / sizeof(Elf64_Sym);

        for (size_t i = 0; i < sym_count; i++) {
            const char* name = strtab + symtab[i].st_name;
            if (strstr(name, pattern) && symtab[i].st_value != 0) {
                if (strstr(name, "_ZN3art6Thread") || strstr(name, "_ZN3art9JNIEnvExt")) {
                    if (strstr(name, "Offset") || strstr(name, "Cookie") ||
                        strstr(name, "Size") || strstr(name, "Capacity") ||
                        strstr(name, "Count") || strstr(name, "Get") ||
                        strstr(name, "Set") || strstr(name, "Check") ||
                        strstr(name, "Trim") || strstr(name, "Remove") ||
                        strstr(name, "Pop") || strstr(name, "Segment")) {
                        LOGI("ELF: Skipping wrong function: %s", name);
                        continue;
                    }

                    bool is_create_func = (strstr(name, "Create") || strstr(name, "New") ||
                                           strstr(name, "Add") || strstr(name, "Push"));
                    bool is_ref_func = (strstr(name, "LocalRef") || strstr(name, "Reference") ||
                                        strstr(name, "JObject"));

                    if (is_create_func && is_ref_func) {
                        result = (void*)(load_bias + symtab[i].st_value);
                        if (found_name && found_name_size > 0) {
                            strncpy(found_name, name, found_name_size - 1);
                            found_name[found_name_size - 1] = '\0';
                        }
                        LOGI("ELF: Found matching symbol '%s': %s at %p", pattern, name, result);
                        goto cleanup;
                    }
                }
            }
        }
    }

cleanup:
    munmap(map, file_size);
    return result;
}

static void* find_interpreter_bridge(JNIEnv* env) {
    (void)env;

    if (g_interpreter_bridge) {
        return g_interpreter_bridge;
    }

    void* handle = dlopen("libart.so", RTLD_NOW | RTLD_NOLOAD);
    if (handle) {
        void* bridge = dlsym(handle, "art_quick_to_interpreter_bridge");
        if (bridge) {
            g_interpreter_bridge = bridge;
            LOGI("Found art_quick_to_interpreter_bridge via dlsym: %p", bridge);
            return bridge;
        }
    }

    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return NULL;

    char line[512];
    uintptr_t libart_base = 0;
    char libart_path[256] = {0};

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libart.so")) {
            unsigned long start;
            char path[256] = {0};
            if (sscanf(line, "%lx-%*lx %*4s %*x %*s %*d %255s", &start, path) >= 1) {
                if (libart_base == 0 || start < libart_base) {
                    libart_base = start;
                    if (path[0]) strncpy(libart_path, path, sizeof(libart_path) - 1);
                }
            }
        }
    }
    fclose(fp);

    if (!libart_base || !libart_path[0]) {
        LOGE("Could not find libart.so in /proc/self/maps");
        return NULL;
    }

    LOGI("libart.so base: 0x%lx, path: %s", (unsigned long)libart_base, libart_path);

    void* bridge = elf_find_symbol(libart_path, libart_base, "art_quick_to_interpreter_bridge");
    if (bridge) {
        g_interpreter_bridge = bridge;
        return bridge;
    }

    LOGE("Could not find art_quick_to_interpreter_bridge in ELF");
    return NULL;
}


#define ROUND_UP_PTR(x) (((x) + 7) & ~7)

const ArtMethodOffsets* get_art_method_offsets(void) {
    if (g_offsets.api_level > 0) {
        return &g_offsets;
    }

    int api = get_android_api_level();
    g_offsets.api_level = api;


    g_offsets.access_flags_offset = 4;


    // ArtMethod layout changed between Android 11 and Android 12:
    // - Android 11 (API 30) and earlier: has dex_code_item_offset_ field
    //   Layout: declaring_class(4) + access_flags(4) + dex_code_item_offset(4) +
    //           dex_method_index(4) + method_index(2) + hotness_count(2) = 20 bytes
    //   Aligned to 8: 24, then data_(8), then entry_point at offset 32
    //
    // - Android 12+ (API 31+): dex_code_item_offset_ was removed
    //   Layout: declaring_class(4) + access_flags(4) + dex_method_index(4) +
    //           method_index(2) + hotness_count(2) = 16 bytes
    //   Aligned to 8: 16, then data_(8), then entry_point at offset 24
    //
    // Sources:
    // - Android 11: https://android.googlesource.com/platform/art/+/android-11.0.0_r1/runtime/art_method.h
    // - Android 12: https://android.googlesource.com/platform/art/+/android-12.0.0_r1/runtime/art_method.h

    if (api >= 31) {
        // Android 12+ (API 31+): dex_code_item_offset_ removed, entry_point at offset 24
        g_offsets.entry_point_offset = ROUND_UP_PTR(4 + 4 + 4 + 2 + 2) + 8;  // = 24
        g_offsets.art_method_size = g_offsets.entry_point_offset + 8;  // = 32
    } else if (api >= 26) {
        // Android 8.0-11 (API 26-30): has dex_code_item_offset_, entry_point at offset 32
        g_offsets.entry_point_offset = ROUND_UP_PTR(4 + 4 + 4 + 4 + 2 + 2) + 8;  // = 32
        g_offsets.art_method_size = g_offsets.entry_point_offset + 8;  // = 40
    } else {
        // Older versions
        g_offsets.entry_point_offset = 32;
        g_offsets.art_method_size = 40;
    }

    LOGI("ArtMethod offsets for API %d: access_flags=%zu, entry_point=%zu, size=%zu",
         api, g_offsets.access_flags_offset, g_offsets.entry_point_offset,
         g_offsets.art_method_size);

    return &g_offsets;
}


void* jmethodid_to_art_method(JNIEnv* env, jmethodID method_id, jclass clazz) {
    if (!method_id) {
        LOGE("jmethodid_to_art_method: method_id is NULL");
        return NULL;
    }

    int api = get_android_api_level();

    if (api >= 30 && ((uintptr_t)method_id & 1)) {
        LOGI("Android 11+ detected index-based jmethodID: %p", method_id);


        jobject method_obj = (*env)->ToReflectedMethod(env, clazz, method_id, JNI_FALSE);
        if (!method_obj) {
            (*env)->ExceptionClear(env);
            method_obj = (*env)->ToReflectedMethod(env, clazz, method_id, JNI_TRUE);
            if (!method_obj) {
                LOGE("Failed to get reflected method");
                (*env)->ExceptionClear(env);
                return NULL;
            }
        }

        jclass executable_class = (*env)->FindClass(env, "java/lang/reflect/Executable");
        if (!executable_class) {
            LOGE("Failed to find Executable class");
            (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, method_obj);
            return NULL;
        }

        jfieldID art_method_field = (*env)->GetFieldID(env, executable_class, "artMethod", "J");
        if (!art_method_field) {
            LOGE("Failed to get artMethod field");
            (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, method_obj);
            (*env)->DeleteLocalRef(env, executable_class);
            return NULL;
        }

        jlong art_method_ptr = (*env)->GetLongField(env, method_obj, art_method_field);

        (*env)->DeleteLocalRef(env, method_obj);
        (*env)->DeleteLocalRef(env, executable_class);

        LOGI("Got ArtMethod pointer via reflection: %p", (void*)art_method_ptr);
        return (void*)art_method_ptr;
    }

    LOGI("Using direct jmethodID as ArtMethod pointer: %p", method_id);
    return (void*)method_id;
}


static uint64_t java_hook_call_original(int hook_index, uint64_t* saved_regs);

void* create_java_hook_trampoline(int hook_index) {
    void* trampoline = mmap(NULL, PAGE_SIZE,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trampoline == MAP_FAILED) {
        LOGE("Failed to allocate trampoline: %s", strerror(errno));
        return NULL;
    }

    uint32_t* code = (uint32_t*)trampoline;
    int idx = 0;

    // Prologue
    code[idx++] = 0xA9BF7BFD;  // stp x29, x30, [sp, #-16]!
    code[idx++] = 0x910003FD;  // mov x29, sp
    code[idx++] = 0xD10483FF;  // sub sp, sp, #288

    // Save x0-x28
    code[idx++] = 0xA90007E0;  // stp x0, x1, [sp, #0]
    code[idx++] = 0xA9010FE2;  // stp x2, x3, [sp, #16]
    code[idx++] = 0xA90217E4;  // stp x4, x5, [sp, #32]
    code[idx++] = 0xA9031FE6;  // stp x6, x7, [sp, #48]
    code[idx++] = 0xA90427E8;  // stp x8, x9, [sp, #64]
    code[idx++] = 0xA9052FEA;  // stp x10, x11, [sp, #80]
    code[idx++] = 0xA90637EC;  // stp x12, x13, [sp, #96]
    code[idx++] = 0xA9073FEE;  // stp x14, x15, [sp, #112]
    code[idx++] = 0xA90847F0;  // stp x16, x17, [sp, #128]
    code[idx++] = 0xA9094FF2;  // stp x18, x19, [sp, #144]
    code[idx++] = 0xA90A57F4;  // stp x20, x21, [sp, #160]
    code[idx++] = 0xA90B5FF6;  // stp x22, x23, [sp, #176]
    code[idx++] = 0xA90C67F8;  // stp x24, x25, [sp, #192]
    code[idx++] = 0xA90D6FFA;  // stp x26, x27, [sp, #208]
    code[idx++] = 0xF90073FC;  // str x28, [sp, #224]

    // Call onEnter(hook_index, saved_regs)
    code[idx++] = 0xD2800000 | ((hook_index & 0xFFFF) << 5);  // movz x0, #hook_index
    code[idx++] = 0x910003E1;  // mov x1, sp
    int onenter_ldr_idx = idx;
    code[idx++] = 0x58000010;  // ldr x16, [pc, #offset]
    code[idx++] = 0xD63F0200;  // blr x16

    code[idx++] = 0xD2800000 | ((hook_index & 0xFFFF) << 5);
    code[idx++] = 0x910003E1;
    int call_original_ldr_idx = idx;
    code[idx++] = 0x58000010;  // ldr x16, [pc, #offset]
    code[idx++] = 0xD63F0200;  // blr x16

    code[idx++] = 0xF90083E0;  // str x0, [sp, #256]

    // Call onLeave(hook_index, retval)
    code[idx++] = 0xD2800000 | ((hook_index & 0xFFFF) << 5);  // movz x0, #hook_index
    code[idx++] = 0xF94083E1;  // ldr x1, [sp, #256]
    int onleave_ldr_idx = idx;
    code[idx++] = 0x58000010;  // ldr x16, [pc, #offset]
    code[idx++] = 0xD63F0200;  // blr x16

    // Epilogue
    code[idx++] = 0x910483FF;  // add sp, sp, #288
    code[idx++] = 0xA8C17BFD;  // ldp x29, x30, [sp], #16
    code[idx++] = 0xD65F03C0;  // ret

    if (idx % 2 != 0) {
        code[idx++] = 0xD503201F;  // nop (align)
    }

    // Data section
    int onenter_addr_idx = idx;
    *(uint64_t*)(&code[idx]) = (uint64_t)java_hook_on_enter;
    idx += 2;

    int onleave_addr_idx = idx;
    *(uint64_t*)(&code[idx]) = (uint64_t)java_hook_on_leave;
    idx += 2;

    int call_original_addr_idx = idx;
    *(uint64_t*)(&code[idx]) = (uint64_t)java_hook_call_original;
    idx += 2;

    *(uint64_t*)(&code[idx]) = (uint64_t)hook_index;
    idx += 2;

    // Patch LDR offsets
    int onenter_offset = (onenter_addr_idx - onenter_ldr_idx) * 4;
    code[onenter_ldr_idx] = 0x58000010 | ((onenter_offset / 4) << 5);

    int call_original_offset = (call_original_addr_idx - call_original_ldr_idx) * 4;
    code[call_original_ldr_idx] = 0x58000010 | ((call_original_offset / 4) << 5);

    int onleave_offset = (onleave_addr_idx - onleave_ldr_idx) * 4;
    code[onleave_ldr_idx] = 0x58000010 | ((onleave_offset / 4) << 5);

    __builtin___clear_cache((char*)trampoline, (char*)trampoline + idx * 4 + 32);

    LOGI("Created Java hook trampoline at %p (size=%d bytes)", trampoline, idx * 4);

    return trampoline;
}


typedef void* (*DecodeJObject_t)(void* thread, jobject obj);
static DecodeJObject_t g_decode_jobject = NULL;
static int g_decode_jobject_init_tried = 0;
static int g_decode_global_only = 0;

typedef struct {
    void* functions;
    void* self;
    void* vm;
} JNIEnvExt;

static void init_decode_jobject(void) {
    if (g_decode_jobject_init_tried) return;
    g_decode_jobject_init_tried = 1;

    const char* general_symbols[] = {
        "_ZNK3art6Thread13DecodeJObjectEP8_jobject",
        "_ZN3art6Thread13DecodeJObjectEP8_jobject",
        NULL
    };

    const char* global_symbols[] = {
        "_ZNK3art6Thread19DecodeGlobalJObjectEP8_jobject",
        NULL
    };

    void* handle = dlopen("libart.so", RTLD_NOW | RTLD_NOLOAD);

    if (handle) {
        for (int i = 0; general_symbols[i] && !g_decode_jobject; i++) {
            g_decode_jobject = (DecodeJObject_t)dlsym(handle, general_symbols[i]);
            if (g_decode_jobject) {
                LOGI("Found DecodeJObject: %s at %p", general_symbols[i], g_decode_jobject);
                return;
            }
        }
        for (int i = 0; global_symbols[i] && !g_decode_jobject; i++) {
            g_decode_jobject = (DecodeJObject_t)dlsym(handle, global_symbols[i]);
            if (g_decode_jobject) {
                g_decode_global_only = 1;
                LOGI("Found DecodeGlobalJObject: %s at %p", global_symbols[i], g_decode_jobject);
                return;
            }
        }
    }

    for (int i = 0; general_symbols[i] && !g_decode_jobject; i++) {
        g_decode_jobject = (DecodeJObject_t)dlsym(RTLD_DEFAULT, general_symbols[i]);
        if (g_decode_jobject) {
            LOGI("Found DecodeJObject via RTLD_DEFAULT: %s at %p", general_symbols[i], g_decode_jobject);
            return;
        }
    }
    for (int i = 0; global_symbols[i] && !g_decode_jobject; i++) {
        g_decode_jobject = (DecodeJObject_t)dlsym(RTLD_DEFAULT, global_symbols[i]);
        if (g_decode_jobject) {
            g_decode_global_only = 1;
            LOGI("Found DecodeGlobalJObject via RTLD_DEFAULT: %s at %p", global_symbols[i], g_decode_jobject);
            return;
        }
    }

    FILE* fp = fopen("/proc/self/maps", "r");
    if (fp) {
        char line[512];
        uintptr_t libart_base = 0;
        char libart_path[256] = {0};

        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "libart.so")) {
                unsigned long start;
                char path[256] = {0};
                if (sscanf(line, "%lx-%*lx %*4s %*x %*s %*d %255s", &start, path) >= 1) {
                    if (libart_base == 0 || start < libart_base) {
                        libart_base = (uintptr_t)start;
                        if (path[0]) strncpy(libart_path, path, sizeof(libart_path) - 1);
                    }
                }
            }
        }
        fclose(fp);

        if (libart_base && libart_path[0]) {
            LOGI("DecodeJObject: trying ELF lookup in %s @ 0x%lx", libart_path, libart_base);
            for (int i = 0; general_symbols[i] && !g_decode_jobject; i++) {
                g_decode_jobject = (DecodeJObject_t)elf_lookup_symbol(libart_path, libart_base, general_symbols[i]);
                if (g_decode_jobject) {
                    LOGI("Found DecodeJObject via ELF: %s at %p", general_symbols[i], g_decode_jobject);
                    return;
                }
            }
            for (int i = 0; global_symbols[i] && !g_decode_jobject; i++) {
                g_decode_jobject = (DecodeJObject_t)elf_lookup_symbol(libart_path, libart_base, global_symbols[i]);
                if (g_decode_jobject) {
                    g_decode_global_only = 1;
                    LOGI("Found DecodeGlobalJObject via ELF: %s at %p", global_symbols[i], g_decode_jobject);
                    return;
                }
            }
        }
    }

    if (!g_decode_jobject) {
        LOGW("DecodeJObject not found - JNI ref to raw ptr conversion may fail");
    }
}

void* jni_ref_to_raw_ptr(JNIEnv* env, jobject ref) {
    if (!ref) return NULL;

    init_decode_jobject();

    if (g_decode_jobject) {
        JNIEnvExt* env_ext = (JNIEnvExt*)env;
        void* thread = env_ext->self;

        if (thread) {
            jobject decode_ref = ref;
            jobject tmp_global = NULL;
            if (g_decode_global_only) {
                tmp_global = (*env)->NewGlobalRef(env, ref);
                decode_ref = tmp_global;
            }
            void* raw_ptr = g_decode_jobject(thread, decode_ref);
            if (tmp_global) {
                (*env)->DeleteGlobalRef(env, tmp_global);
            }
            LOGI("jni_ref_to_raw_ptr: %p -> %p", ref, raw_ptr);
            return raw_ptr;
        }
    }

    uintptr_t ref_val = (uintptr_t)ref;
    if ((ref_val & 0x3) == 0x1) {
        uintptr_t slot_addr = ref_val & ~((uintptr_t)0x3);
        if (slot_addr > 0x10000) {
            uint64_t slot_val = *(uint64_t*)slot_addr;
            uint32_t lower32 = (uint32_t)(slot_val & 0xFFFFFFFF);
            if (lower32 >= 0x01000000 && lower32 < 0x40000000) {
                LOGI("jni_ref_to_raw_ptr: %p -> 0x%x (via stacked ref decode)", ref, lower32);
                return (void*)(uintptr_t)lower32;
            }
        }
    }

    LOGW("jni_ref_to_raw_ptr: Cannot decode %p, returning as-is", ref);
    return (void*)ref;
}

// Resolve a dynamic symbol from the in-memory ELF image (no file I/O, SELinux-safe)
// One past the highest dynamic symbol index reachable through a DT_GNU_HASH
// table - what DT_HASH's header would have given directly as its symbol
// count, which DT_GNU_HASH does not store anywhere. API 23+ system
// libraries (including libart.so) are built with --hash-style=gnu only, so
// DT_HASH is normally absent and this is the only reliable way to bound a
// linear scan of .dynsym.
static uint32_t gnu_hash_symbol_count(const uint32_t* gnu_hash) {
    uint32_t nbuckets = gnu_hash[0];
    uint32_t symoffset = gnu_hash[1];
    uint32_t bloom_size = gnu_hash[2];
    const uint32_t* buckets = (const uint32_t*)((const uint8_t*)gnu_hash + 16 + (size_t)bloom_size * 8);
    const uint32_t* chain = buckets + nbuckets;

    uint32_t max_index = 0;
    for (uint32_t b = 0; b < nbuckets; b++) {
        uint32_t idx = buckets[b];
        if (idx == 0) continue;
        while (1) {
            uint32_t h = chain[idx - symoffset];
            if (idx > max_index) max_index = idx;
            if (h & 1) break; // low bit set: end of this bucket's chain
            idx++;
        }
    }
    return max_index ? max_index + 1 : 0;
}

static void* find_symbol_in_mapped_elf(uintptr_t base, const char* symbol_name) {
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)base;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        LOGW("ELF(mem): bad magic at 0x%lx", (unsigned long)base);
        return NULL;
    }

    Elf64_Phdr* phdr = (Elf64_Phdr*)(base + ehdr->e_phoff);

    uintptr_t load_bias = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            load_bias = base - phdr[i].p_vaddr;
            break;
        }
    }

    Elf64_Dyn* dynamic = NULL;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dynamic = (Elf64_Dyn*)(load_bias + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dynamic) {
        LOGW("ELF(mem): no PT_DYNAMIC");
        return NULL;
    }

    uintptr_t dyn_bias = load_bias; // assume NOT relocated
    for (Elf64_Dyn* d = dynamic; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_SYMTAB || d->d_tag == DT_STRTAB) {
            if (d->d_un.d_ptr >= base) {
                dyn_bias = 0; // already absolute, don't add bias
            }
            break;
        }
    }
    LOGI("ELF(mem): base=0x%lx load_bias=0x%lx dyn_bias=0x%lx",
         (unsigned long)base, (unsigned long)load_bias, (unsigned long)dyn_bias);

    Elf64_Sym* symtab = NULL;
    const char* strtab = NULL;
    uint32_t nchain = 0;
    uint32_t* gnu_hash = NULL;

    for (Elf64_Dyn* d = dynamic; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_SYMTAB)
            symtab = (Elf64_Sym*)(dyn_bias + d->d_un.d_ptr);
        else if (d->d_tag == DT_STRTAB)
            strtab = (const char*)(dyn_bias + d->d_un.d_ptr);
        else if (d->d_tag == DT_HASH) {
            uint32_t* h = (uint32_t*)(dyn_bias + d->d_un.d_ptr);
            nchain = h[1];
        } else if (d->d_tag == DT_GNU_HASH) {
            gnu_hash = (uint32_t*)(dyn_bias + d->d_un.d_ptr);
        }
    }

    if (!symtab || !strtab) {
        LOGW("ELF(mem): symtab=%p strtab=%p - missing", symtab, strtab);
        return NULL;
    }

    // API 23+ system libraries (libart.so included) are built with
    // --hash-style=gnu only, so DT_HASH - and the chain count it would have
    // given directly - is normally absent. The previous fallback guessed the
    // symbol count from the byte gap between symtab and strtab; on a layout
    // where they aren't adjacent that silently produced a count far larger
    // than the real table, walking the loop below into unrelated, often
    // non-readable pages and crashing strcmp() on a garbage pointer
    // (SEGV_ACCERR) - exactly the Xiaomi/Android 16 libagent.so crash this
    // function was rewritten to fix.
    if (nchain == 0 && gnu_hash) {
        nchain = gnu_hash_symbol_count(gnu_hash);
    }

    if (nchain == 0) {
        LOGW("ELF(mem): no DT_HASH or DT_GNU_HASH, cannot safely size the symbol table");
        return NULL;
    }

    LOGI("ELF(mem): symtab=%p strtab=%p nchain=%u, searching for %s",
         symtab, strtab, nchain, symbol_name);

    for (uint32_t i = 0; i < nchain; i++) {
        if (symtab[i].st_name && symtab[i].st_value) {
            const char* name = strtab + symtab[i].st_name;
            if (strcmp(name, symbol_name) == 0) {
                void* result = (void*)(load_bias + symtab[i].st_value);
                LOGI("ELF(mem): Found %s at %p (st_value=0x%lx + bias=0x%lx)",
                     symbol_name, result,
                     (unsigned long)symtab[i].st_value, (unsigned long)load_bias);
                return result;
            }
        }
    }
    LOGW("ELF(mem): %s not found in %u symbols", symbol_name, nchain);
    return NULL;
}

typedef jobject (*CreateLocalRef_t)(void* self, void* obj);
static CreateLocalRef_t g_create_local_ref = NULL;
static pthread_once_t g_create_local_ref_once = PTHREAD_ONCE_INIT;
static int g_create_local_ref_is_env = 0;

static const char* thread_symbols[] = {
    "_ZN3art6Thread14NewLocalRefLRTEPNS_6mirror6ObjectE",
    "_ZN3art6Thread16NewLocalRefLRTEEPNS_6mirror6ObjectE",
    "_ZN3art6Thread15AddLocalRefLRTEPNS_6mirror6ObjectE",
    "_ZN3art6Thread14CreateLocalRefEPNS_6mirror6ObjectE",
    "_ZNK3art6Thread14CreateLocalRefEPNS_6mirror6ObjectE",
    "_ZN3art6Thread13CreateJObjectEPNS_6mirror6ObjectE",
    NULL
};

static const char* env_symbols[] = {
    "_ZN3art9JNIEnvExt11NewLocalRefEPNS_6mirror6ObjectE",
    "_ZN3art9JNIEnvExt17AddLocalReferenceINS_6mirror6ObjectEEEP8_jobjectNS_6ObjPtrIT_EE",
    "_ZN3art9JNIEnvExt17AddLocalReferenceINS_6mirror6ObjectEEEP8_jobjectPT_",
    NULL
};

static void try_resolve_symbols(const char** syms, int is_env, void* handle, const char* method) {
    for (int i = 0; syms[i] && !g_create_local_ref; i++) {
        CreateLocalRef_t fn = NULL;
        if (handle) {
            fn = (CreateLocalRef_t)dlsym(handle, syms[i]);
        } else {
            fn = (CreateLocalRef_t)dlsym(RTLD_DEFAULT, syms[i]);
        }
        if (fn) {
            g_create_local_ref = fn;
            g_create_local_ref_is_env = is_env;
            LOGI("Found CreateLocalRef via %s: %s at %p (is_env=%d)",
                 method, syms[i], fn, is_env);
        }
    }
}

static void try_resolve_elf(const char** syms, int is_env, const char* path, uintptr_t base) {
    for (int i = 0; syms[i] && !g_create_local_ref; i++) {
        CreateLocalRef_t fn = (CreateLocalRef_t)elf_find_symbol(path, base, syms[i]);
        if (fn) {
            g_create_local_ref = fn;
            g_create_local_ref_is_env = is_env;
            LOGI("Found CreateLocalRef via ELF: %s at %p (is_env=%d)", syms[i], fn, is_env);
        }
    }
}

static void init_create_local_ref_once(void) {
    // Try dlsym first (Thread symbols, then JNIEnvExt symbols)
    void* handle = dlopen("libart.so", RTLD_NOW | RTLD_NOLOAD);
    if (handle) {
        try_resolve_symbols(thread_symbols, 0, handle, "dlsym");
        if (!g_create_local_ref)
            try_resolve_symbols(env_symbols, 1, handle, "dlsym");
    }
    if (!g_create_local_ref) {
        try_resolve_symbols(thread_symbols, 0, NULL, "RTLD_DEFAULT");
        if (!g_create_local_ref)
            try_resolve_symbols(env_symbols, 1, NULL, "RTLD_DEFAULT");
    }

    if (g_create_local_ref) return;

    // Fall back to ELF parsing
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("CreateLocalRef: Cannot open /proc/self/maps");
        return;
    }

    char line[512];
    uintptr_t libart_base = 0;
    char libart_path[256] = {0};

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libart.so")) {
            unsigned long start;
            char path[256] = {0};
            if (sscanf(line, "%lx-%*lx %*4s %*x %*s %*d %255s", &start, path) >= 1) {
                if (libart_base == 0 || start < libart_base) {
                    libart_base = start;
                    if (path[0]) strncpy(libart_path, path, sizeof(libart_path) - 1);
                }
            }
        }
    }
    fclose(fp);

    if (!libart_base || !libart_path[0]) {
        LOGE("CreateLocalRef: Could not find libart.so in maps");
        return;
    }

    LOGI("CreateLocalRef: libart.so at 0x%lx: %s", (unsigned long)libart_base, libart_path);

    try_resolve_elf(thread_symbols, 0, libart_path, libart_base);
    if (!g_create_local_ref)
        try_resolve_elf(env_symbols, 1, libart_path, libart_base);

    if (!g_create_local_ref && libart_base) {
        LOGI("CreateLocalRef: trying in-memory ELF resolution at 0x%lx", (unsigned long)libart_base);
        for (int i = 0; env_symbols[i] && !g_create_local_ref; i++) {
            CreateLocalRef_t fn = (CreateLocalRef_t)find_symbol_in_mapped_elf(libart_base, env_symbols[i]);
            if (fn) {
                g_create_local_ref = fn;
                g_create_local_ref_is_env = 1;
                LOGI("Found CreateLocalRef via mapped ELF: %s at %p (is_env=1)", env_symbols[i], fn);
            }
        }
        if (!g_create_local_ref) {
            for (int i = 0; thread_symbols[i] && !g_create_local_ref; i++) {
                CreateLocalRef_t fn = (CreateLocalRef_t)find_symbol_in_mapped_elf(libart_base, thread_symbols[i]);
                if (fn) {
                    g_create_local_ref = fn;
                    g_create_local_ref_is_env = 0;
                    LOGI("Found CreateLocalRef via mapped ELF: %s at %p (is_env=0)", thread_symbols[i], fn);
                }
            }
        }
    }

    if (!g_create_local_ref) {
        LOGW("CreateLocalRef not found - raw_ptr_to_jni_ref will not work");
    }
}

// Resolves and caches g_create_local_ref. Several threads can reach this on
// their very first call into a hook whose callback replaces an object/String
// value (any hooked method can be called concurrently from multiple ART
// threads) - pthread_once makes every caller but the first block until the
// one-time dlsym/ELF-parsing work above has actually finished, instead of
// racing through it together.
static void init_create_local_ref(void) {
    pthread_once(&g_create_local_ref_once, init_create_local_ref_once);
}

typedef jobject (*IRT_Add_t)(void* table, uint32_t cookie, void* obj);
static IRT_Add_t g_irt_add = NULL;
static int g_irt_add_init_tried = 0;

static void init_irt_add(const char* libart_path, uintptr_t libart_base) {
    if (g_irt_add_init_tried) return;
    g_irt_add_init_tried = 1;

    const char* patterns[] = {
        "IndirectReferenceTable",
        NULL
    };

    char found_name[512] = {0};
    for (int i = 0; patterns[i] && !g_irt_add; i++) {
        void* func = elf_find_symbol_containing(libart_path, libart_base,
                                                 "Add", found_name, sizeof(found_name));
        if (func && strstr(found_name, "IndirectReferenceTable")) {
            g_irt_add = (IRT_Add_t)func;
            LOGI("Found IRT::Add: %s at %p", found_name, func);
        }
    }
}

jobject raw_ptr_to_jni_ref(JNIEnv* env, void* raw_ptr) {
    if (!raw_ptr) return NULL;

    init_create_local_ref();

    if (g_create_local_ref) {
        void* self;
        if (g_create_local_ref_is_env) {
            // JNIEnvExt method: this = JNIEnv* (which IS JNIEnvExt*)
            self = env;
        } else {
            // Thread method: this = Thread* (at JNIEnvExt offset 8)
            void** env_ptr = (void**)env;
            self = env_ptr[1];
        }

        if (self) {
            jobject ref = g_create_local_ref(self, raw_ptr);
            LOGI("raw_ptr_to_jni_ref: %p -> %p (via CreateLocalRef, is_env=%d)",
                 raw_ptr, ref, g_create_local_ref_is_env);
            return ref;
        }
    }

    LOGW("raw_ptr_to_jni_ref: Cannot convert %p, CreateLocalRef unavailable", raw_ptr);
    return NULL;
}

static __thread uint32_t g_in_original_call_mask = 0;

static void call_original_via_jni(JavaHookInfo* hook, uint64_t* saved_regs) {
    int hook_index = hook->hook_index;
    uint32_t hook_bit = (hook_index < 32) ? (1u << hook_index) : 0;

    if (hook_bit && (g_in_original_call_mask & hook_bit)) {
        LOGW("call_original_via_jni: recursive call detected for hook #%d, skipping", hook_index);
        hook->stored_return_value = 0;
        hook->has_stored_return = true;
        return;
    }

    JNIEnv* env = get_jni_env();

    if (!env || !hook->method_id) {
        LOGE("call_original_via_jni: env=%p, method_id=%p (get_jni_env failed?)", env, hook->method_id);
        hook->stored_return_value = 0;
        hook->has_stored_return = true;
        return;
    }

    // saved_regs[1] is a raw ART object pointer from the trampoline, not a JNI reference
    // We need to convert it to a JNI local reference for use with JNI calls
    jobject receiver = NULL;
    if (!hook->is_static && saved_regs[1]) {
        receiver = raw_ptr_to_jni_ref(env, (void*)saved_regs[1]);
        if (!receiver) {
            LOGE("call_original_via_jni: failed to convert receiver to JNI ref");
            hook->stored_return_value = 0;
            hook->has_stored_return = true;
            return;
        }
    }

    LOGI("call_original_via_jni: %s.%s%s (env=%p, raw_receiver=0x%llx, jni_receiver=%p)",
         hook->class_name, hook->method_name, hook->method_sig, env,
         (unsigned long long)saved_regs[1], receiver);

    const ArtMethodOffsets* offsets = get_art_method_offsets();
    uint32_t* access_flags_ptr = (uint32_t*)((uintptr_t)hook->art_method + offsets->access_flags_offset);

    void* page = (void*)((uintptr_t)access_flags_ptr & ~(PAGE_SIZE - 1));
    if (mprotect(page, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        LOGE("call_original_via_jni: mprotect failed: %s", strerror(errno));
        hook->stored_return_value = 0;
        hook->has_stored_return = true;
        return;
    }

    void** entry_point_ptr = (void**)((uintptr_t)hook->art_method + offsets->entry_point_offset);

    void* page_entry = (void*)((uintptr_t)entry_point_ptr & ~(PAGE_SIZE - 1));
    if (mprotect(page_entry, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        LOGE("call_original_via_jni: mprotect entry_point failed: %s", strerror(errno));
        hook->stored_return_value = 0;
        hook->has_stored_return = true;
        return;
    }

    uint32_t current_flags = *access_flags_ptr;
    void* current_entry = *entry_point_ptr;

    *access_flags_ptr = hook->original_access_flags;  // Remove kAccNative
    *entry_point_ptr = hook->original_entry_point;    // Restore original entry point

    __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    LOGI("  Temporarily restored flags: 0x%x -> 0x%x", current_flags, hook->original_access_flags);
    LOGI("  Temporarily restored entry_point: %p -> %p", current_entry, hook->original_entry_point);

    jvalue args[6] = {0};
    const char* sig = hook->method_sig;
    const char* p = sig;
    if (*p == '(') p++;

    int arg_idx = 0;
    int reg_idx = 2;

    while (*p && *p != ')' && arg_idx < 6) {
        switch (*p) {
            case 'Z': args[arg_idx].z = (jboolean)saved_regs[reg_idx]; break;
            case 'B': args[arg_idx].b = (jbyte)saved_regs[reg_idx]; break;
            case 'C': args[arg_idx].c = (jchar)saved_regs[reg_idx]; break;
            case 'S': args[arg_idx].s = (jshort)saved_regs[reg_idx]; break;
            case 'I': args[arg_idx].i = (jint)saved_regs[reg_idx]; break;
            case 'J': args[arg_idx].j = (jlong)saved_regs[reg_idx]; break;
            case 'F': args[arg_idx].f = *(float*)&saved_regs[reg_idx]; break;
            case 'D': args[arg_idx].d = *(double*)&saved_regs[reg_idx]; break;
            case 'L':
                // Convert raw pointer to JNI reference for object arguments
                if (saved_regs[reg_idx]) {
                    args[arg_idx].l = raw_ptr_to_jni_ref(env, (void*)saved_regs[reg_idx]);
                } else {
                    args[arg_idx].l = NULL;
                }
                while (*p && *p != ';') p++;
                break;
            case '[':
                // Convert raw pointer to JNI reference for array arguments
                if (saved_regs[reg_idx]) {
                    args[arg_idx].l = raw_ptr_to_jni_ref(env, (void*)saved_regs[reg_idx]);
                } else {
                    args[arg_idx].l = NULL;
                }
                p++;
                if (*p == 'L') {
                    while (*p && *p != ';') p++;
                }
                break;
        }
        LOGI("  arg[%d] = 0x%llx -> jni=%p", arg_idx, (unsigned long long)saved_regs[reg_idx], args[arg_idx].l);
        arg_idx++;
        reg_idx++;
        if (*p) p++;
    }

    while (*p && *p != ')') p++;
    if (*p == ')') p++;
    char return_type = *p;

    LOGI("  Calling method (return_type=%c, is_static=%d)", return_type, hook->is_static);

    if (hook_bit) {
        g_in_original_call_mask |= hook_bit;
    }

    if (hook->is_static) {
        switch (return_type) {
            case 'V':
                (*env)->CallStaticVoidMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                hook->stored_return_value = 0;
                break;
            case 'Z':
                hook->stored_return_value = (*env)->CallStaticBooleanMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                break;
            case 'B':
                hook->stored_return_value = (*env)->CallStaticByteMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                break;
            case 'C':
                hook->stored_return_value = (*env)->CallStaticCharMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                break;
            case 'S':
                hook->stored_return_value = (*env)->CallStaticShortMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                break;
            case 'I':
                hook->stored_return_value = (*env)->CallStaticIntMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                break;
            case 'J':
                hook->stored_return_value = (*env)->CallStaticLongMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                break;
            case 'F': {
                float f = (*env)->CallStaticFloatMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                hook->stored_return_value = *(uint32_t*)&f;
                break;
            }
            case 'D': {
                double d = (*env)->CallStaticDoubleMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                hook->stored_return_value = *(uint64_t*)&d;
                break;
            }
            case 'L':
            case '[': {
                jobject result = (*env)->CallStaticObjectMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                hook->stored_return_value = (uint64_t)result;

                if (result && return_type == 'L') {
                    const char* ret_sig = strchr(hook->method_sig, ')');
                    if (ret_sig && strncmp(ret_sig + 1, "Ljava/lang/String;", 18) == 0) {
                        if (hook->stored_string_value) {
                            free(hook->stored_string_value);
                            hook->stored_string_value = NULL;
                        }

                        jstring jstr = (jstring)result;
                        const char* chars = (*env)->GetStringUTFChars(env, jstr, NULL);
                        if (chars) {
                            hook->stored_string_value = strdup(chars);
                            hook->has_stored_string = true;
                            LOGI("  Captured static string return value: \"%s\"", chars);
                            (*env)->ReleaseStringUTFChars(env, jstr, chars);
                        } else {
                            hook->has_stored_string = false;
                            LOGW("  Failed to read static string return value");
                        }
                    }
                }
                break;
            }
        }
    } else {
        switch (return_type) {
            case 'V':
                (*env)->CallVoidMethodA(env, receiver, hook->method_id, args);
                hook->stored_return_value = 0;
                break;
            case 'Z':
                hook->stored_return_value = (*env)->CallBooleanMethodA(env, receiver, hook->method_id, args);
                break;
            case 'B':
                hook->stored_return_value = (*env)->CallByteMethodA(env, receiver, hook->method_id, args);
                break;
            case 'C':
                hook->stored_return_value = (*env)->CallCharMethodA(env, receiver, hook->method_id, args);
                break;
            case 'S':
                hook->stored_return_value = (*env)->CallShortMethodA(env, receiver, hook->method_id, args);
                break;
            case 'I':
                hook->stored_return_value = (*env)->CallIntMethodA(env, receiver, hook->method_id, args);
                break;
            case 'J':
                hook->stored_return_value = (*env)->CallLongMethodA(env, receiver, hook->method_id, args);
                break;
            case 'F': {
                float f = (*env)->CallFloatMethodA(env, receiver, hook->method_id, args);
                hook->stored_return_value = *(uint32_t*)&f;
                break;
            }
            case 'D': {
                double d = (*env)->CallDoubleMethodA(env, receiver, hook->method_id, args);
                hook->stored_return_value = *(uint64_t*)&d;
                break;
            }
            case 'L':
            case '[': {
                jobject result = (*env)->CallObjectMethodA(env, receiver, hook->method_id, args);
                hook->stored_return_value = (uint64_t)result;

                // Check if return type is String and read the value
                if (result && return_type == 'L') {
                    const char* ret_sig = strchr(hook->method_sig, ')');
                    if (ret_sig && strncmp(ret_sig + 1, "Ljava/lang/String;", 18) == 0) {
                        if (hook->stored_string_value) {
                            free(hook->stored_string_value);
                            hook->stored_string_value = NULL;
                        }

                        jstring jstr = (jstring)result;
                        const char* chars = (*env)->GetStringUTFChars(env, jstr, NULL);
                        if (chars) {
                            hook->stored_string_value = strdup(chars);
                            hook->has_stored_string = true;
                            LOGI("  Captured string return value: \"%s\"", chars);
                            (*env)->ReleaseStringUTFChars(env, jstr, chars);
                        } else {
                            hook->has_stored_string = false;
                            LOGW("  Failed to read string return value");
                        }
                    }
                }
                break;
            }
        }
    }

    if (hook_bit) {
        g_in_original_call_mask &= ~hook_bit;
    }

    if ((*env)->ExceptionCheck(env)) {
        LOGE("call_original_via_jni: exception occurred");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        hook->stored_return_value = 0;
    }

    *access_flags_ptr = current_flags;
    *entry_point_ptr = current_entry;
    __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    hook->has_stored_return = true;
    LOGI("  Result: 0x%llx", (unsigned long long)hook->stored_return_value);
}

typedef uint64_t (*interpreter_call_t)(void* bridge, uint64_t* regs);

static uint64_t call_interpreter_bridge_asm(void* bridge, uint64_t* regs) {
    uint64_t result = 0;

    __asm__ volatile(
        // Prologue: proper frame setup for ART compatibility
        "stp x29, x30, [sp, #-96]!\n"  // Push frame and allocate 96 bytes
        "mov x29, sp\n"                 // Set frame pointer (CRITICAL for nested calls)
        "stp x19, x20, [sp, #16]\n"     // Save more callee-saved regs
        "stp x21, x22, [sp, #32]\n"

        // Store our parameters in callee-saved locations
        "mov x20, %[bridge]\n"          // x20 = bridge (callee-saved)
        "mov x21, %[regs]\n"            // x21 = regs (callee-saved)
        "mov x22, %[result_ptr]\n"      // x22 = result_ptr (callee-saved)

        // Load x19 from regs[19] (ART thread pointer for some ART versions)
        "ldr x19, [x21, #152]\n"        // x19 = regs[19]

        // Load argument registers from saved_regs
        "ldr x0, [x21, #0]\n"           // x0 = regs[0] (ArtMethod*)
        "ldr x1, [x21, #8]\n"           // x1 = regs[1] (receiver/this)
        "ldr x2, [x21, #16]\n"          // x2 = regs[2] (arg1)
        "ldr x3, [x21, #24]\n"          // x3 = regs[3] (arg2)
        "ldr x4, [x21, #32]\n"          // x4 = regs[4] (arg3)
        "ldr x5, [x21, #40]\n"          // x5 = regs[5] (arg4)
        "ldr x6, [x21, #48]\n"          // x6 = regs[6] (arg5)
        "ldr x7, [x21, #56]\n"          // x7 = regs[7] (arg6)

        // Call the original entry point
        "blr x20\n"

        // Store result - x22 is preserved across calls (callee-saved)
        "str x0, [x22]\n"

        // Epilogue: restore callee-saved registers
        "ldp x21, x22, [sp, #32]\n"
        "ldp x19, x20, [sp, #16]\n"
        "ldp x29, x30, [sp], #96\n"     // Restore frame and deallocate

        :
        : [bridge] "r"(bridge), [regs] "r"(regs), [result_ptr] "r"(&result)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
          "x16", "x17", "x18", "memory", "cc"
    );

    return result;
}

static void call_original_via_interpreter(JavaHookInfo* hook, uint64_t* saved_regs) {
    int hook_index = hook->hook_index;
    uint32_t hook_bit = (hook_index < 32) ? (1u << hook_index) : 0;

    if (hook_bit && (g_in_original_call_mask & hook_bit)) {
        LOGW("call_original_via_interpreter: recursive call detected for hook #%d, skipping", hook_index);
        hook->stored_return_value = 0;
        hook->has_stored_return = true;
        return;
    }

    const ArtMethodOffsets* offsets = get_art_method_offsets();

    uint32_t* access_flags_ptr = (uint32_t*)((uintptr_t)hook->art_method + offsets->access_flags_offset);
    void** entry_point_ptr = (void**)((uintptr_t)hook->art_method + offsets->entry_point_offset);

    uint32_t current_flags = *access_flags_ptr;
    void* current_entry = *entry_point_ptr;

    LOGI("call_original_via_interpreter: %s.%s%s",
         hook->class_name, hook->method_name, hook->method_sig);
    LOGI("  Current flags: 0x%x, original: 0x%x", current_flags, hook->original_access_flags);
    LOGI("  Current entry: %p, interpreter bridge: %p", current_entry, g_interpreter_bridge);

    if (!g_interpreter_bridge) {
        LOGE("call_original_via_interpreter: No interpreter bridge available");
        hook->stored_return_value = 0;
        hook->has_stored_return = true;
        return;
    }

    void* page = (void*)((uintptr_t)access_flags_ptr & ~(PAGE_SIZE - 1));
    if (mprotect(page, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        LOGE("call_original_via_interpreter: mprotect failed: %s", strerror(errno));
        hook->stored_return_value = 0;
        hook->has_stored_return = true;
        return;
    }

    *access_flags_ptr = hook->original_access_flags;
    __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);

    *entry_point_ptr = g_interpreter_bridge;
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    LOGI("  Temporarily restored: flags=0x%x, entry=%p",
         *access_flags_ptr, *entry_point_ptr);

    LOGI("  Calling interpreter bridge with x0=%p x1=%p x2=%p x3=%p x19=%p",
         (void*)saved_regs[0], (void*)saved_regs[1],
         (void*)saved_regs[2], (void*)saved_regs[3], (void*)saved_regs[19]);

    if (hook_bit) {
        g_in_original_call_mask |= hook_bit;
    }

    uint64_t result = call_interpreter_bridge_asm(g_interpreter_bridge, saved_regs);

    if (hook_bit) {
        g_in_original_call_mask &= ~hook_bit;
    }

    {
        JNIEnv* env = get_jni_env();
        if (env && (*env)->ExceptionCheck(env)) {
            LOGI("  Clearing pending Java exception (interpreter path)");
            (*env)->ExceptionClear(env);
        }
    }

    LOGI("  Interpreter bridge returned: 0x%llx", (unsigned long long)result);

    *entry_point_ptr = current_entry;
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    *access_flags_ptr = current_flags;
    __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);

    LOGI("  Restored: flags=0x%x, entry=%p", *access_flags_ptr, *entry_point_ptr);

    hook->stored_return_value = result;
    hook->has_stored_return = true;
}

static uint64_t java_hook_call_original(int hook_index, uint64_t* saved_regs) {
    if (hook_index < 0 || hook_index >= g_java_hook_count) {
        LOGE("java_hook_call_original: Invalid hook index: %d", hook_index);
        return 0;
    }

    JavaHookInfo* hook = &g_java_hooks[hook_index];

    LOGI("java_hook_call_original: hook #%d, was_nativized=%d, method_id=%p",
         hook_index, hook->was_nativized, hook->method_id);

    if (hook->skip_original) {
        LOGI("  Skipping original call (skip_original set by onEnter)");
        return 0;
    }

    // Note: We cannot use JNI reflection (call_original_via_jni) from the trampoline context
    // because saved_regs values are raw ART pointers/compressed OOPs, not JNI references.
    // Converting them with raw_ptr_to_jni_ref fails because they're not valid mirror::Object*.
    // We always use the interpreter bridge path which handles ART internals correctly.
    // String capture is not supported in this path.
    const ArtMethodOffsets* offsets = get_art_method_offsets();
    uint32_t* access_flags_ptr = (uint32_t*)((uintptr_t)hook->art_method + offsets->access_flags_offset);
    void** entry_point_ptr = (void**)((uintptr_t)hook->art_method + offsets->entry_point_offset);

    uint32_t current_flags = *access_flags_ptr;
    void* current_entry = *entry_point_ptr;

    void* page = (void*)((uintptr_t)access_flags_ptr & ~(PAGE_SIZE - 1));
    if (mprotect(page, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        LOGE("java_hook_call_original: mprotect failed: %s", strerror(errno));
        return 0;
    }

    *access_flags_ptr = hook->original_access_flags;
    *entry_point_ptr = hook->original_entry_point;
    __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    LOGI("  Temporarily restored: flags 0x%x -> 0x%x, entry %p -> %p",
         current_flags, hook->original_access_flags,
         current_entry, hook->original_entry_point);

    uint64_t result = call_interpreter_bridge_asm(hook->original_entry_point, saved_regs);

    {
        JNIEnv* env = get_jni_env();
        if (env && (*env)->ExceptionCheck(env)) {
            LOGI("  Clearing pending Java exception for hooked method");
            (*env)->ExceptionClear(env);
        }
    }

    LOGI("  Original entry point returned: 0x%llx", (unsigned long long)result);

    *access_flags_ptr = current_flags;
    *entry_point_ptr = current_entry;
    __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    // Try to capture String return value
    // The result from interpreter bridge is a raw ART mirror::String* pointer
    // We read the string directly from memory using ART's internal layout
    if (result != 0) {
        const char* ret_sig = strchr(hook->method_sig, ')');
        if (ret_sig && strncmp(ret_sig + 1, "Ljava/lang/String;", 18) == 0) {
            // Free previous string if any
            if (hook->stored_string_value) {
                free(hook->stored_string_value);
                hook->stored_string_value = NULL;
                hook->has_stored_string = false;
            }

            // Read string directly from ART mirror::String layout
            // Android 9+ (API 28+) uses String compression:
            //   - If all chars are ASCII/Latin-1, stored as uint8_t[] (compressed)
            //   - Otherwise stored as uint16_t[] (uncompressed)
            // Layout:
            //   offset 0x00: object header (4 bytes klass ref + 4 bytes monitor/hash)
            //   offset 0x08: int32 count - high bit indicates compression
            //                bit 31 = 0: compressed (Latin-1), bit 31 = 1: uncompressed (UTF-16)
            //                bits 0-30: length
            //   offset 0x0C: int32 hash (cached hash code)
            //   offset 0x10: char data (uint8_t[] if compressed, uint16_t[] if not)

            uint8_t* str_ptr = (uint8_t*)result;
            LOGI("  Reading string from raw ptr: 0x%llx", (unsigned long long)result);

            // Read count at offset 0x08
            int32_t raw_count = *(int32_t*)(str_ptr + 0x08);

            // Check compression bit (bit 31)
            // Note: In some Android versions, 0 = uncompressed, in others 0 = compressed
            // The safest way is to check if high bit is set
            bool is_compressed = (raw_count >= 0);  // high bit not set = compressed
            int32_t count = raw_count & 0x7FFFFFFF;  // mask out high bit to get length

            LOGI("  String raw_count: 0x%x, count: %d, compressed: %d", raw_count, count, is_compressed);

            if (count >= 0 && count < 65536) {  // Sanity check
                char* utf8_str = malloc(count * 3 + 1);
                if (utf8_str) {
                    int utf8_idx = 0;

                    if (is_compressed) {
                        // Compressed: Latin-1 encoded (1 byte per char)
                        uint8_t* latin1_chars = str_ptr + 0x10;
                        for (int i = 0; i < count; i++) {
                            uint8_t ch = latin1_chars[i];
                            if (ch < 0x80) {
                                utf8_str[utf8_idx++] = (char)ch;
                            } else {
                                // Latin-1 extended chars (0x80-0xFF) -> 2-byte UTF-8
                                utf8_str[utf8_idx++] = 0xC0 | (ch >> 6);
                                utf8_str[utf8_idx++] = 0x80 | (ch & 0x3F);
                            }
                        }
                    } else {
                        // Uncompressed: UTF-16 encoded (2 bytes per char)
                        uint16_t* utf16_chars = (uint16_t*)(str_ptr + 0x10);
                        for (int i = 0; i < count; i++) {
                            uint16_t ch = utf16_chars[i];
                            if (ch < 0x80) {
                                utf8_str[utf8_idx++] = (char)ch;
                            } else if (ch < 0x800) {
                                utf8_str[utf8_idx++] = 0xC0 | (ch >> 6);
                                utf8_str[utf8_idx++] = 0x80 | (ch & 0x3F);
                            } else {
                                utf8_str[utf8_idx++] = 0xE0 | (ch >> 12);
                                utf8_str[utf8_idx++] = 0x80 | ((ch >> 6) & 0x3F);
                                utf8_str[utf8_idx++] = 0x80 | (ch & 0x3F);
                            }
                        }
                    }
                    utf8_str[utf8_idx] = '\0';

                    hook->stored_string_value = utf8_str;
                    hook->has_stored_string = true;
                    LOGI("  Captured string (raw read): \"%s\"", utf8_str);
                }
            } else {
                LOGW("  Invalid string count: %d", count);
            }
        }
    }

    return result;
}

// Callbacks wait for the Lua VM, but not forever: a script that runs for a
// long time (or a callback of another hook that is slow) would otherwise
// hold up every thread that calls a hooked method - on the main thread
// that is an ANR. After the timeout the call goes on without its callback,
// and the skipped callbacks are reported, the same policy as native hooks.
#define JAVA_CALLBACK_LOCK_TIMEOUT_MS 500

static volatile unsigned long g_java_cb_skipped = 0;
static volatile long g_java_cb_skip_reported_at = 0;

static bool java_callback_lock(const JavaHookInfo* hook) {
    if (lua_vm_lock_timed(JAVA_CALLBACK_LOCK_TIMEOUT_MS)) {
        return true;
    }
    unsigned long total = __atomic_add_fetch(&g_java_cb_skipped, 1, __ATOMIC_RELAXED);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long last = __atomic_load_n(&g_java_cb_skip_reported_at, __ATOMIC_RELAXED);
    if (now.tv_sec - last >= 2 &&
        __atomic_compare_exchange_n(&g_java_cb_skip_reported_at, &last, (long)now.tv_sec, false,
                                    __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        char msg[320];
        int n = snprintf(msg, sizeof(msg),
                         "[renef] %lu Java hook callback(s) skipped (last: %s.%s): Lua VM busy for >%dms "
                         "(a script or another callback is still running)\n",
                         total, hook->class_name, hook->method_name, JAVA_CALLBACK_LOCK_TIMEOUT_MS);
        if (n > 0) {
            LOGW("%s", msg);
            output_queue_push(msg, (size_t)n);
        }
    }
    return false;
}

void* java_libart_symbol(const char* name) {
    static uintptr_t libart_base = 0;
    if (!libart_base) {
        FILE* fp = fopen("/proc/self/maps", "r");
        if (!fp) return NULL;
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "/libart.so")) {
                unsigned long start;
                if (sscanf(line, "%lx-", &start) == 1 && (libart_base == 0 || start < libart_base)) {
                    libart_base = start;
                }
            }
        }
        fclose(fp);
    }
    return libart_base ? find_symbol_in_mapped_elf(libart_base, name) : NULL;
}

static __thread char g_tls_last_error[256];

const char* java_hook_last_error(void) {
    return g_tls_last_error;
}

void java_hook_set_error(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_tls_last_error, sizeof(g_tls_last_error), fmt, ap);
    va_end(ap);
}

static __thread char* g_tls_return_string = NULL;

void java_hook_set_return_string(char* text) {
    free(g_tls_return_string);
    g_tls_return_string = text;
}

static __thread bool g_tls_skip_original = false;

bool java_hook_skip_requested(void) {
    return g_tls_skip_original;
}

// A ready-made local JNI reference for the onLeave return value that just
// ran on this thread, when onLeave produced its replacement through a
// higher-level helper (currently JNI.string) that already holds a valid
// jobject. Handing that reference straight back avoids a needless round
// trip through raw_ptr_to_jni_ref()/CreateLocalRef(), whose ART-internal
// symbol lookup is version-fragile and unresolved on some builds (e.g.
// Android 16). jj_dispatch() consumes (and clears) this once per call,
// regardless of the return type, so a stale value can't leak into the
// next hook invocation on this thread.
static __thread jobject g_tls_return_object = NULL;

jobject java_hook_take_return_object(void) {
    jobject obj = g_tls_return_object;
    g_tls_return_object = NULL;
    return obj;
}

void java_hook_abandon_call(void) {
    if (g_hook_call_stack.depth > 0) {
        g_hook_call_stack.depth--;
        g_current_java_hook_index = g_hook_call_stack.depth > 0
            ? g_hook_call_stack.hook_indices[g_hook_call_stack.depth - 1] : -1;
    }
}

void java_hook_on_enter(int hook_index, uint64_t* saved_regs) {
    if (hook_index < 0 || hook_index >= g_java_hook_count) {
        LOGE("Invalid Java hook index: %d", hook_index);
        return;
    }

    JavaHookInfo* hook = &g_java_hooks[hook_index];
    __atomic_add_fetch(&hook->hits, 1, __ATOMIC_RELAXED);

    if (g_hook_call_stack.depth < MAX_HOOK_CALL_DEPTH) {
        g_hook_call_stack.hook_indices[g_hook_call_stack.depth] = hook_index;
        g_hook_call_stack.depth++;
    } else {
        LOGW("Hook call stack overflow! depth=%d, skipping hook #%d",
             g_hook_call_stack.depth, hook_index);
        return;
    }

    g_current_java_hook_index = hook_index;

    LOGI("=== Java Hook #%d onEnter: %s.%s%s (depth=%d) ===",
         hook_index, hook->class_name, hook->method_name, hook->method_sig,
         g_hook_call_stack.depth);

    uint64_t x0 = saved_regs[0];
    uint64_t x1 = saved_regs[1];
    uint64_t x2 = saved_regs[2];
    uint64_t x3 = saved_regs[3];

    LOGI("  Args: X0=0x%llx X1=0x%llx X2=0x%llx X3=0x%llx",
         (unsigned long long)x0, (unsigned long long)x1,
         (unsigned long long)x2, (unsigned long long)x3);

    hook->skip_original = false;
    g_tls_skip_original = false;

    if (hook->lua_onEnter_ref != LUA_NOREF && g_lua_engine && java_callback_lock(hook)) {
        lua_State* L = lua_engine_get_state(g_lua_engine);
        if (L) {
            lua_rawgeti(L, LUA_REGISTRYINDEX, hook->lua_onEnter_ref);

            lua_newtable(L);

            lua_pushstring(L, hook->class_name);
            lua_setfield(L, -2, "class");
            lua_pushstring(L, hook->method_name);
            lua_setfield(L, -2, "method");
            lua_pushstring(L, hook->method_sig);
            lua_setfield(L, -2, "signature");
            lua_pushboolean(L, hook->is_static);
            lua_setfield(L, -2, "isStatic");

            for (int i = 0; i < 8; i++) {
                lua_pushinteger(L, saved_regs[i]);
                lua_rawseti(L, -2, i);
            }

            lua_pushvalue(L, -1);
            int args_ref = luaL_ref(L, LUA_REGISTRYINDEX);

            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                LOGE("Java hook onEnter callback failed: %s", lua_tostring(L, -1));
                lua_pop(L, 1);
            } else {
                lua_rawgeti(L, LUA_REGISTRYINDEX, args_ref);

                lua_getfield(L, -1, "skip");
                if (lua_toboolean(L, -1)) {
                    g_tls_skip_original = true;
                    hook->skip_original = true;
                    LOGI("  skip_original set by onEnter callback");
                }
                lua_pop(L, 1);

                for (int i = 0; i < 8; i++) {
                    lua_rawgeti(L, -1, i);
                    if (lua_isinteger(L, -1)) {
                        uint64_t new_val = (uint64_t)lua_tointeger(L, -1);
                        if (new_val != saved_regs[i]) {
                            LOGI("  Arg %d modified: 0x%llx -> 0x%llx", i,
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
}

uint64_t java_hook_on_leave(int hook_index, uint64_t ret_val) {
    if (hook_index < 0 || hook_index >= g_java_hook_count) {
        LOGE("Invalid Java hook index in onLeave: %d", hook_index);
        return ret_val;
    }

    JavaHookInfo* hook = &g_java_hooks[hook_index];

    LOGI("=== Java Hook #%d onLeave: %s.%s%s (depth=%d) ===",
         hook_index, hook->class_name, hook->method_name, hook->method_sig,
         g_hook_call_stack.depth);
    LOGI("  Return value: 0x%llx (%lld)", (unsigned long long)ret_val, (long long)ret_val);

    // Log captured string value if available
    if (hook->has_stored_string && hook->stored_string_value) {
        LOGI("  String value: \"%s\"", hook->stored_string_value);
    }

    if (hook->lua_onLeave_ref != LUA_NOREF && g_lua_engine && java_callback_lock(hook)) {
        lua_State* L = lua_engine_get_state(g_lua_engine);
        if (L) {
            lua_rawgeti(L, LUA_REGISTRYINDEX, hook->lua_onLeave_ref);

            lua_newtable(L);

            lua_pushinteger(L, ret_val);
            lua_setfield(L, -2, "raw");

            if (g_tls_return_string) {
                lua_pushstring(L, g_tls_return_string);
                lua_setfield(L, -2, "value");
            } else if (hook->has_stored_string && hook->stored_string_value) {
                lua_pushstring(L, hook->stored_string_value);
                lua_setfield(L, -2, "value");

                free(hook->stored_string_value);
                hook->stored_string_value = NULL;
                hook->has_stored_string = false;
            }

            if (lua_pcall(L, 1, 1, 0) == LUA_OK) {
                int api = get_android_api_level();
                bool method_expects_jni_refs = hook->was_nativized;
                bool can_modify_objects = (api < 30 || api >= 35 || method_expects_jni_refs);

                if (lua_isnil(L, -1)) {
                } else if (lua_istable(L, -1)) {
                    lua_getfield(L, -1, "__jni_type");
                    if (lua_isstring(L, -1)) {
                        const char* jni_type = lua_tostring(L, -1);
                        lua_pop(L, 1);
                        lua_getfield(L, -1, "value");

                        if (strcmp(jni_type, "string") == 0 && lua_isstring(L, -1)) {
                            if (can_modify_objects) {
                                const char* str_value = lua_tostring(L, -1);
                                JNIEnv* env = get_jni_env();
                                if (env && str_value) {
                                    jstring new_str = (*env)->NewStringUTF(env, str_value);
                                    if (new_str) {
                                        void* raw_ptr = jni_ref_to_raw_ptr(env, new_str);
                                        if (raw_ptr) {
                                            ret_val = (uint64_t)raw_ptr;
                                            g_tls_return_object = new_str;
                                            LOGI("  Modified to jstring: \"%s\" (jni_ref=%p, raw_ptr=%p)",
                                                 str_value, new_str, raw_ptr);
                                        } else {
                                            LOGE("  Failed to convert jstring to raw ptr");
                                        }
                                    } else {
                                        LOGE("  NewStringUTF failed for: \"%s\"", str_value);
                                        if ((*env)->ExceptionCheck(env)) {
                                            (*env)->ExceptionDescribe(env);
                                            (*env)->ExceptionClear(env);
                                        }
                                    }
                                } else {
                                    LOGE("  Cannot create jstring: env=%p, str_value=%p", env, str_value);
                                }
                            } else {
                                LOGW("  Return value modification (string) not supported on API %d", api);
                            }
                        } else if (strcmp(jni_type, "int") == 0 || strcmp(jni_type, "long") == 0) {
                            ret_val = (uint64_t)lua_tointeger(L, -1);
                            LOGI("  Modified to %s: %lld", jni_type, (long long)ret_val);
                        } else if (strcmp(jni_type, "boolean") == 0) {
                            ret_val = lua_toboolean(L, -1) ? 1 : 0;
                            LOGI("  Modified to boolean: %s", ret_val ? "true" : "false");
                        }
                        lua_pop(L, 1);
                    } else {
                        lua_pop(L, 1);
                    }
                } else if (lua_isinteger(L, -1) || lua_isnumber(L, -1)) {
                    uint64_t new_val = (uint64_t)lua_tointeger(L, -1);
                    if (!can_modify_objects && new_val < 0x10000) {
                        LOGW("  Return value modification (0x%llx) blocked - method not nativized on API %d",
                             (unsigned long long)new_val, api);
                    } else {
                        ret_val = new_val;
                        if (method_expects_jni_refs && new_val < 0x10000) {
                            LOGI("  Modified to JNI ref: 0x%llx", (unsigned long long)ret_val);
                        } else {
                            LOGI("  Modified to: 0x%llx", (unsigned long long)ret_val);
                        }
                    }
                }
                lua_pop(L, 1);
            } else {
                LOGE("Java hook onLeave callback failed: %s", lua_tostring(L, -1));
                lua_pop(L, 1);
            }
        }
        lua_vm_unlock();
    }

    java_hook_set_return_string(NULL);

    if (g_hook_call_stack.depth > 0) {
        g_hook_call_stack.depth--;
        if (g_hook_call_stack.depth > 0) {
            g_current_java_hook_index = g_hook_call_stack.hook_indices[g_hook_call_stack.depth - 1];
        } else {
            g_current_java_hook_index = -1;
        }
    }

    return ret_val;
}


int java_hook_init(JNIEnv* env) {
    if (g_java_hook_initialized) {
        return 0;
    }

    pthread_mutex_lock(&g_java_hook_mutex);

    if (g_java_hook_initialized) {
        pthread_mutex_unlock(&g_java_hook_mutex);
        return 0;
    }

    get_art_method_offsets();

    memset(g_java_hooks, 0, sizeof(g_java_hooks));
    g_java_hook_count = 0;

    if (!g_interpreter_bridge) {
        g_interpreter_bridge = find_interpreter_bridge(env);
        if (g_interpreter_bridge) {
            LOGI("Interpreter bridge found during init: %p", g_interpreter_bridge);
        } else {
            LOGW("Interpreter bridge not found during init - will try again later");
        }
    }

    g_java_hook_initialized = true;

    pthread_mutex_unlock(&g_java_hook_mutex);

    LOGI("Java hook subsystem initialized (API %d)", get_android_api_level());
    return 0;
}

int install_java_hook(JNIEnv* env,
                      const char* class_name,
                      const char* method_name,
                      const char* signature,
                      int onEnter_ref,
                      int onLeave_ref) {

    if (!env) {
        LOGE("JNIEnv is NULL");
        return -1;
    }

    java_hook_init(env);
    java_hook_set_error("%s", "");

    pthread_mutex_lock(&g_java_hook_mutex);

    if (g_java_hook_count >= MAX_JAVA_HOOKS) {
        LOGE("Maximum Java hooks reached (%d)", MAX_JAVA_HOOKS);
        pthread_mutex_unlock(&g_java_hook_mutex);
        return -1;
    }

    LOGI("Installing Java hook: %s.%s%s", class_name, method_name, signature);

    char java_class_name[256];
    strncpy(java_class_name, class_name, sizeof(java_class_name) - 1);
    java_class_name[sizeof(java_class_name) - 1] = '\0';
    for (char* p = java_class_name; *p; p++) {
        if (*p == '/') *p = '.';
    }

    // FindClass wants slashes. A dotted name ("java.lang.String") is an
    // error there, and with CheckJNI on - every debuggable app - that error
    // aborts the process instead of returning NULL.
    char jni_class_name[256];
    strncpy(jni_class_name, class_name, sizeof(jni_class_name) - 1);
    jni_class_name[sizeof(jni_class_name) - 1] = '\0';
    for (char* p = jni_class_name; *p; p++) {
        if (*p == '.') *p = '/';
    }

    jclass clazz = (*env)->FindClass(env, jni_class_name);

    if (!clazz || (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        LOGI("FindClass failed, trying application ClassLoader for: %s", java_class_name);

        jclass activity_thread_class = (*env)->FindClass(env, "android/app/ActivityThread");
        if (!activity_thread_class) {
            LOGE("Failed to find ActivityThread class");
            (*env)->ExceptionClear(env);
            pthread_mutex_unlock(&g_java_hook_mutex);
            return -1;
        }

        jmethodID current_application_method = (*env)->GetStaticMethodID(env, activity_thread_class,
            "currentApplication", "()Landroid/app/Application;");
        if (!current_application_method) {
            LOGE("Failed to find currentApplication method");
            (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, activity_thread_class);
            pthread_mutex_unlock(&g_java_hook_mutex);
            return -1;
        }

        jobject application = (*env)->CallStaticObjectMethod(env, activity_thread_class, current_application_method);
        (*env)->DeleteLocalRef(env, activity_thread_class);

        if (!application) {
            LOGE("currentApplication() returned null");
            (*env)->ExceptionClear(env);
            pthread_mutex_unlock(&g_java_hook_mutex);
            return -1;
        }

        jclass context_class = (*env)->FindClass(env, "android/content/Context");
        jmethodID get_classloader_method = (*env)->GetMethodID(env, context_class,
            "getClassLoader", "()Ljava/lang/ClassLoader;");
        (*env)->DeleteLocalRef(env, context_class);

        jobject classloader = (*env)->CallObjectMethod(env, application, get_classloader_method);
        (*env)->DeleteLocalRef(env, application);

        if (!classloader) {
            LOGE("getClassLoader() returned null");
            (*env)->ExceptionClear(env);
            pthread_mutex_unlock(&g_java_hook_mutex);
            return -1;
        }

        jclass classloader_class = (*env)->FindClass(env, "java/lang/ClassLoader");
        jmethodID load_class_method = (*env)->GetMethodID(env, classloader_class,
            "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        (*env)->DeleteLocalRef(env, classloader_class);

        jstring class_name_str = (*env)->NewStringUTF(env, java_class_name);
        clazz = (jclass)(*env)->CallObjectMethod(env, classloader, load_class_method, class_name_str);
        (*env)->DeleteLocalRef(env, class_name_str);
        (*env)->DeleteLocalRef(env, classloader);

        if (!clazz || (*env)->ExceptionCheck(env)) {
            LOGE("Class not found via application ClassLoader: %s", java_class_name);
            java_hook_set_error("class %s not found", java_class_name);
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            pthread_mutex_unlock(&g_java_hook_mutex);
            return -1;
        }

        LOGI("Class loaded via application ClassLoader: %s", java_class_name);
    }

    jmethodID method_id = (*env)->GetMethodID(env, clazz, method_name, signature);
    bool is_static = false;

    if (!method_id) {
        (*env)->ExceptionClear(env);
        method_id = (*env)->GetStaticMethodID(env, clazz, method_name, signature);
        if (method_id) {
            is_static = true;
        }
    }

    if (!method_id) {
        LOGE("Method not found: %s.%s%s", class_name, method_name, signature);
        java_hook_set_error("method %s%s not found in %s", method_name, signature, class_name);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, clazz);
        pthread_mutex_unlock(&g_java_hook_mutex);
        return -1;
    }

    LOGI("Found method: %s (jmethodID=%p, static=%d)", method_name, method_id, is_static);

    void* art_method = jmethodid_to_art_method(env, method_id, clazz);
    if (!art_method) {
        LOGE("Failed to get ArtMethod pointer");
        (*env)->DeleteLocalRef(env, clazz);
        pthread_mutex_unlock(&g_java_hook_mutex);
        return -1;
    }

    LOGI("ArtMethod pointer: %p", art_method);

    // Preferred engine: the method becomes a real JNI native method and the
    // original runs through a copy (java_jni.c). Everything below is the
    // original engine, kept for devices where that one cannot be set up.
    {
        int jni_index = java_jni_install(env, clazz, method_id, art_method, is_static,
                                         class_name, method_name, signature,
                                         onEnter_ref, onLeave_ref);
        if (jni_index != -1) {
            (*env)->DeleteLocalRef(env, clazz);
            pthread_mutex_unlock(&g_java_hook_mutex);
            return jni_index < 0 ? -1 : jni_index;
        }
        LOGW("JNI hook engine unavailable, using the trampoline engine for %s.%s", class_name, method_name);
    }

    const ArtMethodOffsets* offsets = get_art_method_offsets();

    void** entry_point_ptr = (void**)((uintptr_t)art_method + offsets->entry_point_offset);

    void* page = (void*)((uintptr_t)entry_point_ptr & ~(PAGE_SIZE - 1));
    if (mprotect(page, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        LOGE("Failed to change page protection: %s", strerror(errno));
        (*env)->DeleteLocalRef(env, clazz);
        pthread_mutex_unlock(&g_java_hook_mutex);
        return -1;
    }

    void* original_entry = *entry_point_ptr;
    LOGI("Original entry point: %p", original_entry);

    uint32_t* access_flags_ptr = (uint32_t*)((uintptr_t)art_method + offsets->access_flags_offset);
    uint32_t original_flags = *access_flags_ptr;
    bool need_nativize = false;

    LOGI("Original access_flags: 0x%x (native=%d)", original_flags, (original_flags & kAccNative) ? 1 : 0);

    if (original_entry == NULL || original_entry == (void*)0) {
        LOGI("Entry point is NULL - method not JIT compiled, using nativization approach");

        void* bridge = find_interpreter_bridge(env);
        if (bridge) {
            LOGI("Found interpreter bridge: %p", bridge);
            original_entry = bridge;
        }

        if (original_entry == NULL || original_entry == (void*)0) {
            jclass system_class = (*env)->FindClass(env, "java/lang/System");
            if (system_class) {
                jmethodID arraycopy = (*env)->GetStaticMethodID(env, system_class,
                    "arraycopy", "(Ljava/lang/Object;ILjava/lang/Object;II)V");
                if (arraycopy) {
                    void* arraycopy_art = jmethodid_to_art_method(env, arraycopy, system_class);
                    if (arraycopy_art) {
                        void** arraycopy_entry_ptr = (void**)((uintptr_t)arraycopy_art + offsets->entry_point_offset);
                        void* arraycopy_entry = *arraycopy_entry_ptr;
                        if (arraycopy_entry && arraycopy_entry != (void*)0) {
                            LOGI("Found entry point from System.arraycopy (native): %p", arraycopy_entry);
                        }
                    }
                }
                (*env)->DeleteLocalRef(env, system_class);
            }

            jclass runtime_class = (*env)->FindClass(env, "java/lang/Runtime");
            if (runtime_class) {
                jmethodID gc = (*env)->GetMethodID(env, runtime_class, "gc", "()V");
                if (gc) {
                    void* gc_art = jmethodid_to_art_method(env, gc, runtime_class);
                    if (gc_art) {
                        void** gc_entry_ptr = (void**)((uintptr_t)gc_art + offsets->entry_point_offset);
                        void* gc_entry = *gc_entry_ptr;
                        if (gc_entry && gc_entry != (void*)0) {
                            LOGI("Found entry point from Runtime.gc (native): %p", gc_entry);
                        }
                    }
                }
                (*env)->DeleteLocalRef(env, runtime_class);
            }
        }

        if (original_entry == NULL || original_entry == (void*)0) {
            LOGI("No interpreter bridge found, will nativize method (callbacks only mode)");
            need_nativize = true;
            original_entry = (void*)nativized_method_stub;
            LOGI("Using nativized_method_stub as fallback original: %p", original_entry);
        }
    }

    int hook_index = g_java_hook_count;
    JavaHookInfo* hook = &g_java_hooks[hook_index];

    strncpy(hook->class_name, class_name, sizeof(hook->class_name) - 1);
    strncpy(hook->method_name, method_name, sizeof(hook->method_name) - 1);
    strncpy(hook->method_sig, signature, sizeof(hook->method_sig) - 1);
    hook->is_static = is_static;
    hook->art_method = art_method;
    hook->original_entry_point = original_entry;
    hook->lua_onEnter_ref = onEnter_ref;
    hook->lua_onLeave_ref = onLeave_ref;
    hook->hook_index = hook_index;
    hook->original_access_flags = original_flags;
    hook->was_nativized = need_nativize;

    hook->clazz_global_ref = (*env)->NewGlobalRef(env, clazz);
    hook->method_id = method_id;
    hook->stored_return_value = 0;
    hook->has_stored_return = false;

    void* trampoline = create_java_hook_trampoline(hook_index);
    if (!trampoline) {
        LOGE("Failed to create trampoline");
        (*env)->DeleteLocalRef(env, clazz);
        pthread_mutex_unlock(&g_java_hook_mutex);
        return -1;
    }

    hook->hook_trampoline = trampoline;

    int api = get_android_api_level();
    if (api >= 30 && !(original_flags & kAccNative)) {
        LOGI("Setting kAccNative flag for proper hook on API %d (0x%x -> 0x%x)",
             api, original_flags, original_flags | kAccNative);
        *access_flags_ptr = original_flags | kAccNative;
        __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);
        hook->was_nativized = true;

        LOGI("Method was nativized - will use JNI reflection to call original (nested hooks supported)");
    } else if (need_nativize) {
        LOGI("Nativizing method: setting kAccNative flag (0x%x -> 0x%x)",
             original_flags, original_flags | kAccNative);
        *access_flags_ptr = original_flags | kAccNative;
        __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);
    }


    LOGI("Setting entry_point: %p -> %p", *entry_point_ptr, trampoline);
    *entry_point_ptr = trampoline;
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    void* verify = *entry_point_ptr;
    if (verify == trampoline) {
        LOGI("Entry point successfully changed to trampoline");
    } else {
        LOGE("Entry point write FAILED! Expected %p, got %p", trampoline, verify);
    }

    hook->is_hooked = true;
    g_java_hook_count++;

    (*env)->DeleteLocalRef(env, clazz);
    pthread_mutex_unlock(&g_java_hook_mutex);

    LOGI("Java hook #%d installed: %s.%s%s (onEnter=%d, onLeave=%d)",
         hook_index, class_name, method_name, signature, onEnter_ref, onLeave_ref);
    return hook_index;
}

int uninstall_java_hook(int hook_index) {
    if (hook_index < 0 || hook_index >= g_java_hook_count) {
        LOGE("Invalid hook index: %d", hook_index);
        return -1;
    }

    pthread_mutex_lock(&g_java_hook_mutex);

    JavaHookInfo* hook = &g_java_hooks[hook_index];

    if (!hook->is_hooked) {
        LOGI("Hook %d already uninstalled", hook_index);
        pthread_mutex_unlock(&g_java_hook_mutex);
        return 0;
    }

    if (hook->engine == JAVA_HOOK_ENGINE_JNI) {
        if (java_jni_uninstall(hook_index) != 0) {
            pthread_mutex_unlock(&g_java_hook_mutex);
            return -1;
        }
        hook->hook_trampoline = NULL;   // owned by java_jni.c, never unmapped
        goto release_callbacks;
    }

    const ArtMethodOffsets* offsets = get_art_method_offsets();
    void** entry_point_ptr = (void**)((uintptr_t)hook->art_method + offsets->entry_point_offset);

    void* page = (void*)((uintptr_t)entry_point_ptr & ~(PAGE_SIZE - 1));
    if (mprotect(page, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        LOGE("Failed to change page protection for unhook: %s", strerror(errno));
        pthread_mutex_unlock(&g_java_hook_mutex);
        return -1;
    }

    if (hook->was_nativized) {
        uint32_t* access_flags_ptr = (uint32_t*)((uintptr_t)hook->art_method + offsets->access_flags_offset);
        LOGI("Restoring original access_flags: 0x%x", hook->original_access_flags);
        *access_flags_ptr = hook->original_access_flags;
        __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);
    }

    *entry_point_ptr = hook->original_entry_point;
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    if (hook->hook_trampoline) {
        munmap(hook->hook_trampoline, PAGE_SIZE);
        hook->hook_trampoline = NULL;
    }

release_callbacks:
    // Same rationale as native.c's uninstall_hook(): this runs on the
    // connection/command thread, outside any script's lua_pcall, so it must
    // take the VM lock itself before touching the Lua registry.
    if (g_lua_engine) {
        lua_vm_lock();
        lua_State* L = lua_engine_get_state(g_lua_engine);
        if (L) {
            if (hook->lua_onEnter_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, hook->lua_onEnter_ref);
            }
            if (hook->lua_onLeave_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, hook->lua_onLeave_ref);
            }
        }
        lua_vm_unlock();
    }

    hook->lua_onEnter_ref = LUA_NOREF;
    hook->lua_onLeave_ref = LUA_NOREF;
    hook->is_hooked = false;

    pthread_mutex_unlock(&g_java_hook_mutex);

    LOGI("Java hook #%d uninstalled", hook_index);
    return 0;
}

int uninstall_all_java_hooks(void) {
    int count = 0;
    for (int i = 0; i < g_java_hook_count; i++) {
        if (g_java_hooks[i].is_hooked) {
            if (uninstall_java_hook(i) == 0) {
                count++;
            }
        }
    }
    LOGI("Uninstalled %d Java hooks", count);
    return count;
}

void* get_java_hook_original_entry(int hook_index) {
    if (hook_index < 0 || hook_index >= g_java_hook_count) {
        return NULL;
    }
    return g_java_hooks[hook_index].original_entry_point;
}
