/*
 * Java method hooks that ART can walk past.
 *
 * The first engine (java.c) pointed a hooked method's entry at a block of
 * code of its own and called the original method from inside that block.
 * ART knows nothing about those frames. Whenever it had to walk the stack
 * while one of them was on it - to fill in the stack trace of an exception,
 * to find a catch handler, to visit references during a collection - it read
 * garbage where it expected a managed frame and crashed
 * (StackVisitor::WalkStack). Hooking File.exists() and calling it on a
 * missing file was enough: the original throws an ErrnoException inside.
 *
 * This engine never puts a frame on the stack that ART cannot walk. For
 * every hooked method there are two more method records:
 *
 *   the twin  A native method with the hooked method's class, name and
 *             signature, whose JNI function is a stub of ours and whose
 *             entry point is ART's own generic JNI entry code. The hooked
 *             method's entry point becomes three instructions that load the
 *             twin and jump to its entry. ART then builds the transition
 *             frame for the twin, hands our stub JNI arguments (JNIEnv*,
 *             this/class, the parameters where the C calling convention
 *             puts them, references as jobjects), and knows how to walk
 *             that frame because the twin really is a native method.
 *
 *   the copy  The method as it was, entry point included. The original code
 *             is run through it with a plain JNI call. The hook stays in
 *             place while the original runs, and an exception the original
 *             throws stays pending and reaches the caller the normal way.
 *
 * The hooked method itself keeps its kind: a managed method stays managed.
 * That matters for threads that are inside it at the moment the hook goes in
 * or comes out - their frames are still what ART expects them to be. (An
 * earlier version turned the hooked method itself into a native method; a
 * thread that was in the middle of a call when the hook was removed then
 * had a frame ART could no longer interpret.)
 *
 * Twin and copy live in method slots of a helper class loaded from a dex
 * file in memory (agent/slots_dex.h), because the collector only updates
 * class references it can find, and the method array of a real class is
 * where it looks.
 */

#include <jni.h>
#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <lauxlib.h>

#include <agent/globals.h>
#include <agent/hook_java.h>
#include <agent/slots_dex.h>

#define TAG "RENEF_JHOOK"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/* ---- ART access flags (the ones this file touches) ---------------------- */

#define ACC_NATIVE                 0x00000100u
#define ACC_ABSTRACT               0x00000400u
/* Bits whose meaning depends on ACC_NATIVE. On an ordinary method they are
 * "skip access checks" and the nterp fast-path flags; once the method is
 * native the same bits say @FastNative / @CriticalNative, i.e. "call the JNI
 * function without the usual transition" and "without JNIEnv and class".
 * They have to go, or our stub is called with the wrong arguments. */
#define ACC_FAST_NATIVE_OR_SKIP    0x00080000u
#define ACC_NTERP_ENTRY_OR_CRIT    0x00100000u
#define ACC_NTERP_INVOKE_OR_CRIT   0x00200000u
#define ACC_PRE_COMPILED           0x00800000u
#define ACC_COMPILE_DONT_BOTHER    0x02000000u
#define ACC_SINGLE_IMPLEMENTATION  0x08000000u
#define ACC_FAST_INTERP_INVOKE     0x40000000u
#define ACC_INTRINSIC              0x80000000u

/* ---- signatures --------------------------------------------------------- */

#define JJ_MAX_ARGS 32

typedef struct {
    char ret;                   /* V Z B C S I J F D L (arrays count as L) */
    bool ret_is_string;
    int nargs;
    char types[JJ_MAX_ARGS];
} JjSig;

static const char* skip_type(const char* p, char* out) {
    char c = *p;
    if (c == '[') {
        while (*p == '[') p++;
        if (*p == 'L') {
            while (*p && *p != ';') p++;
        }
        if (!*p) return NULL;
        *out = 'L';
        return p + 1;
    }
    if (c == 'L') {
        while (*p && *p != ';') p++;
        if (!*p) return NULL;
        *out = 'L';
        return p + 1;
    }
    if (c && strchr("ZBCSIJFDV", c)) {
        *out = c;
        return p + 1;
    }
    return NULL;
}

static bool parse_signature(const char* sig, JjSig* out) {
    memset(out, 0, sizeof(*out));
    if (!sig || sig[0] != '(') return false;
    const char* p = sig + 1;
    while (*p && *p != ')') {
        char t;
        p = skip_type(p, &t);
        if (!p || t == 'V' || out->nargs >= JJ_MAX_ARGS) return false;
        out->types[out->nargs++] = t;
    }
    if (*p != ')') return false;
    out->ret_is_string = strcmp(p + 1, "Ljava/lang/String;") == 0;
    p = skip_type(p + 1, &out->ret);
    return p != NULL && *p == '\0';
}

/* ---- per-hook state ----------------------------------------------------- */

typedef struct {
    bool used;
    void* backup;               /* slot: the method as it was */
    void* twin;                 /* slot: native method our stub is the JNI function of */
    void* stub;                 /* JNI function of the twin */
    void* entry;                /* what the hooked method's entry point is set to */
    void* orig_entry;
    uint32_t orig_flags;
    JjSig sig;
} JjHook;

static JjHook g_jj[MAX_JAVA_HOOKS];

/* ---- one-time setup ----------------------------------------------------- */

#define JJ_SLOTS (MAX_JAVA_HOOKS * 2)   /* copy and twin for every hook */

static int g_init_state = 0;            /* 0 not tried, 1 ready, -1 unavailable */
static void* g_slots[JJ_SLOTS];
static void* g_generic_jni_entry = NULL;
static void* g_interpreter_bridge = NULL;
static void* g_unbound_jni = NULL;
static unsigned char* g_stub_page = NULL;
#define JJ_CODE_PER_HOOK 48     /* JNI stub (24 bytes) + entry point code (24 bytes) */
#define JJ_CODE_BYTES ((size_t)MAX_JAVA_HOOKS * JJ_CODE_PER_HOOK)

typedef void (*SuspendAllCtor)(void* self, const char* cause, bool long_suspend);
typedef void (*SuspendAllDtor)(void* self);
static SuspendAllCtor g_suspend_all = NULL;
static SuspendAllDtor g_resume_all = NULL;

static size_t data_offset(const ArtMethodOffsets* o) {
    return o->entry_point_offset - sizeof(void*);   /* data_ sits right before the entry point */
}

static bool make_writable(void* addr, size_t len) {
    uintptr_t start = (uintptr_t)addr & ~((uintptr_t)PAGE_SIZE - 1);
    uintptr_t end = ((uintptr_t)addr + len + PAGE_SIZE - 1) & ~((uintptr_t)PAGE_SIZE - 1);
    return mprotect((void*)start, end - start, PROT_READ | PROT_WRITE) == 0;
}

static jclass load_slots_class(JNIEnv* env) {
    jclass result = NULL;
    jobject buf = (*env)->NewDirectByteBuffer(env, (void*)slots_dex, slots_dex_len);
    jclass loader_class = (*env)->FindClass(env, "dalvik/system/InMemoryDexClassLoader");
    if (buf && loader_class) {
        jmethodID ctor = (*env)->GetMethodID(env, loader_class, "<init>",
            "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
        jmethodID load = (*env)->GetMethodID(env, loader_class, "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;");
        jobject loader = ctor ? (*env)->NewObject(env, loader_class, ctor, buf, NULL) : NULL;
        jstring name = (*env)->NewStringUTF(env, "com.renef.lab.Slots");
        if (loader && load && name) {
            jclass cls = (jclass)(*env)->CallObjectMethod(env, loader, load, name);
            if (cls && !(*env)->ExceptionCheck(env)) {
                result = (jclass)(*env)->NewGlobalRef(env, cls);
                /* The loader is what keeps the class (and with it the slots)
                 * alive for as long as the process runs. */
                (*env)->NewGlobalRef(env, loader);
            }
        }
    }
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }
    return result;
}

static int jj_init(JNIEnv* env) {
    if (g_init_state != 0) return g_init_state;
    g_init_state = -1;

    const ArtMethodOffsets* off = get_art_method_offsets();
    if (!off || off->art_method_size == 0) {
        LOGW("unknown ArtMethod layout");
        return -1;
    }

    jclass slots = load_slots_class(env);
    if (!slots) {
        LOGW("could not load the slot class");
        return -1;
    }

    for (int i = 0; i < JJ_SLOTS; i++) {
        char name[16];
        snprintf(name, sizeof(name), "s%d", i);
        /* An instance native method without compiled code has ART's
         * generic JNI entry code as its entry point from the moment the
         * class is linked. (A static one keeps the class-resolution entry
         * code until the class is visibly initialised.) */
        jmethodID mid = (*env)->GetMethodID(env, slots, name, "()V");
        void* art = mid ? jmethodid_to_art_method(env, mid, slots) : NULL;
        if (!art) {
            (*env)->ExceptionClear(env);
            LOGW("slot %d not found", i);
            return -1;
        }
        g_slots[i] = art;
    }

    /* ART's generic JNI entry code is what a native method without a
     * compiled stub is entered through. The slots themselves do not show
     * it: in an app that is not debuggable ART hands a new native method
     * the stub its boot image holds for that kind of signature, and such a
     * stub passes the arguments of that signature only (an instance "()V"
     * stub in front of a static method with seven ints shifted every
     * argument by one). The two probe methods have signatures no boot image
     * method has, and different ones: what they share is the generic code. */
    static const char* const probe_names[2] = { "probeA", "probeB" };
    static const char* const probe_sigs[2] = {
        "(DJFILjava/lang/Object;DJFILjava/lang/Object;DJFILjava/lang/Object;SBCZDJ)D",
        "(Ljava/lang/Object;FJDILjava/lang/Object;FJDICSBZLjava/lang/Object;FJDI)J",
    };
    void* probe_entry[2] = { NULL, NULL };
    void* probe_data[2] = { NULL, NULL };
    uint32_t probe_flags[2] = { 0, 0 };
    for (int i = 0; i < 2; i++) {
        jmethodID mid = (*env)->GetMethodID(env, slots, probe_names[i], probe_sigs[i]);
        void* art = mid ? jmethodid_to_art_method(env, mid, slots) : NULL;
        if (!art) {
            (*env)->ExceptionClear(env);
            LOGW("%s not found in the slot class", probe_names[i]);
            return -1;
        }
        probe_entry[i] = *(void**)((uintptr_t)art + off->entry_point_offset);
        probe_data[i] = *(void**)((uintptr_t)art + data_offset(off));
        probe_flags[i] = *(uint32_t*)((uintptr_t)art + off->access_flags_offset);
    }
    if (!probe_entry[0] || probe_entry[0] != probe_entry[1] ||
        !(probe_flags[0] & ACC_NATIVE) || !(probe_flags[1] & ACC_NATIVE)) {
        LOGW("cannot tell where the generic JNI entry code is (probe entries %p/%p, flags 0x%x/0x%x)",
             probe_entry[0], probe_entry[1], probe_flags[0], probe_flags[1]);
        return -1;
    }
    g_generic_jni_entry = probe_entry[0];
    /* Nobody registered a function for the probes, so what their JNI slot
     * holds is ART's "look the symbol up on the first call" stub: the mark
     * of a native method that is not bound to its function yet. */
    g_unbound_jni = (probe_data[0] == probe_data[1]) ? probe_data[0] : NULL;
    LOGI("generic JNI entry %p (a plain slot has %p)", g_generic_jni_entry,
         *(void**)((uintptr_t)g_slots[0] + off->entry_point_offset));

    {
        char sig[320];
        memset(sig, 'I', 251);
        sig[0] = '(';
        memcpy(sig + 251, ")I", 3);
        jmethodID mid = (*env)->GetMethodID(env, slots, "interpreted", sig);
        void* art = mid ? jmethodid_to_art_method(env, mid, slots) : NULL;
        if (art) {
            g_interpreter_bridge = *(void**)((uintptr_t)art + off->entry_point_offset);
            /* That is the bridge only while the method cannot run in the
             * fast interpreter ("nterp"), whose entry code must not be
             * handed an arbitrary method. Ask ART when it can be asked. */
            typedef bool (*CanUseNterp)(void* method, int instruction_set);
            CanUseNterp can_use = (CanUseNterp)java_libart_symbol("_ZN3art17CanMethodUseNterpEPNS_9ArtMethodENS_14InstructionSetE");
            if ((can_use && can_use(art, 2 /* InstructionSet::kArm64 */)) || g_interpreter_bridge == g_generic_jni_entry) {
                LOGW("the probe method does not show the interpreter bridge (entry %p): "
                     "copies of JIT-compiled methods keep their entry point", g_interpreter_bridge);
                g_interpreter_bridge = NULL;
            }
        } else {
            (*env)->ExceptionClear(env);
            LOGW("interpreter bridge not found: copies of JIT-compiled methods keep their entry point");
        }
    }

    g_suspend_all = (SuspendAllCtor)java_libart_symbol("_ZN3art16ScopedSuspendAllC2EPKcb");
    g_resume_all = (SuspendAllDtor)java_libart_symbol("_ZN3art16ScopedSuspendAllD2Ev");
    if (!g_suspend_all || !g_resume_all) {
        g_suspend_all = NULL;
        g_resume_all = NULL;
        LOGW("ScopedSuspendAll not found: methods are patched without stopping other threads");
    }

    g_stub_page = mmap(NULL, JJ_CODE_BYTES, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_stub_page == MAP_FAILED) {
        g_stub_page = NULL;
        LOGW("could not allocate stub memory: %s", strerror(errno));
        return -1;
    }

    LOGI("ready: %d slots, generic JNI entry %p, interpreter bridge %p, suspend-all %s",
         JJ_SLOTS, g_generic_jni_entry, g_interpreter_bridge, g_suspend_all ? "yes" : "no");
    g_init_state = 1;
    return 1;
}

/* True if `addr` lies in ART's JIT code cache. Code there belongs to the
 * method it was compiled for and is freed once it is no longer that
 * method's entry point - which is exactly what hooking does to it. */
static bool in_jit_code_cache(void* addr) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) continue;
        if ((uintptr_t)addr < start || (uintptr_t)addr >= end) continue;
        found = strstr(line, "jit-cache") || strstr(line, "jit-code-cache") ||
                strstr(line, "jit-zygote-cache");
        break;
    }
    fclose(fp);
    return found;
}

/* ---- making freshly initialised classes "visibly initialised" ------------ */

static bool read_mem(const void* addr, void* out, size_t len) {
    static int fd = -1;
    if (fd < 0) fd = agent_open_self_mem(O_RDONLY);
    /* Heap pointers carry a tag in their top byte; the file offset must not. */
    uintptr_t untagged = (uintptr_t)addr & 0x00FFFFFFFFFFFFFFULL;
    return fd >= 0 && pread(fd, out, len, (off_t)untagged) == (ssize_t)len;
}

/* ART keeps no exported accessor for its ClassLinker. It is a field of the
 * Runtime object, a fixed number of fields before the JavaVM pointer (how
 * many depends on the release), directly after the intern table - which the
 * ClassLinker also points to, and that is what a candidate is checked
 * against before it is used. */
static void* find_class_linker(JNIEnv* env) {
    void** instance = (void**)java_libart_symbol("_ZN3art7Runtime9instance_E");
    void* runtime = NULL;
    JavaVM* vm = NULL;
    if (!instance || !read_mem(instance, &runtime, sizeof(runtime)) || !runtime) return NULL;
    if ((*env)->GetJavaVM(env, &vm) != JNI_OK || !vm) return NULL;

    void* fields[512];
    if (!read_mem(runtime, fields, sizeof(fields))) return NULL;
    for (int j = 6; j < 512; j++) {
        if (fields[j] != (void*)vm) continue;
        static const int back[] = { 4, 3, 2, 5 };
        for (size_t k = 0; k < sizeof(back) / sizeof(back[0]); k++) {
            void* linker = fields[j - back[k]];
            void* intern_table = fields[j - back[k] - 1];
            void* body[128];
            if (!linker || !intern_table || ((uintptr_t)linker & 7) || !read_mem(linker, body, sizeof(body))) continue;
            for (int m = 0; m < 128; m++) {
                if (body[m] == intern_table) return linker;
            }
        }
    }
    return NULL;
}

static void make_classes_visibly_initialized(JNIEnv* env) {
    typedef void (*Fn)(void* class_linker, void* self, bool wait);
    static int state = 0;           /* 0 not tried, 1 usable, -1 not available */
    static Fn fn = NULL;
    static void* linker = NULL;
    if (state == 0) {
        fn = (Fn)java_libart_symbol("_ZN3art11ClassLinker40MakeInitializedClassesVisiblyInitializedEPNS_6ThreadEb");
        linker = fn ? find_class_linker(env) : NULL;
        state = (fn && linker) ? 1 : -1;
        if (state > 0) {
            LOGI("class linker at %p", linker);
        } else {
            LOGW("cannot ask ART to finish class initialisation (fn=%p linker=%p): a static method "
                 "hooked right after its class was initialised may lose its hook", (void*)fn, linker);
        }
    }
    if (state == 1) {
        void* self = ((void**)env)[1];      /* JNIEnvExt::self_ */
        if (self) fn(linker, self, true);
    }
}

/* ---- entry stubs -------------------------------------------------------- */

void jj_dispatch(uint64_t hook_index, uint64_t* regs, uint64_t* stack_args, uint64_t* result);

/* Common entry. A per-hook stub loads the hook index into x17 and branches
 * here. This is an ordinary C-ABI function as far as ART is concerned: it is
 * called through the JNI transition, so nothing ever unwinds through it. */
__attribute__((naked)) static void jj_entry(void) {
    __asm__(
        "stp x29, x30, [sp, #-16]!\n"
        "mov x29, sp\n"
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp d0, d1, [sp, #64]\n"
        "stp d2, d3, [sp, #80]\n"
        "stp d4, d5, [sp, #96]\n"
        "stp d6, d7, [sp, #112]\n"
        "stp xzr, xzr, [sp, #128]\n"
        "mov x0, x17\n"             /* hook index */
        "mov x1, sp\n"              /* x0-x7 then d0-d7 */
        "add x2, x29, #16\n"        /* arguments the caller passed on the stack */
        "add x3, sp, #128\n"        /* result: [0] integer/reference, [1] float/double */
        "bl jj_dispatch\n"
        "ldr x0, [sp, #128]\n"
        "ldr d0, [sp, #136]\n"
        "add sp, sp, #160\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n");
}

/* JNI function of a twin: load the hook index, go to the common entry. */
static void* make_stub(int hook_index) {
    uint32_t* code = (uint32_t*)(g_stub_page + (size_t)hook_index * JJ_CODE_PER_HOOK);
    code[0] = 0xD2800011u | (((uint32_t)hook_index & 0xFFFF) << 5);   /* movz x17, #index */
    code[1] = 0x58000050u;                                             /* ldr  x16, [pc, #8] */
    code[2] = 0xD61F0200u;                                             /* br   x16 */
    uint64_t target = (uint64_t)(uintptr_t)&jj_entry;
    memcpy(&code[3], &target, sizeof(target));
    __builtin___clear_cache((char*)code, (char*)code + 24);
    return code;
}

/* Entry point of a hooked method: the caller arrives with the hooked
 * method in x0 and the arguments in place. Swap in the twin and continue at
 * the twin's entry point - no frame, nothing for ART to walk. */
static void* make_entry(int hook_index, void* twin, size_t entry_offset) {
    uint32_t* code = (uint32_t*)(g_stub_page + (size_t)hook_index * JJ_CODE_PER_HOOK + 24);
    code[0] = 0x58000060u;                                             /* ldr x0, [pc, #12]   (the twin) */
    code[1] = 0xF9400010u | (((uint32_t)(entry_offset / 8) & 0xFFF) << 10);  /* ldr x16, [x0, #entry] */
    code[2] = 0xD61F0200u;                                             /* br  x16 */
    uint64_t lit = (uint64_t)(uintptr_t)twin;
    memcpy(&code[3], &lit, sizeof(lit));
    __builtin___clear_cache((char*)code, (char*)code + 24);
    return code;
}

/* ---- the call ----------------------------------------------------------- */

/* Managed references are 32 bits wide, so a raw object address is below
 * 4 GB; JNI references (stack slots, reference tables) are not. Scripts get
 * raw addresses, as they always did, and may hand either kind back. */
static jobject as_jobject(JNIEnv* env, uint64_t value) {
    if (value == 0) return NULL;
    if (value < 0x100000000ULL) return raw_ptr_to_jni_ref(env, (void*)(uintptr_t)value);
    return (jobject)(uintptr_t)value;
}

static uint64_t as_raw(JNIEnv* env, jobject ref) {
    return ref ? (uint64_t)(uintptr_t)jni_ref_to_raw_ptr(env, ref) : 0;
}

void jj_dispatch(uint64_t hook_index, uint64_t* regs, uint64_t* stack_args, uint64_t* result) {
    result[0] = 0;
    result[1] = 0;
    if (hook_index >= MAX_JAVA_HOOKS || !g_jj[hook_index].used) return;

    JjHook* jj = &g_jj[hook_index];
    JavaHookInfo* hook = &g_java_hooks[hook_index];
    const JjSig* sig = &jj->sig;
    JNIEnv* env = (JNIEnv*)(uintptr_t)regs[0];
    jobject self = (jobject)(uintptr_t)regs[1];     /* `this`, or the class for a static method */
    const uint64_t* fpregs = regs + 8;

    /* Parameters, from where the C calling convention put them. */
    jvalue jargs[JJ_MAX_ARGS];
    int gp = 2, fp = 0, st = 0;
    for (int i = 0; i < sig->nargs; i++) {
        char t = sig->types[i];
        uint64_t v;
        if (t == 'F' || t == 'D') {
            v = (fp < 8) ? fpregs[fp++] : stack_args[st++];
        } else {
            v = (gp < 8) ? regs[gp++] : stack_args[st++];
        }
        memset(&jargs[i], 0, sizeof(jvalue));
        switch (t) {
            case 'Z': jargs[i].z = (jboolean)(v & 0xff); break;
            case 'B': jargs[i].b = (jbyte)v; break;
            case 'C': jargs[i].c = (jchar)v; break;
            case 'S': jargs[i].s = (jshort)v; break;
            case 'I': jargs[i].i = (jint)v; break;
            case 'J': jargs[i].j = (jlong)v; break;
            case 'F': { uint32_t bits = (uint32_t)v; memcpy(&jargs[i].f, &bits, 4); break; }
            case 'D': memcpy(&jargs[i].d, &v, 8); break;
            default:  jargs[i].l = (jobject)(uintptr_t)v; break;
        }
    }

    /* What the script sees: args[0] the method, then `this` (instance
     * methods) and the non-floating-point parameters in order - the layout
     * the callbacks have always had. References are given as raw addresses. */
    uint64_t seen[8] = {0};
    int param_of[8];
    for (int i = 0; i < 8; i++) param_of[i] = -1;
    int n_seen = 1;
    bool want_enter = hook->lua_onEnter_ref != LUA_NOREF;
    seen[0] = (uint64_t)(uintptr_t)hook->art_method;
    if (want_enter) {
        if (!hook->is_static) {
            seen[n_seen] = as_raw(env, self);
            param_of[n_seen++] = -2;
        }
        for (int i = 0; i < sig->nargs && n_seen < 8; i++) {
            char t = sig->types[i];
            if (t == 'F' || t == 'D') continue;
            switch (t) {
                case 'Z': seen[n_seen] = jargs[i].z; break;
                case 'B': seen[n_seen] = (uint32_t)(int32_t)jargs[i].b; break;
                case 'C': seen[n_seen] = jargs[i].c; break;
                case 'S': seen[n_seen] = (uint32_t)(int32_t)jargs[i].s; break;
                case 'I': seen[n_seen] = (uint32_t)jargs[i].i; break;
                case 'J': seen[n_seen] = (uint64_t)jargs[i].j; break;
                default:  seen[n_seen] = as_raw(env, jargs[i].l); break;
            }
            param_of[n_seen++] = i;
        }
    }

    uint64_t before[8];
    memcpy(before, seen, sizeof(before));

    java_hook_on_enter((int)hook_index, seen);
    bool skip = java_hook_skip_requested();

    for (int k = 1; k < n_seen; k++) {
        if (seen[k] == before[k]) continue;
        if (param_of[k] == -2) {
            self = as_jobject(env, seen[k]);
            continue;
        }
        int i = param_of[k];
        switch (sig->types[i]) {
            case 'Z': jargs[i].z = (jboolean)(seen[k] != 0); break;
            case 'B': jargs[i].b = (jbyte)seen[k]; break;
            case 'C': jargs[i].c = (jchar)seen[k]; break;
            case 'S': jargs[i].s = (jshort)seen[k]; break;
            case 'I': jargs[i].i = (jint)seen[k]; break;
            case 'J': jargs[i].j = (jlong)seen[k]; break;
            default:  jargs[i].l = as_jobject(env, seen[k]); break;
        }
    }

    /* The original, through its copy. */
    jmethodID original = (jmethodID)jj->backup;
    jclass cls = hook->clazz_global_ref;
    uint64_t raw = 0;
    float rf = 0;
    double rd = 0;
    jobject robj = NULL;

    if (!skip) {
#define CALL(Type) (hook->is_static \
        ? (*env)->CallStatic##Type##MethodA(env, cls, original, jargs) \
        : (*env)->CallNonvirtual##Type##MethodA(env, self, cls, original, jargs))
        switch (sig->ret) {
            case 'V': CALL(Void); break;
            case 'Z': raw = CALL(Boolean); break;
            case 'B': raw = (uint32_t)(int32_t)CALL(Byte); break;
            case 'C': raw = CALL(Char); break;
            case 'S': raw = (uint32_t)(int32_t)CALL(Short); break;
            case 'I': raw = (uint32_t)CALL(Int); break;
            case 'J': raw = (uint64_t)CALL(Long); break;
            case 'F': rf = CALL(Float); break;
            case 'D': rd = CALL(Double); break;
            default:  robj = CALL(Object); break;
        }
#undef CALL
        if ((*env)->ExceptionCheck(env)) {
            /* Left pending on purpose: ART delivers it to the caller when
             * this native method returns. onLeave is not run - there is no
             * return value, and JNI calls are off limits until then. */
            java_hook_abandon_call();
            return;
        }
    }

    if (sig->ret == 'F') { uint32_t bits; memcpy(&bits, &rf, 4); raw = bits; }
    else if (sig->ret == 'D') { memcpy(&raw, &rd, 8); }
    else if (sig->ret == 'L') { raw = as_raw(env, robj); }

    if (sig->ret_is_string && robj && hook->lua_onLeave_ref != LUA_NOREF) {
        const char* chars = (*env)->GetStringUTFChars(env, (jstring)robj, NULL);
        if (chars) {
            java_hook_set_return_string(strdup(chars));
            (*env)->ReleaseStringUTFChars(env, (jstring)robj, chars);
        }
    }

    uint64_t after = java_hook_on_leave((int)hook_index, raw);
    jobject replacement_obj = java_hook_take_return_object();

    switch (sig->ret) {
        case 'V': break;
        case 'F': case 'D':
            result[1] = after;
            break;
        case 'L':
            if (replacement_obj) {
                result[0] = (uint64_t)(uintptr_t)replacement_obj;
            } else {
                result[0] = (after == raw) ? (uint64_t)(uintptr_t)robj
                                           : (uint64_t)(uintptr_t)as_jobject(env, after);
            }
            break;
        case 'Z': result[0] = (after != 0); break;
        default:  result[0] = after; break;
    }
}

/* ---- install / uninstall ------------------------------------------------ */

static uint32_t* flags_of(void* method, const ArtMethodOffsets* off) {
    return (uint32_t*)((uintptr_t)method + off->access_flags_offset);
}
static void** data_of(void* method, const ArtMethodOffsets* off) {
    return (void**)((uintptr_t)method + data_offset(off));
}
static void** entry_of(void* method, const ArtMethodOffsets* off) {
    return (void**)((uintptr_t)method + off->entry_point_offset);
}

int java_jni_install(JNIEnv* env, jclass clazz, jmethodID method_id, void* art_method,
                     bool is_static, const char* class_name, const char* method_name,
                     const char* signature, int onEnter_ref, int onLeave_ref) {
    /* The access-flag values and the method layout used here are those of
     * Android 12 and later; older releases keep the original engine. */
    if (get_android_api_level() < 31) return -1;
    if (jj_init(env) != 1) return -1;

    JjSig sig;
    if (!parse_signature(signature, &sig)) {
        LOGW("signature not understood: %s", signature);
        return -1;
    }

    const ArtMethodOffsets* off = get_art_method_offsets();
    if (is_static) {
        /* A static method of a class that is initialised but not yet
         * "visibly initialised" still has the class-resolution code as its
         * entry point, and ART replaces that later - which would undo the
         * hook. Have ART finish that step now. */
        make_classes_visibly_initialized(env);
    }

    uint32_t flags = *flags_of(art_method, off);
    if (flags & ACC_ABSTRACT) {
        LOGE("%s.%s%s is abstract: there is no code to hook", class_name, method_name, signature);
        java_hook_set_error("%s.%s is abstract (an interface or abstract method has no code): "
                            "hook the method of the class that implements it", class_name, method_name);
        return -2;
    }

    int index = g_java_hook_count;
    if (index >= MAX_JAVA_HOOKS) return -2;
    for (int i = 0; i < g_java_hook_count; i++) {
        if (g_java_hooks[i].is_hooked && g_java_hooks[i].art_method == art_method) {
            LOGE("%s.%s%s is already hooked (j%d)", class_name, method_name, signature, i);
            java_hook_set_error("%s.%s%s is already hooked (j%d): remove that hook first", class_name, method_name, signature, i);
            return -2;
        }
    }

    void* backup = g_slots[index * 2];
    void* twin = g_slots[index * 2 + 1];
    if (!make_writable(art_method, off->art_method_size) ||
        !make_writable(backup, off->art_method_size) ||
        !make_writable(twin, off->art_method_size)) {
        LOGE("cannot make the method records writable: %s", strerror(errno));
        return -2;
    }

    JjHook* jj = &g_jj[index];
    memset(jj, 0, sizeof(*jj));
    jj->backup = backup;
    jj->twin = twin;
    jj->stub = make_stub(index);
    jj->entry = make_entry(index, twin, off->entry_point_offset);
    jj->sig = sig;
    jj->orig_flags = flags;
    jj->orig_entry = *entry_of(art_method, off);

    JavaHookInfo* hook = &g_java_hooks[index];
    memset(hook, 0, sizeof(*hook));
    strncpy(hook->class_name, class_name, sizeof(hook->class_name) - 1);
    strncpy(hook->method_name, method_name, sizeof(hook->method_name) - 1);
    strncpy(hook->method_sig, signature, sizeof(hook->method_sig) - 1);
    hook->is_static = is_static;
    hook->art_method = art_method;
    hook->original_entry_point = jj->orig_entry;
    hook->hook_trampoline = jj->entry;
    hook->lua_onEnter_ref = onEnter_ref;
    hook->lua_onLeave_ref = onLeave_ref;
    hook->hook_index = index;
    hook->original_access_flags = flags;
    hook->was_nativized = true;
    hook->clazz_global_ref = (*env)->NewGlobalRef(env, clazz);
    hook->method_id = method_id;
    hook->engine = JAVA_HOOK_ENGINE_JNI;

    bool intrinsic = (flags & ACC_INTRINSIC) != 0;
    bool native = (flags & ACC_NATIVE) != 0;

    /* The twin: same class, name and signature, but a native method with
     * the ordinary JNI calling convention. */
    uint32_t twin_flags;
    if (intrinsic) {
        /* For an intrinsic the upper bits hold its number, not flags. */
        twin_flags = (flags & 0x000FFFFFu & ~ACC_FAST_NATIVE_OR_SKIP) | ACC_NATIVE | ACC_COMPILE_DONT_BOTHER;
    } else {
        twin_flags = (flags & ~(ACC_FAST_NATIVE_OR_SKIP | ACC_NTERP_ENTRY_OR_CRIT | ACC_NTERP_INVOKE_OR_CRIT |
                                ACC_PRE_COMPILED | ACC_SINGLE_IMPLEMENTATION | ACC_FAST_INTERP_INVOKE))
                     | ACC_NATIVE | ACC_COMPILE_DONT_BOTHER;
    }

    /* The copy keeps the original's entry point unless ART could not cope
     * with that:
     *  - a native method may be entered through a compiled JNI stub that ART
     *    looks up by method when it walks the stack. The copy is not the
     *    method that stub is registered for, so it goes through the generic
     *    JNI entry code, which needs no lookup;
     *  - JIT-compiled code is freed when it stops being its method's entry
     *    point. The copy runs the method from its bytecode instead. */
    void* backup_entry = jj->orig_entry;
    if (native) {
        backup_entry = g_generic_jni_entry;
    } else if (g_interpreter_bridge && in_jit_code_cache(jj->orig_entry)) {
        backup_entry = g_interpreter_bridge;
    }

    /* The hooked method keeps its kind. For a managed method, the paths
     * that would run it without going through its entry point are switched
     * off, and the JIT is told to leave it alone. */
    uint32_t target_flags = flags;
    if (!native && !intrinsic) {
        target_flags = (flags & ~(ACC_PRE_COMPILED | ACC_SINGLE_IMPLEMENTATION | ACC_FAST_INTERP_INVOKE))
                       | ACC_COMPILE_DONT_BOTHER;
    }

    /* Other threads may be calling the method right now: stop them for the
     * moment it takes to set this up. */
    char scope[64];
    memset(scope, 0, sizeof(scope));
    jj->used = true;
    if (g_suspend_all) g_suspend_all(scope, "renef java hook", false);

    memcpy(backup, art_method, off->art_method_size);
    *entry_of(backup, off) = backup_entry;
    if (!intrinsic) {
        /* The copy is called a lot but is not a method of its class as far
         * as the compiler's bookkeeping goes: keep the JIT away from it. */
        *flags_of(backup, off) = (flags & ~ACC_PRE_COMPILED) | ACC_COMPILE_DONT_BOTHER;
    }

    memcpy(twin, art_method, off->art_method_size);
    *flags_of(twin, off) = twin_flags;
    *data_of(twin, off) = jj->stub;
    *entry_of(twin, off) = g_generic_jni_entry;

    *flags_of(art_method, off) = target_flags;
    *entry_of(art_method, off) = jj->entry;

    if (g_resume_all) g_resume_all(scope);

    hook->is_hooked = true;
    g_java_hook_count++;

    LOGI("hook j%d: %s.%s%s  method=%p flags 0x%x -> 0x%x entry %p -> %p | twin=%p flags 0x%x | copy=%p runs %p",
         index, class_name, method_name, signature, art_method, flags, target_flags,
         jj->orig_entry, jj->entry, twin, twin_flags, backup, backup_entry);
    return index;
}

void* java_jni_unbound_stub(JNIEnv* env) {
    if (get_android_api_level() < 31 || !env) return NULL;
    if (jj_init(env) != 1) return NULL;
    return g_unbound_jni;
}

int java_jni_uninstall(int hook_index) {
    if (hook_index < 0 || hook_index >= MAX_JAVA_HOOKS || !g_jj[hook_index].used) return -1;
    JjHook* jj = &g_jj[hook_index];
    JavaHookInfo* hook = &g_java_hooks[hook_index];
    const ArtMethodOffsets* off = get_art_method_offsets();

    if (!make_writable(hook->art_method, off->art_method_size)) return -1;

    /* ScopedSuspendAll needs a thread that is attached to the runtime. The
     * agent's command thread detaches after every command, and the cleanup
     * at the end of a session runs on it in that state: without this the
     * runtime dereferenced a null Thread* and the target died (Android 13). */
    if (!get_jni_env()) {
        LOGE("hook j%d not removed: thread cannot attach to the runtime", hook_index);
        return -1;
    }

    char scope[64];
    memset(scope, 0, sizeof(scope));
    if (g_suspend_all) g_suspend_all(scope, "renef java unhook", false);
    /* Only if the entry point is still ours: ART may have given the method
     * a new one in the meantime, and that one must not be undone. */
    if (*entry_of(hook->art_method, off) == jj->entry) {
        *entry_of(hook->art_method, off) = jj->orig_entry;
    }
    *flags_of(hook->art_method, off) = jj->orig_flags;
    if (g_resume_all) g_resume_all(scope);

    /* Twin, copy and code stay as they are, and jj->used stays set: a thread
     * may still be inside a call that came in through the hook. Its frame
     * belongs to the twin, which is and remains a native method. */
    LOGI("hook j%d removed", hook_index);
    return 0;
}
