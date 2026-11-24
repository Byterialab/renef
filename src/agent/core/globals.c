#include <agent/globals.h>
#include <agent/hook.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/prctl.h>

LuaEngine* g_lua_engine = NULL;

// Process-wide Lua VM lock (see globals.h for the full rationale). Recursive
// so that a hook callback or script can re-enter via NativeFunction()/
// Java.use():call() on the same thread without deadlocking. Lazily
// initialized via pthread_once since a plain static initializer can't
// express PTHREAD_MUTEX_RECURSIVE portably across glibc/bionic.
static pthread_mutex_t g_lua_vm_mutex;
static pthread_once_t g_lua_vm_mutex_once = PTHREAD_ONCE_INIT;

static void init_lua_vm_mutex(void) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_lua_vm_mutex, &attr);
    pthread_mutexattr_destroy(&attr);
}

void lua_vm_lock(void) {
    pthread_once(&g_lua_vm_mutex_once, init_lua_vm_mutex);
    pthread_mutex_lock(&g_lua_vm_mutex);
    // Lua is about to run on this thread - hold the hook
    // reentrancy guard so the VM's own (direct or indirect) libc calls
    // cannot re-enter it through a native hook. See native.c.
    hook_agent_lua_enter();
}

// Bounded variant for native hook callbacks (see hook_callback_lock in
// native.c). Returns false if the VM lock could not be taken in time; the
// caller must then NOT call lua_vm_unlock().
bool lua_vm_lock_timed(int timeout_ms) {
    pthread_once(&g_lua_vm_mutex_once, init_lua_vm_mutex);

    if (pthread_mutex_trylock(&g_lua_vm_mutex) != 0) {
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += timeout_ms / 1000;
        deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec += 1;
            deadline.tv_nsec -= 1000000000L;
        }
        if (pthread_mutex_timedlock(&g_lua_vm_mutex, &deadline) != 0) {
            return false;
        }
    }
    hook_agent_lua_enter();
    return true;
}

void lua_vm_unlock(void) {
    // No pthread_once here: unlock must only ever follow a successful lock,
    // which has already run init via pthread_once.
    hook_agent_lua_leave();
    pthread_mutex_unlock(&g_lua_vm_mutex);
}

int g_output_client_fd = -1;

bool g_verbose_mode = false;

// Found live while cross-version testing the trampoline relocation fix: this runs on
// EVERY hook call (generic_hook_handler -> hook_logger -> verbose_log),
// on WHATEVER thread happens to call the hooked function - including
// short-stack system/binder worker threads. The old body unconditionally
// vsnprintf'd into a 512-byte LOCAL (stack) buffer before even checking
// g_verbose_mode, which was enough added stack usage to overflow one of
// those threads under real concurrent hook load (confirmed via
// tombstone: "Cause: stack pointer is close to top of stack; likely
// stack overflow", in this exact call chain). The common (non-verbose)
// path now hands the format string straight to liblog's own
// __android_log_vprint() instead of double-buffering through a local
// array first - only the (rarer) verbose-mode path, which needs the
// formatted string as one buffer to write() to the CLI socket, still
// uses a local buffer.
void verbose_log(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    if (g_verbose_mode && g_output_client_fd >= 0) {
        char buf[512];
        va_list args_copy;
        va_copy(args_copy, args);
        vsnprintf(buf, sizeof(buf), fmt, args_copy);
        va_end(args_copy);

        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", buf);

        write(g_output_client_fd, "[DBG] ", 6);
        write(g_output_client_fd, buf, strlen(buf));
        write(g_output_client_fd, "\n", 1);
    } else {
        __android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, fmt, args);
    }

    va_end(args);
}

JNIEnv* g_current_jni_env = NULL;

JavaVM* g_java_vm = NULL;


JNIEnv* get_current_jni_env(void) {
    JNIEnv* env = NULL;
    if (g_java_vm) {
        int status = (*g_java_vm)->GetEnv(g_java_vm, (void**)&env, JNI_VERSION_1_6);
        if (status == JNI_EDETACHED) {
            (*g_java_vm)->AttachCurrentThread(g_java_vm, &env, NULL);
        }
    }
    return env;
}

// /proc/self/mem is how the agent reads and writes its own process where a
// plain load or store cannot: execute-only code, and code pages that should
// not be made writable. The file belongs to root while the process is not
// "dumpable", and that is the state of every app that is not debuggable -
// there the open fails with EACCES and the callers used to fall back to
// mprotect() and direct access (a crash on execute-only code).
//
// The owner is decided when the file is opened, so the flag only has to be
// set for the duration of the open: set it, open, put it back.
int agent_open_self_mem(int flags) {
    int fd = open("/proc/self/mem", flags | O_CLOEXEC);
    if (fd >= 0 || errno != EACCES) return fd;

    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&lock);
    int saved_errno = EACCES;
    fd = open("/proc/self/mem", flags | O_CLOEXEC);   // another thread may be mid-toggle
    if (fd < 0) {
        int was = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
        if (was == 0 && prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0) {
            fd = open("/proc/self/mem", flags | O_CLOEXEC);
            saved_errno = errno;
            prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
    pthread_mutex_unlock(&lock);
    if (fd < 0) errno = saved_errno;
    return fd;
}
