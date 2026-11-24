#ifndef AGENT_GLOBALS_H
#define AGENT_GLOBALS_H

#include <android/log.h>
#include <stdint.h>
#include <stdbool.h>
#include <jni.h>
#include <pthread.h>
#include <agent/lua_engine.h>

#define LOG_TAG "RENEF_AGENT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define PAGE_SIZE 4096
#define PAGE_START(addr) ((void*)((uintptr_t)(addr) & ~(PAGE_SIZE - 1)))
#define ALIGN_UP(addr, size) (((addr) + (size) - 1) & ~((size) - 1))

// Bumped from 32 -- a realistic pentest script set (crypto +
// SSL pinning + Java recon + native layer together) easily uses 10+ hooks,
// and the agent is already injected into the target process, so a few extra
// KB of static HookInfo storage is immaterial. 128 gives real headroom
// without the capacity check becoming the common failure mode.
#define MAX_HOOKS 128

extern LuaEngine* g_lua_engine;

extern int g_output_client_fd;

extern JNIEnv* g_current_jni_env;

extern JavaVM* g_java_vm;


extern bool g_verbose_mode;

void verbose_log(const char* fmt, ...);

JNIEnv* get_current_jni_env(void);
JNIEnv* get_jni_env(void);

// open("/proc/self/mem", flags | O_CLOEXEC) that also works in a process
// that is not dumpable (every app that is not debuggable). The caller
// closes the descriptor. See globals.c.
int agent_open_self_mem(int flags);

// Single, process-wide Lua VM lock. Every path that touches g_lua_engine's
// lua_State — native hook onEnter/onLeave/replace callbacks (native.c), Java
// hook onEnter/onLeave callbacks (java.c), and normal script load/eval
// (engine.c lua_engine_load_script/lua_engine_load_file) — must hold this
// lock while doing so. It is recursive: a Lua callback may itself trigger a
// (possibly different) hook callback on the same thread (e.g. a script or
// onEnter handler calling NativeFunction()/Java.use():call() on another
// hooked target), which must be able to re-enter without deadlocking.
void lua_vm_lock(void);
void lua_vm_unlock(void);
bool lua_vm_lock_timed(int timeout_ms); // false = not acquired, do not unlock

#endif
