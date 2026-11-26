#ifndef HOOK_JAVA_H
#define HOOK_JAVA_H

#include <jni.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Bumped alongside MAX_HOOKS/MAX_PENDING_HOOKS
// (globals.h/native.c) for the same reason -- a realistic script set uses
// more than 32 hooks, and this was the actual capacity blocker for the
// Java-overload bulk-install use case (one method with 235 native overloads).
#define MAX_JAVA_HOOKS 128

typedef struct {
    int api_level;
    size_t access_flags_offset;
    size_t entry_point_offset;
    size_t art_method_size;
} ArtMethodOffsets;

// ART access flags
#define kAccNative 0x0100

typedef struct {
    char class_name[256];
    char method_name[128];
    char method_sig[256];
    bool is_static;

    void* art_method;
    void* original_entry_point;
    void* hook_trampoline;

    int lua_onEnter_ref;
    int lua_onLeave_ref;

    bool is_hooked;
    int hook_index;

    // For method nativization (Android 11+ interpreter mode support)
    uint32_t original_access_flags;
    bool was_nativized;

    // For JNI reflection call (Android 11+ workaround)
    jclass clazz_global_ref;
    jmethodID method_id;

    // Stored return value from JNI reflection call
    uint64_t stored_return_value;
    bool has_stored_return;

    // Stored string value for object return types (if applicable)
    char* stored_string_value;
    bool has_stored_string;

    bool skip_original;

    // Which engine installed the hook: the original one (java.c) or the
    // one that turns the method into a real JNI native method (java_jni.c).
    int engine;

    // Calls that reached the hook since it was installed.
    unsigned long hits;
} JavaHookInfo;

#define JAVA_HOOK_ENGINE_LEGACY 0
#define JAVA_HOOK_ENGINE_JNI    1

extern JavaHookInfo g_java_hooks[MAX_JAVA_HOOKS];
extern int g_java_hook_count;

int java_hook_init(JNIEnv* env);

int get_android_api_level(void);

const ArtMethodOffsets* get_art_method_offsets(void);

void* jmethodid_to_art_method(JNIEnv* env, jmethodID method_id, jclass clazz);

int install_java_hook(JNIEnv* env,
                      const char* class_name,
                      const char* method_name,
                      const char* signature,
                      int onEnter_ref,
                      int onLeave_ref);

int uninstall_java_hook(int hook_index);

int uninstall_all_java_hooks(void);

void* get_java_hook_original_entry(int hook_index);

// Hook callback handlers
void java_hook_on_enter(int hook_index, uint64_t* saved_regs);
uint64_t java_hook_on_leave(int hook_index, uint64_t ret_val);

void* create_java_hook_trampoline(int hook_index);

void* jni_ref_to_raw_ptr(JNIEnv* env, jobject ref);
jobject raw_ptr_to_jni_ref(JNIEnv* env, void* raw_ptr);

// Address of a dynamic symbol of libart.so, or NULL.
void* java_libart_symbol(const char* name);

// Hands the text of a String result to the onLeave callback that runs next
// on this thread (it becomes retval.value). Takes ownership of `text`.
void java_hook_set_return_string(char* text);

// Returns and clears the ready-made local JNI reference (if any) that
// java_hook_on_leave() stashed on this thread for the return value it just
// produced, so jj_dispatch() can hand it straight back instead of rebuilding
// it from a raw pointer via raw_ptr_to_jni_ref(). NULL if onLeave didn't
// produce one (e.g. no replacement, or a replacement given as a raw address).
jobject java_hook_take_return_object(void);

// Whether the onEnter callback that just ran on this thread asked for the
// original to be skipped (args.skip = true). Per thread: the flag in
// JavaHookInfo is shared by every thread that is inside the hook.
bool java_hook_skip_requested(void);

// Undoes java_hook_on_enter()'s bookkeeping for a call whose onLeave will
// not run (the original threw).
void java_hook_abandon_call(void);

// Why the last install_java_hook() on this thread failed ("" if it gave no
// reason). For the error a script sees.
const char* java_hook_last_error(void);
void java_hook_set_error(const char* fmt, ...);

// java_jni.c. Install returns the hook index, -1 if this engine cannot be
// used here (the caller falls back to the original one), -2 on a failure
// that the original engine would not fix either.
int java_jni_install(JNIEnv* env, jclass clazz, jmethodID method_id, void* art_method,
                     bool is_static, const char* class_name, const char* method_name,
                     const char* signature, int onEnter_ref, int onLeave_ref);
int java_jni_uninstall(int hook_index);
// What the JNI slot of a native method holds while no function is bound
// to it (ART's lookup stub), or NULL when that cannot be told here.
void* java_jni_unbound_stub(JNIEnv* env);

#ifdef __cplusplus
}
#endif

#endif
