#ifndef AGENT_HOOK_H
#define AGENT_HOOK_H

#include <stdint.h>
#include <stdbool.h>
#include <agent/lua_hook.h>
#include <agent/globals.h>  // for MAX_HOOKS -- keep g_hooks[] sized consistently

enum hook_type {
    HOOK_TRAMPOLINE,
    HOOK_PLT_GOT,
    HOOK_JAVA_METHOD
};

typedef struct {
    void* target_addr;
    void* trampoline_addr;
    void* hook_addr;
    size_t original_size;
    uint32_t original_insn[4];
    enum hook_type type;
} TrampolineHook;

typedef struct {
    void** got_entries[64];
    void* original_funcs[64];
    int patched_count;
    void* hook_func;
} PltGotHook;

typedef struct {
    enum hook_type type;
    union {
        TrampolineHook trampoline;
        PltGotHook plt_got;
    } data;

    struct HookTarget target;

    int lua_onEnter_ref;
    int lua_onLeave_ref;
    int lua_replace_ref;   // Interceptor.replace callback (valid when is_replace)
    int is_replace;        // 1 = replace hook: run callback, skip the original

    // 1 = fire-and-forget hook. hook_logger() enqueues
    // args onto the async ring buffer (native.c) instead of calling the
    // Lua onEnter callback synchronously under g_lua_vm_mutex -- the
    // dedicated consumer thread runs it later, off the hot path. Only
    // meaningful for native (trampoline/PLT-GOT) hooks with onEnter set
    // and no onLeave; enforced at the Lua binding (api_hook.c).
    int is_async;

    void* thunk_addr;
    int hook_index;

    // The resolved absolute address this
    // slot was installed against, set at install time for BOTH trampoline
    // and PLT/GOT hooks (unlike TrampolineHook.target_addr, which only
    // exists for the trampoline variant and is cleared to NULL on
    // uninstall). Lets revert-by-(lib,offset) find the right slot
    // regardless of which install path was used, without needing a
    // separate lookup table.
    void* logical_target_addr;

    // Calls that reached this hook since it was installed. Counted in the
    // handler whatever the callback does (or whether it could run at all),
    // so `hooks` can report activity without anyone reading hook output.
    unsigned long hits;
} HookInfo;

extern HookInfo g_hooks[MAX_HOOKS];
extern int g_hook_count;
// Caller frame of the native hook currently being processed on this thread
// (0 outside a hook callback). Kept in native.c's libc-free per-thread
// table rather than a `__thread` variable.
uintptr_t hook_current_caller_fp(void);
uintptr_t hook_current_caller_lr(void);

int change_page_protection(void* addr, int prot);
uint32_t create_branch_insn(void* from, void* to);
void* allocate_trampoline(size_t size);
size_t disassemble_instructions(void* addr, void** insn_out, size_t min_bytes);
bool is_pc_relative(void* insn);
int install_trampoline_hook(void* target_func, void* hook_func, HookInfo* hook_info);
int install_plt_got_hook(void* target_func, void* hook_func, HookInfo* hook_info, const char* caller_lib);
bool install_lua_hook(const char* lib_name, uintptr_t offset, int onEnter_ref, int onLeave_ref, const char* caller_lib, bool is_async);
bool install_lua_replace(const char* lib_name, uintptr_t offset, int replace_ref, const char* caller_lib);

void generic_hook_handler(void);

// The agent's own Lua execution holds the
// hook reentrancy guard so hooked functions it reaches are bypassed.
// lua_vm_lock()/lua_vm_unlock() call the enter/leave pair; the outcall pair
// lifts the guard around an explicit script->target call (NativeFunction,
// Java method invocation) so hooks DO fire there. hook_outcall_begin()
// returns the previous state, to be handed back to hook_outcall_end().
void hook_mark_agent_thread(void); // call first thing in every thread the agent creates
void hook_agent_lua_enter(void);
void hook_agent_lua_leave(void);
int hook_outcall_begin(void);
void hook_outcall_end(int prev);
uint64_t get_replace_retval(void);
int hook_logger(uint64_t* saved_regs);
uint64_t log_return_value(uint64_t ret_val);
void* get_current_trampoline(void);

// Call a native function with up to 8 integer/pointer args (x0-x7), returning x0.
// Used by NativeFunction() to invoke native code (incl. hooked originals via the
// thread-local reentrancy guard) from Lua. Floating-point / >8 args unsupported.
uint64_t native_call8(void* fn, uint64_t* args);

// native_call8 extended with the
// AAPCS64 float/double register file (d0-d7, independent from x0-x7).
// `fret_out` always receives the callee's d0 on return; still no support
// for more than 8 int or 8 float/double args (AAPCS64 stack-passing) or
// struct-by-value. See the comment above its definition (native.c).
uint64_t native_call_ext(void* fn, uint64_t* iargs, double* fargs, double* fret_out);

void* create_hook_thunk(int hook_index);
void set_current_hook_index(int index);

int uninstall_hook(int hook_id);
int uninstall_all_hooks(void);

// Interceptor.revert(lib, offset) -- same (lib_name, offset)
// shape as install_lua_hook/install_lua_replace (not a raw absolute
// address, consistent with the rest of the Lua API resolving addresses
// internally). Resolves to an absolute address and reverts whichever
// installed hook slot matches (trampoline or PLT/GOT, whichever was used).
// Returns 0 on success, -1 if the library isn't loaded or no installed
// hook matches that address.
int interceptor_revert(const char* lib_name, uintptr_t offset);

#include "hook_java.h"

bool install_lua_java_hook(const char* class_name, const char* method_name,
                           const char* signature, int onEnter_ref, int onLeave_ref);

#endif
