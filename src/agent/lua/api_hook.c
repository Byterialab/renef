#include <agent/hook_java.h>
#include <agent/lua_hook.h>
#include <agent/hook.h>
#include <agent/globals.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <lua.h>
#include <lauxlib.h>
#include <string.h>
#include <android/log.h>

#define TAG "LUA_HOOK"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)


static struct HookTarget create_native_target(lua_State* L) {
    struct HookTarget target;
    target.type = NATIVE_METHOD;

    const char* lib_name = luaL_checkstring(L, 1);
    strncpy(target.info.native.lib_name, lib_name, 127);
    target.info.native.lib_name[127] = '\0';

    target.info.native.offset = (uintptr_t)luaL_checkinteger(L, 2);

    if (lua_isnumber(L, 3)) {
        target.info.native.size = (size_t)lua_tointeger(L, 3);
    } else {
        target.info.native.size = 0;
    }

    return target;
}

static struct HookTarget create_java_target(lua_State* L) {
    struct HookTarget target;
    target.type = JAVA_METHOD;

    const char* class_name = luaL_checkstring(L, 1);
    strncpy(target.info.java.class_name, class_name, 127);
    target.info.java.class_name[127] = '\0';

    const char* method_name = luaL_checkstring(L, 2);
    strncpy(target.info.java.method_name, method_name, 127);
    target.info.java.method_name[127] = '\0';

    if (lua_isstring(L, 3)) {
        const char* sig = lua_tostring(L, 3);
        strncpy(target.info.java.method_sig, sig, 127);
        target.info.java.method_sig[127] = '\0';
    } else {
        target.info.java.method_sig[0] = '\0';
    }

    return target;
}

static int lua_hook(lua_State* L) {
    struct HookTarget target;

    if (lua_isnumber(L, 2)) {
        target = create_native_target(L);
    } else if (lua_isstring(L, 2)) {
        target = create_java_target(L);
    } else {
        return luaL_error(L, "Invalid hook arguments");
    }

    int callback_index = 0;

    if (target.type == NATIVE_METHOD)
        callback_index = 3;
    else
        if (lua_isstring(L, 3))
            callback_index = 4;
        else
            callback_index = 3;


    if (!lua_istable(L, callback_index)) {
        return luaL_error(L, "Callbacks must be a table");
    }

    int onEnter_ref = LUA_NOREF;
    lua_getfield(L, callback_index, "onEnter");
    if (lua_isfunction(L, -1)) {
        onEnter_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        lua_pop(L, 1);
    }


    int onLeave_ref = LUA_NOREF;
    lua_getfield(L, callback_index, "onLeave");
    if (lua_isfunction(L, -1)) {
        onLeave_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        lua_pop(L, 1);
    }

    if (onEnter_ref != LUA_NOREF) {
        verbose_log("onEnter callback registered (ref: %d)", onEnter_ref);
    }
    if (onLeave_ref != LUA_NOREF) {
        verbose_log("onLeave callback registered (ref: %d)", onLeave_ref);
    }

    // Opt-in fire-and-forget mode for high-frequency,
    // observation-only native hooks. onEnter runs later, off the hot
    // path, on a dedicated consumer thread -- it can read args but can't
    // modify them or the return value (the original always runs
    // immediately, synchronously, in the calling thread), and onLeave
    // isn't supported at all, so both are rejected up front with a clear
    // error instead of silently doing something the caller didn't ask for.
    bool is_async = false;
    lua_getfield(L, callback_index, "async");
    if (lua_toboolean(L, -1)) {
        is_async = true;
    }
    lua_pop(L, 1);

    if (is_async) {
        if (target.type != NATIVE_METHOD) {
            if (onEnter_ref != LUA_NOREF) luaL_unref(L, LUA_REGISTRYINDEX, onEnter_ref);
            if (onLeave_ref != LUA_NOREF) luaL_unref(L, LUA_REGISTRYINDEX, onLeave_ref);
            return luaL_error(L, "hook(): async=true is only supported for native hooks, not Java methods");
        }
        if (onLeave_ref != LUA_NOREF) {
            luaL_unref(L, LUA_REGISTRYINDEX, onEnter_ref);
            luaL_unref(L, LUA_REGISTRYINDEX, onLeave_ref);
            return luaL_error(L, "hook(): async=true doesn't support onLeave (observation-only, onEnter args) -- "
                                  "drop onLeave or drop async");
        }
        if (onEnter_ref == LUA_NOREF) {
            return luaL_error(L, "hook(): async=true with no onEnter callback does nothing -- add one");
        }
        verbose_log("Hook marked async (fire-and-forget)");
    }

    // Parse optional 'caller' field for PLT/GOT targeted hooking
    // Can be a string (single library) or a table (array of library names)
    const char* caller_lib = NULL;
    static char caller_buf[1024];
    caller_buf[0] = '\0';

    lua_getfield(L, callback_index, "caller");
    if (lua_isstring(L, -1)) {
        caller_lib = lua_tostring(L, -1);
        verbose_log("Caller library specified: %s", caller_lib);
    } else if (lua_istable(L, -1)) {
        size_t buf_pos = 0;
        int len = (int)lua_rawlen(L, -1);
        for (int i = 1; i <= len; i++) {
            lua_rawgeti(L, -1, i);
            if (lua_isstring(L, -1)) {
                const char* name = lua_tostring(L, -1);
                if (buf_pos > 0 && buf_pos < sizeof(caller_buf) - 1) {
                    caller_buf[buf_pos++] = ',';
                }
                size_t name_len = strlen(name);
                if (buf_pos + name_len < sizeof(caller_buf) - 1) {
                    memcpy(caller_buf + buf_pos, name, name_len);
                    buf_pos += name_len;
                }
            }
            lua_pop(L, 1);
        }
        caller_buf[buf_pos] = '\0';
        if (buf_pos > 0) {
            caller_lib = caller_buf;
            verbose_log("Caller libraries specified: %s", caller_lib);
        }
    }
    lua_pop(L, 1);

    // Auto-detect hook type: caller present = PLT/GOT, absent = trampoline
    if (caller_lib) {
        verbose_log("Hook type auto-selected: PLT/GOT (caller=%s)", caller_lib);
    } else {
        verbose_log("Hook type auto-selected: Trampoline (no caller)");
    }

    verbose_log("Hook target: type=%d, callbacks registered", target.type);

    // Check capacity BEFORE attempting install, so a full
    // hook table gives a specific, actionable Lua error instead of
    // collapsing into the same generic "Failed to install X hook" message
    // every other install failure (bad address, thunk alloc failure, ...)
    // also produces -- a script author hitting the cap had to go dig
    // through `adb logcat` to learn why.
    if (target.type == NATIVE_METHOD) {
        if (g_hook_count >= MAX_HOOKS) {
            return luaL_error(L,
                "hook(): max native hooks reached (%d/%d) -- unhook something "
                "first, or raise MAX_HOOKS in globals.h and rebuild", g_hook_count, MAX_HOOKS);
        }
        bool result = install_lua_hook(target.info.native.lib_name,
                                       target.info.native.offset,
                                       onEnter_ref, onLeave_ref,
                                       caller_lib, is_async);
        if (!result) {
            return luaL_error(L, "Failed to install native hook");
        }
    } else if (target.type == JAVA_METHOD) {
        if (g_java_hook_count >= MAX_JAVA_HOOKS) {
            return luaL_error(L,
                "hook(): max Java hooks reached (%d/%d) -- unhook something "
                "first, or raise MAX_JAVA_HOOKS in hook_java.h and rebuild", g_java_hook_count, MAX_JAVA_HOOKS);
        }
        bool result = install_lua_java_hook(target.info.java.class_name,
                                            target.info.java.method_name,
                                            target.info.java.method_sig,
                                            onEnter_ref, onLeave_ref);
        if (!result) {
            const char* why = java_hook_last_error();
            if (why && *why) {
                return luaL_error(L, "Failed to install Java hook: %s", why);
            }
            return luaL_error(L, "Failed to install Java hook");
        }
    }

    return 0;
}

// True for an argType string naming a float/double slot.
static bool is_float_argtype(const char* t) {
    return t && (strcmp(t, "float") == 0 || strcmp(t, "double") == 0);
}

/*
 * The callable returned by NativeFunction(). Upvalues:
 *   1 = target address (integer)
 *   2 = return type (string)
 *   3 = argTypes table, or nil (v1 behavior: every arg is int/pointer)
 * Lua args are marshalled by ACTUAL Lua type: numbers pass by value, strings
 * pass as a pointer to their NUL-terminated bytes (valid for the duration of
 * the call). A number whose declared argType (upvalue 3) is "float" or
 * "double" goes into the next free AAPCS64 float register
 * (d0-d7) instead of the next free integer register (x0-x7) -- the two
 * counters advance independently, per the ABI. The result is converted
 * according to the declared return type; "float"/"double" reads the
 * callee's d0 (via native_call_ext's fret_out) instead of x0.
 */
static int native_function_call(lua_State* L) {
    uintptr_t addr = (uintptr_t)lua_tointeger(L, lua_upvalueindex(1));
    const char* ret_type = lua_tostring(L, lua_upvalueindex(2));
    bool has_argtypes = lua_istable(L, lua_upvalueindex(3));

    int nargs = lua_gettop(L);

    uint64_t iargs[8] = {0};
    double fargs[8] = {0};
    int iidx = 0, fidx = 0; // independent AAPCS64 register counters

    for (int i = 0; i < nargs && (iidx < 8 || fidx < 8); i++) {
        int idx = i + 1;
        const char* argtype = NULL;
        if (has_argtypes) {
            lua_rawgeti(L, lua_upvalueindex(3), idx);
            argtype = lua_tostring(L, -1);
        }

        bool as_float = is_float_argtype(argtype) && lua_type(L, idx) == LUA_TNUMBER;

        if (as_float && fidx < 8) {
            double v = lua_tonumber(L, idx);
            if (strcmp(argtype, "float") == 0) {
                // AAPCS64: a `float` arg occupies only the low 32 bits of
                // its D-register slot -- write just those 4 bytes.
                float f = (float)v;
                memcpy(&fargs[fidx], &f, sizeof(f));
            } else {
                fargs[fidx] = v;
            }
            fidx++;
        } else if (iidx < 8) {
            switch (lua_type(L, idx)) {
                case LUA_TNUMBER:
                    iargs[iidx] = (uint64_t)lua_tointeger(L, idx);
                    break;
                case LUA_TSTRING:
                    iargs[iidx] = (uint64_t)(uintptr_t)lua_tostring(L, idx);
                    break;
                case LUA_TBOOLEAN:
                    iargs[iidx] = lua_toboolean(L, idx) ? 1 : 0;
                    break;
                case LUA_TNIL:
                case LUA_TNONE:
                    iargs[iidx] = 0;
                    break;
                default:
                    iargs[iidx] = (uint64_t)lua_tointeger(L, idx);
                    break;
            }
            iidx++;
        }

        if (has_argtypes) lua_pop(L, 1); // pop the argtype string pushed above
    }

    double fret = 0;
    // Explicit script->target call - lift the "agent's own
    // Lua execution is not hooked" guard for its duration (a no-op inside
    // a native hook callback, where the guard must stay held so calling
    // the hooked address reaches the original).
    int outcall_prev = hook_outcall_begin();
    uint64_t ret = native_call_ext((void*)addr, iargs, fargs, &fret);
    hook_outcall_end(outcall_prev);

    if (ret_type == NULL || strcmp(ret_type, "void") == 0) {
        return 0;
    } else if (strcmp(ret_type, "bool") == 0 || strcmp(ret_type, "boolean") == 0) {
        lua_pushboolean(L, ret != 0);
    } else if (strcmp(ret_type, "string") == 0) {
        if (ret) lua_pushstring(L, (const char*)(uintptr_t)ret);
        else lua_pushnil(L);
    } else if (strcmp(ret_type, "float") == 0) {
        float f;
        memcpy(&f, &fret, sizeof(f)); // low 32 bits, see native_call_ext's comment
        lua_pushnumber(L, (lua_Number)f);
    } else if (strcmp(ret_type, "double") == 0) {
        lua_pushnumber(L, (lua_Number)fret);
    } else {
        // int / long / uint / pointer / anything else -> integer
        lua_pushinteger(L, (lua_Integer)ret);
    }
    return 1;
}

/*
 * NativeFunction(addr [, retType [, argTypes]])
 *
 * Wrap a native function address in a Lua callable. Supports up to 8
 * integer/pointer arguments (ARM64 x0-x7), up to 8 float/double arguments
 * (ARM64 d0-d7 -- declare them in argTypes, e.g. {"float",
 * "pointer"}; positions not covered by argTypes, or when argTypes is
 * omitted entirely, default to integer/pointer, matching v1), and an
 * integer/pointer/bool/string/float/double return. retType defaults to
 * "pointer".
 *
 *   local strlen = NativeFunction(Module.find("libc.so") + off, "int", {"pointer"})
 *   print(strlen(Memory.allocStr("hello")))   -- 5
 *
 *   local sinf = NativeFunction(Module.find("libm.so") + off, "float", {"float"})
 *   print(sinf(1.5))
 *
 * Also lets a replaced function call the original: calling the hooked address
 * re-enters the hook, and the thread-local reentrancy guard runs the original.
 */
static int lua_native_function(lua_State* L) {
    luaL_checkinteger(L, 1);  // addr
    const char* ret_type = luaL_optstring(L, 2, "pointer");

    lua_pushvalue(L, 1);            // upvalue 1: addr
    lua_pushstring(L, ret_type);    // upvalue 2: retType
    if (lua_istable(L, 3)) {
        lua_pushvalue(L, 3);        // upvalue 3: argTypes table
    } else {
        lua_pushnil(L);             // upvalue 3: none -> v1 all-integer behavior
    }
    lua_pushcclosure(L, native_function_call, 3);
    return 1;
}

/*
 * Interceptor.replace(lib, offset, callback)
 *
 * Replace a native function: `callback(args)` runs INSTEAD of the original,
 * and its return value (a number, or nil/false = 0) becomes the call's result.
 * args[0..7] are the incoming ARM64 x0-x7 registers. To run the original from
 * inside the callback, wrap its address in NativeFunction() and call it — the
 * reentrancy guard routes that through the saved original prologue.
 *
 *   Interceptor.replace("libfoo.so", 0x1234, function(args)
 *       return 0   -- original never runs; call returns 0
 *   end)
 */
static int lua_interceptor_replace(lua_State* L) {
    const char* lib_name = luaL_checkstring(L, 1);
    uintptr_t offset = (uintptr_t)luaL_checkinteger(L, 2);
    luaL_checktype(L, 3, LUA_TFUNCTION);
    // Optional 4th arg: caller library -> installs via PLT/GOT for that caller's
    // call sites instead of the default inline trampoline.
    const char* caller = luaL_optstring(L, 4, NULL);

    lua_pushvalue(L, 3);
    int replace_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Same specific-capacity-error treatment as hook() above.
    if (g_hook_count >= MAX_HOOKS) {
        luaL_unref(L, LUA_REGISTRYINDEX, replace_ref);
        return luaL_error(L,
            "Interceptor.replace(): max native hooks reached (%d/%d) -- unhook "
            "something first, or raise MAX_HOOKS in globals.h and rebuild", g_hook_count, MAX_HOOKS);
    }

    if (!install_lua_replace(lib_name, offset, replace_ref, caller)) {
        luaL_unref(L, LUA_REGISTRYINDEX, replace_ref);
        return luaL_error(L, "Failed to install replace hook");
    }
    return 0;
}

/*
 * Interceptor.revert(lib, offset)
 *
 * Removes a previously-installed hook()/Interceptor.replace() at (lib,
 * offset) -- same (lib_name, offset) shape as installing one, not a raw
 * absolute address, so a script never has to resolve addresses itself.
 * Restores the original bytes/GOT entry and releases the Lua callback
 * ref(s). Useful for iterative pipeline scripts that want to remove/replace
 * a hook without respawning the target.
 *
 *   Interceptor.replace("libfoo.so", 0x1234, function(args) return 0 end)
 *   ...
 *   Interceptor.revert("libfoo.so", 0x1234)
 *
 * Raises a Lua error (does not crash the process) if the library isn't
 * loaded or no installed hook matches that address -- e.g. double-revert,
 * or reverting an address nothing ever hooked.
 */
static int lua_interceptor_revert(lua_State* L) {
    const char* lib_name = luaL_checkstring(L, 1);
    uintptr_t offset = (uintptr_t)luaL_checkinteger(L, 2);

    if (interceptor_revert(lib_name, offset) != 0) {
        // Lua's lua_pushfstring/luaL_error (lobject.c) only understands
        // %d/%u/%s/%c/%p/%U/%% -- no 'l' length modifier and no %x at all,
        // unlike C's printf (same pitfall already documented on
        // Module.disassemble in engine.c). Pre-format with snprintf
        // (which does support %lx) and hand it to luaL_error as a %s.
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "Interceptor.revert: no installed hook found at %s+0x%lx",
                 lib_name, (unsigned long)offset);
        return luaL_error(L, "%s", msg);
    }
    return 0;
}

void register_memory_api(lua_State* L) {
    lua_pushcfunction(L, lua_hook);
    lua_setglobal(L, "hook");

    lua_pushcfunction(L, lua_native_function);
    lua_setglobal(L, "NativeFunction");

    lua_newtable(L);
    lua_pushcfunction(L, lua_interceptor_replace);
    lua_setfield(L, -2, "replace");
    lua_pushcfunction(L, lua_interceptor_revert);
    lua_setfield(L, -2, "revert");
    lua_setglobal(L, "Interceptor");
}
