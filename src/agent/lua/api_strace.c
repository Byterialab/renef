#include <agent/lua_strace.h>
#include <agent/strace.h>
#include <agent/globals.h>
#include <agent/output_queue.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

extern int g_output_client_fd;

/* Enqueues onto the bounded output_queue instead of calling write()
 * directly -- see agent/output_queue.h. Keeps the hook-callback path
 * (which runs with g_lua_mutex held) off of socket I/O. */
static void send_to_cli(const char* msg) {
    if (g_output_client_fd >= 0 && msg) {
        size_t len = strlen(msg);
        char* buf = (char*)malloc(len + 1);
        if (buf) {
            memcpy(buf, msg, len);
            buf[len] = '\n';
            output_queue_push(buf, len + 1);
            free(buf);
        }
    }
}

static int lua_syscall_trace(lua_State* L) {
    int nargs = lua_gettop(L);
    if (nargs == 0) {
        return luaL_error(L, "Syscall.trace requires at least one argument");
    }

    if (nargs == 1 && lua_istable(L, 1)) {
        lua_getfield(L, 1, "category");
        if (lua_isstring(L, -1)) {
            const char* category = lua_tostring(L, -1);
            lua_pop(L, 1);

            SyscallDef* defs[64];
            int count = strace_get_defs_by_category(category, defs, 64);
            if (count == 0) {
                return luaL_error(L, "No syscalls found for category: %s", category);
            }

            int installed = 0;
            for (int i = 0; i < count; i++) {
                if (strace_install(defs[i]->name, NULL, LUA_NOREF, LUA_NOREF) >= 0) {
                    installed++;
                }
            }

            char msg[128];
            snprintf(msg, sizeof(msg), "Tracing %d %s syscalls", installed, category);
            send_to_cli(msg);

            lua_pushinteger(L, installed);
            return 1;
        }
        lua_pop(L, 1);
    }

    const char* caller_lib = NULL;
    int onCall_ref = LUA_NOREF;
    int onReturn_ref = LUA_NOREF;
    int last_string_arg = nargs;

    if (lua_istable(L, nargs)) {
        last_string_arg = nargs - 1;

        lua_getfield(L, nargs, "caller");
        if (lua_isstring(L, -1)) {
            caller_lib = lua_tostring(L, -1);
        }
        lua_pop(L, 1);

        lua_getfield(L, nargs, "onCall");
        if (lua_isfunction(L, -1)) {
            onCall_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        } else {
            lua_pop(L, 1);
        }

        lua_getfield(L, nargs, "onReturn");
        if (lua_isfunction(L, -1)) {
            onReturn_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        } else {
            lua_pop(L, 1);
        }
    }

    int installed = 0;
    for (int i = 1; i <= last_string_arg; i++) {
        if (!lua_isstring(L, i)) continue;
        const char* name = lua_tostring(L, i);
        if (strace_install(name, caller_lib, onCall_ref, onReturn_ref) >= 0) {
            installed++;
        } else {
            char msg[128];
            snprintf(msg, sizeof(msg), "Warning: Failed to trace '%s'", name);
            send_to_cli(msg);
        }
    }

    if (installed > 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Tracing %d syscall(s)", installed);
        send_to_cli(msg);
    }

    lua_pushinteger(L, installed);
    return 1;
}

static int lua_syscall_trace_all(lua_State* L) {
    (void)L;
    SyscallDef* defs[64];
    int count = strace_get_all_defs(defs, 64);
    int installed = 0;

    for (int i = 0; i < count; i++) {
        if (strcmp(defs[i]->name, "getpid") == 0 ||
            strcmp(defs[i]->name, "getuid") == 0) {
            continue;
        }
        if (strace_install(defs[i]->name, NULL, LUA_NOREF, LUA_NOREF) >= 0) {
            installed++;
        }
    }

    char msg[128];
    snprintf(msg, sizeof(msg), "Tracing all %d syscalls", installed);
    send_to_cli(msg);

    lua_pushinteger(L, installed);
    return 1;
}

static int lua_syscall_untrace(lua_State* L) {
    int nargs = lua_gettop(L);
    int removed = 0;

    for (int i = 1; i <= nargs; i++) {
        const char* name = luaL_checkstring(L, i);
        if (strace_remove(name) == 0) {
            removed++;
        }
    }

    char msg[128];
    snprintf(msg, sizeof(msg), "Removed %d trace(s)", removed);
    send_to_cli(msg);

    lua_pushinteger(L, removed);
    return 1;
}

static int lua_syscall_stop(lua_State* L) {
    (void)L;
    strace_remove_all();
    send_to_cli("Syscall tracing stopped");
    return 0;
}

static int lua_syscall_list(lua_State* L) {
    SyscallDef* defs[64];
    int count;

    if (lua_gettop(L) >= 1 && lua_isstring(L, 1)) {
        const char* category = lua_tostring(L, 1);
        count = strace_get_defs_by_category(category, defs, 64);
    } else {
        count = strace_get_all_defs(defs, 64);
    }

    lua_newtable(L);
    for (int i = 0; i < count; i++) {
        lua_newtable(L);
        lua_pushstring(L, defs[i]->name);
        lua_setfield(L, -2, "name");
        lua_pushstring(L, defs[i]->category);
        lua_setfield(L, -2, "category");
        lua_pushinteger(L, defs[i]->nr_args);
        lua_setfield(L, -2, "args");
        lua_rawseti(L, -2, i + 1);
    }

    char header[64];
    snprintf(header, sizeof(header), "Available syscalls (%d):", count);
    send_to_cli(header);

    const char* current_cat = NULL;
    for (int i = 0; i < count; i++) {
        if (!current_cat || strcmp(current_cat, defs[i]->category) != 0) {
            current_cat = defs[i]->category;
            char cat_line[64];
            snprintf(cat_line, sizeof(cat_line), "\n  [%s]", current_cat);
            send_to_cli(cat_line);
        }
        char line[128];
        snprintf(line, sizeof(line), "    %s (%d args)", defs[i]->name, defs[i]->nr_args);
        send_to_cli(line);
    }

    return 1;
}

static int lua_syscall_active(lua_State* L) {
    lua_newtable(L);
    int count = 0;

    for (int i = 0; i < g_strace_count; i++) {
        if (!g_strace_hooks[i].active) continue;
        lua_newtable(L);
        lua_pushstring(L, g_strace_hooks[i].def->name);
        lua_setfield(L, -2, "name");
        lua_pushstring(L, g_strace_hooks[i].def->category);
        lua_setfield(L, -2, "category");
        lua_pushinteger(L, g_strace_hooks[i].hook.data.plt_got.patched_count);
        lua_setfield(L, -2, "hooks");
        lua_rawseti(L, -2, ++count);
    }

    char msg[128];
    snprintf(msg, sizeof(msg), "Active traces: %d", count);
    send_to_cli(msg);

    return 1;
}

void register_strace_api(lua_State* L) {
    lua_newtable(L);

    lua_pushcfunction(L, lua_syscall_trace);
    lua_setfield(L, -2, "trace");

    lua_pushcfunction(L, lua_syscall_trace_all);
    lua_setfield(L, -2, "traceAll");

    lua_pushcfunction(L, lua_syscall_untrace);
    lua_setfield(L, -2, "untrace");

    lua_pushcfunction(L, lua_syscall_stop);
    lua_setfield(L, -2, "stop");

    lua_pushcfunction(L, lua_syscall_list);
    lua_setfield(L, -2, "list");

    lua_pushcfunction(L, lua_syscall_active);
    lua_setfield(L, -2, "active");

    lua_setglobal(L, "Syscall");
}
