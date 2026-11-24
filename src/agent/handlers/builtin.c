#include <agent/hook_java.h>
#include <agent/cmd_registry.h>
#include <agent/globals.h>
#include <agent/hook.h>
#include <agent/proc.h>
#include <agent/handlers.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int cmd_ping(int fd, const char* args) {
    (void)args;
    const char* pong = "pong\n";
    write(fd, pong, strlen(pong));
    return 1;
}

static int cmd_list_apps(int fd, const char* args) {
    const char* filter = NULL;
    if (args && args[0] == '~' && args[1] != '\0') {
        filter = args + 1;
    }

    FILE *fp = popen("pm list packages", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "package:", 8) == 0) {
                char* pkg_name = line + 8;
                size_t len = strlen(pkg_name);
                if (len > 0 && pkg_name[len - 1] == '\n') {
                    pkg_name[len - 1] = '\0';
                    len--;
                }
                if (filter == NULL || strstr(pkg_name, filter) != NULL) {
                    write(fd, pkg_name, len);
                    write(fd, "\n", 1);
                }
            }
        }
        pclose(fp);
    }
    return 1;
}

static int cmd_hooks(int fd, const char* args) {
    (void)args;
    // One line at a time. This used to format every hook into a single
    // `char response[1024]` with `len += snprintf(response + len,
    // sizeof(response) - len, ...)`: once the text outgrew the buffer the
    // size argument wrapped around and the next snprintf wrote past the end
    // of the stack buffer - with the hook table at 128 entries that takes
    // only ~40 hooks. It also read the trampoline union member for every
    // hook type, so PLT/GOT hooks were listed with a bogus target.
    char line[96];
    int len = snprintf(line, sizeof(line), "Active hooks: %d\n", g_hook_count);
    write(fd, line, (size_t)len);
    for (int i = 0; i < g_hook_count; i++) {
        bool installed = (g_hooks[i].type == HOOK_PLT_GOT)
            ? (g_hooks[i].data.plt_got.patched_count > 0)
            : (g_hooks[i].data.trampoline.target_addr != NULL);
        if (installed) {
            len = snprintf(line, sizeof(line), "  [%d] target=%p hits=%lu\n", i, g_hooks[i].logical_target_addr,
                           __atomic_load_n(&g_hooks[i].hits, __ATOMIC_RELAXED));
        } else {
            len = snprintf(line, sizeof(line), "  [%d] (removed)\n", i);
        }
        if (len > 0) write(fd, line, (size_t)len);
    }

    // Java method hooks have their own table and their own ids ("j0", ...).
    // The section only appears when there are any.
    if (g_java_hook_count > 0) {
        char jline[512];
        len = snprintf(jline, sizeof(jline), "Java hooks: %d\n", g_java_hook_count);
        write(fd, jline, (size_t)len);
        for (int i = 0; i < g_java_hook_count; i++) {
            const JavaHookInfo* h = &g_java_hooks[i];
            if (h->is_hooked) {
                len = snprintf(jline, sizeof(jline), "  [j%d] %s.%s%s hits=%lu\n", i,
                               h->class_name, h->method_name, h->method_sig,
                               __atomic_load_n(&h->hits, __ATOMIC_RELAXED));
            } else {
                len = snprintf(jline, sizeof(jline), "  [j%d] (removed)\n", i);
            }
            if (len > 0) write(fd, jline, (size_t)(len < (int)sizeof(jline) ? len : (int)sizeof(jline) - 1));
        }
    }
    return 1;
}

static int cmd_unhook(int fd, const char* args) {
    if (!args || !*args || strcmp(args, "all") == 0) {
        int count = uninstall_all_hooks();
        count += uninstall_all_java_hooks();
        char response[128];
        snprintf(response, sizeof(response), "Removed %d hook(s)\n", count);
        write(fd, response, strlen(response));
    } else if (args[0] == 'j' && args[1] >= '0' && args[1] <= '9') {
        int hook_id = atoi(args + 1);
        if (hook_id < g_java_hook_count && g_java_hooks[hook_id].is_hooked &&
            uninstall_java_hook(hook_id) == 0) {
            char response[128];
            snprintf(response, sizeof(response), "Hook j%d removed\n", hook_id);
            write(fd, response, strlen(response));
        } else {
            const char* error = "ERROR: Failed to remove hook\n";
            write(fd, error, strlen(error));
        }
    } else {
        int hook_id = atoi(args);
        if (uninstall_hook(hook_id) == 0) {
            char response[128];
            snprintf(response, sizeof(response), "Hook %d removed\n", hook_id);
            write(fd, response, strlen(response));
        } else {
            const char* error = "ERROR: Failed to remove hook\n";
            write(fd, error, strlen(error));
        }
    }
    return 1;
}

static int cmd_hook(int fd, const char* args) {
    handle_inspect_binary(fd, args);
    return 1;
}

static int cmd_eval(int fd, const char* args) {
    handle_eval(fd, args);
    return 1;
}

static int cmd_memscan(int fd, const char* args) {
    handle_memscan(fd, args);
    return 1;
}

static int cmd_memdump(int fd, const char* args) {
    handle_memdump(fd, args);
    return 1;
}

static int cmd_sec(int fd, const char* args) {
    char* lib_path = find_library_path(args);
    if (lib_path) {
        dump_elf_sections(fd, lib_path);
        free(lib_path);
    } else {
        char err[256];
        snprintf(err, sizeof(err), "ERROR: Library '%s' not found in process\n", args);
        write(fd, err, strlen(err));
    }
    return 1;
}

static int cmd_help(int fd, const char* args) {
    (void)args;
    cmd_list(fd);
    return 1;
}

static int cmd_verbose(int fd, const char* args) {
    if (!args || !*args) {
        char response[64];
        snprintf(response, sizeof(response), "verbose: %s\n", g_verbose_mode ? "on" : "off");
        write(fd, response, strlen(response));
        return 1;
    }

    if (strcmp(args, "on") == 0 || strcmp(args, "1") == 0) {
        g_verbose_mode = true;
        const char* msg = "verbose: enabled\n";
        write(fd, msg, strlen(msg));
        LOGI("Verbose mode enabled");
    } else if (strcmp(args, "off") == 0 || strcmp(args, "0") == 0) {
        g_verbose_mode = false;
        const char* msg = "verbose: disabled\n";
        write(fd, msg, strlen(msg));
        LOGI("Verbose mode disabled");
    } else {
        const char* err = "Usage: verbose [on|off]\n";
        write(fd, err, strlen(err));
    }
    return 1;
}

static int cmd_hexexec(int fd, const char* args) {
    if (!args || !*args) {
        const char* err = "ERROR: hexexec requires hex-encoded Lua code\n";
        write(fd, err, strlen(err));
        return 1;
    }

    size_t hex_len = strlen(args);
    size_t lua_len = hex_len / 2;
    char* lua_code = (char*)malloc(lua_len + 1);
    if (!lua_code) {
        const char* err = "ERROR: malloc failed\n";
        write(fd, err, strlen(err));
        return 1;
    }

    for (size_t i = 0; i < lua_len; i++) {
        char byte[3] = {args[i * 2], args[i * 2 + 1], 0};
        lua_code[i] = (char)strtol(byte, NULL, 16);
    }
    lua_code[lua_len] = '\0';

    handle_eval(fd, lua_code);
    free(lua_code);
    return 1;
}

void register_builtin_commands(void) {
    cmd_register("ping", cmd_ping);
    cmd_register("la", cmd_list_apps);
    cmd_register("hooks", cmd_hooks);
    cmd_register("unhook", cmd_unhook);
    cmd_register("hookn", cmd_hook);
    cmd_register("exec", cmd_eval);
    cmd_register("hexexec", cmd_hexexec);
    cmd_register("ms", cmd_memscan);
    cmd_register("md", cmd_memdump);
    cmd_register("sec", cmd_sec);
    cmd_register("help", cmd_help);
    cmd_register("verbose", cmd_verbose);
}
