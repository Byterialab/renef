#include <agent/handlers.h>
#include <agent/globals.h>

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * hookn <lib> <offset|symbol>  -  "hook native"
 *
 * Hooks one native function without a script: every call prints the first
 * four argument registers and the return value. It is the quickest way to
 * answer "is this function called, and with what".
 *
 * The hook is installed through the same path as hook() in a script (this
 * builds the script and runs it), so it gets everything that path provides:
 * the per-hook thunk, the reentrancy guard, deferred installation when the
 * library is not loaded yet, a slot in `hooks` with a call counter, removal
 * with `unhook`. An earlier version patched the function to jump straight
 * into the generic handler, without the thunk that tells the handler which
 * hook it is serving.
 */

/* Library and symbol names end up inside Lua string literals. */
static bool name_is_plain(const char* s) {
    if (!*s) return false;
    for (; *s; s++) {
        if (!(isalnum((unsigned char)*s) || strchr("._-+$@:", *s))) return false;
    }
    return true;
}

static bool parse_number(const char* s, unsigned long long* out) {
    char* end = NULL;
    if (!isdigit((unsigned char)s[0])) return false;
    *out = strtoull(s, &end, 0);    /* 0x... or decimal */
    return end && *end == '\0';
}

void handle_inspect_binary(int client_fd, const char* args) {
    char lib_name[128];
    char target[160];

    if (!args || sscanf(args, "%127s %159s", lib_name, target) != 2) {
        const char* error = "ERROR: Usage: hookn <lib_name> <offset|symbol>\n";
        write(client_fd, error, strlen(error));
        return;
    }
    if (!name_is_plain(lib_name) || !name_is_plain(target)) {
        const char* error = "ERROR: hookn: unsupported character in library or symbol name\n";
        write(client_fd, error, strlen(error));
        return;
    }

    char target_lua[200];
    unsigned long long offset = 0;
    if (parse_number(target, &offset)) {
        snprintf(target_lua, sizeof(target_lua), "0x%llx", offset);
    } else {
        snprintf(target_lua, sizeof(target_lua), "\"%s\"", target);
    }

    verbose_log("hookn: lib=%s target=%s", lib_name, target_lua);

    char lua[2048];
    int n = snprintf(lua, sizeof(lua),
        "local ok, err = pcall(function() "
        "local lib, target = \"%s\", %s "
        "local loaded = Module.find(lib) ~= nil "
        "local off = target "
        "if type(target) == \"string\" then "
        "  if not loaded then error(lib .. \" is not loaded: give an offset to hook it when it loads\", 0) end "
        "  local m = Module.findExportByName(lib, target) "
        "  if not m or #m == 0 then error(\"no export '\" .. target .. \"' in \" .. lib, 0) end "
        "  off = m[1].offset "
        "end "
        "local tag = string.format(\"%%s+0x%%x\", lib, off) "
        "hook(lib, off, { "
        "  onEnter = function(args) "
        "    print(string.format(\"[hookn %%s] tid=%%d x0=0x%%x x1=0x%%x x2=0x%%x x3=0x%%x\", "
        "      tag, Thread.id(), args[0], args[1], args[2], args[3])) "
        "  end, "
        "  onLeave = function(retval) "
        "    print(string.format(\"[hookn %%s] ret=0x%%x\", tag, retval)) "
        "  end "
        "}) "
        "if loaded then "
        "  print(\"Hooked \" .. tag .. \" (calls are shown by watch; hooks lists it, unhook removes it)\") "
        "else "
        "  print(lib .. \" is not loaded yet: the hook on \" .. tag .. \" will be installed when it loads\") "
        "end "
        "end) "
        "if not ok then print(\"ERROR: hookn: \" .. tostring(err)) end",
        lib_name, target_lua);
    if (n <= 0 || (size_t)n >= sizeof(lua)) {
        const char* error = "ERROR: hookn: names too long\n";
        write(client_fd, error, strlen(error));
        return;
    }

    handle_eval(client_fd, lua);
}
