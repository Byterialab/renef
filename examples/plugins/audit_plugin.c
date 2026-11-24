// Audit-trail plugin for renef (see plugin.h).
//
// Demonstrates the "claim model" plugin upgrade: instead of owning one
// fixed command name (the classic PLUGIN_COMMAND model -- see
// test_plugin.c), this plugin exports `ren_plugin_want()` and is asked,
// for EVERY command the operator types, "do you want this?". It always
// says yes, logs the raw command line, then calls `ren_dispatch()` to run
// the command through renef's own normal fixed-name dispatch so behavior
// is otherwise unchanged -- it wraps every existing command (e.g. `hooks`,
// `plugins`, `eval ...`) without a single line of cmd_*.cpp being touched.
//
// This is the motivating example for the claim model: an audit-trail
// plugin that logs every command, without touching any cmd_*.cpp.
//
// Caveat -- SELF-UNLOAD HAZARD (real, found while building this example;
// see the long comment on `ren_dispatch()` in plugin.h): this plugin claims
// almost everything, but it deliberately does NOT claim "plugin "-prefixed
// commands (see the want() guard below). If it did, and the operator ran
// `plugin unload audit_plugin`, `ren_plugin_exec()` would call
// `ren_dispatch()`, which runs that command through the normal path, which
// calls `plugin_unload()` -> `dlclose()` on THIS plugin's own shared
// library -- while this exact function is still on the call stack inside
// that library. Unmapping your own code out from under your own still-
// running call stack is undefined behavior; on this host it reliably
// segfaults right after the unload "succeeds". The fix is this plugin's
// job, not the core's: never claim a command that might unload you. A
// plugin that only wants to wrap a narrower, unrelated set of commands
// should scope its `ren_plugin_want()` check accordingly (e.g.
// `strncmp(raw_input, "eval ", 5) == 0`) and will not hit this.
//
// Build: gcc -shared -fPIC -o audit_plugin.so audit_plugin.c
//        (or `make install` from examples/plugins/, same as test_plugin.c)
//
// Usage (after `plugin load <path-to-audit_plugin.so>`):
//   Just use renef normally -- every command typed afterwards gets an
//   "[audit] <command>" line printed before it runs.

#include <renef/plugin.h>
#include <stdio.h>
#include <string.h>

RENPluginMetadata ren_plugin_info = {
    .name = "audit_plugin",
    .author = "renef",
    .version = "1.0.0",
    .description = "Logs every command typed, then runs it normally (claim-model demo)",
    .command = NULL,            // Claim-model plugins don't own a fixed command slot.
    .type = PLUGIN_COMMAND
};

int ren_plugin_init(renef_ctx_t ctx) {
    (void)ctx;
    return 0;
}

// Exporting this symbol is what opts this plugin into the claim model.
// Claims everything EXCEPT "plugin "-prefixed commands -- see the
// self-unload hazard explained above. "plugin"/"plugins" management
// commands are also already visible in renef's own CLI output (Loaded/
// Unloaded messages), so there's little audit value in wrapping them
// anyway.
bool ren_plugin_want(const char* raw_input) {
    if (!raw_input) return false;
    if (strncmp(raw_input, "plugin", 6) == 0) return false; // covers "plugin" and "plugins"
    return true;
}

// Called with the FULL raw command line (not just trailing args, unlike
// the classic exec() model) because `want()` claimed it.
int ren_plugin_exec(renef_ctx_t ctx, char* input) {
    if (!ctx || !input) return -1;

    char msg[320];
    snprintf(msg, sizeof(msg), "[audit] %s\n", input);
    ren_print(ctx, msg);

    // Run it through the real dispatch path so the command actually does
    // what it normally does -- this is the "wrap, don't replace" idiom.
    // ren_dispatch() bypasses the claim-check layer, so this does not
    // re-enter ren_plugin_want()/ren_plugin_exec() for the same input.
    return ren_dispatch(ctx, input);
}

void ren_plugin_close(renef_ctx_t ctx) {
    (void)ctx;
}
