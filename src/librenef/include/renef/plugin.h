#pragma once

#include <stddef.h>
#include <stdbool.h>

#ifdef __APPLE__
    #define RENEF_PLUGIN_DIR "~/.config/renef/plugins"
    #define RENEF_PLUGIN_EXT ".dylib"
#elif __linux__
    #define RENEF_PLUGIN_DIR "~/.config/renef/plugins"
    #define RENEF_PLUGIN_EXT ".so"
#elif _WIN32
    #define RENEF_PLUGIN_DIR "%APPDATA%\\renef\\plugins"
    #define RENEF_PLUGIN_EXT ".dll"
#endif

#ifdef __APPLE__
    #define RENEF_SYSTEM_PLUGIN_DIR "/usr/local/lib/renef/plugins"
#elif __linux__
    #define RENEF_SYSTEM_PLUGIN_DIR "/usr/lib/renef/plugins"
#endif

/* Plugin type enum.
 *
 * A small, purely
 * additive taxonomy inspired by radare2's RLibStruct model, where every
 * subsystem (r_bin, r_anal, r_io, r_core, ...) tags its plugins with a type.
 * Renef doesn't need r2's full breadth yet, so this only grows the enum as
 * concrete use cases land:
 *   - PLUGIN_LUA / PLUGIN_NATIVE: reserved, not yet wired to a loader path.
 *   - PLUGIN_COMMAND: a plugin that owns one fixed top-level CLI command
 *     (`metadata->command`), dispatched the "classic" way -- unchanged.
 *   - PLUGIN_EXTERNAL_TOOL: a thin orchestration layer over an already-
 *     installed external binary (shell out + parse + report, e.g. the Redex
 *     plugin in examples/plugins/). Purely a metadata tag; dispatch-wise it
 *     behaves exactly like PLUGIN_COMMAND.
 *   - PLUGIN_FORMATTER: a plugin that converts a command's raw text
 *     output into a named output format (e.g. "json") via `ren_plugin_format`.
 *     See the comment below `ren_plugin_format_fn`
 *     for the full mechanism and examples/plugins/json_formatter_plugin.c
 *     for a worked example.
 *
 * Note: a `HOOK_STRATEGY`
 * plugin type was also considered (for pluggable native-hook install strategies). It was left
 * out here deliberately -- there is no concrete consumer for it yet (the
 * existing trampoline/PLT-GOT hook strategies in src/agent/hook/native.c are
 * selected by the `caller=` Lua argument, not by a host-side plugin), and
 * adding an unused enum value/callback shape now would just be speculative
 * surface to maintain. Add it in a future pass once an actual plugin wants
 * to provide a custom hook-install strategy.
 */
typedef enum {
    PLUGIN_LUA,
    PLUGIN_NATIVE,
    PLUGIN_COMMAND,
    PLUGIN_EXTERNAL_TOOL,
    PLUGIN_FORMATTER
} PluginType;

/* Plugin context - opaque for C plugins, defined in C++ */
#ifdef __cplusplus
    class CommandRegistry;
    class SocketHelper;

    struct renef_ctx {
        CommandRegistry* command_registry;
        SocketHelper* socket_helper;
        int* client_fd;
        int* target_pid;
    };
#else
    /* Opaque struct for C plugins */
    struct renef_ctx;
#endif

typedef struct renef_ctx* renef_ctx_t;

#ifdef __cplusplus
extern "C" {
#endif

    typedef int (*ren_plugin_init_fn)(renef_ctx_t ctx);
    typedef void (*ren_plugin_close_fn)(renef_ctx_t ctx);
    typedef int (*ren_plugin_exec_fn)(renef_ctx_t ctx, char* input);

    /* OPTIONAL
     * export, radare2-style "claim" model.
     *
     * Background / design: the classic model above (`ren_plugin_exec`) binds
     * a plugin to exactly one fixed command name (`metadata->command`), and
     * only the text *after* that name is handed to `exec`. That's simple and
     * still fully supported -- test_plugin.c and redex_plugin.c use only
     * this model and need no changes. But it means a plugin can only ever
     * *add* a brand-new top-level command; it can never see, wrap, or
     * augment a command some other part of renef already owns (e.g. an
     * audit-trail plugin that logs every command the operator types, or a
     * plugin that wants to post-process the output of an existing command).
     *
     * radare2's r_core plugins solve this by handing the *raw, full* command
     * string to every loaded CORE plugin and letting each one decide for
     * itself ("claim") whether it wants to handle it, before r2 falls back
     * to its own builtin command table.
     *
     * Renef's equivalent: a plugin may *additionally* export a function
     * named exactly "ren_plugin_want" with this signature:
     *
     *     bool ren_plugin_want(const char* raw_input);
     *
     * If present, `plugin_load()` picks it up (see `RENPlugin::want` below)
     * and the plugin is treated as a **claim-model plugin**:
     *   - It is NOT auto-registered as a fixed-name CommandDispatcher (it
     *     doesn't own a command slot -- see `plugin_activate()` in
     *     plugin.cpp). `metadata->command` is ignored for routing purposes
     *     (it may still be set, purely for display in `plugin`/`plugins`
     *     listings).
     *   - On every single command the operator types, `CommandRegistry::
     *     dispatch()` (src/librenef/cmd/cmd.cpp) first asks every loaded
     *     claim-model plugin, in load order, "do you want this?" by calling
     *     `want(raw_input)` with the *exact, unparsed* input line (same
     *     bytes the command's own CommandDispatcher would eventually see --
     *     no "renef://" prefix stripping, no command-name splitting). The
     *     FIRST plugin that returns true wins and gets its `ren_plugin_exec`
     *     called with that same full raw string (not just the trailing
     *     args, unlike the classic model) -- it owns the entire response.
     *   - If no claim-model plugin wants it, dispatch falls through to the
     *     existing fixed-name lookup, completely unchanged. A plugin with no
     *     `ren_plugin_want` export (NULL) is invisible to this step, so
     *     every previously-written plugin keeps working exactly as before.
     *   - To let a claiming plugin still *wrap* (rather than fully replace)
     *     an existing command -- e.g. log it, then run it normally -- call
     *     `ren_dispatch()` (declared below) from inside `ren_plugin_exec`.
     *     `ren_dispatch()` runs the given raw command through the fixed-name
     *     path directly (`CommandRegistry::dispatch_fixed()`), bypassing the
     *     claim-check step entirely, so it is safe to call even when the
     *     plugin unconditionally claims every command (no self-recursion).
     *   - If multiple claim-model plugins are loaded, only the first (in
     *     load order) whose `want()` returns true runs; later ones are not
     *     consulted for that input. Scope `want()` narrowly (e.g. check a
     *     prefix of `raw_input`) unless the plugin really is meant to be a
     *     catch-all (an audit/logging plugin is the one case where claiming
     *     everything is intentional -- see examples/plugins/audit_plugin.c).
     *
     * See examples/plugins/audit_plugin.c for a complete worked example. */
    typedef bool (*ren_plugin_want_fn)(const char* raw_input);

    /* OPTIONAL export
     * for PLUGIN_FORMATTER plugins (also usable by any plugin type).
     *
     * A formatter plugin exports a function named exactly "ren_plugin_format"
     * with this signature:
     *
     *     char* ren_plugin_format(const char* format_name,
     *                              const char* input, size_t input_len);
     *
     * `format_name` is a caller-chosen label (e.g. "json", "sarif"); `input`/
     * `input_len` is the raw text to reformat (NOT necessarily NUL-terminated
     * by the caller -- treat it as a sized buffer). The plugin inspects
     * `format_name` and either:
     *   - returns NULL if it doesn't recognize that format (lets another
     *     loaded formatter plugin, if any, have a turn -- see
     *     `plugin_format()` below), or
     *   - returns a newly heap-allocated (malloc/strdup-family), NUL-
     *     terminated string with the formatted result. Ownership transfers
     *     to the caller, which must free() it.
     *
     * This is intentionally minimal plumbing, not a full "--json" on
     * every cmd_*.cpp effort -- it does not require every existing command
     * to produce a structured result. It exists so a plugin *can* register
     * as a pluggable output formatter, and `plugin_format()` can be called
     * by any host-side code (today: the `format <name> <command...>` CLI
     * command in cmd_plugin.cpp) to find one and use it on arbitrary command
     * text output. See examples/plugins/json_formatter_plugin.c. */
    typedef char* (*ren_plugin_format_fn)(const char* format_name,
                                           const char* input, size_t input_len);

    /* OPTIONAL export
     * so a plugin can hand back a STRUCTURED result instead of (or in
     * addition to) the raw text it already streams via ren_print() during
     * ren_plugin_exec().
     *
     * Why this exists: ren_plugin_exec() can only write human-readable text
     * to client_fd and return a pass/fail int -- there is no way for a
     * plugin to say "here is the actual data I found" in a form another
     * program could consume without re-parsing free-form text. A
     * FORMATTER only reformats text *after the fact*; it cannot invent
     * structure the plugin itself never produced. This closes that gap:
     * invoke(args) -> structured result.
     *
     * A plugin may export a function named exactly "ren_plugin_result_json"
     * with this signature:
     *
     *     char* ren_plugin_result_json(void);
     *
     * Called by PluginCommandDispatcher::dispatch() (plugin.cpp) immediately
     * after ren_plugin_exec() returns, *regardless* of its return value (0
     * or -1) -- a failed run is itself structured data worth reporting
     * (e.g. {"status":"error","reason":"not_installed"}), not just a text
     * error line. The plugin is expected to remember its own last-run
     * result (static state is fine -- renef runs one command at a time, no
     * concurrent exec calls) and return it here as a newly heap-allocated
     * (malloc/strdup-family), NUL-terminated JSON string. Ownership
     * transfers to the caller, which free()s it. Return NULL if there is
     * nothing to report (e.g. exec was never called).
     *
     * Deliberately a plugin-local convention (the plugin builds its own
     * JSON by hand -- same minimal-dependency spirit as
     * json_formatter_plugin.c, no JSON library vendored into examples/).
     * See examples/plugins/redex_plugin.c for a worked example: it builds
     * this from the real invocation's exit status, input, and failure
     * reason, instead of just streaming text. */
    typedef char* (*ren_plugin_result_json_fn)(void);

    typedef struct RENPluginMetadata {
        const char* name;
        const char* author;
        const char* version;
        const char* description;
        const char* command;      /* Command prefix (e.g. "test" -> "test <args>").
                                    * Ignored for routing by claim-model plugins
                                    * (those exporting ren_plugin_want); display-only
                                    * in that case. May be NULL for a plugin that owns
                                    * no CLI command at all (e.g. a pure formatter). */
        PluginType type;
    } RENPluginMetadata;

    typedef struct RENPlugin {
        RENPluginMetadata* metadata;
        void* handle;
        bool loaded;
        ren_plugin_init_fn init;
        ren_plugin_close_fn close;
        ren_plugin_exec_fn exec;
        ren_plugin_want_fn want;      /* NULL unless the plugin exports ren_plugin_want */
        ren_plugin_format_fn format;  /* NULL unless the plugin exports ren_plugin_format */
        ren_plugin_result_json_fn result_json; /* NULL unless the plugin exports ren_plugin_result_json */
    } RENPlugin;


    /* Plugin management functions */
    RENPlugin* plugin_load(const char* path);
    void plugin_unload(RENPlugin* plugin);
    int plugin_list(RENPlugin** out, int max);
    int plugin_autoload(renef_ctx_t ctx);
    int plugin_count();
    RENPlugin* plugin_find(const char* name);

    /* Runs ren_plugin_init (if present) and, on success, registers the
     * plugin's command with the CommandRegistry (if not already taken) --
     * the same two steps plugin_autoload() performs per-plugin. Used both
     * by plugin_autoload() and by the `plugin load <path>` CLI subcommand
     * (cmd_plugin.cpp) so manual and automatic loads stay consistent.
     * Returns 0 on success, -1 if ren_plugin_init failed (caller owns
     * deciding whether to plugin_unload() in that case).
     *
     * A plugin exporting ren_plugin_want is NOT registered as a
     * fixed-name CommandDispatcher here (see the ren_plugin_want_fn comment
     * above) -- it is picked up instead by plugin_find_claim() below. */
    int plugin_activate(RENPlugin* plugin, renef_ctx_t ctx);

    /* Human-readable PluginType name, for listing/log output. */
    const char* plugin_type_name(PluginType type);

    /* Returns the first loaded claim-model plugin (ren_plugin_want !=
     * NULL) whose want(raw_input) returns true, in load order, or NULL if
     * none claims it. Called from CommandRegistry::dispatch() (cmd.cpp)
     * before the classic fixed-name lookup. `raw_input` should be the exact
     * command text the operator typed (NUL-terminated). */
    RENPlugin* plugin_find_claim(const char* raw_input);

    /* Tries every loaded PLUGIN_FORMATTER-capable plugin (ren_plugin_format
     * != NULL), in load order, until one returns non-NULL for `format_name`.
     * Returns a heap-allocated, NUL-terminated string the caller must free(),
     * or NULL if no loaded plugin supports `format_name`. */
    char* plugin_format(const char* format_name, const char* input, size_t input_len);

    /* Public interface for plugin developers */
    void  ren_print(renef_ctx_t ctx, char* msg);
    int   ren_exec(const char* cmd);
    char* ren_recv();

    /* Runs `raw_cmd` through renef's own LOCAL fixed-name command
     * dispatch (CommandRegistry::dispatch_fixed() in cmd.cpp) -- the same
     * path a command typed directly into the CLI takes, and the same path
     * the classic (non-claim) plugin model already uses. Output is written
     * to ctx->client_fd, exactly like running the command normally. Unlike
     * ren_exec()/ren_recv() (which talk to the remote on-device agent over
     * the socket connection), this stays entirely host-side.
     *
     * Deliberately bypasses the claim-check step (plugin_find_claim()), so
     * it is safe to call from inside a claim-model plugin's ren_plugin_exec
     * -- including one that unconditionally claims every command -- without
     * risking infinite self-recursion. This is the mechanism a "wrap an
     * existing command" plugin (e.g. an audit-trail logger) uses to run the
     * real command after doing its own thing; see
     * examples/plugins/audit_plugin.c.
     *
     * Returns 0 if the command's own CommandResult reported success, -1
     * otherwise (including "unknown command" and a NULL ctx/raw_cmd).
     *
     * HAZARD -- do not pass through a command that might unload yourself:
     * if `raw_cmd` resolves to "plugin unload <this-plugin's-name>",
     * dispatch_fixed() ends up calling plugin_unload() -> dlclose() on THIS
     * plugin's own shared library while this very call is still on the
     * stack inside it. Unmapping your own code out from under your own
     * running call stack is undefined behavior (reliably segfaults in
     * testing). A claim-model plugin's ren_plugin_want() MUST exclude any
     * command that could unload itself (simplest: exclude all "plugin "-
     * prefixed commands, as examples/plugins/audit_plugin.c does) before
     * ever calling ren_dispatch() unconditionally. */
    int ren_dispatch(renef_ctx_t ctx, const char* raw_cmd);


#ifdef __cplusplus
}
#endif
