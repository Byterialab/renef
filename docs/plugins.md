---
title: Plugin Development
layout: default
nav_order: 9
---

# Plugin Development

Renef supports native plugins that extend the CLI with custom commands. Plugins are shared libraries (`.so`, `.dylib`, `.dll`) that are automatically loaded at startup.

## Plugin Directory

Plugins are loaded from the following directories:

| Platform | User Directory | System Directory |
|----------|----------------|------------------|
| Linux | `~/.config/renef/plugins/` | `/usr/lib/renef/plugins/` |
| macOS | `~/.config/renef/plugins/` | `/usr/local/lib/renef/plugins/` |
| Windows | `%APPDATA%\renef\plugins\` | - |

**File extensions:**
- Linux: `.so`
- macOS: `.dylib`
- Windows: `.dll`

---

## Creating a Plugin

### Required Exports

Every plugin must export the following:

```c
#include <renef/plugin.h>

// Plugin metadata (required)
RENPluginMetadata ren_plugin_info = {
    .name = "my_plugin",
    .author = "Your Name",
    .version = "1.0.0",
    .description = "Description of your plugin",
    .command = "mycommand",    // CLI command prefix
    .type = PLUGIN_COMMAND
};

// Called when plugin is loaded (optional but recommended)
int ren_plugin_init(renef_ctx_t ctx);

// Called when CLI command is executed (required for PLUGIN_COMMAND)
int ren_plugin_exec(renef_ctx_t ctx, char* input);

// Called when plugin is unloaded (optional)
void ren_plugin_close(renef_ctx_t ctx);
```

### Plugin Metadata

| Field | Type | Description |
|-------|------|-------------|
| `name` | `const char*` | Plugin identifier |
| `author` | `const char*` | Author name |
| `version` | `const char*` | Version string |
| `description` | `const char*` | Short description |
| `command` | `const char*` | CLI command prefix (e.g., `"test"` → `test <args>`). Ignored for routing by claim-model plugins (see below); may be `nil` for a plugin that owns no CLI command at all (e.g. a pure formatter). |
| `type` | `PluginType` | Plugin type — see the table below |

### Plugin Types (`PluginType`)

A small, purely additive taxonomy inspired by radare2's `RLibStruct` model —
every plugin tags itself with a type, and the type determines which
optional exports (if any) it's expected to provide.

| Type | Meaning |
|---|---|
| `PLUGIN_COMMAND` | Classic plugin: owns one fixed top-level CLI command (`metadata.command`). |
| `PLUGIN_EXTERNAL_TOOL` | A thin orchestration layer over an already-installed external binary (shell out + parse + report) — see the [Redex example](#example-external_tool-plugin-redex) below. Dispatch-wise, identical to `PLUGIN_COMMAND`; purely a metadata tag. |
| `PLUGIN_FORMATTER` | Converts a command's raw text output into a named output format (e.g. `"json"`) via `ren_plugin_format` — see [FORMATTER plugins](#formatter-plugins-pluggable-output-formats) below. |
| `PLUGIN_LUA` / `PLUGIN_NATIVE` | Reserved, not yet wired to a loader path. |

Independent of `type`, a plugin may *additionally* opt into either (or both)
of two orthogonal mechanisms by exporting extra functions — see below:
the **claim model** (`ren_plugin_want`) and **structured results**
(`ren_plugin_result_json`).

### Plugin API

Plugins have access to the following functions:

```c
// Print message to CLI output
void ren_print(renef_ctx_t ctx, char* msg);

// Send command to attached target (agent)
int ren_exec(const char* cmd);

// Receive response from target (blocking with 5s timeout)
char* ren_recv();  // Returns malloc'd string, caller must free()
```

---

## Example Plugin

### Basic Hello World

```c
// hello_plugin.c
#include <renef/plugin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

RENPluginMetadata ren_plugin_info = {
    .name = "hello",
    .author = "developer",
    .version = "1.0.0",
    .description = "Simple hello world plugin",
    .command = "hello",
    .type = PLUGIN_COMMAND
};

int ren_plugin_init(renef_ctx_t ctx) {
    (void)ctx;
    return 0;  // Success
}

int ren_plugin_exec(renef_ctx_t ctx, char* input) {
    if (!ctx) return -1;

    char msg[256];

    if (input && strlen(input) > 0) {
        snprintf(msg, sizeof(msg), "Hello, %s!\n", input);
    } else {
        snprintf(msg, sizeof(msg), "Hello, World!\n");
    }

    ren_print(ctx, msg);
    return 0;
}

void ren_plugin_close(renef_ctx_t ctx) {
    (void)ctx;
}
```

### Communicating with Target

Plugins can send commands to the attached target process:

```c
int ren_plugin_exec(renef_ctx_t ctx, char* input) {
    if (!ctx) return -1;

    // Send ping command to agent
    if (input && strcmp(input, "ping") == 0) {
        ren_exec("ping");

        char* response = ren_recv();
        if (response) {
            ren_print(ctx, response);
            free(response);
        }
    }

    return 0;
}
```

---

## The Claim Model: Seeing Every Command (`ren_plugin_want`)

The classic model above binds a plugin to exactly one fixed command name —
it can only ever *add* a new top-level command, never see or wrap a command
some other part of Renef (or another plugin) already owns.

A plugin may *additionally* export a function named exactly `ren_plugin_want`:

```c
bool ren_plugin_want(const char* raw_input);
```

If present, the plugin is treated as a **claim-model plugin**:

- It is **not** auto-registered under a fixed command slot — `metadata.command`
  is ignored for routing (it may still be set, display-only, in `plugins`
  listings, where it shows as `*claim*` instead of a command name).
- On every command the operator types, each loaded claim-model plugin is
  asked, in load order, "do you want this?" via `want(raw_input)` — the
  *exact, unparsed* input line (same bytes the command's own handler would
  eventually see). The **first** plugin that returns `true` wins and gets
  its `ren_plugin_exec` called with that same full raw string (not just the
  trailing args, unlike the classic model) — it owns the entire response.
- If no claim-model plugin wants the input, dispatch falls through to the
  classic fixed-name lookup, unchanged.
- To *wrap* (rather than fully replace) an existing command — e.g. log it,
  then run it normally — call `ren_dispatch()` from inside `ren_plugin_exec`:

```c
int ren_dispatch(renef_ctx_t ctx, const char* raw_cmd);
```

`ren_dispatch()` runs `raw_cmd` through Renef's own normal fixed-name
dispatch directly, bypassing the claim-check step — safe to call even from
a plugin that unconditionally claims every command, with no risk of
infinite self-recursion.

{: .warning }
> **Self-unload hazard:** if a claim-model plugin unconditionally claims
> everything and the operator runs `plugin unload <this-plugin's-name>`,
> `ren_dispatch()` ends up calling `plugin_unload()` → `dlclose()` on the
> plugin's *own* shared library while this exact call is still on the
> stack inside it — undefined behavior (reliably segfaults). A claim-model
> plugin's `ren_plugin_want()` **must** exclude any command that could
> unload itself — simplest: exclude every `"plugin "`-prefixed command.

**Example: an audit-trail plugin that logs every command, then runs it
normally — with zero changes to any existing command's code:**

```c
RENPluginMetadata ren_plugin_info = {
    .name = "audit_plugin",
    .command = NULL,            // Claim-model plugins don't own a command slot.
    .type = PLUGIN_COMMAND
};

bool ren_plugin_want(const char* raw_input) {
    if (!raw_input) return false;
    if (strncmp(raw_input, "plugin", 6) == 0) return false; // self-unload guard
    return true;                                            // claim everything else
}

int ren_plugin_exec(renef_ctx_t ctx, char* input) {
    char msg[320];
    snprintf(msg, sizeof(msg), "[audit] %s\n", input);
    ren_print(ctx, msg);
    return ren_dispatch(ctx, input);  // run it through the real dispatch path
}
```

```
renef> plugin load audit_plugin.dylib
renef> redex app.apk -c config.json -o out.apk
[audit] redex app.apk -c config.json -o out.apk
... redex's normal output follows ...
```

See `examples/plugins/audit_plugin.c` for the full source.

---

## FORMATTER Plugins: Pluggable Output Formats

A plugin may export `ren_plugin_format` to register as a named output
formatter:

```c
char* ren_plugin_format(const char* format_name,
                         const char* input, size_t input_len);
```

`format_name` is a caller-chosen label (e.g. `"json"`, `"sarif"`); `input`/
`input_len` is the raw text to reformat (not necessarily NUL-terminated —
treat it as a sized buffer). The plugin either:

- returns `NULL` if it doesn't recognize that `format_name` (lets another
  loaded formatter plugin, if any, have a turn), or
- returns a newly heap-allocated, NUL-terminated string with the formatted
  result — ownership transfers to the caller, which `free()`s it.

A formatter plugin typically owns no CLI command of its own (`command`
is `NULL`, no `ren_plugin_exec`) — it's pure formatting plumbing, invoked by
the host-side `format <format_name> <command...>` CLI command, which runs
`<command...>` through the normal dispatch path exactly as if the operator
had typed it directly, captures that command's text output, and hands it to
`plugin_format()` to find a loaded `PLUGIN_FORMATTER` plugin that recognizes
`format_name`.

```c
RENPluginMetadata ren_plugin_info = {
    .name = "json_formatter",
    .command = NULL,
    .type = PLUGIN_FORMATTER
};

char* ren_plugin_format(const char* format_name, const char* input, size_t input_len) {
    if (!format_name || strcmp(format_name, "json") != 0) {
        return NULL; // Not ours.
    }
    // ... build a JSON string from `input`, e.g. one array entry per line ...
    return strdup(json_buffer);
}
```

```
renef> plugin load json_formatter_plugin.dylib
renef> format json plugins
{"format":"json","lines":["Loaded plugins (1):","  [1] json_formatter ..."]}
```

If no loaded plugin supports `format_name`, `format` falls back to printing
the raw, unformatted output with a `NOTE:` line.

{: .note }
> This is minimal plumbing to prove the mechanism works end to end — it does
> **not** require every existing command to produce a structured result
> internally; `format` captures whatever text a command already prints.

See `examples/plugins/json_formatter_plugin.c` for the full source.

---

## Structured Results (`ren_plugin_result_json`)

`ren_plugin_exec()` can only write human-readable text via `ren_print()` and
return a pass/fail `int` — there is no built-in way for a plugin to hand
back "here is the actual data I found" in a form another program could
consume without re-parsing free-form text. A plugin may close that gap by
exporting:

```c
char* ren_plugin_result_json(void);
```

Called immediately after `ren_plugin_exec()` returns, **regardless** of its
return value — a failed run is itself structured data worth reporting (e.g.
`{"status":"error","reason":"not_installed"}`), not just a text error line.
The plugin remembers its own last-run result (static state is fine — Renef
runs one command at a time) and returns it as a newly heap-allocated,
NUL-terminated JSON string; the caller `free()`s it. Return `NULL` if there
is nothing to report yet.

The result is relayed as its own `"[json] ..."` output line, right after
whatever text `ren_plugin_exec()` already printed:

```
renef> redex app.apk -c config.json -o out.apk
[redex] Done (exit 0).
[json] {"tool":"redex","status":"ok","exit_code":0,"input":"app.apk -c config.json -o out.apk"}
```

This is a plugin-local convention (build the JSON string by hand with
`snprintf`, same minimal-dependency spirit as the FORMATTER example above —
no JSON library is vendored into `examples/plugins/`). See
`examples/plugins/redex_plugin.c` for a worked example that reports
`status`/`exit_code`/`input`/`reason` for both success and every failure
path.

---

## Example `EXTERNAL_TOOL` Plugin: Redex

`examples/plugins/redex_plugin.c` ships with Renef as a complete,
real-world `PLUGIN_EXTERNAL_TOOL` example: it shells out to an
already-installed [Redex](https://github.com/facebook/redex) (Meta's DEX
bytecode optimizer/deobfuscator) binary — Renef does **not** vendor or
reimplement Redex itself, only orchestrates it.

```
renef> plugin load redex_plugin.dylib
renef> redex app.apk -c default.config -j android.jar -o out.apk
```

It tries both `redex` and `redex.py` on `PATH` (different install methods
name the binary differently — e.g. Homebrew's `redex` formula only provides
`redex.py`), streams Redex's own stdout/stderr live via `ren_print()`, and
reports a clear error if neither name resolves. It also runs an **advisory**
pre-flight check: Redex's own pass manager refuses to run most optimization
passes on an APK whose bytecode genuinely contains `invoke-custom`/
`invoke-polymorphic` instructions (Java 8 method-handle/`invokedynamic` —
intentional upstream behavior, not a bug). The plugin scans for this with
`unzip`+`dexdump` before handing off to Redex and prints an early warning if
found — but this is a cheap textual approximation of Redex's own CFG-level
scan, **not** authoritative; it can disagree with Redex's actual result.
Redex's own exit code is always the real source of truth. The result is
also surfaced in the structured JSON output as
`"dex38_features_detected": true/false/null` (`null` = check inconclusive,
e.g. `unzip`/`dexdump` missing or no `.apk` path found in the arguments).

---

## Example `EXTERNAL_TOOL` Plugin: Protector Fingerprint

`examples/plugins/protector_fingerprint_plugin.c` answers "which commercial
protector was this APK built with?" **before** the app is ever spawned. It is a
static, host-only pre-scan in the same style as the Redex plugin, and looks at
two independent layers:

- **Native loader layer** (DexProtector-style): a shared object that exports
  only `JNI_OnLoad`, has almost no dependencies and carries a high-entropy
  segment. Checked with [LIEF](https://lief.re) through `python3`.
- **DEX layer** (DexGuard-style): bytecode signatures found with `dexdump`
  from the Android SDK build-tools.

Both helpers are optional; a layer whose tool is missing is reported as
skipped rather than failing the command. The result is also available as JSON
through `ren_plugin_result_json`, so another plugin or a script can decide how
to proceed (for example which bypass recipe to load).

---

## Building Plugins

### Manual Build

```bash
# Linux
gcc -shared -fPIC -I/path/to/renef/include -o my_plugin.so my_plugin.c

# macOS
gcc -dynamiclib -fPIC -I/path/to/renef/include -o my_plugin.dylib my_plugin.c
```

### Using the Example Makefile

Renef includes a plugin build system in `examples/plugins/`:

```bash
cd examples/plugins

# Build all plugins in directory
make all

# Install to ~/.config/renef/plugins/
make install

# Clean build artifacts
make clean

# List available plugins
make list
```

**Makefile variables:**

| Variable | Description |
|----------|-------------|
| `RENEF_SDK` | Path to renef include directory |
| `PLUGIN_DIR` | Installation directory |
| `CC` | C compiler |
| `CFLAGS` | Compiler flags |

---

## CLI Commands

### `plugins`

List all loaded plugins (claim-model plugins show `*claim*` instead of a
command name):

```
renef> plugins
Loaded plugins (2):
  [1] hello (hello) - Simple hello world plugin [COMMAND]
  [2] audit_plugin (*claim*) - Logs every command typed, then runs it normally [COMMAND]
```

### `plugin load <path>` / `plugin unload <name>` / `plugin list`

Load or unload a plugin manually at runtime, without relying on autoload —
useful for e.g. a CI pipeline that only wants a plugin (like the Redex
`EXTERNAL_TOOL` example) loaded for the one step that needs it.

```
renef> plugin load ./examples/plugins/redex_plugin.dylib
Loaded plugin 'redex_plugin' [EXTERNAL_TOOL] as command 'redex'

renef> plugin load ./examples/plugins/audit_plugin.dylib
Loaded plugin 'audit_plugin' [COMMAND] (claim-model: sees every command via ren_plugin_want)

renef> plugin list
Loaded plugins (2):
  ...

renef> plugin unload audit_plugin
Unloaded plugin 'audit_plugin'
```

`<path>` may be a relative/absolute path to a `.so`/`.dylib`/`.dll`, or a
bare name resolved against the plugin directory (same lookup `make install`
in `examples/plugins/` deploys to).

### Using Plugin Commands

Plugin commands are invoked by their command prefix:

```
renef> hello World
Hello, World!

renef> hello
Hello, World!

renef> test ping
pong
```

---

## Plugin Lifecycle

1. **Autoload**: At startup, renef scans the plugin directory and loads all valid plugins (also triggered manually via `plugin load <path>`)
2. **Init**: `ren_plugin_init()` is called for each loaded plugin
3. **Registration**: A plugin that does **not** export `ren_plugin_want` registers its fixed command (`metadata.command`) with the CLI, exactly as before. A plugin that **does** export it (the claim model) is *not* given a fixed command slot — it's consulted on every command instead (see [The Claim Model](#the-claim-model-seeing-every-command-ren_plugin_want))
4. **Execution**: For a fixed-name command, `ren_plugin_exec()` is called when the user invokes that command. For a claim-model plugin, it's called with the full raw input whenever its `ren_plugin_want()` returns `true`. Either way, if the plugin also exports `ren_plugin_result_json()`, it's called right after and relayed as a `"[json] ..."` line
5. **Unload**: `ren_plugin_close()` is called when renef exits or the plugin is unloaded (`plugin unload <name>`)

---

## Best Practices

- Always check if `ctx` is valid before using it
- Free memory returned by `ren_recv()`
- Keep `ren_plugin_init()` lightweight (it may be called during autoload)
- Use descriptive command names to avoid conflicts
- Return `0` for success, `-1` for failure from `init` and `exec` functions
- Handle `NULL` input in `ren_plugin_exec()` gracefully
- If exporting `ren_plugin_want()`, scope it narrowly (e.g. a prefix check) unless the plugin really is meant to be a catch-all — and always exclude `"plugin "`-prefixed commands if it might ever call `ren_dispatch()` unconditionally (see the self-unload hazard above)
- If exporting `ren_plugin_result_json()`, call it for both success and failure — a failure reason is structured data too
- Treat any pre-flight/heuristic check the plugin runs before invoking its external tool as advisory only — never block or mislabel the run based on it; the tool's own exit code is the real source of truth
