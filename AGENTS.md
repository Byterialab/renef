# AGENTS.md

Guidance for AI coding agents working in the **Renef** repository.

## What this project is

Renef is a **dynamic instrumentation toolkit for Android ARM64** (a Frida-like).
It hooks native and Java functions, scans/patches memory, and injects into running
processes, all driven by a **Lua scripting interface**. Default injection is
signal-based (no ptrace); the `--pause` spawn-gate path uses ptrace (see below).

Target: `aarch64-linux-android` only. Disassembly via Capstone, scripting via Lua 5.4.

## Architecture (three parts)

Renef is split into a **host client** and an **on-device agent + server**:

```
Host (macOS/Linux/WSL)                 Android device (ARM64)
┌────────────────────┐   TCP/UDS   ┌──────────────────────────┐
│ renef CLI client   │◄──────────► │ renef_server (daemon)     │
│ librenef (C++)     │             │   └─ spawns/attaches app  │
│ python binding     │             │ libagent.so (injected)    │
└────────────────────┘             │   └─ Lua VM + hooks       │
                                   └──────────────────────────┘
```

- **`src/binr/renef/`** — the CLI client entry point (`main.cpp`, arg parsing).
- **`src/binr/renef-strace/`** — standalone strace-style front end.
- **`src/librenef/`** — host-side C++ library: command dispatch, transport, plugins.
  - `cmd/` — one file per command (`cmd_spawn.cpp`, `cmd_eval.cpp`, `cmd_hooks.cpp`, `cmd_resume.cpp`, …). Each registers a `CommandDispatcher`.
  - `transport/` — TCP / Unix-domain socket transport (ASIO).
  - `include/renef/framing.h` — optional request framing used on both hops (host↔server, server↔agent):
    `@req <id> <len>\n<payload>` → output + `\x1e@done <id>\n`. Unframed line mode still works; new
    commands that talk to the agent should use `renef_agent_request::run()` (`agent_request.h`) instead of
    hand-rolled `poll`/`recv` loops.
  - `binding/` — C ABI consumed by the Python binding.
  - `plugin/` — host plugin loading.
- **`src/inject/`** — process injection. `ptrace_injector.cpp` is the `--pause` path; the signal-based injector is the default.
- **`src/agent/`** — code that runs **inside the target process** (`libagent.so`):
  - `lua/` — the Lua API surface, one `api_*.c` per module + `engine.c` (VM init). **This is the file to touch when adding a script-facing API.**
  - `hook/` — `native.c` (trampoline + PLT/GOT hooking, ARM64 codegen) and `java.c` (ART method hooking).
  - `kcov/`, `strace/`, `proc/`, `handlers/`, `core/` — coverage, syscall tracing, /proc helpers, command handlers, agent main loop.
- **`src/server/`** — the on-device `renef_server` daemon.
- **`bindings/python/renef/`** — pure-Python client (`client.py`, `transport.py`, `lua.py`); talks to
  `renef_server` over TCP, no native library. `core.py` keeps the old `Renef`/`RenefSession` names.
  Tests: `bindings/python/tests/` (`test_api.py` offline with a mock server, `test_device.py` on a device).
- **`external/`** — vendored deps (asio, lua, capstone). Populated by `make setup`.

## Build & deploy

Prerequisites: CMake 3.16+, a C++17 compiler, Android NDK r25+.

```bash
make setup        # first time: fetch + build asio, lua, capstone (host + android)
make all          # build client + server + agent payload (== client server payload)
make install      # build, push server + agent to device, start server (needs adb)
make payload      # rebuild only the injected agent (libagent.so)
make server       # rebuild only the on-device server
make client       # rebuild only the host CLI
make release      # optimized build
make debug        # debug build
make deploy-local # build android client + server + payload locally (no push)
make clean        # clean build artifacts (clean-all also clears capstone)
make info         # print resolved build variables/paths
```

Client-only on Windows: `build_wsl.bat` (runs inside WSL Ubuntu).

After `make install`, the host CLI binary is `./renef` (or `./build/renef`).
Run e.g. `./renef -s com.example.app -l script.lua`.

## The Lua API surface (what scripts call)

Each module lives in `src/agent/lua/` and is documented under `renef-doc/docs/api/`:

This table is an **orientation summary**, not the exhaustive per-function reference.
The authoritative full API (every function, args, return values) lives in
`renef-doc/docs/api/`. The exact registration tables are the `luaL_Reg` arrays and
`lua_setfield`/`lua_setglobal` calls in each `api_*.c` and in `engine.c`.

| Global    | Registered in     | Functions |
|-----------|-------------------|-----------|
| `hook`    | `api_hook.c`      | global function `hook(...)` — native + Java; `{onEnter, onLeave}`; `caller=` for PLT/GOT |
| `Interceptor` | `api_hook.c`  | `replace(lib, offset, callback)` — replace a native function; callback's return becomes the result |
| `NativeFunction` | `api_hook.c` | global — `NativeFunction(addr[, retType[, argTypes]])` calls native code from Lua (≤8 int/ptr args, x0-x7); also reaches a hooked original via the reentrancy guard |
| `Memory`  | `api_memory.c`    | `search`, `scan`, `dump`, `read`, `write`, `patch`, `alloc`, `allocStr`, `free`, `protect`, `readU8/16/32/64`, `writeU8/16/32/64`, `readStr`/`readString`, `hexdump` (+ global `hexdump`) |
| `Module`  | `engine.c`        | `list`, `find`, `exports`, `symbols` |
| `Java`    | `api_java.c`      | `use`, `registerClass`, `array`, `enumerateLoadedClasses`, `methodInfo`; wrapper `:new`/`:call`; instance `:call` + `.raw` |
| `JNI`     | `engine.c`        | type-tag helpers: `string`, `int`, `long`, `boolean` |
| `Jni`     | `api_jni.c`       | raw JNI: `newStringUTF`, `getStringUTF`, `getStringLength`, `deleteGlobalRef` (note: lowercase, distinct from `JNI`) |
| `Thread`  | `api_thread.c`    | `backtrace` (PAC-aware), `id` |
| `Syscall` | `api_strace.c`    | `trace`, `traceAll`, `untrace`, `stop`, `list`, `active` |
| `KCov`    | `api_kcov.c`      | `open`; on the state object: `enable`, `disable`, `collect`, `count`, `reset`, `close`, `edges`, `diff` |
| `File`    | `api_file.c`      | `readlink`, `read`, `write`, `exists`, `fdpath` |
| `OS`      | `api_os.c`        | `getpid`, `kill`, `tgkill`, `listdir` |
| `console` | `engine.c`        | `console.log`; overridden global `print`; color globals `RESET`/`RED`/`GREEN`/`YELLOW`/`BLUE`/`MAGENTA`/`CYAN`/`WHITE` |

**Adding a new Lua function:** implement it in the relevant `api_*.c`, register it
in that module's `luaL_Reg` table (or `engine.c` for globals), rebuild with
`make payload`, redeploy, and document it under `renef-doc/docs/api/`.

## Hooking model (important context)

- **Trampoline / inline** (default): `native.c` disassembles the prologue with
  Capstone, relocates PC-relative instrs (ADRP/ADR/LDR-literal), and branches to a
  thunk. Works on any function.
- **PLT/GOT**: pass `caller="liblib.so"` (or a list, or `"*"`). Patches GOT entries
  found via `dl_iterate_phdr` + ELF reloc parsing. Non-invasive; only dynamically
  linked call sites.
- **Java/ART** (Android 12+, `java_jni.c`): the hooked method's entry point is redirected to a native
  "twin" method with the same signature whose JNI function is our stub; ART builds the transition frame,
  so stack walks (exceptions, GC) are safe. The original runs through a copy of the method record, called
  with plain JNI. Twin and copy live in method slots of a helper class loaded from an in-memory dex
  (`hook/java_slots/Slots.java` -> `include/agent/slots_dex.h`, regenerate with
  `scripts/dev/gen_java_slots_dex.sh`) so the GC keeps their class reference current. onEnter/onLeave can
  read `this`/args and modify args + return value. Older Android falls back to the original engine in
  `java.c`, which puts frames on the stack that ART cannot walk - do not extend that one.
- **Args in callbacks** map to ARM64 registers `x0..x7` as `args[0..7]`; `onLeave`
  gets `retval` (x0) and may return a replacement.
- ARM64-only. PAC stripping is applied in backtraces.

## `--pause` spawn gate (ptrace)

`--pause` uses `ptrace_inject()` (`src/inject/ptrace_injector.cpp`): `PTRACE_ATTACH`
freezes the main thread before app code runs, the linker's `__loader_dlopen` is
called to load the agent, and the thread is left **ptrace-stopped**. It resumes via
`PTRACE_DETACH` (`ptrace_resume`) when a script is delivered (`exec`/`load`
auto-resume) or on a manual `resume`. Pairs with **deferred hooks**: hooks for
not-yet-loaded libraries are registered pending and installed by a poll thread the
instant the library loads — catching the first call. Gated state lives in
`CommandRegistry::gated_pid`. (Note: the default, non-`--pause` injection is
signal-based and does **not** use ptrace.)

**Anti-debug caveat:** `--pause` being attached means `TracerPid` in `/proc/self/status`
is non-zero, and a target's own `ptrace(PTRACE_TRACEME, ...)` self-check
will fail — exactly the anti-debug signal that the default signal-based
injection (no ptrace) is otherwise immune to. The same applies to hardware
breakpoints/watchpoints, which on ARM64/Android require ptrace to arm (so
they do **not** avoid this detection vector either, despite not patching
code bytes). **Prefer the default (non-`--pause`) injection path against
any target suspected of anti-debug/TracerPid checks**; reach for `--pause`
only when its spawn-gate/deferred-hook timing guarantee is actually needed
and the target's ptrace-sensitivity is unknown or confirmed absent.

## Conventions for changes

- **Agent code (`src/agent/`) is C**; host code (`src/librenef/`, `src/binr/`) is C++17. Match the language and style of the file you edit.
- Adding a host command: create `cmd_<name>.cpp` in `src/librenef/cmd/`, follow the existing `CommandDispatcher` pattern, and register it.
- Keep the **docs in sync**: user-facing behavior is documented in the separate
  `renef-doc/` repo (`docs/api/`, `docs/commands/`, `docs/release-notes/`). When you
  change a flag, command, or API, update the matching page there.
- The project version lives in `CMakeLists.txt` (`project(renef VERSION …)`).
- Example Lua scripts live in `scripts/examples/` and `examples/`.

## Gotchas

- `make server` / `make payload` do not track header dependencies: after changing only a `.h`, `touch` the
  sources that include it (or the build silently reuses stale objects).
- Calls made by `libagent.so` itself (and by agent threads) never enter native hooks; only a script's
  explicit `NativeFunction` / Java method calls do. Per-thread hook state lives in a libc-free table in
  `native.c`, not in `__thread` variables (emulated TLS allocates) — keep it that way on the handler path.
- Output has two channels. What the command thread prints is the reply and goes to the command socket;
  what hook callbacks and the syscall tracer print goes to a second connection the server opens
  (`@events`, see `core/output_queue.c` and `SocketHelper::pump_events`). The server buffers it and only
  `events`/`watch` deliver it; a framed reply's marker says how much is waiting (`@done <id> ev=<n>`).
  New agent code that prints from a hooked thread must go through `output_queue_push()`, not `write()`
  on `g_output_client_fd`.
- Without the event channel (older peer, `RENEF_NO_EVENT_CHANNEL=1`, gadget mode) both kinds share the
  command socket: a server command that expects a fixed-size binary reply from the agent then gets the
  wrong bytes while a hook prints. `md` therefore reads `/proc/<pid>/mem` in the server and only falls
  back to the agent. Use framed, text replies for new commands.
- An app that is not debuggable is not "dumpable": `/proc/self/mem` belongs to root there. Agent code
  that needs it goes through `agent_open_self_mem()` (`core/globals.c`), which sets the flag just for the
  open. Test agent changes in an ordinary app too, not only in a debuggable one - ART behaves differently
  there (boot-image JNI stubs, the fast interpreter), which is why `java_jni.c` learns its two entry
  points from probe methods in `Slots.java`.
- The host CLI forwards and connects to `RENEF_PORT` (default 1907); `RENEF_ADB_FORWARD=off` leaves the
  forward to the user (second device, or a server started with `--transport TCP`).
- ARM64 / Android only — don't add x86 or iOS assumptions.
- The agent runs **inside another process**; avoid heavy host-only deps in `src/agent/`.
- Hooks are capped (`MAX_HOOKS`) and Lua calls are serialized under `g_lua_mutex` — keep callbacks fast.
- `Memory.search` scans `/proc/self/maps` with a size cap; large scans are bounded on purpose.
