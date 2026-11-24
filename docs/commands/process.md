---
title: Process Management
layout: default
parent: Command Reference
nav_order: 1
---

# Process Management

## `spawn <package> [options]`

Spawn a new process and inject payload.

```bash
# Spawn with default trampoline hooking
spawn com.example.app

# Spawn with PLT/GOT hooking
spawn com.example.app --hook=pltgot

# Spawn with pause (spawn gate) — freezes app before onCreate
renef -s com.example.app -l bypass.lua --pause
```

**Options:**

| Flag | Description |
|---|---|
| `--hook=pltgot` | Use PLT/GOT hooking instead of trampoline |
| `--pause` | Freeze the main thread via ptrace before app code runs (spawn gate) |

**Output:**
```
OK 12345
```

### Spawn Gate (`--pause`)

The `--pause` flag freezes the target's main thread **before any application code runs**, using a ptrace-based injection path. This ensures hooks are installed before startup code executes — critical for bypassing root detection, integrity checks, or other startup-time protections.

**How it works:**
1. App is launched and its PID is obtained.
2. Instead of the normal signal-based injection, RENEF uses `ptrace_inject()`:
   - `PTRACE_ATTACH` (followed by `waitpid`) stops the main thread immediately — before app code runs.
   - The original CPU registers are saved, then hijacked to call the linker's `__loader_dlopen` (the 3-arg form). The caller address is set to the **libc base**, which resolves the load into the default/platform namespace — the only namespace allowed to `dlopen` from `/data/local/tmp/`. The app's classloader namespace cannot, and the 2-arg `dlopen` stub (which derives the caller from `LR`, `0` in our setup) would land in the wrong namespace.
   - The agent path is written into libc's `timezone` variable, an always-mapped RW page in `.bss` — writing below the stack can hit unmapped guard pages in freshly-forked zygote children. The original bytes are backed up and restored after the load.
   - `libagent.so` is loaded (on failure, `dlerror()` is invoked via ptrace for diagnostics); the original registers are restored, but the **main thread is left ptrace-stopped**.
3. The agent connection is established and the gated PID is recorded. When a script is loaded (`-l` flag or `l`/`exec` command), it is sent to the agent over the socket.
4. On resume the gate calls `ptrace_resume()` → **`PTRACE_DETACH`**, and the main thread runs.

**Trade-off: this gives up RENEF's no-ptrace advantage.** The default, non-`--pause` injection path (signal-based, `malloc()` hijack — see [Architecture](../architecture.md)) never touches ptrace at all, which is what lets RENEF attach to targets that check `TracerPid` in `/proc/self/status` or call `ptrace(PTRACE_TRACEME, ...)` themselves as a classic anti-debug/anti-instrumentation self-check (a second `PTRACE_ATTACH` on an already-traced process fails, so the target can detect it). `--pause` uses real `PTRACE_ATTACH`/`PTRACE_DETACH` specifically to win the startup-time race, so a target with that kind of self-check will see a non-zero `TracerPid` and can act on it (abort, report, etc.) for as long as the gate holds the process, and some targets check this once at launch — exactly the window `--pause` holds open. Pick `--pause` when you need to beat startup-time initialization (root/integrity checks that run before your hooks could otherwise land); prefer the default path when the target's own ptrace self-check matters more than winning that race. The two concerns don't automatically conflict — plenty of targets check root/integrity at startup without also self-checking `TracerPid` — but when a target does both, `--pause` trades one problem for the other.

**Holding the gate (`--hold`):** by default the gate opens when the first script is delivered. A scripted client that needs several round trips before the app may run can spawn with `spawn <package> --pause --hold`: then `exec`/`rpc`/`l` do **not** resume the target, only the `resume` command does. The Python client's `spawn(pkg, pause=True)` uses this.

**Deferred hooks — catching the very first call:**

Pause mode is designed to pair with deferred hooks. If a hook targets a library that is **not yet loaded** when the script runs, the agent registers it as pending and starts a background poll thread that watches for the library. The thread is a tight busy-wait (`sched_yield`, no sleep between iterations) so it wins the narrow race between the library appearing in memory and the first call into it. When the main thread is detached and resumes, the library loads, the poll thread catches it, and the hook is installed **before the first call** to the target function — even in libraries that load after the script. This lets a single gated script hook functions in code that does not exist in memory yet at injection time.

Hooks are also re-entrancy-safe: a per-thread guard bypasses the handler when a hooked function is called from inside the handler itself, so you can safely hook low-level or logging functions (`strlen`, `malloc`, `__android_log_print`, `fopen`, …) without crashing on infinite recursion.

```bash
# With script — auto-resumes once the script is delivered to the agent
renef -s com.example.app -l root_bypass.lua --pause

# Without script — stays paused until manual resume
renef -s com.example.app --pause
renef> l scripts/root_bypass.lua    # loads script and auto-resumes
# or
renef> resume                       # manual resume without a script
```

> On the launcher, `-p` is a short alias for `--pause` (e.g. `renef -s com.example.app -l root_bypass.lua -p`). The interactive `spawn` command accepts the long form `--pause` only.

{: .note }
> Spawn gate stops the main thread via ptrace (`PTRACE_ATTACH` … `PTRACE_DETACH`). The process stays attached only for the brief injection window and the gated interval; it is detached the moment you resume.

---

## Headless / CI Usage (`--timeout`, `--headless`)

For a pipeline/CI step, `renef` normally can't sit in an interactive shell
waiting for `Ctrl+C`. `--timeout <seconds>` combined with `--headless` runs
non-interactively: load a script, run for up to `N` seconds (driving the
same relay `watch` uses under the hood, so hook-triggered `send()`/`print()`
output during that window isn't dropped), then auto-detach and exit with a
result-derived code.

```bash
renef -s com.example.app -l audit.lua --timeout 30 --headless
```

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | OK — script ran, no errors |
| `2` | Connect/spawn/attach failure |
| `3` | Lua script error |
| `4` | Best-effort hook-install failure (detected via `adb logcat`; falls back to `3` if undetectable) |

This pairs naturally with `send()` (see the [Console API]({% link
docs/api/console.md %})): a script can emit `send({...})` findings during
the timeout window, and the pipeline parses `"[event] ..."` lines out of
stdout once the process exits.

---

## `resume`

Resume a spawn-gated process. Only needed when `--pause` was used without a script.

```bash
renef> resume
Resumed pid 12345
```

---

## `attach <pid> [--hook=type]`

Attach to running process by PID.

```bash
# Attach to PID
attach 1234

# Attach with PLT/GOT hooking
attach 1234 --hook=pltgot
```

**Output:**
```
OK
```
