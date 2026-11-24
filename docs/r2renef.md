---
title: r2renef
layout: default
nav_order: 11.5
---

# r2renef

[r2renef](https://github.com/Ahmeth4n/r2renef) is a Radare2 IO plugin that connects Radare2 to Renef: open a live Android process as if it were a file, read and patch its memory with ordinary r2 commands, and hook the function under the cursor.

This page describes r2renef 0.2, which is meant for Renef 0.4.0 and newer. It still talks to older servers, with the limits listed under [Older servers](#older-servers).

---

## Features

- **Live memory** - `px`, `pd`, `pf`, `w` ... work on the target's memory
- **Maps and flags** - the target's memory ranges become io maps; modules, exports and symbols become flags
- **Hook at the cursor** - `:hook` hooks the function you are looking at; hooks show up as flags and comments, with hit counts
- **Backtraces, syscall tracing, search** - `:bt`, `:strace`, `:/x` run inside the target
- **Execute-only code** - system libraries whose code the app itself cannot read are still disassembled
- **Renef commands** - everything else after `:` goes to `renef_server` as is (`:exec`, `:la`, `:ms` ...)
- **Scripts** - `:l file.lua` runs a local Lua script in the target, `:watch` follows hook output

---

## Installation

### Requirements

- Radare2 >= 5.9.0 (developed and tested with 6.1.4)
- `renef_server` running on an ARM64 Android device
- A POSIX host (macOS, Linux, WSL)

### Build & Install

```bash
git clone https://github.com/Ahmeth4n/r2renef
cd r2renef
make
make install
```

Or with Meson:

```bash
meson setup build
ninja -C build
ninja -C build install
```

To try a build without installing it, hand the plugin file to r2 with `-I`:

```bash
r2 -I ./build/io_renef.dylib renef://spawn/com.example.app    # .so on Linux
```

---

## Quick Start

```bash
# 1. Start renef_server on the device, then forward its socket
adb forward tcp:1907 localabstract:com.android.internal.os.RuntimeInit

# 2. Open the target
r2 renef://spawn/com.example.app              # spawn
r2 renef://attach/12345                       # attach by PID
r2 renef://192.168.1.20:1907/attach/12345     # server on another host/port
```

`renef_server` serves one client at a time: close the `renef` CLI (or another r2) before connecting.

On open the plugin sets `asm.arch=arm`/`asm.bits=64`, maps the target's memory ranges, defines a `lib.<name>` flag per module and seeks to libc.

---

## Radare2 Commands

```bash
[0x7f8a1c2000]> pd 20                   # disassemble
[0x7f8a1c2000]> px 64                   # hex dump
[0x7f8a1c2000]> s lib.libssl.so         # seek to a module
[0x7f8a1c2000]> om                      # the target's memory ranges, as io maps
[0x7f8a1c2000]> wx 1f2003d5 @ $$        # patch (the agent makes code pages writable)
```

{: .note }
> Radare2's own search (`/x`, `/`) reads every io map through the plugin, which on a real app means gigabytes over the socket. Use `:/x` and `:/` instead: they search inside the target and only send back the hits.

Memory mapped after the last sync (a library loaded later) is not in the io maps yet: run `:sync`.

---

## Renef Commands

`:?` prints this list. Anything that is not one of these is sent to `renef_server` unchanged, so `:exec`, `:la`, `:md`, `:ms` and the rest of the Renef CLI keep working.

| Command | What it does |
|---|---|
| `:info` | connection, protocol, target, read path |
| `:sync [-s] [module]` | refresh io maps and `lib.*` flags; with a module also flag its exports (`-s`: `.symtab` too) as `sym.<module>.<name>` |
| `:dm[*] [filter]` | memory ranges of the target |
| `:il[*] [filter]` | loaded modules (`xom` marks execute-only code) |
| `:ie[*] [module]`, `:is[*] [module]` | exports / `.symtab` symbols (default: the module at `$$`) |
| `:hook [addr] [-i\|-g[=lib]] [-r] [-b] [-e <lua>]` | hook the function at `addr` (default `$$`) |
| `:hooks`, `:unhook <id>\|all` | list / remove hooks; flags and comments follow |
| `:hookgen [addr]` | print a hook script template for `addr` |
| `:bt[*] [addr]` | last backtrace captured by a `:hook -b` hook |
| `:strace <a,b,..> [-f lib]` | trace syscalls (`-a`, `-c <category>`, `-u`, `--list`, `--active`, `--stop`) |
| `:/x [-m module] <hex>`, `:/ [-m module] <text>` | search inside the target (`??` or `..` = any byte); hits become `renef.hit<n>` flags |
| `:l <file.lua>` | run a local Lua script in the target |
| `:watch [seconds]` | show hook/trace output until Ctrl+C (or for the given time) |
| `:cache [flush\|<ms>]` | lifetime of cached pages (default 2000 ms) |
| `:raw <cmd>` | send `<cmd>` to the server without any interpretation |

Commands with a `*` print Radare2 commands instead: `.:il*`, `.:ie* libfoo.so`, `.:bt*`.

### Hooking from the cursor

```bash
[0x7100004140]> :hook                 # hook the function at the current seek
hook #0 installed at 0x7100004140 (libtarget.so+0x4140, inline)
[0x7100004140]> :hook sym.libc.so.open -r -b
[0x7100004140]> :watch                # Ctrl+C to stop
[hook libtarget.so+0x4140 @0x7100004140] tid=4242 x0=0x10 x1=0x20 x2=0x30 x3=0x40
[0x7100004140]> :hooks                # hit counts; also written as comments (CC)
[0x7100004140]> :bt                   # backtrace of the last call that hit a -b hook
```

`-r` also logs the return value, `-b` a backtrace per call, `-e <lua>` replaces the default logger with your own `onEnter(args)` body.

Two kinds of hook exist and they are not interchangeable:

- **inline** (default, `-i`): the first instruction of the function is rewritten. Sees every call. On **execute-only** code (`xom` in `:il`, `--x` in `:dm`) `:hook` asks you to choose explicitly, because Renef versions before 0.4.0 crashed the target there.
- **PLT/GOT** (`-g=<lib>`, or `-g` for all libraries): only the call sites in `<lib>` are patched; the hooked code is not touched. The address must be exactly an exported symbol, and only calls that go through the PLT of libraries loaded at that moment are seen - not calls from inside the library itself, not calls through function pointers, not libraries loaded later. At most 64 GOT slots are patched per hook, so name the caller for popular libc functions.

### Hook output

What hooks and the syscall tracer print is kept apart from command replies. It waits on the server until `:watch` asks for it (first what has been waiting, then live). Every other command shows only its own output, plus one line when something is waiting:

```
[0x7b0a45af0c]> :hooks
Active hooks: 1
  [0] target=0x7b0a45af0c hits=820
known to r2renef:
  [0] 0x7b0a45af0c libtarget.so+0x4f0c inline hits=820
(334 lines of hook output waiting, :watch shows them)
```

`hits` is the agent's own counter, so it is exact even when the server had to drop old lines of a very busy hook.

### Loading scripts

```bash
[0x00000000]> :l /path/to/hook.lua
[0x00000000]> :watch
```

---

## Reading Memory

On a current server the plugin reads through `Memory.read` in the target (plain hex, up to 32 KB per request) after checking against the memory map that the range is readable; `:info` shows the read path in use. Pages are cached for `RENEF_CACHE_MS` (2000 ms) and the cache is dropped after every write and every `:` command that can change the target.

**Execute-only code** (`--x` in `:dm`) cannot be read from inside the target at all. For those pages the plugin asks `renef_server` to read `/proc/<pid>/mem` (the [`memdump`]({% link docs/commands/memory.md %}) command), so system libraries with execute-only text disassemble like any other code. `:info` shows this as `xom reads`.

---

## Using Static Analysis Results in a Live Session

Flags produced by another r2 session or tool for the library *file* can be brought into the live session by shifting them to the module's runtime base:

```bash
# static session: export the flags of the file
r2 -q -c 'f*~sym.' libnative.so > flags.r2

# live session: import them at the runtime base, then use the names
[0x00000000]> s lib.libnative.so
[0x7ae3dea000]> fb `s`
[0x7ae3dea000]> . flags.r2
[0x7ae3dea000]> fb 0
[0x7ae3dea000]> :hook sym.some_internal_function -r
```

The same works for the output of metadata recovery plugins that print r2 flag commands.

---

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `RENEF_HOST`, `RENEF_PORT` | `127.0.0.1`, `1907` | server address (the URI can carry it too) |
| `RENEF_FRAMING` | `auto` | `auto` probes the server; `off` forces the legacy protocol, `on` framing |
| `RENEF_TIMEOUT` | `35` | seconds without any data before a request is given up on |
| `RENEF_SPAWN_TIMEOUT` | `60` | seconds to wait for spawn/attach |
| `RENEF_CONNECT_TIMEOUT` | `5` | seconds to wait for the TCP connection |
| `RENEF_PROBE_TIMEOUT_MS` | `3000` | how long the framing probe waits for any answer |
| `RENEF_READ` | `auto` | `auto`, `lua` or `md` |
| `RENEF_CACHE_MS` | `2000` | page cache lifetime, `0` = off |
| `RENEF_MAPS` | `ranges` | `ranges`: one io map per range; `full`: keep Radare2's single map over everything |
| `RENEF_NOSYNC` | unset | `1`: do not sync maps/flags or seek on open |
| `RENEF_LEGACY_FIRST_MS`, `RENEF_LEGACY_QUIET_MS` | `8000`, `400` | legacy protocol only: wait for the first byte / silence that ends a reply of unknown shape |

---

## Older Servers

The plugin probes the server on connect. With Renef before 0.4.0 it falls back to the legacy line protocol, and some things work differently:

- **Slow `exec`-based commands.** An old server stays in its `exec` handler for about five seconds after every script. Reads use `md`, which has no such wait, but the sync on open, `:hook`, `:sync <module>` and writes take those seconds per request.
- **Execute-only code reads as `ff`** (no server-side read), and `:hook` on it needs `-g` or an explicit `-i`.
- **`md` can return wrong bytes while a hook is printing**: the agent sends the dump and the hook output over the same socket. Remove printing hooks before trusting what you read.
- **Hook output** that nobody asked for is shown on stderr around the next command, and `hits` is counted from the hook lines that were seen.

---

## Comparison: r2renef vs r2frida

| | r2renef | r2frida |
|---|---|---|
| **Backend** | Renef | Frida |
| **Platform** | Android ARM64 | Multi-platform |
| **Scripting** | Lua | JavaScript |
| **Hook commands** | `:hook`, `:hooks`, `:bt` (or `:exec hook(...)`) | `\di`, `\dif` |
| **Memory read** | Native r2 IO, execute-only code included | Native r2 IO |
| **Java hooks** | `:exec hook("class", ...)` | `\dij` |
| **Root required** | Yes (or gadget mode) | Yes (or gadget) |

---

## Roadmap

- [x] Basic IO (read/seek), memory write
- [x] Renef command passthrough, script loading, hook watch
- [x] Maps/flags integration
- [x] Hook at cursor, backtraces, syscall tracing, search in the target
- [ ] Debug plugin (breakpoints, stepping)
- [ ] Register access
