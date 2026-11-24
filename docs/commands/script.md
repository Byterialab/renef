---
title: Script Execution
layout: default
parent: Command Reference
nav_order: 3
---

# Script Execution

## `exec <lua_code>`

Execute Lua code in target process. If you type code without a known command prefix, it's automatically wrapped with `exec`.

```bash
# Explicit
exec print("Hello")

# Implicit (auto-wrapped)
print("Hello")
Module.list()
```

**Output:**
```
Hello
✓ Lua executed
```

**Timeout:** `exec` waits until the code has finished. If it produces no output for 30 seconds the command gives up (the code keeps running in the target). Use `exec --timeout <seconds> <code>` for calls that legitimately take longer. A result that arrives after a timeout is discarded; it is never shown as the output of a later command.

**Machine-readable result:** `exec --json <code>` answers with exactly one JSON line instead of free text, for scripts and pipelines that drive the CLI:

```json
{"ok":true,"pid":12345,"timed_out":false,"output":"Hello\n"}
```

`ok` is false if the Lua code failed, `timed_out` is true if no completion arrived in time, and `output` is everything the code printed. To get a *value* back rather than printed text, use `rpc` below.

## `rpc [--timeout <seconds>] <lua_expression>`

Evaluate a Lua expression in the target and get the value back as one JSON line. Meant for tools and scripts; tables become JSON objects/arrays.

```bash
rpc Module.find("libc.so")
rpc {pid = OS.getpid(), tid = Thread.id()}
rpc --timeout 120 slowDecrypt()
```

**Output:**
```
{"ok":true,"value":540619386880,"__rpc_call":true}
{"ok":false,"error":"...attempt to call a nil value...","__rpc_call":true}
```

The result line always comes first. Anything else the call produced while it ran (`print()` output, `send()` events from hooks) follows on separate lines.

## `events [wait_ms]`

Return the hook output the server is holding — `print()` text and `send({...})` events (`[event] {...}` lines) from hook callbacks. Waits up to `wait_ms` milliseconds for something to arrive (default 0: only what is already there). Unlike `watch` it returns, so a scripted client can poll with it.

Hook output is delivered only by `events` and `watch`; it is not mixed into the replies of other commands. A client that uses framed requests learns from every reply how many lines are waiting (see [Wire Protocol](../architecture.md#wire-protocol)), so it only needs to ask when there is something to fetch.

What a script prints on the command thread — the body of an `exec`, or a hook callback that runs because that script called the hooked function itself — is part of that command's reply, as before.

```bash
events 500
```

## `l <file> [file2 ...] [-w|--watch]`

Load and execute one or more Lua scripts from files. Use `-w` or `--watch` to enable auto-watch mode after loading.

```bash
# Load single script
l hook.lua

# Load multiple scripts
l init.lua hooks.lua utils.lua

# Load with auto-watch (starts watching after loading)
l hook.lua -w
l script1.lua script2.lua --watch
```

**Output:**
```
Loading 2 script(s) (auto-watch enabled):
  ✓ script1.lua
  ✓ script2.lua

[Auto-watch enabled - Press Ctrl+C to exit]
📡 Watching hook output...
```
