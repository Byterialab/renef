---
title: Architecture
layout: default
nav_order: 3
---

# Architecture

## Components

**Client (build/renef)**
- Native macOS/Linux CLI application
- Interactive REPL with tab completion
- Connects to server via ADB-forwarded TCP (localhost:1907)

**Server (renef_server)**
- ARM64 Android binary
- Listens on Abstract Unix Domain Socket
- Performs process injection via memfd + shellcode
- Routes commands to injected payload

**Payload (libagent.so)**
- Shared library injected into target
- Contains Lua 5.4 engine
- Implements hooking engine (Capstone-based)
- Executes user scripts in process context

## Communication Flow

```
Host Machine                          Android Device
┌─────────────┐                      ┌──────────────┐
│   Client    │ ───TCP:1907───────> │    Server    │
│ (renef CLI) │  (adb forwarded)     │              │
└─────────────┘                      └──────┬───────┘
                                           │ memfd+shellcode
                                           │ injection
                                           ▼
                                    ┌──────────────┐
                                    │   Payload    │
                                    │ libagent.so  │
                                    │              │
                                    │ ┌──────────┐ │
                                    │ │  Lua 5.4 │ │
                                    │ └──────────┘ │
                                    └──────────────┘
                               Target Process Memory
```

## Injection Method

Renef loads its agent by borrowing one call to `malloc()`:

1. **Code cave** - The server finds a stretch of unused bytes in libc's executable memory and writes the stage 1 shellcode there (through `/proc/<pid>/mem`).
2. **One-instruction patch** - The first instruction of `malloc()` is replaced by a branch to the cave. Only four bytes of live code change, so no thread can be caught halfway through a multi-instruction patch.
3. **Trigger** - The next thread that calls `malloc()` runs stage 1, which maps a fresh region for stage 2.
4. **Stage 2** - Calls `dlopen()` on the agent (`libagent.so`).
5. **Restoration** - `malloc()` gets its original instruction back and the call continues as if nothing had happened; the cave is cleared a few seconds later.

This path does **not** use ptrace. The exception is the spawn gate (`--pause`), which attaches with ptrace to freeze the app before its first instruction; see [Process Management]({% link docs/commands/process.md %}) for when that matters.

## Communication: Abstract Unix Domain Sockets

Renef uses **Abstract Unix Domain Sockets (UDS)** instead of TCP for on-device communication. This provides several advantages:

### Why Abstract Sockets?

| Feature | Abstract UDS | TCP |
|---------|-------------|-----|
| Namespace | Kernel-managed, no filesystem | Requires port binding |
| Security | Process-level isolation | Network accessible |
| Performance | Zero-copy, no network stack | TCP/IP overhead |
| Cleanup | Auto-removed on process exit | Port may linger |

### Abstract Socket Details

Abstract sockets are identified by a null byte prefix (`\0`) in the socket path:

```c
// Server binds to abstract socket
struct sockaddr_un addr;
addr.sun_family = AF_UNIX;
addr.sun_path[0] = '\0';  // Abstract namespace indicator
strcpy(&addr.sun_path[1], "com.android.internal.os.RuntimeInit");
```

**Benefits:**
- No filesystem permissions needed
- Socket automatically cleaned up when server exits
- Not visible in `/tmp` or other filesystem locations
- Isolated from network-based attacks

### ADB Port Forwarding

The client connects via ADB forward which bridges TCP to the abstract socket:

```bash
# Setup (done automatically by renef)
adb forward tcp:1907 localabstract:com.android.internal.os.RuntimeInit

# Client connects to localhost:1907
# ADB forwards to abstract socket on device
```


## Wire Protocol

Commands are text. A client sends a command and reads the reply. There are two ways to delimit them:

**Line mode** (all versions): send `command\n`; the reply is whatever arrives until the connection goes quiet. Simple, but a client cannot tell a finished reply from a pause, and a reply that arrives after the client stopped waiting is read as the reply to its next command.

**Framed requests** (optional, newer servers): 

```
request :  @req <id> <len>\n   followed by exactly <len> bytes (the command)
response:  <everything the command wrote>   \x1e@done <id>\n
```

`<id>` is a positive number chosen by the client and increased for every request. The reply ends at the marker carrying the same id, so multi-line commands, slow commands and back-to-back requests are unambiguous; a late reply to an abandoned request is recognised by its id and skipped. A client can probe for support by sending a framed `ping`: a framing-aware server answers `pong` plus the marker, an older one answers `ERROR: Unknown command` with no marker. The `renef` CLI and the Python client use framed requests when available; line mode keeps working unchanged. Streaming commands (`watch`) use line mode.

**Hook output has its own channel.** The agent sends two kinds of output: the reply to the command it is executing, and what hook callbacks and the syscall tracer print whenever they fire. With one connection the second kind ended up inside whatever reply was read next. `renef_server` therefore opens a second connection to the agent (first line `@events`, acknowledged with `@events ok`) and the agent routes by caller: output of the command thread goes to the command connection, everything else to the event connection. The server keeps events in a bounded buffer and hands them out through `events` and `watch`.

On the host side the completion marker of a framed reply may carry one more field:

```
\x1e@done <id> ev=<n>\n
```

`<n>` lines of hook output are waiting on the server (the field is absent when there are none). Clients use it to show a notice or to fetch the events right away. An agent or server that does not know the event channel behaves as before: everything arrives on the one connection.
