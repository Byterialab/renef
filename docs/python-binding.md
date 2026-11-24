---
title: Python Binding
layout: default
nav_order: 9
---

# Python API Reference

The Python package talks to `renef_server` directly over its TCP socket, the
same way the `renef` CLI does. It is pure Python: no `librenef.so` has to be
built or located.

---

## Setup

1. Server and agent on the device, port forwarded (from the repo root):

   ```bash
   make install
   adb shell su -c /data/local/tmp/renef_server &
   adb forward tcp:1907 localabstract:com.android.internal.os.RuntimeInit
   ```

2. Install the package (or just put `bindings/python` on `PYTHONPATH`):

   ```bash
   pip install ./bindings/python
   ```

Requires Python 3.8+. No third-party dependencies.

## Quick start

```python
import renef

client = renef.connect()                       # 127.0.0.1:1907
with client.spawn("com.example.app") as s:
    libc = s.Module.find("libc.so")
    print(hex(libc), s.Memory.read(libc, 4))   # b'\x7fELF'

    # Evaluate Lua in the target; tables come back as dicts/lists.
    print(s.rpc("OS.getpid()"))
    print(s.rpc("{pid = OS.getpid(), tid = Thread.id()}"))

    # Hook with a Python callback (observes the call). `capture` evaluates
    # Lua in the target while the call is running.
    def on_open(event):
        print("open(%r) on thread %d" % (event.data["path"], event.thread_id))

    hook = s.hook("libc.so", "open", on_enter=on_open,
                  capture={"path": "Memory.readStr(args[0])"})
    s.poll(wait=5)                             # deliver events for 5 seconds
    hook.remove()

    # Hook with Lua source (runs in the target, can change the result).
    s.hook("libnative.so", 0x1234, on_leave="return 1")
```

## What is where

| | |
|---|---|
| `renef.connect(host, port)` | `Client`: `spawn`, `attach`, `list_apps`, `memdump`, `memdump_maps`, `ping` |
| `Session.eval(code)` | run Lua; returns `EvalResult(ok, output, error)` |
| `Session.rpc(expr)` / `call(name, *args)` | evaluate a Lua expression / call a Lua function, get the value back |
| `Session.load_script(path)` | run a Lua file |
| `Session.hook(lib, target, on_enter, on_leave, caller=, asynchronous=, capture=, capture_leave=)` | native hook; `target` is an offset or an export name |
| `Session.hook_java(cls, method, sig, on_enter, on_leave)` | Java method hook |
| `Session.Interceptor.replace / revert` | replace a native function |
| `Session.native_function(addr, ret, args)` | call native code from Python |
| `Session.Memory` | `read`, `write`, `read_u8..u64`, `write_u8..u64`, `read_string`, `alloc`, `alloc_str`, `free`, `protect`, `patch`, `search`, `hexdump` |
| `Session.Module` | `find`, `list`, `exports`, `symbols`, `find_exports`, `find_export`, `disassemble` |
| `Session.Process` / `Thread` | `ranges`, `threads` / `id`, `backtrace` |
| `Session.Java` | `use(cls)` → `call` / `new`; `enumerate_loaded_classes` |
| `Session.OS`, `File`, `Syscall`, `KCov` | wrappers over the Lua modules of the same name |
| `Session.poll`, `start_listener`, `on_event`, `on_output` | receive hook output and `send({...})` events |
| `Session.command(text)` | any server command, as typed in the renef shell |

Errors raise `renef.RenefError` subclasses: `RenefConnectionError`,
`RenefTimeoutError`, `CommandError`, `LuaError`, `HookInstallError`,
`SessionClosedError`.

## Things to know

- **One target per server.** `spawn`/`attach` replace the previous session.
- **Python hook callbacks observe, they do not intercept.** The event
  reaches Python after the hooked function has continued. To change
  arguments or the return value, pass Lua source for `on_enter`/`on_leave`
  (`args` / `retval` are in scope) or use `Interceptor.replace`.
- **Events arrive when you talk to the server.** Call `poll(wait)` or run
  `start_listener()` for a background thread. Hook output is never part of
  a command's reply: the server holds it and reports with every reply how
  much is waiting, and the client then fetches it at once - so callbacks and
  `on_output` handlers still fire with whatever command you run next, but
  `eval()`/`rpc()` return only what the command itself produced.
- **The agent's own calls are not hooked.** A hook on `getpid` does not
  affect `s.OS.getpid()`; call through `s.native_function(...)` to exercise
  a hook from your script.
- **`Memory.read`/`write` check the mapping first**, so a bad address raises
  `LuaError` instead of crashing the target.
- **Timeouts.** `rpc(expr, timeout=...)` and `eval(code, timeout=...)` wait
  that many seconds without output (default 30). A reply that arrives after
  a timeout is discarded; it is never returned for a later call.
- **`spawn(pkg, pause=True)`** freezes the app before its own code runs
  (ptrace spawn gate) and keeps it frozen until `resume()`, so hooks -
  including hooks on libraries that are not loaded yet - are in place for
  the first call. The target is ptrace-attached while paused.
- **Addresses are unsigned.** Lua integers are signed 64-bit; the client
  converts addresses (e.g. tagged heap pointers) to unsigned Python ints.

## The original API

`Renef` and `RenefSession` are still there with the same method names and
return conventions as the ctypes binding (`None` / `-1` /
`(success, output, error)` instead of exceptions):

```python
from renef import Renef

s = Renef().spawn("com.example.app")
ok, out, err = s.eval("print(1 + 1)")
s.hook("libc.so", 0x1234, "print(args[0])", "print(retval)")
```

Differences from the ctypes version: no `librenef.so` is needed,
`Module.list()`/`exports()` return records (also usable as dicts) parsed
from structured data, and `unhook()` works.

---

## API details

### `renef.connect(host="127.0.0.1", port=1907)` → `Client`

| Method | Description |
|---|---|
| `spawn(package, hook_type=0, pause=False)` | Start the app and inject; returns a `Session`. `hook_type`: `renef.HOOK_TRAMPOLINE` / `renef.HOOK_PLT` |
| `attach(pid, hook_type=0)` | Inject into a running process |
| `list_apps(name_filter=None)` | Installed packages (no injection) |
| `memdump(pid, start, end)` | Read memory of any process through the server (`/proc/<pid>/mem`), no injection and no ptrace; unreadable pages come back as zeros |
| `memdump_maps(pid)` | `/proc/<pid>/maps` of any process |
| `ping()` / `framed` / `close()` | Liveness check / whether the server supports framed requests / disconnect |

### `Session`

| Method | Returns |
|---|---|
| `eval(code, timeout=None)` | `EvalResult(ok, output, error)` — `output` is what the code printed, `error` the Lua error message |
| `rpc(expression, timeout=None)` | The value of the Lua expression (tables → `dict`/`list`); raises `LuaError` |
| `call(function, *args)` | Calls a global Lua function with Python arguments |
| `load_script(path)` | `EvalResult` |
| `hook(lib, target, on_enter=None, on_leave=None, *, caller=None, asynchronous=False, capture=None, capture_leave=None)` | `Hook` (`agent_id`, `deferred`, `remove()`) |
| `hook_java(class_name, method, signature, on_enter=None, on_leave=None)` | `Hook` |
| `unhook(agent_id)` / `unhook_all()` / `hooks()` | — / — / the hook table as text |
| `native_function(address, ret="pointer", args=None)` | A callable; `ret`: `int`, `long`, `pointer`, `bool`, `string`, `void`, `float`, `double` |
| `poll(wait=0.0)` | Fetches pending hook output; fires callbacks; returns unclaimed `send()` events |
| `start_listener(interval=0.2)` / `stop_listener()` | Background delivery of hook output |
| `on_event(handler)` / `on_output(handler)` / `events()` | `send({...})` events / printed text / queued events |
| `resume()` | Opens the spawn gate (`pause=True`) |
| `command(text)` | Any server command |

`on_enter` / `on_leave` take either **Lua source** (a function body with
`args` / `retval` in scope; runs in the target and can change the call) or a
**Python callable** receiving a `HookEvent` (`phase`, `thread_id`, `args`,
`retval`, `data`). `capture={"name": "<lua expr>"}` evaluates expressions in
the target while the call is in progress and delivers them as `event.data`.

### Namespaces

Every namespace hangs off the session (`s.Memory`, `s.Module`, ...).
Addresses are plain `int`s.

**`Memory`**

| Method | |
|---|---|
| `read(addr, size)` → `bytes`, `write(addr, data)` → bytes written | raise if the range is not mapped; `write` patches read-only pages |
| `read_u8/u16/u32/u64(addr)`, `read_pointer(addr)` | little-endian integers |
| `write_u8/u16/u32/u64(addr, value)` | |
| `read_string(addr, max_len=256)` | NUL-terminated string, `None` for address 0 |
| `alloc(size, prot="rw-")`, `alloc_str(text)`, `free(addr, size=None)`, `protect(addr, size, prot)` | memory allocated in the target |
| `patch(addr, data)` | write to code or read-only memory |
| `search(pattern, lib=None)` → `list[SearchHit]` | a string or a hex pattern with wildcards (`"FD 7B ?? A9"`), optionally in one library |
| `scan(pattern)` | the server's `ms` command; returns `(ok, output, error)` |
| `hexdump(addr, length=64)` → `str` | |

**`Module`**: `find(name)` → base address, `list()` → `list[ModuleInfo]`,
`exports(name)` / `symbols(name)` → `list[Symbol]`, `find_exports(name, pattern)`
(wildcards), `find_export(name, symbol)` → address or `None`,
`disassemble(addr, count=16)` → `list[Instruction]`.

**`Process`**: `ranges()` → `list[MemoryRange]`, `threads()` → `list[int]`.
**`Thread`**: `id()`, `backtrace()` → `list[Frame]` (of the thread that runs
the command; inside hooks use a `capture` expression).

**`Java`**: `use(class_name)` → `JavaClass` with `call(method, signature, *args)`
for static methods and `new(signature, *args)` → `JavaObject`. A `JavaObject`
has `call(method, signature, *args)`, `raw` (the object reference as an
integer) and `release()`. `enumerate_loaded_classes(pattern=None)` returns the
class names of the app's dex files, optionally only those containing `pattern`.

**`OS`**: `getpid()`, `kill(pid, sig)`, `tgkill(tgid, tid, sig)`, `listdir(path)`.

**`File`**: `read(path)`, `exists(path)`, `readlink(path)`, `fdpath(fd)`,
`write(path, addr, size)` (dump target memory to a file on the device).

**`Syscall`**: `trace(*names)`, `trace_category(category)`, `trace_all()`,
`untrace(*names)`, `stop()` return `(ok, output, error)`; `active()` returns the
list of active traces. Trace lines arrive through `on_output` / `poll()`.

**`KCov`**: `start(buf_size=0)`, `collect()` → list of PCs, `count()`,
`reset()`, `stop()`.

**`Interceptor`**: `replace(lib, target, replacement, caller=None)` where
`replacement` is an integer to return, or Lua source of a function taking
`args` (`"function(args) return 1 end"`) that runs in the target;
`revert(lib, target)`.

`Session.memscan(pattern)` is the same as `Memory.scan`.

### Records

`ModuleInfo(name, base, size, path)`, `Symbol(name, offset)`,
`MemoryRange(start, end, size, perms, path)`, `Frame(index, pc, module, offset, base, path)`,
`Instruction(address, size, mnemonic, op_str, is_branch, is_call, is_jump)`,
`SearchHit(addr, offset, library, hex, ascii)`. All are dataclasses and also
readable like dicts (`m["base"]`).

---

## Tests

```bash
# offline (mock server)
python -m unittest discover -s bindings/python/tests -p "test_api.py"

# against a device
RENEF_TEST_PACKAGE=<package> python -m unittest bindings/python/tests/test_device.py
```
