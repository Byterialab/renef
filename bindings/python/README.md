# renef — Python client

Drive [Renef](../../README.md) (dynamic instrumentation for Android ARM64)
from Python. Pure Python, no native library: the client talks to
`renef_server` over its TCP socket, like the `renef` CLI does.

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
  `eval()`/`rpc()` return only what the command itself produced. (What a
  hook prints because *your own* call triggered it, e.g. through
  `native_function`, is that call's output and comes back with it.)
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

## Tests

```bash
# offline (mock server)
python -m unittest discover -s bindings/python/tests -p "test_api.py"

# against a device
RENEF_TEST_PACKAGE=<package> python -m unittest bindings/python/tests/test_device.py
```
