"""Pure-Python client for renef_server.

Nothing here needs the native ``librenef`` library: the client talks to the
server over its TCP socket, the same way the ``renef`` CLI does. Everything
that runs in the target is expressed as Lua and sent with ``exec``/``rpc``;
results come back as JSON, so nothing is recovered by splitting text.
"""

import json
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Union

from .errors import (
    CommandError,
    HookInstallError,
    LuaError,
    RenefConnectionError,
    RenefError,
    RenefTimeoutError,
    SessionClosedError,
)
from .lua import PRELUDE, quote, to_lua
from .transport import DEFAULT_HOST, DEFAULT_PORT, Connection

_EVENT_TAG = "[event] "
# lines of a reply that belong to the protocol, not to the target's output
_STATUS_LINES = frozenset(("OK", "ERROR: Lua execution failed"))


def _is_rpc_reply(line):
    return line.startswith("{") and '"__rpc_call"' in line
_U64 = 0xFFFFFFFFFFFFFFFF

HOOK_TRAMPOLINE = 0
HOOK_PLT = 1


def u64(value):
    """Lua integers are signed 64-bit; addresses with the top bit set (MTE /
    TBI tagged heap pointers) arrive negative. Returns the unsigned value."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value & _U64
    return value


class LuaExpr:
    """Marks a string as Lua source to be inserted verbatim (not quoted)
    when passed as an argument, e.g. ``session.call("f", LuaExpr("args[0]"))``."""

    def __init__(self, source):
        self.source = source

    def __repr__(self):
        return "LuaExpr(%r)" % self.source


class EvalResult(NamedTuple):
    """Result of :meth:`Session.eval`. Unpacks like the old
    ``(success, output, error)`` tuple."""

    ok: bool
    output: Optional[str]
    error: Optional[str]


class _Record:
    """Dataclass mixin: also readable like the dicts the old API returned
    (``m["base"]``, ``m.get("name")``)."""

    def __getitem__(self, key):
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key) from None

    def get(self, key, default=None):
        return getattr(self, key, default)

    def keys(self):
        return list(self.__dataclass_fields__)  # type: ignore[attr-defined]


@dataclass
class ModuleInfo(_Record):
    name: str
    base: int
    size: int = 0
    path: str = ""


@dataclass
class Symbol(_Record):
    name: str
    offset: int


@dataclass
class MemoryRange(_Record):
    start: int
    end: int
    size: int
    perms: str
    path: str = ""


@dataclass
class Frame(_Record):
    index: int
    pc: int
    module: str = ""
    offset: int = 0
    base: int = 0
    path: str = ""


@dataclass
class Instruction(_Record):
    address: int
    size: int
    mnemonic: str
    op_str: str
    is_branch: bool = False
    is_call: bool = False
    is_jump: bool = False

    def __str__(self):
        return "0x%x: %s %s" % (self.address, self.mnemonic, self.op_str)


@dataclass
class SearchHit(_Record):
    addr: int
    offset: int = 0
    library: str = ""
    hex: str = ""
    ascii: str = ""


@dataclass
class HookEvent:
    """Delivered to a Python hook callback. Observation only: by the time
    Python sees it the hooked function has already continued."""

    hook: "Hook"
    phase: str                      # "enter" or "leave"
    thread_id: int
    args: List[int] = field(default_factory=list)   # x0..x7 on enter
    retval: Optional[int] = None                    # x0 on leave
    data: Dict[str, Any] = field(default_factory=dict)   # values of the hook's `capture` expressions
    raw: Dict[str, Any] = field(default_factory=dict)


class Hook:
    """A hook installed through :meth:`Session.hook` / :meth:`Session.hook_java`."""

    def __init__(self, session, local_id, description, agent_id, deferred, java=False):
        self._session = session
        self.id = local_id            # client-side id (event routing)
        self.agent_id = agent_id      # slot in the agent's hook table, None if unknown
        self.deferred = deferred      # library not loaded yet: installs when it loads
        self.description = description
        self.java = java
        self.on_enter: Optional[Callable[[HookEvent], None]] = None
        self.on_leave: Optional[Callable[[HookEvent], None]] = None
        self.removed = False

    def remove(self):
        """Removes the hook from the target."""
        if self.removed:
            return
        if self.java:
            raise RenefError("Java hooks cannot be removed individually; close the session to restore them")
        if self.agent_id is None:
            raise RenefError("this hook has no agent-side id yet (deferred until its library loads)")
        self._session.unhook(self.agent_id)
        self.removed = True
        self._session._hooks.pop(self.id, None)

    def __repr__(self):
        state = "removed" if self.removed else ("deferred" if self.deferred else "active")
        return "<Hook #%s %s (%s)>" % (self.agent_id, self.description, state)


class JavaObject:
    """Handle to a Java object kept alive in the target."""

    def __init__(self, session, handle):
        self._session = session
        self.handle = handle

    def call(self, method, signature, *args, timeout=None):
        """Calls an instance method, e.g. ``obj.call("length", "()I")``."""
        expr = "__renef_py.box(__renef_py.objs[%d]:call(%s))" % (
            self.handle, ", ".join([quote(method), quote(signature)] + [to_lua(a) for a in args]))
        return self._session._unbox(self._session.rpc(expr, timeout=timeout))

    @property
    def raw(self):
        """Raw ``mirror::Object*`` pointer of the object."""
        return u64(self._session.rpc("__renef_py.objs[%d].raw" % self.handle))

    def release(self):
        """Drops the target-side reference."""
        self._session.rpc("__renef_py.release(%d)" % self.handle)

    def __repr__(self):
        return "<JavaObject handle=%d>" % self.handle


class JavaClass:
    """Wrapper around ``Java.use(class_name)``."""

    def __init__(self, session, class_name):
        self._session = session
        self.name = class_name

    def call(self, method, signature, *args, timeout=None):
        """Calls a static method, e.g. ``System.call("currentTimeMillis", "()J")``."""
        expr = "__renef_py.box(Java.use(%s):call(%s))" % (
            quote(self.name), ", ".join([quote(method), quote(signature)] + [to_lua(a) for a in args]))
        return self._session._unbox(self._session.rpc(expr, timeout=timeout))

    def new(self, signature="()V", *args, timeout=None):
        """Creates an instance, e.g. ``File.new("(Ljava/lang/String;)V", "/tmp")``."""
        expr = "__renef_py.box(Java.use(%s):new(%s))" % (
            quote(self.name), ", ".join([quote(signature)] + [to_lua(a) for a in args]))
        obj = self._session._unbox(self._session.rpc(expr, timeout=timeout))
        if not isinstance(obj, JavaObject):
            raise LuaError("could not create an instance of %s" % self.name)
        return obj

    def __repr__(self):
        return "<JavaClass %s>" % self.name


class NativeFunction:
    """A native function in the target, callable from Python."""

    def __init__(self, session, address, ret="pointer", args=None):
        self._session = session
        self.address = address
        self.ret = ret
        self.arg_types = list(args or [])
        self._id = session._new_id()

    def __call__(self, *args, timeout=None):
        types = "{" + ", ".join(quote(t) for t in self.arg_types) + "}"
        expr = (
            "(function() local f = __renef_py.nf[%d]; "
            "if not f then f = NativeFunction(%s, %s, %s); __renef_py.nf[%d] = f end; "
            "return f(%s) end)()"
            % (self._id, to_lua(self.address), quote(self.ret), types, self._id,
               ", ".join(to_lua(a) for a in args))
        )
        value = self._session.rpc(expr, timeout=timeout)
        if self.ret in ("pointer", "long"):
            return u64(value) if self.ret == "pointer" else value
        return value


def _guarded(default):
    """In strict sessions errors propagate; the backward-compatible
    ``RenefSession`` (strict=False) gets ``default`` instead, matching what
    the ctypes binding returned."""

    def decorator(fn):
        def wrapper(self, *args, **kwargs):
            try:
                return fn(self, *args, **kwargs)
            except RenefError:
                if self._session.strict:
                    raise
                return default() if callable(default) else default

        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        return wrapper

    return decorator


class _Namespace:
    def __init__(self, session):
        self._session = session


class Memory(_Namespace):
    """Read, write, allocate and search the target's memory."""

    CHUNK = 64 * 1024

    @_guarded(None)
    def read(self, addr: int, size: int) -> Optional[bytes]:
        """Reads ``size`` bytes. Unmapped/unreadable ranges raise instead of
        crashing the target."""
        out = bytearray()
        while len(out) < size:
            n = min(self.CHUNK, size - len(out))
            hexdata = self._session.rpc("__renef_py.read(%s, %d)" % (to_lua(addr + len(out)), n))
            out += bytes.fromhex(hexdata)
        return bytes(out)

    @_guarded(-1)
    def write(self, addr: int, data: bytes) -> int:
        """Writes bytes. Read-only/executable pages are patched via
        ``Memory.patch``. Returns the number of bytes written."""
        data = bytes(data)
        done = 0
        while done < len(data):
            chunk = data[done:done + self.CHUNK // 2]
            self._session.rpc("__renef_py.write(%s, %s)" % (to_lua(addr + done), quote(chunk.hex())))
            done += len(chunk)
        return done

    def _read_int(self, addr, size):
        return int.from_bytes(self.read(addr, size), "little")

    @_guarded(0)
    def read_u8(self, addr: int) -> int:
        return self._read_int(addr, 1)

    @_guarded(0)
    def read_u16(self, addr: int) -> int:
        return self._read_int(addr, 2)

    @_guarded(0)
    def read_u32(self, addr: int) -> int:
        return self._read_int(addr, 4)

    @_guarded(0)
    def read_u64(self, addr: int) -> int:
        return self._read_int(addr, 8)

    @_guarded(None)
    def read_pointer(self, addr: int) -> int:
        return self._read_int(addr, 8)

    @_guarded(None)
    def read_string(self, addr: int, max_len: int = 256) -> Optional[str]:
        """Reads a NUL-terminated string (``None`` for a NULL pointer)."""
        return self._session.rpc("__renef_py.readstr(%s, %d)" % (to_lua(addr), max_len))

    def _write_int(self, addr, value, size):
        self.write(addr, (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little"))
        return 0

    @_guarded(-1)
    def write_u8(self, addr: int, val: int) -> int:
        return self._write_int(addr, val, 1)

    @_guarded(-1)
    def write_u16(self, addr: int, val: int) -> int:
        return self._write_int(addr, val, 2)

    @_guarded(-1)
    def write_u32(self, addr: int, val: int) -> int:
        return self._write_int(addr, val, 4)

    @_guarded(-1)
    def write_u64(self, addr: int, val: int) -> int:
        return self._write_int(addr, val, 8)

    def patch(self, addr: int, data: bytes) -> None:
        """Writes into code/read-only memory (``Memory.patch``)."""
        data = bytes(data)
        self._session.rpc(
            "(function() local ok, err = Memory.patch(%s, __renef_py.unhex(%s)); "
            "if not ok then error(tostring(err), 0) end; return true end)()"
            % (to_lua(addr), quote(data.hex())))

    def alloc(self, size: int, prot: str = "rw-") -> int:
        """Allocates ``size`` bytes in the target; returns the address."""
        return u64(self._session.rpc(
            "(function() local p, err = Memory.alloc(%d, %s); "
            "if not p then error(tostring(err), 0) end; return p end)()" % (size, quote(prot))))

    def alloc_str(self, text: Union[str, bytes]) -> int:
        """Allocates a NUL-terminated copy of ``text`` in the target."""
        return u64(self._session.rpc("Memory.allocStr(%s)" % quote(text)))

    def free(self, addr: int, size: Optional[int] = None) -> None:
        if size is None:
            self._session.rpc("Memory.free(%s)" % to_lua(addr))
        else:
            self._session.rpc("Memory.free(%s, %d)" % (to_lua(addr), size))

    def protect(self, addr: int, size: int, prot: str) -> None:
        self._session.rpc(
            "(function() local ok, err = Memory.protect(%s, %d, %s); "
            "if not ok then error(tostring(err), 0) end; return true end)()"
            % (to_lua(addr), size, quote(prot)))

    def search(self, pattern: str, lib: Optional[str] = None) -> List[SearchHit]:
        """Searches for a string or hex pattern (``"FD 7B ?? A9"``)."""
        args = quote(pattern) + (", " + quote(lib) if lib else "")
        rows = self._session.rpc("Memory.search(%s)" % args, timeout=60) or []
        hits = []
        for r in rows if isinstance(rows, list) else []:
            hits.append(SearchHit(addr=u64(r.get("addr", 0)), offset=u64(r.get("offset", 0)),
                                  library=r.get("library", "") or "", hex=r.get("hex", "") or "",
                                  ascii=r.get("ascii", "") or ""))
        return hits

    def scan(self, pattern: str):
        """Server-side scan (the ``ms`` command). Returns ``(success, output, error)``."""
        return self._session.memscan(pattern)

    def hexdump(self, addr: int, length: int = 64) -> str:
        return self._session.rpc("hexdump(%s, %d)" % (to_lua(addr), length)) or ""


class Module(_Namespace):
    """Loaded libraries and their symbols."""

    @_guarded(0)
    def find(self, name: str) -> int:
        """Base address of a loaded library, 0 if it is not loaded."""
        return u64(self._session.rpc("Module.find(%s)" % quote(name)) or 0)

    @_guarded(list)
    def list(self) -> List[ModuleInfo]:
        """Every file mapped into the process, with base address and size."""
        rows = self._session.rpc("__renef_py.modules()", timeout=60) or []
        if not isinstance(rows, list):
            rows = []
        return [ModuleInfo(name=r.get("name", ""), base=u64(r.get("base", 0)),
                           size=u64(r.get("size", 0)), path=r.get("path", "")) for r in rows]

    def _symbols(self, func, name):
        rows = self._session.rpc("%s(%s)" % (func, quote(name)), timeout=60)
        if not isinstance(rows, list):
            return []
        return [Symbol(name=r.get("name", ""), offset=u64(r.get("offset", 0))) for r in rows]

    @_guarded(list)
    def exports(self, name: str) -> List[Symbol]:
        """Exported (``.dynsym``) symbols of a library."""
        return self._symbols("Module.exports", name)

    @_guarded(list)
    def symbols(self, name: str) -> List[Symbol]:
        """All (``.symtab``) symbols; empty for stripped libraries."""
        return self._symbols("Module.symbols", name)

    def find_exports(self, name: str, pattern: str) -> List[Symbol]:
        """Exports matching a glob pattern (``"pthread_*"``) or an exact name."""
        rows = self._session.rpc("Module.findExportByName(%s, %s)" % (quote(name), quote(pattern)), timeout=60)
        if rows is None:
            raise RenefError("library %r is not loaded (or could not be parsed)" % name)
        if not isinstance(rows, list):
            return []
        return [Symbol(name=r.get("name", ""), offset=u64(r.get("offset", 0))) for r in rows]

    def find_export(self, name: str, symbol: str) -> Optional[int]:
        """Absolute address of an exported symbol, ``None`` if it does not exist."""
        matches = [s for s in self.find_exports(name, symbol) if s.name == symbol]
        if not matches:
            return None
        base = u64(self._session.rpc("Module.find(%s)" % quote(name)) or 0)
        return base + matches[0].offset if base else None

    def disassemble(self, addr: int, count: int = 16) -> List[Instruction]:
        rows = self._session.rpc("Module.disassemble(%s, %d)" % (to_lua(addr), count)) or []
        if not isinstance(rows, list):
            return []
        return [Instruction(address=u64(r.get("address", 0)), size=r.get("size", 4),
                            mnemonic=r.get("mnemonic", ""), op_str=r.get("op_str", ""),
                            is_branch=bool(r.get("is_branch")), is_call=bool(r.get("is_call")),
                            is_jump=bool(r.get("is_jump"))) for r in rows]


class Thread(_Namespace):
    @_guarded(0)
    def id(self) -> int:
        """Thread id of the agent thread that runs your Lua."""
        return self._session.rpc("Thread.id()") or 0

    @_guarded(list)
    def backtrace(self) -> List[Frame]:
        rows = self._session.rpc("Thread.backtrace()") or []
        if not isinstance(rows, list):
            return []
        return [Frame(index=r.get("index", i + 1), pc=u64(r.get("pc", 0)), module=r.get("module", "") or "",
                      offset=u64(r.get("offset", 0)), base=u64(r.get("base", 0)), path=r.get("path", "") or "")
                for i, r in enumerate(rows)]


class Process(_Namespace):
    def ranges(self) -> List[MemoryRange]:
        """Every mapping of the target (``/proc/self/maps``)."""
        rows = self._session.rpc("Process.enumerateRanges()", timeout=60) or []
        return [MemoryRange(start=u64(r.get("start", 0)), end=u64(r.get("end", 0)), size=u64(r.get("size", 0)),
                            perms=r.get("perms", ""), path=r.get("path", "") or "")
                for r in rows if isinstance(r, dict)]

    def threads(self) -> List[int]:
        rows = self._session.rpc("Process.enumerateThreads()") or []
        return [t for t in rows if isinstance(t, int)]


class OS(_Namespace):
    @_guarded(None)
    def getpid(self) -> Optional[int]:
        return self._session.rpc("OS.getpid()")

    @_guarded(None)
    def kill(self, pid: int, sig: int) -> Optional[int]:
        return self._session.rpc("OS.kill(%d, %d)" % (pid, sig))

    @_guarded(None)
    def tgkill(self, tgid: int, tid: int, sig: int) -> Optional[int]:
        return self._session.rpc("OS.tgkill(%d, %d, %d)" % (tgid, tid, sig))

    @_guarded(None)
    def listdir(self, path: str) -> Optional[List[str]]:
        """Directory entries (dotfiles excluded), ``None`` if it cannot be read."""
        rows = self._session.rpc("OS.listdir(%s)" % quote(path))
        if rows is None:
            return None
        return list(rows) if isinstance(rows, list) else []


class File(_Namespace):
    @_guarded(None)
    def read(self, path: str) -> Optional[str]:
        return self._session.rpc("File.read(%s)" % quote(path))

    @_guarded(False)
    def exists(self, path: str) -> bool:
        return bool(self._session.rpc("File.exists(%s)" % quote(path)))

    @_guarded(None)
    def readlink(self, path: str) -> Optional[str]:
        return self._session.rpc("File.readlink(%s)" % quote(path))

    @_guarded(None)
    def fdpath(self, fd: int) -> Optional[str]:
        return self._session.rpc("File.fdpath(%d)" % fd)

    @_guarded(False)
    def write(self, path: str, addr: int, size: int) -> bool:
        """Dumps a memory region of the target to a file on the device."""
        return bool(self._session.rpc("File.write(%s, %s, %d)" % (quote(path), to_lua(addr), size)))


class Syscall(_Namespace):
    def trace(self, *names: str):
        """Starts tracing the given syscalls. Returns ``(success, output, error)``."""
        return self._session.eval("Syscall.trace(%s)" % ", ".join(quote(n) for n in names))

    def trace_category(self, category: str):
        return self._session.eval("Syscall.trace({category=%s})" % quote(category))

    def trace_all(self):
        return self._session.eval("Syscall.traceAll()")

    def untrace(self, *names: str):
        return self._session.eval("Syscall.untrace(%s)" % ", ".join(quote(n) for n in names))

    def stop(self):
        return self._session.eval("Syscall.stop()")

    def active(self):
        return self._session.rpc("Syscall.active()")


class KCov(_Namespace):
    def start(self, buf_size: int = 0):
        return self._session.eval("_kcov = KCov.open(%d); _kcov:enable(); print('ok')" % buf_size)

    def stop(self):
        return self._session.eval("if _kcov then _kcov:disable(); _kcov:close(); _kcov = nil end; print('ok')")

    @_guarded(None)
    def collect(self) -> Optional[List[int]]:
        rows = self._session.rpc("(function() if _kcov then return _kcov:collect() end return nil end)()")
        if rows is None:
            return None
        return [u64(pc) for pc in rows] if isinstance(rows, list) else []

    @_guarded(None)
    def count(self) -> Optional[int]:
        return self._session.rpc("(function() if _kcov then return _kcov:count() end return -1 end)()")

    def reset(self):
        return self._session.eval("if _kcov then _kcov:reset() end; print('ok')")


class Interceptor(_Namespace):
    def replace(self, lib: str, target: Union[int, str], replacement: Union[int, str], caller: Optional[str] = None):
        """Replaces a native function.

        ``replacement`` is either an integer (the function then always
        returns it) or Lua source of a function taking ``args``, e.g.
        ``"function(args) return 1 end"``. It runs in the target, so it can
        change the result - which a Python callback cannot.
        """
        offset = self._session._resolve_offset(lib, target)
        if isinstance(replacement, bool):
            replacement = int(replacement)
        fn = "function(args) return %d end" % replacement if isinstance(replacement, int) else "(%s)" % replacement
        extra = ", " + quote(caller) if caller else ""
        result = self._session.eval("Interceptor.replace(%s, 0x%x, %s%s)" % (quote(lib), offset, fn, extra))
        if not result.ok:
            raise HookInstallError(result.error or "Interceptor.replace failed")

    def revert(self, lib: str, target: Union[int, str]):
        offset = self._session._resolve_offset(lib, target)
        result = self._session.eval("Interceptor.revert(%s, 0x%x)" % (quote(lib), offset))
        if not result.ok:
            raise RenefError(result.error or "Interceptor.revert failed")


class Java(_Namespace):
    def use(self, class_name: str) -> JavaClass:
        """``Java.use``: a class wrapper for static calls and construction.
        Use ``/`` separators: ``"java/lang/System"``."""
        return JavaClass(self._session, class_name)

    def enumerate_loaded_classes(self, pattern: Optional[str] = None) -> List[str]:
        """Class names from the app's dex files. ``pattern`` keeps only the
        names that contain it (the agent call itself takes no filter)."""
        rows = self._session.rpc("Java.enumerateLoadedClasses()", timeout=120)
        names = list(rows) if isinstance(rows, list) else []
        if pattern:
            names = [n for n in names if pattern in n]
        return names


class Session:
    """A spawned or attached target process.

    Errors raise exceptions (:class:`LuaError`, :class:`CommandError`,
    :class:`RenefTimeoutError`, ...). ``RenefSession`` is the same object in
    a compatibility mode that returns the old sentinel values instead.
    """

    strict = True

    def __init__(self, client, pid):
        self._client = client
        self._conn = client._conn
        self._pid = pid
        self._closed = False
        self._prelude_ready = False
        self._ids = 0
        self._hooks: Dict[int, Hook] = {}
        self._event_handlers: List[Callable[[Dict[str, Any]], None]] = []
        self._output_handlers: List[Callable[[str], None]] = []
        self._events = deque(maxlen=10000)
        self._eval_results: Dict[int, Dict[str, Any]] = {}
        self._listener = None
        self._listener_stop = threading.Event()
        self._state_lock = threading.RLock()

        self.Memory = Memory(self)
        self.Module = Module(self)
        self.Thread = Thread(self)
        self.Process = Process(self)
        self.OS = OS(self)
        self.File = File(self)
        self.Syscall = Syscall(self)
        self.KCov = KCov(self)
        self.Interceptor = Interceptor(self)
        self.Java = Java(self)

    # -- lifecycle ---------------------------------------------------------

    @property
    def pid(self) -> int:
        return self._pid if not self._closed else -1

    def close(self):
        """Ends the session and closes the connection. The agent restores
        every hook when its connection goes away."""
        if self._closed:
            return
        self.stop_listener()
        self._closed = True
        self._client._session_closed(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _new_id(self):
        with self._state_lock:
            self._ids += 1
            return self._ids

    # -- raw command path --------------------------------------------------

    def _command(self, command, timeout=35.0):
        """Sends a server command; returns its output with event lines
        removed (and dispatched)."""
        if self._closed:
            raise SessionClosedError("session is closed")
        raw = self._conn.request(command, timeout=timeout)
        out = self._process_output(raw)
        if self._conn.pending_events:
            self._fetch_pending_events()
        return out

    def _fetch_pending_events(self, max_rounds=8):
        """Collects hook output the server is holding.

        Output of hook callbacks is not part of command replies: the server
        keeps it apart and only says, with every reply, how much is waiting.
        Fetching it here keeps the old behaviour for callers - events and
        printed lines reach their handlers with whatever command comes
        next - without that output ever being mistaken for a reply.
        Bounded, because a hook on a busy function never runs dry.
        """
        for _ in range(max_rounds):
            raw = self._conn.request("events 0", timeout=15.0)
            self._process_output(raw)
            if not self._conn.pending_events:
                break

    def _process_output(self, raw: bytes) -> str:
        text = raw.decode("utf-8", "surrogateescape")
        kept = []
        events = []
        for line in text.split("\n"):
            if line.startswith(_EVENT_TAG):
                try:
                    events.append(json.loads(line[len(_EVENT_TAG):]))
                    continue
                except ValueError:
                    pass
            kept.append(line)
        out = "\n".join(kept)
        self._emit_output(kept)
        for ev in events:
            self._dispatch_event(ev)
        return out

    def _emit_output(self, lines):
        """Hands printed text to the output handlers. A reply also carries
        the protocol's own lines (exec status, the rpc result); those are not
        output of the target and are left out."""
        if not self._output_handlers:
            return
        shown = [ln for ln in lines if ln not in _STATUS_LINES and not _is_rpc_reply(ln)]
        text = "\n".join(shown)
        if text.strip("\n"):
            for handler in list(self._output_handlers):
                handler(text)

    def _dispatch_event(self, ev):
        if not isinstance(ev, dict):
            return
        if "__py_eval" in ev:
            self._eval_results[ev["__py_eval"]] = ev
            return
        if "__py_hook" in ev:
            hook = self._hooks.get(ev["__py_hook"])
            if hook is None:
                return
            phase = ev.get("phase", "")
            event = HookEvent(hook=hook, phase=phase, thread_id=ev.get("tid", 0),
                              args=[u64(a) for a in ev.get("args", []) or []],
                              retval=u64(ev.get("retval")) if "retval" in ev else None,
                              data=ev.get("data") if isinstance(ev.get("data"), dict) else {}, raw=ev)
            callback = hook.on_enter if phase == "enter" else hook.on_leave
            if callback is not None:
                callback(event)
            return
        self._events.append(ev)
        for handler in list(self._event_handlers):
            handler(ev)

    def _ensure_prelude(self):
        if self._prelude_ready:
            return
        # Through eval(): the source travels as one quoted Lua string, so
        # its newlines and quotes cannot interfere with command parsing.
        result = self.eval(PRELUDE)
        if not result.ok:
            raise RenefError("could not install the client support code in the target: %s"
                             % (result.error or result.output or "unknown error"))
        self._prelude_ready = True

    # -- Lua ---------------------------------------------------------------

    def eval(self, lua_code: str, timeout: Optional[float] = None) -> EvalResult:
        """Runs Lua code in the target.

        Returns ``EvalResult(ok, output, error)``: ``output`` is what the
        code printed, ``error`` the Lua error message if it failed. Does not
        raise on a Lua error (use :meth:`rpc` for a value-or-exception call).
        """
        if self._closed:
            return EvalResult(False, None, "Session closed")
        eval_id = self._new_id()
        wrapped = (
            "local __f, __e = load(%s, \"=eval\") "
            "if not __f then send({__py_eval = %d, ok = false, error = tostring(__e)}) else "
            "local __ok, __err = pcall(__f) "
            "if __ok then send({__py_eval = %d, ok = true}) "
            "else send({__py_eval = %d, ok = false, error = tostring(__err)}) end end"
            % (quote(lua_code), eval_id, eval_id, eval_id)
        )
        wait = 30.0 if timeout is None else float(timeout)
        try:
            out = self._command("exec --timeout %d %s" % (max(1, int(wait)), wrapped), timeout=wait + 5)
        except RenefTimeoutError as e:
            return EvalResult(False, e.partial or None, str(e))
        except RenefError as e:
            if self.strict and isinstance(e, RenefConnectionError):
                raise
            return EvalResult(False, None, str(e))

        status = self._eval_results.pop(eval_id, None)
        lines = [ln for ln in out.split("\n") if ln not in ("OK", "ERROR: Lua execution failed")]
        output = "\n".join(lines).strip("\n")
        if status is None:
            server_error = next((ln for ln in lines if ln.startswith("ERROR:")), None)
            return EvalResult(False, output or None, server_error or "no completion status from the target")
        if status.get("ok"):
            return EvalResult(True, output if output else None, None)
        return EvalResult(False, output if output else None, status.get("error") or "Lua error")

    exec = eval

    def rpc(self, expression: str, timeout: Optional[float] = None) -> Any:
        """Evaluates a Lua *expression* in the target and returns its value
        (tables become dicts/lists). Raises :class:`LuaError` if it fails."""
        if self._closed:
            raise SessionClosedError("session is closed")
        self._ensure_prelude()
        wait = 30.0 if timeout is None else float(timeout)
        out = self._command("rpc --timeout %d %s" % (max(1, int(wait)), expression), timeout=wait + 5)
        # Output of hooks that fired meanwhile can come before the result line.
        first = next((ln for ln in out.split("\n") if _is_rpc_reply(ln)), "")
        if not first:
            message = out.strip() or "empty reply"
            if "no completion" in message or "timed out" in message:
                raise RenefTimeoutError(message)
            raise CommandError(message, output=out)
        try:
            reply = json.loads(first)
        except ValueError as e:
            raise CommandError("unparseable rpc reply: %r" % first[:200], output=out) from e
        if not reply.get("ok"):
            raise LuaError(reply.get("error") or "Lua error")
        return reply.get("value")

    def call(self, function: str, *args, timeout: Optional[float] = None) -> Any:
        """Calls a global Lua function defined by a loaded script:
        ``session.call("extract_key", 3)``."""
        return self.rpc("%s(%s)" % (function, ", ".join(to_lua(a) for a in args)), timeout=timeout)

    def load_script(self, path: str, timeout: Optional[float] = None) -> EvalResult:
        """Runs a Lua script file (read on the host)."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                source = f.read()
        except OSError as e:
            if self.strict:
                raise RenefError("cannot read script %s: %s" % (path, e)) from e
            return EvalResult(False, None, "Cannot read file: %s" % path)
        return self.eval(source, timeout=timeout)

    load = eval

    def _unbox(self, value):
        if isinstance(value, dict) and "__py_obj" in value and len(value) == 1:
            return JavaObject(self, value["__py_obj"])
        return value

    # -- hooks -------------------------------------------------------------

    def _resolve_offset(self, lib, target):
        if isinstance(target, int):
            return target
        matches = [s for s in self.Module.find_exports(lib, target) if s.name == target]
        if not matches:
            raise HookInstallError("%s has no export named %r" % (lib, target))
        return matches[0].offset

    def _hook_count(self):
        out = self._command("hooks")
        for line in out.split("\n"):
            if line.startswith("Active hooks:"):
                try:
                    return int(line.split(":", 1)[1].strip())
                except ValueError:
                    break
        raise CommandError("unexpected reply to 'hooks': %r" % out[:200], output=out)

    @staticmethod
    def _capture_source(capture):
        """Lua that fills a table `d` with values computed IN THE TARGET at
        the moment the hook fires (each one guarded, so a failing expression
        just leaves its key out)."""
        if not capture:
            return "local d = {} "
        parts = ["local d = {} "]
        for key, expr in capture.items():
            parts.append("do local ok, v = pcall(function() return (%s) end) if ok then d[%s] = v end end "
                         % (expr, quote(key)))
        return "".join(parts)

    @classmethod
    def _native_shim(cls, local_id, phase, capture=None):
        if phase == "enter":
            return ("function(args) %s__renef_py.emit(%d, \"enter\", "
                    "{args = {args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]}, "
                    "data = d}) end" % (cls._capture_source(capture), local_id))
        return ("function(retval) %s__renef_py.emit(%d, \"leave\", {retval = retval, data = d}) end"
                % (cls._capture_source(capture), local_id))

    @classmethod
    def _java_shim(cls, local_id, phase, capture=None):
        if phase == "enter":
            return ("function(args) %slocal a = {} for i = 0, 7 do local v = args[i] "
                    "a[i + 1] = (type(v) == \"number\") and v or 0 end "
                    "__renef_py.emit(%d, \"enter\", {args = a, data = d}) end"
                    % (cls._capture_source(capture), local_id))
        return ("function(retval) %s__renef_py.emit(%d, \"leave\", "
                "{retval = (type(retval) == \"number\") and retval or 0, data = d}) end"
                % (cls._capture_source(capture), local_id))

    def _callbacks_source(self, local_id, on_enter, on_leave, shim, capture=None, capture_leave=None):
        parts = []
        for phase, cb, var, cap in (("enter", on_enter, "args", capture),
                                    ("leave", on_leave, "retval", capture_leave)):
            if cb is None:
                continue
            key = "onEnter" if phase == "enter" else "onLeave"
            if callable(cb):
                parts.append("%s = %s" % (key, shim(local_id, phase, cap)))
            else:
                parts.append("%s = function(%s) %s end" % (key, var, cb))
        return parts

    def hook(self, lib: str, target: Union[int, str], on_enter=None, on_leave=None, *,
             caller: Optional[str] = None, asynchronous: bool = False,
             capture: Optional[Dict[str, str]] = None,
             capture_leave: Optional[Dict[str, str]] = None) -> Hook:
        """Installs a native hook.

        ``target`` is an offset from the library base or an export name.
        ``on_enter`` / ``on_leave`` are each either

        * Lua source (a function body; ``args`` / ``retval`` are in scope),
          which runs inside the target and may change arguments or the
          return value, or
        * a Python callable taking a :class:`HookEvent`. Events are
          delivered when the session next talks to the server - call
          :meth:`poll`, or :meth:`start_listener` for a background thread.
          A Python callback observes; it cannot change the call.

        ``capture`` (for ``on_enter``) and ``capture_leave`` (for
        ``on_leave``) map names to Lua expressions that are evaluated in the
        target while the call is in progress - ``args`` / ``retval`` in
        scope - and delivered as ``event.data``. Use them for anything that
        is only valid during the call, such as string arguments::

            s.hook("libc.so", "open", on_enter=cb,
                   capture={"path": "Memory.readStr(args[0])"})

        ``caller`` selects PLT/GOT hooking for that library's call sites
        (``"*"`` for all) instead of patching the function. ``asynchronous``
        uses the agent's fire-and-forget mode for hot functions.
        """
        self._ensure_prelude()
        offset = self._resolve_offset(lib, target)
        local_id = self._new_id()
        parts = self._callbacks_source(local_id, on_enter, on_leave, self._native_shim, capture, capture_leave)
        if not parts:
            raise HookInstallError("hook() needs on_enter and/or on_leave")
        if caller:
            parts.append("caller = %s" % quote(caller))
        if asynchronous:
            parts.append("async = true")

        hook = Hook(self, local_id, "%s+0x%x" % (lib, offset), None, False)
        hook.on_enter = on_enter if callable(on_enter) else None
        hook.on_leave = on_leave if callable(on_leave) else None
        self._hooks[local_id] = hook      # before installing: the first event may come at once

        try:
            before = self._hook_count()
            result = self.eval("hook(%s, 0x%x, {%s})" % (quote(lib), offset, ", ".join(parts)))
            if not result.ok:
                raise HookInstallError(result.error or "hook() failed for %s+0x%x" % (lib, offset))
            after = self._hook_count()
        except Exception:
            self._hooks.pop(local_id, None)
            raise
        if after > before:
            hook.agent_id = before
        else:
            hook.deferred = True          # library not loaded yet
        return hook

    def hook_java(self, class_name: str, method_name: str, signature: str,
                  on_enter=None, on_leave=None) -> Hook:
        """Installs a Java method hook. Callbacks as in :meth:`hook`."""
        self._ensure_prelude()
        local_id = self._new_id()
        parts = self._callbacks_source(local_id, on_enter, on_leave, self._java_shim)
        if not parts:
            raise HookInstallError("hook_java() needs on_enter and/or on_leave")
        hook = Hook(self, local_id, "%s.%s%s" % (class_name, method_name, signature), None, False, java=True)
        hook.on_enter = on_enter if callable(on_enter) else None
        hook.on_leave = on_leave if callable(on_leave) else None
        self._hooks[local_id] = hook
        result = self.eval("hook(%s, %s, %s, {%s})" % (
            quote(class_name), quote(method_name), quote(signature), ", ".join(parts)))
        if not result.ok:
            self._hooks.pop(local_id, None)
            raise HookInstallError(result.error or "Java hook failed for %s" % hook.description)
        return hook

    def unhook(self, hook_id: int) -> None:
        """Removes a native hook by its agent-side id."""
        out = self._command("unhook %d" % hook_id)
        if "removed" not in out:
            raise RenefError("could not remove hook %d: %s" % (hook_id, out.strip()))

    def unhook_all(self) -> None:
        self._command("unhook all")
        for hook in self._hooks.values():
            hook.removed = True
        self._hooks.clear()

    def hooks(self) -> str:
        """The agent's hook table as text (``Active hooks: N`` ...)."""
        if self._closed:
            return ""
        return self._command("hooks")

    def native_function(self, address: int, ret: str = "pointer", args: Optional[List[str]] = None) -> NativeFunction:
        """Wraps a native function of the target in a Python callable.
        ``ret``: int, long, pointer, bool, string, void, float, double."""
        return NativeFunction(self, address, ret, args)

    # -- events ------------------------------------------------------------

    def on_event(self, handler: Callable[[Dict[str, Any]], None]) -> None:
        """Registers a handler for ``send({...})`` events from scripts."""
        self._event_handlers.append(handler)

    def on_output(self, handler: Callable[[str], None]) -> None:
        """Registers a handler for text printed by scripts and hooks."""
        self._output_handlers.append(handler)

    def poll(self, wait: float = 0.0) -> List[Dict[str, Any]]:
        """Fetches output produced by hooks since the last command, waiting
        up to ``wait`` seconds for some to arrive. Callbacks are invoked;
        ``send()`` events not claimed by a hook are also returned."""
        start = len(self._events)
        self._command("events %d" % int(max(0.0, wait) * 1000), timeout=wait + 10)
        return list(self._events)[start:]

    def events(self) -> List[Dict[str, Any]]:
        """Returns and clears the queue of received ``send()`` events."""
        out = list(self._events)
        self._events.clear()
        return out

    def start_listener(self, interval: float = 0.2) -> None:
        """Polls for hook output on a background thread, so callbacks fire
        without explicit :meth:`poll` calls."""
        if self._listener is not None:
            return
        self._listener_stop.clear()

        def run():
            while not self._listener_stop.is_set() and not self._closed:
                try:
                    self.poll(interval)
                except RenefError:
                    break

        self._listener = threading.Thread(target=run, name="renef-listener", daemon=True)
        self._listener.start()

    def stop_listener(self) -> None:
        thread = self._listener
        if thread is None:
            return
        self._listener_stop.set()
        if thread is not threading.current_thread():
            thread.join(timeout=5)
        self._listener = None

    # -- misc commands -----------------------------------------------------

    def memscan(self, pattern: str):
        """Server-side memory scan (``ms``). Returns ``(success, output, error)``."""
        if self._closed:
            return EvalResult(False, None, "Session closed")
        try:
            out = self._command("ms %s" % pattern, timeout=60)
        except RenefError as e:
            return EvalResult(False, None, str(e))
        return EvalResult(True, out if out else None, None)

    def resume(self) -> str:
        """Resumes a target that was spawned with ``pause=True``."""
        return self._command("resume")

    def command(self, command: str, timeout: float = 35.0) -> str:
        """Sends any server command (as typed in the renef shell)."""
        return self._command(command, timeout=timeout)


class Client:
    """Connection to a renef_server. One server drives one target at a time:
    spawning or attaching again replaces the previous session."""

    session_class = Session

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, connect_timeout: float = 5.0):
        self.host = host
        self.port = port
        self._connect_timeout = connect_timeout
        self._conn_obj: Optional[Connection] = None
        self._session: Optional[Session] = None

    @property
    def _conn(self) -> Connection:
        if self._conn_obj is None or self._conn_obj.closed:
            self._conn_obj = Connection(self.host, self.port, self._connect_timeout)
        return self._conn_obj

    @property
    def framed(self) -> bool:
        """True if the server supports framed requests."""
        return self._conn.framed

    def close(self):
        if self._session is not None:
            self._session._closed = True
            self._session = None
        if self._conn_obj is not None:
            self._conn_obj.close()
            self._conn_obj = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _session_closed(self, session):
        if self._session is session:
            self._session = None
            if self._conn_obj is not None:
                self._conn_obj.close()
                self._conn_obj = None

    def _text(self, command, timeout=35.0):
        return self._conn.request(command, timeout=timeout).decode("utf-8", "surrogateescape")

    def _start(self, command, timeout, what):
        if self._session is not None:
            self._session.stop_listener()
            self._session._closed = True
            self._session = None
        reply = self._text(command, timeout=timeout)
        first = reply.strip().split("\n", 1)[0] if reply.strip() else ""
        if not first.startswith("OK"):
            raise CommandError("%s failed: %s" % (what, reply.strip() or "no reply"), output=reply)
        return first

    def spawn(self, package: str, hook_type: int = HOOK_TRAMPOLINE, pause: bool = False,
              timeout: float = 30.0) -> Session:
        """Starts ``package`` and injects the agent.

        ``pause=True`` uses the ptrace spawn gate: the app is frozen before
        its own code runs, so hooks can be in place for the first call. The
        gate stays shut - whatever you run in between - until
        :meth:`Session.resume`.
        """
        hook = "plt" if hook_type == HOOK_PLT else "trampoline"
        command = "spawn %s --hook=%s%s" % (package, hook, " --pause --hold" if pause else "")
        first = self._start(command, timeout, "spawn %s" % package)
        try:
            pid = int(first.split()[1])
        except (IndexError, ValueError):
            raise CommandError("unexpected reply to spawn: %r" % first) from None
        self._session = self.session_class(self, pid)
        return self._session

    def attach(self, pid: int, hook_type: int = HOOK_TRAMPOLINE, timeout: float = 30.0) -> Session:
        """Injects the agent into a running process."""
        hook = "plt" if hook_type == HOOK_PLT else "trampoline"
        self._start("attach %d --hook=%s" % (pid, hook), timeout, "attach %d" % pid)
        self._session = self.session_class(self, pid)
        return self._session

    def ping(self) -> bool:
        return self._text("ping", timeout=5).strip() == "pong"

    def list_apps(self, name_filter: Optional[str] = None) -> List[str]:
        """Installed packages (no injection needed)."""
        reply = self._text("la" + ("~" + name_filter if name_filter else ""), timeout=30)
        return [ln.strip() for ln in reply.split("\n")
                if ln.strip() and not ln.startswith("Total:") and not ln.startswith("ERROR")]

    def memdump_maps(self, pid: int) -> str:
        """``/proc/<pid>/maps`` of any process, read by the server - no
        injection, no ptrace."""
        reply = self._text("memdump %d --maps" % pid, timeout=30)
        lines = []
        for line in reply.split("\n"):
            if line.startswith("MEMDUMP_ERROR"):
                raise CommandError(line, output=reply)
            if line.startswith("MEMDUMP_") or not line:
                continue
            lines.append(line)
        return "\n".join(lines)

    def memdump(self, pid: int, start: int, end: int) -> bytes:
        """Reads ``[start, end)`` of any process through the server's
        ``/proc/<pid>/mem`` - no injection, no ptrace. Unreadable pages are
        returned as zero bytes."""
        out = bytearray(end - start)
        chunk = 2 * 1024 * 1024
        pos = start
        while pos < end:
            stop = min(end, pos + chunk)
            reply = self._text("memdump %d %x-%x" % (pid, pos, stop), timeout=60)
            got = False
            for line in reply.split("\n"):
                if line.startswith("MEMDUMP_ERROR"):
                    raise CommandError(line, output=reply)
                if line.startswith("SEG OK"):
                    fields = dict(f.split("=", 1) for f in line.split()[2:] if "=" in f)
                    seg_start = int(fields["start"], 16)
                    data = bytes.fromhex(fields.get("hex", ""))
                    out[seg_start - start:seg_start - start + len(data)] = data
                    got = True
            if not got and "SEG ERR" not in reply:
                raise CommandError("unexpected memdump reply: %r" % reply[:200], output=reply)
            pos = stop
        return bytes(out)


def connect(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, connect_timeout: float = 5.0) -> Client:
    """Connects to a renef_server (by default through ``adb forward tcp:1907``)."""
    client = Client(host, port, connect_timeout)
    client._conn  # connect now, so a wrong address fails here
    return client
