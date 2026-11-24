"""Python client for Renef (Android ARM64 dynamic instrumentation).

Quick start::

    import renef

    client = renef.connect()                      # adb forward tcp:1907 ... must be set
    with client.spawn("com.example.app") as s:
        base = s.Module.find("libc.so")
        print(s.rpc("OS.getpid()"))

        def on_open(event):
            print("open(%s)" % s.Memory.read_string(event.args[0]))

        s.hook("libc.so", "open", on_enter=on_open)
        s.poll(wait=5)                            # deliver hook events

The original ``Renef`` / ``RenefSession`` API is still available and keeps
its old return conventions.
"""

from .client import (
    HOOK_PLT,
    HOOK_TRAMPOLINE,
    Client,
    EvalResult,
    File,
    Frame,
    Hook,
    HookEvent,
    Instruction,
    Interceptor,
    Java,
    JavaClass,
    JavaObject,
    KCov,
    LuaExpr,
    Memory,
    MemoryRange,
    Module,
    ModuleInfo,
    NativeFunction,
    OS,
    Process,
    SearchHit,
    Session,
    Symbol,
    Syscall,
    Thread,
    connect,
    u64,
)
from .core import Renef, RenefResult, RenefSession
from .errors import (
    CommandError,
    HookInstallError,
    LuaError,
    RenefConnectionError,
    RenefError,
    RenefTimeoutError,
    SessionClosedError,
)
from .lua import quote as lua_quote

__all__ = [
    # new API
    "connect", "Client", "Session", "EvalResult", "LuaExpr", "lua_quote", "u64",
    "Hook", "HookEvent", "NativeFunction", "JavaClass", "JavaObject",
    "ModuleInfo", "Symbol", "MemoryRange", "Frame", "Instruction", "SearchHit",
    "Memory", "Module", "Thread", "Process", "OS", "File", "Syscall", "KCov",
    "Interceptor", "Java",
    "HOOK_TRAMPOLINE", "HOOK_PLT",
    # errors
    "RenefError", "RenefConnectionError", "RenefTimeoutError", "CommandError",
    "LuaError", "HookInstallError", "SessionClosedError",
    # compatibility API
    "Renef", "RenefSession", "RenefResult",
]
__version__ = "0.4.0"
