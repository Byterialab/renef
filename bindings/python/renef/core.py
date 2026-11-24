"""Backward-compatible API: ``Renef`` / ``RenefSession``.

The classes here keep the names, signatures and return conventions of the
original ctypes binding (``None`` / ``-1`` / ``(success, output, error)`` on
failure instead of exceptions), but run on the pure-Python client in
:mod:`renef.client` - no ``librenef`` shared library is loaded any more, so
this works from any directory and on macOS as well as Linux.

New code should prefer :func:`renef.connect` and :class:`renef.Session`,
which raise exceptions and return typed objects.
"""

from dataclasses import dataclass
from typing import Callable, Optional

from .client import (
    HOOK_PLT,
    HOOK_TRAMPOLINE,
    Client,
    File,
    KCov,
    Memory,
    Module,
    OS,
    Session,
    Syscall,
    Thread,
)
from .errors import RenefError
from .transport import DEFAULT_HOST, DEFAULT_PORT

__all__ = [
    "Renef", "RenefSession", "RenefResult",
    "Memory", "Module", "Thread", "OS", "File", "Syscall", "KCov",
    "HOOK_TRAMPOLINE", "HOOK_PLT",
]


@dataclass
class RenefResult:
    """Kept for import compatibility with the ctypes binding, where it was
    the C result struct. Nothing returns it any more."""

    success: int = 0
    output: Optional[str] = None
    error: Optional[str] = None


class RenefSession(Session):
    """A :class:`renef.Session` that reports failures the way the ctypes
    binding did, instead of raising."""

    strict = False

    def __init__(self, client, pid):
        super().__init__(client, pid)
        self._watch_handler = None

    def hook(self, lib: str, offset, on_enter=None, on_leave=None, **kwargs) -> int:
        """Installs a native hook. Returns 0 on success, -1 on failure."""
        try:
            Session.hook(self, lib, offset, on_enter, on_leave, **kwargs)
            return 0
        except RenefError:
            return -1

    def hook_java(self, class_name: str, method_name: str, signature: str,
                  on_enter=None, on_leave=None) -> int:
        """Installs a Java method hook. Returns 0 on success, -1 on failure."""
        try:
            Session.hook_java(self, class_name, method_name, signature, on_enter, on_leave)
            return 0
        except RenefError:
            return -1

    def unhook(self, hook_id: int) -> int:
        """Removes a hook by id. Returns 0 on success, -1 on failure."""
        try:
            Session.unhook(self, hook_id)
            return 0
        except RenefError:
            return -1

    def hooks(self) -> str:
        try:
            return Session.hooks(self)
        except RenefError:
            return ""

    def watch_start(self, callback: Callable[[bytes], None]) -> int:
        """Delivers hook output to ``callback(message: bytes)`` from a
        background thread. Returns 0 on success, -1 on failure."""
        if self._closed or self._watch_handler is not None:
            return -1

        def handler(text):
            callback(text.encode("utf-8", "surrogateescape"))

        self._watch_handler = handler
        self.on_output(handler)
        self.start_listener()
        return 0

    def watch_stop(self):
        """Stops :meth:`watch_start`."""
        if self._watch_handler is None:
            return
        self.stop_listener()
        try:
            self._output_handlers.remove(self._watch_handler)
        except ValueError:
            pass
        self._watch_handler = None

    def close(self):
        self.watch_stop()
        super().close()


class _CompatClient(Client):
    session_class = RenefSession


class Renef:
    """Main Renef client (compatibility entry point).

    ``library_path`` is accepted and ignored: the native library is no
    longer needed.
    """

    def __init__(self, library_path: Optional[str] = None,
                 host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self._client = _CompatClient(host, port)

    def spawn(self, package: str, hook_type: int = HOOK_TRAMPOLINE, pause: bool = False) -> Optional[RenefSession]:
        """Spawns ``package`` and injects. Returns ``None`` on failure."""
        try:
            return self._client.spawn(package, hook_type, pause=pause)
        except RenefError:
            return None

    def attach(self, pid: int, hook_type: int = HOOK_TRAMPOLINE) -> Optional[RenefSession]:
        """Attaches to a running process. Returns ``None`` on failure."""
        try:
            return self._client.attach(pid, hook_type)
        except RenefError:
            return None

    def list_apps(self, name_filter: Optional[str] = None):
        return self._client.list_apps(name_filter)

    def close(self):
        self._client.close()
