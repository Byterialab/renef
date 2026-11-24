"""Socket transport to renef_server.

Speaks the framed request protocol when the server supports it and the
original line protocol otherwise. Wire format (see
``src/librenef/include/renef/framing.h``)::

    request :  "@req <id> <len>\\n"  + exactly <len> payload bytes
    response:  <everything the command wrote>  "\\x1e@done <id>[ ev=<n>]\\n"

``ev=<n>`` says that <n> lines of hook/trace output are waiting on the
server: such output is never part of a reply, ``events`` fetches it.

A reply that arrives after its request was given up on is skipped by id, so
it can never be returned as the reply to a later command.
"""

import socket
import threading
import time
from collections import deque

from .errors import RenefConnectionError, RenefTimeoutError

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 1907

_DONE_MARK = b"\x1e@done "
_REQ_PREFIX = b"@req "


class ResponseReader:
    """Demultiplexes a framed response stream by request id.

    A port of ``renef_framing::ResponseReader``: the responder handles
    requests strictly in order, so everything received before
    ``@done <id>`` was produced while ``<id>`` (or an older, abandoned
    request) was running.
    """

    def __init__(self):
        self._buf = bytearray()
        self._outstanding = deque()
        #: ``ev=<n>`` of the marker that completed the last request
        self.pending_events = 0

    def sent(self, request_id):
        self._outstanding.append(request_id)

    def feed(self, data):
        self._buf += data

    def reset(self):
        self._buf.clear()
        self._outstanding.clear()

    def forget_outstanding(self):
        self._outstanding.clear()

    def busy_with_older(self, request_id):
        return bool(self._outstanding) and self._outstanding[0] < request_id

    def _partial_marker_suffix(self):
        """Length of the longest tail of the buffer that is a proper prefix
        of the done-marker (a marker split across two reads)."""
        limit = min(len(self._buf), len(_DONE_MARK) - 1)
        for k in range(limit, 0, -1):
            if self._buf[-k:] == _DONE_MARK[:k]:
                return k
        return 0

    def _take(self, n, request_id, out):
        if n <= 0:
            return
        mine = (not self._outstanding) or self._outstanding[0] >= request_id
        if mine:
            out += self._buf[:n]
        del self._buf[:n]

    def poll(self, request_id, out):
        """Moves bytes that belong to ``request_id`` into ``out`` (a
        bytearray). Returns True once its completion marker was consumed."""
        while True:
            p = self._buf.find(_DONE_MARK)
            nl = self._buf.find(b"\n", p) if p >= 0 else -1
            if p < 0 or nl < 0:
                limit = p if p >= 0 else len(self._buf) - self._partial_marker_suffix()
                self._take(limit, request_id, out)
                return False
            fields = bytes(self._buf[p + len(_DONE_MARK):nl]).split()
            try:
                marker_id = int(fields[0]) if fields else 0
            except ValueError:
                marker_id = 0
            pending = 0
            for field in fields[1:]:
                if field.startswith(b"ev="):
                    try:
                        pending = int(field[3:])
                    except ValueError:
                        pass
            # Length of the marker line, measured before the bytes in front
            # of it are removed.
            marker_len = nl + 1 - p
            self._take(p, request_id, out)
            del self._buf[:marker_len]
            while self._outstanding and self._outstanding[0] <= marker_id:
                self._outstanding.popleft()
            if marker_id == request_id:
                self.pending_events = pending
                return True


class Connection:
    """One TCP connection to renef_server. Thread-safe: requests are
    serialised with a lock, so a background event poller and the caller's
    own commands can share it."""

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, connect_timeout=5.0):
        self.host = host
        self.port = port
        self._lock = threading.RLock()
        self._reader = ResponseReader()
        self._next_id = 1
        self._sock = None
        self.framed = False
        try:
            self._sock = socket.create_connection((host, port), timeout=connect_timeout)
        except OSError as e:
            raise RenefConnectionError(
                "cannot connect to renef_server at %s:%d (%s). Is the server running and is "
                "`adb forward tcp:%d localabstract:com.android.internal.os.RuntimeInit` set?"
                % (host, port, e, port)
            ) from e
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._probe_framing()

    # -- lifecycle ---------------------------------------------------------

    @property
    def closed(self):
        return self._sock is None

    def close(self):
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- internals ---------------------------------------------------------

    def _send_all(self, data):
        try:
            self._sock.sendall(data)
        except OSError as e:
            self.close()
            raise RenefConnectionError("connection to renef_server lost while sending (%s)" % e) from e

    def _recv(self, wait):
        """Returns received bytes, b"" on timeout. Raises on a closed peer."""
        self._sock.settimeout(max(wait, 0.001))
        try:
            data = self._sock.recv(65536)
        except socket.timeout:
            return b""
        except OSError as e:
            self.close()
            raise RenefConnectionError("connection to renef_server lost (%s)" % e) from e
        if not data:
            self.close()
            raise RenefConnectionError("renef_server closed the connection")
        return data

    def _probe_framing(self):
        # A framing-aware server completes this within milliseconds; an
        # older one answers "ERROR: Unknown command..." without a marker.
        try:
            self._framed_request(b"ping", 1.5)
            self.framed = True
        except RenefTimeoutError:
            self.framed = False
            self._reader.reset()

    def _framed_request(self, payload, timeout):
        request_id = self._next_id
        self._next_id += 1
        # The payload always ends in "\n": harmless for a framing-aware
        # server, and it keeps an old server from blocking on a partial line.
        body = payload + b"\n"
        self._send_all(_REQ_PREFIX + b"%d %d\n" % (request_id, len(body)) + body)
        self._reader.sent(request_id)

        out = bytearray()
        deadline = time.monotonic() + timeout
        while True:
            if self._reader.poll(request_id, out):
                return bytes(out)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RenefTimeoutError(
                    "no completion from renef_server within %.1fs" % timeout,
                    partial=bytes(out).decode("utf-8", "replace"),
                )
            data = self._recv(min(remaining, 0.25))
            if data:
                self._reader.feed(data)
                deadline = time.monotonic() + timeout  # silence timeout: any data resets it

    def _legacy_request(self, payload, timeout, quiet=0.35):
        if b"\n" in payload:
            raise RenefConnectionError(
                "this renef_server does not support framed requests, so multi-line commands "
                "cannot be sent reliably; update renef_server on the device"
            )
        self._send_all(payload + b"\n")
        out = bytearray()
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if out:
                    return bytes(out)
                raise RenefTimeoutError("no reply from renef_server within %.1fs" % timeout)
            data = self._recv(min(remaining, quiet if out else 0.25))
            if data:
                out += data
            elif out:
                return bytes(out)  # the line went quiet: that is the only end-of-reply there is

    # -- public ------------------------------------------------------------

    @property
    def pending_events(self):
        """Lines of hook/trace output waiting on the server after the last
        request (always 0 on a server without framing)."""
        return self._reader.pending_events if self.framed else 0

    def request(self, command, timeout=35.0):
        """Sends one command and returns its complete reply as bytes."""
        if isinstance(command, str):
            command = command.encode("utf-8", "surrogateescape")
        command = command.rstrip(b"\n")
        with self._lock:
            if self._sock is None:
                raise RenefConnectionError("connection is closed")
            if self.framed:
                return self._framed_request(command, timeout)
            return self._legacy_request(command, timeout)
