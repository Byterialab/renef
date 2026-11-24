"""A small stand-in for renef_server, for tests that must run without a device.

Speaks both wire modes: framed requests (``@req <id> <len>\\n`` + payload,
answered with output + ``\\x1e@done <id>\\n``) and plain lines. Behaviour is
supplied by a handler: ``handler(command: str) -> str | bytes | Reply``.
"""

import socket
import threading
import time


class Reply:
    """A reply with a delay before it is written (to model slow commands)."""

    def __init__(self, data, delay=0.0):
        self.data = data.encode() if isinstance(data, str) else data
        self.delay = delay


class MockServer:
    def __init__(self, handler, framing=True):
        self.handler = handler
        self.framing = framing
        self.commands = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _run(self, command):
        self.commands.append(command)
        reply = self.handler(command)
        if isinstance(reply, Reply):
            if reply.delay:
                time.sleep(reply.delay)
            return reply.data
        if isinstance(reply, str):
            return reply.encode()
        return reply or b""

    def _client(self, conn):
        buf = b""
        try:
            while True:
                if self.framing and buf.startswith(b"@req "):
                    nl = buf.find(b"\n")
                    if nl >= 0:
                        rid, length = (int(x) for x in buf[5:nl].split())
                        if len(buf) >= nl + 1 + length:
                            payload = buf[nl + 1:nl + 1 + length]
                            buf = buf[nl + 1 + length:]
                            command = payload.decode("utf-8", "surrogateescape").rstrip("\n")
                            reply = self._run(command)
                            # A server with an event channel reports how many
                            # lines of hook output it is holding.
                            pending = getattr(self.handler, "pending_count", lambda: 0)()
                            field = b" ev=%d" % pending if pending else b""
                            conn.sendall(reply + b"\x1e@done %d%s\n" % (rid, field))
                            continue
                elif buf.endswith(b"\n"):
                    command = buf.decode("utf-8", "surrogateescape").rstrip("\n")
                    buf = b""
                    if command.startswith("@req "):
                        # What a server without framing does with a frame.
                        conn.sendall(b"ERROR: Unknown command. Type 'help' for available commands.\n")
                    else:
                        conn.sendall(self._run(command))
                    continue
                data = conn.recv(65536)
                if not data:
                    return
                buf += data
        except OSError:
            pass
        finally:
            conn.close()
