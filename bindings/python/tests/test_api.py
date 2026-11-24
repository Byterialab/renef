"""Offline tests for the renef Python client.

No device and no native library needed: the client talks to
``tests/mock_server.py``, which implements the server's wire protocol.

    python -m unittest discover -s bindings/python/tests -v
"""

import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import renef  # noqa: E402
from mock_server import MockServer, Reply  # noqa: E402
from renef.lua import quote, to_lua  # noqa: E402
from renef.transport import Connection, ResponseReader  # noqa: E402


def done(n):
    return b"\x1e@done %d\n" % n


class LuaQuotingTests(unittest.TestCase):
    def test_quote_neutralises_everything_that_could_end_the_literal(self):
        for value in ['plain', 'has "quotes"', "back\\slash", "new\nline", "nul\x00byte", "]]", "café", ""]:
            literal = quote(value)
            self.assertTrue(literal.startswith('"') and literal.endswith('"'))
            body = literal[1:-1]
            self.assertNotIn('"', body)
            self.assertNotIn("\n", body)
            # every backslash must start a 3-digit decimal escape
            i = 0
            while i < len(body):
                if body[i] == "\\":
                    self.assertTrue(body[i + 1:i + 4].isdigit(), literal)
                    i += 4
                else:
                    i += 1

    def test_quote_round_trips_bytes(self):
        data = bytes(range(256))
        literal = quote(data)[1:-1]
        out = bytearray()
        i = 0
        while i < len(literal):
            if literal[i] == "\\":
                out.append(int(literal[i + 1:i + 4]))
                i += 4
            else:
                out.append(ord(literal[i]))
                i += 1
        self.assertEqual(bytes(out), data)

    def test_to_lua(self):
        self.assertEqual(to_lua(None), "nil")
        self.assertEqual(to_lua(True), "true")
        self.assertEqual(to_lua(42), "42")
        self.assertEqual(to_lua(-1), "-1")
        self.assertEqual(to_lua(0xB400007C14003E7E), "0xb400007c14003e7e")  # stays an integer in Lua
        self.assertEqual(to_lua([1, "a"]), '{1, "a"}')
        self.assertEqual(to_lua({"k": 1}), '{["k"] = 1}')
        self.assertEqual(to_lua(renef.LuaExpr("args[0]")), "args[0]")
        with self.assertRaises(TypeError):
            to_lua(object())

    def test_u64(self):
        self.assertEqual(renef.u64(-1), 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(renef.u64(5), 5)
        self.assertIsNone(renef.u64(None))


class ResponseReaderTests(unittest.TestCase):
    def _run(self, stream, chunk, want, sent):
        reader = ResponseReader()
        for request_id in sent:
            reader.sent(request_id)
        out = bytearray()
        finished = False
        for i in range(0, len(stream), chunk):
            reader.feed(stream[i:i + chunk])
            if reader.poll(want, out):
                finished = True
                break
        return finished, bytes(out)

    def test_every_chunk_size_with_and_without_stale_output(self):
        mine = b'[event] {"value":6}\nOK\n'
        stale = b'[event] {"value":99}\nOK\n' + done(57)
        for chunk in range(1, 81):
            finished, out = self._run(stale + mine + done(58) + b"late hook output\n", chunk, 58, [57, 58])
            self.assertTrue(finished, chunk)
            self.assertEqual(out, mine, chunk)
            finished, out = self._run(mine + done(58), chunk, 58, [58])
            self.assertTrue(finished, chunk)
            self.assertEqual(out, mine, chunk)

    def test_completion_marker_may_carry_a_pending_event_count(self):
        reader = ResponseReader()
        reader.sent(1)
        reader.sent(2)
        reader.feed(b"one\x1e@done 1 ev=42\ntwo\x1e@done 2\n")
        out = bytearray()
        self.assertTrue(reader.poll(1, out))
        self.assertEqual((bytes(out), reader.pending_events), (b"one", 42))
        out = bytearray()
        self.assertTrue(reader.poll(2, out))
        self.assertEqual((bytes(out), reader.pending_events), (b"two", 0))

    def test_output_before_any_request_belongs_to_the_next_one(self):
        finished, out = self._run(b"hook said hi\nresult\n" + done(3), 7, 3, [3])
        self.assertTrue(finished)
        self.assertEqual(out, b"hook said hi\nresult\n")


class TransportTests(unittest.TestCase):
    def test_framed_mode_is_detected_and_used(self):
        with MockServer(lambda c: "pong\n" if c == "ping" else "echo:" + c + "\n") as server:
            conn = Connection("127.0.0.1", server.port)
            self.assertTrue(conn.framed)
            self.assertEqual(conn.request("hello"), b"echo:hello\n")
            self.assertEqual(conn.request("multi\nline"), b"echo:multi\nline\n")
            conn.close()

    def test_falls_back_to_line_mode_on_a_server_without_framing(self):
        with MockServer(lambda c: "pong\n" if c == "ping" else "echo:" + c + "\n", framing=False) as server:
            conn = Connection("127.0.0.1", server.port)
            self.assertFalse(conn.framed)
            self.assertEqual(conn.request("hello"), b"echo:hello\n")
            with self.assertRaises(renef.RenefConnectionError):
                conn.request("multi\nline")
            conn.close()

    def test_late_reply_is_not_returned_for_the_next_command(self):
        def handler(command):
            if command == "ping":
                return "pong\n"
            if command == "slow":
                return Reply("slow-result\n", delay=0.8)
            return "fast-result\n"

        with MockServer(handler) as server:
            conn = Connection("127.0.0.1", server.port)
            with self.assertRaises(renef.RenefTimeoutError):
                conn.request("slow", timeout=0.2)
            # The slow reply arrives while this one is being waited for.
            self.assertEqual(conn.request("fast", timeout=5), b"fast-result\n")
            conn.close()

    def test_connection_refused_is_reported_clearly(self):
        with self.assertRaises(renef.RenefConnectionError):
            Connection("127.0.0.1", 1, connect_timeout=1)


class FakeTarget:
    """Handler that answers like renef_server driving one target."""

    def __init__(self):
        self.rpc = {}          # substring of the expression -> Python value (or Exception)
        self.hook_count = 0
        self.pending_events = []
        self.announce_pending = False   # report pending_events in the completion marker
        self.evals = []

    def pending_count(self):
        return len(self.pending_events) if self.announce_pending else 0

    def __call__(self, command):
        if command == "ping":
            return "pong\n"
        if command.startswith("spawn "):
            return "OK 4242\n"
        if command.startswith("attach "):
            return "OK\n" if "999" not in command else "ERROR: Failed to attach\n"
        if command == "hooks":
            return "Active hooks: %d\n" % self.hook_count
        if command.startswith("unhook "):
            return "Hook %s removed\n" % command.split()[1] if command.split()[1] != "77" else "ERROR: Failed to remove hook\n"
        if command.startswith("events"):
            out = "".join("[event] %s\n" % json.dumps(e) for e in self.pending_events)
            self.pending_events = []
            return out
        if command.startswith("la"):
            return "com.example.one\ncom.example.two\n\nTotal: 2 packages\n"
        if command.startswith("memdump "):
            if "--maps" in command:
                return "MEMDUMP_MAPS pid=1\n1000-2000 r-xp 00000000 00:00 0 /x.so\nMEMDUMP_END\n"
            return "MEMDUMP_MANIFEST pid=1\nSEG OK start=0x1000 len=4 hex=7f454c46\nSEG ERR start=0x1004 len=4 errno=5 msg=EIO\nMEMDUMP_END\n"
        if command.startswith("exec "):
            self.evals.append(command)
            eval_id = int(command.split("__py_eval = ")[1].split(",")[0])
            if "hook(" in command and "FAILHOOK" not in command:
                self.hook_count += 1
            if "BOOM" in command:
                return '[event] {"__py_eval":%d,"ok":false,"error":"eval:1: boom"}\nERROR: Lua execution failed\n' % eval_id
            if "FAILHOOK" in command:
                return '[event] {"__py_eval":%d,"ok":false,"error":"Failed to install native hook"}\nOK\n' % eval_id
            printed = "printed line\n" if "PRINT" in command else ""
            return '%s[event] {"__py_eval":%d,"ok":true}\nOK\n' % (printed, eval_id)
        if command.startswith("rpc "):
            for key, value in self.rpc.items():
                if key in command:
                    if isinstance(value, Exception):
                        return '{"ok":false,"error":%s,"__rpc_call":true}\n' % json.dumps(str(value))
                    if isinstance(value, Reply):
                        return value
                    return json.dumps({"ok": True, "value": value, "__rpc_call": True}) + "\n"
            return '{"ok":true,"__rpc_call":true}\n'
        return "ERROR: Unknown command. Type 'help' for available commands.\n"


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.target = FakeTarget()
        self.server = MockServer(self.target)
        self.client = renef.connect("127.0.0.1", self.server.port)
        self.session = self.client.spawn("com.example.app")

    def tearDown(self):
        self.client.close()
        self.server.close()

    def test_spawn_returns_pid(self):
        self.assertEqual(self.session.pid, 4242)
        self.assertIn("spawn com.example.app --hook=trampoline", self.server.commands)

    def test_spawn_with_pause_and_plt(self):
        self.client.spawn("com.example.app", hook_type=renef.HOOK_PLT, pause=True)
        self.assertIn("spawn com.example.app --hook=plt --pause --hold", self.server.commands)

    def test_failed_attach_raises(self):
        with self.assertRaises(renef.CommandError):
            self.client.attach(999)

    def test_eval_success_and_output(self):
        result = self.session.eval("PRINT something")
        self.assertEqual(result, (True, "printed line", None))
        ok, output, error = result            # unpacks like the old tuple
        self.assertTrue(ok)

    def test_eval_reports_the_lua_error_message(self):
        result = self.session.eval('error("BOOM")')
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "eval:1: boom")

    def test_eval_sends_the_code_as_one_quoted_literal(self):
        self.session.eval('print("a")\n-- comment with // and ~ and "quotes"')
        sent = self.target.evals[-1]
        self.assertNotIn("\n", sent)
        self.assertNotIn('print("a")', sent)   # quotes were escaped, not embedded

    def test_rpc_returns_values_and_raises_lua_errors(self):
        self.target.rpc["Module.find"] = 0x7000
        self.target.rpc["nosuch"] = RuntimeError("attempt to call a nil value")
        self.assertEqual(self.session.Module.find("libc.so"), 0x7000)
        with self.assertRaises(renef.LuaError) as ctx:
            self.session.rpc("nosuch()")
        self.assertIn("nil value", str(ctx.exception))

    def test_output_handlers_get_target_output_without_protocol_lines(self):
        got = []
        self.session.on_output(got.append)
        self.session.eval("PRINT something")
        # output of a hook that fired meanwhile, around the rpc result line
        self.target.rpc["busy()"] = Reply('[tid:1] read(3, 0x10, 8) = 8\n{"__rpc_call":true,"ok":true,"value":7}\nhook says hi\n')
        self.assertEqual(self.session.rpc("busy()"), 7)
        self.session.rpc("1")                       # nothing printed: handlers are not called
        self.assertEqual(got, ["printed line\n", "[tid:1] read(3, 0x10, 8) = 8\nhook says hi\n"])

    def test_enumerate_loaded_classes_filters_on_the_client(self):
        self.target.rpc["Java.enumerateLoadedClasses()"] = ["com.example.Main", "com.example.net.Api", "okhttp3.Call"]
        self.assertEqual(len(self.session.Java.enumerate_loaded_classes()), 3)
        self.assertEqual(self.session.Java.enumerate_loaded_classes("example.net"), ["com.example.net.Api"])

    def test_rpc_server_timeout_message_becomes_timeout_error(self):
        self.target.rpc["slow()"] = Reply("ERROR: rpc got no completion from target after 1s without output\n")
        with self.assertRaises(renef.RenefTimeoutError):
            self.session.rpc("slow()", timeout=1)

    def test_negative_addresses_become_unsigned(self):
        self.target.rpc["Module.find"] = 0xB400007C14003E7E - (1 << 64)   # how Lua prints a tagged pointer
        self.assertEqual(self.session.Module.find("x"), 0xB400007C14003E7E)

    def test_module_and_symbol_records(self):
        self.target.rpc["__renef_py.modules()"] = [{"name": "libc.so", "path": "/apex/libc.so", "base": 4096, "size": 8192}]
        self.target.rpc["Module.exports"] = [{"name": "operator new(unsigned long)", "offset": 16}]
        modules = self.session.Module.list()
        self.assertEqual(modules[0].name, "libc.so")
        self.assertEqual(modules[0]["base"], 4096)             # dict-style access still works
        exports = self.session.Module.exports("libc.so")
        self.assertEqual(exports[0].name, "operator new(unsigned long)")   # spaces in names survive

    def test_memory_read_write(self):
        self.target.rpc["__renef_py.read("] = "7f454c46"
        self.assertEqual(self.session.Memory.read(0x1000, 4), b"\x7fELF")
        self.assertEqual(self.session.Memory.read_u32(0x1000), 0x464C457F)
        self.assertEqual(self.session.Memory.write(0x1000, b"\x00\xff"), 2)
        self.assertTrue(any('__renef_py.write(4096, "00ff")' in c for c in self.server.commands))

    def test_paths_are_quoted_not_interpolated(self):
        self.session.File.exists('/tmp/a"b\\c')
        sent = [c for c in self.server.commands if "File.exists" in c][-1]
        self.assertIn('File.exists("/tmp/a\\034b\\092c")', sent)

    def test_hook_with_python_callbacks_and_event_delivery(self):
        seen = []
        hook = self.session.hook("libc.so", 0x100, on_enter=seen.append, on_leave=seen.append)
        self.assertEqual(hook.agent_id, 0)
        self.assertFalse(hook.deferred)
        self.target.pending_events = [
            {"__py_hook": hook.id, "phase": "enter", "tid": 7, "args": [1, -1, 3, 4, 5, 6, 7, 8]},
            {"__py_hook": hook.id, "phase": "leave", "tid": 7, "retval": 0},
            {"kind": "finding"},
        ]
        other = self.session.poll(0.1)
        self.assertEqual([e.phase for e in seen], ["enter", "leave"])
        self.assertEqual(seen[0].args[1], 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(seen[0].thread_id, 7)
        self.assertEqual(seen[1].retval, 0)
        self.assertEqual(other, [{"kind": "finding"}])

    def test_held_hook_output_arrives_with_the_next_command_but_not_in_its_reply(self):
        # A server with an event channel keeps hook output out of replies
        # and reports how much it holds; the client collects it right away.
        seen = []
        hook = self.session.hook("libc.so", 0x100, on_enter=seen.append)
        self.target.announce_pending = True
        self.target.pending_events = [
            {"__py_hook": hook.id, "phase": "enter", "tid": 7, "args": [1]},
            {"kind": "finding"},
        ]
        self.assertEqual(self.session.hooks(), "Active hooks: 1\n")
        self.assertEqual(len(seen), 1)
        self.assertEqual(self.session.events(), [{"kind": "finding"}])
        self.assertEqual(self.server.commands[-2:], ["hooks", "events 0"])
        # nothing waiting: no extra round trip
        self.session.hooks()
        self.assertEqual(self.server.commands[-1], "hooks")

    def test_hook_with_lua_source_and_options(self):
        self.session.hook("libc.so", 0x100, on_leave="return 1", caller="*", asynchronous=True)
        sent = self.target.evals[-1]
        for expected in ("onLeave = function(retval) return 1 end", "caller = ", "async = true"):
            self.assertIn(expected.replace('"', "\\034"), sent)

    def test_hook_install_failure_raises(self):
        with self.assertRaises(renef.HookInstallError):
            self.session.hook("libc.so", 0x100, on_enter="FAILHOOK")

    def test_hook_on_a_library_that_is_not_loaded_is_marked_deferred(self):
        self.target.hook_count = 0
        original = self.target.__call__

        hook = None
        # the fake counts hooks on every hook( call; emulate "pending" by undoing it
        def handler(command):
            reply = original(command)
            if command.startswith("exec ") and "hook(" in command:
                self.target.hook_count -= 1
            return reply

        self.server.handler = handler
        hook = self.session.hook("libnotyet.so", 0x10, on_enter="print(1)")
        self.assertTrue(hook.deferred)
        self.assertIsNone(hook.agent_id)

    def test_unhook(self):
        self.session.unhook(3)
        with self.assertRaises(renef.RenefError):
            self.session.unhook(77)

    def test_listener_thread_delivers_events(self):
        got = []
        self.session.on_event(got.append)
        self.session.start_listener(interval=0.05)
        self.target.pending_events = [{"n": 1}]
        deadline = time.time() + 3
        while not got and time.time() < deadline:
            time.sleep(0.02)
        self.session.stop_listener()
        self.assertEqual(got, [{"n": 1}])

    def test_client_helpers(self):
        self.assertEqual(self.client.list_apps(), ["com.example.one", "com.example.two"])
        self.assertIn("/x.so", self.client.memdump_maps(1))
        self.assertEqual(self.client.memdump(1, 0x1000, 0x1008), b"\x7fELF\x00\x00\x00\x00")

    def test_closed_session(self):
        self.session.close()
        self.assertEqual(self.session.pid, -1)
        with self.assertRaises(renef.SessionClosedError):
            self.session.rpc("1")


class CompatibilityApiTests(unittest.TestCase):
    """``Renef`` / ``RenefSession`` keep the ctypes binding's conventions."""

    def setUp(self):
        self.target = FakeTarget()
        self.server = MockServer(self.target)
        self.renef = renef.Renef(host="127.0.0.1", port=self.server.port)
        self.session = self.renef.spawn("com.example.app")

    def tearDown(self):
        self.renef.close()
        self.server.close()

    def test_library_path_argument_is_accepted(self):
        renef.Renef("/nonexistent/librenef.so", host="127.0.0.1", port=self.server.port).close()

    def test_spawn_failure_returns_none(self):
        self.assertIsNone(self.renef.attach(999))
        self.assertIsNone(renef.Renef(host="127.0.0.1", port=1).spawn("x"))

    def test_hook_returns_zero_or_minus_one(self):
        self.assertEqual(self.session.hook("libc.so", 0x10, "print(args[0])", "print(retval)"), 0)
        self.assertEqual(self.session.hook("libc.so", 0x10, "FAILHOOK"), -1)
        self.assertEqual(self.session.hook_java("a/B", "m", "()V", "print(1)"), 0)
        self.assertEqual(self.session.unhook(1), 0)
        self.assertEqual(self.session.unhook(77), -1)
        self.assertIn("Active hooks", self.session.hooks())

    def test_errors_become_sentinels_instead_of_exceptions(self):
        self.target.rpc["__renef_py.read("] = RuntimeError("not readable")
        self.target.rpc["Module.find"] = RuntimeError("x")
        self.target.rpc["File.exists"] = RuntimeError("x")
        self.assertIsNone(self.session.Memory.read(0x10, 4))
        self.assertEqual(self.session.Module.find("libc.so"), 0)
        self.assertFalse(self.session.File.exists("/x"))
        self.assertEqual(self.session.Memory.write_u32(0x10, 1), 0)

    def test_eval_returns_a_three_tuple(self):
        ok, out, err = self.session.eval("PRINT x")
        self.assertEqual((ok, out, err), (True, "printed line", None))

    def test_watch_start_delivers_output_as_bytes(self):
        got = []
        self.assertEqual(self.session.watch_start(got.append), 0)
        self.assertEqual(self.session.watch_start(got.append), -1)     # already running
        self.target.pending_events = []
        original = self.target.__call__
        state = {"sent": False}

        def handler(command):
            if command.startswith("events") and not state["sent"]:
                state["sent"] = True
                return "hook output line\n"
            return original(command)

        self.server.handler = handler
        deadline = time.time() + 3
        while not got and time.time() < deadline:
            time.sleep(0.02)
        self.session.watch_stop()
        self.assertEqual(got, [b"hook output line\n"])


if __name__ == "__main__":
    unittest.main()
