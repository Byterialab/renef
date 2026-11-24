"""Device tests for the renef Python client.

Needs a running renef_server (``adb forward tcp:1907 ...``) and an installed
test app. Skipped unless RENEF_TEST_PACKAGE is set:

    RENEF_TEST_PACKAGE=<package> \\
        python -m unittest bindings/python/tests/test_device.py -v

Written against the project's own test app (not part of the repository);
the tests that depend on it are skipped for any other package.
"""

import os
import sys
import re
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import renef  # noqa: E402

PACKAGE = os.environ.get("RENEF_TEST_PACKAGE")
HOST = os.environ.get("RENEF_HOST", "127.0.0.1")
PORT = int(os.environ.get("RENEF_PORT", "1907"))


@unittest.skipUnless(PACKAGE, "set RENEF_TEST_PACKAGE to run device tests")
class DeviceTestCase(unittest.TestCase):
    pause = False

    @classmethod
    def setUpClass(cls):
        cls.client = renef.connect(HOST, PORT)
        cls.s = cls.client.spawn(PACKAGE, pause=cls.pause)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def export(self, name, lib="libc.so"):
        address = self.s.Module.find_export(lib, name)
        self.assertIsNotNone(address, name)
        return address


class BasicsTests(DeviceTestCase):
    def test_connection(self):
        self.assertTrue(self.client.framed, "server does not support framed requests")
        self.assertGreater(self.s.pid, 0)
        self.assertEqual(self.s.OS.getpid(), self.s.pid)
        self.assertIn(PACKAGE, self.client.list_apps(PACKAGE.split(".")[-1]))

    def test_eval_output_and_errors(self):
        self.assertEqual(self.s.eval('print("hello"); print(1 + 1)'), (True, "hello\n2", None))
        syntax = self.s.eval("this is not lua")
        self.assertFalse(syntax.ok)
        self.assertIn("syntax error", syntax.error)
        runtime = self.s.eval('error("boom")')
        self.assertFalse(runtime.ok)
        self.assertIn("boom", runtime.error)

    def test_code_with_slashes_tildes_and_urls(self):
        # `//` anywhere in a command used to make the server reject it.
        result = self.s.eval('print(7 // 2); print("https://example.com/a~b")')
        self.assertEqual(result, (True, "3\nhttps://example.com/a~b", None))
        self.assertEqual(self.s.rpc('"http://x//y" .. tostring(9 // 4)'), "http://x//y2")

    def test_rpc_values(self):
        value = self.s.rpc('{a = 1, b = {1, 2, 3}, s = "x\\0y", t = true, f = 1.5}')
        self.assertEqual(value, {"a": 1, "b": [1, 2, 3], "s": "x\x00y", "t": True, "f": 1.5})
        self.assertIsNone(self.s.rpc("nil"))
        with self.assertRaises(renef.LuaError):
            self.s.rpc("this_function_does_not_exist()")

    def test_call_and_large_script(self):
        lines = ["function py_test_sum(a, b) return a + b end", "local acc = 0"]
        lines += ["acc = acc + %d -- padding to make this script large" % (i % 7) for i in range(6000)]
        lines.append("py_test_acc = acc")
        result = self.s.eval("\n".join(lines))
        self.assertTrue(result.ok, result.error)
        self.assertEqual(self.s.rpc("py_test_acc"), sum(i % 7 for i in range(6000)))
        self.assertEqual(self.s.call("py_test_sum", 40, 2), 42)
        self.assertEqual(self.s.call("string.upper", 'q"uote\\d'), 'Q"UOTE\\D')

    def test_timeout_then_recovery(self):
        slow = "(function() local t = os.time(); while os.time() - t < 3 do end; return 'late' end)()"
        with self.assertRaises(renef.RenefTimeoutError):
            self.s.rpc(slow, timeout=1)
        # The late reply must not be handed to the next call.
        self.assertEqual(self.s.rpc("1 + 1", timeout=15), 2)
        self.assertEqual(self.s.rpc('"after"'), "after")


class ModuleMemoryTests(DeviceTestCase):
    def test_modules(self):
        base = self.s.Module.find("libc.so")
        self.assertGreater(base, 0)
        self.assertEqual(self.s.Module.find("libdoes_not_exist.so"), 0)
        by_name = {m.name: m for m in self.s.Module.list()}
        self.assertEqual(by_name["libc.so"].base, base)
        self.assertGreater(by_name["libc.so"].size, 0x10000)
        exports = self.s.Module.exports("libc.so")
        self.assertGreater(len(exports), 1000)
        names = {e.name for e in exports}
        self.assertTrue({"open", "malloc", "getpid"} <= names)
        globbed = [e.name for e in self.s.Module.find_exports("libc.so", "pthread_mutex_*")]
        self.assertIn("pthread_mutex_lock", globbed)
        self.assertEqual(self.export("getpid"), base + next(e.offset for e in exports if e.name == "getpid"))
        self.assertIsNone(self.s.Module.find_export("libc.so", "no_such_symbol_xyz"))
        instructions = self.s.Module.disassemble(self.export("getpid"), 4)
        self.assertEqual(len(instructions), 4)
        self.assertEqual(instructions[1].address - instructions[0].address, 4)

    def test_memory_read_write(self):
        base = self.s.Module.find("libc.so")
        self.assertEqual(self.s.Memory.read(base, 4), b"\x7fELF")
        self.assertEqual(self.s.Memory.read_u32(base), 0x464C457F)
        big = self.s.Memory.read(base, 300 * 1024)             # several chunks
        self.assertEqual(len(big), 300 * 1024)
        self.assertEqual(big[:4], b"\x7fELF")

        p = self.s.Memory.alloc(8192)
        payload = bytes(range(256)) * 20                        # every byte value, incl. NUL / 0x1e / newline
        self.assertEqual(self.s.Memory.write(p, payload), len(payload))
        self.assertEqual(self.s.Memory.read(p, len(payload)), payload)
        self.s.Memory.write_u64(p, 0xDEADBEEFCAFEBABE)
        self.assertEqual(self.s.Memory.read_u64(p), 0xDEADBEEFCAFEBABE)
        self.s.Memory.write_u8(p + 8, 0x7F)
        self.assertEqual(self.s.Memory.read_u8(p + 8), 0x7F)
        self.s.Memory.free(p)

        text = self.s.Memory.alloc_str('q"uo\\te and ç')
        self.assertEqual(self.s.Memory.read_string(text), 'q"uo\\te and ç')
        self.assertIsNone(self.s.Memory.read_string(0))

    def test_unmapped_memory_raises_and_target_survives(self):
        with self.assertRaises(renef.LuaError):
            self.s.Memory.read(0x10, 8)
        with self.assertRaises(renef.LuaError):
            self.s.Memory.write(0x10, b"\x00")
        self.assertEqual(self.s.OS.getpid(), self.s.pid)

    def test_patch_code_page(self):
        address = self.export("getppid")
        original = self.s.Memory.read(address, 4)
        self.s.Memory.write(address, original)                  # read-only page: goes through Memory.patch
        self.assertEqual(self.s.Memory.read(address, 4), original)

    def test_search_ranges_threads_backtrace(self):
        hits = self.s.Memory.search("7f 45 4c 46", "libc.so")
        self.assertTrue(any(h.addr == self.s.Module.find("libc.so") for h in hits))
        ranges = self.s.Process.ranges()
        self.assertGreater(len(ranges), 100)
        self.assertTrue(any(r.path.endswith("libc.so") and "x" in r.perms for r in ranges))
        self.assertIn(self.s.pid, self.s.Process.threads())
        self.assertGreater(self.s.Thread.id(), 0)
        frames = self.s.Thread.backtrace()
        self.assertTrue(frames and frames[0].pc > 0)

    def test_files_and_os(self):
        self.assertTrue(self.s.File.exists("/proc/self/maps"))
        self.assertFalse(self.s.File.exists('/no"such\\path'))
        self.assertTrue(self.s.File.readlink("/proc/self/exe").startswith("/"))
        self.assertIn("maps", self.s.OS.listdir("/proc/self"))
        self.assertIsNone(self.s.OS.listdir("/no/such/dir"))

    def test_passive_memdump(self):
        base = self.s.Module.find("libc.so")
        self.assertEqual(self.client.memdump(self.s.pid, base, base + 4), b"\x7fELF")
        self.assertIn("libc.so", self.client.memdump_maps(self.s.pid))


class CallAndHookTests(DeviceTestCase):
    def test_native_function(self):
        self.assertEqual(self.s.native_function(self.export("getpid"), "int")(), self.s.pid)
        atoi = self.s.native_function(self.export("atoi"), "int", ["pointer"])
        self.assertEqual(atoi("1234"), 1234)
        strlen_addr = self.s.Memory.alloc_str("twelve chars")
        self.assertEqual(self.s.native_function(self.export("atoi"), "int")(strlen_addr), 0)

    def test_java(self):
        system = self.s.Java.use("java/lang/System")
        self.assertGreater(system.call("currentTimeMillis", "()J"), 1_600_000_000_000)
        f = self.s.Java.use("java/io/File").new("(Ljava/lang/String;)V", "/proc/self/maps")
        self.assertTrue(f.call("exists", "()Z"))
        self.assertEqual(f.call("getName", "()Ljava/lang/String;"), "maps")
        self.assertGreater(f.raw, 0)
        f.release()
        # The list holds the classes of the app's own dex files (framework
        # classes are not in it); the pattern is a substring filter.
        names = self.s.Java.enumerate_loaded_classes()
        self.assertTrue(names)
        some = names[0]
        self.assertIn(some, self.s.Java.enumerate_loaded_classes(some))
        self.assertEqual(self.s.Java.enumerate_loaded_classes("no.such.package.zz"), [])

    def test_java_hook_survives_exceptions_and_collections(self):
        # The original engine crashed the target here: File.exists() on a
        # missing file throws (and catches) an ErrnoException inside, and
        # ART could not walk the stack past the hook to build its trace.
        result = self.s.eval("""
            jh = { exists = 0, access_enter = 0, access_leave = 0 }
            hook("java/io/File", "exists", "()Z", { onEnter = function(a) jh.exists = jh.exists + 1 end })
            hook("libcore/io/Linux", "access", "(Ljava/lang/String;I)Z", {
                onEnter = function(a) jh.access_enter = jh.access_enter + 1 end,
                onLeave = function(r) jh.access_leave = jh.access_leave + 1 end })
            local File = Java.use("java/io/File")
            jh.real = File:new("(Ljava/lang/String;)V", "/proc/self/maps")
            jh.missing = File:new("(Ljava/lang/String;)V", "/no/such/file/zz")
            jh.rt = Java.use("java/lang/Runtime"):call("getRuntime", "()Ljava/lang/Runtime;")
        """)
        self.assertTrue(result.ok, result.error)
        try:
            for _ in range(15):
                self.assertEqual(self.s.rpc('{jh.real:call("exists", "()Z"), jh.missing:call("exists", "()Z")}'),
                                 [True, False])
                self.assertTrue(self.s.eval('jh.rt:call("gc", "()V")').ok)
            counts = self.s.rpc("{jh.exists, jh.access_enter, jh.access_leave}")
            self.assertGreaterEqual(counts[0], 30)
            # the native Linux.access() throws for the missing file: onLeave
            # is skipped for those calls and the exception reaches the Java
            # code that catches it
            self.assertGreater(counts[1], counts[2])
            self.assertGreater(counts[2], 0)
            listing = self.s.hooks()
            self.assertIn("java/io/File.exists()Z hits=", listing)
        finally:
            self.assertRegex(self.s.command("unhook all"), r"Removed \d+ hook")
        self.assertEqual(self.s.rpc('{jh.real:call("exists", "()Z"), jh.missing:call("exists", "()Z")}'), [True, False])
        self.assertEqual(self.s.OS.getpid(), self.s.pid)

    def test_python_callbacks_on_a_native_hook(self):
        events = []
        hook = self.s.hook("libc.so", "atoi", on_enter=events.append, on_leave=events.append)
        self.assertIsNotNone(hook.agent_id)
        atoi = self.s.native_function(self.export("atoi"), "int", ["pointer"])
        text = self.s.Memory.alloc_str("777")
        self.assertEqual(atoi(text), 777)
        self.s.poll(0.3)
        mine = [e for e in events if e.phase == "enter" and e.args and e.args[0] == text]
        self.assertTrue(mine, "no enter event for our call")
        self.assertTrue(any(e.phase == "leave" and e.retval == 777 for e in events))
        hook.remove()
        events.clear()
        atoi(text)
        self.s.poll(0.2)
        self.assertFalse(events, "callback fired after remove()")

    def test_capture_expressions_are_evaluated_during_the_call(self):
        events = []
        hook = self.s.hook("libc.so", "atoi", on_enter=events.append, on_leave=events.append,
                           capture={"text": "Memory.readStr(args[0])", "bad": "nosuchfn()"},
                           capture_leave={"doubled": "retval * 2"})
        atoi = self.s.native_function(self.export("atoi"), "int", ["pointer"])
        self.assertEqual(atoi("4321"), 4321)       # the string only lives for the call
        self.s.poll(0.3)
        hook.remove()
        enters = [e for e in events if e.phase == "enter" and e.data.get("text") == "4321"]
        self.assertTrue(enters, [e.data for e in events])
        self.assertNotIn("bad", enters[0].data)    # failing expression: key left out, hook unharmed
        self.assertTrue(any(e.phase == "leave" and e.data.get("doubled") == 8642 for e in events))

    def test_lua_source_hook_changes_the_result(self):
        hook = self.s.hook("libc.so", "getppid", on_leave="return 4242")
        getppid = self.s.native_function(self.export("getppid"), "int")
        self.assertEqual(getppid(), 4242)
        hook.remove()
        self.assertNotEqual(getppid(), 4242)

    def test_interceptor_replace_and_revert(self):
        abs_fn = self.s.native_function(self.export("abs"), "int", ["int"])
        self.assertEqual(abs_fn(-5), 5)
        self.s.Interceptor.replace("libc.so", "abs", 99)
        self.assertEqual(abs_fn(-5), 99)
        self.s.Interceptor.revert("libc.so", "abs")
        self.assertEqual(abs_fn(-5), 5)
        self.s.Interceptor.replace("libc.so", "abs", "function(args) return args[0] + 1000 end")
        self.assertEqual(abs_fn(5), 1005)
        self.s.Interceptor.revert("libc.so", "abs")

    def test_hook_errors(self):
        with self.assertRaises(renef.HookInstallError):
            self.s.hook("libc.so", "no_such_export_xyz", on_enter="print(1)")
        with self.assertRaises(renef.HookInstallError):
            self.s.hook("libc.so", "atoi")

    def test_send_events_and_listener(self):
        got = []
        self.s.on_event(got.append)
        self.assertTrue(self.s.eval('send({kind = "finding", n = 3})').ok)
        self.assertIn({"kind": "finding", "n": 3}, got)

        seen = []
        hook = self.s.hook("libc.so", "atol", on_enter=seen.append)
        self.s.start_listener(interval=0.1)
        atol = self.s.native_function(self.export("atol"), "long", ["pointer"])
        for _ in range(5):
            atol("5")
        deadline = time.time() + 5
        while len(seen) < 5 and time.time() < deadline:
            time.sleep(0.05)
        self.s.stop_listener()
        hook.remove()
        self.assertGreaterEqual(len(seen), 5)

    def test_syscall_trace(self):
        # bionic exports openat under the alias openat64 as well; the tracer
        # used to look for importers of the alias and found none.
        lines = []
        handler = lines.append
        self.s.on_output(handler)
        try:
            result = self.s.Syscall.trace("openat", "read")
            self.assertTrue(result.ok, result.error)
            self.assertIn("Tracing 2 syscall(s)", result.output)
            self.assertNotIn("Failed", result.output)
            active = {t["name"]: t["hooks"] for t in self.s.Syscall.active()}
            self.assertGreater(active.get("openat", 0), 0)
            self.assertGreater(active.get("read", 0), 0)
            deadline = time.time() + 6
            while time.time() < deadline and not any("read(" in ln for ln in lines):
                self.s.poll(0.3)
            self.assertTrue(any("read(" in ln for ln in lines), lines[-3:])
        finally:
            self.s.Syscall.stop()
            self.s._output_handlers.remove(handler)
        self.assertFalse(self.s.Syscall.active())
        # what handlers get is the target's output, not protocol lines
        text = "\n".join(lines)
        self.assertNotIn("__rpc_call", text)
        self.assertNotIn("\nOK\n", "\n" + text + "\n")
        self.assertEqual(self.s.OS.getpid(), self.s.pid)

    def test_hook_output_stays_out_of_command_replies(self):
        if PACKAGE != "com.renef.pentestapp":
            self.skipTest("needs the project test app")
        if os.environ.get("RENEF_NO_EVENT_CHANNEL"):
            self.skipTest("the server was started without the event channel")
        # integrityHeartbeat runs on a timer, well over a hundred times a
        # second: a hook that prints there used to end up in front of the
        # reply to whatever command came next.
        symbol = "Java_com_renef_pentestapp_NativeBridge_integrityHeartbeat"
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                if self.s.Module.find_export("libpentestapp.so", symbol):
                    break
            except renef.RenefError:
                pass
            time.sleep(0.2)
        lines = []
        handler = lines.append
        self.s.on_output(handler)
        hook = self.s.hook("libpentestapp.so", symbol, on_enter='print("[beat] call")')
        try:
            time.sleep(1.0)
            listing = ""
            for _ in range(20):
                listing = self.s.hooks()
                self.assertTrue(listing.startswith("Active hooks:"), listing[:80])
                self.assertNotIn("[beat]", listing)
            result = self.s.eval("print(6 * 7)")
            self.assertEqual((result.ok, result.output), (True, "42"))
            self.assertEqual(self.s.rpc("1 + 1"), 2)
            base = self.s.Module.find("libc.so")
            self.assertEqual(self.s.Memory.read(base, 4), b"\x7fELF")
            # calls are counted by the agent, whoever reads the output
            hits = [int(n) for n in re.findall(r"hits=(\d+)", listing)]
            self.assertTrue(hits and max(hits) > 20, listing)
            # and the output itself still arrives, through its own channel
            self.assertTrue(any("[beat] call" in text for text in lines))
        finally:
            hook.remove()
            self.s._output_handlers.remove(handler)
        self.assertEqual(self.s.OS.getpid(), self.s.pid)

    def test_hook_table_listing_is_complete(self):
        # The agent's listing used to overflow a 1KB buffer at ~40 hooks.
        exports = [e for e in self.s.Module.exports("libc.so") if e.name.startswith("is")][:60]
        installed = []
        for e in exports:
            try:
                installed.append(self.s.hook("libc.so", e.offset, on_enter="local x = 1"))
            except renef.HookInstallError:
                pass
        self.assertGreater(len(installed), 40)
        listing = self.s.hooks()
        self.assertEqual(listing.count("target="), sum(1 for ln in listing.split("\n") if "target=" in ln))
        self.assertIn("[%d]" % installed[-1].agent_id, listing)
        self.s.unhook_all()
        self.assertEqual(self.s.OS.getpid(), self.s.pid)


class CompatibilityApiDeviceTests(unittest.TestCase):
    @unittest.skipUnless(PACKAGE, "set RENEF_TEST_PACKAGE to run device tests")
    def test_old_api_end_to_end(self):
        r = renef.Renef(host=HOST, port=PORT)
        s = r.spawn(PACKAGE)
        self.assertIsNotNone(s)
        try:
            ok, out, err = s.eval("print(1 + 1)")
            self.assertEqual((ok, out, err), (True, "2", None))
            base = s.Module.find("libc.so")
            self.assertGreater(base, 0)
            self.assertEqual(s.Memory.read(base, 4), b"\x7fELF")
            self.assertIsNone(s.Memory.read(0x10, 4))            # sentinel, not an exception
            self.assertEqual(s.Module.list()[0]["name"], s.Module.list()[0].name)
            getpid_offset = next(e["offset"] for e in s.Module.exports("libc.so") if e["name"] == "getpid")
            self.assertEqual(s.hook("libc.so", getpid_offset, None, "return 31337"), 0)
            # Through NativeFunction: the agent's own getpid() (what
            # OS.getpid() uses) is deliberately not hooked.
            getpid = s.native_function(base + getpid_offset, "int")
            self.assertEqual(getpid(), 31337)
            self.assertEqual(s.OS.getpid(), s.pid)
            self.assertIn("Active hooks: 1", s.hooks())
            self.assertEqual(s.unhook(0), 0)
            self.assertEqual(getpid(), s.pid)
            self.assertEqual(s.hook("libc.so", 0x1, "print(1)"), -1)   # not a function start
            got = []
            self.assertEqual(s.watch_start(got.append), 0)
            s.eval('print("from watch")')
            s.watch_stop()
        finally:
            s.close()
            r.close()
        self.assertEqual(s.pid, -1)


class SpawnGateTests(DeviceTestCase):
    """--pause: hooks are registered before the app's own library exists."""

    pause = True

    def test_deferred_hook_catches_calls_after_resume(self):
        if PACKAGE != "com.renef.pentestapp":
            self.skipTest("needs the project test app")
        self.assertEqual(self.s.Module.find("libpentestapp.so"), 0)
        calls = []
        # Java_com_renef_pentestapp_NativeBridge_integrityHeartbeat
        hook = self.s.hook("libpentestapp.so", 0x4F0C, on_enter=calls.append)
        self.assertTrue(hook.deferred)
        # The gate must hold through any number of round trips: the app's
        # own library may not appear until resume() is called.
        for _ in range(5):
            self.s.rpc("1")
        time.sleep(1.0)
        self.s.poll(0.1)
        self.assertEqual(self.s.Module.find("libpentestapp.so"), 0, "target ran before resume()")
        self.assertEqual(calls, [])
        self.assertIn("Resumed", self.s.resume())
        deadline = time.time() + 10
        while len(calls) < 3 and time.time() < deadline:
            self.s.poll(0.3)
        self.assertGreaterEqual(len(calls), 3)
        self.assertGreater(self.s.Module.find("libpentestapp.so"), 0)


if __name__ == "__main__":
    unittest.main()
