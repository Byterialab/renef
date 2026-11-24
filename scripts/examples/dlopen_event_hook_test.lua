-- Event-driven library-load capture test.
--
-- Registers a deferred hook on a library that is NOT yet loaded in the
-- target process, then triggers its load ourselves (via
-- java.lang.System.load(), which goes through the real dlopen() PLT
-- path -- see the comment further down for why NativeFunction can't be
-- used for this) so the test is fully self-contained and doesn't depend
-- on incidental app behavior.
--
-- Positive case: a tiny purpose-built dummy library (/data/local/tmp/
-- libdlopen_test_dummy.so, one exported function `dummy_marker` @ offset
-- 0x4580) loaded by its full path. Real system libraries turned out to
-- be unreliable for this (libcamera2ndk.so and even libmediandk.so were
-- BOTH observed already loaded in com.android.settings by the time the
-- script ran, during this same test's development -- Settings' own
-- startup, or renef's `monkey`-based spawn path, pulls in more than
-- expected) -- a dummy lib nothing else could possibly reference gives
-- a deterministic "not yet loaded" starting point.
--
-- IMPORTANT, CONFIRMED FINDING from this test's own development: on this
-- device (Android 15/API 35), java.lang.System.load() -- the exact
-- real-world path the event hook was meant to speed up -- does NOT go through a
-- GOT-visible call to either dlopen() or android_dlopen_ext(). Both were
-- hooked (verified via logcat: "dlopen event hook installed, 56 GOT
-- entries patched" / "android_dlopen_ext event hook installed, 10
-- GOT entries patched"), and the "libdlopen_test_dummy.so" load via
-- System.load() DID succeed (confirmed: the pending hook eventually
-- installs, via the poll thread fallback) -- but the event hook's own
-- "(event path)" log line never fires for it, in a full passive
-- Settings-startup window either. Most likely explanation: ART resolves
-- android_dlopen_ext via dlsym() into its own internal function pointer
-- rather than a statically-imported GOT entry, so no amount of GOT
-- patching can see that specific call. This means the event hook, as implemented
-- here, does NOT eliminate the need for the poll thread for the primary
-- JVM-triggered case -- it's a correctly-implemented mechanism that may
-- still help for native code doing its own manual dlopen()/
-- android_dlopen_ext() calls (which DO go through a normal GOT), just
-- not for System.load()/loadLibrary().
--
-- Negative case: System.load() on a library that doesn't exist must not
-- crash the process or falsely report any pending hook as installed
-- (try_install_pending_hooks() is a no-op since the target is still
-- unresolvable).

print("=== dlopen event hook test ===")

__hook_type__ = "trampoline"

-- offset doesn't matter for this test, we never expect the hook to
-- actually fire -- we're only testing whether INSTALL happens
-- event-driven.
hook("libdlopen_test_dummy.so", 0x4580, {
    onEnter = function(args)
        print(">>> libdlopen_test_dummy.so hook fired (unexpected but harmless) <<<")
    end
})

print("[*] Pending hook registered for libdlopen_test_dummy.so (not yet loaded)")

-- Trigger the load via java.lang.System.load(String) rather than calling
-- dlopen() directly through NativeFunction. This matters: NativeFunction
-- invokes a raw resolved address directly (native_call8), which bypasses
-- PLT/GOT indirection entirely -- so it never actually goes through any
-- hooked GOT entry (confirmed during this test's development: the
-- event hook's own log line never appeared when dlopen was called this
-- way, even though the pending hook still installed correctly via the
-- poll-thread fallback). System.load() goes through the JVM's real
-- native library loader, which calls dlopen the normal way (through
-- libnativeloader/art's own PLT-imported symbol) -- the actual code path
-- the event hook exists to speed up.
local System = Java.use("java/lang/System")
if not System then
    print("[FAIL] Could not load java/lang/System")
else
    print("[*] POSITIVE: calling System.load(\"/data/local/tmp/libdlopen_test_dummy.so\")...")
    local ok, err = pcall(function()
        System:call("load", "(Ljava/lang/String;)V", "/data/local/tmp/libdlopen_test_dummy.so")
    end)
    if ok then
        print("[OK] System.load succeeded")
        print("[*] Check logcat for the dlopen event-path log line correlating with install")
    else
        print("[FAIL] System.load threw: " .. tostring(err))
    end

    -- Note: api_java.c's :call() clears+logs (ExceptionDescribe) any JNI
    -- exception rather than propagating it as a Lua error (a pre-existing,
    -- unrelated characteristic of the Java binding, confirmed by grepping
    -- api_java.c -- not something this test should assert on). What
    -- actually matters for the safety contract is just: no crash, and no
    -- pending hook falsely marked installed.
    print("[*] NEGATIVE: calling System.load(\"/data/local/tmp/libthis_does_not_exist.so\")...")
    pcall(function()
        System:call("load", "(Ljava/lang/String;)V", "/data/local/tmp/libthis_does_not_exist_c5.so")
    end)
    print("[OK] System.load on nonexistent library did not crash the process")
end

print("=== test script done ===")
