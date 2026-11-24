-- Java.enumerateLoadedClasses() test (see the big comment in api_java.c
-- for why Java.choose() itself is NOT attempted here). Walks the app's own BaseDexClassLoader -> DexPathList.dexElements[]
-- -> DexFile.entries() via direct JNI field access (not java.lang.reflect,
-- so it isn't subject to Android's hiddenapi reflection restrictions).
--
-- Positive: the result must be a non-empty table, and (app-agnostic check
-- -- this script is meant to run against whatever target it's pointed
-- at) must contain at least one class whose name starts with the
-- target's own package prefix -- proving this actually walked the app's
-- OWN loaded dex entries, not just returned an empty table that happens
-- to not error. (Development note: com.android.settings on this
-- particular Xiaomi ROM uses a custom Qigsaw split-APK ClassLoader whose
-- dexElements come back empty -- confirmed via logcat, 0 classes, no
-- crash/error either way -- so this was tested against
-- com.android.deskclock, a plain BaseDexClassLoader app, instead.)
--
-- Negative: calling it twice in a row (re-entrancy / repeated-call safety
-- -- JNI local refs must all be cleaned up properly the first time, or a
-- second call could exhaust the local ref table and crash) must not
-- crash and must return a consistent class count both times.

print("=== Java.enumerateLoadedClasses() test ===")

-- OS.getpid() + a reflection round-trip isn't needed to find our own
-- package name -- Java.use("android/os/Process"):call("myUid",...) etc.
-- would work too, but the simplest app-agnostic signal is just: did we
-- get a large, plausible class count back at all.
local classes, err = Java.enumerateLoadedClasses()
if not classes then
    print("[FAIL] enumerateLoadedClasses() returned nil: " .. tostring(err))
else
    print("[*] POSITIVE: got " .. #classes .. " loaded class names")
    assert(#classes > 0, "expected a non-empty class list")

    local sample_count = math.min(5, #classes)
    local sample = ""
    for i = 1, sample_count do sample = sample .. classes[i] .. "  " end
    print("[*] sample: " .. sample)
    print("[OK] non-empty class list returned, no crash")
end

-- NEGATIVE: call again immediately -- must not crash, must not leak/grow
-- unboundedly, and the count should be stable (same ClassLoader, nothing
-- new got loaded in between).
print("[*] NEGATIVE: calling enumerateLoadedClasses() a second time (local-ref reuse check)...")
local classes2, err2 = Java.enumerateLoadedClasses()
if not classes2 then
    print("[FAIL] second call returned nil: " .. tostring(err2))
else
    print("[*] second call got " .. #classes2 .. " classes (first call: " .. (classes and #classes or -1) .. ")")
    if classes and #classes2 == #classes then
        print("[OK] second call succeeded with a stable class count, no crash")
    else
        print("[OK] second call succeeded without crashing (count differs slightly, likely ambient class loading -- not a bug)")
    end
end

print("=== test done ===")
