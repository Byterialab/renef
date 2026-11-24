-- Java hook engine test suite. It uses framework classes, so any app works:
--   renef -s <package> -l scripts/examples/java_hook_engine_test.lua --headless --timeout 40
-- (Section 3 needs the project's own test app and is skipped elsewhere.)
-- Every line starts with [js]; the last one is "[js] RESULT pass=N fail=0".
local pass, fail = 0, 0
local function check(name, cond, detail)
    if cond then pass = pass + 1; print("[js] PASS " .. name)
    else fail = fail + 1; print("[js] FAIL " .. name .. (detail and (" :: " .. tostring(detail)) or "")) end
end
local function near(a, b) return type(a) == "number" and type(b) == "number" and math.abs(a - b) < 1e-4 end

-- 1. the original throws and catches inside (the old crash)
local File = Java.use("java/io/File")
local exists_hits = 0
hook("java/io/File", "exists", "()Z", { onEnter = function(args) exists_hits = exists_hits + 1 end })
local f1 = File:new("(Ljava/lang/String;)V", "/proc/self/maps")
local f2 = File:new("(Ljava/lang/String;)V", "/no/such/file/zz")
check("exists(real file)", f1:call("exists", "()Z") == true)
check("exists(missing file) survives the inner exception", f2:call("exists", "()Z") == false)
check("exists onEnter ran twice", exists_hits == 2, exists_hits)

-- 2. the original throws to its caller: the exception must arrive, not be swallowed
local Integer = Java.use("java/lang/Integer")
local pi_enter, pi_leave = 0, 0
hook("java/lang/Integer", "parseInt", "(Ljava/lang/String;)I", {
    onEnter = function(args) pi_enter = pi_enter + 1 end,
    onLeave = function(ret) pi_leave = pi_leave + 1 end })
check("parseInt('123')", Integer:call("parseInt", "(Ljava/lang/String;)I", "123") == 123)
local bad = Integer:call("parseInt", "(Ljava/lang/String;)I", "abc")
-- (the Lua Java API reports the exception to logcat and returns 0/nil for the call)
check("parseInt('abc') ended with the exception, not with a value", bad == nil or bad == 0, bad)
check("onLeave skipped for the call that threw", pi_enter == 2 and pi_leave == 1, pi_enter .. "/" .. pi_leave)
check("parseInt works again afterwards", Integer:call("parseInt", "(Ljava/lang/String;)I", "77") == 77)

-- 2b. an exception thrown by the original is delivered to MANAGED callers that catch it:
--     File.exists() -> UnixFileSystem.checkAccess() -> ... -> Linux.access() [native, hooked]
--     The native throws ErrnoException for a missing file; checkAccess() catches it.
local acc_enter, acc_leave = 0, 0
hook("libcore/io/Linux", "access", "(Ljava/lang/String;I)Z", {
    onEnter = function(args) acc_enter = acc_enter + 1 end,
    onLeave = function(ret) acc_leave = acc_leave + 1 end })
check("managed catch: exists(real) through hooked Linux.access", f1:call("exists", "()Z") == true)
check("managed catch: exists(missing) through hooked Linux.access", f2:call("exists", "()Z") == false)
check("Linux.access hook fired for both, onLeave only for the one that returned",
      acc_enter == 2 and acc_leave == 1, acc_enter .. "/" .. acc_leave)

-- 3. float / double arguments and results (static native, FastNative/CriticalNative ones too)
local okNB, NB = pcall(Java.use, "com/renef/pentestapp/NativeBridge")
if okNB and NB then
local wantF = NB:call("computeTrustScoreF", "(FFF)F", 1.5, 2.25, 3.0)
local wantD = NB:call("computeTrustScoreD", "(DDD)D", 1.5, 2.25, 3.0)
local fhits = 0
hook("com/renef/pentestapp/NativeBridge", "computeTrustScoreF", "(FFF)F", { onEnter = function(a) fhits = fhits + 1 end })
hook("com/renef/pentestapp/NativeBridge", "computeTrustScoreD", "(DDD)D", { onEnter = function(a) fhits = fhits + 1 end, onLeave = function(r) end })
check("float args/result through a hook", near(NB:call("computeTrustScoreF", "(FFF)F", 1.5, 2.25, 3.0), wantF), wantF)
check("double args/result through a hook", near(NB:call("computeTrustScoreD", "(DDD)D", 1.5, 2.25, 3.0), wantD), wantD)
check("float/double hooks fired", fhits == 2, fhits)
else
    print("[js] SKIP float/double through a hook (needs the test app's NativeBridge)")
end
local SM = Java.use("java/lang/StrictMath")
hook("java/lang/StrictMath", "pow", "(DD)D", { onEnter = function(a) end })
check("StrictMath.pow (critical native) hooked", near(SM:call("pow", "(DD)D", 2.0, 10.0), 1024.0))
local Dbl = Java.use("java/lang/Double")
hook("java/lang/Double", "compare", "(DD)I", { onLeave = function(r) end })
check("Double.compare(1.5, 2.5) == -1", Dbl:call("compare", "(DD)I", 1.5, 2.5) == -1)

-- 4. more arguments than registers: 7 ints, the last one on the stack
local LDT = Java.use("java/time/LocalDateTime")
local seen7 = nil
hook("java/time/LocalDateTime", "of", "(IIIIIII)Ljava/time/LocalDateTime;", {
    onEnter = function(args) seen7 = { args[1], args[2], args[3], args[4], args[5], args[6], args[7] } end })
local dt = LDT:call("of", "(IIIIIII)Ljava/time/LocalDateTime;", 2026, 11, 24, 12, 34, 56, 789)
local dts = dt and dt:call("toString", "()Ljava/lang/String;")
check("7 int args (one on the stack)", dts == "2026-11-24T12:34:56.000000789", dts)
check("onEnter saw the first 7 integers", seen7 and seen7[1] == 2026 and seen7[6] == 56 and seen7[7] == 789,
      seen7 and table.concat(seen7, ","))

-- 5. changing arguments and the return value
local M = Java.use("java/lang/Math")
hook("java/lang/Math", "addExact", "(II)I", { onEnter = function(args) args[1] = 40 end })
check("onEnter changes an int argument", M:call("addExact", "(II)I", 1, 2) == 42, M:call("addExact", "(II)I", 1, 2))
hook("java/lang/Math", "multiplyExact", "(II)I", { onLeave = function(ret) return 99 end })
check("onLeave replaces an int result", M:call("multiplyExact", "(II)I", 3, 4) == 99)
hook("java/lang/Math", "floorMod", "(II)I", { onEnter = function(args) args.skip = true end, onLeave = function(ret) return 7 end })
check("skip: original not run, onLeave supplies the result", M:call("floorMod", "(II)I", 10, 0) == 7)

-- 6. objects: read a String argument, replace a String result
local Str = Java.use("java/lang/String")
local tail_seen = nil
hook("java/lang/String", "concat", "(Ljava/lang/String;)Ljava/lang/String;", {
    onEnter = function(args) tail_seen = Jni.getStringUTF(args[2]) end })
local head = Str:new("(Ljava/lang/String;)V", "head-")
check("instance method with an object argument", head:call("concat", "(Ljava/lang/String;)Ljava/lang/String;", "tail") == "head-tail")
check("onEnter read the String argument", tail_seen == "tail", tail_seen)
local trimmed_seen = nil
hook("java/lang/String", "trim", "()Ljava/lang/String;", { onLeave = function(ret) trimmed_seen = ret.value; return JNI.string("replaced") end })
local padded = Str:new("(Ljava/lang/String;)V", "  x  ")
check("onLeave replaces a String result", padded:call("trim", "()Ljava/lang/String;") == "replaced")
check("onLeave sees the original String result as retval.value", trimmed_seen == "x", trimmed_seen)

-- 7. garbage collections while hooks are installed and being called
local Runtime = Java.use("java/lang/Runtime")
local rt = Runtime:call("getRuntime", "()Ljava/lang/Runtime;")
local ok_all = true
for i = 1, 40 do
    rt:call("gc", "()V")
    if f1:call("exists", "()Z") ~= true or f2:call("exists", "()Z") ~= false then ok_all = false end
    if Integer:call("parseInt", "(Ljava/lang/String;)I", tostring(i)) ~= i then ok_all = false end
    if head:call("concat", "(Ljava/lang/String;)Ljava/lang/String;", "t" .. i) ~= "head-t" .. i then ok_all = false end
    local junk = {}
    for k = 1, 200 do junk[k] = Str:new("(Ljava/lang/String;)V", "garbage-" .. i .. "-" .. k) end
end
check("40 forced GCs with hooked calls in between", ok_all)

print(string.format("[js] RESULT pass=%d fail=%d", pass, fail))
