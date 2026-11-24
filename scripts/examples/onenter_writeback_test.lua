-- onEnter arg write-back verification test.
--
-- Written to live-verify a specific claim before
-- building RootDetection.forceBooleanArgs() in
-- scripts/recipes/root_emulator_bypass.lua on top of it: that modifying
-- args[N] in a Java hook's onEnter callback actually changes what the
-- REAL method does with that parameter (not just what Lua-side bookkeeping
-- sees). renef-doc/docs/api/hook.md documents this
-- ("Arguments are modifiable: args[2] = newValue will change the
-- parameter passed to the original method") and the agent source
-- (src/agent/hook/java.c, around java_hook_on_enter's handling of the
-- `args` table / `saved_regs[i] = new_val`, and java_hook_call_original
-- which invokes the original with that same saved_regs array) backs that
-- up - but this script is the thing to actually RUN against a live
-- target to confirm it, not just read the source and trust it.
--
-- Mechanism under test: java.io.File.setReadable(boolean readable,
-- boolean ownerOnly) -> boolean, JNI signature "(ZZ)Z". We hook it and
-- force the `readable` parameter (args[2]) to false in onEnter, then call
-- it with readable=true. If the write-back is real, the method's ACTUAL
-- effect (a chmod on the underlying file) must end up as "not readable",
-- not "readable" - this is an externally observable side effect
-- (filesystem permission bits), not just a return value we could fake by
-- accident.
--
-- Usage:
--   renef> l scripts/examples/onenter_writeback_test.lua
--
-- The script prints PASS/FAIL/INCONCLUSIVE itself - no extra commands
-- needed, everything runs at load time.

print("=== onEnter arg write-back test (File.setReadable(Z,Z)) ===")

local pid = OS.getpid()
local path = "/data/local/tmp/renef_wb_test_" .. tostring(pid) .. ".txt"

local JFile = Java.use("java/io/File")
local f = JFile:new("(Ljava/lang/String;)V", path)
local created = f:call("createNewFile", "()Z")
print("File.createNewFile(" .. path .. ") -> " .. tostring(created))

-- Start from a known state: readable and writable for everyone, before
-- the hook is even installed.
f:call("setReadable", "(Z)Z", true)
f:call("setWritable", "(Z)Z", true)

local hook_fired = false

hook("java/io/File", "setReadable", "(ZZ)Z", {
    onEnter = function(args)
        print(string.format(
            "[onEnter] setReadable(readable=%d, ownerOnly=%d) called - forcing readable -> 0",
            args[2], args[3]))
        args[2] = 0 -- force "readable" to false, no matter what was asked
        hook_fired = true
    end
})

-- Caller explicitly asks for readable=true, ownerOnly=true.
local ok = f:call("setReadable", "(ZZ)Z", true, true)
local canRead = f:call("canRead", "()Z")

print("")
print("=== RESULT ===")
print("hook fired:                      " .. tostring(hook_fired))
print("setReadable(true, true) returned: " .. tostring(ok))
print("file.canRead() after the call:    " .. tostring(canRead))
print("on-disk path (inspect with `ls -l` as this process's uid): " .. path)

if hook_fired and canRead == false then
    print("")
    print("PASS: onEnter args[] write-back reached the real method.")
    print("      Caller asked for readable=true; the hook forced it to")
    print("      false in onEnter; the REAL chmod the method performed")
    print("      reflects the override, not the caller's original value.")
elseif hook_fired and canRead == true then
    print("")
    print("FAIL: onEnter args[] write-back did NOT affect real behavior.")
    print("      Caller asked readable=true, onEnter forced it to false,")
    print("      but canRead() is still true -- the original method ran")
    print("      with the UNMODIFIED argument. RootDetection.forceBooleanArgs()")
    print("      and the SplashFragment.a(ZZZ)-style pattern in")
    print("      scripts/recipes/root_emulator_bypass.lua would NOT work")
    print("      as designed if this is what you see live.")
else
    print("")
    print("INCONCLUSIVE: hook did not fire (check class/method/signature")
    print("resolved - e.g. ART version differences) or state unexpected.")
end

function writeback_test_path()
    return path
end
