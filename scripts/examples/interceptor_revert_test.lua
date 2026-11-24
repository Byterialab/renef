-- Interceptor.revert(lib, offset).
-- Positive: install a replace hook that forces getpid() to return 999,
-- verify the override takes effect, revert it, verify getpid() goes back
-- to returning the REAL pid (proves the original bytes were correctly
-- restored, not just "hook stopped firing").
-- Negative: reverting an address nothing hooked, and double-revert of the
-- same hook, should raise a clean Lua error (caught here), not crash.
print("=== Interceptor.revert test ===")

local base = Module.find("libc.so")
assert(base, "libc.so not found")
local offset = nil
for _, e in ipairs(Module.exports("libc.so")) do
    if e.name == "getpid" then offset = e.offset; break end
end
assert(offset, "getpid not found")

local real_pid = Java.use("android/os/Process"):call("myPid", "()I")
print("[test] real pid (via Java, unaffected by the native replace below): " .. tostring(real_pid))

-- Install: force getpid() to return 999.
Interceptor.replace("libc.so", offset, function(args)
    return 999
end)

local NF = NativeFunction(base + offset, "int", {})
local overridden = NF()
print("[test] getpid() via NativeFunction while replaced: " .. tostring(overridden))

local positive_pass = (overridden == 999)
print("[test] positive (override active): " .. (positive_pass and "PASS" or "FAIL"))

-- Revert and confirm the REAL value comes back (proves original bytes
-- were restored, not just that our callback stopped being invoked).
Interceptor.revert("libc.so", offset)

local restored = NF()
print("[test] getpid() via NativeFunction after revert: " .. tostring(restored))

local revert_pass = (restored ~= 999 and restored == real_pid)
print("[test] positive (revert restored real behavior): " .. (revert_pass and "PASS" or "FAIL"))

-- Negative 1: double-revert should error cleanly, not crash.
local ok1, err1 = pcall(function() Interceptor.revert("libc.so", offset) end)
print("[test] negative (double-revert) ok=" .. tostring(ok1) .. " err=" .. tostring(err1))
local negative1_pass = (ok1 == false)
print("[test] negative-1 (double-revert raises, doesn't crash): " .. (negative1_pass and "PASS" or "FAIL"))

-- Negative 2: reverting an address nothing ever hooked.
local ok2, err2 = pcall(function() Interceptor.revert("libc.so", 0x1) end)
print("[test] negative (revert unhooked addr) ok=" .. tostring(ok2) .. " err=" .. tostring(err2))
local negative2_pass = (ok2 == false)
print("[test] negative-2 (revert-never-hooked raises, doesn't crash): " .. (negative2_pass and "PASS" or "FAIL"))

print(string.format("[test] SUMMARY: positive=%s revert=%s neg1=%s neg2=%s",
    tostring(positive_pass), tostring(revert_pass), tostring(negative1_pass), tostring(negative2_pass)))
