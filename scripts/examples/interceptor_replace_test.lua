-- Interceptor.replace end-to-end test.
-- Replaces libc atoi() with "original + 1000", proving:
--   (1) the replacement runs for top-level (non-reentrant) calls
--   (2) the original is reachable from inside the callback (reentrancy guard)
--   (3) the returned value overrides the real result
local base = Module.find("libc.so")
assert(base and base ~= 0, "libc.so not found")

local function resolve(name)
    for _, e in ipairs(Module.exports("libc.so")) do
        if e.name == name then return base + e.offset end
    end
end
local atoi_addr = assert(resolve("atoi"), "atoi not found")
local atoi_off  = atoi_addr - base

-- Wrapper used to call the ORIGINAL from inside the replacement (reentrant).
local atoi_orig = NativeFunction(atoi_addr, "int", {"pointer"})

-- Baseline BEFORE the replace: plain original behaviour.
local before = atoi_orig("50")
print("before replace: atoi('50') = " .. before)
assert(before == 50, "baseline expected 50, got " .. before)

-- Install the replacement.
Interceptor.replace("libc.so", atoi_off, function(args)
    local r = atoi_orig(args[0])   -- reentrant call -> runs the ORIGINAL atoi
    return r + 1000
end)

-- Top-level calls now hit the replacement (non-reentrant).
local a = NativeFunction(atoi_addr, "int", {"pointer"})("50")
print("after replace: atoi('50') = " .. a)
assert(a == 1050, "expected 1050, got " .. a)

local b = NativeFunction(atoi_addr, "int", {"pointer"})("7")
print("after replace: atoi('7')  = " .. b)
assert(b == 1007, "expected 1007, got " .. b)

print(GREEN .. "Interceptor.replace OK -- replace + call-original work" .. RESET)
