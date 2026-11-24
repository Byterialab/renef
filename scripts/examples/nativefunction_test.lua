-- NativeFunction smoke test. Uses non-IFUNC libc symbols (many ARM64 string
-- funcs like strlen are IFUNCs whose export offset points at the resolver).
local base = Module.find("libc.so")
assert(base and base ~= 0, "libc.so not found")

local function resolve(name)
    for _, e in ipairs(Module.exports("libc.so")) do
        if e.name == name then return base + e.offset end
    end
    return nil
end

-- (1) getpid(): no args, integer return
local a_getpid = assert(resolve("getpid"), "getpid not found")
local getpid = NativeFunction(a_getpid, "int")
local pid = getpid()
print("getpid() = " .. tostring(pid))
assert(pid == OS.getpid(), "getpid mismatch: " .. pid .. " vs " .. OS.getpid())

-- (2) atoi("1234"): string arg (marshalled as char*), integer return
local a_atoi = assert(resolve("atoi"), "atoi not found")
local atoi = NativeFunction(a_atoi, "int", {"pointer"})
local n = atoi("1234")
print("atoi('1234') = " .. tostring(n))
assert(n == 1234, "expected 1234, got " .. tostring(n))

-- (3) atoi with an allocStr pointer
local p = Memory.allocStr("567")
local n2 = atoi(p)
print("atoi(allocStr '567') = " .. tostring(n2))
assert(n2 == 567, "expected 567, got " .. tostring(n2))
Memory.free(p)

print(GREEN .. "NativeFunction OK -- native calls from Lua work" .. RESET)
