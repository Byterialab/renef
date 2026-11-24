-- Memory.alloc / allocStr / protect / free smoke test
-- Run: ./renef -s <pkg> -l scripts/examples/memory_alloc_test.lua

-- 1) plain alloc + read/write
local p = Memory.alloc(64)
assert(p, "alloc failed")
print(GREEN .. "alloc: 0x" .. string.format("%x", p) .. RESET)
Memory.writeU32(p, 0xdeadbeef)
print("readU32 -> 0x" .. string.format("%x", Memory.readU32(p)))

-- 2) allocStr + read back
local s = Memory.allocStr("/system/bin/sh")
print(GREEN .. "allocStr: 0x" .. string.format("%x", s) .. RESET)
print("readStr -> " .. tostring(Memory.readStr(s)))

-- 3) make the first region executable, then restore
assert(Memory.protect(p, 64, "rwx"), "protect rwx failed")
print(GREEN .. "protect rwx ok" .. RESET)
assert(Memory.protect(p, 64, "rw-"), "protect rw- failed")

-- 4) free both (size looked up from the registry)
assert(Memory.free(p), "free p failed")
assert(Memory.free(s), "free s failed")
print(GREEN .. "free ok -- all Memory alloc APIs working" .. RESET)
