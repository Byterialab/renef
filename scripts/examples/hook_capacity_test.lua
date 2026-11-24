-- MAX_HOOKS raised 32 -> 128, plus a specific Lua error
-- message once the table is genuinely full (instead of the old generic
-- "Failed to install native hook").
--
-- The boundary-check logic itself was verified precisely with a temporary
-- scratch build (MAX_HOOKS=3): 3 hooks installed cleanly, the 4th failed
-- with exactly "max native hooks reached (3/3) -- unhook something first,
-- or raise MAX_HOOKS..." -- not a crash, not the old generic message.
--
-- This script only does a small-scale real-build sanity check (the same
-- handful of libc functions root_frida_detection_bypass.lua already hooks
-- together successfully) to confirm the array resize itself didn't break
-- normal operation. It deliberately does NOT try to install dozens of
-- hooks at once: doing that in an earlier test run tripped a real,
-- SEPARATE, pre-existing issue (some trampoline/target address pairs
-- appear to go out of ARM64 branch-encoding range once several trampolines
-- are allocated in quick succession -- unrelated to the table size, and
-- since fixed by the absolute-jump fallback).
print("=== sanity check (small-scale, real MAX_HOOKS=128 build) ===")

local SAFE = {"access", "stat", "lstat", "open", "fopen", "strstr", "connect"}
local exports = Module.exports("libc.so")
local by_name = {}
for _, e in ipairs(exports) do by_name[e.name] = e.offset end

local installed = 0
for _, name in ipairs(SAFE) do
    local offset = by_name[name]
    if offset then
        local ok, err = pcall(function()
            hook("libc.so", offset, { onEnter = function(args) end })
        end)
        if ok then
            installed = installed + 1
        else
            print("[test] " .. name .. " failed: " .. tostring(err))
        end
    end
end

print(string.format("[test] installed=%d/%d known-safe hooks", installed, #SAFE))
if installed == #SAFE then
    print("[test] PASS -- array resize didn't break normal small-scale hook installation")
else
    print("[test] FAIL -- expected all " .. #SAFE .. " to install cleanly")
end
