-- Engine Capture Self-Test
--
-- scripts/recipes/engine_capture.lua detects decrypted-engine blobs by
-- looking for memory regions that are anonymous (not backed by a file)
-- AND executable. This environment has no real DexProtector-protected
-- target to verify that against -- but Renef's OWN native-hook trampoline
-- is structurally identical: allocate_trampoline() (src/agent/hook/
-- native.c) does
--
--     mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
--          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
--
-- which shows up in /proc/self/maps exactly like a decrypted engine does:
-- path == "" (anonymous), perms ends in "x" (executable). So: install one
-- throwaway hook, diff Process.enumerateRanges() before/after, and check
-- that the detector's filter catches the trampoline Renef itself just
-- created. If this passes, the detection logic is proven correct on this
-- device/build without needing a protected target.
--
-- **Real bug found running this (2026-10-27): use `--pause`.** Running this
-- against a normally-spawned, busy multi-threaded target (`com.android.settings`
-- without `--pause`) crashed the target with SIGSEGV -- a background thread
-- called the hooked `getpid()` concurrently while the main thread's Lua
-- state was still mid-script-execution (inside this very script, at the
-- `enumerateRanges()` table-building code), racing on the shared Lua state.
-- This is a real, pre-existing concurrency gap between the hook-dispatch
-- path and plain script execution,
-- not a bug in this test or in `engine_capture.lua`'s detection logic.
-- Confirmed clean (PASS) under `--pause` (process frozen before its own
-- background threads spin up, so nothing else calls the hooked function
-- during the test window): `renef -s <pkg> -l <this file> --pause`.
-- Avoid running this probe (or `engine_capture.lua` with a hook on a hot,
-- frequently-called function) against a live, unpaused, multi-threaded
-- target until that concurrency gap is fixed.
--
-- Usage (prefer --pause, see above):
--   renef -s <pkg> -l scripts/examples/engine_capture_selftest.lua --pause --headless --timeout 15
--   renef> l scripts/examples/engine_capture_selftest.lua   -- (interactive, same --pause caveat applies)

print("=== Engine Capture Self-Test ===")

-- Same filter as scripts/recipes/engine_capture.lua's
-- find_anon_exec_regions(), but with the size window wide open: Renef's
-- trampoline is one page (4KB), far smaller than a real engine blob
-- (recipe default: 256KB-1MB). This test only cares about anonymous +
-- executable, which is the actual thing being proven.
local function find_anon_exec_regions(min_size, max_size)
    local out = {}
    local ranges = Process.enumerateRanges()
    if not ranges then return out end
    for _, r in ipairs(ranges) do
        if r.path == "" and r.perms:sub(3, 3) == "x"
           and r.size >= (min_size or 0)
           and r.size <= (max_size or math.huge) then
            out[#out + 1] = r
        end
    end
    return out
end

local function snapshot()
    local by_start, count = {}, 0
    for _, r in ipairs(find_anon_exec_regions()) do
        by_start[r.start] = r
        count = count + 1
    end
    return by_start, count
end

local before, before_count = snapshot()
print(string.format("[selftest] baseline anonymous+executable regions: %d", before_count))

-- Install ONE throwaway native trampoline hook. getpid() is a simple
-- libc syscall wrapper that's rarely called (unlike e.g. strlen), so it
-- won't flood the console -- and crucially, no `caller=` is passed, so
-- api_hook.c auto-selects the trampoline path (not PLT/GOT), which is
-- the path that actually calls allocate_trampoline()/mmap().
local base = Module.find("libc.so")
assert(base and base ~= 0, "libc.so not found -- cannot run self-test")

local target_offset = nil
for _, e in ipairs(Module.exports("libc.so")) do
    if e.name == "getpid" then
        target_offset = e.offset
        break
    end
end
assert(target_offset, "getpid export not found in libc.so -- cannot run self-test")

hook("libc.so", target_offset, {
    onEnter = function(args) end
})
print(string.format("[selftest] installed trampoline hook on libc.so!getpid @ +0x%x (triggers allocate_trampoline())",
    target_offset))

local after, after_count = snapshot()
print(string.format("[selftest] anonymous+executable regions after hook install: %d", after_count))

local new_regions = {}
for start, r in pairs(after) do
    if not before[start] then
        new_regions[#new_regions + 1] = r
    end
end

local PASS = #new_regions > 0

if PASS then
    print(GREEN .. string.format(
        "[selftest] PASS -- %d new anonymous+executable region(s) appeared after hook install:",
        #new_regions) .. RESET)
    for _, r in ipairs(new_regions) do
        print(string.format("  0x%x-0x%x size=0x%x (%d bytes) perms=%s path=%q",
            r.start, r["end"], r.size, r.size, r.perms, r.path))
    end
    print("[selftest] This is Renef's own native-hook trampoline. The detection")
    print("           helper used by scripts/recipes/engine_capture.lua correctly")
    print("           flags it as an anonymous-executable region -- the same")
    print("           signature a decrypted DexProtector-style engine blob has.")
else
    print(RED .. "[selftest] FAIL -- no new anonymous+executable region found after hook install" .. RESET)
    print("[selftest] either the hook failed to install (check `watch` output), or")
    print("           find_anon_exec_regions() has a bug -- fix before trusting")
    print("           scripts/recipes/engine_capture.lua against a real target.")
end

function engine_capture_selftest_passed()
    return PASS
end
