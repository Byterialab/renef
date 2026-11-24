-- Async/fire-and-forget hook mode test.
--
-- Part 1 (measurement - measure first, optimize second): hooks getpid() SYNCHRONOUSLY and getppid() ASYNCHRONOUSLY (two
-- different targets so the two installs don't collide), calls each N
-- times in a tight native loop via NativeFunction, and compares elapsed
-- time against an unhooked baseline. This is the actual justification
-- for building this feature at all.
--
-- Part 2 (positive): checking delivery can't happen inside THIS script at
-- all -- found live during this test's development: lua_engine_load_script()
-- (engine.c) holds lua_vm_lock() for the full duration of ONE script's
-- lua_pcall, so the consumer thread's own lua_vm_lock() call (needed to
-- actually run the queued onEnter callback) blocks until this entire
-- script returns, no matter how long a busy-wait loop spins in here.
-- "Eventual delivery" is only observable from a SEPARATE, later exec call
-- -- which is also the realistic usage pattern (install async hooks, let
-- the target run, check results later) -- so the delivery check is done
-- by the caller of this script (the test driver), not
-- inside it.
--
-- Part 3 (negative): floods the SAME async hook with far more calls than
-- the ring buffer holds (ASYNC_RING_SIZE=4096) in one tight loop with no
-- gap for the consumer thread to drain concurrently, forcing real drops
-- -- must not crash, must not hang, and logcat must show "[async] Ring
-- buffer full". Also checks that async=true+onLeave and async=true on a
-- Java hook both raise clean Lua errors instead of installing something
-- broken.

print("=== async hook test ===")

local base = Module.find("libc.so")
assert(base and base ~= 0, "libc.so not found")

local function resolve(name)
    for _, e in ipairs(Module.exports("libc.so")) do
        if e.name == name then return base + e.offset end
    end
    return nil
end

-- Development note: this originally hooked gettid(), not getppid() --
-- that crashed the target with a real stack overflow (SIGSEGV,
-- "stack pointer is not in a rw map"). Root cause: hook_logger()'s own
-- verbose_log() goes through __android_log_print(), and Android's
-- liblog internally calls gettid() to tag the log message's thread id
-- -- hooking gettid() means THAT call re-enters hook_logger(), which
-- logs again, which calls gettid() again... infinite recursion. Not an
-- async-specific bug (it would do the same thing to a plain synchronous
-- hook), but a real, general gotcha worth keeping in mind for ANY hook
-- target: don't hook a function the agent's own logging path depends
-- on. getppid() has no such relationship and is just as cheap/stable a
-- target for this measurement.
local a_getpid = assert(resolve("getpid"), "getpid not found")
local a_getppid = assert(resolve("getppid"), "getppid not found")
local getpid_fn = NativeFunction(a_getpid, "int")
local getppid_fn = NativeFunction(a_getppid, "int")

local N = 20000

-- ---- Baseline: no hooks at all ----
local t0 = os.clock()
for i = 1, N do getpid_fn() end
local baseline_s = os.clock() - t0
print(string.format("[*] baseline: %d unhooked getpid() calls in %.4fs (%.2f ns/call)",
      N, baseline_s, (baseline_s / N) * 1e9))

-- ---- Sync hook on getpid() ----
sync_calls = 0
hook("libc.so", a_getpid - base, {
    onEnter = function(args) sync_calls = sync_calls + 1 end
})

local t1 = os.clock()
for i = 1, N do getpid_fn() end
local sync_s = os.clock() - t1
print(string.format("[*] SYNC hook: %d calls in %.4fs (%.2f ns/call, overhead %.2f ns/call)",
      N, sync_s, (sync_s / N) * 1e9, ((sync_s - baseline_s) / N) * 1e9))
print("[*] sync onEnter observed " .. sync_calls .. " calls (synchronous: should equal " .. N .. ")")
assert(sync_calls == N, "sync hook should have observed every call synchronously")

-- ---- Async hook on getppid() (different target, avoids colliding with the sync hook above) ----
async_calls = 0
hook("libc.so", a_getppid - base, {
    async = true,
    onEnter = function(args) async_calls = async_calls + 1 end
})

local t2 = os.clock()
for i = 1, N do getppid_fn() end
local async_s = os.clock() - t2
print(string.format("[*] ASYNC hook: %d calls in %.4fs (%.2f ns/call, overhead %.2f ns/call)",
      N, async_s, (async_s / N) * 1e9, ((async_s - baseline_s) / N) * 1e9))
print(string.format("[*] async overhead vs sync overhead: %.1fx lower",
      math.max(sync_s - baseline_s, 1e-9) / math.max(async_s - baseline_s, 1e-9)))

print("[*] async_calls right after the loop (expected near 0 -- consumer thread " ..
      "can't run until THIS script returns, see Part 2 comment above): " .. async_calls)

-- Part 3a: flood the SAME async hook far beyond ring capacity (4096),
-- in one tight loop -- must not crash/hang, some drops are expected and
-- fine (that's the documented fire-and-forget contract).
local FLOOD_N = 50000
print("[*] NEGATIVE: flooding async hook with " .. FLOOD_N .. " calls (ring capacity is 4096)...")
for i = 1, FLOOD_N do getppid_fn() end
print("[OK] flood completed without crashing or hanging (check logcat for '[async] Ring buffer full')")
-- (no point busy-waiting here either -- same reason as Part 2, the
-- consumer thread can't run until this script returns the lock)

-- Part 3b: async=true + onLeave must be rejected cleanly.
local ok1, err1 = pcall(function()
    hook("libc.so", resolve("close") - base, {
        async = true,
        onEnter = function(args) end,
        onLeave = function(retval) end,
    })
end)
print("[OK] async+onLeave rejected cleanly (ok=" .. tostring(ok1) .. "): " .. tostring(err1))
assert(not ok1, "expected async+onLeave to raise a Lua error")

-- Part 3c: async=true on a Java hook must be rejected cleanly.
local ok2, err2 = pcall(function()
    hook("java/lang/StringBuilder", "toString", "()Ljava/lang/String;", {
        async = true,
        onEnter = function(args) end,
    })
end)
print("[OK] async on a Java hook rejected cleanly (ok=" .. tostring(ok2) .. "): " .. tostring(err2))
assert(not ok2, "expected async=true on a Java hook to raise a Lua error")

print("=== test done ===")
