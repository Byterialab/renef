-- A hook() on a library that will NEVER load
-- (typo'd name) must not spin the poll thread's CPU core forever. Before the
-- fix, deferred_poll_thread looped with sched_yield() and no sleep/deadline
-- -- pure busy-spin forever. After the fix it busy-spins briefly, backs off
-- exponentially, and gives up (LOGE "Timed out...") after
-- DEFERRED_TIMEOUT_SECONDS (45s). This script only installs the hook; check
-- `adb logcat | grep deferred` ~45-50s later for the timeout log line, and
-- confirm the process's CPU usage (`top`/`adb shell top`) is NOT pegged at
-- 100% on one core the whole time (that's the actual regression being
-- tested, not something Lua itself can observe).
print("=== deferred-hook timeout test ===")

local ok, err = pcall(function()
    hook("libthis_library_does_not_exist_xyz123.so", 0x100, {
        onEnter = function(args) end
    })
end)

-- This always returns true immediately (the library isn't loaded yet, so
-- it's queued as a pending hook and the real behavior -- busy-spin, then
-- backoff, then give up -- happens on deferred_poll_thread, not here).
print("[test] hook() call for nonexistent library returned: " .. tostring(ok) ..
      (err and (" / " .. tostring(err)) or ""))
print("[test] now check `adb logcat -s RENEF_AGENT:I` in ~45-50s for the")
print("     '[deferred] Timed out after 45s ... giving up' line, and confirm")
print("     CPU usage wasn't pegged the whole time.")
