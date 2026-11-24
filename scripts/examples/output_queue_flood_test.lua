-- Live reproduction / regression test for the send_to_cli() lock-order
-- bug (see AGENTS.md task: "Socket write()'i g_lua_mutex disina al +
-- sinirli/throttled kuyruk ekle").
--
-- Mechanism: install a native trampoline hook on libc.so!getpid (chosen
-- because it is a trivial, side-effect-free function to call repeatedly),
-- then call the REAL hooked function from Lua via NativeFunction() in a
-- tight loop. Every call re-enters the hook's onEnter (under
-- g_lua_mutex, per native.c), which does console.log() with a sizeable
-- (32KB) payload -- so a handful of iterations is enough to overrun any
-- reasonable kernel socket buffer if nobody on the host side is
-- draining the agent<->server socket (no `-w`/`watch` running).
--
-- Pre-fix (send_to_cli() calling write() directly while g_lua_mutex is
-- held): once the kernel buffer fills, write() blocks -- and since the
-- Lua VM + hook dispatch is single-threaded under g_lua_mutex, this
-- whole loop (and hence this script, and hence anything else that needs
-- the Lua state) hangs until a reader drains the socket. "Flood loop
-- finished" will NOT print promptly.
--
-- Post-fix (send_to_cli() -> output_queue_push(), bounded ring buffer,
-- real write() done by a separate writer thread outside g_lua_mutex):
-- this loop finishes almost instantly regardless of whether the host is
-- reading, because the hook callback only ever does an in-memory
-- enqueue. The writer thread may itself block on the real write(), but
-- that no longer blocks the target app.
--
-- Usage:
--   renef -s com.android.settings -l scripts/examples/output_queue_flood_test.lua \
--         --pause --headless --timeout 20
--   (deliberately WITHOUT -w/watch, so nothing drains the agent socket)

print("=== output_queue flood/regression test ===")

local base = Module.find("libc.so")
assert(base and base ~= 0, "libc.so not found")

local target_offset = nil
for _, e in ipairs(Module.exports("libc.so")) do
    if e.name == "getpid" then
        target_offset = e.offset
        break
    end
end
assert(target_offset, "getpid export not found in libc.so")

local getpid_addr = base + target_offset
print(string.format("[flood] libc.so!getpid @ 0x%x", getpid_addr))

local PAYLOAD = string.rep("A", 32 * 1024) -- 32KB per hook call
local call_count = 0

hook("libc.so", target_offset, {
    onEnter = function(args)
        call_count = call_count + 1
        console.log(string.format("[flood #%d] ", call_count) .. PAYLOAD)
    end
})
print("[flood] hook installed on getpid")

local getpidFn = NativeFunction(getpid_addr)

local N = 40
print(string.format("[flood] starting loop of %d real getpid() calls (~%dKB total output)...", N, (N * 32)))

local t0 = OS.getpid() -- just to exercise something cheap before timing; real timing is wall-clock via loop completion marker
for i = 1, N do
    getpidFn()
end

print(string.format("[flood] FLOOD LOOP FINISHED. hook fired %d times.", call_count))
print("=== output_queue flood/regression test: DONE ===")
