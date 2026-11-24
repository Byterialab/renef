-- Minimal hang repro for the send_to_cli() lock-order bug. Installs a
-- native hook on libc.so!getpid with a large (32KB) per-call payload,
-- then returns immediately. The interesting behavior happens AFTER this
-- script finishes: com.android.settings calls getpid() extremely often
-- on its own (logging macros, Binder, etc. -- NOT something this script
-- needs to drive), so the hook keeps firing continuously in the
-- background with no action from the CLI. If nothing is draining the
-- agent<->server socket (no `-w`/`watch`, no --headless auto-drain),
-- pre-fix this will eventually block whichever thread's write() is in
-- flight while it holds g_lua_mutex -- freezing dispatch of every other
-- hooked call (and anything else needing the Lua state) in the process.
print("=== output_queue hang repro: installing hook ===")

local target_offset = nil
for _, e in ipairs(Module.exports("libc.so")) do
    if e.name == "getpid" then
        target_offset = e.offset
        break
    end
end
assert(target_offset, "getpid export not found in libc.so")

local PAYLOAD = string.rep("A", 32 * 1024) -- 32KB per hook call
local call_count = 0

hook("libc.so", target_offset, {
    onEnter = function(args)
        call_count = call_count + 1
        console.log(string.format("[hang-repro #%d] ", call_count) .. PAYLOAD)
    end
})

print("=== output_queue hang repro: hook installed, script returning now ===")
