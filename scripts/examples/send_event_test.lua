-- send_event_test.lua
--
-- Exercises the new structured event channel: send(table)
-- JSON-encodes its argument and writes it to the agent<->host stream
-- tagged "[event] ", distinct from console.log()/print() plain-text lines.
--
-- Run with:
--   ./build/renef -s com.android.settings -l scripts/examples/send_event_test.lua
--   ./build/renef -s com.android.settings -l scripts/examples/send_event_test.lua --headless --timeout 10

console.log("send_event_test.lua starting")

send({type = "test_finding", value = 42, nested = {a = 1, b = "two"}})

send({type = "test_finding", value = 43, nested = {a = 2, b = "three"}, tags = {"alpha", "beta", "gamma"}})

send({type = "test_finding", value = 44, ok = true, missing = nil})

console.log("send_event_test.lua done")
