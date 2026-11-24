---
title: Console API
layout: default
parent: Lua API Reference
nav_order: 5
---

# Console API

## `console.log(message)`

Print message to console (same as `print()`).

```lua
console.log("Hello from Lua")
```

## `print(...)`

Standard Lua print, outputs to renef client.

```lua
print("Value:", 42)
print(string.format("Hex: 0x%x", 255))
```

## `send(table)`

Emit a structured, JSON-serializable event — a **separate channel** from
`print()`/`console.log()`'s human-readable text output.

```lua
send({type = "key_found", algo = "AES", key = key_hex})
-- Output line: [event] {"type":"key_found","algo":"AES","key":"..."}

send({"item1", "item2", "item3"})
-- Output line: [event] ["item1","item2","item3"]
```

**Why a separate channel:** `print()`/`console.log()` output is meant for a
human watching the console. `send()` is meant for a pipeline/CI step (or,
in principle, a future automated consumer) that wants to parse out specific
findings without scraping free-form log text. A consumer recovers events by
reading the output stream line by line and checking for the `"[event] "`
prefix — everything after it on that line is one compact JSON value.

**Parameters:**
- `table` - A Lua table. Tables that are plain sequences (keys `1..#t` with
  no gaps) encode as a JSON array; anything else encodes as a JSON object.
  Nested tables, strings, numbers, and booleans are all supported. Functions,
  userdata, and threads encode as `null` rather than raising an error.
  Non-string table keys are stringified rather than dropped.

**Returns:** Nothing.

**Known limitation:** if a script's own `print()`/`console.log()` call
happens to produce text starting with `"[event] "`, a consumer would
misclassify that line as a structured event. Both channels are plain text
over the same stream — avoid starting manual log lines with that exact
prefix.

**Depth limit:** nested tables deeper than 16 levels encode as `null` at the
cutoff point (guards against accidentally sending a cyclic/pathological
table) — `send()` payloads are meant to be small, mostly-flat findings, not
deep object graphs.

```lua
-- Use send() for a finding a pipeline should parse...
send({type = "root_detection_bypassed", method = "RootBeer.isRooted"})

-- ...and print() for everything else (progress, debug output, etc.)
print("[+] Hooked RootBeer.isRooted")
```

## Global Color Codes

Available color codes for terminal output:

```lua
print(RED .. "Error!" .. RESET)
print(GREEN .. "Success!" .. RESET)
print(YELLOW .. "Warning" .. RESET)
print(BLUE .. "Info" .. RESET)
print(CYAN .. "Debug" .. RESET)
print(MAGENTA .. "Trace" .. RESET)
print(WHITE .. "Normal" .. RESET)
```

Available colors:
- `RESET` - Reset to default
- `RED`, `GREEN`, `YELLOW`, `BLUE`, `MAGENTA`, `CYAN`, `WHITE`
