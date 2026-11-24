---
title: Process API
layout: default
parent: Lua API Reference
nav_order: 11
---

# Process API

The `Process` global provides whole-process introspection: the memory map and the
set of live threads. It complements `Module` (which is scoped to a single
library) and `OS.listdir("/proc/self/task")` (which returns raw directory
entry names instead of typed thread IDs).

---

## `Process.enumerateRanges()`

List every mapped region of the current process by parsing `/proc/self/maps`.

Unlike `Memory.search`'s internal scan, this is **not** filtered to
readable/non-device regions — it reports the full address space, including
anonymous mappings, device-backed mappings, and ART/Dalvik-internal regions,
so scripts get a complete picture.

```lua
local ranges = Process.enumerateRanges()
print(string.format("%d mapped regions", #ranges))

for _, r in ipairs(ranges) do
    if r.path:find("libc.so") then
        print(string.format("0x%x-0x%x (%s) %s", r.start, r["end"], r.perms, r.path))
    end
end
```

**Returns:** Array table, each entry containing:

| Field   | Type    | Description                                              |
|---------|---------|-----------------------------------------------------------|
| `start` | integer | Region start address                                      |
| `end`   | integer | Region end address                                         |
| `size`  | integer | `end - start`, in bytes                                    |
| `perms` | string  | Raw `/proc/self/maps` permission string, e.g. `"r-xp"`     |
| `path`  | string  | Backing file path, or `""` for anonymous mappings          |

Returns `nil` if `/proc/self/maps` could not be opened.

{: .note }
> `end` is a Lua keyword-adjacent identifier (not reserved, but easy to
> mistype as a field access). Index it with `r["end"]` rather than `r.end`
> inside an expression if your Lua version's parser complains — `r.end` is
> valid Lua, but some editors/linters flag it.

---

## `Process.enumerateThreads()`

List the thread IDs of the current process by reading `/proc/self/task`.

This is a typed equivalent of `OS.listdir("/proc/self/task")`: that call
returns directory entry names as strings (you'd need `tonumber()` on each
one yourself), while `Process.enumerateThreads()` returns ready-to-use
integers.

```lua
local tids = Process.enumerateThreads()
print(string.format("%d threads", #tids))

for _, tid in ipairs(tids) do
    print("  tid: " .. tid)
end
```

**Returns:** Array of integers (thread IDs), or `nil` if `/proc/self/task`
could not be opened.

---

## Examples

### Find which mapped library covers an address

```lua
local function module_for(addr)
    for _, r in ipairs(Process.enumerateRanges()) do
        if addr >= r.start and addr < r["end"] then
            return r
        end
    end
    return nil
end

local r = module_for(some_pc)
if r then
    print(string.format("0x%x is in %s (+0x%x)", some_pc, r.path, some_pc - r.start))
end
```

### Count executable regions

```lua
local exec_count = 0
for _, r in ipairs(Process.enumerateRanges()) do
    if r.perms:sub(3, 3) == "x" then
        exec_count = exec_count + 1
    end
end
print(string.format("%d executable regions", exec_count))
```

### Signal every thread except the current one

```lua
local pid = OS.getpid()
for _, tid in ipairs(Process.enumerateThreads()) do
    if tid ~= Thread.id() then
        OS.tgkill(pid, tid, 0)  -- liveness probe; swap 0 for a real signal
    end
end
```
