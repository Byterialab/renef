---
title: Module API
layout: default
parent: Lua API Reference
nav_order: 1
---

# Module API

The `Module` global provides functions for inspecting loaded libraries and their symbols.

---

## `Module.find(lib_name)`

Find the base address of a loaded library.

```lua
local base = Module.find("libc.so")
if base then
    print(string.format("libc.so loaded at: 0x%x", base))
else
    print("libc.so not loaded")
end

-- Also works with partial names
local flutter = Module.find("libflutter.so")
```

**Parameters:**
- `lib_name` - Library name (can be partial, e.g., "libc.so" or "flutter")

**Returns:** Base address as integer, or `nil` if not found

---

## `Module.list()`

Get a string listing all loaded libraries.

```lua
local libs = Module.list()
print(libs)
```

**Returns:** Newline-separated string of all loaded `.so` files with their addresses

---

## `Module.exports(lib_name)`

Get exported symbols from a library's `.dynsym` section (dynamic symbol table).

```lua
local exports = Module.exports("libc.so")
if exports then
    for _, sym in ipairs(exports) do
        print(string.format("%s: 0x%x", sym.name, sym.offset))
    end
end

-- Find specific export
for _, sym in ipairs(Module.exports("libc.so")) do
    if sym.name == "malloc" then
        print(string.format("malloc offset: 0x%x", sym.offset))
        break
    end
end
```

**Parameters:**
- `lib_name` - Library name

**Returns:** Table of symbols, each with:
- `name` - Symbol name
- `offset` - Offset from library base

**Note:** This only returns publicly exported symbols. For internal/static symbols, use `Module.symbols()`.

---

## `Module.symbols(lib_name)`

Get all symbols from a library's `.symtab` section (full symbol table).

This includes internal/static symbols that are not exported via `.dynsym`. Useful for hooking internal functions in system binaries like `linker64`.

```lua
-- Get linker's internal symbols (includes do_dlopen, call_constructors, etc.)
local symbols = Module.symbols("linker64")
if symbols then
    print(string.format("Found %d symbols", #symbols))

    for _, sym in ipairs(symbols) do
        if sym.name:find("do_dlopen") then
            print(string.format("Found: %s at 0x%x", sym.name, sym.offset))
        end
    end
end
```

**Parameters:**
- `lib_name` - Library name

**Returns:** Table of symbols, each with:
- `name` - Symbol name
- `offset` - Offset from library base

**Returns `nil` if:**
- Library not found
- Binary is stripped (no `.symtab` section)
- Not a valid ELF file

---

## `Module.findExportByName(lib_name, pattern)`

Search a library's exports (`.dynsym`) for names matching a glob pattern —
`*` matches any run of characters, `?` matches exactly one character. A
pattern with no wildcard characters behaves as an exact-name match, so this
subsumes a plain lookup as well as a search over `Module.exports()`.

```lua
-- All pthread_* exports in libc.so
local matches = Module.findExportByName("libc.so", "pthread_*")
for _, sym in ipairs(matches) do
    print(string.format("%s -> 0x%x", sym.name, sym.offset))
end

-- Exact match (no wildcards) - equivalent to filtering Module.exports() yourself
local exact = Module.findExportByName("libc.so", "malloc")
if #exact > 0 then
    print(string.format("malloc offset: 0x%x", exact[1].offset))
end
```

**Parameters:**
- `lib_name` - Library name
- `pattern` - Glob pattern (`*` / `?` wildcards) or an exact export name

**Returns:** Table of matches (same shape as `Module.exports()`: `name` +
`offset`), possibly empty if the library was found but nothing matched, or
`nil` if the library itself could not be found/parsed.

---

## `Module.disassemble(addr, count)`

Disassemble `count` ARM64 instructions starting at `addr`, read directly out
of the agent's own address space (the agent already lives inside the target
process, so there is no separate "read memory first" step).

```lua
local liblog = Module.find("liblog.so")
local exports = Module.exports("liblog.so")
for _, exp in ipairs(exports) do
    if exp.name == "__android_log_print" then
        local insns = Module.disassemble(liblog + exp.offset, 8)
        for _, insn in ipairs(insns) do
            local flags = ""
            if insn.is_call then flags = flags .. " call" end
            if insn.is_jump then flags = flags .. " jump" end
            print(string.format("0x%x %s %s%s", insn.address, insn.mnemonic, insn.op_str, flags))
        end
        break
    end
end
```

**Parameters:**
- `addr` - Address to start disassembling from (must be non-zero)
- `count` - Number of instructions to decode (1-1024; larger values are
  capped at 1024)

**Returns:** 1-indexed table of instructions, each with:

| Field | Type | Description |
|---|---|---|
| `address` | integer | Instruction's own address |
| `size` | integer | Instruction size in bytes (always 4 on AArch64) |
| `mnemonic` | string | Capstone's mnemonic, e.g. `"mov"` |
| `op_str` | string | Capstone's formatted operand string, e.g. `"x0, x1, #4"` (not decomposed into structured operands) |
| `is_branch` | boolean | True for any control-flow-transferring instruction (jump, call, return, or PC-relative branch) |
| `is_call` | boolean | True for call instructions specifically |
| `is_jump` | boolean | True for jump instructions specifically |

**Raises a Lua error** (catchable with `pcall`) rather than crashing the
process if:
- `addr` is `0`, or `count` is `<= 0`
- the `[addr, addr + count*4)` range isn't entirely inside one readable
  `/proc/self/maps` region
- Capstone fails to decode anything at `addr`

```lua
local ok, err = pcall(function() return Module.disassemble(0xdead0000, 4) end)
if not ok then
    print("disassemble failed: " .. tostring(err))
end
```

---

## Difference: `exports()` vs `symbols()`

| Feature | `Module.exports()` | `Module.symbols()` |
|---------|-------------------|-------------------|
| ELF Section | `.dynsym` | `.symtab` |
| Symbol Types | Public/exported only | All symbols (including static/internal) |
| Availability | Always available | Only if not stripped |
| Use Case | Hook public APIs | Hook internal functions |
| Performance | Fast (smaller table) | Slower (larger table) |

**Example - Finding linker internals:**

```lua
-- exports() won't find internal linker functions
local exports = Module.exports("linker64")
-- do_dlopen NOT in exports (it's internal)

-- symbols() includes everything
local symbols = Module.symbols("linker64")
for _, s in ipairs(symbols) do
    if s.name:find("do_dlopen") then
        -- Found! __dl__Z9do_dlopenPKciPK17android_dlextinfoPKv
        print(s.name, string.format("0x%x", s.offset))
    end
end
```

---

## Examples

### Hook library load

```lua
-- Wait for a library to be loaded by hooking linker
local linker_syms = Module.symbols("linker64")
for _, sym in ipairs(linker_syms) do
    if sym.name:find("do_dlopen") then
        hook("linker64", sym.offset, {
            onEnter = function(args)
                local path = Memory.readString(args[0])
                if path then
                    print("[dlopen] " .. path)
                end
            end
        })
        break
    end
end
```

### Calculate absolute address

```lua
local base = Module.find("libtarget.so")
local exports = Module.exports("libtarget.so")

for _, sym in ipairs(exports) do
    if sym.name == "target_function" then
        local abs_addr = base + sym.offset
        print(string.format("Absolute address: 0x%x", abs_addr))
        break
    end
end
```

### Search for symbol by pattern

```lua
local symbols = Module.symbols("libflutter.so") or Module.exports("libflutter.so")

if symbols then
    for _, sym in ipairs(symbols) do
        if sym.name:find("ssl") or sym.name:find("verify") then
            print(string.format("%s: 0x%x", sym.name, sym.offset))
        end
    end
end
```

For a glob search over exports specifically (skipping `Module.symbols()`
when you don't need internal/static symbols), `Module.findExportByName()`
does the filtering for you:

```lua
for _, sym in ipairs(Module.findExportByName("libflutter.so", "*ssl*")) do
    print(string.format("%s: 0x%x", sym.name, sym.offset))
end
```

---

## Notes

1. **Stripped binaries**: Most release binaries are stripped and won't have `.symtab`. In this case, `Module.symbols()` returns `nil`. Fall back to `Module.exports()` or pattern scanning.

2. **Symbol names**: C++ symbols are mangled. Use pattern matching:
   ```lua
   if sym.name:find("do_dlopen") then  -- matches __dl__Z9do_dlopenPKc...
   ```

3. **Linker symbols**: Android's `linker64` is typically not stripped and contains useful internal symbols like `do_dlopen`, `call_constructors`, etc.

4. **Performance**: `Module.symbols()` can return thousands of symbols. Cache the result if calling multiple times.
