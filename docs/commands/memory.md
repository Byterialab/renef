---
title: Memory Operations
layout: default
parent: Command Reference
nav_order: 4
---

# Memory Operations (CLI)

## `ms <pattern>`

Scan memory for hex pattern or string in all readable .so regions.

```bash
# Scan for hex bytes
ms DEADBEEF

# Scan for ARM64 ret instruction
ms C0035FD6

# Scan for string (as hex)
ms 4A617661    # "Java"
```

**Output:**
```
Found 2 match(es):
------------------------------------------------------------
[1] /system/lib64/libc.so + 0x1a2b0 (addr: 0x7f8a1c2b0)
    Hex:   01 02 03 [DE AD BE EF] 90 90 90 90
    ASCII: ....[....]....
[2] /data/app/com.example/lib/arm64/libapp.so + 0x5f80 (addr: 0x7f9b3f80)
    Hex:   FF FF [DE AD BE EF] 00 00
    ASCII: ..[....]..
------------------------------------------------------------
```

---

A scan covers the readable memory of the process and takes several seconds on
a large app (about ten with 400 loaded modules). Device memory that cannot be
read safely (GPU driver mappings, for example) is skipped. The
pattern must be complete pairs of hex digits; anything else is rejected with
`Invalid pattern`.

## `msj <pattern>`

The same scan with a machine-readable result, one JSON line:

```json
{"success":true,"count":2,"results":[{"library":"libc.so","offset":4096,"address":530242908160,"hex":"...","ascii":"..."}]}
```

`address` and `offset` are decimal. This is what the TUI and other tools use;
at the prompt `ms` is easier to read.

## `msi <pattern>`

Interactive memory scan with TUI. Allows selecting results and performing actions.

```bash
msi DEADBEEF
```

**Interactive Interface:**
```
Memory Scan Results (2 matches)
────────────────────────────────────────
[1] libc.so + 0x1a2b0
[2] libapp.so + 0x5f80
────────────────────────────────────────
Actions: [d]ump [p]atch [w]atch [c]opy [q]uit
```

**Actions:**
- `d` - Dump memory at selected address
- `p` - Patch bytes at selected address
- `w` - Watch memory for changes
- `c` - Copy address to clipboard
- `q` - Quit interactive mode

---

## `md <address> <size> [-d]`

Dump memory at address. Use `-d` flag to disassemble as ARM64 code.

```bash
# Hex dump (256 bytes)
md 0x7f8a1c2b0 256

# Disassemble as ARM64
md 0x7f8a1c2b0 64 -d
```

`renef_server` reads the bytes from `/proc/<pid>/mem` itself, so the result does
not depend on the agent: it stays correct while hooks are printing, and it also
covers execute-only code (`--x` mappings) that the target cannot read. Where
that file cannot be opened (a server not running as root), the agent is asked
instead.

**Hex Dump Output:**
```
Memory at 0x7f8a1c2b0 (256 bytes):
0x7f8a1c2b0:  01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10  |................|
0x7f8a1c2c0:  de ad be ef 90 90 90 90 00 00 00 00 ff ff ff ff  |................|
0x7f8a1c2d0:  fd 7b bf a9 fd 03 00 91 00 00 00 94 fd 7b c1 a8  |.{...........{..|
```

**Disassembly Output:**
```
Memory at 0x7f8a1c2b0 (64 bytes):
0x7f8a1c2b0:  fd 7b bf a9    stp x29, x30, [sp, #-0x10]!
0x7f8a1c2b4:  fd 03 00 91    mov x29, sp
0x7f8a1c2b8:  00 00 00 94    bl #0x7f8a1d000
0x7f8a1c2bc:  fd 7b c1 a8    ldp x29, x30, [sp], #0x10
0x7f8a1c2c0:  c0 03 5f d6    ret
```

---

## `sec <library>`

List the ELF sections of a loaded library, as found in its file on the device.

```bash
sec libnative.so
```

```
Sections in /data/app/.../lib/arm64/libnative.so (23 total):
Name                 Addr             Size             Type
------------------------------------------------------------
.dynsym              0x00000000000308 0x00000000000288 DYNSYM
.dynstr              0x00000000000648 0x0000000000028a STRTAB
.text                0x00000000004e08 0x00000000000554 PROGBITS
...
```

`Addr` is the section's address inside the library; add the library's base
(`Module.find`) for the address in the running process.

---

## `memdump <pid> --maps` / `memdump <pid> <start>-<end>`

Read the memory of **any** process without injecting into it. `renef_server`
reads `/proc/<pid>/maps` and `/proc/<pid>/mem` itself: no agent, no spawn or
attach, no `ptrace`, and nothing in the target is modified. Useful for a first
look at a protected app, or for a process you do not want to touch.

```bash
# What is mapped where
memdump 12345 --maps

# Read a range (hex addresses, at most 4 MiB per request)
memdump 12345 7b0a45a000-7b0a45b000
```

The reply is text, so it survives any transport: a manifest line, one
`SEG OK start=0x... len=N hex=...` line per readable piece (`SEG ERR ...` for
pages that cannot be read), and a summary with a checksum of the bytes.

The same thing from the host, written straight to a file:

```bash
./build/renef --memdump-pid 12345 --memdump-maps
./build/renef --memdump-pid 12345 --memdump-range 7b0a45a000-7b0a45b000 --out dump.bin
```

`--out` writes the bytes to `dump.bin` and a manifest next to it; without it
the output goes to the terminal. `--memdump-port <port>` talks to a server on a
port other than the default 1907.

{: .note }
> "No injection" is not the same as "undetectable": the read is still subject to SELinux and to what the kernel lets a root process see of the target.

---

## Lua Script Integration

For more advanced memory operations, use the `exec` command with Lua scripts:

```bash
# String search with wildcards
exec r = Memory.search("native") Memory.dump(r)

# Pattern search (ARM64)
exec r = Memory.search("FD 7B ?? A9") Memory.dump(r)

# Search in specific library
exec r = Memory.search("C0 03 5F D6", "libc.so") Memory.dump(r)

# Read memory
exec print(string.format("0x%X", Memory.readU32(0x7f8a1c2b0)))

# Write memory
exec Memory.writeU32(0x7f8a1c2b0, 0xD503201F)
```

See [Lua Memory API](../api/memory.md) for full documentation.

---

## Common ARM64 Patterns

| Pattern | Description |
|---------|-------------|
| `FD7B??A9` | Function prologue (`stp x29, x30, [sp, #?]`) |
| `C0035FD6` | Return instruction (`ret`) |
| `1F2003D5` | NOP instruction |
| `??????94` | Branch with link (`bl`) |
| `??????97` | Branch with link (`bl`, different range) |
| `00000014` | Unconditional branch (`b`) |

---

## Tips

1. **Hex vs String**: The CLI `ms` command expects hex. For string search, convert to hex first or use Lua:
   ```bash
   exec Memory.dump(Memory.search("mystring"))
   ```

2. **Large Searches**: Pattern search is limited to 50MB to prevent timeout. Use library filter for large apps:
   ```bash
   exec Memory.dump(Memory.search("pattern", "libtarget.so"))
   ```

3. **Address Format**: All addresses are displayed and expected in hexadecimal with `0x` prefix.

4. **Wildcards**: Only available via Lua API. Use `??` for any byte:
   ```bash
   exec Memory.dump(Memory.search("FD 7B ?? A9"))
   ```
