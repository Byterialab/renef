---
title: Hook Management
layout: default
parent: Command Reference
nav_order: 5
---

# Hook Management

## `hooks`

List all active hooks in the target process.

```bash
hooks
```

**Output:**
```
Active hooks: 3
  [0] target=0x7b0a45af0c hits=820
  [1] target=0x7ddf753e60 hits=0
  [2] (removed)
```

Java method hooks are listed after the native ones, with ids of their own:

```
Java hooks: 2
  [j0] java/io/File.exists()Z hits=311
  [j1] com/example/Checker.isRooted()Z hits=0
```

`target` is the hooked address. `hits` counts the calls that reached the hook since it was installed; the agent counts them itself, so the number is exact whether or not anyone reads the hook's output. A removed hook keeps its slot (ids are not reused within a session).

## `hookn <library> <offset|symbol>`

"Hook native": hook one native function without writing a script. Every call
prints the first four argument registers and the return value - the quickest
way to find out whether a function is called at all, and with what.

```bash
hookn libnative.so 0x4f0c        # by offset
hookn libc.so getpid             # by exported symbol name
```

```
renef> hookn libnative.so 0x4f0c
Hooked libnative.so+0x4f0c (calls are shown by watch; hooks lists it, unhook removes it)
renef> watch
[hookn libnative.so+0x4f0c] tid=28643 x0=0xb400007d0200e610 x1=0x7a40026270 x2=0x7b04b35538 x3=0x4
[hookn libnative.so+0x4f0c] ret=0x1ed
```

The hook is an ordinary one: it appears in `hooks` with its call counter and is
removed with `unhook`. With an offset, a library that is not loaded yet is
fine - the hook is installed when it loads. When you need more than a log line
(other arguments, strings, changing values), generate a script with `hookgen`
or write a `hook()` call.

## `unhook <id|all>`

Remove hook(s) by ID or remove all hooks.

```bash
# Remove a native hook by ID
unhook 0

# Remove a Java hook by ID
unhook j0

# Remove all hooks, native and Java
unhook all
```

**Output:**
```
Hook 0 removed
Hook j0 removed
Removed 5 hook(s)
```

## `hookgen <args>`

Generate Lua hook template code.

```bash
# Generate hook for library + offset
hookgen libc.so 0x12340

# Generate hook for library + symbol
hookgen libc.so malloc

# Search symbol in common libraries
hookgen malloc
```

**Output:**
```lua
hook("libc.so", 0x12340, {
    onEnter = function(args)
        print("[+] libc.so+0x12340 called")
        print("    arg0: " .. string.format("0x%x", args[0]))
        print("    arg1: " .. string.format("0x%x", args[1]))
    end,
    onLeave = function(retval)
        print("[-] Returning: " .. string.format("0x%x", retval))
        return retval
    end
})
```
