---
title: Hook API
layout: default
parent: Lua API Reference
nav_order: 3
---

# Hook API

{: .note }
> Renef's hook engine writes to memory via `/proc/self/mem` (`pwrite`) instead of `mprotect`. This bypasses SELinux/seccomp restrictions, maintains W^X compliance, and leaves no permission changes visible in `/proc/self/maps`. Falls back to `mprotect` automatically if `/proc/self/mem` is unavailable.

## `hook(library, offset, callbacks)`

Hook a native function by library name and offset.

```lua
hook("libc.so", 0x12340, {
    onEnter = function(args)
        print("[+] malloc called")
        print(string.format("    size: 0x%x", args[0]))

        -- Modify argument
        args[0] = 0x200
    end,

    onLeave = function(retval)
        print(string.format("[-] malloc returning: 0x%x", retval))

        -- Modify return value
        return retval + 0x100
    end
})
```

**Parameters:**
- `library` - Library name (e.g., "libc.so")
- `offset` - Offset from library base (hex number)
- `callbacks` - Table with `onEnter` and/or `onLeave` functions, and optional `caller` field

**Callbacks table fields:**

| Field | Type | Description |
|-------|------|-------------|
| `onEnter` | function | Called before the original function |
| `onLeave` | function | Called after the original function returns |
| `caller` | string or table | Filter: only hook calls from this library (enables PLT/GOT hooking) |
| `async` | boolean | Fire-and-forget: run `onEnter` later on a worker thread instead of inside the call (see [Async hooks](#async-hooks)) |

```lua
-- Hook only calls to malloc from libnative.so (PLT/GOT mode)
hook("libc.so", malloc_offset, {
    caller = "libnative.so",
    onEnter = function(args)
        print(string.format("malloc(0x%x) from libnative.so", args[0]))
    end
})

-- Hook calls from multiple libraries
hook("libc.so", open_offset, {
    caller = {"libnative.so", "libutils.so"},
    onEnter = function(args) ... end
})
```

{: .note }
> Without `caller`, a **trampoline hook** is used (patches the target function directly). With `caller`, a **PLT/GOT hook** is used (patches the caller's GOT entries only).

**onEnter arguments:**
- `args` - Table with function arguments (args[0], args[1], ... args[7] for x0-x7)
- Arguments can be modified by assignment

**onLeave arguments:**
- `retval` - Return value from function (x0 register)
- Return a value to replace the original return value

### Hooks on libraries that are not loaded yet

If `library` is not loaded when `hook()` runs, the hook is registered as
pending and installed the moment the library is loaded: the agent watches
`dlopen`/`android_dlopen_ext`, so the hook is in place before the library's
own code gets to run. Together with `--pause` (the target is frozen until the
script has been delivered) this catches the very first call.

### Async hooks

A normal hook runs its Lua callback inside the hooked call: the calling thread
waits for the Lua VM and for your code. For a function that is called very
often and that you only want to observe, `async = true` takes that cost off
the caller:

```lua
hook("libc.so", malloc_offset, {
    async = true,
    onEnter = function(args)
        counts = (counts or 0) + 1
    end
})
```

The hooked thread only copies the eight argument registers into a ring buffer
and carries on; a worker thread calls `onEnter` afterwards. This has
consequences:

- **Observation only.** Changing `args` has no effect, and there is no
  `onLeave` (`hook()` raises an error if both are given).
- **The call has already happened** when the callback runs. `args` are the
  register values as they were; memory they point to may have changed or been
  freed in the meantime, so read strings and buffers with care.
- **Native hooks only**, not Java methods.
- The buffer holds 4096 calls. If the worker cannot keep up, further calls are
  not recorded (the count of dropped calls is logged to logcat) - the hooked
  function is never slowed down or blocked.

### Stack Trace in Hooks

Use `Thread.backtrace()` inside hook callbacks to see who called the hooked function:

```lua
hook("libc.so", fopen_offset, {
    onEnter = function(args)
        local path = Memory.readString(args[0])
        print("fopen(" .. tostring(path) .. ")")
        print(Thread.backtrace())
    end
})
```

---

## `Interceptor.replace(library, offset, callback [, caller])`

Replace a native function entirely. `callback(args)` runs **instead of** the
original, and its return value becomes the call's result. `args[0..7]` are the
incoming ARM64 argument registers `x0-x7`.

```lua
-- Force a check to always "succeed" (return 1)
Interceptor.replace("libnative.so", 0x1234, function(args)
    return 1
end)
```

To run the original from inside the replacement, wrap its address in
`NativeFunction` and call it. Calling the hooked address re-enters the hook, and
a thread-local reentrancy guard routes that call through the saved original
prologue — so you get the real function, not infinite recursion:

```lua
local base = Module.find("libnative.so")
local original = NativeFunction(base + 0x1234, "int", {"pointer", "int"})

Interceptor.replace("libnative.so", 0x1234, function(args)
    local real = original(args[0], args[1])   -- runs the ORIGINAL
    return real + 1                            -- tamper the result
end)
```

- The return value may be a number (returned in `x0`), or `nil`/`false` (= 0).
- A replace hook occupies a hook slot like any other hook (`MAX_HOOKS`).
- If the library is not loaded yet, the replace is deferred and installed the
  moment it loads (same as `hook`).
- Pass an optional `caller` library (string) to install via **PLT/GOT** for that
  caller's call sites instead of the default inline trampoline; `"*"` targets all
  loaded libraries.

---

## `Interceptor.revert(library, offset)`

Remove the hook that was installed at `(library, offset)` - by `hook()` or by
`Interceptor.replace()` - and restore the original code (or GOT entries). The
target keeps running; nothing has to be respawned.

```lua
Interceptor.replace("libnative.so", 0x1234, function(args) return 0 end)
-- ... later ...
Interceptor.revert("libnative.so", 0x1234)
```

It takes the same `(library, offset)` pair that installed the hook, so a script
never has to remember hook ids or resolve addresses. A Lua error is raised if
the library is not loaded or nothing is hooked at that address (for example a
second `revert` of the same hook); wrap it in `pcall` if that can happen.

From the CLI, `unhook <id>` and `unhook all` do the same by hook id.

---

## `NativeFunction(address [, retType [, argTypes]])`

Wrap a native function address in a Lua callable, so you can invoke native code
directly from a script (including a hooked function's original).

```lua
local base   = Module.find("libc.so")
local getpid = NativeFunction(base + off_getpid, "int")
print(getpid())                      -- current pid

local atoi = NativeFunction(base + off_atoi, "int", {"pointer"})
print(atoi("1234"))                  -- 1234
print(atoi(Memory.allocStr("567")))  -- 567
```

**Arguments** are marshalled into `x0-x7`:

| Lua type | Passed as |
|----------|-----------|
| number   | integer value (also used for pointers/addresses) |
| string   | pointer to its NUL-terminated bytes (valid for the call) |
| boolean  | `1` / `0` |
| nil      | `0` |

**`retType`** (default `"pointer"`) controls how the result is converted:
`"int"` / `"long"` / `"pointer"` → integer (from `x0`), `"bool"` → boolean,
`"string"` → Lua string (reads the returned `char*`), `"float"` / `"double"` →
number (from `d0`), `"void"` → no return value.

**`argTypes`** is only needed for floating-point arguments. A position declared
as `"float"` or `"double"` is passed in the next free floating-point register
(`d0-d7`) instead of the next integer register, as the ARM64 calling convention
requires; everything else is passed as an integer/pointer whatever its declared
type. The argument count is taken from the call itself.

```lua
local libm = Module.find("libm.so")
local sym  = Module.findExportByName("libm.so", "pow")[1]
local pow  = NativeFunction(libm + sym.offset, "double", {"double", "double"})
print(pow(2.0, 10.0))                -- 1024.0
```

{: .warning }
> **Limits:** up to 8 integer/pointer arguments (`x0-x7`) and up to 8
> floating-point arguments (`d0-d7`). More arguments than that (stack-passed)
> and struct arguments/returns are not supported.

{: .note }
> Many ARM64 libc functions (`strlen`, `strcmp`, `memcpy`...) are IFUNC symbols: the symbol table points at a resolver, not at the code that runs. `Module.exports()` and `Module.findExportByName()` return the resolved implementation, so the addresses they give can be hooked and called directly.

---

## `hook(class, method, signature, callbacks)`

Hook a Java method.

```lua
hook("com/example/MainActivity", "getSecret", "(Ljava/lang/String;)Ljava/lang/String;", {
    onEnter = function(args)
        print("[+] MainActivity.getSecret() called")
        print("    param1: " .. tostring(Jni.getStringUTF(args[2])))
    end,
    onLeave = function(retval)
        if retval.value then
            print("    returned: " .. retval.value)
        end
        return JNI.string("Modified!")      -- replace the result
    end
})
```

**Parameters:**
- `class` - Class name (`com/example/MainActivity`; dots are accepted too)
- `method` - Method name
- `signature` - JNI signature (e.g., "(Ljava/lang/String;)Ljava/lang/String;")
- `callbacks` - Table with `onEnter` and/or `onLeave` functions

Static and instance methods, constructors (`<init>`) and methods that are
already `native` can all be hooked. The hook shows up in `hooks` as `[jN]` with
its call counter and is removed with `unhook jN` or `unhook all`.

**`onEnter` — `args` table:**

| Key | Type | Description |
|-----|------|-------------|
| `args[0]` | integer | ArtMethod pointer (internal, not useful to scripts) |
| `args[1]` | integer | `this` (instance methods) or the first parameter (static methods) |
| `args[2..7]` | integer | The following parameters. Objects are raw references (pass them to `Jni.getStringUTF` etc.), integers and booleans their value |
| `args.class` | string | Class name |
| `args.method` | string | Method name |
| `args.signature` | string | JNI signature |
| `args.isStatic` | boolean | Whether method is static |
| `args.skip` | boolean | Set to `true` to skip calling the original method entirely |

Arguments are modifiable: `args[2] = newValue` changes the parameter passed to
the original method. `float` and `double` parameters are passed through to the
original correctly but do not appear in `args`; the numbered entries are the
other parameters, in order.

**`onLeave` — `retval` table:**

| Field | Type | Description |
|-------|------|-------------|
| `retval.raw` | integer | Return value: the number, or a raw reference for an object |
| `retval.value` | string or nil | Decoded string content (only for methods returning `String`) |

**Modifying return values (`onLeave`):**

| Return from onLeave | Effect |
|---|---|
| `nil` (or no return) | Original return value unchanged |
| integer | The new value (e.g., `return 1` for true, `return 0` for false) |
| `JNI.string("...")` | A new Java String |
| `JNI.int(N)`, `JNI.long(N)`, `JNI.boolean(b)` | The value, typed |
| `Jni.newStringUTF("...")` | Reference to a new Java String |

**`args.skip` — skip the original method:**

Setting `args.skip = true` in `onEnter` prevents the original method from being
called. `onLeave` still runs and supplies the result (zero / `null` if it
returns nothing). Use it for checks that signal failure by throwing:

```lua
-- Hook the class that implements the check, not the interface
hook("com/example/net/PinningTrustManager", "checkServerTrusted",
    "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V", {
    onEnter = function(args)
        args.skip = true            -- the original (and its exception) never runs
        print("[*] checkServerTrusted bypassed")
    end
})
```

### How it behaves

- **Exceptions pass through.** If the original method throws, the exception
  reaches the caller exactly as without the hook. `onLeave` is not called for
  that call (there is no return value).
- **Interface and abstract methods cannot be hooked** - they have no code.
  `hook()` raises an error that says so; hook the method of the implementing
  class instead (`Java.enumerateLoadedClasses()` helps to find it).
- **One hook per method.** A second `hook()` on the same method is refused
  until the first is removed.
- **Callbacks do not wait forever.** If the Lua VM is busy for more than half
  a second (a long-running script, a slow callback), the call goes ahead
  without its callback and a `callback(s) skipped` line is reported, so a
  hooked method on the UI thread cannot freeze the app.
- **Calls that the compiler inlined are not seen.** ART may copy the body of a
  small method into its callers; those callers then never enter the method.
  The sign is a hook that installs fine but whose `hits=` in `hooks` stays at
  0, or grows slower than expected. Hook a larger method up or down the call
  chain instead.

{: .note }
> **Android versions.** On Android 12 and later a hooked method is routed through a real JNI native method that ART knows how to walk past, so exceptions and garbage collections during a hooked call are safe. This was verified on Android 16. Android 10 and 11 still use the original mechanism, where a hooked method that throws (or a collection at the wrong moment) can crash the app.

---

## Jni Namespace

The `Jni` global provides JNI helper functions for working with Java objects in hooks.

### `Jni.newStringUTF(str)`

Create a new Java String from a Lua string. Returns a raw object pointer that can be used as a return value in Java hooks.

```lua
local jstr = Jni.newStringUTF("Hello from Lua!")
return jstr  -- Use in onLeave to replace return value
```

**Parameters:**
- `str` - Lua string to convert

**Returns:** Raw object pointer (integer) for the new Java String

### `Jni.getStringUTF(ref)`

Get the content of a Java String as a Lua string.

```lua
local content = Jni.getStringUTF(args[1])
if content then
    print("String content: " .. content)
end
```

**Parameters:**
- `ref` - Raw object pointer or JNI reference to a String

**Returns:** Lua string with the content, or `nil` if invalid

### `Jni.getStringLength(ref)`

Get the length of a Java String.

```lua
local len = Jni.getStringLength(args[1])
print("String length: " .. len)
```

**Parameters:**
- `ref` - Raw object pointer or JNI reference to a String

**Returns:** Integer length of the string

### `Jni.deleteGlobalRef(ref)`

Delete a global JNI reference to free memory.

```lua
Jni.deleteGlobalRef(globalRef)
```

**Parameters:**
- `ref` - Global reference to delete

---

## JNI Signature Reference

Common JNI type signatures:

| Java Type | JNI Signature |
|-----------|---------------|
| `void` | `V` |
| `boolean` | `Z` |
| `byte` | `B` |
| `char` | `C` |
| `short` | `S` |
| `int` | `I` |
| `long` | `J` |
| `float` | `F` |
| `double` | `D` |
| `String` | `Ljava/lang/String;` |
| `Object` | `Ljava/lang/Object;` |
| `int[]` | `[I` |
| `String[]` | `[Ljava/lang/String;` |

**Method signature format:** `(ParameterTypes)ReturnType`

**Examples:**
```lua
-- void method()
"()V"

-- int method(int x, int y)
"(II)I"

-- String method(String s)
"(Ljava/lang/String;)Ljava/lang/String;"

-- void method(int[] arr, boolean flag)
"([IZ)V"

-- Object method(String name, int count)
"(Ljava/lang/String;I)Ljava/lang/Object;"
```
