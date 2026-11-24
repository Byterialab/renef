---
title: Troubleshooting
layout: default
nav_order: 10
---

# Troubleshooting

## Server Won't Start

```bash
# Check if port is already in use
adb shell "lsof | grep renef_server"

# Kill existing instance
adb shell "killall renef_server"

# Check permissions
adb shell "chmod +x /data/local/tmp/renef_server"
```

## Injection Fails

```bash
# Check if process is running
adb shell "ps | grep <package>"

# Check SELinux status (may need permissive mode)
adb shell "getenforce"

# Try with root
adb root
```

## Port Forwarding Issues

```bash
# Remove existing forward
adb forward --remove tcp:1907

# Re-setup forwarding
adb forward tcp:1907 localabstract:com.android.internal.os.RuntimeInit

# Verify forwarding
adb forward --list
```

### adb cannot reach the server

On some devices (seen on a Samsung with SELinux enforcing) `adbd` is not
allowed to connect to the server's abstract socket: the client reports that
the server closed the connection, and `adb logcat` shows
`failed to connect to socket 'localabstract:...' (Permission denied)`. Run the
server on a local TCP port instead and manage the forward yourself:

```bash
adb shell 'su -c "/data/local/tmp/renef_server --transport TCP --port 1907 &"'
adb forward tcp:1907 tcp:1907
RENEF_ADB_FORWARD=off renef -s com.example.app
```

The server listens on `127.0.0.1` only.

### Two devices at once

`adb forward` binds one host port to one device. Give the second device its
own port:

```bash
adb -s <serial2> forward tcp:1908 localabstract:com.android.internal.os.RuntimeInit
RENEF_PORT=1908 RENEF_ADB_FORWARD=off renef -d <serial2> -s com.example.app
```

In Python: `renef.connect(port=1908)`.

## Hooks Not Triggering

1. Verify the offset is correct:
```lua
local exports = Module.exports("libc.so")
for i, exp in ipairs(exports) do
    if exp.name == "malloc" then
        print(string.format("malloc offset: 0x%x", exp.offset))
    end
end
```

2. Check if hook type matches:
```bash
# Try PLT/GOT hooking instead of trampoline
spawn com.example.app --hook=pltgot
```

3. Verify library is loaded:
```lua
local base = Module.find("libapp.so")
if not base then
    print("Library not loaded yet")
end
```

### Hook output does not appear

Hook output is not printed in the middle of other commands. It waits on the
server until you run `watch` (the CLI says `(N lines of hook output waiting)`
under the reply of whatever you ran). `hooks` shows a `hits=` counter per hook,
which tells you whether the hook is being reached at all - if it stays at 0 the
function is not called (or you hooked the wrong address), if it grows your
callback runs and the output is waiting for `watch`.

## Memory Access Violations

```lua
-- Always check addresses before reading
local addr = 0x12345678
local success, err = pcall(function()
    local data = Memory.read(addr, 16)
    print("Data: " .. data)
end)

if not success then
    print("Memory read failed: " .. err)
end
```

## Client Connection Issues

```bash
# Check server is running
adb shell "ps | grep renef_server"

# Check port forwarding
adb forward --list

# Test connection
telnet localhost 1907

# Check firewall (macOS)
sudo pfctl -d  # Disable firewall temporarily
```

## Script Execution Errors

```lua
-- Use pcall for error handling
local success, err = pcall(function()
    -- Your code here
    hook("libc.so", 0x12340, {
        onEnter = function(args)
            print("Called")
        end
    })
end)

if not success then
    print(RED .. "Error: " .. err .. RESET)
end
```

## Build Errors

```bash
# Missing NDK
export NDK=$HOME/Library/Android/sdk/ndk/26.3.11579264

# Capstone not found
make setup

# Lua not found
make setup-lua

# Clean and rebuild
make clean
make all
```

---

# Advanced Topics

## Custom Hook Types

Renef supports two hooking methods:

**Trampoline Hooking (Default)**
- Inline hooking at function entry
- Modifies first instructions to jump to hook
- Works for any function
- Slight performance overhead

**PLT/GOT Hooking**
- Modifies Procedure Linkage Table / Global Offset Table
- Intercepts dynamic library calls
- Faster than trampoline
- Only works for imported functions

```bash
# Use trampoline (default)
spawn com.example.app

# Use PLT/GOT
spawn com.example.app --hook=pltgot
```

## Session Keys

Renef uses session keys for security. Each injection generates a 32-character authentication key that must be prepended to agent commands. This is handled automatically by the client.

## Filter Syntax

Many commands support filtering with the `~` operator:

```bash
# List apps containing "google"
la~google

# List specific package
la~com.example.app
```

The filter is sent to the agent, which applies it to the output.

## Background Execution

```bash
# Start server in background on device
adb shell "nohup /data/local/tmp/renef_server > /dev/null 2>&1 &"

# Check if running
adb shell "ps | grep renef_server"
```

## Multiple Devices

```bash
# List devices
adb devices

# Specify device
./build/renef -d emulator-5554 -s com.example.app
```

---

# Performance Considerations

## Hook Overhead

- Trampoline hooks add ~10-50ns per call
- PLT/GOT hooks add ~5-10ns per call
- Lua execution in hooks adds additional overhead
- Keep hook logic minimal for high-frequency functions

## Memory Scanning

- `Memory.scan()` scans all readable .so regions
- Can be slow for large processes
- Use specific patterns to reduce matches
- Results are limited to 1000 matches by default

## Script Loading

- Scripts are executed in the target process context
- Large scripts may cause temporary freeze
- Use `l script1.lua script2.lua` to load multiple files efficiently
- Auto-watch mode (`-w`) starts monitoring immediately after loading

---

# API Comparison with Frida

Renef aims for API compatibility with Frida where possible:

| Frida | Renef | Notes |
|-------|-------|-------|
| `Interceptor.attach()` | `hook()` | Similar API, different syntax |
| `Module.load()` | `Module.find()` | Returns base address |
| `Module.enumerateExports()` | `Module.exports()` | Returns table |
| `Memory.scan()` | `Memory.scan()` | Similar functionality |
| `Memory.readByteArray()` | `Memory.read()` | Returns string |
| `Memory.writeByteArray()` | `Memory.patch()` | Handles mprotect |
| `Java.use()` | `hook(class, method, sig)` | Direct JNI hooking |
| `send()` | `print()` | Output to client |

## Environment Switches

For narrowing down a problem or for an unusual setup; none of them is needed in normal use.

| Variable | Where | Effect |
|----------|-------|--------|
| `RENEF_NO_CODE_CAVE=1` | `renef_server` | Inject with the older method (several instructions of `malloc` are overwritten) instead of the code-cave method. Try it if injection fails on a device. |
| `RENEF_NO_EVENT_CHANNEL=1` | `renef_server` | Do not open the separate connection for hook output; it is mixed into command replies as in older versions. |
| `RENEF_DEVICE_ID` | host | Set by the CLI from `-d <device>`; the ADB device used for port forwarding. |
| `RENEF_PORT=<port>` | host | Host port the CLI forwards and connects to (default `1907`). |
| `RENEF_ADB_FORWARD=off` | host | The CLI leaves `adb forward` alone; set the forward yourself. |

```bash
adb shell 'su -c "RENEF_NO_CODE_CAVE=1 /data/local/tmp/renef_server"'
```
