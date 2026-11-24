---
title: Getting Started
layout: default
nav_order: 5
---

# Getting Started

## Quick Start

```bash
# 1. Start server on Android device
adb shell /data/local/tmp/renef_server

# 2. Run client on host
./build/renef

# 3. Spawn an app
renef> spawn com.example.app

# 4. List installed apps (with filter)
renef> la~example

# 5. Execute Lua code
renef> print("Hello from " .. _VERSION)

# 6. Load and execute a script
renef> l scripts/hook.lua

# 7. Load multiple scripts with auto-watch
renef> l script1.lua script2.lua -w
```

## Command-line Options

```
Usage: ./build/renef [options]

Options:
  -s, --spawn <package>    Spawn app by package name
  -a, --attach <pid>       Attach to running process by PID
  -g, --gadget <pid>       Connect to embedded gadget agent (non-root)
  -d, --device <id>        Specify ADB device ID (for multiple devices)
  -l, --load <script>      Load Lua script after connection
  -w, --watch              Enable auto-watch mode after loading script
  -p, --pause              Freeze app after spawn until a script is loaded (spawn gate)
  -v, --verbose            Show logcat debug output from agent
  -m, --mode <mode>        Interface mode: v/view opens the terminal UI (default: CLI)
  --json                   Machine-readable output (no colors, script results as JSON)
  --timeout <seconds>      Auto-detach and exit after N seconds
  --headless               No interactive shell: load -l script (if any) and wait
  --memdump-pid <pid>      Passive memory read of <pid> (no injection); with
                           --memdump-maps or --memdump-range <s>-<e>, and --out <file>
  --local                  Local mode: connect via UDS directly (for Termux/on-device)
  --hook <type>            Hook engine type: trampoline (default) or pltgot
  -h, --help               Show help message
```

### Option Details

| Option | Description |
|--------|-------------|
| `-s <package>` | Spawns a new process from the given package name. The app will be started and payload injected automatically. |
| `-a <pid>` | Attaches to an already running process by its PID. Use `adb shell pidof <package>` to find the PID. |
| `-g <pid>` | Connects to an embedded gadget agent (v0.3.0+). Use this for non-rooted devices with patched APKs. See [Gadget Mode]({% link docs/gadget-mode.md %}). |
| `-d <device>` | Specifies which ADB device to use when multiple devices are connected. Use `adb devices` to list available devices. |
| `-l <script>` | Loads and executes a Lua script immediately after successful injection. Can be combined with `-s` or `-a`. |
| `-w` | Enables auto-watch mode. After loading the script, Renef monitors hook output in real-time. Press Ctrl+C to exit watch mode. |
| `-p, --pause` | Spawn gate: the app is frozen before any of its code runs and resumes when the first script has been delivered, so hooks are in place for the very first call. Uses `ptrace` (see [Process Management]({% link docs/commands/process.md %})). |
| `-m v`, `--mode view` | Starts the terminal UI instead of the prompt: tabs for hooks and modules, memory scan results, live hook output, logs and a console. Tab switches between them, Ctrl+C quits. |
| `--json` | For scripts that drive the CLI: output is printed without color codes, and the `-l` script (and every `exec`) is answered with one JSON line - `{"ok":..., "pid":..., "timed_out":..., "output":"..."}` - instead of free text. Usually combined with `--headless`. |
| `--headless` | Skips the interactive shell. Renef spawns/attaches, loads the `-l` script, relays hook output to stdout and waits - until `--timeout` expires, or Ctrl+C. For CI jobs and pipelines. |
| `--timeout <seconds>` | Detaches and exits after the given time. Mostly used with `--headless`. |
| `--memdump-pid <pid>` | Reads another process's memory through `renef_server` without injecting anything. See [`memdump`]({% link docs/commands/memory.md %}). |
| `-v, --verbose` | Enables verbose mode. Shows agent debug output from logcat during `spawn`, `attach`, and script loading (`l`). Useful for troubleshooting injection and hook issues. |
| `--local` | Connects via Unix Domain Socket directly, skipping ADB and TCP. For running on the device itself (Termux/ADB shell). Works with SELinux enforcing. See [Local Mode]({% link docs/local-mode.md %}). |
| `--hook <type>` | Selects the hooking engine. `trampoline` (default) uses inline hooks, `pltgot` hooks via PLT/GOT table. |

### Examples

```bash
# Interactive mode (no auto-spawn/attach)
./build/renef

# Spawn app and enter interactive mode
./build/renef -s com.example.app

# Spawn app and load script
./build/renef -s com.example.app -l hook.lua

# Attach to running process by PID
./build/renef -a 12345

# Attach with PLT/GOT hooking and load script
./build/renef -a 12345 --hook pltgot -l script.lua

# Use specific device (emulator)
./build/renef -d emulator-5554 -s com.example.app

# Use specific device (physical device)
./build/renef -d XXXXXXXX -s com.example.app -l bypass.lua

# Spawn, load script, and auto-watch hook output
./build/renef -s com.example.app -l hook.lua -w

# Multiple scripts can be loaded inside REPL after connection
renef> l script1.lua script2.lua -w

# Gadget mode (non-rooted device with patched APK)
./build/renef -g 12345 -l script.lua

# Spawn with verbose output (shows agent debug logs)
./build/renef -s com.example.app -v

# Load script with verbose to debug hook issues
./build/renef -s com.example.app -l hook.lua -v
```

### Hook Types

| Type | Description | Use Case |
|------|-------------|----------|
| `trampoline` | Inline hooking via Capstone disassembly | General purpose, works on any address |
| `pltgot` | PLT/GOT table hooking | Faster, but only works on imported functions |
