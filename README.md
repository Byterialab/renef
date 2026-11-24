<img src="assets/img/renef-logo-black.svg" alt="Renef Logo" width="180"/>

# Renef

**Dynamic Instrumentation Toolkit for Android ARM64**

[![Release](https://img.shields.io/github/v/release/Byterialab/renef?style=flat-square&color=blue)](https://github.com/Byterialab/renef/releases)
[![License](https://img.shields.io/github/license/Byterialab/renef?style=flat-square)](https://github.com/Byterialab/renef/blob/main/LICENSE)
[![Stars](https://img.shields.io/github/stars/Byterialab/renef?style=flat-square)](https://github.com/Byterialab/renef/stargazers)
[![Issues](https://img.shields.io/github/issues/Byterialab/renef?style=flat-square)](https://github.com/Byterialab/renef/issues)
[![Docs](https://img.shields.io/badge/docs-renef.io-green?style=flat-square)](https://renef.io)

[Documentation](https://renef.io) • [Installation](https://renef.io/docs/installation.html) • [Getting Started](https://renef.io/docs/getting-started.html) • [Examples](https://renef.io/docs/examples/)

---

## Overview

Renef is a dynamic instrumentation toolkit for Android ARM64 applications, focused primarily on native code analysis. It provides runtime manipulation capabilities through Lua scripting, allowing you to hook native functions, scan and patch memory, and analyze running processes.

## Key Features

- **ARM64 Function Hooking** - PLT/GOT and inline trampoline hooking via Capstone
- **Lua Scripting** - Frida-like API with Module, Memory, Hook, Thread
- **Process Injection** - memfd + shellcode injection (no ptrace required)
- **Memory Operations** - Scan, read, write, patch memory with wildcard patterns
- **Live Scripting** - Load multiple scripts at runtime with auto-watch
- **Interactive TUI** - Memory scanner with interactive interface
- **Java Hooks** - Hook Java methods via JNI

## Quick Start

```bash
# Build and deploy
make deploy

# Connect to device
./build/renef
```

Once connected:

```bash
# List installed apps
la
la~chrome                      # Filter by name

# Spawn or attach to process
spawn com.example.app          # Spawn new process
attach 12345                   # Attach by PID

# Load Lua scripts
l hook.lua                     # Load single script
l ssl.lua utils.lua -w         # Load multiple with auto-watch

# Memory operations
ms DEADBEEF                    # Scan for hex pattern
md 0x7f8a1c2b0 64 -d           # Dump with disassembly
msi C0035FD6                   # Interactive memory scanner

# Inline Lua execution
exec Module.list()
exec Memory.dump(Memory.search("secret", "libtarget.so"))
```

## Documentation

Full documentation is available at **[renef.io](https://renef.io)**

| Section | Description |
|---------|-------------|
| [Installation](https://renef.io/docs/installation.html) | Build and setup instructions |
| [Getting Started](https://renef.io/docs/getting-started.html) | First steps with Renef |
| [Command Reference](https://renef.io/docs/commands/) | CLI commands documentation |
| [Lua API](https://renef.io/docs/api/) | Scripting API reference |
| [Examples](https://renef.io/docs/examples/) | Real-world usage examples |

## Example: Flutter SSL Pinning Bypass

```lua
-- Flutter SSL Pinning Bypass for RENEF
-- Works for Flutter apps using BoringSSL

print("[*] Flutter SSL Pinning Bypass loading...")

-- Hardcoded offset for ssl_crypto_x509_session_verify_cert_chain
-- This offset may vary per Flutter version - update if needed
local SSL_VERIFY_OFFSET = 0x5dc730

local bypass_installed = false

-- Function to install SSL bypass on libflutter.so
local function install_ssl_bypass()
    if bypass_installed then
        return true
    end

    local flutter_base = Module.find("libflutter.so")
    if not flutter_base then
        return false
    end

    print(string.format("[+] libflutter.so found at: 0x%x", flutter_base))
    print(string.format("[+] Installing hook at offset: 0x%x", SSL_VERIFY_OFFSET))

    -- Install hook to bypass SSL verification
    hook("libflutter.so", SSL_VERIFY_OFFSET, {
        onEnter = function(args)
            print("[*] SSL verify called!")
        end,
        onLeave = function(retval)
            print("[*] SSL verify bypassing, returning 1")
            return 1  -- Return success (1 = verified)
        end
    })

    bypass_installed = true
    print("[+] SSL pinning bypass ACTIVE!")
    return true
end

-- Try to install bypass immediately if libflutter is already loaded
if install_ssl_bypass() then
    print("[+] Bypass installed on existing libflutter.so")
else
    print("[*] libflutter.so not loaded yet, hooking linker...")

    -- Hook android_dlopen_ext which is used to load libraries
    local linker_name = "linker64"
    local linker_base = Module.find(linker_name)

    if not linker_base then
        print("[-] linker64 not found, trying linker")
        linker_name = "linker"
        linker_base = Module.find(linker_name)
    end

    if not linker_base then
        print("[-] Cannot find linker!")
    else
        print(string.format("[+] %s found at: 0x%x", linker_name, linker_base))

        -- Get linker symbols
        local linker_symbols = Module.symbols(linker_name)
        if not linker_symbols then
            print("[-] Cannot get linker symbols (may be stripped)")
            print("[*] Trying exports instead...")
            linker_symbols = Module.exports(linker_name)
        end

        if linker_symbols then
            -- Find __dl__Z9do_dlopenPKciPK17android_dlextinfoPKv or similar
            local dlopen_offset = nil
            for _, sym in ipairs(linker_symbols) do
                if sym.name:find("do_dlopen") then
                    dlopen_offset = sym.offset
                    print(string.format("[+] Found %s at offset 0x%x", sym.name, sym.offset))
                    break
                end
            end

            if dlopen_offset then
                print(string.format("[+] Hooking %s + 0x%x", linker_name, dlopen_offset))

                hook(linker_name, dlopen_offset, {
                    onEnter = function(args)
                        -- args[0] is the library path
                        local path = Memory.readString(args[0])
                        if path and path:find("libflutter") then
                            print("[+] libflutter.so loading: " .. path)
                        end
                    end,
                    onLeave = function(retval)
                        -- After library loads, try to install bypass
                        if not bypass_installed then
                            install_ssl_bypass()
                        end
                    end
                })
                print("[+] Linker hook installed, waiting for libflutter.so...")
            else
                print("[-] do_dlopen not found in linker symbols")
            end
        else
            print("[-] Cannot get linker symbols/exports")
        end
    end
end

print("[+] Flutter SSL Bypass script loaded")

```

## Example: CTF Challenge (DereLabs 0x9)

```lua
local lib_name = "liba0x9.so"

if not Module.find(lib_name) then
    print("[WARN] Library not loaded yet")
    return
end

local exports = Module.exports(lib_name)
local func = exports[1]

hook(lib_name, func.offset, {
    onEnter = function(args)
        print("[CALLED] " .. func.name)
    end,
    onLeave = function(retval)
        print("Original retval: " .. retval)
        return 1337  -- Flag value
    end
})
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐
│   Renef CLI     │────▶│  Target Process  │
│   (Host)        │     │  (Android ARM64) │
└────────┬────────┘     └────────┬─────────┘
         │                       │
         │ TCP/USB               │ Injected
         │                       ▼
         │              ┌──────────────────┐
         └─────────────▶│   Renef Agent    │
                        │  + Lua Engine    │
                        │  + Hook Engine   │
                        └──────────────────┘
```

## Acknowledgements

This project was inspired by [Frida](https://frida.re) and [Radare2](https://rada.re). Special thanks to their developers for creating excellent tools that shaped the design of Renef.

## Contributing

Contributions are welcome! Please read the [Contributing Guide](https://renef.io/docs/contributing.html) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Made with dedication for the security research community
