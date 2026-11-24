---
title: Utility Commands
layout: default
parent: Command Reference
nav_order: 7
---

# Utility Commands

## `help`

Show available commands.

## `q`

Exit renef client.

## `clear`

Clear the terminal screen.

## `color <theme>=<COLOR>`

Set terminal color theme.

```bash
# List current theme
color

# Set prompt color
color prompt=CYAN

# Set response color
color response=GREEN
```

## `verbose [on|off]`

Switch the agent's debug output for the current session. With it on, every
command also returns the agent's `[DBG]` lines (script compilation, hook
installation steps, symbol resolution), which helps when a hook does not
install or a script fails silently. Without an argument it prints the current
state.

```bash
renef> verbose on
verbose: enabled
renef> exec print(1)
[DBG] Loading Lua script (8 bytes)
[DBG] Script compiled successfully, executing...
[DBG] Script executed successfully
1
renef> verbose off
```

The command-line flag `-v` does the same from the start and additionally shows
the agent's logcat output while spawning and attaching.

## `ping`

Answers `pong`. Checks that `renef_server` is reachable without touching any
target; clients also use it to find out whether the server supports framed
requests.

## `mcp connect|list-tools|call|disconnect`

A small [Model Context Protocol](https://modelcontextprotocol.io) client inside
the CLI: connect to an MCP server that runs as a local process (stdio
transport) and call its tools from the Renef prompt - for example a
disassembler's MCP server, to look something up without leaving the session.

```bash
mcp connect python3 /path/to/server.py     # start a server by command
mcp connect binja                          # ... or by a name from the config file
mcp list-tools
mcp call rename_function {"address":"0x4f0c","name":"heartbeat"}
mcp disconnect
```

Names are looked up in `~/.renef/mcp_servers.json`:

```json
{ "servers": { "binja": "python3 /opt/binja-mcp/server.py" } }
```

This command runs on the host only; nothing is sent to the device. Only stdio
servers are supported (no HTTP transport).
