#!/usr/bin/env python3
# A minimal, self-contained MCP server used ONLY to
# test src/librenef/mcp/mcp_client.cpp end-to-end, written from scratch
# (stdlib only, no installed MCP SDK) since downloading/running a real
# third-party reference MCP server wasn't available in this environment.
#
# Implements just enough of the MCP stdio transport (JSON-RPC 2.0,
# newline-delimited messages on stdin/stdout) to exercise initialize,
# tools/list, and tools/call: one trivial "echo" tool, plus an
# intentionally-failing "always_fails" tool for the client's error-path
# test.

import sys
import json


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = req.get("method")
        req_id = req.get("id")

        if method == "initialize":
            send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "renef-test-server", "version": "0.1.0"},
                    "capabilities": {"tools": {}},
                },
            })
        elif method == "notifications/initialized":
            pass  # notification, no response
        elif method == "tools/list":
            send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "echo",
                            "description": "Echoes back the given text",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"text": {"type": "string"}},
                                "required": ["text"],
                            },
                        },
                        {
                            "name": "always_fails",
                            "description": "Always returns an error, for client error-path testing",
                            "inputSchema": {"type": "object", "properties": {}},
                        },
                    ]
                },
            })
        elif method == "tools/call":
            params = req.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {})
            if name == "echo":
                send({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": "echo: " + str(args.get("text", ""))}],
                        "isError": False,
                    },
                })
            elif name == "always_fails":
                send({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": "intentional failure for testing"}],
                        "isError": True,
                    },
                })
            else:
                send({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Unknown tool: " + str(name)},
                })
        else:
            send({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": "Method not found: " + str(method)},
            })


if __name__ == "__main__":
    main()
