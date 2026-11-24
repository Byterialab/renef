#pragma once

// Minimal MCP (Model Context Protocol) client.
//
// Stdio only, no HTTP+SSE transport -- stdio is the transport every local MCP
// server (the kind this is meant to connect to: Binary Ninja MCP,
// ida-pro-mcp, r2mcp, GhidraMCP) actually uses in practice, and it's
// enough to validate the pattern end-to-end before spending effort on
// HTTP+SSE for a remote server nothing in this project talks to yet.
//
// Spawns the MCP server as a child process (via `sh -c <command>`, same
// "let the shell handle word-splitting/quoting" approach as popen() and
// this codebase's own redex_plugin.c) connected over pipes, speaks
// JSON-RPC 2.0 with newline-delimited framing (the MCP stdio transport's
// wire format), and implements exactly the three calls needed to
// discover and invoke tools: initialize, tools/list, tools/call.
//
// JSON handling is deliberately the same lightweight, hand-rolled
// field-extraction style already used in this codebase (cmd_ai.cpp's
// json_extract_string) rather than a new vendored JSON library --
// MCP's reply shapes used here are simple enough not to need a real
// parser, and the project's own pattern (the plugin result JSON, cmd_ai.cpp)
// already established this is the preferred approach here.

#include <string>
#include <vector>
#include <sys/types.h>

struct McpTool {
    std::string name;
    std::string description;
};

class McpClient {
public:
    McpClient() = default;
    ~McpClient();

    // Non-copyable (owns a child process + fds).
    McpClient(const McpClient&) = delete;
    McpClient& operator=(const McpClient&) = delete;

    // Spawns `command` and performs the MCP handshake (initialize +
    // notifications/initialized). Returns false on spawn or handshake
    // failure -- check last_error().
    bool connect(const std::string& command);

    // Closes the pipes and waits for the child. Safe to call even if
    // connect() was never called or already failed.
    void disconnect();

    bool is_connected() const { return child_pid_ > 0; }

    // tools/list -- returns the discovered tools. Empty + a non-empty
    // last_error() means the call failed; empty + an empty last_error()
    // means the server genuinely has no tools.
    std::vector<McpTool> list_tools();

    // tools/call. `args_json` must be a valid JSON object literal (e.g.
    // "{\"text\":\"hi\"}", or "{}" for no arguments). On a successful
    // round trip (whether the TOOL itself reported success or failure),
    // returns true, fills result_text with the concatenated
    // content[].text entries, and sets tool_is_error from the response's
    // isError field. Returns false only on a transport/protocol failure
    // (e.g. the server process died) -- check last_error() for that case.
    bool call_tool(const std::string& name, const std::string& args_json,
                    std::string& result_text, bool& tool_is_error);

    const std::string& last_error() const { return last_error_; }

private:
    pid_t child_pid_ = -1;
    int stdin_fd_ = -1;   // parent write end -> child's stdin
    int stdout_fd_ = -1;  // parent read end <- child's stdout
    int next_id_ = 1;
    std::string read_buf_; // leftover bytes after the last complete line
    std::string last_error_;

    bool send_line(const std::string& json_line);
    // Reads lines from the child until one parses as a JSON-RPC message
    // with "id" == expected_id (skipping notifications/other ids),
    // within timeout_ms. Returns the raw matching line, or empty on
    // timeout/EOF (check last_error()).
    std::string read_response_for_id(int expected_id, int timeout_ms);
};
