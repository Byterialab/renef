#include <renef/cmd.h>
#include "../mcp/mcp_client.h"

#include <cstdio>
#include <cstring>
#include <memory>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <pwd.h>
#include <sys/types.h>

// Config/discovery. ~/.renef/mcp_servers.json maps
// a short name to the stdio command that starts that MCP server, so
// `mcp connect binja` can be used instead of retyping the full command
// every session. Deliberately a flat {"servers": {"name": "cmd"}}
// shape -- no nested config, no host:port variant
// yet (this client is stdio-only, see mcp_client.h).
//
// Hand-rolled parsing (same reasoning as mcp_client.cpp: no vendored
// JSON library in this codebase) -- the shape is fixed and flat enough
// that a real parser isn't needed.
static std::string mcp_config_path() {
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : nullptr;
    }
    if (!home) return "";
    return std::string(home) + "/.renef/mcp_servers.json";
}

// Looks up `name` as a key under "servers" in ~/.renef/mcp_servers.json.
// Returns its command string, or "" if the file/key doesn't exist (the
// caller then falls back to treating the whole input as a raw command).
static std::string resolve_named_server(const std::string& name) {
    std::string path = mcp_config_path();
    if (path.empty()) return "";

    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::stringstream ss;
    ss << f.rdbuf();
    std::string json = ss.str();

    size_t servers_key = json.find("\"servers\"");
    if (servers_key == std::string::npos) return "";
    size_t brace = json.find('{', servers_key);
    if (brace == std::string::npos) return "";

    std::string key = "\"" + name + "\"";
    size_t name_pos = json.find(key, brace);
    if (name_pos == std::string::npos) return "";

    size_t colon = json.find(':', name_pos + key.size());
    if (colon == std::string::npos) return "";
    size_t value_start = json.find('"', colon);
    if (value_start == std::string::npos) return "";
    value_start++;

    std::string result;
    size_t pos = value_start;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            pos++;
            result += json[pos];
        } else {
            result += json[pos];
        }
        pos++;
    }
    return result;
}

// `mcp` command -- a thin CLI surface over
// McpClient (src/librenef/mcp/mcp_client.cpp), independently testable
// before anything (e.g. cmd_ai.cpp) is wired up to use MCP tools
// automatically. Unlike every other cmd_*.cpp, this one never touches
// SocketHelper/the target app's agent at all -- an MCP server is a
// separate local process (a static-analysis tool's own MCP plugin,
// e.g. Binary Ninja MCP), not anything running on the Android device.
//
//   mcp connect <command...>      -- spawn + handshake with an MCP server
//   mcp list-tools                -- tools/list on the connected server
//   mcp call <tool> <json-args>   -- tools/call (json-args defaults to {})
//   mcp disconnect
class Mcp : public CommandDispatcher {
public:
    std::string get_name() const override { return "mcp"; }
    std::string get_description() const override {
        return "MCP client: mcp connect <cmd...> | list-tools | call <tool> <json-args> | disconnect";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        std::string full(cmd_buffer, cmd_size);
        while (!full.empty() && (full.back() == '\n' || full.back() == '\r')) full.pop_back();

        size_t sp = full.find(' ');
        std::string rest = (sp == std::string::npos) ? "" : full.substr(sp + 1);
        size_t sp2 = rest.find(' ');
        std::string sub = (sp2 == std::string::npos) ? rest : rest.substr(0, sp2);
        std::string args = (sp2 == std::string::npos) ? "" : rest.substr(sp2 + 1);

        if (sub == "connect") {
            if (args.empty()) {
                return reply(client_fd, false, "ERROR: Usage: mcp connect <name-or-command...>\n");
            }
            // If `args` (or just its first word, for the
            // common "mcp connect <name>" case) names a server in
            // ~/.renef/mcp_servers.json, use its configured command.
            // Otherwise args IS the command, verbatim (backward
            // compatible with calling connect directly, as above).
            std::string resolved = resolve_named_server(args);
            if (resolved.empty()) {
                size_t first_space = args.find(' ');
                std::string first_word = (first_space == std::string::npos) ? args : args.substr(0, first_space);
                resolved = resolve_named_server(first_word);
            }
            std::string command_to_run = resolved.empty() ? args : resolved;

            client_.reset(new McpClient());
            if (!client_->connect(command_to_run)) {
                std::string err = "ERROR: mcp connect failed: " + client_->last_error() + "\n";
                client_.reset();
                return reply(client_fd, false, err);
            }
            return reply(client_fd, true, "OK: MCP server connected\n");
        }

        if (sub == "list-tools") {
            if (!client_ || !client_->is_connected()) {
                return reply(client_fd, false, "ERROR: Not connected. Use 'mcp connect <command...>' first.\n");
            }
            std::vector<McpTool> tools = client_->list_tools();
            if (tools.empty() && !client_->last_error().empty()) {
                return reply(client_fd, false, "ERROR: mcp list-tools failed: " + client_->last_error() + "\n");
            }
            std::string out = "OK: " + std::to_string(tools.size()) + " tool(s)\n";
            for (const McpTool& t : tools) {
                out += "  " + t.name + " - " + t.description + "\n";
            }
            return reply(client_fd, true, out);
        }

        if (sub == "call") {
            if (!client_ || !client_->is_connected()) {
                return reply(client_fd, false, "ERROR: Not connected. Use 'mcp connect <command...>' first.\n");
            }
            size_t sp3 = args.find(' ');
            std::string tool_name = (sp3 == std::string::npos) ? args : args.substr(0, sp3);
            std::string json_args = (sp3 == std::string::npos) ? "{}" : args.substr(sp3 + 1);
            if (tool_name.empty()) {
                return reply(client_fd, false, "ERROR: Usage: mcp call <tool> [json-args]\n");
            }

            std::string result_text;
            bool tool_is_error = false;
            if (!client_->call_tool(tool_name, json_args, result_text, tool_is_error)) {
                return reply(client_fd, false, "ERROR: mcp call failed: " + client_->last_error() + "\n");
            }
            std::string out = std::string(tool_is_error ? "TOOL_ERROR" : "OK") + ": " + result_text + "\n";
            return reply(client_fd, !tool_is_error, out);
        }

        if (sub == "disconnect") {
            client_.reset();
            return reply(client_fd, true, "OK: disconnected\n");
        }

        return reply(client_fd, false, "ERROR: Usage: mcp connect <cmd...> | list-tools | call <tool> <json-args> | disconnect\n");
    }

private:
    static CommandResult reply(int client_fd, bool ok, const std::string& msg) {
        write(client_fd, msg.c_str(), msg.size());
        return CommandResult(ok, ok ? "" : msg);
    }

    // One MCP connection per host CLI process -- matches how
    // ServerConnection/SocketHelper are process-wide singletons for the
    // agent connection elsewhere in this codebase.
    std::unique_ptr<McpClient> client_;
};

std::unique_ptr<CommandDispatcher> create_mcp_command() {
    return std::make_unique<Mcp>();
}
