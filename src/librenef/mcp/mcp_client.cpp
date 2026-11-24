#include "mcp_client.h"

#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>

McpClient::~McpClient() {
    disconnect();
}

void McpClient::disconnect() {
    if (stdin_fd_ >= 0) { close(stdin_fd_); stdin_fd_ = -1; }
    if (stdout_fd_ >= 0) { close(stdout_fd_); stdout_fd_ = -1; }
    if (child_pid_ > 0) {
        kill(child_pid_, SIGTERM);
        int status;
        waitpid(child_pid_, &status, 0);
        child_pid_ = -1;
    }
    read_buf_.clear();
}

// ─── Minimal JSON field extraction (same hand-rolled style as cmd_ai.cpp's
//     json_extract_string -- see mcp_client.h for why no JSON library) ───

static std::string json_extract_string(const std::string& json, const std::string& field, size_t from = 0) {
    std::string key = "\"" + field + "\"";
    size_t pos = json.find(key, from);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos + key.size());
    if (pos == std::string::npos) return "";
    pos++;
    while (pos < json.size() && json[pos] == ' ') pos++;
    if (pos >= json.size() || json[pos] != '"') return "";

    pos++;
    std::string result;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            pos++;
            switch (json[pos]) {
                case 'n': result += '\n'; break;
                case 't': result += '\t'; break;
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                default: result += json[pos]; break;
            }
        } else {
            result += json[pos];
        }
        pos++;
    }
    return result;
}

static bool json_extract_int(const std::string& json, const std::string& field, long* out) {
    std::string key = "\"" + field + "\"";
    size_t pos = json.find(key);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + key.size());
    if (pos == std::string::npos) return false;
    pos++;
    while (pos < json.size() && json[pos] == ' ') pos++;
    char* end = nullptr;
    long val = strtol(json.c_str() + pos, &end, 10);
    if (end == json.c_str() + pos) return false;
    *out = val;
    return true;
}

static bool json_extract_bool(const std::string& json, const std::string& field, bool default_val) {
    std::string key = "\"" + field + "\"";
    size_t pos = json.find(key);
    if (pos == std::string::npos) return default_val;
    pos = json.find(':', pos + key.size());
    if (pos == std::string::npos) return default_val;
    pos++;
    while (pos < json.size() && json[pos] == ' ') pos++;
    if (json.compare(pos, 4, "true") == 0) return true;
    if (json.compare(pos, 5, "false") == 0) return false;
    return default_val;
}

// Finds the index of the bracket matching the one at `open_pos` (which
// must itself be open_char), tracking string-literal/escape state so
// braces/brackets inside quoted strings (e.g. a tool's own JSON-looking
// description text) don't throw off the depth count. Returns
// std::string::npos if unmatched.
static size_t find_matching_bracket(const std::string& s, size_t open_pos, char open_char, char close_char) {
    if (open_pos >= s.size() || s[open_pos] != open_char) return std::string::npos;
    int depth = 0;
    bool in_string = false;
    for (size_t i = open_pos; i < s.size(); i++) {
        char c = s[i];
        if (in_string) {
            if (c == '\\') { i++; continue; }
            if (c == '"') in_string = false;
            continue;
        }
        if (c == '"') { in_string = true; continue; }
        if (c == open_char) depth++;
        else if (c == close_char) {
            depth--;
            if (depth == 0) return i;
        }
    }
    return std::string::npos;
}

// Splits the content of a JSON array of objects (the bytes strictly
// between its '[' and ']') into the spans of each top-level object,
// depth/string-aware (same reasoning as find_matching_bracket).
static std::vector<std::string> split_json_object_array(const std::string& array_content) {
    std::vector<std::string> objects;
    bool in_string = false;
    int depth = 0;
    size_t obj_start = std::string::npos;
    for (size_t i = 0; i < array_content.size(); i++) {
        char c = array_content[i];
        if (in_string) {
            if (c == '\\') { i++; continue; }
            if (c == '"') in_string = false;
            continue;
        }
        if (c == '"') { in_string = true; continue; }
        if (c == '{') {
            if (depth == 0) obj_start = i;
            depth++;
        } else if (c == '}') {
            depth--;
            if (depth == 0 && obj_start != std::string::npos) {
                objects.push_back(array_content.substr(obj_start, i - obj_start + 1));
                obj_start = std::string::npos;
            }
        }
    }
    return objects;
}

// ─── Process/transport ──────────────────────────────────────────────

bool McpClient::connect(const std::string& command) {
    int in_pipe[2];  // parent writes in_pipe[1] -> child reads in_pipe[0] (child's stdin)
    int out_pipe[2]; // child writes out_pipe[1] -> parent reads out_pipe[0] (child's stdout)

    if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0) {
        last_error_ = "pipe() failed";
        return false;
    }

    pid_t pid = fork();
    if (pid < 0) {
        last_error_ = "fork() failed";
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        return false;
    }

    if (pid == 0) {
        // Child: wire stdin/stdout to the pipes, inherit stderr (so the
        // server's own logs stay visible and don't pollute the JSON-RPC
        // stream on stdout).
        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        execl("/bin/sh", "sh", "-c", command.c_str(), (char*)nullptr);
        _exit(127); // execl failed
    }

    // Parent
    close(in_pipe[0]);
    close(out_pipe[1]);
    stdin_fd_ = in_pipe[1];
    stdout_fd_ = out_pipe[0];
    child_pid_ = pid;

    // MCP handshake: initialize (expects a result), then the
    // notifications/initialized notification (no id, no response).
    int init_id = next_id_++;
    char req[512];
    snprintf(req, sizeof(req),
        "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"initialize\",\"params\":"
        "{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},"
        "\"clientInfo\":{\"name\":\"renef\",\"version\":\"0.1.0\"}}}",
        init_id);
    if (!send_line(req)) {
        disconnect();
        return false;
    }

    std::string resp = read_response_for_id(init_id, 5000);
    if (resp.empty()) {
        if (last_error_.empty()) last_error_ = "no response to initialize (timeout or server exited)";
        disconnect();
        return false;
    }
    if (resp.find("\"error\"") != std::string::npos && resp.find("\"result\"") == std::string::npos) {
        last_error_ = "initialize failed: " + json_extract_string(resp, "message");
        disconnect();
        return false;
    }

    send_line("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}");
    return true;
}

bool McpClient::send_line(const std::string& json_line) {
    if (stdin_fd_ < 0) {
        last_error_ = "not connected";
        return false;
    }
    std::string line = json_line + "\n";
    size_t total = 0;
    while (total < line.size()) {
        ssize_t n = write(stdin_fd_, line.c_str() + total, line.size() - total);
        if (n <= 0) {
            last_error_ = "write to MCP server failed (it may have exited)";
            return false;
        }
        total += (size_t)n;
    }
    return true;
}

std::string McpClient::read_response_for_id(int expected_id, int timeout_ms) {
    if (stdout_fd_ < 0) {
        last_error_ = "not connected";
        return "";
    }

    char chunk[4096];
    while (true) {
        // Any complete line(s) already buffered?
        size_t nl;
        while ((nl = read_buf_.find('\n')) != std::string::npos) {
            std::string line = read_buf_.substr(0, nl);
            read_buf_.erase(0, nl + 1);
            if (line.empty()) continue;
            long id = -1;
            if (json_extract_int(line, "id", &id) && id == expected_id) {
                return line;
            }
            // Not the message we're waiting for (a notification, or a
            // response to an earlier/unrelated request) -- keep reading.
        }

        struct pollfd pfd = {stdout_fd_, POLLIN, 0};
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret == 0) {
            last_error_ = "timed out waiting for MCP server response";
            return "";
        }
        if (ret < 0) {
            last_error_ = "poll() failed";
            return "";
        }
        ssize_t n = read(stdout_fd_, chunk, sizeof(chunk));
        if (n <= 0) {
            last_error_ = "MCP server closed its output (exited?)";
            return "";
        }
        read_buf_.append(chunk, (size_t)n);
    }
}

std::vector<McpTool> McpClient::list_tools() {
    std::vector<McpTool> tools;
    if (!is_connected()) {
        last_error_ = "not connected";
        return tools;
    }

    int id = next_id_++;
    char req[128];
    snprintf(req, sizeof(req), "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"tools/list\",\"params\":{}}", id);
    if (!send_line(req)) return tools;

    std::string resp = read_response_for_id(id, 5000);
    if (resp.empty()) return tools; // last_error_ already set

    if (resp.find("\"error\"") != std::string::npos && resp.find("\"result\"") == std::string::npos) {
        last_error_ = "tools/list failed: " + json_extract_string(resp, "message");
        return tools;
    }

    size_t tools_key = resp.find("\"tools\"");
    if (tools_key == std::string::npos) {
        last_error_.clear(); // genuinely no tools, not a failure
        return tools;
    }
    size_t bracket = resp.find('[', tools_key);
    if (bracket == std::string::npos) return tools;
    size_t end_bracket = find_matching_bracket(resp, bracket, '[', ']');
    if (end_bracket == std::string::npos) return tools;

    std::string array_content = resp.substr(bracket + 1, end_bracket - bracket - 1);
    for (const std::string& obj : split_json_object_array(array_content)) {
        McpTool tool;
        tool.name = json_extract_string(obj, "name");
        tool.description = json_extract_string(obj, "description");
        if (!tool.name.empty()) tools.push_back(tool);
    }
    last_error_.clear();
    return tools;
}

bool McpClient::call_tool(const std::string& name, const std::string& args_json,
                          std::string& result_text, bool& tool_is_error) {
    result_text.clear();
    tool_is_error = false;
    if (!is_connected()) {
        last_error_ = "not connected";
        return false;
    }

    int id = next_id_++;
    std::string req = "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
        ",\"method\":\"tools/call\",\"params\":{\"name\":\"" + name +
        "\",\"arguments\":" + (args_json.empty() ? "{}" : args_json) + "}}";
    if (!send_line(req)) return false;

    std::string resp = read_response_for_id(id, 15000); // tools can be slow (e.g. a decompiler query)
    if (resp.empty()) return false; // last_error_ already set

    if (resp.find("\"error\"") != std::string::npos && resp.find("\"result\"") == std::string::npos) {
        last_error_ = "tools/call failed: " + json_extract_string(resp, "message");
        return false;
    }

    tool_is_error = json_extract_bool(resp, "isError", false);

    // Concatenate every content[].text entry (MCP tool results are a
    // list of content blocks; text is the only kind this client reads).
    size_t content_key = resp.find("\"content\"");
    if (content_key != std::string::npos) {
        size_t bracket = resp.find('[', content_key);
        size_t end_bracket = (bracket == std::string::npos) ? std::string::npos
            : find_matching_bracket(resp, bracket, '[', ']');
        if (bracket != std::string::npos && end_bracket != std::string::npos) {
            std::string array_content = resp.substr(bracket + 1, end_bracket - bracket - 1);
            for (const std::string& obj : split_json_object_array(array_content)) {
                if (!result_text.empty()) result_text += "\n";
                result_text += json_extract_string(obj, "text");
            }
        }
    }

    last_error_.clear();
    return true;
}
