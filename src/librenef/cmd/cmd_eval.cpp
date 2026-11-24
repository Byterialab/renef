#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <renef/agent_request.h>
#include <cstdio>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>
#include <signal.h>

extern bool ptrace_resume(int pid);

// Machine-readable output prototype. `exec --json <code>`
// (the leading "--json " is stripped by the host before it ever reaches the
// agent -- the agent only ever sees plain Lua) buffers the full response
// instead of streaming it, then emits exactly one JSON line instead of the
// usual free-text stream. Deliberately local to this file, matching the
// existing per-file json_escape() precedent (cmd_ai.cpp) rather than adding
// a shared JSON utility -- this is meant to validate the pattern on one
// command before deciding whether/how to spread it to the other cmd_*.cpp
// files.
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 64);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    char hex[8];
                    snprintf(hex, sizeof(hex), "\\u%04x", (unsigned char)c);
                    out += hex;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

class Eval : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "exec";
    }

    std::string get_description() const override {
        return "Execute Lua code in the target process.";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        int pid = CommandRegistry::instance().get_current_pid();

        if (pid <= 0) {
            const char* error_msg = "ERROR: No target PID set. Please attach/spawn first.\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "No target PID set");
        }

        SocketHelper& socket_helper = CommandRegistry::instance().get_socket_helper();
        int sock = socket_helper.ensure_connection(pid);

        if (sock < 0) {
            const char* error_msg = "ERROR: Failed to connect to agent\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "Socket connection failed");
        }

        if (cmd_size <= 5) {
            const char* error = "ERROR: Usage: exec <lua_code>\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "No Lua code provided");
        }

        // Flags (host-only, stripped here -- the agent always just gets
        // plain Lua): "--json " and "--timeout <seconds> ", in
        // either order.
        std::string code(cmd_buffer + 5, cmd_size - 5);
        while (!code.empty() && (code.back() == '\n' || code.back() == '\r')) code.pop_back();

        bool json_mode = false;
        int silence_timeout_ms = renef_agent_request::DEFAULT_SILENCE_TIMEOUT_MS;
        static const std::string JSON_FLAG = "--json ";
        for (int pass = 0; pass < 2; pass++) {
            if (code.compare(0, JSON_FLAG.size(), JSON_FLAG) == 0) {
                json_mode = true;
                code.erase(0, JSON_FLAG.size());
            }
            if (code.compare(0, 10, "--timeout ") == 0) {
                silence_timeout_ms = renef_agent_request::take_timeout_flag(code);
            }
        }
        if (code.empty()) {
            const char* error = json_mode ? "ERROR: Usage: exec --json <lua_code>\n"
                                          : "ERROR: Usage: exec <lua_code>\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "No Lua code provided");
        }

        // Framed request, completion is the agent's own
        // marker for this request id. Previously completion was "a recv()
        // chunk contains OK\\n" (true for any script that prints OK, and
        // missed when the status line was split across two reads) with a
        // 5s-of-silence fallback, and the agent's status line could
        // overtake the script's own queued output - whatever arrived late
        // was then read as the next command's response.
        bool has_ok = false, has_fail = false;
        std::string status_tail;      // carry-over so a status line split across chunks is still seen
        std::string json_buffer;      // only accumulated when json_mode
        size_t total_bytes = 0;

        renef_agent_request::Outcome outcome = renef_agent_request::run(
            socket_helper, pid, "exec " + code, silence_timeout_ms,
            [&](const std::string& data) {
                total_bytes += data.size();
                std::string scan = status_tail + data;
                if (scan.find("ERROR: Lua execution failed") != std::string::npos) has_fail = true;
                if (scan.compare(0, 3, "OK\n") == 0 || scan.find("\nOK\n") != std::string::npos) has_ok = true;
                status_tail = scan.size() > 32 ? scan.substr(scan.size() - 32) : scan;

                if (json_mode) {
                    json_buffer += data; // binary-safe: append(ptr, n), not operator+=(const char*)
                } else {
                    write(client_fd, data.data(), data.size());
                }
            });

        if (!outcome.sent) {
            const char* error = "ERROR: Failed to send command to agent\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "Send failed");
        }

        bool script_done = outcome.done;
        bool script_ok = has_ok && !has_fail;

        if (!script_done && !json_mode) {
            std::string msg = renef_agent_request::timeout_message("exec", outcome, silence_timeout_ms);
            write(client_fd, msg.c_str(), msg.size());
        }

        if (json_mode) {
            // script_done false (poll/recv timed out or the connection
            // dropped before either marker showed up) is reported as its
            // own failure case, distinct from a Lua-side error.
            std::string result = "{\"ok\":" + std::string(script_done && script_ok ? "true" : "false") +
                ",\"pid\":" + std::to_string(pid) +
                ",\"timed_out\":" + std::string(script_done ? "false" : "true") +
                ",\"output\":\"" + json_escape(json_buffer) + "\"}\n";
            write(client_fd, result.c_str(), result.size());
        }

        return CommandResult(true, "Eval executed");
    }
};

std::unique_ptr<CommandDispatcher> create_eval_command() {
    return std::make_unique<Eval>();
}
