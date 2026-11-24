#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <renef/agent_request.h>
#include <cstdio>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>

// `rpc <lua_expression>` -- call a Lua expression in the
// target process and get back a single, clean JSON line, instead of the
// free-form text `exec`/`eval` streams. Deliberately does NOT invent a new
// wire protocol or a new agent-side JSON encoder: it reuses two things
// that already exist --
//   - the `exec` command's existing connect/send/poll plumbing (same as
//     cmd_eval.cpp, just buffering the response instead of streaming it
//     straight to client_fd), and
//   - send()/json_encode_* (engine.c) for the actual value -> JSON
//     conversion, by wrapping the user's expression in a pcall + send({...})
//     and having send() do the real work.
//
// This follows the "prototype on one command first" approach:
// a single, self-contained new command, not a change spread across every
// existing cmd_*.cpp.
class Rpc : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "rpc";
    }

    std::string get_description() const override {
        return "Call a Lua expression in the target and get back one JSON line: rpc <expression>";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        int pid = CommandRegistry::instance().get_current_pid();
        if (pid <= 0) {
            const char* error_msg = "ERROR: No target PID set. Please attach/spawn first.\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "No target PID set");
        }

        // Strip the leading "rpc " token.
        std::string full(cmd_buffer, cmd_size);
        while (!full.empty() && (full.back() == '\n' || full.back() == '\r')) full.pop_back();
        size_t space = full.find(' ');
        std::string expr = (space != std::string::npos) ? full.substr(space + 1) : "";
        if (expr.empty()) {
            const char* error_msg = "ERROR: Usage: rpc <lua_expression>  (e.g. rpc extractedKey())\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "Missing expression");
        }

        // Optional leading "--timeout <seconds> ".
        int silence_timeout_ms = renef_agent_request::take_timeout_flag(expr);
        if (expr.empty()) {
            const char* error_msg = "ERROR: Usage: rpc [--timeout <seconds>] <lua_expression>\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "Missing expression");
        }

        SocketHelper& socket_helper = CommandRegistry::instance().get_socket_helper();
        int sock = socket_helper.ensure_connection(pid);
        if (sock < 0) {
            const char* error_msg = "ERROR: Failed to connect to agent\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "Socket connection failed");
        }

        // The wrapper always calls send() exactly once, whether the
        // expression succeeds or raises -- so the host always gets exactly
        // one "[event] {...}" line to look for, success or failure, instead
        // of having to separately detect a Lua error out of free-form exec
        // output (cmd_eval.cpp's own "\xe2\x9c\x93/\xe2\x9c\x97 Lua executed" marker
        // approach).
        //
        // Found live (2026-10-29, regression testing against a real app):
        // the original "value = __rpc_ok and __rpc_val or nil" ternary-
        // style idiom silently collapsed a successful call's `false`
        // return into a MISSING value field -- Lua's `a and b or c` falls
        // through to `c` whenever `b` itself is falsy, not just when `a`
        // is. Any expression that legitimately evaluates to `false` (e.g.
        // rpc'ing a boolean-returning Java method that returns false) came
        // back indistinguishable from "no value" instead of "value:false".
        // Fixed with a real if/else branch instead of the idiom.
        std::string wrapped =
            "local __rpc_ok, __rpc_val = pcall(function() return (" + expr + ") end); "
            "if __rpc_ok then "
            "send({__rpc_call = true, ok = true, value = __rpc_val}) "
            "else "
            "send({__rpc_call = true, ok = false, error = tostring(__rpc_val)}) "
            "end";

        // Framed request. The response is everything the
        // agent wrote for THIS request id up to its completion marker --
        // not "the first [event] line that shows up on the socket". That
        // used to hand a slow call's late reply to the next rpc (measured:
        // an 8s call followed by `rpc 2+2` answered 42), and could also
        // return a hook's unrelated send() event as the rpc result.
        std::string response;
        renef_agent_request::Outcome outcome = renef_agent_request::run(
            socket_helper, pid, "exec " + wrapped, silence_timeout_ms,
            [&](const std::string& data) { response += data; });

        if (!outcome.sent) {
            const char* error_msg = "ERROR: Failed to send command to agent\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "Send failed");
        }

        // Find OUR event line: the one produced by the wrapper's send(),
        // identified by "__rpc_call":true, not merely the first event.
        const std::string marker = "[event] ";
        std::string json_line;
        std::string other_output;
        size_t pos = 0;
        while (pos < response.size()) {
            size_t eol = response.find('\n', pos);
            std::string line = response.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
            pos = (eol == std::string::npos) ? response.size() : eol + 1;
            if (line.empty()) continue;
            if (json_line.empty() && line.compare(0, marker.size(), marker) == 0 &&
                line.find("\"__rpc_call\":true") != std::string::npos) {
                json_line = line.substr(marker.size());
                continue;
            }
            if (line == "OK" || line == "ERROR: Lua execution failed") continue; // exec's own status line
            other_output += line + "\n";
        }

        if (json_line.empty()) {
            std::string err = outcome.done
                ? std::string("ERROR: rpc completed without a result event\n")
                : renef_agent_request::timeout_message("rpc", outcome, silence_timeout_ms);
            write(client_fd, err.c_str(), err.size());
            if (!other_output.empty()) write(client_fd, other_output.c_str(), other_output.size());
            return CommandResult(false, "No RPC response");
        }

        // Result first (a consumer that reads one line gets exactly the
        // rpc result), then anything else the call produced meanwhile --
        // print() output and hook send() events -- instead of silently
        // discarding it as before.
        json_line += "\n";
        write(client_fd, json_line.c_str(), json_line.size());
        if (!other_output.empty()) write(client_fd, other_output.c_str(), other_output.size());
        return CommandResult(true, "RPC executed");
    }
};

std::unique_ptr<CommandDispatcher> create_rpc_command() {
    return std::make_unique<Rpc>();
}
