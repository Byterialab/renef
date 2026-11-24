#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <renef/agent_request.h>
#include <renef/string_utils.h>
#include <cstdio>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cstring>

class InspectBinary : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "hookn";
    }

    std::string get_description() const override {
        return "Hook a native function and log its calls. Usage: hookn <lib_name> <offset|symbol>";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        (void)cmd_size;
        int pid = CommandRegistry::instance().get_current_pid();

        if (pid <= 0) {
            const char* error_msg = "ERROR: No target PID set. Please attach/spawn first.\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "No target PID set");
        }

        std::vector<std::string> cmd_parts = split(cmd_buffer, ' ');
        if (cmd_parts.size() < 3) {
            const char* error = "ERROR: Usage: hookn <lib_name> <offset|symbol>\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "Invalid arguments");
        }

        SocketHelper& socket_helper = CommandRegistry::instance().get_socket_helper();
        if (socket_helper.ensure_connection(pid) < 0) {
            const char* error_msg = "ERROR: Failed to connect to agent\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "Socket connection failed");
        }

        // The agent builds and runs the hook script itself (handlers/
        // inspect.c). This used to send "hook ..." - a command the agent
        // does not have - so hookn never did anything but report
        // "Unknown command".
        std::string reply;
        renef_agent_request::Outcome outcome = renef_agent_request::run(
            socket_helper, pid, "hookn " + cmd_parts[1] + " " + cmd_parts[2], 15000,
            [&](const std::string& data) { reply += data; }, /*may_resume=*/false);
        if (!outcome.sent || !outcome.done) {
            std::string error = renef_agent_request::timeout_message("hookn", outcome, 15000);
            write(client_fd, error.c_str(), error.size());
            return CommandResult(false, "No response from agent");
        }

        // The script's status line is not part of this command's output.
        std::string out;
        bool failed = false;
        size_t pos = 0;
        while (pos < reply.size()) {
            size_t eol = reply.find('\n', pos);
            std::string line = reply.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
            pos = (eol == std::string::npos) ? reply.size() : eol + 1;
            if (line == "OK") continue;
            if (line == "ERROR: Lua execution failed") { failed = true; continue; }
            if (line.compare(0, 13, "ERROR: hookn:") == 0) failed = true;
            out += line + "\n";
        }
        if (failed && out.empty()) out = "ERROR: hookn failed\n";
        write(client_fd, out.c_str(), out.size());

        return CommandResult(!failed, failed ? "Hook failed" : "Hook installed");
    }
};

std::unique_ptr<CommandDispatcher> create_inspect_command() {
    return std::make_unique<InspectBinary>();
}
