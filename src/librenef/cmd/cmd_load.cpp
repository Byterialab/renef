#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <renef/agent_request.h>
#include <renef/string_utils.h>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <string>
#include <iostream>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <signal.h>

extern bool ptrace_resume(int pid);

static std::string read_file(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return "";
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0) { fclose(f); return ""; }
    std::string content(size, '\0');
    fread(&content[0], 1, size, f);
    fclose(f);
    return content;
}

class LoadScriptCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "l";
    }

    std::string get_description() const override {
        return "Load and execute a Lua script in the target process.";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        std::vector<std::string> cmd_parts = split(cmd_buffer, ' ');
        if (cmd_parts.size() < 2) {
            const char* error = "ERROR: Usage: l <filename>\n";
            write(client_fd, error, strlen(error));
            return CommandResult(false, "Invalid arguments");
        }

        std::string file_path = cmd_parts[1];

        std::string lua_script = read_file(file_path.c_str());
        if (lua_script.empty()) {
            std::string error = "ERROR: Cannot read file: " + file_path + "\n";
            write(client_fd, error.c_str(), error.length());
            return CommandResult(false, "File read failed");
        }

        int pid = CommandRegistry::instance().get_current_pid();
        if (pid <= 0) {
            const char* error_msg = "ERROR: No target PID set. Please attach first.\n";
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

        std::string hex = hex_encode(lua_script);

        // Framed request. This used to wait for a
        // completion marker the agent never sends, so every `l <script>`
        // sat through a full 5s of silence before returning, and output
        // arriving after that was read by the next command.
        renef_agent_request::Outcome outcome = renef_agent_request::run(
            socket_helper, pid, "hexexec " + hex,
            renef_agent_request::DEFAULT_SILENCE_TIMEOUT_MS,
            [&](const std::string& data) { write(client_fd, data.data(), data.size()); });

        if (!outcome.sent) {
            const char* error_msg = "ERROR: Failed to send script to agent\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "Send failed");
        }
        if (!outcome.done) {
            std::string msg = renef_agent_request::timeout_message(
                "script", outcome, renef_agent_request::DEFAULT_SILENCE_TIMEOUT_MS);
            write(client_fd, msg.c_str(), msg.size());
            return CommandResult(false, "Script did not complete");
        }
        return CommandResult(true, "Script loaded and executed");
    }
};

std::unique_ptr<CommandDispatcher> create_load_command() {
    return std::make_unique<LoadScriptCommand>();
}
