#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <renef/agent_request.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <poll.h>

class HooksCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "hooks";
    }

    std::string get_description() const override {
        return "List active hooks";
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

        // Framed request: the reply is complete at the agent's completion
        // marker. The old code did one recv() into a small fixed buffer
        // after a 2s poll, so a long hook list was cut off and anything
        // still on the socket was taken for the reply.
        (void)sock;
        std::string reply;
        renef_agent_request::Outcome outcome = renef_agent_request::run(
            socket_helper, pid, std::string("hooks"), 5000,
            [&](const std::string& data) { reply += data; }, /*may_resume=*/false);
        if (!outcome.sent || !outcome.done) {
            const char* error = "ERROR: No response from agent\n";
            write(client_fd, error, strlen(error));
        } else if (!reply.empty()) {
            write(client_fd, reply.data(), reply.size());
        }

        return CommandResult(true, "Hooks listed");
    }
};

class UnhookCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "unhook";
    }

    std::string get_description() const override {
        return "Remove hook(s): unhook [id] or unhook all";
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

        std::string cmd(cmd_buffer, cmd_size);
        if (cmd.empty() || cmd.back() != '\n') {
            cmd += "\n";
        }
        std::string agent_cmd = cmd;
        while (!agent_cmd.empty() && (agent_cmd.back() == '\n' || agent_cmd.back() == '\r')) agent_cmd.pop_back();
        // Framed request: the reply is complete at the agent's completion
        // marker. The old code did one recv() into a small fixed buffer
        // after a 2s poll, so a long hook list was cut off and anything
        // still on the socket was taken for the reply.
        (void)sock;
        std::string reply;
        renef_agent_request::Outcome outcome = renef_agent_request::run(
            socket_helper, pid, agent_cmd, 5000,
            [&](const std::string& data) { reply += data; }, /*may_resume=*/false);
        if (!outcome.sent || !outcome.done) {
            const char* error = "ERROR: No response from agent\n";
            write(client_fd, error, strlen(error));
        } else if (!reply.empty()) {
            write(client_fd, reply.data(), reply.size());
        }

        return CommandResult(true, "Unhook completed");
    }
};

class VerboseCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "verbose";
    }

    std::string get_description() const override {
        return "Toggle verbose mode: verbose [on|off]";
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

        std::string cmd(cmd_buffer, cmd_size);
        if (cmd.empty() || cmd.back() != '\n') {
            cmd += "\n";
        }
        std::string agent_cmd = cmd;
        while (!agent_cmd.empty() && (agent_cmd.back() == '\n' || agent_cmd.back() == '\r')) agent_cmd.pop_back();
        // Framed request: the reply is complete at the agent's completion
        // marker. The old code did one recv() into a small fixed buffer
        // after a 2s poll, so a long hook list was cut off and anything
        // still on the socket was taken for the reply.
        (void)sock;
        std::string reply;
        renef_agent_request::Outcome outcome = renef_agent_request::run(
            socket_helper, pid, agent_cmd, 5000,
            [&](const std::string& data) { reply += data; }, /*may_resume=*/false);
        if (!outcome.sent || !outcome.done) {
            const char* error = "ERROR: No response from agent\n";
            write(client_fd, error, strlen(error));
        } else if (!reply.empty()) {
            write(client_fd, reply.data(), reply.size());
        }

        return CommandResult(true, "Verbose mode toggled");
    }
};

std::unique_ptr<CommandDispatcher> create_hooks_command() {
    return std::make_unique<HooksCommand>();
}

std::unique_ptr<CommandDispatcher> create_unhook_command() {
    return std::make_unique<UnhookCommand>();
}

std::unique_ptr<CommandDispatcher> create_verbose_command() {
    return std::make_unique<VerboseCommand>();
}
