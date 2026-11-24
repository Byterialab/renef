#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <cstdio>
#include <string>
#include <sstream>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <iostream>
#include <cstring>
#include <cerrno>

class StraceCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "renef-strace";
    }

    std::string get_description() const override {
        return "Trace syscalls in target process (strace-like)";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        int pid = CommandRegistry::instance().get_current_pid();

        if (pid <= 0) {
            const char* error_msg = "ERROR: No target PID set. Please attach/spawn first.\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "No target PID set");
        }

        std::string full_cmd(cmd_buffer, cmd_size);
        while (!full_cmd.empty() && (full_cmd.back() == '\n' || full_cmd.back() == '\r' || full_cmd.back() == ' '))
            full_cmd.pop_back();

        std::string args;
        size_t space_pos = full_cmd.find(' ');
        if (space_pos != std::string::npos) {
            args = full_cmd.substr(space_pos + 1);
        }

        std::string lua_code;

        if (args.empty() || args == "--help" || args == "-h") {
            const char* help =
                "Usage: renef-strace <syscalls|options>\n"
                "  renef-strace open,read,write,close    Trace specific syscalls\n"
                "  renef-strace -c file                  Trace by category (file/network/memory/process/ipc)\n"
                "  renef-strace -a                        Trace all syscalls\n"
                "  renef-strace --list                   List available syscalls\n"
                "  renef-strace --active                 Show active traces\n"
                "  renef-strace --stop                   Stop all tracing\n";
            write(client_fd, help, strlen(help));
            return CommandResult(true, "Help shown");
        }

        if (args == "--stop") {
            lua_code = "Syscall.stop()";
        } else if (args == "--list") {
            lua_code = "Syscall.list()";
        } else if (args == "--active") {
            lua_code = "Syscall.active()";
        } else if (args == "-a") {
            lua_code = "Syscall.traceAll()";
        } else if (args.substr(0, 3) == "-c ") {
            std::string category = args.substr(3);
            lua_code = "Syscall.trace({ category = '" + category + "' })";
        } else if (args.substr(0, 3) == "-f ") {
            size_t f_pos = args.find("-f ");
            std::string syscalls_part = args.substr(0, f_pos);
            std::string filter_lib = args.substr(f_pos + 3);

            while (!syscalls_part.empty() && syscalls_part.back() == ' ')
                syscalls_part.pop_back();
            while (!filter_lib.empty() && filter_lib.back() == ' ')
                filter_lib.pop_back();

            lua_code = generate_trace_lua(syscalls_part, filter_lib);
        } else {
            size_t f_pos = args.find(" -f ");
            if (f_pos != std::string::npos) {
                std::string syscalls_part = args.substr(0, f_pos);
                std::string filter_lib = args.substr(f_pos + 4);
                lua_code = generate_trace_lua(syscalls_part, filter_lib);
            } else {
                lua_code = generate_trace_lua(args, "");
            }
        }

        SocketHelper& socket_helper = CommandRegistry::instance().get_socket_helper();
        int sock = socket_helper.ensure_connection(pid);

        if (sock < 0) {
            const char* error_msg = "ERROR: Failed to connect to agent\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "Socket connection failed");
        }

        std::string exec_cmd = "exec " + lua_code + "\n";
        socket_helper.send_data(exec_cmd.c_str(), exec_cmd.size());

        if (args == "--stop" || args == "--list" || args == "--active") {
            int flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);

            char buffer[4096];
            struct pollfd pfd = {sock, POLLIN, 0};

            for (int attempt = 0; attempt < 4; attempt++) {
                int ret = poll(&pfd, 1, 500);
                if (ret > 0 && (pfd.revents & POLLIN)) {
                    ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
                    if (n > 0) {
                        buffer[n] = '\0';
                        write(client_fd, buffer, n);
                    }
                }
            }

            fcntl(sock, F_SETFL, flags);
            return CommandResult(true, "Done");
        }

        const char* start_msg = "Tracing syscalls... (press Ctrl+C or send any key to stop)\n";
        write(client_fd, start_msg, strlen(start_msg));

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        int client_flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, client_flags | O_NONBLOCK);

        char buffer[4096];
        bool running = true;

        while (running) {
            // With an event channel the trace lines arrive there; the
            // command socket only carries the reply of the exec above.
            int ev = socket_helper.get_event_fd();
            struct pollfd pfds[3];
            pfds[0] = {sock, POLLIN, 0};
            pfds[1] = {client_fd, POLLIN, 0};
            pfds[2] = {ev, POLLIN, 0};

            int ret = poll(pfds, ev >= 0 ? 3 : 2, 1000);

            if (ret > 0) {
                if (ev >= 0 && (pfds[2].revents & (POLLIN | POLLHUP | POLLERR))) {
                    socket_helper.pump_events();
                    std::string lines = socket_helper.take_events();
                    if (!lines.empty()) write(client_fd, lines.c_str(), lines.size());
                }

                if (pfds[0].revents & POLLIN) {
                    ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
                    if (n > 0) {
                        write(client_fd, buffer, n);
                    } else if (n == 0) {
                        const char* msg = "Agent disconnected\n";
                        write(client_fd, msg, strlen(msg));
                        running = false;
                    }
                }

                if (pfds[1].revents & (POLLHUP | POLLERR)) {
                    running = false;
                }

                if (pfds[1].revents & POLLIN) {
                    char cmd[32];
                    ssize_t n = recv(client_fd, cmd, sizeof(cmd) - 1, 0);
                    if (n <= 0) {
                        running = false;
                    } else {
                        running = false;
                    }
                }
            } else if (ret < 0) {
                running = false;
            }
        }

        std::string stop_cmd = "exec Syscall.stop()\n";
        socket_helper.send_data(stop_cmd.c_str(), stop_cmd.size());

        {
            struct pollfd drain_pfd = {sock, POLLIN, 0};
            for (int i = 0; i < 10; i++) {
                int ret = poll(&drain_pfd, 1, 100);
                if (ret > 0 && (drain_pfd.revents & POLLIN)) {
                    ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
                    if (n <= 0) break;
                } else {
                    break;
                }
            }
        }

        fcntl(sock, F_SETFL, flags);
        fcntl(client_fd, F_SETFL, client_flags);

        const char* done_msg = "Syscall tracing stopped.\n";
        write(client_fd, done_msg, strlen(done_msg));

        return CommandResult(true, "Strace completed");
    }

private:
    std::string generate_trace_lua(const std::string& syscalls, const std::string& filter_lib) {
        std::vector<std::string> names;
        std::istringstream ss(syscalls);
        std::string token;
        while (std::getline(ss, token, ',')) {
            size_t start = token.find_first_not_of(" \t");
            size_t end = token.find_last_not_of(" \t");
            if (start != std::string::npos) {
                names.push_back(token.substr(start, end - start + 1));
            }
        }

        if (names.empty()) return "print('No syscalls specified')";

        std::string lua = "Syscall.trace(";
        for (size_t i = 0; i < names.size(); i++) {
            if (i > 0) lua += ", ";
            lua += "'" + names[i] + "'";
        }

        if (!filter_lib.empty()) {
            lua += ", { caller = '" + filter_lib + "' }";
        }

        lua += ")";
        return lua;
    }
};

std::unique_ptr<CommandDispatcher> create_strace_command() {
    return std::make_unique<StraceCommand>();
}
