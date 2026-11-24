#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <cstdio>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <poll.h>
#include <iostream>
#include <cstring>
#include <cerrno>

class WatchCommand : public CommandDispatcher {
    // Watch with an event channel: first what has been waiting in the event
    // buffer, then whatever arrives, until the client sends anything.
    // Nothing is thrown away when it stops - later events stay buffered for
    // the next watch.
    static CommandResult watch_events(SocketHelper& helper, int client_fd) {
        auto forward = [&]() {
            helper.pump_events();
            std::string out = helper.take_events();
            if (!out.empty()) write(client_fd, out.c_str(), out.size());
        };

        forward();
        const char* start_msg = "Watching hook output... (waiting for hooks to trigger)\n";
        write(client_fd, start_msg, strlen(start_msg));

        int client_flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, client_flags | O_NONBLOCK);

        bool running = true;
        while (running) {
            int ev = helper.get_event_fd();
            struct pollfd pfds[2];
            pfds[0] = {client_fd, POLLIN, 0};
            pfds[1] = {ev, POLLIN, 0};
            int ret = poll(pfds, ev >= 0 ? 2 : 1, 1000);
            if (ret < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (ret == 0) continue;
            if (ev >= 0 && (pfds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
                forward();
                if (!helper.has_event_channel()) {
                    const char* msg = "Agent disconnected\n";
                    write(client_fd, msg, strlen(msg));
                    running = false;
                }
            }
            if (pfds[0].revents & (POLLHUP | POLLERR)) {
                running = false;
            } else if (pfds[0].revents & POLLIN) {
                char cmd[32];
                recv(client_fd, cmd, sizeof(cmd) - 1, 0);   // any input (or EOF) stops it
                running = false;
            }
        }

        fcntl(client_fd, F_SETFL, client_flags);
        return CommandResult(true, "Watch completed");
    }

public:
    std::string get_name() const override {
        return "watch";
    }

    std::string get_description() const override {
        return "Watch hook output in real-time (Ctrl+C to stop).";
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

        if (socket_helper.has_event_channel()) {
            return watch_events(socket_helper, client_fd);
        }

        fprintf(stderr, "[WATCH] Starting watch on agent socket fd=%d, client_fd=%d\n", sock, client_fd);

        // Drain any data already in socket buffer (e.g. hook output that
        // fired between script execution and watch startup) and forward to client
        {
            int old_flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, old_flags | O_NONBLOCK);
            char buf[4096];
            ssize_t drained_total = 0;
            while (true) {
                ssize_t n = recv(sock, buf, sizeof(buf), 0);
                if (n > 0) {
                    write(client_fd, buf, n);
                    drained_total += n;
                } else {
                    break;
                }
            }
            fcntl(sock, F_SETFL, old_flags);
            if (drained_total > 0) {
                fprintf(stderr, "[WATCH] forwarded %zd bytes of buffered hook output\n", drained_total);
            }
        }

        const char* start_msg = "Watching hook output... (waiting for hooks to trigger)\n";
        write(client_fd, start_msg, strlen(start_msg));

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        int client_flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, client_flags | O_NONBLOCK);

        char buffer[4096];
        bool running = true;

        int poll_count = 0;
        while (running) {
            struct pollfd pfds[2];
            pfds[0] = {sock, POLLIN, 0};
            pfds[1] = {client_fd, POLLIN, 0};

            int ret = poll(pfds, 2, 1000);
            poll_count++;
            if (poll_count % 5 == 0) {
                // Also try a non-blocking recv to see if there's data poll missed
                char peek_buf[64];
                ssize_t peek = recv(sock, peek_buf, sizeof(peek_buf), MSG_PEEK | MSG_DONTWAIT);
                fprintf(stderr, "[WATCH] poll iter=%d, ret=%d, sock_rev=0x%x, client_rev=0x%x, peek=%zd\n",
                        poll_count, ret, pfds[0].revents, pfds[1].revents, peek);
                if (peek > 0) {
                    fprintf(stderr, "[WATCH] peek data: %.*s\n", (int)peek, peek_buf);
                }
            }

            if (ret > 0) {
                if (pfds[0].revents & POLLIN) {
                    ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
                    fprintf(stderr, "[WATCH] recv from agent: n=%zd\n", n);
                    if (n > 0) {
                        buffer[n] = '\0';
                        fprintf(stderr, "[WATCH] Forwarding to client: %.*s\n", (int)n, buffer);
                        write(client_fd, buffer, n);
                    } else if (n == 0) {
                        const char* msg = "Agent disconnected\n";
                        write(client_fd, msg, strlen(msg));
                        running = false;
                    }
                }

                if (pfds[1].revents & (POLLHUP | POLLERR)) {
                    std::cout << "[WATCH] Client disconnected\n";
                    running = false;
                }

                if (pfds[1].revents & POLLIN) {
                    char cmd[32];
                    ssize_t n = recv(client_fd, cmd, sizeof(cmd) - 1, 0);
                    if (n <= 0) {
                        running = false;
                    } else {
                        cmd[n] = '\0';
                        std::cout << "[WATCH] Client sent data: '" << cmd << "', exiting watch mode\n";
                        running = false;
                    }
                }
            } else if (ret < 0) {
                std::cout << "[WATCH] poll error: " << strerror(errno) << "\n";
                running = false;
            }
        }

        {
            // Drop what the agent sent while watch was stopping. Bounded: a
            // hook that fires more often than every 50 ms would otherwise
            // keep this loop (and with it the whole server) busy forever.
            char drain_buf[4096];
            struct pollfd drain_pfd = {sock, POLLIN, 0};
            for (int rounds = 0; rounds < 8; rounds++) {
                if (poll(&drain_pfd, 1, 25) <= 0 || !(drain_pfd.revents & POLLIN)) break;
                ssize_t n = recv(sock, drain_buf, sizeof(drain_buf), MSG_DONTWAIT);
                if (n <= 0) break;
            }
        }

        fcntl(sock, F_SETFL, flags);
        fcntl(client_fd, F_SETFL, client_flags);

        return CommandResult(true, "Watch completed");
    }
};

std::unique_ptr<CommandDispatcher> create_watch_command() {
    return std::make_unique<WatchCommand>();
}
