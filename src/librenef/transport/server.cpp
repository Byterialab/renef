#include "server.h"
#include <renef/cmd.h>
#include <renef/framing.h>
#include <string>
#include <vector>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <poll.h>

TransportServer::TransportServer(ITransport* transport)
    : transport(transport) {
}

TransportServer::~TransportServer() {
    close_server();
}

int TransportServer::create_server() {
    return transport->create_server();
}

int TransportServer::accept_client() {
    return transport->accept_client();
}

ssize_t TransportServer::send_data(const void* data, size_t size) {
    return transport->send_data(data, size);
}

ssize_t TransportServer::receive_data(void* buffer, size_t size) {
    return transport->receive_data(buffer, size);
}

void TransportServer::handle_client() {
    std::cout << "Entering handle_client loop (" << transport->get_type() << ")\n";

    // Bytes received but not yet consumed as a command. Persistent across
    // commands so a framed request that arrives together with (or right
    // behind) another one is kept for the next iteration.
    std::string inbuf;

    while (true) {
        std::string command;
        unsigned long req_id = 0;   // 0 = legacy (unframed) command
        char chunk[BUFFER_SIZE];

        while (true) {
            // --- Framed request (renef/framing.h) ---
            // Exact length, so multi-line payloads (-l scripts) and
            // back-to-back requests are delimited correctly instead of by
            // "a chunk ended in \\n and 50ms passed".
            bool malformed = false;
            int r = inbuf.empty() ? -1 : renef_framing::take_request(inbuf, req_id, command, &malformed);
            if (r == 1) break;
            if (malformed) {
                std::cerr << "Malformed request frame, dropping client\n";
                const char* error = "ERROR: Malformed request frame\n";
                send_data(error, strlen(error));
                return;
            }

            // --- Legacy command directly followed by a framed request in
            // the same buffer: the frame header starts at a line boundary,
            // so the legacy command ends there (otherwise the mixed buffer
            // matches neither rule and we would wait forever).
            if (r == -1 && !inbuf.empty()) {
                size_t q = inbuf.find(std::string("\n") + renef_framing::REQ_PREFIX);
                if (q != std::string::npos) {
                    command.assign(inbuf, 0, q);
                    inbuf.erase(0, q + 1);
                    req_id = 0;
                    break;
                }
            }

            // --- Legacy (unframed) command: unchanged heuristic ---
            if (r == -1 && !inbuf.empty() && inbuf.back() == '\n') {
                int fd = transport->get_fd();
                struct pollfd pfd = {fd, POLLIN, 0};
                if (poll(&pfd, 1, 50) <= 0) {
                    command.swap(inbuf);
                    inbuf.clear();
                    req_id = 0;
                    break;
                }
            }

            ssize_t n = receive_data(chunk, sizeof(chunk));
            if (n <= 0) {
                if (inbuf.empty()) {
                    std::cout << "Client disconnected (recv returned " << n << ")\n";
                } else {
                    std::cout << "Client disconnected mid-command\n";
                }
                return;
            }
            inbuf.append(chunk, (size_t)n);

            if (inbuf.size() > 8 * 1024 * 1024) {
                std::cerr << "Command too large (>8MB), rejecting\n";
                const char* error = "ERROR: Command too large\n";
                send_data(error, strlen(error));
                return;
            }
        }

        if (!command.empty() && command.back() == '\n') {
            command.pop_back();
        }
        if (command.empty()) {
            if (req_id) {
                std::string done = renef_framing::make_done(req_id);
                send_data(done.c_str(), done.size());
            }
            continue;
        }

        std::cout << "Received command (" << command.size() << " bytes, req=" << req_id << ")\n";
        // handle_command expects a NUL-terminated buffer of `size` bytes.
        std::vector<char> buffer(command.begin(), command.end());
        buffer.push_back('\0');
        handle_command(buffer.data(), command.size());

        // Hook/trace output is not part of any reply: the agent sends it on
        // its own connection and it waits in the event buffer until the
        // client asks for it (`events`, `watch`). A framed client is told
        // how much is waiting. An unframed one is told nothing - appending
        // the lines to its reply would hand them to whatever internal query
        // happened to be running - and sees them with its next `watch`.
        SocketHelper& events = CommandRegistry::instance().get_socket_helper();
        events.pump_events();

        // Completion marker for a framed request: every byte the command
        // wrote has gone out synchronously by now, so the requester can
        // stop reading exactly here instead of waiting for silence.
        if (req_id) {
            std::string done = renef_framing::make_done(req_id, events.pending_event_lines());
            send_data(done.c_str(), done.size());
        }
    }

    std::cout << "Exiting handle_client loop\n";
}

void TransportServer::handle_command(const char* cmd_buffer, size_t cmd_size) {
    CommandRegistry& registry = CommandRegistry::instance();
    int client_fd = transport->get_fd();
    registry.dispatch(client_fd, cmd_buffer, cmd_size);
}

void TransportServer::close_server() {
    if (transport) {
        transport->close();
    }
}
