#pragma once

#include <string>
#include <mutex>
#include <renef/framing.h>

// Host port the client reaches renef_server on: RENEF_PORT, or 1907. A
// second device needs its own host port, since `adb forward` binds one host
// port to one device.
int renef_host_port();

class ServerConnection {
public:
    static ServerConnection& instance();

    bool connect(const std::string& host = "127.0.0.1", int port = 1907);
    void disconnect();
    bool is_connected() const;

    bool send(const std::string& data);
    std::string receive(int timeout_ms = 2000);
    // For streams (watch): waits up to timeout_ms for data and returns what
    // is there right now, without waiting for the line to go quiet.
    // receive() only returns after 50ms of silence, which a hook on a busy
    // function never leaves - nothing was shown and `q` was never seen.
    std::string receive_some(int timeout_ms = 100);

    // --- Framed request/response (renef/framing.h) ---
    // True if the server on the other end understands framed requests.
    // Probed once per connection; an older renef_server answers the probe
    // like any unknown command and the connection stays in legacy mode.
    bool supports_framing();
    // Sends `command` as a framed request and returns everything the server
    // wrote for it, up to its completion marker. A reply to an earlier
    // request that arrives late is skipped by id instead of being returned
    // here. *completed is false if silence_timeout_ms passed without any
    // data (or the connection dropped) before the marker.
    std::string request(const std::string& command, int silence_timeout_ms, bool* completed = nullptr);
    // Lines of hook/trace output waiting on the server after the last
    // request() (they are not part of replies; `watch` shows them).
    unsigned long pending_events();

    // Connection parameters (for creating additional connections)
    std::string get_host() const;
    int get_port() const;

    // Raw socket fd for direct poll/recv (watch streaming)
    int get_socket_fd() const;

private:
    ServerConnection();
    ~ServerConnection();
    ServerConnection(const ServerConnection&) = delete;
    ServerConnection& operator=(const ServerConnection&) = delete;

    int sock_fd;
    mutable std::mutex mtx;  // mutable: is_connected() is const but still needs to lock it
    std::string connected_host_;
    int connected_port_ = 0;

    // Framing state; guarded by mtx, valid for the current sock_fd only.
    int framing_state_ = 0;              // 0 = not probed, 1 = supported, -1 = legacy server
    int framing_probed_fd_ = -1;
    unsigned long next_request_id_ = 1;
    renef_framing::ResponseReader reader_;

    bool send_all_locked(const std::string& data);
    std::string request_locked(const std::string& command, int silence_timeout_ms, bool* completed);
};
