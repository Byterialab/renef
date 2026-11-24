#include <cerrno>
#include <renef/server_connection.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>
#include <iostream>
#include <cstdlib>

int renef_host_port() {
    static int port = 0;
    if (port == 0) {
        port = 1907;
        const char* env = getenv("RENEF_PORT");
        if (env && *env) {
            int value = atoi(env);
            if (value > 0 && value < 65536) port = value;
        }
    }
    return port;
}

ServerConnection& ServerConnection::instance() {
    static ServerConnection inst;
    return inst;
}

ServerConnection::ServerConnection() : sock_fd(-1) {}

ServerConnection::~ServerConnection() {
    disconnect();
}

bool ServerConnection::connect(const std::string& host, int port) {
    std::lock_guard<std::mutex> lock(mtx);

    if (sock_fd >= 0) {
        return true;
    }

    // Check if host starts with @ -> abstract UDS
    if (!host.empty() && host[0] == '@') {
        sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock_fd < 0) {
            std::cerr << "[ServerConnection] socket(AF_UNIX) failed\n";
            return false;
        }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        addr.sun_path[0] = '\0';  // Abstract namespace
        strncpy(addr.sun_path + 1, host.c_str() + 1, sizeof(addr.sun_path) - 2);
        socklen_t addr_len = sizeof(addr.sun_family) + 1 + strlen(host.c_str() + 1);

        if (::connect(sock_fd, (struct sockaddr*)&addr, addr_len) < 0) {
            std::cerr << "[ServerConnection] connect(UDS) failed: " << strerror(errno) << "\n";
            close(sock_fd);
            sock_fd = -1;
            return false;
        }

        std::cout << "[*] Connected to UDS: " << host << "\n";
        connected_host_ = host;
        connected_port_ = port;
        return true;
    }

    // TCP connection
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        std::cerr << "[ServerConnection] socket() failed\n";
        return false;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host.c_str());

    if (::connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[ServerConnection] connect() failed\n";
        close(sock_fd);
        sock_fd = -1;
        return false;
    }

    connected_host_ = host;
    connected_port_ = port;
    return true;
}

void ServerConnection::disconnect() {
    std::lock_guard<std::mutex> lock(mtx);

    if (sock_fd >= 0) {
        close(sock_fd);
        sock_fd = -1;
    }
}

bool ServerConnection::is_connected() const {
    // Must take the same lock as connect()/disconnect()/send()/receive():
    // without it, another thread can close() sock_fd (and reset it to -1,
    // or the fd number can be reused by an unrelated socket/file right
    // after close()) between our `sock_fd < 0` check and the recv() call
    // below, making this probe race against the fd's own lifetime.
    std::lock_guard<std::mutex> lock(mtx);

    if (sock_fd < 0) return false;

    char probe;
    ssize_t n = recv(sock_fd, &probe, 1, MSG_PEEK | MSG_DONTWAIT);
    if (n == 0) {
        return false;
    }
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        return false;
    }
    return true;
}

bool ServerConnection::send(const std::string& data) {
    std::lock_guard<std::mutex> lock(mtx);

    if (sock_fd < 0) return false;

    // Legacy (unframed) send: its caller reads the socket directly and
    // will consume any completion markers still in flight.
    reader_.forget_outstanding();

    ssize_t total = 0;
    ssize_t len = data.length();
    const char* ptr = data.c_str();

    while (total < len) {
        ssize_t n = ::send(sock_fd, ptr + total, len - total, MSG_NOSIGNAL);
        if (n <= 0) {
            close(sock_fd);
            sock_fd = -1;
            return false;
        }
        total += n;
    }

    return true;
}

std::string ServerConnection::receive_some(int timeout_ms) {
    std::lock_guard<std::mutex> lock(mtx);

    if (sock_fd < 0) return "";

    struct pollfd pfd;
    pfd.fd = sock_fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout_ms) <= 0) return "";

    std::string result;
    char buffer[8192];
    // Bounded, so the caller gets to print and to look at the keyboard
    // however fast the data keeps coming.
    while (result.size() < 64 * 1024) {
        ssize_t n = recv(sock_fd, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (n > 0) {
            result.append(buffer, (size_t)n);
            continue;
        }
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
            close(sock_fd);
            sock_fd = -1;
        }
        break;
    }
    return result;
}

std::string ServerConnection::receive(int timeout_ms) {
    std::lock_guard<std::mutex> lock(mtx);

    if (sock_fd < 0) return "";

    std::string result;
    char buffer[4096];

    struct pollfd pfd;
    pfd.fd = sock_fd;
    pfd.events = POLLIN;

    if (poll(&pfd, 1, timeout_ms) <= 0) return "";

    while (true) {
        ssize_t n = recv(sock_fd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);

        if (n > 0) {
            // Append exactly the n bytes read, including any embedded NUL
            // bytes (unavoidable in raw/binary payloads, e.g. memory dumps).
            // `result += buffer` would go through operator+=(const char*),
            // which calls strlen() internally and silently truncates at the
            // first NUL byte in the data -- losing everything after it.
            // std::string::append(ptr, n) copies exactly n bytes regardless
            // of their content.
            result.append(buffer, n);
            continue;
        }

        if (n == 0) {
            // Peer closed connection - mark as disconnected
            close(sock_fd);
            sock_fd = -1;
            break;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (poll(&pfd, 1, 50) <= 0) break;
            continue;
        }

        // Real recv error - mark as disconnected
        close(sock_fd);
        sock_fd = -1;
        break;
    }

    return result;
}

std::string ServerConnection::get_host() const {
    return connected_host_;
}

int ServerConnection::get_port() const {
    return connected_port_;
}

int ServerConnection::get_socket_fd() const {
    return sock_fd;
}

bool ServerConnection::send_all_locked(const std::string& data) {
    if (sock_fd < 0) return false;
    size_t total = 0;
    while (total < data.size()) {
        ssize_t n = ::send(sock_fd, data.data() + total, data.size() - total, MSG_NOSIGNAL);
        if (n <= 0) {
            close(sock_fd);
            sock_fd = -1;
            return false;
        }
        total += (size_t)n;
    }
    return true;
}

std::string ServerConnection::request_locked(const std::string& command, int silence_timeout_ms, bool* completed) {
    if (completed) *completed = false;
    if (sock_fd < 0) return "";

    unsigned long id = next_request_id_++;
    // Payload always ends in '\n': harmless for a framing-aware server
    // (stripped), and it keeps an OLD server - which would read the whole
    // frame as one unknown text command - from blocking on a partial line.
    if (!send_all_locked(renef_framing::make_request(id, command + "\n"))) return "";
    reader_.sent(id);

    std::string result;
    char buffer[8192];
    int waited_ms = 0;

    for (;;) {
        if (reader_.poll(id, result)) {
            if (completed) *completed = true;
            return result;
        }
        if (sock_fd < 0) return result;

        struct pollfd pfd;
        pfd.fd = sock_fd;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, 100);
        if (ret > 0) {
            ssize_t n = recv(sock_fd, buffer, sizeof(buffer), MSG_DONTWAIT);
            if (n > 0) {
                reader_.feed(buffer, (size_t)n);
                waited_ms = 0;
            } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                close(sock_fd);
                sock_fd = -1;
                reader_.poll(id, result);
                return result;
            }
        } else if (ret == 0) {
            waited_ms += 100;
            if (waited_ms >= silence_timeout_ms) return result;
        } else if (errno != EINTR) {
            return result;
        }
    }
}

std::string ServerConnection::request(const std::string& command, int silence_timeout_ms, bool* completed) {
    std::lock_guard<std::mutex> lock(mtx);
    return request_locked(command, silence_timeout_ms, completed);
}

unsigned long ServerConnection::pending_events() {
    std::lock_guard<std::mutex> lock(mtx);
    return reader_.pending_events();
}

bool ServerConnection::supports_framing() {
    std::lock_guard<std::mutex> lock(mtx);
    if (sock_fd < 0) return false;

    if (framing_probed_fd_ != sock_fd) {
        // New connection: previous stream state is void.
        framing_state_ = 0;
        framing_probed_fd_ = sock_fd;
        reader_.reset();
    }
    if (framing_state_ != 0) return framing_state_ > 0;

    // A framing-aware server completes this within milliseconds. An older
    // one replies "ERROR: Unknown command..." with no marker; give it a
    // short window, then stay in legacy mode for this connection.
    bool completed = false;
    request_locked("ping", 1500, &completed);
    framing_state_ = completed ? 1 : -1;
    if (!completed) {
        reader_.reset();
    }
    return completed;
}
