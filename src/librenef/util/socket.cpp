#include <renef/socket_helper.h>
#include "../transport/uds.h"
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <string>
#include <fcntl.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/un.h>
#include <cstdlib>
#include <algorithm>

namespace {

// What the event buffer may hold before the oldest lines are dropped.
const size_t EVENT_BUF_MAX = 1024 * 1024;

int connect_agent_raw(int pid) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    std::string name = "renef_pl_" + std::to_string(pid);
    strncpy(addr.sun_path + 1, name.c_str(), sizeof(addr.sun_path) - 2);
    socklen_t len = sizeof(addr.sun_family) + name.length() + 1;
    if (connect(fd, (struct sockaddr*)&addr, len) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

} // namespace

SocketHelper::SocketHelper()
    : transport(nullptr), current_pid(-1) {
}

SocketHelper::~SocketHelper() {
    close_connection();
}

int SocketHelper::ensure_connection(int pid) {
    if (current_pid == pid && transport && transport->is_connected()) {
        return transport->get_fd();
    }

    if (transport) {
        close_connection();
    }

    // Before the command connection: the agent serves one connection at a
    // time and parks this one as soon as it has said hello.
    if (open_event_channel(pid) < 0) {
        return -1;      // nothing is listening for this pid (retried already)
    }

    transport.reset(new UDSTransport("", true));

    char target[64];
    snprintf(target, sizeof(target), "%d", pid);

    int max_retries = 10;
    int retry_delay_ms = 20;

    for (int i = 0; i < max_retries; i++) {
        int fd = transport->connect_to_server(std::string(target));
        if (fd >= 0) {
            current_pid = pid;
            return fd;
        }

        usleep(retry_delay_ms * 1000);
        retry_delay_ms *= 2;
    }

    transport.reset();
    close_event_channel();
    return -1;
}

// 1: open. 0: the agent has no event channel (or it is switched off).
// -1: the agent could not be reached at all.
int SocketHelper::open_event_channel(int pid) {
    close_event_channel();
    if (getenv("RENEF_NO_EVENT_CHANNEL")) return 0;

    int fd = -1;
    int delay_ms = 20;
    for (int i = 0; i < 10 && fd < 0; i++) {
        fd = connect_agent_raw(pid);
        if (fd < 0) {
            usleep(delay_ms * 1000);
            delay_ms *= 2;
        }
    }
    if (fd < 0) return -1;

    static const char hello[] = "@events\n";
    static const char ack[] = "@events ok\n";
    bool ok = send(fd, hello, sizeof(hello) - 1, MSG_NOSIGNAL) == (ssize_t)(sizeof(hello) - 1);
    std::string got;
    // The agent answers after its 50ms "is that the whole command" pause;
    // one that does not know the hello never answers.
    for (int waited = 0; ok && waited < 600 && got.size() < sizeof(ack) - 1; waited += 20) {
        struct pollfd pfd = {fd, POLLIN, 0};
        if (poll(&pfd, 1, 20) > 0) {
            char buf[32];
            ssize_t n = recv(fd, buf, sizeof(ack) - 1 - got.size(), MSG_DONTWAIT);
            if (n > 0) got.append(buf, (size_t)n);
            else if (n == 0) break;
        }
    }
    if (!ok || got != ack) {
        ::close(fd);
        // Let an agent without event support finish with this connection
        // (it treats the close as the end of a session) before the command
        // connection is made.
        usleep(30000);
        return 0;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    event_fd = fd;
    fprintf(stderr, "[SocketHelper] event channel to pid %d open (fd=%d)\n", pid, fd);
    return 1;
}

void SocketHelper::close_event_channel() {
    if (event_fd >= 0) {
        ::close(event_fd);
        event_fd = -1;
    }
    event_buf.clear();
    event_lines = 0;
    event_lines_dropped = 0;
}

void SocketHelper::pump_events() {
    if (event_fd < 0) return;
    char buffer[16384];
    // Bounded: a hook on a hot function can produce output as fast as it is
    // read, and the caller is a command that has to finish.
    for (int rounds = 0; rounds < 256; rounds++) {
        ssize_t n = recv(event_fd, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (n > 0) {
            event_lines += (size_t)std::count(buffer, buffer + n, '\n');
            event_buf.append(buffer, (size_t)n);
            continue;
        }
        if (n == 0) {
            // The agent closed it (target gone, or the session ended).
            ::close(event_fd);
            event_fd = -1;
        }
        break;
    }
    if (event_buf.size() > EVENT_BUF_MAX) {
        // Drop the oldest lines, down to three quarters, so this is not
        // done again for every line that arrives next.
        size_t cut = event_buf.size() - EVENT_BUF_MAX * 3 / 4;
        size_t nl = event_buf.find('\n', cut);
        cut = (nl == std::string::npos) ? event_buf.size() : nl + 1;
        size_t gone = (size_t)std::count(event_buf.begin(), event_buf.begin() + (long)cut, '\n');
        event_buf.erase(0, cut);
        event_lines -= gone;
        event_lines_dropped += gone;
    }
}

std::string SocketHelper::take_events(size_t max_bytes) {
    std::string out;
    if (event_lines_dropped > 0) {
        out = "[dropped " + std::to_string(event_lines_dropped) +
              " older lines, event buffer full]\n";
        event_lines_dropped = 0;
    }
    // Whole lines only: an incomplete last line stays for the next call.
    size_t end = event_buf.rfind('\n');
    if (end == std::string::npos) return out;
    end += 1;
    if (max_bytes != 0 && end > max_bytes) {
        size_t nl = event_buf.rfind('\n', max_bytes - 1);
        // A single line longer than max_bytes is handed out whole.
        end = (nl == std::string::npos) ? event_buf.find('\n') + 1 : nl + 1;
    }
    out.append(event_buf, 0, end);
    event_lines -= (size_t)std::count(event_buf.begin(), event_buf.begin() + (long)end, '\n');
    event_buf.erase(0, end);
    return out;
}

ssize_t SocketHelper::send_data(const void* data, size_t size, bool prefix_key) {
    if (!transport || !transport->is_connected()) {
        return -1;
    }

    // An unframed (legacy) command is about to be sent and its caller will
    // read the socket directly, consuming whatever arrives - including the
    // completion markers of framed requests that were abandoned. Stop
    // waiting for those, or the next framed request would treat all of its
    // own output as belonging to them.
    if (prefix_key) {
        response_reader.forget_outstanding();
    }

    ssize_t result;
    if (prefix_key && !session_key.empty()) {
        std::string full_data = session_key + " " + std::string((const char*)data, size);
        result = transport->send_data(full_data.c_str(), full_data.length());
    } else {
        result = transport->send_data(data, size);
    }

    if (result < 0 && current_pid > 0) {
        fprintf(stderr, "[SocketHelper] send failed, reconnecting to pid %d...\n", current_pid);
        int pid = current_pid;
        close_connection();

        if (ensure_connection(pid) < 0) {
            fprintf(stderr, "[SocketHelper] reconnect failed\n");
            return -1;
        }

        if (!session_key.empty()) {
            std::string con_cmd = "con " + session_key + "\n";
            transport->send_data(con_cmd.c_str(), con_cmd.length());

            char drain[256];
            usleep(50000);
            int old_flags = fcntl(transport->get_fd(), F_GETFL, 0);
            fcntl(transport->get_fd(), F_SETFL, old_flags | O_NONBLOCK);
            while (recv(transport->get_fd(), drain, sizeof(drain), 0) > 0) {}
            fcntl(transport->get_fd(), F_SETFL, old_flags);
        }

        if (prefix_key && !session_key.empty()) {
            std::string full_data = session_key + " " + std::string((const char*)data, size);
            result = transport->send_data(full_data.c_str(), full_data.length());
        } else {
            result = transport->send_data(data, size);
        }
    }

    return result;
}

unsigned long SocketHelper::send_request(const std::string& cmd) {
    if (!transport || !transport->is_connected()) {
        return 0;
    }

    unsigned long id = next_request_id++;
    std::string payload = session_key.empty() ? cmd : (session_key + " " + cmd);
    std::string frame = renef_framing::make_request(id, payload);

    // prefix_key=false: the key is already inside the framed payload.
    // send_data() transparently reconnects on failure; a reconnect means a
    // new agent-side stream, so anything buffered for the old one is void.
    int fd_before = transport->get_fd();
    ssize_t sent = send_data(frame.c_str(), frame.size(), false);
    if (sent < 0) {
        return 0;
    }
    if (!transport || transport->get_fd() != fd_before) {
        response_reader.reset();
    }
    response_reader.sent(id);
    return id;
}

SocketHelper::RecvResult SocketHelper::recv_response(
        unsigned long id, int silence_timeout_ms,
        const std::function<void(const std::string&)>& on_data,
        bool* busy_with_older) {
    if (busy_with_older) *busy_with_older = false;
    if (!transport || !transport->is_connected()) {
        return RecvResult::Closed;
    }
    int fd = transport->get_fd();
    if (fd < 0) return RecvResult::Closed;

    char buffer[8192];
    std::string out;
    int waited_ms = 0;

    for (;;) {
        out.clear();
        bool done = response_reader.poll(id, out);
        if (!out.empty() && on_data) on_data(out);
        if (done) return RecvResult::Done;

        struct pollfd pfd = {fd, POLLIN, 0};
        int ret = poll(&pfd, 1, 100);
        if (ret > 0) {
            ssize_t n = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
            if (n > 0) {
                response_reader.feed(buffer, (size_t)n);
                waited_ms = 0;
            } else if (n == 0) {
                return RecvResult::Closed;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                return RecvResult::Closed;
            }
        } else if (ret == 0) {
            waited_ms += 100;
            if (waited_ms >= silence_timeout_ms) {
                if (busy_with_older) *busy_with_older = response_reader.busy_with_older(id);
                return RecvResult::Timeout;
            }
        } else if (errno != EINTR) {
            return RecvResult::Closed;
        }
    }
}

std::string SocketHelper::read_pending(int wait_ms) {
    std::string out;
    if (!transport || !transport->is_connected()) return out;
    int fd = transport->get_fd();
    if (fd < 0) return out;

    if (event_fd >= 0) {
        // Events have their own connection: hand out what is buffered, or
        // wait for the first ones. A burst is collected for a short moment
        // so one call does not return a single line of many.
        const size_t max_bytes = 256 * 1024;
        pump_events();
        int budget_ms = wait_ms;
        while (event_lines == 0 && event_lines_dropped == 0 && budget_ms > 0 && event_fd >= 0) {
            struct pollfd pfd = {event_fd, POLLIN, 0};
            int step = budget_ms < 50 ? budget_ms : 50;
            if (poll(&pfd, 1, step) > 0) {
                pump_events();
                struct pollfd more = {event_fd, POLLIN, 0};
                for (int i = 0; i < 5 && event_fd >= 0 && event_buf.size() < max_bytes
                                && poll(&more, 1, 30) > 0; i++) {
                    pump_events();
                    more.fd = event_fd;
                }
                break;
            }
            budget_ms -= step;
        }
        out = take_events(max_bytes);
        // Anything unsolicited that still came in on the command socket
        // (output of a request that was given up on).
        response_reader.drain(out);
        return out;
    }

    char buffer[8192];
    int budget_ms = wait_ms;          // until the first byte
    const int quiet_ms = 30;          // "the burst is over"
    // A hook on a hot function produces output without ever going quiet,
    // so "until quiet" alone would never return: also stop after a fixed
    // time / amount once data has started to arrive.
    int collect_budget_ms = 150;
    const size_t max_bytes = 256 * 1024;
    bool got_data = false;

    for (;;) {
        response_reader.drain(out);
        if (!out.empty()) got_data = true;
        if (out.size() >= max_bytes) break;

        struct pollfd pfd = {fd, POLLIN, 0};
        int step = got_data ? quiet_ms : (budget_ms < 50 ? budget_ms : 50);
        if (step < 0) step = 0;
        int ret = poll(&pfd, 1, step);
        if (ret > 0) {
            ssize_t n = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
            if (n > 0) {
                response_reader.feed(buffer, (size_t)n);
                if (got_data) {
                    collect_budget_ms -= 5;   // each further chunk eats into the burst budget
                    if (collect_budget_ms <= 0) break;
                }
                continue;
            }
            // Readable but nothing to read (peer gone, or an error state
            // poll keeps reporting): stop instead of spinning on it.
            break;
        } else if (ret == 0) {
            if (got_data) break;
            budget_ms -= step;
            if (budget_ms <= 0) break;
        } else if (errno != EINTR) {
            break;
        }
    }
    response_reader.drain(out);
    return out;
}

ssize_t SocketHelper::receive_data(void* buffer, size_t size) {
    if (!transport || !transport->is_connected()) {
        return -1;
    }
    return transport->receive_data(buffer, size);
}

void SocketHelper::drain_buffer() {
    if (!transport || !transport->is_connected()) return;

    int fd = transport->get_fd();
    if (fd < 0) return;

    int old_flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, old_flags | O_NONBLOCK);

    char drain[4096];
    for (int i = 0; i < 50; i++) {
        struct pollfd pfd = {fd, POLLIN, 0};
        int ret = poll(&pfd, 1, 10);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = recv(fd, drain, sizeof(drain), 0);
            if (n <= 0) break;
        } else {
            break;
        }
    }

    fcntl(fd, F_SETFL, old_flags);
}

bool SocketHelper::is_connected() const {
    return transport && transport->is_connected();
}

int SocketHelper::get_socket_fd() const {
    return transport ? transport->get_fd() : -1;
}

void SocketHelper::close_connection() {
    response_reader.reset();
    close_event_channel();
    if (transport) {
        transport->close();
        transport.reset();
        current_pid = -1;
    }
}

void SocketHelper::set_session_key(std::string key) {
    session_key = key;
}

std::string SocketHelper::get_session_key() {
    return session_key;
}
