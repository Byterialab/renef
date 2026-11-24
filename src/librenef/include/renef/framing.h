#pragma once
// Request framing shared by both hops of the wire protocol
// (host <-> renef_server and renef_server <-> agent).
//
// The original protocol has no message boundaries at all: a command is
// "whatever arrived until a chunk ended in '\n' and 50ms passed", and a
// response is "whatever arrived until the line went quiet". Two real bugs
// follow directly from that, both reproduced on a device:
//   - a reply that arrives after its requester gave up is read as the
//     reply to the NEXT command (an 8s `rpc` followed by `rpc 2+2`
//     answered 42, the previous call's result);
//   - output that pauses for longer than the quiet window is split across
//     two commands.
//
// Framing is opt-in per request, so peers that do not know it (older
// clients such as r2renef, older agents) keep working unchanged:
//
//   request :  "@req <id> <len>\n"  followed by exactly <len> bytes
//   response:  <everything the command wrote>  "\x1e@done <id>\n"
//
// On the host <-> server hop the marker may carry one more field,
// "\x1e@done <id> ev=<n>\n": <n> lines of hook/trace output are waiting in
// the server's event buffer (they are not part of any reply; `events` and
// `watch` deliver them). The field is left out when <n> is 0.
//
// <id> is a positive decimal chosen by the requester, increasing per
// connection. A responder handles requests strictly in order, so
// everything received before "@done <id>" was produced while <id> (or an
// older, abandoned request) was running.
#include <cstdlib>
#include <cstring>
#include <deque>
#include <string>

namespace renef_framing {

static const char REQ_PREFIX[] = "@req ";
static const size_t REQ_PREFIX_LEN = 5;
static const char DONE_MARK[] = "\x1e@done ";
static const size_t DONE_MARK_LEN = 7;

inline std::string make_request(unsigned long id, const std::string& payload) {
    std::string out = std::string(REQ_PREFIX) + std::to_string(id) + " " +
                      std::to_string(payload.size()) + "\n";
    out += payload;
    return out;
}

inline std::string make_done(unsigned long id, unsigned long pending_events = 0) {
    std::string out = std::string(DONE_MARK) + std::to_string(id);
    if (pending_events > 0) out += " ev=" + std::to_string(pending_events);
    return out + "\n";
}

// Value of the "ev=<n>" field of a marker line [line, line + len), 0 if absent.
inline unsigned long marker_pending_events(const char* line, size_t len) {
    static const char KEY[] = " ev=";
    for (size_t i = 0; i + 4 < len; i++) {
        if (std::memcmp(line + i, KEY, 4) == 0) {
            return std::strtoul(line + i + 4, nullptr, 10);
        }
    }
    return 0;
}

// If `buf` starts with a complete request frame, moves its payload into
// `payload`, sets `id`, erases the frame from `buf` and returns 1.
// Returns 0 if `buf` starts with a frame header but more bytes are needed,
// -1 if it does not start with a frame header (legacy command) or the
// header is malformed (`malformed` set in that case).
inline int take_request(std::string& buf, unsigned long& id, std::string& payload,
                        bool* malformed = nullptr, size_t max_len = 8 * 1024 * 1024) {
    if (malformed) *malformed = false;
    if (buf.size() < REQ_PREFIX_LEN) {
        // Could still become a header once more bytes arrive.
        return (std::memcmp(buf.data(), REQ_PREFIX, buf.size()) == 0 && !buf.empty()) ? 0 : -1;
    }
    if (std::memcmp(buf.data(), REQ_PREFIX, REQ_PREFIX_LEN) != 0) return -1;

    size_t nl = buf.find('\n');
    if (nl == std::string::npos) {
        if (buf.size() > 64) { if (malformed) *malformed = true; return -1; }
        return 0;
    }
    char* end = nullptr;
    unsigned long rid = std::strtoul(buf.c_str() + REQ_PREFIX_LEN, &end, 10);
    if (rid == 0 || !end || *end != ' ') { if (malformed) *malformed = true; return -1; }
    char* end2 = nullptr;
    unsigned long len = std::strtoul(end + 1, &end2, 10);
    if (!end2 || end2 != buf.c_str() + nl || len > max_len) {
        if (malformed) *malformed = true;
        return -1;
    }
    if (buf.size() < nl + 1 + len) return 0;

    id = rid;
    payload.assign(buf, nl + 1, len);
    buf.erase(0, nl + 1 + len);
    return 1;
}

// Requester side: demultiplexes a response byte stream by request id.
class ResponseReader {
public:
    void sent(unsigned long id) { outstanding_.push_back(id); }
    void feed(const char* data, size_t n) { buf_.append(data, n); }
    void reset() { buf_.clear(); outstanding_.clear(); }
    // Forget abandoned requests (used when the stream is about to be read
    // by code that does not understand framing).
    void forget_outstanding() { outstanding_.clear(); }

    // True while a request older than `id` has not completed yet, i.e. the
    // responder is still busy with something the requester gave up on.
    bool busy_with_older(unsigned long id) const {
        return !outstanding_.empty() && outstanding_.front() < id;
    }

    // "ev=<n>" of the marker that completed the last request: lines of
    // hook/trace output waiting on the responder's side.
    unsigned long pending_events() const { return pending_events_; }

    // Consumes buffered bytes on behalf of request `id`. Bytes that belong
    // to `id` are appended to `out`; bytes that belong to an older
    // (abandoned) request are discarded. Returns true once the completion
    // marker of `id` has been consumed.
    bool poll(unsigned long id, std::string& out) {
        for (;;) {
            size_t p = buf_.find(DONE_MARK, 0, DONE_MARK_LEN);
            size_t nl = (p == std::string::npos) ? std::string::npos : buf_.find('\n', p);

            if (p == std::string::npos || nl == std::string::npos) {
                // No complete marker yet. Everything up to a possible
                // partial marker at the tail can be handed out now.
                size_t limit = (p != std::string::npos) ? p : buf_.size() - partial_marker_suffix();
                take_segment(limit, id, out);
                return false;
            }

            unsigned long mid = std::strtoul(buf_.c_str() + p + DONE_MARK_LEN, nullptr, 10);
            // Length of the marker line, taken BEFORE take_segment() erases
            // the p bytes in front of it. (Erasing `nl + 1` bytes afterwards
            // removed p bytes too many - i.e. the beginning of the NEXT
            // response, including the first byte of its marker, whenever an
            // abandoned request had left output behind.)
            size_t marker_len = nl + 1 - p;
            unsigned long pending = marker_pending_events(buf_.c_str() + p, marker_len);
            take_segment(p, id, out);     // output produced while `mid` (or older) ran
            buf_.erase(0, marker_len);    // drop the marker line itself
            if (mid == id) pending_events_ = pending;
            while (!outstanding_.empty() && outstanding_.front() <= mid) outstanding_.pop_front();
            if (mid == id) return true;
            // Marker of an abandoned request: keep going.
        }
    }

    // Hands out everything buffered that is not part of a completion
    // marker - output that arrived while no request was being waited for
    // (e.g. hook callbacks printing between commands). Markers of
    // abandoned requests found on the way are consumed and dropped.
    void drain(std::string& out) {
        for (;;) {
            size_t p = buf_.find(DONE_MARK, 0, DONE_MARK_LEN);
            size_t nl = (p == std::string::npos) ? std::string::npos : buf_.find('\n', p);
            if (p == std::string::npos || nl == std::string::npos) {
                size_t limit = (p != std::string::npos) ? p : buf_.size() - partial_marker_suffix();
                out.append(buf_, 0, limit);
                buf_.erase(0, limit);
                return;
            }
            unsigned long mid = std::strtoul(buf_.c_str() + p + DONE_MARK_LEN, nullptr, 10);
            size_t marker_len = nl + 1 - p;
            out.append(buf_, 0, p);
            buf_.erase(0, p + marker_len);
            while (!outstanding_.empty() && outstanding_.front() <= mid) outstanding_.pop_front();
        }
    }

private:
    // Hands out (or discards) buf_[0, n) and erases it.
    void take_segment(size_t n, unsigned long id, std::string& out) {
        if (n == 0) return;
        bool mine = outstanding_.empty() || outstanding_.front() >= id;
        if (mine) out.append(buf_, 0, n);
        buf_.erase(0, n);
    }

    // Length of the longest suffix of buf_ that is a proper prefix of
    // DONE_MARK (a marker split across two reads).
    size_t partial_marker_suffix() const {
        size_t max = buf_.size() < DONE_MARK_LEN - 1 ? buf_.size() : DONE_MARK_LEN - 1;
        for (size_t k = max; k > 0; k--) {
            if (std::memcmp(buf_.data() + buf_.size() - k, DONE_MARK, k) == 0) return k;
        }
        return 0;
    }

    std::string buf_;
    std::deque<unsigned long> outstanding_;
    unsigned long pending_events_ = 0;
};

} // namespace renef_framing
