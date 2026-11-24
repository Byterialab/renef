// Host-side self-test for the request framing (src/librenef/include/renef/framing.h).
// Feeds a response stream to ResponseReader in every chunk size from 1 to 80 bytes,
// with and without output left behind by an abandoned request.
//
// Build & run (no device needed):
//   c++ -std=c++17 -I src/librenef/include tests/framing_selftest.cpp -o /tmp/framing_selftest && /tmp/framing_selftest
#include <renef/framing.h>
#include <cassert>
#include <cstdio>
#include <string>
#include <algorithm>
using namespace renef_framing;
static std::string run(const std::string& stream, size_t chunk, unsigned long want, std::deque<unsigned long> sent, bool* done) {
    ResponseReader r; for (auto id : sent) r.sent(id);
    std::string out; *done = false;
    for (size_t i = 0; i < stream.size() && !*done; i += chunk) {
        r.feed(stream.data() + i, std::min(chunk, stream.size() - i));
        *done = r.poll(want, out);
    }
    return out;
}
int main() {
    std::string stale = "[event] {\"value\":99}\nOK\n" + make_done(57);
    std::string mine = "[event] {\"value\":6}\nOK\n" + make_done(58);
    std::string next = "late hook output\n";
    int bad = 0;
    for (size_t chunk = 1; chunk <= 80; chunk++) {
        bool done;
        std::string out = run(stale + mine + next, chunk, 58, {57, 58}, &done);
        if (!done || out != "[event] {\"value\":6}\nOK\n") { bad++; printf("chunk=%zu done=%d out=%s\n", chunk, done, out.c_str()); }
        out = run(mine, chunk, 58, {58}, &done);
        if (!done || out != "[event] {\"value\":6}\nOK\n") { bad++; printf("single chunk=%zu done=%d\n", chunk, done); }
    }
    // drain(): output that arrives while no request is being waited for
    for (size_t chunk = 1; chunk <= 60; chunk++) {
        ResponseReader r; r.sent(41);
        std::string stream = "hook line 1\n" + make_done(41) + "[event] {\"n\":1}\nhook line 2\n";
        std::string out;
        for (size_t i = 0; i < stream.size(); i += chunk) {
            r.feed(stream.data() + i, std::min(chunk, stream.size() - i));
            r.drain(out);
        }
        if (out != "hook line 1\n[event] {\"n\":1}\nhook line 2\n") { bad++; printf("drain chunk=%zu out=%s\n", chunk, out.c_str()); }
        // the abandoned request's marker was consumed: a new request is not held up by it
        if (r.busy_with_older(42)) { bad++; printf("drain chunk=%zu: stale id still outstanding\n", chunk); }
    }

    // request framing
    std::string buf = make_request(7, "rpc 3+3\n") + make_request(8, "ping\n"); unsigned long id = 0; std::string payload;
    assert(take_request(buf, id, payload) == 1 && id == 7 && payload == "rpc 3+3\n");
    assert(take_request(buf, id, payload) == 1 && id == 8 && payload == "ping\n" && buf.empty());
    std::string partial = "@req 9 10\nabc"; assert(take_request(partial, id, payload) == 0);
    std::string legacy = "ping\n"; assert(take_request(legacy, id, payload) == -1);
    // "ev=<n>" on the marker: hook output waiting on the responder's side
    for (size_t chunk = 1; chunk <= 40; chunk++) {
        ResponseReader r; r.sent(7); r.sent(8);
        std::string stream = "a\n" + make_done(7, 1234) + "b\n" + make_done(8);
        if (make_done(8) != std::string("\x1e@done 8\n") ||
            make_done(7, 1234) != std::string("\x1e@done 7 ev=1234\n")) { bad++; printf("make_done format\n"); }
        std::string out, o8;
        bool done7 = false, done8 = false;
        unsigned long ev7 = 99, ev8 = 99;
        for (size_t off = 0; off < stream.size(); off += chunk) {
            r.feed(stream.data() + off, std::min(chunk, stream.size() - off));
            if (!done7) { if (r.poll(7, out)) { done7 = true; ev7 = r.pending_events(); } }
            if (done7 && !done8) { if (r.poll(8, o8)) { done8 = true; ev8 = r.pending_events(); out += "|" + o8; } }
        }
        if (!done7 || !done8 || ev7 != 1234 || ev8 != 0 || out != "a\n|b\n") {
            bad++; printf("ev chunk=%zu done=%d/%d ev=%lu/%lu out=%s\n", chunk, done7, done8, ev7, ev8, out.c_str());
        }
    }

    printf("framing self-test: %s (%d failures)\n", bad ? "FAIL" : "PASS", bad);
    return bad != 0;
}
