#pragma once
// Shared by the commands that run Lua in the target (exec, rpc, l):
// framed request to the agent + bounded wait for its completion marker.
// See renef/framing.h.
#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>

extern bool ptrace_resume(int pid);

namespace renef_agent_request {

// How long to wait WITHOUT ANY DATA from the agent before giving up on a
// request (it resets whenever output arrives). Overridable per command
// with a leading "--timeout <seconds> ". The old value was a hard-coded
// 5s, which made any call that legitimately takes longer (a real network
// request, a slow decryption routine) fail.
static const int DEFAULT_SILENCE_TIMEOUT_MS = 30000;

// Strips a leading "--timeout <seconds> " from `args` (in place) and
// returns the timeout in ms, or DEFAULT_SILENCE_TIMEOUT_MS if absent.
inline int take_timeout_flag(std::string& args) {
    static const char FLAG[] = "--timeout ";
    const size_t flag_len = sizeof(FLAG) - 1;
    if (args.compare(0, flag_len, FLAG) != 0) return DEFAULT_SILENCE_TIMEOUT_MS;
    char* end = nullptr;
    long secs = std::strtol(args.c_str() + flag_len, &end, 10);
    if (!end || end == args.c_str() + flag_len || secs <= 0) return DEFAULT_SILENCE_TIMEOUT_MS;
    size_t consumed = (size_t)(end - args.c_str());
    while (consumed < args.size() && args[consumed] == ' ') consumed++;
    args.erase(0, consumed);
    if (secs > 3600) secs = 3600;
    return (int)(secs * 1000);
}

struct Outcome {
    bool sent = false;        // request reached the agent socket
    bool done = false;        // completion marker received
    bool closed = false;      // agent connection dropped while waiting
    bool busy_older = false;  // timed out while the agent was still on an earlier request
};

// Sends `agent_cmd` as a framed request and feeds its output to `on_data`
// until the agent's completion marker. Handles the --pause spawn gate the
// same way the three commands always did: the target is ptrace-stopped,
// so give the agent a short moment to run the script, then resume the
// process - and (new) keep waiting for the marker afterwards instead of
// abandoning the response.
//
// may_resume=false is for commands that merely query the agent (hooks,
// unhook, verbose): they must never open the gate. The gate also stays
// shut for everything while it is held explicitly (`spawn --pause --hold`,
// CommandRegistry::gate_hold) - then only the `resume` command opens it.
inline Outcome run(SocketHelper& sh, int pid, const std::string& agent_cmd, int silence_timeout_ms,
                   const std::function<void(const std::string&)>& on_data, bool may_resume = true) {
    Outcome o;
    unsigned long id = sh.send_request(agent_cmd);
    if (id == 0) return o;
    o.sent = true;

    int gated = CommandRegistry::instance().gated_pid;
    bool need_resume = (gated > 0 && gated == pid) && may_resume &&
                       !CommandRegistry::instance().gate_hold;

    SocketHelper::RecvResult r;
    if (need_resume) {
        r = sh.recv_response(id, 500, on_data, nullptr);
        fprintf(stderr, "[spawn-gate] Script delivered, resuming (pid=%d)\n", gated);
        ptrace_resume(gated);
        CommandRegistry::instance().gated_pid = -1;
        if (r == SocketHelper::RecvResult::Timeout) {
            r = sh.recv_response(id, silence_timeout_ms, on_data, &o.busy_older);
        }
    } else {
        r = sh.recv_response(id, silence_timeout_ms, on_data, &o.busy_older);
    }

    o.done = (r == SocketHelper::RecvResult::Done);
    o.closed = (r == SocketHelper::RecvResult::Closed);
    return o;
}

inline std::string timeout_message(const char* what, const Outcome& o, int silence_timeout_ms) {
    std::string m = std::string("ERROR: ") + what + " got no completion from target";
    if (o.closed) {
        m += " (agent connection closed)";
    } else if (o.busy_older) {
        m += " (target is still busy with an earlier command)";
    } else {
        m += " after " + std::to_string(silence_timeout_ms / 1000) +
             "s without output (still running? use --timeout <seconds>)";
    }
    return m + "\n";
}

} // namespace renef_agent_request
