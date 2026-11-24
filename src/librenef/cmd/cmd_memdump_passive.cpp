// cmd_memdump_passive.cpp - injection-free, read-only memory access.
//
// This command does not touch the agent and injects nothing into the target:
// - it lists address ranges by reading /proc/<pid>/maps directly
// - it reads the requested range from /proc/<pid>/mem, opened O_RDONLY,
//   with pread()
//
// No ptrace() call is made, there is no SIGSTOP/PTRACE_ATTACH, and the
// target's code and data are not modified. renef_server runs as root, so it
// passes the kernel's ptrace_may_access() check through CAP_SYS_PTRACE.
// ("Read-only" is not the same as "undetectable": the read is still subject
// to SELinux and PR_SET_DUMPABLE, and no universal guarantee is given.)
//
// Syntax (host -> server, over the ordinary CommandDispatcher protocol):
//   memdump <pid> --maps
//   memdump <pid> <start_hex>-<end_hex>
//
// The output is always plain text (newline-delimited, no NUL bytes): raw
// bytes are never written to the socket, they are hex-encoded, so the reply
// survives any text-based transport.

#include <renef/cmd.h>
#include <renef/string_utils.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <sstream>
#include <fstream>
#include <vector>

namespace {

// Maximum bytes a single range request may cover. Mirrors the project's
// existing convention of capping bounded /proc scans (see Memory.search,
// AGENTS.md "Gotchas") — this is a synchronous text protocol, not a stream,
// so we keep requests bounded.
constexpr size_t MAX_MEMDUMP_BYTES = 4ull * 1024 * 1024; // 4 MiB

// Chunk size used for each pread() attempt. Not a hard page boundary — just
// an efficiency knob. Partial/failed reads are reported at whatever
// granularity the kernel actually gives us.
constexpr size_t READ_CHUNK = 64 * 1024;

// Fingerprint accumulation uses FNV-1a 64-bit, folded incrementally as bytes
// are read (see dump_range()) purely so the host side can confirm the hex
// payload it decoded matches what the server actually read (transport-
// corruption check). Not a security primitive.

void send_line(int fd, const std::string& line) {
    std::string out = line;
    if (out.empty() || out.back() != '\n') out += '\n';
    write(fd, out.c_str(), out.length());
}

// Reads /proc/<pid>/stat and extracts comm (field 2) + starttime (field 22).
// Returns false if the process doesn't exist / stat can't be parsed.
bool read_proc_identity(int pid, std::string& comm_out, unsigned long long& starttime_out) {
    std::string path = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream f(path);
    if (!f.is_open()) return false;

    std::string line;
    if (!std::getline(f, line)) return false;

    size_t open_paren = line.find('(');
    size_t close_paren = line.rfind(')');
    if (open_paren == std::string::npos || close_paren == std::string::npos || close_paren < open_paren) {
        return false;
    }

    comm_out = line.substr(open_paren + 1, close_paren - open_paren - 1);

    std::string rest = line.substr(close_paren + 1);
    std::istringstream iss(rest);
    std::vector<std::string> fields;
    std::string tok;
    while (iss >> tok) fields.push_back(tok);

    // fields[0] = state(3), ... fields[19] = starttime(22) — 20 fields between
    // state and starttime inclusive.
    if (fields.size() < 20) return false;

    try {
        starttime_out = std::stoull(fields[19]);
    } catch (...) {
        return false;
    }
    return true;
}

class MemDumpPassiveCommand : public CommandDispatcher {
public:
    std::string get_name() const override { return "memdump"; }

    std::string get_description() const override {
        return "Injection-free passive memory read via /proc/<pid>/mem "
               "(memdump <pid> --maps | memdump <pid> <start>-<end>)";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        std::vector<std::string> parts = split(std::string(cmd_buffer, cmd_size), ' ');

        if (parts.size() < 3) {
            send_line(client_fd, "MEMDUMP_ERROR reason=usage_memdump_<pid>_--maps_or_<start>-<end>");
            return CommandResult(false, "Invalid arguments");
        }

        int pid = 0;
        try {
            pid = std::stoi(parts[1]);
        } catch (...) {
            send_line(client_fd, "MEMDUMP_ERROR reason=invalid_pid");
            return CommandResult(false, "Invalid pid");
        }
        if (pid <= 0) {
            send_line(client_fd, "MEMDUMP_ERROR reason=invalid_pid");
            return CommandResult(false, "Invalid pid");
        }

        std::string comm;
        unsigned long long starttime = 0;
        if (!read_proc_identity(pid, comm, starttime)) {
            send_line(client_fd, "MEMDUMP_ERROR pid=" + std::to_string(pid) +
                                  " reason=process_not_found_or_unreadable_proc_stat");
            return CommandResult(false, "No such process");
        }

        std::string mode = parts[2];

        if (mode == "--maps") {
            return dump_maps(client_fd, pid, comm, starttime);
        }

        return dump_range(client_fd, pid, comm, starttime, mode);
    }

private:
    // --- mode 1: list ranges, no /proc/<pid>/mem touched at all -----------
    CommandResult dump_maps(int client_fd, int pid, const std::string& comm,
                             unsigned long long starttime) {
        std::string path = "/proc/" + std::to_string(pid) + "/maps";
        std::ifstream f(path);
        if (!f.is_open()) {
            send_line(client_fd, "MEMDUMP_ERROR pid=" + std::to_string(pid) +
                                  " reason=cannot_open_proc_maps errno=" + std::to_string(errno));
            return CommandResult(false, "Cannot open maps");
        }

        std::ostringstream header;
        header << "MEMDUMP_MAPS pid=" << pid << " starttime=" << starttime
               << " comm=" << comm;
        send_line(client_fd, header.str());

        std::string line;
        size_t total = 0;
        while (std::getline(f, line)) {
            send_line(client_fd, line);
            total += line.size();
            // maps files are tiny in practice, but keep this bounded too.
            if (total > MAX_MEMDUMP_BYTES) {
                send_line(client_fd, "MEMDUMP_ERROR reason=maps_truncated_too_large");
                break;
            }
        }

        send_line(client_fd, "MEMDUMP_END");
        return CommandResult(true, "maps listed, no injection, no ptrace");
    }

    // --- mode 2: read [start,end) from /proc/<pid>/mem, O_RDONLY, no ptrace ---
    CommandResult dump_range(int client_fd, int pid, const std::string& comm,
                              unsigned long long starttime, const std::string& range_str) {
        size_t dash = range_str.find('-');
        if (dash == std::string::npos || dash == 0 || dash + 1 >= range_str.size()) {
            send_line(client_fd, "MEMDUMP_ERROR reason=invalid_range_use_<start>-<end>_hex");
            return CommandResult(false, "Invalid range");
        }

        uint64_t start = 0, end = 0;
        try {
            start = std::stoull(range_str.substr(0, dash), nullptr, 16);
            end = std::stoull(range_str.substr(dash + 1), nullptr, 16);
        } catch (...) {
            send_line(client_fd, "MEMDUMP_ERROR reason=invalid_range_hex_parse_failed");
            return CommandResult(false, "Invalid range");
        }

        if (end <= start) {
            send_line(client_fd, "MEMDUMP_ERROR reason=end_must_be_greater_than_start");
            return CommandResult(false, "Invalid range");
        }

        uint64_t requested = end - start;
        if (requested > MAX_MEMDUMP_BYTES) {
            send_line(client_fd, "MEMDUMP_ERROR reason=requested_too_large max=" +
                                  std::to_string(MAX_MEMDUMP_BYTES));
            return CommandResult(false, "Range too large");
        }

        std::string mem_path = "/proc/" + std::to_string(pid) + "/mem";
        // O_RDONLY only — never O_RDWR. No PTRACE_ATTACH anywhere in this path.
        int mem_fd = open(mem_path.c_str(), O_RDONLY);
        if (mem_fd < 0) {
            send_line(client_fd, "MEMDUMP_ERROR pid=" + std::to_string(pid) +
                                  " reason=open_proc_mem_failed errno=" + std::to_string(errno) +
                                  " msg=" + strerror(errno));
            return CommandResult(false, "Cannot open /proc/pid/mem");
        }

        std::ostringstream header;
        header << "MEMDUMP_MANIFEST pid=" << pid << " starttime=" << starttime
               << " comm=" << comm << " start=0x" << std::hex << start
               << " end=0x" << end << std::dec << " requested=" << requested;
        send_line(client_fd, header.str());

        uint64_t offset = start;
        uint64_t remaining = requested;
        uint64_t total_read = 0;
        int segments_ok = 0, segments_err = 0;
        uint64_t hash_acc = 0xcbf29ce484222325ull; // combined over all OK bytes, in order

        std::vector<uint8_t> buf(READ_CHUNK);

        while (remaining > 0) {
            size_t want = (size_t)std::min<uint64_t>(remaining, READ_CHUNK);
            ssize_t n = pread(mem_fd, buf.data(), want, (off_t)offset);

            if (n > 0) {
                std::string chunk_hex = hex_encode(std::string(reinterpret_cast<char*>(buf.data()), (size_t)n));
                std::ostringstream seg;
                seg << "SEG OK start=0x" << std::hex << offset << std::dec
                    << " len=" << n << " hex=" << chunk_hex;
                send_line(client_fd, seg.str());

                // fold into the running fingerprint without re-hashing from scratch
                for (ssize_t i = 0; i < n; i++) {
                    hash_acc ^= buf[i];
                    hash_acc *= 0x100000001b3ull;
                }
                segments_ok++;
                offset += (uint64_t)n;
                remaining -= (uint64_t)n;
                total_read += (uint64_t)n;
            } else {
                int err = (n == 0) ? 0 : errno;
                const char* msg = (n == 0) ? "EOF/unmapped" : strerror(errno);
                // Report the whole attempted window as unreadable at this
                // offset, then skip forward one page so a single bad page
                // (permission/swap/unmapped) doesn't stall the whole dump.
                size_t skip = std::min<uint64_t>(remaining, 4096);
                std::ostringstream seg;
                seg << "SEG ERR start=0x" << std::hex << offset << std::dec
                    << " len=" << skip << " errno=" << err << " msg=" << msg;
                send_line(client_fd, seg.str());

                segments_err++;
                offset += skip;
                remaining -= skip;
            }
        }

        close(mem_fd);

        std::ostringstream summary;
        summary << "MEMDUMP_SUMMARY total_requested=" << requested
                << " total_read=" << total_read
                << " segments_ok=" << segments_ok
                << " segments_err=" << segments_err
                << " hash=" << std::hex << hash_acc << std::dec;
        send_line(client_fd, summary.str());
        send_line(client_fd, "MEMDUMP_END");

        bool any_read = total_read > 0;
        return CommandResult(any_read, any_read ? "memdump complete (no injection, no ptrace)"
                                                 : "memdump failed: nothing readable");
    }
};

} // namespace

std::unique_ptr<CommandDispatcher> create_memdump_passive_command() {
    return std::make_unique<MemDumpPassiveCommand>();
}
