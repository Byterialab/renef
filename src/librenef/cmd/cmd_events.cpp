#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

// `events [wait_ms]` -- hand over whatever the agent has written on its
// own since the last command: output of hook callbacks (print/console.log)
// and send() events ("[event] {...}" lines) that fired while no command
// was running.
//
// Before this, such output could only be read by entering the streaming
// `watch` mode (which blocks the connection for anything else) or it
// showed up glued to the front of whichever command happened to run next.
// A scripted client -- the Python binding's event/callback dispatch -- needs
// a bounded, non-streaming way to ask for it: wait up to wait_ms for the
// first byte (default 0 = only what is already there, capped at 30s),
// return it, done. With a framed request the reply ends at the completion
// marker even when it is empty.
class EventsCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "events";
    }

    std::string get_description() const override {
        return "Return pending hook output/events from the target: events [wait_ms]";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        int pid = CommandRegistry::instance().get_current_pid();
        if (pid <= 0) {
            const char* error_msg = "ERROR: No target PID set. Please attach/spawn first.\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "No target PID set");
        }

        std::string full(cmd_buffer, cmd_size);
        size_t space = full.find(' ');
        long wait_ms = 0;
        if (space != std::string::npos) {
            wait_ms = std::strtol(full.c_str() + space + 1, nullptr, 10);
        }
        if (wait_ms < 0) wait_ms = 0;
        if (wait_ms > 30000) wait_ms = 30000;

        SocketHelper& socket_helper = CommandRegistry::instance().get_socket_helper();
        if (socket_helper.ensure_connection(pid) < 0) {
            const char* error_msg = "ERROR: Failed to connect to agent\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "Socket connection failed");
        }

        std::string pending = socket_helper.read_pending((int)wait_ms);
        if (!pending.empty()) {
            write(client_fd, pending.data(), pending.size());
        }
        return CommandResult(true, "Events delivered");
    }
};

std::unique_ptr<CommandDispatcher> create_events_command() {
    return std::make_unique<EventsCommand>();
}
