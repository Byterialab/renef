#pragma once

#include <string>
#include <memory>
#include <map>
#include <vector>
#include <renef/socket_helper.h>

struct CommandResult {
    bool success;
    std::string output;

    CommandResult(bool ok = true, const std::string& msg = "")
        : success(ok), output(msg) {}
};

inline std::string extract_filter(const char* cmd_buffer, size_t cmd_size) {
    std::string cmd(cmd_buffer, cmd_size);
    size_t tilde_pos = cmd.find('~');
    if (tilde_pos != std::string::npos) {
        return cmd.substr(tilde_pos);  // Returns "~pattern"
    }
    return "";
}

inline std::string build_agent_command(const std::string& agent_cmd, const std::string& filter) {
    return agent_cmd + filter + "\n";
}

class CommandDispatcher {
public:
    virtual ~CommandDispatcher() = default;

    virtual CommandResult dispatch(
        int client_fd,
        const char* cmd_buffer,
        size_t cmd_size) = 0;

    virtual std::string get_name() const = 0;

    virtual std::string get_description() const = 0;
};

class CommandRegistry {
public:

    static CommandRegistry& instance() {
        static CommandRegistry registry;
        return registry;
    }


    int current_pid = -1;
    int gated_pid = -1;  // PID that is SIGSTOP'd waiting for first exec
    // Spawn gate held open explicitly (`spawn ... --pause --hold`): exec/rpc/l
    // do NOT resume the target on their own, only the `resume` command does.
    // For scripted clients that need several round trips (install support
    // code, resolve symbols, register hooks) while the app is still frozen.
    bool gate_hold = false;
    SocketHelper sock;

    int get_current_pid() const;
    void set_current_pid(int pid);

    void register_command(std::unique_ptr<CommandDispatcher> cmd);
    bool unregister_command(const std::string& name);

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size);

    // The classic fixed-name lookup + dispatch, with
    // no claim-model plugin check. dispatch() calls this after no loaded
    // claim-model plugin (see plugin_find_claim() in plugin.h/plugin.cpp)
    // wants the raw input. Also exposed so ren_dispatch() (plugin.cpp) can
    // let a claim-model plugin run a command through the normal path
    // (e.g. to wrap/pass-through) without re-entering the claim check and
    // risking self-recursion.
    CommandResult dispatch_fixed(int client_fd, const char* cmd_buffer, size_t cmd_size);

    void setup_all_commands();
    bool is_command_exist(const std::string& name);

    std::vector<std::pair<std::string, std::string>> get_all_commands_with_descriptions() const;


    SocketHelper& get_socket_helper();

private:
    CommandRegistry() = default;

    CommandRegistry(const CommandRegistry&) = delete;
    CommandRegistry& operator=(const CommandRegistry&) = delete;

    std::map<std::string, std::unique_ptr<CommandDispatcher>> commands;
};
