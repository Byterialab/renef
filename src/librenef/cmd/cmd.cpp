#include <renef/cmd.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>

// The claim-model check below needs plugin_find_claim()
// from src/librenef/plugin/plugin.cpp. That file -- and the whole plugin
// subsystem -- is intentionally NOT part of the on-device renef_server build
// (see SERVER_SRCS in Makefile: it reuses this same cmd.cpp for its own
// CommandRegistry, but never links plugin.cpp -- "renef_server has no plugin
// support at all", per the existing comment in main.cpp). RENEF_HAS_PLUGINS
// is defined only for targets that DO link plugin.cpp (the host CLI client
// via CMakeLists.txt's renef_core, and the Android on-device CLI client via
// Makefile's CLIENT_ANDROID_SRCS/CLIENT_ANDROID_CXXFLAGS) so this file can be
// shared, unmodified, by both the server (classic fixed-name dispatch only)
// and every plugin-capable client (fixed-name dispatch + claim-model check).
#ifdef RENEF_HAS_PLUGINS
#include <renef/plugin.h>
#endif

// Forward declarations for command classes
class PingCommand;
class AttachCommand;
class SpawnCommand;
class ListAppsCommand;
class InspectBinary;
class Eval;
class LoadScriptCommand;
class WatchCommand;
class MemScan;
class MemScanJson;
class HooksCommand;
class UnhookCommand;
class SecCommand;
class MemDumpCommand;
class HookGen;

// These are implemented in separate cmd_*.cpp files
std::unique_ptr<CommandDispatcher> create_ping_command();
std::unique_ptr<CommandDispatcher> create_attach_command();
std::unique_ptr<CommandDispatcher> create_spawn_command();
std::unique_ptr<CommandDispatcher> create_list_command();
std::unique_ptr<CommandDispatcher> create_inspect_command();
std::unique_ptr<CommandDispatcher> create_eval_command();
std::unique_ptr<CommandDispatcher> create_load_command();
std::unique_ptr<CommandDispatcher> create_watch_command();
std::unique_ptr<CommandDispatcher> create_memscan_command();
std::unique_ptr<CommandDispatcher> create_memscanjson_command();
std::unique_ptr<CommandDispatcher> create_hooks_command();
std::unique_ptr<CommandDispatcher> create_unhook_command();
std::unique_ptr<CommandDispatcher> create_sec_command();
std::unique_ptr<CommandDispatcher> create_memdump_command();
std::unique_ptr<CommandDispatcher> create_memdump_passive_command();
std::unique_ptr<CommandDispatcher> create_hookgen_command();
std::unique_ptr<CommandDispatcher> create_rpc_command();
std::unique_ptr<CommandDispatcher> create_events_command();
// Host-tooling-only (spawns a LOCAL MCP server
// subprocess via /bin/sh -- meaningless on the Android device, which
// has no "/bin/sh" and no static-analysis MCP servers to connect to
// anyway). Gated the same way the plugin system is: available to the
// host CLI and the on-device CLI client, not renef_server.
#ifdef RENEF_HAS_PLUGINS
std::unique_ptr<CommandDispatcher> create_mcp_command();
#endif
std::unique_ptr<CommandDispatcher> create_verbose_command();
std::unique_ptr<CommandDispatcher> create_strace_command();
std::unique_ptr<CommandDispatcher> create_resume_command();
std::unique_ptr<CommandDispatcher> create_ai_command();

void CommandRegistry::register_command(std::unique_ptr<CommandDispatcher> cmd) {
    if (!cmd) {
        std::cerr << "ERROR: Trying to register null command\n";
        return;
    }

    std::string name = cmd->get_name();
    commands[name] = std::move(cmd);
}

std::vector<std::pair<std::string, std::string>>
CommandRegistry::get_all_commands_with_descriptions() const {
    std::vector<std::pair<std::string, std::string>> result;

    for (const auto& [name, cmd] : commands) {
        result.push_back({
            cmd->get_name(),
            cmd->get_description()
        });
    }

    return result;
}

CommandResult CommandRegistry::dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) {
    if (!cmd_buffer || cmd_size == 0) {
        return CommandResult(false, "Empty command");
    }

    // Give
    // every loaded claim-model plugin (one exporting ren_plugin_want, see
    // plugin.h) first look at the *exact raw bytes* the operator typed,
    // before any of the "renef://"/space/tilde parsing below. The first
    // plugin (in load order) whose want() returns true gets its exec()
    // called with that same full raw string and owns the entire response --
    // dispatch_fixed() below (the pre-existing fixed-name path) is skipped
    // for this input. Plugins that don't export ren_plugin_want (NULL,
    // which is every plugin written before this feature -- e.g.
    // test_plugin.c, redex_plugin.c) are invisible to plugin_find_claim()
    // and never short-circuit anything here, so this is a strict addition:
    // behavior for non-claiming plugins and all built-in commands is
    // unchanged. Compiled out entirely for targets with no plugin subsystem
    // (see the RENEF_HAS_PLUGINS comment above the #include at the top).
#ifdef RENEF_HAS_PLUGINS
    std::string raw_cmd(cmd_buffer, cmd_size);
    RENPlugin* claimer = plugin_find_claim(raw_cmd.c_str());
    if (claimer && claimer->exec) {
        renef_ctx ctx;
        ctx.client_fd = &client_fd;
        ctx.socket_helper = &sock;
        ctx.command_registry = this;
        ctx.target_pid = nullptr;

        int ret = claimer->exec(&ctx, const_cast<char*>(raw_cmd.c_str()));

        // Same structured-result relay as PluginCommandDispatcher::
        // dispatch() (plugin.cpp) -- this claimer branch is a separate exec()
        // call site, found missing this while consolidating all three
        // plugin-exec call sites onto one relay.
        // Without it, a claim-model plugin that also exports
        // ren_plugin_result_json() would have its structured result silently
        // dropped whenever it won the claim check (the common case for e.g.
        // an audit-trail plugin that claims every command).
        if (claimer->result_json) {
            char* json = claimer->result_json();
            if (json) {
                std::string line = "[json] ";
                line += json;
                if (line.empty() || line.back() != '\n') line += "\n";
                write(client_fd, line.c_str(), line.size());
                free(json);
            }
        }

        return CommandResult(ret == 0, "");
    }
#endif

    return dispatch_fixed(client_fd, cmd_buffer, cmd_size);
}

CommandResult CommandRegistry::dispatch_fixed(int client_fd, const char* cmd_buffer, size_t cmd_size) {
    if (!cmd_buffer || cmd_size == 0) {
        return CommandResult(false, "Empty command");
    }

    std::string full_cmd(cmd_buffer, cmd_size);

    while (!full_cmd.empty() && (full_cmd.back() == '\n' || full_cmd.back() == '\r' || full_cmd.back() == ' ' || full_cmd.back() == '\0')) {
        full_cmd.pop_back();
    }

    const std::string prefix = "renef://";

    if (full_cmd.find(prefix) == 0) {
        full_cmd = full_cmd.substr(prefix.length());
    }

    // Command name = everything up to the first separator: a space, a
    // `~` (output filter) or the `//` of the "renef://cmd//args" form.
    //
    // `//` used to be searched for in the WHOLE command first, so any
    // command whose arguments merely contained it was split there and
    // rejected as unknown - e.g. `exec print("https://example.com")`, or
    // Lua's floor division (`a // b`). Only a `//` that comes before any
    // other separator belongs to the command syntax.
    std::string cmd_name;
    {
        size_t delim_pos = full_cmd.find("//");
        size_t space_pos = full_cmd.find(' ');
        size_t tilde_pos = full_cmd.find('~');
        size_t split_pos = std::string::npos;
        for (size_t pos : {delim_pos, space_pos, tilde_pos}) {
            if (pos != std::string::npos && (split_pos == std::string::npos || pos < split_pos)) {
                split_pos = pos;
            }
        }
        cmd_name = (split_pos != std::string::npos) ? full_cmd.substr(0, split_pos) : full_cmd;
    }

    auto it = commands.find(cmd_name);
    if (it == commands.end()) {
        const char* error_msg = "ERROR: Unknown command. Type 'help' for available commands.\n";
        write(client_fd, error_msg, strlen(error_msg));
        return CommandResult(false, "Unknown command: " + cmd_name);
    }

    // Drain stale agent output before most commands. Skip for watch —
    // the hook output we want to display may already be in the buffer
    // (hook fired between exec return and watch start).
    //
    // Also skipped for the commands that read the agent through the framed
    // request path (exec/rpc/l) and for `events`: they attribute replies by
    // request id, so nothing stale can be mistaken for their own output -
    // and what is waiting on the socket at that point is hook output the
    // user wants (print()/send() from callbacks that fired between
    // commands), which this drain was silently throwing away.
    if (sock.is_connected() && cmd_name != "watch" && cmd_name != "events" &&
        cmd_name != "exec" && cmd_name != "rpc" && cmd_name != "l") {
        sock.drain_buffer();
    }

    return it->second->dispatch(client_fd, cmd_buffer, cmd_size);
}

void CommandRegistry::setup_all_commands() {
    register_command(create_ping_command());
    register_command(create_attach_command());
    register_command(create_spawn_command());
    register_command(create_list_command());
    register_command(create_inspect_command());
    register_command(create_eval_command());
    register_command(create_load_command());
    register_command(create_watch_command());
    register_command(create_memscan_command());
    register_command(create_memscanjson_command());
    register_command(create_hooks_command());
    register_command(create_unhook_command());
    register_command(create_sec_command());
    register_command(create_memdump_command());
    register_command(create_memdump_passive_command());
    register_command(create_hookgen_command());
    register_command(create_rpc_command());
    register_command(create_events_command());
#ifdef RENEF_HAS_PLUGINS
    register_command(create_mcp_command());
#endif
    register_command(create_verbose_command());
    register_command(create_strace_command());
    register_command(create_resume_command());
    register_command(create_ai_command());
}

bool CommandRegistry::unregister_command(const std::string& name) {
    auto it = commands.find(name);
    if (it == commands.end()) {
        return false;
    }
    commands.erase(it);
    return true;
}

bool CommandRegistry::is_command_exist(const std::string& name) {
    if (commands.find(name) != commands.end()) {
        return true;
    }
    return false;
}

int CommandRegistry::get_current_pid() const {
    return current_pid;
}

void CommandRegistry::set_current_pid(int pid) {
    if (current_pid > 0 && pid != current_pid) {
        sock.close_connection();
    }
    current_pid = pid;
}

SocketHelper& CommandRegistry::get_socket_helper() {
    return sock;
}
