#include <renef/cmd.h>
#include <renef/plugin.h>
#include <unistd.h>
#include <string.h>
#include <string>
#include <cstdio>
#include <cstdlib>

// Writes the current loaded-plugin table to client_fd. Shared by the
// "plugins" list command and "plugin list".
static void write_plugin_list(int client_fd) {
    int count = plugin_count();
    if (count == 0) {
        const char* msg = "No plugins loaded.\n";
        write(client_fd, msg, strlen(msg));
        return;
    }

    RENPlugin* plugins[64];
    int n = plugin_list(plugins, 64);

    char header[64];
    snprintf(header, sizeof(header), "Loaded plugins (%d):\n", n);
    write(client_fd, header, strlen(header));

    for (int i = 0; i < n; i++) {
        char line[340];
        if (plugins[i]->metadata && plugins[i]->metadata->name) {
            // Show "*claim*" instead of a command name for claim-model
            // plugins (ren_plugin_want present) -- they don't own a fixed
            // command slot, so metadata->command (if set at all) would be
            // display-only and misleading to print as if it were routed.
            const char* slot = plugins[i]->want
                ? "*claim*"
                : (plugins[i]->metadata->command ? plugins[i]->metadata->command : plugins[i]->metadata->name);
            snprintf(line, sizeof(line), "  [%d] %s (%s) - %s [%s]\n",
                i + 1,
                plugins[i]->metadata->name,
                slot,
                plugins[i]->metadata->description ? plugins[i]->metadata->description : "",
                plugin_type_name(plugins[i]->metadata->type));
        } else {
            snprintf(line, sizeof(line), "  [%d] (unnamed plugin)\n", i + 1);
        }
        write(client_fd, line, strlen(line));
    }
}

class PluginsCommand : public CommandDispatcher{

    std::string get_name() const override {
        return "plugins";
    }

    std::string get_description() const override {
        return "List loaded plugins";
    }

    CommandResult dispatch(int client_fd, const char*, size_t) override {
        write_plugin_list(client_fd);
        return CommandResult(true, "");
    }
};

// P1: `plugin load <path>` / `plugin unload <name>`, wired directly to the
// existing plugin_load()/plugin_unload()/plugin_find() (src/librenef/plugin/
// plugin.cpp). Previously those functions existed but no CLI command ever
// called them -- only plugin_autoload() at startup did. This lets e.g. a CI
// pipeline conditionally load a plugin (such as the Redex plugin) only
// for the step that needs it.
class PluginCtlCommand : public CommandDispatcher {

    std::string get_name() const override {
        return "plugin";
    }

    std::string get_description() const override {
        return "Manage plugins: plugin load <path> | plugin unload <name> | plugin list";
    }

    static void write_line(int client_fd, const std::string& line) {
        write(client_fd, line.c_str(), line.size());
    }

    static std::string trim(const std::string& s) {
        size_t start = s.find_first_not_of(" \t");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t");
        return s.substr(start, end - start + 1);
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        std::string full(cmd_buffer, cmd_size);
        while (!full.empty() && (full.back() == '\n' || full.back() == '\r')) {
            full.pop_back();
        }

        // Strip the leading "plugin" token.
        std::string rest;
        size_t space = full.find(' ');
        if (space != std::string::npos) {
            rest = trim(full.substr(space + 1));
        }

        if (rest.empty()) {
            write_line(client_fd, "Usage: plugin load <path> | plugin unload <name> | plugin list\n");
            return CommandResult(true, "");
        }

        std::string sub = rest;
        std::string arg;
        size_t sub_space = rest.find(' ');
        if (sub_space != std::string::npos) {
            sub = rest.substr(0, sub_space);
            arg = trim(rest.substr(sub_space + 1));
        }

        if (sub == "list") {
            write_plugin_list(client_fd);
            return CommandResult(true, "");
        }

        if (sub == "load") {
            if (arg.empty()) {
                write_line(client_fd, "Usage: plugin load <path>\n");
                return CommandResult(false, "Missing path");
            }

            RENPlugin* plugin = plugin_load(arg.c_str());
            if (!plugin) {
                write_line(client_fd, "ERROR: Failed to load plugin from '" + arg + "'\n");
                return CommandResult(false, "load failed");
            }

            // P2: build a real context (not nullptr) for ren_plugin_init,
            // consistent with what an autoloaded plugin now gets and what
            // PluginCommandDispatcher::dispatch builds for exec().
            renef_ctx ctx;
            ctx.client_fd = &client_fd;
            ctx.socket_helper = &CommandRegistry::instance().get_socket_helper();
            ctx.command_registry = &CommandRegistry::instance();
            ctx.target_pid = nullptr;

            if (plugin_activate(plugin, &ctx) != 0) {
                write_line(client_fd, "ERROR: Plugin init failed for '" + arg + "', not loaded.\n");
                plugin_unload(plugin);
                return CommandResult(false, "init failed");
            }

            std::string name = (plugin->metadata && plugin->metadata->name) ? plugin->metadata->name : arg;
            std::string cmd = (plugin->metadata && plugin->metadata->command) ? plugin->metadata->command : name;
            const char* type = plugin->metadata ? plugin_type_name(plugin->metadata->type) : "UNKNOWN";

            // A claim-model plugin (ren_plugin_want present) never gets a
            // fixed-name CommandDispatcher slot (see plugin_activate()), so
            // say so explicitly instead of the misleading "as command 'X'"
            // (which used to only check plugin->exec, true for these too).
            std::string status;
            if (plugin->want) {
                status = " (claim-model: sees every command via ren_plugin_want)\n";
            } else if (plugin->exec) {
                status = " as command '" + cmd + "'\n";
            } else {
                status = " (no exec function)\n";
            }

            write_line(client_fd, "Loaded plugin '" + name + "' [" + std::string(type) + "]" + status);
            return CommandResult(true, "");
        }

        if (sub == "unload") {
            if (arg.empty()) {
                write_line(client_fd, "Usage: plugin unload <name>\n");
                return CommandResult(false, "Missing name");
            }

            RENPlugin* plugin = plugin_find(arg.c_str());
            if (!plugin) {
                write_line(client_fd, "ERROR: No loaded plugin named '" + arg + "'\n");
                return CommandResult(false, "not found");
            }

            std::string cmd_name;
            if (plugin->metadata) {
                cmd_name = plugin->metadata->command ? plugin->metadata->command
                                                      : (plugin->metadata->name ? plugin->metadata->name : "");
            }

            if (plugin->close) {
                renef_ctx ctx;
                ctx.client_fd = &client_fd;
                ctx.socket_helper = &CommandRegistry::instance().get_socket_helper();
                ctx.command_registry = &CommandRegistry::instance();
                ctx.target_pid = nullptr;
                plugin->close(&ctx);
            }

            if (!cmd_name.empty()) {
                CommandRegistry::instance().unregister_command(cmd_name);
            }

            plugin_unload(plugin);

            write_line(client_fd, "Unloaded plugin '" + arg + "'\n");
            return CommandResult(true, "");
        }

        write_line(client_fd, "ERROR: Unknown plugin subcommand '" + sub + "'. Usage: plugin load <path> | plugin unload <name> | plugin list\n");
        return CommandResult(false, "Unknown subcommand");
    }
};

// `format <format_name> <command...>` -- minimal
// plumbing that proves the PLUGIN_FORMATTER mechanism (plugin.h) actually
// works end to end, without requiring every cmd_*.cpp to grow a structured
// result type (a separate, larger piece of work). It runs <command...>
// through the normal fixed-name dispatch path exactly as if the operator
// had typed it directly, captures that command's text output via a pipe,
// then asks plugin_format() (plugin.cpp) for a loaded PLUGIN_FORMATTER
// plugin that recognizes `format_name` and hands it that captured text.
//
// Example: `format json plugins` runs the existing `plugins` (list) command
// and, if examples/plugins/json_formatter_plugin.c is loaded, prints its
// JSON rendering instead of the normal human-readable table.
//
// Capture caveat (documented, not fixed -- fine for this proof-of-concept):
// output is read back only after dispatch_fixed() returns, so a wrapped
// command whose output exceeds the OS pipe buffer (commonly 64KiB on Linux,
// smaller on macOS) before we start draining it could block. Every existing
// command's output is far below that; this is not a generic/production
// output-capture facility.
class FormatCommand : public CommandDispatcher {

    std::string get_name() const override {
        return "format";
    }

    std::string get_description() const override {
        return "Run a command through a loaded PLUGIN_FORMATTER plugin: format <format_name> <command...>";
    }

    static void write_line(int client_fd, const std::string& line) {
        write(client_fd, line.c_str(), line.size());
    }

    static std::string trim(const std::string& s) {
        size_t start = s.find_first_not_of(" \t");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t");
        return s.substr(start, end - start + 1);
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        std::string full(cmd_buffer, cmd_size);
        while (!full.empty() && (full.back() == '\n' || full.back() == '\r')) {
            full.pop_back();
        }

        // Strip the leading "format" token.
        std::string rest;
        size_t space = full.find(' ');
        if (space != std::string::npos) {
            rest = trim(full.substr(space + 1));
        }

        if (rest.empty()) {
            write_line(client_fd, "Usage: format <format_name> <command...>\n");
            return CommandResult(true, "");
        }

        std::string format_name = rest;
        std::string sub_cmd;
        size_t sub_space = rest.find(' ');
        if (sub_space != std::string::npos) {
            format_name = rest.substr(0, sub_space);
            sub_cmd = trim(rest.substr(sub_space + 1));
        }

        if (sub_cmd.empty()) {
            write_line(client_fd, "Usage: format <format_name> <command...>\n");
            return CommandResult(false, "Missing command");
        }

        int pipe_fds[2];
        if (pipe(pipe_fds) != 0) {
            write_line(client_fd, "ERROR: Failed to create capture pipe.\n");
            return CommandResult(false, "pipe() failed");
        }

        CommandResult sub_result = CommandRegistry::instance().dispatch_fixed(
            pipe_fds[1], sub_cmd.c_str(), sub_cmd.size());
        close(pipe_fds[1]);

        std::string captured;
        char buf[4096];
        ssize_t n;
        while ((n = read(pipe_fds[0], buf, sizeof(buf))) > 0) {
            captured.append(buf, (size_t)n);
        }
        close(pipe_fds[0]);

        char* formatted = plugin_format(format_name.c_str(), captured.data(), captured.size());
        if (formatted) {
            write_line(client_fd, formatted);
            size_t flen = strlen(formatted);
            if (flen == 0 || formatted[flen - 1] != '\n') {
                write_line(client_fd, "\n");
            }
            free(formatted);
        } else {
            write_line(client_fd, "NOTE: No loaded plugin formats '" + format_name +
                "'. Showing raw output:\n");
            write(client_fd, captured.data(), captured.size());
        }

        return CommandResult(sub_result.success, "");
    }
};

std::unique_ptr<CommandDispatcher> create_plugins_command() {
    return std::make_unique<PluginsCommand>();
}

std::unique_ptr<CommandDispatcher> create_plugin_command() {
    return std::make_unique<PluginCtlCommand>();
}

std::unique_ptr<CommandDispatcher> create_format_command() {
    return std::make_unique<FormatCommand>();
}
