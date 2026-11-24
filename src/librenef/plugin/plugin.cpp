#include <renef/plugin.h>
#include <renef/socket_helper.h>
#include <renef/server_connection.h>
#include <renef/cmd.h>
#include <iostream>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <vector>
#include <pwd.h>

class PluginCommandDispatcher : public CommandDispatcher {
    RENPlugin* plugin;
    std::string cmd_name;
    std::string cmd_desc;

public:
    PluginCommandDispatcher(RENPlugin* p) : plugin(p) {
        if (p->metadata) {
            cmd_name = p->metadata->command ? p->metadata->command : p->metadata->name;
            cmd_desc = p->metadata->description ? p->metadata->description : "Plugin command";
        }
    }

    std::string get_name() const override { return cmd_name; }
    std::string get_description() const override { return cmd_desc; }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t) override {
        if (!plugin || !plugin->exec) {
            return CommandResult(false, "Plugin has no exec function");
        }

        std::string cmd(cmd_buffer);
        std::string args;
        size_t space = cmd.find(' ');
        if (space != std::string::npos) {
            args = cmd.substr(space + 1);
        }

        renef_ctx ctx;
        ctx.client_fd = &client_fd;
        ctx.socket_helper = &CommandRegistry::instance().get_socket_helper();
        ctx.command_registry = &CommandRegistry::instance();
        ctx.target_pid = nullptr;

        int ret = plugin->exec(&ctx, args.empty() ? nullptr : const_cast<char*>(args.c_str()));

        // If the plugin can hand back a structured result (see
        // ren_plugin_result_json_fn in plugin.h), relay it as a distinct
        // "[json] ..." line -- asked for regardless of ret, since a failed
        // run (e.g. "tool not installed") is itself structured data worth
        // reporting, not just the human-readable error text exec() already
        // printed via ren_print() above.
        if (plugin->result_json) {
            char* json = plugin->result_json();
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
};

static std::vector<RENPlugin*> g_loaded_plugins;

static std::string expand_path(const char* path) {
    std::string result(path);
    if (!result.empty() && result[0] == '~') {
        const char* home = getenv("HOME");
        if (!home) {
            struct passwd* pw = getpwuid(getuid());
            if (pw) home = pw->pw_dir;
        }
        if (home) {
            result = std::string(home) + result.substr(1);
        }
    }
    return result;
}

const char* get_user_plugin_dir(){
    return RENEF_PLUGIN_DIR;
}
const char* get_user_plugin_ext(){
    return RENEF_PLUGIN_EXT;
}

RENPlugin* plugin_load(const char* path){
    RENPlugin* r_plugin = (struct RENPlugin*)malloc(sizeof(struct RENPlugin));
    if (!r_plugin) return nullptr;

    memset(r_plugin, 0, sizeof(struct RENPlugin));

    std::string full_path;

    if (path[0] == '/' || path[0] == '.') {
        full_path = path;
    } else {
        std::string plugin_dir = expand_path(get_user_plugin_dir());
        full_path = plugin_dir + "/" + path;

        std::string ext = get_user_plugin_ext();
        if (full_path.length() < ext.length() ||
            full_path.substr(full_path.length() - ext.length()) != ext) {
            full_path += ext;
        }
    }

    void* plg_file = dlopen(full_path.c_str(), RTLD_NOW);
    if (!plg_file) {
        std::cerr << "[plugin] Failed to load: " << full_path << "\n";
        std::cerr << "[plugin] Error: " << dlerror() << "\n";
        free(r_plugin);
        return nullptr;
    }

    r_plugin->handle = plg_file;
    r_plugin->metadata = (RENPluginMetadata*)dlsym(plg_file, "ren_plugin_info");
    r_plugin->init = (ren_plugin_init_fn)dlsym(plg_file, "ren_plugin_init");
    r_plugin->close = (ren_plugin_close_fn)dlsym(plg_file, "ren_plugin_close");
    r_plugin->exec = (ren_plugin_exec_fn)dlsym(plg_file, "ren_plugin_exec");
    // Both optional exports. dlsym() returns NULL (not found) for a
    // plugin that doesn't provide them -- test_plugin.c/redex_plugin.c
    // (predate both) resolve both fields to NULL here, which is exactly
    // the "classic plugin" behavior plugin_activate()/dispatch() already
    // check for. See the ren_plugin_want_fn/ren_plugin_format_fn comments
    // in plugin.h for the full design.
    r_plugin->want = (ren_plugin_want_fn)dlsym(plg_file, "ren_plugin_want");
    r_plugin->format = (ren_plugin_format_fn)dlsym(plg_file, "ren_plugin_format");
    // Optional too -- NULL for every plugin that predates it.
    r_plugin->result_json = (ren_plugin_result_json_fn)dlsym(plg_file, "ren_plugin_result_json");
    r_plugin->loaded = true;

    g_loaded_plugins.push_back(r_plugin);

    return r_plugin;
}

void plugin_unload(RENPlugin* plugin){
    if (!plugin) return;

    if (plugin->handle) {
        dlclose(plugin->handle);
    }

    for (auto it = g_loaded_plugins.begin(); it != g_loaded_plugins.end(); ++it) {
        if (*it == plugin) {
            g_loaded_plugins.erase(it);
            break;
        }
    }

    free(plugin);
}

int plugin_list(RENPlugin** out, int max){
    int count = 0;
    for (size_t i = 0; i < g_loaded_plugins.size() && count < max; i++) {
        out[count++] = g_loaded_plugins[i];
    }
    return count;
}

int plugin_count(){
    return (int)g_loaded_plugins.size();
}

RENPlugin* plugin_find(const char* name){
    for (auto* plugin : g_loaded_plugins) {
        if (plugin && plugin->metadata) {
            if (plugin->metadata->command && strcmp(plugin->metadata->command, name) == 0) {
                return plugin;
            }
            if (plugin->metadata->name && strcmp(plugin->metadata->name, name) == 0) {
                return plugin;
            }
        }
    }
    return nullptr;
}

int plugin_activate(RENPlugin* plugin, renef_ctx_t ctx){
    if (!plugin) return -1;

    if (plugin->init) {
        int ret = plugin->init(ctx);
        if (ret != 0) {
            return -1;
        }
    }

    // A claim-model plugin (exports ren_plugin_want) does not get a
    // fixed-name CommandDispatcher slot -- it's picked up per-dispatch by
    // plugin_find_claim() instead (see CommandRegistry::dispatch(),
    // cmd.cpp). Plugins with want == NULL (every plugin predating the claim model) hit
    // the exact same registration path as before.
    if (plugin->metadata && plugin->metadata->name && plugin->exec && !plugin->want) {
        const char* cmd = plugin->metadata->command ? plugin->metadata->command : plugin->metadata->name;
        if (!CommandRegistry::instance().is_command_exist(cmd)) {
            CommandRegistry::instance().register_command(
                std::make_unique<PluginCommandDispatcher>(plugin)
            );
        }
    }

    return 0;
}

const char* plugin_type_name(PluginType type){
    switch (type) {
        case PLUGIN_LUA: return "LUA";
        case PLUGIN_NATIVE: return "NATIVE";
        case PLUGIN_COMMAND: return "COMMAND";
        case PLUGIN_EXTERNAL_TOOL: return "EXTERNAL_TOOL";
        case PLUGIN_FORMATTER: return "FORMATTER";
        default: return "UNKNOWN";
    }
}

RENPlugin* plugin_find_claim(const char* raw_input){
    if (!raw_input) return nullptr;

    for (auto* plugin : g_loaded_plugins) {
        if (plugin && plugin->want && plugin->exec) {
            if (plugin->want(raw_input)) {
                return plugin;
            }
        }
    }
    return nullptr;
}

char* plugin_format(const char* format_name, const char* input, size_t input_len){
    if (!format_name) return nullptr;

    for (auto* plugin : g_loaded_plugins) {
        if (plugin && plugin->format) {
            char* result = plugin->format(format_name, input, input_len);
            if (result) {
                return result;
            }
        }
    }
    return nullptr;
}

int ren_dispatch(renef_ctx_t ctx, const char* raw_cmd){
    if (!ctx || !ctx->client_fd || !raw_cmd) return -1;

    CommandResult result = CommandRegistry::instance().dispatch_fixed(
        *ctx->client_fd, raw_cmd, strlen(raw_cmd));
    return result.success ? 0 : -1;
}

int plugin_autoload(renef_ctx_t ctx){
    int loaded = 0;
    std::string plugin_dir = expand_path(get_user_plugin_dir());
    std::string ext = get_user_plugin_ext();

    struct stat st;
    if (stat(plugin_dir.c_str(), &st) != 0) {
        return 0;
    }

    DIR* dir = opendir(plugin_dir.c_str());
    if (!dir) {
        return 0;
    }

    // P2 fix: previously this always ran with ctx == nullptr because the
    // only call site (main.cpp startup) had no live connection yet and
    // passed nullptr; ren_plugin_init() for every autoloaded plugin was
    // therefore unable to inspect command_registry/socket_helper. If the
    // caller didn't build a real context, fall back to one here -- same
    // shape of context a manually-loaded plugin gets via plugin_activate()/
    // PluginCommandDispatcher::dispatch (client_fd/socket_helper/
    // command_registry wired to the live CommandRegistry singleton).
    static int autoload_stdout_fd = STDOUT_FILENO;
    renef_ctx fallback_ctx;
    renef_ctx_t use_ctx = ctx;
    if (!use_ctx) {
        fallback_ctx.client_fd = &autoload_stdout_fd;
        fallback_ctx.socket_helper = &CommandRegistry::instance().get_socket_helper();
        fallback_ctx.command_registry = &CommandRegistry::instance();
        fallback_ctx.target_pid = nullptr;
        use_ctx = &fallback_ctx;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string filename = entry->d_name;

        if (filename == "." || filename == "..") continue;

        if (filename.length() < ext.length()) continue;
        if (filename.substr(filename.length() - ext.length()) != ext) continue;

        std::string full_path = plugin_dir + "/" + filename;


        RENPlugin* plugin = plugin_load(full_path.c_str());
        if (plugin) {
            if (plugin_activate(plugin, use_ctx) != 0) {
                std::cerr << "[plugin] Init failed for: " << filename << "\n";
                plugin_unload(plugin);
                continue;
            }

            loaded++;
        }
    }

    closedir(dir);


    return loaded;
}

void ren_print(renef_ctx_t ctx, char* msg){
    write(*ctx->client_fd, msg, strlen(msg));
}

int ren_exec(const char* cmd){
    ServerConnection& conn = ServerConnection::instance();
    if (!conn.is_connected()) {
        if (!conn.connect()) {
            return -1;
        }
    }

    return conn.send(std::string(cmd) + "\n");
}

char* ren_recv(){
    ServerConnection& conn = ServerConnection::instance();
    std::string data = conn.receive(5000);

    if (data.empty()) {
        return nullptr;
    }

    char* result = strdup(data.c_str());
    return result;
}
