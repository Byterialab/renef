#include <agent/handlers.h>
#include <agent/globals.h>
#include <agent/output_queue.h>

#include <string.h>
#include <unistd.h>

void handle_eval(int client_fd, const char* lua_code) {
    LOGI("Evaluating Lua: %s", lua_code);

    if (!g_lua_engine) {
        const char* error = "ERROR: Lua engine not initialized\n";
        write(client_fd, error, strlen(error));
        return;
    }

    bool success = lua_engine_load_script(g_lua_engine, lua_code);

    // print()/console.log only enqueue their text (output_queue); the
    // status line below is written directly. Without this flush the status
    // overtook the script's own output, so a client saw "OK\n<output>"
    // instead of "<output>\nOK\n". That is not cosmetic: the public wire
    // behaviour (v0.3.7, before the output queue existed) is output first,
    // and clients depend on it - r2renef reads the reply to
    // `exec print(Module.find(...))` and requires it to START with "0x".
    output_queue_flush(2000);

    if (success) {
        const char* ok = "OK\n";
        write(client_fd, ok, strlen(ok));
    } else {
        const char* error = "ERROR: Lua execution failed\n";
        write(client_fd, error, strlen(error));
    }
}
