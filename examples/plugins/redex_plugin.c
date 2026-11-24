// Redex plugin for renef
//
// Meta's Redex (https://github.com/facebook/redex) is a DEX bytecode
// optimizer/deobfuscator with its own passes (StringEncryption,
// RecoverHiddenAccess, ...). It runs entirely host-side and offline, on an
// APK/DEX file -- it never touches a live process. That makes it a natural
// fit for renef's existing host plugin system rather than a Lua recipe.
//
// This plugin does NOT vendor or reimplement Redex. It shells out (popen)
// to a `redex` binary that must already be installed on the host (its own
// JDK + Python toolchain), streams stdout/stderr back to the renef client
// via ren_print(), and reports a clear error if `redex` isn't on PATH.
//
// In addition to streaming raw text, this plugin now also
// exports ren_plugin_result_json() (see the ren_plugin_result_json_fn
// contract in plugin.h) so the outcome of a run -- success/failure, exit
// code, which input was given, why it failed -- is available as actual
// structured data, not something a caller has to re-parse out of the text
// lines above. This does NOT parse Redex's own internal stats/report files
// (that would need a real Redex install to verify field names against --
// left as a follow-up); it structures what this plugin itself already
// knows about the invocation.
//
// Build: gcc -shared -fPIC -o redex_plugin.so redex_plugin.c
//        (or `make install` from examples/plugins/, same as test_plugin.c)
//
// Usage (after `plugin load <path-to-redex_plugin.so>`):
//   redex <path-to-apk-or-dex> [extra redex args...]

#include <renef/plugin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>

// Plugin metadata (required export).
// type = PLUGIN_EXTERNAL_TOOL: this plugin is an
// orchestration layer over an external binary, not a generic new command.
RENPluginMetadata ren_plugin_info = {
    .name = "redex_plugin",
    .author = "renef",
    .version = "1.0.0",
    .description = "Shells out to Meta's Redex DEX bytecode optimizer/deobfuscator",
    .command = "redex",              // Command prefix: "redex <apk-or-dex-path> [args...]"
    .type = PLUGIN_EXTERNAL_TOOL
};

int ren_plugin_init(renef_ctx_t ctx) {
    (void)ctx;  // ctx may be NULL during autoload if the caller didn't build one
    return 0;
}

// Real-world finding (found while testing this plugin against an actual
// Homebrew install on macOS, 2026-10-27): `brew install redex` does NOT
// provide a plain `redex` binary on PATH -- only `redex.py` (a thin shell
// wrapper, see /opt/homebrew/opt/redex/bin/redex.py). The upstream project's
// own build/install docs use `redex` as the invocation name, so both are
// real, legitimate names depending on how a given host installed it. Try
// `redex` first (matches the upstream docs / a from-source build), then
// fall back to `redex.py` (the Homebrew bottle). Returns the name to exec,
// or NULL if neither resolves through PATH.
static const char* find_redex_binary(void) {
    if (system("command -v redex >/dev/null 2>&1") == 0) return "redex";
    if (system("command -v redex.py >/dev/null 2>&1") == 0) return "redex.py";
    return NULL;
}

// Structured-result state for the most recent run, consumed by
// ren_plugin_result_json() below. One command at a time -- static state is
// fine, see the contract comment on ren_plugin_result_json_fn in plugin.h.
static int g_last_ran = 0;          // 0 until ren_plugin_exec() is called at least once
static int g_last_status = 0;       // popen/pclose exit status, or -1 for a pre-flight failure
static char g_last_input[256] = ""; // what the operator typed after "redex "
static char g_last_reason[32] = ""; // non-empty only on failure: "missing_input" | "not_installed" | "popen_failed"
// -1 = not checked (no .apk found in input, or unzip/dexdump unavailable --
// advisory only, never blocks the run), 0 = clean, 1 = detected.
static int g_last_dex38_precheck = -1;

// Found in live testing: redex's own
// PassManager.cpp (verified against upstream facebook/redex source, both
// the exact installed tag and current HEAD -- the logic is unchanged, this
// is intentional upstream behavior, not a bug) refuses to run most
// optimization passes -- including ClassReorderingPass, which is itself
// MANDATORY for dex37+ input -- whenever its OWN internal CFG-level scan
// decides the input's bytecode contains `invoke-custom`/`invoke-polymorphic`
// (Java 8 method-handle/invokedynamic) instructions.
//
// IMPORTANT, also found in testing: this function is only a cheap, textual
// APPROXIMATION of that scan (unzip + `dexdump -d` + grep for the mnemonics)
// -- it is NOT the same analysis redex itself runs, and in testing it
// disagreed with redex's own result at least once (reported "clean" on an
// APK that redex's real run then rejected as having dex38 features; the
// dexdump text dump showed no invoke-custom/invoke-polymorphic instruction,
// so either dexdump and redex's CFG walker disagree on how to classify this
// particular input, or something about redex's check isn't fully captured
// by a flat mnemonic grep). Treat a "clean" (0) result from this function
// as a weak, unverified hint only -- NEVER as proof the real run will
// succeed. Advisory-only in every direction: if `unzip`/`dexdump` aren't on
// PATH, or no `*.apk` token is found in the input, it silently skips
// (returns -1) rather than blocking the run -- redex's own exit code is
// always the actual source of truth, this just tries to save a slow
// unpack-and-crash cycle on the common/true-positive case.
static int apk_has_dex38_opcodes(const char* apk_path) {
    if (system("command -v unzip >/dev/null 2>&1") != 0) return -1;
    if (system("command -v dexdump >/dev/null 2>&1") != 0) return -1;

    char cmd[4608];
    int n = snprintf(cmd, sizeof(cmd),
        "d=$(mktemp -d) && cd \"$d\" && unzip -oq '%s' 'classes*.dex' >/dev/null 2>&1 "
        "&& for f in classes*.dex; do [ -f \"$f\" ] && dexdump -d \"$f\" 2>/dev/null; done "
        "| grep -qE 'invoke-custom|invoke-polymorphic'; rc=$?; rm -rf \"$d\"; exit $rc",
        apk_path);
    if (n < 0 || (size_t)n >= sizeof(cmd)) return -1;

    int status = system(cmd);
    if (status == -1 || !WIFEXITED(status)) return -1;

    int code = WEXITSTATUS(status);
    if (code == 0) return 1; // grep matched invoke-custom/invoke-polymorphic
    if (code == 1) return 0; // grep ran, found nothing
    return -1;                // unzip/dexdump themselves failed (bad path, no dex, ...)
}

// Best-effort extraction of the INPUT apk path out of `input` (everything
// typed after "redex "): redex's own argparse takes a single positional
// `input_apk` that can appear anywhere relative to its optional flags, and
// `-o OUT.apk` means a second ".apk"-suffixed token is common too (see our
// own test invocations: "-c cfg.json -j android.jar -o out.apk in.apk
// --ignore-zipalign"). Rule: skip any ".apk" token that is itself `-o`'s
// value (the token right after a literal "-o"), and among what's left keep
// the LAST ".apk" token -- true positional args land after the flags in
// every real invocation seen in testing. Never used to actually invoke
// redex (that still gets the raw, unparsed `input` string) -- this is
// advisory-only input to apk_has_dex38_opcodes() below.
static int find_apk_token(const char* input, char* out, size_t out_size) {
    // Bug found in testing: this used to be char copy[256], silently
    // truncating any realistic invocation (multiple absolute paths for
    // -c/-j/-P/-o easily exceed 256 bytes) and losing the real input apk
    // token before ever reaching it. Match the size of `cmd` in
    // ren_plugin_exec below, since that's the real ceiling on how long an
    // `input` this plugin will ever actually try to run.
    char copy[4096];
    snprintf(copy, sizeof(copy), "%s", input);

    int found = 0;
    const char* prev = NULL;
    char* tok = strtok(copy, " \t");
    while (tok) {
        size_t len = strlen(tok);
        int is_output_value = (prev && strcmp(prev, "-o") == 0);
        if (len > 4 && strcasecmp(tok + len - 4, ".apk") == 0 &&
            tok[0] != '-' && !is_output_value) {
            snprintf(out, out_size, "%s", tok);
            found = 1;
        }
        prev = tok;
        tok = strtok(NULL, " \t");
    }
    return found;
}

// Copies `src` into `dst` (size `dst_size`) escaping '"' and '\\' so the
// result is safe to embed inside a JSON string literal. Minimal on purpose
// (same spirit as json_formatter_plugin.c) -- control chars beyond that
// aren't expected in a shell command line/path and are passed through.
static void copy_json_escaped(char* dst, size_t dst_size, const char* src) {
    size_t w = 0;
    for (size_t i = 0; src && src[i] && w + 2 < dst_size; i++) {
        char c = src[i];
        if (c == '"' || c == '\\') {
            if (w + 3 >= dst_size) break;
            dst[w++] = '\\';
        }
        dst[w++] = c;
    }
    dst[w] = '\0';
}

int ren_plugin_exec(renef_ctx_t ctx, char* input) {
    if (!ctx) return -1;

    g_last_ran = 1;
    snprintf(g_last_input, sizeof(g_last_input), "%s", input ? input : "");
    g_last_reason[0] = '\0';
    g_last_dex38_precheck = -1;

    if (!input || !*input) {
        ren_print(ctx, (char*)"Usage: redex <apk-or-dex-path> [extra redex args...]\n");
        g_last_status = -1;
        snprintf(g_last_reason, sizeof(g_last_reason), "missing_input");
        return -1;
    }

    const char* redex_bin = find_redex_binary();
    if (!redex_bin) {
        ren_print(ctx, (char*)
            "[redex] Neither 'redex' nor 'redex.py' found on PATH.\n"
            "[redex] Install Meta's Redex (https://github.com/facebook/redex), "
            "make sure its wrapper script is on PATH, then retry.\n"
            "[redex] Renef only orchestrates an installed Redex toolchain -- "
            "it does not bundle or reimplement it.\n");
        g_last_status = -1;
        snprintf(g_last_reason, sizeof(g_last_reason), "not_installed");
        return -1;
    }

    char apk_token[1024];
    if (find_apk_token(input, apk_token, sizeof(apk_token))) {
        g_last_dex38_precheck = apk_has_dex38_opcodes(apk_token);
        if (g_last_dex38_precheck == 1) {
            ren_print(ctx, (char*)
                "[redex] WARNING: this APK's dex contains invoke-custom/"
                "invoke-polymorphic bytecode (Java 8 method handles/"
                "invokedynamic). Redex's own PassManager refuses most "
                "optimization passes on such input -- ClassReorderingPass, "
                "which is itself mandatory for dex37+, will likely abort. "
                "This is intentional upstream behavior, not a bug (verified "
                "against facebook/redex source, 2026-10-27) -- proceeding "
                "anyway so redex's own error is the final word.\n");
        }
    }

    // `input` is whatever the operator typed after "redex " (path + any
    // extra redex flags), forwarded to the shell as-is. This mirrors the
    // trust model of this kind of plugin (popen / fork+exec of a host tool):
    // the operator already has arbitrary Lua/eval execution on the target
    // process through renef, so this is not a new trust boundary.
    char cmd[4096];
    int n = snprintf(cmd, sizeof(cmd), "%s %s 2>&1", redex_bin, input);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        ren_print(ctx, (char*)"[redex] Command too long.\n");
        g_last_status = -1;
        snprintf(g_last_reason, sizeof(g_last_reason), "command_too_long");
        return -1;
    }

    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
        ren_print(ctx, (char*)"[redex] Failed to launch redex (popen failed).\n");
        g_last_status = -1;
        snprintf(g_last_reason, sizeof(g_last_reason), "popen_failed");
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), pipe)) {
        ren_print(ctx, line);
    }

    int status = pclose(pipe);
    g_last_status = status;
    char summary[128];
    if (status == 0) {
        snprintf(summary, sizeof(summary), "[redex] Done (exit 0).\n");
    } else {
        snprintf(summary, sizeof(summary), "[redex] Exited with status %d.\n", status);
    }
    ren_print(ctx, summary);

    return (status == 0) ? 0 : -1;
}

// Hands back everything ren_plugin_exec() just printed as text, as one
// JSON object instead -- a caller (pipeline, AI tool-calling, or just
// `format json redex ...`) can read ["status"]/["exit_code"] directly
// instead of grepping "[redex] Done" out of free-form stdout lines.
char* ren_plugin_result_json(void) {
    if (!g_last_ran) return NULL;

    char input_escaped[512];
    copy_json_escaped(input_escaped, sizeof(input_escaped), g_last_input);

    // "null" when the precheck wasn't run/couldn't run (no .apk token found,
    // or unzip/dexdump missing) -- distinct from "false" (checked, clean).
    const char* dex38_field =
        g_last_dex38_precheck == 1 ? "true" :
        g_last_dex38_precheck == 0 ? "false" : "null";

    char buf[896];
    if (g_last_reason[0]) {
        snprintf(buf, sizeof(buf),
            "{\"tool\":\"redex\",\"status\":\"error\",\"reason\":\"%s\",\"input\":\"%s\","
            "\"dex38_features_detected\":%s}",
            g_last_reason, input_escaped, dex38_field);
    } else {
        snprintf(buf, sizeof(buf),
            "{\"tool\":\"redex\",\"status\":\"%s\",\"exit_code\":%d,\"input\":\"%s\","
            "\"dex38_features_detected\":%s}",
            g_last_status == 0 ? "ok" : "failed", g_last_status, input_escaped, dex38_field);
    }
    return strdup(buf);
}

void ren_plugin_close(renef_ctx_t ctx) {
    (void)ctx;
}
