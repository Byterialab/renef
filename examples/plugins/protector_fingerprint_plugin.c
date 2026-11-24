// Protector fingerprinting plugin for renef.
//
// A static, offline pre-scan that guesses which commercial Android app
// protector(s) (DexGuard, DexProtector, ...) an APK was built with, BEFORE
// ever spawning/attaching to the app. Same host-only, popen-based
// EXTERNAL_TOOL pattern as examples/plugins/redex_plugin.c (see plugin.h's
// ren_plugin_result_json_fn comment and PLUGIN_EXTERNAL_TOOL comment for the
// contract this follows).
//
// "Which protector" is really TWO independent questions at TWO different
// binary layers, and they must not be conflated:
//
//   Layer A -- ELF/native-loader layer (DexProtector-style):
//     DexProtector's native loader stub has a recognizable ELF shape: a
//     shared object that exports exactly one dynamic symbol (JNI_OnLoad),
//     has no (or almost no) DT_NEEDED dependencies (looks "static-pie"-like
//     even though it's technically ET_DYN -- see the python helper below for
//     the exact nuance), and carries a PT_LOAD segment whose Shannon entropy
//     is consistent with an encrypted/compressed payload rather than code.
//     LIEF is the right tool for this (ELF parsing), but LIEF is a Python
//     *library*, not a `popen`-able binary like redex -- so
//     this shells out via `python3 -c "import lief"` / a generated python
//     script, instead of adding a new build-time (C/C++) LIEF dependency.
//
//   Layer B -- DEX/bytecode layer (DexGuard-style):
//     LIEF does not parse DEX. This layer uses `dexdump` (ships in the
//     Android SDK build-tools; find it with `which dexdump`) to disassemble
//     classes*.dex and greps for three REAL, pentest-verified signatures
//     (not guesses):
//       1. Opaque-predicate arithmetic: constant-modulo ops (`rem-int`
//          family -- `int i = 2 % 2;`-style junk) -- weak/common on its own
//          (legitimate code uses modulo too), so this is only ever a
//          corroborating signal below, never a trigger by itself.
//       2. Junk-API vocabulary: call sites to a short list of real-world
//          decoy APIs (ViewConfiguration.getScrollFriction/
//          getDoubleTapTimeout, CdmaCellLocation.convertQuartSecToDecDegrees,
//          AndroidCharacter.getMirror, TypedValue.complexToFloat, Color.rgb,
//          SystemClock.elapsedRealtime) whose return values get folded into
//          decoder arguments by DexGuard's string-encryption pass.
//       3. Decoder-signature density: static methods whose descriptor is
//          EXACTLY one of three real inline-string-decoder shapes --
//          "(I[C[Ljava/lang/Object;)V", "(CII[Ljava/lang/Object;)V",
//          "([BZ[I[Ljava/lang/Object;)V" -- seen densely only in
//          decoder-class-heavy, string-encrypted DEX.
//
// Both layers feed ONE merged `candidates` array (never a single "protector="
// verdict): a real APK can legitimately
// carry a DexGuard app-wide pass AND a DexProtector-wrapped sub-SDK at the
// same time, so this reports independent (name, layer, confidence, evidence)
// entries rather than picking one winner.
//
// Single command, both layers, one file: given plugin.h's classic model
// binds exactly one `metadata->command` per plugin, and a real APK scan
// should run BOTH layers together anyway (that's the whole point of the
// "found together" observation above), this plugin does not split into
// a second "protofp-dex" command/plugin. Instead the *input* decides what
// runs: a bare `.so` only exercises layer A, a bare `.dex` only exercises layer B,
// and an `.apk` extracts both `lib/*/*.so` and `classes*.dex` and runs both,
// merging into one `candidates` list. An operator who wants to force one
// layer on an apk can always point this at an already-extracted .so/.dex
// instead (see `ren_dispatch`-free design: no new plugin.h surface needed).
//
// Build: gcc -shared -fPIC -o protector_fingerprint_plugin.so protector_fingerprint_plugin.c
//        (or `make install` from examples/plugins/, same as redex_plugin.c)
//
// Usage (after `plugin load <path-to-protector_fingerprint_plugin.so>`):
//   protofp <path-to-apk-or-so-or-dex>
//
// Test APKs used while writing this: neither is actually
// protected by DexGuard/DexProtector -- they're small unprotected CTF-style
// apps. They exist here to validate the TRUE-NEGATIVE case: this plugin
// must report "candidates":[] (not a false "DexProtector found!") on them.
// Confirmed in testing (2026-10-27): both report empty candidates.

#include <renef/plugin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/wait.h>

RENPluginMetadata ren_plugin_info = {
    .name = "protector_fingerprint",
    .author = "renef",
    .version = "1.0.0",
    .description = "Static pre-scan guessing which commercial protector(s) (DexGuard/DexProtector-style) an APK uses, via LIEF (ELF layer) + dexdump (DEX layer)",
    .command = "protofp",            // Command prefix: "protofp <apk-or-so-or-dex-path>"
    .type = PLUGIN_EXTERNAL_TOOL
};

int ren_plugin_init(renef_ctx_t ctx) {
    (void)ctx;  // ctx may be NULL during autoload if the caller didn't build one
    return 0;
}

void ren_plugin_close(renef_ctx_t ctx) {
    (void)ctx;
}

// ---------------------------------------------------------------------------
// Structured-result state for the most recent run, consumed by
// ren_plugin_result_json() below. One command at a time -- static state is
// fine (same contract as redex_plugin.c).
// ---------------------------------------------------------------------------
static int  g_last_ran = 0;
static char g_last_result_json[8192] = "";

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

static int cmd_on_path(const char* bin) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "command -v %s >/dev/null 2>&1", bin);
    return system(cmd) == 0;
}

// Direct importability check, NOT `pip3 show lief`: `pip3` and the `python3`
// this plugin actually invokes below can resolve to two different
// interpreters/environments (venvs, pyenv, Homebrew's shimmed python3, ...),
// so `pip3 show lief` can say "installed" for an environment this plugin
// will never actually run under, or "not found" for one where lief truly is
// importable. Checking `python3 -c "import lief"` directly asks the exact
// question that matters: will the invocation below work. (Verified while
// writing this: a fresh venv's `pip install lief` succeeds instantly on
// macOS/arm64 -- current PyPI ships a prebuilt wheel -- but the system
// python3 on PATH here refuses system-wide installs (PEP 668), which is
// exactly the ambiguity this check sidesteps.)
static int lief_importable(void) {
    if (!cmd_on_path("python3")) return 0;
    return system("python3 -c \"import lief\" >/dev/null 2>&1") == 0;
}

static int has_suffix_ci(const char* s, const char* suffix) {
    size_t ls = strlen(s), lsuf = strlen(suffix);
    if (ls < lsuf) return 0;
    return strcasecmp(s + (ls - lsuf), suffix) == 0;
}

// Copies `src` into `dst` (size `dst_size`) escaping '"' and '\\' so the
// result is safe to embed inside a JSON string literal (same as
// redex_plugin.c's copy_json_escaped).
static void json_escape(char* dst, size_t dst_size, const char* src) {
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

// Appends `path` single-quote-escaped (shell-safe) to `cmd` (bounded).
static void append_shell_quoted(char* cmd, size_t cmd_size, const char* path) {
    size_t len = strlen(cmd);
    if (len + 3 >= cmd_size) return;
    cmd[len++] = ' ';
    cmd[len++] = '\'';
    for (size_t i = 0; path[i] && len + 5 < cmd_size; i++) {
        if (path[i] == '\'') {
            cmd[len++] = '\''; cmd[len++] = '\\'; cmd[len++] = '\''; cmd[len++] = '\'';
        } else {
            cmd[len++] = path[i];
        }
    }
    cmd[len++] = '\'';
    cmd[len] = '\0';
}

#define MAX_FILES 32
#define FILE_PATH_SZ 768

typedef struct {
    char paths[MAX_FILES][FILE_PATH_SZ];
    int count;
} FileList;

// Runs `find <dir> -type f -name <glob>` and fills `out` (bounded). Used only
// for files WE just extracted into our own mktemp workdir below.
static void find_files(const char* dir, const char* glob, FileList* out) {
    out->count = 0;
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "find '%s' -type f -name '%s' 2>/dev/null", dir, glob);
    FILE* p = popen(cmd, "r");
    if (!p) return;
    char line[FILE_PATH_SZ];
    while (out->count < MAX_FILES && fgets(line, sizeof(line), p)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        if (n == 0) continue;
        snprintf(out->paths[out->count], FILE_PATH_SZ, "%s", line);
        out->count++;
    }
    pclose(p);
}

// Runs `grep -cE <pattern> <dumpfile>` and returns the match count (0 if the
// dumpfile doesn't exist, is empty, or nothing matches -- grep exiting 1 on
// "no matches" still prints "0", which is all this reads).
//
// Bug found in live testing (2026-10-27): DECODER_SIG_PATTERN below matches
// dexdump's `type          : '...'` field, which means the pattern string
// itself contains literal `'` characters (it has to, to match dexdump's own
// quoting) -- naively wrapping it in '%s' broke the shell command outright
// ("syntax error near unexpected token `('"), silently producing a 0 count
// for every pattern afterwards rather than a clean failure. Must go through
// the same embedded-quote-escaping append_shell_quoted() already uses for
// paths, not a bare snprintf("'%s'", ...).
static int grep_count(const char* dumpfile, const char* pattern) {
    char cmd[2048] = "grep -cE";
    append_shell_quoted(cmd, sizeof(cmd), pattern);
    append_shell_quoted(cmd, sizeof(cmd), dumpfile);
    strncat(cmd, " 2>/dev/null", sizeof(cmd) - strlen(cmd) - 1);
    FILE* p = popen(cmd, "r");
    if (!p) return 0;
    int n = 0;
    if (fscanf(p, "%d", &n) != 1) n = 0;
    pclose(p);
    return n;
}

// ---------------------------------------------------------------------------
// Layer A -- ELF/native-loader layer (LIEF, python3 shell-out)
//
// Writes a small python helper to <workdir>/lief_probe.py and runs it once
// over every discovered .so, with each .so path as its own argv entry
// (avoids any shell-quoting/embedding of the SCRIPT itself -- only the
// already-extracted file paths need shell-quoting, via
// append_shell_quoted()). The script prints exactly one line: a JSON array
// of candidate objects (possibly "[]"), which this function splices
// (brackets stripped) straight into the final merged JSON -- same
// hand-built, no-JSON-library spirit as redex_plugin.c/
// json_formatter_plugin.c, just delegated to python's own (trustworthy)
// json.dumps() for the per-candidate escaping instead of re-deriving it
// here a second time.
// ---------------------------------------------------------------------------

static const char* k_lief_probe_py =
"import sys, json, math\n"
"from collections import Counter\n"
"\n"
"def entropy(data):\n"
"    if not data:\n"
"        return 0.0\n"
"    cnt = Counter(data)\n"
"    n = len(data)\n"
"    return -sum((v / n) * math.log2(v / n) for v in cnt.values())\n"
"\n"
"def analyze(path):\n"
"    try:\n"
"        import lief\n"
"    except Exception:\n"
"        return None\n"
"    try:\n"
"        b = lief.parse(path)\n"
"    except Exception:\n"
"        return None\n"
"    if b is None:\n"
"        return None\n"
"    try:\n"
"        exported = [f.name for f in b.exported_functions]\n"
"    except Exception:\n"
"        exported = []\n"
"    try:\n"
"        needed = list(b.libraries)\n"
"    except Exception:\n"
"        needed = []\n"
"    try:\n"
"        stripped = b.get_section('.symtab') is None\n"
"    except Exception:\n"
"        stripped = False\n"
"\n"
"    max_entropy = 0.0\n"
"    try:\n"
"        for seg in b.segments:\n"
"            try:\n"
"                if 'LOAD' not in str(seg.type):\n"
"                    continue\n"
"                data = bytes(seg.content)\n"
"            except Exception:\n"
"                continue\n"
"            if len(data) < 256:\n"
"                continue\n"
"            e = entropy(data)\n"
"            if e > max_entropy:\n"
"                max_entropy = e\n"
"    except Exception:\n"
"        pass\n"
"\n"
"    single_jni_export = (len(exported) == 1 and exported[0] == 'JNI_OnLoad')\n"
"    no_needed = (len(needed) == 0)\n"
"    high_entropy = max_entropy > 7.2\n"
"\n"
"    # Gate: a lone JNI_OnLoad export is common in plenty of ordinary,\n"
"    # unprotected JNI libraries too -- NOT distinctive by itself. Only\n"
"    # treat this as a DexProtector-style loader fingerprint when it ALSO\n"
"    # looks static-like (no dynamic deps -- the 'static-pie'-ish shape\n"
"    # DexProtector's loader stub has, even though it's technically ET_DYN)\n"
"    # or carries a high-entropy LOAD segment (likely encrypted payload).\n"
"    if not single_jni_export or not (no_needed or high_entropy):\n"
"        return None\n"
"\n"
"    evidence = ['single JNI_OnLoad export']\n"
"    confidence = 0.30\n"
"    if no_needed:\n"
"        evidence.append('no dynamic library dependencies (static-like loader)')\n"
"        confidence += 0.25\n"
"    if high_entropy:\n"
"        evidence.append('high-entropy PT_LOAD segment (H=%.2f/8.0)' % max_entropy)\n"
"        confidence += 0.35\n"
"    if stripped:\n"
"        evidence.append('stripped (.symtab absent)')\n"
"        confidence += 0.05\n"
"\n"
"    return {\n"
"        'name': 'DexProtector',\n"
"        'layer': 'elf',\n"
"        'confidence': round(min(confidence, 0.95), 2),\n"
"        'evidence': evidence,\n"
"        'library': path,\n"
"    }\n"
"\n"
"out = []\n"
"for p in sys.argv[1:]:\n"
"    try:\n"
"        r = analyze(p)\n"
"    except Exception:\n"
"        r = None\n"
"    if r:\n"
"        out.append(r)\n"
"\n"
"print(json.dumps(out))\n";

// Runs the LIEF probe over `so_list`, returns a heap-allocated JSON array
// string (caller frees), or NULL on any failure to even run it (missing
// python3/lief is checked by the caller BEFORE this is called -- this only
// handles the actual invocation).
static char* run_lief_probe(const char* workdir, const FileList* so_list) {
    char script_path[FILE_PATH_SZ + 32];
    snprintf(script_path, sizeof(script_path), "%s/lief_probe.py", workdir);
    FILE* f = fopen(script_path, "w");
    if (!f) return NULL;
    fputs(k_lief_probe_py, f);
    fclose(f);

    char cmd[8192];
    snprintf(cmd, sizeof(cmd), "python3");
    append_shell_quoted(cmd, sizeof(cmd), script_path);
    for (int i = 0; i < so_list->count; i++) {
        append_shell_quoted(cmd, sizeof(cmd), so_list->paths[i]);
    }
    strncat(cmd, " 2>/dev/null", sizeof(cmd) - strlen(cmd) - 1);

    FILE* p = popen(cmd, "r");
    if (!p) return NULL;
    char* buf = malloc(16384);
    if (!buf) { pclose(p); return NULL; }
    size_t total = 0;
    size_t n;
    while ((n = fread(buf + total, 1, 16384 - 1 - total, p)) > 0) {
        total += n;
        if (total >= 16384 - 1) break;
    }
    buf[total] = '\0';
    pclose(p);

    // Trim trailing whitespace/newline.
    while (total > 0 && (buf[total - 1] == '\n' || buf[total - 1] == '\r' || buf[total - 1] == ' ')) {
        buf[--total] = '\0';
    }
    if (total < 2 || buf[0] != '[' || buf[total - 1] != ']') {
        free(buf);
        return NULL; // probe produced something unparseable -- treat as "no candidates" upstream
    }
    return buf;
}

// ---------------------------------------------------------------------------
// Layer B -- DEX/bytecode layer (dexdump, pure shell -- no python needed here)
// ---------------------------------------------------------------------------

#define JUNK_API_PATTERN \
    "Landroid/view/ViewConfiguration;(\\.|->)getScrollFriction" \
    "|Landroid/view/ViewConfiguration;(\\.|->)getDoubleTapTimeout" \
    "|Landroid/telephony/cdma/CdmaCellLocation;(\\.|->)convertQuartSecToDecDegrees" \
    "|Landroid/text/AndroidCharacter;(\\.|->)getMirror" \
    "|Landroid/util/TypedValue;(\\.|->)complexToFloat" \
    "|Landroid/graphics/Color;(\\.|->)rgb" \
    "|Landroid/os/SystemClock;(\\.|->)elapsedRealtime"

#define DECODER_SIG_PATTERN \
    "type +: '\\((I\\[C\\[Ljava/lang/Object;\\)V" \
    "|CII\\[Ljava/lang/Object;\\)V" \
    "|\\[BZ\\[I\\[Ljava/lang/Object;\\)V)'"

#define OPAQUE_PREDICATE_PATTERN "rem-int"

// Builds a candidate JSON object for a DexGuard-style finding, or an empty
// string ("" -- not "[]"/"{}") if the gate doesn't pass. Writes into `out`
// (bounded, `out_size`).
static void build_dexguard_candidate(const char* dumpfile, int dex_files_analyzed,
                                      char* out, size_t out_size) {
    out[0] = '\0';

    int junk = grep_count(dumpfile, JUNK_API_PATTERN);
    int decoder = grep_count(dumpfile, DECODER_SIG_PATTERN);
    int opaque = grep_count(dumpfile, OPAQUE_PREDICATE_PATTERN);

    // Gate: constant-modulo ("opaque predicate") arithmetic alone is common
    // in ordinary, unprotected code (parity checks, hashing, ...) -- real
    // finding while testing this plugin: one of the unprotected test APKs
    // has 13 incidental `rem-int` hits and ZERO junk-API/decoder hits, and
    // must NOT be reported as DexGuard. Only the rarer, much more specific
    // signals (junk-API decoy calls, decoder-shaped method descriptors) are
    // allowed to trigger a candidate at all; `rem-int` density only adds
    // corroborating confidence once one of those has already fired.
    if (junk < 3 && decoder < 3) return;

    double confidence = 0.15;
    char evidence[1024] = "";
    size_t ev_len = 0;

    if (junk > 0) {
        double add = junk * 0.04; if (add > 0.40) add = 0.40;
        confidence += add;
        ev_len += snprintf(evidence + ev_len, sizeof(evidence) - ev_len,
            "%s\"junk-API decoy call sites: %d (ViewConfiguration/CdmaCellLocation/"
            "AndroidCharacter/TypedValue/Color/SystemClock vocabulary)\"",
            ev_len ? "," : "", junk);
    }
    if (decoder > 0) {
        double add = decoder * 0.03; if (add > 0.40) add = 0.40;
        confidence += add;
        ev_len += snprintf(evidence + ev_len, sizeof(evidence) - ev_len,
            "%s\"decoder-shaped static method signatures: %d "
            "((I[C[Ljava/lang/Object;)V / (CII[Ljava/lang/Object;)V / "
            "([BZ[I[Ljava/lang/Object;)V)\"",
            ev_len ? "," : "", decoder);
    }
    if (opaque > 0) {
        double add = opaque * 0.005; if (add > 0.15) add = 0.15;
        confidence += add;
        ev_len += snprintf(evidence + ev_len, sizeof(evidence) - ev_len,
            "%s\"constant-modulo / opaque-predicate ops: %d (rem-int family)\"",
            ev_len ? "," : "", opaque);
    }
    if (confidence > 0.95) confidence = 0.95;

    snprintf(out, out_size,
        "{\"name\":\"DexGuard\",\"layer\":\"dex\",\"confidence\":%.2f,"
        "\"evidence\":[%s],\"dex_files_analyzed\":%d}",
        confidence, evidence, dex_files_analyzed);
}

// ---------------------------------------------------------------------------
// Error-shape JSON (mirrors redex_plugin.c's {"status":"error","reason":...}
// path exactly -- same field names, same spirit) for preconditions that
// block the ENTIRE scan (bad input, nothing on disk, no usable tool at all).
// ---------------------------------------------------------------------------
static void set_error_result(const char* input, const char* reason) {
    char input_escaped[512];
    json_escape(input_escaped, sizeof(input_escaped), input ? input : "");
    snprintf(g_last_result_json, sizeof(g_last_result_json),
        "{\"tool\":\"protofp\",\"status\":\"error\",\"reason\":\"%s\",\"input\":\"%s\"}",
        reason, input_escaped);
}

int ren_plugin_exec(renef_ctx_t ctx, char* input) {
    if (!ctx) return -1;
    g_last_ran = 1;
    g_last_result_json[0] = '\0';

    if (!input || !*input) {
        ren_print(ctx, (char*)"Usage: protofp <path-to-apk-or-so-or-dex>\n");
        set_error_result("", "missing_input");
        return -1;
    }

    // Single positional argument: everything up to the first whitespace.
    char path[FILE_PATH_SZ];
    {
        char copy[FILE_PATH_SZ];
        snprintf(copy, sizeof(copy), "%s", input);
        char* tok = strtok(copy, " \t\r\n");
        if (!tok) {
            ren_print(ctx, (char*)"Usage: protofp <path-to-apk-or-so-or-dex>\n");
            set_error_result(input, "missing_input");
            return -1;
        }
        snprintf(path, sizeof(path), "%s", tok);
    }

    if (access(path, R_OK) != 0) {
        ren_print(ctx, (char*)"[protofp] Input path not found or not readable: ");
        ren_print(ctx, path);
        ren_print(ctx, (char*)"\n");
        set_error_result(path, "file_not_found");
        return -1;
    }

    int is_apk = has_suffix_ci(path, ".apk");
    int is_so  = has_suffix_ci(path, ".so");
    int is_dex = has_suffix_ci(path, ".dex");
    if (!is_apk && !is_so && !is_dex) {
        ren_print(ctx, (char*)
            "[protofp] Unsupported input (expected .apk, .so, or .dex): ");
        ren_print(ctx, path);
        ren_print(ctx, (char*)"\n");
        set_error_result(path, "unsupported_input");
        return -1;
    }

    // mktemp a scratch workdir -- always (not just for .apk): the python
    // probe script and the combined dexdump dump both get written to it, so
    // a bare .so/.dex input needs one too, to avoid falling back to a
    // shared, predictable path like "/tmp/lief_probe.py" for every run.
    char workdir[64] = "/tmp/renef_protofp_XXXXXX";
    int have_workdir = (mkdtemp(workdir) != NULL);
    if (!have_workdir) {
        set_error_result(path, "mktemp_failed");
        return -1;
    }

    FileList so_list = { .count = 0 };
    FileList dex_list = { .count = 0 };

    if (is_so) {
        snprintf(so_list.paths[0], FILE_PATH_SZ, "%s", path);
        so_list.count = 1;
    } else if (is_dex) {
        snprintf(dex_list.paths[0], FILE_PATH_SZ, "%s", path);
        dex_list.count = 1;
    } else if (is_apk) {
        char cmd[1536];
        snprintf(cmd, sizeof(cmd),
            "unzip -oq '%s' 'lib/*/*.so' 'classes*.dex' -d '%s' >/dev/null 2>&1",
            path, workdir);
        system(cmd); // non-zero if ONE pattern matches nothing is fine; checked via find below
        find_files(workdir, "*.so", &so_list);
        find_files(workdir, "classes*.dex", &dex_list);
    }

    if (so_list.count == 0 && dex_list.count == 0) {
        ren_print(ctx, (char*)
            "[protofp] Nothing to analyze (no .so or classes*.dex found in input).\n");
        set_error_result(path, "nothing_to_analyze");
        if (have_workdir) { char rm[96]; snprintf(rm, sizeof(rm), "rm -rf '%s'", workdir); system(rm); }
        return -1;
    }

    char warnings[512] = "";
    size_t warn_len = 0;
    char* elf_json = NULL;    // heap, from run_lief_probe() -- "[...]"
    char dex_candidate[1536] = "";
    int ran_elf = 0, ran_dex = 0;

    // --- ELF layer ---
    if (so_list.count > 0) {
        if (!lief_importable()) {
            ren_print(ctx, (char*)
                "[protofp] LIEF not installed for the python3 on PATH -- ELF/"
                "native-loader layer (DexProtector-style fingerprint) "
                "skipped.\n"
                "[protofp] Install it with: pip3 install lief\n"
                "[protofp] (If that's refused with an 'externally-managed-"
                "environment' error, use a venv: python3 -m venv .venv && "
                ".venv/bin/pip install lief, then put that venv's python3 on "
                "PATH.)\n");
            warn_len += snprintf(warnings + warn_len, sizeof(warnings) - warn_len,
                "%s\"lief not installed, elf layer skipped\"", warn_len ? "," : "");
        } else {
            char* probe = run_lief_probe(workdir, &so_list);
            if (probe) {
                elf_json = probe;
                ran_elf = 1;
            } else {
                warn_len += snprintf(warnings + warn_len, sizeof(warnings) - warn_len,
                    "%s\"elf probe produced no parseable output\"", warn_len ? "," : "");
            }
        }
    }

    // --- DEX layer ---
    if (dex_list.count > 0) {
        if (!cmd_on_path("dexdump")) {
            ren_print(ctx, (char*)
                "[protofp] 'dexdump' not found on PATH -- DEX/bytecode layer "
                "(DexGuard-style fingerprint) skipped. It ships with the "
                "Android SDK build-tools (find it with `which dexdump` after "
                "adding <sdk>/build-tools/<ver>/ to PATH).\n");
            warn_len += snprintf(warnings + warn_len, sizeof(warnings) - warn_len,
                "%s\"dexdump not installed, dex layer skipped\"", warn_len ? "," : "");
        } else {
            char dumpfile[128];
            snprintf(dumpfile, sizeof(dumpfile), "%s/dexdump_combined.txt", workdir);
            char cmd[4096] = "";
            for (int i = 0; i < dex_list.count; i++) {
                char one[1024];
                snprintf(one, sizeof(one), "dexdump -d '%s' 2>/dev/null; ", dex_list.paths[i]);
                strncat(cmd, one, sizeof(cmd) - strlen(cmd) - 1);
            }
            char full[4608];
            snprintf(full, sizeof(full), "(%s) > '%s' 2>/dev/null", cmd, dumpfile);
            system(full);
            build_dexguard_candidate(dumpfile, dex_list.count, dex_candidate, sizeof(dex_candidate));
            ran_dex = 1;
        }
    }

    if (!ran_elf && !ran_dex) {
        // Nothing could actually run (e.g. a bare .so with no lief, or a
        // bare .dex with no dexdump) -- there is truly nothing to report.
        ren_print(ctx, (char*)"[protofp] No usable analysis tool available for this input; aborting.\n");
        set_error_result(path, so_list.count > 0 ? "lief_not_installed" : "dexdump_not_installed");
        if (have_workdir) { char rm[96]; snprintf(rm, sizeof(rm), "rm -rf '%s'", workdir); system(rm); }
        return -1;
    }

    // --- Merge candidates ---
    char candidates[4096] = "";
    size_t cand_len = 0;
    if (elf_json) {
        // Strip outer "[" "]" and splice the inner items verbatim.
        size_t n = strlen(elf_json);
        if (n >= 2) {
            size_t inner_len = n - 2;
            if (inner_len > 0) {
                cand_len += snprintf(candidates + cand_len, sizeof(candidates) - cand_len,
                    "%.*s", (int)inner_len, elf_json + 1);
            }
        }
        free(elf_json);
    }
    if (dex_candidate[0]) {
        cand_len += snprintf(candidates + cand_len, sizeof(candidates) - cand_len,
            "%s%s", cand_len ? "," : "", dex_candidate);
    }

    const char* coverage;
    if (ran_elf && ran_dex) coverage = "elf+dex";
    else if (ran_elf)       coverage = "elf-loader-only";
    else                    coverage = "dex-bytecode-only";

    char input_escaped[512];
    json_escape(input_escaped, sizeof(input_escaped), path);

    if (warn_len > 0) {
        snprintf(g_last_result_json, sizeof(g_last_result_json),
            "{\"tool\":\"protofp\",\"status\":\"ok\",\"input\":\"%s\",\"coverage\":\"%s\","
            "\"candidates\":[%s],\"warnings\":[%s]}",
            input_escaped, coverage, candidates, warnings);
    } else {
        snprintf(g_last_result_json, sizeof(g_last_result_json),
            "{\"tool\":\"protofp\",\"status\":\"ok\",\"input\":\"%s\",\"coverage\":\"%s\","
            "\"candidates\":[%s]}",
            input_escaped, coverage, candidates);
    }

    if (cand_len == 0) {
        ren_print(ctx, (char*)"[protofp] No protector signatures detected (candidates: []).\n");
    } else {
        ren_print(ctx, (char*)"[protofp] Candidate(s) found -- see structured result for details:\n");
    }
    ren_print(ctx, g_last_result_json);
    ren_print(ctx, (char*)"\n");

    if (have_workdir) {
        char rm[96];
        snprintf(rm, sizeof(rm), "rm -rf '%s'", workdir);
        system(rm);
    }

    return 0;
}

// Hands back the most recent run's structured result (success or error
// shape -- see set_error_result() / the "ok" branch in ren_plugin_exec()
// above) as one JSON object, consumed by PluginCommandDispatcher::dispatch()
// immediately after ren_plugin_exec() returns (see plugin.h's
// ren_plugin_result_json_fn contract, and redex_plugin.c for the pattern
// this mirrors).
char* ren_plugin_result_json(void) {
    if (!g_last_ran || !g_last_result_json[0]) return NULL;
    return strdup(g_last_result_json);
}
