#include <agent/lua_engine.h>
#include <agent/globals.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <unistd.h>
#include <sys/mman.h>
#include <android/log.h>
#include <agent/lua_hook.h>
#include <agent/lua_memory.h>
#include <agent/lua_thread.h>
#include <agent/lua_file.h>
#include <agent/lua_os.h>
#include <agent/lua_jni.h>
#include <agent/lua_java.h>
#include <agent/lua_strace.h>
#include <agent/lua_kcov.h>
#include <agent/proc.h>
#include <agent/output_queue.h>
#include <capstone/capstone.h>

#define TAG "RENEF_LUA"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

extern int g_output_client_fd;

/* ---------------------------------------------------------------------- *
 * send(table) -- structured event channel.
 *
 * Wire-level design (read this before touching any host-side code that
 * parses agent output -- cmd_eval.cpp, cmd_watch.cpp, cmd_load.cpp, the
 * TUI/GUI console tabs, main.cpp's send_command()):
 *
 *   - console.log()/print() already stream to the host as plain,
 *     newline-delimited text over the *same* agent<->server socket used
 *     for everything else (see send_to_cli() below, and
 *     capture_write()/filter_and_send() in agent.c). Every existing
 *     forwarder (cmd_watch.cpp's relay loop, cmd_eval.cpp's recv loop) just
 *     copies those bytes through verbatim -- there is no separate
 *     "message type" in this transport, only lines of text.
 *   - Rather than inventing a second wire format/message type (which every
 *     one of those forwarders would then have to learn to demux), send()
 *     reuses that exact same line-oriented channel. A send() line is a
 *     normal output line that always starts with the literal prefix
 *     "[event] ", followed by one line of compact JSON (the encoder below
 *     never emits a raw '\n' -- string values are escaped as \n), e.g.:
 *
 *         [event] {"type":"test_finding","value":42}
 *
 *   - This is purely additive: any client that has never heard of send()
 *     still just sees one more harmless text line; nothing about the
 *     existing "OK"/"ERROR: ..." markers (cmd_eval.cpp) or the
 *     `{"success":...}` command-result JSON (cmd.cpp) changes shape.
 *     A pipeline (or the host CLI, see main.cpp) can reliably recover
 *     structured events by splitting stdout/the stream on '\n' and
 *     checking line.startswith("[event] ") -- no socket/framing change
 *     needed on the client side.
 *   - Known, accepted limitation: if a script's own print()/console.log()
 *     call happens to emit text starting with "[event] ", a consumer would
 *     misclassify that line as a structured event. Both channels are
 *     fully script-controlled text, so this is the accepted tradeoff for
 *     keeping this the smallest possible change to the transport
 *     (reusing the existing framing instead of a new wire message type).
 * ---------------------------------------------------------------------- */
#define RENEF_EVENT_TAG "[event] "
#define JSON_MAX_DEPTH 16

typedef struct {
    char* data;
    size_t cap;
    size_t len;
} json_buf_t;

static void jbuf_init(json_buf_t* b) {
    b->cap = 256;
    b->data = (char*)malloc(b->cap);
    b->len = 0;
    if (b->data) b->data[0] = '\0';
}

static void jbuf_ensure(json_buf_t* b, size_t extra) {
    if (!b->data) return;
    if (b->len + extra + 1 <= b->cap) return;
    size_t new_cap = b->cap * 2;
    while (new_cap < b->len + extra + 1) new_cap *= 2;
    char* nb = (char*)realloc(b->data, new_cap);
    if (!nb) {
        /* Keep the old buffer (truncated output) rather than leak/crash. */
        return;
    }
    b->data = nb;
    b->cap = new_cap;
}

static void jbuf_putc(json_buf_t* b, char c) {
    jbuf_ensure(b, 1);
    if (!b->data) return;
    b->data[b->len++] = c;
    b->data[b->len] = '\0';
}

static void jbuf_puts(json_buf_t* b, const char* s) {
    size_t n = strlen(s);
    jbuf_ensure(b, n);
    if (!b->data) return;
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static void jbuf_put_escaped(json_buf_t* b, const char* s, size_t len) {
    jbuf_putc(b, '"');
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  jbuf_puts(b, "\\\""); break;
            case '\\': jbuf_puts(b, "\\\\"); break;
            case '\n': jbuf_puts(b, "\\n"); break;
            case '\r': jbuf_puts(b, "\\r"); break;
            case '\t': jbuf_puts(b, "\\t"); break;
            default:
                if (c < 0x20) {
                    char esc[8];
                    snprintf(esc, sizeof(esc), "\\u%04x", c);
                    jbuf_puts(b, esc);
                } else {
                    jbuf_putc(b, (char)c);
                }
        }
    }
    jbuf_putc(b, '"');
}

/* A table is encoded as a JSON array iff its raw length n > 0 and the
 * table has *exactly* n keys total (i.e. the integer keys 1..n account for
 * every entry) -- otherwise it's encoded as an object. Good enough for the
 * common send() payloads (plain arrays or plain string-keyed objects);
 * sparse/mixed tables fall back to object encoding with stringified keys
 * rather than being dropped. */
static int lua_table_is_array(lua_State* L, int idx) {
    lua_Integer n = (lua_Integer)lua_rawlen(L, idx);
    if (n == 0) return 0;

    lua_Integer total_keys = 0;
    lua_pushnil(L);
    while (lua_next(L, idx) != 0) {
        total_keys++;
        lua_pop(L, 1); /* pop value; key stays on stack for next lua_next */
    }
    return total_keys == n;
}

static void json_encode_value(lua_State* L, int idx, json_buf_t* buf, int depth);

static void json_encode_table(lua_State* L, int idx, json_buf_t* buf, int depth) {
    idx = lua_absindex(L, idx);

    if (depth >= JSON_MAX_DEPTH) {
        /* Guards against pathological/cyclic tables; send() payloads are
         * expected to be small, flat-ish findings, not deep graphs. */
        jbuf_puts(buf, "null");
        return;
    }

    if (lua_table_is_array(L, idx)) {
        lua_Integer n = (lua_Integer)lua_rawlen(L, idx);
        jbuf_putc(buf, '[');
        for (lua_Integer i = 1; i <= n; i++) {
            if (i > 1) jbuf_putc(buf, ',');
            lua_rawgeti(L, idx, i);
            json_encode_value(L, -1, buf, depth + 1);
            lua_pop(L, 1);
        }
        jbuf_putc(buf, ']');
        return;
    }

    jbuf_putc(buf, '{');
    int first = 1;
    lua_pushnil(L);
    while (lua_next(L, idx) != 0) {
        /* stack: ... key value */
        if (!first) jbuf_putc(buf, ',');
        first = 0;

        if (lua_type(L, -2) == LUA_TSTRING) {
            size_t klen;
            const char* kstr = lua_tolstring(L, -2, &klen);
            jbuf_put_escaped(buf, kstr, klen);
        } else {
            /* Stringify non-string keys (e.g. numeric keys in a sparse
             * table) so the field isn't silently dropped. */
            lua_pushvalue(L, -2);
            const char* kstr = lua_tostring(L, -1);
            size_t klen = kstr ? strlen(kstr) : 0;
            jbuf_put_escaped(buf, kstr ? kstr : "", klen);
            lua_pop(L, 1);
        }

        jbuf_putc(buf, ':');
        json_encode_value(L, -1, buf, depth + 1);

        lua_pop(L, 1); /* pop value, keep key for lua_next */
    }
    jbuf_putc(buf, '}');
}

static void json_encode_value(lua_State* L, int idx, json_buf_t* buf, int depth) {
    idx = lua_absindex(L, idx);
    int t = lua_type(L, idx);
    switch (t) {
        case LUA_TNIL:
            jbuf_puts(buf, "null");
            break;
        case LUA_TBOOLEAN:
            jbuf_puts(buf, lua_toboolean(L, idx) ? "true" : "false");
            break;
        case LUA_TNUMBER:
            if (lua_isinteger(L, idx)) {
                char tmp[32];
                snprintf(tmp, sizeof(tmp), "%lld", (long long)lua_tointeger(L, idx));
                jbuf_puts(buf, tmp);
            } else {
                double d = (double)lua_tonumber(L, idx);
                if (isnan(d) || isinf(d)) {
                    jbuf_puts(buf, "null"); /* JSON has no NaN/Infinity */
                } else {
                    char tmp[48];
                    snprintf(tmp, sizeof(tmp), "%.17g", d);
                    jbuf_puts(buf, tmp);
                }
            }
            break;
        case LUA_TSTRING: {
            size_t slen;
            const char* s = lua_tolstring(L, idx, &slen);
            jbuf_put_escaped(buf, s, slen);
            break;
        }
        case LUA_TTABLE:
            json_encode_table(L, idx, buf, depth);
            break;
        default:
            /* functions/userdata/threads/light userdata: not representable
             * in JSON -- emit null rather than erroring the whole event. */
            jbuf_puts(buf, "null");
            break;
    }
}

static int lua_send(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);

    json_buf_t buf;
    jbuf_init(&buf);
    if (!buf.data) {
        return luaL_error(L, "send(): out of memory");
    }

    json_encode_value(L, 1, &buf, 0);

    LOGI("[SEND] %s", buf.data);

    if (g_output_client_fd >= 0) {
        // One write() for the whole line. As three separate writes (tag,
        // payload, newline) the output writer thread - or another
        // thread's send() - could land in between and split the event
        // line, which is exactly the line rpc and scripted clients parse.
        size_t tag_len = strlen(RENEF_EVENT_TAG);
        size_t total = tag_len + buf.len + 1;
        char stack_line[1024];
        char* line = (total <= sizeof(stack_line)) ? stack_line : (char*)malloc(total);
        if (line) {
            memcpy(line, RENEF_EVENT_TAG, tag_len);
            memcpy(line + tag_len, buf.data, buf.len);
            line[tag_len + buf.len] = '\n';
            if (output_queue_is_event_context()) {
                // send() from a hook callback: an event, not part of
                // whatever command happens to be running.
                output_queue_push(line, total);
            } else {
                // Written directly, not queued: an rpc result can be far
                // larger than the queue, which would drop it whole.
                write(g_output_client_fd, line, total);
            }
            if (line != stack_line) free(line);
        }
    }

    free(buf.data);
    return 0;
}


/* NOTE: this only enqueues into the bounded output_queue (see
 * agent/output_queue.h) -- it never calls write() itself. The real,
 * possibly-blocking socket write happens later on a dedicated writer
 * thread that does not hold g_lua_mutex, so a slow/stalled host read
 * can no longer freeze every hooked call in the target process. */
static void send_to_cli(const char* msg) {
    LOGI("[CLI_SEND] g_output_client_fd=%d, msg=%s", g_output_client_fd, msg ? msg : "NULL");
    if (g_output_client_fd >= 0 && msg) {
        size_t len = strlen(msg);
        // No heap allocation on this path for ordinary lines: print() is
        // what callbacks do, and a callback can be running inside the
        // process allocator (see lua_private_alloc).
        char stack_buf[2048];
        if (len + 1 <= sizeof(stack_buf)) {
            memcpy(stack_buf, msg, len);
            stack_buf[len] = '\n';
            output_queue_push(stack_buf, len + 1);
        } else {
            char* buf = (char*)malloc(len + 1);
            if (buf) {
                memcpy(buf, msg, len);
                buf[len] = '\n';
                output_queue_push(buf, len + 1);
                free(buf);
            }
        }
    } else {
        LOGI("[CLI_SEND] SKIPPED - fd=%d", g_output_client_fd);
    }
}

static int lua_console_log(lua_State* L) {
    const char* msg = luaL_checkstring(L, 1);

    LOGI("[SCRIPT] %s", msg);

    send_to_cli(msg);

    return 0;
}


static int lua_list_modules(lua_State* L){
    char* l_libs = get_loaded_libraries();
    lua_pushstring(L, l_libs);
    free(l_libs); 
    return 1;
}

static int lua_find_module(lua_State* L){
    const char* lib_name = luaL_checkstring(L, 1);
    void* base = find_library_base(lib_name); 
    
    if (base) {
        lua_pushinteger(L, (uintptr_t)base);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

static int lua_module_exports(lua_State* L) {
    const char* lib_name = luaL_checkstring(L, 1);
    elf_exports_t* exports = get_exports(lib_name);

    if (!exports) {
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);
    for (size_t i = 0; i < exports->count; i++) {
        lua_newtable(L);
        lua_pushstring(L, exports->exports[i].name);
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, exports->exports[i].offset);
        lua_setfield(L, -2, "offset");
        lua_rawseti(L, -2, i + 1);
    }

    free_elf_exports(exports);
    return 1;
}

/* Classic shell-style glob matcher: '*' matches any run of characters
 * (including none), '?' matches exactly one character, everything else must
 * match literally. Case-sensitive. Used by Module.findExportByName so a
 * plain name (no wildcards) still behaves as an exact match. */
static bool glob_match(const char* pattern, const char* str) {
    const char* p = pattern;
    const char* s = str;
    const char* star_p = NULL;
    const char* star_s = NULL;

    while (*s) {
        if (*p == '?' || *p == *s) {
            p++;
            s++;
        } else if (*p == '*') {
            star_p = p++;
            star_s = s;
        } else if (star_p) {
            p = star_p + 1;
            s = ++star_s;
        } else {
            return false;
        }
    }

    while (*p == '*') p++;
    return *p == '\0';
}

/*
 * Module.findExportByName(module, pattern)
 *
 * Search a module's exports for names matching a glob pattern ('*' = any run
 * of characters, '?' = any single character). A pattern with no wildcard
 * characters behaves as an exact-name match, so this subsumes a plain
 * lookup as well as a search:
 *
 *   Module.findExportByName("libc.so", "pthread_*")  -- all pthread_* exports
 *   Module.findExportByName("libc.so", "malloc")     -- exact match only
 *
 * Returns: array of { name, offset } (possibly empty if nothing matches),
 * or nil if the module itself could not be found/parsed.
 */
static int lua_module_find_export_by_name(lua_State* L) {
    const char* lib_name = luaL_checkstring(L, 1);
    const char* pattern = luaL_checkstring(L, 2);

    elf_exports_t* exports = get_exports(lib_name);
    if (!exports) {
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);
    int idx = 1;
    for (size_t i = 0; i < exports->count; i++) {
        if (!glob_match(pattern, exports->exports[i].name)) {
            continue;
        }
        lua_newtable(L);
        lua_pushstring(L, exports->exports[i].name);
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, exports->exports[i].offset);
        lua_setfield(L, -2, "offset");
        lua_rawseti(L, -2, idx++);
    }

    free_elf_exports(exports);
    return 1;
}

static int lua_module_symbols(lua_State* L) {
    const char* lib_name = luaL_checkstring(L, 1);
    elf_exports_t* symbols = get_symbols(lib_name);

    if (!symbols) {
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);
    for (size_t i = 0; i < symbols->count; i++) {
        lua_newtable(L);
        lua_pushstring(L, symbols->exports[i].name);
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, symbols->exports[i].offset);
        lua_setfield(L, -2, "offset");
        lua_rawseti(L, -2, i + 1);
    }

    free_elf_exports(symbols);
    return 1;
}

/* Cap on Module.disassemble's `count` argument. Keeps a single call bounded
 * (same spirit as Memory.search's DEFAULT_MAX_RESULTS / size caps) instead
 * of letting a script disassemble an unbounded number of instructions in
 * one shot. */
#define MAX_DISASM_COUNT 1024

/* Returns true iff [addr, addr+len) lies entirely inside one readable
 * /proc/self/maps region. The agent is injected into the target process, so
 * Module.disassemble reads straight out of its own address space (no IPC,
 * no separate "read" step) - but a script can pass any integer as `addr`,
 * so this guards against disassembling garbage/unmapped memory and
 * crashing the whole target process. Same maps-scanning approach already
 * used throughout api_memory.c (memory_search et al.). */
static bool addr_range_is_readable(uintptr_t addr, size_t len) {
    if (len == 0) return false;

    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return false;

    char line[512];
    bool ok = false;

    while (fgets(line, sizeof(line), maps)) {
        char range[64], perms[8];
        if (sscanf(line, "%63s %7s", range, perms) < 2) continue;
        if (perms[0] != 'r') continue;  /* region must be readable */

        char* dash = strchr(range, '-');
        if (!dash) continue;
        *dash = '\0';

        uintptr_t start = (uintptr_t)strtoull(range, NULL, 16);
        uintptr_t end = (uintptr_t)strtoull(dash + 1, NULL, 16);

        if (addr >= start && addr <= end && (end - addr) >= len) {
            ok = true;
            break;
        }
    }

    fclose(maps);
    return ok;
}

/*
 * Module.disassemble(addr, count)
 *
 * Disassemble `count` ARM64 instructions starting at `addr`. Capstone reads
 * directly from the live process buffer at `addr` - the agent already lives
 * inside the target's address space (that's what libagent.so being injected
 * means), so there is no separate memory-read step to perform first, unlike
 * a hypothetical remote-process disassembler. This mirrors
 * disassemble_instructions() in hook/native.c, which does the same thing for
 * trampoline-hook prologues.
 *
 * AArch64 (A64 state - this target never uses Thumb) instructions are a
 * fixed 4 bytes wide, so `count * 4` is exactly the byte range that must be
 * mapped and readable; that range is validated up front via
 * addr_range_is_readable() before Capstone ever touches it, so a bogus
 * address raises a Lua error instead of crashing the hooked process.
 *
 * CS_OPT_DETAIL is enabled so cs_insn.detail->groups is populated (needed to
 * compute is_branch/is_call/is_jump below). Detail mode makes Capstone fill
 * in a much larger per-instruction struct (operands, groups, regs
 * read/written, etc.) which costs extra time/memory per decoded instruction
 * versus the default; since `count` is capped (MAX_DISASM_COUNT) and this
 * isn't a hot path like the inline-hook codegen, that tradeoff is fine here.
 *
 * Returns a 1-indexed table of instructions:
 *   { address, size, mnemonic, op_str, is_branch, is_call, is_jump }
 * `op_str` is Capstone's formatted operand string (e.g. "x0, x1, #4") -
 * deliberately not decomposed into structured operand objects, that's out
 * of scope here. is_call/is_jump come straight from
 * Capstone's generic CS_GRP_CALL/CS_GRP_JUMP groups; is_branch is the
 * broader "this instruction can transfer control flow" umbrella (jump, call,
 * return, or PC-relative branch).
 *
 * On a bad address, a bad count, or a Capstone failure this raises a Lua
 * error via luaL_error, matching the convention used by other hard-failure
 * paths in this module (e.g. hexdump's unsupported-type errors).
 */
static int lua_module_disassemble(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_Integer count = luaL_checkinteger(L, 2);

    if (addr == 0) {
        return luaL_error(L, "Module.disassemble: addr must be non-zero");
    }
    if (count <= 0) {
        return luaL_error(L, "Module.disassemble: count must be > 0");
    }
    if (count > MAX_DISASM_COUNT) {
        count = MAX_DISASM_COUNT;
    }

    size_t need_bytes = (size_t)count * 4;

    /* Lua's own lua_pushfstring/luaL_error formatter (lua_pushvfstring in
     * lobject.c) only understands %d/%u/%s/%c/%p/%U/%% - no 'l' length
     * modifier and no %x at all, unlike C's printf. So addresses are
     * pre-formatted into a plain buffer with snprintf (which does support
     * %lx) and handed to luaL_error as a %s instead of being interpolated
     * directly. */
    if (!addr_range_is_readable(addr, need_bytes)) {
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "Module.disassemble: 0x%lx (%d instructions) is not in a readable memory region",
                 (unsigned long)addr, (int)count);
        return luaL_error(L, "%s", msg);
    }

    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        return luaL_error(L, "Module.disassemble: cs_open failed");
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insn = NULL;
    size_t n = cs_disasm(handle, (const uint8_t*)addr, need_bytes,
                          (uint64_t)addr, (size_t)count, &insn);
    if (n == 0) {
        cs_close(&handle);
        char msg[96];
        snprintf(msg, sizeof(msg),
                 "Module.disassemble: failed to decode any instruction at 0x%lx",
                 (unsigned long)addr);
        return luaL_error(L, "%s", msg);
    }

    lua_newtable(L);
    for (size_t i = 0; i < n; i++) {
        cs_insn* ins = &insn[i];

        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)ins->address);
        lua_setfield(L, -2, "address");
        lua_pushinteger(L, (lua_Integer)ins->size);
        lua_setfield(L, -2, "size");
        lua_pushstring(L, ins->mnemonic);
        lua_setfield(L, -2, "mnemonic");
        lua_pushstring(L, ins->op_str);
        lua_setfield(L, -2, "op_str");

        bool is_jump = cs_insn_group(handle, ins, CS_GRP_JUMP);
        bool is_call = cs_insn_group(handle, ins, CS_GRP_CALL);
        bool is_branch = is_jump || is_call ||
                          cs_insn_group(handle, ins, CS_GRP_RET) ||
                          cs_insn_group(handle, ins, CS_GRP_BRANCH_RELATIVE);

        lua_pushboolean(L, is_branch);
        lua_setfield(L, -2, "is_branch");
        lua_pushboolean(L, is_call);
        lua_setfield(L, -2, "is_call");
        lua_pushboolean(L, is_jump);
        lua_setfield(L, -2, "is_jump");

        lua_rawseti(L, -2, (int)(i + 1));
    }

    cs_free(insn, n);
    cs_close(&handle);
    return 1;
}


static int lua_jni_string(lua_State* L) {
    const char* value = luaL_checkstring(L, 1);
    lua_newtable(L);
    lua_pushstring(L, "string");
    lua_setfield(L, -2, "__jni_type");
    lua_pushstring(L, value);
    lua_setfield(L, -2, "value");
    return 1;
}

static int lua_jni_int(lua_State* L) {
    lua_Integer value = luaL_checkinteger(L, 1);
    lua_newtable(L);
    lua_pushstring(L, "int");
    lua_setfield(L, -2, "__jni_type");
    lua_pushinteger(L, value);
    lua_setfield(L, -2, "value");
    return 1;
}

static int lua_jni_long(lua_State* L) {
    lua_Integer value = luaL_checkinteger(L, 1);
    lua_newtable(L);
    lua_pushstring(L, "long");
    lua_setfield(L, -2, "__jni_type");
    lua_pushinteger(L, value);
    lua_setfield(L, -2, "value");
    return 1;
}

static int lua_jni_boolean(lua_State* L) {
    int value = lua_toboolean(L, 1);
    lua_newtable(L);
    lua_pushstring(L, "boolean");
    lua_setfield(L, -2, "__jni_type");
    lua_pushboolean(L, value);
    lua_setfield(L, -2, "value");
    return 1;
}


static int lua_print(lua_State* L) {
    int n = lua_gettop(L);
    lua_getglobal(L, "tostring");

    for (int i = 1; i <= n; i++) {
        lua_pushvalue(L, -1);
        lua_pushvalue(L, i);
        lua_call(L, 1, 1);

        const char* s = lua_tostring(L, -1);
        if (s) {
            LOGI("[SCRIPT] %s", s);
            send_to_cli(s);
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
    return 0;
}

void register_renef_api(lua_State* L) {
    lua_pushcfunction(L, lua_print);
    lua_setglobal(L, "print");

    lua_pushcfunction(L, lua_send);
    lua_setglobal(L, "send");

    lua_pushstring(L, "\033[0m");
    lua_setglobal(L, "RESET");
    lua_pushstring(L, "\033[31m");
    lua_setglobal(L, "RED");
    lua_pushstring(L, "\033[32m");
    lua_setglobal(L, "GREEN");
    lua_pushstring(L, "\033[33m");
    lua_setglobal(L, "YELLOW");
    lua_pushstring(L, "\033[34m");
    lua_setglobal(L, "BLUE");
    lua_pushstring(L, "\033[35m");
    lua_setglobal(L, "MAGENTA");
    lua_pushstring(L, "\033[36m");
    lua_setglobal(L, "CYAN");
    lua_pushstring(L, "\033[37m");
    lua_setglobal(L, "WHITE");

    lua_newtable(L);
    lua_pushcfunction(L, lua_console_log);
    lua_setfield(L, -2, "log");
    lua_setglobal(L, "console");

    lua_newtable(L);
    lua_pushcfunction(L, lua_list_modules);
    lua_setfield(L, -2, "list");
    lua_pushcfunction(L, lua_find_module);
    lua_setfield(L, -2, "find");
    lua_pushcfunction(L, lua_module_exports);
    lua_setfield(L, -2, "exports");
    lua_pushcfunction(L, lua_module_symbols);
    lua_setfield(L, -2, "symbols");
    lua_pushcfunction(L, lua_module_find_export_by_name);
    lua_setfield(L, -2, "findExportByName");
    lua_pushcfunction(L, lua_module_disassemble);
    lua_setfield(L, -2, "disassemble");

    lua_setglobal(L, "Module");


    lua_newtable(L);
    lua_pushcfunction(L, lua_jni_string);
    lua_setfield(L, -2, "string");
    lua_pushcfunction(L, lua_jni_int);
    lua_setfield(L, -2, "int");
    lua_pushcfunction(L, lua_jni_long);
    lua_setfield(L, -2, "long");
    lua_pushcfunction(L, lua_jni_boolean);
    lua_setfield(L, -2, "boolean");
    lua_setglobal(L, "JNI");

    LOGI("Registering memory API...");
    register_memory_api(L);
    LOGI("Registering thread API...");
    lua_register_thread(L);
    LOGI("Registering JNI API...");
    lua_register_jni(L);
    LOGI("Registering Java API...");
    lua_register_java(L);
    LOGI("All APIs registered");
}

// ---------------------------------------------------------------------------
// Private allocator for the Lua VM
//
// The VM must not share the process allocator. Hook callbacks run on the
// target's own threads, at whatever point the hooked function is called -
// which, for functions libc uses internally (syscall() carries every futex
// wait, mmap()/munmap()/madvise() serve the allocator), can be INSIDE
// malloc() with allocator locks held. A Lua callback that then allocates
// through the same allocator takes those locks in the opposite order.
// Found live with syscall() hooked: the main thread sat in a callback,
// inside lua's realloc() -> scudo lock slow path, forever; the app froze.
// (Frida's runtime avoids the process heap for the same reason.)
//
// Lua always tells its allocator the old size of a block, so no headers
// are needed: blocks come from size-class free lists carved out of
// anonymous mmap()ed chunks, anything large is its own mapping. mmap() is a
// plain system call - it takes no user-space lock. Chunks for small blocks
// are never returned to the OS.
// ---------------------------------------------------------------------------
#define LA_SMALL_STEP 16
#define LA_SMALL_MAX 512                       /* 32 classes: 16, 32, ... 512 */
#define LA_SMALL_CLASSES (LA_SMALL_MAX / LA_SMALL_STEP)
#define LA_POW2_MIN_SHIFT 10                   /* 1KB */
#define LA_POW2_MAX_SHIFT 16                   /* 64KB */
#define LA_POW2_CLASSES (LA_POW2_MAX_SHIFT - LA_POW2_MIN_SHIFT + 1)
#define LA_CLASSES (LA_SMALL_CLASSES + LA_POW2_CLASSES)
#define LA_LARGE_THRESHOLD ((size_t)1 << LA_POW2_MAX_SHIFT)
#define LA_CHUNK_SIZE ((size_t)1 << 20)        /* 1MB */

static void* g_la_free[LA_CLASSES];
static char* g_la_chunk_cur = NULL;
static char* g_la_chunk_end = NULL;
static volatile int g_la_lock = 0;

// Every Lua entry point already holds the VM lock, so this is uncontended;
// it only makes a missing VM lock somewhere a slowdown instead of heap
// corruption. Spin, never block: no libc lock may be taken in here.
static inline void la_lock(void) {
    while (__atomic_exchange_n(&g_la_lock, 1, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_la_lock, __ATOMIC_RELAXED)) { }
    }
}

static inline void la_unlock(void) {
    __atomic_store_n(&g_la_lock, 0, __ATOMIC_RELEASE);
}

static inline size_t la_page_round(size_t n) {
    return (n + 4095) & ~(size_t)4095;
}

// Size class for a small/medium request, and that class's block size.
static inline int la_class(size_t size, size_t* block_size) {
    if (size <= LA_SMALL_MAX) {
        size_t n = (size + LA_SMALL_STEP - 1) / LA_SMALL_STEP;
        if (n == 0) n = 1;
        *block_size = n * LA_SMALL_STEP;
        return (int)(n - 1);
    }
    int shift = LA_POW2_MIN_SHIFT;
    while (((size_t)1 << shift) < size) shift++;
    *block_size = (size_t)1 << shift;
    return LA_SMALL_CLASSES + (shift - LA_POW2_MIN_SHIFT);
}

static void* la_new(size_t size) {
    if (size > LA_LARGE_THRESHOLD) {
        void* m = mmap(NULL, la_page_round(size), PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return (m == MAP_FAILED) ? NULL : m;
    }

    size_t block = 0;
    int cls = la_class(size, &block);
    void* p = g_la_free[cls];
    if (p) {
        g_la_free[cls] = *(void**)p;
        return p;
    }
    if (g_la_chunk_cur == NULL || (size_t)(g_la_chunk_end - g_la_chunk_cur) < block) {
        void* chunk = mmap(NULL, LA_CHUNK_SIZE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (chunk == MAP_FAILED) return NULL;
        g_la_chunk_cur = (char*)chunk;
        g_la_chunk_end = g_la_chunk_cur + LA_CHUNK_SIZE;
    }
    p = g_la_chunk_cur;
    g_la_chunk_cur += block;
    return p;
}

static void la_delete(void* ptr, size_t size) {
    if (!ptr) return;
    if (size > LA_LARGE_THRESHOLD) {
        munmap(ptr, la_page_round(size));
        return;
    }
    size_t block = 0;
    int cls = la_class(size, &block);
    *(void**)ptr = g_la_free[cls];
    g_la_free[cls] = ptr;
}

static void* lua_private_alloc(void* ud, void* ptr, size_t osize, size_t nsize) {
    (void)ud;
    void* result = NULL;
    la_lock();

    if (nsize == 0) {
        la_delete(ptr, osize);
    } else if (ptr == NULL) {
        // (osize carries the object type here, not a size.)
        result = la_new(nsize);
    } else {
        bool same;
        if (osize > LA_LARGE_THRESHOLD || nsize > LA_LARGE_THRESHOLD) {
            same = (osize > LA_LARGE_THRESHOLD && nsize > LA_LARGE_THRESHOLD &&
                    la_page_round(osize) == la_page_round(nsize));
        } else {
            size_t ob = 0, nb = 0;
            same = (la_class(osize, &ob) == la_class(nsize, &nb));
        }
        if (same) {
            result = ptr;
        } else {
            result = la_new(nsize);
            if (result) {
                memcpy(result, ptr, osize < nsize ? osize : nsize);
                la_delete(ptr, osize);
            }
            // On failure the original block is left untouched, as Lua requires.
        }
    }

    la_unlock();
    return result;
}

static int lua_engine_panic(lua_State* L) {
    const char* msg = lua_tostring(L, -1);
    LOGE("PANIC: unprotected error in call to Lua API (%s)", msg ? msg : "error object is not a string");
    return 0; // return to Lua to abort, same as luaL_newstate's default panic
}

LuaEngine* lua_engine_create(void) {
    LuaEngine* engine = malloc(sizeof(LuaEngine));
    if (!engine) {
        LOGI("Failed to allocate LuaEngine");
        return NULL;
    }

    // Equivalent to luaL_newstate(), but on the private allocator above.
    engine->L = lua_newstate(lua_private_alloc, NULL);
    if (engine->L) {
        lua_atpanic(engine->L, lua_engine_panic);
    }
    if (!engine->L) {
        LOGI("Failed to create Lua state");
        free(engine);
        return NULL;
    }

    luaL_openlibs(engine->L);

    register_renef_api(engine->L);
    register_memory_search_api(engine->L);
    register_process_api(engine->L);
    register_file_api(engine->L);
    register_os_api(engine->L);
    register_strace_api(engine->L);
    register_kcov_api(engine->L);

    engine->initialized = true;
    LOGI("Lua engine initialized");

    return engine;
}

void lua_engine_destroy(LuaEngine* engine) {
    if (engine) {
        if (engine->L) {
            lua_close(engine->L);
        }
        free(engine);
        LOGI("Lua engine destroyed");
    }
}

bool lua_engine_load_script(LuaEngine* engine, const char* script) {
    if (!engine || !engine->initialized || !script) {
        return false;
    }

    verbose_log("Loading Lua script (%zu bytes)", strlen(script));

    // Normal script execution (eval/exec/hexexec, and the initial "ready"
    // banner) shares this lua_State with native/Java hook callbacks
    // (native.c, java.c), which run on arbitrary app threads. Without this
    // lock a hot hook firing mid-script-execution races the same lua_State
    // from another thread (reproduced as a SIGSEGV on a device).
    lua_vm_lock();

    int load_result = luaL_loadstring(engine->L, script);
    if (load_result != LUA_OK) {
        const char* error = lua_tostring(engine->L, -1);
        LOGI("Lua compile error: %s", error);
        lua_pop(engine->L, 1);
        lua_vm_unlock();
        return false;
    }

    verbose_log("Script compiled successfully, executing...");

    int exec_result = lua_pcall(engine->L, 0, 0, 0);
    if (exec_result != LUA_OK) {
        const char* error = lua_tostring(engine->L, -1);
        LOGI("Lua runtime error: %s", error);
        lua_pop(engine->L, 1);
        lua_vm_unlock();
        return false;
    }

    lua_vm_unlock();
    verbose_log("Script executed successfully");
    return true;
}

bool lua_engine_load_file(LuaEngine* engine, const char* filepath) {
    if (!engine || !engine->initialized || !filepath) {
        return false;
    }

    verbose_log("Loading Lua file: %s", filepath);

    // Same shared-lua_State rationale as lua_engine_load_script() above.
    lua_vm_lock();

    int load_result = luaL_loadfile(engine->L, filepath);
    if (load_result != LUA_OK) {
        const char* error = lua_tostring(engine->L, -1);
        LOGI("Lua file load error: %s", error);
        lua_pop(engine->L, 1);
        lua_vm_unlock();
        return false;
    }

    verbose_log("File compiled successfully, executing...");

    int exec_result = lua_pcall(engine->L, 0, 0, 0);
    if (exec_result != LUA_OK) {
        const char* error = lua_tostring(engine->L, -1);
        LOGI("Lua file exec error: %s", error);
        lua_pop(engine->L, 1);
        lua_vm_unlock();
        return false;
    }

    lua_vm_unlock();
    verbose_log("File executed successfully: %s", filepath);
    return true;
}

lua_State* lua_engine_get_state(LuaEngine* engine) {
    if (!engine || !engine->initialized) {
        return NULL;
    }
    return engine->L;
}
