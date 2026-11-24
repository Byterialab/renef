// JSON formatter plugin for renef (see plugin.h).
//
// Demonstrates the PLUGIN_FORMATTER plugin type: it exports
// `ren_plugin_format("json", input, input_len)`, which splits whatever text
// it's handed into lines and renders them as a JSON object
// ({"format":"json","lines":[...]}). It declines (returns NULL) for any
// format name other than "json", which is the documented contract in
// plugin.h -- lets another loaded formatter plugin have a turn.
//
// This plugin intentionally owns no CLI command of its own (metadata.command
// is NULL, no ren_plugin_exec export) -- it's pure formatting plumbing,
// invoked by the host-side `format <format_name> <command...>` command
// (src/librenef/cmd/cmd_plugin.cpp), which captures another command's text
// output and hands it to plugin_format().
//
// Build: gcc -shared -fPIC -o json_formatter_plugin.so json_formatter_plugin.c
//        (or `make install` from examples/plugins/, same as test_plugin.c)
//
// Usage (after `plugin load <path-to-json_formatter_plugin.so>`):
//   format json plugins
//   format json plugin list
//
// This is deliberately minimal plumbing -- it does NOT require every
// cmd_*.cpp to grow a structured result type (a separate, larger piece of
// work); it just proves a plugin *can* register as a named
// output formatter and have arbitrary command text routed through it.

#include <renef/plugin.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

RENPluginMetadata ren_plugin_info = {
    .name = "json_formatter",
    .author = "renef",
    .version = "1.0.0",
    .description = "Formats a captured command's text output as JSON (PLUGIN_FORMATTER demo)",
    .command = NULL,            // Pure formatter -- owns no CLI command slot.
    .type = PLUGIN_FORMATTER
};

int ren_plugin_init(renef_ctx_t ctx) {
    (void)ctx;
    return 0;
}

void ren_plugin_close(renef_ctx_t ctx) {
    (void)ctx;
}

// Small growable byte buffer, NUL-terminated after every append.
typedef struct {
    char* data;
    size_t len;
    size_t cap;
    int bad; // set if an allocation ever failed; format() returns NULL in that case
} Buf;

static void buf_init(Buf* b) {
    b->cap = 128;
    b->data = (char*)malloc(b->cap);
    b->len = 0;
    b->bad = (b->data == NULL);
    if (b->data) b->data[0] = '\0';
}

static void buf_ensure(Buf* b, size_t extra) {
    if (b->bad) return;
    if (b->len + extra + 1 <= b->cap) return;

    size_t ncap = b->cap ? b->cap * 2 : 128;
    while (ncap < b->len + extra + 1) ncap *= 2;

    char* nd = (char*)realloc(b->data, ncap);
    if (!nd) {
        b->bad = 1;
        return;
    }
    b->data = nd;
    b->cap = ncap;
}

static void buf_append(Buf* b, const char* s, size_t n) {
    buf_ensure(b, n);
    if (b->bad) return;
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static void buf_append_cstr(Buf* b, const char* s) {
    buf_append(b, s, strlen(s));
}

// Minimal JSON string escaping: quote, backslash, tab, and other C0 control
// chars via \uXXXX. Carriage returns are dropped (line splitting below is
// done on '\n' only, so a lingering '\r' from CRLF output would otherwise
// show up as a literal \r inside the string).
static void buf_append_json_escaped(Buf* b, const char* s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  buf_append_cstr(b, "\\\""); break;
            case '\\': buf_append_cstr(b, "\\\\"); break;
            case '\t': buf_append_cstr(b, "\\t"); break;
            case '\r': break;
            default:
                if (c < 0x20) {
                    char tmp[8];
                    snprintf(tmp, sizeof(tmp), "\\u%04x", c);
                    buf_append_cstr(b, tmp);
                } else {
                    buf_append(b, (const char*)&c, 1);
                }
        }
    }
}

char* ren_plugin_format(const char* format_name, const char* input, size_t input_len) {
    if (!format_name || strcmp(format_name, "json") != 0) {
        return NULL; // Not ours -- let another loaded formatter plugin try.
    }

    Buf b;
    buf_init(&b);
    if (b.bad) return NULL;

    buf_append_cstr(&b, "{\"format\":\"json\",\"lines\":[");

    size_t line_start = 0;
    int first = 1;
    for (size_t i = 0; i <= input_len; i++) {
        if (i == input_len || (input && input[i] == '\n')) {
            size_t line_len = i - line_start;
            int is_trailing_empty = (i == input_len && line_len == 0);
            if (!is_trailing_empty) {
                if (!first) buf_append_cstr(&b, ",");
                first = 0;
                buf_append_cstr(&b, "\"");
                buf_append_json_escaped(&b, input + line_start, line_len);
                buf_append_cstr(&b, "\"");
            }
            line_start = i + 1;
        }
    }

    buf_append_cstr(&b, "]}");

    if (b.bad) {
        free(b.data);
        return NULL;
    }
    return b.data; // Caller (plugin_format(), plugin.cpp) owns this -- it free()s it.
}
