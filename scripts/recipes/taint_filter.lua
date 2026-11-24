-- Taint-Filter Recipe - keyword/function list from a real pentest
--
-- Source: this is NOT a made-up wordlist. Both the keyword list and the
-- function list below come from real, authorized assessments of apps
-- protected by a commercial RASP SDK, where this exact set of libc calls
-- and needles was what the RASP used to detect instrumentation/root
-- tooling. The list was reviewed specifically for the "neutralize if
-- ANY argument contains a keyword" bug described below.
--
-- What this recipe does:
--   Hooks libc string/file functions and, if an argument matches one of the
--   known instrumentation/root/pentest-tooling keywords, makes the call
--   report "not found" - but the CORRECT "not found" for that specific
--   function, not a single blanket answer. Also scrubs TracerPid from
--   /proc/self/status reads (the classic ptrace-self-check anti-debug
--   pattern), since that's a `read()` content-rewrite, not an
--   existence/match check.
--
-- THE BUG THIS RECIPE DELIBERATELY AVOIDS (read this before extending it):
--   An earlier draft of this recipe used one rule for every hooked
--   function: "if any arg contains a keyword, neutralize the call" with a
--   single, shared return value. That is wrong:
--     - strcmp/strncmp/strcasecmp must return NOT EQUAL (non-zero,
--       conventionally 1) - returning 0 would make the "equal" case look
--       like a MATCH, which is backwards for a bypass (most detection code
--       does `if (strcmp(a, "frida") == 0) flag_as_rooted()`, so the
--       correct bypass makes strcmp report "not equal", not "equal").
--     - strstr/strcasestr "not found" is NULL (0), not -1 and not 0-as-a-
--       boolean - these return char*.
--     - fopen "failure" is NULL (0) - a FILE*, not an int.
--     - open/openat/access/stat/lstat/faccessat/readlink "failure" is -1 -
--       these are int/ssize_t, NOT NULL.
--   Mixing these up produces a script that LOOKS like it bypasses
--   detection (your own print() lines say "[*] blocked") while the real
--   return value is nonsensical for that function's ABI and the target's
--   detection logic either crashes the target or - worse - gets a value
--   it doesn't expect and takes the "unknown/safe" branch, OR a value
--   it DOES expect but which is wrong semantically (e.g. "found" instead
--   of "not found"). Every hook below has its own explicit, function-
--   correct return value - there is deliberately no single
--   "neutralize()" helper that every hook funnels through.
--
-- Stability note: this recipe hooks libc functions that every thread calls
-- all the time (access/stat/open/fopen/str*). Renef versions before 0.4.0
-- could crash a busy target after 15-60 s of that traffic. Both causes are
-- fixed: a PC-relative instruction copied into the trampoline without being
-- relocated, and the old Java hook engine, which left a frame on the stack
-- that ART could not walk when an exception was thrown. On Android 11 and
-- older, Java hooks still use the old engine, so the second one can still
-- happen there. Callbacks run under one lock: keep them short on hot
-- functions.
--
-- Usage:
--   renef> l scripts/recipes/taint_filter.lua
--   renef> watch
--   renef> exec taint_filter_stats()
--
-- Depends on (real Renef Lua API - see renef-doc/docs/api/hook.md,
-- memory.md, file.md, thread.md):
--   Interceptor.replace(library, offset, cb) / NativeFunction(addr, retType)
--   Module.find / Module.exports
--   Memory.read / Memory.write / Memory.readString
--   File.fdpath(fd)
--   Thread.id()

__hook_type__ = "trampoline"

-- =====================================================================
-- CONFIG - toggle which hooked functions are active. Off by default:
-- strcmp/strncmp/strcasecmp are hot in some processes (string-heavy
-- native code calls them constantly) - enable deliberately, same spirit
-- as enable_string_contains in root_frida_detection_bypass.lua.
-- =====================================================================
local CONFIG = {
    enable_strstr      = true,
    enable_strcasestr  = true,
    enable_strcmp      = true,
    enable_strncmp     = true,
    enable_strcasecmp  = true,
    enable_open        = true,
    enable_openat      = true,
    enable_access      = true,
    enable_fopen       = true,
    enable_stat        = true,
    enable_lstat       = true,
    enable_faccessat   = true,
    enable_readlink    = true,

    -- /proc/self/status TracerPid scrub via read(). Hot-ish (read() is
    -- called constantly by any process for lots of unrelated things), but
    -- the hook itself is cheap (path check, then skip) unless the fd
    -- really points at /proc/self/status - still off by default to match
    -- the "hot function, opt in" convention used elsewhere in this recipe
    -- library.
    enable_tracerpid_scrub = false,

    verbose = true,
}

local stats = {
    strstr_blocked = 0,
    strcasestr_blocked = 0,
    strcmp_blocked = 0,
    strncmp_blocked = 0,
    strcasecmp_blocked = 0,
    open_blocked = 0,
    openat_blocked = 0,
    access_blocked = 0,
    fopen_blocked = 0,
    stat_blocked = 0,
    lstat_blocked = 0,
    faccessat_blocked = 0,
    readlink_blocked = 0,
    tracerpid_scrubbed = 0,
}

local function log(msg)
    if CONFIG.verbose then
        print(msg)
    end
end

-- =====================================================================
-- THE WORDLIST.
-- Each entry carries its own match mode because treating every token as
-- a blind substring match is itself a smaller version of the same
-- "one rule for everything" bug described above: "su" as a plain
-- substring would false-positive on "assume", "status", "result", ...
-- which are completely ordinary strings a RASP-protected app passes to
-- libc constantly. "su\0" in the source finding specifically means the
-- whole C string IS "su" (a bare argv0/comm/package-name style check),
-- and "/su" means a path ENDING in "/su" (e.g. "/system/bin/su",
-- "/sbin/su") - not merely containing the two characters anywhere.
-- =====================================================================
local KEYWORDS = {
    { tok = "frida",           mode = "substring" },
    { tok = "gum-js",          mode = "substring" },
    { tok = "gmain",           mode = "substring" },
    { tok = "linjector",       mode = "substring" },
    { tok = "pool-frida",      mode = "substring" },
    { tok = "gadget",          mode = "substring" },
    { tok = "magisk",          mode = "substring" },
    { tok = "supolicy",        mode = "substring" },
    { tok = "su",              mode = "exact" },     -- "su\0" in the finding
    { tok = "/su",             mode = "suffix" },    -- path ending in /su
    { tok = "busybox",         mode = "substring" },
    { tok = "xposed",          mode = "substring" },
    { tok = "riru",            mode = "substring" },
    { tok = "zygisk",          mode = "substring" },
    { tok = "substrate",       mode = "substring" },
    { tok = "concon",          mode = "substring" },
    { tok = "topjohnwu",       mode = "substring" },
    { tok = "byteria",         mode = "substring" },
    { tok = "renef",           mode = "substring" },
    { tok = "/data/local/tmp", mode = "substring" },
}

-- Returns true if `str` matches any keyword under its own match mode.
local function taint_match(str)
    if not str then return false end
    local lower = string.lower(str)
    for _, kw in ipairs(KEYWORDS) do
        if kw.mode == "exact" then
            if lower == kw.tok then return true end
        elseif kw.mode == "suffix" then
            local tlen = #kw.tok
            if #lower >= tlen and lower:sub(-tlen) == kw.tok then return true end
        else -- "substring"
            if string.find(lower, kw.tok, 1, true) then return true end
        end
    end
    return false
end

-- =====================================================================
-- Function + argument-role + match-type + result-behavior table.
-- This table IS the real content of this recipe - the keyword list above is just
-- the data it feeds on. Every row says exactly which argument carries the
-- "needle" being checked and what a correct bypass must return.
-- =====================================================================
-- name         | tainted-arg role         | what "no match" means for the ABI
-- -------------+--------------------------+-----------------------------------
-- strstr       | arg1 needle (also arg0)  | NULL (0) - "not found"
-- strcasestr   | arg1 needle (also arg0)  | NULL (0) - "not found"
-- strcmp       | arg0 or arg1             | non-zero - "not equal" (return 1)
-- strncmp      | arg0 or arg1             | non-zero - "not equal" (return 1)
-- strcasecmp   | arg0 or arg1             | non-zero - "not equal" (return 1)
-- open         | arg0 path                | -1  (and conceptually ENOENT)
-- openat       | arg1 path (arg0 is dirfd)| -1
-- access       | arg0 path                | -1
-- fopen        | arg0 path                | NULL (0)
-- stat         | arg0 path                | -1
-- lstat        | arg0 path                | -1
-- faccessat    | arg1 path (arg0 is dirfd)| -1
-- readlink     | arg0 path                | -1

local function safe_native_hook(label, install_fn)
    local ok, err = pcall(install_fn)
    if ok then
        print("[OK] " .. label .. " hooked")
    else
        print("[skip] " .. label .. " hook failed: " .. tostring(err))
    end
    return ok
end

local libc = Module.find("libc.so")
if not libc then
    print("[WARN] libc.so not found (native hooks skipped - shouldn't happen)")
else
    local exports = Module.exports("libc.so")
    local off = {}
    if exports then
        local wanted = {
            "strstr", "strcasestr", "strcmp", "strncmp", "strcasecmp",
            "open", "openat", "access", "fopen", "stat", "lstat",
            "faccessat", "readlink", "read",
        }
        local wanted_set = {}
        for _, n in ipairs(wanted) do wanted_set[n] = true end
        for _, exp in ipairs(exports) do
            if wanted_set[exp.name] then
                off[exp.name] = exp.offset
            end
        end
    end

    -- ---------------------------------------------------------------
    -- strstr(haystack, needle) -> char* ; NULL = "not found"
    -- ---------------------------------------------------------------
    if CONFIG.enable_strstr and off.strstr then
        safe_native_hook("libc strstr()", function()
            local real = NativeFunction(libc + off.strstr, "pointer")
            Interceptor.replace("libc.so", off.strstr, function(args)
                local haystack = Memory.readString(args[0])
                local needle = Memory.readString(args[1])
                if taint_match(needle) or taint_match(haystack) then
                    stats.strstr_blocked = stats.strstr_blocked + 1
                    log("[*] strstr() tainted needle/haystack -> NULL (needle=\"" ..
                        tostring(needle) .. "\")")
                    return 0 -- NULL: "not found"
                end
                return real(args[0], args[1])
            end)
        end)
    end

    -- ---------------------------------------------------------------
    -- strcasestr(haystack, needle) -> char* ; NULL = "not found"
    -- ---------------------------------------------------------------
    if CONFIG.enable_strcasestr and off.strcasestr then
        safe_native_hook("libc strcasestr()", function()
            local real = NativeFunction(libc + off.strcasestr, "pointer")
            Interceptor.replace("libc.so", off.strcasestr, function(args)
                local haystack = Memory.readString(args[0])
                local needle = Memory.readString(args[1])
                if taint_match(needle) or taint_match(haystack) then
                    stats.strcasestr_blocked = stats.strcasestr_blocked + 1
                    log("[*] strcasestr() tainted needle/haystack -> NULL (needle=\"" ..
                        tostring(needle) .. "\")")
                    return 0 -- NULL: "not found"
                end
                return real(args[0], args[1])
            end)
        end)
    end

    -- ---------------------------------------------------------------
    -- strcmp(a, b) -> int ; correct bypass = NOT EQUAL (non-zero).
    -- Returning 0 here would tell the caller "these ARE equal", which is
    -- backwards - most detection code does
    -- `if (strcmp(x, "frida") == 0) report_rooted();`, so "not equal" is
    -- the value that makes the detector conclude "no match".
    -- ---------------------------------------------------------------
    if CONFIG.enable_strcmp and off.strcmp then
        safe_native_hook("libc strcmp()", function()
            local real = NativeFunction(libc + off.strcmp, "int")
            Interceptor.replace("libc.so", off.strcmp, function(args)
                local a = Memory.readString(args[0])
                local b = Memory.readString(args[1])
                if taint_match(a) or taint_match(b) then
                    stats.strcmp_blocked = stats.strcmp_blocked + 1
                    log(string.format("[*] strcmp(\"%s\", \"%s\") forced NOT-EQUAL", tostring(a), tostring(b)))
                    return 1 -- non-zero: "not equal"
                end
                return real(args[0], args[1])
            end)
        end)
    end

    -- ---------------------------------------------------------------
    -- strncmp(a, b, n) -> int ; same "not equal" rule as strcmp.
    -- ---------------------------------------------------------------
    if CONFIG.enable_strncmp and off.strncmp then
        safe_native_hook("libc strncmp()", function()
            local real = NativeFunction(libc + off.strncmp, "int")
            Interceptor.replace("libc.so", off.strncmp, function(args)
                local n = args[2]
                local a = Memory.readString(args[0], n)
                local b = Memory.readString(args[1], n)
                if taint_match(a) or taint_match(b) then
                    stats.strncmp_blocked = stats.strncmp_blocked + 1
                    log(string.format("[*] strncmp(\"%s\", \"%s\", %d) forced NOT-EQUAL",
                        tostring(a), tostring(b), n))
                    return 1 -- non-zero: "not equal"
                end
                return real(args[0], args[1], args[2])
            end)
        end)
    end

    -- ---------------------------------------------------------------
    -- strcasecmp(a, b) -> int ; same "not equal" rule, case-insensitive
    -- comparison is already handled by taint_match()'s lower() step.
    -- ---------------------------------------------------------------
    if CONFIG.enable_strcasecmp and off.strcasecmp then
        safe_native_hook("libc strcasecmp()", function()
            local real = NativeFunction(libc + off.strcasecmp, "int")
            Interceptor.replace("libc.so", off.strcasecmp, function(args)
                local a = Memory.readString(args[0])
                local b = Memory.readString(args[1])
                if taint_match(a) or taint_match(b) then
                    stats.strcasecmp_blocked = stats.strcasecmp_blocked + 1
                    log(string.format("[*] strcasecmp(\"%s\", \"%s\") forced NOT-EQUAL", tostring(a), tostring(b)))
                    return 1 -- non-zero: "not equal"
                end
                return real(args[0], args[1])
            end)
        end)
    end

    -- ---------------------------------------------------------------
    -- open(path, flags, ...) -> int fd ; -1 = failure
    -- ---------------------------------------------------------------
    if CONFIG.enable_open and off.open then
        safe_native_hook("libc open()", function()
            local real = NativeFunction(libc + off.open, "int")
            Interceptor.replace("libc.so", off.open, function(args)
                local path = Memory.readString(args[0])
                if taint_match(path) then
                    stats.open_blocked = stats.open_blocked + 1
                    log("[*] open(\"" .. tostring(path) .. "\") -> -1")
                    return -1
                end
                return real(args[0], args[1], args[2])
            end)
        end)
    end

    -- ---------------------------------------------------------------
    -- openat(dirfd, path, flags, ...) -> int fd ; path is arg[1], -1 = fail
    -- ---------------------------------------------------------------
    if CONFIG.enable_openat and off.openat then
        safe_native_hook("libc openat()", function()
            local real = NativeFunction(libc + off.openat, "int")
            Interceptor.replace("libc.so", off.openat, function(args)
                local path = Memory.readString(args[1])
                if taint_match(path) then
                    stats.openat_blocked = stats.openat_blocked + 1
                    log("[*] openat(..., \"" .. tostring(path) .. "\") -> -1")
                    return -1
                end
                return real(args[0], args[1], args[2], args[3])
            end)
        end)
    end

    -- ---------------------------------------------------------------
    -- access(path, mode) -> int ; -1 = failure
    -- ---------------------------------------------------------------
    if CONFIG.enable_access and off.access then
        safe_native_hook("libc access()", function()
            local real = NativeFunction(libc + off.access, "int")
            Interceptor.replace("libc.so", off.access, function(args)
                local path = Memory.readString(args[0])
                if taint_match(path) then
                    stats.access_blocked = stats.access_blocked + 1
                    log("[*] access(\"" .. tostring(path) .. "\") -> -1")
                    return -1
                end
                return real(args[0], args[1])
            end)
        end)
    end

    -- ---------------------------------------------------------------
    -- fopen(path, mode) -> FILE* ; NULL = failure (NOT -1 - this is a
    -- pointer-returning function, not an int-returning one)
    -- ---------------------------------------------------------------
    if CONFIG.enable_fopen and off.fopen then
        safe_native_hook("libc fopen()", function()
            local real = NativeFunction(libc + off.fopen, "pointer")
            Interceptor.replace("libc.so", off.fopen, function(args)
                local path = Memory.readString(args[0])
                if taint_match(path) then
                    stats.fopen_blocked = stats.fopen_blocked + 1
                    log("[*] fopen(\"" .. tostring(path) .. "\") -> NULL")
                    return 0 -- NULL
                end
                return real(args[0], args[1])
            end)
        end)
    end

    -- ---------------------------------------------------------------
    -- stat(path, buf) / lstat(path, buf) -> int ; -1 = failure
    -- ---------------------------------------------------------------
    for _, name in ipairs({ "stat", "lstat" }) do
        if CONFIG["enable_" .. name] and off[name] then
            safe_native_hook("libc " .. name .. "()", function()
                local real = NativeFunction(libc + off[name], "int")
                Interceptor.replace("libc.so", off[name], function(args)
                    local path = Memory.readString(args[0])
                    if taint_match(path) then
                        stats[name .. "_blocked"] = stats[name .. "_blocked"] + 1
                        log(string.format("[*] %s(\"%s\") -> -1", name, tostring(path)))
                        return -1
                    end
                    return real(args[0], args[1])
                end)
            end)
        end
    end

    -- ---------------------------------------------------------------
    -- faccessat(dirfd, path, mode, flags) -> int ; path is arg[1], -1 = fail
    -- ---------------------------------------------------------------
    if CONFIG.enable_faccessat and off.faccessat then
        safe_native_hook("libc faccessat()", function()
            local real = NativeFunction(libc + off.faccessat, "int")
            Interceptor.replace("libc.so", off.faccessat, function(args)
                local path = Memory.readString(args[1])
                if taint_match(path) then
                    stats.faccessat_blocked = stats.faccessat_blocked + 1
                    log("[*] faccessat(..., \"" .. tostring(path) .. "\") -> -1")
                    return -1
                end
                return real(args[0], args[1], args[2], args[3])
            end)
        end)
    end

    -- ---------------------------------------------------------------
    -- readlink(path, buf, bufsize) -> ssize_t ; -1 = failure
    -- ---------------------------------------------------------------
    if CONFIG.enable_readlink and off.readlink then
        safe_native_hook("libc readlink()", function()
            local real = NativeFunction(libc + off.readlink, "int")
            Interceptor.replace("libc.so", off.readlink, function(args)
                local path = Memory.readString(args[0])
                if taint_match(path) then
                    stats.readlink_blocked = stats.readlink_blocked + 1
                    log("[*] readlink(\"" .. tostring(path) .. "\") -> -1")
                    return -1
                end
                return real(args[0], args[1], args[2])
            end)
        end)
    end

    -- ---------------------------------------------------------------
    -- TracerPid scrub via read(). This is NOT an existence/match check
    -- like everything above - it is a CONTENT rewrite of a successful
    -- read() of /proc/self/status, patching the "TracerPid:\t<N>" line
    -- to read 0 so the classic ptrace-self-attach anti-debug check
    -- believes nothing is tracing it. Per-call state is keyed by
    -- Thread.id() (not a single shared upvalue) because onEnter/onLeave
    -- for *different* threads' concurrent read() calls can interleave
    -- under the single Lua mutex (see AGENTS.md: "Lua calls are
    -- serialized under g_lua_mutex" - serialized globally, but onEnter
    -- and onLeave of the SAME call are not adjacent in that serialization
    -- since the real syscall runs in between).
    -- ---------------------------------------------------------------
    if CONFIG.enable_tracerpid_scrub and off.read then
        local pending_status_reads = {}

        safe_native_hook("libc read() [TracerPid scrub]", function()
            hook("libc.so", off.read, {
                onEnter = function(args)
                    local fd = args[0]
                    local path = File.fdpath(fd)
                    if path and (path == "/proc/self/status" or
                                 string.find(path, "^/proc/%d+/status$")) then
                        pending_status_reads[Thread.id()] = { buf = args[1] }
                    end
                end,
                onLeave = function(retval)
                    local tid = Thread.id()
                    local pending = pending_status_reads[tid]
                    if not pending then return end
                    pending_status_reads[tid] = nil

                    if not retval or retval <= 0 then return end
                    local data = Memory.read(pending.buf, retval)
                    if not data then return end

                    -- Find "TracerPid:" then the run of digits after the
                    -- separating whitespace, and stamp it to "0" + spaces
                    -- (keeps the buffer length identical; strtol/%d stop
                    -- at the first non-digit so "0   " still parses as 0).
                    local prefix_start, prefix_end = string.find(data, "TracerPid:%s*")
                    if not prefix_start then return end
                    local digit_start, digit_end = string.find(data, "%d+", prefix_end + 1)
                    if not digit_start then return end

                    local digits = string.sub(data, digit_start, digit_end)
                    if digits == "0" then return end -- already clean, nothing to do

                    local replacement = "0" .. string.rep(" ", #digits - 1)
                    local patched = string.sub(data, 1, digit_start - 1) ..
                                     replacement ..
                                     string.sub(data, digit_end + 1)

                    Memory.write(pending.buf, patched)
                    stats.tracerpid_scrubbed = stats.tracerpid_scrubbed + 1
                    log("[*] /proc/self/status TracerPid scrubbed (was " .. digits .. ")")
                end
            })
        end)
    end
end

-- =====================================================================
-- CONTROL FUNCTIONS
-- =====================================================================
function taint_filter_stats()
    print("=== Taint Filter Statistics ===")
    print(string.format("strstr blocked:       %d", stats.strstr_blocked))
    print(string.format("strcasestr blocked:   %d", stats.strcasestr_blocked))
    print(string.format("strcmp blocked:        %d", stats.strcmp_blocked))
    print(string.format("strncmp blocked:       %d", stats.strncmp_blocked))
    print(string.format("strcasecmp blocked:    %d", stats.strcasecmp_blocked))
    print(string.format("open blocked:          %d", stats.open_blocked))
    print(string.format("openat blocked:        %d", stats.openat_blocked))
    print(string.format("access blocked:        %d", stats.access_blocked))
    print(string.format("fopen blocked:         %d", stats.fopen_blocked))
    print(string.format("stat blocked:          %d", stats.stat_blocked))
    print(string.format("lstat blocked:         %d", stats.lstat_blocked))
    print(string.format("faccessat blocked:     %d", stats.faccessat_blocked))
    print(string.format("readlink blocked:      %d", stats.readlink_blocked))
    print(string.format("TracerPid scrubbed:    %d", stats.tracerpid_scrubbed))
end

-- Exposed so root_emulator_bypass.lua can reuse the exact same
-- match logic/wordlist instead of duplicating it.
function taint_filter_match(str)
    return taint_match(str)
end

print("=== Taint Filter loaded ===")
print("")
print("Commands:")
print("  exec taint_filter_stats()  -- show per-function block counters")
print("")
print("Monitoring tainted libc calls... use 'watch' to see output")
