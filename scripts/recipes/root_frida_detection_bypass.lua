-- Root / Frida(-style) Detection Bypass (Recipe / Template)
--
-- What this does:
--   During an authorized pentest you frequently need to disable an app's
--   OWN defensive checks (root detection, instrumentation/"Frida" detection)
--   so you can actually exercise the rest of the attack surface. This is
--   the same legitimate use case covered by Frida's own
--   frida-android-unpinning / anti-root recipes - it does not attack
--   anything outside the target app's own process.
--
--   Root detection covered:
--     - su binary existence checks (/system/bin/su, /system/xbin/su, ...)
--       at both the native layer (access/stat/open/fopen) and Java layer
--       (java.io.File.exists())
--     - Runtime.exec("su") / Runtime.exec({"which","su"})
--     - android.os.Build.TAGS (patches the "test-keys" value to
--       "release-keys" via reflection, best-effort)
--
--   "Frida"/instrumentation detection covered:
--     - native strstr() calls where the needle contains "frida" (catches
--       the common "read /proc/self/maps and grep for frida" pattern,
--       regardless of how the buffer was read)
--     - native connect() to frida-server's default ports (27042/27043)
--     - the same su-style path hiding extended to known frida-server file
--       paths (/data/local/tmp/frida-server, re.frida.server, ...)
--     - OPTIONAL (off by default, see CONFIG.enable_string_contains):
--       java.lang.String.contains(CharSequence) forced to return false for
--       a small keyword list ("frida", "su", "magisk", ...). This is a very
--       hot method across the whole process (the Android framework calls
--       String.contains constantly), so it is gated behind a config flag -
--       expect a real performance hit if you turn it on.
--
-- Depends on (real Renef Lua API - see renef-doc/docs/api/hook.md,
-- file.md, java.md):
--   hook(library, offset, callbacks)            -- native trampoline hooks
--   Interceptor.replace(library, offset, cb)      -- full native replacement
--   NativeFunction(addr, retType)                 -- call the real libc fn
--   Module.find / Module.exports                   -- resolve libc symbols
--   Memory.read / Memory.readString                -- inspect args
--   hook(class, method, signature, callbacks)      -- Java hooks, args.skip
--   Jni.getStringUTF(ref)                           -- read Java Strings
--     from a RAW object pointer (hook args), no cast helper needed
--   Java.use(class_name):call(...)                  -- java.lang.reflect.*
--     plumbing for the Build.TAGS patch
--
-- THIS IS A TEMPLATE. Root/Frida detection libraries (RootBeer, SafetyNet/
-- Play Integrity, custom native checks, etc.) vary per app and there is no
-- single bypass that covers all of them:
--   - SafetyNet/Play Integrity attestation is a server-side check; nothing
--     client-side (including this script) can fully "bypass" it. It is out
--     of scope here.
--   - Custom native anti-debug/anti-frida checks (ptrace-self-attach, CRC
--     of the agent's own libc trampolines, timing checks, thread-name
--     scanning of /proc/self/task/*/comm for "gum-js-loop"/"gmain") are NOT
--     handled by this script - they would require content-rewriting hooks
--     on read()/fgets() rather than existence/connect checks, which is
--     beyond what this recipe attempts.
--   - If a check reads a real file's CONTENTS (not just whether it exists),
--     path hiding here does nothing; you'd need to hook the read and
--     rewrite the returned buffer.
-- Inspect the target APK (jadx/apktool) to find the actual detection logic
-- and adapt the hooks below (class/method names, path lists, ports).
--
-- Stability note: this recipe hooks libc functions that every thread calls
-- all the time (access/stat/lstat/open/fopen/strstr/connect). Renef versions before 0.4.0
-- could crash a busy target after 15-60 s of that traffic. Both causes are
-- fixed: a PC-relative instruction copied into the trampoline without being
-- relocated, and the old Java hook engine, which left a frame on the stack
-- that ART could not walk when an exception was thrown. On Android 11 and
-- older, Java hooks still use the old engine, so the second one can still
-- happen there. Callbacks run under one lock: keep them short on hot
-- functions.
--
-- Usage:
--   renef> l scripts/recipes/root_frida_detection_bypass.lua
--   renef> watch
--   renef> exec detection_bypass_stats()

__hook_type__ = "trampoline"

-- =====================================================================
-- CONFIG
-- =====================================================================
local CONFIG = {
    enable_root_bypass = true,
    enable_frida_bypass = true,

    -- Aggressive, hooks a VERY hot method process-wide. Off by default.
    enable_string_contains = false,

    verbose = true,
}

local stats = {
    paths_hidden = 0,
    exec_blocked = 0,
    build_tags_patched = false,
    strstr_blocked = 0,
    connect_blocked = 0,
    string_contains_blocked = 0,
}

local function log(msg)
    if CONFIG.verbose then
        print(msg)
    end
end

local function safe_java_hook(class_name, method_name, signature, callbacks, label)
    local ok, err = pcall(hook, class_name, method_name, signature, callbacks)
    if ok then
        log(string.format("[OK] %s", label or (class_name .. "." .. method_name)))
    else
        log(string.format("[skip] %s not present/hookable here (%s)",
            label or (class_name .. "." .. method_name), tostring(err)))
    end
    return ok
end

-- True if `haystack` contains any of the `keywords` (plain substring, no
-- pattern magic - paths/commands can contain '.' etc).
local function contains_any(haystack, keywords)
    if not haystack then return false end
    local lower = string.lower(haystack)
    for _, kw in ipairs(keywords) do
        if string.find(lower, kw, 1, true) then
            return true
        end
    end
    return false
end

print("=== Root / Frida Detection Bypass (template) ===")

-- Paths that commonly indicate root (su binaries, root-manager apps) or a
-- Frida deployment left on disk. Extend this list after inspecting what the
-- target app actually checks for.
local SENSITIVE_PATH_KEYWORDS = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
    "/system/sbin/su", "/system/bin/.ext/.su", "/data/local/su",
    "/data/local/bin/su", "/data/local/xbin/su",
    "superuser.apk", "supersu.apk", "magisk",
    "/data/local/tmp/frida-server", "re.frida.server", "/sdcard/frida-server",
}

-- =====================================================================
-- JAVA LAYER
-- =====================================================================

-- java.io.File.exists() has no path argument of its own (the path lives in
-- a private field on `this`), so we capture it in the constructor and key
-- it by the File object's raw ART pointer, then decide in exists() whether
-- to lie about it. Note: this is a plain table, not a weak one - ART
-- pointers can in principle be reused after GC, but for a short recon/
-- pentest session this is an acceptable template-level simplification.
local file_paths = {}

if CONFIG.enable_root_bypass or CONFIG.enable_frida_bypass then
    safe_java_hook("java/io/File", "<init>", "(Ljava/lang/String;)V", {
        onEnter = function(args)
            local path = Jni.getStringUTF(args[2])
            if path then
                file_paths[args[1]] = path
            end
        end
    }, "java.io.File.<init>(String)")

    safe_java_hook("java/io/File", "exists", "()Z", {
        onEnter = function(args)
            local path = file_paths[args[1]]
            if path and contains_any(path, SENSITIVE_PATH_KEYWORDS) then
                args.skip = true -- returns false (0)
                stats.paths_hidden = stats.paths_hidden + 1
                log("[*] File.exists() hidden for: " .. path)
            end
        end
    }, "java.io.File.exists")
end

if CONFIG.enable_root_bypass then
    -- Runtime.exec(String) - e.g. `Runtime.getRuntime().exec("which su")`.
    -- Skipping returns null; most root checks treat a null Process (or the
    -- IOException a missing binary would normally throw) as "not rooted",
    -- but this varies - adapt if the target expects an exception instead.
    safe_java_hook("java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;", {
        onEnter = function(args)
            local cmd = Jni.getStringUTF(args[2])
            if cmd and contains_any(cmd, { "su", "which", "busybox" }) then
                args.skip = true
                stats.exec_blocked = stats.exec_blocked + 1
                log("[*] Runtime.exec(\"" .. cmd .. "\") blocked")
            end
        end
    }, "java.lang.Runtime.exec(String)")

    -- Runtime.exec(String[]) - e.g. `exec(new String[]{"/system/xbin/which","su"})`.
    -- Reads element 0 generically via java.lang.reflect.Array, no cast API
    -- needed: Array.get(Object array, int index) accepts the raw array
    -- pointer directly (see api/java.md - a raw integer argument in an
    -- Object-typed slot is converted via the same mechanism hook args use).
    local ReflectArray = Java.use("java/lang/reflect/Array")
    safe_java_hook("java/lang/Runtime", "exec", "([Ljava/lang/String;)Ljava/lang/Process;", {
        onEnter = function(args)
            if not ReflectArray or args[2] == 0 then return end
            local ok, cmd0 = pcall(function()
                return ReflectArray:call("get", "(Ljava/lang/Object;I)Ljava/lang/Object;", args[2], 0)
            end)
            if ok and type(cmd0) == "string" and contains_any(cmd0, { "su", "which", "busybox" }) then
                args.skip = true
                stats.exec_blocked = stats.exec_blocked + 1
                log("[*] Runtime.exec(String[]) blocked (argv[0]=\"" .. cmd0 .. "\")")
            end
        end
    }, "java.lang.Runtime.exec(String[])")

    -- android.os.Build.TAGS patch: TAGS is assigned from a system property
    -- at class-init time (not a compile-time literal), so rewriting the
    -- live Field's value DOES affect every later read of Build.TAGS in the
    -- process. Best-effort: newer Android hidden-API enforcement can block
    -- setAccessible() on framework fields, in which case this silently
    -- no-ops (wrapped in pcall below).
    pcall(function()
        local ClassCls = Java.use("java/lang/Class")
        local buildClass = ClassCls:call("forName", "(Ljava/lang/String;)Ljava/lang/Class;", "android.os.Build")
        if buildClass then
            local tagsField = buildClass:call("getField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;", "TAGS")
            if tagsField then
                tagsField:call("setAccessible", "(Z)V", true)
                tagsField:call("set", "(Ljava/lang/Object;Ljava/lang/Object;)V", nil, "release-keys")
                stats.build_tags_patched = true
                log("[*] android.os.Build.TAGS patched to \"release-keys\"")
            end
        end
    end)
end

-- Aggressive, process-wide, OFF by default - see CONFIG comment at top.
if CONFIG.enable_string_contains then
    local STRING_KEYWORDS = { "frida", "su", "magisk", "xposed" }
    safe_java_hook("java/lang/String", "contains", "(Ljava/lang/CharSequence;)Z", {
        onEnter = function(args)
            local needle = Jni.getStringUTF(args[2])
            if needle and contains_any(needle, STRING_KEYWORDS) then
                args.skip = true -- returns false (0)
                stats.string_contains_blocked = stats.string_contains_blocked + 1
            end
        end
    }, "java.lang.String.contains (aggressive)")
end

-- =====================================================================
-- NATIVE LAYER (libc.so)
-- =====================================================================
-- Unlike Java hooks (wrapped per-call via safe_java_hook above), a failure
-- in NativeFunction()/Interceptor.replace() here is NOT automatically
-- recoverable - a bad offset/signature can raise a raw Lua error that,
-- left unguarded, kills the whole script (observed live: a crash here left
-- every hook installed up to that point active but aborted everything
-- after it, with no indication of which hook was the culprit). Every
-- install below goes through this same pcall-guarded pattern as the Java
-- hooks, so one bad hook degrades gracefully instead of taking the rest
-- of the recipe down with it.
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
if libc then
    local exports = Module.exports("libc.so")
    local off = {}
    if exports then
        for _, exp in ipairs(exports) do
            if exp.name == "access" or exp.name == "stat" or exp.name == "lstat"
               or exp.name == "open" or exp.name == "fopen" or exp.name == "strstr"
               or exp.name == "connect" then
                off[exp.name] = exp.offset
            end
        end
    end

    local function hidden_path_check(path)
        return path and contains_any(path, SENSITIVE_PATH_KEYWORDS)
    end

    -- access(path, mode) -> int (0 = exists, -1 = not found)
    if (CONFIG.enable_root_bypass or CONFIG.enable_frida_bypass) and off.access then
        safe_native_hook("libc access()", function()
            local real = NativeFunction(libc + off.access, "int")
            Interceptor.replace("libc.so", off.access, function(args)
                local path = Memory.readString(args[0])
                if hidden_path_check(path) then
                    stats.paths_hidden = stats.paths_hidden + 1
                    log("[*] access() hidden: " .. path)
                    return -1
                end
                return real(args[0], args[1])
            end)
        end)
    end

    -- stat(path, buf) / lstat(path, buf) -> int
    for _, name in ipairs({ "stat", "lstat" }) do
        if (CONFIG.enable_root_bypass or CONFIG.enable_frida_bypass) and off[name] then
            safe_native_hook("libc " .. name .. "()", function()
                local real = NativeFunction(libc + off[name], "int")
                Interceptor.replace("libc.so", off[name], function(args)
                    local path = Memory.readString(args[0])
                    if hidden_path_check(path) then
                        stats.paths_hidden = stats.paths_hidden + 1
                        log(string.format("[*] %s() hidden: %s", name, path))
                        return -1
                    end
                    return real(args[0], args[1])
                end)
            end)
        end
    end

    -- open(path, flags, ...) -> int fd (-1 = failure)
    if (CONFIG.enable_root_bypass or CONFIG.enable_frida_bypass) and off.open then
        safe_native_hook("libc open()", function()
            local real = NativeFunction(libc + off.open, "int")
            Interceptor.replace("libc.so", off.open, function(args)
                local path = Memory.readString(args[0])
                if hidden_path_check(path) then
                    stats.paths_hidden = stats.paths_hidden + 1
                    log("[*] open() hidden: " .. path)
                    return -1
                end
                return real(args[0], args[1], args[2])
            end)
        end)
    end

    -- fopen(path, mode) -> FILE* (0/NULL = failure)
    if (CONFIG.enable_root_bypass or CONFIG.enable_frida_bypass) and off.fopen then
        safe_native_hook("libc fopen()", function()
            local real = NativeFunction(libc + off.fopen, "pointer")
            Interceptor.replace("libc.so", off.fopen, function(args)
                local path = Memory.readString(args[0])
                if hidden_path_check(path) then
                    stats.paths_hidden = stats.paths_hidden + 1
                    log("[*] fopen() hidden: " .. path)
                    return 0
                end
                return real(args[0], args[1])
            end)
        end)
    end

    -- strstr(haystack, needle) -> catches the common "read /proc/self/maps
    -- then grep for 'frida'" detection pattern at the libc level, no matter
    -- how the buffer was produced.
    if CONFIG.enable_frida_bypass and off.strstr then
        safe_native_hook("libc strstr()", function()
            local real = NativeFunction(libc + off.strstr, "pointer")
            Interceptor.replace("libc.so", off.strstr, function(args)
                local needle = Memory.readString(args[1])
                if needle and string.find(string.lower(needle), "frida", 1, true) then
                    stats.strstr_blocked = stats.strstr_blocked + 1
                    log("[*] strstr(..., \"" .. needle .. "\") forced to NULL")
                    return 0
                end
                return real(args[0], args[1])
            end)
        end)
    end

    -- connect(sockfd, sockaddr*, addrlen) -> blocks connections to
    -- frida-server's default ports (27042 control, 27043 gdb-remote).
    if CONFIG.enable_frida_bypass and off.connect then
        safe_native_hook("libc connect()", function()
            local real = NativeFunction(libc + off.connect, "int")
            Interceptor.replace("libc.so", off.connect, function(args)
                local addr = args[1]
                local family = addr ~= 0 and Memory.readU16(addr) or nil
                if family == 2 then -- AF_INET
                    local port_bytes = Memory.read(addr + 2, 2)
                    if port_bytes then
                        local port = string.byte(port_bytes, 1) * 256 + string.byte(port_bytes, 2)
                        if port == 27042 or port == 27043 then
                            stats.connect_blocked = stats.connect_blocked + 1
                            log(string.format("[*] connect() to port %d blocked (frida-server default)", port))
                            return -1
                        end
                    end
                end
                return real(args[0], args[1], args[2])
            end)
        end)
    end
else
    print("[WARN] libc.so not found (native hooks skipped - shouldn't happen)")
end

-- =====================================================================
-- CONTROL FUNCTIONS
-- =====================================================================
function detection_bypass_stats()
    print("=== Root/Frida Detection Bypass Statistics ===")
    print(string.format("Paths hidden (access/stat/open/fopen/File.exists): %d", stats.paths_hidden))
    print(string.format("Runtime.exec() blocked:        %d", stats.exec_blocked))
    print(string.format("Build.TAGS patched:            %s", tostring(stats.build_tags_patched)))
    print(string.format("strstr(\"frida\") blocked:       %d", stats.strstr_blocked))
    print(string.format("connect() to frida ports blocked: %d", stats.connect_blocked))
    print(string.format("String.contains() blocked:     %d", stats.string_contains_blocked))
end

print("")
print("Commands:")
print("  exec detection_bypass_stats()  -- show bypass counters")
print("")
print("Monitoring root/frida detection calls... use 'watch' to see output")
