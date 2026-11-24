-- Modular Root/Emulator Detection Bypass Library
--
-- This is a modular, opt-in rewrite of root_frida_detection_bypass.lua's
-- root-detection half (that file stays as-is - it is still a good single-
-- file starting template). Here, each technique is its own toggle-able
-- function under one of two namespaces:
--
--   RootDetection.hideSuBinaries([extraPaths])
--   RootDetection.hidePackages(pkgList)
--   RootDetection.forceBooleanArgs(class, method, signature, argIndices,
--                                  forcedValue [, label])
--   EmulatorDetection.spoofBuildProps([fields])
--   EmulatorDetection.spoofSystemProperties([props])
--
-- Root-indicator FILE hiding and EMULATOR sysprop/Build spoofing are two
-- different mechanisms against two different signals and should not be
-- conflated, so they live in separate
-- namespaces here instead of one "bypass everything" blob.
--
-- Composes with taint_filter.lua: if you load that script FIRST,
-- RootDetection.hideSuBinaries() reuses its `taint_filter_match()` for the
-- generic frida/root/pentest-tooling wordlist on top of its own su-path
-- list. It is NOT a hard dependency - load this file alone and it still
-- works with its own (smaller) built-in path list.
--
--   renef> l scripts/recipes/taint_filter.lua          -- optional, load first
--   renef> l scripts/recipes/root_emulator_bypass.lua
--   renef> exec RootDetection.hideSuBinaries()
--   renef> exec EmulatorDetection.spoofBuildProps()
--   renef> watch
--   renef> exec root_bypass_stats()
--
-- Stability note: RootDetection.hideSuBinaries() hooks libc functions that every thread calls
-- all the time (access/stat/open/fopen). Renef versions before 0.4.0
-- could crash a busy target after 15-60 s of that traffic. Both causes are
-- fixed: a PC-relative instruction copied into the trampoline without being
-- relocated, and the old Java hook engine, which left a frame on the stack
-- that ART could not walk when an exception was thrown. On Android 11 and
-- older, Java hooks still use the old engine, so the second one can still
-- happen there. Callbacks run under one lock: keep them short on hot
-- functions.
--
-- ============================================================================
-- THE CRITICAL FINDING THIS FILE IS BUILT AROUND (read before using
-- RootDetection.forceBooleanArgs):
--
-- A real pentest target had a method shaped like
-- `SplashFragment.a(boolean, boolean, boolean)` (JNI signature "(ZZZ)V")
-- that made its root/debug/emulator decision INSIDE that call, based on
-- those three booleans. You cannot fix this from `onLeave`: by the time
-- `onLeave` runs, the method has ALREADY executed its branches using the
-- real (untampered) parameter values - onLeave only gets to see/replace
-- the final return value (or do nothing, for a `void` method like this
-- one), it cannot retroactively change what the method DID internally
-- with those three booleans.
--
-- The only place you can affect "what the method does with its own
-- parameters" is `onEnter`, by writing to `args[N]` BEFORE the original
-- runs - Renef's Java hook documentation (renef-doc/docs/api/hook.md)
-- states this is supported ("Arguments are modifiable: args[2] = newValue
-- will change the parameter passed to the original method") and the
-- agent-side implementation (src/agent/hook/java.c, java_hook_on_enter /
-- java_hook_call_original) writes any `args[i]` changes back into the
-- same saved-register array that is then used to actually invoke the
-- original method - so the write-back is not just a Lua-side bookkeeping
-- trick, it changes the x-registers the real call runs with.
--
-- The write-back is exercised by scripts/examples/onenter_writeback_test.lua
-- (hooks java.io.File.setReadable(boolean,boolean), forces the "readable"
-- arg to false in onEnter while the caller passes true, then checks
-- canRead()) and by the "onEnter changes an int argument" check in
-- scripts/examples/java_hook_engine_test.lua.
-- ============================================================================
--
-- Depends on (real Renef Lua API - see renef-doc/docs/api/hook.md,
-- java.md, file.md, memory.md):
--   hook(class, method, signature, callbacks)   -- Java hooks, args[N]=, args.skip
--   Jni.getStringUTF / Jni.newStringUTF
--   Java.use(class):call(...)                    -- reflection (Build field patch)
--   hook/Interceptor.replace/NativeFunction       -- native (su paths, sysprops)
--   Module.find / Module.exports

__hook_type__ = "trampoline"

-- =====================================================================
-- CONFIG
-- =====================================================================
local CONFIG = {
    verbose = true,
}

local stats = {
    su_paths_hidden = 0,
    packages_hidden = 0,
    bool_args_forced = 0,
    build_props_patched = 0,
    system_props_spoofed = 0,
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

local function safe_native_hook(label, install_fn)
    local ok, err = pcall(install_fn)
    if ok then
        print("[OK] " .. label .. " hooked")
    else
        print("[skip] " .. label .. " hook failed: " .. tostring(err))
    end
    return ok
end

-- Falls back to a small built-in contains-check if taint_filter.lua
-- was not loaded first - see module header.
local function match_token(str, extra_list)
    if not str then return false end
    if type(taint_filter_match) == "function" and taint_filter_match(str) then
        return true
    end
    local lower = string.lower(str)
    for _, tok in ipairs(extra_list or {}) do
        if string.find(lower, string.lower(tok), 1, true) then
            return true
        end
    end
    return false
end

-- =====================================================================
-- RootDetection namespace
-- =====================================================================
RootDetection = {}

-- Built-in su-indicator paths (same set as root_frida_detection_bypass.lua).
-- Extend via the `extraPaths` parameter rather than editing this list.
local DEFAULT_SU_PATHS = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
    "/system/sbin/su", "/system/bin/.ext/.su", "/data/local/su",
    "/data/local/bin/su", "/data/local/xbin/su",
    "superuser.apk", "supersu.apk", "magisk",
}

-- RootDetection.hideSuBinaries([extraPaths])
-- Hooks java.io.File.exists() + native access/stat/lstat/open/fopen so
-- that su-indicator paths report "doesn't exist" / "failed to open".
-- Independent of EmulatorDetection - this only affects file-existence
-- signals, not device-identity sysprops/Build fields.
function RootDetection.hideSuBinaries(extraPaths)
    local paths = {}
    for _, p in ipairs(DEFAULT_SU_PATHS) do table.insert(paths, p) end
    for _, p in ipairs(extraPaths or {}) do table.insert(paths, p) end

    local function is_su_path(p)
        return match_token(p, paths)
    end

    -- Java layer: java.io.File.<init> captures the path (File.exists()
    -- itself takes no path argument - it lives on `this`), same pattern
    -- as root_frida_detection_bypass.lua.
    local file_paths = {}
    safe_java_hook("java/io/File", "<init>", "(Ljava/lang/String;)V", {
        onEnter = function(args)
            local path = Jni.getStringUTF(args[2])
            if path then file_paths[args[1]] = path end
        end
    }, "java.io.File.<init>(String) [capture for hideSuBinaries]")

    safe_java_hook("java/io/File", "exists", "()Z", {
        onEnter = function(args)
            local path = file_paths[args[1]]
            if path and is_su_path(path) then
                args.skip = true -- returns false
                stats.su_paths_hidden = stats.su_paths_hidden + 1
                log("[*] File.exists() hidden: " .. path)
            end
        end
    }, "java.io.File.exists [hideSuBinaries]")

    -- Native layer.
    local libc = Module.find("libc.so")
    if not libc then
        print("[WARN] libc.so not found - native su-path hooks skipped")
        return
    end
    local exports = Module.exports("libc.so")
    local off = {}
    if exports then
        for _, exp in ipairs(exports) do
            if exp.name == "access" or exp.name == "stat" or exp.name == "lstat"
               or exp.name == "open" or exp.name == "fopen" then
                off[exp.name] = exp.offset
            end
        end
    end

    if off.access then
        safe_native_hook("libc access() [hideSuBinaries]", function()
            local real = NativeFunction(libc + off.access, "int")
            Interceptor.replace("libc.so", off.access, function(args)
                local path = Memory.readString(args[0])
                if is_su_path(path) then
                    stats.su_paths_hidden = stats.su_paths_hidden + 1
                    log("[*] access() hidden: " .. path)
                    return -1
                end
                return real(args[0], args[1])
            end)
        end)
    end

    for _, name in ipairs({ "stat", "lstat" }) do
        if off[name] then
            safe_native_hook("libc " .. name .. "() [hideSuBinaries]", function()
                local real = NativeFunction(libc + off[name], "int")
                Interceptor.replace("libc.so", off[name], function(args)
                    local path = Memory.readString(args[0])
                    if is_su_path(path) then
                        stats.su_paths_hidden = stats.su_paths_hidden + 1
                        log(string.format("[*] %s() hidden: %s", name, path))
                        return -1
                    end
                    return real(args[0], args[1])
                end)
            end)
        end
    end

    if off.open then
        safe_native_hook("libc open() [hideSuBinaries]", function()
            local real = NativeFunction(libc + off.open, "int")
            Interceptor.replace("libc.so", off.open, function(args)
                local path = Memory.readString(args[0])
                if is_su_path(path) then
                    stats.su_paths_hidden = stats.su_paths_hidden + 1
                    log("[*] open() hidden: " .. path)
                    return -1
                end
                return real(args[0], args[1], args[2])
            end)
        end)
    end

    if off.fopen then
        safe_native_hook("libc fopen() [hideSuBinaries]", function()
            local real = NativeFunction(libc + off.fopen, "pointer")
            Interceptor.replace("libc.so", off.fopen, function(args)
                local path = Memory.readString(args[0])
                if is_su_path(path) then
                    stats.su_paths_hidden = stats.su_paths_hidden + 1
                    log("[*] fopen() hidden: " .. path)
                    return 0
                end
                return real(args[0], args[1])
            end)
        end)
    end
end

-- RootDetection.hidePackages(pkgList)
-- Makes PackageManager.getPackageInfo(String, int) report "not installed"
-- for the given package names, by rewriting the QUERIED NAME in onEnter
-- to a package that genuinely does not exist. The real method then runs
-- normally and throws its own real NameNotFoundException - this is
-- deliberately NOT faking a return value, because callers vary between
-- "catch the exception" and "check for null", and letting the real
-- method hit its real "not found" path satisfies both.
--
-- Scope note (template limitation): this covers the single-lookup
-- getPackageInfo() path only. Filtering getInstalledPackages()/
-- getInstalledApplications() list results (removing matching entries
-- from the returned List<PackageInfo>) is a reasonable extension but
-- needs per-item reflection on a non-trivial object graph; left out of
-- this template rather than shipped half-tested - see root_frida_
-- detection_bypass.lua's header for the same "this is a template, not a
-- universal bypass" framing.
function RootDetection.hidePackages(pkgList)
    pkgList = pkgList or {
        "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su",
        "com.koushikdutta.superuser", "com.thirdparty.superuser",
        "com.yellowes.su", "com.zachspong.temprootremovejb",
        "com.ramdroid.appquarantine", "de.robv.android.xposed.installer",
    }
    local hidden = {}
    for _, p in ipairs(pkgList) do hidden[p] = true end

    safe_java_hook("android/app/ApplicationPackageManager", "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;", {
        onEnter = function(args)
            local pkg = Jni.getStringUTF(args[2])
            if pkg and hidden[pkg] then
                -- Rewrite the argument so the REAL method looks up a
                -- package that doesn't exist, and throws its own real
                -- NameNotFoundException - onEnter write-back, not a
                -- faked return value.
                args[2] = Jni.newStringUTF("com.renef.__hidden_pkg_shadow__")
                stats.packages_hidden = stats.packages_hidden + 1
                log("[*] getPackageInfo(\"" .. pkg .. "\") redirected to a nonexistent package")
            end
        end
    }, "ApplicationPackageManager.getPackageInfo [hidePackages]")
end

-- RootDetection.forceBooleanArgs(class, method, signature, argIndices, forcedValue [, label])
--
-- Generic onEnter write-back helper for the exact pattern this file is
-- built around: a method that takes several boolean (or int)
-- parameters and makes its OWN internal decision from them, so the fix
-- must happen before the original runs, not after (see the module header
-- - this is the single most important function in this file).
--
-- `argIndices` are hook args[] indices (args[1] = `this`/first static
-- param, args[2..] = subsequent params - same numbering as everywhere
-- else in Renef's Java hook API). `forcedValue` is typically 0 or 1 for
-- booleans but passed through as-is, so this also works for forcing an
-- int-typed "mode"/"flags" parameter.
--
-- Example - the real finding this models (adjust names before using):
--   RootDetection.forceBooleanArgs(
--       "com/example/app/SplashFragment", "a", "(ZZZ)V",
--       {2, 3, 4}, 0, "SplashFragment.a(ZZZ) root/debug/emulator flags")
function RootDetection.forceBooleanArgs(class_name, method_name, signature, argIndices, forcedValue, label)
    forcedValue = forcedValue or 0
    return safe_java_hook(class_name, method_name, signature, {
        onEnter = function(args)
            for _, idx in ipairs(argIndices) do
                args[idx] = forcedValue
            end
            stats.bool_args_forced = stats.bool_args_forced + 1
            log(string.format("[*] %s%s: forced args[%s] = %d",
                method_name, signature, table.concat(argIndices, ","), forcedValue))
        end
    }, label)
end

-- =====================================================================
-- EmulatorDetection namespace - sysprop/Build identity spoofing.
-- Deliberately separate from RootDetection: an emulator can be un-rooted
-- and a real device can be rooted: these are two independent signals.
-- =====================================================================
EmulatorDetection = {}

-- EmulatorDetection.spoofBuildProps([fields])
-- Patches android.os.Build fields via reflection (same mechanism as the
-- Build.TAGS patch in root_frida_detection_bypass.lua, generalized to any
-- field set). Best-effort: newer Android hidden-API enforcement can block
-- setAccessible() on framework fields, in which case this silently no-ops
-- per field (wrapped in pcall).
function EmulatorDetection.spoofBuildProps(fields)
    fields = fields or {
        FINGERPRINT  = "samsung/d2s/d2s:13/TP1A.220624.014/G973FXXUFEWK2:user/release-keys",
        MODEL        = "SM-G973F",
        MANUFACTURER = "samsung",
        BRAND        = "samsung",
        PRODUCT      = "d2s",
        HARDWARE     = "exynos9820",
        DEVICE       = "d2s",
        TAGS         = "release-keys",
    }

    local ok, err = pcall(function()
        local ClassCls = Java.use("java/lang/Class")
        local buildClass = ClassCls:call("forName", "(Ljava/lang/String;)Ljava/lang/Class;", "android.os.Build")
        if not buildClass then return end

        for field_name, value in pairs(fields) do
            local field_ok, field_err = pcall(function()
                local field = buildClass:call("getField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;", field_name)
                field:call("setAccessible", "(Z)V", true)
                field:call("set", "(Ljava/lang/Object;Ljava/lang/Object;)V", nil, value)
                stats.build_props_patched = stats.build_props_patched + 1
                log(string.format("[*] Build.%s patched to \"%s\"", field_name, tostring(value)))
            end)
            if not field_ok then
                log(string.format("[skip] Build.%s not patchable here (%s)", field_name, tostring(field_err)))
            end
        end
    end)
    if not ok then
        log("[skip] EmulatorDetection.spoofBuildProps failed entirely: " .. tostring(err))
    end
end

-- EmulatorDetection.spoofSystemProperties([props])
-- Hooks libc __system_property_get(name, value) and overrides the
-- returned value for a configurable set of known emulator-telltale
-- property NAMES (the standard sysprop-faking approach - name-keyed, not
-- a value/content scan). Runs the REAL lookup first, then overwrites the
-- caller's buffer only for names we're configured to spoof - anything
-- else passes through untouched.
function EmulatorDetection.spoofSystemProperties(props)
    props = props or {
        ["ro.kernel.qemu"]        = "0",
        ["ro.boot.qemu"]          = "",
        ["ro.hardware"]           = "qcom",
        ["ro.hardware.chipname"]  = "SM8250",
        ["ro.boot.hardware"]      = "qcom",
        ["ro.bootloader"]         = "unknown",
        ["qemu.hw.mainkeys"]      = "",
        ["ro.kernel.android.qemud"] = "",
        ["init.svc.qemud"]        = "",
    }

    local libc = Module.find("libc.so")
    if not libc then
        print("[WARN] libc.so not found - EmulatorDetection.spoofSystemProperties skipped")
        return
    end
    local exports = Module.exports("libc.so")
    local off = nil
    if exports then
        for _, exp in ipairs(exports) do
            if exp.name == "__system_property_get" then
                off = exp.offset
                break
            end
        end
    end
    if not off then
        print("[skip] __system_property_get not exported here")
        return
    end

    safe_native_hook("libc __system_property_get() [spoofSystemProperties]", function()
        local real = NativeFunction(libc + off, "int")
        Interceptor.replace("libc.so", off, function(args)
            local len = real(args[0], args[1])
            local name = Memory.readString(args[0])
            if name and props[name] ~= nil then
                local value = props[name]
                Memory.write(args[1], value .. "\0")
                stats.system_props_spoofed = stats.system_props_spoofed + 1
                log(string.format("[*] sysprop %s spoofed -> \"%s\"", name, value))
                return #value
            end
            return len
        end)
    end)
end

-- =====================================================================
-- CONTROL FUNCTIONS
-- =====================================================================
function root_bypass_stats()
    print("=== Root/Emulator Bypass Statistics ===")
    print(string.format("su paths hidden:        %d", stats.su_paths_hidden))
    print(string.format("packages hidden:        %d", stats.packages_hidden))
    print(string.format("boolean-arg hooks fired: %d", stats.bool_args_forced))
    print(string.format("Build fields patched:   %d", stats.build_props_patched))
    print(string.format("sysprops spoofed:       %d", stats.system_props_spoofed))
end

print("=== Modular Root/Emulator Bypass loaded ===")
print("")
print("RootDetection.hideSuBinaries([extraPaths])")
print("RootDetection.hidePackages([pkgList])")
print("RootDetection.forceBooleanArgs(class, method, sig, argIndices, forcedValue [, label])")
print("EmulatorDetection.spoofBuildProps([fields])")
print("EmulatorDetection.spoofSystemProperties([props])")
print("")
print("Nothing runs automatically - call the functions you need, e.g.:")
print("  exec RootDetection.hideSuBinaries()")
print("  exec EmulatorDetection.spoofBuildProps()")
print("  exec root_bypass_stats()")
