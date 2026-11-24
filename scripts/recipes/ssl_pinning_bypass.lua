-- SSL/TLS Certificate Pinning Bypass (Recipe / Template)
--
-- What this does:
--   Forces TLS certificate validation to "succeed" at the places Android apps
--   most commonly implement pinning:
--     1. X509TrustManager implementations: checkServerTrusted /
--        checkClientTrusted (and the Socket / SSLEngine overloads)
--     2. OkHttp's okhttp3.CertificatePinner.check(...)
--     3. HostnameVerifier implementations: verify() forced to true
--     4. Native BoringSSL SSL_CTX_set_custom_verify / SSL_set_custom_verify
--        (replaces the app's verify callback with one that always returns
--        ssl_verify_ok)
--
-- X509TrustManager and HostnameVerifier are INTERFACES: they have no code,
-- so there is nothing to hook on them. What has to be hooked is the class
-- that implements them, and which class that is differs per app. This
-- recipe finds implementations three ways:
--     a. known ones that ship with Android (Conscrypt's TrustManagerImpl,
--        the Network Security Config trust managers, the platform's OkHttp
--        hostname verifier),
--     b. classes of the app whose name suggests one (CONFIG.class_keywords),
--     c. at run time: every TrustManager passed to SSLContext.init() and
--        every HostnameVerifier passed to HttpsURLConnection is hooked the
--        moment the app hands it over. This is what catches anonymous and
--        obfuscated classes - but only for contexts created AFTER the recipe
--        is loaded, so load it early (renef --pause) when the app sets up
--        TLS at startup.
--   Add classes you found with jadx/apktool to CONFIG.extra_trust_managers /
--   CONFIG.extra_hostname_verifiers.
--
-- THIS IS A TEMPLATE, NOT A UNIVERSAL BYPASS. Pinning implementations vary
-- wildly between apps:
--   - Some apps bundle their OWN copy of OkHttp (Proguard/R8 may rename
--     "okhttp3.CertificatePinner" to something obfuscated) - use jadx/apktool
--     on the target APK to find the real class/method names first.
--   - Flutter / React Native / Xamarin apps often ship their own TLS stack
--     (BoringSSL statically linked into a different .so, or a non-OkHttp
--     HTTP client) and none of the Java hooks below will ever fire.
--   - Certificate Transparency checks, public-key pinning via a hash list,
--     and multi-layer pinning (both Java AND native) are all possible in the
--     same app at once.
-- Treat every hook here as a starting point to adapt, not a guarantee.
--
-- Usage:
--   renef> l scripts/recipes/ssl_pinning_bypass.lua
--   renef> watch
--   renef> exec ssl_bypass_stats()
--
-- Only use this against targets you are authorized to assess. Bypassing an
-- app's own certificate pinning on a device/app you are authorized to test
-- is standard practice (the same use case as Frida's
-- frida-android-unpinning project).

__hook_type__ = "trampoline"

-- =====================================================================
-- CONFIG
-- =====================================================================
local CONFIG = {
    enable_java = true,
    enable_native = true,

    -- Also force HostnameVerifier.verify() -> true (extremely common
    -- alongside TrustManager pinning).
    enable_hostname_verifier = true,

    -- Accept any chain in Android's own trust managers too (Conscrypt,
    -- Network Security Config). Needed when the proxy's CA is not in the
    -- device's trust store; switch off to bypass only the app's pinning.
    bypass_system_trust = true,

    -- App classes whose (lower-case) name contains one of these are tried as
    -- TrustManager / HostnameVerifier implementations.
    class_keywords = { "trustmanager", "pinn", "x509", "hostnameverifier" },
    max_scanned_classes = 300,

    -- Implementations found by hand (jadx/apktool), e.g. "com/acme/a/b".
    extra_trust_managers = {},
    extra_hostname_verifiers = {},

    verbose = true,
}

local stats = {
    trust_manager_bypassed = 0,
    cert_pinner_bypassed = 0,
    hostname_verifier_bypassed = 0,
    native_verify_bypassed = 0,
}

local function log(msg)
    if CONFIG.verbose then
        print(msg)
    end
end

-- Wrap a Java hook() install in pcall: on a target this class/method does
-- not exist on (e.g. no OkHttp in the app, or a different pinning impl),
-- hook() raises a Lua error. We want every OTHER recipe hook in this file
-- to still install, so every Java hook below goes through this helper.
-- quiet = true: a miss is expected (probing a class for a method it may not
-- have) and is not reported.
local function safe_java_hook(class_name, method_name, signature, callbacks, label, quiet)
    local ok, err = pcall(hook, class_name, method_name, signature, callbacks)
    if ok then
        log(string.format("[OK] %s", label or (class_name .. "." .. method_name)))
    elseif not quiet then
        log(string.format("[skip] %s (%s)", label or (class_name .. "." .. method_name),
            tostring(err):gsub("^.-Failed to install Java hook: ", "")))
    end
    return ok
end

print("=== SSL/TLS Pinning Bypass (template) ===")

-- =====================================================================
-- JAVA LAYER
-- =====================================================================
if CONFIG.enable_java then

    local X509 = "[Ljava/security/cert/X509Certificate;"
    local hooked = {}          -- class name -> true (each class is hooked once)
    local pending_list = {}    -- thread id -> List to return from a skipped call

    local function slashed(name) return (name:gsub("%.", "/")) end

    -- Hooks the validation methods of ONE class that implements
    -- X509TrustManager (or X509ExtendedTrustManager). Returns how many
    -- methods were hooked; 0 means the class has none of them itself.
    local function hook_trust_manager(class_name, quiet)
        class_name = slashed(class_name)
        if hooked["tm:" .. class_name] then return 0 end
        hooked["tm:" .. class_name] = true

        local function bypass(what)
            return {
                onEnter = function(args)
                    args.skip = true        -- the check (and its exception) never runs
                    stats.trust_manager_bypassed = stats.trust_manager_bypassed + 1
                    log(string.format("[*] %s.%s bypassed", class_name, what))
                end
            }
        end

        local n = 0
        for _, m in ipairs({
            { "checkServerTrusted", "(" .. X509 .. "Ljava/lang/String;)V" },
            { "checkClientTrusted", "(" .. X509 .. "Ljava/lang/String;)V" },
            { "checkServerTrusted", "(" .. X509 .. "Ljava/lang/String;Ljava/net/Socket;)V" },
            { "checkServerTrusted", "(" .. X509 .. "Ljava/lang/String;Ljavax/net/ssl/SSLEngine;)V" },
            { "checkClientTrusted", "(" .. X509 .. "Ljava/lang/String;Ljava/net/Socket;)V" },
            { "checkClientTrusted", "(" .. X509 .. "Ljava/lang/String;Ljavax/net/ssl/SSLEngine;)V" },
        }) do
            if safe_java_hook(class_name, m[1], m[2], bypass(m[1]), class_name .. "." .. m[1] .. m[2]:match("%b()"), true) then
                n = n + 1
            end
        end

        -- checkServerTrusted(chain, authType, hostname) -> List<X509Certificate>
        -- (Conscrypt / Network Security Config). The caller uses the list, so
        -- a skipped call has to return the chain it was given.
        local list_sig = "(" .. X509 .. "Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;"
        if safe_java_hook(class_name, "checkServerTrusted", list_sig, {
            onEnter = function(args)
                args.skip = true
                local ok, list = pcall(function()
                    return Java.use("java/util/Arrays"):call("asList", "([Ljava/lang/Object;)Ljava/util/List;", args[2])
                end)
                pending_list[Thread.id()] = ok and list or nil
                stats.trust_manager_bypassed = stats.trust_manager_bypassed + 1
                log(string.format("[*] %s.checkServerTrusted(chain, authType, host) bypassed", class_name))
            end,
            onLeave = function(retval)
                local list = pending_list[Thread.id()]
                pending_list[Thread.id()] = nil
                if list then return list.raw end
            end
        }, class_name .. ".checkServerTrusted(chain, authType, host)", true) then
            n = n + 1
        end

        if n == 0 and not quiet then
            log(string.format("[skip] %s has no checkServerTrusted/checkClientTrusted of its own", class_name))
        end
        return n
    end

    local function hook_hostname_verifier(class_name, quiet)
        class_name = slashed(class_name)
        if hooked["hv:" .. class_name] then return false end
        hooked["hv:" .. class_name] = true
        return safe_java_hook(class_name, "verify", "(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z", {
            onLeave = function(retval)
                stats.hostname_verifier_bypassed = stats.hostname_verifier_bypassed + 1
                log(string.format("[*] %s.verify() forced to true", class_name))
                return 1
            end
        }, class_name .. ".verify", quiet)
    end

    -- Class name of a Java object: `obj` is an instance from the Java API, or
    -- a raw reference as hook callbacks get them in args[].
    local function class_of(obj)
        if not obj or obj == 0 then return nil end
        local ok, name = pcall(function()
            if type(obj) == "number" then
                -- a static method that hands the object back turns the raw
                -- reference into an instance we can call methods on
                obj = Java.use("java/util/Objects"):call("requireNonNull", "(Ljava/lang/Object;)Ljava/lang/Object;", obj)
            end
            return obj:call("getClass", "()Ljava/lang/Class;"):call("getName", "()Ljava/lang/String;")
        end)
        return ok and name or nil
    end

    -- -----------------------------------------------------------------
    -- a. Implementations that ship with Android
    -- -----------------------------------------------------------------
    if CONFIG.bypass_system_trust then
        for _, cls in ipairs({
            "com/android/org/conscrypt/TrustManagerImpl",
            "android/security/net/config/RootTrustManager",
            "android/security/net/config/NetworkSecurityTrustManager",
        }) do
            hook_trust_manager(cls, true)
        end
    end
    if CONFIG.enable_hostname_verifier then
        hook_hostname_verifier("com/android/okhttp/internal/tls/OkHostnameVerifier", true)
        hook_hostname_verifier("okhttp3/internal/tls/OkHostnameVerifier", true)
    end

    -- -----------------------------------------------------------------
    -- b. Classes of the app, by name
    -- -----------------------------------------------------------------
    for _, cls in ipairs(CONFIG.extra_trust_managers) do hook_trust_manager(cls) end
    for _, cls in ipairs(CONFIG.extra_hostname_verifiers) do hook_hostname_verifier(cls) end

    local classes = Java.enumerateLoadedClasses()
    if classes then
        local tried = 0
        for _, name in ipairs(classes) do
            local lower = name:lower()
            local match = false
            for _, kw in ipairs(CONFIG.class_keywords) do
                if lower:find(kw, 1, true) then match = true break end
            end
            if match then
                tried = tried + 1
                if tried > CONFIG.max_scanned_classes then
                    log("[*] class scan stopped at max_scanned_classes")
                    break
                end
                hook_trust_manager(name, true)
                if CONFIG.enable_hostname_verifier then hook_hostname_verifier(name, true) end
            end
        end
        log(string.format("[*] scanned %d app classes by name", math.min(tried, CONFIG.max_scanned_classes)))
    end

    -- -----------------------------------------------------------------
    -- c. At run time: whatever the app registers
    -- -----------------------------------------------------------------
    safe_java_hook("javax/net/ssl/SSLContext", "init",
        "([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V", {
        onEnter = function(args)
            local managers = args[3]            -- TrustManager[] (may be null: default trust)
            if not managers or managers == 0 then return end
            local Array = Java.use("java/lang/reflect/Array")
            local ok, len = pcall(function() return Array:call("getLength", "(Ljava/lang/Object;)I", managers) end)
            if not ok or not len then return end
            for i = 0, len - 1 do
                local ok2, tm = pcall(function()
                    return Array:call("get", "(Ljava/lang/Object;I)Ljava/lang/Object;", managers, i)
                end)
                local name = ok2 and tm and class_of(tm)
                if name and not hooked["tm:" .. slashed(name)] then
                    log("[*] SSLContext.init: TrustManager " .. name)
                    hook_trust_manager(name)
                end
            end
        end
    }, "SSLContext.init (hooks every TrustManager the app registers)")

    if CONFIG.enable_hostname_verifier then
        local function on_verifier(args, index)
            local name = class_of(args[index])
            if name and not hooked["hv:" .. slashed(name)] then
                log("[*] HostnameVerifier registered: " .. name)
                hook_hostname_verifier(name)
            end
        end
        safe_java_hook("javax/net/ssl/HttpsURLConnection", "setHostnameVerifier",
            "(Ljavax/net/ssl/HostnameVerifier;)V",
            { onEnter = function(args) on_verifier(args, 2) end },
            "HttpsURLConnection.setHostnameVerifier (hooks the verifier)", true)
        safe_java_hook("javax/net/ssl/HttpsURLConnection", "setDefaultHostnameVerifier",
            "(Ljavax/net/ssl/HostnameVerifier;)V",
            { onEnter = function(args) on_verifier(args, 1) end },
            "HttpsURLConnection.setDefaultHostnameVerifier (hooks the verifier)", true)
    end

    -- -----------------------------------------------------------------
    -- okhttp3.CertificatePinner.check(...)
    -- Which overload(s) exist depends on the OkHttp version bundled with the
    -- app. All of them skip = accept any chain.
    -- -----------------------------------------------------------------
    for _, sig in ipairs({
        "(Ljava/lang/String;Ljava/util/List;)V",
        "(Ljava/lang/String;[Ljava/security/cert/Certificate;)V",
    }) do
        safe_java_hook("okhttp3/CertificatePinner", "check", sig, {
            onEnter = function(args)
                args.skip = true
                stats.cert_pinner_bypassed = stats.cert_pinner_bypassed + 1
                log("[*] OkHttp CertificatePinner.check bypassed")
            end
        }, "okhttp3.CertificatePinner.check" .. sig:match("%b()"), true)
    end
    safe_java_hook("okhttp3/CertificatePinner", "check$okhttp",
        "(Ljava/lang/String;Lkotlin/jvm/functions/Function0;)V", {
        onEnter = function(args)
            args.skip = true
            stats.cert_pinner_bypassed = stats.cert_pinner_bypassed + 1
            log("[*] OkHttp CertificatePinner.check$okhttp bypassed")
        end
    }, "okhttp3.CertificatePinner.check$okhttp", true)

    print("[OK] Java pinning hooks installed")
end

-- =====================================================================
-- NATIVE LAYER (BoringSSL / libssl.so)
-- =====================================================================
if CONFIG.enable_native then

    local libssl = Module.find("libssl.so")
    if libssl then
        local exports = Module.exports("libssl.so")
        local offsets = {}
        if exports then
            for _, exp in ipairs(exports) do
                if exp.name == "SSL_CTX_set_custom_verify" or exp.name == "SSL_set_custom_verify" then
                    offsets[exp.name] = exp.offset
                end
            end
        end

        if offsets.SSL_CTX_set_custom_verify or offsets.SSL_set_custom_verify then
            -- Build a tiny ARM64 stub that always reports ssl_verify_ok (0),
            -- ignoring its arguments:
            --   mov x0, #0   ; D2800000 -> bytes: 00 00 80 D2
            --   ret          ; D65F03C0 -> bytes: C0 03 5F D6
            local stub = Memory.alloc(0x1000, "rwx")
            if stub then
                Memory.write(stub, "\x00\x00\x80\xd2\xc0\x03\x5f\xd6")
                log(string.format("[*] custom_verify stub built at 0x%x", stub))

                -- void SSL_CTX_set_custom_verify(SSL_CTX *ctx, int mode, callback)
                -- args[0]=ctx args[1]=mode args[2]=callback  -> replace args[2]
                -- with our stub before the original runs; the original call
                -- still executes normally and just registers OUR callback.
                if offsets.SSL_CTX_set_custom_verify then
                    hook("libssl.so", offsets.SSL_CTX_set_custom_verify, {
                        onEnter = function(args)
                            log(string.format("[*] SSL_CTX_set_custom_verify(ctx=0x%x, mode=%d) -> callback replaced",
                                args[0], args[1]))
                            args[2] = stub
                            stats.native_verify_bypassed = stats.native_verify_bypassed + 1
                        end
                    })
                    print("[OK] SSL_CTX_set_custom_verify hooked")
                end

                -- void SSL_set_custom_verify(SSL *ssl, int mode, callback) --
                -- same idea, per-connection variant used by some apps/Conscrypt.
                if offsets.SSL_set_custom_verify then
                    hook("libssl.so", offsets.SSL_set_custom_verify, {
                        onEnter = function(args)
                            log(string.format("[*] SSL_set_custom_verify(ssl=0x%x, mode=%d) -> callback replaced",
                                args[0], args[1]))
                            args[2] = stub
                            stats.native_verify_bypassed = stats.native_verify_bypassed + 1
                        end
                    })
                    print("[OK] SSL_set_custom_verify hooked")
                end
            else
                print("[WARN] Memory.alloc failed, native custom_verify bypass skipped")
            end
        else
            print("[WARN] SSL_CTX_set_custom_verify/SSL_set_custom_verify not exported by libssl.so on this device/app (skipped)")
        end
    else
        print("[WARN] libssl.so not loaded yet (native hooks skipped - try again after the app opens a connection)")
    end
end

-- =====================================================================
-- CONTROL FUNCTIONS
-- =====================================================================
function ssl_bypass_stats()
    print("=== SSL Pinning Bypass Statistics ===")
    print(string.format("TrustManager checks bypassed:    %d", stats.trust_manager_bypassed))
    print(string.format("CertificatePinner checks bypassed: %d", stats.cert_pinner_bypassed))
    print(string.format("HostnameVerifier checks forced:   %d", stats.hostname_verifier_bypassed))
    print(string.format("Native custom_verify installs hijacked: %d", stats.native_verify_bypassed))
end

print("")
print("Commands:")
print("  exec ssl_bypass_stats()  -- show bypass counters")
print("")
print("Waiting for TLS handshakes... use 'watch' to see output")
