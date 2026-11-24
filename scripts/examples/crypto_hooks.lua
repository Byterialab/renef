-- Android Cryptography Hook Script
-- Intercepts AES/RSA/DES encryption and decryption at Java and native layers
--
-- Usage:
--   renef> l scripts/examples/crypto_hooks.lua
--   renef> watch

__hook_type__ = "trampoline"

-- =====================================================================
-- CONFIG
-- =====================================================================
local CONFIG = {
    -- Hook layers: "java", "native", or "both"
    layer = "both",

    -- Max bytes to hexdump for key/iv/data
    max_dump = 64,

    -- Show stack traces
    backtrace = false,

    -- Filter by algorithm (nil = all)
    -- Examples: "AES", "RSA", "DES", "HmacSHA256"
    filter_algorithm = nil,

    -- Log key material (SENSITIVE - disable in production)
    log_keys = true,

    -- Log plaintext/ciphertext data
    log_data = true,
}

-- =====================================================================
-- HELPERS
-- =====================================================================

-- ART byte[] layout: [class:8][monitor:4][length:4][data...]
local ART_ARRAY_LENGTH_OFFSET = 12
local ART_ARRAY_DATA_OFFSET = 16

local function read_byte_array(ptr)
    if ptr == 0 or ptr == nil then return nil, 0 end
    local len = Memory.readU32(ptr + ART_ARRAY_LENGTH_OFFSET)
    if not len or len == 0 or len > 65536 then return nil, 0 end
    local data = Memory.read(ptr + ART_ARRAY_DATA_OFFSET, len)
    return data, len
end

local function hexstr(data, max)
    if not data then return "<null>" end
    max = max or CONFIG.max_dump
    local len = #data
    local parts = {}
    local show = math.min(len, max)
    for i = 1, show do
        parts[#parts + 1] = string.format("%02x", string.byte(data, i))
    end
    local s = table.concat(parts)
    if len > max then
        s = s .. string.format("... (%d bytes total)", len)
    end
    return s
end

local CIPHER_MODES = {
    [1] = "ENCRYPT",
    [2] = "DECRYPT",
    [3] = "WRAP",
    [4] = "UNWRAP",
}

local stats = {
    encrypt = 0,
    decrypt = 0,
    keys_seen = 0,
    init_calls = 0,
    doFinal_calls = 0,
}

-- Track current cipher state per-thread (simplified: last seen)
local cipher_state = {}

print("=== Android Crypto Hooks ===")
print("Layer: " .. CONFIG.layer)
if CONFIG.filter_algorithm then
    print("Filter: " .. CONFIG.filter_algorithm)
end

-- =====================================================================
-- JAVA LAYER HOOKS
-- =====================================================================
if CONFIG.layer == "java" or CONFIG.layer == "both" then

    -- -----------------------------------------------------------------
    -- javax.crypto.Cipher.init(int opmode, Key key)
    -- Captures encryption mode and key
    -- -----------------------------------------------------------------
    hook("javax/crypto/Cipher", "init",
        "(ILjava/security/Key;)V", {
        onEnter = function(args)
            stats.init_calls = stats.init_calls + 1
            local opmode = args[2] & 0xFFFFFFFF
            local mode_str = CIPHER_MODES[opmode] or tostring(opmode)

            print(string.format("\n[Cipher.init] mode=%s", mode_str))

            if CONFIG.backtrace then
                print(Thread.backtrace())
            end

            if opmode == 1 then stats.encrypt = stats.encrypt + 1
            elseif opmode == 2 then stats.decrypt = stats.decrypt + 1
            end
        end
    })

    -- -----------------------------------------------------------------
    -- javax.crypto.Cipher.init(int opmode, Key key, AlgorithmParameterSpec)
    -- Captures mode, key, and IV/params
    -- -----------------------------------------------------------------
    hook("javax/crypto/Cipher", "init",
        "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V", {
        onEnter = function(args)
            stats.init_calls = stats.init_calls + 1
            local opmode = args[2] & 0xFFFFFFFF
            local mode_str = CIPHER_MODES[opmode] or tostring(opmode)

            print(string.format("\n[Cipher.init] mode=%s (with params)", mode_str))

            if CONFIG.backtrace then
                print(Thread.backtrace())
            end

            if opmode == 1 then stats.encrypt = stats.encrypt + 1
            elseif opmode == 2 then stats.decrypt = stats.decrypt + 1
            end
        end
    })

    -- -----------------------------------------------------------------
    -- javax.crypto.Cipher.doFinal(byte[]) -> byte[]
    -- Main encryption/decryption point
    -- -----------------------------------------------------------------
    hook("javax/crypto/Cipher", "doFinal",
        "([B)[B", {
        onEnter = function(args)
            stats.doFinal_calls = stats.doFinal_calls + 1
            local input_ptr = args[2]

            print(string.format("\n[Cipher.doFinal] call #%d", stats.doFinal_calls))

            if CONFIG.log_data and input_ptr ~= 0 then
                local data, len = read_byte_array(input_ptr)
                if data then
                    print(string.format("  input (%d bytes): %s", len, hexstr(data)))
                end
            end

            if CONFIG.backtrace then
                print(Thread.backtrace())
            end
        end,

        onLeave = function(retval)
            if CONFIG.log_data and retval.raw ~= 0 then
                local data, len = read_byte_array(retval.raw)
                if data then
                    print(string.format("  output (%d bytes): %s", len, hexstr(data)))
                end
            end
        end
    })

    -- -----------------------------------------------------------------
    -- javax.crypto.Cipher.doFinal(byte[], int, int) -> byte[]
    -- -----------------------------------------------------------------
    hook("javax/crypto/Cipher", "doFinal",
        "([BII)[B", {
        onEnter = function(args)
            stats.doFinal_calls = stats.doFinal_calls + 1
            local input_ptr = args[2]
            local offset = args[3] & 0xFFFFFFFF
            local len = args[4] & 0xFFFFFFFF

            print(string.format("\n[Cipher.doFinal] call #%d (offset=%d, len=%d)",
                stats.doFinal_calls, offset, len))

            if CONFIG.log_data and input_ptr ~= 0 then
                local data, arr_len = read_byte_array(input_ptr)
                if data and len > 0 and offset < arr_len then
                    local slice = string.sub(data, offset + 1, offset + len)
                    print(string.format("  input (%d bytes): %s", len, hexstr(slice)))
                end
            end
        end,

        onLeave = function(retval)
            if CONFIG.log_data and retval.raw ~= 0 then
                local data, len = read_byte_array(retval.raw)
                if data then
                    print(string.format("  output (%d bytes): %s", len, hexstr(data)))
                end
            end
        end
    })

    -- -----------------------------------------------------------------
    -- javax.crypto.spec.SecretKeySpec.<init>(byte[], String)
    -- Captures raw key material
    -- -----------------------------------------------------------------
    hook("javax/crypto/spec/SecretKeySpec", "<init>",
        "([BLjava/lang/String;)V", {
        onEnter = function(args)
            stats.keys_seen = stats.keys_seen + 1
            local key_ptr = args[2]
            local algo_ptr = args[3]

            local algo = Jni.getStringUTF(algo_ptr)
            if CONFIG.filter_algorithm and algo then
                if not string.find(algo, CONFIG.filter_algorithm, 1, true) then
                    return
                end
            end

            print(string.format("\n[SecretKeySpec] algorithm=%s", algo or "???"))

            if CONFIG.log_keys and key_ptr ~= 0 then
                local key_data, key_len = read_byte_array(key_ptr)
                if key_data then
                    print(string.format("  key (%d bytes / %d bit): %s",
                        key_len, key_len * 8, hexstr(key_data)))
                end
            end

            if CONFIG.backtrace then
                print(Thread.backtrace())
            end
        end
    })

    -- -----------------------------------------------------------------
    -- javax.crypto.spec.IvParameterSpec.<init>(byte[])
    -- Captures IV
    -- -----------------------------------------------------------------
    hook("javax/crypto/spec/IvParameterSpec", "<init>",
        "([B)V", {
        onEnter = function(args)
            local iv_ptr = args[2]

            if CONFIG.log_keys and iv_ptr ~= 0 then
                local iv_data, iv_len = read_byte_array(iv_ptr)
                if iv_data then
                    print(string.format("[IvParameterSpec] IV (%d bytes): %s",
                        iv_len, hexstr(iv_data)))
                end
            end
        end
    })

    -- -----------------------------------------------------------------
    -- javax.crypto.spec.GCMParameterSpec.<init>(int, byte[])
    -- Captures GCM tag length and IV/nonce
    -- -----------------------------------------------------------------
    hook("javax/crypto/spec/GCMParameterSpec", "<init>",
        "(I[B)V", {
        onEnter = function(args)
            local tag_len = args[2] & 0xFFFFFFFF
            local iv_ptr = args[3]

            print(string.format("[GCMParameterSpec] tagLen=%d bits", tag_len))

            if CONFIG.log_keys and iv_ptr ~= 0 then
                local iv_data, iv_len = read_byte_array(iv_ptr)
                if iv_data then
                    print(string.format("  nonce (%d bytes): %s", iv_len, hexstr(iv_data)))
                end
            end
        end
    })

    -- -----------------------------------------------------------------
    -- javax.crypto.Mac.doFinal(byte[]) -> byte[]
    -- HMAC operations
    -- -----------------------------------------------------------------
    hook("javax/crypto/Mac", "doFinal",
        "([B)[B", {
        onEnter = function(args)
            local input_ptr = args[2]
            print("\n[Mac.doFinal] HMAC computation")

            if CONFIG.log_data and input_ptr ~= 0 then
                local data, len = read_byte_array(input_ptr)
                if data then
                    print(string.format("  input (%d bytes): %s", len, hexstr(data)))
                end
            end
        end,

        onLeave = function(retval)
            if CONFIG.log_data and retval.raw ~= 0 then
                local data, len = read_byte_array(retval.raw)
                if data then
                    print(string.format("  mac (%d bytes): %s", len, hexstr(data)))
                end
            end
        end
    })

    -- -----------------------------------------------------------------
    -- java.security.MessageDigest.digest(byte[]) -> byte[]
    -- Hash operations (SHA-256, MD5, etc.)
    -- -----------------------------------------------------------------
    hook("java/security/MessageDigest", "digest",
        "([B)[B", {
        onEnter = function(args)
            local input_ptr = args[2]
            print("\n[MessageDigest.digest]")

            if CONFIG.log_data and input_ptr ~= 0 then
                local data, len = read_byte_array(input_ptr)
                if data then
                    print(string.format("  input (%d bytes): %s", len, hexstr(data)))
                end
            end
        end,

        onLeave = function(retval)
            if CONFIG.log_data and retval.raw ~= 0 then
                local data, len = read_byte_array(retval.raw)
                if data then
                    print(string.format("  hash (%d bytes): %s", len, hexstr(data)))
                end
            end
        end
    })

    print("[OK] Java crypto hooks installed")
end

-- =====================================================================
-- NATIVE LAYER HOOKS (BoringSSL / libcrypto.so)
-- =====================================================================
if CONFIG.layer == "native" or CONFIG.layer == "both" then

    local libcrypto = Module.find("libcrypto.so")
    if libcrypto then
        local exports = Module.exports("libcrypto.so")
        if exports then
            local targets = {
                EVP_EncryptUpdate = nil,
                EVP_DecryptUpdate = nil,
                EVP_CipherInit_ex = nil,
            }

            for _, exp in ipairs(exports) do
                if targets[exp.name] ~= nil or targets[exp.name] == nil and targets[exp.name] ~= false then
                    if exp.name == "EVP_EncryptUpdate" or
                       exp.name == "EVP_DecryptUpdate" or
                       exp.name == "EVP_CipherInit_ex" then
                        targets[exp.name] = exp.offset
                    end
                end
            end

            -- EVP_CipherInit_ex(ctx, type, impl, key, iv, enc)
            if targets.EVP_CipherInit_ex then
                hook("libcrypto.so", targets.EVP_CipherInit_ex, {
                    onEnter = function(args)
                        local ctx = args[0]
                        local enc = args[5]
                        local mode = "???"
                        if enc == 1 then mode = "ENCRYPT"
                        elseif enc == 0 then mode = "DECRYPT"
                        end

                        print(string.format("\n[EVP_CipherInit_ex] ctx=0x%x mode=%s", ctx, mode))

                        -- Key pointer (arg 3)
                        if CONFIG.log_keys and args[3] ~= 0 then
                            local key = Memory.read(args[3], 32)
                            if key then
                                print(string.format("  key: %s", hexstr(key, 32)))
                            end
                        end

                        -- IV pointer (arg 4)
                        if CONFIG.log_keys and args[4] ~= 0 then
                            local iv = Memory.read(args[4], 16)
                            if iv then
                                print(string.format("  iv: %s", hexstr(iv, 16)))
                            end
                        end
                    end
                })
                print(string.format("[OK] EVP_CipherInit_ex @ libcrypto+0x%x", targets.EVP_CipherInit_ex))
            end

            -- EVP_EncryptUpdate(ctx, out, outl, in, inl)
            if targets.EVP_EncryptUpdate then
                hook("libcrypto.so", targets.EVP_EncryptUpdate, {
                    onEnter = function(args)
                        local inl = args[4] & 0xFFFFFFFF
                        print(string.format("\n[EVP_EncryptUpdate] %d bytes", inl))

                        if CONFIG.log_data and args[3] ~= 0 and inl > 0 then
                            local show = math.min(inl, CONFIG.max_dump)
                            local data = Memory.read(args[3], show)
                            if data then
                                print(string.format("  plaintext: %s", hexstr(data)))
                            end
                        end
                    end
                })
                print(string.format("[OK] EVP_EncryptUpdate @ libcrypto+0x%x", targets.EVP_EncryptUpdate))
            end

            -- EVP_DecryptUpdate(ctx, out, outl, in, inl)
            if targets.EVP_DecryptUpdate then
                hook("libcrypto.so", targets.EVP_DecryptUpdate, {
                    onEnter = function(args)
                        local inl = args[4] & 0xFFFFFFFF
                        print(string.format("\n[EVP_DecryptUpdate] %d bytes", inl))

                        if CONFIG.log_data and args[3] ~= 0 and inl > 0 then
                            local show = math.min(inl, CONFIG.max_dump)
                            local data = Memory.read(args[3], show)
                            if data then
                                print(string.format("  ciphertext: %s", hexstr(data)))
                            end
                        end
                    end
                })
                print(string.format("[OK] EVP_DecryptUpdate @ libcrypto+0x%x", targets.EVP_DecryptUpdate))
            end
        end
    else
        print("[WARN] libcrypto.so not found (native hooks skipped)")
    end

    print("[OK] Native crypto hooks installed")
end

-- =====================================================================
-- CONTROL FUNCTIONS
-- =====================================================================
function crypto_stats()
    print("=== Crypto Statistics ===")
    print(string.format("Cipher.init calls:    %d", stats.init_calls))
    print(string.format("Cipher.doFinal calls: %d", stats.doFinal_calls))
    print(string.format("  Encrypt: %d", stats.encrypt))
    print(string.format("  Decrypt: %d", stats.decrypt))
    print(string.format("Keys seen: %d", stats.keys_seen))
end

print("")
print("Commands:")
print("  exec crypto_stats()  -- show statistics")
print("")
print("Monitoring crypto operations... use 'watch' to see output")
