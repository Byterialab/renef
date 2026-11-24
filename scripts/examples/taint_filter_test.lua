-- Loads the taint_filter.lua recipe (scripts/recipes/) and checks it
-- from outside, via NativeFunction calls into the
-- now-Interceptor.replace'd libc functions -- deterministic, independent
-- of which Java/native code path would naturally trigger them.
--
-- Positive: a keyword-containing argument must come back as the
-- function-correct "not found/failed" value (strcmp: non-zero "not
-- equal", strstr: NULL, open: -1).
-- Negative: a normal, keyword-free argument must behave exactly as the
-- real libc function would (not forced to fail) -- proves the filter
-- isn't a blanket "always fail" hack that would break the app's own
-- normal operation.

-- NOTE: load scripts/recipes/taint_filter.lua FIRST (a separate `l`
-- command, host-side -- dofile() would look on the ANDROID device's own
-- filesystem, not the host repo, so it can't be used to chain-load a
-- second host-side script file from in here).
print("=== taint_filter.lua live test ===")

print("[*] taint_filter_match(\"frida\") = " .. tostring(taint_filter_match("frida")))
print("[*] taint_filter_match(\"hello\") = " .. tostring(taint_filter_match("hello")))
assert(taint_filter_match("frida") == true, "expected 'frida' to match the taint wordlist")
assert(taint_filter_match("hello") == false, "expected 'hello' to NOT match the taint wordlist")
print("[OK] taint_filter_match() keyword matching correct")

local base = Module.find("libc.so")
local function resolve(name)
    for _, e in ipairs(Module.exports("libc.so")) do
        if e.name == name then return base + e.offset end
    end
    return nil
end

local strcmp_fn = NativeFunction(resolve("strcmp"), "int", {"pointer", "pointer"})
local strstr_fn = NativeFunction(resolve("strstr"), "pointer", {"pointer", "pointer"})
local open_fn = NativeFunction(resolve("open"), "int", {"pointer", "int"})

-- POSITIVE: keyword-containing args must report function-correct failure.
local r1 = strcmp_fn("/data/local/tmp/libdlopen_test_dummy.so", "/data/local/tmp/libdlopen_test_dummy.so")
print("[*] POSITIVE strcmp(identical strings containing '/data/local/tmp') = " .. tostring(r1) .. " (expect non-zero, i.e. forced 'not equal')")
assert(r1 ~= 0, "expected strcmp to report 'not equal' for a taint-matched argument, got equal (0)")

local r2 = strstr_fn("this path has frida inside it", "frida")
print("[*] POSITIVE strstr(haystack containing 'frida', \"frida\") = " .. tostring(r2) .. " (expect 0/NULL, i.e. forced 'not found')")
assert(r2 == 0 or r2 == nil, "expected strstr to report NULL for a taint-matched needle, got " .. tostring(r2))

local r3 = open_fn("/data/local/tmp/some_file", 0)
print("[*] POSITIVE open(\"/data/local/tmp/...\", O_RDONLY) = " .. tostring(r3) .. " (expect -1, i.e. forced failure)")
assert(r3 == -1, "expected open() to report -1 for a taint-matched path, got " .. tostring(r3))
print("[OK] all 3 positive taint-match cases returned the function-correct failure value")

-- NEGATIVE: normal, keyword-free args must behave like real libc, not be
-- forced to fail.
local r4 = strcmp_fn("hello", "hello")
print("[*] NEGATIVE strcmp(\"hello\", \"hello\") = " .. tostring(r4) .. " (expect 0, i.e. real 'equal', unaffected)")
assert(r4 == 0, "expected strcmp('hello','hello') to pass through as equal (0), got " .. tostring(r4))

local r5 = strstr_fn("a perfectly normal haystack", "normal")
print("[*] NEGATIVE strstr(\"...normal...\", \"normal\") = " .. tostring(r5) .. " (expect non-zero, real match found)")
assert(r5 ~= 0 and r5 ~= nil, "expected strstr to find a real, non-keyword match, got " .. tostring(r5))

local r6 = open_fn("/system/bin/sh", 0)
print("[*] NEGATIVE open(\"/system/bin/sh\", O_RDONLY) = " .. tostring(r6) .. " (expect a real fd >= 0, unaffected)")
assert(r6 ~= nil and r6 >= 0, "expected open() on a normal, keyword-free path to succeed (real fd), got " .. tostring(r6))
print("[OK] all 3 negative (keyword-free) cases behaved like real, unfiltered libc")

print("=== test done ===")
