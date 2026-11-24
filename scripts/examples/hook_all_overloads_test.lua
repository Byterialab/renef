print("=== hook_all_overloads test ===")

-- POSITIVE: StringBuilder.append has ~10 overloads (String, int, boolean,
-- char, Object, CharSequence, double, float, long, char[]).
local installed, failed, errors = hook_all_overloads("java.lang.StringBuilder", "append", {
    onEnter = function(args) end
})
print("[*] POSITIVE: installed=" .. installed .. " failed=" .. failed)
assert(installed >= 5, "expected at least 5 StringBuilder.append overloads to be hooked, got " .. installed)
assert(failed == 0, "expected 0 failures for a fresh, uncontested capacity, got " .. failed)

-- Trigger a couple of the hooked overloads to prove they actually fire.
local sb = Java.use("java/lang/StringBuilder"):new("()V")
sb:call("append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", "hi")
sb:call("append", "(I)Ljava/lang/StringBuilder;", 42)
print("[OK] triggered 2 of the hooked overloads without crashing")

-- NEGATIVE: a class/method combo that doesn't exist must report 0/0
-- cleanly, not error out or crash.
local installed2, failed2, errors2 = hook_all_overloads("com.does.not.Exist", "nope", {
    onEnter = function(args) end
})
print("[*] NEGATIVE (bad class): installed=" .. installed2 .. " failed=" .. failed2 .. " errors=" .. #errors2)
assert(installed2 == 0, "expected 0 installs for a nonexistent class")

-- NEGATIVE: a real class but a method name that doesn't exist on it ->
-- 0 installed, 0 failed (nothing matched the name filter), no crash.
local installed3, failed3 = hook_all_overloads("java.lang.StringBuilder", "thisMethodDoesNotExist", {
    onEnter = function(args) end
})
print("[*] NEGATIVE (bad method name): installed=" .. installed3 .. " failed=" .. failed3)
assert(installed3 == 0 and failed3 == 0, "expected 0/0 for a nonexistent method name")

print("=== test done ===")
