print("=== EmulatorDetection.spoofBuildProps test ===")
local ClassCls = Java.use("java/lang/Class")
local buildClass = ClassCls:call("forName", "(Ljava/lang/String;)Ljava/lang/Class;", "android.os.Build")
local field = buildClass:call("getField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;", "MODEL")
field:call("setAccessible", "(Z)V", true)
local before = field:call("get", "(Ljava/lang/Object;)Ljava/lang/Object;", nil)
print("[*] BEFORE: Build.MODEL = " .. tostring(before))

EmulatorDetection.spoofBuildProps()

local after = field:call("get", "(Ljava/lang/Object;)Ljava/lang/Object;", nil)
print("[*] AFTER: Build.MODEL = " .. tostring(after))
if after == "SM-G973F" and before ~= "SM-G973F" then
    print("[OK] POSITIVE: Build.MODEL was successfully spoofed to the fake Samsung value")
else
    print("[FAIL] Build.MODEL spoofing did not take effect as expected")
end

-- NEGATIVE: an unrelated, non-spoofed field must stay untouched.
local vfield = buildClass:call("getField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;", "TYPE")
vfield:call("setAccessible", "(Z)V", true)
local vtype_val = vfield:call("get", "(Ljava/lang/Object;)Ljava/lang/Object;", nil)
print("[*] NEGATIVE: Build.TYPE (not in the spoof list) = " .. tostring(vtype_val) .. " (expect real, unaffected value)")
