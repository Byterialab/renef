print("=== java_reflection_dump.lua test ===")
print("[*] POSITIVE: dump_class_schema(\"android.os.Build\")")
dump_class_schema("android.os.Build")

print("[*] NEGATIVE: dump_class_schema(\"com.does.not.Exist\")")
local ok, err = pcall(function() dump_class_schema("com.does.not.Exist") end)
print("ok=" .. tostring(ok) .. " err=" .. tostring(err))

print("[*] POSITIVE: dump_instance_fields on a real instance")
local f = Java.use("java/io/File"):new("(Ljava/lang/String;)V", "/data/local/tmp/h3a_test.txt")
dump_instance_fields(f, "java.io.File")

print("=== test done ===")
