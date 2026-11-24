-- Hook __android_log_print - called hundreds of times per second by every Android app
__hook_type__ = "trampoline"

print("=== __android_log_print Hook Test ===")

local liblog = Module.find("liblog.so")
if not liblog then
    print("[ERROR] liblog.so not found")
    return
end
print("[OK] liblog.so @ " .. string.format("0x%x", liblog))

local exports = Module.exports("liblog.so")
if not exports then
    print("[ERROR] No exports")
    return
end
print("[OK] Got " .. #exports .. " exports")

for i, exp in ipairs(exports) do
    if exp.name == "__android_log_print" then
        print("[FOUND] __android_log_print @ offset: " .. string.format("0x%x", exp.offset))
        print("[INSTALL] Installing hook...")
        hook("liblog.so", exp.offset, {
            onEnter = function(args)
                print(">>> LOG CALLED! <<<")
            end
        })
        print("[OK] Hook installed!")
        break
    end
end

print("")
print("You should see 'LOG CALLED' messages immediately")
