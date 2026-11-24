-- Simple open() hook test - open is called very frequently
__hook_type__ = "trampoline"

print("=== Simple open() Hook Test ===")

local libc = Module.find("libc.so")
if not libc then
    print("[ERROR] libc.so not found")
    return
end

print("[OK] libc.so @ " .. string.format("0x%x", libc))

local exports = Module.exports("libc.so")
if not exports then
    print("[ERROR] No exports")
    return
end

print("[OK] Got " .. #exports .. " exports")

for i, exp in ipairs(exports) do
    if exp.name == "open" then
        print("[FOUND] open @ offset: " .. string.format("0x%x", exp.offset))

        print("[INSTALL] Installing hook...")
        hook("libc.so", exp.offset, {
            onEnter = function(args)
                print(">>> OPEN CALLED! <<<")
            end
        })
        print("[OK] Hook installed!")
        break
    end
end

print("")
print("Test the app now - you should see '>>> OPEN CALLED! <<<' messages")
