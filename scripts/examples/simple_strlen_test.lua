-- Hook strlen - called extremely frequently by every app
__hook_type__ = "trampoline"

print("=== strlen Hook Test ===")

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

local count = 0

for i, exp in ipairs(exports) do
    if exp.name == "strlen" then
        print("[FOUND] strlen @ offset: " .. string.format("0x%x", exp.offset))
        print("[INSTALL] Installing hook...")
        hook("libc.so", exp.offset, {
            onEnter = function(args)
                count = count + 1
                if count <= 10 then
                    print(">>> STRLEN CALLED! (#" .. count .. ") <<<")
                end
            end
        })
        print("[OK] Hook installed!")
        break
    end
end

print("")
print("You should see 'STRLEN CALLED' messages immediately")
