-- Module.disassemble() smoke test: resolve __android_log_print in liblog.so
-- the same way simple_log_test.lua does, then disassemble a handful of
-- instructions from its entry point and print them out.
__hook_type__ = "trampoline"

print("=== Module.disassemble Test ===")

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

local target_offset = nil
for i, exp in ipairs(exports) do
    if exp.name == "__android_log_print" then
        target_offset = exp.offset
        break
    end
end

if not target_offset then
    print("[ERROR] __android_log_print not found in exports")
    return
end

local addr = liblog + target_offset
print(string.format("[FOUND] __android_log_print @ 0x%x (offset 0x%x)", addr, target_offset))

print("[DISASM] Module.disassemble(addr, 8)")
local insns = Module.disassemble(addr, 8)

if not insns then
    print("[ERROR] disassemble returned nil")
    return
end

print(string.format("[OK] decoded %d instructions", #insns))
for i, insn in ipairs(insns) do
    local flags = ""
    if insn.is_branch then flags = flags .. " branch" end
    if insn.is_call then flags = flags .. " call" end
    if insn.is_jump then flags = flags .. " jump" end
    print(string.format("  [%d] 0x%x (sz=%d) %s %s%s",
        i, insn.address, insn.size, insn.mnemonic, insn.op_str, flags))
end

-- Negative test: an unmapped / bogus address should raise a Lua error,
-- not crash the hooked process.
print("[NEG] Module.disassemble(0xdead0000, 4) -- expect a Lua error")
local ok, err = pcall(function() return Module.disassemble(0xdead0000, 4) end)
if ok then
    print("[ERROR] expected an error for unmapped address, got success")
else
    print("[OK] got expected error: " .. tostring(err))
end

print("=== Done ===")
