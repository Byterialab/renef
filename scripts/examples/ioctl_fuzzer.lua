-- ioctl Kernel Fuzzer for Android
-- Intercepts ioctl() calls, logs device/request details, and optionally fuzzes arguments
--
-- Usage:
--   renef> l scripts/examples/ioctl_fuzzer.lua
--   renef> watch
--
-- Configuration: edit the CONFIG table below

__hook_type__ = "trampoline"

-- =====================================================================
-- CONFIG
-- =====================================================================
local CONFIG = {
    -- Fuzzing mode: "monitor" (log only) or "fuzz" (mutate arguments)
    mode = "monitor",

    -- Filter by device path (nil = all devices)
    -- Examples: "/dev/binder", "/dev/ashmem", "/dev/ion", "/dev/kgsl-3d0"
    target_device = nil,

    -- Filter by ioctl request code (nil = all)
    -- Example: 0xC0306201 (specific binder ioctl)
    target_request = nil,

    -- Max struct size to dump (bytes)
    max_dump_size = 128,

    -- Fuzz settings
    fuzz = {
        -- Mutation strategies: "bitflip", "byteflip", "interesting", "random", "overflow"
        strategies = {"bitflip", "interesting", "overflow"},

        -- Probability of fuzzing a matched ioctl (0.0 - 1.0)
        probability = 0.3,

        -- Max bytes to mutate per call
        max_mutations = 4,

        -- Skip first N calls (let app initialize normally)
        skip_first = 50,
    },

    -- Crash detection
    crash = {
        -- Log calls that return EFAULT, EINVAL, ENOTTY
        log_errors = true,

        -- Stop fuzzing after N consecutive errors
        max_consecutive_errors = 20,
    },

    -- Verbose output
    verbose = false,
}

-- =====================================================================
-- IOCTL REQUEST CODE DECODER
-- Linux _IOC(dir, type, nr, size) macro layout:
--   bits 31-30: direction (0=none, 1=write, 2=read, 3=read/write)
--   bits 29-16: argument size
--   bits 15-8:  type (magic number)
--   bits 7-0:   number (command)
-- =====================================================================
local function ioc_dir(cmd)   return (cmd >> 30) & 0x3 end
local function ioc_type(cmd)  return (cmd >> 8) & 0xFF end
local function ioc_nr(cmd)    return cmd & 0xFF end
local function ioc_size(cmd)  return (cmd >> 16) & 0x3FFF end

local DIR_NAMES = {
    [0] = "IOC_NONE",
    [1] = "IOC_WRITE",
    [2] = "IOC_READ",
    [3] = "IOC_RDWR",
}

-- Known Android ioctl types
local KNOWN_TYPES = {
    [0x62] = "binder",        -- 'b'
    [0x77] = "ashmem",        -- 'w' (ASHMEM_NAME_DEF)
    [0x49] = "ion",           -- 'I'
    [0x09] = "kgsl",          -- KGSL
    [0xAE] = "loop",          -- loop device
    [0x89] = "socket",        -- SIOC*
    [0x03] = "hid",           -- HID
}

-- Known binder ioctl numbers
local BINDER_IOCTLS = {
    [0x01] = "BINDER_WRITE_READ",
    [0x02] = "BINDER_SET_IDLE_TIMEOUT",
    [0x03] = "BINDER_SET_MAX_THREADS",
    [0x05] = "BINDER_SET_CONTEXT_MGR",
    [0x06] = "BINDER_THREAD_EXIT",
    [0x07] = "BINDER_VERSION",
    [0x09] = "BINDER_GET_NODE_DEBUG_INFO",
    [0x0C] = "BINDER_FREEZE",
    [0x0E] = "BINDER_ENABLE_ONEWAY_SPAM_DETECTION",
}

local function decode_ioctl(cmd)
    local dir = ioc_dir(cmd)
    local typ = ioc_type(cmd)
    local nr = ioc_nr(cmd)
    local size = ioc_size(cmd)
    local dir_name = DIR_NAMES[dir] or "???"
    local type_name = KNOWN_TYPES[typ]

    local name = nil
    if typ == 0x62 then -- binder
        name = BINDER_IOCTLS[nr]
    end

    return {
        dir = dir,
        dir_name = dir_name,
        type = typ,
        type_name = type_name,
        nr = nr,
        size = size,
        name = name,
    }
end

-- =====================================================================
-- FD -> PATH RESOLVER
-- Note: readlink not available in Lua API, fd shown as number only
-- =====================================================================
local function resolve_fd(fd)
    return nil
end

-- =====================================================================
-- HEX DUMP
-- =====================================================================
local function hexdump(addr, size)
    if size <= 0 or size > CONFIG.max_dump_size then
        size = CONFIG.max_dump_size
    end

    local data = Memory.read(addr, size)
    if not data then return "  <unreadable>" end

    local lines = {}
    for i = 0, #data - 1, 16 do
        local hex = {}
        local ascii = {}
        for j = 0, 15 do
            if i + j < #data then
                local b = string.byte(data, i + j + 1)
                hex[#hex + 1] = string.format("%02x", b)
                ascii[#ascii + 1] = (b >= 0x20 and b <= 0x7e) and string.char(b) or "."
            else
                hex[#hex + 1] = "  "
                ascii[#ascii + 1] = " "
            end
        end
        lines[#lines + 1] = string.format("  %04x: %-48s |%s|",
            i, table.concat(hex, " "), table.concat(ascii))
    end
    return table.concat(lines, "\n")
end

-- =====================================================================
-- INTERESTING VALUES (AFL-style)
-- =====================================================================
local INTERESTING_8  = {0, 1, 0x7F, 0x80, 0xFF}
local INTERESTING_16 = {0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF}
local INTERESTING_32 = {0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF,
                        0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF}

-- =====================================================================
-- MUTATION ENGINE
-- =====================================================================
local function mutate_buffer(addr, size)
    if size <= 0 then return {} end

    local mutations = {}
    local num_mutations = math.random(1, CONFIG.fuzz.max_mutations)
    local strategies = CONFIG.fuzz.strategies

    for _ = 1, num_mutations do
        local strategy = strategies[math.random(#strategies)]
        local offset = math.random(0, size - 1)

        if strategy == "bitflip" then
            local orig = Memory.readU8(addr + offset)
            if orig then
                local bit = math.random(0, 7)
                local new_val = orig ~ (1 << bit)
                Memory.writeU8(addr + offset, new_val)
                mutations[#mutations + 1] = string.format(
                    "bitflip @+0x%x: 0x%02x -> 0x%02x (bit %d)", offset, orig, new_val, bit)
            end

        elseif strategy == "byteflip" then
            local orig = Memory.readU8(addr + offset)
            if orig then
                local new_val = orig ~ 0xFF
                Memory.writeU8(addr + offset, new_val)
                mutations[#mutations + 1] = string.format(
                    "byteflip @+0x%x: 0x%02x -> 0x%02x", offset, orig, new_val)
            end

        elseif strategy == "interesting" then
            -- Pick interesting value based on alignment
            if offset % 4 == 0 and offset + 4 <= size then
                local orig = Memory.readU32(addr + offset)
                local val = INTERESTING_32[math.random(#INTERESTING_32)]
                Memory.writeU32(addr + offset, val)
                mutations[#mutations + 1] = string.format(
                    "interesting32 @+0x%x: 0x%08x -> 0x%08x", offset, orig or 0, val)
            elseif offset % 2 == 0 and offset + 2 <= size then
                local orig = Memory.readU16(addr + offset)
                local val = INTERESTING_16[math.random(#INTERESTING_16)]
                Memory.writeU16(addr + offset, val)
                mutations[#mutations + 1] = string.format(
                    "interesting16 @+0x%x: 0x%04x -> 0x%04x", offset, orig or 0, val)
            else
                local orig = Memory.readU8(addr + offset)
                local val = INTERESTING_8[math.random(#INTERESTING_8)]
                Memory.writeU8(addr + offset, val)
                mutations[#mutations + 1] = string.format(
                    "interesting8 @+0x%x: 0x%02x -> 0x%02x", offset, orig or 0, val)
            end

        elseif strategy == "random" then
            local orig = Memory.readU8(addr + offset)
            local new_val = math.random(0, 255)
            Memory.writeU8(addr + offset, new_val)
            mutations[#mutations + 1] = string.format(
                "random @+0x%x: 0x%02x -> 0x%02x", offset, orig or 0, new_val)

        elseif strategy == "overflow" then
            -- Write boundary values at struct field boundaries
            if offset % 4 == 0 and offset + 4 <= size then
                local orig = Memory.readU32(addr + offset)
                -- Large values to trigger integer overflow in kernel
                local overflows = {0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0x10000}
                local val = overflows[math.random(#overflows)]
                Memory.writeU32(addr + offset, val)
                mutations[#mutations + 1] = string.format(
                    "overflow32 @+0x%x: 0x%08x -> 0x%08x", offset, orig or 0, val)
            end
        end
    end

    return mutations
end

-- =====================================================================
-- STATISTICS
-- =====================================================================
local stats = {
    total_calls = 0,
    fuzzed_calls = 0,
    errors = 0,
    consecutive_errors = 0,
    by_device = {},
    by_request = {},
    crashes = {},
}

-- =====================================================================
-- ERRNO TABLE
-- =====================================================================
local ERRNO = {
    [1] = "EPERM", [2] = "ENOENT", [9] = "EBADF",
    [12] = "ENOMEM", [13] = "EACCES", [14] = "EFAULT",
    [16] = "EBUSY", [22] = "EINVAL", [25] = "ENOTTY",
    [38] = "ENOSYS",
}

-- =====================================================================
-- INSTALL HOOK
-- =====================================================================
print("=== ioctl Kernel Fuzzer ===")
print("Mode: " .. CONFIG.mode)
if CONFIG.target_device then
    print("Target device: " .. CONFIG.target_device)
end

local libc = Module.find("libc.so")
if not libc then
    print("[ERROR] libc.so not found")
    return
end

local exports = Module.exports("libc.so")
if not exports then
    print("[ERROR] Cannot get libc exports")
    return
end

local ioctl_offset = nil
for _, exp in ipairs(exports) do
    if exp.name == "ioctl" then
        ioctl_offset = exp.offset
        break
    end
end

if not ioctl_offset then
    print("[ERROR] ioctl not found in libc exports")
    return
end

print(string.format("[OK] ioctl @ libc+0x%x", ioctl_offset))

-- Seed RNG
math.randomseed(os.time())

-- Saved original arg buffers for restoration after fuzz
local saved_buffers = {}

hook("libc.so", ioctl_offset, {
    onEnter = function(args)
        local ok, err = pcall(function()
            local fd = args[0]
            local request = args[1]
            local arg_ptr = args[2]

            stats.total_calls = stats.total_calls + 1

            -- Decode ioctl request (mask to 32-bit for _IOC macros)
            local cmd = request & 0xFFFFFFFF
            local info = decode_ioctl(cmd)

            -- Track stats
            local dev_key = string.format("fd:%d", fd)
            stats.by_device[dev_key] = (stats.by_device[dev_key] or 0) + 1
            local req_key = string.format("0x%08x", cmd)
            stats.by_request[req_key] = (stats.by_request[req_key] or 0) + 1

            -- Build log line
            local req_str = info.name or string.format("0x%08x", cmd)
            local detail = string.format("%s(type='%s' nr=%d size=%d)",
                info.dir_name,
                info.type_name or string.format("0x%02x", info.type),
                info.nr, info.size)

            print(string.format("[ioctl #%d] fd=%d %s %s",
                stats.total_calls, fd, req_str, detail))

            -- Dump argument buffer if direction includes WRITE (userspace -> kernel)
            if arg_ptr ~= 0 and info.size > 0 and (info.dir == 1 or info.dir == 3) then
                if CONFIG.verbose then
                    print(string.format("  arg buffer @ 0x%x (%d bytes):", arg_ptr, info.size))
                    print(hexdump(arg_ptr, info.size))
                end
            end

            -- FUZZ MODE
            if CONFIG.mode == "fuzz"
               and arg_ptr ~= 0
               and info.size > 0
               and (info.dir == 1 or info.dir == 3)
               and stats.total_calls > CONFIG.fuzz.skip_first
               and stats.consecutive_errors < CONFIG.crash.max_consecutive_errors
            then
                if math.random() < CONFIG.fuzz.probability then
                    local orig_data = Memory.read(arg_ptr, info.size)
                    if orig_data then
                        saved_buffers[fd] = {
                            addr = arg_ptr,
                            size = info.size,
                            data = orig_data,
                        }

                        local mutations = mutate_buffer(arg_ptr, info.size)
                        if #mutations > 0 then
                            stats.fuzzed_calls = stats.fuzzed_calls + 1
                            print(string.format("  [FUZZ #%d] %d mutation(s):",
                                stats.fuzzed_calls, #mutations))
                            for _, m in ipairs(mutations) do
                                print("    " .. m)
                            end
                        end
                    end
                end
            end
        end)
        if not ok then
            print("[onEnter error] " .. tostring(err))
        end
    end,

    onLeave = function(retval)
        local ret = retval & 0xFFFFFFFF

        -- Error tracking (only in fuzz mode to reduce noise)
        if ret == 0xFFFFFFFF then -- -1
            stats.errors = stats.errors + 1
            stats.consecutive_errors = stats.consecutive_errors + 1

            if CONFIG.mode == "fuzz" and CONFIG.crash.log_errors then
                print(string.format("  => ERROR (total: %d, consecutive: %d)",
                    stats.errors, stats.consecutive_errors))

                if stats.consecutive_errors >= CONFIG.crash.max_consecutive_errors then
                    print("[!] Too many consecutive errors, pausing fuzz")
                end
            end
        else
            stats.consecutive_errors = 0
        end
    end
})

print("[OK] ioctl hook installed")
print("")
print("Commands (via exec):")
print("  exec ioctl_stats()    -- show statistics")
print("  exec ioctl_fuzz()     -- switch to fuzz mode")
print("  exec ioctl_monitor()  -- switch to monitor mode")
print("")

-- =====================================================================
-- CONTROL FUNCTIONS (callable via `exec`)
-- =====================================================================
function ioctl_stats()
    print("=== ioctl Statistics ===")
    print(string.format("Total calls: %d", stats.total_calls))
    print(string.format("Fuzzed calls: %d", stats.fuzzed_calls))
    print(string.format("Errors: %d (consecutive: %d)", stats.errors, stats.consecutive_errors))
    print("")

    print("By device:")
    for dev, count in pairs(stats.by_device) do
        print(string.format("  %-40s %d", dev, count))
    end
    print("")

    print("By request code:")
    for req, count in pairs(stats.by_request) do
        local cmd = tonumber(req)
        if cmd then
            local info = decode_ioctl(cmd)
            local name = info.name or (info.type_name or "?")
            print(string.format("  %s (%s nr=%d) %d", req, name, info.nr, count))
        else
            print(string.format("  %s %d", req, count))
        end
    end
end

function ioctl_fuzz()
    CONFIG.mode = "fuzz"
    stats.consecutive_errors = 0
    print("[*] Switched to FUZZ mode")
end

function ioctl_monitor()
    CONFIG.mode = "monitor"
    print("[*] Switched to MONITOR mode")
end
