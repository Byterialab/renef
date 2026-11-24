-- Engine Capture Recipe
--
-- Target: native code-integrity engines that keep themselves encrypted on
-- disk and only decrypt into an anonymous, executable mmap region at
-- runtime (real finding: DexProtector). Reading that blob off disk gets
-- you ciphertext; this recipe catches the moment it exists in cleartext
-- in memory and dumps it, without patching a single instruction of the
-- target's own code -- it only observes dlopen() returning and diffs
-- /proc/self/maps.
--
-- Why this beats passive memdump: memdump reads memory you already
-- know the address of, whenever you ask. This recipe is *active* (a hook
-- fires exactly when the engine appears) but still non-invasive (no
-- patched bytes, no replaced function) -- the engine never finds out it
-- was observed.
--
-- Detection signature (from real DexProtector-protected targets, the same
-- pattern repeated across three separate field scripts): a decrypted
-- engine blob shows up as a memory region that is
--   (a) anonymous       -- not backed by any file (`path == ""`)
--   (b) executable       -- `perms:sub(3,3) == "x"`
--   (c) a plausible size  -- real-world engines were ~256KB-1MB, but this
--                            varies by target/protector, hence CONFIG below
--                            instead of a hardcoded range.
--
-- "Grab-and-die" pattern (standard for this recipe and for crypto-hook
-- recipes in general): don't wait for a hook to "survive" -- a real
-- DexProtector target killed the process the moment a patched function
-- was called next, AES key material was captured in onEnter() (3rd arg =
-- key-schedule pointer) and the result in onLeave() (2nd arg = output
-- buffer) *before* that happened. Send what you have the instant you have
-- it; don't assume there will be a next call.
--
-- Usage:
--   renef> l scripts/recipes/engine_capture.lua
--   renef> watch
--   renef> exec engine_capture_stats()
--   renef> exec engine_capture_scan_now()   -- manual re-scan, e.g. if the
--                                              dlopen hook didn't fire
--
-- Self-test (no real protected target needed): see
-- scripts/examples/engine_capture_selftest.lua -- it points the exact same
-- detection helper at Renef's OWN native-hook trampoline (an anonymous
-- PROT_READ|WRITE|EXEC mmap created by allocate_trampoline(),
-- src/agent/hook/native.c) to prove the mechanism works end to end.

__hook_type__ = "trampoline"

-- =====================================================================
-- CONFIG
-- =====================================================================
local CONFIG = {
    -- Size window for what counts as a "probable decrypted engine" blob.
    -- Real-world DexProtector finding: 256KB-1MB. Different protectors/
    -- targets will differ -- inspect `Process.enumerateRanges()` output
    -- against a known-good run of the target before trusting the default.
    min_size = 0x40000,   -- 256 KB
    max_size = 0x100000,  -- 1 MB

    -- dlopen entry points to try hooking, in order. Whichever ones are
    -- actually exported by libc.so on this Android version get hooked;
    -- the rest are skipped silently.
    dlopen_targets = { "android_dlopen_ext", "dlopen" },

    -- Where dumped blobs are written on-device (pull with
    -- `adb pull <dump_dir>` after the run).
    dump_dir = "/data/local/tmp/renef_dump",

    -- Also emit a send() event (type="engine_capture") per dumped region.
    report = true,

    -- Re-scan on every dlopen() return, not just the first. Most targets
    -- only load their protected engine once, but leaving this on costs
    -- nothing (the `seen` set below makes repeat scans a no-op for
    -- regions already dumped).
    rescan_every_dlopen = true,
}

-- =====================================================================
-- DETECTION HELPER
-- =====================================================================
-- Process.enumerateRanges() filtered down to
-- "probable decrypted engine" regions. This is the one piece of logic
-- that used to be hand-copied into three different field scripts.
local function find_anon_exec_regions(min_size, max_size)
    local out = {}
    local ranges = Process.enumerateRanges()
    if not ranges then return out end
    for _, r in ipairs(ranges) do
        if r.path == "" and r.perms:sub(3, 3) == "x"
           and r.size >= min_size and r.size <= max_size then
            out[#out + 1] = r
        end
    end
    return out
end

-- =====================================================================
-- STATE
-- =====================================================================
local stats = {
    dlopen_calls = 0,
    regions_found = 0,
    bytes_dumped = 0,
    dumps = {},
}

-- Baseline: regions matching the filter that already existed before we
-- started watching (e.g. ART's own JIT cache, if it happens to fall in
-- the configured size window) should not be reported as "captured".
local seen = {}
for _, r in ipairs(find_anon_exec_regions(CONFIG.min_size, CONFIG.max_size)) do
    seen[r.start] = true
end

-- =====================================================================
-- CAPTURE
-- =====================================================================
local function dump_region(r)
    stats.regions_found = stats.regions_found + 1

    local path = string.format("%s/engine_%d_%x.bin",
        CONFIG.dump_dir, OS.getpid(), r.start)

    local ok, err = File.write(path, r.start, r.size)
    if ok then
        stats.bytes_dumped = stats.bytes_dumped + r.size
        stats.dumps[#stats.dumps + 1] = path

        print(string.format(
            "[engine_capture] CAPTURED 0x%x-0x%x (%d bytes, perms=%s) -> %s",
            r.start, r["end"], r.size, r.perms, path))

        if CONFIG.report then
            send({
                type = "engine_capture",
                pid = OS.getpid(),
                addr_start = r.start,
                addr_end = r["end"],
                size = r.size,
                perms = r.perms,
                dump_path = path,
            })
        end
    else
        print(string.format("[engine_capture] FAILED to dump 0x%x: %s",
            r.start, tostring(err)))
    end

    -- Mark as seen either way: a failed dump (e.g. dump_dir not
    -- writable) will fail the same way on every re-scan, and retrying
    -- it automatically would just spam the log. To retry after fixing
    -- the cause, clear the relevant key from `seen` by reloading the
    -- script, or extend this recipe with an explicit retry function.
    seen[r.start] = true
end

local function scan_for_new_engines()
    for _, r in ipairs(find_anon_exec_regions(CONFIG.min_size, CONFIG.max_size)) do
        if not seen[r.start] then
            dump_region(r)
        end
    end
end

-- =====================================================================
-- TRIGGER: hook dlopen, scan on return
-- =====================================================================
-- Why onLeave and not onEnter: by the time dlopen()/android_dlopen_ext()
-- *returns*, the linker has already run the library's constructors
-- (including JNI_OnLoad), which is where a DexProtector-style engine
-- decrypts itself into memory. Scanning onEnter would be too early.
--
-- Why a trampoline hook on libc.so and not a caller= PLT/GOT hook: the
-- decrypting engine may call dlopen() itself (self-loading a second
-- stage) via a resolved function pointer rather than through its own
-- GOT, which a caller= hook would miss. A direct trampoline hook on
-- libc.so's own dlopen entry point catches every call site. See
-- AGENTS.md's hooking-model section: "Trampoline... works on any
-- function" vs. "PLT/GOT... only dynamically linked call sites."
local function install_dlopen_hooks()
    local installed = 0

    local libc_exports = Module.exports("libc.so")
    if libc_exports then
        local offset_by_name = {}
        for _, e in ipairs(libc_exports) do
            offset_by_name[e.name] = e.offset
        end

        for _, name in ipairs(CONFIG.dlopen_targets) do
            local off = offset_by_name[name]
            if off then
                hook("libc.so", off, {
                    onLeave = function(retval)
                        stats.dlopen_calls = stats.dlopen_calls + 1
                        if CONFIG.rescan_every_dlopen or stats.dlopen_calls == 1 then
                            scan_for_new_engines()
                        end
                    end
                })
                print(string.format("[engine_capture] hooked libc.so!%s @ +0x%x", name, off))
                installed = installed + 1
            end
        end
    end

    if installed == 0 then
        -- Fallback: some Android versions don't export android_dlopen_ext/
        -- dlopen from libc.so's dynamic symbol table in a way Module.exports()
        -- sees. The linker's internal do_dlopen is the choke point every
        -- dlopen variant eventually reaches. See docs/api/module.md,
        -- "Hook library load".
        local linker_syms = Module.symbols("linker64")
        if linker_syms then
            for _, sym in ipairs(linker_syms) do
                if sym.name:find("do_dlopen") then
                    hook("linker64", sym.offset, {
                        onLeave = function(retval)
                            stats.dlopen_calls = stats.dlopen_calls + 1
                            if CONFIG.rescan_every_dlopen or stats.dlopen_calls == 1 then
                                scan_for_new_engines()
                            end
                        end
                    })
                    print(string.format("[engine_capture] hooked linker64!%s @ +0x%x",
                        sym.name, sym.offset))
                    installed = installed + 1
                    break
                end
            end
        end
    end

    if installed == 0 then
        print("[engine_capture] WARNING: no dlopen entry point found on this device.")
        print("[engine_capture]          falling back to manual-only mode -- call")
        print("[engine_capture]          exec engine_capture_scan_now() after the")
        print("[engine_capture]          target library you care about has loaded.")
    end
end

install_dlopen_hooks()

-- Also catch the case where the protected library was already loaded by
-- the time this script ran (e.g. attached late, or --pause wasn't used).
scan_for_new_engines()

-- =====================================================================
-- CONTROL FUNCTIONS
-- =====================================================================
function engine_capture_scan_now()
    scan_for_new_engines()
end

function engine_capture_stats()
    print("=== Engine Capture Statistics ===")
    print(string.format("dlopen() calls observed: %d", stats.dlopen_calls))
    print(string.format("engine regions captured: %d", stats.regions_found))
    print(string.format("bytes dumped:             %d", stats.bytes_dumped))
    for _, p in ipairs(stats.dumps) do
        print("  " .. p)
    end
end

print("[engine_capture] ready. Window: " ..
    string.format("0x%x-0x%x bytes, dump_dir=%s", CONFIG.min_size, CONFIG.max_size, CONFIG.dump_dir))
