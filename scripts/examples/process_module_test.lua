-- Live test for Process/Module introspection:
--   Process.enumerateRanges()
--   Process.enumerateThreads()
--   Module.findExportByName(module, pattern)

print("=== Process.enumerateRanges ===")
local ranges = Process.enumerateRanges()
if ranges then
    print(string.format("total ranges: %d", #ranges))
    for i = 1, math.min(5, #ranges) do
        local r = ranges[i]
        print(string.format("[%d] 0x%x-0x%x size=0x%x perms=%s path=%s",
            i, r.start, r["end"], r.size, r.perms, r.path))
    end
else
    print("Process.enumerateRanges returned nil")
end

print("=== Process.enumerateThreads ===")
local tids = Process.enumerateThreads()
if tids then
    print(string.format("total threads: %d", #tids))
    for i = 1, math.min(10, #tids) do
        print(string.format("  tid[%d] = %d", i, tids[i]))
    end
else
    print("Process.enumerateThreads returned nil")
end

print("=== Module.findExportByName (glob) ===")
local matches = Module.findExportByName("libc.so", "pthread_*")
if matches then
    print(string.format("pthread_* matches in libc.so: %d", #matches))
    for i = 1, math.min(8, #matches) do
        print(string.format("  %s -> 0x%x", matches[i].name, matches[i].offset))
    end
else
    print("Module.findExportByName(pthread_*) returned nil")
end

print("=== Module.findExportByName (exact) ===")
local exact = Module.findExportByName("libc.so", "malloc")
if exact then
    print(string.format("exact 'malloc' matches: %d", #exact))
    for i = 1, #exact do
        print(string.format("  %s -> 0x%x", exact[i].name, exact[i].offset))
    end
else
    print("Module.findExportByName(malloc) returned nil")
end

print("=== Module.findExportByName (no match) ===")
local none = Module.findExportByName("libc.so", "this_symbol_does_not_exist_*")
if none then
    print(string.format("no-match count: %d", #none))
else
    print("Module.findExportByName(no-match) returned nil")
end

print("DONE")
