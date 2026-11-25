-- Frida Labs 0xA: the flag comes from a native get_flag(int,int) in
-- libfrida0xa.so that the app never calls. Since Renef 0.4.0 there is a
-- NativeFunction API, so we can call it directly: the function checks that
-- the two arguments sum to 3 and logs the decoded flag.

local lib = 'libfrida0xa.so'
local base = Module.find(lib)
if not base then
    print('[0xA] ' .. lib .. ' not loaded; reload after the app draws')
    return
end

-- _Z8get_flagii @ 0x1dd60 (readelf), takes two ints, returns void
local get_flag = NativeFunction(base + 0x1dd60, 'void', { 'int', 'int' })
get_flag(1, 2)
print('[0xA] get_flag(1,2) called; check logcat tag FLAG')
