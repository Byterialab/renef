---
title: Root Detection Bypass
layout: default
parent: Real-World Examples
nav_order: 2
---

# Root Detection Bypass

```lua
-- Common root detection functions
local patterns = {
    "access",
    "fopen",
    "stat"
}

local libc_exports = Module.exports("libc.so")

-- Hook file access functions
for _, pattern in ipairs(patterns) do
    for i, exp in ipairs(libc_exports) do
        if exp.name == pattern then
            hook("libc.so", exp.offset, {
                onEnter = function(args)
                    local path_ptr = args[0]
                    local path = Memory.readString(path_ptr)

                    -- Block access to su and Magisk paths
                    if path and (
                        string.find(path, "/su") or
                        string.find(path, "magisk") or
                        string.find(path, "supersu")
                    ) then
                        print(RED .. "[ROOT] Blocked: " .. path .. RESET)
                        -- Return -1 (file not found)
                        args.block = true
                    end
                end,
                onLeave = function(retval)
                    if args.block then
                        return -1
                    end
                    return retval
                end
            })
        end
    end
end
```

## What this does *not* bypass

Hooking the app's own root/tamper checks (as above) only defeats detection logic that runs **on the device, inside the app's own process**. It has no effect on **server-side attestation** — most notably [Google Play Integrity API](https://developer.android.com/google/play/integrity) (the successor to SafetyNet Attestation) — where the app sends a request to Google's servers and the server returns a cryptographically signed verdict about the device's integrity, computed from signals Google collects independently of anything the app itself reports.

A local hook backend like RENEF cannot forge that signed verdict: the signature is produced by Google's own keys from attestation data the device/OS layer provides, not from a value the running app computes and could have had patched in memory. Bypassing a *local* "is this device rooted / is this app instrumented" check and bypassing *server-attested* integrity are two different problems — this page, and RENEF's hooking model generally, only addresses the first. Don't assume a successful local bypass implies the target's backend-side integrity check (if any) would also pass.
