-- Hook secret_function in libnative-lib.so
-- With --pause + deferred hooks: lib not loaded yet → agent defers the hook,
-- intercepts dlopen, installs hook when lib loads → catches first call
__hook_type__ = "trampoline"

print("=== Pause Test: secret_function Hook ===")

-- Just install the hook — if lib isn't loaded yet, agent will defer it
-- and install automatically when the lib loads (via dlopen interception)
print("[INSTALL] Hooking libnative-lib.so+0x6d4 (secret_function)...")
hook("libnative-lib.so", 0x6d4, {
    onEnter = function(args)
        print(">>> SECRET_FUNCTION CAUGHT BY HOOK! <<<")
    end
})
print("[OK] Hook registered!")
print("If lib not loaded yet, hook will be installed when it loads.")
