# Frida_Labs examples for Renef

These are the eleven Frida_Labs challenges, translated from the Frida solutions
to Renef Lua. I worked through them one at a time on a rooted ARM64 phone and
kept whichever script actually produced the flag — not the one that looked like
it should work. All eleven passed twice in a row through the little harness in
`tests/` (gitignored, so it stays on this machine).

Running one is usually just two calls:

```
renef_spawn("com.ad2001.frida0x4")
renef_load_script(".../challenge_0x4.lua")
```

The first load resumes the gated process, so there is no separate resume step.
A few of them need a button press or a second submit; the write-up says which.

## What's in here

- **0x1** — hook `check(II)V` and read the random number out of `args[2]`. The
  original hooks `get_random()`, but that method is tiny and gets inlined, so
  the hook never fires. Submit any number, then the one the hook prints.
  Result: `FRIDA{BABY_HOOK_0x1}` in the TextView.

- **0x2** — call `get_flag(4919)`. Calling it from the agent thread hangs, so the
  script posts a Runnable to the main looper with `Java.registerClass` and
  `Handler.post`. Result: `FLAG{BABY_HOOKS_0x2}`.

- **0x3** — `Checker.code` needs to reach 512. Renef can't write static fields,
  so we call `increase()` 256 times and press Click me. Result:
  `FRIDA{INJECT_AND_INSPECT}`.

- **0x4** — create a `Check` instance with `:new("()V")` and call
  `get_flag(1337)`. Result: `FLAG FRIDA{XORED_INSTANCE}` in the MCP output; this
  one never changes the UI.

- **0x5**, **0x6**, **0x7** — these are the instance challenges. There is no
  `Java.choose` in Renef, so we walk `ActivityThread.mActivities` with reflection,
  find the live `MainActivity`, and invoke the method ourselves. 0x6 and 0x7
  also build a `Checker` and set its numbers (or use the two-arg constructor).
  Results: `FRIDA{ON_MATCH_THIS_INSTANCE}`, `FRIDA{INSTANCES_AND_INSTANCES}`,
  `FRIDA{HOOKING_CONSTRUCTORS}`.

- **0x8** — a deferred native hook on `cmpstr` at `libfrida0x8.so+0x864`, forcing
  the return to 1. Android's translate popup sometimes eats the first tap, so
  click Submit twice if needed. Verified by the hook output and a screenshot:
  `YEY YOU GOT THE FLAG candidate`.

- **0x9** — same idea for `check_flag` at `liba0x9.so+0x614`, returning 1337.
  Screenshot: `You won FRIDA{NATIVE_LAND_0x2}`.

- **0xA** — call the uncalled native `get_flag(int,int)` directly with Renef's
  `NativeFunction` (added in 0.4.0). On older agents the fallback is a
  hand-encoded ARM64 patch of `stringFromJNI`'s entry. logcat then shows
  `Decrypted Flag: FRIDA{DONT_CALL_ME}`.

- **0xB** — NOP the `b.ne` at `libfrida0xb.so+0x15248`. Click once to get the
  library loaded, load the script, click again. logcat shows
  `FRIDA{NATIVE_HACKER}`.

Each challenge has a `Solution_0xN.md` next to its script, written the same way
the Frida_Labs solutions are: what the app does, what the decompilation shows,
how the Frida version solves it, and how we do it in Renef.

`_prelude.lua` is the app-classloader snippet the Java scripts need. It is
inlined in each script because Renef Lua has no `require()`.

## Things I learned the hard way

- Java class names use slashes and need the full JNI signature.
- `Java.use()` cannot see app classes until you give the agent thread the app's
  classloader. That is what the prelude does.
- Don't call a Java method from inside a hook handler. Re-entering `check()` from
  its own `onEnter` crashed the agent.
- Native return overrides work when the app calls the function, but not always
  when Lua calls it through JNI directly. Verify against the app's behaviour,
  not just the hook print.
- If a class is loaded on the first click, click once before loading the script.
- Toasts don't show up in `uiautomator dump` or logcat. For 0x8 and 0x9 I took a
  screenshot and read it instead of guessing from a passing hook.
