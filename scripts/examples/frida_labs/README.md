# Frida_Labs challenges solved with Renef

DERE-ad2001's [Frida_Labs](https://github.com/DERE-ad2001/Frida-labs) is a nice
series of eleven Android challenges for learning instrumentation. This folder
has a Renef Lua script for each one, worked the same way the original solutions
do it — hook a method, call a method, patch an instruction — only with Renef's
API instead of Frida's.

Every script was run on a rooted ARM64 device until it produced the challenge
flag, twice in a row. They were driven through the Renef agent directly, so they
work the same from the CLI or from any tooling that talks to the agent.

## Running them

Install the APKs from the Frida_Labs repository first. Then, from the renef
CLI:

```
spawn com.ad2001.frida0x4
l scripts/examples/frida_labs/challenge_0x4.lua
```

Some challenges want a button press or a number typed into the app afterwards —
each bullet below says which.

## The challenges

- **0x1** — hook `check(II)V` and read the random number out of `args[2]`. The
  obvious hook on `get_random()` doesn't fire because ART inlines that tiny
  static method into `check`. Submit any number, then the one the hook prints.
  Flag: `FRIDA{BABY_HOOK_0x1}`.

- **0x2** — `get_flag(4919)` is never called. Call it on the main thread: the
  script registers a `Runnable` with `Java.registerClass` and posts it through a
  `Handler`, because doing Android UI work from the agent thread hangs.
  Flag: `FLAG{BABY_HOOKS_0x2}`.

- **0x3** — `Checker.code` needs to reach 512. Renef can't write static fields,
  so the script calls `increase()` 256 times, then you press the button.
  Flag: `FRIDA{INJECT_AND_INSPECT}`.

- **0x4** — build a `Check` object with `:new("()V")` and call
  `get_flag(1337)`. The flag comes back as the return value.
  Flag: `FRIDA{XORED_INSTANCE}`.

- **0x5**, **0x6**, **0x7** — the instance challenges. There is no
  `Java.choose`, so we walk `ActivityThread.mActivities` with reflection, find
  the live `MainActivity`, and invoke the target method on it. 0x6 and 0x7 also
  build a `Checker` (with reflection-set fields, or the two-argument
  constructor) and pass it in.
  Flags: `FRIDA{ON_MATCH_THIS_INSTANCE}`, `FRIDA{INSTANCES_AND_INSTANCES}`,
  `FRIDA{HOOKING_CONSTRUCTORS}`.

- **0x8** — a native hook on `cmpstr` at `libfrida0x8.so+0x864`, forced to
  return 1. The library is loaded on the first Submit, and the hook is deferred
  until then. A screenshot confirmed the toast.
  Flag: your input, shown as `YEY YOU GOT THE FLAG ...`.

- **0x9** — the same idea for `check_flag` at `liba0x9.so+0x614`, returning
  1337 (this overlaps with the existing `dere_0x9.lua` example, which is where
  the pattern came from).
  Toast: `You won FRIDA{NATIVE_LAND_0x2}`.

- **0xA** — the flag comes from a native `get_flag(int,int)` that is never
  called, and Renef has no `NativeFunction` to call it with. Instead the script
  patches the entry of `stringFromJNI` — which the app does call — with
  `mov w0,#1`, `mov w1,#2` and a branch to `get_flag`. logcat then shows
  `Decrypted Flag: FRIDA{DONT_CALL_ME}`.

- **0xB** — NOP the `b.ne` at `libfrida0xb.so+0x15248` so execution falls
  through into the decoder. Click the button once to load the library, load the
  script, click again. logcat: `FRIDA{NATIVE_HACKER}`.

`_prelude.lua` is the classloader snippet the Java scripts need. It is inlined
in each script because the Lua sandbox has no `require()`.

## Things learned while writing these

- Java class names use slashes and hooks need the full JNI signature.
- `Java.use()` can't see app classes until the agent thread's context
  classloader is pointed at the Application's classloader — that is what
  `_prelude.lua` does.
- Don't call a Java method from inside a hook handler; re-entering a method
  from its own `onEnter` crashed the agent.
- ART inlines small static methods, so a hook on them may never fire — hook the
  caller instead.
- If a class or library loads on the first user interaction, interact once
  before hooking it.
- Native return overrides work when the app calls the function, but do not
  always propagate when Lua calls the same function through JNI directly.

## Verification note

Verified against the 0.3.x agent on a rooted ARM64 device (OnePlus CPH2487,
Android 16). The scripts only use core APIs (`hook`, `Module`, `Memory`,
`Java`), but they have not been re-run against the 0.4.0 agent yet — happy to
re-verify before merge if that would help.
