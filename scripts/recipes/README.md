# Recipes

Ready-to-run pentest scripts for recurring tasks, built entirely on Renef's
existing `hook()` / `Java.*` / `Interceptor.*` / `Memory.*` Lua API - no
agent or host code changes required. `scripts/examples/crypto_hooks.lua` was the template
these follow in style (CONFIG table, stats counters, a `*_stats()` control
function, graceful no-op when a target isn't present).

**Every recipe here is a template, not a drop-in universal bypass.** Each
file documents its own assumptions and limitations at the top - read that
header before running it against a new target. Different apps implement
pinning/detection differently; expect to adjust class names, method
signatures, and native offsets after inspecting the actual target APK
(jadx/apktool).

Only use these against apps/devices you are authorized to test. Bypassing
an app's own certificate pinning and root/instrumentation checks during an
authorized pentest is standard, legitimate practice - the same use case
covered by Frida's own `frida-android-unpinning` project.

## Files

### `ssl_pinning_bypass.lua`
Forces TLS certificate validation to succeed. `X509TrustManager` and
`HostnameVerifier` are interfaces and have no code to hook, so the recipe
hooks the classes that implement them. It finds those three ways: the ones
that ship with Android (Conscrypt's `TrustManagerImpl`, the Network Security
Config trust managers, the platform's OkHttp hostname verifier), app classes
whose name suggests one (`CONFIG.class_keywords`), and - at run time - every
`TrustManager` the app passes to `SSLContext.init()` and every
`HostnameVerifier` it sets on an `HttpsURLConnection`. Classes found by hand go
into `CONFIG.extra_trust_managers` / `CONFIG.extra_hostname_verifiers`. Hooks:
- `checkServerTrusted`/`checkClientTrusted` of each implementation (plus the
  Socket/SSLEngine overloads and Conscrypt's list-returning variant)
- OkHttp's `okhttp3.CertificatePinner.check(...)` (all known overloads)
- `verify()` of each `HostnameVerifier` implementation, forced to `true`
- Native BoringSSL `SSL_CTX_set_custom_verify` / `SSL_set_custom_verify`
  (replaces the registered verify callback with a tiny generated ARM64 stub
  that always returns `ssl_verify_ok`)

```
renef> l scripts/recipes/ssl_pinning_bypass.lua
renef> watch
renef> exec ssl_bypass_stats()
```

### `root_frida_detection_bypass.lua`
Disables common root-detection and Frida/instrumentation-detection checks:
- su binary existence (native `access`/`stat`/`open`/`fopen` + Java
  `File.exists()`) for a configurable list of root-indicator paths
- `Runtime.exec("su")` / `Runtime.exec(String[])`
- `android.os.Build.TAGS` patched to `"release-keys"` (best-effort, via
  reflection)
- native `strstr()` calls whose needle contains `"frida"` (catches
  `/proc/self/maps` scanning regardless of how the buffer was read)
- native `connect()` to frida-server's default ports (27042/27043)
- optional, off by default: `java.lang.String.contains()` keyword
  filtering (very hot method process-wide - real performance cost)

```
renef> l scripts/recipes/root_frida_detection_bypass.lua
renef> watch
renef> exec detection_bypass_stats()
```

Explicitly out of scope (see the file's header): SafetyNet/Play Integrity
(server-side), and any check that reads a real file's *contents* rather
than just its existence (e.g. thread-name scanning of
`/proc/self/task/*/comm` for Frida's internal thread names) - those need
content-rewriting hooks on `read()`/`fgets()`, which this recipe does not
attempt.

### `taint_filter.lua`
Hooks libc string/file functions and neutralizes calls whose arguments
match a keyword from a real pentest's verified wordlist. Each hooked
function gets its own ABI-correct "not found/failed" value - there is no
single "neutralize everything the same way" helper:
- `strstr`/`strcasestr` -> `NULL` ("not found")
- `strcmp`/`strncmp`/`strcasecmp` -> non-zero ("not equal", not "equal" -
  most detection code treats `== 0` as a match)
- `open`/`openat`/`access`/`stat`/`lstat`/`faccessat`/`readlink` -> `-1`
- `fopen` -> `NULL` (it returns a `FILE*`, not an int - `-1` would be wrong)
- optional (off by default): `read()`-based `TracerPid:` scrub on
  `/proc/self/status` reads (a content rewrite, not a match/exist check -
  the classic ptrace-self-attach anti-debug pattern)

Every hooked function is independently toggleable via `CONFIG` - see the
file header for why the "any arg contains a keyword -> block" rule from
an earlier draft was wrong and why the wordlist itself uses per-token match modes
(`exact`/`suffix`/`substring`) instead of one blind substring scan.

```
renef> l scripts/recipes/taint_filter.lua
renef> watch
renef> exec taint_filter_stats()
```

Exposes a global `taint_filter_match(str)` so `root_emulator_bypass.lua`
can reuse the same wordlist/match logic when loaded first.

### `root_emulator_bypass.lua`
Modular rewrite of the root-detection half of
`root_frida_detection_bypass.lua`, split into independently toggleable
functions under two namespaces instead of one monolithic script:
- `RootDetection.hideSuBinaries([extraPaths])` - su-indicator path hiding
  (native + `File.exists()`), same mechanism as the monolithic recipe
- `RootDetection.hidePackages([pkgList])` - redirects
  `PackageManager.getPackageInfo()` lookups for root-manager/Xposed
  package names to a nonexistent package in `onEnter`, so the real method
  throws its own real "not found" rather than faking a return value
- `RootDetection.forceBooleanArgs(class, method, signature, argIndices, forcedValue [, label])` -
  generic helper for the "a method takes N booleans and decides based on
  them internally" pattern (real finding: a 3-boolean method,
  `(ZZZ)V`). **Must run in `onEnter`, not `onLeave`** - by the time
  `onLeave` fires the method already branched on the real parameter
  values; `onLeave` can only replace the final return value, which is too
  late for a `void` method or for internal control flow. See the file's
  header for the full writeup; `scripts/examples/onenter_writeback_test.lua`
  and `scripts/examples/java_hook_engine_test.lua` exercise the write-back.
- `EmulatorDetection.spoofBuildProps([fields])` - reflection patch of
  `android.os.Build` fields (`FINGERPRINT`, `MODEL`, `HARDWARE`, ...)
- `EmulatorDetection.spoofSystemProperties([props])` - hooks
  `__system_property_get()` and spoofs known qemu/emulator-telltale
  property values by name (`ro.kernel.qemu`, `ro.hardware`, ...)

Root-indicator file hiding and emulator identity spoofing are kept in
separate namespaces deliberately - an emulator can be unrooted and a real
device can be rooted, so conflating the two mechanisms would be wrong.

Composes with `taint_filter.lua` if loaded first (reuses its wordlist via
`taint_filter_match()`), but has no hard dependency on it.

```
renef> l scripts/recipes/taint_filter.lua          -- optional, load first
renef> l scripts/recipes/root_emulator_bypass.lua
renef> exec RootDetection.hideSuBinaries()
renef> exec EmulatorDetection.spoofBuildProps()
renef> watch
renef> exec root_bypass_stats()
```

### `engine_capture.lua`
Catches native code-integrity "engines" that keep themselves encrypted on
disk and decrypt into an anonymous, executable `mmap` region only at
runtime (real finding: DexProtector). Hooks `dlopen`/`android_dlopen_ext`
(falls back to the linker's internal `do_dlopen` if those aren't exported
on this Android version), and on return diffs `Process.enumerateRanges()`
against a baseline to find newly-appeared regions that are anonymous
(`path == ""`) and executable (`perms:sub(3,3) == "x"`) within a
configurable size window (default: 256KB-1MB, the real-world DexProtector
range - override per target). Matches get dumped with `File.write()` and
reported with `send({type = "engine_capture", ...})`.

This is **more powerful than a passive memdump**: it's active
(fires exactly when the engine appears) but still fully non-invasive - no
instruction gets patched, nothing the target can detect.

```
renef> l scripts/recipes/engine_capture.lua
renef> watch
renef> exec engine_capture_stats()
renef> exec engine_capture_scan_now()   -- manual re-scan if the dlopen
                                            hook didn't fire for your target
```

No real DexProtector-protected target in this environment? Run
`scripts/examples/engine_capture_selftest.lua` instead - it points the
exact same detection filter at Renef's own native-hook trampoline (an
anonymous `PROT_READ|WRITE|EXEC` mmap the agent creates for every
trampoline-style `hook()` call) and asserts it gets flagged, proving the
mechanism end to end without needing a protected binary.

### `java_reflection_dump.lua`
Generic `Java.use`/reflection recon helpers, usable against any class:
- `dump_class_schema(class_name)` - fields + methods of a class, by name
  (modifiers, types, signatures), via `Class.forName` +
  `java.lang.reflect.Array`/`Modifier`
- `dump_instance_fields(instance [, class_name])` - live field *values* of
  an object you already hold a reference to (`setAccessible` + `Field.get`)
- `java_tostring(obj)` - generic "describe anything" helper, works on a
  `JavaInstance` userdata *or* a raw ART object pointer straight out of a
  hook's `args[N]` (no cast API needed - see the file's header comment for
  how that trick works)
- a `java.lang.reflect.Method.invoke()` recon hook that logs every
  reflective call in the process (method signature, target class, arg
  count) - useful against apps that hide logic behind reflection

```
renef> l scripts/recipes/java_reflection_dump.lua
renef> exec dump_class_schema("android.os.Build")
renef> watch
renef> exec reflection_stats()
```
