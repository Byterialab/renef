---
title: Pentest Recipes
layout: default
parent: Real-World Examples
nav_order: 8
---

# Pentest Recipes

Ready-to-run scripts for recurring tasks live in `scripts/recipes/` of the Renef repository. They are built only on the public Lua API (`hook()`, `Java.*`, `Interceptor.*`, `Memory.*`), so they also serve as larger examples of how to use it.

{: .warning }
> Every recipe is a template, not a universal bypass. Apps implement pinning and detection differently; each file documents its assumptions at the top, and you should expect to adjust class names, signatures and offsets for a new target. Use them only on apps and devices you are authorized to test.

```
renef> l scripts/recipes/ssl_pinning_bypass.lua
renef> watch
renef> exec ssl_bypass_stats()
```

| Recipe | What it does |
|--------|--------------|
| `ssl_pinning_bypass.lua` | Makes TLS certificate validation succeed. It hooks the classes that *implement* `X509TrustManager` and `HostnameVerifier` (the interfaces themselves have no code): Android's own, app classes found by name, and every one the app registers with `SSLContext.init()` at run time. Also OkHttp `CertificatePinner.check` and BoringSSL's custom verify callback in native code. |
| `root_frida_detection_bypass.lua` | Hides common root and instrumentation indicators: su paths (native `access`/`stat`/`open`/`fopen` and `File.exists()`), `Runtime.exec("su")`, `Build.TAGS`, `strstr` searches for `frida`, connections to frida-server's default ports. |
| `root_emulator_bypass.lua` | The same ground split into functions you switch on one by one (`RootDetection.hideSuBinaries()`, `RootDetection.hidePackages()`, ...), plus emulator indicators. |
| `taint_filter.lua` | Hooks libc string and file functions and neutralises calls whose arguments match a keyword list, returning each function's own "not found" value (`NULL` for `strstr`, non-zero for `strcmp`, `-1` for `open`/`access`/`stat`...). |
| `engine_capture.lua` | Catches protection engines that only exist decrypted in memory: watches `dlopen`, diffs `Process.enumerateRanges()` for new anonymous executable regions and dumps them with `File.write()`. |
| `java_reflection_dump.lua` | Recon helpers for any class: `dump_class_schema(name)`, `dump_instance_fields(obj)`, `java_tostring(obj)`. |

The bypass recipes print what they hooked when they load, count what they intercepted, and expose a `*_stats()` function you can call with `exec`.

Not covered by any recipe: server-side attestation (SafetyNet / Play Integrity), which no client-side hook can change.
