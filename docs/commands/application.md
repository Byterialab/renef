---
title: Application Management
layout: default
parent: Command Reference
nav_order: 2
---

# Application Management

## `la [~filter]`

List installed applications on the device. Supports filtering with the `~` operator.

**No target required.** Like `frida-ps -Uai`, `la` queries the device's package
manager directly through `renef_server` — you do **not** need to spawn or attach
to an app first. It works as soon as the server is running and the client is
connected.

```bash
# List all apps
la

# Filter by package name
la~google

# Filter for specific app
la~com.example
```

**Output:**
```
com.google.android.gms
com.google.android.gsf
com.google.android.telephony.satellite
com.android.vending

Total: 4 packages
```
