---
title: Real-time Monitoring
layout: default
parent: Command Reference
nav_order: 6
---

# Real-time Monitoring

## `watch [address]`

Watch hook output in real-time. Press 'q' to exit watch mode.

Hook output is never part of another command's reply. What hook callbacks (and the syscall tracer) print travels on its own connection from the agent to `renef_server` and waits there until you ask for it: `watch` first shows what has been waiting, then follows new output live. Any other command prints only its own result; if hook output is waiting, the CLI adds one line under it:

```
renef> hooks
Active hooks: 1
  [0] target=0x7b0a45af0c hits=820
(334 lines of hook output waiting - `watch` shows them)
```

The buffer on the server is bounded (about 1 MB). When it is full the oldest lines are dropped and the next `watch` starts with a line saying how many. A hook on a busy function can easily produce more than that between two looks: use the `hits=` counter of `hooks` for "how often", and `watch` for "what".

```bash
# Watch all hooks
watch

# Watch specific address (if supported)
watch 0x7f8a1c2b0
```

**Output:**
```
📡 Watching hook output... (waiting for hooks to trigger)
(Press 'q' to exit watch mode)

[+] malloc called
    size: 0x100
[-] Returning: 0x7f9b4000
[+] free called
    ptr: 0x7f9b4000
```
