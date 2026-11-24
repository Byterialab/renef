#!/usr/bin/env python3
"""
Basic usage of the renef Python client.

Prerequisites:
    1. make install                      (server + agent on the device)
    2. adb shell su -c /data/local/tmp/renef_server &
    3. adb forward tcp:1907 localabstract:com.android.internal.os.RuntimeInit

Usage:
    python basic.py com.example.app
"""

import os
import sys

# Allow running from a checkout without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import renef


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: basic.py <package>")

    client = renef.connect()
    with client.spawn(sys.argv[1]) as s:
        print("[+] spawned, pid %d" % s.pid)

        libc = s.Module.find("libc.so")
        print("[+] libc.so at 0x%x, starts with %r" % (libc, s.Memory.read(libc, 4)))
        print("[+] %d exports in libc.so" % len(s.Module.exports("libc.so")))

        # Lua in the target, value back as Python data.
        info = s.rpc("{pid = OS.getpid(), tid = Thread.id()}")
        print("[+] rpc: %r" % (info,))

        # A Python callback on every open(). The path string only exists
        # while the call is running, so it is captured in the target
        # (`capture`) and arrives with the event.
        def on_open(event):
            print("    open(%r) on thread %d" % (event.data.get("path"), event.thread_id))

        hook = s.hook("libc.so", "open", on_enter=on_open,
                      capture={"path": "Memory.readStr(args[0])"})
        print("[+] watching open() for 3 seconds...")
        s.poll(wait=3)
        hook.remove()

        # Lua-source callback: runs in the target and may change the result.
        s.hook("libc.so", "getppid", on_leave="return 4242")
        getppid = s.native_function(s.Module.find_export("libc.so", "getppid"), "int")
        print("[+] getppid() through the hook: %d" % getppid())

    print("[+] done")


if __name__ == "__main__":
    main()
