# NOTE(vanya): This file...
# Implements a service that:
# - Detect the Minecraft process
# - Pauses it
# - Detect the version and the loader type
# - Runs the setup


import os
import sys
import time
import threading

from collections.abc import Callable


def watch_new_processes_wmi() -> None:
    pass


def watch_new_processes_linux(new_process_cb: Callable) -> None:
    def get_pids() -> set[int]:
        pids = set()

        for entry in os.scandir("/proc"):
            if entry.name.isdigit():
                pids.add(int(entry.name))

        return pids


    known_pids: set[int] = get_pids()

    while True:
        current_pids: set[int] = get_pids()

        for pid in (current_pids - known_pids):
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\0", b" ").decode(
                    errors="replace"
                )

            new_process_cb(pid, cmdline)

        known_pids = current_pids
        time.sleep(0.05)


def new_process_cb(pid: int, cmdline: str) -> None:
    print(f"Process spawned: PID={pid}")
    print(f"Command: {cmdline}")

    if "java" in cmdline.lower():
        print("Java detected!!!")


threading.Thread(
        # LIMITATION(vanya): This inline if statement only implement linux and windows 
        target=watch_new_processes_linux if sys.platform.startswith("linux") else watch_new_processes_wmi,
        name="new_process_watcher",
        args=(new_process_cb,)
).start()


time.sleep(1000)