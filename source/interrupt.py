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


POLL_RATE: float = 0.1


def watch_new_processes_windows(new_process_cb: Callable) -> None:
    import ctypes
    import ctypes.wintypes


    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_VM_READ = 0x0010
    STATUS_SUCCESS = 0x00000000
    ProcessBasicInformation = 0


    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.wintypes.DWORD),
            ("cntUsage", ctypes.wintypes.DWORD),
            ("th32ProcessID", ctypes.wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", ctypes.wintypes.DWORD),
            ("cntThreads", ctypes.wintypes.DWORD),
            ("th32ParentProcessID", ctypes.wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.wintypes.DWORD),
            ("szExeFile", ctypes.wintypes.WCHAR * 260),
        ]


    class UNICODE_STRING(ctypes.Structure):
        _fields_ = [
            ("Length", ctypes.wintypes.USHORT),
            ("MaximumLength", ctypes.wintypes.USHORT),
            ("Buffer", ctypes.c_void_p),
        ]


    class PROCESS_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("Reserved1", ctypes.c_void_p),
            ("PebBaseAddress", ctypes.c_void_p),
            ("Reserved2", ctypes.c_void_p * 2),
            ("UniqueProcessId", ctypes.c_void_p),
            ("Reserved3", ctypes.c_void_p),
        ]


    kernel32.CreateToolhelp32Snapshot.argtypes = [
        ctypes.wintypes.DWORD, ctypes.wintypes.DWORD
    ]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE

    kernel32.Process32FirstW.argtypes = [
        ctypes.wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)
    ]
    kernel32.Process32FirstW.restype = ctypes.wintypes.BOOL

    kernel32.Process32NextW.argtypes = [
        ctypes.wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)
    ]
    kernel32.Process32NextW.restype = ctypes.wintypes.BOOL

    kernel32.OpenProcess.argtypes = [
        ctypes.wintypes.DWORD,
        ctypes.wintypes.BOOL,
        ctypes.wintypes.DWORD,
    ]
    kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE

    kernel32.ReadProcessMemory.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = ctypes.wintypes.BOOL

    kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    kernel32.CloseHandle.restype = ctypes.wintypes.BOOL

    ntdll.NtQueryInformationProcess.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.c_uint,
        ctypes.c_void_p,
        ctypes.wintypes.ULONG,
        ctypes.POINTER(ctypes.wintypes.ULONG),
    ]
    ntdll.NtQueryInformationProcess.restype = ctypes.c_long


    def get_processes() -> dict[int, tuple[str, int]]:
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

        if snapshot == INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())

        processes = {}

        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(entry)

            success = kernel32.Process32FirstW(
                snapshot, ctypes.byref(entry)
            )

            while success:
                processes[entry.th32ProcessID] = (
                    entry.szExeFile,
                    entry.th32ParentProcessID,
                )

                success = kernel32.Process32NextW(
                    snapshot, ctypes.byref(entry)
                )

        finally:
            kernel32.CloseHandle(snapshot)

        return processes


    def get_process_command_line(pid: int) -> str:
        process = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            False,
            pid,
        )

        if not process or process == INVALID_HANDLE_VALUE:
            return ""

        try:
            pbi = PROCESS_BASIC_INFORMATION()
            bytes_written = ctypes.wintypes.ULONG()
            status = ntdll.NtQueryInformationProcess(
                process,
                ProcessBasicInformation,
                ctypes.byref(pbi),
                ctypes.sizeof(pbi),
                ctypes.byref(bytes_written),
            )

            if status != STATUS_SUCCESS:
                return ""

            pointer_size = ctypes.sizeof(ctypes.c_void_p)
            peb_process_parameters_offset = 0x20 if pointer_size == 8 else 0x10
            process_parameters_address = ctypes.c_void_p()
            bytes_read = ctypes.c_size_t()

            if not kernel32.ReadProcessMemory(
                process,
                ctypes.c_void_p(int(pbi.PebBaseAddress) + peb_process_parameters_offset),
                ctypes.byref(process_parameters_address),
                pointer_size,
                ctypes.byref(bytes_read),
            ):
                return ""

            command_line_offset = 0x70 if pointer_size == 8 else 0x48
            command_line = UNICODE_STRING()

            if not kernel32.ReadProcessMemory(
                process,
                ctypes.c_void_p(int(process_parameters_address.value) + command_line_offset),
                ctypes.byref(command_line),
                ctypes.sizeof(command_line),
                ctypes.byref(bytes_read),
            ):
                return ""

            if command_line.Length == 0:
                return ""

            buffer = ctypes.create_unicode_buffer(command_line.Length // 2 + 1)
            if not kernel32.ReadProcessMemory(
                process,
                command_line.Buffer,
                buffer,
                command_line.Length,
                ctypes.byref(bytes_read),
            ):
                return ""

            return buffer.value
        finally:
            kernel32.CloseHandle(process)


    # NOTE(vanya): Poll the active processes
    known_processes = get_processes()

    while True:
        current_processes = get_processes()

        for pid in current_processes.keys() - known_processes.keys():
            name, parent_pid = current_processes[pid]
            cmdline = get_process_command_line(pid) or name

            new_process_cb(pid, cmdline)

        known_processes = current_processes
        time.sleep(POLL_RATE)


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
        time.sleep(POLL_RATE)


def new_process_cb(pid: int, cmdline: str) -> None:
    print(f"Process spawned: PID={pid}")
    print(f"Command: {cmdline}")

    if "java" in cmdline.lower():
        print("Java detected!!!")


threading.Thread(
        # LIMITATION(vanya): This inline if statement only implement linux and windows 
        target=watch_new_processes_linux if sys.platform.startswith("linux") else watch_new_processes_windows,
        name="new_process_watcher",
        args=(new_process_cb,)
).start()


time.sleep(1000)
