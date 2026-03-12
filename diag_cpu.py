"""IDA-MCP CPU Diagnostic Script.

Run inside the IDA Python console:
    exec(open(r"D:\\workspace\\project\\pc\\IDA-MCP\\diag_cpu.py").read())

It measures per-thread CPU consumption over a short interval so we can
identify whether idle CPU comes from MCP threads or IDA itself.
"""
import ctypes
import ctypes.wintypes
import os
import threading
import time


kernel32 = ctypes.windll.kernel32


class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", ctypes.wintypes.DWORD),
        ("dwHighDateTime", ctypes.wintypes.DWORD),
    ]

    def to_100ns(self):
        return self.dwLowDateTime + (self.dwHighDateTime << 32)


THREAD_QUERY_INFORMATION = 0x0040
TH32CS_SNAPTHREAD = 0x00000004

OpenThread = kernel32.OpenThread
OpenThread.restype = ctypes.wintypes.HANDLE
OpenThread.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]

GetThreadTimes = kernel32.GetThreadTimes
CloseHandle = kernel32.CloseHandle
CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
Thread32First = kernel32.Thread32First
Thread32Next = kernel32.Thread32Next


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.wintypes.DWORD),
        ("cntUsage", ctypes.wintypes.DWORD),
        ("th32ThreadID", ctypes.wintypes.DWORD),
        ("th32OwnerProcessID", ctypes.wintypes.DWORD),
        ("tpBasePri", ctypes.wintypes.LONG),
        ("tpDeltaPri", ctypes.wintypes.LONG),
        ("dwFlags", ctypes.wintypes.DWORD),
    ]


def get_thread_ids(pid):
    tids = []
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == ctypes.wintypes.HANDLE(-1).value:
        return tids

    te = THREADENTRY32()
    te.dwSize = ctypes.sizeof(THREADENTRY32)
    if Thread32First(snap, ctypes.byref(te)):
        while True:
            if te.th32OwnerProcessID == pid:
                tids.append(te.th32ThreadID)
            if not Thread32Next(snap, ctypes.byref(te)):
                break
    CloseHandle(snap)
    return tids


def get_thread_cpu_time(tid):
    h = OpenThread(THREAD_QUERY_INFORMATION, False, tid)
    if not h:
        return None

    creation = FILETIME()
    exit_t = FILETIME()
    kernel_t = FILETIME()
    user_t = FILETIME()
    ok = GetThreadTimes(
        h,
        ctypes.byref(creation),
        ctypes.byref(exit_t),
        ctypes.byref(kernel_t),
        ctypes.byref(user_t),
    )
    CloseHandle(h)
    if not ok:
        return None
    return kernel_t.to_100ns() + user_t.to_100ns()


def get_python_thread_names():
    mapping = {}
    for thread in threading.enumerate():
        native_id = getattr(thread, "native_id", None)
        if native_id:
            mapping[native_id] = thread.name
    return mapping


def measure_cpu(duration_sec=5):
    pid = os.getpid()
    print(f"\n{'=' * 60}")
    print(f"[IDA-MCP CPU Diag] PID={pid}, measuring for {duration_sec}s ...")
    print(f"{'=' * 60}")

    snap1 = {}
    name_map = get_python_thread_names()
    for tid in get_thread_ids(pid):
        cpu = get_thread_cpu_time(tid)
        if cpu is not None:
            snap1[tid] = cpu

    time.sleep(duration_sec)

    snap2 = {}
    for tid in get_thread_ids(pid):
        cpu = get_thread_cpu_time(tid)
        if cpu is not None:
            snap2[tid] = cpu

    results = []
    for tid in sorted(set(list(snap1.keys()) + list(snap2.keys()))):
        t1 = snap1.get(tid, 0)
        t2 = snap2.get(tid, 0)
        delta_100ns = t2 - t1
        delta_ms = delta_100ns / 10000.0
        cpu_pct = (delta_100ns / (duration_sec * 10_000_000)) * 100.0
        results.append((cpu_pct, delta_ms, tid, name_map.get(tid, "?")))

    results.sort(reverse=True)

    print(f"\n{'Thread Name':<30} {'TID':>8} {'CPU ms':>10} {'CPU %':>8}")
    print("-" * 60)
    total_pct = 0.0
    for cpu_pct, delta_ms, tid, name in results:
        total_pct += cpu_pct
        marker = " <<<" if cpu_pct > 0.5 else ""
        print(f"{name:<30} {tid:>8} {delta_ms:>10.1f} {cpu_pct:>7.2f}%{marker}")

    print("-" * 60)
    print(f"{'TOTAL':<30} {'':>8} {'':>10} {total_pct:>7.2f}%")
    print("\nThreads with > 0.5% CPU are marked with <<<")
    print("Look for IDA-MCP-Server, IDA-MCP-HTTP-Proxy, IDA-MCP-Registry")
    print(f"{'=' * 60}\n")


measure_cpu(5)
