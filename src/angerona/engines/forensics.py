"""
forensics.py — Autonomous Incident Forensics Artifact Extraction Module
"""
import os
import re
import ctypes
from ctypes import wintypes
import subprocess
import threading
from queue import Queue

from angerona.core.win import check_output_hidden, NO_WINDOW

# Windows API constants
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000

def run_autonomous_capture(pid: int, alert_queue: Queue, log_module):
    """Dispatches a non-blocking thread to extract live forensics data from a suspect process."""
    forensics_thread = threading.Thread(
        target=_extract_artifacts_worker,
        args=(pid, alert_queue, log_module),
        daemon=True
    )
    forensics_thread.start()

def create_evidence_locker(pid: int, log_module) -> str:
    """Creates a dedicated filesystem directory case folder for extracting evidence files."""
    base_dir = f"C:\\UDE_Forensics\\Case_{pid}"
    try:
        os.makedirs(base_dir, exist_ok=True)
        return base_dir
    except Exception as e:
        log_module.error("FORENSICS", f"Could not establish local evidence directory path for PID {pid}", data={"error": str(e)})
        return os.path.expandvars(r"%USERPROFILE%\AppData\Local\Temp")

def _extract_artifacts_worker(pid: int, alert_queue: Queue, log_module):
    """Forensic pipeline worker execution routing through data pillars independently."""
    log_module.info("FORENSICS", f"Beginning hot live volatile telemetry capture on suspect PID {pid}")
    evidence_path = create_evidence_locker(pid, log_module)
    
    # Pillar 1: Dump cleartext ASCII and Unicode strings out of live running memory
    _dump_volatile_ram_strings(pid, evidence_path, log_module)
    
    # Pillar 2: Map established and listening network sockets
    _audit_active_network_sockets(pid, evidence_path, log_module)
    
    # Pillar 3: Extract shell histories if processing an active shell chain
    _harvest_shell_history(pid, evidence_path, log_module)

    # Push notice to core application loops
    alert_queue.put({
        "type": "FORENSIC_COLLECTION_COMPLETED",
        "pid": pid,
        "path": evidence_path,
        "details": f"All volatile artifacts saved under {evidence_path}"
    })

def _dump_volatile_ram_strings(pid: int, storage_dir: str, log_module):
    """Iterates virtual memory mapping blocks via VirtualQueryEx and parses cleartext strings."""
    k32 = ctypes.windll.kernel32
    # Pointer-correct ctypes signatures so 64-bit handles, addresses and the
    # (potentially >2GB) RegionSize passed to ReadProcessMemory aren't truncated
    # to 32-bit. Idempotent.
    k32.OpenProcess.restype          = wintypes.HANDLE
    k32.OpenProcess.argtypes         = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.VirtualQueryEx.restype       = ctypes.c_size_t
    k32.VirtualQueryEx.argtypes      = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    k32.ReadProcessMemory.restype    = wintypes.BOOL
    k32.ReadProcessMemory.argtypes   = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.CloseHandle.argtypes         = [wintypes.HANDLE]
    handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)

    if not handle:
        log_module.warning("FORENSICS", f"Access Denied to raw memory spaces of PID {pid} (Protected Token)")
        return

    out_file_path = os.path.join(storage_dir, "mem_strings.txt")
    string_regex = re.compile(br'[ -~]{4,}')  # Matches ASCII characters length 4 or higher
    
    addr = 0
    # Match Windows memory block structs size requirements dynamically 
    class MBI(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.c_ulong), ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_ulong), ("Protect", ctypes.c_ulong), ("Type", ctypes.c_ulong)
        ]
        
    mbi = MBI()
    try:
        with open(out_file_path, "w", encoding="utf-8", errors="ignore") as out_f:
            while k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) > 0:
                # Process only committed memory blocks
                if mbi.State == MEM_COMMIT:
                    buffer = ctypes.create_string_buffer(mbi.RegionSize)
                    bytes_read = ctypes.c_size_t(0)
                    if k32.ReadProcessMemory(handle, mbi.BaseAddress, buffer, mbi.RegionSize, ctypes.byref(bytes_read)):
                        matches = string_regex.findall(buffer.raw[:bytes_read.value])
                        for match in matches:
                            out_f.write(match.decode('ascii', errors='ignore') + "\n")
                addr += mbi.RegionSize
    except Exception as e:
        log_module.error("FORENSICS", f"Error encountered copying memory structures from PID {pid}", data={"error": str(e)})
    finally:
        k32.CloseHandle(handle)

def _audit_active_network_sockets(pid: int, storage_dir: str, log_module):
    """Executes low-overhead system netstat scans to capture networking states."""
    out_file_path = os.path.join(storage_dir, "network_sockets.txt")
    try:
        output = check_output_hidden(
            ["cmd", "/c", f"netstat -ano | findstr {pid}"],
            shell=False, text=True, creationflags=NO_WINDOW,
        )
        with open(out_file_path, "w", encoding="utf-8") as f:
            f.write(output)
    except subprocess.CalledProcessError:
        with open(out_file_path, "w", encoding="utf-8") as f:
            f.write("No active network network connection endpoints tracked at extraction time.\n")

def _harvest_shell_history(pid: int, storage_dir: str, log_module):
    """Locks in local command trails by extracting standard user shell history logs."""
    out_file_path = os.path.join(storage_dir, "shell_history_manifest.txt")
    target_history = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
    
    if os.path.exists(target_history):
        try:
            with open(target_history, "r", encoding="utf-8", errors="ignore") as src, \
                 open(out_file_path, "w", encoding="utf-8") as dest:
                dest.write(src.read())
        except Exception as e:
            log_module.error("FORENSICS", "Could not capture active shell context trails",
                             data={"error": str(e)})