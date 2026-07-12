import os
import sys
import time
import json
import socket
import hashlib
import threading
import ctypes
from ctypes import wintypes
from queue import Queue
import psutil
import requests
from dotenv import load_dotenv

load_dotenv()

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
MODEL_NAME = os.getenv("MODEL_NAME", "llama3:latest")
STATUS_FILE = "edr_status.json"

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_EXECUTE_READWRITE = 0x40

WATCH_DIRECTORIES = [
    os.path.expandvars(r"%USERPROFILE%\AppData\Local\Temp"),
    r"D:\local-security-ai"
]

engine_state = {
    "host_verdict": "SAFE",
    "host_analysis": "System monitored. Process lineage, FIM loops, RAM auditing, and MITRE matrix active.",
    "active_code_trace": [],
    "monitored_pids": 0,
    "tracked_files": 0,
    "memory_scans_completed": 0
}
state_lock = threading.Lock()
alert_queue = Queue()

fim_baseline = {}

def calculate_sha256(file_path):
    if not os.path.exists(file_path) or os.path.isdir(file_path):
        return None
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def initialize_fim_baseline():
    global fim_baseline
    tracked_count = 0
    for directory in WATCH_DIRECTORIES:
        if not os.path.exists(directory):
            continue
        for root, _, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                file_hash = calculate_sha256(full_path)
                if file_hash:
                    fim_baseline[full_path] = file_hash
                    tracked_count += 1
    engine_state["tracked_files"] = tracked_count

def fim_watcher_worker():
    while True:
        current_hashes = {}
        for directory in WATCH_DIRECTORIES:
            if not os.path.exists(directory):
                continue
            for root, _, files in os.walk(directory):
                for file in files:
                    full_path = os.path.join(root, file)
                    file_hash = calculate_sha256(full_path)
                    if file_hash:
                        current_hashes[full_path] = file_hash

                        if full_path not in fim_baseline:
                            alert_queue.put({
                                "type": "FIM_NEW_FILE_DROP",
                                "target": full_path,
                                "details": f"Unrecognized asset dropped into monitored space: Hash {file_hash[:16]}"
                            })
                            fim_baseline[full_path] = file_hash
                        elif fim_baseline[full_path] != file_hash:
                            alert_queue.put({
                                "type": "FIM_MODIFICATION",
                                "target": full_path,
                                "details": f"File modified! Previous: {fim_baseline[full_path][:12]} -> New: {file_hash[:12]}"
                            })
                            fim_baseline[full_path] = file_hash

        deleted_files = [f for f in fim_baseline if f not in current_hashes]
        for f in deleted_files:
            alert_queue.put({
                "type": "FIM_DELETION",
                "target": f,
                "details": "Monitored protective asset removed from system."
            })
            del fim_baseline[f]

        engine_state["tracked_files"] = len(fim_baseline)
        time.sleep(5)

def capture_process_lineage():
    telemetry_batch = []
    try:
        all_processes = list(psutil.process_iter(['pid', 'name', 'ppid']))
        engine_state["monitored_pids"] = len(all_processes)

        for p in all_processes:
            try:
                pid = p.info['pid']
                name = p.info['name']
                ppid = p.info['ppid']

                try:
                    parent_proc = psutil.Process(ppid)
                    parent_name = parent_proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    parent_name = "UNKNOWN/ORPHANED"

                try:
                    cmdline = " ".join(psutil.Process(pid).cmdline())
                except:
                    cmdline = "N/A"

                telemetry_batch.append({
                    "pid": pid,
                    "process_name": name,
                    "parent_pid": ppid,
                    "parent_name": parent_name,
                    "command_line": cmdline
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return telemetry_batch

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

def inspect_volatile_process_memory(pid):
    kernel32 = ctypes.windll.kernel32
    process_handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not process_handle:
        return None

    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    
    try:
        while kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)) > 0:
            if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_EXECUTE_READWRITE:
                return f"Unmapped executable page allocation (PAGE_EXECUTE_READWRITE) discovered at base: {hex(mbi.BaseAddress or 0)}"
            address += mbi.RegionSize
    except Exception:
        pass
    finally:
        kernel32.CloseHandle(process_handle)
    return None

def volatile_memory_scanner_worker():
    global engine_state
    while True:
        try:
            scan_count = 0
            for proc in psutil.process_iter(['pid', 'name']):
                pid = proc.info['pid']
                p_name = proc.info['name']
                
                if pid <= 4 or p_name.lower() in ["svchost.exe", "lsass.exe", "msmpeng.exe"]:
                    continue
                    
                memory_anomaly = inspect_volatile_process_memory(pid)
                scan_count += 1
                
                if memory_anomaly:
                    alert_queue.put({
                        "type": "FILELESS_MEMORY_INJECTION",
                        "target": f"{p_name} (PID: {pid})",
                        "details": memory_anomaly
                    })
            
            with state_lock:
                engine_state["memory_scans_completed"] = scan_count
        except Exception:
            pass
        time.sleep(8)

def analyze_anomaly_with_mitre(alert_event):
    payload_dump = json.dumps(alert_event, indent=4)
    prompt = f"""
    You are an advanced defensive SecOps telemetry analyzer. 
    Correlate the following endpoint anomaly directly to the industry-standard MITRE ATT&CK Framework.
    
    Anomalous Event Context:
    {payload_dump}
    
    Provide your evaluation in exactly this strict, scannable structure:
    MITRE ATT&CK MAPPING:
    - Tactic: [Tactics matching the event]
    - Technique: [Technique IDs matching the event]
    
    VERDICT: [SAFE | SUSPICIOUS | CRITICAL]
    REASON: [1-sentence explanation detailing the parent/child lineage abnormality, RAM security violation, or file integrity threat]
    """
    try:
        response = requests.post(OLLAMA_URL, json={"model": MODEL_NAME, "prompt": prompt, "stream": False, "keep_alive": "30m"}, timeout=45)
        if response.status_code == 200:
            return response.json().get("response", "").strip()
    except Exception as e:
        return f"MITRE Engine Exception: Could not query model. Error: {str(e)}"
    return "Local processing timeout reached during MITRE technique mapping."

def alert_dispatcher_worker():
    while True:
        event = alert_queue.get()
        try:
            raw_analysis = analyze_anomaly_with_mitre(event)
            
            verdict_line = "SAFE"
            for line in raw_analysis.split("\n"):
                if line.upper().startswith("VERDICT:"):
                    verdict_line = line.upper()
                    break
            
            with state_lock:
                if "CRITICAL" in verdict_line:
                    engine_state["host_verdict"] = "CRITICAL"
                elif "SUSPICIOUS" in verdict_line:
                    engine_state["host_verdict"] = "SUSPICIOUS"
                else:
                    engine_state["host_verdict"] = "SAFE"
                
                engine_state["host_analysis"] = raw_analysis
                engine_state["active_code_trace"].append(f"# MITRE ALERT TRIGGERED: {event['type']}")
                if len(engine_state["active_code_trace"]) > 10:
                    engine_state["active_code_trace"].pop(0)
            export_engine_status()
        except Exception: 
            pass
        finally:
            alert_queue.task_done()

def export_engine_status():
    """FIX REALIZED: Writes to a staging .tmp file first, then swaps atomically to prevent corruption."""
    with state_lock:
        status_update = {
            "time": time.strftime("%H:%M:%S"),
            "host_verdict": engine_state["host_verdict"],
            "host_analysis": engine_state["host_analysis"],
            "wire_frames": engine_state["monitored_pids"],
            "wire_verdict": f"FIM ACTIVE ({engine_state['tracked_files']} files)",
            "wire_analysis": f"RAM Scan Active ({engine_state['memory_scans_completed']} PIDs audited)",
            "last_scan_time": time.strftime('%H:%M:%S'),
            "last_sniff_time": "LIVE MONITORING",
            "active_code_trace": list(engine_state["active_code_trace"])
        }
    try:
        temp_file = STATUS_FILE + ".tmp"
        with open(temp_file, "w") as f:
            json.dump(status_update, f, indent=4)
        # Safe atomic swap
        os.replace(temp_file, STATUS_FILE)
    except:
        pass

def live_ancestry_loop():
    while True:
        lineage_data = capture_process_lineage()
        for proc in lineage_data:
            p_name = proc["process_name"].lower()
            p_parent = proc["parent_name"].lower()
            
            if p_parent in ["explorer.exe", "svchost.exe"] and p_name in ["cmd.exe", "powershell.exe", "python.exe"]:
                if "local-security-ai" not in proc["command_line"]:
                    alert_queue.put({
                        "type": "SUSPICIOUS_PARENT_CHILD_LINEAGE",
                        "target": f"{proc['process_name']} (PID: {proc['pid']})",
                        "details": f"Parent '{proc['parent_name']}' spawned shell runtime with arguments: {proc['command_line']}"
                    })
        export_engine_status()
        time.sleep(4)

if __name__ == "__main__":
    print("[*] Initializing Unified Security AI Defense Engine...")
    initialize_fim_baseline()
    print(f"[+] Baseline secure. Monitoring {engine_state['tracked_files']} system files.")
    
    threading.Thread(target=fim_watcher_worker, daemon=True).start()
    threading.Thread(target=volatile_memory_scanner_worker, daemon=True).start()
    threading.Thread(target=alert_dispatcher_worker, daemon=True).start()
    
    print("[+] Core operational loops running live. Analyzing process ancestry and memory pools...")
    live_ancestry_loop()