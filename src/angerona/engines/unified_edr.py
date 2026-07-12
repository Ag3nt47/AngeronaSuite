"""
unified_edr.py — Optional Secondary Status Viewer (read-only)

NOT the primary interface. agent.py's own embedded console (the rich
boxed-panel TUI with the 'UDE-Containment#' prompt) is the actual dashboard
people interact with — this file just polls edr_status.json and reprints a
plain-text status grid. There's no input prompt here at all; it can't run
commands, only display.

Run this in a separate terminal alongside an already-running agent.py if you
want a second, lower-overhead window showing status without the full
interactive console. Requires agent.py to be running first (it's what
writes edr_status.json).

Renders a real-time status matrix grid with an AI Cognition & Diagnostics logger.
Fixed: Fixed strict width calculations to prevent layout overflow.
"""

import os
import sys
import time
import json
import socket

# Configuration matching the agent pipeline
STATUS_FILE = "edr_status.json"
END_SENTINEL = b"<<END>>" 

# ANSI Terminal Formatting Colors
CLR_TITLE = "\033[1;35m"  # Bold Purple
CLR_PANEL = "\033[36m"    # Cyan
CLR_TEXT  = "\033[97m"    # White
CLR_RESET = "\033[0m"     # Reset

# Verdict Severity Colors
CLR_SAFE = "\033[92m"      # Bright Green
CLR_SUSP = "\033[93m"      # Bright Yellow
CLR_CRIT = "\033[91m"      # Bright Red

def get_verdict_color(verdict: str) -> str:
    v = verdict.upper()
    if "CRITICAL" in v:
        return CLR_CRIT
    if "SUSPICIOUS" in v:
        return CLR_SUSP
    return CLR_SAFE

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def fit_line_to_width(text: str, max_width: int) -> str:
    """Truncates text safely and appends an ellipsis if it exceeds panel width bounds."""
    text = text.strip().replace("\n", " ")
    if len(text) > max_width:
        return text[:max_width - 3] + "..."
    return text.ljust(max_width)

def query_agent_interactive(command: str) -> str:
    """Fallback terminal tool query directly via IPC pipe socket."""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(('127.0.0.1', 65432)) 
        client.sendall(command.encode('utf-8'))
        
        full_buffer = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            full_buffer += chunk
            if END_SENTINEL in full_buffer: 
                break
                
        response = full_buffer.replace(END_SENTINEL, b"").decode('utf-8')
        client.close()
        return response
    except Exception as e:
        return f"IPC Communication Failure: {e}"

def read_status_payload() -> dict:
    """Reads the current engine runtime data synchronized from agent.py."""
    if not os.path.exists(STATUS_FILE):
        return {}
    try:
        with open(STATUS_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, PermissionError):
        return {}

def draw_dashboard(data: dict):
    """Renders the scannable layout grid architecture."""
    clear_screen()
    
    # Extract synchronized metrics with defaults
    ts         = data.get("time", time.strftime("%H:%M:%S"))
    host_v     = data.get("host_verdict", "INITIALIZING")
    host_a     = data.get("host_analysis", "Synchronizing agent structures...")
    wire_v     = data.get("wire_verdict", "INITIALIZING")
    wire_a     = data.get("wire_analysis", "Initializing packet captures...")
    engine     = data.get("active_engine", "NONE")
    trace_logs = data.get("active_code_trace", ["Awaiting backend telemetry hooks..."])
    
    # Retrieve our new observability and thinking section safely
    ai_thinking = data.get("ai_thinking_logs", ["No active cognitive transactions tracked."])
    
    # ── HEADER BANNER ────────────────────────────────────────────────────────
    print(f"{CLR_TITLE}================================================================================{CLR_RESET}")
    print(f"{CLR_TITLE}   🛡️  UNIFIED SECURITY AI SUITE — REAL-TIME DEFENSE RADAR DISPLAY   [{ts}]  {CLR_RESET}")
    print(f"{CLR_TITLE}================================================================================{CLR_RESET}\n")
    
    # Total outer width of rows is 80 characters. 
    # Left border "│ " takes 2, Right border " │" takes 2. Total inner usable text is 76.

    # ── PANEL 1: HOST MONITOR GRID ───────────────────────────────────────────
    h_color = get_verdict_color(host_v)
    print(f"{CLR_PANEL}┌── [ EDR COMPREHENSIVE HOST SECURITY SCANNER ] ────────────────────────────────┐{CLR_RESET}")
    print(f"{CLR_PANEL}│{CLR_RESET} VERDICT : {h_color}{host_v:<66}{CLR_PANEL} │{CLR_RESET}")
    
    # "DETAILS : " is 10 chars -> remaining space is 76 - 10 = 66
    host_summary = fit_line_to_width(host_a, 66)
    print(f"{CLR_PANEL}│{CLR_RESET} DETAILS : {CLR_TEXT}{host_summary}{CLR_PANEL} │{CLR_RESET}")
    print(f"{CLR_PANEL}└───────────────────────────────────────────────────────────────────────────────┘{CLR_RESET}")
    
    # ── PANEL 2: NETWORK SNIFFER GRID ─────────────────────────────────────────
    w_color = get_verdict_color(wire_v)
    print(f"{CLR_PANEL}┌── [ WIRE NET_MONITOR & NDR DEEP PACKET INSPECTION ] ──────────────────────────┐{CLR_RESET}")
    print(f"{CLR_PANEL}│{CLR_RESET} MATRIX  : {w_color}{wire_v:<66}{CLR_PANEL} │{CLR_RESET}")
    
    # "CAPTURE : " is 10 chars -> remaining space is 76 - 10 = 66
    wire_summary = fit_line_to_width(wire_a, 66)
    print(f"{CLR_PANEL}│{CLR_RESET} CAPTURE : {CLR_TEXT}{wire_summary}{CLR_PANEL} │{CLR_RESET}")
    print(f"{CLR_PANEL}└───────────────────────────────────────────────────────────────────────────────┘{CLR_RESET}")
    
    # ── PANEL 3: AI THINKING LOGS AND RUNTIME ISSUES ────────────────────────
    print(f"{CLR_PANEL}┌── [ AI COGNITION LAYER & OBSERVABILITY LOG (THINKING TRACE) ] ────────────────┐{CLR_RESET}")
    
    # "CURRENT STRATEGY ENGINE: " is 25 chars -> remaining space is 76 - 25 = 51
    print(f"{CLR_PANEL}│{CLR_RESET} CURRENT STRATEGY ENGINE: {CLR_TITLE}{engine:<51}{CLR_PANEL} │{CLR_RESET}")
    print(f"{CLR_PANEL}├───────────────────────────────────────────────────────────────────────────────┤{CLR_RESET}")
    
    # Full line fills full width of 76 chars
    for line in ai_thinking[:4]:
        padded_line = fit_line_to_width(line, 76)
        print(f"{CLR_PANEL}│{CLR_RESET} {CLR_TEXT}{padded_line}{CLR_PANEL} │{CLR_RESET}")
    print(f"{CLR_PANEL}└───────────────────────────────────────────────────────────────────────────────┘{CLR_RESET}")

    # ── PANEL 4: SUBSYSTEM LOG TRACE & EVENTS ────────────────────────────────
    print(f"{CLR_PANEL}┌── [ SYSTEM CRITICAL OVERWATCH LOGS & SUBSYSTEM TRACE ] ───────────────────────┐{CLR_RESET}")
    for trace in trace_logs[-5:]: 
        padded_trace = fit_line_to_width(trace, 76)
        print(f"{CLR_PANEL}│{CLR_RESET} {CLR_TEXT}{padded_trace}{CLR_PANEL} │{CLR_RESET}")
    print(f"{CLR_PANEL}└───────────────────────────────────────────────────────────────────────────────┘{CLR_RESET}")
    
    print(f"\n💡 {CLR_PANEL}Press [ Ctrl + C ] anytime to power down the dashboard visual field console.{CLR_RESET}")

def main():
    """Initializes the operational terminal visual pipeline."""
    if os.name == 'nt':
        os.system('')
        
    try:
        while True:
            status_payload = read_status_payload()
            if status_payload:
                draw_dashboard(status_payload)
            else:
                clear_screen()
                print("[*] Connecting to Unified AI Agent Pipeline Adapter...")
                print("    Ensure start_stack.py has spun up the active listeners...")
                
            time.sleep(1.5)
    except KeyboardInterrupt:
        clear_screen()
        print("[-] Detaching grid dashboard panel layer interface. Execution ceased.")
        sys.exit(0)

if __name__ == "__main__":
    main()