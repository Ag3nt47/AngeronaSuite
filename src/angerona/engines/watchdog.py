"""
watchdog.py — Dual-Process Cross-Monitoring Defensive Watchdog Script
"""
import sys
import time
import os
import subprocess

def run_standalone_watchdog(parent_pid: int):
    """Independent infinite checking routine monitoring main agent process handles via native execution wrappers."""
    # Native dynamic tracking mapping configurations
    import psutil
    
    print(f"[+] [WATCHDOG] Active process tracking armed successfully against parent EDR PID {parent_pid}")
    
    while True:
        try:
            # Check if parent process remains alive cleanly
            if not psutil.pid_exists(parent_pid):
                _trigger_emergency_agent_recovery()
                break
        except Exception:
            pass
        time.sleep(1.0)

def _trigger_emergency_agent_recovery():
    """Drops recovery data statements directly into native application systems and rebuilds core infrastructure operations."""
    try:
        import win32evtlog
        import win32evtlogutil
        
        # Log critical failure alerts out to native Windows Application Event Log systems
        appName = "Unified Defense Engine"
        win32evtlogutil.ReportEvent(
            appName, 1001, eventCategory=0,
            eventType=win32evtlog.EVENTLOG_ERROR_TYPE,
            strings=["EDR Agent process line dropped unexpectedly! Instantiating automated watchdog recovery script chains..."],
            data=b""
        )
    except Exception:
        pass

    # Respawn agent process lines cleanly inside separate isolated terminals
    agent_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.py")
    subprocess.Popen([sys.executable, agent_script], creationflags=subprocess.CREATE_NEW_CONSOLE)
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_standalone_watchdog(int(sys.argv[1]))