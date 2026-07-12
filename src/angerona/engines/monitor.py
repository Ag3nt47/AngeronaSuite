import psutil
import json

def get_active_connections():
    try:
        connections = psutil.net_connections(kind='inet')
    except Exception:
        return []
        
    telemetry_data = []

    for conn in connections:
        if conn.status == 'ESTABLISHED' and conn.raddr:
            # conn.pid is None when the OS won't attribute the socket to a process.
            # psutil.Process(None) would silently return THIS process (mislabeling
            # the connection), so handle the unattributed case explicitly instead.
            if conn.pid is None:
                telemetry_data.append({
                    "pid": None,
                    "process_name": "Unknown/Unattributed",
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "status": conn.status
                })
                continue
            try:
                process = psutil.Process(conn.pid)
                # Force the process name string to lowercase for safe checking
                proc_name_lower = process.name().lower()
                
                # Check against an entirely lowercase exclusion baseline
                if proc_name_lower in [
                    'chrome.exe', 'msedge.exe', 'discord.exe', 
                    'python.exe', 'protonvpn.exe', 'protonvpn.client.exe', 'protonvpn.service.exe',
                    'ccleaner_service.exe', 'nvidia overlay.exe', 'nvspcaps64.exe'
                ]:
                    continue
                    
                proc_name = process.name() # Keep original casing for display
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "Unknown/AccessDenied"

            telemetry_data.append({
                "pid": conn.pid,
                "process_name": proc_name,
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                "status": conn.status
            })
            
    return telemetry_data

if __name__ == "__main__":
    print(json.dumps(get_active_connections(), indent=2))