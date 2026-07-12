"""
persistence.py — SQLite3 Database Local Telemetry Flight Recorder Engine
"""
import os
import sqlite3
import time
import threading
from queue import Queue

# C:\Windows\Temp is ACL-restricted — a non-elevated run can't create the DB there,
# so the flight recorder would silently never persist. Default to a file next to this
# script (works on any drive/folder, elevated or not), overridable via EDR_FLIGHT_DB.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("EDR_FLIGHT_DB", os.path.join(_SCRIPT_DIR, "ude_telemetry.db"))

def _ensure_column(cursor, table: str, column: str, col_type: str):
    """Adds `column` to `table` if it doesn't already exist.
    CREATE TABLE IF NOT EXISTS only helps on a brand-new database file --
    if the table already exists from a previous run (the common case here,
    since DB_PATH persists across restarts), it silently does nothing and
    new columns referenced by later INSERTs would otherwise just fail."""
    cursor.execute(f"PRAGMA table_info({table})")
    existing_cols = {row[1] for row in cursor.fetchall()}
    if column not in existing_cols:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")


def initialize_flight_recorder(db_queue: Queue, log_module) -> threading.Thread:
    """Verifies schema table structures and initializes the async background database writer."""
    try:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                pid INTEGER, ppid INTEGER, image_path TEXT, command_line TEXT
            )""")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                pid INTEGER, local_ip TEXT, local_port INTEGER, remote_ip TEXT, remote_port INTEGER, state TEXT
            )""")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                event_type TEXT, target_pid INTEGER, details TEXT, risk_score REAL
            )""")

        # Migration: add columns introduced after the table may already exist.
        _ensure_column(cursor, "alerts", "mitre_mapping", "TEXT")
        _ensure_column(cursor, "alerts", "remediation", "TEXT")

        conn.commit()
        conn.close()
    except Exception as e:
        log_module.error("PERSISTENCE", "Database verification schema failure", data={"error": str(e)})

    # Dispatch dedicated worker to bypass write blocks
    worker = threading.Thread(target=_db_commit_worker, args=(db_queue, log_module), daemon=True)
    worker.start()
    return worker

def query_historical_timeline(pid: int) -> list:
    """Returns chronologically organized listings matching actions tied to a suspect process."""
    events = []
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, image_path, command_line FROM process_events WHERE pid=? ORDER BY timestamp ASC", (pid,))
        events = cursor.fetchall()
        conn.close()
    except Exception:
        pass
    return events

def _db_commit_worker(db_queue: Queue, log_module):
    """Pulls payloads from the processing engine queue and processes them sequentially via atomic transactions."""
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Batch process up to 20 queue entries concurrently to reduce disk I/O overhead
            processed_count = 0
            while not db_queue.empty() and processed_count < 20:
                table, payload = db_queue.get()
                
                if table == "process":
                    cursor.execute("INSERT INTO process_events (timestamp, pid, ppid, image_path, command_line) VALUES (?,?,?,?,?)",
                                   (time.strftime('%Y-%m-%d %H:%M:%S'), payload['pid'], payload['ppid'], payload['name'], payload.get('cmdline', '')))
                elif table == "network":
                    cursor.execute("INSERT INTO network_events (timestamp, pid, local_ip, local_port, remote_ip, remote_port, state) VALUES (?,?,?,?,?,?,?)",
                                   (time.strftime('%Y-%m-%d %H:%M:%S'), payload['pid'], payload.get('local_ip',''), payload.get('local_port',0), payload.get('remote_ip',''), payload.get('remote_port',0), payload.get('state','')))
                elif table == "alert":
                    cursor.execute("INSERT INTO alerts (timestamp, event_type, target_pid, details, risk_score, mitre_mapping, remediation) VALUES (?,?,?,?,?,?,?)",
                                   (time.strftime('%Y-%m-%d %H:%M:%S'), payload['type'], payload.get('pid', 0), payload['details'], payload.get('score', 0.5), payload.get('mitre_mapping', ''), payload.get('remediation', '')))
                
                db_queue.task_done()
                processed_count += 1
                
            if processed_count > 0:
                conn.commit()
            conn.close()
        except sqlite3.OperationalError:
            time.sleep(0.5)  # Handle database locking exceptions gracefully
        except Exception as e:
            log_module.error("PERSISTENCE", "Critical error executing database batch update", data={"error": str(e)})
        time.sleep(0.2)