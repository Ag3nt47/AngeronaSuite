"""
ai_telemetry.py — AI Observability, Routing Performance, and Diagnostics
"""
import threading
import time

# Thread-safe telemetry ring buffer
_TELEMETRY_SIZE = 15
_ai_history = []
_telemetry_lock = threading.Lock()

def record_ai_transaction(engine: str, prompt_preview: str, status: str, duration: float, error_msg: str = None, token_estimate: int = 0):
    """
    Tracks an AI execution or fallback event.
    Status can be: 'SUCCESS', 'FALLBACK', or 'CRITICAL_FAIL'
    """
    with _telemetry_lock:
        entry = {
            "timestamp": time.strftime("%H:%M:%S"),
            "engine": engine,
            "prompt_hint": prompt_preview[:50] + "..." if len(prompt_preview) > 50 else prompt_preview,
            "status": status,
            "duration_sec": round(duration, 2),
            "error": error_msg or "None",
            "token_est": token_estimate if token_estimate > 0 else round(len(prompt_preview) / 4)
        }
        _ai_history.append(entry)
        if len(_ai_history) > _TELEMETRY_SIZE:
            _ai_history.pop(0)

def get_ai_diagnostic_summary() -> list[dict]:
    """Returns the raw history log for status exports."""
    with _telemetry_lock:
        return list(_ai_history)

def get_formatted_ai_panel() -> list[str]:
    """Formats telemetry lines specifically for the terminal UI dashboard grid."""
    with _telemetry_lock:
        lines = []
        for tx in reversed(_ai_history):
            status_symbol = "✓" if tx["status"] == "SUCCESS" else "⚠" if tx["status"] == "FALLBACK" else "✗"
            line = f"[{tx['timestamp']}] {status_symbol} {tx['engine']} ({tx['duration_sec']}s) | Tok:~{tx['token_est']} | Hint: {tx['prompt_hint']}"
            if tx["error"] != "None":
                line += f" -> ERR: {tx['error']}"
            lines.append(line)
        return lines if lines else ["No AI transactions recorded yet."]