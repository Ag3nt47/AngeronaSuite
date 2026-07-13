import os
import sys
import json
import socket
import requests
import subprocess
import importlib.util
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
STAGING_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "staging_core")

# Ensure the isolation sandbox directory exists
if not os.path.exists(STAGING_DIR):
    os.makedirs(STAGING_DIR)

def query_gemini_engineer(prompt_text):
    """Fallback gateway optimized to return pure, compilable Python source blocks."""
    if not GEMINI_API_KEY:
        return "ERROR: GEMINI_API_KEY missing from environment rules."
        
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
    headers = {"Content-Type": "application/json"}
    
    payload = {
        "contents": [{
            "parts": [{"text": prompt_text}]
        }],
        "generationConfig": {
            "temperature": 0.0,  # Enforce zero creativity for code syntax accuracy
            "maxOutputTokens": 1500
        }
    }
    
    try:
        res = requests.post(url, headers=headers, json=payload, timeout=45)
        if res.status_code == 200:
            candidates = res.json().get("candidates", [])
            if candidates:
                return candidates[0]["content"]["parts"][0]["text"].strip()
        return f"ERROR: API Communication Fault (HTTP {res.status_code})"
    except Exception as e:
        return f"ERROR: Gateway Exception ({str(e)})"

def extract_pure_code(raw_response):
    """Strips Markdown backticks out of the model payload response to isolate raw code."""
    lines = raw_response.split("\n")
    cleaned_lines = []
    in_code_block = False
    
    for line in lines:
        if line.strip().startswith("```python"):
            in_code_block = True
            continue
        elif line.strip().startswith("```") and in_code_block:
            in_code_block = False
            continue
        
        # If the model didn't use blocks, try to keep everything except obvious text notes
        if in_code_block or (not line.startswith("Here is") and not line.startswith("Notes:")):
            cleaned_lines.append(line)
            
    return "\n".join(cleaned_lines).strip()

def run_syntax_audit(file_path):
    """Executes a non-destructive Python compilation pass to catch structural bugs."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return True, "Syntax valid."
        return False, result.stderr
    except Exception as e:
        return False, str(e)

# ── A-01 hardening: self-modification is OFF by default and gated ────────────
# Executing AI-generated Python in-process is the highest-impact capability in
# the suite, so it ships disabled. The operator must knowingly opt in AND the
# generated source must pass a static security scan before it is ever run.
SELF_EVOLVE_ENABLED = os.getenv("ANGERONA_SELF_EVOLVE", "0") == "1"

# Dangerous constructs that must NOT appear in autonomously-generated code.
_DENY_PATTERNS = (
    "os.system", "subprocess", "popen", "pty.spawn", "eval(", "exec(",
    "__import__", "compile(", "ctypes", "cffi", "winreg", "_winreg",
    "shutil.rmtree", "os.remove", "os.unlink", "os.rmdir", "os.replace",
    "socket.", "urllib.request", "requests.", "httpx", "ftplib", "smtplib",
    "base64.b64decode", "marshal", "pickle", "importlib", "setattr(",
    "open(",  # arbitrary file writes from generated code are not allowed
)


def scan_generated_source(source: str) -> list[str]:
    """Return the list of denied constructs found in *source* (empty = clean)."""
    low = (source or "").lower()
    return [p for p in _DENY_PATTERNS if p.lower() in low]


def hot_reload_capability(module_name, file_path, authorized: bool = False):
    """Injects a newly compiled script live into runtime memory.

    Refuses unless (a) self-evolution is explicitly enabled via ANGERONA_SELF_EVOLVE=1
    or the caller passes authorized=True after human review, AND (b) the source
    passes the static security scan. This prevents autonomous execution of
    unreviewed, potentially poisoned AI-generated code (finding A-01).
    """
    if not (SELF_EVOLVE_ENABLED or authorized):
        return False, ("BLOCKED: self-evolution is disabled by default. Review the "
                       "generated source and set ANGERONA_SELF_EVOLVE=1 (or pass "
                       "authorized=True) to allow execution.")
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except Exception as e:
        return False, f"could not read generated source: {e}"
    hits = scan_generated_source(src)
    if hits:
        return False, ("BLOCKED by static security scan — generated code contains "
                       f"disallowed constructs: {', '.join(hits)}. Not executed.")
    try:
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        new_module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = new_module
        spec.loader.exec_module(new_module)
        return True, new_module
    except Exception as e:
        return False, str(e)

def orchestrate_self_evolution(capability_name, feature_request, iterations=3):
    """Manages the autonomous code, syntax check, and recursive debugging lifecycle."""
    filename = f"dynamic_{capability_name.lower()}.py"
    target_path = os.path.join(STAGING_DIR, filename)
    
    engineering_prompt = f"""
    You are an expert autonomous software engineer script inside an EDR/NDR security runtime agent.
    Generate a complete, optimized Python function or module that fulfills this requirement:
    "{feature_request}"
    
    CRITICAL INSTRUCTIONS:
    - Include all necessary library imports (e.g., os, sys, psutil, socket, json) explicitly inside your response.
    - Write robust try/except defensive safety catch blocks around system calls.
    - The code must be clean, runnable Python. Return the code cleanly wrapped inside ```python and ``` blocks.
    - Do not use markdown bullet formatting or text commentary outside of standard inline code comments.
    """
    
    current_prompt = engineering_prompt
    
    for run in range(1, iterations + 1):
        print(f"[*] Evolution Iteration [{run}/{iterations}]: Requesting source delta from cloud...")
        raw_output = query_gemini_engineer(current_prompt)
        
        if raw_output.startswith("ERROR"):
            return f"Evolution Aborted: {raw_output}"
            
        source_code = extract_pure_code(raw_output)
        
        # Write out to the isolated sandbox target staging path
        with open(target_path, "w") as f:
            f.write(source_code)
            
        # Run the syntax audit pass
        success, diagnostics = run_syntax_audit(target_path)
        
        if success:
            print(f"[+] Syntax audit complete. Source code compiled with 0 errors.")
            # Execute the live module hot-reload mirror step
            reload_success, module_ref = hot_reload_capability(capability_name, target_path)
            if reload_success:
                return f"SUCCESS: Capability '{capability_name}' generated, validated, and hot-reloaded live into memory memory."
            else:
                return f"CRITICAL: Structural hot-reload mapping exception: {diagnostics}"
                
        print(f"[-] Syntax check failed on run {run}. Engaging self-correction loop...")
        
        # Feed the compiler errors directly back to the cloud model for autonomous debugging
        current_prompt = f"""
        The script you generated failed compilation testing with the following Python syntax error trace:
        \"\"\"{diagnostics}\"\"\"
        
        Review your previous code, fix the structural error or missing dependency import statement immediately, and output the corrected version wrapped inside a fresh code block.
        """
        
    return "FAILURE: Autonomous modification limits exceeded without obtaining code synthesis validity."

if __name__ == "__main__":
    # Local lab simulation run if executed directly
    print("=== Operational AI Self-Evolution Staging System ===")
    test_module = "PidTracker"
    test_request = "Write a function named 'execute' that scans for any process running with 'python' in its name using psutil and returns a list of their active PIDs."
    
    status = orchestrate_self_evolution(test_module, test_request)
    print(f"\nResult: {status}")