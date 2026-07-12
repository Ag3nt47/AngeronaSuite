"""
rag.py — Local knowledge base / context retrieval

FIX APPLIED:
  Same hardcoded D:\\ path problem as storage.py and edr_logger.py.
  KNOWLEDGE_BASE_PATH now defaults to a file next to this script,
  with an EDR_KB_PATH environment variable override.
"""

import os

_SCRIPT_DIR         = os.path.dirname(os.path.abspath(__file__))
KNOWLEDGE_BASE_PATH = os.getenv(
    "EDR_KB_PATH",
    os.path.join(_SCRIPT_DIR, "knowledge_base.txt")
)

if not os.path.exists(KNOWLEDGE_BASE_PATH):
    os.makedirs(os.path.dirname(KNOWLEDGE_BASE_PATH), exist_ok=True)
    with open(KNOWLEDGE_BASE_PATH, "w") as f:
        f.write("[ASSET LOG]: Custom script monitor agent.py running out of the project directory.\n")
        f.write("[ASSET LOG]: Ollama local model inference engine running port 11434.\n")
        f.write("[RULES]: Treat any unsigned process running out of user AppData\\Local\\Temp as high threat.\n")


def query_local_context(process_name):
    if not os.path.exists(KNOWLEDGE_BASE_PATH):
        return ""
    with open(KNOWLEDGE_BASE_PATH, "r") as f:
        lines = f.readlines()
    relevant_context = []
    for line in lines:
        if process_name.lower() in line.lower() or "rule" in line.lower():
            relevant_context.append(line.strip())
    return "\n".join(relevant_context) if relevant_context else "No local assets conflict found."
