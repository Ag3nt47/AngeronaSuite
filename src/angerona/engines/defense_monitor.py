import json
import os
from typing import Literal
from angerona.engines import ollama_client
from pydantic import BaseModel, Field

class SecurityIncident(BaseModel):
    threat_detected: bool = Field(description="Set to true if the text indicates suspicious or malicious activity.")
    category: Literal["Unauthorized Access", "Malicious Process", "Network Anomaly", "Normal Activity"]
    severity: Literal["Low", "Medium", "High", "Critical"]
    target_identifier: str = Field(description="The IP address, Process ID (PID), or username associated with the threat. Return 'None' if normal.")
    reasoning: str = Field(description="A brief explanation of why this conclusion was reached.")
    recommended_action: Literal["Block IP", "Kill Process", "Log Event", "No Action"]

def analyze_logs(log_file_path: str):
    if not os.path.exists(log_file_path):
        print(f"[-] Target log file not found at: {log_file_path}")
        return

    print(f"[*] Reading latest entries from {log_file_path}...")
    with open(log_file_path, 'r', encoding='utf-8') as file:
        log_content = file.read()

    system_prompt = (
        "You are an expert local host-based intrusion detection system (HIDS) analyst. "
        "Analyze the provided log data or system notes strictly. Determine if a threat exists "
        "and populate the JSON schema exactly as requested."
    )

    print("[*] Dispatching to Ollama for evaluation...")
    
    try:
        # Enforce json format via explicit option injection mapping
        response = ollama_client.call(
            {
                "model": os.getenv("MODEL_NAME", "llama3:latest"),
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {
                        "role": "user",
                        "content": "Analyze the attached untrusted activity evidence.",
                    },
                ],
                "format": "json",
                "stream": False,
                "options": {"temperature": 0},
            },
            "/api/chat",
            timeout=60,
            neutralized_telemetry=log_content,
        )
        if response.get("error"):
            raise RuntimeError(str(response["error"]))
        message = response.get("message")
        content = message.get("content", "") if isinstance(message, dict) else ""
        incident_data = SecurityIncident.model_validate_json(content)
        print("\n[+] Analysis complete. Structure enforced successfully.")
        print(json.dumps(incident_data.model_dump(), indent=2))
        
        if incident_data.threat_detected and incident_data.recommended_action != "No Action":
            gate = trigger_mitigation_gate(incident_data)
            print(json.dumps(gate, indent=2))
        else:
            print("[+] System determined activity is normal or low priority. No action taken.")

    except Exception as e:
        print(f"[-] Parsing failed: {e}")

def trigger_mitigation_gate(incident: SecurityIncident):
    print(f"\n[⚠️] CRITICAL ALERT TRIGGERED: {incident.category} ({incident.severity})")
    print(f"Proposed Action: {incident.recommended_action} on target: {incident.target_identifier}")
    
    # The legacy mitigation gate discovered arbitrary generated PowerShell and
    # dot-sourced it under elevation. It had no exact target binding,
    # postcondition, rollback, or trustworthy receipt. Version 12 therefore
    # makes this analysis-only path explicitly review-gated. Host changes live
    # behind typed broker actions (SOAR queue / Auto Adapt) instead of model
    # prose or repository scripts.
    return {
        "schema": "angerona.mitigation-proposal.v12",
        "status": "review_required",
        "category": incident.category,
        "severity": incident.severity,
        "target_identifier": str(incident.target_identifier)[:256],
        "proposed_action": incident.recommended_action,
        "executed": False,
        "reason": (
            "Legacy dynamic-script execution is disabled; review a typed, "
            "precondition-bound action in the SOAR queue."
        ),
    }

if __name__ == "__main__":
    target_log = "system_activity_log.txt"
    analyze_logs(target_log)
