import json
import os
import subprocess
from typing import Literal
from angerona.core.win import run_hidden
from pydantic import BaseModel, Field
import ollama

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
        response = ollama.chat(
            model=os.getenv("MODEL_NAME", "llama3:latest"), 
            messages=[
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': f"Analyze this activity:\n\n{log_content}"}
            ],
            format="json",
            options={
                'temperature': 0,
                'timeout': 60  
            }
        )
        
        incident_data = SecurityIncident.model_validate_json(response.message.content)
        print("\n[+] Analysis complete. Structure enforced successfully.")
        print(json.dumps(incident_data.model_dump(), indent=2))
        
        if incident_data.threat_detected and incident_data.recommended_action != "No Action":
            trigger_mitigation_gate(incident_data)
        else:
            print("[+] System determined activity is normal or low priority. No action taken.")

    except Exception as e:
        print(f"[-] Parsing failed: {e}")

def trigger_mitigation_gate(incident: SecurityIncident):
    print(f"\n[⚠️] CRITICAL ALERT TRIGGERED: {incident.category} ({incident.severity})")
    print(f"Proposed Action: {incident.recommended_action} on target: {incident.target_identifier}")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    ps_script_path = os.path.join(script_dir, "mitigation_gate.ps1")
    temp_payload_path = os.path.join(script_dir, "incident_payload.json")
    
    try:
        with open(temp_payload_path, "w", encoding='utf-8') as f:
            json.dump(incident.model_dump(), f, indent=4)
        
        ps_cmd = f"& '{ps_script_path}' -PayloadPath '{temp_payload_path}'"
        run_hidden(["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd])
    finally:
        if os.path.exists(temp_payload_path):
            os.remove(temp_payload_path)

if __name__ == "__main__":
    target_log = "system_activity_log.txt"
    analyze_logs(target_log)
