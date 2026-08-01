import string
import json
import time
import threading
import os
from queue import Full, Queue
from scapy.all import sniff, IP, TCP, UDP, ICMP
from angerona.engines import ollama_client

stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Total_Packets": 0}
unique_ips = set()
geo_cache = {}

OLLAMA_HOST = os.getenv("OLLAMA_HOST") or os.getenv(
    "OLLAMA_URL", "http://localhost:11434/api/generate"
).removesuffix("/api/generate")
MODEL_NAME = os.getenv("MODEL_NAME", "llama3:latest")

dpi_processing_queue = Queue(maxsize=256)

def asynchronous_dpi_worker():
    """Consumes frame payloads out-of-band so Scapy network loops never freeze."""
    while True:
        try:
            payload_text, packet_context = dpi_processing_queue.get()
            prompt = """
            You are an NDR (Network Detection and Response) Deep Packet Inspection tool. 
            Analyze this raw text payload extracted from a network packet.
            Determine if this text contains sensitive exposed data (unencrypted passwords, cleartext API keys, PII, or credentials).
            Respond strictly in one sentence using this exact format:
            [INSPECTION VERDICT]: (SAFE or CRITICAL LEAK) - (Brief reason why)
            """
            try:
                response = ollama_client.analyze_telemetry(
                    prompt,
                    json.dumps({"context": packet_context, "payload": payload_text}),
                    MODEL_NAME,
                    host=OLLAMA_HOST,
                    timeout=5,
                )
                if not response.get("error"):
                    pass
            except Exception:
                pass
        except Exception:
            pass
        finally:
            dpi_processing_queue.task_done()

# R1-04: this legacy engine is DEAD CODE (superseded by modules/packet_sniffer.py;
# see engines/__init__.py — nothing imports it). The import-time DPI worker thread
# that used to start here has been removed so merely importing this module has no
# side effects. Call start_dpi_worker() explicitly if you ever revive it.
def start_dpi_worker():
    """Opt-in: launch the out-of-band DPI worker. Off by default (dead code)."""
    threading.Thread(target=asynchronous_dpi_worker, daemon=True).start()

def get_geo_location(ip_address):
    # Address classification only; this function never binds a socket.
    if ip_address in ["127.0.0.1", "0.0.0.0"] or ip_address.startswith("192.168.") or ip_address.startswith("10."):  # nosec B104
        return "Local Network"

    if ip_address in geo_cache:
        return geo_cache[ip_address]

    # R1-04: the previous implementation POSTed every observed remote IP to
    # http://ip-api.com over cleartext HTTP — an information leak to a third party.
    # That external call has been removed; geolocation is now a no-op. If ever
    # revived, use HTTPS and gate it behind an explicit, default-off opt-in
    # (mirroring remote_bridge/siem_forwarder).
    geo_cache[ip_address] = "[Unknown Region]"
    return "[Unknown Region]"

def is_printable_text(payload_bytes):
    if not payload_bytes: return False
    printable_chars = set(string.printable.encode('ascii'))
    printable_count = sum(1 for byte in payload_bytes if byte in printable_chars)
    return (printable_count / len(payload_bytes)) > 0.85

def packet_callback(packet):
    global stats, unique_ips
    
    if packet.haslayer(IP):
        stats["Total_Packets"] += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        remote_ip = dst_ip if src_ip.startswith("192.168.") or src_ip in ["127.0.0.1"] else src_ip
        # Address comparison only; no socket bind occurs here.
        if remote_ip not in ["127.0.0.1", "0.0.0.0"]:  # nosec B104
            unique_ips.add(remote_ip)
            
        if packet.haslayer(TCP):
            stats["TCP"] += 1
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            raw_payload = bytes(packet[TCP].payload)
            if raw_payload and is_printable_text(raw_payload):
                ascii_snippet = raw_payload[:250].decode('ascii', errors='ignore').strip()
                if ascii_snippet and len(ascii_snippet) > 10:
                    context_str = f"TCP packet from {src_ip}:{sport} to {dst_ip}:{dport}"
                    try:
                        dpi_processing_queue.put_nowait((ascii_snippet, context_str))
                    except Full:
                        pass
                    
        elif packet.haslayer(UDP):
            stats["UDP"] += 1
            
        elif packet.haslayer(ICMP):
            stats["ICMP"] += 1

def run_extended_session(packet_count=20):
    global stats, unique_ips
    stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Total_Packets": 0}
    unique_ips.clear()
    
    try:
        sniff(prn=packet_callback, count=packet_count, timeout=5)
        return {
            "Total Captured Frames": stats["Total_Packets"],
            "TCP_Count": stats["TCP"],
            "UDP_Count": stats["UDP"],
            "ICMP_Count": stats["ICMP"],
            "Unique_Hosts_Count": len(unique_ips)
        }
    except Exception:
        return {"Total Captured Frames": 0, "TCP_Count": 0, "UDP_Count": 0, "ICMP_Count": 0, "Unique_Hosts_Count": 0}
