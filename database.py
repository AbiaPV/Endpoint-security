import json
import os
from scoring.risk_engine import calculate_risk

DATA_FILE = os.path.join("data", "security_data.json")
LIVE_ENDPOINT_LOG = os.path.join("data", "endpoint_events", "endpoint_events.json")
LIVE_NETWORK_LOG = os.path.join("data", "network_events", "tshark_events.jsonl")

def get_security_data():
    """
    Reads live JSON event logs from Member 1 & 3, calculates risk scores
    using Member 4's engine, and updates security_data.json for Member 5's dashboard.
    """
    os.makedirs("data", exist_ok=True)

    all_alerts = []
    total_threats = 0
    network_alerts_count = 0
    suspicious_processes = 0

    # 1. Read live process/network events from endpoint_events.json
    if os.path.exists(LIVE_ENDPOINT_LOG):
        try:
            with open(LIVE_ENDPOINT_LOG, "r", encoding="utf-8") as f:
                events = json.load(f)
                # Look at the latest captured events
                for event in events[-15:]:
                    event_type = event.get("event_type", "")
                    if "process" in event:
                        proc = event["process"]
                        name = proc.get("name", "Unknown")
                        
                        # Flag specific processes or all process start/stop activity
                        is_suspicious = name.lower() in ["powershell.exe", "cmd.exe", "mimikatz.exe", "nc.exe"]
                        if is_suspicious or "STARTED" in event_type:
                            if is_suspicious:
                                total_threats += 1
                                suspicious_processes += 1
                                severity = "HIGH" if "mimikatz" in name.lower() else "MEDIUM"
                            else:
                                severity = "LOW"

                            all_alerts.append({
                                "type": "Process",
                                "description": f"{event_type}: Process {name} (PID: {proc.get('pid')})",
                                "name": name,
                                "risk": severity,
                                "severity": severity,
                                "rule": event_type
                            })
                    elif "network" in event:
                        net = event["network"]
                        network_alerts_count += 1
                        all_alerts.append({
                            "type": "Network",
                            "description": f"Connection {net.get('protocol')} {net.get('status')} -> {net.get('remote_address')}",
                            "name": net.get("process_name", "Unknown"),
                            "risk": "LOW",
                            "severity": "LOW",
                            "rule": event_type
                        })
        except (json.JSONDecodeError, FileNotFoundError):
            pass

    # 2. Read live Wireshark/TShark packets if available
    if os.path.exists(LIVE_NETWORK_LOG):
        try:
            with open(LIVE_NETWORK_LOG, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        packet = json.loads(line)
                        network_alerts_count += 1
                        data = packet.get("data", {})
                        all_alerts.append({
                            "type": "Network Packet",
                            "description": f"Packet metadata captured on port {data.get('destination_port', 'N/A')}",
                            "name": f"{data.get('source_ip')} -> {data.get('destination_ip')}",
                            "risk": "LOW",
                            "severity": "LOW",
                            "rule": "NETWORK_PACKET_METADATA"
                        })
        except (json.JSONDecodeError, FileNotFoundError):
            pass

    # 3. Calculate risk score using Member 4's scoring engine
    risk_result = calculate_risk({"alerts": all_alerts})

    security_data = {
        "risk_score": risk_result["risk_score"],
        "risk_level": risk_result["risk_level"],
        "total_threats": total_threats + network_alerts_count,
        "network_alerts": network_alerts_count,
        "suspicious_processes": suspicious_processes,
        "alerts": [
            {
                "type": a["type"],
                "description": a["description"],
                "name": a["name"],
                "risk": a["risk"]
            } for a in all_alerts[-20:] # Keep latest 20 alerts for display
        ] if all_alerts else [{
            "type": "System", "description": "Monitoring live system activity. No threats detected.", "name": "None", "risk": "Low"
        }]
    }

    # Save to central JSON store for Flask app and PDF report generator
    with open(DATA_FILE, "w", encoding="utf-8") as file:
        json.dump(security_data, file, indent=4)

    return security_data

if __name__ == "__main__":
    data = get_security_data()
    print("Database updated successfully with live logs!")
    print(json.dumps(data, indent=4))
