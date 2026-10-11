import json
import os
from scoring.risk_engine import calculate_risk

DATA_FILE = os.path.join("data", "security_data.json")
DETECTION_LOG = "detection_results.json"
NETWORK_REPORT = os.path.join("data", "network_events", "network_analysis_report.json")

def get_security_data():
    """
    Aggregates process detections and network events, calculates risk score 
    using risk_engine.py, and structures the output for the Flask dashboard.
    """
    os.makedirs("data", exist_ok=True)

    all_alerts = []
    total_threats = 0
    network_alerts_count = 0
    suspicious_processes = 0

    # 1. Load Process/Endpoint Detection Results
    if os.path.exists(DETECTION_LOG):
        try:
            with open(DETECTION_LOG, "r", encoding="utf-8") as f:
                results = json.load(f)
                for item in results:
                    if item.get("threat_detected", False):
                        total_threats += 1
                        suspicious_processes += 1
                        for alert in item.get("alerts", []):
                            all_alerts.append({
                                "type": "Process",
                                "description": alert.get("description", "Suspicious activity detected"),
                                "name": item.get("event", {}).get("process_name") or item.get("process_name", "Unknown"),
                                "risk": alert.get("severity", "MEDIUM").upper(),
                                "rule": alert.get("rule", "Unknown Rule"),
                                "severity": alert.get("severity", "MEDIUM").upper(),
                                "event_id": alert.get("event_id")
                            })
        except (json.JSONDecodeError, FileNotFoundError):
            pass

    # 2. Load Network Analysis Report from TShark
    if os.path.exists(NETWORK_REPORT):
        try:
            with open(NETWORK_REPORT, "r", encoding="utf-8") as f:
                net_report = json.load(f)
                network_alerts_count = net_report.get("alert_count", 0)
                for alert in net_report.get("alerts", []):
                    all_alerts.append({
                        "type": "Network",
                        "description": alert.get("message", "Network watchlist match"),
                        "name": f"{alert.get('source_ip', 'IP')} -> {alert.get('destination_ip', 'IP')}:{alert.get('destination_port', '')}",
                        "risk": alert.get("severity", "MEDIUM").upper(),
                        "rule": alert.get("rule", "NETWORK_WATCHLIST"),
                        "severity": alert.get("severity", "MEDIUM").upper(),
                        "event_id": alert.get("event_id")
                    })
        except (json.JSONDecodeError, FileNotFoundError):
            pass

    # 3. Calculate Risk Score using Member 3/4's risk_engine.py
    detection_payload = {"alerts": all_alerts}
    risk_result = calculate_risk(detection_payload)

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
            } for a in all_alerts
        ]
    }

    # Save to central data store for Flask and PDF reports
    with open(DATA_FILE, "w", encoding="utf-8") as file:
        json.dump(security_data, file, indent=4)

    return security_data

if __name__ == "__main__":
    data = get_security_data()
    print("Security Data Aggregated Successfully:")
    print(json.dumps(data, indent=4))
