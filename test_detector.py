from detection.detector import detect_threat


event = {
    "process_name": "powershell.exe",
    "command_line": "powershell -EncodedCommand test",
    "parent_name": "winword.exe"
}

result = detect_threat(event)

print("\n===== THREAT DETECTION =====")
print("Threat Detected:", result["threat_detected"])
print("Alert Count:", result["alert_count"])

for alert in result["alerts"]:
    print("\nRule:", alert["rule"])
    print("Severity:", alert["severity"])
    print("Message:", alert["message"])