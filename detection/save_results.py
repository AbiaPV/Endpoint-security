import json
from detection.detector import detect_threat

INPUT_FILE = "events.jsonl"
OUTPUT_FILE = "detection_results.json"

results = []

with open(INPUT_FILE, "r", encoding="utf-8") as file:
    for line in file:
        if not line.strip():
            continue

        event = json.loads(line)
        result = detect_threat(event)

        results.append({
            "process_name": event.get("process_name"),
            "threat_detected": result["threat_detected"],
            "alert_count": result["alert_count"],
            "alerts": result["alerts"]
        })

with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
    json.dump(results, file, indent=4)

print("Detection completed!")
print("Results saved to:", OUTPUT_FILE)