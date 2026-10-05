import json
import os


DATA_FILE = os.path.join("data", "security_data.json")


def get_security_data():

    # Create data folder if it doesn't exist
    os.makedirs("data", exist_ok=True)

    # If data file doesn't exist, create sample data
    if not os.path.exists(DATA_FILE):

        sample_data = {
            "risk_score": 75,
            "risk_level": "HIGH",
            "total_threats": 5,
            "network_alerts": 12,
            "suspicious_processes": 3,

            "alerts": [
                {
                    "type": "Process",
                    "description": "Suspicious process detected",
                    "name": "malware.exe",
                    "risk": "High"
                },
                {
                    "type": "Network",
                    "description": "Unusual network connection",
                    "name": "192.168.1.100",
                    "risk": "Medium"
                },
                {
                    "type": "File",
                    "description": "Suspicious file pattern detected",
                    "name": "suspicious_file.exe",
                    "risk": "High"
                }
            ]
        }

        with open(DATA_FILE, "w") as file:
            json.dump(sample_data, file, indent=4)


    # Read security data
    with open(DATA_FILE, "r") as file:

        data = json.load(file)

    return data