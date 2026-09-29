import json
import os
from datetime import datetime


LOG_FILE = "data/endpoint_events/process_events.json"


def save_event(event_type, process):
    event = {
        "event_type": event_type,
        "timestamp": datetime.now().isoformat(),
        "process": {
            "pid": process["pid"],
            "name": process["name"],
            "parent_pid": process["parent_pid"],
            "username": process["username"],
            "status": process["status"],
            "create_time": process["create_time"]
        }
    }

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    events = []

    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as file:
                events = json.load(file)
        except json.JSONDecodeError:
            events = []

    events.append(event)

    with open(LOG_FILE, "w") as file:
        json.dump(events, file, indent=4)