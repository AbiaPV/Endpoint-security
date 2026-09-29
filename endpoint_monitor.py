import psutil
import time
import json
import os
import uuid
from datetime import datetime

LOG_FILE = "data/endpoint_events/endpoint_events.json"
SCAN_INTERVAL = 2


def generate_event_id():
    return str(uuid.uuid4())


def save_event(event):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    events = []

    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as file:
                events = json.load(file)
        except (json.JSONDecodeError, FileNotFoundError):
            events = []

    events.append(event)

    with open(LOG_FILE, "w", encoding="utf-8") as file:
        json.dump(events, file, indent=4)


# ---------------------------------------------------
# PROCESS MONITORING
# ---------------------------------------------------

def get_processes():

    processes = {}

    for process in psutil.process_iter(
        ["pid", "name", "ppid", "username", "status", "create_time"]
    ):

        try:
            info = process.info

            processes[info["pid"]] = {
                "pid": info["pid"],
                "name": info["name"],
                "parent_pid": info["ppid"],
                "username": info["username"],
                "status": info["status"],
                "create_time": datetime.fromtimestamp(
                    info["create_time"]
                ).isoformat()
            }

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return processes


# ---------------------------------------------------
# NETWORK MONITORING
# ---------------------------------------------------

def get_network_connections():

    connections = []

    try:
        network_connections = psutil.net_connections(kind="inet")

    except psutil.AccessDenied:

        print("[WARNING] Access denied while reading network connections.")

        return connections

    for connection in network_connections:

        try:

            pid = connection.pid

            process_name = "Unknown"

            if pid:

                try:

                    process = psutil.Process(pid)

                    process_name = process.name()

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied
                ):

                    process_name = "Unknown"

            # Determine protocol

            if connection.type == 1:
                protocol = "TCP"

            elif connection.type == 2:
                protocol = "UDP"

            else:
                protocol = "UNKNOWN"

            # Local address

            if connection.laddr:

                local_address = (
                    f"{connection.laddr.ip}:"
                    f"{connection.laddr.port}"
                )

            else:

                local_address = None

            # Remote address

            if connection.raddr:

                remote_address = (
                    f"{connection.raddr.ip}:"
                    f"{connection.raddr.port}"
                )

            else:

                remote_address = None

            status = connection.status

            connection_data = {

                "pid": pid,

                "process_name": process_name,

                "protocol": protocol,

                "local_address": local_address,

                "remote_address": remote_address,

                "status": status
            }

            connections.append(connection_data)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):

            continue

    return connections


# ---------------------------------------------------
# DISPLAY EVENTS
# ---------------------------------------------------

def print_event(event):

    print("\n" + "=" * 70)

    print(f"EVENT ID : {event['event_id']}")

    print(f"EVENT    : {event['event_type']}")

    print(f"TIME     : {event['timestamp']}")

    # Process event

    if "process" in event:

        process = event["process"]

        print(f"Process      : {process['name']}")

        print(f"PID          : {process['pid']}")

        print(f"Parent PID   : {process['parent_pid']}")

        print(f"Username     : {process['username']}")

        print(f"Status       : {process['status']}")

    # Network event

    if "network" in event:

        network = event["network"]

        print(f"Process      : {network['process_name']}")

        print(f"PID          : {network['pid']}")

        print(f"Protocol     : {network['protocol']}")

        print(f"Local        : {network['local_address']}")

        print(f"Remote       : {network['remote_address']}")

        print(f"Status       : {network['status']}")

    print("=" * 70)


# ---------------------------------------------------
# MAIN MONITOR
# ---------------------------------------------------

def monitor_endpoint():

    print("=" * 70)

    print("          ENDPOINT SECURITY MONITOR")

    print("=" * 70)

    print("Process monitoring : ENABLED")

    print("Network monitoring : ENABLED")

    print(f"Scan interval      : {SCAN_INTERVAL} seconds")

    print("Press CTRL+C to stop.")

    print()

    # Initial process snapshot

    previous_processes = get_processes()

    # Initial network snapshot

    previous_connections = {}

    for connection in get_network_connections():

        network_key = (

            connection["pid"],

            connection["protocol"],

            connection["local_address"],

            connection["remote_address"]
        )

        previous_connections[network_key] = connection


    # Continuous monitoring

    while True:

        time.sleep(SCAN_INTERVAL)

        # =================================================
        # PROCESS MONITORING
        # =================================================

        current_processes = get_processes()

        previous_pids = set(previous_processes.keys())

        current_pids = set(current_processes.keys())

        # New processes

        started_pids = current_pids - previous_pids

        for pid in started_pids:

            process = current_processes[pid]

            event = {

                "event_id": generate_event_id(),

                "event_type": "PROCESS_STARTED",

                "timestamp": datetime.now().isoformat(),

                "source": "endpoint_monitor",

                "process": process
            }

            print_event(event)

            save_event(event)


        # Stopped processes

        stopped_pids = previous_pids - current_pids

        for pid in stopped_pids:

            process = previous_processes[pid]

            event = {

                "event_id": generate_event_id(),

                "event_type": "PROCESS_STOPPED",

                "timestamp": datetime.now().isoformat(),

                "source": "endpoint_monitor",

                "process": process
            }

            print_event(event)

            save_event(event)


        previous_processes = current_processes


        # =================================================
        # NETWORK MONITORING
        # =================================================

        current_connections = {}

        for connection in get_network_connections():

            network_key = (

                connection["pid"],

                connection["protocol"],

                connection["local_address"],

                connection["remote_address"]
            )

            current_connections[network_key] = connection


        # -------------------------------------------------
        # NEW NETWORK CONNECTIONS
        # -------------------------------------------------

        new_connections = (

            set(current_connections.keys())

            - set(previous_connections.keys())
        )


        for key in new_connections:

            network = current_connections[key]

            event = {

                "event_id": generate_event_id(),

                "event_type": "NETWORK_CONNECTION_STARTED",

                "timestamp": datetime.now().isoformat(),

                "source": "endpoint_monitor",

                "network": network
            }

            print_event(event)

            save_event(event)


        # -------------------------------------------------
        # CLOSED NETWORK CONNECTIONS
        # -------------------------------------------------

        closed_connections = (

            set(previous_connections.keys())

            - set(current_connections.keys())
        )


        for key in closed_connections:

            network = previous_connections[key]

            event = {

                "event_id": generate_event_id(),

                "event_type": "NETWORK_CONNECTION_STOPPED",

                "timestamp": datetime.now().isoformat(),

                "source": "endpoint_monitor",

                "network": network
            }

            print_event(event)

            save_event(event)


        previous_connections = current_connections


# ---------------------------------------------------
# START PROGRAM
# ---------------------------------------------------

if __name__ == "__main__":

    try:

        monitor_endpoint()

    except KeyboardInterrupt:

        print("\n\nEndpoint monitoring stopped.")