import psutil
import time
from datetime import datetime
from event_logger import save_event

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

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes


def print_event(event_type, process):
    print("\n" + "=" * 60)
    print(f"EVENT: {event_type}")
    print("=" * 60)
    print(f"Process Name : {process['name']}")
    print(f"PID          : {process['pid']}")
    print(f"Parent PID   : {process['parent_pid']}")
    print(f"Username     : {process['username']}")
    print(f"Timestamp    : {datetime.now().isoformat()}")
    print("=" * 60)


def monitor_processes():
    print("Endpoint Process Monitor Started")
    print("Monitoring processes...")
    print("Press CTRL+C to stop.\n")

    previous_processes = get_processes()

    while True:
        time.sleep(2)

        current_processes = get_processes()

        previous_pids = set(previous_processes.keys())
        current_pids = set(current_processes.keys())

        # Detect newly started processes
        started_pids = current_pids - previous_pids

        for pid in started_pids:
            print_event(
                "PROCESS_STARTED",
                current_processes[pid]
            )

        # Detect stopped processes
        stopped_pids = previous_pids - current_pids

        for pid in stopped_pids:
            print_event(
                "PROCESS_STOPPED",
                previous_processes[pid]
            )

        previous_processes = current_processes


if __name__ == "__main__":
    try:
        monitor_processes()

    except KeyboardInterrupt:
        print("\nProcess monitoring stopped.")