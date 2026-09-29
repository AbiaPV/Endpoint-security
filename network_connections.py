import psutil
from datetime import datetime


def get_network_connections():
    connections = []

    for connection in psutil.net_connections(kind="inet"):

        try:
            pid = connection.pid

            process_name = "Unknown"

            if pid:
                try:
                    process = psutil.Process(pid)
                    process_name = process.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            local_address = (
                f"{connection.laddr.ip}:{connection.laddr.port}"
                if connection.laddr
                else None
            )

            remote_address = (
                f"{connection.raddr.ip}:{connection.raddr.port}"
                if connection.raddr
                else None
            )

            connection_data = {
                "timestamp": datetime.now().isoformat(),
                "pid": pid,
                "process_name": process_name,
                "protocol": "TCP" if connection.type == 1 else "UDP",
                "local_address": local_address,
                "remote_address": remote_address,
                "status": connection.status
            }

            connections.append(connection_data)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return connections


if __name__ == "__main__":

    print("Network Connection Monitor")
    print("-" * 70)

    connections = get_network_connections()

    print(f"Active connections: {len(connections)}")
    print()

    for connection in connections:
        print(connection)