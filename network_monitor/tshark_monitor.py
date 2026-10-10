
import csv
import json
import socket
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
INTERFACE = "4"  # Your Wi-Fi interface
PACKET_LIMIT = 50

OUTPUT = Path("data/network_events/tshark_events.jsonl")

FIELDS = [
    "frame.time_epoch",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
]

def monitor_network():
    if not Path(TSHARK).is_file():
        raise FileNotFoundError(
            f"TShark not found at {TSHARK}"
        )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    command = [
        TSHARK,
        "-n",
        "-i", INTERFACE,
        "-c", str(PACKET_LIMIT),
        "-T", "fields",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ]

    for field in FIELDS:
        command.extend(["-e", field])

    print(f"Capturing up to {PACKET_LIMIT} packets...")
    print(f"Interface: {INTERFACE} (Wi-Fi)")
    print(f"Output: {OUTPUT}")

    # Capture metadata only; stderr remains visible for diagnostics.
    with subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=None,
        text=True,
        encoding="utf-8",
        errors="replace",
    ) as process:
        with OUTPUT.open("a", encoding="utf-8") as output:
            reader = csv.reader(process.stdout)

            for row in reader:
                row += [""] * (len(FIELDS) - len(row))
                packet = dict(zip(FIELDS, row))

                epoch = packet["frame.time_epoch"]
                try:
                    timestamp = datetime.fromtimestamp(
                        float(epoch), timezone.utc
                    ).isoformat()
                except (ValueError, TypeError, OverflowError, OSError):
                    timestamp = datetime.now(timezone.utc).isoformat()

                event = {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": timestamp,
                    "host": socket.gethostname(),
                    "source": "tshark",
                    "event_type": "NETWORK_PACKET_METADATA",
                    "severity": "LOW",
                    "data": {
                        "protocols": packet["frame.protocols"],
                        "source_ip": packet["ip.src"] or packet["ipv6.src"],
                        "destination_ip": packet["ip.dst"] or packet["ipv6.dst"],
                        "source_port": packet["tcp.srcport"] or packet["udp.srcport"],
                        "destination_port": packet["tcp.dstport"] or packet["udp.dstport"],
                        "packet_length": packet["frame.len"],
                    },
                }

                output.write(json.dumps(event) + "\n")
                output.flush()
                print(json.dumps(event, indent=2))

            return_code = process.wait()

        if return_code != 0:
            raise RuntimeError(
                f"TShark failed with exit code {return_code}"
            )
    print(f"Capture finished. Events saved to {OUTPUT}")

if __name__ == "__main__":
    monitor_network()

