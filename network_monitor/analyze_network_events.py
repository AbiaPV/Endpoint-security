"""Analyze TShark JSONL events with the project's risk engine and correlator.

Run from the project root:
    python -m network_monitor.analyze_network_events

This is a lightweight heuristic demonstration, not a malware detector. A matching
port is an investigation hint, not proof of malicious activity.
"""
from __future__ import annotations

import argparse
import json
import socket
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scoring.risk_engine import calculate_risk
from correlation.event_correlator import correlate_events

DEFAULT_INPUT = Path("data/network_events/tshark_events.jsonl")
DEFAULT_OUTPUT = Path("data/network_events/network_analysis_report.json")

# Ports sometimes seen in remote-control/testing tools or suspicious services.
# These are configurable heuristics and can also be used legitimately.
WATCH_PORTS = {1337, 4444, 5555, 12345, 31337}


def parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (ValueError, TypeError):
        return None



def read_jsonl(path):
    events = []
    warnings = []

    if not path.exists():
        raise FileNotFoundError(
            f"Input file not found: {path}. Run tshark_monitor.py from the project root first."
        )

    with path.open("r", encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                warnings.append(
                    f"Line {line_number}: invalid JSON ({exc}); skipped"
                )

    return events, warnings



def port_number(value: Any) -> Optional[int]:
    try:
        port = int(str(value).strip())
        return port if 1 <= port <= 65535 else None
    except (ValueError, TypeError):
        return None


def build_alerts(events: List[Dict[str, Any]], watch_ports: set[int]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    for event in events:
        data = event.get("data")
        if not isinstance(data, dict):
            continue

        dst_port = port_number(data.get("destination_port"))
        if dst_port not in watch_ports:
            continue

        protocols = str(data.get("protocols") or "unknown")
        src_ip = str(data.get("source_ip") or "unknown")
        dst_ip = str(data.get("destination_ip") or "unknown")
        event_id = event.get("event_id")

        alerts.append({
            "event_id": str(event_id) if event_id is not None else None,
            "rule": "NETWORK_WATCHLIST_DESTINATION_PORT",
            "severity": "MEDIUM",
            "message": (
                f"Observed packet to watchlisted destination port {dst_port} "
                f"({src_ip} -> {dst_ip}; protocols={protocols}). "
                "This is a heuristic indicator, not proof of compromise."
            ),
            "timestamp": event.get("timestamp"),
            "host": event.get("host"),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": dst_port,
            "protocols": protocols,
        })
    return alerts


def network_correlate(
    alerts: List[Dict[str, Any]], window_seconds: int = 300
) -> Dict[str, Any]:
    """Group alert records sharing the same network endpoint tuple in a time window."""
    groups: Dict[Tuple[str, str, int], List[Dict[str, Any]]] = defaultdict(list)
    untimed: List[Dict[str, Any]] = []

    for alert in alerts:
        key = (
            str(alert.get("source_ip") or "unknown"),
            str(alert.get("destination_ip") or "unknown"),
            int(alert["destination_port"]),
        )
        groups[key].append(alert)

    incidents: List[Dict[str, Any]] = []
    standalone: List[str] = []
    for (src_ip, dst_ip, dst_port), group in sorted(groups.items()):
        group.sort(key=lambda item: parse_time(item.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc))
        clusters: List[List[Dict[str, Any]]] = []
        for alert in group:
            current_time = parse_time(alert.get("timestamp"))
            if not clusters:
                clusters.append([alert])
                continue
            previous_time = parse_time(clusters[-1][-1].get("timestamp"))
            if current_time is None or previous_time is None:
                # Don't infer a time relationship from missing timestamps.
                if alert is clusters[-1][-1]:
                    clusters[-1].append(alert)
                else:
                    clusters.append([alert])
            elif (current_time - previous_time).total_seconds() <= window_seconds:
                clusters[-1].append(alert)
            else:
                clusters.append([alert])

        for cluster in clusters:
            ids = [str(item.get("event_id") or "unknown") for item in cluster]
            if len(cluster) < 2:
                standalone.extend(ids)
                continue
            times = [parse_time(item.get("timestamp")) for item in cluster]
            valid_times = [value for value in times if value is not None]
            incidents.append({
                "incident_id": f"NET-{len(incidents) + 1:04d}",
                "status": "possible_network_indicator",
                "event_ids": ids,
                "event_count": len(cluster),
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "first_seen": min(valid_times).isoformat() if valid_times else None,
                "last_seen": max(valid_times).isoformat() if valid_times else None,
                "note": (
                    "Multiple watchlist-port observations shared the same endpoint tuple "
                    f"within {window_seconds}s. Investigate; this does not confirm an attack."
                ),
            })

    return {
        "incident_count": len(incidents),
        "incidents": incidents,
        "standalone_alert_event_ids": standalone,
        "time_window_seconds": window_seconds,
        "method": "same source IP + destination IP + destination port within time window",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Score and correlate TShark network events.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="Input JSONL file")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output JSON report")
    parser.add_argument(
        "--watch-ports",
        default=",".join(str(port) for port in sorted(WATCH_PORTS)),
        help="Comma-separated destination ports to flag (default: 1337,4444,5555,12345,31337)",
    )
    parser.add_argument("--window", type=int, default=300, help="Network correlation window in seconds")
    args = parser.parse_args()

    try:
        watch_ports = {int(item.strip()) for item in args.watch_ports.split(",") if item.strip()}
    except ValueError:
        parser.error("--watch-ports must contain comma-separated integers")
    if any(port < 1 or port > 65535 for port in watch_ports):
        parser.error("watch ports must be between 1 and 65535")
    if args.window < 0:
        parser.error("--window must be >= 0")

    events, input_warnings = read_jsonl(args.input)
    alerts = build_alerts(events, watch_ports)

    detection_result = {
        "threat_detected": bool(alerts),
        "alert_count": len(alerts),
        "alerts": alerts,
    }
    risk_result = calculate_risk(detection_result)

    # Run the project's existing correlator on the raw packet records. It uses
    # process/parent-process relationships; packet metadata usually lacks those,
    # so the network-specific endpoint correlation below is included separately.
    process_correlation = correlate_events(events, time_window_seconds=args.window)
    network_correlation = network_correlate(alerts, window_seconds=args.window)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(args.input),
        "packet_event_count": len(events),
        "watch_ports": sorted(watch_ports),
        "alert_count": len(alerts),
        "alerts": alerts,
        "risk": risk_result,
        "process_event_correlation": process_correlation,
        "network_indicator_correlation": network_correlation,
        "warnings": input_warnings,
        "limitations": [
            "A watched port is a heuristic indicator, not proof of malicious activity.",
            "This analyzes captured packet metadata only; it does not inspect payloads.",
            "The process correlator needs PID/PPID fields to link process-related events.",
            "A clean result means no configured indicator matched in this capture, not that the host is guaranteed safe.",
        ],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Packet events read : {len(events)}")
    print(f"Watchlist alerts   : {len(alerts)}")
    print(f"Risk score         : {risk_result.get('risk_score', 'n/a')}")
    print(f"Risk level         : {risk_result.get('risk_level', 'n/a')}")
    print(f"Network incidents  : {network_correlation['incident_count']}")
    print(f"Report saved       : {args.output}")
    if not alerts:
        print("No configured watchlist-port indicators matched; this is not a guarantee of safety.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
