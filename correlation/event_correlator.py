"""Event correlation for the Endpoint Security System (Member 3).

Groups related events into POSSIBLE incidents and removes duplicate records.
Correlation shows possible relationships only; it never claims an attack is
confirmed.

Correlation rules (all configurable via arguments):
  1. same_pid      - two events from the same process ID, and
  2. parent_child  - one event's pid equals another's parent pid,
  both only when the events are within ``time_window_seconds`` of each other
  (PIDs get reused by the OS, so PID alone is not enough) and not from
  different hosts. Events with a missing/invalid timestamp are NOT linked
  unless ``allow_untimed_links=True``.
  The alert/rule name is never used to link events.
  Links are transitive (A-B and B-C puts A, B, C in one incident).

Duplicate rule:
  * events with an event ID: same ID = same record (first one kept);
  * events without an ID: byte-identical records (all fields equal).
"""
from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_TIME_WINDOW_SECONDS = 300

# Accepted field names per concept (schema from Member 1 still to be confirmed).
FIELD_ALIASES = {
    "event_id": ("event_id", "id"),
    "timestamp": ("timestamp", "time", "ts"),
    "pid": ("pid", "process_id"),
    "ppid": ("ppid", "parent_pid", "parent_process_id"),
    "host": ("host", "hostname", "endpoint"),
    "rule": ("rule", "alert", "alert_name"),
}


def parse_timestamp(value: Any) -> Optional[float]:
    """Return seconds since the epoch (UTC), or None if unusable.

    Accepts epoch seconds (int/float/numeric string) and ISO-8601 strings
    (a trailing 'Z' is allowed; naive times are treated as UTC).
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) if math.isfinite(value) else None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            number = float(text)
            return number if math.isfinite(number) else None
        except ValueError:
            pass
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    return None


def _to_pid(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, float):
            if not value.is_integer():
                return None
            value = int(value)
        elif isinstance(value, str):
            value = int(value.strip())
        elif not isinstance(value, int):
            return None
    except ValueError:
        return None
    return value if value > 0 else None  # 0/negative = no real process


def _first(event: Dict[str, Any], concept: str) -> Any:
    for name in FIELD_ALIASES[concept]:
        value = event.get(name)
        if value is not None and value != "":
            return value
    return None


def _fingerprint(event: Dict[str, Any]) -> str:
    try:
        text = json.dumps(event, sort_keys=True, default=str)
    except (TypeError, ValueError):
        text = repr(event)
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()


def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _normalise(index: int, raw: Dict[str, Any]) -> Dict[str, Any]:
    event_id = _first(raw, "event_id")
    event_id = None if event_id is None else str(event_id)
    host = _first(raw, "host")
    rule = _first(raw, "rule")
    return {
        "index": index,
        "event_id": event_id,
        "ref": event_id if event_id is not None else f"unidentified-{index}",
        "ts": parse_timestamp(_first(raw, "timestamp")),
        "pid": _to_pid(_first(raw, "pid")),
        "ppid": _to_pid(_first(raw, "ppid")),
        "host": None if host is None else str(host),
        "rule": None if rule is None else str(rule),
    }


def _link_reason(a: Dict[str, Any], b: Dict[str, Any], window: float,
                 allow_untimed: bool) -> Optional[str]:
    if a["host"] and b["host"] and a["host"] != b["host"]:
        return None
    if a["ts"] is not None and b["ts"] is not None:
        if abs(a["ts"] - b["ts"]) > window:
            return None
    elif not allow_untimed:
        return None
    if a["pid"] and a["pid"] == b["pid"]:
        return "same_pid"
    if (a["pid"] and a["pid"] == b["ppid"]) or (b["pid"] and b["pid"] == a["ppid"]):
        return "parent_child"
    return None


def correlate_events(
    events: Any,
    time_window_seconds: float = DEFAULT_TIME_WINDOW_SECONDS,
    allow_untimed_links: bool = False,
) -> Dict[str, Any]:
    """Deduplicate ``events`` and group related ones into possible incidents.

    Returns::

        {"incident_count": int,
         "incidents": [{"incident_id", "status", "event_ids", "event_count",
                        "process_ids", "hosts", "rules", "first_seen",
                        "last_seen", "correlation_links", "note"}],
         "correlated_event_ids": [ids that belong to an incident],
         "standalone_event_ids": [ids not related to any other event],
         "duplicate_count": int, "duplicate_events": [...],
         "invalid_event_count": int, "event_count": int (unique events),
         "warnings": [...], "parameters": {...}}

    Never raises on bad event data; raises ValueError only if
    ``time_window_seconds`` is not a non-negative number.
    """
    if (isinstance(time_window_seconds, bool)
            or not isinstance(time_window_seconds, (int, float))
            or not math.isfinite(time_window_seconds) or time_window_seconds < 0):
        raise ValueError("time_window_seconds must be a number >= 0")

    warnings: List[str] = []
    if events is None:
        sequence: List[Any] = []
    elif isinstance(events, (list, tuple)):
        sequence = list(events)
    else:
        warnings.append(f"events must be a list, got {type(events).__name__}")
        sequence = []

    # ---- 1. validate + deduplicate -------------------------------------
    unique: List[Dict[str, Any]] = []
    duplicates: List[Dict[str, Any]] = []
    invalid = 0
    id_fingerprints: Dict[str, str] = {}
    id_first_index: Dict[str, int] = {}
    anon_fingerprints: Dict[str, str] = {}

    for index, raw in enumerate(sequence):
        if not isinstance(raw, dict):
            invalid += 1
            warnings.append(f"event at index {index} is not an object; ignored")
            continue
        ev = _normalise(index, raw)
        fp = _fingerprint(raw)
        if ev["event_id"] is not None:
            eid = ev["event_id"]
            if eid in id_fingerprints:
                if id_fingerprints[eid] != fp:
                    warnings.append(
                        f"event_id '{eid}' appears with different contents "
                        f"(index {id_first_index[eid]} kept, index {index} dropped)"
                    )
                duplicates.append({"input_index": index, "event_id": eid,
                                   "duplicate_of": eid})
                continue
            id_fingerprints[eid] = fp
            id_first_index[eid] = index
        else:
            if fp in anon_fingerprints:
                duplicates.append({"input_index": index, "event_id": None,
                                   "duplicate_of": anon_fingerprints[fp]})
                continue
            anon_fingerprints[fp] = ev["ref"]
        unique.append(ev)

    # ---- 2. find links (union-find) -------------------------------------
    parent = list(range(len(unique)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    by_pid: Dict[int, List[int]] = {}
    for i, ev in enumerate(unique):
        if ev["pid"]:
            by_pid.setdefault(ev["pid"], []).append(i)

    candidate_pairs = set()
    for i, ev in enumerate(unique):
        for key in (ev["pid"], ev["ppid"]):
            if key:
                for j in by_pid.get(key, ()):
                    if j != i:
                        candidate_pairs.add((min(i, j), max(i, j)))

    links: List[Tuple[int, int, str]] = []
    for i, j in sorted(candidate_pairs):
        reason = _link_reason(unique[i], unique[j], float(time_window_seconds),
                              allow_untimed_links)
        if reason:
            links.append((i, j, reason))
            ri, rj = find(i), find(j)
            if ri != rj:
                parent[max(ri, rj)] = min(ri, rj)

    # ---- 3. build incidents ----------------------------------------------
    groups: Dict[int, List[int]] = {}
    for i in range(len(unique)):
        groups.setdefault(find(i), []).append(i)

    def sort_key(i: int) -> Tuple[bool, float, int]:
        ts = unique[i]["ts"]
        return (ts is None, ts if ts is not None else 0.0, i)

    incidents: List[Dict[str, Any]] = []
    in_incident = set()
    for root, members in groups.items():
        if len(members) < 2:
            continue
        members.sort(key=sort_key)
        refs = [unique[i]["ref"] for i in members]
        in_incident.update(members)
        stamps = [unique[i]["ts"] for i in members if unique[i]["ts"] is not None]
        digest = hashlib.sha1("|".join(sorted(refs)).encode()).hexdigest()[:8]
        member_set = set(members)
        incidents.append({
            "incident_id": f"INC-{digest}",
            "status": "possible_incident",
            "event_ids": refs,
            "event_count": len(refs),
            "process_ids": sorted({unique[i]["pid"] for i in members if unique[i]["pid"]}),
            "hosts": sorted({unique[i]["host"] for i in members if unique[i]["host"]}),
            "rules": sorted({unique[i]["rule"] for i in members if unique[i]["rule"]}),
            "first_seen": _iso(min(stamps)) if stamps else None,
            "last_seen": _iso(max(stamps)) if stamps else None,
            "correlation_links": [
                {"type": reason, "event_ids": [unique[i]["ref"], unique[j]["ref"]]}
                for i, j, reason in links if i in member_set
            ],
            "note": "Possible related activity based on process/time links; "
                    "not a confirmed attack.",
            "_sort": sort_key(members[0]),
        })

    incidents.sort(key=lambda inc: inc["_sort"])
    for inc in incidents:
        del inc["_sort"]

    correlated_ids = [unique[i]["ref"] for i in sorted(in_incident, key=sort_key)]
    standalone_ids = [ev["ref"] for i, ev in enumerate(unique) if i not in in_incident]

    return {
        "incident_count": len(incidents),
        "incidents": incidents,
        "correlated_event_ids": correlated_ids,
        "standalone_event_ids": standalone_ids,
        "duplicate_count": len(duplicates),
        "duplicate_events": duplicates,
        "invalid_event_count": invalid,
        "event_count": len(unique),
        "warnings": warnings,
        "parameters": {
            "time_window_seconds": time_window_seconds,
            "allow_untimed_links": allow_untimed_links,
        },
    }