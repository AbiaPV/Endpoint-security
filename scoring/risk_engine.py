"""Risk scoring for the Endpoint Security System (Member 3).

Takes the detector result produced by Member 2 and returns a 0-100 risk
score, a risk level, and an explanation of how the score was calculated.

The weights and thresholds below are a PROPOSED policy pending team approval.
They can be overridden per call without editing this file.

Never raises on bad *input data*; it records what it ignored in
``risk_details``. It raises ``ValueError`` only for invalid *configuration*
(bad weights/thresholds), because that is a programmer error.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

MAX_SCORE = 100

# PROPOSED policy - subject to team approval.
DEFAULT_SEVERITY_WEIGHTS: Dict[str, int] = {
    "LOW": 5,
    "MEDIUM": 15,
    "HIGH": 25,
    "CRITICAL": 40,
}

# (minimum score, level), checked from highest to lowest.
DEFAULT_LEVEL_THRESHOLDS: Tuple[Tuple[int, str], ...] = (
    (75, "CRITICAL"),
    (50, "HIGH"),
    (25, "MEDIUM"),
    (0, "LOW"),
)


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and value == value  # excludes NaN
        and value not in (float("inf"), float("-inf"))
    )


def _normalise_weights(weights: Optional[Dict[str, Any]]) -> Dict[str, float]:
    if weights is None:
        return dict(DEFAULT_SEVERITY_WEIGHTS)
    if not isinstance(weights, dict) or not weights:
        raise ValueError("severity_weights must be a non-empty dict")
    out: Dict[str, float] = {}
    for label, points in weights.items():
        if not isinstance(label, str) or not label.strip():
            raise ValueError(f"invalid severity label: {label!r}")
        if not _is_number(points) or points < 0:
            raise ValueError(f"weight for {label!r} must be a number >= 0")
        out[label.strip().upper()] = points
    return out


def _normalise_thresholds(
    thresholds: Optional[Iterable[Sequence[Any]]],
) -> List[Tuple[float, str]]:
    raw = DEFAULT_LEVEL_THRESHOLDS if thresholds is None else thresholds
    try:
        pairs = [(minimum, str(level).strip().upper()) for minimum, level in raw]
    except (TypeError, ValueError):
        raise ValueError("level_thresholds must be (min_score, level) pairs")
    if not pairs or any(not _is_number(m) for m, _ in pairs):
        raise ValueError("level_thresholds needs numeric minimum scores")
    return sorted(pairs, key=lambda p: p[0], reverse=True)


def classify_risk(
    score: float,
    level_thresholds: Optional[Iterable[Sequence[Any]]] = None,
) -> str:
    """Map a 0-100 score to LOW / MEDIUM / HIGH / CRITICAL."""
    pairs = _normalise_thresholds(level_thresholds)
    for minimum, level in pairs:
        if score >= minimum:
            return level
    return pairs[-1][1]  # below every threshold -> lowest level


def _extract_alerts(detection_result: Any, warnings: List[str]) -> List[Any]:
    if detection_result is None:
        warnings.append("detection_result is missing (None)")
        return []
    if isinstance(detection_result, (list, tuple)):
        return list(detection_result)  # be lenient: a bare alert list
    if not isinstance(detection_result, dict):
        warnings.append(
            f"detection_result must be a dict, got {type(detection_result).__name__}"
        )
        return []
    if "alerts" not in detection_result or detection_result["alerts"] is None:
        warnings.append("detection_result has no 'alerts' field")
        return []
    alerts = detection_result["alerts"]
    if not isinstance(alerts, (list, tuple)):
        warnings.append(f"'alerts' must be a list, got {type(alerts).__name__}")
        return []
    return list(alerts)


def calculate_risk(
    detection_result: Any,
    severity_weights: Optional[Dict[str, Any]] = None,
    level_thresholds: Optional[Iterable[Sequence[Any]]] = None,
) -> Dict[str, Any]:
    """Calculate the overall risk from Member 2's detector result.

    Expected input (schema still to be confirmed with Member 2)::

        {"threat_detected": bool, "alert_count": int,
         "alerts": [{"rule": str, "severity": str, "message": str,
                     "event_id": str (optional)}]}

    Returns::

        {"risk_score": int 0-100, "risk_level": str,
         "alert_count": int,            # alerts that contributed points
         "risk_details": {...}}         # full explanation

    Duplicate rule: an alert is a duplicate ONLY when it carries an
    ``event_id`` and the same (event_id, rule) pair was already counted.
    Alerts without an ``event_id`` are always counted, so genuinely separate
    events that share a rule name are never silently discarded.
    """
    weights = _normalise_weights(severity_weights)
    thresholds = _normalise_thresholds(level_thresholds)

    warnings: List[str] = []
    alerts = _extract_alerts(detection_result, warnings)

    total_points: float = 0
    by_severity: Dict[str, Dict[str, float]] = {}
    scored: List[Dict[str, Any]] = []
    ignored: List[Dict[str, Any]] = []
    duplicates: List[Dict[str, Any]] = []
    seen = set()

    for index, alert in enumerate(alerts):
        if not isinstance(alert, dict):
            ignored.append({"index": index, "reason": "alert is not an object"})
            continue

        rule = alert.get("rule")
        rule = rule if isinstance(rule, str) and rule.strip() else "unknown"
        raw_severity = alert.get("severity")
        if not isinstance(raw_severity, str) or not raw_severity.strip():
            ignored.append(
                {"index": index, "rule": rule, "reason": "missing or non-text severity"}
            )
            continue
        severity = raw_severity.strip().upper()
        if severity not in weights:
            ignored.append(
                {
                    "index": index,
                    "rule": rule,
                    "reason": f"unknown severity '{raw_severity}'",
                }
            )
            continue

        event_id = alert.get("event_id")
        if event_id is not None and str(event_id).strip() != "":
            key = (str(event_id), rule)
            if key in seen:
                duplicates.append(
                    {"index": index, "rule": rule, "event_id": str(event_id)}
                )
                continue
            seen.add(key)

        points = weights[severity]
        total_points += points
        bucket = by_severity.setdefault(severity, {"count": 0, "points": 0})
        bucket["count"] += 1
        bucket["points"] += points
        scored.append(
            {
                "index": index,
                "rule": rule,
                "severity": severity,
                "points": points,
                "event_id": None if event_id is None else str(event_id),
            }
        )

    capped = total_points > MAX_SCORE
    risk_score = int(round(min(MAX_SCORE, total_points)))

    return {
        "risk_score": risk_score,
        "risk_level": classify_risk(risk_score, thresholds),
        "alert_count": len(scored),
        "risk_details": {
            "total_points": total_points,
            "score_capped": capped,
            "alerts_received": len(alerts),
            "points_by_severity": by_severity,
            "scored_alerts": scored,
            "ignored_alerts": ignored,
            "duplicate_alerts": duplicates,
            "warnings": warnings,
            "policy": {
                "severity_weights": dict(weights),
                "level_thresholds": [list(p) for p in thresholds],
                "max_score": MAX_SCORE,
            },
        },
    }