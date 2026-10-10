from .rules import check_rules

SEVERITY_POINTS = {"low": 10, "medium": 40, "high": 80}


def detect_threat(event):
    """Check one process event and return the detection result."""
    alerts = check_rules(event)

    score = sum(SEVERITY_POINTS.get(a["severity"], 0) for a in alerts)
    score = min(score, 100)

    if score >= 80:
        risk_level = "high"
    elif score >= 40:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "threat_detected": len(alerts) > 0,
        "alert_count": len(alerts),
        "risk_score": score,
        "risk_level": risk_level,
        "alerts": alerts,
    }