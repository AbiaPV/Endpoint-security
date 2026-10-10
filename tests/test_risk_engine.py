import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from scoring.risk_engine import calculate_risk, classify_risk

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_events.json")


def alerts(*severities, **extra):
    return {"threat_detected": bool(severities),
            "alerts": [{"rule": f"r{i}", "severity": s, "message": "m", **extra}
                       for i, s in enumerate(severities)]}


def test_empty_alerts_score_zero():
    r = calculate_risk({"threat_detected": False, "alert_count": 0, "alerts": []})
    assert r["risk_score"] == 0
    assert r["risk_level"] == "LOW"
    assert r["alert_count"] == 0


def test_high_alert():
    r = calculate_risk(alerts("HIGH"))
    assert r["risk_score"] == 25
    assert r["risk_level"] == "MEDIUM"
    assert r["alert_count"] == 1


def test_critical_alert_per_policy():
    r = calculate_risk(alerts("CRITICAL"))
    assert r["risk_score"] == 40
    assert r["risk_level"] == "MEDIUM"


def test_multiple_alerts_combine():
    r = calculate_risk(alerts("HIGH", "CRITICAL"))
    assert r["risk_score"] == 65
    assert r["risk_level"] == "HIGH"
    assert r["risk_details"]["points_by_severity"]["HIGH"]["count"] == 1


def test_score_never_exceeds_100():
    r = calculate_risk(alerts(*["CRITICAL"] * 10))
    assert r["risk_score"] == 100
    assert r["risk_level"] == "CRITICAL"
    assert r["risk_details"]["score_capped"] is True
    assert r["risk_details"]["total_points"] == 400


def test_severity_is_case_insensitive():
    assert calculate_risk(alerts(" high "))["risk_score"] == 25


def test_unknown_severity_scores_zero_and_is_reported():
    r = calculate_risk(alerts("SEVERE", "HIGH"))
    assert r["risk_score"] == 25
    assert r["alert_count"] == 1
    ignored = r["risk_details"]["ignored_alerts"]
    assert len(ignored) == 1 and "SEVERE" in ignored[0]["reason"]


@pytest.mark.parametrize("bad", [
    None, "text", 42, 3.5, True, [], {}, {"alerts": None}, {"alerts": "nope"},
    {"alerts": 7}, {"alerts": [None, 3, "x", {}, []]},
    {"alerts": [{"severity": None}, {"severity": 5}, {"severity": ""}]},
    {"alerts": [{"rule": ["a"], "severity": ["HIGH"]}]},
])
def test_malformed_input_does_not_crash(bad):
    r = calculate_risk(bad)
    assert set(r) == {"risk_score", "risk_level", "alert_count", "risk_details"}
    assert isinstance(r["risk_score"], int) and 0 <= r["risk_score"] <= 100
    assert r["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_bare_alert_list_accepted():
    r = calculate_risk([{"rule": "x", "severity": "LOW"}])
    assert r["risk_score"] == 5


def test_same_event_id_and_rule_counted_once():
    a = {"rule": "x", "severity": "HIGH", "event_id": "e1"}
    r = calculate_risk({"alerts": [a, dict(a)]})
    assert r["risk_score"] == 25
    assert len(r["risk_details"]["duplicate_alerts"]) == 1


def test_same_rule_different_events_both_counted():
    r = calculate_risk({"alerts": [
        {"rule": "x", "severity": "HIGH", "event_id": "e1"},
        {"rule": "x", "severity": "HIGH", "event_id": "e2"}]})
    assert r["risk_score"] == 50


def test_same_rule_without_ids_not_discarded():
    r = calculate_risk({"alerts": [{"rule": "x", "severity": "HIGH"}] * 2})
    assert r["risk_score"] == 50


@pytest.mark.parametrize("score,level", [
    (0, "LOW"), (24, "LOW"), (25, "MEDIUM"), (49, "MEDIUM"),
    (50, "HIGH"), (74, "HIGH"), (75, "CRITICAL"), (100, "CRITICAL")])
def test_level_boundaries(score, level):
    assert classify_risk(score) == level


def test_custom_policy():
    r = calculate_risk(alerts("HIGH"), severity_weights={"HIGH": 60},
                       level_thresholds=[(0, "OK"), (50, "BAD")])
    assert r["risk_score"] == 60 and r["risk_level"] == "BAD"


@pytest.mark.parametrize("weights", [{}, {"HIGH": -1}, {"HIGH": "x"}, {"HIGH": True}, []])
def test_invalid_config_raises(weights):
    with pytest.raises(ValueError):
        calculate_risk(alerts("HIGH"), severity_weights=weights)


def test_input_not_modified():
    data = alerts("HIGH", "BOGUS")
    before = copy.deepcopy(data)
    calculate_risk(data)
    assert data == before


def test_sample_file():
    with open(SAMPLE, encoding="utf-8") as fh:
        detection = json.load(fh)["detection_result"]
    r = calculate_risk(detection)
    # HIGH(1002) + CRITICAL(1003, duplicate ignored) + HIGH(2001) = 25+40+25
    assert r["risk_score"] == 90
    assert r["risk_level"] == "CRITICAL"
    assert len(r["risk_details"]["duplicate_alerts"]) == 1