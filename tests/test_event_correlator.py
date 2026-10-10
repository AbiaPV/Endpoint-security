import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from correlation.event_correlator import correlate_events, parse_timestamp

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_events.json")
T0 = 1_800_000_000


def ev(eid, pid, ppid=None, t=0, **extra):
    e = {"event_id": eid, "pid": pid, "ppid": ppid, "timestamp": T0 + t}
    e.update(extra)
    return e


def test_empty_inputs():
    for empty in ([], None, (), "nope", 5, {}):
        r = correlate_events(empty)
        assert r["incident_count"] == 0 and r["incidents"] == []
        assert r["duplicate_count"] == 0 and r["event_count"] == 0


def test_single_event_is_standalone():
    r = correlate_events([ev("a", 10, 1)])
    assert r["incidents"] == []
    assert r["standalone_event_ids"] == ["a"]


def test_parent_child_chain_forms_one_incident():
    r = correlate_events([ev("a", 10, 1, 0), ev("b", 20, 10, 30), ev("c", 30, 20, 60)])
    assert r["incident_count"] == 1
    inc = r["incidents"][0]
    assert inc["event_ids"] == ["a", "b", "c"]
    assert inc["status"] == "possible_incident"
    assert "not a confirmed attack" in inc["note"]
    assert r["correlated_event_ids"] == ["a", "b", "c"]
    assert r["standalone_event_ids"] == []
    assert {l["type"] for l in inc["correlation_links"]} == {"parent_child"}


def test_same_pid_within_window_linked():
    r = correlate_events([ev("a", 10, 1, 0), ev("b", 10, 1, 100)])
    assert r["incident_count"] == 1
    assert r["incidents"][0]["correlation_links"][0]["type"] == "same_pid"


def test_unrelated_events_stay_separate():
    r = correlate_events([ev("a", 10, 1, 0), ev("b", 20, 2, 5)])
    assert r["incident_count"] == 0
    assert r["standalone_event_ids"] == ["a", "b"]


def test_same_rule_name_alone_does_not_merge():
    r = correlate_events([ev("a", 10, 1, 0, rule="powershell"),
                          ev("b", 20, 2, 1, rule="powershell")])
    assert r["incident_count"] == 0


def test_duplicate_event_id_counted_and_removed():
    r = correlate_events([ev("a", 10, 1), ev("a", 10, 1), ev("b", 20, 10, 5)])
    assert r["duplicate_count"] == 1
    assert r["event_count"] == 2
    assert r["incidents"][0]["event_ids"] == ["a", "b"]


def test_same_id_different_content_warns():
    r = correlate_events([ev("a", 10, 1), ev("a", 99, 1)])
    assert r["duplicate_count"] == 1
    assert any("different contents" in w for w in r["warnings"])


def test_identical_records_without_id_are_duplicates():
    e = {"pid": 10, "timestamp": T0, "process_name": "x"}
    r = correlate_events([e, dict(e)])
    assert r["duplicate_count"] == 1 and r["event_count"] == 1


def test_outside_time_window_stays_separate():
    events = [ev("a", 10, 1, 0), ev("b", 10, 1, 3600)]
    assert correlate_events(events)["incident_count"] == 0
    assert correlate_events(events, time_window_seconds=7200)["incident_count"] == 1


def test_different_hosts_not_merged():
    r = correlate_events([ev("a", 10, 1, 0, host="A"), ev("b", 10, 1, 1, host="B")])
    assert r["incident_count"] == 0


def test_missing_event_id_gets_generated_reference():
    r = correlate_events([{"pid": 10, "timestamp": T0}, ev("b", 20, 10, 5)])
    assert r["incident_count"] == 1
    assert "unidentified-0" in r["incidents"][0]["event_ids"]


def test_missing_timestamp_not_linked_by_default():
    events = [ev("a", 10, 1), {"event_id": "b", "pid": 20, "ppid": 10}]
    assert correlate_events(events)["incident_count"] == 0
    assert correlate_events(events, allow_untimed_links=True)["incident_count"] == 1


@pytest.mark.parametrize("junk", [None, "x", 7, ["a"], {"pid": "abc", "timestamp": "garbage"},
                                  {"pid": True, "ppid": -4, "timestamp": float("nan")}])
def test_malformed_events_do_not_crash(junk):
    r = correlate_events([junk, ev("a", 10, 1)])
    assert "a" in r["standalone_event_ids"] + r["correlated_event_ids"]


def test_invalid_window_raises():
    with pytest.raises(ValueError):
        correlate_events([], time_window_seconds=-1)


def test_input_not_modified():
    data = [ev("a", 10, 1), ev("a", 10, 1), ev("b", 20, 10)]
    before = copy.deepcopy(data)
    correlate_events(data)
    assert data == before


def test_timestamp_formats_equivalent():
    assert parse_timestamp("2026-10-10T10:00:00Z") == parse_timestamp("2026-10-10T10:00:00+00:00")
    assert parse_timestamp("2026-10-10T10:00:00") == parse_timestamp("2026-10-10T10:00:00Z")
    assert parse_timestamp("1800000000") == 1_800_000_000.0
    for bad in (None, "", "nope", True, float("inf")):
        assert parse_timestamp(bad) is None


def test_sample_file():
    with open(SAMPLE, encoding="utf-8") as fh:
        events = json.load(fh)["events"]
    r = correlate_events(events)
    assert r["duplicate_count"] == 1
    assert r["incident_count"] == 1
    assert r["incidents"][0]["event_ids"] == ["evt-1001", "evt-1002", "evt-1003"]
    # same rule on another host, and same PID hours later, stay separate
    assert r["standalone_event_ids"] == ["evt-2001", "evt-3001"]