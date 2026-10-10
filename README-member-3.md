# Endpoint Security System - Member 3: Risk Scoring & Event Correlation

Standalone module. It needs only Python 3.8+ (tests need `pytest`) and does not
require Flask or any other member's code.

```
endpoint-security/
  scoring/risk_engine.py          calculate_risk(), classify_risk()
  correlation/event_correlator.py correlate_events(), parse_timestamp()
  tests/                          pytest suites for both modules
  examples/sample_events.json     sample detector result + events
```

## Setup and tests

```
pip install pytest
python -m pytest tests/ -v
```
Run from the `endpoint-security/` folder.

## 1. Risk engine

```python
from scoring.risk_engine import calculate_risk
result = calculate_risk(detection_result)
```

**Input** (Member 2's detector result, schema to be confirmed):
`{"threat_detected", "alert_count", "alerts": [{"rule", "severity", "message", "event_id"?}]}`

**Output** (always the same keys, never raises on bad data):

| Key | Meaning |
|---|---|
| `risk_score` | int, 0-100 |
| `risk_level` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `alert_count` | alerts that contributed points |
| `risk_details` | `total_points`, `score_capped`, `alerts_received`, `points_by_severity`, `scored_alerts`, `ignored_alerts` (with reasons), `duplicate_alerts`, `warnings`, `policy` |

### Scoring policy (PROPOSED - needs team approval)

| Severity | Points | | Score | Level |
|---|---|---|---|---|
| LOW | 5 | | 0-24 | LOW |
| MEDIUM | 15 | | 25-49 | MEDIUM |
| HIGH | 25 | | 50-74 | HIGH |
| CRITICAL | 40 | | 75-100 | CRITICAL |

`risk_score = min(100, sum of points)`. Severity matching ignores case and
surrounding spaces. Both tables are constants at the top of `risk_engine.py`
and can be overridden per call (`severity_weights=`, `level_thresholds=`).
Note that under this policy a single CRITICAL alert (40) is MEDIUM; the team
may want a higher CRITICAL weight.

### Handling bad data
- `None`, wrong types, missing/non-list `alerts`: score 0, reason in `warnings`.
- Non-object alerts, missing severity, unknown severity (e.g. `SEVERE`): worth
  0 points, listed in `ignored_alerts` with a reason. They are never guessed.
- Invalid weights/thresholds passed by the caller raise `ValueError`.

### Repeated alerts
An alert is a duplicate only if it has an `event_id` and the same
`(event_id, rule)` was already counted. Alerts without an `event_id` are always
counted, so separate events sharing a rule name are not discarded.

## 2. Event correlator

```python
from correlation.event_correlator import correlate_events
result = correlate_events(events, time_window_seconds=300)
```

**Event fields used** (aliases accepted; schema from Member 1 to be confirmed):
`event_id`/`id`, `timestamp`/`time`/`ts` (ISO-8601 or epoch seconds),
`pid`/`process_id`, `ppid`/`parent_pid`, `host`/`hostname`, `rule` (info only).

**Output**: `incidents`, `incident_count`, `correlated_event_ids`,
`standalone_event_ids`, `duplicate_count`, `duplicate_events`,
`invalid_event_count`, `event_count`, `warnings`, `parameters`.
Each incident has `incident_id` (stable hash of its events), `status`
(`possible_incident`), `event_ids`, `process_ids`, `hosts`, `rules`,
`first_seen`, `last_seen`, `correlation_links` (why events were joined) and a
note that it is not a confirmed attack.

**Rules**
1. Same PID, or parent-child (one event's `pid` = another's `ppid`).
2. Only if the two timestamps are within the window (default 300 s), because
   PIDs are reused by the OS.
3. Events from different hosts are never linked.
4. Missing/invalid timestamps: not linked (override: `allow_untimed_links=True`).
5. The rule/alert name is never used for linking.
6. Links are transitive; very long chains can therefore span more than one window.
7. Sibling processes (same parent) are not linked by themselves.

**Duplicates**: same `event_id` = same record (first kept; a warning is added if
the contents differ). Events with no ID are duplicates only if every field is
identical. Events with no ID get a reference like `unidentified-3`.

## Integration note

- **Member 2 (detector):** no change needed. Please add an `event_id` to each
  alert so alerts can be tied to events and de-duplicated safely.
- **Member 4 (dashboard):** call `calculate_risk(detection_result)` and show
  `risk_score`, `risk_level`, `alert_count`; call `correlate_events(events)` and
  list `incidents`. Both return plain JSON-serializable dicts.
- **Member 5 (response/reports):** use `risk_details` for the explanation in the
  PDF and `incidents[*].event_ids` / `correlation_links` for the timeline. Treat
  incidents as *possible* activity in report wording.

## Assumptions and decisions still open
- [ ] Member 1 event schema (field names, timestamp format)
- [ ] Member 2 alert schema, severity labels, rule names (current ones are from earlier examples)
- [ ] Approved weights and thresholds
- [ ] Definition of a duplicate event
- [ ] Correlation fields and time window
- [ ] Output structures expected by Members 4 and 5

## Git
```
git checkout -b feature/member-3-risk-correlation
python -m pytest tests/ -v
git add scoring correlation tests examples README.md
git commit -m "Implement risk scoring and event correlation"
git push -u origin feature/member-3-risk-correlation
```