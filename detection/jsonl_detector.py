import ast
import json
from pathlib import Path

from detection.detector import detect_threat

# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "events.jsonl"
OUTPUT_FILE = BASE_DIR / "detection_results.json"


def read_text(path):
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-16"):
        try:
            return raw.decode(encoding)
        except UnicodeError:
            continue
    return raw.decode("utf-8", errors="ignore")


def load_events(path):
    """Load events from JSONL, multi-line JSON objects, or a JSON list."""
    text = read_text(path)
    decoder = json.JSONDecoder()
    events = []
    index = 0

    try:
        while index < len(text):
            # skip spaces/newlines between objects
            while index < len(text) and text[index].isspace():
                index += 1
            if index >= len(text):
                break
            obj, index = decoder.raw_decode(text, index)
            if isinstance(obj, list):
                events.extend(o for o in obj if isinstance(o, dict))
            elif isinstance(obj, dict):
                events.append(obj)
        return events
    except json.JSONDecodeError:
        pass

    # Fallback: one event per line (also accepts Python-style dicts)
    events = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            try:
                obj = ast.literal_eval(line)
            except (ValueError, SyntaxError):
                print(f"Skipping invalid line {line_number}: {line[:60]}")
                continue
        if isinstance(obj, dict):
            events.append(obj)
    return events


def run_detection():
    if not INPUT_FILE.exists():
        print(f"Input file not found: {INPUT_FILE}")
        return []

    events = load_events(INPUT_FILE)
    results = []

    for event in events:
        result = detect_threat(event)
        results.append({"event": event, **result})

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    threats = sum(1 for r in results if r["threat_detected"])
    print(f"Processed {len(results)} events, {threats} with threats.")
    print(f"Results saved to {OUTPUT_FILE}")
    return results


def main():
    run_detection()


if __name__ == "__main__":
    main()