import json
import pandas as pd
from dateutil import parser as dparser
from pathlib import Path

INPUT_JSON = "sample_test.json"  # our test file
INPUT_CSV = ""                   # leave blank, no CSV right now
OUTPUT_NORMALIZED = "normalized_logs.csv"


def safe_parse_time(t):
    try:
        return dparser.parse(t)
    except Exception:
        return pd.NaT

def normalize_record(rec):
    return {
        "timestamp": safe_parse_time(rec.get("timestamp") or rec.get("time") or ""),
        "source_ip": rec.get("source_ip") or rec.get("src_ip") or rec.get("src"),
        "dest_ip": rec.get("dest_ip") or rec.get("dst_ip") or rec.get("dst"),
        "user": rec.get("user") or rec.get("username") or rec.get("acct"),
        "event_type": rec.get("event_type") or rec.get("event") or rec.get("action"),
        "severity": rec.get("severity") or rec.get("level") or "unknown",
        "raw_message": rec.get("message") or rec.get("msg") or json.dumps(rec)
    }

def load_json(path):
    content = Path(path).read_text(encoding="utf-8")
    try:
        j = json.loads(content)
    except json.JSONDecodeError:
        # Handle newline-delimited JSON (NDJSON / JSONL)
        j = [json.loads(line) for line in content.splitlines() if line.strip()]

    data = []
    for row in j:
        data.append(normalize_record(row))  # <-- call normalize_record here
    return pd.DataFrame(data)


def load_csv(path):
    df = pd.read_csv(path)
    rows = []
    for _, r in df.iterrows():
        rows.append(normalize_record(r.to_dict()))
    return pd.DataFrame(rows)

def main():
    frames = []

    # Load JSON only if the variable is not empty AND file exists
    if INPUT_JSON and Path(INPUT_JSON).exists():
        print("Loading JSON logs...")
        frames.append(load_json(INPUT_JSON))

    # Load CSV only if the variable is not empty AND file exists
    if INPUT_CSV and Path(INPUT_CSV).exists():
        print("Loading CSV logs...")
        frames.append(load_csv(INPUT_CSV))

    if not frames:
        print("No input files found.")
        return


    df = pd.concat(frames, ignore_index=True)

    # Ensure timestamp column is consistent before sorting
    if "timestamp" in df.columns:
        # convert any timestamp (string, number, datetime) to datetime, coerce errors to NaT
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        # sort by timestamp safely
        df = df.sort_values(by="timestamp", na_position="last")
        # convert back to ISO string for CSV readability, empty string for NaT
        df["timestamp"] = df["timestamp"].apply(lambda x: x.isoformat() if pd.notna(x) else "")

    # fill remaining NaNs and write output
    df.fillna("", inplace=True)
    df.to_csv(OUTPUT_NORMALIZED, index=False)
    print(f"Normalized {len(df)} records -> {OUTPUT_NORMALIZED}")

if __name__ == "__main__":
    main()

