# correlator.py
import pandas as pd
import uuid
from datetime import timedelta

# Config (change if needed)
INPUT_NORMALIZED = "normalized_logs.csv"
OUTPUT_CORRELATED = "correlated_alerts.csv"
WINDOW_MINUTES = 10          # time window to consider (minutes)
THRESH_SUCCESS = 2           # >= this many failed_logins before a success -> incident
THRESH_NO_SUCCESS = 5        # >= this many failed_logins within window without success -> incident

MITRE_BRUTE = "T1110"        # MITRE ID for brute force / credential access

def load_logs(path):
    df = pd.read_csv(path, parse_dates=["timestamp"])
    # Ensure uniform event_type lowercasing
    df["event_type"] = df["event_type"].astype(str).str.lower()
    return df

def find_bruteforce_incidents(df):
    incidents = []
    window = timedelta(minutes=WINDOW_MINUTES)

    # consider all unique source_ip + user combos
    combos = df.groupby(["source_ip","user"])
    for (src, user), group in combos:
        # sort by time
        group = group.sort_values("timestamp").reset_index(drop=True)
        # find successful logins in this group
        successes = group[group["event_type"].str.contains("successful_login|login_success|login_successful", na=False)]
        fails = group[group["event_type"].str.contains("failed_login|login_failed|authentication_failed|failed", na=False)]

        # Rule A: failed(s) before a success within window
        for _, succ in successes.iterrows():
            t_succ = succ["timestamp"]
            # failed events strictly before success and within window
            prior_fails = fails[(fails["timestamp"] >= (t_succ - window)) & (fails["timestamp"] < t_succ)]
            cnt = len(prior_fails)
            if cnt >= THRESH_SUCCESS:
                incident = {
                    "incident_id": str(uuid.uuid4()),
                    "incident_type": "Brute Force (with success)",
                    "source_ip": src,
                    "user": user,
                    "start_time": prior_fails["timestamp"].min(),
                    "end_time": t_succ,
                    "event_count": cnt + 1,  # include the success
                    "events": list(prior_fails["raw_message"].astype(str)) + [str(succ["raw_message"])],
                    "severity": "high",
                    "mitre": MITRE_BRUTE,
                    "summary": f"{cnt} failed login(s) followed by a successful login for user '{user}' from {src} within {WINDOW_MINUTES} minutes."
                }
                incidents.append(incident)

        # Rule B: many fails within window (no success involved)
        # sliding window over fail events
        fail_times = list(fails["timestamp"])
        for i in range(len(fail_times)):
            start = fail_times[i]
            end = start + window
            # count fails in [start, end]
            cnt_window = sum(1 for t in fail_times if (t >= start and t <= end))
            if cnt_window >= THRESH_NO_SUCCESS:
                window_fails = fails[(fails["timestamp"] >= start) & (fails["timestamp"] <= end)]
                incident = {
                    "incident_id": str(uuid.uuid4()),
                    "incident_type": "Possible Brute Force (no success)",
                    "source_ip": src,
                    "user": user,
                    "start_time": start,
                    "end_time": end,
                    "event_count": cnt_window,
                    "events": list(window_fails["raw_message"].astype(str)),
                    "severity": "medium",
                    "mitre": MITRE_BRUTE,
                    "summary": f"{cnt_window} failed login(s) observed from {src} for user '{user}' between {start} and {end}."
                }
                incidents.append(incident)
                # avoid duplicate detection for same window start
    return incidents

def save_incidents(incidents, path):
    if not incidents:
        print("No incidents detected.")
        # create empty file
        pd.DataFrame(columns=["incident_id","incident_type","source_ip","user","start_time","end_time","event_count","severity","mitre","summary"]).to_csv(path, index=False)
        return
    rows = []
    for inc in incidents:
        rows.append({
            "incident_id": inc["incident_id"],
            "incident_type": inc["incident_type"],
            "source_ip": inc["source_ip"],
            "user": inc["user"],
            "start_time": inc["start_time"],
            "end_time": inc["end_time"],
            "event_count": inc["event_count"],
            "severity": inc["severity"],
            "mitre": inc["mitre"],
            "summary": inc["summary"],
            "events": " || ".join(inc["events"])
        })
    df = pd.DataFrame(rows)
    df.to_csv(path, index=False)
    print(f"Saved {len(rows)} incidents -> {path}")

def pretty_print(incidents):
    if not incidents:
        print("No incidents to show.")
        return
    for i, inc in enumerate(incidents, start=1):
        print("="*60)
        print(f"INCIDENT #{i}: {inc['incident_type']}")
        print(f"ID       : {inc['incident_id']}")
        print(f"Source   : {inc['source_ip']}")
        print(f"User     : {inc['user']}")
        print(f"Time     : {inc['start_time']} -> {inc['end_time']}")
        print(f"Count    : {inc['event_count']}")
        print(f"Severity : {inc['severity']}")
        print(f"MITRE    : {inc['mitre']}")
        print(f"Summary  : {inc['summary']}")
        print("Events   :")
        for ev in inc["events"]:
            print("  -", ev)
        print("="*60)
        print()

def main():
    df = load_logs(INPUT_NORMALIZED)
    incidents = find_bruteforce_incidents(df)
    pretty_print(incidents)
    save_incidents(incidents, OUTPUT_CORRELATED)

if __name__ == "__main__":
    main()
