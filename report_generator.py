# report_generator.py
import pandas as pd

MITRE_INFO = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts with weak credentials.",
        "recommended_actions": [
            "Reset affected user's password immediately.",
            "Block source IP temporarily at firewall or SIEM.",
            "Check for lateral movement attempts after successful login.",
            "Review authentication logs for similar patterns."
        ]
    }
}

def generate_report(csv_path):
    df = pd.read_csv(csv_path)
    if df.empty:
        print("No incidents found in CSV.")
        return

    for i, row in df.iterrows():
        mitre = row.get("mitre", "")
        mitre_info = MITRE_INFO.get(mitre, {})
        print("=" * 70)
        print(f"INCIDENT REPORT #{i+1}")
        print("-" * 70)
        print(f"Incident Type : {row['incident_type']}")
        print(f"Source IP     : {row['source_ip']}")
        print(f"User          : {row['user']}")
        print(f"Start Time    : {row['start_time']}")
        print(f"End Time      : {row['end_time']}")
        print(f"Severity      : {row['severity'].upper()}")
        print(f"MITRE ID      : {mitre} - {mitre_info.get('name','Unknown')}")
        print(f"Tactic        : {mitre_info.get('tactic','Unknown')}")
        print(f"Description   : {mitre_info.get('description','No info available.')}")
        print(f"\nSummary       : {row['summary']}")
        print("\nRecommended Actions:")
        for action in mitre_info.get("recommended_actions", ["No playbook available."]):
            print(f"  - {action}")
        print("=" * 70)
        print("\n")

if __name__ == "__main__":
    generate_report("correlated_alerts.csv")
