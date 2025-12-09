# ip_reputation.py
import os, requests, pandas as pd
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_KEY")
INPUT = "correlated_alerts.csv"
OUTPUT = "enriched_alerts.csv"

def check_ip(ip):
    if not API_KEY:
        return "No API key"
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            if score >= 75:
                return f"Malicious (Score {score})"
            elif score >= 25:
                return f"Suspicious (Score {score})"
            else:
                return f"Clean (Score {score})"
        return f"Error {r.status_code}"
    except Exception as e:
        return f"Error: {e}"

def enrich():
    df = pd.read_csv(INPUT)
    df["ip_reputation"] = df["source_ip"].apply(check_ip)
    df.to_csv(OUTPUT, index=False)
    print(f"Enriched {len(df)} records -> {OUTPUT}")
    print(df[["source_ip","ip_reputation","severity","incident_type"]])

if __name__ == "__main__":
    enrich()
