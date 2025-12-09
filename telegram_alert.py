# telegram_alert.py
import os, pandas as pd, requests
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
INPUT = "enriched_alerts.csv"

def send_telegram(msg):
    if not BOT_TOKEN or not CHAT_ID:
        print("Telegram not configured.")
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": msg}
    try:
        r = requests.post(url, data=payload, timeout=10)
        if r.status_code == 200:
            print("✅ Alert sent to Telegram")
        else:
            print(f"⚠️  Telegram API error: {r.status_code}")
    except Exception as e:
        print(f"Error sending alert: {e}")

def alert_high_severity():
    df = pd.read_csv(INPUT)
    high = df[df["severity"].str.lower() == "high"]
    if high.empty:
        print("No high-severity incidents to alert.")
        return
    for _, row in high.iterrows():
        msg = (
            f"🚨 SOC ALERT 🚨\n"
            f"Type: {row['incident_type']}\n"
            f"Source IP: {row['source_ip']} ({row.get('ip_reputation','')})\n"
            f"User: {row.get('user','N/A')}\n"
            f"Severity: {row['severity']}\n"
            f"MITRE: {row.get('mitre','N/A')}\n"
            f"Summary: {row.get('summary','N/A')}\n"
            f"Time: {row.get('start_time','')} → {row.get('end_time','')}"
        )
        send_telegram(msg)

if __name__ == "__main__":
    alert_high_severity()
