**🧠 SOC Alert Analyzer \& Correlator**



**A lightweight Python-based SOC assistant that parses, correlates, enriches, and alerts on suspicious activity — built to help analysts reduce alert fatigue and automate triage.**



**⚙️ Features**



**Log Normalization: Reads raw JSON/CSV logs and converts them into a consistent structure.**



**Correlation Engine: Detects brute-force patterns and groups related alerts.**



**MITRE ATT\&CK Mapping: Tags alerts with relevant MITRE techniques (e.g., T1110 – Brute Force).**



**Threat Intelligence Enrichment: Integrates with AbuseIPDB API for IP reputation checks.**



**Real-Time Alerting: Sends high-severity incidents directly to Telegram.**



**Analyst Report Generator: Produces human-readable SOC-style incident summaries and recommended playbook actions.**



**🧰 Tech Stack**



**Language: Python**



**Libraries: pandas, requests, python-dotenv, python-dateutil**



**APIs: AbuseIPDB, Telegram Bot API**



**Environment: Windows PowerShell, Virtual Environment (venv)**



**📁 Project Structure**

**SOC\_Project/**

**│**

**├── parser\_normalize.py      → Converts raw logs into normalized format**

**├── correlator.py            → Detects brute-force and creates correlated alerts**

**├── report\_generator.py      → Creates human-readable SOC reports**

**├── ip\_reputation.py         → Enriches alerts with AbuseIPDB IP reputation**

**├── telegram\_alert.py        → Sends high-severity alerts to Telegram**

**├── sample\_logs.json         → Example log data**

**├── .env                     → Stores API keys (AbuseIPDB + Telegram)**

**├── requirements.txt         → Python dependencies**

**└── README.md                → Project documentation**



**🚀 How to Run**



**Clone or copy the folder.**



**Create a virtual environment:**



**python -m venv venv**

**.\\venv\\Scripts\\Activate.ps1**

**pip install -r requirements.txt**





**Add your API keys in .env:**



**ABUSEIPDB\_KEY=your\_abuseipdb\_api\_key**

**TELEGRAM\_BOT\_TOKEN=your\_bot\_token**

**TELEGRAM\_CHAT\_ID=your\_chat\_id**





**Run everything with one command:**



**.\\run\_all.ps1**



**🧾 Sample Output**

**INCIDENT REPORT #1**

**Type: Brute Force (with success)**

**Source IP: 192.168.1.10 (Clean)**

**User: admin**

**Severity: HIGH**

**MITRE: T1110 - Brute Force**

**Summary: 2 failed logins followed by success.**

**✅ Alert sent to Telegram**



**👤 Author**



**Devesh Kapase**

**SOC Analyst | Cybersecurity Enthusiast**

**GitHub**

www.linkedin.com/in/dev4921




