"""Generates SYNTHETIC alerts and mock threat intel (no real data/PII)."""
import json, random
from datetime import datetime, timedelta

random.seed(42)
BASE = datetime(2026, 11, 1, 9, 0, 0)

# Mock threat intel (stands in for VirusTotal / AbuseIPDB cached data)
INTEL = {
    "203.0.113.45": {"reputation": "malicious", "score": 92, "tags": ["brute-force", "scanner"]},
    "198.51.100.7": {"reputation": "malicious", "score": 88, "tags": ["c2", "malware"]},
    "192.0.2.99":   {"reputation": "suspicious", "score": 55, "tags": ["tor-exit"]},
    "203.0.113.200":{"reputation": "clean", "score": 3, "tags": []},
    "198.51.100.23":{"reputation": "unknown", "score": None, "tags": []},  # missing data case
}
HOSTS = ["web-01", "db-01", "hr-laptop-07", "dev-ws-12", "mail-01", "fileserver-02"]
USERS = ["asha", "rohan", "meera", "admin", "svc_backup"]

alerts, n = [], 0
def add(minutes, source, atype, sev, src_ip, host, user, desc, mitre):
    global n; n += 1
    alerts.append({
        "id": f"ALR-{n:03d}",
        "timestamp": (BASE + timedelta(minutes=minutes)).isoformat(),
        "source": source, "type": atype, "raw_severity": sev,
        "src_ip": src_ip, "host": host, "user": user,
        "description": desc, "mitre_hint": mitre,
    })

# Chain 1: brute force -> successful login -> privilege escalation (true incident)
t = 0
for i in range(6):
    add(t+i, "auth", "failed_login", "low", "203.0.113.45", "web-01", "admin",
        "Failed SSH login for admin", "T1110")
add(t+8, "auth", "successful_login_after_failures", "medium", "203.0.113.45", "web-01", "admin",
    "Successful login after 6 failures", "T1078")
add(t+12, "endpoint", "privilege_escalation", "high", "203.0.113.45", "web-01", "admin",
    "sudo to root from unusual session", "T1068")

# Chain 2: phishing -> malware -> C2 beacon
t = 90
add(t, "email", "phishing_link_click", "medium", "192.0.2.99", "hr-laptop-07", "meera",
    "User clicked link flagged as phishing", "T1566")
add(t+3, "endpoint", "malware_detected", "high", "198.51.100.7", "hr-laptop-07", "meera",
    "Suspicious executable dropped in temp folder", "T1204")
for i in range(3):
    add(t+6+i*5, "firewall", "c2_beacon", "high", "198.51.100.7", "hr-laptop-07", "meera",
        "Periodic outbound connection to known bad IP", "T1071")

# Chain 3: data exfil with ambiguous/conflicting evidence
t = 200
add(t, "firewall", "large_outbound_transfer", "medium", "198.51.100.23", "fileserver-02", "svc_backup",
    "4.2 GB outbound transfer at 02:00", "T1041")
add(t+5, "endpoint", "scheduled_backup_job", "low", "198.51.100.23", "fileserver-02", "svc_backup",
    "Backup job ran (could explain transfer)", None)

# Noise / false positives
noise = [("auth", "failed_login", "low", "T1110", "Single failed login"),
         ("firewall", "port_scan", "low", "T1046", "Internal vulnerability scan"),
         ("endpoint", "usb_inserted", "low", None, "USB device connected"),
         ("web", "waf_block", "low", "T1190", "WAF blocked suspicious request")]
for i in range(30):
    s, ty, sv, m, d = random.choice(noise)
    add(random.randint(0, 300), s, ty, sv,
        random.choice(["203.0.113.200", "10.0.0." + str(random.randint(2, 50))]),
        random.choice(HOSTS), random.choice(USERS), d, m)

alerts.sort(key=lambda a: a["timestamp"])
json.dump(alerts, open("data/alerts.json", "w"), indent=2)
json.dump(INTEL, open("data/threat_intel.json", "w"), indent=2)
print(f"Wrote {len(alerts)} alerts and {len(INTEL)} intel records")
