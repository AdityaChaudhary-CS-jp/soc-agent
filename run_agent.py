"""Run the agent on one alert.   Usage: python run_agent.py ALR-008"""
import json
import sys
from google import genai

from app.config import get_api_key
from app.agent.audit import AuditLog
from app.agent.investigator import investigate
from app.agent.llm_retry import ResilientClient
from app.tools.search_logs import search_logs

alert_id = sys.argv[1] if len(sys.argv) > 1 else "ALR-008"
matches = [a for a in search_logs(limit=1000) if a["id"] == alert_id]
if not matches:
    raise SystemExit(f"Alert {alert_id} not found in data/alerts.json")

audit = AuditLog(alert_id)
client = ResilientClient(genai.Client(api_key=get_api_key()), audit)

print(f"=== Investigating {alert_id} ===")
report = investigate(matches[0], client, audit)
audit.add("report", report=report)
audit.save()

print("\n=== FINAL REPORT ===")
print(json.dumps(report, indent=2))
print("\nAudit log saved to logs/audit_log.jsonl")
