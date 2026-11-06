"""Investigate ONE alert the same way the accuracy check does.

  python run_agent.py ALR-039

It shows what the AI said on its own, then the final verdict after the
guardrails. If the alert belongs to an incident, the whole incident is
investigated. Nothing is queued for approval, nothing is saved to the
database, and the audit log file is not touched (events are only printed).
"""
import copy
import json
import sys

from google import genai

from app.config import get_api_key
from app.agent.audit import AuditLog
from app.agent.correlation import correlate
from app.agent.guardrails import apply_guardrails
from app.agent.investigator import investigate
from app.agent.llm_retry import ResilientClient
from app.agent.pipeline import build_case, pseudo_incident
from app.agent.scoring import score_incident

alert_id = (sys.argv[1] if len(sys.argv) > 1 else "ALR-039").upper()

incidents, standalone = correlate()
case = next((i for i in incidents
             if alert_id in {a["id"] for a in i["alerts"]}), None)
if case is not None:
    print(f"{alert_id} is part of {case['incident_id']}; investigating the whole incident.")
else:
    alert = next((a for a in standalone if a["id"] == alert_id), None)
    if alert is None:
        raise SystemExit(f"Alert {alert_id} not found in data/alerts.json")
    case = pseudo_incident(alert)

score = score_incident(case)
print(f"Rule-based score: {score['score']} ({score['level']}); "
      f"known-bad IPs: {score['known_bad_ips'] or 'none'}; "
      f"highest raw severity: {score['max_raw_severity']}")

audit = AuditLog(case["incident_id"])          # prints events; never saved
client = ResilientClient(genai.Client(api_key=get_api_key()), audit)

print(f"\n=== Investigating {case['incident_id']} ===")
report = investigate(build_case(case), client, audit)
final = apply_guardrails(copy.deepcopy(report), score)

print("\n=== RESULT ===")
print(f"AI alone:        {report.get('verdict')}  (confidence {report.get('confidence')})")
print(f"After guardrails: {final['verdict']}  (confidence {final['confidence']})")
print(f"Models used:     {', '.join(client.models.used) or 'unknown'}")
for n in final["guardrail_notes"]:
    print("Guardrail:", n)
print("\n=== FINAL REPORT ===")
print(json.dumps(final, indent=2))
