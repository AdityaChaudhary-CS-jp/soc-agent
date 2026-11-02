"""Group alerts into incidents, score them, and investigate one with the AI.

  python run_incident.py            -> list incidents and scores (no AI call)
  python run_incident.py INC-001    -> investigate that incident
"""
import json
import sys

from app.agent.correlation import correlate
from app.agent.scoring import score_incident

incidents, standalone = correlate()
scored = {inc["incident_id"]: (inc, score_incident(inc)) for inc in incidents}

print(f"{len(incidents)} incidents found; {len(standalone)} standalone alerts\n")
for inc, sc in scored.values():
    print(f"{inc['incident_id']}  alerts={inc['alert_count']:<2} "
          f"score={sc['score']:<5} level={sc['level']:<8} "
          f"stage={sc['highest_stage']}")
    print(f"           hosts={inc['hosts']} ips={inc['ips']}")
    if sc["missing_intel_ips"]:
        print(f"           ! no threat intel for {sc['missing_intel_ips']}")

if len(sys.argv) < 2:
    print("\nTo investigate one, run: python run_incident.py INC-001")
    raise SystemExit

incident_id = sys.argv[1].upper()
if incident_id not in scored:
    raise SystemExit(f"{incident_id} not found. Pick one from the list above.")
incident, score = scored[incident_id]

# Imported here so that listing incidents works without the AI library.
from google import genai
from app.agent import approvals
from app.agent.audit import AuditLog
from app.agent.guardrails import apply_guardrails
from app.agent.investigator import investigate
from app.config import get_api_key

KEEP = ("id", "timestamp", "type", "raw_severity", "src_ip", "host",
        "user", "description", "mitre_hint")
case = {
    "case_type": "incident",
    "incident_id": incident_id,
    "alert_count": incident["alert_count"],
    "start": incident["start"],
    "end": incident["end"],
    "alerts": [{k: a[k] for k in KEEP} for a in incident["alerts"]],
}

client = genai.Client(api_key=get_api_key())
audit = AuditLog(incident_id)
audit.add("rule_based_score", **score)

print(f"\n=== Investigating {incident_id} ===")
report = investigate(case, client, audit)
report = apply_guardrails(report, score, audit)
audit.add("report", report=report)
queued = approvals.submit_actions(incident, report, audit)
audit.save()

print("\n=== FINAL REPORT ===")
print(json.dumps(report, indent=2))
print("\nAudit log saved to logs/audit_log.jsonl")
print(f"{len(queued)} proposed action(s) are waiting for human approval.")
print("See them with: python approve.py list")
