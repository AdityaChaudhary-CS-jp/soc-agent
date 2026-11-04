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
from app.agent.pipeline import run_pipeline
from app.config import get_api_key

client = genai.Client(api_key=get_api_key())
print(f"\n=== Investigating {incident_id} ===")
report, queued = run_pipeline(incident, score, client)

print("\n=== FINAL REPORT ===")
print(json.dumps(report, indent=2))
print("\nAudit log saved to logs/audit_log.jsonl")
print(f"{len(queued)} proposed action(s) are waiting for human approval.")
print("See them with: python approve.py list")
print(f"Make a report file with: python make_report.py {incident_id}")
