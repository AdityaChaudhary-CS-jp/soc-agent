# SOC Triage & Incident Response Agent (PS-07)
Agentic AI that investigates security alerts, enriches them with threat intel,
correlates related alerts into incidents, scores severity, and proposes
response actions that require human approval.

## Structure
- data/generate_data.py : builds synthetic alerts + mock threat intel
- app/agent/ : planner, investigation loop, scoring
- app/tools/ : threat-intel lookup, MITRE mapping, log search
- app/api/ : FastAPI backend (approvals, audit log, roles)
- tests/ , docs/

## Setup
pip install -r requirements.txt
python data/generate_data.py
