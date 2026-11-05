"""One full run for an incident: investigate -> guardrails -> save -> queue
actions for human approval. Used by run_incident.py and the dashboard."""
from app.agent import approvals, store
from app.agent.audit import AuditLog
from app.agent.guardrails import apply_guardrails
from app.agent.investigator import investigate
from app.agent.llm_retry import ResilientClient

KEEP = ("id", "timestamp", "type", "raw_severity", "src_ip", "host",
        "user", "description", "mitre_hint")


def build_case(incident: dict) -> dict:
    """The compact description of an incident that the AI receives."""
    return {
        "case_type": "incident",
        "incident_id": incident["incident_id"],
        "alert_count": incident["alert_count"],
        "start": incident["start"],
        "end": incident["end"],
        "alerts": [{k: a[k] for k in KEEP} for a in incident["alerts"]],
    }


def run_pipeline(incident: dict, score: dict, client, max_steps: int = 8):
    """Returns (report, list_of_queued_action_ids)."""
    audit = AuditLog(incident["incident_id"])
    audit.add("rule_based_score", **score)
    client = ResilientClient(client, audit)   # retries and model fallback

    report = investigate(build_case(incident), client, audit, max_steps)
    report = apply_guardrails(report, score, audit)
    audit.add("report", report=report)
    store.save_report(incident["incident_id"], report)
    queued = approvals.submit_actions(incident, report, audit)
    audit.save()
    return report, queued
