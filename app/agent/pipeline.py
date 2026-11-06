"""One full run for an incident: investigate -> guardrails -> save -> queue
actions for human approval. Used by run_incident.py and the dashboard."""
from app.agent import approvals, store
from app.agent.audit import AuditLog
from app.agent.guardrails import apply_guardrails
from app.agent.investigator import investigate
from app.agent.llm_retry import ResilientClient

KEEP = ("id", "timestamp", "type", "raw_severity", "src_ip", "host",
        "user", "description", "mitre_hint")

# Told to the AI for a lone alert. It is a fact computed by correlation.py.
STANDALONE_NOTE = (
    "The correlation engine linked no other alerts to this one. It links "
    "alerts that share a non-clean external IP within 60 minutes, or the "
    "same host and user within 15 minutes at medium/high severity.")


def pseudo_incident(alert: dict) -> dict:
    """Wrap one standalone alert so it can be scored and investigated
    like an incident (used by evaluation.py and run_agent.py)."""
    return {"incident_id": alert["id"], "alert_count": 1,
            "start": alert["timestamp"], "end": alert["timestamp"],
            "ips": [alert["src_ip"]], "hosts": [alert["host"]],
            "users": [alert["user"]],
            "mitre_techniques": [alert["mitre_hint"]] if alert["mitre_hint"] else [],
            "alerts": [alert]}


def build_case(incident: dict) -> dict:
    """The compact description of an incident that the AI receives."""
    single = incident["alert_count"] == 1
    case = {
        "case_type": "standalone_alert" if single else "incident",
        "incident_id": incident["incident_id"],
        "alert_count": incident["alert_count"],
        "start": incident["start"],
        "end": incident["end"],
        "alerts": [{k: a[k] for k in KEEP} for a in incident["alerts"]],
    }
    if single:
        case["correlation_note"] = STANDALONE_NOTE
    return case


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
