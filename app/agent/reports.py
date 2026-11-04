"""Incident report generator: turns everything we know about an incident
into a readable Markdown document (timeline, evidence, score, approvals)."""
from app.agent import approvals, store
from app.agent.correlation import correlate
from app.agent.scoring import score_incident
from app.tools.mitre_map import mitre_map


def _bullets(items, empty="None recorded."):
    return "\n".join(f"- {i}" for i in items) if items else empty


def build_report_md(incident, score, ai, actions, events) -> str:
    out = [f"# Incident Report: {incident['incident_id']}", ""]

    out += ["## Overview", "",
            f"- **Window:** {incident['start']} to {incident['end']}",
            f"- **Alerts:** {incident['alert_count']}",
            f"- **Hosts:** {', '.join(incident['hosts'])}",
            f"- **Source IPs:** {', '.join(incident['ips'])}",
            f"- **Users:** {', '.join(incident['users'])}", ""]

    b = score["breakdown"]
    out += ["## Rule-based severity score", "",
            f"**{score['score']} / 100 ({score['level']})**. Furthest attack stage: "
            f"{score['highest_stage']}.", "",
            "| Component | Points |", "|---|---|",
            f"| Threat intel | {b['intel']} |", f"| Attack stage | {b['stage']} |",
            f"| Alert volume | {b['volume']} |", f"| Raw severity | {b['severity']} |", ""]
    if score["missing_intel_ips"]:
        out += [f"> No threat-intel data for: {', '.join(score['missing_intel_ips'])}", ""]

    out += ["## Timeline", "", "| Time | Alert | Type | Host | Source IP | Description |",
            "|---|---|---|---|---|---|"]
    for a in incident["alerts"]:
        out.append(f"| {a['timestamp']} | {a['id']} | {a['type']} | {a['host']} "
                   f"| {a['src_ip']} | {a['description']} |")
    out.append("")

    techniques = []
    for tid in incident["mitre_techniques"]:
        m = mitre_map(tid)
        techniques.append(f"{tid}: {m['name']} ({m['stage']})" if m["found"] else tid)
    out += ["## MITRE ATT&CK techniques", "", _bullets(techniques), ""]

    out += ["## AI investigation", ""]
    if ai is None:
        out += ["_This incident has not been investigated by the agent yet._", ""]
    else:
        r = ai["report"]
        out += [f"- **Verdict:** {r.get('verdict')}",
                f"- **Severity:** {r.get('severity')}",
                f"- **Confidence:** {r.get('confidence')}",
                f"- **Investigated at:** {ai['created_at']}", "",
                "### Summary", "", r.get("summary", ""), "",
                "### Evidence", "", _bullets(r.get("evidence", [])), "",
                "### Uncertainties", "", _bullets(r.get("uncertainties", [])), ""]
        if r.get("guardrail_notes"):
            out += ["### Guardrail corrections", "", _bullets(r["guardrail_notes"]), ""]

    out += ["## Proposed actions and approvals", ""]
    if not actions:
        out += ["No actions proposed.", ""]
    else:
        out += ["| # | Action | Needs | Status | Decided by | Result |",
                "|---|---|---|---|---|---|"]
        for a in actions:
            needs = "admin" if a["sensitive"] else "analyst"
            who = f"{a['decided_by']} ({a['decided_role']})" if a["decided_by"] else "-"
            out.append(f"| {a['id']} | {a['action']} | {needs} | {a['status']} "
                       f"| {who} | {a['execution_result'] or '-'} |")
        out.append("")

    calls = sum(1 for e in events if e["event"] == "tool_call")
    retries = sum(1 for e in events if e["event"] == "tool_retry")
    denied = sum(1 for e in events if e["event"] == "approval_denied")
    out += ["## Audit summary", "",
            f"- Tool calls made by the agent: {calls}",
            f"- Tool retries after failures: {retries}",
            f"- Refused approval attempts: {denied}",
            f"- Total audit events: {len(events)}", "",
            "_All response actions are simulated. No real systems were modified._", ""]
    return "\n".join(out)


def gather_markdown(incident_id: str) -> str:
    """Collect everything for one incident and build its report."""
    incidents, _ = correlate()
    incident = next((i for i in incidents if i["incident_id"] == incident_id), None)
    if incident is None:
        raise KeyError(f"{incident_id} not found")
    return build_report_md(
        incident, score_incident(incident), store.latest_report(incident_id),
        approvals.list_actions(incident_id=incident_id),
        store.read_audit_events(incident_id))
