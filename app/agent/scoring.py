"""Rule-based severity score (0-100) for an incident.

The score is plain arithmetic, so it is explainable and repeatable. It is
used to cross-check what the AI says (see guardrails.py).

  intel      up to 40  best threat-intel score among the incident's IPs x 0.4
  stage      up to 30  furthest MITRE attack stage reached (rank / 6 x 30)
  volume     up to 20  number of correlated alerts (max 10) x 2
  severity   up to 10  raw severity: high = 10, medium = 5
"""
from app.agent.correlation import safe_lookup
from app.tools.mitre_map import mitre_map

LEVELS = ["low", "medium", "high", "critical"]


def level_for(score: float) -> str:
    if score >= 70:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def score_incident(incident: dict) -> dict:
    best_intel, missing_ips = 0, []
    for ip in incident["ips"]:
        info = safe_lookup(ip)
        if info["status"] == "ok":
            best_intel = max(best_intel, info["score"])
        elif info["status"] in ("no_data", "not_found"):
            missing_ips.append(ip)

    stage_rank, stage_name = 0, "none"
    for tid in incident["mitre_techniques"]:
        m = mitre_map(tid)
        if m["found"] and m["stage_rank"] > stage_rank:
            stage_rank, stage_name = m["stage_rank"], m["stage"]

    severities = {a["raw_severity"] for a in incident["alerts"]}
    severity_points = 10 if "high" in severities else 5 if "medium" in severities else 0

    breakdown = {
        "intel": round(best_intel * 0.4, 1),
        "stage": round(stage_rank / 6 * 30, 1),
        "volume": min(incident["alert_count"], 10) * 2,
        "severity": severity_points,
    }
    total = round(sum(breakdown.values()), 1)
    return {
        "score": total,
        "level": level_for(total),
        "breakdown": breakdown,
        "highest_stage": stage_name,
        "stage_rank": stage_rank,
        "missing_intel_ips": missing_ips,
    }
