"""Rule-based severity score (0-100) for an incident.

The score is plain arithmetic, so it is explainable and repeatable. It is
used to cross-check what the AI says (see guardrails.py).

  intel      up to 40  best threat-intel score among the incident's IPs x 0.4
  stage      up to 30  furthest MITRE attack stage reached (rank / 6 x 30)
  volume     up to 20  number of correlated alerts (max 10) x 2
  severity   up to 10  raw severity: high = 10, medium = 5

Besides the number, the result also lists facts the guardrails need:
  known_bad_ips      IPs that threat intel calls malicious or suspicious
  max_raw_severity   the highest raw severity among the alerts (low/medium/high)
"""
from app.agent.correlation import safe_lookup
from app.tools.mitre_map import mitre_map

LEVELS = ["low", "medium", "high", "critical"]

# An IP counts as "known bad" if threat intel calls it one of these, or
# gives it a score at or above KNOWN_BAD_SCORE.
BAD_REPUTATIONS = ("malicious", "suspicious")
KNOWN_BAD_SCORE = 50


def level_for(score: float) -> str:
    if score >= 70:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def score_incident(incident: dict) -> dict:
    best_intel, missing_ips, known_bad_ips = 0, [], []
    for ip in incident["ips"]:
        info = safe_lookup(ip)
        if info["status"] == "ok":
            ip_score = info.get("score") or 0
            best_intel = max(best_intel, ip_score)
            if (info.get("reputation") in BAD_REPUTATIONS
                    or ip_score >= KNOWN_BAD_SCORE):
                known_bad_ips.append(ip)
        elif info["status"] in ("no_data", "not_found"):
            missing_ips.append(ip)

    stage_rank, stage_name = 0, "none"
    for tid in incident["mitre_techniques"]:
        m = mitre_map(tid)
        if m["found"] and m["stage_rank"] > stage_rank:
            stage_rank, stage_name = m["stage_rank"], m["stage"]

    severities = {a["raw_severity"] for a in incident["alerts"]}
    severity_points = 10 if "high" in severities else 5 if "medium" in severities else 0
    if severities & {"high", "critical"}:
        max_raw_severity = "high"
    elif "medium" in severities:
        max_raw_severity = "medium"
    else:
        max_raw_severity = "low"

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
        "known_bad_ips": known_bad_ips,
        "max_raw_severity": max_raw_severity,
    }
