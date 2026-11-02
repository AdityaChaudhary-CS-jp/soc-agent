"""The tools the AI agent is allowed to call.

Gemini reads each function's name, type hints and docstring to decide when
to use it, so keep those clear. Each one wraps a tool from app/tools/.
"""
from app.tools.threat_intel import threat_intel_lookup
from app.tools.mitre_map import mitre_map
from app.tools.search_logs import search_logs

KEEP = ("id", "timestamp", "type", "raw_severity", "src_ip", "host",
        "user", "description", "mitre_hint")


def lookup_ip_reputation(ip: str) -> dict:
    """Check an IP address in the threat-intelligence data.
    Returns a status: ok, no_data, not_found, internal or invalid.
    If there is no data, the reputation is unknown; never guess."""
    return threat_intel_lookup(ip)


def map_mitre_technique(technique_id: str) -> dict:
    """Look up a MITRE ATT&CK technique ID such as T1110. Returns its name,
    attack stage and stage_rank (a higher rank is a later, riskier stage)."""
    return mitre_map(technique_id)


def find_related_alerts(ip: str = "", host: str = "", user: str = "",
                        alert_type: str = "") -> dict:
    """Search recorded alerts. Give any of ip, host, user or alert_type;
    only alerts matching ALL given filters are returned, oldest first."""
    rows = search_logs(ip=ip or None, host=host or None,
                       user=user or None, alert_type=alert_type or None,
                       limit=25)
    return {"count": len(rows),
            "alerts": [{k: r[k] for k in KEEP} for r in rows]}


TOOLS = {f.__name__: f for f in
         (lookup_ip_reputation, map_mitre_technique, find_related_alerts)}
