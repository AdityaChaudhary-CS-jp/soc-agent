"""Correlation engine: group related alerts into incidents.

Two alerts are linked when:
  Rule A - they share the same EXTERNAL source IP (not internal, not known
           clean) and happened within 60 minutes of each other.
  Rule B - they hit the same host AND user within 15 minutes, and both are
           medium/high severity (so low-level noise never links up).
Linked alerts are merged into one incident (chains of links are followed).
"""
from datetime import datetime, timedelta

from app.tools.search_logs import search_logs
from app.tools.threat_intel import threat_intel_lookup

IP_WINDOW = timedelta(minutes=60)
HOST_USER_WINDOW = timedelta(minutes=15)


def safe_lookup(ip: str) -> dict:
    """Threat-intel lookup that never crashes the pipeline."""
    try:
        return threat_intel_lookup(ip)
    except TimeoutError:
        return {"ip": ip, "status": "no_data", "reputation": "unknown"}


def _time(alert: dict) -> datetime:
    return datetime.fromisoformat(alert["timestamp"])


def correlate(alerts=None):
    """Return (incidents, standalone_alerts). Incidents have 2+ alerts."""
    alerts = sorted(alerts if alerts is not None else search_logs(limit=1000),
                    key=_time)

    # Which IPs are worth linking on? External ones that are not known clean.
    infos = {ip: safe_lookup(ip) for ip in {a["src_ip"] for a in alerts}}
    linkable = {ip for ip, i in infos.items()
                if i["status"] not in ("internal", "invalid")
                and i.get("reputation") != "clean"}

    parent = list(range(len(alerts)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i, a in enumerate(alerts):
        for j in range(i + 1, len(alerts)):
            b = alerts[j]
            gap = _time(b) - _time(a)
            if gap > IP_WINDOW:
                break                       # alerts are sorted by time
            same_ip = a["src_ip"] == b["src_ip"] and a["src_ip"] in linkable
            same_host_user = (
                a["host"] == b["host"] and a["user"] == b["user"]
                and gap <= HOST_USER_WINDOW
                and a["raw_severity"] != "low" and b["raw_severity"] != "low")
            if same_ip or same_host_user:
                parent[find(i)] = find(j)

    groups = {}
    for i, a in enumerate(alerts):
        groups.setdefault(find(i), []).append(a)

    incidents, standalone = [], []
    for members in sorted(groups.values(), key=lambda g: _time(g[0])):
        if len(members) < 2:
            standalone.extend(members)
            continue
        incidents.append({
            "incident_id": f"INC-{len(incidents) + 1:03d}",
            "alert_count": len(members),
            "start": members[0]["timestamp"],
            "end": members[-1]["timestamp"],
            "ips": sorted({a["src_ip"] for a in members}),
            "hosts": sorted({a["host"] for a in members}),
            "users": sorted({a["user"] for a in members}),
            "mitre_techniques": sorted({a["mitre_hint"] for a in members
                                        if a["mitre_hint"]}),
            "alerts": members,
        })
    return incidents, standalone
