"""Tool 3: search our synthetic alerts by IP, host, user or alert type."""
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2] / "data"


def search_logs(ip=None, host=None, user=None, alert_type=None, limit=50):
    """Return alerts that match ALL the filters given, oldest first."""
    with open(DATA_DIR / "alerts.json", encoding="utf-8") as f:
        alerts = json.load(f)

    results = []
    for a in alerts:
        if ip and a["src_ip"] != ip:
            continue
        if host and a["host"] != host:
            continue
        if user and a["user"] != user:
            continue
        if alert_type and a["type"] != alert_type:
            continue
        results.append(a)

    results.sort(key=lambda a: a["timestamp"])
    return results[:limit]
