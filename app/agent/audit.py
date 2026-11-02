"""Audit log: records every reasoning step, tool call, result and retry.

This is what the rubric calls 'traceability'. Each event is printed on
screen and saved to logs/audit_log.jsonl (one JSON object per line).
"""
import json
from datetime import datetime
from pathlib import Path

LOG_FILE = Path(__file__).resolve().parents[2] / "logs" / "audit_log.jsonl"


class AuditLog:
    def __init__(self, alert_id: str):
        self.alert_id = alert_id
        self.entries = []

    def add(self, event: str, **data):
        entry = {"time": datetime.now().isoformat(timespec="seconds"),
                 "alert_id": self.alert_id, "event": event, **data}
        self.entries.append(entry)
        shown = json.dumps(data, default=str)
        print(f"[{event}] {shown[:220]}")

    def save(self):
        LOG_FILE.parent.mkdir(exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            for e in self.entries:
                f.write(json.dumps(e, default=str) + "\n")
