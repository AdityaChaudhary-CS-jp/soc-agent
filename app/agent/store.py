"""Saved AI reports (SQLite) and audit-log reading, used by the dashboard
and the incident report generator."""
import json
import sqlite3
from datetime import datetime

from app.agent import approvals
from app.agent import audit as audit_module


def _connect():
    approvals.DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(approvals.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT, created_at TEXT, report_json TEXT)""")
    return conn


def save_report(incident_id: str, report: dict) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT INTO reports (incident_id, created_at, report_json) VALUES (?,?,?)",
            (incident_id, datetime.now().isoformat(timespec="seconds"),
             json.dumps(report, default=str)))


def latest_report(incident_id: str):
    """Newest saved AI report for an incident, or None."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT created_at, report_json FROM reports WHERE incident_id=? "
            "ORDER BY id DESC LIMIT 1", (incident_id,)).fetchone()
    if row is None:
        return None
    return {"created_at": row["created_at"], "report": json.loads(row["report_json"])}


def read_audit_events(incident_id=None) -> list:
    """Events from the audit log file, oldest first."""
    path = audit_module.LOG_FILE
    if not path.exists():
        return []
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if incident_id is None or event.get("alert_id") == incident_id:
                events.append(event)
    return events
