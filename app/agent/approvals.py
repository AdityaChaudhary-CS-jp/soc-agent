"""Human-in-the-loop approval queue (SQLite).

The agent only PROPOSES actions. They are stored as pending_approval and
nothing runs until a person with the right role approves them. Every
decision (including refused attempts) goes to the audit log.

Statuses: pending_approval -> executed_simulated | rejected
"""
import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path

from app.auth import can_decide, role_of
from app.agent.actions import IP_RE, classify, simulate
from app.agent.audit import AuditLog

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "soc.db"


def _connect():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT, action TEXT, reason TEXT, kind TEXT,
        sensitive INTEGER, status TEXT, entities TEXT, created_at TEXT,
        decided_by TEXT, decided_role TEXT, decided_at TEXT,
        decision_comment TEXT, execution_result TEXT)""")
    return conn


def _now():
    return datetime.now().isoformat(timespec="seconds")


# Which target identifies a sensitive action (to spot overlapping proposals).
TARGET_FIELD = {"block_ip": "ips", "isolate_host": "hosts",
                "reset_credentials": "users", "terminate_sessions": "users",
                "disable_account": "users"}


def _target_key(kind: str, text: str, entities: dict):
    """(kind, targets) for sensitive actions, or None for other kinds."""
    field = TARGET_FIELD.get(kind)
    if field is None:
        return None
    if field == "ips":
        found = sorted(set(IP_RE.findall(text)))
    else:
        found = sorted(e for e in entities.get(field, [])
                       if re.search(rf"\b{re.escape(e)}\b", text))
    return (kind, tuple(found or sorted(entities.get(field, []))))


def submit_actions(incident: dict, report: dict, audit=None) -> list:
    """Queue the report's recommended actions. Returns the new action ids.

    Skipped: the exact same text already pending, and any sensitive action
    of the same kind on the same target that is already pending or done
    (so a re-run does not queue a second 'block this IP')."""
    entities_dict = {k: incident.get(k, []) for k in ("ips", "hosts", "users")}
    entities = json.dumps(entities_dict)
    new_ids = []
    with _connect() as conn:
        seen = set()
        for r in conn.execute(
                "SELECT action, kind, entities FROM actions WHERE incident_id=? "
                "AND status IN ('pending_approval', 'executed_simulated')",
                (incident["incident_id"],)):
            key = _target_key(r["kind"], r["action"], json.loads(r["entities"]))
            if key:
                seen.add(key)

        for item in report.get("recommended_actions", []):
            text = item.get("action", "").strip()
            if not text:
                continue
            dup = conn.execute(
                "SELECT id FROM actions WHERE incident_id=? AND action=? "
                "AND status='pending_approval'",
                (incident["incident_id"], text)).fetchone()
            if dup:
                continue
            info = classify(text)
            key = _target_key(info["kind"], text, entities_dict)
            if key and key in seen:
                if audit:
                    audit.add("action_skipped", action=text, kind=info["kind"],
                              reason="same kind of action on the same target "
                                     "is already pending or done")
                continue
            if key:
                seen.add(key)
            cur = conn.execute(
                "INSERT INTO actions (incident_id, action, reason, kind, sensitive,"
                " status, entities, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (incident["incident_id"], text, item.get("reason", ""),
                 info["kind"], int(info["sensitive"]), "pending_approval",
                 entities, _now()))
            new_ids.append(cur.lastrowid)
            if audit:
                audit.add("action_queued", action_id=cur.lastrowid, action=text,
                          kind=info["kind"], sensitive=info["sensitive"])
    return new_ids


def list_actions(status=None, incident_id=None) -> list:
    query, params = "SELECT * FROM actions WHERE 1=1", []
    if status:
        query += " AND status=?"
        params.append(status)
    if incident_id:
        query += " AND incident_id=?"
        params.append(incident_id)
    with _connect() as conn:
        return [dict(r) for r in conn.execute(query + " ORDER BY id", params)]


def decide(action_id: int, username: str, approve: bool, comment: str = "") -> dict:
    """Approve or reject one action. Raises PermissionError if the user's
    role is not allowed, ValueError if it was already decided."""
    try:
        role = role_of(username)
    except PermissionError:
        # Refused attempts by unknown users are logged too.
        with _connect() as conn:
            row = conn.execute("SELECT incident_id FROM actions WHERE id=?",
                               (action_id,)).fetchone()
        audit = AuditLog(row["incident_id"] if row else f"ACTION-{action_id}")
        audit.add("approval_denied", action_id=action_id, user=username,
                  role="unknown", attempted="approve" if approve else "reject",
                  reason="unknown user")
        audit.save()
        raise
    with _connect() as conn:
        row = conn.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
        if row is None:
            raise KeyError(f"Action {action_id} not found.")
        row = dict(row)
        audit = AuditLog(row["incident_id"])

        if row["status"] != "pending_approval":
            raise ValueError(f"Action {action_id} was already {row['status']}.")

        if not can_decide(role, bool(row["sensitive"]), approve):
            audit.add("approval_denied", action_id=action_id, user=username,
                      role=role, attempted="approve" if approve else "reject",
                      sensitive=bool(row["sensitive"]))
            audit.save()
            raise PermissionError(
                f"{username} ({role}) may not {'approve' if approve else 'reject'} "
                f"this action. Sensitive actions need an admin.")

        result = None
        if approve:
            result = simulate(row, json.loads(row["entities"]))
            status = "executed_simulated"
        else:
            status = "rejected"
        cur = conn.execute(
            "UPDATE actions SET status=?, decided_by=?, decided_role=?, decided_at=?,"
            " decision_comment=?, execution_result=? WHERE id=? "
            "AND status='pending_approval'",
            (status, username, role, _now(), comment, result, action_id))
        if cur.rowcount == 0:      # someone else decided it a moment ago
            raise ValueError(f"Action {action_id} was already decided.")
        audit.add("approval_decision", action_id=action_id, user=username,
                  role=role, decision="approved" if approve else "rejected",
                  comment=comment, result=result)
        audit.save()
        row.update(status=status, decided_by=username, execution_result=result)
        return row
