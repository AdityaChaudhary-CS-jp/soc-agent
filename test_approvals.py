"""Checks the approval workflow and role rules (no AI needed).
Run: python test_approvals.py
Uses a temporary database, so it never touches your real queue.
"""
import tempfile
from pathlib import Path

from app.agent import approvals, audit
from app.agent.actions import classify

tmp = Path(tempfile.mkdtemp())
approvals.DB_PATH = tmp / "test.db"
audit.LOG_FILE = tmp / "audit.jsonl"

incident = {"incident_id": "INC-001", "ips": ["203.0.113.45"],
            "hosts": ["web-01"], "users": ["admin"]}
report = {"recommended_actions": [
    {"action": "Block traffic from IP 203.0.113.45 at the firewall", "reason": "malicious"},
    {"action": "Isolate host web-01 from the network", "reason": "contain"},
    {"action": "Force password reset for user 'admin'", "reason": "credentials"},
    {"action": "Perform forensic log review on host web-01", "reason": "scope"},
    {"action": "Do something unusual", "reason": "?"},
]}

ids = approvals.submit_actions(incident, report)
assert len(ids) == 5
assert approvals.submit_actions(incident, report) == [], "duplicates not blocked"
print("PASS: 5 actions queued, duplicates ignored")

kinds = {a["id"]: (a["kind"], a["sensitive"]) for a in approvals.list_actions()}
assert kinds[1] == ("block_ip", 1) and kinds[2] == ("isolate_host", 1)
assert kinds[3] == ("reset_credentials", 1) and kinds[4] == ("manual_review", 0)
assert kinds[5] == ("unknown", 1), "unknown actions must be sensitive"
print("PASS: actions classified (unknown = sensitive)")

def refused(fn):
    try:
        fn()
    except PermissionError as e:
        return str(e)
    raise AssertionError("expected PermissionError")

print("PASS: analyst blocked ->", refused(lambda: approvals.decide(1, "analyst1", True)))
refused(lambda: approvals.decide(4, "viewer1", True))
refused(lambda: approvals.decide(4, "ghost", True))
assert approvals.list_actions("pending_approval")[0]["id"] == 1
print("PASS: viewer and unknown users blocked; nothing changed")

r = approvals.decide(4, "analyst1", True, "looks fine")
assert r["status"] == "executed_simulated"
print("PASS: analyst approved safe action ->", r["execution_result"])

r = approvals.decide(2, "admin1", True, "confirmed compromise")
assert "isolated" in r["execution_result"] and "SIMULATED" in r["execution_result"]
print("PASS: admin approved sensitive action ->", r["execution_result"])

r = approvals.decide(1, "analyst1", False, "need more evidence")
assert r["status"] == "rejected"
print("PASS: analyst rejected a sensitive action")

try:
    approvals.decide(2, "admin1", True)
    raise AssertionError("double decision allowed")
except ValueError as e:
    print("PASS: second decision refused ->", e)

log = (tmp / "audit.jsonl").read_text()
assert "approval_denied" in log and "approval_decision" in log
print("PASS: denials and decisions are in the audit log")

assert '"user": "ghost"' in log and '"role": "unknown"' in log
print("PASS: a refused attempt by an unknown user is also in the audit log")
