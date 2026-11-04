"""Checks the incident report generator (no AI needed).
Run: python test_reports.py     (uses a temporary database)
"""
import tempfile
from pathlib import Path

from app.agent import approvals, audit, store
from app.agent.correlation import correlate
from app.agent.reports import gather_markdown

tmp = Path(tempfile.mkdtemp())
approvals.DB_PATH = tmp / "test.db"
audit.LOG_FILE = tmp / "audit.jsonl"

incidents, _ = correlate()
inc = incidents[0]
assert "not been investigated" in gather_markdown("INC-001")
print("PASS: report works before any investigation")

ai = {"verdict": "true_positive", "severity": "high", "confidence": 0.95,
      "summary": "Brute force then root.", "evidence": ["ALR-001 to ALR-006 failed logins"],
      "uncertainties": ["Attacker commands unknown"],
      "guardrail_notes": ["Severity raised"],
      "recommended_actions": [{"action": "Block IP 203.0.113.45", "reason": "malicious"},
                              {"action": "Review logs on web-01", "reason": "scope"}]}
store.save_report("INC-001", ai)
approvals.submit_actions(inc, ai)
try:
    approvals.decide(1, "analyst1", True)
except PermissionError:
    pass
approvals.decide(1, "admin1", True, "confirmed")

md = gather_markdown("INC-001")
for needle in ("# Incident Report: INC-001", "82.8 / 100 (critical)", "Brute Force",
               "true_positive", "Brute force then root.", "Severity raised",
               "executed_simulated", "admin1 (admin)", "Refused approval attempts: 1",
               "ALR-008"):
    assert needle in md, f"missing: {needle}"
print("PASS: report has score, timeline, AI result, approvals and audit summary")
print(md[:700])
