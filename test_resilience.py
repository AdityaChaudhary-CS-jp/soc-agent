"""Checks AI-outage handling and duplicate-action skipping (no AI needed).
Run: python test_resilience.py
"""
import tempfile
from pathlib import Path
from types import SimpleNamespace as NS

from app.agent import approvals, audit
from app.agent.audit import AuditLog
from app.agent.llm_retry import ResilientClient

tmp = Path(tempfile.mkdtemp())
approvals.DB_PATH = tmp / "t.db"
audit.LOG_FILE = tmp / "a.jsonl"


class Fake:
    """Fails with 503 a set number of times for the main model."""
    def __init__(self, failures, error="503 UNAVAILABLE: high demand"):
        self.failures, self.error, self.calls = failures, error, []
        self.models = NS(generate_content=self.generate_content)

    def generate_content(self, model, contents, config=None, **kw):
        self.calls.append(model)
        if model == "main" and self.failures > 0:
            self.failures -= 1
            raise Exception(self.error)
        return NS(text=f"ok from {model}")


def events(a):
    return [e["event"] for e in a.entries]

# 1. Recovers after two temporary failures (same model)
a = AuditLog("T"); f = Fake(2)
r = ResilientClient(f, a, fallbacks=("backup",), wait=0).models.generate_content("main", "hi")
assert r.text == "ok from main" and events(a).count("llm_retry") == 2
print("PASS: retried the main model twice, then it worked")

# 2. Falls back when the main model stays down
a = AuditLog("T"); f = Fake(99)
r = ResilientClient(f, a, fallbacks=("backup",), wait=0).models.generate_content("main", "hi")
assert r.text == "ok from backup" and "llm_fallback" in events(a)
print("PASS: main model down -> switched to the backup model")

# 3. Permanent errors are not retried
a = AuditLog("T"); f = Fake(99, error="400 API key not valid")
try:
    ResilientClient(f, a, fallbacks=("backup",), wait=0).models.generate_content("main", "hi")
    raise AssertionError("should have raised")
except Exception as e:
    assert "API key" in str(e) and f.calls == ["main"]
print("PASS: permanent error raised immediately, no pointless retries")

# 4. Everything down -> clear error
a = AuditLog("T"); f = Fake(99); f.models = NS(generate_content=lambda **k: (_ for _ in ()).throw(Exception("503 UNAVAILABLE")))
try:
    ResilientClient(f, a, fallbacks=("backup",), wait=0).models.generate_content("main", "hi")
    raise AssertionError("should have raised")
except RuntimeError as e:
    assert "unavailable" in str(e).lower()
print("PASS: all models down -> clear error message")

# 4b. A retired model (404) is skipped, and the next model is used
a = AuditLog("T"); f = Fake(99, error="404 NOT_FOUND: This model is no longer available to new users")
r = ResilientClient(f, a, fallbacks=("backup",), wait=0).models.generate_content("main", "hi")
assert r.text == "ok from backup" and f.calls == ["main", "backup"]
assert "llm_model_unavailable" in events(a)
print("PASS: retired model skipped without retrying, backup model used")

# 4c. Every model retired -> clear error, no crash loop
a = AuditLog("T")
dead = NS(models=NS(generate_content=lambda **k: (_ for _ in ()).throw(Exception("404 NOT_FOUND no longer available"))))
try:
    ResilientClient(dead, a, fallbacks=("backup",), wait=0).models.generate_content("main", "hi")
    raise AssertionError("should have raised")
except RuntimeError as e:
    assert "unavailable" in str(e).lower()
print("PASS: all models retired -> clear error message")

# 4d. Daily free-tier quota used up -> skip that model at once (no retries)
quota = ("429 RESOURCE_EXHAUSTED. Quota exceeded for metric: generate_content_free_tier_requests, "
         "limit: 20. quotaId: GenerateRequestsPerDayPerProjectPerModel-FreeTier")
a = AuditLog("T"); f = Fake(99, error=quota)
rc = ResilientClient(f, a, fallbacks=("backup",), wait=0)
r = rc.models.generate_content("main", "hi")
assert r.text == "ok from backup" and f.calls == ["main", "backup"]
assert "llm_quota_exhausted" in events(a) and rc.models.used == ["backup"]
print("PASS: daily quota used up -> next model at once, and the model used is recorded")

# 5. Duplicate / overlapping actions are skipped
inc = {"incident_id": "INC-001", "ips": ["203.0.113.45"], "hosts": ["web-01"], "users": ["admin"]}
first = {"recommended_actions": [
    {"action": "Block source IP 203.0.113.45 at the perimeter firewall", "reason": "r"},
    {"action": "Reset credentials for the admin account", "reason": "r"}]}
second = {"recommended_actions": [
    {"action": "Block source IP 203.0.113.45 on network firewalls and security devices", "reason": "r"},
    {"action": "Terminate active user sessions for admin and force a credential reset", "reason": "r"},
    {"action": "Isolate host web-01 from the network", "reason": "r"},
    {"action": "Review host logs on web-01", "reason": "r"}]}
a = AuditLog("INC-001")
assert len(approvals.submit_actions(inc, first, a)) == 2
new = approvals.submit_actions(inc, second, a)
assert len(new) == 2, new          # isolate + review only
assert events(a).count("action_skipped") == 2
print("PASS: overlapping block/reset proposals skipped, new ones queued")

# 6. Already-executed actions are also not proposed again
approvals.decide(1, "admin1", True)
again = approvals.submit_actions(inc, first, a)
assert again == [], again
print("PASS: an executed action is not proposed again")

# 7. A rejected action can be proposed again
approvals.decide(2, "analyst1", False, "not yet")
assert len(approvals.submit_actions(inc, {"recommended_actions": [first["recommended_actions"][1]]}, a)) == 1
print("PASS: a rejected action may be re-proposed")
