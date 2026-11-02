"""Checks correlation, scoring and guardrails (no AI needed).
Run: python test_scoring.py
"""
from app.agent.correlation import correlate
from app.agent.scoring import score_incident
from app.agent.guardrails import apply_guardrails

incidents, standalone = correlate()
scores = [score_incident(i) for i in incidents]

print("Incidents:", len(incidents), "| standalone alerts:", len(standalone))
for inc, sc in zip(incidents, scores):
    print(inc["incident_id"], "alerts:", inc["alert_count"],
          "score:", sc["score"], sc["level"], sc["breakdown"])

assert [i["alert_count"] for i in incidents] == [8, 5, 2], "wrong grouping"
assert [s["level"] for s in scores] == ["critical", "critical", "medium"]
assert len(standalone) == 30
print("PASS: grouping and scores")

# Guardrail 1: overconfident false positive on the ambiguous incident
report = {"verdict": "false_positive", "severity": "low", "confidence": "0.85",
          "recommended_actions": [{"action": "Verify IP", "reason": "no intel"}]}
out = apply_guardrails(report, scores[2])
assert out["verdict"] == "needs_review" and out["confidence"] <= 0.6
assert out["recommended_actions"][0]["status"] == "pending_approval"
print("PASS: false positive corrected ->", out["guardrail_notes"])

# Guardrail 2: AI says low for a critical attack
report = {"verdict": "true_positive", "severity": "low", "confidence": 0.9}
out = apply_guardrails(report, scores[0])
assert out["severity"] == "critical"
print("PASS: severity raised ->", out["guardrail_notes"])

# A correct report is left alone
report = {"verdict": "true_positive", "severity": "high", "confidence": 0.95}
out = apply_guardrails(report, scores[0])
assert out["guardrail_notes"] == [] and out["severity"] == "high"
print("PASS: correct report unchanged")
