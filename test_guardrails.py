"""Checks the guardrails WITHOUT the AI. Run: python test_guardrails.py

It uses pretend AI answers, so it costs no API requests. The main promise:
routine alerts are never called attacks, and real attacks are never
dismissed.
"""
import copy

from app.agent.correlation import correlate
from app.agent.guardrails import apply_guardrails
from app.agent.pipeline import build_case, pseudo_incident
from app.agent.scoring import score_incident

incidents, standalone = correlate()
scores = {i["incident_id"]: score_incident(i) for i in incidents}


def ai(verdict, severity="medium", confidence=0.9):
    return {"verdict": verdict, "severity": severity, "confidence": confidence,
            "recommended_actions": [{"action": "Review logs", "reason": "x"}]}


# ---- scoring facts used by the guardrails ----
assert scores["INC-001"]["known_bad_ips"] == ["203.0.113.45"]
assert set(scores["INC-002"]["known_bad_ips"]) == {"192.0.2.99", "198.51.100.7"}
assert scores["INC-003"]["known_bad_ips"] == [] and scores["INC-003"]["missing_intel_ips"]
print("PASS: known-bad IPs found for the real incidents")

# ---- 1. every routine alert: a confident true_positive becomes needs_review ----
assert len(standalone) == 30
for a in standalone:
    sc = score_incident(pseudo_incident(a))
    assert sc["level"] == "low" and not sc["known_bad_ips"] and sc["max_raw_severity"] == "low", a["id"]
    out = apply_guardrails(ai("true_positive", "high", 0.95), sc)
    assert out["verdict"] == "needs_review", a["id"]
    assert out["confidence"] <= 0.6, a["id"]
    assert any("true_positive changed to needs_review" in n for n in out["guardrail_notes"])
print("PASS: all 30 routine alerts: true_positive -> needs_review, confidence capped at 0.6")

# a correct false_positive on routine noise is left alone
sc = score_incident(pseudo_incident(standalone[0]))
out = apply_guardrails(ai("false_positive", "low", 0.9), sc)
assert out["verdict"] == "false_positive" and out["guardrail_notes"] == []
print("PASS: a correct false_positive on a routine alert is not touched")

# ---- 2. real attacks stay safe ----
for inc_id in ("INC-001", "INC-002"):
    out = apply_guardrails(ai("true_positive", "high", 0.95), scores[inc_id])
    assert out["verdict"] == "true_positive" and out["guardrail_notes"] == [], inc_id
print("PASS: INC-001 and INC-002 stay true_positive")

all_alerts = {a["id"]: a for i in incidents for a in i["alerts"]}
checked = 0
for n in range(1, 14):                       # ALR-001..013 are the attack alerts
    alert = all_alerts[f"ALR-{n:03d}"]
    sc = score_incident(pseudo_incident(alert))
    assert sc["known_bad_ips"], alert["id"]  # every attack alert comes from a bad IP
    kept = apply_guardrails(ai("true_positive", "high", 0.95), sc)
    assert kept["verdict"] == "true_positive", alert["id"]
    dismissed = apply_guardrails(ai("false_positive", "low", 0.95), sc)
    assert dismissed["verdict"] == "needs_review", alert["id"]
    checked += 1
print(f"PASS: each of the {checked} attack alerts alone: true_positive kept, false_positive blocked")

# ---- 3. each condition of the downgrade rule on its own ----
low = {"score": 7.0, "level": "low", "breakdown": {}, "stage_rank": 1,
       "highest_stage": "Initial Access", "missing_intel_ips": [],
       "known_bad_ips": [], "max_raw_severity": "low"}
assert apply_guardrails(ai("true_positive"), copy.deepcopy(low))["verdict"] == "needs_review"
for change in ({"known_bad_ips": ["203.0.113.45"]}, {"max_raw_severity": "medium"},
               {"max_raw_severity": "high"}, {"level": "medium", "score": 35.0}):
    sc = {**low, **change}
    assert apply_guardrails(ai("true_positive"), sc)["verdict"] == "true_positive", change
print("PASS: downgrade needs ALL of: low score, no known-bad IP, only low-severity alerts")

# false_positive is blocked for a known-bad IP even when the score is low
sc = {**low, "known_bad_ips": ["192.0.2.99"]}
out = apply_guardrails(ai("false_positive"), sc)
assert out["verdict"] == "needs_review" and "192.0.2.99" in out["guardrail_notes"][0]
print("PASS: a known-bad IP can never be dismissed as false_positive")

# ---- 4. the AI answers in a strange format ----
out = apply_guardrails(ai("True Positive", "high"), scores["INC-001"])
assert out["verdict"] == "true_positive"
out = apply_guardrails(ai("malicious", "high"), scores["INC-001"])
assert out["verdict"] == "needs_review" and out["guardrail_notes"]
print("PASS: verdict spelling fixed; unknown verdict -> needs_review")

for bad in (None, "Block the IP", ["Block the IP", 42, {"action": "Review logs"}]):
    report = ai("needs_review")
    report["recommended_actions"] = bad
    out = apply_guardrails(report, scores["INC-001"])
    assert isinstance(out["recommended_actions"], list)
    assert all(a["status"] == "pending_approval" for a in out["recommended_actions"])
assert [a["action"] for a in out["recommended_actions"]] == ["Block the IP", "Review logs"]
print("PASS: strange recommended_actions never crash and still wait for approval")

out = apply_guardrails({"parse_error": True, "raw": "I think it is bad"}, scores["INC-001"])
assert out["verdict"] == "needs_review" and out["confidence"] == 0.0
assert out["summary"] and any("not valid JSON" in n for n in out["guardrail_notes"])
out = apply_guardrails(ai("needs_review", confidence="NaN"), scores["INC-001"])
assert out["confidence"] == 0.5
out = apply_guardrails("not even a dict", scores["INC-001"])
assert out["verdict"] == "needs_review"
print("PASS: unparsable answer, NaN confidence and non-dict answer are handled")

# ---- 5. what the AI is told about a lone alert ----
single = build_case(pseudo_incident(standalone[0]))
assert single["case_type"] == "standalone_alert" and "correlation_note" in single
full = build_case(incidents[0])
assert full["case_type"] == "incident" and "correlation_note" not in full
print("PASS: lone alerts are labelled standalone_alert; incidents are unchanged")
