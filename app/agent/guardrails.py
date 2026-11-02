"""Guardrails: the code double-checks the AI's report against the score.

The AI may be overconfident, so these rules always win over its answer.
Every change is written into report["guardrail_notes"] and the audit log.
"""
from app.agent.scoring import LEVELS


def apply_guardrails(report: dict, score: dict, audit=None) -> dict:
    notes = []

    def note(text):
        notes.append(text)
        if audit:
            audit.add("guardrail", note=text)

    # Confidence must be a number between 0 and 1.
    try:
        confidence = max(0.0, min(1.0, float(report.get("confidence", 0.5))))
    except (TypeError, ValueError):
        confidence = 0.5
        note("Confidence was not a number; reset to 0.5.")

    verdict = report.get("verdict", "needs_review")
    severity = report.get("severity", "low")

    # 1. AI severity may not be 2+ levels below the rule-based level.
    if severity in LEVELS:
        if LEVELS.index(severity) <= LEVELS.index(score["level"]) - 2:
            note(f"Severity raised from {severity} to {score['level']} "
                 f"(rule-based score {score['score']}).")
            severity = score["level"]
    else:
        severity = score["level"]
        note(f"Unknown severity; using rule-based level {severity}.")

    # 2. A medium+ incident cannot be dismissed as a false positive.
    if verdict == "false_positive" and LEVELS.index(score["level"]) >= 1:
        note(f"Verdict false_positive changed to needs_review "
             f"(rule-based level {score['level']}).")
        verdict = "needs_review"

    # 3. Missing threat intel means the evidence is incomplete.
    if score["missing_intel_ips"]:
        if confidence > 0.6:
            note("Confidence capped at 0.6: no threat intel for "
                 + ", ".join(score["missing_intel_ips"]) + ".")
            confidence = 0.6
        if score["stage_rank"] >= 5 and verdict != "needs_review":
            note(f"Verdict {verdict} changed to needs_review: late attack "
                 f"stage ({score['highest_stage']}) with missing intel.")
            verdict = "needs_review"

    report["verdict"] = verdict
    report["severity"] = severity
    report["confidence"] = confidence
    report["guardrail_notes"] = notes
    report["rule_based_score"] = {"score": score["score"],
                                  "level": score["level"],
                                  "breakdown": score["breakdown"]}

    # 4. Every proposed action waits for a human (approval step comes next).
    for action in report.get("recommended_actions", []):
        action["requires_approval"] = True
        action["status"] = "pending_approval"
    return report
