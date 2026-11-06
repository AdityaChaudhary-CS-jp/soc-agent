"""Guardrails: the code double-checks the AI's report against the score.

The AI may be overconfident or may answer in the wrong format, so these
rules always win over its answer. Every change is written into
report["guardrail_notes"] and the audit log.

Rules, in the order they run:
  0. A report that is not valid JSON becomes needs_review.
  1. The verdict must be one of true_positive / false_positive / needs_review.
  2. The AI severity may not be 2+ levels below the rule-based level.
  3. A medium+ incident cannot be dismissed as a false positive.
  4. Nothing involving a known-bad IP can be dismissed as a false positive.
  5. A true_positive on a routine alert (low score, low severity, no known-bad
     IP) becomes needs_review. A person still looks at it, but the system
     does not shout "attack" about noise.
  6. Missing threat intel caps confidence (and forces needs_review late in
     an attack).
  7. Every proposed action waits for a human.
"""
import math

from app.agent.scoring import LEVELS

VERDICTS = ("true_positive", "false_positive", "needs_review")
CONFIDENCE_CAP = 0.6


def _clean_verdict(raw):
    """'True Positive' and 'true-positive' are accepted; anything else is None."""
    text = str(raw or "").strip().lower().replace("-", "_").replace(" ", "_")
    return text if text in VERDICTS else None


def _clean_actions(raw):
    """Return (list_of_action_dicts, number_of_entries_fixed_or_dropped)."""
    if raw is None:
        return [], 0
    if not isinstance(raw, list):
        return [], 1
    actions, fixed = [], 0
    for item in raw:
        if isinstance(item, dict):
            actions.append(item)
        elif isinstance(item, str) and item.strip():
            actions.append({"action": item.strip(), "reason": ""})
            fixed += 1
        else:
            fixed += 1
    return actions, fixed


def apply_guardrails(report: dict, score: dict, audit=None) -> dict:
    notes = []

    def note(text):
        notes.append(text)
        if audit:
            audit.add("guardrail", note=text)

    if not isinstance(report, dict):
        report = {"parse_error": True, "raw": str(report)}

    # 0. The AI did not return usable JSON.
    if report.get("parse_error"):
        note("The AI's answer was not valid JSON; verdict set to needs_review. "
             "A person must review this case.")
        report["verdict"] = "needs_review"
        report["confidence"] = 0.0
        report.setdefault("summary", "The AI did not return a valid report. "
                          "Use the rule-based score and review manually.")
        report.setdefault("uncertainties", ["AI answer could not be parsed."])

    # Confidence must be a number between 0 and 1.
    try:
        confidence = float(report.get("confidence", 0.5))
        if math.isnan(confidence):
            raise ValueError("nan")
        confidence = max(0.0, min(1.0, confidence))
    except (TypeError, ValueError):
        confidence = 0.5
        note("Confidence was not a number; reset to 0.5.")

    # 1. The verdict must be one of the three allowed words.
    verdict = _clean_verdict(report.get("verdict"))
    if verdict is None:
        note(f"Unknown verdict {report.get('verdict')!r}; changed to needs_review.")
        verdict = "needs_review"
    severity = report.get("severity", "low")

    # 2. AI severity may not be 2+ levels below the rule-based level.
    if severity in LEVELS:
        if LEVELS.index(severity) <= LEVELS.index(score["level"]) - 2:
            note(f"Severity raised from {severity} to {score['level']} "
                 f"(rule-based score {score['score']}).")
            severity = score["level"]
    else:
        severity = score["level"]
        note(f"Unknown severity; using rule-based level {severity}.")

    # 3. A medium+ incident cannot be dismissed as a false positive.
    if verdict == "false_positive" and LEVELS.index(score["level"]) >= 1:
        note(f"Verdict false_positive changed to needs_review "
             f"(rule-based level {score['level']}).")
        verdict = "needs_review"

    # 4. Anything involving a known-bad IP cannot be dismissed, even when the
    #    score is low (for example a single alert from a malicious IP).
    bad_ips = score.get("known_bad_ips", [])
    if verdict == "false_positive" and bad_ips:
        note("Verdict false_positive changed to needs_review: threat intel "
             "rates " + ", ".join(bad_ips) + " as malicious or suspicious.")
        verdict = "needs_review"

    # 5. Over-flagging: a confident true_positive on a routine alert.
    routine = (score["level"] == "low"
               and not bad_ips
               and score.get("max_raw_severity", "low") == "low")
    if verdict == "true_positive" and routine:
        text = (f"Verdict true_positive changed to needs_review: the "
                f"rule-based score is low ({score['score']}), no IP is known "
                f"to be bad and every alert is low severity.")
        if confidence > CONFIDENCE_CAP:
            text += f" Confidence capped at {CONFIDENCE_CAP}."
            confidence = CONFIDENCE_CAP
        note(text)
        verdict = "needs_review"

    # 6. Missing threat intel means the evidence is incomplete.
    if score["missing_intel_ips"]:
        if confidence > CONFIDENCE_CAP:
            note(f"Confidence capped at {CONFIDENCE_CAP}: no threat intel for "
                 + ", ".join(score["missing_intel_ips"]) + ".")
            confidence = CONFIDENCE_CAP
        if score["stage_rank"] >= 5 and verdict != "needs_review":
            note(f"Verdict {verdict} changed to needs_review: late attack "
                 f"stage ({score['highest_stage']}) with missing intel.")
            verdict = "needs_review"

    # 7. Every proposed action waits for a human (approval step comes next).
    actions, fixed = _clean_actions(report.get("recommended_actions"))
    if fixed:
        note(f"{fixed} recommended action(s) were not in the expected format "
             f"and were converted or dropped.")
    for action in actions:
        action["requires_approval"] = True
        action["status"] = "pending_approval"

    report["verdict"] = verdict
    report["severity"] = severity
    report["confidence"] = confidence
    report["recommended_actions"] = actions
    report["guardrail_notes"] = notes
    report["rule_based_score"] = {"score": score["score"],
                                  "level": score["level"],
                                  "breakdown": score["breakdown"]}
    return report
