"""Shows the guardrails at work WITHOUT calling the AI (safe for a demo).

  python demo_guardrails.py

Each scenario is a pretend AI answer that is wrong or badly formatted. The
code checks it against the rule-based score and corrects it.
"""
from app.agent.correlation import correlate
from app.agent.guardrails import apply_guardrails
from app.agent.pipeline import pseudo_incident
from app.agent.scoring import score_incident

incidents, standalone = correlate()
by_id = {i["incident_id"]: i for i in incidents}
first_alert = {a["id"]: a for i in incidents for a in i["alerts"]}


def show(title, case, ai_answer):
    score = score_incident(case)
    fixed = apply_guardrails(dict(ai_answer), score)
    print(f"\n--- {title}")
    print(f"Rule-based score: {score['score']} ({score['level']})")
    if ai_answer.get("parse_error"):
        print("AI said:      (an answer that is not valid JSON)")
    else:
        print(f"AI said:      {ai_answer.get('verdict')}"
              f"  (confidence {ai_answer.get('confidence')})")
    print(f"Final answer: {fixed['verdict']}  (confidence {fixed['confidence']})")
    for note in fixed["guardrail_notes"]:
        print("  Guardrail:", note)
    if not fixed["guardrail_notes"]:
        print("  Guardrail: no change needed")


print("GUARDRAIL DEMO: no AI is called, the AI answers below are pretend.")

show("1. The AI is overconfident about the ambiguous transfer (INC-003)",
     by_id["INC-003"],
     {"verdict": "false_positive", "severity": "low", "confidence": 0.95})

show(f"2. The AI calls a routine alert ({standalone[0]['id']}) an attack",
     pseudo_incident(standalone[0]),
     {"verdict": "true_positive", "severity": "high", "confidence": 0.9})

show("3. The AI dismisses a login attempt from a malicious IP (ALR-001)",
     pseudo_incident(first_alert["ALR-001"]),
     {"verdict": "false_positive", "severity": "low", "confidence": 0.9})

show("4. The AI answers in the wrong format",
     by_id["INC-001"],
     {"parse_error": True, "raw": "Looks bad to me!"})

show("5. A correct answer is left alone (INC-001)",
     by_id["INC-001"],
     {"verdict": "true_positive", "severity": "high", "confidence": 0.95})

print("\nEvery proposed action also waits for a human: "
      "see approvals.py and the Approvals tab.")
