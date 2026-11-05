"""Accuracy check: run the agent on cases whose correct answer is known.

The answers come from how data/generate_data.py builds the data:
  ALR-001..013  two real attack chains        -> expected true_positive
  ALR-014..015  ambiguous transfer, no intel  -> expected needs_review
  ALR-016..045  routine noise                 -> expected false_positive
Because the labels come from OUR synthetic data, the score shows how the
system behaves on this dataset, not how accurate it would be in real life.
"""
import copy
import time
from pathlib import Path

from app.agent.audit import AuditLog
from app.agent.correlation import correlate
from app.agent.guardrails import apply_guardrails
from app.agent.investigator import investigate
from app.agent.llm_retry import ResilientClient
from app.agent.pipeline import build_case
from app.agent.scoring import score_incident

ATTACK = {f"ALR-{n:03d}" for n in range(1, 14)}
AMBIGUOUS = {"ALR-014", "ALR-015"}


class _QuietAudit(AuditLog):
    """Keeps events in memory only: no printing, nothing written to disk."""
    def add(self, event, **data):
        self.entries.append({"event": event, **data})


def expected_verdict(alert_ids) -> str:
    ids = set(alert_ids)
    if ids & ATTACK:
        return "true_positive"
    if ids & AMBIGUOUS:
        return "needs_review"
    return "false_positive"


def _pseudo_incident(alert: dict) -> dict:
    return {"incident_id": alert["id"], "alert_count": 1,
            "start": alert["timestamp"], "end": alert["timestamp"],
            "ips": [alert["src_ip"]], "hosts": [alert["host"]],
            "users": [alert["user"]],
            "mitre_techniques": [alert["mitre_hint"]] if alert["mitre_hint"] else [],
            "alerts": [alert]}


def build_cases(noise_count: int = 7) -> list:
    """3 incidents + noise alerts, interleaved so partial runs are varied."""
    incidents, standalone = correlate()
    real = [(i, "incident") for i in incidents]
    noise = [(_pseudo_incident(a), "alert") for a in standalone[::4][:noise_count]]
    cases = []
    while real or noise:
        if real:
            cases.append(real.pop(0))
        if noise:
            cases.append(noise.pop(0))
    return [(inc, kind, expected_verdict(a["id"] for a in inc["alerts"]))
            for inc, kind in cases]


def run_evaluation(client, limit=None, pause=8.0, progress=print) -> list:
    cases = build_cases()
    if limit:
        cases = cases[:limit]
    results = []
    errors_in_a_row = 0
    for n, (inc, kind, expected) in enumerate(cases, 1):
        cid = inc["incident_id"]
        score = score_incident(inc)
        audit = _QuietAudit(cid)
        row = {"case": cid, "kind": kind, "expected": expected,
               "ai_verdict": "error", "final_verdict": "error",
               "severity": "-", "confidence": "-"}
        try:
            report = investigate(build_case(inc),
                                ResilientClient(client, audit, wait=8.0), audit)
            row["ai_verdict"] = report.get("verdict", "missing")
            final = apply_guardrails(copy.deepcopy(report), score)
            row.update(final_verdict=final["verdict"], severity=final["severity"],
                       confidence=final["confidence"])
        except Exception as e:
            row["error"] = str(e)[:300]
        row["exact"] = row["final_verdict"] == expected
        row["missed_attack"] = (expected == "true_positive"
                                and row["final_verdict"] == "false_positive")
        results.append(row)
        progress(f"[{n}/{len(cases)}] {cid:<8} expected={expected:<14} "
                 f"AI alone={row['ai_verdict']:<14} final={row['final_verdict']:<14} "
                 f"{'OK' if row['exact'] else 'MISS'}")
        if "error" in row:
            progress(f"        error: {row['error']}")
        errors_in_a_row = errors_in_a_row + 1 if row["final_verdict"] == "error" else 0
        if errors_in_a_row >= 3:
            progress("Stopping early: 3 errors in a row. The AI service looks "
                     "overloaded. Try again later.")
            break
        if n < len(cases):
            time.sleep(pause)      # stay under free-tier rate limits
    return results


def summarize(results: list) -> dict:
    n = len(results)
    return {
        "cases": n,
        "ai_alone_correct": sum(r["ai_verdict"] == r["expected"] for r in results),
        "final_correct": sum(r["exact"] for r in results),
        "missed_attacks_ai_alone": sum(r["expected"] == "true_positive"
                                       and r["ai_verdict"] == "false_positive" for r in results),
        "missed_attacks_final": sum(r["missed_attack"] for r in results),
        "false_alarms_final": sum(r["expected"] == "false_positive"
                                  and r["final_verdict"] != "false_positive" for r in results),
        "errors": sum(r["final_verdict"] == "error" for r in results),
    }


def write_markdown(results: list, path) -> Path:
    s = summarize(results)
    lines = ["# Evaluation on the synthetic dataset", "",
             f"- Cases: **{s['cases']}** (real incidents and routine noise alerts)",
             f"- AI alone correct: **{s['ai_alone_correct']}/{s['cases']}**",
             f"- With guardrails correct: **{s['final_correct']}/{s['cases']}**",
             f"- Attacks missed (marked false positive): AI alone **{s['missed_attacks_ai_alone']}**, "
             f"with guardrails **{s['missed_attacks_final']}**",
             f"- False alarms (routine alert not dismissed): **{s['false_alarms_final']}**",
             f"- Errors: **{s['errors']}**", "",
             "| Case | Expected | AI alone | Final | Severity | Confidence | Result |",
             "|---|---|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r['case']} | {r['expected']} | {r['ai_verdict']} | "
                     f"{r['final_verdict']} | {r['severity']} | {r['confidence']} | "
                     f"{'correct' if r['exact'] else 'miss'} |")
    lines += ["", "_Labels come from the synthetic data generator, so this measures "
              "behaviour on this dataset, not real-world accuracy._", ""]
    path = Path(path)
    path.parent.mkdir(exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
