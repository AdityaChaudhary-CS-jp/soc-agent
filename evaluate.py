"""Accuracy check on cases with known answers.

  python evaluate.py        -> all 10 cases (about 30-40 AI calls)
  python evaluate.py 4      -> only the first 4 cases (a quick test)

Writes the results to docs/evaluation.md.
"""
import sys
from pathlib import Path

from google import genai

from app.agent.evaluation import run_evaluation, summarize, write_markdown
from app.config import get_api_key

limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
client = genai.Client(api_key=get_api_key())

print("Running the agent on cases with known answers...\n")
results = run_evaluation(client, limit)
s = summarize(results)

print("\n=== RESULT ===")
print(f"AI alone:        {s['ai_alone_correct']}/{s['cases']} correct")
print(f"With guardrails: {s['final_correct']}/{s['cases']} correct")
print(f"Attacks missed:  {s['missed_attacks_final']} (AI alone: {s['missed_attacks_ai_alone']})")
print(f"False alarms:    {s['false_alarms_final']}")
if s["errors"]:
    print(f"Errors:          {s['errors']} (re-run later if the AI was overloaded)")

if s["errors"] == 0 and s["cases"] == 10:
    path = write_markdown(results, Path(__file__).parent / "docs" / "evaluation.md")
    print(f"\nSaved to {path}")
else:
    print("\nNot saved: only a complete run with no errors is written to "
          "docs/evaluation.md.")
