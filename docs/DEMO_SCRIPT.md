# Demo script (about 3 minutes)

## Before the demo (do this once, while the AI service is working)

1. Stop the dashboard if it is running.
2. Delete `data/soc.db` and `logs/audit_log.jsonl` for a clean start.
3. Run each investigation so the reports are saved and the actions are queued:
   ```
   python run_incident.py INC-001
   python run_incident.py INC-002
   python run_incident.py INC-003
   ```
4. Start the dashboard: `python -m streamlit run dashboard.py`
5. Do not approve anything in advance. Keep the approvals for the live demo.
6. Practise the two terminal extras below (`python demo_guardrails.py` and `python test_resilience.py`): they need no AI.
7. Record a backup screen video of the whole flow below, including the extras.

## Script

**0:00 The problem (20 s)**
"Security teams get thousands of alerts and most are noise. My agent does the first pass, but people stay in control."

**0:20 Incidents and scoring (30 s)**
Open the Incidents tab. "45 alerts came in. 15 of them were grouped into 3 incidents and 30 are routine noise. Each incident has a transparent score: threat intel, attack stage, alert volume, severity. INC-001 is critical, 82.8." Open INC-001 and show the timeline: failed logins, a successful login, then root.

**0:50 The AI investigation (40 s)**
Show the saved AI report for INC-001. "It chose its own tools: IP reputation, related alerts, MITRE mapping. Every evidence line cites an alert ID or a tool result. It also states what it does not know."

**1:30 Human approval and roles (40 s)**
Go to Approvals. Sign in as `analyst1` and click Approve on a sensitive action: the red refusal appears. "Analysts can't approve sensitive actions." Switch to `admin1`, approve it: the simulated result appears. "Nothing runs without approval, and it is only a simulation."

**2:10 Handling uncertainty (25 s)**
Open INC-003. "The destination IP has no threat-intel data, so the agent says needs_review and lowers its confidence instead of guessing. Code guardrails enforce this even if the AI is overconfident." Then run `python demo_guardrails.py` in a terminal: it shows pretend wrong AI answers being corrected (no AI call).

**2:35 Audit and report (15 s)**
Open the Audit log tab (refusal, approval, tool calls). Click Download incident report.

**Optional extra (20 s): error recovery without the AI**
Run `python test_resilience.py`. "This simulates the AI service being overloaded, a retired model and a used-up daily limit. The agent retries, skips to a backup model, records which model answered, and reports a clear error if every model is down."

**2:50 Close (10 s)**
"Agentic investigation, human control, full audit trail, and it survives AI outages by retrying and switching models."

## If the AI service is down during the demo

Do not click Investigate. Use the saved reports and the audit log, and say so: "The agent retries and falls back across models, and reports outages clearly. Here are the reports from earlier runs." Play the backup video if needed.

## Likely questions

- **Is this really an agent?** The model chooses which tools to call and in what order, reads each result, retries failures, and stops when it has enough evidence.
- **How do you stop made-up facts?** It may only use tool results; missing data comes back as `no_data` and is reported as an uncertainty; guardrails cap confidence when intel is missing.
- **What if the AI is wrong?** Guardrails cross-check it against the rule-based score, and no action runs without human approval. `python demo_guardrails.py` shows it.
- **The report says severity "high" but the score says "critical". Why?** The score is the code's number. The AI's severity is accepted if it is within one level of the score; the guardrail only raises it when it is two or more levels lower.
- **Why is a routine alert sometimes sent to needs_review?** A person reviews anything the system is not sure about. The guardrail never lets a routine alert be called an attack, and never lets an alert from a bad IP be dismissed.
- **Is the login real?** No. Sign-in is a drop-down to show the role rules; the rules themselves are enforced in code.
- **What is simulated?** All response actions and all data. No real systems are touched.
- **How accurate is it?** Say what `docs/evaluation.md` shows: 10 cases, labels from the synthetic data generator, no real attack missed. Say that some misses were routine alerts on the same host or user as a real attack.
