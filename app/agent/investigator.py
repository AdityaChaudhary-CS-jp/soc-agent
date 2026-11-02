"""The agent loop: Gemini decides which tool to call, we run it, and we
feed the result back until Gemini has enough evidence for a verdict.
"""
import json
from google.genai import types

from app.config import MODEL
from app.agent.tools_registry import TOOLS

SYSTEM_PROMPT = """You are a SOC (security operations) triage agent.
Investigate the alert you are given by calling tools to gather evidence.

Rules:
- Use ONLY facts returned by your tools. Never invent IPs, reputations,
  MITRE techniques or events.
- Always check the IP reputation and search for related alerts (same IP,
  host and user) before deciding.
- If a tool reports no_data, not_found or tool_failed, say the evidence is
  missing and lower your confidence. Do not guess.
- If the evidence is contradictory or points to a more serious incident,
  investigate further before concluding.
- You may only PROPOSE response actions. Every action needs human approval.
  Never say an action was already carried out.
- A large outbound transfer to an external IP with no threat-intel data cannot be a confirmed false positive. An innocent explanation (such as a backup job) is only circumstantial unless an alert directly confirms the destination is approved. In that case use verdict needs_review, severity at least medium, and confidence at most 0.6.
- confidence must be a number such as 0.6, not a string.
- Never recommend lowering alert thresholds or suppressing alerts.

When finished, reply with ONLY a JSON object with these keys:
verdict (true_positive | false_positive | needs_review),
severity (low | medium | high | critical),
confidence (0.0 to 1.0),
summary (2-3 sentences),
evidence (list of short facts, each citing an alert id or tool result),
mitre_techniques (list of IDs),
recommended_actions (list of {"action": str, "reason": str}),
uncertainties (list of anything missing or unclear).
"""


def run_tool(name: str, args: dict, audit, retries: int = 3):
    """Run one tool. Retries timeouts; reports bad calls back to the model."""
    fn = TOOLS.get(name)
    if fn is None:
        audit.add("tool_error", tool=name, error="unknown tool")
        return {"status": "error", "message": f"Unknown tool '{name}'."}
    for attempt in range(1, retries + 1):
        try:
            return fn(**args)
        except TimeoutError as e:
            audit.add("tool_retry", tool=name, attempt=attempt, error=str(e))
        except TypeError as e:  # wrong or missing arguments
            audit.add("tool_error", tool=name, error=str(e))
            return {"status": "error", "message": f"Bad arguments: {e}"}
        except Exception as e:
            audit.add("tool_error", tool=name, error=str(e))
            return {"status": "error", "message": str(e)}
    audit.add("tool_failed", tool=name, attempts=retries)
    return {"status": "tool_failed",
            "message": "Tool kept timing out. Evidence is unavailable."}


def parse_report(text: str) -> dict:
    """Pull the JSON object out of the model's final answer."""
    try:
        start, end = text.index("{"), text.rindex("}") + 1
        return json.loads(text[start:end])
    except (ValueError, json.JSONDecodeError):
        return {"parse_error": True, "raw": text}


def investigate(alert: dict, client, audit, max_steps: int = 8) -> dict:
    """Investigate one alert and return the agent's report."""
    prompt = "Investigate this alert:\n" + json.dumps(alert, indent=2)
    audit.add("start", alert=alert)
    contents = [types.Content(role="user",
                              parts=[types.Part.from_text(text=prompt)])]
    config = types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT,
        tools=list(TOOLS.values()),
        automatic_function_calling=types.AutomaticFunctionCallingConfig(
            disable=True),   # we run the loop ourselves so we can log it
    )

    for step in range(1, max_steps + 1):
        response = client.models.generate_content(
            model=MODEL, contents=contents, config=config)
        calls = response.function_calls or []
        if not calls:                       # no more tools wanted: done
            audit.add("final_answer", step=step)
            return parse_report(response.text or "")

        contents.append(response.candidates[0].content)
        result_parts = []
        for call in calls:
            args = dict(call.args or {})
            audit.add("tool_call", step=step, tool=call.name, args=args)
            result = run_tool(call.name, args, audit)
            audit.add("tool_result", step=step, tool=call.name, result=result)
            result_parts.append(types.Part.from_function_response(
                name=call.name, response={"result": result}))
        contents.append(types.Content(role="user", parts=result_parts))

    # Safety stop: too many steps, so ask for a verdict with what we have.
    audit.add("max_steps_reached", steps=max_steps)
    contents.append(types.Content(role="user", parts=[types.Part.from_text(
        text="Stop investigating. Give your final JSON verdict now, "
             "using only the evidence gathered so far.")]))
    final = client.models.generate_content(
        model=MODEL, contents=contents,
        config=types.GenerateContentConfig(system_instruction=SYSTEM_PROMPT))
    return parse_report(final.text or "")
