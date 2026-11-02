"""Classify the agent's proposed actions and simulate them.

Nothing here touches a real system: approved actions only produce a
[SIMULATED] message, as the event rules require.
"""
import re

# Checked in order. First match decides the kind.
RULES = [
    ("isolate_host",       r"\b(isolate|quarantine|contain)"),
    ("block_ip",           r"\b(block|blacklist|deny|null-route)"),
    ("reset_credentials",  r"\b(reset|rotate)\b"),
    ("terminate_sessions", r"\b(terminate|kill|revoke)"),
    ("disable_account",    r"\b(disable|lock)\b"),
]
SAFE_WORDS = r"\b(verify|inspect|review|audit|check|investigate|analy[sz]e|monitor|collect|confirm|forensic|document|notify)"

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def classify(action_text: str) -> dict:
    """Return {'kind': ..., 'sensitive': bool}. Unknown actions are
    treated as sensitive (fail-safe)."""
    text = action_text.lower()
    for kind, pattern in RULES:
        if re.search(pattern, text):
            return {"kind": kind, "sensitive": True}
    if re.search(SAFE_WORDS, text):
        return {"kind": "manual_review", "sensitive": False}
    return {"kind": "unknown", "sensitive": True}


def simulate(action: dict, entities: dict) -> str:
    """Pretend to carry out an approved action. Returns a description."""
    text = action["action"]
    ips = IP_RE.findall(text) or entities.get("ips", [])
    hosts = [h for h in entities.get("hosts", []) if h in text] or entities.get("hosts", [])
    users = [u for u in entities.get("users", []) if re.search(rf"\b{re.escape(u)}\b", text)]
    kind = action["kind"]

    if kind == "block_ip":
        msg = f"Firewall rule added: block {', '.join(ips)}"
    elif kind == "isolate_host":
        msg = f"Host {', '.join(hosts)} isolated from the network"
    elif kind == "reset_credentials":
        msg = f"Password reset forced for {', '.join(users) or 'affected accounts'}"
    elif kind == "terminate_sessions":
        msg = f"Active sessions terminated for {', '.join(users) or 'affected accounts'}"
    elif kind == "disable_account":
        msg = f"Account disabled: {', '.join(users) or 'affected accounts'}"
    elif kind == "manual_review":
        msg = "Task added to the analyst work queue"
    else:
        msg = "Unrecognised action: logged for manual handling"
    return f"[SIMULATED] {msg}. No real systems were modified."
