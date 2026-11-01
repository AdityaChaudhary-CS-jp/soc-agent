"""Tool 2: turn a MITRE ATT&CK technique ID into a name and attack stage.

This is a small, simplified subset covering the techniques in our data.
"""

# Order of stages in a typical attack. Higher number = later stage = riskier.
STAGE_RANK = {
    "Initial Access": 1,
    "Execution": 2,
    "Credential Access": 3,
    "Privilege Escalation": 4,
    "Discovery": 2,
    "Command and Control": 5,
    "Exfiltration": 6,
}

TECHNIQUES = {
    "T1110": ("Brute Force", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1566": ("Phishing", "Initial Access"),
    "T1204": ("User Execution", "Execution"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
}


def mitre_map(technique_id):
    """Return name, stage and stage_rank for a technique ID like 'T1110'."""
    if not technique_id:
        return {"technique_id": None, "found": False,
                "note": "No MITRE technique provided."}
    tid = technique_id.strip().upper()
    if tid not in TECHNIQUES:
        return {"technique_id": tid, "found": False,
                "note": "Technique not in our local MITRE list."}
    name, stage = TECHNIQUES[tid]
    return {"technique_id": tid, "found": True, "name": name,
            "stage": stage, "stage_rank": STAGE_RANK[stage]}
