"""Tool 1: look up an IP address in our MOCK threat-intel data.

Rule: never invent facts. If we have no data, say so clearly.
"""
import ipaddress
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2] / "data"

# Company-internal ranges. (We do NOT use addr.is_private, because Python
# also treats the documentation IPs used in our test data as "private".)
INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]

# For the error-recovery demo: the FIRST lookup of these IPs raises a
# TimeoutError, the second one works. Leave empty for normal use.
FAIL_ONCE = set()
_already_failed = set()


def threat_intel_lookup(ip: str) -> dict:
    """Return the reputation of an IP. Always returns a dict with a 'status'.

    status values:
      ok         -> we have a record (see reputation, score, tags)
      no_data    -> IP is known but has no score (reputation 'unknown')
      not_found  -> IP is not in our threat-intel file
      internal   -> private/company IP, not checked against intel
      invalid    -> not a valid IP address
    Raises TimeoutError only when FAIL_ONCE is used for the demo.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "status": "invalid", "reputation": "unknown",
                "note": "Not a valid IP address."}

    if any(addr in net for net in INTERNAL_NETS):
        return {"ip": ip, "status": "internal", "reputation": "internal",
                "note": "Private IP address; threat intel does not apply."}

    if ip in FAIL_ONCE and ip not in _already_failed:
        _already_failed.add(ip)
        raise TimeoutError(f"Threat-intel service timed out for {ip}")

    with open(DATA_DIR / "threat_intel.json", encoding="utf-8") as f:
        intel = json.load(f)

    record = intel.get(ip)
    if record is None:
        return {"ip": ip, "status": "not_found", "reputation": "unknown",
                "note": "IP not present in threat-intel data."}
    if record.get("score") is None:
        return {"ip": ip, "status": "no_data", "reputation": "unknown",
                "note": "IP is listed but has no reputation score."}
    return {"ip": ip, "status": "ok", **record}