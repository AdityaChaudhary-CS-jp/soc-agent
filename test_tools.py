"""Quick check that the three tools work. Run: python test_tools.py"""
from app.tools import threat_intel
from app.tools.threat_intel import threat_intel_lookup
from app.tools.mitre_map import mitre_map
from app.tools.search_logs import search_logs

print("1) Known bad IP:")
print("  ", threat_intel_lookup("203.0.113.45"))

print("2) IP with missing data (Chain 3):")
print("  ", threat_intel_lookup("198.51.100.23"))

print("3) Internal IP:")
print("  ", threat_intel_lookup("10.0.0.5"))

print("4) MITRE lookup:")
print("  ", mitre_map("T1110"))
print("  ", mitre_map("T9999"))

print("5) Alerts from the brute-force IP:")
hits = search_logs(ip="203.0.113.45")
print("  ", len(hits), "alerts; first:", hits[0]["id"], hits[0]["type"])

print("6) Error-recovery demo (fails once, then works):")
threat_intel.FAIL_ONCE.add("192.0.2.99")
for attempt in (1, 2):
    try:
        print("   attempt", attempt, "->", threat_intel_lookup("192.0.2.99")["status"])
    except TimeoutError as e:
        print("   attempt", attempt, "-> TIMEOUT:", e)