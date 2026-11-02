"""Approve or reject actions proposed by the agent.

  python approve.py list                      (pending actions)
  python approve.py list --all                (everything)
  python approve.py approve 3 --user admin1 --comment "confirmed"
  python approve.py reject 2 --user analyst1 --comment "not needed"

Users: viewer1, analyst1, analyst2, admin1 (see app/auth.py)
"""
import argparse

from app.agent import approvals

parser = argparse.ArgumentParser(description="Action approval queue")
sub = parser.add_subparsers(dest="command", required=True)
p_list = sub.add_parser("list")
p_list.add_argument("--all", action="store_true")
for name in ("approve", "reject"):
    p = sub.add_parser(name)
    p.add_argument("action_id", type=int)
    p.add_argument("--user", required=True)
    p.add_argument("--comment", default="")
args = parser.parse_args()

if args.command == "list":
    rows = approvals.list_actions(None if args.all else "pending_approval")
    if not rows:
        print("No actions to show.")
    for r in rows:
        flag = "ADMIN ONLY" if r["sensitive"] else "analyst ok"
        print(f"#{r['id']}  {r['incident_id']}  [{r['status']}]  ({flag})")
        print(f"     {r['action']}")
        if r["execution_result"]:
            print(f"     -> {r['execution_result']}  (by {r['decided_by']})")
else:
    try:
        row = approvals.decide(args.action_id, args.user,
                               approve=(args.command == "approve"),
                               comment=args.comment)
        print(f"Action #{row['id']} is now: {row['status']}")
        if row["execution_result"]:
            print(row["execution_result"])
    except (PermissionError, ValueError, KeyError) as e:
        print("Refused:", e)
