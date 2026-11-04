"""SOC Triage dashboard.   Run:  streamlit run dashboard.py"""
import json

import streamlit as st

from app.agent import approvals, store
from app.agent.correlation import correlate
from app.agent.reports import gather_markdown
from app.agent.scoring import score_incident
from app.auth import USERS, role_of
from app.tools.mitre_map import mitre_map

st.set_page_config(page_title="SOC Triage Agent", layout="wide")

# ---------- sign in (role-based access) ----------
st.sidebar.title("SOC Triage Agent")
user = st.sidebar.selectbox("Sign in as", list(USERS))
role = role_of(user)
st.sidebar.write(f"Role: **{role}**")
st.sidebar.caption(
    "viewer: read only. analyst: run investigations, approve safe actions, "
    "reject any. admin: everything, including sensitive actions.")
if st.sidebar.button("Refresh data"):
    st.rerun()
st.sidebar.caption("All response actions are simulated.")

# ---------- data ----------
incidents, standalone = correlate()
scores = {i["incident_id"]: score_incident(i) for i in incidents}
ranked = sorted(incidents, key=lambda i: -scores[i["incident_id"]]["score"])
pending = approvals.list_actions("pending_approval")

st.title("Security Operations: Incident Triage")
c1, c2, c3 = st.columns(3)
c1.metric("Incidents", len(incidents))
c2.metric("Actions awaiting approval", len(pending))
c3.metric("Standalone low-level alerts", len(standalone))

tab_inc, tab_app, tab_audit = st.tabs(["Incidents", "Approvals", "Audit log"])

# ---------- incidents ----------
with tab_inc:
    st.dataframe([{
        "Incident": i["incident_id"],
        "Score": scores[i["incident_id"]]["score"],
        "Level": scores[i["incident_id"]]["level"],
        "Alerts": i["alert_count"],
        "Stage": scores[i["incident_id"]]["highest_stage"],
        "Hosts": ", ".join(i["hosts"]),
        "IPs": ", ".join(i["ips"]),
    } for i in ranked], hide_index=True)

    ids = [i["incident_id"] for i in ranked]
    chosen = st.selectbox("Open incident", ids) if ids else None
    if chosen:
        inc = next(i for i in incidents if i["incident_id"] == chosen)
        sc = scores[chosen]

        st.subheader(f"{chosen}: {sc['level'].upper()} ({sc['score']}/100)")
        st.progress(min(sc["score"] / 100, 1.0))
        b = sc["breakdown"]
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Threat intel", b["intel"])
        m2.metric("Attack stage", b["stage"])
        m3.metric("Alert volume", b["volume"])
        m4.metric("Raw severity", b["severity"])
        if sc["missing_intel_ips"]:
            st.warning("No threat-intel data for: " + ", ".join(sc["missing_intel_ips"]))

        names = []
        for tid in inc["mitre_techniques"]:
            m = mitre_map(tid)
            names.append(f"{tid} {m['name']} ({m['stage']})" if m["found"] else tid)
        st.write("**MITRE ATT&CK:** " + (", ".join(names) or "none"))

        st.markdown("**Timeline**")
        st.dataframe([{
            "Time": a["timestamp"], "Alert": a["id"], "Type": a["type"],
            "Severity": a["raw_severity"], "Host": a["host"], "IP": a["src_ip"],
            "User": a["user"], "Description": a["description"],
        } for a in inc["alerts"]], hide_index=True)

        st.markdown("**AI investigation**")
        saved = store.latest_report(chosen)
        if saved is None:
            st.info("Not investigated yet.")
        else:
            r = saved["report"]
            v1, v2, v3 = st.columns(3)
            v1.metric("Verdict", str(r.get("verdict")))
            v2.metric("Severity", str(r.get("severity")))
            v3.metric("Confidence", str(r.get("confidence")))
            st.write(r.get("summary", ""))
            st.markdown("**Evidence**")
            st.markdown("\n".join(f"- {e}" for e in r.get("evidence", [])) or "None")
            st.markdown("**Uncertainties**")
            st.markdown("\n".join(f"- {u}" for u in r.get("uncertainties", [])) or "None")
            for note in r.get("guardrail_notes", []):
                st.warning("Guardrail: " + note)
            st.caption(f"Investigated at {saved['created_at']}")

        if st.button("Investigate with AI", disabled=(role == "viewer")):
            try:
                from google import genai
                from app.agent.pipeline import run_pipeline
                from app.config import get_api_key
                client = genai.Client(api_key=get_api_key())
                with st.spinner("Agent is investigating..."):
                    _, queued = run_pipeline(inc, sc, client)
                st.session_state["flash"] = (
                    f"{chosen} investigated. {len(queued)} action(s) queued for approval.")
                st.rerun()
            except SystemExit as e:
                st.error(f"Setup problem: {e}")
            except Exception as e:
                st.error(f"Investigation failed: {e}")
        if role == "viewer":
            st.caption("Viewers cannot run investigations.")

        st.download_button("Download incident report (Markdown)",
                           gather_markdown(chosen), file_name=f"{chosen}.md",
                           mime="text/markdown")

# ---------- approvals ----------
with tab_app:
    flash = st.session_state.pop("flash", None)
    if flash:
        st.success(flash)

    st.subheader("Waiting for a human decision")
    if not pending:
        st.info("Nothing is waiting for approval.")
    for a in pending:
        who = "admin only" if a["sensitive"] else "analyst or admin"
        st.markdown(f"**#{a['id']}** | {a['incident_id']} | needs: {who}")
        st.write(a["action"])
        st.caption("Reason: " + (a["reason"] or "-"))
        comment = st.text_input("Comment", key=f"comment_{a['id']}")
        b1, b2 = st.columns(2)
        decision = None
        if b1.button("Approve", key=f"approve_{a['id']}", disabled=(role == "viewer")):
            decision = True
        if b2.button("Reject", key=f"reject_{a['id']}", disabled=(role == "viewer")):
            decision = False
        if decision is not None:
            try:
                row = approvals.decide(a["id"], user, decision, comment)
                st.session_state["flash"] = (
                    f"#{row['id']} {row['status']}. " + (row["execution_result"] or ""))
                st.rerun()
            except PermissionError as e:
                st.error(str(e))
            except (ValueError, KeyError) as e:
                st.error(str(e))
        st.divider()

    st.subheader("Decision history")
    done = [a for a in approvals.list_actions() if a["status"] != "pending_approval"]
    st.dataframe([{
        "#": a["id"], "Incident": a["incident_id"], "Action": a["action"],
        "Status": a["status"], "By": a["decided_by"], "Role": a["decided_role"],
        "When": a["decided_at"], "Comment": a["decision_comment"],
        "Result": a["execution_result"],
    } for a in done], hide_index=True)

# ---------- audit log ----------
with tab_audit:
    pick = st.selectbox("Show events for", ["All"] + [i["incident_id"] for i in ranked])
    events = store.read_audit_events(None if pick == "All" else pick)
    st.caption(f"{len(events)} events (newest first, showing up to 300)")
    st.dataframe([{
        "Time": e.get("time"), "Case": e.get("alert_id"), "Event": e.get("event"),
        "Details": json.dumps({k: v for k, v in e.items()
                               if k not in ("time", "alert_id", "event")},
                              default=str)[:300],
    } for e in reversed(events[-300:])], hide_index=True)
