"""Write an incident report file.   Usage: python make_report.py INC-001"""
import sys
from pathlib import Path

from app.agent.reports import gather_markdown

if len(sys.argv) < 2:
    raise SystemExit("Usage: python make_report.py INC-001")
incident_id = sys.argv[1].upper()
try:
    text = gather_markdown(incident_id)
except KeyError as e:
    raise SystemExit(str(e))

folder = Path(__file__).parent / "reports"
folder.mkdir(exist_ok=True)
path = folder / f"{incident_id}.md"
path.write_text(text, encoding="utf-8")
print(f"Report written to {path}")
