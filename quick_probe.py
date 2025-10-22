# run_me_once.py (example)
from auditor.tools.python.ruff import RuffTool
from auditor.tools.python.bandit import BanditTool
from auditor.tools.python.radon import RadonTool
from auditor.tools.python.pyright import PyrightTool
from auditor.tools.python.mypy import MypyTool
# from auditor.tools.python.gitleaks import GitleaksTool
from auditor.storage.writers import SQLiteWriter
from auditor.tools.python.vulture import VultureTool
from auditor.tools.python.jscpd import PythonJscpdTool
from auditor.tools.tsx import (
    EslintTool,
    TscTool,
    MadgeTool,
    TsPruneTool,
    BiomeTool,
    DepcheckTool,
    TsxJscpdTool
)
import os
os.environ.setdefault("AUDITOR_NODE_PREFIX", "/abs/path/to/CodeQAuditor")

repo = "pits"
tools = [
    BanditTool(timeout_s=180),
    MypyTool(timeout_s=300, ignore_missing_imports=True),
    PyrightTool(timeout_s=300),
    RadonTool(timeout_s=120),
    RuffTool(timeout_s=120),
    VultureTool(min_confidence=80),
    PythonJscpdTool(min_tokens=50),
    # # GitleaksTool(timeout_s=60),
    EslintTool(timeout_s=300),
    TscTool(timeout_s=300),
    MadgeTool(timeout_s=300),
    TsPruneTool(timeout_s=300),
    BiomeTool(timeout_s=300),
    DepcheckTool(timeout_s=300),
    TsxJscpdTool(min_tokens=50),
]

json_data=[]


db = SQLiteWriter("out/auditor.sqlite3")
for t in tools:
    scan_id = db.start_scan(t.name, repo)
    findings, run = t.audit(repo)
    # write findings to json
    json_data.append([f.to_dict() for f in findings])
    db.write_findings(scan_id, [f.to_dict() for f in findings])
    d = run.to_dict()
    db.finish_scan(
        scan_id,
        returncode=d["returncode"],
        duration_s=d["duration_s"],
        stdout_bytes=d["stdout_bytes"],
        stderr_bytes=d["stderr_bytes"],
    )
db.close()
# save json data to file
import json
with open("out/audit_results.json", "w") as f:
    json.dump(json_data, f, indent=2)
print("done")
