from auditor.tools.mypy.base import MypyTool
from auditor.tools.bandit.base import BanditTool
from auditor.tools.radon.base import RadonTool
from auditor.tools.vulture.base import VultureTool
from auditor.tools.eslint.base import EslintTool
from auditor.models.schema import (
    bandit_json_to_models,
    mypy_ndjson_to_models,
    radon_to_models,
    vulture_text_to_models,
    eslint_rows_to_models,
)

# completed
# bandit

target = "sample/control/control_commerce_mix_next_py_01/frontend/app"


# # ---- Bandit JSON → DB
# tool = BanditTool()
# run = tool.audit(target)

# data = {}

# # run results


# bandit_payload = run.parsed_json or {}
# bandit_raw_json_list = bandit_payload.get("results", [])
# scan_row, bandit_rows = bandit_json_to_models(bandit_raw_json_list, cwd=run.cwd)

# # ---- Mypy NDJSON (string) → DB

# mypy_tool = MypyTool()
# mypy_run = mypy_tool.audit(target)

# mypy_text = mypy_run.stdout.strip()
# mypy_scan_row, mypy_rows = mypy_ndjson_to_models(mypy_text, cwd=mypy_run.cwd)

# # --- Radon (example usage, not converted to DB rows here)
# radon_tool = RadonTool()
# radon_run = radon_tool.audit(target)
# radon_json = radon_run.parsed_json or {}
# radon_scan_row, radon_rows = radon_to_models(radon_json, cwd=radon_run.cwd)


# # print("Radon Run:", radon_run)

# vulture_tool = VultureTool(min_confidence=50)
# vulture_run = vulture_tool.audit(target)
# vulture_scan_row, vulture_rows = vulture_text_to_models(
#     vulture_run.stdout,
#     cwd=vulture_run.cwd,
#     min_confidence=vulture_tool.min_confidence,
# )

eslint_tool = EslintTool()
eslint_run = eslint_tool.audit(target)
scan_row, eslint_rows = eslint_rows_to_models(eslint_run)

# eslint_json = eslint_run.parsed_json or []


# print("Bandit Scan Row:", scan_row)
# print("Bandit Result Rows:", bandit_rows)
# print("Sample Row:", bandit_rows[0].__dict__ if bandit_rows else "No findings")
# print("Mypy Scan Row:", mypy_scan_row)
# print("Mypy Result Rows:", mypy_rows)
# print("Sample Mypy Row:", mypy_rows[0].__dict__  if mypy_rows else "No findings")
# print("Radon Scan Row:", radon_scan_row)
# print("Radon Result Rows:", radon_rows)
# print("Sample Radon Row:", radon_rows[0].__dict__ if radon_rows else "No findings")
# print("Vulture Scan Row:", vulture_scan_row)
# print("Vulture Result Rows:", vulture_rows)
# print("Sample Vulture Row:", vulture_rows[0].__dict__ if vulture_rows else "No findings")
print("ESLint Scan Row:", scan_row)
print("ESLint Result Rows:", eslint_rows)
print("Sample ESLint Row:", eslint_rows[0].__dict__ if eslint_rows else "No findings")
