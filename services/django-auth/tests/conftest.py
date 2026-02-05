# conftest.py
import pytest
import json
import pandas as pd
from pathlib import Path
from datetime import datetime

# =====================
# Directories
# =====================
BASE_DIR = Path("test_results")
CURRENT_RUN = BASE_DIR / datetime.now().strftime("%Y%m%d_%H%M%S")
EXCEL_DIR = CURRENT_RUN / "excel_reports"
LOGS_DIR = CURRENT_RUN / "logs"

for d in [BASE_DIR, CURRENT_RUN, EXCEL_DIR, LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# =====================
# Global storage
# =====================
test_results = []

# =====================
# Pytest hook (runs ONCE)
# =====================
@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    if not test_results:
        print("⚠️ No test results collected")
        return

    df = pd.DataFrame(test_results)

    # Excel
    excel_file = EXCEL_DIR / "api_test_results.xlsx"
    df.to_excel(excel_file, index=False)

    # CSV
    csv_file = EXCEL_DIR / "api_test_results.csv"
    df.to_csv(csv_file, index=False)

    # JSON
    json_file = CURRENT_RUN / "api_test_results.json"
    with open(json_file, "w") as f:
        json.dump(test_results, f, indent=2, default=str)

    # Summary log
    summary = {
        "total_tests": session.testscollected,
        "failed": session.testsfailed,
        "exit_status": exitstatus,
        "timestamp": datetime.now().isoformat(),
    }

    with open(LOGS_DIR / "pytest_summary.log", "w") as f:
        f.write(json.dumps(summary, indent=2))

    print(f"✅ Test results written to {CURRENT_RUN}")
