import datetime as dt
import json
from pathlib import Path
import platform
import subprocess

LAB_OLD = "7.0.0-1012-oracle"
LAB_FIXED = "7.0.0-1013-oracle"
FIXED_PACKAGE_VERSION = "7.0.0-1013.13~24.04.1"

result = subprocess.run(
    ["dpkg-query", "-W",
     "-f=${binary:Package}\t${Version}\t${Status}\n",
     "linux-image-[0-9]*"],
    capture_output=True, text=True, timeout=30, check=True
)

installed = {}
for line in result.stdout.splitlines():
    name, version, status = line.split("\t", 2)
    if status == "install ok installed":
        installed[name.split(":")[0]] = version

active = platform.release()
fixed_installed = (
    installed.get("linux-image-" + LAB_FIXED) == FIXED_PACKAGE_VERSION
)

if active == LAB_OLD and fixed_installed:
    status = "fixed_kernel_installed_not_active"
    runbook = "activate-fixed-kernel"
elif active == LAB_FIXED and fixed_installed:
    status = "fixed_kernel_active_for_lab_case"
    runbook = None
else:
    status = "requires_review"
    runbook = None

timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
inventory = {
    "schema_version": 1,
    "asset_id": "secops-kernel-lab",
    "collected_at": timestamp,
    "collection_status": "complete",
    "hostname": platform.node(),
    "architecture": platform.machine(),
    "os_release": platform.freedesktop_os_release(),
    "active_kernel": active,
    "installed_kernel_packages": installed
}
assessment = {
    "asset_id": inventory["asset_id"],
    "inventory_collected_at": timestamp,
    "rule_id": "lab-oracle-kernel-v1",
    "scope": "Exact laboratory versions; not a general vulnerability scanner",
    "reference": "https://ubuntu.com/security/CVE-2026-92502",
    "checks": {
        "expected_old_kernel_active": active == LAB_OLD,
        "fixed_kernel_package_installed": fixed_installed,
        "fixed_kernel_active": active == LAB_FIXED
    },
    "status": status,
    "recommended_runbook": runbook,
    "approval_required": True,
    "exploitation_confirmed": False,
    "action_executed": False
}

folder = Path.home() / "secops-lab/reports"
folder.mkdir(parents=True, exist_ok=True)
for name, report in (
    ("kernel-inventory.json", inventory),
    ("kernel-assessment.json", assessment)
):
    content = json.dumps(report, indent=2)
    (folder / name).write_text(content + "\n")
    print(content)
