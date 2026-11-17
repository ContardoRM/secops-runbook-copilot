import datetime
import json
from pathlib import Path
import subprocess

reports = Path.home() / "secops-lab/reports"
source = reports / "docker-inventory.json"
data = json.loads(source.read_text())

# Recolectar evidencia de PAM directamente del ejecutable.
result = subprocess.run(
    ["sudo", "docker", "exec", "ssh-vulnerable",
     "/opt/openssh/sbin/sshd", "-t", "-o", "UsePAM=yes"],
    capture_output=True, text=True, timeout=30
)
diagnostic = (result.stdout + result.stderr).strip()
pam_disabled = "Unsupported option UsePAM" in diagnostic

software = data.get("software", {})
config = data.get("ssh_configuration", {})
accounts = data.get("account_conditions", {})

checks = {
    "expected_lab_openssh": software.get("openssh", "").startswith(
        "OpenSSH_10.6p1,"
    ),
    "musl_identified": bool(software.get("musl")),
    "pam_unsupported": pam_disabled,
    "password_authentication_enabled":
        config.get("passwordauthentication") == ["yes"],
    "target_account_has_star": accounts.get("labuser_has_star") is True,
    "reference_sha_crypt_present":
        accounts.get("reference_has_sha_crypt") is True,
    "target_account_allowed":
        config.get("allowusers") == ["labuser"],
}

if all(checks.values()):
    status = "exposure_conditions_present"
elif config.get("passwordauthentication") == ["no"]:
    status = "password_authentication_mitigated"
else:
    status = "requires_review"

assessment = {
    "asset_id": data["asset_id"],
    "evaluated_at": datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat(),
    "inventory_collected_at": data["collected_at"],
    "rule_id": "lab-openssh-musl-authentication-v1",
    "scope": "Exact laboratory build; not a general vulnerability scanner",
    "checks": checks,
    "pam_diagnostic": diagnostic,
    "status": status,
    "exploitation_confirmed": False,
    "recommended_runbook": (
        "disable-ssh-password-authentication"
        if status == "exposure_conditions_present" else None
    ),
    "approval_required": True,
    "action_executed": False,
}

output = reports / "ssh-assessment.json"
output.write_text(json.dumps(assessment, indent=2) + "\n")
print(output.read_text())
