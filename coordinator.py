import argparse
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
import yaml

ROOT = Path(__file__).resolve().parent

CASES = {
    "docker": {
        "asset": "ssh-vulnerable",
        "collect": "collect.sh",
        "analyze": "analyze.py",
        "execute": "execute.py",
        "inventory": "docker-inventory.json",
        "assessment": "ssh-assessment.json",
        "plan": "ai-plan.json",
        "actionable": "exposure_conditions_present",
        "runbook": "disable-ssh-password-authentication",
    },
    "kernel": {
        "asset": "secops-kernel-lab",
        "collect": "collect-kernel.sh",
        "analyze": "analyze-kernel.py",
        "execute": "execute-kernel.py",
        "inventory": "kernel-inventory.json",
        "assessment": "kernel-assessment.json",
        "plan": "ai-kernel-plan.json",
        "actionable": "fixed_kernel_installed_not_active",
        "runbook": "activate-fixed-kernel",
    },
}

def run(script):
    executable = "bash" if script.endswith(".sh") else sys.executable
    subprocess.run([executable, str(ROOT / script)], cwd=ROOT, check=True)

def load(name):
    return json.loads((ROOT / "reports" / name).read_text())

def asset_policy(asset_id):
    document = yaml.safe_load((ROOT / "inventory/assets.yaml").read_text())
    matches = [
        asset for asset in document["assets"] if asset["id"] == asset_id
    ]
    if len(matches) != 1:
        raise ValueError("Activo ausente o duplicado en el inventario.")
    return matches[0]

def validate(case):
    evidence = load(case["inventory"])
    assessment = load(case["assessment"])
    if (
        evidence["asset_id"] != case["asset"]
        or assessment["asset_id"] != case["asset"]
        or evidence["collection_status"] != "complete"
        or assessment["inventory_collected_at"] != evidence["collected_at"]
    ):
        raise ValueError("Evidencia incompleta o inconsistente.")
    age = (
        dt.datetime.now(dt.timezone.utc)
        - dt.datetime.fromisoformat(evidence["collected_at"])
    ).total_seconds()
    if not 0 <= age <= 900:
        raise ValueError("Evidencia fuera del límite de 15 minutos.")
    return evidence, assessment

def validate_plan(case, evidence, assessment):
    policy = asset_policy(case["asset"])
    plan = load(case["plan"])
    selected = plan["proposal"].get("recommended_runbook")
    if (
        plan["proposal"].get("asset_id") != case["asset"]
        or plan["inventory_collected_at"] != evidence["collected_at"]
        or assessment["status"] != case["actionable"]
        or selected != case["runbook"]
        or selected not in policy.get("allowed_runbooks", [])
        or assessment.get("recommended_runbook") != selected
        or policy.get("approval_required") is not True
        or plan.get("approval_required") is not True
        or plan.get("approved") is not False
        or plan.get("action_executed") is not False
        or not (ROOT / "runbooks" / (selected + ".md")).is_file()
    ):
        raise ValueError("La propuesta no cumple la política del laboratorio.")

def report():
    lines = [
        "# Reporte del laboratorio SecOps",
        "",
        "Generado: " + dt.datetime.now(dt.timezone.utc).isoformat(),
        "",
        "## Estado observado",
        "",
        "| Activo | Evidencia UTC | Estado | Detalle |",
        "|---|---|---|---|",
    ]
    for name, case in CASES.items():
        try:
            evidence, assessment = validate(case)
            if name == "kernel":
                detail = "Kernel activo: " + evidence["active_kernel"]
            else:
                values = evidence["ssh_configuration"]["passwordauthentication"]
                detail = "PasswordAuthentication: " + ", ".join(values)
            lines.append(
                f'| {case["asset"]} | {evidence["collected_at"]} | '
                f'{assessment["status"]} | {detail} |'
            )
        except Exception:
            lines.append(
                f'| {case["asset"]} | — | Sin evidencia reciente válida | Revisar |'
            )

    lines.extend([
        "",
        "## Alcance",
        "",
        "- Docker: mitigación de configuración; no acredita parche permanente.",
        "- Kernel: comprobación limitada a las versiones del caso seleccionado.",
        "- No se ha confirmado explotación mediante estas comprobaciones.",
        "- Gemini propone; las reglas y la aprobación controlan la ejecución.",
        "",
        "## Registros de ejecución",
        "",
    ])
    for path in sorted((ROOT / "reports").glob("*/execution.json")):
        try:
            audit = json.loads(path.read_text())
            lines.append(
                f'- [{path.parent.name}]({path.parent.name}/execution.json): '
                f'`{audit.get("status", "desconocido")}`'
            )
        except (ValueError, OSError):
            lines.append(f"- Registro ilegible: {path.parent.name}")

    destination = ROOT / "reports/lab-report.md"
    destination.write_text("\n".join(lines) + "\n")
    print("\nReporte:", destination)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["status", "analyze", "execute"])
    parser.add_argument("--asset", choices=list(CASES))
    args = parser.parse_args()
    if args.action != "status" and not args.asset:
        parser.error("analyze y execute requieren --asset.")

    targets = [args.asset] if args.asset else list(CASES)
    for name in targets:
        case = CASES[name]
        run(case["collect"])
        evidence, assessment = validate(case)
        print(f'\n{name}: {assessment["status"]}', flush=True)

        if args.action == "status":
            continue
        if assessment["status"] != case["actionable"]:
            print("No corresponde ejecutar el runbook de este caso.")
            continue

        run(case["analyze"])
        validate_plan(case, evidence, assessment)
        print("Propuesta compatible con la política.", flush=True)

        if args.action == "execute":
            # El ejecutor conserva su propia aprobación interactiva.
            run(case["execute"])

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("Detenido:", error)
        sys.exit(1)
    finally:
        report()
