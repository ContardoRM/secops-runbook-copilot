import datetime as dt
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parent
TARGET = "7.0.0-1013-oracle"
ENTRY = "Advanced options for Ubuntu>Ubuntu, with Linux " + TARGET

def ssh(command, check=True):
    return subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
         "-o", "ConnectTimeout=5", "vm1", command],
        capture_output=True, text=True, timeout=30, check=check
    )

def observe():
    result = ssh(
        "hostname; uname -r; cat /proc/sys/kernel/random/boot_id"
    )
    lines = result.stdout.strip().splitlines()
    if len(lines) != 3 or lines[0] != "secops-kernel-lab":
        raise ValueError("Identidad o respuesta inesperada de VM1.")
    return {"hostname": lines[0], "kernel": lines[1], "boot_id": lines[2]}

def main():
    plan = json.loads((ROOT / "reports/ai-kernel-plan.json").read_text())
    inventory = json.loads(
        (ROOT / "reports/kernel-inventory.json").read_text()
    )
    assessment = json.loads(
        (ROOT / "reports/kernel-assessment.json").read_text()
    )
    proposal = plan["proposal"]
    if (
        proposal.get("asset_id") != "secops-kernel-lab"
        or proposal.get("recommended_runbook") != "activate-fixed-kernel"
        or assessment["status"] != "fixed_kernel_installed_not_active"
        or plan["inventory_collected_at"] != inventory["collected_at"]
        or assessment["inventory_collected_at"] != inventory["collected_at"]
    ):
        raise ValueError("Plan y evidencia no compatibles.")

    age = (
        dt.datetime.now(dt.timezone.utc)
        - dt.datetime.fromisoformat(inventory["collected_at"])
    ).total_seconds()
    if not 0 <= age <= 900:
        raise ValueError("Actualiza la recolección y el análisis de VM1.")

    before = observe()
    if before["kernel"] != "7.0.0-1012-oracle":
        raise ValueError("El kernel activo cambió; vuelve a evaluar.")

    print("VM1: secops-kernel-lab")
    print("Se seleccionará 1013 y se programará un reinicio en un minuto.")
    print("Se interrumpirán temporalmente todos los servicios de VM1.")
    if input("Escribe APROBAR REINICIO: ").strip() != "APROBAR REINICIO":
        print("Cancelado. Sin cambios.")
        return

    run_id = dt.datetime.now(dt.timezone.utc).strftime(
        "kernel-execution-%Y%m%dT%H%M%S%fZ"
    )
    folder = ROOT / "reports" / run_id
    folder.mkdir()
    record = folder / "execution.json"
    audit = {
        "plan": plan, "before": before,
        "approved": True, "status": "started"
    }

    def save():
        record.write_text(json.dumps(audit, indent=2, ensure_ascii=False))

    save()
    try:
        preparation = r'''
set -eu
test "$(hostname)" = secops-kernel-lab
test "$(uname -r)" = 7.0.0-1012-oracle
test "$(cat /proc/sys/kernel/random/boot_id)" = EXPECTED_BOOT
test "$(dpkg-query -W -f='${Version}' linux-image-7.0.0-1013-oracle)" = '7.0.0-1013.13~24.04.1'
test "$(dpkg-query -W -f='${Status}' linux-image-7.0.0-1013-oracle)" = 'install ok installed'
sudo -n grep -Fq "menuentry 'Ubuntu, with Linux 7.0.0-1013-oracle'" /boot/grub/grub.cfg
existing=$(sudo -n grub-editenv list)
if printf '%s\n' "$existing" | grep -q '^next_entry=.'; then
    echo "Ya hay otro arranque programado; requiere revisión." >&2
    exit 1
fi
sudo -n grub-reboot 'Advanced options for Ubuntu>Ubuntu, with Linux 7.0.0-1013-oracle'
if ! sudo -n grub-editenv list | grep -Fxq 'next_entry=Advanced options for Ubuntu>Ubuntu, with Linux 7.0.0-1013-oracle'; then
    sudo -n grub-editenv /boot/grub/grubenv unset next_entry
    exit 1
fi
if ! sudo -n shutdown -r +1 'SecOps lab: activar kernel corregido'; then
    sudo -n grub-editenv /boot/grub/grubenv unset next_entry
    exit 1
fi
'''
        import shlex
        preparation = preparation.replace(
            "EXPECTED_BOOT", shlex.quote(before["boot_id"])
        )
        result = ssh(preparation)
        audit["status"] = "reboot_scheduled"
        audit["schedule_output"] = result.stdout + result.stderr
        save()
        print("Reinicio programado. Esperando hasta 5 minutos...")

        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            time.sleep(5)
            try:
                after = observe()
            except (subprocess.SubprocessError, ValueError):
                continue
            if after["boot_id"] == before["boot_id"]:
                continue
            audit["after"] = after
            if after["kernel"] != TARGET:
                raise RuntimeError("La VM arrancó con otro kernel.")
            break
        else:
            raise RuntimeError(
                "No se verificó el nuevo arranque; revisar consola de Oracle."
            )

        subprocess.run(
            ["bash", str(ROOT / "collect-kernel.sh")], check=True
        )
        final = json.loads(
            (ROOT / "reports/kernel-assessment.json").read_text()
        )
        audit["after_assessment"] = final
        if (
            final["status"] != "fixed_kernel_active_for_lab_case"
            or final["inventory_collected_at"] == inventory["collected_at"]
        ):
            raise RuntimeError("La evaluación posterior no confirmó el cambio.")

        audit["status"] = "completed"
        print("Kernel corregido activo:", TARGET)
    except Exception:
        audit["status"] = "requires_review"
        raise
    finally:
        save()
        print("Registro:", record)

try:
    main()
except Exception as error:
    print("Detenido:", error)
    print("No se harán reintentos de reinicio automáticos.")
    raise SystemExit(1)
