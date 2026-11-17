import datetime as dt
import json
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
RUNBOOK = "disable-ssh-password-authentication"

REMOTE = r'''
import pathlib
import re
import subprocess
import sys
import tempfile

name = "ssh-vulnerable"
expected_image = sys.argv[1]
run_id = sys.argv[2]

def docker(*args):
    return subprocess.check_output(
        ["sudo", "-n", "docker", *args],
        text=True, stderr=subprocess.STDOUT, timeout=60
    )

import json
state = json.loads(docker("inspect", name))[0]
if state["Image"] != expected_image or not state["State"]["Running"]:
    raise RuntimeError("El contenedor cambió o no está ejecutándose.")
if state["HostConfig"]["PortBindings"]:
    raise RuntimeError("Hay puertos publicados inesperados.")

original = docker("exec", name, "cat", "/etc/ssh/sshd_config")
pattern = r"(?im)^[ \t]*PasswordAuthentication[ \t]+yes[ \t]*$"
if len(re.findall(pattern, original)) != 1:
    raise RuntimeError("Configuración distinta a la esperada; requiere revisión.")
candidate = re.sub(pattern, "PasswordAuthentication no", original)

backup = pathlib.Path.home() / "secops-lab/reports" / run_id
backup.mkdir(parents=True, exist_ok=False)
(backup / "sshd_config.before").write_text(original)

changed = False
try:
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "sshd_config"
        path.write_text(candidate)
        docker("cp", str(path), name + ":/etc/ssh/sshd_config.secops")

    docker("exec", name, "/opt/openssh/sbin/sshd",
           "-t", "-f", "/etc/ssh/sshd_config.secops")

    changed = True
    docker("exec", name, "mv",
           "/etc/ssh/sshd_config.secops", "/etc/ssh/sshd_config")
    docker("restart", name)

    config = docker("exec", name, "/opt/openssh/sbin/sshd", "-T")
    lines = [line.lower().strip() for line in config.splitlines()]
    if "passwordauthentication no" not in lines:
        raise RuntimeError("No se confirmó la mitigación.")

    print("MITIGACION_VERIFICADA")
    print("Copia de recuperación en VM2:", backup)
except Exception:
    if changed:
        try:
            docker("cp", str(backup / "sshd_config.before"),
                   name + ":/etc/ssh/sshd_config")
            docker("restart", name)
            print("Se restauró la configuración anterior; requiere revisión.")
        except Exception:
            print("FALLO DE RECUPERACION: revisar el contenedor en VM2.")
    raise
'''

def main():
    plan = json.loads((ROOT / "reports/ai-plan.json").read_text())
    inventory = json.loads(
        (ROOT / "reports/docker-inventory.json").read_text()
    )
    assessment = json.loads(
        (ROOT / "reports/ssh-assessment.json").read_text()
    )
    proposal = plan["proposal"]
    if (
        proposal.get("asset_id") != "ssh-vulnerable"
        or proposal.get("recommended_runbook") != RUNBOOK
        or assessment.get("status") != "exposure_conditions_present"
        or plan["inventory_collected_at"] != inventory["collected_at"]
        or assessment["inventory_collected_at"] != inventory["collected_at"]
    ):
        raise ValueError("Plan o evidencia no compatibles.")

    age = (
        dt.datetime.now(dt.timezone.utc)
        - dt.datetime.fromisoformat(inventory["collected_at"])
    ).total_seconds()
    if not 0 <= age <= 900:
        raise ValueError("Evidencia antigua. Recolecta y analiza nuevamente.")

    print("Activo: ssh-vulnerable, dentro de VM2")
    print("Acción: deshabilitar contraseñas y reiniciar SOLO el contenedor.")
    print("El acceso SSH al host Ubuntu no se modifica.")
    print("labuser no podrá entrar por SSH mientras no tenga claves.")
    if input("Escribe APROBAR para continuar: ").strip() != "APROBAR":
        print("Cancelado. Sin cambios.")
        return

    run_id = dt.datetime.now(dt.timezone.utc).strftime(
        "execution-%Y%m%dT%H%M%S%fZ"
    )
    folder = ROOT / "reports" / run_id
    folder.mkdir()
    audit = {
        "runbook": RUNBOOK,
        "approved": True,
        "approved_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "plan": plan,
        "before": inventory,
        "status": "started"
    }
    record = folder / "execution.json"
    record.write_text(json.dumps(audit, indent=2, ensure_ascii=False))

    remote_command = "python3 - " + shlex.join([
        inventory["container"]["image_id"], run_id
    ])
    try:
        result = subprocess.run(
            ["ssh", "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=yes",
             "-o", "ConnectTimeout=10", "vm2", remote_command],
            input=REMOTE, text=True, capture_output=True, timeout=300
        )
        audit.update({
            "status": (
                "mitigation_verified"
                if result.returncode == 0 else "requires_review"
            ),
            "stdout": result.stdout,
            "stderr": result.stderr
        })
        print(result.stdout)
        if result.returncode:
            print(result.stderr)
            raise RuntimeError("La ejecución necesita revisión.")

        subprocess.run(["bash", str(ROOT / "collect.sh")], check=True)
        after = json.loads(
            (ROOT / "reports/ssh-assessment.json").read_text()
        )
        audit["after_assessment"] = after
        if after["status"] != "password_authentication_mitigated":
            raise RuntimeError("El evaluador no confirmó la mitigación.")
        audit["status"] = "completed"
        print("Mitigación confirmada. Registro:", record)
    except Exception:
        audit["status"] = "requires_review"
        raise
    finally:
        record.write_text(json.dumps(audit, indent=2, ensure_ascii=False))

try:
    main()
except Exception as error:
    print("Detenido:", error)
    sys.exit(1)
