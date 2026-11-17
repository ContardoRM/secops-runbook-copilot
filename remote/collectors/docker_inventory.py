import datetime
import json
import pathlib
import subprocess

CONTAINER = "ssh-vulnerable"

def command(args):
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=30
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Falló la consulta")
    return (result.stdout.strip() or result.stderr.strip())

def inside(*args):
    return command(["sudo", "docker", "exec", CONTAINER, *args])

container = json.loads(command(
    ["sudo", "docker", "inspect", CONTAINER]
))[0]

version = inside("/opt/openssh/sbin/sshd", "-V")
config_text = inside("/opt/openssh/sbin/sshd", "-T")
config = {}
for line in config_text.splitlines():
    key, _, value = line.partition(" ")
    config.setdefault(key.lower(), []).append(value.strip())

# Solo salen indicadores booleanos; los hashes permanecen en el contenedor.
account_flags = inside(
    "awk", "-F:",
    '''BEGIN { star=0; sha=0 }
    $1=="labuser" && $2=="*" { star=1 }
    $1=="referenceuser" && $2 ~ /^\\$[56]\\$/ { sha=1 }
    END {
      printf "{\\"labuser_has_star\\":%s,\\"reference_has_sha_crypt\\":%s}",
             star ? "true" : "false", sha ? "true" : "false"
    }''',
    "/etc/shadow"
)

report = {
    "schema_version": 1,
    "asset_id": CONTAINER,
    "collected_at": datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat(),
    "collection_status": "complete",
    "container": {
        "running": container["State"]["Running"],
        "image_reference": container["Config"]["Image"],
        "image_id": container["Image"],
        "network_mode": container["HostConfig"]["NetworkMode"],
        "port_bindings": container["HostConfig"]["PortBindings"],
    },
    "software": {
        "openssh": version,
        "musl": next(
            line[2:]
            for record in inside("cat", "/lib/apk/db/installed").split("\n\n")
            if "P:musl" in record.splitlines()
            for line in record.splitlines()
            if line.startswith("V:")
        ),
        "alpine_release": inside("cat", "/etc/alpine-release"),
        "architecture": inside("uname", "-m"),
    },
    "ssh_configuration": {
        key: config.get(key, [])
        for key in (
            "passwordauthentication", "usepam",
            "permitrootlogin", "allowusers"
        )
    },
    "account_conditions": json.loads(account_flags),
    "assessment": "pending",
}

destination = (
    pathlib.Path.home() / "secops-lab/reports/docker-inventory.json"
)
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text(json.dumps(report, indent=2) + "\n")
print(destination.read_text())
