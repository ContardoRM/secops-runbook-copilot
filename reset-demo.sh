#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

echo "Se restaurarán los escenarios de prueba en Docker y VM1."
echo "VM1 reiniciará; el contenedor seguirá sin puertos publicados."
read -r -p "Escribe RESET LAB para continuar: " answer
if [ "$answer" != "RESET LAB" ]; then
  echo "Cancelado."
  exit 0
fi

run_id="reset-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "reports/$run_id"

# Comprobaciones de VM1 antes de modificar los escenarios.
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes vm1 'bash -s' <<'REMOTE'
set -euo pipefail
test "$(hostname)" = secops-kernel-lab
test "$(uname -r)" = 7.0.0-1013-oracle
test "$(dpkg-query -W -f='${Status}' linux-image-7.0.0-1012-oracle)" = 'install ok installed'
sudo -n grep -Fq "menuentry 'Ubuntu, with Linux 7.0.0-1012-oracle'" /boot/grub/grub.cfg
if sudo -n grub-editenv list | grep -q '^next_entry=.'; then
  echo "Hay otro arranque seleccionado; revisar antes de continuar."
  exit 1
fi
REMOTE

# Solo se modifica el contenedor conocido del laboratorio.
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes vm2 'bash -s' <<'REMOTE'
set -euo pipefail
test "$(hostname)" = secops-docker-lab
test "$(sudo -n docker inspect -f '{{.State.Running}}' ssh-vulnerable)" = true
test "$(sudo -n docker inspect -f '{{.HostConfig.NetworkMode}}' ssh-vulnerable)" = secops-ssh-net
test "$(sudo -n docker network inspect -f '{{.Internal}}' secops-ssh-net)" = true
test "$(sudo -n docker inspect -f '{{json .HostConfig.PortBindings}}' ssh-vulnerable)" = '{}'
test "$(sudo -n docker inspect -f '{{.Image}}' ssh-vulnerable)" = 'sha256:648a43a9b4adbdc08a20a694024204ea180fead33bdd2fa85a61ad7690e7fcfd'

sudo -n docker exec ssh-vulnerable sh -ec '
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.before-reset
  sed "s/^PasswordAuthentication no$/PasswordAuthentication yes/" \
    /etc/ssh/sshd_config > /etc/ssh/sshd_config.reset
  /opt/openssh/sbin/sshd -t -f /etc/ssh/sshd_config.reset
  mv /etc/ssh/sshd_config.reset /etc/ssh/sshd_config
'
sudo -n docker restart ssh-vulnerable
sudo -n docker exec ssh-vulnerable /opt/openssh/sbin/sshd -T |
  grep -i '^PasswordAuthentication yes$'
REMOTE

# Selección de kernel para un único arranque.
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes vm1 'bash -s' <<'REMOTE'
set -euo pipefail
sudo -n grub-reboot 'Advanced options for Ubuntu>Ubuntu, with Linux 7.0.0-1012-oracle'
if ! sudo -n grub-editenv list |
  grep -Fxq 'next_entry=Advanced options for Ubuntu>Ubuntu, with Linux 7.0.0-1012-oracle'; then
  sudo -n grub-editenv /boot/grub/grubenv unset next_entry
  exit 1
fi
if ! sudo -n shutdown -r +1 'SecOps lab: preparar demostracion'; then
  sudo -n grub-editenv /boot/grub/grubenv unset next_entry
  exit 1
fi
REMOTE

# Archivar propuestas anteriores para que no se reutilicen.
for file in ai-plan.json ai-kernel-plan.json; do
  if [ -f "reports/$file" ]; then
    mv "reports/$file" "reports/$run_id/"
  fi
done

echo "Docker restaurado; reinicio de VM1 programado en un minuto."
echo "Espera a que VM1 vuelva y comprueba el estado con el coordinador."
