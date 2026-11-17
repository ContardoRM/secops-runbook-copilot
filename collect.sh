#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

ssh -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o ConnectTimeout=10 vm2 \
  'python3 ~/secops-lab/collectors/docker_inventory.py &&
   python3 ~/secops-lab/collectors/evaluate_ssh.py'

scp vm2:secops-lab/reports/docker-inventory.json reports/
scp vm2:secops-lab/reports/ssh-assessment.json reports/

echo "Reportes recogidos en: $PWD/reports"
