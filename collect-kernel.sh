#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

ssh -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o ConnectTimeout=10 vm1 \
  'python3 ~/secops-lab/collectors/kernel_inventory.py'

scp vm1:secops-lab/reports/kernel-inventory.json reports/
scp vm1:secops-lab/reports/kernel-assessment.json reports/
