#!/usr/bin/env bash
# Command-line test against ONE host (SOP section 27).
#   ./scripts/run-one-host.sh RHEL-DB01 [-u ansible_audit] [--private-key ~/.ssh/rhel_audit_ed25519] [-K]
# E-mail is disabled for this run; reports are written to ./reports
set -euo pipefail
cd "$(dirname "$0")/.."
HOST="${1:?usage: $0 <inventory-host> [extra ansible-playbook args]}"; shift || true
mkdir -p reports
AUDIT_REPORT_DIR="$PWD/reports" ansible-playbook -i inventory/hosts.yml site.yml \
  --limit "$HOST" -e '{"mail": {"enabled": false}}' "$@"
