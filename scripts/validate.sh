#!/usr/bin/env bash
# Offline sanity checks. Run from the project root:  ./scripts/validate.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== YAML syntax"
python3 - <<'PY'
import glob, yaml
files = glob.glob('**/*.yml', recursive=True) + glob.glob('**/*.example', recursive=True)
for f in sorted(files):
    yaml.safe_load(open(f))
    print("ok", f)
PY

echo "== Python filter plugin"
python3 -c "import ast,sys; ast.parse(open('filter_plugins/audit_filters.py').read()); print('ok filter_plugins/audit_filters.py')"

if command -v ansible-playbook >/dev/null 2>&1; then
  echo "== ansible-playbook --syntax-check"
  ansible-playbook -i inventory/hosts.yml site.yml --syntax-check
else
  echo "ansible-playbook not installed here - skipped syntax check"
fi
