#!/usr/bin/env bash
# Operator step: install PRGuard's FailproofAI policy where failproofai loads it.
# Agents cannot run this (failproofai's guard blocks writes under .failproofai/).
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p .failproofai/policies
cp failproofai/prguard-policies.mjs .failproofai/policies/prguard-policies.mjs
echo "Installed .failproofai/policies/prguard-policies.mjs"
echo
echo "Next:"
echo "  failproofai policies --list            # expect prguard-tool-gateway"
echo "  set ENFORCER=FAILPROOFAI in .env, then restart the backend"
echo "  .venv/bin/python scripts/failproofai_check.py"
