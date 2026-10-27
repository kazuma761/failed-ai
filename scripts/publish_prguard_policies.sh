#!/usr/bin/env bash
# Publish PRGuard's six policies to FailproofAI Cloud, one new version each.
# FailproofAI Cloud runs each published policy as one self-contained file, so this stamps
# `const ONLY = "<name>";` into a copy of failproofai/prguard-policies.mjs per policy.
# Publishing deploys nothing: use `fp fleet deploy <machine> --add <name>@<version>:observe`.
#   ./scripts/publish_prguard_policies.sh            (needs `fp login`)
set -euo pipefail
cd "$(dirname "$0")/.."
SRC=failproofai/prguard-policies.mjs
FP=$(command -v fp || echo "$HOME/.local/bin/fp")   # uv installs fp there, not always on PATH
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
NAMES=$(grep -o '{ name: "prguard-[a-z-]*"' "$SRC" | cut -d'"' -f2)
[ "$(echo "$NAMES" | wc -l | tr -d ' ')" = 6 ] || { echo "expected 6 policies in $SRC" >&2; exit 1; }
grep -q '^const ONLY = null;$' "$SRC" || { echo "ONLY marker missing in $SRC" >&2; exit 1; }
for name in $NAMES; do
  copy="$OUT/$name-policies.mjs"
  sed "s/^const ONLY = null;\$/const ONLY = \"$name\";/" "$SRC" > "$copy"
  description=$(grep -A1 "{ name: \"$name\"" "$SRC" | grep -o 'description: "[^"]*"' | cut -d'"' -f2)
  "$FP" --json policies publish "$name" "$copy" --description "$description" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print("published", d["id"], "v%s" % d["version"], "syntax ok:", d["syntax"]["ok"])'
done
