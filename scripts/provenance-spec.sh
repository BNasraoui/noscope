#!/usr/bin/env bash
# Materializes the requirements-as-code declaration and reconciles it.
#
#   scripts/provenance-spec.sh plan     # preview; writes nothing (default)
#   scripts/provenance-spec.sh apply    # reconcile, then prove the replay is a no-op
#
# Builds the Provenance CLI from the pinned commit, so the check does not depend
# on a published release or on whatever binary happens to be installed.
set -euo pipefail

PROVENANCE_REPO="https://github.com/quality-sh/provenance.git"
PROVENANCE_REV="49ed0162e9e3fea46332d5f769bac17f863ff348"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

mode="${1:-plan}"
if [ "$mode" != "plan" ] && [ "$mode" != "apply" ]; then
  echo "usage: $0 [plan|apply]" >&2
  exit 2
fi

src="$root/target/provenance-src"
cli="$src/target/release/provenance"

if [ ! -d "$src/.git" ]; then
  git clone --filter=blob:none "$PROVENANCE_REPO" "$src"
fi
if [ "$(git -C "$src" rev-parse HEAD)" != "$PROVENANCE_REV" ]; then
  git -C "$src" fetch --filter=blob:none origin "$PROVENANCE_REV"
  git -C "$src" checkout --detach "$PROVENANCE_REV"
  rm -f "$cli"
fi
if [ ! -x "$cli" ]; then
  cargo build --manifest-path "$src/Cargo.toml" --release -p provenance-cli
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
document="$work/document.json"
replay="$work/replay.json"

cargo run --quiet --features provenance-spec --bin noscope-provenance-spec > "$document"

echo "== provenance sdk $mode =="
"$cli" sdk "$mode" --repo . --quiet < "$document"

if [ "$mode" = "apply" ]; then
  echo "== replay =="
  "$cli" sdk plan --repo . --quiet < "$document" > "$replay"
  python3 - "$replay" <<'PY'
import json, sys

plan = json.load(open(sys.argv[1]))
busy = {
    field: plan[field]
    for field in ("created", "updated", "moved", "retired", "conflicts")
    if plan.get(field)
}
if busy:
    raise SystemExit(f"replay is not idempotent: {busy}")
print(f"replay is idempotent: {plan['unchanged']} unchanged")
PY
fi
