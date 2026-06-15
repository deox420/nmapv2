#!/usr/bin/env bash
# Aggregate runner for fork improvement tests. Runs the smoke test plus every
# tests/improvements/<id>/run.sh that exists. Safe: all tests target localhost / lab nets only.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
fail=0

run_one() {
  local script="$1"
  echo "::group::$script"
  if bash "$script"; then
    echo "PASS: $script"
  else
    echo "FAIL: $script"
    fail=1
  fi
  echo "::endgroup::"
}

# Smoke first
run_one "$HERE/smoke/run.sh"

# Then each proposal test (skip smoke, already run)
for d in "$HERE"/*/; do
  name="$(basename "$d")"
  [ "$name" = "smoke" ] && continue
  [ -f "$d/run.sh" ] && run_one "$d/run.sh"
done

if [ "$fail" -ne 0 ]; then
  echo "=== some improvement tests FAILED ==="
  exit 1
fi
echo "=== all improvement tests passed ==="
