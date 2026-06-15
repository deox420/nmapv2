#!/usr/bin/env bash
# No-regression smoke test: the enhanced nmap must still scan localhost correctly.
# Safe: targets only 127.0.0.1.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NMAP="${NMAP:-$HERE/../../../nmap}"

if [[ ! -x "$NMAP" ]]; then
  echo "FAIL: nmap binary not found at $NMAP (build first: ./configure && make)"; exit 1
fi

echo "[smoke] nmap version:"; "$NMAP" --version | head -1

echo "[smoke] fast scan of 127.0.0.1 ..."
out="$("$NMAP" -F 127.0.0.1 2>&1)"
echo "$out"

# Assertions: scan completes and reports the host as up.
echo "$out" | grep -q "Nmap done: 1 IP address" || { echo "FAIL: scan did not complete"; exit 1; }
echo "$out" | grep -q "Host is up"                || { echo "FAIL: localhost not reported up"; exit 1; }

echo "[smoke] PASS"
