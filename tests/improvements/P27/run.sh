#!/usr/bin/env bash
# P27 — memory-safety hardening: regression test for the serviceDeductions
# use-after-free / double-free in service detection (CPE handling).
#
# Upstream nmap crashes ("free(): double free detected", or a SIGSEGV) when -sV
# detects a service bearing a CPE on an open port while at least one other port
# (e.g. closed) is in the same scan: getServiceDeductions shallow-copies the open
# port's CPE pointers into a reused struct, then erase() frees those borrowed
# pointers when the next port has no service. This test asserts the scan now
# completes cleanly. Safe: localhost only.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NMAP="${NMAP:-$HERE/../../../nmap}"
OUT="$HERE/out"; mkdir -p "$OUT"

[[ -x "$NMAP" ]] || { echo "FAIL: nmap not built at $NMAP"; exit 1; }
command -v python3 >/dev/null || { echo "SKIP: python3 not available"; exit 0; }

# python's http.server reports a CPE (cpe:/a:python:simplehttpserver), which is
# exactly what triggered the freed-CPE crash.
( python3 -m http.server 8123 --bind 127.0.0.1 >/dev/null 2>&1 & echo $! >"$OUT/h.pid" )
sleep 1.3

echo "[P27] -sV over open(CPE)+closed ports must not crash"
"$NMAP" -sV -p 8123,8124 127.0.0.1 >"$OUT/scan.log" 2>&1
rc=$?
kill "$(cat "$OUT/h.pid")" 2>/dev/null

if [[ $rc -ne 0 ]]; then
  echo "  FAIL: nmap exited $rc (crash regression)"; tail -5 "$OUT/scan.log"; exit 1
fi
if grep -qiE 'double free|Segmentation fault|AddressSanitizer|corrupt' "$OUT/scan.log"; then
  echo "  FAIL: memory error detected in output"; grep -iE 'double free|Segmentation' "$OUT/scan.log"; exit 1
fi
grep -q "Nmap done" "$OUT/scan.log" || { echo "  FAIL: scan did not complete"; exit 1; }
echo "  ok: scan completed cleanly (exit 0, no memory errors)"
echo "[P27] PASS"
