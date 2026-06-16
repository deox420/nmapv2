#!/usr/bin/env bash
# P24 — honeypot/tarpit/fake-response detection (honeypot-detect.nse).
# Positive: a fake host with many uniform-banner ports must be flagged LIKELY.
# Negative: a normal single-service host must NOT be flagged.
# Safe: localhost only, no docker.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NMAP="${NMAP:-$HERE/../../../nmap}"
SCRIPT="$HERE/../../../scripts/honeypot-detect.nse"
OUT="$HERE/out"; mkdir -p "$OUT"
fail=0
start_bg() { ( "$@" >/dev/null 2>&1 & echo $! ); }
stop() { [[ -n "${1:-}" ]] && kill "$1" 2>/dev/null; }

[[ -x "$NMAP" ]] || { echo "FAIL: nmap not built at $NMAP"; exit 1; }
command -v python3 >/dev/null || { echo "SKIP: python3 not available"; exit 0; }

# ---- Positive: 40-port fake honeypot, uniform SSH banner ----
echo "[P24] positive: fake-response honeypot flagged"
PID_HP=$(start_bg python3 "$HERE/honeypot.py" 9000 40 $'SSH-2.0-OpenSSH_8.9p1 Honeypot\r\n')
sleep 1.3
"$NMAP" -sV -p 9000-9039 --script "$SCRIPT" 127.0.0.1 >"$OUT/honeypot.out" 2>&1
stop "$PID_HP"
if grep -q "LIKELY honeypot" "$OUT/honeypot.out" \
   && grep -q "excessive open TCP ports" "$OUT/honeypot.out" \
   && grep -q "identical service signature" "$OUT/honeypot.out"; then
  echo "  ok: honeypot flagged LIKELY with both indicators"
else
  echo "  FAIL: honeypot not flagged as expected"; sed -n '/Host script/,/^$/p' "$OUT/honeypot.out"; fail=1
fi

# ---- Negative: one normal HTTP service must not be flagged ----
echo "[P24] negative: normal single-service host not flagged"
PID_H=$(start_bg python3 -m http.server 8123 --bind 127.0.0.1)
sleep 1.2
"$NMAP" -sV -p 8123 --script "$SCRIPT" 127.0.0.1 >"$OUT/normal.out" 2>&1
stop "$PID_H"
if grep -q "honeypot-detect" "$OUT/normal.out"; then
  echo "  FAIL: normal host wrongly flagged"; sed -n '/Host script/,/^$/p' "$OUT/normal.out"; fail=1
else
  echo "  ok: normal host produced no honeypot verdict"
fi

if [[ "$fail" -ne 0 ]]; then echo "[P24] FAIL"; exit 1; fi
echo "[P24] PASS"
