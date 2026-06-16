#!/usr/bin/env bash
# P14 — per-port state-reliability scoring. Asserts the score discriminates
# states proven by a response (high) from states inferred from silence (low).
# Safe: localhost only. UDP case needs root (raw socket); skipped gracefully if not.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NMAP="${NMAP:-$HERE/../../../nmap}"
OUT="$HERE/out"; mkdir -p "$OUT"
fail=0
start_bg() { ( "$@" >/dev/null 2>&1 & echo $! ); }
stop() { [[ -n "${1:-}" ]] && kill "$1" 2>/dev/null; }

[[ -x "$NMAP" ]] || { echo "FAIL: nmap not built at $NMAP"; exit 1; }
command -v python3 >/dev/null || { echo "SKIP: python3 not available"; exit 0; }

# Case 1+2: open TCP (banner) and closed TCP — both proven by a response -> high.
echo "[P14] case 1/2: open + closed TCP scored high (response-proven)"
PID_H=$(start_bg python3 -m http.server 8123 --bind 127.0.0.1)
sleep 1.2
"$NMAP" -sV -p 8123 -oJ "$OUT/open.json"   127.0.0.1 >/dev/null 2>&1
"$NMAP"     -p 8199 -oJ "$OUT/closed.json" 127.0.0.1 >/dev/null 2>&1
stop "$PID_H"

python3 - "$OUT/open.json" "$OUT/closed.json" <<'PY'
import json, sys
o = json.load(open(sys.argv[1]))["nmaprun"]["hosts"][0]["ports"][0]
c = json.load(open(sys.argv[2]))["nmaprun"]["hosts"][0]["ports"][0]
assert o["state"] == "open" and o["reliability"] == 10 and o["reliability_level"] == "high", o
assert c["state"] == "closed" and c["reliability"] >= 8 and c["reliability_level"] == "high", c
print("  ok: open=%d(%s) closed=%d(%s)" % (o["reliability"], o["reliability_level"],
                                            c["reliability"], c["reliability_level"]))
PY
[[ $? -eq 0 ]] || fail=1

# Case 3: UDP open|filtered inferred from silence -> low. Needs raw socket (root).
if [[ "$(id -u)" -eq 0 ]]; then
  echo "[P14] case 3: UDP open|filtered (no-response) scored low (silence-inferred)"
  PID_U=$(start_bg python3 "$HERE/udp_silent.py" 9876)
  sleep 1.2
  "$NMAP" -sU -p 9876 -oJ "$OUT/udp.json" 127.0.0.1 >/dev/null 2>&1
  stop "$PID_U"
  python3 - "$OUT/udp.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))["nmaprun"]["hosts"][0]["ports"][0]
assert p["reason"] == "no-response", p
assert p["reliability"] <= 4 and p["reliability_level"] == "low", p
print("  ok: udp %s reliability=%d(%s)" % (p["state"], p["reliability"], p["reliability_level"]))
PY
  [[ $? -eq 0 ]] || fail=1
else
  echo "[P14] case 3: SKIP (needs root for UDP scan)"
fi

if [[ "$fail" -ne 0 ]]; then echo "[P14] FAIL"; exit 1; fi
echo "[P14] PASS"
