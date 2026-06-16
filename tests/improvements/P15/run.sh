#!/usr/bin/env bash
# P15 — per-host scan diagnostics telemetry in JSON output.
# Asserts the diagnostics block explains the results: state/reason tallies,
# reliability buckets, and a derived note when probes go unanswered.
# Safe: localhost only. UDP/notes case needs root.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NMAP="${NMAP:-$HERE/../../../nmap}"
OUT="$HERE/out"; mkdir -p "$OUT"
fail=0
start_bg() { ( "$@" >/dev/null 2>&1 & echo $! ); }
stop() { [[ -n "${1:-}" ]] && kill "$1" 2>/dev/null; }

[[ -x "$NMAP" ]] || { echo "FAIL: nmap not built at $NMAP"; exit 1; }
command -v python3 >/dev/null || { echo "SKIP: python3 not available"; exit 0; }

# Case 1: mixed open + closed TCP -> state/reason tallies + reliability buckets.
echo "[P15] case 1: diagnostics tallies (open + closed TCP)"
PID_H=$(start_bg python3 -m http.server 8123 --bind 127.0.0.1)
sleep 1.2
"$NMAP" -sV -p 8120-8126 -oJ "$OUT/diag.json" 127.0.0.1 >/dev/null 2>&1
stop "$PID_H"
python3 - "$OUT/diag.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["nmaprun"]["hosts"][0]["diagnostics"]
sc, rc, rel = d["state_counts"], d["reason_counts"], d["reliability"]
assert sc.get("open", 0) >= 1, sc
assert sc.get("closed", 0) >= 1, sc
# open port -> syn-ack; closed -> reset (SYN scan/root) or conn-refused (connect scan/non-root)
assert "syn-ack" in rc, rc
assert ("reset" in rc or "conn-refused" in rc), rc
assert sum(sc.values()) == 7, sc            # 7 ports scanned
assert rel["high"] >= 1, rel
print("  ok: state_counts=%s reason_counts=%s reliability=%s" % (sc, rc, rel))
PY
[[ $? -eq 0 ]] || fail=1

# Case 2: a host that stays silent -> derived "filtering/blackholing" note (root only).
if [[ "$(id -u)" -eq 0 ]]; then
  echo "[P15] case 2: derived note on unanswered probes (UDP silence)"
  PID_U=$(start_bg python3 "$HERE/../P14/udp_silent.py" 9876)
  sleep 1.2
  # Scan only the silent port: it is open|filtered via no-response, so the host's
  # answered/unanswered ratio is dominated by silence and the note must fire.
  "$NMAP" -sU -p 9876 -oJ "$OUT/udp.json" 127.0.0.1 >/dev/null 2>&1
  stop "$PID_U"
  python3 - "$OUT/udp.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["nmaprun"]["hosts"][0]["diagnostics"]
joined = " ".join(d["notes"]).lower()
assert "no response" in joined or "filtering" in joined or "blackholing" in joined, d["notes"]
print("  ok: note present -> %s" % d["notes"])
PY
  [[ $? -eq 0 ]] || fail=1
else
  echo "[P15] case 2: SKIP (needs root for UDP scan)"
fi

if [[ "$fail" -ne 0 ]]; then echo "[P15] FAIL"; exit 1; fi
echo "[P15] PASS"
