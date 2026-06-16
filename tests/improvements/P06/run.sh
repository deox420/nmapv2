#!/usr/bin/env bash
# P06 — SARIF / OCSF / STIX exporters (tools/nmap-export.py) over real -oJ output.
# Safe: localhost only.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NMAP="${NMAP:-$HERE/../../../nmap}"
EXPORT="$HERE/../../../tools/nmap-export.py"
OUT="$HERE/out"; mkdir -p "$OUT"
fail=0
start_bg() { ( "$@" >/dev/null 2>&1 & echo $! ); }
stop() { [[ -n "${1:-}" ]] && kill "$1" 2>/dev/null; }

[[ -x "$NMAP" ]] || { echo "FAIL: nmap not built at $NMAP"; exit 1; }
command -v python3 >/dev/null || { echo "SKIP: python3 not available"; exit 0; }

PID_H=$(start_bg python3 -m http.server 8123 --bind 127.0.0.1)
sleep 1.2
"$NMAP" -sV -p 8123 -oJ "$OUT/scan.json" 127.0.0.1 >/dev/null 2>&1
stop "$PID_H"

echo "[P06] SARIF / OCSF / STIX conversion of a real scan"
python3 "$EXPORT" -f sarif "$OUT/scan.json" >"$OUT/out.sarif" 2>/dev/null
python3 "$EXPORT" -f ocsf  "$OUT/scan.json" >"$OUT/out.ocsf" 2>/dev/null
# also exercise stdin piping
python3 "$EXPORT" -f stix  - <"$OUT/scan.json" >"$OUT/out.stix" 2>/dev/null

python3 - "$OUT/out.sarif" "$OUT/out.ocsf" "$OUT/out.stix" <<'PY'
import json, sys
sarif = json.load(open(sys.argv[1]))
ocsf  = json.load(open(sys.argv[2]))
stix  = json.load(open(sys.argv[3]))

assert sarif["version"] == "2.1.0", sarif["version"]
res = sarif["runs"][0]["results"]
assert any(r["properties"]["port"] == 8123 for r in res), "SARIF missing open port"
assert sarif["runs"][0]["tool"]["driver"]["name"] == "nmap"
print("  ok: SARIF 2.1.0 with result for port 8123")

assert isinstance(ocsf, list) and ocsf, "OCSF empty"
assert any(o["dst_endpoint"]["port"] == 8123 and o["class_uid"] == 4001 for o in ocsf)
print("  ok: OCSF Network Activity finding for port 8123")

assert stix["type"] == "bundle" and stix["spec_version"] == "2.1"
types = [o["type"] for o in stix["objects"]]
assert "ipv4-addr" in types, types
nt = [o for o in stix["objects"] if o["type"] == "network-traffic"]
assert nt and nt[0]["dst_port"] == 8123, nt
print("  ok: STIX 2.1 bundle with ipv4-addr + network-traffic dst_port 8123")
PY
[[ $? -eq 0 ]] || fail=1

# Negative: non-nmap JSON must be rejected cleanly (exit 2), not crash.
echo "[P06] rejects non-nmap JSON"
echo '{"foo":1}' | python3 "$EXPORT" -f sarif - >/dev/null 2>"$OUT/err.txt"
rc=$?
if [[ $rc -eq 2 ]] && grep -q "nmaprun" "$OUT/err.txt"; then
  echo "  ok: clean rejection (exit 2)"
else
  echo "  FAIL: expected exit 2 with message, got $rc"; fail=1
fi

if [[ "$fail" -ne 0 ]]; then echo "[P06] FAIL"; exit 1; fi
echo "[P06] PASS"
