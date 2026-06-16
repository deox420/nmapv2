#!/usr/bin/env bash
# P05 — native JSON output (-oJ) verification against real local services.
# Safe: binds/scans 127.0.0.1 only. No external network, no docker required.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NMAP="${NMAP:-$HERE/../../../nmap}"
OUT="$HERE/out"; mkdir -p "$OUT"
PORT_OK=8123
fail=0

start_server() { # cmd... ; writes pid to $OUT/<name>.pid via caller
  ( "$@" >/dev/null 2>&1 & echo $! )
}
stop_pid() { [[ -n "${1:-}" ]] && kill "$1" 2>/dev/null; }

[[ -x "$NMAP" ]] || { echo "FAIL: nmap not built at $NMAP"; exit 1; }
command -v python3 >/dev/null || { echo "SKIP: python3 not available"; exit 0; }

# ---- Case 1: real HTTP service, full -sV detection serialized to JSON ----
echo "[P05] case 1: real HTTP service (-sV -oJ)"
PID_OK=$(start_server python3 -m http.server "$PORT_OK" --bind 127.0.0.1)
sleep 1.5
"$NMAP" -sV -p "$PORT_OK" -oJ "$OUT/ok.json" 127.0.0.1 >/dev/null 2>&1
stop_pid "$PID_OK"

python3 - "$OUT/ok.json" "$PORT_OK" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); port = int(sys.argv[2])
run = d["nmaprun"]
assert run["hosts"], "no hosts"
h = run["hosts"][0]
assert h["status"]["state"] == "up", h["status"]
p = h["ports"][0]
assert p["portid"] == port and p["protocol"] == "tcp", p
assert p["state"] == "open", p
assert p["service"]["name"] == "http", p["service"]
assert p["service"].get("product"), "no product detected"
assert run["runstats"]["hosts"]["up"] == 1, run["runstats"]
print("  ok: valid JSON, open http port, service detected, runstats.up==1")
PY
[[ $? -eq 0 ]] || fail=1

# ---- Case 2: JSON escaping of hostile characters (quote, backslash, control) ----
# Deterministic: a value containing " \ and a TAB is reflected into the run "args"
# field, which passes through the same json_escape() used for all network-derived
# strings (banners, versions, hostnames). The document must stay valid and the
# special characters must round-trip exactly.
echo "[P05] case 2: JSON escaping of quote/backslash/control characters"
HOSTILE=$'a"b\\c\td'   # a " b \ c <TAB> d
"$NMAP" -sL -oJ "$OUT/escape.json" --data-string "$HOSTILE" 127.0.0.1 >/dev/null 2>&1

python3 - "$OUT/escape.json" <<'PY'
import json, sys
blob = open(sys.argv[1], "rb").read()
assert b"\x09" not in blob, "raw TAB byte leaked into JSON (not escaped)!"
d = json.load(open(sys.argv[1]))            # must be valid JSON
args = d["nmaprun"]["args"]
assert '"'  in args, "double-quote did not round-trip"
assert '\\' in args, "backslash did not round-trip"
assert '\t' in args, "TAB (control char) did not round-trip"
print("  ok: valid JSON; quote, backslash and TAB escaped and round-tripped")
PY
[[ $? -eq 0 ]] || fail=1

if [[ "$fail" -ne 0 ]]; then echo "[P05] FAIL"; exit 1; fi
echo "[P05] PASS"
