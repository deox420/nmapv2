# Improvements index — nmapv2 enhanced fork

This fork of [upstream Nmap](https://github.com/nmap/nmap) develops a set of
enhancements on top of the stock scanner. Each improvement is designed,
implemented, tested against a real service on localhost, and documented before
it is marked **DONE**. Status reflects reality — proposals that have not been
implemented yet are listed as **PENDING**, not aspirationally complete.

Fork base: upstream Nmap `@4c45907f` (see `.upstream-nmap-commit`). License: NPSL
(preserved from upstream; fork changes are derivative).

## Build & test

```
./configure --without-zenmap --without-ndiff && make -j$(nproc)
./tests/improvements/run-all.sh          # smoke + all implemented improvement tests
```

## Status

| ID  | Improvement                                   | Status   | Doc | Test |
|-----|-----------------------------------------------|----------|-----|------|
| P05 | Native JSON output (`-oJ`)                     | **DONE** | [doc](docs/improvements/P05.md) | [test](tests/improvements/P05/run.sh) |
| P14 | Per-detection confidence / reliability scoring | **DONE** | [doc](docs/improvements/P14.md) | [test](tests/improvements/P14/run.sh) |
| P24 | Honeypot / tarpit / fake-response detection    | **DONE** | [doc](docs/improvements/P24.md) | [test](tests/improvements/P24/run.sh) |
| P15 | Probe diagnostics telemetry                    | **DONE** | [doc](docs/improvements/P15.md) | [test](tests/improvements/P15/run.sh) |
| P27 | Parser / memory-safety hardening (CPE double-free fix) | **DONE** | [doc](docs/improvements/P27.md) | [test](tests/improvements/P27/run.sh) |
| P06 | SARIF / OCSF / STIX exporters                 | PENDING  | —   | —    |

Remaining proposals (P01–P04, P07–P13, P16–P23, P25–P36) are tracked as PENDING in
`_agent_memory/STATE.json` and will be added to this table as they are completed.

### P05 — Native JSON output (`-oJ`)
Makes JSON a first-class Nmap output format produced directly by the engine, with a
stable documented schema and safe escaping of untrusted banners.
Example: `nmap -sV -oJ - 127.0.0.1 | jq '.nmaprun.hosts[].ports[]'`

### P14 — Per-detection confidence / reliability scoring
Adds a 0–10 `reliability` score and `high`/`medium`/`low` level to each port,
distinguishing states proven by a response from those merely inferred from silence.
Example: `nmap -sU -oJ - 10.0.0.5 | jq '.nmaprun.hosts[].ports[] | select(.reliability_level=="low")'`

### P24 — Honeypot / tarpit / fake-response detection
`honeypot-detect.nse` host script flags hosts that falsify responses (excessive open
ports, uniform/empty banners) with a LIKELY/POSSIBLE verdict and indicators.
Example: `nmap -sV --script honeypot-detect <target>`

### P15 — Probe diagnostics telemetry
Per-host `diagnostics` block in JSON: state/reason tallies, reliability buckets and
derived notes explaining result quality and probable filtering/blackholing.
Example: `nmap -oJ - 10.0.0.5 | jq '.nmaprun.hosts[0].diagnostics'`

### P27 — Parser / memory-safety hardening
Fixes a real upstream use-after-free / double-free of service CPE data
(`serviceDeductions::erase()` freeing borrowed pointers); adds a non-freeing
`reset()`. Verified crash-free under Valgrind (0 errors).
