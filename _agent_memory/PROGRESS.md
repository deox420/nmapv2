# PROGRESS — nmapv2 enhanced fork

Chronological human-readable log. Newest entries at the bottom of each day.

## 2026-06-15

### Session 1 — Foundation
- Repo `deox420/nmapv2` started **empty** (no commits). Branch: `claude/nmap-enhanced-fork-yn7y8t`.
- Environment: Ubuntu 24.04.4, 4 cores, ~31 GB free, gcc/g++/make/autoconf/docker present.
  libssl-dev + zlib1g-dev present; libpcre2-dev present; nmap bundles libpcap/liblua/libdnet.
- Network egress to github.com works (verified). svn.nmap.org returns 403 (not needed).
- User decision (via AskUserQuestion): **Foundation + depth-first**; agent chooses implementation order.
  Agent will report HONEST per-proposal status — no fake DONE markers. Full 36 fully-built+tested
  in one session is not achievable with integrity; this is explicitly a multi-session effort.
- Cloned upstream nmap (shallow, HEAD `4c45907f...`) and copied source into the fork repo. This IS the fork.
  `.upstream-nmap-commit` records provenance for NPSL-derivative documentation.
- Adaptation: `_agent_memory/` kept INSIDE the repo (committed) instead of outside — the cloud container is
  ephemeral, so only committed content survives. Documented in STATE.json + README of memory.
- Baseline build kicked off: `./configure --without-zenmap --without-ndiff && make -j4`. Log: /tmp/baseline-build.log.

### Planned implementation order (depth-first, highest verifiable-value first)
1. **P05** Native JSON output (`-oJ`) — self-contained, highly testable, foundation for P06.
2. **P14** Confidence/reliability scoring per detection.
3. **P24** Honeypot / tarpit detection (NSE + heuristics).
4. **P15** Probe diagnostics telemetry (why a probe failed).
5. **P06** SARIF/OCSF/STIX exporters (builds on P05 JSON).

### Session 1 — CI hygiene
- Imported nmap tree carried `.github/workflows/build.yml` (full multiplatform release autobuild). Its
  Windows-MSVC / macOS jobs fail in the fork (no Npcap SDK / signing secrets). Scoped build.yml to
  `workflow_dispatch` only and added `fork-ci.yml` (Linux ./configure && make + smoke + improvement tests)
  as the meaningful PR gate. Explained on PR #1. sourcery-ai review-guide comment = informational, no action.

### Session 1 — P05 DONE (native JSON output `-oJ`)
- Self-contained writer `output_json.{cc,h}` reads in-memory Target/PortList/serviceDeductions/FPR at
  run-open / per-host / run-close. Robust `json_escape_into()` for untrusted banners. Wired into nmap.cc
  (option, open, run-open, per-host) and output.cc (run-close). Makefile OBJS updated.
- Tested vs real localhost python HTTP service (-sV → full service+CPE) and a deterministic quote/backslash/
  TAB escape round-trip. Smoke + aggregate suite green. Documented in docs/improvements/P05.md; usage updated.
- Lab finding: docker registry blobs blocked (403) → use local python services. dockerd starts but images
  can't be pulled.
