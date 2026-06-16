# DECISIONS — design decisions & rationale (one section per proposal)

## D0 — Foundation decisions (2026-06-15)
- **Memory inside the repo.** The prompt asked for `_agent_memory/` outside the repo; the cloud container
  is ephemeral and only committed content survives context renewal, so memory lives in-repo and is committed.
- **Fork via source copy, not GitHub fork.** Target repo `deox420/nmapv2` was empty. We copied upstream nmap
  source into it and recorded the exact upstream commit in `.upstream-nmap-commit` to preserve NPSL derivative
  provenance. Upstream can be re-added as a remote later for rebasing.
- **Build flags.** `--without-zenmap --without-ndiff` — engine work doesn't need the Python GUI/diff tools;
  this avoids unrelated Python build friction. P20 (native diff) supersedes ndiff anyway.
- **Honest status reporting.** No proposal is marked DONE without build OK + automated test OK + verification
  against a real lab service, per the prompt's own hard rule #2. Unstarted proposals stay PENDING.
- **Implementation order:** P05 → P14 → P24 → P15 → P06 (self-contained + high verifiable value first).

<!-- Per-proposal design rationale appended below as each is started. -->
