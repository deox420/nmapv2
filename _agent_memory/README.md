# _agent_memory — external memory for the autonomous fork work

This directory is the agent's persistent "second brain" for the long-running task of building
an enhanced nmap fork. It survives context renewal because it is **committed to the repo**
(the cloud execution container is ephemeral — uncommitted files outside the repo are lost).

## Files
- `STATE.json` — machine-readable state: current proposal, phase, branch, last commit, per-proposal
  status (PENDING/IN_PROGRESS/DONE/BLOCKED), global %, and `notas_para_mi_yo_futuro` (the exact next step).
- `PROGRESS.md` — chronological human log of what was done / learned / remains.
- `DECISIONS.md` — design decisions and rationale, one section per proposal.
- `ENVIRONMENT.md` — how the lab + build are set up; commands to re-create services.
- `FINDINGS.md` — reusable nmap codebase notes (file paths, key functions, build gotchas).
- `ledgers/<id>.md` — per-proposal ledger with phases A (design) / B (impl) / C (test) / D (doc).

## Recovery procedure (run on startup or when context feels lost)
1. `cat _agent_memory/STATE.json` → read `proposal_actual`, `fase_actual`, `notas_para_mi_yo_futuro`.
2. `cat _agent_memory/ledgers/<proposal_actual>.md` → recover the detail of where work stopped.
3. `git log --oneline -15` and `git status` → reconcile real code state with memory.
4. `cat _agent_memory/ENVIRONMENT.md` → re-create any needed lab services.
5. Continue from `notas_para_mi_yo_futuro`. Verify with git/tests what was already complete; don't redo it.

## Honesty rule
A proposal is DONE only with: build OK + automated test OK + verification against a real lab service.
Status here reflects reality — unstarted proposals stay PENDING; no aspirational DONE markers.
