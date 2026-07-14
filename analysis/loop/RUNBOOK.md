# Angerona Improvement Loop — Runbook

A repeatable, gated, multi-agent loop that hardens and improves Angerona. Run it
by telling the assistant: **"Run the Angerona improvement loop."** The assistant
acts as coordinator and spawns the subagents below in order.

## The team (`.claude/agents/`)
| Agent | Role | Authority |
|---|---|---|
| `angerona-redteam` | Find vulnerabilities / weaknesses | Read-only (reports) |
| `angerona-remediation` | Fix the red-team findings | Apply behind gates |
| `angerona-bug-tester` | Compile + self_test + selfcheck; find bugs | Apply obvious fixes behind gates |
| `angerona-performance` | Speed / memory optimizations | Apply behind gates (behavior-preserving) |
| `angerona-innovation` | Research cutting-edge defensive ideas | Research only (proposal doc) — **round 1 only** |
| `angerona-docs` | Fold everything into the docs | Docs only — **end of round 3 only** |

## Gates (every code-changing agent)
1. `python -m py_compile` on each changed file (exit 0). Watch for FALSE errors from the sandbox mount serving stale/truncated reads of large files — re-verify via `/tmp` before trusting a SyntaxError.
2. Any `self_test()` on the changed module passes.
3. Change is minimal, behavior-preserving, and never weakens a security control. If unsure → PROPOSE, don't apply.

## Cadence — 3 rounds
- **Round 1:** red-team → remediation → bug-tester → performance → **innovation (web search, ONCE)**.
- **Round 2:** red-team → remediation → bug-tester → performance.
- **Round 3:** red-team → remediation → bug-tester → performance → **docs-updater (updates analysis/ docs, llms.txt, and README.md)**.

Rationale: internet research happens once (round 1) so ideas seed the whole loop; docs are written once at the very end (round 3) so they capture the net result.

## File contract (shared workspace = `analysis/loop/`)
- `state.json` — `{round, phase, started, notes}`; the coordinator updates it.
- `LOOP_LOG.md` — running, human-readable log; every agent appends its section.
- `PRIOR_FINDINGS.md` — known/closed issues so red-team doesn't re-report fixed ones.
- `round<N>/redteam_findings.md` + `.json` — findings for round N.
- `round<N>/remediation_summary.md` — fixes applied/deferred.
- `round<N>/bugtest_results.md` — compile/self_test/selfcheck results + bugs.
- `round<N>/performance_summary.md` — optimizations applied/proposed.
- `innovation_ideas.md` — round-1 research proposals (ranked).

## Stop / safety
- The loop converges when a round's red-team + bug-tester find nothing new.
- All code changes are gated and review-friendly (small diffs). Review `LOOP_LOG.md` + the round summaries after each run.
- Defensive-only: no offensive tooling; nothing weakens Angerona's posture; `.env`/secrets never touched.
