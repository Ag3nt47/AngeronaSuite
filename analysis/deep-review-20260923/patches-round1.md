# Reported fixes — deep review round 1, 2026-09-23

Scope: only D23-R1-01, R1-QA-01 and R1-QA-02 from the current adversary and bug
reports. The patch applier edited `core/analysis_vmware.py`,
`core/tool_analysis_jobs.py`, `gui/analysis_lab.py`,
`modules/memory_timemachine.py`, and their focused regression tests. Shared
ModuleManager/BaseModule, AI triage, detection runtime and unrelated GUI edits
belong to the other agents and were preserved. No commit or publication was made.

| Finding | Change | Compile | Self-test / regression | Status |
|---|---|---|---|---|
| D23-R1-01 | `analysis_vmware.sealed_configuration` validates the exact regenerated VMX bytes, descriptor/path file identity and single-link ownership; retains a Windows read-only sharing handle denying write/delete access. The supervisor verifies custody immediately before start, GO and receipt return, and holds it through teardown. `tool_analysis_jobs._run` independently retains the seal through report parsing. | PASS | Disposable Windows overwrite/delete/replacement attempts refused; boot/device changes, hardlink alias, defective-seal identity/byte changes and pre-seal substitution refused. Inert supervisor checks reject failed custody at start/GO/report boundaries. Native VMware acceptance remains pending. | FIXED in host code; native acceptance pending |
| R1-QA-01 | `gui/analysis_lab.py` tolerates `queue.Empty` when the GUI drains progress after a producer observes Full, then retries the bounded final-outcome insertion. | PASS | Bug hunter's deterministic concurrent-drain regression PASS; controls recover and final readiness/result is delivered. Plain-text hostile-output control PASS. | FIXED |
| R1-QA-02 | `memory_timemachine.py` lets the retiring worker close only its own ring in `finally`; cancellation is rechecked after collection and before bounded queue/dedupe/receipt admission. Closed-ring operations and status reads are safe and lifetime-locked. | PASS | Late collection admits no payload/receipt/activity; blocked collector keeps its ring alive until return; restart opens a new ring only after the old one closes; absent collector cleans up; closed-ring access and existing delivery/backpressure tests PASS. Module self-test PASS. | FIXED |

## Gates

- `py_compile`: all four changed product files and all three focused test files
  passed. No stale/truncated-read workaround was needed.
- **68 tests passed, 0 failed, 0 skipped in 7.56 seconds** across
  `test_deep_review_round1_vmx_custody`,
  `test_deep_review_round1_lab_regressions`,
  `test_deep_review_round1_module_lifecycle`, `test_analysis_lab`,
  `test_analysis_lab_ui`, `test_cycle29_memory_timemachine_delivery`, and
  `test_cycle3_round1_performance`.
- MTM `self_test()` returned `(True, 'dedup verified (4→0 on repeat)')`.
  The other changed files have no `self_test()` method; their gates are the
  focused core/UI regressions. The tracked MTM diff passed `git diff --check`.
- Interpreter: existing `AngeronaSuite/venv/Scripts/python.exe`, with
  `PYTHONPATH` set to this worktree's `src`. Pytest uses its established
  disposable runtime and offscreen Qt fixtures.

The custody tests use generated inert VMX files and fake native supervisor
interfaces. The existing Lab suite also checks a Windows Job Object against
its own disposable sleeping child. No VMware VM, host service change, live
sensor, inference request, malware or containment action was run by this agent.

## Native acceptance boundary

The generated configuration stays sealed for the complete host-supervised
lifecycle. There is deliberately no fallback that permits VMware to rewrite it.
If VMware requires write access to VMX, startup must fail closed; supporting
that version requires a separately reviewed configuration handoff proving the
selected boot media and devices. The parent owns the separately authorized
inert VMware acceptance gate. Passing the Windows file-sharing tests does not
establish that VMware accepts this configuration or custody mechanism.

External analyzer results retain `response_authority=False`. No untrusted
repository content, report prose or model output acquires execution/response
authority through these changes.

Historical `analysis/loop/state.json` still identifies completed cycle34. This
current-round report does not overwrite that historical closure; the parent
owns the consolidated current-round finding status and loop log.
