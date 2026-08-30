# Cycle 32 — DetectionForge governed detection engineering

**Scope:** authorized defensive-only theoretical hardening

**Release target:** 1.13.0
**Disposition:** COMPLETE

## Round 1 — visionary and implementation

Google SecOps retrohunt/observability, Elastic rule preview/history and
`detection-rules`, and Microsoft Sentinel rule health/execution patterns were
compared with Angerona's existing Sigma and detection-package foundations. The
selected program adds immutable digest/high-water/loss-bound replay cohorts,
exact active-versus-candidate diffs, an alert-inert shadow lane, chained quality
receipts, and fresh one-use exact promotion/rollback receipts. `DetectionForge`
is an embeddable Local SOC tab and the native runtime remains detect-only.

## Round 2 — adversarial repair

The initial audit recorded **13 findings (6 High, 7 Medium)** across replay
cohort identity, lossy metric truth, receipt chains, promotion substitution,
concurrency/crash behavior, shadow-lane isolation, recursion, exports, and
resource bounds. First remediation mapped and fixed all 13. Independent
re-attack found `C32-RA-01..05` (**3 Medium, 2 Low**); second remediation fixed
all five. The final bounded re-attack found no new issue, reproduced all five
repairs as blocked, and retained all 13 original closures.

## Round 3 — performance and verification

The runtime preserves separate reserved active and shadow lanes, per-rule
budgets, visible drops, and bounded quality/replay stores. Focused regressions
passed **47/47** and the compatibility gate passed **60/60**. Sanitized exports
exclude source path/operator fields and expose only closed transition fields.

## Residual boundary

All-file rollback needs an external or hardware anchor. An in-process Sigma
evaluator call can be budget-checked after return but cannot be forcibly
preempted without process isolation. Recursion protection assumes synchronous
EventBus dispatch. The bounded quality store may reverify up to a 16 MiB ledger.
This is local governed evaluation, not a distributed detection-content service.
