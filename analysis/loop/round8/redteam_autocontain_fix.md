# Round 8 - Automatic Red Team containment correction

Date: 2026-08-25

## Failure reproduced

An Extreme GUI Red Team report recorded 4/52 eligible detections, 2/4 responses,
and 0/13 action contracts/closures. The marker evidence was real, but the
Auto-contain launch path had armed response without activating Purple Guard's
fixed simulation detector pack.

## Correction

- Auto-contain now activates all 13 simulation-only technique signatures before
  the first Red Team marker is created.
- The pack remains bounded to inert `_redteam_*` artifacts in dedicated or
  explicitly registered drill targets and nonce-tagged idle processes.
- Existing signed candidate lineage is preserved. Activation failure stops the
  run and restores temporary response/coverage settings.
- The AAR prefers an exact, postcondition-verified Adversary Combat receipt over
  an earlier delegation wrapper.
- A verified live Combat receipt now truthfully counts as an applied action
  contract and verified closure.

## Verification loop

- Adversary-boundary negative controls: 128 passed.
- Round 1: 52/52 detection, 51/52 response, 13/13 contracts, 12/13 closure,
  resilience PASS. The validator rejected the round and continued.
- Round 2 (`redteam-1787697587-bf119f`): 52/52 detection, 52/52 automatic
  response, 13/13 contracts, 13/13 verified closure, resilience PASS.
- Average detection: 0.57 seconds. Average mitigation: 1.09 seconds.
- Cleanup: 223 authenticated action records, zero active reversible actions,
  empty journal error, zero recovery requirements, zero marker files, and zero
  tagged processes.
- Full repository: 1,257 passed, 3 intentional skips, 0 failed; 308/308 compile;
  Ruff pass; headless self-check 26/26.

This is 100% of the defined 13-class, 52-step inert campaign. It is not a claim
that a finite endpoint product detects every possible real-world threat.
