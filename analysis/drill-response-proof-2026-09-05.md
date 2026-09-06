# Defensive drill response proof — 2026-09-05

The Red Team console previously declared simulation completion before its
after-action report finished settling. Its response-success total accepted
successful action claims, and timestamp-only correlation could associate a
receipt with the wrong detector. Completing probes, starting deception and
cleaning test files did not establish that the response worker contained a
test target.

## Implemented behavior

- Auto-containment launches inspect Combat's memory-only response snapshot and
  effective policy. A stopped, disabled, starting, full or recovery-held worker
  cannot begin a containment test. The dialog shows the reason. Detection-only
  runs remain explicit and cannot earn a containment pass.
- Accepted, queued and rejected launches have distinct UI states. Completing
  probes leaves the result pending while evidence settles. Only the immutable,
  authenticated report for the current run may finish its result. Combined
  Shark/Red Team runs wait for both report identities.
- Reports distinguish an action report, a claimed applied action, verified
  containment of recorded targets and separately verified detector-fix contracts.
  Every planned detection step remains in the containment denominator. Failed or
  incomplete runs withhold success percentages.
- Combat receipts expose each committed action's identifier, target and checked
  postcondition, with file digest or process creation identity. Exact target
  proof excludes timestamp-only collisions, unrelated targets, wrapper claims,
  honeypot-only actions and engine cleanup. Existing signed history is preserved.
- Purple receipt v2 includes the signed observed content digest. Report-only
  verification can retain a detection after a same-volume quarantine rename,
  provided the original name is absent and the enrolled held object still has
  identical metadata, content and a single link. Replacements, links, inspection
  errors and changed bytes remain unverified. Issuance and cleanup keep their
  existing live-path checks. Cross-volume copy/unlink cannot borrow this held
  object proof and remains unverified by this report path.

This change adds defensive validation and reporting. It does not add exploit
payloads, import executable tools, change journal recovery authority, or certify
real-world attack prevention. VMware Analysis Lab work remains a separate,
unpublished change.

## Local response blocker

Read-only inspection of the operator's existing SourceData confirmed an exact
one-record interrupted startup checkpoint: 19 authenticated journal records and
checkpoint sequence 18. The pending record is startup honeypot activation, with
no host containment actions in that inspected history. Saved diagnostics also
reported RECOVERY REQUIRED; their timestamp was 2026-09-05 19:04:02 and is not a
current live-health attestation.

The test correctly retains this response hold. `tools/recover_combat_startup.py`
offers separate, explicit recovery while Angerona is stopped. It revalidates
the inspected inputs, preserves encrypted backups and advances only the
matching checkpoint. This update did not apply recovery, reset keys, clear
journals, arm response or start Angerona.

## Validation

- The exact isolated publication checkout passed **3,251 tests**, with **17
  platform skips**, in **391.95 seconds**. VMware work in progress was excluded.
- Whole-tree compilation, Ruff correctness checks, documentation drift and
  whitespace checks passed.
- The combined original checkout also passed **67** Analysis Lab, GitHub Tools
  UI and drill UI integration checks with the preserved VMware edits present.
- A real disposable-file check exercised direct and authenticated delegated
  requests, quarantine, exact report proof and reversible byte-identical restore.
  Other new checks reject incorrect content/PID identity, reused detector
  evidence, cleanup, unrelated actions, unverified wrappers, unsupported receipt
  versions and incomplete-run scores.
- Readiness and UI checks cover recovery/disabled/policy holds, queued and busy
  launches, Stop during queued wake-up, delayed reports, combined run identities,
  policy restoration and report authentication failures. The console was
  rendered and inspected at 700 x 520 with blocked, pending and partial results;
  wrapped stage labels and a compact progress ring keep controls readable.

Tests use disposable local artifacts and mocked UI/host boundaries; no live
attack campaign was part of this maintenance pass. A source launch loads the
updated files; an older packaged executable requires a new build.
