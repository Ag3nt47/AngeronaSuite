# Cycle 37 / Round 1 — Red-Team Findings

Read-only review of commit `795cc55` on 2026-09-30. Scope emphasized Combat,
Purple Guard, FIM/native scoring, the Shark and Red Team drill writers, AAR
history, and high-risk code patterns. Reproductions used disposable files only;
no product, test, or live runtime state was changed. The strengthened live
Combat journal, exact Purple/FIM receipts, and Red Team history binding did not
yield a new false-containment or native-credit path in this pass.

## R37-01 — Shark's predictable BYOVD marker overwrites an existing file

- **Severity:** MEDIUM (local drill safety and data integrity).
- **Component:** `src/angerona/shark/shark_attack.py:644-663`, especially
  `_practice_artifact(...)` followed by `Path.write_text(...)`; target preflight
  at `src/angerona/shark/run_manifest.py:391-420` checks the directory but not
  the output object's identity.
- **Description:** The simulated BYOVD step always writes
  `angerona_byovd_drill.sys` in the selected directory. `write_text` truncates an
  existing regular file and follows a hardlink or reparse destination. Path
  registration adds practice provenance but is not an exclusive-create or
  single-link guard. The step then reports success.
- **Proof:** In a temporary directory on Windows, a hardlink at the fixed
  marker name pointed to `unrelated-user-document.txt`. Calling only the inert
  `_step_simulated_byovd((0, 0))` replaced the unrelated document's bytes; both
  names retained the same inode and the recorded step had `ok=True`. This does
  not establish arbitrary protected-file overwrite: the reproducer owned both
  files, and hardlink/reparse creation and target ACLs limit exploitability.
- **Impact:** A pre-existing file of the fixed name, or a linked user file in
  an operator-selected directory, can be corrupted by a benign simulation.
- **Recommendation:** Refuse any existing output name. Create through a held
  exclusive no-follow handle, require a regular single-link object, and bind
  the recorded artifact to that handle/identity. Prefer a unique marker name
  if the detector contract permits it.

## R37-02 — Shark Stop & clean deletes a replacement at a recorded path

- **Severity:** MEDIUM (local drill safety and data integrity).
- **Component:** `src/angerona/shark/shark_attack.py:287-300`.
- **Description:** `stop_and_clean()` unlinks every recorded artifact pathname
  without checking whether the original drill-created object is still there.
  The existing cancellation event and bounded join address the older Cycle 2
  continuation finding; they do not bind cleanup to the created object.
- **Proof:** A disposable marker was recorded, renamed away, and replaced by an
  unrelated file at its old pathname. Calling `stop_and_clean()` deleted the
  replacement and left the original at its renamed path.
- **Impact:** A same-host rename/replacement race in a selected drill directory
  can remove unrelated data while the UI presents this as marker cleanup.
- **Recommendation:** Retain a creation-time object identity/handle and delete
  only that object. If exact object custody is unavailable, fail closed and
  leave the path for explicit operator review. Recheck the no-follow,
  single-link and content contract before any fallback cleanup.

## R37-03 — Historical AAR tab displays unauthenticated text as a report

- **Severity:** LOW (local operator deception; no automatic response credit).
- **Component:** `src/angerona/gui/red_team_console.py:661-695`; signed archive
  JSON and text digest are produced in
  `src/angerona/shark/aar_report.py:1743-1920,1922-2130`.
- **Description:** The Past After-Action Reports tab lists every matching
  `*_aar_*.txt` file and shows selected text via `Path.read_text()`. It never
  verifies the paired signed JSON, text SHA-256, run identity or report kind.
  The current-report dialog uses a stricter authenticated binding, so the two
  report surfaces give different trust guarantees without saying so.
- **Proof:** An inert `redteam_aar_20990101_000000.txt` containing `FORGED
  VERIFIED SIMULATION CONTAINMENT 37/37` was passed to `_on_hist_select` from a
  temporary directory. The method displayed that exact text without a paired
  signed report. The archive is user-private in the normal deployment; an
  attacker must be able to write it, limiting severity.
- **Impact:** The operator can be shown a fabricated passing historical score.
- **Recommendation:** Verify the paired archive JSON HMAC and its exact
  `report_text_sha256` before listing or rendering text, reject links and
  ambiguous names, and show an explicit unverified state on failure.

## R37-04 — Drill history and stale-cleanup reads are unbounded on the UI/run path

- **Severity:** LOW (local responsiveness/resource exhaustion).
- **Component:** `src/angerona/gui/red_team_console.py:661-695` and
  `src/angerona/shark/shark_attack.py:148-178,337-372`.
- **Description:** The History tab sorts all matching report files, stats each,
  and reads a selected file to completion on the Qt thread. Shark startup
  examines all aged matching marker names before applying its two-deletion
  limit; for plain files `_file_has_marker()` calls unbounded `read_text()`.
  Neither path has a per-file byte cap or candidate/time budget. This is a
  code-path finding; a resource-exhaustion run was deliberately not performed.
- **Impact:** A large/many local matching files can stall the console or drill
  and create high transient memory pressure, consistent with the user's freeze
  concern. The attacker needs write access to the selected local directory.
- **Recommendation:** Bound archive list size, each file's bytes, and work per
  refresh; read/verify off the Qt thread. For Shark, stat first, skip oversized
  files, use a bounded streaming marker search, and stop at an explicit
  candidate/time budget before the deletion-selection stage.

## Prior-finding reconciliation

The Cycle 35 response-spoof, guardrail-envelope, and final graph-rebind fixes
remain present: the AAR requires an exact live signed Combat commit and final
journal/binding recheck; the guardrail scans and caps the forwarded envelope.
Among the eight baseline entries in `PRIOR_FINDINGS.md`, **four are now closed
or effectively staged-only** (A-01, A-03, A-05, A-07), and **four remain
mitigated/open boundaries** (A-02 optional local MCP token, A-04 admitted
extension in-process execution, A-06 dispersed PowerShell bypass usage,
R6-03 no retained OS process/executable lease across a full response).
This review did not elevate those known boundaries into new findings.

**Candidate-fix reattack:** The parent-owned worktree patch refused R37-01's
hardlink, preserved R37-02's replacement, and still deleted a legitimate owned
marker in separate-process Windows probes. The new AAR history viewer passed a
forged-text/JSON, hardlink, oversized-file, signed-replay, invalid-date, and
offscreen UI challenge after two Windows listing/invalid-date defects were
reported and corrected during review. These results are targeted; the JSON
below remains the original OPEN finding handoff until combined validation and
publication establish final closure.

| Severity | New findings |
|---|---:|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 2 |
| LOW | 2 |
| INFO | 0 |
