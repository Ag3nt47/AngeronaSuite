# Cycle 26 round 2 adversarial findings

Scope: authorized, defensive-only theoretical hardening. No live intrusion,
persistence, credential access, or weaponized exploit was attempted.

Independent post-remediation review currently records four high-severity, six
medium-severity, and two low-severity findings. `C26-R2-A01` and
`C26-R2-B01` have already been remediated; the independently reproduced
`C26-R2-C01`, `C26-R2-C02`, and `C26-R2-D01` through `C26-R2-D08` are pending
remediation.

`C26-R2-A01` extends the round 1 signing finding: although the threshold
authority was made fail-closed, candidate-controlled Windows prepare and package
steps still received an exportable publisher PFX, its password, and certificate
metadata, allowing repository code to use or exfiltrate the publisher identity.
The required boundary permits candidate builders to emit only unsigned,
explicitly untrusted request artifacts and keeps public release publication
blocked until a real independent non-exportable authority exists.

`C26-R2-B01` is the inert reproduction from round 1 QA: a failed Defender apply
could be reported as applied when the pre-existing real-time setting happened to
match, while the other requested settings were not verified. The finding also
identified PATH-resolved PowerShell, execution-policy bypass, silent error
suppression, and missing prior-state/rollback custody. The safe bounded response
is proposal-only behavior, not a newly improvised privileged mutation broker.

Exact locations, required gates, and current remediation state are recorded in
`redteam_findings.json`.

## C26-R2-C01 — A caller-controlled frozen flag is accepted as installed Windows elevation authority

- **Severity:** HIGH
- **Status:** CONFIRMED
- **Component:** `src/angerona/__main__.py:58-62`;
  `src/angerona/core/privilege.py:466-505`;
  `src/angerona/core/data_paths.py:422-455,507-510`;
  `installer/windows-install-contract.json:1`

### Description

The new source-versus-installed decision is only
`bool(getattr(sys, "frozen", False))`. If that value is true, the entry point
immediately calls `ensure_admin()` and describes the caller as the
"OS-validated installed build." `ensure_admin()` sanitizes the inherited
environment and relaunches the exact `sys.executable`, which are valuable
controls, but it never proves a Windows package full name/family, a pinned
publisher, a protected installed path, or the portable release authorization.

`sys.frozen` is packaging/runtime metadata, not an operating-system trust
claim. PyInstaller sets it for any frozen bundle, and Python code can set the
attribute directly. After elevation, the same flag selects frozen data-root
creation and Administrator/SYSTEM ACL hardening. Consequently, a repackaged or
otherwise caller-controlled frozen build reaches the same UAC and protected
runtime path that the source remediation intended to reserve for an approved
installed authority.

### Impact and existing mitigations

This reopens the core round 1 boundary for frozen candidate code: after an
operator accepts its branded UAC request, that code executes with Angerona's
Administrator token and can enter protected host-mutation paths. This is not a
silent UAC bypass. The operator must launch the executable and approve UAC;
Windows displays publisher state, a genuine signed MSIX is OS-validated before
activation, and protected installed files cannot ordinarily be replaced by a
standard user. Those controls reduce exploitability, but none makes
`sys.frozen` evidence that the current process came from that MSIX or from the
separately authorized protected portable-upgrade path.

### Inert reproduction

The repository's own
`test_frozen_installed_entrypoint_retains_protected_elevation` sets only
`sys.frozen = True`, substitutes a harmless `ensure_admin` sentinel, and proves
that the elevation branch is reached. It passed in this review (`1 passed`). A
static search found no `GetCurrentPackageFullName`, package-family, self-
publisher, or protected portable-authority proof on the pre-UAC call path.

### Recommendation

Replace the boolean packaging check with a bounded, fail-closed installed-
authority proof before UAC, and repeat that proof in the elevated child. For
the public first-install path, query native Windows package identity and require
the exact externally governed package name/family and publisher embedded in the
reviewed release. For the supported portable-upgrade path, accept only the
already installed protected authority after exact executable Authenticode
publisher, owner/DACL, non-reparse location, threshold release authorization,
and rollback-floor verification. Refuse Administrator execution for every
unpackaged, unpinned, user-writable, or unverifiable frozen executable. Bind
checks to the opened executable object where Windows permits rather than to a
pathname that can be reopened.

## C26-R2-C02 — Release policy accepts alternate secret and failed-dependency bypass syntax

- **Severity:** MEDIUM
- **Status:** CONFIRMED
- **Component:** `tools/validate_workflow_policy.py:39-49,71-78,83-146`;
  `tests/test_cycle26_release_signing_boundary.py:22-56,93-106`

### Description

The new release-policy gate recognizes secret names only in dot notation
(`secrets.NAME`) and rejects signing APIs or `secrets.` as literal substrings in
the two unsigned builder blocks. Equivalent GitHub expression syntax such as
`secrets['COMPANY_CODE_SIGNING_PFX']` is not matched. Its SHA-pin scanner covers
step-level `- uses:` entries but not job-level reusable-workflow `uses:`, and it
does not reject `secrets: inherit`. Finally, downstream bypass detection rejects
only literal `always()` and `continue-on-error: true`; other status-check
conditions, including `!cancelled()` or `failure()`, and expression-valued
`continue-on-error` are outside the check.

The structural release assertions are also partly substring based. The focused
mutation test exercises only a `secrets.COMPANY_CODE_SIGNING_PFX` comment, so it
does not cover these semantically equivalent forms.

### Impact and existing mitigations

The validator can return success for a workflow that passes an exportable
signing key through bracket syntax or an inherited reusable workflow, or that
runs a downstream job despite a failed authority. That can allow the
high-severity release-key exposure pattern to recur while its stated regression
gate remains green.

The checked-in workflow is not presently bypassed: it contains no signing-
secret reference, its authority job has no permissions, checkout, download, or
candidate command and exits unconditionally with status 1, and publication has
no status-check override. Therefore no current publisher key is exposed and no
release can publish. The severity reflects the security-regression assurance
gap, not a claim that the current failed gate can be crossed.

### Inert reproduction

Read-only evaluation of the validator's exact expressions confirmed all three
blind spots: the dot-secret regular expression returned false for bracketed
`secrets['COMPANY_CODE_SIGNING_PFX']`; the action-pin regular expression
returned false for a job-level `uses: org/repo/.github/workflows/sign.yml@main`
with `secrets: inherit`; and the literal failure-bypass check returned false for
`if: !cancelled()`. No secret was accessed and no workflow was run.

### Recommendation

Parse workflow YAML with duplicate-key rejection and validate the expression
and dependency structures fail closed. The simplest safe release invariant is
to forbid every secrets-context access and every `secrets: inherit` anywhere in
repository-controlled release jobs. Forbid job-level reusable workflows or
allow only independently maintained exact-SHA entries with explicit empty
secret mappings. Validate the exact `needs` set structurally, require normal
success propagation from the authority, and reject every status function or
`continue-on-error` representation that could make publication run after gate
failure. Add inert mutation regressions for bracketed/dynamic secret access,
secret aliases, job-level reusable workflows, inherited secrets,
`!cancelled()`/`failure()` conditions, and expression-valued continuation.

## Authority surfaces reviewed without another finding

- Source helper entry points delegate to the one canonical unelevated launcher;
  they contain no `runas`, machine-scope install, or recursive ACL mutation.
- The current release authority job remains an unconditional stopping gate. Its
  dependency order, absence of permissions/secrets/candidate workspace, and the
  publisher's ordinary success dependency provide no current artifact or
  condition bypass.
- Exact artifact names and the absence of wildcard merging prevent the prior
  broad artifact-selection issue. A future external authority must still bind
  its returned asset bytes and complete platform set independently before this
  intentionally disabled path is enabled.

## Prior-finding reconciliation for this review

- **Verified resolved:** `C26-R2-A01` in the checked-in workflow: no threshold
  seed, root policy, publisher PFX/password, certificate private-key material,
  import, or SignTool operation remains in repository jobs.
- **Verified resolved:** the source launchers' specific `C26-R1-A01` through
  `C26-R1-A03` privileged setup/recursive ACL/per-user interpreter paths were
  removed.
- **Residual reopened:** the installed half of `C26-R1-A01` is incomplete for
  caller-controlled frozen builds and is tracked precisely as `C26-R2-C01`.

## C26-R2-D01 — Selected-root scan scope accepts hard links to objects outside the root

- **Severity:** MEDIUM
- **Status:** OPEN
- **Component:** `src/angerona/core/security_scan_center.py:263-377,746-887`

### Description

The new descriptor-bound reader correctly rejects final pathnames outside the
selected root, reparse points, cross-volume objects, non-regular files, and
objects that change while being read. It does not prove that the opened file
object originated beneath the selected root. A same-volume hard link created
inside the root has an in-root final pathname, is not a reparse point, and has
the expected volume, while sharing the exact file object and bytes with a name
outside the root.

### Impact and inert reproduction

An elevated scan of an attacker-controlled directory can be induced to read an
otherwise unselected same-volume object with the suite's authority. Raw bytes
are not returned, which limits disclosure, but metadata and YARA findings become
an information oracle and the UI's selected-root privacy/scope claim is false.
In a temporary directory, this review linked `outside.txt` as
`root/inside-link.txt`; `_read_scoped_file` returned `b"outside-sentinel"` and
the descriptor inode matched the outside file. No host or protected file was
read.

### Recommendation

Retain a selected-root directory handle and enumerate/open descendants relative
to it. Reject multiply linked files unless a Windows object-ID/parent-chain
proof establishes the object relationship; if that proof is unavailable, skip
the file and report a limited scan. Preserve the valuable existing byte,
mutation, final-handle, volume, and no-reparse checks.

## C26-R2-D02 — Directory-only trees bypass Scan Center duration and traversal budgets

- **Severity:** MEDIUM
- **Status:** OPEN
- **Component:** `src/angerona/core/security_scan_center.py:655-677,774-859`

### Description

Cancellation, deadline, file-count, and byte-count checks occur only after
`_iter_local_files()` yields a regular file. Traversal itself has no directory
or entry budget and its pending-directory stack is unbounded. A very wide or
deep tree containing only directories can therefore consume unbounded time and
memory without returning control to the guarded loop.

### Impact and inert reproduction

A hostile local tree can hold the Scan Center worker beyond its advertised
120-second limit or exhaust memory while the result eventually says
`completed`. An inert 800-empty-directory fixture with a 0.0001-second limit
took about 0.171 seconds and returned `completed`, `timed_out=False`, zero files.

### Recommendation

Apply cancellation, deadline, directory-entry, and queued-directory limits
inside traversal. Return `limited`/`timed_out` even when no file was yielded and
cover empty, wide, slow-iterator, and cancellation cases.

## C26-R2-D03 — Process-global self-test routing still diverts live resilience workers

- **Severity:** MEDIUM
- **Status:** OPEN
- **Component:** `src/angerona/resilience/_selftest_environment.py:41-77` and
  the resilience self-tests in `diagnostics.py`, `manager.py`, `scanner.py`,
  `selftest.py`, and `supervisor.py`

### Description

`_ENV_LOCK` serializes callers of `isolated_selftest_environment()` with one
another, but ordinary live resilience threads never take that lock. The helper
still replaces process-global `ANGERONA_DATA` and `ANGERONA_DIAG_DIR`, so live
heartbeat, IPC, diagnostics, and stand-down consumers in the same process are
redirected for the entire self-test. Several test-owned threads are stopped but
not joined before root cleanup. Additionally, `variables(root)` executes before
the `try/finally`; if it raises, the owned temporary root is not removed. The
identity check followed by pathname `rmtree` is not object-bound through
deletion.

### Impact and inert reproduction

This can create a live telemetry/heartbeat gap, contaminate test evidence, race
cleanup, or provoke false resilience recovery while an operator runs a module
self-test. Inert concurrency wrote an ordinary thread's live status into the
self-test root and not its configured live diagnostics root. A deliberately
raising `variables(root)` callback left its captured temporary root present.

### Recommendation

Inject immutable roots into test instances or run each complete self-test in a
separately custodied child. Join every owned worker before object-bound cleanup,
and put all root initialization/callback work under exception-safe custody. Add
a concurrent ordinary-writer regression.

## C26-R2-D04 — Health evidence treats forgeable code filename metadata as trusted provenance

- **Severity:** LOW
- **Status:** OPEN
- **Component:** `src/angerona/core/module_base.py:80-114,191-231`;
  `src/angerona/gui/pages.py:2847-2950`

### Description

The evidence classifier trusts `frame.f_code.co_filename` when that string
resolves to an existing Python file in the checkout. Python code controls this
metadata through `compile(..., filename, ...)` without executing the named
file. The GUI then labels the path/line available and highlights unrelated
trusted source.

### Impact and inert reproduction

An admitted in-process extension can misdirect an operator investigating its
degraded state. This does not grant new code execution—the extension boundary
already requires explicit opt-in and authenticated source—but it breaks the
new evidence integrity claim. An inert external function compiled with
`module_base.py` as its filename reported `source_state=available`,
`src/angerona/core/module_base.py:2`, although line 2 did not contain the call.

### Recommendation

Bind built-in implementation provenance at authenticated discovery/load time to
canonical file identity and digest. Label raw frame metadata as a declared/debug
callsite, not trusted provenance, and keep external extension evidence explicitly
untrusted. Add a `co_filename` forgery regression.

## C26-R2-D05 — Module Inspector can hide or mislabel degradation across mixed health snapshots

- **Severity:** LOW
- **Status:** OPEN
- **Component:** `src/angerona/core/module_base.py:525-568`;
  `src/angerona/gui/pages.py:3380-3405,3473-3509`

### Description and impact

`_refresh()` takes one operational snapshot, but `_current_health_evidence()`
first gates on a separate live `module.health` read. A transition after the
snapshot can hide valid sub-100 evidence or combine a 100% snapshot value with a
new degradation reason. Status text and `health_state` also use separate live
reads. The mismatch is transient, but it violates the requirement that every
displayed sub-100 module state has the matching exact reason.

### Recommendation

Use one operational snapshot for the health value, reason, evidence visibility,
state, and status text during a refresh. Add deterministic interleaving tests in
both transition directions.

## C26-R2-D06 — Defender proposal-only policy loses to generic executable action matching

- **Severity:** MEDIUM
- **Status:** OPEN
- **Component:** `src/angerona/modules/remediation_actions.py:465-486,803-854,909-940`

### Description

Proposal actions are consulted only when no executable action matches. Generic
path, IP, PID, and free-text matchers therefore override the explicit Defender
deny/proposal classification. A Defender/T1562 weakness carrying an existing
path is selected as `QuarantineFileAction`, is shown as executable, and can run
without the host-action gate.

### Impact and inert reproduction

This bypasses the round-2 proposal-only guarantee and can convert explanatory
file/path context into mutation authority. `apply=True` remains required and
Posture AAR ingestion is authenticated, which reduces exploitability. The GUI
and opt-in auto-remediation do pass `apply=True`, however. An inert temporary
file on a Defender weakness produced an executable `quarantine_file` plan; no
apply was performed.

### Recommendation

Evaluate dominant deny/proposal classifications before all executable matchers,
replace overlapping heuristics with typed schemas, reject ambiguous multi-match
records, and test Defender records augmented with every generic target field.

## C26-R2-D07 — Failed compensation is recorded as rolled back and apply exceptions skip compensation

- **Severity:** MEDIUM
- **Status:** OPEN
- **Component:** `src/angerona/modules/remediation_actions.py:499-548,939-967`

### Description

When verification fails, the runner always audits outcome `rolled_back` even if
`rollback()` returns `ok=False`. If `apply()` raises after a partial mutation,
the outer exception path performs no rollback at all. Multi-step actions such as
the two-direction firewall rule can enter that path when the second subprocess
times out after the first succeeded.

### Impact and inert reproduction

The audit surface can claim compensation while changed host state remains, and
the failed record is omitted from the returned records. In inert failure
injection, an action returned `ok=False, changed=True`, rollback returned
`ok=False`, and the audit entry was exactly `outcome=rolled_back` with
`record.rolled_back=False`.

### Recommendation

Create a transaction record before the first mutation; compensate partial and
exception paths; distinguish `apply_failed`, `rolled_back`, `rollback_failed`,
and `recovery_required`; retain failed records and trip a mutation circuit when
state is unknown.

## C26-R2-D08 — Legacy quarantine actions move and verify mutable pathnames instead of the detected file object

- **Severity:** HIGH
- **Status:** OPEN
- **Component:** `src/angerona/modules/remediation_actions.py:44-53,168-193,576-621`

### Description

Both registered quarantine actions discover a string pathname, later reopen it
through `shutil.move`, and verify only that the old pathname is absent and some
destination pathname exists. They retain no detection-time file identity,
digest, no-follow parent/source handles, destination create-new claim, or exact
moved-byte proof. A parent-directory junction/reparse swap, destination
preclaim, or ordinary replacement can therefore change the mutated object and
still satisfy verification.

### Impact and existing mitigation

In the intended elevated deployment this is a confused-deputy primitive: a
local actor who controls a reported path's parent can race the response into
moving a different file with Angerona's authority, while the audit marks the
flagged object patched. Explicit `apply=True` and upstream report authentication
are meaningful mitigations but do not bind the target object after approval.
The repository already contains the stronger pinned-file, non-reparse parent,
digest-bound, authenticated quarantine discipline in Adversary Combat; this
legacy path does not use it.

### Recommendation

Require sensor-bound volume/file identity and digest, retain no-follow parent
and source handles through a create-new destination move, verify exact moved
bytes/object identity, and bind rollback to the authenticated record. Reuse the
reviewed pinned-file quarantine primitive and retain hostile swap/preclaim/
hard-link/cross-volume regressions.

## Runtime-boundary prior-finding reconciliation

- `C26-R1-B02` is materially improved: YARA scans the exact bounded descriptor
  snapshot and file/root mutation checks reject ordinary symlink/reparse swaps.
  `C26-R2-D01` and `D02` precisely track the remaining hard-link provenance and
  traversal-budget gaps rather than re-reporting the closed pathname-reopen bug.
- `C26-R1-B01` is not fully closed for live same-process workers. Exact prior
  environment restoration and manager scanner PID custody passed review, while
  `C26-R2-D03` records the remaining global-routing and cleanup gap.
- `C26-R2-B01`'s direct failed-apply promotion is fixed. `C26-R2-D06` and `D07`
  are distinct classification and compensation-receipt bypasses found by the
  independent follow-up.
