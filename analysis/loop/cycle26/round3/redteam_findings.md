# Cycle 26 round 3 adversarial closure findings

Scope: authorized, defensive-only theoretical hardening. This review used only
in-memory/static failure fixtures. It did not access secrets, execute a workflow,
perform host mutation, establish persistence, or attempt a real intrusion.

Three medium-severity residuals were reproduced. The checked-in release remains
fail-closed, Windows packaged elevation remains disabled until an independently
governed exact package/publisher pin exists, and both legacy pathname quarantine
classes are inert and outside the executable action catalog. The findings below
are regression-assurance and response-custody gaps, not claims that the present
failed release gate can publish or that package identity can presently be forged.

## C26-R3-A01 — Workflow-level environment secrets bypass the release authority policy

- **Severity:** MEDIUM
- **Status:** FIXED
- **Component:** `tools/validate_workflow_policy.py:199-208,282-305`;
  `.github/workflows/release.yml:8-15`

### Description

The structural release check forbids the secrets context while iterating each
job, but it does not apply that invariant to the complete workflow document.
The later global pass rejects a literal secret reference only when its *name*
matches a signing-key heuristic. GitHub workflow-level `env` values are inherited
by jobs, so a renamed secret can enter every release job without appearing under
any job mapping or matching the exportable-secret-name expression.

### Impact and existing mitigations

A future workflow edit could reintroduce an exportable release/publisher
authority under an innocuous secret name at workflow scope while the declared
policy gate remains green. Candidate-controlled build steps would then receive
that value. The checked-in workflow contains no such workflow-level secret, all
current release jobs are secret-free, the external-authority job has no
permissions/artifacts/candidate code, and it unconditionally exits 1. Thus the
present release is blocked; this finding is a policy-regression bypass.

### Exact inert reproduction

The parsed release text was modified only in memory by inserting this top-level
mapping after `permissions`:

```yaml
env:
  RELEASE_AUTHORITY_INPUT: ${{ secrets.S }}
```

Running `_load_workflow`, `_validate_release`, the known-marker pass, and the
generic signing-secret-name pass returned respectively `[]` and `[]`, while the
parsed workflow contained `{'RELEASE_AUTHORITY_INPUT': '${{ secrets.S }}'}`.
No secret was resolved and no workflow ran.

### Recommendation

Reject every secrets-context access over the complete parsed release document,
including workflow-level `env`, defaults, concurrency, and future root mappings,
regardless of the referenced secret name. Retain duplicate-key rejection and the
exact gate/dependency/artifact invariants. Add dot/bracket and renamed-alias
fixtures at workflow scope.

## C26-R3-A02 — Response transaction and mutation-circuit custody are only batch-local

- **Severity:** MEDIUM
- **Status:** FIXED
- **Component:** `src/angerona/modules/remediation_actions.py:92-116,979-995,1081-1168`;
  `src/angerona/core/remediation_log.py:129-190`

### Description

`begin_transaction()` creates only an in-memory dictionary. No PREPARED or
MUTATING state is durably written before dispatch; the audit log is called only
after a terminal outcome. Several actions also capture their exact prior state
inside `apply()`, so a crash after mutation but before return loses the data
needed for compensation. When rollback fails, `mutation_circuit_open` blocks the
rest of that Python call only. A new `apply_remediation()` call always starts
with the circuit clear and does not reconcile prior `rollback_failed` or
`recovery_required` receipts.

### Impact and existing mitigations

An abrupt process exit can leave a partial firewall, registry, service, or
process response without a retained recovery transaction. Even when a rollback
failure is successfully audited, a later automatic/manual batch can stack new
mutations on state already declared unknown. Explicit `apply=True` and the host
opt-in remain meaningful gates; ordinary caught exceptions now attempt
compensation and terminal receipts truthfully distinguish rollback failure.
Those controls do not survive a process boundary or later batch.

### Exact inert reproduction

An in-memory action returned a simulated partial failure and a simulated failed
rollback. The first `apply_remediation()` result contained
`transaction_state='rollback_failed'`. A second call in the same process with a
separate inert action returned `applied=1`; the audit outcomes were exactly
`['rollback_failed', 'applied']`. No OS command or file mutation occurred.

### Recommendation

Before any external dispatch, atomically write and fsync an action-specific
PREPARED record containing exact prior state and compensation identities. Move
it durably through MUTATING and terminal states, and open a persistent circuit
on incomplete/unknown/recovery-required state. Reconcile that journal on startup
and before every batch; only exact verified compensation or explicit governed
recovery may clear the circuit. Audit/journal failure must block mutation.

## C26-R3-A03 — Substring proposal dominance and hidden registry candidates produce wrong remediation decisions

- **Severity:** MEDIUM
- **Status:** FIXED
- **Component:** `src/angerona/modules/remediation_actions.py:312-364,482-500,868-939`;
  `src/angerona/modules/posture_hardening.py:848-867`

### Description

The new classifier rejects multiple matching *action objects*, but an action can
still hide multiple internal candidates. `RegistryHardeningAction._entry()`
returns the first table row whose arbitrary substring appears, without proving
that exactly one control matches the weakness's technique. Separately, dominant
Defender matching includes bare `t1562`, so it absorbs the explicitly supported
`T1562.011` script-block-logging control before the registry action is examined.

This is not a type-safe decision: `RemediationDecision` is typed, but its input
and the candidate selection remain overlapping free text. A verified change to
the silently selected registry value can then mark the original MITRE weakness
patched even when that different control did not remediate it.

### Impact and existing mitigations

The broad dominant proposal can suppress a bounded vetted repair, while an
ambiguous record can apply and verify the wrong registry hardening and falsely
close the reported weakness. Host mutations still require explicit apply plus
the host-action opt-in, authenticated practice inputs reduce poisoning, and
cross-action ambiguity now fails closed. The remaining defect is inside the
same action and exact-technique family.

### Exact inert reproductions

- `{'mitre_id':'T1562.011','name':'PowerShell script block logging disabled'}`
  produced proposal `defender_hardening` and no executable action, despite the
  table's explicit T1562.011 script-block control.
- `{'mitre_id':'T1548.002','name':'credential UAC bypass'}` matched three registry
  candidates (LSA RunAsPPL, WDigest, and UAC policy), while `_entry()` silently
  selected the first LSA row. Candidate enumeration only was performed; no
  registry call occurred.

### Recommendation

Use exact technique-family and versioned weakness schemas rather than broad
substrings. Defender dominance must distinguish generic T1562/Defender tampering
from the explicitly supported T1562.011 control. Registry hardening must require
exactly one typed candidate whose declared technique/control matches the finding;
zero or multiple candidates remain proposal-only/manual review and cannot mark
the weakness patched.

## Closed controls credited and prior-finding reconciliation

- **Verified resolved:** `C26-R2-C01`. Frozen Windows startup proves the exact
  process-bound package family/publisher before UAC and again in the elevated
  child. Empty production pins deliberately fail closed, so privileged frozen
  startup is presently unavailable rather than falsely trusted.
- **Verified resolved:** `C26-R2-D08`. Both legacy pathname quarantine classes
  return inert proposals even when called directly and are absent from `ACTIONS`;
  the distinct exact-object Adversary Combat quarantine remains separately gated.
- **Incomplete and re-filed precisely:** `C26-R2-C02` as `C26-R3-A01`,
  `C26-R2-D07` as `C26-R3-A02`, and `C26-R2-D06` as `C26-R3-A03`.

No additional reproducible bypass was found in duplicate-key rejection, exact
job `needs`, the one-step executable `exit 1` authority gate, action SHA pins,
the pre/post-UAC native package-family proof, or direct legacy-quarantine calls.

## Independent runtime and authentication-extension follow-up

This bounded follow-up reviewed only the Cycle 26 runtime remediations and the
new Authentication Extension Integrity Guard. All reproductions used synthetic
objects, temporary files, monkeypatched delays, or in-memory code objects. No
credential was read, no registered authentication component was loaded, no host
setting was changed, and no persistence or intrusion was attempted.

## C26-R3-B01 — Missing or invalid component assurance is graded complete and enrollable

- **Severity:** MEDIUM
- **Status:** FIXED
- **Component:** `src/angerona/core/windows_auth_extensions.py:615-652,1694-1718`;
  `src/angerona/modules/authentication_extension_guard.py:138-153,317-346`

### Description

Snapshot assessment checks fixed-surface coverage and whether each component
path resolved, but it never evaluates `evidence_status`, Authenticode state,
catalog state, owner evidence, or ACL evidence. A resolved component explicitly
marked `authenticode_state="invalid"`, `catalog_state="error"`, and
`evidence_status="partial"` is therefore graded `complete-local`, receives 75%
health, and is eligible for trusted-baseline enrollment.

The production module constructs `WindowsAuthExtensionEvidenceProvider` without
a `signature_probe`, so every resolved production component defaults to unknown
signature/catalog evidence. This is not merely an injected-provider edge case:
the normal provider can claim the same complete/enrollable assessment while the
signature evidence described by the health reason was never collected.

### Impact and existing mitigations

An already-compromised first observation, an invalidly signed authentication
extension, or a component whose ownership/ACL could not be observed can be
presented to an operator as complete and then enrolled as trusted. Later byte
drift remains detectable, enrollment is explicit, the module is observe-only,
and health is honestly capped below 100% for local-only custody. Those controls
do not make absent or explicitly invalid component evidence complete.

### Exact inert reproduction

A synthetic fixed-surface snapshot with one safely resolved component was
constructed using immutable model objects. Its component was set to
`authenticode_state="invalid"`, `catalog_state="error"`, empty owner/ACL tokens,
and `evidence_status="partial"`. `assess_auth_extension_snapshot()` returned:

```text
health=75, state=complete-local, baseline_eligible=True
```

No registry, DLL, credential, or host file was accessed.

### Recommendation

Make assessment and enrollment depend on every required component-evidence
field, not resolution alone. Unknown/error/invalid signature or catalog state,
missing owner/ACL evidence, and `evidence_status != "complete"` must remain
partial and non-enrollable unless a separate explicit risk-acceptance workflow
names the exact component digest and missing evidence. Supply a bounded,
handle-bound Windows signature/catalog verifier; revalidate the file handle
after all metadata probes and never reopen only by pathname.

## C26-R3-B02 — Unauthenticated baseline numbers can escape validation and crash the observer

- **Severity:** MEDIUM
- **Status:** FIXED
- **Component:** `src/angerona/core/windows_auth_extensions.py:845-932`;
  `src/angerona/modules/authentication_extension_guard.py:294-350`

### Description

The baseline loader converts attacker-controlled `captured_at` to `float`
before verifying the HMAC. A sufficiently large but valid JSON integer raises
`OverflowError`; that exception is not normalized to `BaselineIntegrityError`
and is not caught by `observe()`. The module's collection-only exception guard
ends before the baseline call, so the exception escapes `observe_once()`.

### Impact and existing mitigations

A process able to corrupt or replace the local baseline without knowing its
HMAC key can force every observation attempt to raise instead of producing the
intended tampered-baseline event. The common module wrapper retries and then
quarantines a repeatedly crashing capability, making this a persistent sensor
denial until the state is manually repaired. The 512 KiB file limit, exact JSON
fields, duplicate-key rejection, HMAC, protected data-root intent, and
observation-only authority all reduce exposure; the defect occurs before the
authentication decision those controls are meant to reach.

### Exact inert reproduction

A temporary baseline wrapper with all required top-level/body fields, a fake
64-hex-character HMAC, and `captured_at = 10**400` was passed to `_load()` with
an in-memory test key. It raised exactly:

```text
OverflowError: int too large to convert to float
```

The temporary file was removed and no production state was touched.

### Recommendation

Treat every parse/schema/conversion failure before authentication—including
`OverflowError`, `RecursionError`, excessive nesting, and hostile numeric
representations—as bounded baseline-integrity failure. Parse into a strict
depth/cardinality-limited representation, validate numeric type/range without
unsafe conversion, then authenticate and reconstruct the snapshot. Add malformed
pre-HMAC number/depth fixtures and prove `observe_once()` emits a path-safe
tamper/unknown result rather than crashing.

## C26-R3-B03 — Self-test child custody forwards secrets/code-loading controls and bounds output only after capture

- **Severity:** MEDIUM
- **Status:** FIXED
- **Component:** `src/angerona/resilience/_selftest_environment.py:186-265`;
  `src/angerona/core/privilege.py:400-420`

### Description

The isolated runner starts from `os.environ.copy()`, preserves inherited
`PYTHONPATH`, and inherits the caller's working directory. It therefore forwards
provider/API credentials, proxy configuration, Python startup/import controls,
and unrelated Angerona authority into a child whose purpose needs only a small
fixed routing allowlist. The child also starts normally before it is assigned to
the Windows kill-on-close job; injected Python startup code can run in that
window before `_child_main()` blocks on the token.

Separately, `communicate()` accumulates the complete merged stdout/stderr string
in parent memory and only then checks the 16 KiB limit. The job constrains
lifetime but sets no process-count, CPU, or memory limit. A faulty or compromised
self-test can therefore exhaust the parent before the advertised output bound is
enforced.

### Impact and existing mitigations

The new child boundary successfully prevents process-global routing changes,
and the target map, one-use token, timeout, no-shell argv, close-on-exec handles,
Windows job/POSIX process group, and exact temporary-root cleanup are valuable.
The residual can still expose parent-only credentials to a test child, permit a
source-mode import/startup injection, create a pre-job descendant, or exhaust
the security UI/core process while an operator runs a self-test. Packaged frozen
runtimes currently refuse these child tests and source launch is intentionally
unelevated, limiting privilege impact.

### Exact inert reproduction

With `Popen` replaced by a no-process fixture, the parent environment was given
the non-secret sentinel `C26_INERT_API_KEY=sentinel-not-a-real-secret`. The
captured child environment contained that value and inherited `PYTHONPATH`. The
fixture returned 20,032 characters; the runner had already received the entire
string before returning `output exceeded its bound`. No child or network
activity occurred.

### Recommendation

Build the environment with the existing `sanitized_child_environment()` policy
plus an exact per-target routing allowlist; reject all inherited Python/proxy/
credential controls, set a trusted source-root working directory, and use
isolated Python startup flags where compatible. On Windows, create suspended,
assign the configured job, then resume. Stream and terminate at 16 KiB rather
than using unbounded `communicate`, and apply conservative job/process memory,
CPU, and active-process limits. Preserve the fixed target/token/time/temp-root
controls and add secret-forwarding, startup-injection, output-flood, and
pre-assignment-descendant regressions.

## C26-R3-B04 — Direct-file reads can exceed the scan deadline and still report completed

- **Severity:** LOW
- **Status:** FIXED
- **Component:** `src/angerona/core/security_scan_center.py:313-401,828-975`

### Description

The traversal now checks deadline and cancellation before and after each
directory entry, but `_read_scoped_file()` receives neither the deadline nor the
cancellation token and checks neither inside its read loop. For a selected file
root, the generator returns immediately after its one yield, so it never gets a
later opportunity to mark the traversal timed out. YARA work is likewise not
bounded by the remaining overall deadline.

### Impact and existing mitigations

A slow local filesystem/filter or blocking regular-file read can hold the scan
worker beyond its advertised duration and yield a false `completed` result.
The byte/file/entry/directory limits, hard-link rejection, no-follow open,
handle-bound root proof, stable identity checks, and YARA snapshot scan remain
effective; this is a deadline/status and availability weakness, not a recovered
scope escape.

### Exact inert reproduction

A seven-byte temporary direct-file target was scanned with a 0.01-second limit
while `os.read` was monkeypatched to delay harmless reads. The operation took
0.188 seconds but returned:

```text
status=completed, timed_out=False, files_scanned=1
```

### Recommendation

Pass the absolute deadline and cancellation token into descriptor reads and
check them between bounded chunks and before/after YARA. Because a blocking OS
read cannot be cooperatively interrupted, use a custodied worker process (or a
platform cancellation API) when a hard wall-clock guarantee is claimed. A late
result must be `limited`/`timed_out`, including a one-file root.

## C26-R3-B05 — Mutable loaded-module registration can still forge verified source provenance

- **Severity:** LOW
- **Status:** FIXED
- **Component:** `src/angerona/core/module_base.py:86-151,211-282`;
  `src/angerona/gui/pages.py:2858-2977`

### Description

The D04 remediation correctly rejects a free-standing function whose only claim
is a forged `co_filename`. It then proves declaration by searching the *current
mutable* module globals/classes for the exact code object. In-process code can
compile a function with a trusted filename and register that function in the
corresponding loaded Angerona module immediately before calling `set_health`.
The current search then treats the newly inserted object as declared loaded
implementation even though its bytecode did not come from that source file.

### Impact and existing mitigations

An admitted in-process extension can make a fabricated degradation reason point
to an unrelated trusted line highlighted in red, weakening the operator evidence
the new UI is meant to make exact. This requires code already executing inside
the process and grants no additional host authority; the known external-module
isolation residual therefore materially limits severity. Canonical path, module
globals identity, source digest, source revalidation, and packaged-runtime path
withholding all remain useful against simpler forgery.

### Exact inert reproduction

An in-memory function was compiled with `module_base.py` as filename, inserted
temporarily into `angerona.core.module_base.__dict__`, invoked, and removed. Its
evidence was accepted as:

```text
source_state=available
source_provenance=verified-loaded-implementation
source_path=src/angerona/core/module_base.py
source_line=667
```

The highlighted checked-in line was unrelated to the dynamically compiled
function. No file was changed.

### Recommendation

Bind source provenance to an immutable code manifest captured from the canonical
loader/source at trusted module admission, including a stable code-object/source
signature and first-line mapping. Do not treat membership in mutable live module
globals as declaration provenance. If bytecode-to-source identity cannot be
proved, retain the reason but label the path/line unverified and do not highlight
it as exact.

## Runtime/auth boundary results and prior-finding reconciliation

- **Verified resolved:** `C26-R2-D01`. A same-volume hard link is rejected before
  the first content read and makes the result explicitly limited.
- **Verified resolved:** the empty/wide/deep portions of `C26-R2-D02`. Entry,
  visited-directory, discovered-directory, deadline, and cancellation state are
  bounded and reported. `C26-R3-B04` is the narrower remaining direct-read
  deadline gap.
- **Verified resolved:** the process-global routing portion of `C26-R2-D03`.
  All five wrappers route only the child to the temporary root, and cleanup owns
  the exact created directory. `C26-R3-B03` concerns child minimization/resource
  custody rather than reopening parent routing.
- **Residual re-filed:** `C26-R2-D04` survives ordinary forged-filename tests but
  remains bypassable through mutable declaration registration as `C26-R3-B05`.
- **Verified resolved:** `C26-R2-D05`. Status, health, reason, and evidence are
  captured under one lock, and Module Inspector renders one operational snapshot.
- **Survived targeted review:** path-minimized baseline/events; strict duplicate
  JSON keys; purpose-separated keys; exclusive provisional creation; explicit
  trusted enrollment; no drift promotion; symlink/reparse/final-handle checks;
  fixed registry catalogs and cardinality/byte caps; and observe-only/no-response
  authority.
- **Retained disclosed dependency, not re-filed:** authenticated baseline rollback
  and freshness remain local-only without an independent high-water witness
  (`C23-R2-01`).

The focused existing regression set passed **40/40** after these reproductions.

## Independent release/source authority audit addendum

This read-only pass used parsed in-memory workflow mutations and injected no-op
process fixtures only. It did not access secrets, run a workflow, publish,
request UAC, or mutate the host.

## C26-R3-C01 — Bash startup injection and expression-named artifacts compose into a release-gate bypass

- **Severity:** HIGH
- **Status:** OPEN
- **Component:** `tools/validate_workflow_policy.py:142-179,185-190,196-288`;
  `.github/workflows/release.yml:8-15,221-286,557-670`

Workflow-level `env` is unconstrained. GNU Bash reads `BASH_ENV` before a
non-interactive script, so an inherited value can create/source a file defining
`exit(){ :; }` before the gate's literal `exit 1`. Separately, prepare may add
an upload whose `with.name` is an expression that resolves to
`finalized-windows-release-assets`; the validator compares only the unevaluated
string, permits extra prepare uploads, and the publisher authenticates artifact
provenance by name rather than independently verifying its bytes.

An in-memory mutation combined a top-level `BASH_ENV` with a third prepare upload
named `${{ format('{0}{1}', 'finalized-windows-', 'release-assets') }}`.
`_validate_release()` returned `[]`. The installed Bash also emitted an inert
`BASH_ENV` command-substitution marker before its body, confirming startup
expansion precedes the gate. Candidate code can create the exact files the
publish job later attests and releases. The checked-in workflow contains neither
mutation and currently exits 1, so exploitation requires a workflow revision
reaching an authorized release tag; no present release was published.

**Recommendation:** reject workflow-level `env`/`defaults`, require an exact
root/job/runner/shell schema with privileged Bash startup semantics, and forbid
extra uploads or expressions in security-significant artifact metadata. Bind an
externally produced artifact ID, digest, and signed exact bytes before granting
attestation/publication authority; an artifact name must not convey provenance.

## C26-R3-C02 — Whole-context secret serialization bypasses the repaired detector

- **Severity:** MEDIUM
- **Status:** OPEN
- **Component:** `tools/validate_workflow_policy.py:28-34,182-215,303-314`

Both secret detectors require `secrets.` or `secrets[...]`. A workflow value of
`${{ toJSON(secrets) }}` passes the context itself to a function and therefore
evades both. In-memory parsing retained that exact expression while
`_validate_release()`, the known-marker pass, and `LITERAL_SECRET` all returned
no finding. No context was evaluated and no secret was accessed. The checked-in
workflow has no such reference or release secret.

**Recommendation:** reject `secrets` as a standalone lexical token inside every
`${{ ... }}` expression throughout the release document, independent of
accessor/function syntax, and add whole-context fixtures at root, job, and step
scope while continuing to ignore comments and prose outside expressions.

## C26-R3-C03 — Cancelled or failed UAC is followed only by another identity check

- **Severity:** LOW
- **Status:** FIXED
- **Component:** `src/angerona/__main__.py:55-83`;
  `src/angerona/core/privilege.py:466-509`

`ensure_admin()` returns normally when `ShellExecuteW` fails or UAC is cancelled.
The frozen entry point then repeats package identity, which remains true in the
original medium-token process, but never proves `is_admin()` before continuing.
An injected no-op elevation and trusted identity reproduced
`reached_runtime_after_failed_elevation=True`. This grants no privilege, and
protected data custody usually fails closed, but can produce unexplained startup
failure or reduced coverage instead of the stated elevated-child boundary.

**Recommendation:** return a typed elevation result and require both exact
package identity and the effective Administrator token afterward. Fail visibly,
or enter a separately named restricted Observe mode, on cancellation/failure.

## C26-R3-C04 — Publisher verifies mutable worktree assets after its final clean check

- **Severity:** LOW
- **Status:** OPEN
- **Component:** `tools/publish_github_update.py:247-270`;
  `tools/verify_published_readme_assets.py:150-223`

The last clean-worktree check precedes network asset verification. The verifier
then reads README/image bytes from the live worktree rather than captured `HEAD`,
and success has no final clean/HEAD check. A concurrent editor can therefore
change the target set after the check and invalidate the claim that the worktree
stayed clean and every public-HEAD image was examined. Remote SHA/fast-forward
proof remains intact; this is a completion-proof gap.

**Recommendation:** read README and image blobs from the captured immutable
`HEAD` (or a protected archive of it), compare those bytes to public `HEAD`, and
repeat exact local HEAD/worktree cleanliness immediately before success.

### Controls that survived this authority pass

- Source launchers contain no UAC request, machine-scope setup, recursive ACL
  mutation, or runtime package installation; setup remains hash-locked and
  unelevated.
- Native package queries are process-bound and bounded, and empty production
  pins fail closed.
- The publisher proves one credential-free canonical GitHub HTTPS slug, exact
  default `main`, fast-forward ancestry, atomic no-tag refspecs, and both remote
  branch SHAs.

## Independent response-custody post-remediation re-attack

This read-only pass used temporary SQLite databases and inert action objects.
It did not call a host utility, change a security setting, inspect a credential,
or dispatch a product remediation action. Normal same-path, cross-connection
preparation correctly admitted one transaction and rejected the other.

## C26-R3-A04 — Reconciliation can seize a live mutation and run compensation more than once

- **Severity:** MEDIUM
- **Status:** OPEN
- **Component:** `src/angerona/core/remediation_log.py:269-326`;
  `src/angerona/modules/remediation_actions.py:1388-1391,1707-1817`

### Description

`reconcile_incomplete_transactions()` treats every `MUTATING` row as an
interrupted transaction, but the row carries no owner identity, process-start
identity, lease, heartbeat, or stale-after bound. Every new remediation batch
calls that routine. A second batch arriving while the first action is still
running therefore promotes the live row to `RECOVERY_REQUIRED`; the legitimate
owner can no longer commit its terminal result.

The explicit reconciliation path has a second race. It reads a
`RECOVERY_REQUIRED` row and performs the external rollback before claiming that
row with a compare-and-swap state. Two callers can consequently execute the
same rollback twice. Likewise, a reconciler can roll back a live action after
promoting it, commit `ROLLED_BACK`, and then allow the original action to resume
and mutate again. The durable journal then says `ROLLED_BACK` while the inert
effect model is in its post-mutation state.

### Impact and existing mitigations

An overlapping automatic batch causes a conservative availability lockout.
More seriously, an explicitly authorized recovery racing a slow firewall,
registry, service, or process response can interleave compensation with the
live mutation and leave a partial host change behind a false terminal journal
state. Concurrent recovery calls can also dispatch compensation twice. The new
atomic prepare gate still prevents two ordinary same-path transactions from
starting, and recovery requires the explicit `authorized=True` API gate; there
is currently no product UI caller for that API. Those controls lower
exploitability but do not establish transaction ownership or recovery
single-flight.

### Exact inert reproductions

- A blocking inert action reached durable `MUTATING`. Starting another ordinary
  batch changed the first row to `RECOVERY_REQUIRED`; the first action later
  verified successfully but could not commit `APPLIED`.
- A reconciler was run while an inert two-step action paused after step one.
  Reconciliation returned `ROLLED_BACK`; after the original action resumed, the
  effect model ended at step two while the durable row remained `ROLLED_BACK`.
- Two concurrent authorized reconciliations executed the inert rollback twice.
  One returned success; the loser returned `recovery_required=True` even though
  the durable row was already terminal `ROLLED_BACK`.

### Recommendation

Give every transaction a cryptographically random owner ID bound to process
identity/start time and a bounded renewable lease. Only classify `MUTATING` as
interrupted after independently proving its owner is dead or the lease is stale.
Before any compensation, atomically claim exactly one row into a distinct
`RECOVERING` state; only the claim winner may touch host state. Bind recovery
authorization to the exact transaction ID and retained-record digest, and
commit the terminal state plus its truthful audit receipt atomically. Add
late-arrival, live-owner, two-reconciler, and resume-after-rollback schedules.

## C26-R3-A05 — Hard-link database aliases split SQLite WAL custody and authorize two mutations

- **Severity:** MEDIUM
- **Status:** OPEN
- **Component:** `src/angerona/core/remediation_log.py:74-104,109-118,185-230`

### Description

Database identity is only `Path.resolve(strict=False)`. That normalizes lexical
aliases but does not bind the opened database object or reject hard links. On
NTFS, two hard-link names for the same database file receive different
`-wal`/`-shm` sidecars. SQLite consequently gives each name an independent view
and lock domain, bypassing the `BEGIN IMMEDIATE` serialization on which the
persistent mutation circuit relies.

### Impact and existing mitigations

Two Angerona processes started through different data-root/database aliases can
each authorize a response even though both paths name the same base database
object. Their journals can diverge or be corrupted, and neither process sees the
other's unresolved transaction. The process singleton and `init_log()`'s
different-string rejection protect the ordinary one-process/canonical-path
case. Protected release data-root ACLs also make malicious alias creation harder.
They do not prove file identity across process starts, path rebinding, or two
separately aliased instance-lock roots.

### Exact inert reproduction

A temporary `main.db` was hard-linked as `alias.db`; `os.path.samefile()` was
true. One `RemediationLog` was opened through each name. Both
`prepare_transaction()` calls returned transaction ID `1`, and both independently
transitioned that row to `MUTATING`. The directory contained separate
`main.db-wal`/`main.db-shm` and `alias.db-wal`/`alias.db-shm` files. By contrast,
two connections using the exact same pathname admitted one PREPARED row and
raised `RemediationCircuitOpen` for the loser.

### Recommendation

Open the journal beneath the protected canonical data-root handle and bind it to
a stable Windows volume/file identity. Reject reparse targets, hard links
(`nlink != 1`), remote filesystems, and identity changes before and after schema
setup; hold the parent/database handles for the process lifetime. Bind the
single-instance lease to the same root/file identity and fail closed on any
alias or rebinding. Add a Windows hard-link two-process regression that proves
the second process cannot reach PREPARED or MUTATING.

### Response-custody controls that survived this pass

- Same-path SQLite connections serialize prepare atomically: one PREPARED row,
  one `RemediationCircuitOpen`, and no second mutation authorization.
- Existing PREPARED, MUTATING, and RECOVERY_REQUIRED rows block ordinary
  preparation; malformed/oversized records and missing journal custody fail
  before dispatch.
- Terminal pruning removes only APPLIED/ROLLED_BACK rows and refuses a journal
  filled with unresolved state.
- Exact registry selection rejects conflicting MITRE IDs, mismatched control
  IDs, and multi-control T1003.001 input; T1562.011 is not swallowed by the
  Defender proposal.
- The focused checked-in response gate passed **15/15**; the schedules and alias
  reproductions above are missing regressions rather than failures of those
  existing tests.

## Independent release/source-authority post-remediation re-attack

This pass inspected only the Cycle 26 release workflow validator, frozen/UAC
entry boundary, GitHub publisher, and public README asset verifier. Parsed
workflow mutations and monkeypatched temporary-process fixtures were inert: no
workflow ran, no UAC request was made, no executable fixture was launched, no
host setting changed, and nothing was published.

## C26-R3-C05 — Windows asset fallback trusts caller-selected PowerShell and forwards the full environment

- **Severity:** MEDIUM
- **Status:** OPEN
- **Component:** `tools/verify_published_readme_assets.py:146-209`

### Description

The Windows fallback derives `powershell.exe` from the inherited `SystemRoot`
environment variable, checks only `Path.is_file()`, and starts it with
`os.environ.copy()`. A caller that controls the publisher environment can
therefore select an arbitrary executable at
`<SystemRoot>\System32\WindowsPowerShell\v1.0\powershell.exe`. The child also
receives unrelated credentials, proxy settings, Python/PowerShell loading
controls, and every other environment value. `-NoProfile` does not authenticate
the executable and does not remove that inherited environment.

The path is reached when the primary URL request raises `URLError` with an
`OSError` reason on Windows. A caller-controlled proxy can induce that ordinary
network failure. The selected process can then write arbitrary bytes to the
exported temporary path and claim an allowed content type. It can read the local
Git object to return the expected README/image bytes without proving that the
public raw GitHub endpoint served them, so the immutable-blob comparison and
final clean-worktree check do not detect the substitution.

### Impact and existing mitigations

A local foothold able to shape the maintainer's publication environment can run
code as that maintainer, receive any environment-held credentials, and forge
the final public-asset reachability proof without modifying the worktree. The
normal urllib path, fixed raw-GitHub URL, response size/type/PNG/digest checks,
remote-SHA checks, and immutable local blobs remain strong when no fallback is
entered. Exploitability is local and conditional on a Windows network error,
so this is medium rather than high severity.

### Exact inert reproduction

A temporary caller-selected `SystemRoot` contained an inert marker named
`powershell.exe`. `subprocess.run` was monkeypatched, so the marker was never
executed. The fixture recorded that the helper selected that exact temporary
path, forwarded `INERT_PRIVATE_TOKEN=forwarded`, accepted the child's synthetic
`image/png` result, and returned the bytes the child placed at the exported
temporary filename. The fixture and file were then removed.

### Recommendation

Prefer deleting the process fallback and fail closed when the bounded Python
HTTPS client cannot complete. If a Windows fallback is operationally required,
resolve the system executable with a Win32 system-directory API, prove its
Microsoft signature/file identity, use a fresh minimal environment with no
proxy, module, Python, credential, or shell-startup values, and independently
bind the downloaded response to the requested raw-GitHub URL. Add an inert
regression proving a forged `SystemRoot`, `PSModulePath`, proxy, and secret never
reach process selection or the child.

## C26-R3-C06 — Publisher accepts non-canonical origin spellings while claiming exact-origin proof

- **Severity:** LOW
- **Status:** OPEN
- **Component:** `tools/publish_github_update.py:48-78,200-211`

### Description

`github_repository_from_origin()` strips all leading/trailing slashes, discards
empty path components, and accepts the repository name with or without `.git`.
It consequently reduces several different remote strings to the expected slug
instead of proving the configured fetch and push URLs equal the one required
canonical HTTPS origin.

### Impact and existing mitigations

The publisher can report that the exact-origin gate passed while Git config
contains a non-canonical spelling. The reproduced variants still name the same
credential-free GitHub host and repository slug, so this does not by itself
redirect a push or weaken the remote-SHA/fast-forward proofs; impact is limited
to a false completion assertion and configuration drift.

### Exact inert reproduction

Pure parser calls returned `Ag3nt47/AngeronaSuite` for both
`https://github.com//Ag3nt47//AngeronaSuite.git/` and
`https://github.com/Ag3nt47/AngeronaSuite`. No Git command or network request
was made.

### Recommendation

After requiring exactly one fetch URL and one push URL, compare both strings
byte-for-byte with `https://github.com/Ag3nt47/AngeronaSuite.git`; reject extra
slashes, a missing `.git`, whitespace, alternate casing, redirects, and all
other normalized equivalents. Retain the current credential/port/query/fragment
and exact remote-SHA checks.

### Release/source-authority controls that survived this pass

- In-memory root/job/step mutations for workflow `env`, `defaults`, `BASH_ENV`,
  imported-function variables, dot/bracket/whole-context secrets, reusable
  workflows, extra jobs/steps, dynamic security artifact names, and extra or
  duplicate `needs` edges all failed closed.
- The authority job remains one static-notice step under `env -i` and fixed
  `/bin/bash --noprofile --norc`; a real harmless Bash execution confirmed its
  checked-in body exits 1. No current job produces the finalized Windows
  artifact required by publication.
- Frozen startup still proves exact process-bound package identity before and
  after UAC, requires a typed elevation result plus a fresh effective-token
  Administrator check, and defaults to no provisioned pin. Source execution
  never calls the UAC helper and elevated mutable source is refused.
- Immutable commit/README/image selection and the final remote SHA, default-main,
  HEAD, and clean-worktree rechecks survived. The checked-in focused gate passed
  **44/44** tests.

## Final response-custody remediation re-attack

This pass used only temporary databases, inert action objects, injected SQLite
receipt failure, and filename-identity fixtures. It invoked no product response,
host utility, security setting, credential, network request, or publication.

## C26-R3-A06 — Unowned transaction transitions can terminalize live work and authorize a second dispatch

- **Severity:** LOW
- **Status:** OPEN
- **Component:** `src/angerona/core/remediation_log.py:331-371`;
  `src/angerona/modules/remediation_actions.py:1372-1391,1452-1598`

### Description

The reconciliation claim now gives compensation an effective single-flight
boundary, but ordinary transaction transitions still have no owner identity or
capability. `transition_transaction()` accepts any caller-supplied combination
of enumerated expected and target states. It validates neither a fixed state
graph nor that the caller owns the PREPARED/MUTATING transaction.

A competing caller with the process remediation-log reference and a live
transaction ID can therefore change `MUTATING` directly to `APPLIED`. Because
the persistent circuit considers APPLIED terminal, a normal second
`apply_remediation()` call sees no unresolved state, creates another PREPARED
row, reaches MUTATING, and dispatches while the first action is still running.

### Impact and existing mitigations

Two response actions can overlap and the durable ledger can claim the first was
APPLIED before its runner returned or verified anything. The original owner
then fails its own terminal write and reports only a local recovery-required
record while the durable row remains falsely APPLIED. This requires direct
in-process access to the core transaction API; no external route or
attacker-controlled product input currently invokes it, and arbitrary admitted
in-process code already shares the suite token. Those constraints materially
limit exploitability and severity, but the central no-second-dispatch invariant
is not self-enforcing against another module or an accidental caller.

### Exact inert reproduction

An inert action paused after transaction 1 durably reached MUTATING. A competing
call executed:

```python
store.transition_transaction(
    transaction_id,
    expected_states=("MUTATING",),
    state="APPLIED",
    record={"forced_terminal": True},
)
```

A normal second `apply_remediation()` then reached its own action body. Before
either fixture was released, `dispatches == 2` and the durable states were
`[APPLIED, MUTATING]`. After both returned, both durable rows were APPLIED; the
first runner reported `recovery_required` because its legitimate terminal
transition lost the state race. No external or host effect was performed.

### Recommendation

Make PREPARED creation return an opaque, cryptographically random owner
capability and store only its digest. Require that capability on every ordinary
transition and enforce the exact graph `PREPARED -> MUTATING ->
APPLIED|ROLLED_BACK|RECOVERY_REQUIRED`; ordinary transitions must never leave a
terminal state or clear RECOVERY_REQUIRED. Keep reconciliation on its separate
claim capability and atomic finish path. Prefer a runner-owned transaction
object that does not expose the raw state-transition primitive to modules. Add
a synchronized competing-transition regression proving that an unowned or
wrong-owner call cannot terminalize live work and that only one action body is
entered.

### Final response-custody controls that survived

- Ordinary second batches cannot seize or compensate live PREPARED/MUTATING
  rows; without the separate transition-API misuse above, one dispatch remains
  enforced across same-path connections.
- Two explicit reconciliation calls execute exactly one compensation. A crash
  after the winner claims leaves durable RECONCILING, blocks a second claim,
  and blocks all later preparation.
- Retained-record mutation fails the SHA-256 finish check and preserves the
  claim. An injected receipt-insert failure atomically rolled back the terminal
  update, retained RECONCILING, and wrote zero receipts.
- NTFS hard links fail on link count, reparse/8.3 aliases fail canonical proof,
  trailing-dot/space names resolve to the one canonical path, non-fixed/UNC
  roots fail, and Windows denied main-file and parent identity swaps while the
  SQLite handles were open.
- A crashed PREPARED, MUTATING, or RECONCILING transaction can cause a permanent
  conservative lockout until separately governed repair. That is an
  availability/recovery limitation, but these tests found no automatic second
  dispatch through it.
- The final focused checked-in response gate passed **18/18**.

## Independent runtime/authentication post-remediation re-attack

This read-only review used temporary baseline files, hostile bounded JSON,
in-memory process fixtures, slow local scan functions, and source-provenance
forgeries. It did not inspect a registered authentication component, access a
credential, mutate a host control, contact a network service, or write product
state.

## C26-R3-B06 — A crashed authentication-baseline enrollment leaves a permanent stale lockout

- **Severity:** LOW
- **Status:** OPEN
- **Component:** `src/angerona/core/windows_auth_extensions.py:1113-1132`

### Description

Trusted enrollment serializes through a create-exclusive
`.windows_auth_extensions.json.enrollment.lock` file. The lock contains only a
PID string, is removed only by the creating process's `finally` block, and has
no operating-system lock handle, process-start identity, owner proof, expiry,
or separately governed stale-owner recovery. A crash, forced termination, or
power loss after creation therefore leaves an ordinary regular file that every
future enrollment treats as an active owner forever.

### Impact and existing mitigations

The host remains fail-closed and visible: observation continues against the
authenticated provisional baseline, drift is still reported, health remains
below complete, and no stale file can manufacture trusted state. The protected
data-root ACL also makes malicious lock creation harder. The impact is a
persistent availability/reliability failure in the operator's explicit trust
workflow, reachable naturally through a crash in a narrow window or by an actor
that already has write access to that protected baseline directory.

### Exact inert reproduction

A complete synthetic snapshot was recorded to a temporary directory as a valid
provisional baseline. A regular lock file containing an inert nonexistent PID
was then placed at the exact enrollment-lock path. Two later
`establish_trusted(..., approved=True)` calls both returned `another baseline
enrollment is active`; a following observation remained `provisional`. There
is no code path that inspects or recovers the stale owner. The temporary tree
was removed and no production baseline was touched.

### Recommendation

Prefer an operating-system-owned exclusive file lock or no-share handle whose
ownership is released automatically when the process exits. Retain the
protected-root, no-link, and exact-object checks. If a persistent record is
needed, bind it to exact process identity and process start time, and reclaim it
only after independently proving that owner dead; provide a separately reviewed
recovery path. Add live-owner, crash, stale-record, and two-enroller schedules.

### B01-B05 closure and surviving boundaries

- Invalid, unknown, partial, missing-owner, missing-ACL, and missing-signer
  component evidence is non-enrollable. The production provider deliberately
  remains partial until a real handle-bound signature verifier is supplied.
- Duplicate-key, 400-digit integer, unbounded exponent, non-finite constant,
  excessive-depth, excessive-node, excessive-field, oversized-string, and
  invalid-UTF-8 baseline documents all became bounded `tampered` results rather
  than escaping the observer.
- All five real resilience wrappers passed under the isolated child boundary.
  The environment/cwd/bootstrap/output-custody regressions passed, and the
  post-run process inventory found no test-owned survivor.
- Slow direct reads and YARA calls were discarded and reported
  `limited/timed_out`, never `completed`. The limit remains honestly
  cooperative: a kernel or extension call that never returns can retain the
  worker until process-level custody is added.
- Forged filenames, mutable module registration, and a mismatched cached source
  digest produced no trusted red-line highlight. Exact highlighting remains a
  source-checkout facility; packaged builds honestly withhold source paths.
- Same-host HMAC rollback/freshness is still the disclosed independent-custody
  dependency `C23-R2-01`, not a newly re-filed issue. An admitted malicious
  in-process extension also remains governed by the existing isolation residual.

Re-audit gate: **77 passed, 2 expected platform skips** across the focused and
adjacent checked-in tests; **5/5** real resilience wrappers passed; **9/9**
hostile baseline families returned `tampered`; and the exact stale-lock schedule
reproduced **2/2** persistent enrollment refusals.

## Final publication-boundary post-remediation re-attack

This independent pass reviewed only
`tools/verify_published_readme_assets.py`,
`tools/publish_github_update.py`, and their focused tests. It used trusted
PowerShell introspection, process-local environment sentinels, one temporary
hard-link fixture, and read-only Git configuration queries. It did not publish,
push, fetch, request a GitHub asset, execute an untrusted module, or modify
product code or host security state.

## C26-R3-C07 — Minimal PowerShell launch reconstructs a user-writable module search path

- **Severity:** MEDIUM
- **Status:** OPEN
- **Component:** `tools/verify_published_readme_assets.py:226-247`

### Description

The repaired fallback correctly creates a four-entry child environment and
does not copy the caller's `PSModulePath`. For Windows PowerShell, however,
absence is not equivalent to disabled module discovery. At startup it rebuilds
`PSModulePath` from the CurrentUser, AllUsers, and `$PSHOME` module locations.
The CurrentUser location precedes the OS module location. The fixed command then
calls unqualified `Invoke-WebRequest`; that cmdlet is not initially loaded and
PowerShell module autoload resolves it through the reconstructed search path.

An actor that can write the publisher user's Documents module directory can
therefore supply a higher-version or first-discovered
`Microsoft.PowerShell.Utility` module exporting `Invoke-WebRequest`. `-NoProfile`
does not disable module autoload. Its code would run with the publisher token
before the child response framing, output file, or post-launch PowerShell-file
identity checks are evaluated.

Microsoft's documented behavior confirms both parts of the boundary: when
`PSModulePath` is absent Windows PowerShell combines CurrentUser, AllUsers, and
`$PSHOME`, and an unloaded command is auto-imported from the discovered module
set. See
<https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath?view=powershell-5.1>
and
<https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_command_precedence?view=powershell-7.5>.

### Impact and existing mitigations

The fallback can execute same-user module code, fabricate its three-line proof,
alter the pathname output, or tamper with publisher-visible state. This is
reachable only when the Python HTTPS attempt enters the Windows fallback and
requires write access as the publisher user; it is not evidence that the
current host is compromised. The exact WinAPI-derived executable, fixed
System32 cwd, four-entry environment, `-NoProfile`, strict stdout framing,
canonical final host check, size/content-type checks, and immutable expected
digest are all valuable. They do not constrain PowerShell's reconstructed
module discovery.

### Exact inert reproduction

The exact WinAPI-selected Windows PowerShell was launched with only the same
trusted `SystemRoot` entry used by the fallback and a diagnostic command that
did not import an untrusted fixture. It returned:

```text
C:\Users\<local-user>\Documents\WindowsPowerShell\Modules;...;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
Cmdlet
Microsoft.PowerShell.Utility
C:\Windows\system32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1
```

The current machine resolved the genuine system module because no conflicting
module was installed. The observation proves that the allegedly empty module
boundary still admits the user-writable location; no hostile module was created
or executed.

### Recommendation

Prefer removing the PowerShell fallback. If it must remain, disable automatic
module loading, set a deliberately non-default module path that cannot cause
CurrentUser/AllUsers insertion, import the exact OS-owned Utility module by its
verified absolute manifest/binary identity, and invoke the module-qualified
cmdlet. Revalidate the module and process image identities, owner/ACL, reparse
state, signature/catalog, and signer after use. Add a discovery-only fixture
proving a higher-version CurrentUser module is never imported.

## C26-R3-C08 — Pathname-only fallback output permits link replacement and false content custody

- **Severity:** MEDIUM
- **Status:** OPEN
- **Component:** `tools/verify_published_readme_assets.py:222-224,231,283-302`

### Description

The fallback creates an exclusive temporary file, immediately closes its
descriptor, passes only its pathname to PowerShell, and later calls `stat()` and
`read_bytes()` by pathname. No trusted directory is supplied to `mkstemp`, so
the parent process's temporary-directory selection remains authoritative. No
file identity, link count, reparse state, local-volume state, parent identity,
or no-follow handle is retained or revalidated for the output.

A local process with write access to that temporary directory can remove the
empty file after descriptor close and replace it with a hard-link or reparse
alias. PowerShell follows the replacement when opening `-OutFile`; Python then
accepts and unlinks the replacement pathname. This is a content-custody gap and,
when the publisher can write the link target, a confused-deputy overwrite.

### Impact and existing mitigations

An attacker can hide nonmatching downloaded bytes by swapping in the exact
expected payload, or direct the publisher's network write at another
publisher-writable file. A cross-privilege overwrite additionally depends on
the operating system permitting the attacker to create the alias and on the
target's access rules; normal per-user temporary-directory ACLs reduce that
case. The random exclusive creation prevents pre-creation, the size and PNG
validation bound the accepted payload, the later SHA-256/length comparison
requires exact expected bytes, and the `finally` block removes the pathname.
None proves that the object PowerShell wrote is the object Python read.

### Exact inert reproduction

With `subprocess.run` replaced by a no-process fixture, the fixture removed the
just-created output, hard-linked that pathname to an inert temporary victim,
wrote the repository's known 1,490-byte PNG through the alias, and returned the
otherwise valid three-line proof. The production function returned
`accepted=True, image/png`; the separate victim had been overwritten with the
PNG and remained after the temporary alias was unlinked. All objects were under
a disposable temporary directory and were removed. No executable or network
request ran.

### Recommendation

Use a fixed-local, private directory whose parent handle, ACL, owner, and
reparse state are proven. Retain an exclusive output handle where the downloader
supports it. If a pathname handoff is unavoidable, record stable volume/file
identity and single-link/no-reparse state before launch, reopen no-follow, and
revalidate the parent and object identities before size/read/unlink. Fail closed
on any alias, link-count change, replacement, remote volume, or caller-selected
temporary root. Add deterministic hard-link, symlink/reparse, parent-swap, and
read-between-stat fixtures.

## C26-R3-C09 — Ambient Git and HTTPS transport authority can falsify canonical publication proof

- **Severity:** MEDIUM
- **Status:** OPEN
- **Component:** `tools/publish_github_update.py:32-46,110-129,227-298`;
  `tools/verify_published_readme_assets.py:108-117,170-207`

### Description

The publisher proves the displayed fetch/push URL bytes but every Git process
still resolves the executable name `git` through the inherited process search
environment and receives the complete caller environment and Git configuration.
Git's runtime configuration can independently set an HTTPS proxy, disable TLS
verification, select a CA, or install URL rewriting without changing the
configured `remote.origin.url` line that the exact-origin check expects.

The primary Python asset path likewise calls the process-global `urlopen`
without an explicit opener or SSL context. Python's default `ProxyHandler`
honors `HTTPS_PROXY` and, on Windows, user Internet Settings; its default TLS
paths recognize caller `SSL_CERT_FILE`/`SSL_CERT_DIR`. Thus the Git remote/SHA,
push result, and raw-content proof can all share caller-controlled transport
authority. A controlled proxy/CA can acknowledge a push that never reached
GitHub and serve the expected immutable bytes, while a PATH-selected Git
substitute can fabricate local and remote Git results or execute with the
publisher token.

Official Git documentation states that `GIT_CONFIG_COUNT` environment pairs
override file configuration and that `GIT_SSL_NO_VERIFY` disables HTTPS
certificate verification. Python documents that the default opener installs a
proxy handler from environment or Windows registry settings. See
<https://git-scm.com/docs/git-config/2.49.0.html>,
<https://git-scm.com/docs/git>, and
<https://docs.python.org/3.13/library/urllib.request.html>.

### Impact and existing mitigations

The publisher can report the exact canonical repository, target SHA, main
branch, and byte-identical README assets without independently contacting
GitHub; a Git credential presented through a hostile TLS endpoint may also be
exposed. Exploitation requires authority over the maintainer's invocation
environment, trusted-CA/user proxy state, Git installation search path, or Git
configuration. That is a substantial precondition in the intended
maintainer-run workflow and keeps severity at medium. Exact origin bytes,
credential-free HTTPS URLs, atomic non-force refspecs, immutable Git blobs,
public README/image equality, and final local-clean checks remain sound only
after the execution and transport authorities are independently fixed.

### Exact inert reproduction

No transport was contacted. A process-local environment supplied two Git
runtime pairs:

```text
http.sslVerify=false
http.proxy=http://127.0.0.1:65534/inert
```

`git config --get-urlmatch` returned both effective values, while
`git remote get-url --all origin` still emitted exactly:

```text
https://github.com/Ag3nt47/AngeronaSuite.git
```

Separately, Python's environment proxy discovery returned the inert
`HTTPS_PROXY`, and `ssl.get_default_verify_paths()` identified
`SSL_CERT_FILE`/`SSL_CERT_DIR` as active override names. The checks performed no
socket operation and removed the process-local Git variables afterward.

### Recommendation

Run the publisher from an isolated launcher and resolve one explicitly trusted,
stable Git executable rather than PATH. Give every Git subprocess a fresh
allowlisted environment; reject Git runtime-config injection, URL rewrite,
proxy, custom CA, TLS-disable, askpass, hook/fsmonitor, external-helper, and
startup controls. Preserve only an explicitly reviewed credential boundary.
Use a private Python opener with `ProxyHandler({})`, a newly created TLS context
whose trust source cannot be changed by environment, strict hostname/certificate
validation, and no process-global opener. If enterprise proxying is required,
make its exact certificate/policy an explicit separately approved input rather
than ambient state. Add inert proxy/CA/config/PATH regressions proving the URL
string and effective connection authority are both pinned.

## C26-R3-C10 — Remote configuration is mutable after the exact-origin gate

- **Severity:** LOW
- **Status:** OPEN
- **Component:** `tools/publish_github_update.py:227-233,245-276,289-298`

### Description

The sole fetch and push URLs are queried once near the beginning. Subsequent
default-branch, fetch, ancestry, and remote-SHA operations use the name
`origin`, causing each Git process to reread repository/global configuration.
The final proof repeats remote refs and local HEAD/worktree state but never
repeats or identity-binds the exact fetch/push URL/configuration. `.git/config`
and included Git configuration are outside `git status`, so the clean-worktree
checks do not detect a concurrent change.

Git URL `insteadOf`/`pushInsteadOf` rules also apply to an explicit URL. A local
writer can therefore wait until both exact URL checks pass, replace the remote
or add a rewrite before fetch/push/final ref queries, and restore it later. The
literal canonical push argument reduces the attack but does not override those
late runtime rewrites. Public asset lookup by commit SHA proves commit-object
availability, not that public `main` names it; if the target commit already
exists under another canonical-repository ref, a redirected final ref proof can
still falsely report main visibility.

### Impact and existing mitigations

This is a tight local same-user race and often also needs the target commit to
already exist publicly (or the separate hostile-transport condition above), so
severity is low. It can nevertheless redirect read-side ancestry/ref evidence
or make a non-main commit appear to have advanced main. Atomic non-force push,
literal refspecs, exact initial fetch/push URL bytes, immutable commit asset
verification, and final HEAD/worktree checks remain strong against ordinary
remote movement; none custody Git configuration for the complete operation.

### Exact inert reproduction

The checked code has only two `_single_remote_url()` calls, both before the
first `_fetch_branch()`, and none after the network or asset checks. A harmless
read-only Git query also confirmed that a command-level `url.*.insteadOf` rule
changes the effective origin reported by Git, while the separate C09 probe
proved transport configuration can change without changing that URL output.
No configuration file was edited and no fetch or push was performed.

### Recommendation

Hold a no-write handle/lock over every repository and included configuration
object for the publication lifetime, or execute network operations from a
minimal immutable configuration snapshot that cannot read local/global/system
or command-environment overrides. Use the captured canonical transport for all
ref/default-branch/fetch/push queries, prohibit URL rewrites, and repeat the raw
fetch/push URL plus configuration identity proof after asset verification.
Bind the final main-ref proof to an independent canonical GitHub endpoint and
the exact target SHA. Add a deterministic mid-operation configuration-swap
fixture and prove the operation fails before any push or success report.

### Final publication controls that survived

- Stable fetch and push configuration accepts only one exact LF-terminated
  `https://github.com/Ag3nt47/AngeronaSuite.git` value. CRLF, trailing bytes,
  whitespace, a second value, case/slash variants, missing `.git`, alternate
  remote names, and the repository-parameter override fail closed.
- The fallback URL, output path, and integer timeout are passed as environment
  data rather than interpolated into PowerShell code. Requested/final schemes,
  hosts, ports, credentials, query, fragment, stdout line count, status,
  content type, and size are bounded. Extra stdout lines fail closed.
- Expected README targets and image bytes come from bounded blobs at the exact
  captured commit; published README bytes and every valid PNG are compared by
  exact length/SHA-256. Worktree edits cannot alter that expected set.
- PowerShell is selected from WinAPI-derived System32, its path remains beneath
  that root, and its basic file identity is compared before/after. This assumes
  the OS-owned System32 directory and files remain trustworthy; it is not a
  defense after privileged replacement of the OS trust anchor.
- Focused checked-in publication/release tests passed **37/37**. Adding the
  documentation-drift test produced **38 passes and one unrelated failure**
  because README still declares 80 modules while current static discovery finds
  81; that integration mismatch is outside this bounded publication re-attack.

## Final response owner/reconciliation re-attack

This final pass used only temporary SQLite databases, inert action objects,
thread barriers, and injected audit failures. It invoked no product response,
host utility, security setting, credential, network request, or publication.

## C26-R3-A07 — Reconciliation finish authority is reconstructible from public inspection data

- **Severity:** LOW
- **Status:** OPEN
- **Component:** `src/angerona/core/remediation_log.py:493-550,552-737`;
  `src/angerona/modules/remediation_actions.py:1705-1923`

### Description

The unique reconciliation row prevents two callers of
`claim_reconciliation()` from both executing compensation, but the authority
used by `finish_reconciliation()` is not an opaque capability. Inspection
returns the sequential `reconciliation_claim_id` and the complete retained
record. The other required value is an unkeyed SHA-256 of the canonical retained
record JSON, which any caller can recompute. `finish_reconciliation()` then
accepts caller-selected terminal state, replacement record, action title,
outcome, verification flag, and host-level flag.

A second in-process caller with the public remediation-log reference can
therefore reconstruct the claim tuple while the legitimate winner is inside
external compensation, forge `ROLLED_BACK` or `APPLIED` plus an authenticated
receipt, delete the real claim, and clear the persistent circuit. A normal batch
can then dispatch while the legitimate compensator is still running. The
winner's later atomic finish correctly fails because its claim is gone, but the
forged terminal row has already authorized the overlap.

### Impact and existing mitigations

This reopens the response/compensation interleaving that A04 intended to close:
the durable ledger can assert verified rollback, and a second response can
start, before the actual rollback returns. It also lets the forged receipt omit
or misstate the retained response record. Exploitation requires direct
in-process access to the core store API; no external product route currently
exposes it, and arbitrary admitted code already shares the suite token. The
protected single-path database, exact retained-record digest check, SQLite
single-claimer row, and atomic terminal-plus-receipt commit all remain useful
against ordinary callers and storage races. Those constraints make this LOW,
matching the A06 in-process boundary rather than an external privilege gain.

### Exact inert reproduction

An inert reversible action was placed in `RECOVERY_REQUIRED`. Its legitimate
reconciler acquired the claim and paused inside a no-op rollback. A competing
caller read `transaction()`, recomputed the exact SHA-256 from the returned
record, and called `finish_reconciliation()` with the visible claim ID. The call
committed `ROLLED_BACK`, created a proof receipt, and deleted the real claim. A
normal second batch then returned `applied=1` while the first rollback remained
paused. After release, the legitimate reconciler failed with
`reconciliation claim is unavailable`; the forged first row remained terminal.
No host effect was performed.

### Recommendation

Return an exact-type, non-serializable 256-bit reconciliation-owner capability
to the sole claim winner and store only its separately domain-separated digest.
Require that capability, transaction ID, and retained-record digest for finish;
retire it only after the atomic terminal-plus-receipt commit. Inspection may
show that recovery is active but must not expose finish authority. Internalize
the permitted finish outcomes so callers cannot freely choose state, outcome,
verification, host-level metadata, or an unrelated replacement record. Preserve
the current fail-closed crashed-claim behavior and add the synchronized forged-
finish schedule as a regression.

## C26-R3-A08 — Ordinary terminal state and its proof receipt commit separately

- **Severity:** LOW
- **Status:** OPEN
- **Component:** `src/angerona/core/remediation_log.py:430-483,769-840`;
  `src/angerona/modules/remediation_actions.py:1403-1418,1572-1701`

### Description

Ordinary response completion first commits `APPLIED`, `ROLLED_BACK`, or
`RECOVERY_REQUIRED` through `transition_transaction()`. For an applied or
rolled-back terminal it also clears the owner digest and retires the capability.
Only afterward does `_audit()` call the separate receipt ledger, and `_audit()`
suppresses every exception. Consequently a receipt-generation/insert failure,
disk error, or injected audit failure cannot roll back terminalization or open a
circuit.

### Impact and existing mitigations

A verified privileged action can be reported as applied and authorize later
responses while being completely absent from the authenticated remediation
ledger. The transaction table still retains a truthful terminal record until
ordinary pruning, so this does not by itself recreate unknown host state or a
double dispatch. Its impact is loss of audit/accountability and a false
"one receipt per response" expectation, hence LOW severity. Reconciliation
already performs terminal update, proof creation, receipt insertion, and claim
release in one SQLite transaction; the gap is limited to ordinary completion.

### Exact inert reproduction

An inert action durably passed PREPARED and MUTATING and verified successfully.
Its store's `log()` call was replaced with an injected exception. The runner
returned `applied=1`, the durable transaction was `APPLIED`, the returned record
had no `proof_receipt`, and `recent(100)` contained zero audit rows. Restoring
the audit method allowed a second inert batch to return `applied=1`. No host
mutation occurred.

### Recommendation

Replace the separate ordinary terminal transition plus best-effort audit with
one owner-capability-gated SQLite operation that validates the fixed predecessor,
updates the transaction, creates/inserts its bound receipt, clears the owner,
and commits atomically. If receipt creation or insertion fails, roll back the
terminal database update, leave the durable circuit unresolved, and return a
fail-visible custody error. Add APPLIED, ROLLED_BACK, and RECOVERY_REQUIRED
receipt-failure regressions and prove no later action dispatches until a governed
finalization or recovery succeeds.

### Owner-capability controls that survived

- The owner secret is 256 random bits and SQLite retains only a
  domain-separated SHA-256 digest. Raw numeric IDs, wrong/cross-transaction
  owners, skipped transitions, and arbitrary states fail closed.
- `copy.copy`, `copy.deepcopy`, and pickle serialization raise; string/JSON
  logging is redacted; object equality is identity-based. Terminal retirement
  clears the stored digest and stale reuse fails.
- Same-path connections still serialize PREPARED creation, multi-link database
  aliases fail custody, terminal pruning excludes unresolved rows, and process
  restart leaves lost PREPARED/MUTATING ownership conservatively locked.
- The focused checked-in response/remediation gate passed **36/36**. The two
  exact inert reproductions above independently confirmed A07 and A08.

## C26-R3-B07 — Baseline path aliases split enrollment authority and fork trusted state

- **Severity:** LOW
- **Status:** OPEN
- **Component:** `src/angerona/core/windows_auth_extensions.py:999-1012,1014-1042,1181-1208,1246-1268`

### Description

The enrollment rendezvous is unique only for the spelling of `self.path`:
`_exclusive_transition()` derives `.<baseline-name>.enrollment.lock`. The
baseline loader rejects a reparse target and bounds regular-file size, but it
does not require the baseline itself to have a single link or bind the lock to
the opened baseline's stable file identity. Two different NTFS hard-link names
for one authenticated provisional baseline therefore select two independent
zero-share lock files.

Each caller can pass the same HMAC and stable-snapshot checks. Promotion uses a
pathname `os.replace`, so promoting one link detaches only that name from the
shared provisional inode; the other name still exposes the old valid
provisional baseline and can be promoted independently. This forks one
provisional trust decision into two separately trusted documents rather than
enforcing one transition authority for the underlying object.

The POSIX branch has the related namespace assumption: `flock` is attached to
the opened inode, while the named-inode and parent checks occur only once
before `yield`. A writer able to unlink/recreate the rendezvous or rename and
replace its parent after that check can present a new inode to a second
cooperating enroller. This follows directly from the reviewed path-based code;
the current Windows host had no POSIX runtime, so that variant was not executed.

### Impact and existing mitigations

An attacker cannot manufacture a trusted snapshot with this alone: HMAC, host
binding, evidence completeness, exact provisional signature, stable-snapshot
comparison, and explicit operator approval all remain required. Exploitation
also requires either a caller-selected alias or mutation rights in Angerona's
normally private data directory (Administrators/SYSTEM in the installed
Windows boundary and mode 0700 on POSIX). The default module uses one fixed
baseline pathname. These strong preconditions limit severity to LOW.

The residual impact is loss of the promised one-enrollment transition custody:
multiple approved callers can succeed against aliases of the same provisional
object, produce divergent operator/reason proofs, and leave forked authenticated
state. Namespace replacement on POSIX can likewise split the advisory lock and
turn a single transition into two live authorities.

### Exact inert reproduction

Inside one disposable temporary directory, an eligible snapshot was first
observed as provisional at `auth.json`; `os.link` created `alias.json` for the
same NTFS object (`st_nlink == 2`, `samefile == True`). Two stores were pointed
at those names. A barrier paused both after their initial authenticated load and
inside their separately held transition contexts. Both `establish_trusted()`
calls returned successfully. Both paths then observed `stable`, `samefile`
became false after the two pathname replacements, and the directory contained
two distinct rendezvous names:

```text
entered ['alias.json', 'auth.json'] errors []
states stable stable samefile False
locks ['.alias.json.enrollment.lock', '.auth.json.enrollment.lock']
```

No authentication extension, registry setting, credential, or production
baseline was accessed. The temporary directory and all inert files were
removed.

### Recommendation

Reject an existing baseline unless a no-follow handle proves a fixed-local,
regular, single-link object beneath the retained protected-root/parent identity.
Bind transition authority to that exact baseline identity and one canonical
logical baseline ID, not a caller-controlled basename, and revalidate the
named-path-to-handle and parent identities immediately before and after
promotion. Reject any link-count, reparse, parent, object, or volume change.

For POSIX, do not claim hostile-namespace safety from one advisory inode lock:
anchor operations to retained root/parent descriptors, require the private
directory owner/mode and a supported local filesystem, revalidate the
rendezvous name at every critical boundary, and use a separately reviewed
kernel namespace primitive where unlink/recreate by the same authority is in
scope. Add NTFS baseline-hard-link, POSIX unlink/recreate, parent-swap, and
network-filesystem negative regressions proving a second caller cannot enter or
promote.

### Enrollment-lock controls that survived

- **C26-R3-B06 is verified fixed for exact-path use.** A real child crash after
  holding the lock released Windows kernel authority, and later enrollment
  succeeded. Separate crashes immediately after truncation and immediately
  after writing left zero/one-byte stale metadata; both reacquired and
  normalized successfully.
- Two real processes using the same path admitted one owner and rejected the
  other. While the Windows zero-share handle was live, file deletion and parent
  rename/replace failed; a newly created hard-link alias could not acquire a
  second handle to that same lock object.
- Injected `fstat`, `ftruncate`, `write`, `fsync`, and final-path failures all
  released the descriptor; context abandonment followed by CPython GC also
  allowed reacquisition. A 16 MiB stale rendezvous was truncated to one byte in
  bounded time without being read.
- The checked-in focused authentication gate passed **35 tests with one
  expected symlink/reparse privilege skip**. All probes were inert and left no
  child process or temporary file behind.

## C26-R3-A09 — Public recovery claim can self-issue finish authority without compensation proof

- **Severity:** LOW
- **Status:** FIXED
- **Component:** `src/angerona/core/remediation_log.py:833-900,903-1025`;
  `src/angerona/modules/remediation_actions.py:1705-1762,1793-1896`

### Description

The A07 capability is random, exact-type, one-use, and no longer reconstructible
from inspection. Its *issuance* is nevertheless available through the public
`RemediationLog.claim_reconciliation(transaction_id)` method, which requires
only the visible transaction ID. The product coordinator checks the ordinary
`authorized is True` boolean and performs the exact action rollback/postcondition
verification between claim and finish, but that authorization and verified
compensation result are not bound to the store's claim or finish calls.

Consequently, an untrusted or competing ordinary in-process caller with direct
access to the public core API can claim a `RECOVERY_REQUIRED` row first and call
`finish_reconciliation()` with the accepted `reconciled_rolled_back` result.
The store normalizes caller-supplied record fields to `verified=True` and
`rollback_succeeded=True`, commits a valid bound receipt, clears the durable
circuit, and retires the capability without proving that the action rollback or
its verifier ever ran.

### Impact and existing mitigations

This can create a false authenticated rollback receipt, clear unknown host state,
and admit a later response action while compensation has not occurred. Severity
is LOW because exploitation requires direct same-process access to the core
object/API; no GUI, network, CLI, or ordinary external route was found. Arbitrary
introspective code already executing with Angerona's Python token is outside the
process-isolation promise and could attack the database or host more directly;
this finding is limited to an ordinary caller using only the documented public
methods and returned values.

The A07/A08 controls remain substantive: public inspection leaks no claim
authority, only one claimant wins, cross-transaction/stale/owner crossover fails,
record tamper and restart remain fail-closed, and terminal state plus receipt are
atomic under serialization/insert failure. Those controls prevent guessing or
reconstructing someone else's capability, but not self-issuance by the first
public claimant.

### Exact inert reproduction

A disposable SQLite store was advanced with public APIs through `PREPARED`,
`MUTATING`, and `RECOVERY_REQUIRED`. Without constructing an action or calling
any rollback method, the competing caller invoked `claim_reconciliation(id)` and
received the exact `RecoveryCapability`. It then invoked:

```python
store.finish_reconciliation(
    capability,
    result="reconciled_rolled_back",
    record={"asserted_only": True, "rollback_was_called": False},
)
```

The durable state became `ROLLED_BACK`, an authenticated receipt hash was
returned, the committed record said `verified=True` and
`rollback_succeeded=True` while retaining `rollback_was_called=False`, and a new
transaction was immediately admitted as `PREPARED`. No product action, host
control, network endpoint, persistence mechanism, or production database was
used.

### Recommendation

Do not let an ordinary caller self-issue recovery authority from a transaction
ID. Replace the boolean/API split with an exact, one-use governed recovery
authorization bound to the transaction, action identity, retained-record digest,
and intended recovery operation. Keep claim, compensation, exact postcondition
verification, and terminal finish inside one reviewed recovery coordinator; the
store should accept a separately unforgeable verified-compensation witness, not
a caller-selected result token and record. For a boundary that must resist
untrusted in-process extensions, move the response/recovery coordinator and
database authority behind a narrow authenticated helper-process IPC boundary.

### Final convergence controls that survived

- A07's secret type/lifecycle, inspection redaction, single-flight claim,
  retained-record binding, cross-transaction/stale/copy/pickle rejection, crash/
  restart lockout, and ordinary-owner/recovery-owner separation stayed closed.
- A08's ordinary and recovery terminal state/receipt atomicity stayed closed
  under checked-in serialization and receipt-insert failure regressions; no
  receipt-less successful terminal state was reproduced.
- Same-path connection serialization, hard-link/path custody, terminal receipt
  uniqueness, immutable prepared metadata, fixed state graphs, and later-batch
  circuit blocking remained green.
- Focused and adjacent checked-in response/remediation tests passed **39/39**.

## C26-R3-B08 — Promotion check-to-replace race leaves an enrollable provisional alias

- **Severity:** LOW
- **Status:** FIXED
- **Component:** `src/angerona/core/windows_auth_extensions.py:1384-1415,1644-1722`

### Description

The B07 remediation correctly serializes cooperating enrollers through one
data-root-wide operating-system lock and rejects a baseline that is already
multi-link when it is inspected. The provisional baseline handle is not,
however, retained across promotion. `_replace_provisional()` performs its last
baseline/link-count custody check and then calls `os.replace()` by pathname.
A writer of the protected directory can create a hard link to the authenticated
provisional inode after that final check but before the replace. The replace
then installs the trusted temporary object at the original name, while the old
provisional inode survives at the alias with its link count returned to one.

That alias now passes the canonical, no-follow, fixed-local, regular,
single-link checks. Because baseline authentication is not bound to its exact
logical pathname, a later approved `AuthExtensionBaselineStore` for the alias
can authenticate and promote it. The root-wide rendezvous serializes the two
promotions but does not reject the second one after the first releases it.

### Impact and existing mitigations

Two trusted baseline files can still be forked from one reviewed provisional
state, contradicting the one-transition alias-custody invariant. Severity is
LOW: the actor must already be able to mutate Angerona's private baseline
directory during a narrow window and invoke a second approved internal
enrollment against a non-production pathname. The production module constructs
one fixed `baselines/windows_auth_extensions.json` path; no GUI, CLI, IPC, or
network route for choosing an alias was found. HMAC, host binding, explicit
approval, complete-evidence gating, and drift refusal remain effective, and the
actor cannot forge a different snapshot without the HMAC key.

### Exact inert reproduction

A disposable local directory contained one authenticated provisional
`auth.json`. An instrumented `os.replace` schedule created `alias.json` as a
hard link to the old provisional object immediately after the final custody
check and immediately before invoking the real replace. The first approved
enrollment returned successfully. Afterwards:

```text
at injection: link_count=2, samefile(auth.json, alias.json)=True
auth.json after first enrollment: stable
alias.json before second enrollment: provisional, link_count=1
alias.json after second approved enrollment: stable
samefile(auth.json, alias.json)=False
```

Both final files were independently authenticated trusted baselines. The
fixture used only temporary files and the module self-test snapshot; it did not
read credentials, inspect registered authentication extensions, or mutate host
security state.

### Recommendation

Bind every authenticated baseline body to one exact canonical logical slot
(for example a schema-versioned, privacy-minimized relative-path token) and
verify that binding before enrollment and observation. This makes copied or
orphaned provisional bytes invalid under a second name. Also close the
check-to-replace namespace window with an OS-specific handle-bound promotion
primitive or a retained object/parent transaction whose postcondition proves
the old inode did not gain another link before replacement. Add a deterministic
last-check hard-link regression and a byte-copy alias regression; both must
produce zero second trusted enrollments.

### Authentication convergence controls that survived

- B07's constant root-wide lock blocked real two-process contention for both
  the same existing name and two different missing names; each schedule had one
  live owner and one fail-closed caller.
- Exact-path crash release, exception cleanup, hard-linked-at-open rejection,
  parent/root replacement detection, retained directory/lock handles, and
  fixed-local Windows storage rejection remained closed. UNC and an unmapped
  drive were rejected before enrollment.
- The focused and adjacent authentication gate passed **39 tests with 3
  expected platform/privilege skips**. All additional probes were temporary and
  left no process or persistent object behind.

## Final publication-transport convergence re-attack

This bounded pass rechecked C07-C10 after remediation. The PowerShell and
pathname downloader surfaces remain absent, the private Python opener rejects
ambient proxy/CA/OpenSSL selectors and installs `ProxyHandler({})`, every remote
operation receives the literal canonical HTTPS URL, the local configuration is
policy/fingerprint checked around each network operation, and the focused
publication snapshot suite passed **36/36**. One material residual was found in
the premise used to close C09; no network request was made after that premise
failed on the actual host.

## C26-R3-C11 — HKLM-selected Git is accepted without proving its installation ACL or transport closure

- **Severity:** MEDIUM
- **Status:** OPEN
- **Component:** `tools/publication_transport.py:41-83,107-141,188-230,278-345`

### Description

The new boundary selects `git.exe` and Git Credential Manager beneath the
machine-wide `HKLM\\SOFTWARE\\GitForWindows\\InstallPath`, rejects resolved-path
escape/reparse points, and compares pathname-derived device/inode/size/mtime
before and after each subprocess. It never verifies the owner or discretionary
ACL of the registry-selected installation root, its parents, either selected
executable, or the executables/DLLs Git loads to implement HTTPS. An HKLM value
therefore proves where a machine install was registered, not that ordinary local
principals cannot rewrite it.

This is exploitable on the host under test. HKLM selects `D:\\Git`; read-only
`Get-Acl` inspection showed `NT AUTHORITY\\Authenticated Users: FullControl`
(inherited) on all of these objects:

- `D:\\Git`
- `D:\\Git\\cmd\\git.exe`
- `D:\\Git\\mingw64\\bin\\git-credential-manager.exe`
- `D:\\Git\\mingw64\\libexec\\git-core\\git-remote-https.exe`
- both inspected `libcurl-4.dll` copies under `mingw64\\bin` and
  `mingw64\\libexec\\git-core`

Only `git.exe` and GCM are included in `TrustedGitBoundary.revalidate()`.
`git-remote-https.exe`, libcurl and the remaining runtime/DLL closure are not
bound at all. A persistent replacement made before boundary construction is
accepted as the trusted baseline; a replacement of an unbound HTTPS helper or
DLL is not noticed; and pre/post pathname metadata leaves a check-to-execute
window for a cooperating replacer. The minimal environment and command-level
configuration pins do not protect against code already admitted through that
installation.

### Impact and existing mitigations

Any ordinary authenticated principal able to exercise the demonstrated ACL can
replace the selected Git/GCM/HTTPS runtime, execute code with the publisher's
token, receive the GitHub credential presented to the helper/transport, or
falsify the canonical-ref/push transcript. This breaks the publisher's exact
origin and public-main proof at its process trust root.

Severity is MEDIUM because exploitation requires local write access to the
machine Git installation before or during a maintainer-authorized publication;
the standard fresh environment, literal URL, non-force/atomic refspec, immutable
blob checks, strict TLS settings, and config/worktree rechecks remain valuable
once a genuinely protected transport binary closure is established. No product
source, Git binary, credential, network endpoint, host ACL, or repository state
was changed during this audit.

### Recommendation

Fail closed unless Win32 handle-based security inspection proves the HKLM key,
installation root and relevant parents/files are owned by a trusted system or
administrator identity and grant no write/delete/ownership/ACL authority to
`Users`, `Authenticated Users`, `Everyone`, or the publishing user outside the
explicitly trusted administrator boundary. Retain no-follow, deny-write/delete
handles for the complete operation and launch the exact handle-bound image (or
use an equivalently sealed publisher environment) to close pathname
replacement.

Bind and revalidate the complete network execution closure, not only
`cmd\\git.exe`: the real Git program, `git-remote-https`, Git Credential Manager,
shell used for helper execution, and loaded transport/runtime DLLs. Verify
expected vendor signatures/digests where available. Also shell-quote the
absolute GCM command as one argument: Git's own credential documentation states
that the helper string is executed by a shell, while the current `as_posix()`
value is unquoted and a normal `C:\\Program Files\\Git` installation contains
whitespace. Add real ACL fixtures for an untrusted machine install, sidecar/DLL
replacement, pre-launch replacement, whitespace/metacharacter helper roots, and
a standard protected Program Files installation.

### Publication controls that survived

- C07/C08 remain closed: there is no PowerShell module or temporary-path
  downloader boundary.
- C10 remains closed against stable and tested local configuration mutation:
  exact raw origin framing, literal canonical URL use, config fingerprint,
  HEAD, and cleanliness checks remain present around every network operation.
- C09's ambient environment/configuration portion remains closed, but C11 means
  its claimed trusted executable/HTTPS process premise is not yet established.
- Focused checked-in publication snapshot/transport tests passed **36/36**.
  Live GitHub access was deliberately not repeated after the selected local Git
  installation failed the read-only ACL trust check.

## Final C26-R3-A09 convergence re-attack

No new response-recovery finding was reproduced within the documented public
API boundary. Ordinary callers have no public claim or finish method and cannot
submit a caller-selected rollback assertion. The private claim, proof, and
finish path revalidates the exact coordinator object and digest, exact
`RemediationLog` instance, exact action-registry snapshot, winning one-use
capability, action key, retained-record digest, and store-issued proof. The
public coordinator invokes the registered rollback and exact verifier once;
losing or later callers perform no compensation. Missing controls, rollback or
verifier failure, process loss after claim, retained-record tamper, and receipt
commit failure all leave the durable circuit unresolved or `RECONCILING`.

A07 inspection/capability secrecy and A08 ordinary terminal-plus-receipt
atomicity also remained closed. The independently rerun focused response gate
passed **24/24** (`test_cycle26_round3_response_receipt_authority.py` plus
`test_cycle26_round3_response_custody.py`); Ruff and byte-compilation passed for
both product files and both test files. All exercised actions were inert and
temporary. No host mutation, network request, publication, or product edit was
performed. As already disclosed, arbitrary introspective code executing inside
Angerona's Python process is outside this in-process least-authority boundary
and would require authenticated process isolation to treat as hostile.

## C26-R3-B09 — Registry loss reopens slot selection and creates replayable trusted forks

- **Severity:** LOW
- **Status:** OPEN
- **Component:** `src/angerona/core/windows_auth_extensions.py:1279-1466,2307-2329`

### Description

Schema-v2 body authentication, exact canonical root/name binding, and the
fixed-name HMAC-authenticated slot registry all verify correctly while that
registry exists. The loss case does not preserve the one-slot invariant,
however. `_assert_trusted_slot_unclaimed()` treats an absent registry as an
unclaimed root without checking whether a trusted authenticated baseline for a
different slot already remains. `establish_trusted()` can therefore create and
register a second approved filename after the first registry is deleted.

Both baseline bodies and both saved registry documents remain genuinely HMAC
authenticated for the same protected root and their respective exact names.
After the second enrollment, a directory writer can replay the saved registry
for slot A or slot B to select which divergent trusted snapshot reports
`stable`. No HMAC forgery, link race, path normalization ambiguity, or root move
is required.

### Impact and existing mitigations

This restores the trusted-state fork B08 was intended to eliminate. Once two
different complete snapshots have received approved enrollment during the loss
schedule, replay of an old authentic registry can hide the other baseline and
toggle the monitor's accepted authentication-extension state.

Severity is LOW because the actor must be able to mutate Angerona's protected
baseline directory, retain an authentic registry document, and cause a second
explicitly approved internal enrollment under an alternate pathname. The
production module uses one fixed baseline pathname and no GUI, CLI, IPC, or
network route for selecting another filename was found. Ordinary registry
corruption, a missing registry, hard-linked objects, byte copies under another
name, and moved-root copies otherwise fail closed; the schema-v2 HMAC and
promotion handle/link postconditions remain effective.

### Exact inert reproduction

In a disposable temporary directory, the audit enrolled complete snapshot A at
`a.json`, saved registry A, deleted the live registry, and confirmed A reported
`tampered`. It then explicitly enrolled divergent complete snapshot B at
`b.json` and saved registry B. Replacing only the live registry bytes produced:

```text
registry A replay: a.json=stable, b.json=tampered
registry B replay: a.json=tampered, b.json=stable
```

The fixture used only module self-test snapshots and temporary files. It did
not inspect host authentication extensions, credentials, security settings, or
network state.

### Recommendation

Do not let registry absence reopen logical-slot selection. Bind this capability
to one immutable/policy-authenticated expected relative slot before enrollment,
and permit interrupted-registration recovery only when the existing trusted
body matches that exact expected slot. An alternate pathname must be rejected
before a trusted file is created even when the registry is missing. If runtime
slot selection must remain supported, place the root-wide selection/generation
under independent rollback-resistant custody; another replayable file in the
same writer-controlled root is insufficient.

Add a deterministic regression for: enroll A, save/delete registry A, attempt
approved B, and replay every retained registry document. B must never become a
trusted file and no registry replay may make two divergent logical slots
alternately stable. Preserve the current same-slot interrupted-commit recovery.

### B08 controls that survived convergence

- Exact schema-v2 HMAC and canonical root/name/slot binding rejected byte-copy
  aliases and moved-root copies.
- Missing, malformed, HMAC-modified, hard-linked, or multi-link registry state
  failed closed during ordinary observation.
- The late hard-link promotion regression retained the provisional handle,
  detected the retired link, removed the promoted name, and left no trusted
  registration.
- Same-slot interrupted registration recovery remained explicit and successful.
- Focused and adjacent authentication tests passed **38/38 with 3 expected
  platform skips**; the module self-test passed. The additional convergence
  probes were inert and temporary.

### Remediation closure

The baseline store now has one deterministic policy slot per canonical data
root: `baselines/windows_auth_extensions.json`. Construction rejects every
alternate relative filename or directory before observation, creation, or
enrollment. Root/name/schema binding remains inside the authenticated body and
the fixed path is revalidated during custody checks.

Deleting the authenticated slot registry no longer reopens path selection. An
existing trusted body can restore that registry only at the one fixed slot and
only when its HMAC, canonical root/name/schema token, and reviewed current
snapshot all match. Divergent evidence cannot use recovery to replace it. A
saved authentic registry can still be replayed as local bytes, but because it
names the same deterministic slot it cannot select a second divergent trusted
baseline.

The exact loss/replay schedule, alternate-path rejection, fixed-slot recovery,
root move/copy rejection, and all prior handle/link/promotion schedules passed.
Freshness remains explicitly based on the local software clock and HMAC; this
change does **not** claim an external high-water or rollback-resistant witness.

### Independent terminal convergence re-audit

No new B09 bypass was reproduced. Source inspection confirmed that construction
canonicalizes both the protected root and requested baseline before accepting
only `<data_root>/baselines/windows_auth_extensions.json`; normalized spellings
of that same slot converge, while alternate filenames/directories fail before
file creation. The authenticated body binds the exact canonical root, normalized
relative name, and schema, and the authenticated registry can name only the
resulting fixed-slot token. Consequently, replaying a retained registry cannot
select a divergent pathname.

Registry-loss recovery remained limited to an already trusted, HMAC-valid body
at that slot whose security evidence compares stable with the newly reviewed
snapshot. Divergent evidence was rejected, while the deliberately interrupted
same-slot registration recovered. Byte copies and moved/copied roots remained
tampered because their root/name token changed. Same-canonical-path rollback
after a process restart remains outside this control's stated assurance: the
implementation explicitly has no independent monotonic or external high-water
witness and does not claim one.

The independently rerun authentication gate passed **46/46 with 3 expected
platform skips**. The seven exact B09 path/replay/recovery parametrizations and
the module self-test passed separately; Ruff and byte-compilation passed for the
affected product and regression files. All probes were inert and temporary. No
host authentication setting, credential, network endpoint, product source,
publication, commit, or push was changed.

## Final C11 sealed-runtime convergence re-attack

The staged-tree controls added for C11 were independently re-read against the
profile parser, publisher lifecycle, transport environment, and cleanup path.
The closed file set, per-file hashes, retained source/stage handles, exact
executable/GCM paths, helper quoting, staged search path, explicit System32
boundary, and pre/post runtime revalidation are meaningful once the reviewed
profile itself is trusted. No new path traversal, case-collision, reparse,
hard-link, alternate-stream, helper-quoting, ambient proxy/configuration, or
literal-origin bypass was confirmed against that already authenticated profile.

One missing trust anchor remains. This pass used source inspection and read-only
ACL inspection only; it did not stage the 191 MB runtime again, execute Git or
GCM, access a credential, contact GitHub, fetch, push, publish, or modify a host
ACL, repository file, or Git installation.

## C26-R3-C12 — Self-authenticating runtime profile is read before repository custody

- **Severity:** MEDIUM
- **Status:** FIXED
- **Component:** `tools/windows_publication_runtime.py:27,133-151,1107`;
  `tools/publish_github_update.py:434-492`;
  `tools/publication_git_runtime_profile.json`

### Description

The reviewed runtime profile contains the expected per-file digests and tree
digest, but the expected digest is stored only inside that same mutable JSON
document. `load_runtime_profile()` proves internal consistency after an ordinary
pathname `stat/read/stat`; it does not compare the profile bytes or parsed tree
digest with an independently compiled expected value, reject a reparse or
multi-link profile object, or retain a no-write/delete handle to the exact
profile object.

The lifecycle makes this exploitable rather than only a parser-hardening issue.
`publish()` resolves and stages the Git boundary before `_publish_with_trusted_git()`
captures HEAD and checks worktree cleanliness. The original profile pathname is
not checked again after staging. A same-token local actor can therefore present
an internally consistent alternate profile together with matching bytes in the
writable machine Git tree, let those bytes be copied into the private runtime,
and restore the tracked profile before the later clean-worktree gate. The
publisher will then carefully seal and execute the actor-selected runtime.

Read-only host ACL inspection confirmed that the checked-out profile and its
`tools` directory are owned by the publishing account and grant that account
`Modify`; the prior C11 audit already established ordinary write authority over
the selected `D:\\Git` source tree. This schedule does not require modification
of the already loaded publisher Python code or process memory.

### Impact and existing mitigations

The substituted runtime can execute with the publisher token, receive the GCM
credential flow, and falsify local/remote Git results while all per-file hashes,
tree closure, private staging, and later clean/status/configuration checks pass.
Severity is MEDIUM because exploitation requires local write authority to both
the profile pathname and source Git tree plus timing before boundary capture.

The closed schema, bounded path/file counts, exact per-file hashes, source
deny-write/delete handles, protected staged tree, minimal environment, literal
canonical origin, and repeated repository/configuration checks remain useful
after profile authority is established. Pre-start replacement of the publisher
code itself and live process-memory compromise remain outside this in-process
publication boundary; C12 does not claim to solve those stronger threats.

### Recommendation

Compile an exact expected SHA-256 of the approved profile bytes and its expected
tree digest into the already loaded runtime module. Open the profile once through
a stable no-follow, no-write/delete handle; reject reparse and multi-link objects;
hash the bytes from that handle before parsing; and require both compiled
constants to match. Retain the parsed immutable profile for the complete stage
operation and never reopen the pathname.

Keep boundary construction first so every later HEAD/status/configuration proof
still uses the staged Git, but add a deterministic fixture that substitutes a
different internally valid profile before the clean-worktree check and proves
zero process launch. Also regress duplicate JSON keys, Windows non-canonical
names/ADS/8.3 aliases, profile replacement during read, and a normal exact
profile. Document explicitly that trusted publisher code at process start is the
root of this compiled-profile authority.

### Remediation closure

The already-loaded runtime module now pins the exact 54,008-byte LF profile
SHA-256 plus its expected Git version/build, directory/file counts, total bytes,
and tree SHA-256 independently of the JSON. Production admits only the compiled
absolute fixed-local path, reads the file once through retained no-follow
file/parent handles that deny write/delete sharing, rejects non-regular,
multi-link, reparse, wrong-volume, alternate-name, and identity-changing
objects, and revalidates the seal through staging without reopening the profile.
Every Git source identity is checked again before return, and even the
version/build probe runs only through the completed `TrustedGitBoundary` before
publication HEAD/status/configuration/remote logic.

The focused C12 gate passed 9/9, including exact bytes, mutation, internally
consistent addition, duplicate keys, constant mismatch, alternate path,
write/replace/link read races, lightweight end-of-stage seal checks, zero-launch
substitution, and boundary ordering. Changed-file byte-compilation and Ruff
passed. Trusted publisher Python already loaded at process start remains the
explicit root of authority; pre-start code replacement and live process-memory
compromise are outside this same-process claim. No credential, network request,
fetch, push, publication, or host setting was touched.

## Independent terminal C12 convergence re-attack

No new publication-profile bypass was confirmed. The checked-out profile is
exactly **54,008 bytes**, contains no CR/CRLF bytes, and hashes to the compiled
`3d77e4ffa00d2236836e2a90a292cdbf7b3884933771a4ad14176231a8efbfc0`.
Its Git version/build, 8-directory/312-file counts, 191,289,767-byte aggregate,
and tree digest agree with the independent loaded-code constants. The profile
is also explicitly `eol=lf` in `.gitattributes`, so checkout line-ending drift
fails closed instead of silently selecting another document.

Static call-path reinspection confirmed that production accepts only the
compiled absolute profile path, rejects ADS/alternate path tokens before open,
uses retained no-follow file/parent handles with no write/delete sharing,
requires a regular fixed-volume single-link non-reparse object and exact final
handle name, reads the bounded object once, authenticates SHA-256 before JSON
interpretation, and revalidates the same identities through the end of staging.
Duplicate keys remain rejected by the closed object-pairs parser, while any
other parser-edge byte change fails the compiled size/SHA gate first. Every Git
source identity is rechecked before the sealed runtime returns, and `publish()`
constructs and binds `TrustedGitBoundary` before repository HEAD, status,
configuration, or remote Git logic.

The exact focused test file was started but stopped after roughly 90 seconds
without output when the already documented host AV/disk pressure again delayed
ordinary pytest imports; it produced no pass/fail result and is not counted as
a new gate. The prior completed **9/9** result remains the regression evidence,
and this terminal pass used static and byte-level validation only. No staging,
Git/GCM execution, credential access, network request, fetch, push, publication,
host mutation, or product-source edit occurred. Trusted publisher code at
process start and live process-memory compromise remain the explicit boundary.

## C26-R3-C13 — Blanket multi-link rejection blocks the reviewed Git runtime

- **Severity:** LOW
- **Status:** FIXED
- **Component:** `tools/windows_publication_runtime.py:115,686-789,1266-1410,1636-1847`;
  `tests/test_cycle26_publication_snapshot.py:46-63,644-751`

### Description

The reviewed Git-for-Windows installation contains one legitimate NTFS file
identity exposed through the two profiled names `cmd/git.exe` and
`cmd/git-lfs.exe`. Both entries are exactly 46,920 bytes and carry the same
reviewed SHA-256. `stage_pinned_runtime()` nevertheless rejected every source
whose link count was not one, so the exact reviewed host runtime failed before
publication snapshot and configuration-policy assertions could run.

This was an availability and assurance-integration defect, not an execution
bypass: the prior behavior failed closed and launched nothing. Loosening the
check to accept any multi-link source would, however, allow an unprofiled or
outside alias to survive source-tree closure and would weaken byte custody.

### Recommendation

Group source paths by stable Windows volume/file ID. For a multi-link identity,
enumerate its complete hard-link names with Win32 handle APIs and require every
canonical alias to remain non-reparse, beneath the pinned installation root,
and present in the exact profile with identical size and digest. Retain one
no-write/delete source handle per identity, read that identity once, stage an
independent copy at every reviewed name, and repeat identity and alias-set
proofs before and after staging. Keep single-link objects on the stricter
single-name path.

### Remediation closure

Source acquisition now groups exact `(volume serial, file ID)` identities and
retains one deny-write/delete handle per group. Stable single-link identities
must retain their exact final handle name. Multi-link identities use
`FindFirstFileNameW`/`FindNextFileNameW` to prove the complete canonical alias
set; an outside alias, in-root unprofiled alias, reparse/noncanonical name,
identity mismatch, profile size/digest disagreement, link-count change, or
alias swap fails closed. Each accepted identity is read once, while every
reviewed name is materialized as a separate single-link staged file and is
rehash/seal checked under the existing private DACL.

Five inert topology regressions passed: exact profiled pair, outside alias,
unprofiled alias, metadata mismatch, and denied-or-detected alias swap. Six
adjacent profile/stage checks also passed. A direct read-only Win32 probe of
`D:\Git\cmd\git.exe` proved link count two and exactly the two reviewed names.
The one consolidated real-runtime rerun of the three formerly blocked
assertions was stopped at the agreed eight-minute ceiling while the known host
AV/I/O pressure left pytest CPU-flat before private staging; it produced no
test result, no launch/publication/network action, no residual process, and no
`angerona-publish-*` directory. Byte-compilation and Ruff passed after the
final single-link fast path. The terminal full-stage rerun remains part of the
cooled-down final release gate and is not claimed here as passed.

### Terminal C13 adversarial convergence

No concrete C13 bypass was found in the terminal bounded review. Win32 names
are enumerated to the retained handle's exact link count, normalized only after
rejecting ADS, traversal, duplicate-case, and non-volume-relative forms, then
reopened no-follow and matched to the same volume/file ID. Outside and
unprofiled aliases fail closed. Short-name/case aliases do not evade the
deny-write/delete retained object handle, while reparse components are rejected
by tree inspection and exact final-handle-name checks. The complete alias set
and file identities are checked before and after copy; each multi-link object
is read once into independently created destinations, and every destination is
then required to be single-link and independently rehashed.

The exact five small topology tests were started but produced no output under
the documented host I/O pressure after about 90 seconds, so the run was
interrupted and is not claimed as a pass. Process inspection afterward found
zero Python/pytest survivors. No 191 MB stage, Git/GCM launch, credential,
network, publication, product edit, or host mutation occurred. The previously
completed **5/5** C13 regression result remains the test evidence.
