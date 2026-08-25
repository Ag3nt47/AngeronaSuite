# Round 6 — Exact-Target Response Red-Team Findings

Audit date: 2026-08-25
Scope: `core/response_contract.py`, Adversary Combat, the newly authorized
semantic response producers, raw FIM/network/process/Sysmon producers, and their
direct tests. This was a read-only product audit; no product code or host policy
was changed.

Disposition: **NO RELEASE BLOCKER REMAINS IN THIS SCOPE**. All High findings and
every Medium unsafe-mutation/outage defect found in the semantic, GUI, helper,
and host-action surfaces were remediated during the audit. R6-03 remains open as
defense-in-depth hardening for a narrow process-handle/path-lease race. No
product code or host policy was changed by the red-team agent.

## R6-01 — Spoofable LSASS/VSS semantic gates retain whole-host outage authority

- **Severity:** HIGH
- **Component:** `src/angerona/core/response_contract.py:123-185`;
  `src/angerona/modules/lsass_guard.py:43-75,114-141`;
  `src/angerona/modules/shadowcopy_guard.py:43-77,116-151`
- **Status:** RESOLVED

### Description

`process_response()` now requires callers to opt into `escalate_host=True`.
Office lineage, RWX memory, cadence-only beacons, and Evidence Lattice findings
therefore have no host authority. Cadence additionally requires threat-intel
corroboration before receiving exact peer/process containment.

The final LSASS gate parses argv roles. Third-party dump utilities can receive
exact-process containment only when `lsass` occupies the target role; output
paths such as `C:\reports\lsass.dmp` no longer count. Host escalation is limited
to the genuine signed System32 `rundll32.exe`, canonical System32 `comsvcs.dll`
in the first DLL/export argument, exact `MiniDump`, and a following live PID
whose process is LSASS.

The recovery gate requires a genuine Authenticode-valid canonical System32
utility and role-aware destructive argv. `vssadmin`, `wmic`, and `wbadmin` must
begin with a reviewed destructive subcommand. `bcdedit` must be exactly
`/set {boot-entry} <reviewed-field> <reviewed-value>`. PowerShell remains
alert-only because token parsing cannot safely prove script semantics.

### Impact

The confirmed basename/substrings outage paths no longer reproduce. Harmless
output filenames, documentation paths, read-only VSS and BCD queries, renamed
images, and PowerShell text examples do not mint host authority.

### Recommendation

Retain the role-aware negative tests and fail-closed path/signature checks. If
additional script hosts or dump utilities are authorized later, require an
equally explicit argv grammar and keep ambiguous script expressions alert-only.

## R6-02 — Ransomware isolation correlates unrelated entropy and rename evidence

- **Severity:** HIGH
- **Component:** `src/angerona/modules/ransomware_heuristics.py:158-176,
  292-311,337-386`; `src/angerona/core/response_contract.py:174-180`;
  `src/angerona/modules/adversary_combat.py:1077-1094`
- **Status:** RESOLVED

### Description

Rename evidence is now stored as `(timestamp, exact_directory)`, rates are
computed independently per normalized directory, and entropy corroboration
requires a recent flagged path whose normalized parent is that same directory.
Uncorroborated rename churn receives deception authority only. The new
cross-directory negative test proves that an entropy hit under one watched root
cannot promote rename activity under another root to host isolation.

### Impact

The confirmed cross-directory composition outage no longer reproduces. The
remaining same-directory correlation is intentionally heuristic, but it combines
twenty conservatively paired ransomware-like renames with time-local entropy in
that affected directory and is not a release blocker under the stated aggressive
Maximum-mode policy.

### Recommendation

Keep the directory-bound negative test. Future hardening can retain per-rename
file identity and require the entropy-bearing path to participate in the rename
lineage, but that is defense-in-depth beyond closure of this finding.

## R6-03 — Process contracts do not retain OS-handle/program-file identity

- **Severity:** MEDIUM
- **Component:** `src/angerona/core/response_contract.py:123-150`;
  `src/angerona/modules/adversary_combat.py:1632-1739,2027-2072`
- **Status:** OPEN

### Description

An `isolate_program` contract binds PID and process creation time but not an
executable path or file identity, even though the resulting Windows Firewall
rule is path-wide and persists after that process exits. Combat now performs a
valuable PID/create-time/executable recheck after firewall mutation and rolls
the rule back on mismatch. It nevertheless retains only a `psutil.Process`
PID wrapper, not an OS handle, and writes subsequent journal phases before
calling `suspend()`/`kill()`. A narrow reuse window therefore remains between
the last identity check and the PID-based mutation. The persistent rule also
applies to any future binary installed at the same path.

### Impact

The target can still drift in a narrow race, and a future benign executable at
a recycled/updater path may remain network-blocked. Exploitation requires
winning PID reuse or later path replacement, so this is defense-in-depth rather
than a current release blocker.

### Recommendation

Open and retain an OS process handle, verify creation time and executable
identity through that handle, and suspend/terminate through the same handle.
If a handle-based action is unavailable, revalidate after all firewall work and
immediately before mutation. Extend `isolate_program` targets and receipts with
canonical executable path plus stable file identity/hash/signer, and use a
bounded lease so a path-wide rule cannot silently outlive its incident target.

## R6-04 — Secure quarantine cannot move watched user files across volumes

- **Severity:** MEDIUM
- **Component:** `src/angerona/modules/adversary_combat.py:489-541,636-645,
  1353-1392`
- **Status:** RESOLVED

### Description

`_WindowsPinnedFileMove._copy_delete_cross_volume()` now copies from the already
pinned source handle into a create-new destination, flushes and hashes the copy,
then deletes the exact retained source handle. Undo applies the same pinned,
digest-bound restore discipline. The move strategy and identities are retained
in the authenticated action record.

### Impact

The confirmed C:-to-D: quarantine failure no longer reproduces in the reviewed
implementation. Cross-volume copy mismatch removes the partial destination and
fails closed.

### Recommendation

Retain the forced cross-volume success/mismatch tests and add a physical
two-volume Windows acceptance run when release infrastructure permits it.

## R6-05 — Failed journal commit could leave a live orphan outside normal Undo

- **Severity:** MEDIUM
- **Component:** `src/angerona/modules/adversary_combat.py:1223-1305,
  1542-1638,1957-2057,2095-2120,2282-2325,2528-2590`
- **Status:** RESOLVED DURING AUDIT

### Description

The journal now attempts an immediate authenticated rollback after a commit
failure and records orphan/undo phases. If compensation fails, Combat trips a
mutation circuit, marks health `RECOVERY REQUIRED`, exposes the authenticated
orphan in action history, and refuses every later action in the same event plus
all future submissions. Exact manual Undo can recover a reversible orphan and
re-arm only after no pending orphan remains. A commit failure following an
irreversible termination also opens the circuit for operator review instead of
silently allowing later mutations.

### Impact

The confirmed double-fault path no longer continues mutation or hides a
reversible orphan. An irreversible action cannot be undone by definition, but
loss of its durable completion receipt now disarms Combat instead of permitting
an unaudited response cascade.

### Recommendation

Retain the commit-failure, failed-compensation, later-event refusal, manual Undo,
and irreversible-commit-failure regressions. Keep circuit re-arm conditional on
successful exact recovery or explicit review of an irreversible result.

## R6-06 — Local-AI posture advice could execute as elevated PowerShell

- **Severity:** HIGH
- **Component:** `src/angerona/modules/posture_hardening.py:723-850,906-930`;
  `src/angerona/gui/main_window.py:2076-2105`;
  `src/angerona/gui/pages.py:1389-1445,4829-4844`
- **Status:** RESOLVED DURING AUDIT

### Description

The broad pass initially confirmed that an Ollama-authored remediation was
screened only by a deny-list and then executed elevated after a truncated review.
Three harmless direct probes demonstrated that arbitrary `Start-Process`, .NET
file-write, and registry-write forms passed that scan. The current tree no
longer has that execution boundary: model output is stored only as an inert
`.advisory.md`, `execute_remediation()` refuses it even with `authorized=True`,
and Direct Native arbitrary PowerShell is disabled. GUI apply paths now invoke
only the deterministic remediation library.

### Impact

A poisoned or compromised local model can no longer turn advisory text into
elevated code through Posture Hardening.

### Recommendation

Keep the negative tests that assert the advisory remains non-executable. Any new
active operation must be a registered typed action with exact preview,
authorization, postcondition, receipt, and rollback.

## R6-07 — Red Team cleanup deletes user files by filename prefix

- **Severity:** MEDIUM
- **Component:** `src/angerona/shark/red_team.py:182-223,363-415,483-516`;
  `tests/test_redteam_runtime_targets.py:207-224`
- **Status:** RESOLVED DURING AUDIT

### Description

The initial broad pass found start/stop/cancel cleanup globbing every
`_redteam_*` path in the operator-selected directory, including Documents,
without content or run provenance. The current tree removes that glob entirely.
Cleanup now deletes only exact in-memory artifacts owned by the engine run, and
the regression test preserves an unrelated `_redteam_notes_for_project.txt`.

### Impact

An ordinary user file can no longer be deleted merely because its name begins
with the drill prefix. Crash orphans are conservatively left for review.

### Recommendation

Retain the name-only lookalike regression. If automatic crash-orphan cleanup is
reintroduced, require an authenticated persistent per-run manifest plus exact
content/file identity; never restore prefix-only authority.

## R6-08 — Manual SOAR suspension bypassed Combat journal and remained resubmittable

- **Severity:** MEDIUM
- **Component:** `src/angerona/gui/pages.py:275,622-850,3651,3728-3750,
  3890-3950`; `src/angerona/modules/adversary_combat.py:928-995,1223-1330`
- **Status:** RESOLVED DURING AUDIT

### Description

The reviewed GUI originally called `psutil.Process.suspend()` directly after
preflight. The current path publishes an exact PID/create-time suspension
contract and Combat owns durable intent, mutation, postcondition, receipt, and
Undo. `SUBMITTED` is terminal to review/resubmission, Combat deduplicates the
exact queue request ID, and the GUI transitions only from a locally verified,
structurally complete Combat receipt bound to that request. Missing receipts
become an explicit terminal timeout directing the operator to Action history.
If Combat cannot admit a request, it atomically releases the dedup claim and
emits a signed request-bound failure receipt rather than poisoning that ID.

### Impact

The direct host-action bypass, duplicate submission window, forged receipt,
permanent receipt-pending state, and queue-admission identity poisoning no
longer reproduce in the reviewed code/tests.

### Recommendation

Retain the forged/incomplete receipt negatives, exact queue-ID deduplication,
queue-saturation failure receipt, terminal `SUBMITTED`/timeout tests, and Combat
action-history/Undo linkage.

## R6-09 — Top Talkers containment used a stale PID and non-enforcing blocklist

- **Severity:** MEDIUM
- **Component:** `src/angerona/gui/top_talkers.py:70-152,326-405,438-500`
- **Status:** RESOLVED DURING AUDIT

### Description

The initial implementation retained only PID/name/peer display data, wrote an
unused local blocklist, and terminated whatever later occupied that PID. The
current tree captures process creation time, executable, and literal peer;
revalidates the same process instance and exact live connection; and submits a
typed process-and-peer response contract to Combat. "Mark reviewed" is explicitly
non-enforcing and the dialog points to Combat action history/Undo.

### Impact

The stale-PID kill and false claim of persistent blocking are closed.

### Recommendation

Retain stale-PID, changed-executable, changed-peer, and malformed-address
negative tests. Only Combat receipts should be presented as completed action.

## R6-10 — Deployment mirror accepted destructive arbitrary destinations

- **Severity:** MEDIUM
- **Component:** `finalize-and-deploy.ps1:18-115,122-145,151-171`;
  `tests/test_finalize_deploy_safety.py:1-84`
- **Status:** RESOLVED DURING AUDIT

### Description

The helper now canonicalizes every path; rejects filesystem roots, the user
profile root, protected operating-system trees, equal/nested source/home/backup
relationships, and existing unowned destinations; preserves an Angerona
ownership marker; runs a `robocopy /MIR /L` preview; and requires the exact typed
phrase `MIRROR ANGERONA` before each real mirror.

### Impact

The confirmed root/profile/existing-unowned deletion paths now fail before a
destination is changed. Non-interactive automation must provide the same exact
authorization phrase.

### Recommendation

Retain root, overlap, unowned-sentinel, marker, and wrong-confirmation negatives;
apply identical controls to Home and Backup.

## R6-11 — Red STOP killed unrelated Python processes by broad ownership rules

- **Severity:** MEDIUM
- **Component:** `src/angerona/gui/main_window.py:65-113,4587-4630`;
  `tools/angerona_process_owner.ps1:1-73`; `kill-all-angerona.bat:14-21`;
  `tests/test_shutdown_process_ownership.py:1-67`
- **Status:** RESOLVED DURING AUDIT

### Description

The GUI and external helper now require the exact suite interpreter together
with an approved `-m angerona...` module, or one of the explicit canonical suite
entry scripts. Repository-name substrings, arbitrary scripts beneath the tree,
and merely using the suite virtual environment no longer grant kill authority.
The GUI captures process creation time, reacquires the PID, and repeats the full
ownership predicate before termination.

### Impact

The confirmed Jupyter, pytest, `-c`, arbitrary helper-script, and workspace-path
lookalikes no longer match the shutdown authority predicate.

### Recommendation

Retain exact approved-module/script positives plus venv-pytest, Jupyter,
arbitrary-script, `-c`, substring, and PID-reuse negatives in both Python and
PowerShell ownership implementations.

## Verified controls and prior-finding reconciliation

- **R5-02 resolved in scope:** quarantine and restore retain non-reparse parent
  handles, pin file identity, use non-replacing handle/dirfd rename, verify
  digest/identity, and bind undo to the authenticated commit.
- **R5-01 materially narrowed, still open:** generic Documents/Downloads
  changes, filename-only real-driver matches, raw suspicious ports, and raw
  Sysmon EIDs no longer carry mutation authority; drill-driver response now
  requires exact live practice provenance. The LSASS/VSS and ransomware
  escalation paths found in R6-01/R6-02 are resolved; the remaining trust issue
  is the already-known in-process producer boundary, not a raw sensor path.
- Evidence Lattice records process birth time per signal and emits no process
  response contract if clocks are missing or disagree; the reviewed PID-reuse
  fusion defect is fail-closed in the current tree.
- Beacon history is keyed by exact `(pid, create_time, name, peer)`, closing
  cross-PID aggregation; cadence without threat-intel corroboration is alert-only.
- Ransomware now counts only conservative rename pairs, correlates per directory,
  and withholds host isolation from uncorroborated churn. R6-02 is resolved.
- Network Monitor strips inherited response fields and grants a peer block only
  for its explicit threat-intel IOC branch. Sysmon events are evidence-only.
- No new journal forgery, undo-record forgery, quarantine junction swap, remote
  observe-only bypass, or contract target-equality bypass was confirmed.
- Posture AI/CVE advice is inert; external modules require explicit opt-in and
  verified manifest/source bytes; MCP, Remote Bridge, JARVIS, and Fleet retain
  loopback/authentication/authorization boundaries appropriate to their action
  catalogs. No new network-service mutation bypass was confirmed.
- Combat queue saturation releases the failed admission's dedup identity and
  emits a signed request-bound failure receipt, so overload cannot silently
  poison a manual SOAR request. The queue remains intentionally bounded and
  reports degraded health rather than consuming unbounded memory.
- GUI red STOP and the elevated external kill helper require exact approved
  Angerona launch grammar; merely using the suite virtual environment or
  mentioning the workspace is not process-termination authority.
- Deployment mirroring refuses broad/protected/overlapping/unowned destinations,
  previews the destructive mirror, and requires exact typed authorization.
- The known external/drop-in in-process trust boundary remains: EventBus HMAC
  authenticates stored event bytes, not producer identity. It was not refiled.

## Verification

The pre-final focused regression set passed **61/61**:

- `tests/test_semantic_response_contracts.py`
- `tests/test_adversary_response_producers.py`
- `tests/test_adversary_combat_boundaries.py`
- `tests/test_adversary_combat_journal.py`

After the final role-parsing remediation,
`tests/test_semantic_response_contracts.py` passed **20/20** in the root-owned
clean run. Direct non-mutating probes also verified that procdump output-name,
rundll32 notes-path, VSS list, BCD enum, and PowerShell Write-Host cases are
alert-only, while the reviewed exact positives retain their intended scope.
Cross-volume quarantine, commit/rollback failure, SOAR receipt/dedup/admission,
deployment mirror, and red STOP ownership now have focused regressions. The only
open Round-6 item is the non-blocking process-handle/program-file lease described
in R6-03.

The root-owned final focused runs for SOAR receipt/admission, deployment safety,
and shutdown ownership were green after the last changes. This red-team pass did
not run a concurrent full suite so it would not contend with the release gate.

## Severity summary

| Severity | New findings | Release blocking |
|---|---:|---:|
| Critical | 0 | 0 |
| High | 0 open / 3 resolved | 0 |
| Medium | 1 open / 7 resolved | 0 |
| Low | 0 | 0 |
| Info | 0 | 0 |

Prior Round-6 findings verified in the current tree: **4 resolved, 1 still
open** (the defense-in-depth process-handle/program-file lease). Six additional
broad-audit defects were found and all six were resolved during the audit.
**No Critical, High, or Medium release blocker remains in this scope.**
