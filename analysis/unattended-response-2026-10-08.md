# Simulation progress and unattended response

Date: 8 October 2026. Maintenance on v1.13.0; no capability-count change.

## Operator behavior

Benign Shark and Red Team simulations now continue when Combat's response
readiness is unavailable, disabled or held for recovery. The selected profiles,
intensity and inert process/file exercises remain unchanged. A persistent
plain-text warning explains the hold during progress and results. Unready
launches leave the existing temporary SOAR policy environment untouched.

Requested containment scoring still requires authenticated verified receipts.
Completing a simulation with no verified response displays containment as
unverified; it cannot receive a success indication from elapsed time or a
readiness warning. Independent target, ownership, validation-lease and engine
start failures still prevent unsafe or impossible launches.

Automatic response already defaults to enabled, using predetermined exact-target
detector contracts and saved Combat policy. It does not depend on Ollama or
per-alert approval. Severity alone, imported advice and health findings do not
authorize host containment. Recovery failures can prevent the response worker
from arming even when its module appears running.

The response worker now subscribes before startup reconciliation, closing a
reproduced gap where the first detector alerts could be missed. It buffers only
new authenticated current-generation requests in the existing bounded queue;
startup requests older than 30 monotonic seconds expire. The worker rechecks
policy and exact identity at execution. No historical EventBus ring is replayed,
and stop or failed startup closes admission and discards its remaining work.

SOAR reports Combat's standing-rule ownership for signed local actionable
contracts covered by effective policy, or the specific readiness hold. This
diagnostic path neither resubmits requests nor claims queue admission or action
success. Uncovered/unknown policy retains the existing review path. Legacy
recommendation and attack-burst messages now accurately describe whether their
separate automatic-request flags are enabled.

The footer now exposes Auto ARMED, HELD, OFF, STARTING or UNAVAILABLE alongside
posture, reusing the existing memory snapshot without another timer or host
sampler. Settings > Adversary Combat lists the effective file, process, network,
host-isolation and deception rules, including the mode override that makes
Contain suspend processes. Action history and Undo retain their existing proof
requirements.

## Confirmed local diagnosis

Read-only inspection found a valid signed journal with one quarantine intent
beyond an agreeing protected anchor and independent witness. The target was an
inert simulation marker. A pinned read found its original identity and hash
unchanged, with one hard link and no quarantine destination. The existing
startup-honeypot-only recovery tool correctly refused this different case.
Private target names, keys and journal contents are not published.

## Narrow automatic checkpoint recovery

`core/combat_checkpoint_recovery.py` permits only a demonstrably unapplied
quarantine intent for a fixed comprehensive Red Team marker. It validates the
bounded signed chain and phase graph, matching schema-2 anchor and witness,
exactly one trailing intent, and no unsupported recovery/undo history. The
marker must be directly inside the installation drill sandbox and exactly match
the shipped tactic/technique marker bytes, recorded file identity, single-link
count and SHA-256. Its recorded quarantine destination must be absent.

Recovery retains writer/journal/source custody, checks source size before
hashing, revalidates the named POSIX inode where applicable, and verifies private
backups of the unchanged journal, encrypted store and witness. The existing
signing key is never copied or created. Inputs are checked again before advancing
the checkpoint and rereading the unchanged journal. The normal response
reconciler then records the unapplied intent; no file is moved and no applied
containment receipt is created by checkpoint recovery.

The helper is attempted once at enabled Combat startup after the specific
one-record checkpoint mismatch. Unrelated corruption, changed targets, existing
quarantine files, irreversible or ambiguous histories, missing authority and
failed proofs remain held. This is not general automatic acceptance of journal
rollback. The read-only `tools/recover_combat_drill.py --data-root ...` inspection
also exposes a stopped-application repair command requiring a fresh exact review
token; it does not itself rearm Combat.

## Validation and limits

Focused tests use inert targets, isolated authority and mocked host boundaries.
The simulation changes preserve actual response authorization and truthful
receipt scoring; the footer and rules panel grant no authority.

The initial complete Windows regression suite passed: **4,757 passed, 23 skipped** in
791.36 seconds. This includes the live dashboard's two-run Red Team clickthrough
with independent OS containment checks and automatic YARA response/Undo tests.
The offline selfcheck passed **26/26 phases**. Its combined SelfTestRunner
reported **67 passed, 18 declared skips** across module and synthetic-pipeline
checks. Compilation, fatal Ruff checks, documentation drift and whitespace
validation also passed. An independent review cleared startup admission,
checkpoint recovery and shutdown ownership after its combined 81-test gate.

The master manual has 46 rendered pages. The new operator addendum and updated
cover were inspected; the other 44 pages are byte-identical to previously
rendered and visually reviewed pages. Synthetic UI captures verified warnings,
effective-rule text and footer layout at desktop and 480-pixel widths.

Windows source restart uses the canonical unelevated Observe/development
launcher after the elevated stop helper. The separately installed signed
distribution supplies Windows Protect boundaries; this update does not elevate
source code or bypass that installation contract.

The stop helper now includes the canonical `angerona.startup` assistant and a
Windows venv redirector's exact matching base-Python child. Ownership requires
the same captured process inventory, suite-local interpreter parent, identical
approved invocation and creation-time ordering. It stops children before
parents. Unrelated Python applications, changed invocations and reused-parent
identities are excluded.

## CI-discovered Qt lifetime follow-up

The first published commit passed local validation with PySide6 6.11.1, but the
four Windows Python-version jobs installed 6.12.0 and encountered native heap
faults. Eleven other checks passed. The traces included background connection
collection and widget teardown; they were not failing Python assertions.

Review confirmed two unsafe lifetime paths. The orb's application event filter
queried native window state during destruction and unrelated lifecycle events.
It now checks the event type first, handles Destroy using Python bookkeeping
only, and inspects valid widgets only for its four supported operational events.
The native minimize/delete/repaint/GC regression now verifies that its child
process uses the same actual PySide binding as the parent test.

A separate instrumented probe confirmed that Top Talkers' auto-deleted runnable
destroyed its GUI-affinity signal object on a pool thread. Both connection and
AI workers now give the signal carrier application ownership and schedule its
deletion back to the GUI thread, including rejected pool starts. The same probe
then observed destruction on the GUI thread. This follows Qt's documented
[thread-affinity and deferred-deletion contract](https://doc.qt.io/qtforpython-6/overviews/qtdoc-threads-qobject.html).
Closing a dialog remains nonblocking, with existing single-flight and late-result
guards. These are confirmed hazards; the crash traces alone do not establish a
single cause for every native failure.

The isolated full-suite rerun with 6.12.0 still reproduced a native abort.
Package metadata therefore pins **PySide6 6.11.1**, matching the existing
hash-locked release runtime and the operator's unchanged installation. The
6.12.0 combination is not represented as validated or supported by this update.
Both confirmed lifetime fixes remain, and the final suite is rerun with the
supported binding, retaining the complete test selection.

Focused validation passed on each actual binding: **21 orb lifecycle tests**
and **32 Top Talkers tests** on both 6.11.1 and 6.12.0. Four new worker cases
verify GUI-thread destruction after the dialog has already been deleted and
after rejected starts, for both connection and AI work. The table-render-only
test uses an inert collector; native worker lifetime remains separately tested.

The broader rerun also exposed two test-fixture assumptions under host load.
The Windows enrollment retry regression now records real native 1175 errors
and proves both exact-unchanged reconciliations before every permitted retry,
including the unchanged attempt limit. The scan deadline tests use the existing
injected monotonic clock and advance it only inside the operation being tested;
they prove the operation ran and a late YARA finding is discarded. Production
retry and scan-deadline behavior is unchanged. These focused files passed
**23 tests with 3 existing skips** and **15 tests**, respectively.

Final supported-runtime regression result: **4,773 passed, 23 skipped** in
767.05 seconds using PySide6 6.11.1, with the complete 4,796-test selection.
The final master manual remains 46 pages; its Qt-version note changed only
page 46, which was visually rechecked. All other rendered pages match the
previously approved render byte-for-byte.
