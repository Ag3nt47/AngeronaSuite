# Round 5 final release red-team audit

Audit date: 2026-08-25
Scope: current working tree after the round-4/round-5 hardening changes
Disposition: **RELEASE BLOCKED**

This was a read-only audit. No product source, configuration, runtime state, or
host policy was changed. The exact-contract work closes several important trust
failures, but it also exposes a more fundamental issue: some producers now bind
an exact target correctly while still granting mutation authority to evidence
that is only an observation or a broad heuristic. Exact targeting does not make
the underlying verdict trustworthy.

## Prioritized release blockers

### R5-01 — Raw sensor observations have default-on outage authority (HIGH)

**Components:** `src/angerona/core/config.py:140-152`;
`src/angerona/modules/file_integrity.py:21-27,64-86,359-408`;
`src/angerona/modules/network_monitor.py:43-71,249-256`;
`src/angerona/modules/process_monitor.py:96-132`;
`src/angerona/modules/sysmon_listener.py:39-69,153-165,213-268`;
`config/sysmon_config.xml:99-132`;
`src/angerona/modules/adversary_combat.py:337-425,591-681`

A fresh install enables Maximum Combat at LOW severity, file quarantine, host
isolation, and honeypots. FIM watches the user's Documents and Downloads and
sets `response_authorized=True` for every ordinary creation, modification, and
deletion. New files are quarantined; modifications/deletions also authorize
host isolation. Combat counts each signed event as a distinct cause when no
correlation ID exists and isolates after three causes in 30 seconds. Routine
document activity can therefore remove user files and sever host networking.

The same authority mistake appears elsewhere:

- any new connection to one illustrative port authorizes a persistent inbound
  and outbound firewall block for the remote IP;
- any Office child named cmd/PowerShell/wscript/cscript/mshta authorizes process
  isolation, suspension/termination, and host isolation;
- raw Sysmon EIDs 8, 10, and 25 are marked CRITICAL and authorize quarantine,
  host isolation, and honeypots. EID 10 is configured with an OR group for LSASS
  and broad access masks; legitimate security and administration tools can
  produce this observational event. The response boundary does not re-check
  target image, access mask, signer, allowlist, or detector correlation.

An unelevated same-user process can deliberately induce these signed sensor
events and make the elevated suite disrupt the host. EventBus HMAC, exact target
matching, receipts, and undo are useful but do not establish malicious intent.

**Required remediation:** make raw FIM, connection, process, and Sysmon records
evidence-only. Only a reviewed semantic detector/correlator may issue response
contracts. Require at least two independent authoritative signals for outage
actions, separate file quarantine from whole-host isolation authority, and ship
Maximum mode as an explicit operator enrollment with a dry-run burn-in and a
tested circuit breaker. Add benign Office, LSASS-access, normal document-edit,
and suspicious-port negative tests that assert zero mutation.

### R5-02 — Quarantine and recovery remain vulnerable to junction/TOCTOU swaps (HIGH)

**Components:** `src/angerona/modules/adversary_combat.py:466-545,911-955,
1147-1166,1520-1547`

Forward quarantine resolves and checks a source, hashes it, records an intent,
then later calls path-based `shutil.move`. Undo similarly resolves both paths,
checks the quarantined digest and destination protection, creates the parent,
and then calls `shutil.move`. Neither operation pins the source and destination
parent directories or performs a handle-relative rename. A same-user process
that controls a Documents/Downloads ancestor can rename that directory and
replace it with a junction between the last check and move. Forward quarantine
can move a newly redirected privileged file into quarantine; undo can plant the
attacker-controlled quarantined bytes at a privileged redirected destination.

The HMAC journal prevents forged records and intent-before-mutation improves
crash recovery, but neither control closes a real filesystem name-binding race.

**Required remediation:** use Windows directory/file handles opened without
delete sharing, reject `FILE_ATTRIBUTE_REPARSE_POINT` on every component, bind
file identity/volume to the receipt, and perform handle-relative rename/restore
with a final identity and postcondition check. Treat a failed binding as
non-recoverable evidence, never as a reason to retry through a string path.

### R5-03 — Legacy SOAR mutation tiers bypass the new response contract (HIGH)

**Components:** `src/angerona/modules/soar.py:40-82,163-194,214-264,
284-300,319-353,355-375,396-425`;
`src/angerona/modules/soar_engine.py:54-81,169-204,217-290,302-357`

SOAR Automation consumes every local signed HIGH/CRITICAL event without
requiring `response_authorized` or an exact response contract. Under-attack
state is on by default. Corroboration and suspended state are keyed only by PID,
not `(PID, create_time)`, and the sink reopens `psutil.Process(pid)` before
suspend/kill. A reused PID can inherit another process's evidence or the
"already suspended, now kill" state. Its firewall rule has no durable ownership,
return-code/postcondition requirement, or automated undo.

The separately armed Active Response SOAR has the same PID-only problem and,
when no drill scope environment is configured, accepts every qualifying local
event. It kills the named PID and unlinks the first event path without an exact
contract, protected-path gate, reparse/identity binding, journal, or undo. Its
scope gate is strong for temporary drills, but an operator can arm the permanent
path without a scope.

**Required remediation:** remove direct mutation from both legacy modules and
route proposals through one response broker/Combat sink. Require the same exact
contract, `(PID, create_time, executable identity)`, HMAC intent/commit journal,
postcondition, firewall lease, and undo rules everywhere. The permanent
kill-and-rollback mode must fail closed when no protected response scope exists.

### R5-04 — Mobile emergency response is partly a no-op and partly over-broad (HIGH)

**Components:** `src/angerona/modules/mobile_bridge.py:203-230,297-368,
423-463,475-512`; `src/angerona/modules/shadow_shield.py:92-109,125-164`

Sender identity, PIN, single-use token, and token expiry are materially better.
However, KILL, SUSPEND, and LOCKDOWN only publish a
`mobile_response_directive` with `directive_authorized=True`. A repository-wide
search found no consumer of `directive_authorized`, `mobile-directive-only`, or
`MACRO_ISOLATE`; the only other occurrences are tests. The bridge nevertheless
tells the operator that the directive was dropped/lockdown issued. During an
incident these advertised emergency controls do not contain anything.

The one command that does mutate, ROLLBACK, calls
`ShadowShield.trigger_rollback(before_ts=...)` without paths, restoring every
cached Documents/Desktop file rather than the alert's exact artifact. Pending
mobile state stores PID but no process creation time, so a future directive
consumer would also be exposed to PID reuse.

**Required remediation:** add one authenticated, typed directive consumer in the
response broker, bind KILL/SUSPEND to PID + create time + executable, and return
success only after a journaled postcondition. Bind LOCKDOWN to a firewall lease
and exact undo receipt. Bind rollback to explicit, validated paths and signed
cache metadata; never restore all cached files from a single alert token.

## Additional weaknesses

### R5-05 — Source data-custody enforcement is scrubbed before it runs (MEDIUM)

**Components:** `start-angerona.bat:112-120,144`;
`src/angerona/core/privilege.py:423-456`;
`src/angerona/core/data_paths.py:175-197,305-319`

The launcher sets `ANGERONA_ENFORCE_KEY_ACL=1`, but the privileged bootstrap
sanitizer reconstructs the environment and does not preserve that flag. The
source-mode data path later enforces Administrators/SYSTEM custody only when the
missing flag equals `1`. The normal launcher does protect the directory first,
but a direct elevated source launch silently bypasses the application-level
fail-closed assertion. Existing tests call `data_dir()` with the flag directly
and do not exercise sanitizer then data-path initialization.

**Recommendation:** derive source custody from a protected post-elevation
attestation or enforce it unconditionally for elevated source runtime; add a
bootstrap-to-data-path integration test.

### R5-06 — Ollama files are verified, but the serving process is not (MEDIUM)

**Components:** `src/angerona/engines/ai_guardrail.py:40-53`;
`src/angerona/engines/ollama_client.py:200-230`;
`src/angerona/modules/ai_model_integrity.py:190-280`;
`src/angerona/core/model_pack_manager.py:689-726,731-806,836-985`

Catalog, manifest, and content-addressed blob verification are strong, and the
client now pins numeric loopback while disabling proxies. Inference still
trusts whichever unauthenticated process owns loopback port 11434. A local
process can race Ollama after it stops and impersonate the model service. ARIA
writes remain confirmation-gated, limiting direct mutation, but triage,
recommendations, and evolution inputs can be forged despite verified model
files. The source comment explicitly acknowledges this missing ownership gate.

**Recommendation:** supervise Ollama as a child, bind its PID/executable signer
and listening socket, or place it behind an authenticated named-pipe/local
broker. Treat loss of ownership attestation as model unavailable.

### R5-07 — SOAR's normal refusal path throws a GUI exception (LOW)

**Component:** `src/angerona/gui/pages.py:3443,3733-3767`

`_approved_requests` is a dictionary. If final process preflight fails—a normal
case when a process exits or its identity changes—the handler calls
`self._approved_requests.discard(request_id)`. Dictionaries have no `discard`,
so the fail-closed host result is followed by an `AttributeError`; the status
refresh and operator explanation are skipped. The durable record is already
marked failed, so this is a response-console reliability defect rather than an
authority bypass.

**Recommendation:** use `pop(request_id, None)` and add a stale-PID/preflight
failure GUI regression.

## User-facing action-surface map

| Surface | User-visible actions | Mutation/trust result |
|---|---|---|
| Classic header (`main_window.py:171-408`) | Adaption, Self-Test, Red Team Simulation, Chill, World View, ATT&CK Map, Threat Intel, Forensics, Local SOC, Console, Setup, Help, Settings, Stop | Adaption applies/rolls back firewall profiles after explicit review; Red Team is practice-scoped; Chill controls module cadence; Stop/resilience manages Angerona processes. No new direct text-to-host bypass was found. |
| Classic body (`main_window.py:449-463`; `pages.py:2937-3327,3428-4155`) | Modules/inspector, Live Alerts, SOAR Queue, Scan Center, ARIA console | Alert Block and reviewed SOAR revalidate signed evidence and exact process identity before reversible suspend. Scan Center explicitly has no remote target/exploitation/quarantine/automatic remediation (`security_scan_center.py:1-4,441-466,973-1035`). ARIA exact-token confirmation is accepted only from the typed GUI channel (`main_window.py:3046-3075`); voice/callback text cannot confirm. R5-07 affects stale SOAR refusal. |
| Flow / Local SOC (`operations_center.py:279-334,421-593,636-661`) | Overview, Cases, Hunt, Assets, Detection Content, Parity & Interop, Audit; create/update notes, sanitized export, bounded hunts, inventory, stage/activate/rollback detection packages | Mutations are explicit operator workflows and local data/package lifecycle. No autonomous host-response sink was found here. |
| Red Team / Shark (`red_team_console.py:80-119,219-337,496-560,837-1040`; `pages.py:1870-2025,4562-4872`) | Run/history/device lab/sandbox editor, launch/stop/clean, signed device import/export, AAR attempt-fix/retest/source | Practice artifacts are scoped and custom payload text is stored/tested as inert data. Prior live-code reload is removed. AAR remediation remains explicit. |
| Source Sandbox (`sandbox_editor.py:182-315,356-531`; `source_sandbox.py:87-208,284-461,470-596`) | Open/reload, validate, ask AI, find, save/revert working copy, history, exit | Clipboard/AI code stays in an isolated working copy; no import/reload/execute path was found. Windows writes now pin handles and reject reparses. |
| Upgrade Console (`upgrade_console.py:174-415,513-702,739-890`) | Mobile test, governed model-pack install/activate/rollback/remove, paste code to sandbox, watchdog and telemetry views | Model operations accept only bundled digest-pinned catalog entries and reverify local blobs. Pasted code is staged only. Async callbacks use window-lifetime tokens and refuse stale results. Runtime Ollama ownership remains R5-06. |
| Settings (`pages.py:4918-4971,5344-5507,5706-6295,6298-6657,6657-6975`) | Overview, Information, General, System, Adversary Combat/history/undo, Enterprise/fleet, ARIA/tests/model download, Trusted Processes, Mobile, API Keys, privacy reset/save | Explicit settings mutate policy, credentials, allowlists, startup/integration state. Combat undo has R5-02; Mobile has R5-04. API/provider secret compartmentalization remains a known open item below. |
| Tray/help/setup (`main_window.py:3714-3744,4382-4398`; `setup_wizard.py:634-766`) | Open/Quit, read-only help/tour, guided configuration | No untrusted callback-to-write path found; setup writes operator-selected configuration/credentials. |

## Autonomous host-mutation inventory

- **Adversary Combat:** quarantine/restore, suspend/terminate, program/IP/host
  firewall blocks and undo, honeypot activation, crash-orphan recovery. Blocked by
  R5-01/R5-02 despite strong HMAC intent/commit records.
- **SOAR Automation / Active Response SOAR:** suspend/kill, program firewall
  block, artifact unlink. Blocked by R5-03.
- **Ransomware/Shadow Shield:** cache restore and optional VSS snapshot;
  automatic detector integration plus mobile rollback. Mobile scope blocked by
  R5-04.
- **Posture Hardening/remediation actions and Host Adaption:** quarantine,
  process containment, firewall/ACL/service/registry work, and rollback. These
  are operator-stage/apply workflows, not arbitrary LLM execution.
- **Smart Deception:** local decoy-file lifecycle, automatically activatable by
  Combat contracts; authority inherits R5-01.
- **Resilience/shutdown/autostart/model/detection lifecycle:** manages only suite
  processes, startup state, protected data, curated model aliases/runbooks, and
  signed detection packages. No new arbitrary command execution path was found.

## Trust-boundary reconciliation

- **Verified closed:** inherited pre-elevation environment authority (R4-01),
  attacker-selected first fleet migration (R4-02), proxy/rebinding on local HTTP
  (R4-03), unsigned/forged Combat receipts, mutation-before-receipt crash gap,
  voice/callback confirmation, model-pack API-only digest trust, unsigned Sysmon
  cursor, live SourceSandbox reload, and SourceSandbox reparse races.
- **Still open from round 4:** protected provider/mail credentials are still
  republished into global `os.environ` (`secure_store.py:38-52,226-280`) and the
  generic subprocess helpers inherit it (`core/win.py:24-42`); fleet-generated
  operator/device credentials still have `expires_at=0`
  (`fleet_credentials.py:688-703`) while principal expiry rolls forward 366 days
  per restart (`app.py:697-718`).
- **Known deployment boundaries, not refiled:** elevated editable source checkout,
  legacy Remote Bridge confidentiality/authentication, and broad PowerShell
  execution remain deferred boundaries. Packaged data custody is materially
  stronger; source data custody has the R5-05 regression.
- **No new bypass found:** EventBus/cursor/journal HMAC verification, remote
  observe-only rejection, mobile sender/PIN/token checks, exact ARIA typed-token
  gating, curated model blob verification, Scan Center local-only target policy,
  sandbox non-execution, and stale Upgrade Console callback suppression.

## Verification

Focused read-only suites passed **160/160**:

- 99 Combat, producer, ARIA boundary, SourceSandbox, data-root, model-pack,
  Sysmon cursor/coverage, and URL-policy tests;
- 61 SOAR queue, provider-credential, fleet-credential, and optional ARIA tests.

The green suite proves the implemented positive contracts and many fail-closed
checks. It does not contain the benign-negative, junction-race, mobile-consumer,
legacy-SOAR identity, bootstrap ordering, Ollama owner, or stale-SOAR-refusal
gates required above.

## Severity summary

| Severity | New findings | Release blockers |
|---|---:|---:|
| Critical | 0 | 0 |
| High | 4 | 4 |
| Medium | 2 | 1 (source custody) |
| Low | 1 | 0 |

Recent prior hardening controls verified resolved: **9**. Prior/deferred
boundaries verified still open: **5** (credential environment, fleet expiry,
editable source, Remote Bridge, broad PowerShell). The seven round-5 findings
above are additional current-tree results.
