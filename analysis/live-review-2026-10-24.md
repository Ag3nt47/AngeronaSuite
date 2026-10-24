# Live runtime and containment review — 24 October 2026

This is a sanitized review of an authorized local application session. Raw
process rows, commands, network identifiers, original events, signing material
and private backups remain local. Product version remains 1.14.0; this review
does not close the broader 1.15 work or rewrite the October 22 issue register.

## Actual runtime evidence

The core was identified by its command, parent relationship, process creation
identity and matching diagnostic status, separately from the launcher, scanner,
watchdog and Black Box. The checkout initially had a clean worktree at
`9f0fe74a550e56a3d27e6d0f05e785046f96be01`. This does not attest every byte
already loaded by the running process.

The original session had no enabled Live Debug pipe. Review therefore used
bounded, read-only SQLite queries, existing status/watchdog files and an
independent process sampler. Existing original event HMACs were verified with
the existing installation authority, without creating or rotating keys. Archive
integrity does not establish maliciousness or a live producer receipt.

The initial selected original capture contained 78 records. A subsequent
254.438-second durable-log observation recorded 883 events, all with matching
archive HMACs. It ended with an explicit core-generation change when the
operator terminated the application. These selected inputs do not establish
complete session continuity; the observer did not substitute its own records
for authenticated source evidence.

### Spyware Guard

* A repeated startup finding referenced a missing executable in a temporary
  directory. Both observed registry views retained the entry. Its MEDIUM
  persistence heuristic became CRITICAL through the configured single-rule
  host-isolation fallback. No execution or spyware identity was established.
  The entry was not deleted, approved or exempted.
* Nine memory-observation pairs retained exact same-handle receipts. Originals
  described RWX executable-memory metadata, with `active_attack=false` and
  an alert-only producer policy. Spyware Guard requested process containment
  under its standing single-rule policy, including a Black Box process.
  Receipt identity is not proof of injected code; requests are not verified
  completed containment. No binary-name or publisher allowlist was added.
* The captured beacon original described four regularly spaced connections by
  the Windows Defender Core service, without threat-intelligence corroboration.
  Timing alone did not establish C2. Microsoft's [service description](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-core-service-overview)
  and [network requirements](https://learn.microsoft.com/en-us/defender-endpoint/configure-network-connections-microsoft-defender-antivirus)
  provide context, not an exemption or verification of the observed peer.
* Unquoted service-path findings remained configuration exposures with no
  automatic response authority. Familiar names were not treated as trust.

The operator explicitly prioritized automatic containment before human review.
These changes preserve the existing single-rule response requests and exact
process-generation binding. No live payload, arbitrary PID kill or fabricated
successful response was used to validate them.

### Other serious alerts

Canary misses and CHAOS failures established assurance gaps, not proven API
hooking. Gateway drift remained unresolved alongside missing route evidence;
the retained baseline was preserved. HVCI, DMA, release, recovery, audit and
driver findings represented exposures or unavailable evidence rather than
confirmed malware. Registered Purple Guard markers remained drill evidence.
Watchdog restart requests were not treated as completed repairs; provenance
and compliance workers also reached bounded restart exhaustion during review.

Recovery-tamper substring alerts included diagnostic source searches containing
the searched-for command text. Their originals already specified observation
and no response authority. This remains a detector/presentation limitation;
no PowerShell-wide or search-tool exemption was introduced.

### Runtime-tamper report

Three authenticated alerts followed the authorized edit of `core/threat.py`.
Each reported the containing source file changed. The check's source-drift
branch is reached after the live callable fingerprint still matches, whereas
the old universal message incorrectly claimed an in-memory modification.
The timestamps and reviewed diff support authorized source maintenance as the
explanation for these particular records. They do not exonerate unrelated
future drift. Original alerts and armed baselines were retained.

## Performance

The 300-second sampler collected 101 consecutive samples against retained
native handles for the four confirmed process generations. No target-generation
change or status identity mismatch occurred within that interval.

| Measurement | Observed result |
| --- | --- |
| Core mean CPU | 89.33% of one logical CPU; 11.17% of the eight-CPU machine |
| Black Box mean / peak CPU | 0.776% / 2.604% of one logical CPU |
| Host mean / peak CPU | 60.31% / 92.9% |
| Core RSS | 210.0–223.8 MiB |
| Black Box RSS | 27.6–34.8 MiB |
| Minimum available host memory | 5.15 GiB |
| Inline EventBus changes | 16,549 deliveries, 784 budget violations, zero delivery failures |
| Maximum status generated-data age | 87.43 seconds |
| Sampler CPU cost | 34.08 CPU-seconds; about 1.42% machine CPU |

Six same-day core watchdog samples showed 5.2–5.9-second GUI beat delays.
Sampled stacks included dialog construction, a System Pulse bar update and
the native Qt event loop. The log lacks PID/birth binding; timing and stack
correlation do not identify a cause. Black Box's retained watchdog tail had no
same-day stall. Its low CPU does not prove GUI responsiveness.

The per-core runtime-metrics file was absent. `flow_metrics.json` contains
calculated display estimates and was not used as measured queue latency or
loss. Competing host work and the observer's own cost remain relevant. No
performance improvement or complete helper attribution is claimed.

## Applied source changes

1. Status, dashboard, threat window and posture now include retained
   HIGH/CRITICAL EventBus evidence through the existing atomic revision view.
   INFO bursts cannot evict a still-retained critical alert from these
   calculations. Existing acknowledgment, allowlist, resolution and response
   policies remain. Retention overflow and restarts can still lose evidence.
2. Self-integrity distinguishes `source-file-drift`, `runtime-callable-drift`
   and `coverage-unavailable`, with corresponding explanations. CRITICAL
   severity, tamper flags, checks, approval requirements and alert latching
   remain. Live Debug exports only these three exact `tamper_kind` values.
3. A separate rollback-checkpoint maintenance tool admits only the exact
   authenticated completed-undo/failure pattern described below. It does not
   broaden the existing inert-drill recovery or run automatically at startup.

## Containment checkpoint repair

The actual journal held 361 authenticated, newline-complete records. Its
schema-2 protected anchor and witness agreed at record 360, a completed undo.
One trailing authenticated failure record completed the same program-firewall
rollback. This historical terminal-checkpoint gap explained the current
`RECOVERY REQUIRED` state. It was not evidence of a newly observed attacker.

The existing startup and inert-drill tools correctly refused this different
history. The new `tools/recover_combat_rollback.py` inspects read-only by default.
It authenticates the whole bounded history, exact five-record terminal
relationship, existing anchor/witness and an exact native firewall-rule absence
observation. Only the documented missing-rule HRESULT proves absence;
unavailable dependencies, access denial and ambiguous results remain holds.

After the operator terminated the application and the suite processes were
observed absent, explicit apply advanced the existing checkpoint from 360 to
361. Private byte-verified backups preserved the prior journal, encrypted store
and witness. The journal and signing key were unchanged. The command returned
`recovered=true`, `host_actions_executed=0`, `rearmed=false`; restart readiness
and actual containment require their own observations.

Apply uses the reviewed input token, writer lease, pinned journal, credential
transaction, stopped-app checks and fresh rule absence. These are point-in-time
observations, not an atomic OS firewall/process-start interlock. A failure
between anchor and witness writes stays an explicit integrity hold with private
backups; no automatic reset or history deletion is attempted. The old process
generations were absent after operator termination, but their native exit codes
were not retained across that termination.

## Validation and deployment

* Priority visibility: 91 passed, one explicit skip across seven focused suites.
* Recovery and journal: 111 distinct tests passed, zero skips across the staged
  focused runs; repeated cases are not additional coverage. This includes a
  failure after the anchor write, preserving the resulting witness hold.
* Self-integrity: 31 focused/selected tests and its module self-test passed.
* Live Debug enum export: 25 focused tests passed; other cases were deselected.
* The first default offline selfcheck retained 28 passed/one failed phases:
  inherited `OLLAMA_HOST` lacked a URL scheme. Strict URL validation correctly
  refused it. The separate disposable rerun uses a child-process-only validated
  loopback URL, preserving host settings, environment and the failed evidence.
  That rerun passed all 29 phases, with 68 module PASS and 18 explicit module
  SKIP rows. It does not repair the host's separate Ollama configuration.
* Final combined priority/self-integrity/Live Debug gate: 100 passed, zero
  failures/skips, native exit 0. Whole `src`, `tests` and `tools` compilation,
  documentation drift and whitespace checks passed.

Independent post-apply inspection verified matching journal/anchor/witness at
361, all signed records, no pending phases and native exact-rule absence. Key
and journal matched the pre-inspection hashes; verified backups matched the
originals, and this read-only inspection changed no authority bytes. Prior
inspection hashes originally existed in tool output; their later private
transcription is explicitly advisory, separately from the original backups.

Guarded canonical publication and fresh restarted-session observations are
recorded separately as they complete. No host-clean,
all-module efficacy, current CI or containment-success claim follows from the
offline tests or this historical session.
