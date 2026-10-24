# SpywareGuard: surveillanceware defense preview

SpywareGuard is Angerona's newest feature under active development. Open the
wide black-spy **SpywareGuard** button in the dashboard's top-right controls.
It opens one dedicated window and preserves local drafts when hidden. It combines
host audits, spyware-relevant sensor events, reviewed research indicators,
containment receipts, an inert sandbox and optional emergency notifications.
It is included in v1.14.0 as a preview capability.

## Dashboard and first-rule lockdown

The dashboard shows recent rule hits, requested actions, recorded response
outcomes, collection coverage and encrypted-evidence status. Requests and
applied actions are separate records: a request is not proof of containment.

**Single-rule containment is enabled by default for SpywareGuard.** One local
detection requests containment immediately. A bound process supplies its PID
and creation time; a network action supplies a literal public address; a file
action supplies an absolute path and inspected content hash. When a local
rule cannot identify one of those targets, SpywareGuard requests isolation of
the local host. Its response event has critical urgency while preserving the
observation's original severity and stating that spyware identity is unproved.

This availability-aggressive policy can interrupt legitimate software or
network access on a heuristic false positive. Change **Single-rule containment**
in this window's Settings. Adversary Combat's separately configured authority,
platform, protected-process and exact-object checks still apply. Full host
isolation requires its Maximum policy. Unelevated source runs retain their
Observe/development boundary; a request cannot grant missing OS authority.

Research mentions, unreviewed indicators, CVEs, remote observations, malformed
telemetry, health-only events and sandbox rehearsals do not acquire local
response authority. A country, company name or family profile is not a rule.
Unquoted service paths alone are configuration exposures for review; they do
not establish that a writable prefix was exploited and cannot request host
isolation. Persistence analysis uses executable and script targets rather than
task descriptions, names or log/output arguments. Unsupported interpreter
syntax reports partial analysis instead of a clean verdict. Eligible local
execution findings retain the single-rule containment policy above.

## What is collected

| Area | Present implementation | Coverage boundary |
| --- | --- | --- |
| Windows persistence | Run/RunOnce in both registry views, service paths, WMI consumers, COM in-process servers, startup inventory | Read-only; bounded enumeration and permission failures are visible. Shortcut inventory does not resolve `.lnk` targets. Existing Persistence Sweep separately covers scheduled tasks. |
| POSIX persistence | LaunchAgents/Daemons and systemd unit configuration | No service writes; skipped links and unsupported paths remain visible. |
| Memory | Opt-in executable private-region metadata on Windows/Linux, rotating bounded process samples | No memory-content collection or kernel inspection. JIT engines can create these regions legitimately. macOS memory collection is unavailable. |
| Behavioral evidence | Screen/input/camera/microphone API telemetry, sensitive file-read evidence, renderer/shell correlation | Requires trusted local adapters. The module does not intercept arbitrary APIs or file reads itself. |
| Network | Reviewed IP/domain matches, DNS patterns, DDNS/port combinations, encrypted egress-rate changes | Process counters and encryption flags must come from a telemetry adapter. Port 443 alone never proves encryption or exfiltration. |
| Ad-tech | Renderer/WebView behavior and explicit cleartext advertising-identifier field observations | Does not strip IDFA/GAID, decrypt TLS, or provide a universal zero-click exploit blocker. Identifier values are omitted from findings. |

The shared event cursor reports retention overflow. Native audit failures,
unsupported platforms and inaccessible processes remain coverage gaps. Empty
results do not prove that a host is free of spyware. Actor attribution is not
performed.

Host audits normally run every five minutes. Memory auditing inspects at most
four eligible processes and 512 regions per sampled process per sweep. All
queues, evidence lists, indicator stores and deduplication tables have limits.
Research fetching uses a separate bounded worker so a slow source cannot hold
up the detection loop. The visible dashboard refreshes its snapshot every
three seconds; news motion stops when hidden, paused or disabled by UI motion
preferences.

### Memory identity and lifecycle

Windows executable-region metadata now brackets collection with PID and exact
process creation-time checks on the same retained query handle. Inventory or
later psutil enrichment cannot replace that inspected identity. No memory bytes
are read and no additional VM_READ/VM_WRITE rights are requested. The existing
four-process/512-region sampling limits remain.

Partial, unavailable, unsupported or inconsistent identity stays advisory with
response_eligible=false. Linux region metadata has no equivalent native identity
receipt in this path. An obsolete worker generation loses publication authority
after stop/restart. A receipt is metadata, not a signature: authenticated producer
provenance and the existing exact-target response boundary remain required.
An executable private region can be legitimate JIT activity; this change does
not identify an implant or prove a clean host. See the
[identity and key review](key-and-communication-integrity.md).

## Intelligence, source links and news

Enable **Network intelligence ingestion** to allow outbound research downloads.
The module supports the official Citizen Lab and Project Zero research indexes
and CISA's Known Exploited Vulnerabilities catalog. KEV entries remain
vulnerability metadata; they are not converted into invented spyware domains.

Enter a public HTTPS research URL and select the ingest action. Downloads
reject credentials, private or local destinations, nonstandard ports,
redirects, compression, oversized responses and unexpected content types.
DNS results are checked and the TLS connection is pinned to the selected
public address with hostname certificate verification. No page scripts,
embedded resources, report instructions or remote detection code execute.
Supported report formats are UTF-8 text, HTML, JSON and STIX; PDF import is
not provided by this workflow.

Literal indicators are normalized, deduplicated, given source/expiry metadata
and shown as candidates. Approve the exact displayed candidate before its live
matches become rules. Each row carries a frozen IndicatorReviewIdentity: kind,
value, source URL, source SHA-256, observation and expiry times, CSPRNG-generated
store session and per-item revision. Module session and lifecycle generation
travel with the queued review. The comparison and approval assignment share
store → module lock order; callbacks and publication run after both release.

A refresh requires a new review even when report bytes are identical. Expired
evidence is not revived, and another source's copy of the same literal cannot
substitute for the approved receipt. A successful refresh removes indicators
absent from that source; failed parsing does not replace the prior source.
Revocation applies to the selected exact receipt and cannot silently remove a
different newer approval. Store reload or a changed module generation cannot
inherit a stale runtime approval. Review state reports queued, stale, approved
or revoked outcomes rather than treating a click as proof of acceptance.

Findings retain the exact receipt in their evidence and dedup key. Snapshot
rows remain capped at 500 and serialize detached JSON, including review identity
and exact approval state. This repairs stale-review admission, not report
truthfulness, actor attribution or administrator-resistant key custody. Runtime
review identities are not signatures. Imported narratives cannot grant response
authority. Parsing is deterministic and requires no cloud AI key.

**Stage YARA / Sigma / NDR candidates** writes inactive literal-rule review
artifacts to the private SpywareGuard data folder. Imported prose cannot
activate executable rules. Angerona's existing DetectionForge governed rule
workflow remains the route for reviewed package activation.

The top news strip uses official Citizen Lab, Project Zero and CISA bulletins.
It shows publication dates, bounded summaries and per-source refresh/failure
state. Select a headline to inspect cached details, then explicitly open its
validated source link. Downloads run on the research worker ahead of queued
report ingestion; Qt never downloads the article.

Three bundled primary-source briefs, reviewed on **22 October 2026**, populate
the banner offline. They are labelled **REFERENCE**, with fixed publication and
review dates; they are never presented as a live check. Retained downloaded
headlines remain inspectable when downloads are disabled, with their age and
cached status visible. Old, missing, future-dated or failed feed data is not
presented as fresh news. News is advisory and cannot authorize response.
Refresh is asynchronous and uses the same explicit network opt-in.
Citizen Lab's bounded official homepage research cards are used because its
generic RSS stream omitted the reviewed recent research reports.
Project Zero uses its bounded recent-post index because its complete archive
feed exceeds the download budget; its day-only dates are represented in UTC.
An unavailable or denied source stays a visible retrieval failure.

The catalog explains documented commercial surveillance and espionage
examples from multiple regions with primary-source links. It illustrates
worldwide behavioral coverage; it is not an exhaustive list of every country's
tools or evidence that the local device has any named implant.

## Sandbox, isolation and encrypted evidence

The sandbox provides offline DNS-tunneling, egress-spike and renderer-child
telemetry rehearsals. These exercise the classifier with inert records and
never request real containment. The Analysis Lab link opens the existing
separate source-analysis workflow. No sample is executed by a telemetry
rehearsal.

Live response uses Adversary Combat's exact-target journal and its existing
Undo workflow. Automatic deletion of persistence entries is not enabled by
this preview: it needs typed identity, a retained backup and verified rollback.

After a successful SpywareGuard file-quarantine receipt, the module can create
an AES-256-GCM encrypted forensic archive. Its key is read only from the
OS-protected credential store and is excluded from child-process environments.
First-key creation participates in the shared protected-store transaction;
an existing malformed value is not silently replaced. Concurrent cooperative
writers cannot install different archive keys or discard another credential.
Archive metadata and contents are authenticated. Restore is an explicit
non-overwriting operation in the archive API. The archive is an encrypted
copy: the separately journaled plaintext combat quarantine remains and the
dashboard states that fact. Failure to create an archive does not become a
false encrypted-isolation success.

## Hail Mary emergency beacon

Enable the emergency beacon and select a destination already authorized in
**Settings → Integrations** or **Settings → Mobile Integration**. The selected
channel or Signal bridge must also be enabled and valid. Optional cloud APIs
are not required. No destination is guessed and no development test sends a
live notification.

High-priority local compromise/exfiltration findings can enqueue a small
notification containing a generated incident ID, timestamp, rule code,
severity and optional PID. Files, memory, commands, paths, report text,
advertising IDs and credentials are excluded. Rate limits, bounded retries
and deduplication protect the destination.

An independently launched watcher detects the disappearance of the exact
parent process or loss of its authenticated heartbeat lease. The lease is
120 seconds to accommodate bounded host checks; process termination need not
wait for that lease. The watcher suppresses delivery on a verified normal
stop, revoked persisted configuration, PID reuse, ambiguous identity or invalid
IPC. Bootstrap authority travels through an anonymous pipe, not a command
line or plaintext sidecar. Destination authorization is rechecked before
last-chance delivery.

### Watcher lifecycle and test-ownership limits (draft)

The source retains the original Popen, READY reader, cleanup worker, streams
and Windows primary handle through proved retirement. Graceful cleanup runs
on the retained worker; snapshot inspection does not wait or join. Unresolved
cleanup remains stopping/unavailable and prevents replacement. There is no
production force-kill fallback. Intentional emergency detach before graceful
admission remains; after admission a later detach cannot unsend the stop or
discard unresolved ownership.

A narrow repair permits BrokenPipeError from stdin.close only when that same
stream reports closed. It still requires the original wait/poll agreement,
READY-reader retirement, explicit closure of every stream and primary-handle
closure before completing. Generic OSError or an unclosed stream stays
unavailable. Closed stdin does not prove authenticated stop-frame delivery.
Pipe write/flush/close can still block before finite waits: total cleanup is
NOT bounded. Startup's five-second READY wait and heartbeat/instance locking
remain limitations.

The test fixture requires strict live kernel-image admission, plain non-alias
paths, PE/file fingerprints and retained original child handles. Terminal proof
is separate: the same PID/raw FILETIME birth, WAIT0 and native exit must agree
with Popen's exact integer exit. Failed native proof stays sticky after resource
cleanup; cached returncode cannot green a retry. Test bootstrap supplies explicit
win32, win32/lib and Pythonwin paths and retains the pywin32_system32 DLL-directory
handle. These are fixture-only changes, not a product runtime/bootstrap redesign
or whole-runtime attestation.

All five native scenarios passed in R4, including the genuine production API
scenario with its explicitly adapted test launcher. That does not prove the
unmodified production launcher/redirector tree or unknown descendants. The
independent outer native attestation still covers exactly two generations;
nested cases use their own in-test ownership/retirement checks. The 12 private
product controls and 38 fixture controls also passed separately (a3738ecec2658723f5c0bc56296823f56c93e7bf95d7a5d6fe390c8b5cfdb740
/ 3c26afc83e27b1e37f1bc136279e9175fe5ec8f48bcd8ee8f22d634534ee5e66); they are inert and do not themselves establish native proof.
Earlier R3 nested retirement was unproved and is not retroactively supplied by
this new passing run; its exact historical cleanup API cause stays UNKNOWN.

Delivery is best effort. Host network isolation can block the notification,
and simultaneous power loss, network loss or compromise of the watcher can
prevent it. The UI reports attempts and outcomes separately.

## Extend the code and improve your security posture

Angerona is MIT-licensed source software. You can edit its code, add detection
rules, build sensors and improve the dashboard for your own requirements.
Start with [Writing modules](writing-modules.md), the
[contribution guide](../CONTRIBUTING.md), and these implementation files:

- `src/angerona/modules/spyware_guard.py`: lifecycle, policy and queued workflows.
- `src/angerona/core/spyware_sensors.py`: read-only host collectors.
- `src/angerona/core/spyware_behavior.py`: bounded telemetry classifiers.
- `src/angerona/core/spyware_intel.py`: provenance, parsing and candidate rules.
- `src/angerona/core/spyware_news.py`: dated bulletin feeds.
- `src/angerona/core/spyware_beacon.py`: emergency notification and liveness proof.
- `src/angerona/core/spyware_quarantine.py`: encrypted evidence API.
- `src/angerona/gui/spyware_guard_page.py`: the dedicated Qt page.

Keep new collectors bounded, preserve coverage failures, test with inert
fixtures and bind response to exact local targets. External Python modules
still require reviewed capability manifests and source digests. Editing source
does not bypass installed-package trust, signer or OS permission requirements.

### Current maintenance validation

The accepted R4 gate covered 34 complete suites, 491 function occurrences and 973
unique cases: 971 passed, zero failures/errors and two exact Windows availability
skips. All 75 privacy cases and seven named nested regressions passed, including
five native beacon scenarios with their own ownership/retirement checks. The
independent outer attestation covers exactly two generations, not every nested
process. Gate receipt 78b36785802635147855f0cbc8ce1cba88cc35b483c0ebfb319547b97b773f29;
root review 92d47b23cce1e400fa4b3dcf6df00c26f6ee0c88eafc3c51eb982d7644d7797c.

The fresh isolated selfcheck accepted 29 phases with zero failed phases in
32.609 seconds. Its 86-module inventory has 87 rows: 68 module PASS plus Event
pipeline PASS (69 total PASS), 18 module SKIP. Four required origins loaded;
five configured optional components, including beacon, were not loaded. These
remain explicit coverage limits. Receipt
ecd25a52f7731aeff24b071a2e68f1cbbbb5326ea9324586cfb6270fe65dc572;
root review 0167976c26da936ba8767765f306c8676141bb38e3a81c537ca15a0ada7eb91e.

Serial passive observations used the same tested pre-documentation source:

- SpywareGuard: 30.094-second window / 36.766 seconds total, three events
  (two LOW / one MEDIUM), zero recorded errors/drops/pending work;
  OBSERVED_WITH_GAPS. Health 85/degraded and two coverage strings remain.
  Receipt 65a957fc5ff7d73e7ced9ae34b64b51f53ba6108b9b6d75fb4c72417c64fe58e.
- Raw scanner: 30.172-second window / 35.719 seconds total, 31 heartbeats,
  zero recorded errors/drops/pending work/gap strings; OBSERVED. No module
  workers were selected, so worker-CPU coverage is false. Receipt
  840e5f87acecaec74b56ca8f8dfbcaa34f97953e3144f3c421906252f0b09fec.
- Combined 15 modules: 600.312-second window / 609.860 seconds total, 1933
  heartbeats and 369 events (one CRITICAL, two HIGH, 350 INFO, 13 LOW, three
  MEDIUM). Zero recorded errors, supervisor errors, capture/export/console drops,
  pending work or observed crashes; clean normal shutdown. OBSERVED_WITH_GAPS
  retains 17 interval gap strings across nine modules. Receipt
  42bc0a86bc8f3746c87aa82de109728e1a429c1294a7d7453da3bf22899c685f;
  root review 8c0662cd612e29e1857583557a5def472031aa765e9a8ca357d067c42cfa763e.

The nine modules with retained gaps are AegisPath, Fleet, Identity, Immutable
Recovery, LSASS, Process Monitor, Self-Integrity and SpywareGuard (two strings
each), plus Sysmon (one interval gap). Missing configuration, unavailable
evidence and unknown health are preserved; events are not adjudicated as
infection or false positives. Each completed profile retained the independently
observed outer two generations and separately query-held admitted core, with
WAIT0/native-zero, required closures and stable source/index/runtime. This does
not establish original-handle proof for every descendant. A possible competing
source-reader diagnostic and the observation harness's own reader lack separate
retirement proof. Primary worker CPU sampling is not helper-complete or a global
exclusive workload measurement; timing establishes no speedup or failure cause.

Only unavailable Windows 8.3 alias and symlink-creation cases skipped; acceptance
and coverage differ. Preserve original precollection failure
be111aa05ef19cc995ae0bbfe39b8b5892c47a766b02ef2ce8814dfb2225ddc1,
failed R2 cf17c1f491117f540c0d73a2d8c3b60b96f4ba0d9c896628d8e19619529029c0,
and failed R3 38768982d0cd8d557b81c5c0636d831cd87086882931755ca1861e177d6a0b9e.
R3's exact cleanup API cause stays UNKNOWN and its missing nested proof is not
retroactively supplied by later passing combined repairs. HOST-03/HOST-04 and
older gaps stay open; a restored 2 GiB buffer is not established.

Tested pre-documentation inventory
87acb370d9e68a75244b29da3297c3496d3330dc22a3bc2dc2f68fc7b31d4f47;
the final 19-path review covers 11 code/test and eight documentation paths
(two additions). After documentation, final guards must recheck all 1164 tested
Python pins and the complete root-held source inventory, run fresh offline
checks, and invoke the unchanged canonical guarded publisher only for a
completed reviewed commit. These are mandatory completion gates, not preclaimed
results or public self-referential hashes. Product remains 1.14 maintenance;
broader 1.15 is incomplete.

## Validation

The `tests/test_spyware_*.py` fixtures cover malicious report data, pinned HTTPS
policy, stale/replayed telemetry, process reuse, single-rule response contracts,
archive tampering, independent watcher shutdown/revocation, UI lifecycle and
inert sandbox behavior. Run them with the repository's validated interpreter.
The inventory, documentation drift, full compile and offline selfcheck gates
remain part of publication.
