# SpywareGuard: surveillanceware defense preview

SpywareGuard is Angerona's newest feature under active development. Open the
wide black-spy **SpywareGuard** button in the dashboard's top-right controls.
It opens one dedicated window and preserves local drafts when hidden. It combines
host audits, spyware-relevant sensor events, reviewed research indicators,
containment receipts, an inert sandbox and optional emergency notifications.
It ships with v1.13.0 as a preview capability.

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

Literal indicators are normalized, deduplicated, given a source digest and an
expiry, and shown as candidates. Approve individual values before their live
matches become detection rules. Approval is scoped to that report digest and
the current module session; changed reporting and expired indicators require
review again. Narrative parsing is deterministic and needs no cloud AI key.

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

## Validation

The `tests/test_spyware_*.py` fixtures cover malicious report data, pinned HTTPS
policy, stale/replayed telemetry, process reuse, single-rule response contracts,
archive tampering, independent watcher shutdown/revocation, UI lifecycle and
inert sandbox behavior. Run them with the repository's validated interpreter.
The inventory, documentation drift, full compile and offline selfcheck gates
remain part of publication.
