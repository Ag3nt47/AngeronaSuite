# GitHub Tools and Zero Breach Toolkit

Angerona's **GitHub Tools** button opens curated scanners, source review,
verification, settings, analysis and credits. **SpywareGuard > Zero Breach** uses
the same prepared tool and job state. Opening a second view does not install a
second copy or start a second scan.

The first curated engine is [Zero Breach Toolkit v0.1.10](https://github.com/interplains/Zero-Breach-Toolkit/releases/tag/v0.1.10),
by archivegenocide.com / interplains. Its complete single-file release is bundled
unchanged, alongside its licenses and notices. It runs as a separate supervised
process behind Angerona's controls. It is never imported into the security core
or GUI interpreter: the upstream scanner temporarily changes Python socket
functions while scanning, which must not affect Angerona's other services.

## Installation, download and revert

Optional automatic preparation happens after the dashboard paints. Preparing
the bundled standard-library engine needs no pip installation and does not
modify Angerona's Python environment. A download/restore action retrieves the
exact cataloged release; a newer upstream branch or release does not silently
replace that reviewed version.

Both views expose the prepared version, integrity state, job status and storage
information. Settings control automatic preparation, permitted downloads and
job/report limits. Disabling preparation or a failed optional download does not
make the dashboard depend on the toolkit.

**Revert** retires the exact managed installation after confirmation. Preferences
and retained reports remain available. Unknown or changed files require review
rather than becoming targets for a broad cleanup. **Prepare/Restore** can make a
verified copy available again.

## Integrated checks

Use the native controls to select a default, full, browser or selected-target
check; quick/preview options, existing Windows records, custom local indicators
and supported local phone collections can refine that request. The adapter can
inspect existing AndroidQF collections and local iPhone backup, filesystem or
sysdiagnose inputs. Availability depends on the selected input and platform;
unavailable or skipped checks remain visible as coverage gaps.

Integrated execution currently requires an ordinary-user source process.
Installed or elevated execution remains **HELD** until an accepted ordinary-user
broker is available. Opening the native page or verifying Administrator coverage
does not bypass that boundary or request elevation for the third-party engine.

Ordinary integrated scans use the bundled indicators without refreshing feeds.
The scanner does not require administrator privileges. Angerona does not infer
that a privileged collector succeeded merely because a window or process opened.

**Advanced toolkit options** explains the following upstream capabilities and
links the complete pinned release and its download. Their execution inside
Angerona remains **HELD** until separate managed adapters and dependency or
acquisition runtimes are reviewed; this is not a runnable native full-menu path:

- Encrypted iPhone backups use a private terminal password prompt. Passwords
  must not be supplied through command-line arguments, environment variables,
  logs or saved settings.
- Optional Candiru patterns require the separately pinned YARA-X dependency;
  encrypted-backup extras also have their own requirements. They do not belong
  in Angerona's shared environment.
- Indicator refresh is a network operation. The upstream updater's per-source
  limit is not an aggregate cache quota; automatic execution must retain the
  managed adapter's download/storage policy.
- AndroidQF acquisition is separate from examining an existing collection. It
  downloads a collector, needs device-owner consent, changes device state and
  can retain sensitive partial output.
- Evidence exports are private, unencrypted ZIP files. Only explicitly selected
  originals belong in an export; a path mentioned in a finding is not permission
  to copy that file.
- The optional browser ad-blocking test opens an external website after a user
  action. It is separate from the scanner's offline checks.

The upstream `--deep` option is unimplemented and is not a supported capability.
See the pinned [machine contract](https://github.com/interplains/Zero-Breach-Toolkit/blob/81bd556ba604685dbd1c0ecb48138c10f43cccf8/scan/CONTRACT.md)
and [privacy documentation](https://github.com/interplains/Zero-Breach-Toolkit/blob/81bd556ba604685dbd1c0ecb48138c10f43cccf8/PRIVACY.md)
for the original behavior and limitations.

## Reports, cancellation and storage

Every job receives a fresh private temporary directory. The upstream tool can
delete old matching-prefix temporary folders and can create complete browser
database snapshots or temporary plaintext phone databases. Its temporary path
must therefore never be Angerona's general temp directory or the user's system
temp directory. Interrupted sensitive snapshots need controlled retention and
cleanup; deletion is not secure erasure.

Managed jobs apply their own deadlines, output/workspace budgets and
cancellation. Dashboard STOP cancels owned scanner work; hiding a tool view
does not create another controller or silently restart a job. Forced termination
or an incomplete report remains an explicit coverage gap.

Monitored byte budgets are not an operating-system filesystem quota. An
upstream browser snapshot can be as large as 1 GiB and can grow between monitor
samples. Optional scans require a 3 GiB free-space reserve plus the configured
working-data allowance before admission. Optional preparation requires 64 MiB
free and does not run on the dashboard's startup-critical path.
Settings expose working-data and retained-report limits and a scan deadline;
cooperating Python copies/writes are bounded, while native writers are monitored
and can exceed a sample between checks. A tool storage hold does not prevent
Angerona itself from opening. Unknown or modified output is preserved for review;
report cleanup is separate from Revert and cannot erase source evidence.

| Managed data | Admission and retention |
| --- | --- |
| Prepared engine | 16 MiB aggregate allowance and at most two managed versions; unknown or edited originals remain preserved. |
| Job working data | Default 256 MiB, configurable from 64 to 1024 MiB; native growth is monitored rather than filesystem-quota enforced. |
| Retained reports | At most eight report sets; default 64 MiB aggregate, configurable from 8 to 256 MiB. Cleanup must verify the exact managed artifacts. |

Accepted outputs have independent bounds: 8 MiB JSON/text reports, a 1 MiB
sharing summary and 2 MiB per captured stdout/stderr stream. Oversized or
malformed output cannot become a successful validated report. Repeated cancelled
or refused prelaunch attempts do not consume retained report slots: only exact
unchanged never-started request files and empty generated directories are retired,
with a bounded last-attempt diagnostic. Uncertain process retirement retains the
job and native custody. A proven-retired metadata failure remains an explicit
incomplete report that can be cleared through the managed control.
Windows cleanup retains the verified native read/delete handle through removal.
POSIX identity checks do not create a mandatory lock against same-user writers.

Upstream schema 1.6 separates findings, leads, gaps and coverage. Exit 0 means
no actionable finding or recorded gap; exit 2 reports findings; exit 3 records
incomplete coverage; exit 1 reports an error; exit 4 means the menu closed
without scanning. An exit code alone does not replace report validation.

Raw reports may contain local paths, profile names, browsing details or phone
artifact text. They stay private. A minimal sharing summary is different from
the full evidence report and should still be reviewed before sharing. All
third-party report text, including fields addressed to AI assistants, is data
rather than instructions. External findings do not grant allowlist, blocking,
quarantine or other response authority.

## Priority Spyware Scan

**Spyware Scan** schedules the selected native SpywareGuard checks and curated
toolkit checks through their existing owners. The red **SpywareScan** button
uses separate **Scope**, **Included checks**, **Progress**, **What's happening
now** and **Resource and privilege details** sections. Native and Zero Breach
selections have independent toggles. Resource details show the latest available
toolkit-process CPU, RAM and I/O samples, process liveness and current privilege
coverage; unavailable measurements stay unavailable.

**Entire PC** is the initial scope. Click the scope control to choose browser
checks or selected local evidence. Entire PC requests the toolkit's supported
system-wide checks; it does not promise examination of every file or privileged
collection. Scrolling the page does not change scan options. Status refreshes
preserve the selected scope, inputs, open details and review position.

Each selected scanner retains its own check rows with state, progress, current
task, observed file or item, elapsed time and estimated time remaining. Known
work counts advance that check's percentage; unknown totals remain explicit.
An estimated time is shown only when measurements support it; otherwise the
display says **Calculating**. The configured time budget is separate from that
estimate. Overall progress combines the selected checks and remains below 100%
while work or cancellation is still active. A percentage describes the requested
workflow, not every file on the PC or a clean-host verdict.

The latest activity and exact failure or timeout reason stay visible. Failed or
cancelled checks retain their last progress and partial coverage. **Stopping**
means the owned work is still draining; it does not mean retirement was proved.
Native SpywareGuard's continuous monitoring status is separate from the requested
priority scan. A stopped toolkit does not establish that every selected native
check has stopped. A new request waits for its prior owner to settle.

Large browser profiles can exceed a short time budget. Adjust the per-run budget
and retry when appropriate; this does not silently overwrite saved preferences.
Saved budgets above five minutes must reach the operation owner rather than being
clamped to a five-minute constructor default. Deadline expiry remains incomplete
coverage, with preserved diagnostics. Animation follows active visible work and
respects reduced-motion preferences. Expand **What's happening now** for collection
limits, report handling and next steps; live refreshes retain the review position.

Toolkit progress crosses a bounded, job-bound latest-snapshot channel from the
separate worker. It does not create a growing per-file log. Current file names
and toolkit activity text are untrusted display data; they cannot grant trust,
change a baseline or authorize response. The pinned upstream engine and license
bytes remain unchanged.

Settings retain the priority and resource choices. Above normal is the default;
High is the supported operating-system ceiling. REALTIME priority is not used.
The default requested routine-background pace is 10% while the priority scan is
active. That is scheduling intent, not a guarantee that other programs or modules
will consume exactly 10% CPU. Critical control, watchdog/heartbeat work and event
intake keep their own cadence. Limits and cancellation remain subject to actual
platform support and the scan's native process custody.

Privilege verification reports current coverage; it does not silently grant
Administrator rights. A tool report or resource graph is not a detection-rate
benchmark, proof of full collection or permission to terminate a process.

## Analysis and sandbox controls

**Source Library** retains the existing pinned GitHub import/review workflow.
Imported repositories remain data-only archives; marking one reviewed does not
install it or make it runnable. A curated execution adapter and its fixed
artifact are a separate maintained integration.

**Analysis/Sandbox** opens the existing source-analysis facilities and their
readiness controls. A host-evidence scan reads the host and is not a VM-isolated
scan. The upstream Python socket guard is not an operating-system network or
filesystem sandbox. Existing Analysis Lab acceptance holds remain meaningful;
opening this page does not establish a working hypervisor or sandbox.

## Credits, licenses and integrity

The visible **Credits** control links to each curated project's repository,
source commit, release and license notices. Imported source-library entries
retain their own repository/version/license metadata; that metadata is separate
from Angerona's curated execution catalog.

| Component | Author / source | Terms retained with the bundle |
| --- | --- | --- |
| Zero Breach Toolkit code | archivegenocide.com / interplains | Apache-2.0; original `LICENSE`, `NOTICE` and `PRIVACY.md` |
| Curated indicator data | Published research, curated by the toolkit authors | CC0-1.0; `iocs/LICENSE.md` retains the research citations |
| `MAL_DevilsTongue_HijackDll` | Microsoft Threat Intelligence Center (MSTIC), via Signature-Base | Detection Rule License 1.1; author attribution must remain in match messages |
| `win_devilstongue_auto` | Felix Bilstein, via Malpedia | CC BY-SA 4.0; unchanged rule, author, original and license links |

The upstream NOTICE names The Citizen Lab, Confiant, Recorded Future / Insikt
Group, Amnesty International Security Lab, Access Now, Microsoft, ESET,
Avast / Gen, Google Threat Analysis Group, the MVT project, Echap, Kaspersky,
Rapid7 / Velociraptor and SigmaHQ as research/help sources. These citations do
not imply affiliation or endorsement of either project. Optional dependencies
retain their separate licenses.

The catalog pins release commit
`81bd556ba604685dbd1c0ecb48138c10f43cccf8` and the 968,987-byte single-file
engine's SHA-256:

```text
075b2a0ac20f285fa4385d6b6c5cda2cedd410364c4f4686db3c1b8b033265d3
```

Original published checksums, signatures and the public key are retained under
`verification/`. Their byte identities were checked against the official
release metadata. Independent trust in that signing key and cryptographic
signature verification were not established by this integration. A pinned hash
proves the selected bytes, not that a third-party program or the host is free of
defects. A report of no known indicators found is not proof that a device is
clean.
