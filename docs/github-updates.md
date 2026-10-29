# GitHub update checks and preserving custom code

Current development version: v1.14.2. This feature has two separate parts: discovering changes and preparing a
source candidate. Preparing a candidate does not install it.

**Historical validation:** daily/settings/setup/manual controls passed 179 focused cases
with one optional native-8.3 skip. Frozen full R10 passed 7,554/0/49 for its
exact snapshot; later installer/tooltip changes passed 141 controls and a
default 29-phase selfcheck. Those are separate scopes. Daily checks default off;
preparing or downloading source never authorizes installation. Activation
remains held until trusted release, recovery and runtime checks are satisfied.

The October 28 review separately exercised 266 updater cases with one native
availability skip and the actual shared discovery transport. Canonical main
returned HTTP 200; no stable release returned HTTP 404 and was reported as
unavailable for installation. App and selected package metadata agreed on
1.14.1. This read-only check did not download a payload or change preferences.
See the [current review](../analysis/startup-storage-recovery-2026-10-28.md).

## Choose when Angerona checks

Open **Settings → General** and toggle **Check GitHub for updates once a day
while Angerona is open (network)**, then save. The same choice appears in
**Full Setup → Updates and storage**, with the other current feature settings.
It starts off. The setup review includes it among optional network features.

**Check now** works independently of the daily preference. It runs in the
background and displays its result in Settings. Turning daily checks off stops
their scheduling and revokes automatic prompts from an outstanding check.
An explicit manual check remains an operator request.

Checks use the public `Ag3nt47/AngeronaSuite` repository. Source `main` and
published stable releases are reported separately. A different source revision
does not prove that the running checkout is older or that a release is safe.
Unavailable metadata or source identity is shown as unknown.

The app and CLI share a file lease and persisted attempt timestamp. Automatic
attempts are limited to once per 24 hours; failed attempts also count. Manual
checks retain a 60-second retry floor. A clock rollback holds the check.
Daily checks run while the application is open. The CLI can be scheduled
externally for use while it is closed; Angerona does not install a scheduled
task or service for this option.

```powershell
python tools/check_github_updates.py --json
python tools/check_github_updates.py --check-now --json
```

## Download without replacing local edits

When an observed source revision differs, the dashboard offers to prepare an
isolated source candidate. Declining keeps the working installation unchanged.
The Yes/No question defaults to No and describes candidate preparation. It does
not authorize activating the candidate or granting installed-release trust.
Preparation requires a canonical source checkout, a known canonical ancestor,
and the installed trusted Git runtime. Missing prerequisites hold preparation.

The candidate is stored below the configured data directory at
`github-updates/stages/source-<identifier>`, outside the source installation.
Preparation retains the base, user and upstream bytes in content-addressed
blobs. Local committed changes, working-file edits, deletions and non-ignored
new files are included as file content. Ignored files remain in the original
installation and are excluded from the candidate.

Source preparation admits at most two retained candidates and 2 GiB of total
logical candidate data, with a separate 2 GiB free-space reserve on the stage
volume. Admission happens under the shared stage lease before a new download.
Resolution and validation use the same capacity checks. Unknown entries,
unsafe paths or incomplete accounting hold preparation for review; the updater
does not silently delete earlier candidates to make room. A low-space validation
result may be shown without persisting another report, and says so explicitly.

Clean, disjoint UTF-8 edits can be merged automatically. Overlapping edits,
different binary content, incompatible additions or deletions, and work-limit
violations remain conflicts. LF/CRLF differences can also require review.
Conflicts preserve all available sides; the updater does not guess which code
is correct. The original checkout, index, refs, environment, runtime evidence,
virtual environment and UGCAP baseline remain unchanged.

The CLI also supports `--stage FULL_SHA` with an optional known `--base FULL_SHA`.
Its result prints the stage identifier and exact manifest digest needed for
later review. Use `--help` for the explicit `--resolve`, `--choose` and
`--validate` operations. Review acts only on the isolated candidate.

## Installation remains a separate boundary

### Canonical Windows executable custody (UPD-05)

The inbox PowerShell executable can have multiple hardlinks from normal Windows
servicing. Its dedicated validator uses the exact WinAPI-derived System32 path,
bounded regular-file shape, non-reparse ancestry, native owner/DACL checks and
before/after identity comparison. It does not execute PowerShell to establish
PowerShell's own custody. Release archives, checksums, the protected installer
script and state still require a single link; this exception does not apply to
caller-selected executables. Missing or unsafe custody evidence holds installation
before the elevation request.

Seven full updater suites and an actual read-only refusal check passed218 cases
with exact process retirement. The observed OS-volume-root permissions contain
an unsafe applicable Users grant, so **HOST-03 remains open and installation
custody stays HELD** (`native_custody_accepted=false`). No ACL or validation
policy changed. The detailed review preserves the original failed host assumption
and diagnostic collection refusal, plus the overlapping capture evidence.
Archive audits and guarded-publication receipts retain their own source scopes.

These checks provide snapshots, not a retained executable/file-object lease
through UAC and payload copying, a publisher-signature bootstrap or resistance
to a malicious administrator/kernel. No live installation, UAC or restart-health
result is claimed. A passing test that expects unsafe custody to be refused does
not make the underlying host exposure healthy.

The source-stage workflow retains user changes as file bytes with explicit
conflicts. The packaged-release helper does not transplant those changes into a
signed binary installation. Protected-installer backups and recovery holds
remain separate; source staging does not authorize installation, UGCAP baseline
replacement or automatic destructive conflict recovery.

For scheduled metadata-only checks, inspect structured `status`: a partial
result can exit zero while network metadata remains unavailable. Process exit
alone does not prove that a newer release was discovered or is safe to install.

### Approved verified-release helper

For an existing protected Windows installation, the source tooling now includes
an interactive release updater. Run it from an installed Angerona development
environment, with the suite closed before requesting installation:

```powershell
python tools/update_angerona.py --check-only
python tools/update_angerona.py --check-now --json
python tools/update_angerona.py --download
python tools/update_angerona.py --install
```

The helper shares the app's daily attempt record and manual retry floor.
Noninteractive and JSON invocations only check; they cannot approve an update.
Interactive download or installation requires an explicit decision after the
release tag, asset IDs, size and exact candidate identity are displayed.

It selects only a newer stable `Angerona-vMAJOR.MINOR.PATCH-win64.zip` and its
adjacent `.sha256` file from the canonical repository. Source archives,
prereleases and `-unsigned` build artifacts are ineligible. The observed asset
identity is checked again before downloading. Downloads use bounded private
staging, byte/size/checksum checks and an owned networking worker with a deadline.
The archive must have a GitHub SHA-256 metadata digest, so the approved identity
pins its bytes even if a release asset is later replaced. Older assets without
that digest are held.
Neither GitHub metadata nor the checksum establishes publisher trust.

Installation uses only the already-installed protected
`Program Files\Angerona\Install-Angerona-Release.ps1`. Its custody preflight runs
before an elevation request. The existing publisher-signature, threshold release
authorization and rollback-floor verification remain the installation authority;
no script from the downloaded archive is executed by the helper. Missing trusted
installation files hold the operation and direct first installs to the signed
MSIX. Source staging still cannot activate an update.

The comparison version normally comes from protected installed release metadata.
If it is unavailable, the helper labels its source-version comparison as advisory
and holds installation. An operator who knows the installed version may supply
`--installed-version 1.14.0`; this only selects candidates and cannot bypass the
protected installer's independent rollback checks.

Installed executable candidates are verified by exact path, PID and creation
time. A running or uninspectable candidate holds installation; nothing is killed
by name or memory use. Quit the suite and its installed components normally.
Same-user installation attempts share a lease. A pending, unknown or failed
privileged installation is retained and holds later attempts for explicit
recovery review. A nonzero installer exit can follow partial file changes; it
does not prove that retrying is safe. Do not clear that state to force a retry.

On successful installation the protected installer requests Angerona startup.
The helper reports `restart_requested` and `runtime_health=unverified`; it does
not claim that the restarted suite is healthy. No updater task or service is
registered. Use the existing daily setting while the app is open, or schedule
`--check-only` externally if checks are needed while it is closed.

Pushing ordinary source changes makes them discoverable. End-user installation
requires publishing the verified stable release assets through the existing
release process. It does not apply an arbitrary `main` push to Angerona.

The October 23 helper review passed **128 focused tests** covering release
selection, approval binding, bounded download adapters, installer custody,
running-component holds and recovery receipts. The existing settings,
controller, setup, source-staging and update-authority regression gate passed
**120 tests with one optional native-8.3 skip**. Installer, UAC and process
adapters were inert in these tests. A separate metadata-only public GitHub
check succeeded and the next invocation reused its daily result; no stable
release was published to offer. No live installation or restart-health result
is claimed.

The first full Python 3.10 CI run of helper commit
`f848c01228f325ed0ca8ffb2091459554036bb4f` reported **6 failed, 7,859 passed and
19 skipped**. All six failures exposed a floating-point timeout handoff of
`900.0000000000002` seconds. The handoff now clamps remaining time to the
original approved budget, and networking workers reject invalid budgets before
creating a child. Deterministic regressions cover both 900-second and
0.1-second rounding, elapsed budget reduction and shared-deadline expiry.
The follow-up focused gate passed **139 tests**. Its first attempt also observed
one unexplained Windows staging-rename permission failure; that exact case and
the complete focused gate passed reruns. No permission or rename behavior was
relaxed. Full CI results must be checked for the follow-up commit separately.

### Shared transport deadline follow-up (UPD-06)

The checksum and archive share one absolute transport deadline. Each handoff
is clamped to the original scalar budget, preventing floating-point subtraction
from passing a slightly larger value to the worker. Invalid direct worker budgets
are rejected before multiprocessing setup. The merge retains canonical inbox
custody checks, strict single-link assets and HOST-03's unsafe-host hold.

Current combined-source tests and fresh native refusal: **229 focused checks passed: 228 production cases and one actual native custody-refusal check, with no failures/errors/skips**.
The eleven deterministic additions exercise budget handoff with inert transports;
they do not establish payload networking, installation or healthy host custody.
The historical paragraph above is retained as reported remote evidence; it is
not a current combined-revision CI result. Its unexplained rename refusal remains
unresolved. This change adds no deadline for metadata, hashing, filesystem
staging/rename, privileged installer runtime or entire providers. Actual archive
audits and guarded-publication proof remain separate source-bound receipts.

**Activation: HELD.** Checking, preparing and reviewing a stage do not install it.

Static validation checks candidate hashes, Python syntax, required entry
points and unresolved conflicts without executing downloaded code. It does not
prove runtime health, dependency compatibility or privileged-service behavior.
This phase therefore always holds activation, including a conflict-free stage.

Packaged-installer backup retention is applied and passed 27 confined controls.
Durable crash reconciliation and restart-health proof remain unproven. See the
[recovery review](../analysis/live-debug-2026-10-22/weakness-review.md); staging
cannot grant recovery or release authority.

A future activation workflow must stop the suite, validate an isolated runtime
and dependencies, preserve recovery, verify service compatibility and obtain
explicit UGCAP baseline review when enabled. It must retain the existing
independently pinned signed-release authorization. HTTPS, a Git SHA, a clean
merge and an AI recommendation do not replace that authorization.

Staging currently preserves file bytes rather than Git history or executable
permission modes. Path checks are not an atomic boundary against a concurrently
malicious administrator or compromised kernel.

Protocol references: [GitHub branch metadata](https://docs.github.com/en/rest/branches/branches#get-a-branch)
and [published stable release metadata](https://docs.github.com/en/rest/releases/releases#get-the-latest-release).

Focused follow-ups passed 73 test-only cases and 83 YARA cache cases, followed
by a fresh 29-phase module selfcheck. The historical failed full regression remains
retained; its five failing nodes passed R7, which failed a separate GUI launch
assertion. Later R10 passed7,554/0/49 for its frozen snapshot. These passes grant no
update activation or packaged-recovery authority.

## Maintainer publication staging errors

The reviewed Windows publication runtime now pins Git for Windows
`2.56.0.windows.3` and its UCRT layout: 314 exact files, eight directories and
193,726,694 bytes. The compiled profile digest and aggregate tree authority
remain independent of the JSON document. Runtime discovery does not authorize
an installed binary or a different Git version. A later machine Git upgrade
can therefore hold publication until another reviewed profile update.

This pin was checked against official release archive bytes and selected
payloads from the validly signed official installer. Four preexisting packaging
alias names were individually derived from their exact official Git executable
bytes and checked against the previous reviewed alias relationships; the
published profile contains only literal paths and hashes. It adds no runtime
rename rule, alternate toolchain, downgrade or installed-only trust fallback.
Source/staged handle sealing, credential isolation, canonical origin,
fast-forward-only publication, clean-worktree and public README asset proofs
retain their existing checks.

The guarded publisher may report `private publication runtime copy failed` with
a numeric `errno` and/or `winerror`. These bounded codes distinguish OS failures
without exposing private filenames or raw error text. For example, confirmed
`errno=28` indicates ENOSPC; retain the exact private cause and check available
space before retrying. The code does not relax runtime custody, redirect staging,
remove user files, approve installation or automatically repair disk space.
