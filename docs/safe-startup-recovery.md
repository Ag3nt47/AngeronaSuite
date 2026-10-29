# Safe Startup recovery

Windows source Safe Startup opens an independent native dashboard before Python
and dependency checks. It then tries a fixed sequence of verified alternatives
while showing the failed phase, attempted actions and remaining uncertainty.
Every candidate needs fresh checks and the live dashboard-ready handshake.
A recovery window is not a running protection engine.

![Safe Startup decisions and recovery boundaries](../assets/security-flow-startup.png)

## Controls

**Settings > General** exposes automatic startup recovery and GitHub source recovery. Both
default on for the normal source profile. The master control disables automatic
recovery mutations; the GitHub control independently disables public source
fetches. Invalid or ambiguous retained settings hold automatic recovery instead
of silently enabling it. Neither control grants installed Protect,
administrator, allowlist or baseline authority.

With automatic recovery disabled, startup still inspects for unresolved
source/runtime transactions. A mixed or ambiguous state holds the engine until
custody can be proven; the recovery interface can still show the reason.
Enabling recovery does not authorize overwriting a new concurrent editor change.

## Ordered alternatives

After the fixed operational files are verified, the source supervisor starts the
OS Windows Forms startup dashboard without importing Python, Qt or application
code. It waits up to 20 seconds for a first-paint receipt tied to the exact
supervisor and shell PID generations and the current run. Only then do backend
checks begin. The native window remains responsive while those checks and
eligible repairs run in owned background processes. Missing or unsafe reports
leave it open with **Verification pending / Protection unavailable**.

The shell follows bounded private status records from its own run. It closes
automatically only after the supervisor verifies the real dashboard-ready
handshake. A successful setup-only check does not count as an open dashboard.
**Retry safe startup** becomes available when recovery is held. **Close** during
checking cancels further attempts; the current bounded check may finish before
the supervisor stops. Neither button executes diagnostic text or grants response
authority. Closing the shell does not terminate an unrelated or possibly live
engine.

If the supervisor cannot prove retirement of an owned command, it retains that
command's native job/process handles and startup leases. The shell shows
**Process retirement requires review** and disables Retry. Closing the interface
cannot grant a second attempt against ambiguous process ownership.

The normal unelevated source supervisor can try ordinary startup, software Qt
rendering, a dashboard path without the Tk startup window, and one independently
verified runtime repair for a recognized runtime/dependency/native GUI failure.
For a qualifying application-code failure, it can restore a retained
dashboard-ready snapshot, then exact canonical GitHub HEAD or its first parent
as candidates. The installed release retains its signed repair boundary.
Each explicit Retry starts another bounded round; this is not an unbounded loop
of downloads, child processes or writes.

Launcher admission, scratch, process-capture and monitoring failures are
infrastructure outcomes. They do not establish an application-source defect and
cannot select source rollback or runtime reinstallation. The diagnostics retain
the failed phase and native result; Retry repeats the ownership checks. A
genuine returned application failure remains eligible for its scoped recovery.

Each disposable dependency/import probe has its own 30-second phase budget,
inside a 100-second overall probe budget. Exit **85** identifies infrastructure
failure, **87** identifies a timed-out disposable probe whose owned process tree
was retired, and **1223** identifies cancellation. A retired probe timeout may
try the independently verified path without the Tk startup window once. These
outcomes do not select source rollback. Exit **1** becomes an application-code
candidate only after successful probes and a verified dashboard-child failure.

An alive or unretired dashboard, occupied runtime, cancellation, unsafe path,
missing trust, low persistent disk space or ambiguous custody stops automatic
mutation. Read-only source inspection and launching an already coherent runtime
can coexist with another diagnostic job using that runtime; replacing the runtime
or publishing changed application source still requires exclusive mutation
custody. A timeout cannot justify a second engine or killing a process guessed
from memory use. The native startup shell needs no Python/Tk/Qt runtime; the
separate source-review interface retains its existing fallback. No source program can guarantee a functioning
window when the operating system's windowing services are unavailable.

## Preserve edits before source rollback

`tools/startup_source_recovery.py` imports no Angerona package. The parent holds
exclusive startup/repair authority and proves no active core before source
publication. Only first-party Python under `src/angerona` and `src/srt` is
eligible. Settings, credentials, keys, evidence, baselines, Git metadata,
dependencies and external modules remain outside this rollback. Operational
startup files have their separate pinned recovery-bundle boundary.

Operational restoration has a separate post-ready notice listing restored files
and private preserved originals. A changed file is not automatically proven to
be the individual cause of the crash. Intentional startup/trust-check edits
require maintainer review and rebuilt pins; there is no automatic trust override.

Source candidates must also meet the current STOP lifecycle compatibility floor.
An older snapshot or GitHub parent cannot undo the fix that prevents watchdog
resurrection after operator STOP. Legacy edits stay preserved for review and must
include that remediation before they can be scheduled for restoration. The
version marker prevents a known incompatible downgrade; it is not a security
attestation or permission to act on the host.

Dashboard STOP and tray Quit first persist the authenticated operator stop,
then fence new AI requests and watchdog launches, unload configured resident
models, and retire Angerona-owned helper/process generations. A shared Ollama
daemon is preserved; model files remain on disk. A failed primary stop write
leaves the dashboard open with an error so the operator can retry.

Modern sign-in and automatic recovery launches carry an inhibition-only marker
and honor that stop without reopening the dashboard or starting another repair
round. An explicit source launch clears the previous authenticated stop once,
after the full preflight, and its child honors any new stop during warmup.
Check-only startup does not resume protection. Prepared native launchers must be
rebuilt and signed before installed users receive this behavior; legacy signed
binaries do not acquire it from a source publication.

The helper preserves the complete eligible failed source and manifest before
publication. File identities and digests are rechecked; a concurrent editor
change holds recovery. Private transaction/progress records identify partial
publication. A later launch reconciles only its own provable before/after file
generations; unknown edits remain in place and the engine stays held. It does
not reset, merge or rebase Git, or erase an unknown pending transaction.

After a recovered dashboard is genuinely ready, a separate review offers:

- **Keep working:** keep the recovered version; retain the original through the
  decision and permit bounded rotation of that resolved backup on a later failure.
- **Try preserved edits next startup:** schedule restoration for a later exclusive
  startup. It never changes code under the running dashboard.
- **Review later:** retain undecided originals; recovery cannot evict them merely
  to fit a new failed candidate.

A ready snapshot must match the source fingerprint captured before launch.
Post-import editor changes cannot acquire a false known-ready label. Readiness
means that revision opened a responding dashboard; it is not a security
attestation or a guarantee of future stability.

## Capacity and retention

| Data | Limit and behavior |
| --- | --- |
| Source snapshots | Two ready snapshots and one preserved failed candidate at most; each archive up to 64 MiB, 4096 files, 2 MiB per file. Requires 2 GiB free reserve plus staging. Capacity holds preserve undecided edits. |
| GitHub candidate | Compressed and eligible expanded source each up to 64 MiB; fixed endpoints, verified TLS, exact commit/tree/blob identities and scoped publication. |
| Operational recovery originals | Private quarantine up to 32 MiB with an entry cap; full quarantine holds repair without deleting unreviewed originals. |
| Runtime repair admission | Requires 5 GiB free before new work: 2 GiB reserve plus 3 GiB conservative transaction capacity. A retained full runtime backup holds another full repair (maximum one). At most two recognized repair-wheel staging transactions including the new one. Unknown/malformed retained work is held for review. |
| Recovery diagnostic viewer | Status/report up to 64 KiB; requested log view up to 128 KiB. Untrusted text is displayed literally. |
| Parent startup diagnostics | Supervisor journal rotates at 512 KiB with three retained generations; child capture retains up to 8 MiB per stdout/stderr stream and counts drained overflow. Persistent failure details survive scratch cleanup. |
| Startup scratch | Only immediate named `startup-temp.*` attempts are inspected. Per base: at most 32 attempts, 128 files per attempt, no unknown nested directories, 256 MiB aggregate with 32 MiB reserved for a new attempt and 2 GiB free reserve. Full capacity holds; it does not erase unreviewed evidence. |
| ShadowShield file recovery | Separate configurable cache cap/reserve, admission holds and visible storage controls. Default cap 2048 MiB. Deleting copies removes their file restore points. |

These separate budgets do not cap total suite disk usage. Case evidence,
protected history and pending transactions can require operator review. Use
**Settings > System > Drive space and recovery data** and the storage warning
to block, delete, allow or change cache policy.
Do not delete evidence or keys as a generic cleanup workaround.

The core's direct `startup-dashboard.log` stream and native installer command
logs are not hard-capped for their entire lifetime. Parent capture limits do
not change those producers. Retention/storage review is still required for a
long-running noisy core or a large native installer failure.

Runtime repair reconciles a proven prior transaction before admitting a new
candidate or download. Its 3 GiB capacity allowance is an admission estimate,
not a measured hard quota on every installer byte. Retained runtime backups and
wheel stages are not automatically deleted; the error identifies the exact
owned roots for review and freeing space before Retry.

## Diagnostics and egress

Source diagnostics live in
`%LOCALAPPDATA%\Angerona\SourceData\logs\startup-recovery`, including the
supervisor journal, current status and bounded command capture.
`startup-preflight.log` and `startup-dashboard.log` retain the Python probe and
dashboard explanation, plus previous copies. Private source recovery reports,
index and archives live in `SourceData\startup-recovery`. Missing logs are
explicit. Redaction is bounded best effort; review raw diagnostics before sharing.

GitHub recovery sends HTTPS reads to the fixed
`api.github.com/repos/Ag3nt47/AngeronaSuite` Git APIs and
`codeload.github.com/Ag3nt47/AngeronaSuite` archive endpoint. Operational recovery
fetches exact pinned public Git blobs. It uploads no host evidence or failed
edits; the server still sees request metadata and requested public identities.
Ambient proxies, redirects and imported URLs do not become recovery authority.
GitHub documents [blobs](https://docs.github.com/en/rest/git/blobs),
[commits](https://docs.github.com/en/rest/git/commits) and
[trees](https://docs.github.com/en/rest/git/trees).

Runtime repair separately uses reviewed PSF-signed Python, hash-locked
dependencies and reviewed local packages. Independent ABI, dependency, Tk/Qt
and startup gates still apply. A download or successful `pip check` alone is
insufficient. No Ollama start or AI-generated repair command is needed.

## Independent entry for signed package builds

The release build prepares `AngeronaSafeStart.exe` as the MSIX application
entry. It uses the OS .NET Framework/Windows Forms independently of Python,
Tk, Qt and Angerona application imports. It verifies the embedded SHA-256 of
its fixed sibling `AngeronaStartup.exe`, retains native read leases on the
helper and its ancestry, and monitors the exact created process handle and
creation time. Its 180-second deadline cannot attest a ready dashboard; a
possible live helper/core is preserved and another attempt stays blocked until
that exact helper exits. A user can close the independent interface without
killing existing work.

`--verify-bootstrap` checks the fixed pin/path without launching the helper.
The wrapper accepts no alternate executable, root or digest on its command
line. Its recovery UI links the official release page only after a user click;
it never downloads raw replacement code into a signed package.

The helper must reach its final signed bytes before the wrapper's digest is
embedded, and the wrapper must then be signed. Any later helper-byte change
requires rebuilding and re-verifying the wrapper before release acceptance.
The repository's external release-signing authority remains unprovisioned and
publication-disabled. These build/source capabilities do not claim an accepted
signed release or create publisher/service authority. See the
[release signing boundary](enterprise/RELEASE_SIGNING_BOUNDARY.md).

## Cache deletion and the observed dependency failure

The observed failure was the reviewed dependency check rejecting installed
`certifi 2026.10.23` against the `2026.10.19` pin, before the storage settings UI
loaded. Removing approved file recovery copies does not alter that dependency
version. Cache deletion and runtime/source repair are separate operations;
startup must tolerate an empty disposable cache.

## Trust and validation limits

Source pins verify reviewed bytes relative to the local launcher anchor. The
writable checkout and batch file are not an independent trust root against the
same user or a hostile administrator. GitHub history is a candidate, not proof
of clean, current or compatible code. UGCAP, installed authority, producer
evidence and response approvals retain their existing gates.

The [security-flow matrix](security-flow.md#attack-surface-review-matrix) maps
focused regression suites to the implementation. README historical totals remain
dated evidence; final validation and fresh runtime observation are separate
receipts for the published revision.
