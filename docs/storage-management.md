# Drive space and recovery data

Shadow Shield keeps earlier versions of Documents and Desktop files for
ransomware recovery. These are file recovery copies, separate from scan reports.
Previously, keeping six versions per file did not limit the total cache across
many files. The cache now defaults to 2,048 MiB, with a 2,048 MiB free-space
reserve on its volume. New copies must fit both limits, including staging and
source-mapping metadata. Existing copies count after restart.

Open **Settings > System > Drive space and recovery data** to change the cache
limit, reserve or permission to create recovery copies. The cache limit accepts
64–16,384 MiB; the reserve accepts 512–65,536 MiB. Save Settings to persist the
choice. Reducing a limit holds new copies; it does not automatically delete
existing recovery points.

## Storage warning

The dashboard checks the data and temporary-file volumes asynchronously,
including while recovery collection is paused. Shared volumes are checked once;
the warning names the affected drive and retains unavailable measurements.
It warns when the cache reaches 80% of its limit, storage
admission is held, or available space reaches the configured reserve. New
recovery writes are held while a warning awaits a decision. Repeated readings
of the same condition do not open repeated dialogs. Holding optional recovery
writes does not require closing the dashboard.

- **Block new recovery data** holds new recovery copies and automatic shadow
  requests for this run. Save the corresponding Settings choices to retain the
  block after restart.
- **Delete recovery copies** asks for a second confirmation before removing
  recognized Shadow Shield cache artifacts. Original documents remain intact.
- **Allow / change limits** opens Settings. Saving the policy can admit new
  copies within the configured limit; it does not bypass the free-space reserve.

Deletion runs outside the GUI thread with the cache writer excluded. It checks
plain directory ancestry and exact regular-file identities, rejects links and
hardlinks, and preserves unknown or pinned artifacts. Work has entry and time
limits; the worker continues bounded passes while time or entry limits are the
only interruption and each pass makes progress. One request stops at completion,
cancellation, unsafe or unavailable input, no progress, 256 passes or 30 minutes.
The controls show cumulative progress and an explicit complete or incomplete
result. Another request can continue remaining cleanup. Filesystem calls can
exceed the cooperative time budget. A successful request is not a claim that
other applications have stopped using the drive.
The worker releases I/O custody between passes while admission flags continue
to block copies, so primary policy and observation turns can advance during a
long deletion. Maintenance remains explicitly limited recovery coverage.

Older copies can inherit a source file's read-only flag, including interrupted
staging files. Cache cleanup, six-version pruning and owned staging retirement
now use identity-bound deletion that handles those artifacts without rewriting
their attributes. On Windows, read-only deletion uses the documented
[handle disposition flag](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex).
Unsupported operations preserve the file and report incomplete work. The shared
alert-archive writer and original documents are outside this deletion path.

## Windows source startup working space

In Windows source Safe Startup, retained logs and recommended free-space reserves
do not prevent normal dashboard startup. Its critical launch route reuses four
fixed purpose folders per canonical temporary-data base, with a 32 MiB / 128-entry
admission budget per folder. Managed startup capture uses the remaining byte
budget; this is not a filesystem quota on general runtime temporary-file writers.
An inherited native lease prevents clearing a folder while an original or
orphaned producer still holds it. Only recognized disposable outputs can be
retired for reuse; legacy nonempty logs, unknown files and security originals
remain preserved.

The launcher can proceed below the native 2 GiB and Python 128 MiB recommended
reserves after proving its actual private read/write access and critical lease.
An unusable filesystem, unsafe path or ambiguous process ownership still needs
attention. The process-helper compiler retains its separate 2 MiB / 120-entry
content guard. Downloads, runtime replacement and source snapshots retain their
own admission requirements; a storage hold on that optional work does not turn
retained diagnostic history into a dashboard permission check. See
[Safe Startup recovery](safe-startup-recovery.md#capacity-and-retention).

## Windows shadow copies and other data

Automatic Windows VSS snapshot requests now default off. Their advanced opt-in
is separate because Windows shadow differences can grow after creation and may
be stored on another volume. Review Windows shadow-storage allocation before
enabling it. Angerona does not resize Windows shadow-storage quotas or delete
existing Windows shadows through the recovery-cache control. A reserve check
before a request is not a quota on future VSS growth.

Disposable runtime-alert diagnostic archives have their existing independent
30-day / 256 MiB retention defaults. Their Settings control excludes signed
event history, pending events, case evidence, action receipts and exports.
The storage warning does not authorize a broad sweep of temporary folders,
recovery evidence, baselines, signing keys or databases. Low free space can be
caused by other applications, and security evidence can require a separately
reviewed retention or relocation decision.

Cache admission has bounded inventory work, including source and entry limits.
Incomplete or unsafe inventory holds new copies and reports limited recovery
coverage. These controls bound admitted cache content; they are not a total
quota for every file on a drive or a guarantee of complete ransomware recovery.

## Validation

The final focused integration gate passed 218 cases with seven platform
or privilege skips. It covered cache admission, exact-artifact restoration,
read-only cleanup and retention, custody and cancellation, stopped-module and
multiple-pass maintenance, inter-pass primary progress, restart writer exclusion,
storage dialogs, configuration, alert retention and affected Settings and shutdown
paths. Source digests stayed unchanged throughout that run; all five retained
owned process handles signaled completion and were closed.
Lint, in-memory syntax checks and offline documentation validation also passed.
These are scoped offline and offscreen results, not a full live-host observation.
