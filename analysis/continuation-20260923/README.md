# September 23 continuation: Analysis Lab and Ollama

This continuation addresses the two native acceptance gaps left after the
[three-round review](../deep-review-20260923/README.md): VMware could not start
under its configuration seal, and elevated Ollama startup needed real Windows
testing. Product version remains **v1.13.0**, with **84 catalog capabilities**.
The QEMU backend adds no module to that count and no resident idle VM.

## Analysis Lab

The Lab now has a separate **QEMU 11.1.0 backend for 64-bit Intel/AMD Windows**.
It runs pinned **Bandit 1.9.4** and **Gitleaks 8.30.1** against a bounded copy of
local UTF-8 source. Submitted code is inspected as data, never executed.
Reports contain redacted findings and have no native response authority.

Workstation needs to write its VMX configuration while running. Allowing that
would break the existing custody guarantee. Its backend and seal remain
unchanged in that respect; QEMU supplies the complete device configuration in
fixed arguments instead. An existing VMware VM is not used by the QEMU Lab.

### Optional setup and use

Use a normal, non-administrator Angerona session. Full Setup's **Optional
Analysis Lab** step and the Lab setup dialog explain what the scanners do,
resource costs and the **Skip** choice before any setup action. Monitoring,
automatic defense and Ollama work without the Lab.

1. Choose **Download and configure the optional Lab emulator**. Setup reuses an
   exact matching QEMU installation or downloads the reviewed installer. Keep
   the vendor's default `Program Files\qemu` destination. Its normal installer,
   license and UAC prompts remain visible; a separate administrator prompt
   creates the protected Lab copy. Cancel through the native prompts if needed.
2. Choose **Prepare runtime** to acquire and verify the pinned guest tools.
3. Choose **Check readiness**. Both actual guest fixtures must produce their
   expected findings for the current catalog/runtime identity before Run is
   enabled. A recheck retires any stale readiness result first.

| Cost or boundary | Current implementation |
| --- | --- |
| Emulator download | About 197 MiB; full vendor installation when needed. |
| Protected Lab copy | 109 files, 127,443,388 bytes (about 122 MiB), including two ROMs and the recursive DLL closure. |
| Setup free-space check | At least 2 GiB on the Windows application drive. |
| Guest resources | One virtual CPU, 768 MiB RAM, single-threaded TCG emulation. |
| Host process limits | One process, 2 GiB memory, 25% of total host CPU capacity, below-normal priority. |
| Job duration | At most five minutes; bounded output and cancellation. |
| Guest devices | No external NIC, block disk, host folder share, monitor, user configuration or arbitrary plugin. |
| Idle behavior | Manual analysis only; no Lab VM remains running after a job. |

The distributor's installer has an expired signing certificate. This path
trusts an explicitly reviewed artifact identity with pinned SHA-256/SHA-512
checks, then verifies the exact runtime file set and each file's bytes. It does
not describe that certificate as currently valid. See
[runtime provenance and design](qemu-design.md).

Diskless describes the guest. Source snapshots, redacted reports and runtime
artifacts exist on the host; normal Windows paging and crash dumps also apply
to host memory. These controls do not establish a no-trace forensic environment
or immunity to administrator/kernel compromise.

### Hardening and native corrections

The runtime namespace is administrator-owned and excludes ordinary-user
mutation. Files stay sealed against writes/deletion, and ancestor handles
prevent directory substitution during setup and execution. The child starts
suspended; the exact executable and same-user medium token must verify, and
the process must enter its kill-on-close Job Object, before it resumes.
Cleanup uses owned process handles rather than a PID supplied by input.

The independent adversary pass identified and re-reviewed three corrections:

- Validate the generated setup archive's exact members, sizes and hashes while
  holding its seal, before authorizing privileged copying.
- Retain destination ancestor handles inside the privileged helper as well as
  the parent, through copying and cleanup.
- Override compiled GnuTLS/OpenSSL configuration and provider search defaults
  with fixed disabled paths; a minimal inherited environment alone was
  insufficient.

QA also corrected the setup bootstrap to establish its trusted PowerShell
module path using .NET before any cmdlet could resolve. Native read-only and
contract checks passed after the ordering change.

Native execution exposed a Windows serial-input bug that mocked tests missed.
The guest now enters cbreak mode before READY and receives one start byte
through its exclusive inherited pipe. This avoids dropped bytes without
timing-based pacing; per-job UUID and report checks remain mandatory. The v3
profile explicitly disables the unused VAPIC ROM while preserving ordinary
APIC operation and the reviewed two-ROM runtime.
[Independent boundary review](qemu-adversary.md).

**Both real analyzer readiness checks passed** with the current v3 profile,
guest image and 109-file runtime. Reports were schema-valid with loopback only,
zero block devices, no host shares and no analyzer errors.

| Native fixture | Expected finding | Elapsed time | Peak emulator RSS |
| --- | --- | --- | --- |
| Bandit | B101 | 117.328 seconds | 408,109,056 bytes |
| Gitleaks | github-pat | 62.593 seconds | 472,223,744 bytes |

Loaded DLLs came only from the protected runtime or Windows System32/WinSxS.
Both owned emulator processes were reaped, and no QEMU process remained after
the check. Readiness returned true and the saved result matched the current
catalog identity. These are explicit analysis-job measurements on this machine,
not idle usage or a speed guarantee for other hosts.

The original Gitleaks token was an alphabetical fixture covered by its
legitimate allowlist; it was replaced with a locally generated, never-issued
value. The earlier valid empty report was not counted as a passing detection
check.

A separate end-to-end source scan completed in **47.719 seconds**. Gitleaks
reported the expected redacted `github-pat` finding, remapped its opaque input
name to the original source path and retained `response_authority: false`.
Its isolation inventory again showed loopback only, zero disks and no host
shares. Cancelling a second VM reaped its process without adding a history
entry or retiring the established readiness result. The offscreen GUI showed
the expected ready state, report and history.
[Native Lab acceptance](native-lab.md).

## Ollama

Native elevated Windows tests reproduced a failure in the previous startup
implementation: Windows supplied the elevated user's linked, limited medium
token as an **impersonation token (type 2)**. The implementation required a
primary token immediately and stopped before creating a process.

The candidate verifies the linked token's user, session and limited medium
authority before a narrowly requested `DuplicateTokenEx` conversion. It checks
the resulting primary token again, then independently verifies the suspended
child's token and executable before resume. There is no administrator fallback.

Native, non-elevated token-only controls prove that level-2 impersonation tokens
convert successfully, while identification-only level-1 tokens fail with
`ERROR_BAD_IMPERSONATION_LEVEL` (1346). These checks did not create a process.
The earlier elevated diagnostic did not record the linked token's impersonation
level. This candidate therefore is **not yet proven to fix this host's elevated
startup**; conversion cannot supply authority the source token lacks.

The focused Ollama regression suite passed **146 tests**, including two real
Windows token-only regressions. The candidate native
acceptance request was cancelled at UAC with Windows error **1223**; that
bootstrap did not execute. Any future consented retry needs a freshly reviewed
probe matching the current source. **Elevated startup is not yet natively accepted.**
[Probe design, evidence and limits](ollama-native.md).

The earlier normal-user Windows cold start reached 100% in 16.44 seconds with
no loaded model. That remains separate evidence: service readiness is not model
approval or inference. Deterministic detection and policy-authorized response
operate without Ollama.

## Validation and remaining work

The first full offline run recorded **4,103 passed, 19 skipped and 3 failed**
in 705.51 seconds. The failures were stale VMware expectations after the QEMU
job-runner change; the corrected affected Lab gate passed **188 tests**. A
skip audit also repaired a hard-link fixture whose destination already existed;
its entire **six-test** file then passed, including actual hard-link rejection.

The final Lab selection passed **192 tests** after three unsupported-architecture
cases and a visible-panel setup/Skip refresh regression were added. Unsupported
machines are rejected before downloading the emulator, and closing setup now
refreshes readiness in the background without requiring the panel to reopen.

This reconciles the original population to **4,107 passed and 18 skipped**.
It is a full baseline plus focused correction checks, **not a second full-suite
execution**. Fourteen remaining skips require Windows link privileges absent
from this normal-user session; four require POSIX or native Mac/Linux checks.
Compilation of **393 package** and **56 tool** sources, focused Ruff checks and
documentation drift passed. The later **146-test Ollama gate** includes the
two native token-only controls described above. Overlapping selections must
not be added into a unique total. [Detailed validation and fixture corrections](validation.md).

The published predecessor's Python 3.10–3.13 CI, native Mac Intel/Apple Silicon
and Ubuntu installation checks are historical evidence for that commit, not
new acceptance runs for this continuation. See the
[publication follow-up](../deep-review-20260923/publication-followup.md).

Elevated Ollama startup remains an open native acceptance boundary. Native
macOS/Linux Lab execution, arbitrary imported program execution, and broader
comparison-research proposals are not shipped by this update. The VMware
configuration-write incompatibility remains. Publication uses the guarded
publisher to verify canonical origin, fast-forward main, a clean worktree and
all public README image bytes.
