# Native Windows acceptance — 2026-09-23

## Ollama

The installed vendor-signed `ollama.exe` passed a real cold-start test after the
test-owned daemon was stopped. Angerona's shared startup helper progressed
through 10, 25, 45, 60, 80 and 100 percent in **16.44 seconds**. The daemon's
resident-model inventory remained empty. No model was downloaded or loaded.

A stopped AI Triage module's explicit Chill self-test also passed with the
service at 100 percent and the model asleep. A subsequent warm check after the
IPv4/IPv6 endpoint-binding correction returned ready/100 percent. These are
service and lifecycle checks, not proof that every installed model is approved
or that inference will succeed. The newly started local daemon remains available.

Native testing found and corrected a Windows connection-refusal timeout and a
Python 3.12 `stat`/`fstat` creation-time mismatch. Final cancellation handling
also rechecks shutdown after executable verification and the deadline before
process creation. The focused final startup/Lab regression batch passed 83 tests.

The final Protect-mode path launches with the elevated user's linked normal
token, never an inherited administrator token. Before resuming its suspended
child it verifies the same user/session, primary limited token, medium integrity,
and exact executable. Only validated model storage is recovered from that user's
environment; credentials are not forwarded. Inert policy/Win32-boundary tests
pass, and a read-only native check of the current normal user's token adapter
passed. **Actual elevated-to-medium process creation remains untested** on this
host; no additional UAC authorization was assumed from the Lab service approval.
Unavailable or mismatched tokens fail closed with manual-start guidance.

## Analysis Lab — not accepted on this host

The maintainer explicitly approved enabling VMware Authorization Service and
testing the Lab. The reviewed, immutable elevated helper verified the installed
service image and vendor signature, set **VMAuthdService to Manual**, and started
it. Native observation confirmed **Running / Manual**. Existing virtual machines
were neither modified nor started.

Workstation 25.0.1 build 25219725 refused the Lab's generated VMX while Angerona
held its deny-write/delete seal. `vmrun` reported a file-access error; VMware's
own diagnostic log recorded `ERROR_SHARING_VIOLATION` while opening that generated
configuration. Adding `config.readOnly = "TRUE"` did not resolve the failure.
Bounded direct-VMX experiments also failed and were not added to production code.
No analyzer receipt or successful native readiness record was accepted.

The seal remains in place. Permitting concurrent writes and merely comparing
the configuration afterwards would reopen the pre-boot configuration race.
The supervisor now explains this specific failure without echoing uncontrolled
VMware output. Its readiness identity binds the fixed VM profile and custody
revision, and a new explicit check invalidates any previous success before it
starts. A failed or cancelled check therefore cannot retain a green readiness
result from an earlier run.

**Remaining work:** a reviewed VMware-compatible custody handoff, or a separately
reviewed backend, followed by actual passing Bandit and Gitleaks guest fixtures.
The UI and offline tests must not be described as proof of a working native Lab.
Installing or configuring VMware alone does not satisfy this acceptance gate.

Broadcom documents `config.readOnly` for
[ESXi](https://knowledge.broadcom.com/external/article/389193); that documentation
does not establish compatibility with Workstation. The optional VMware setup
flow uses Broadcom's official download process, which may require an account
and export-compliance approval:
[desktop hypervisor downloads](https://knowledge.broadcom.com/external/article/368734).

## macOS and Linux

This machine cannot validate native macOS/Linux GUI operation or the Intel
cryptography build. Dedicated CI lanes perform source installation and actual
offscreen GUI rendering on Ubuntu 24.04, Apple Silicon macOS and Intel macOS.
Local validation includes hashes, dependency metadata, shell syntax, hostile
paths, native-library diagnostics, and Windows offscreen GUI rendering. See
[native installer evidence](native-installers.md) for counts and limitations.

After publication, GitHub's Ubuntu 24.04 runner completed source installation,
dependency checks, offscreen QApplication rendering and XCB plugin loading,
then verified both installed entry points. Both Mac runners exposed an unquoted
default runtime path; this is a native finding beyond the Windows fixtures.
See the [publication follow-up](publication-followup.md) for the correction and
updated CI acceptance. Visible desktop operation remains separate from these
automated rendering checks.
