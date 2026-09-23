# Adversary review — deep review round 3, 2026-09-23

Scope: `Start-Angerona-macOS.command`, `Start-Angerona-Linux.sh`,
`tools/native-quickstart.sh`, `install-angerona.sh`,
`tools/posix_install_support.py`, `tools/build_macos_intel_crypto.py`, the three
source-runtime lock/manifest pairs and `tools/enable_analysis_lab_vmware.ps1`.
Adjacent wheel verification, the Linux unit template and POSIX autostart
serialization were read where needed to follow trust boundaries.

This bounded pass changed no product files. Verification used literal string
fixtures, dependency metadata and isolated tests. It did not run an installer,
download/build a dependency, start a sensor/VM/service, change host settings or
invoke elevation. Historical cycle34 loop reports were preserved; September 23
round1/round2 findings and the patch agent's round2 closure were consulted.

## D23-R3-01 — Service helper accepts an ambiguous unquoted executable path

- **Severity:** MEDIUM, conditional on a pre-existing unquoted service
  registration and a writable earlier executable candidate.
- **Status:** Resolved in source during this review. The completed coordinator
  fix was re-read and the full helper passed PowerShell AST parsing; native
  service/VM acceptance evidence belongs to the coordinator's separate gate.
- **Component:** `tools/enable_analysis_lab_vmware.ps1:11-34` at discovery,
  specifically service `PathName` parsing, Authenticode checking and subsequent
  `Start-Service`.

### Description and verified data flow

The helper reads the VMware Authorization Service registration. If the whole
path is quoted it strips those quotes; otherwise it accepts any drive-absolute
path matching the expected `vmware-authd.exe` leaf. It then checks that complete
literal path with `Get-Item` and `Get-AuthenticodeSignature` before starting the
service using the unchanged registered command line.

The pre-fix parser accepted this unquoted string:

```text
C:\Program Files\VMware\VMware Workstation\vmware-authd.exe
```

Windows service executable paths containing spaces require quotes. With an
ambiguous unquoted registration, the verified full-path executable need not be
the image selected by process creation: an earlier executable candidate such
as `C:\Program.exe` can take precedence if present. The helper's signature check
then authenticates a different file from the one that starts.

This behavior is documented by Microsoft's
[CreateServiceW parameter contract](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)
and [CreateProcessW command-line parsing rules](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw).
No claim is made that this machine's actual VMware registration is malformed
or that an earlier candidate is writable here.

### Inert reproduction

The exact discovery-time regex was evaluated against a literal string; no
service query, filesystem access, process launch or settings mutation was needed:

```powershell
$sample = 'C:\Program Files\VMware\VMware Workstation\vmware-authd.exe'
$pattern = '^[A-Za-z]:\\(?:[^"\\\r\n]+\\)*vmware-authd\.exe$'
$sample -match $pattern
# True
```

Manual tracing confirmed that this accepted value flows into literal-path
signature verification while `Start-Service -Name 'VMAuthdService'` consumes the
registered service command line instead. The discrepancy establishes the
missing binding; no real malicious candidate was created or executed.

### Impact, existing controls and recommendation

On an already misconfigured installation, an actor able to create an earlier
candidate can turn an administrator's explicit service-enablement step into
execution of a different image under the service account. The helper does not
create that misconfiguration and a normal attacker cannot arbitrarily rewrite
a protected service registration. Those prerequisites limit exploitability and
justify MEDIUM rather than an unconditional high-severity claim.

Credited controls: explicit administrator requirement, fixed service name,
standalone executable-name restriction, rejection of a reparse-point leaf,
valid Authenticode status and VMware/Broadcom publisher allowlist, manual rather
than automatic startup, and no VM invocation.

Reject any unquoted registration containing whitespace before changing startup
mode or attempting to start the service. Preserve exact standalone executable
validation and retain the original registered string; recheck it immediately
before mutation/start so a changed registration does not inherit an earlier
signature verdict. Do not silently rewrite ambiguous service configuration.
Bind file/path custody through the privileged operation where practical.

Acceptance cases should cover a valid quoted path with spaces, a valid
unquoted no-space path, unquoted whitespace, appended arguments, invalid signer,
and a changed service registration. Every negative case must prove zero
`Set-Service` and zero `Start-Service` calls when rejection occurs before
mutation; a change observed after startup-mode modification must still prove
zero `Start-Service` calls.

### Closure verification

The completed helper now rejects unquoted whitespace before `Get-Item` or any
service mutation, retains the original registration including quotes, and checks
that exact registration again before both `Set-Service` and `Start-Service`.
It retains a read-only file handle with `FileShare.Read` through signature
verification and the wait for service startup, disposing it in `finally`.
This denies writes/deletion of the verified executable during that interval.
The complete PowerShell script parsed without errors. The coordinator reports
that this host's actual registered no-space path is `D:\vmware-authd.exe` and
separately owns the explicitly user-authorized native readiness test; this
reviewer did not execute that test or claim its outcome.

## Native-installer review results

- **Shell/path handling:** inspected every executable dispatch and generated
  entry point. Installer paths are passed as arguments, shell launcher payloads
  use `shlex.quote`, control characters are rejected, desktop arguments escape
  field codes/metacharacters, and systemd arguments escape specifiers and
  executable environment expansion. No new confirmed shell injection was found.
- **Elevation:** the POSIX installer refuses root. Guided elevation is limited
  to fixed package-manager commands after an explicit prompt. Homebrew's remote
  installation guide is opened, not executed as downloaded shell code.
- **Staging/rollback:** each generation uses `mktemp` under the runtime directory
  and a one-installer directory lock. Cleanup resolves and checks the staging
  parent, refuses a symlink staging leaf and retains prior validated generations.
  Launchers change only after package consistency/module discovery checks. The
  generation is preserved once publication begins, including partial entry-point
  publication failures. No new confirmed cross-boundary deletion was found.
- **Wheel trust:** downloads are binary-only, no-dependency and hash-required;
  the verifier checks the exact filename/size/digest set before installation.
  All source-lock hashes match their manifests exactly: **Linux x86_64: 23**,
  **macOS arm64: 23**, **macOS x86_64 base: 22**. Intel's sole omitted runtime
  dependency is the separately built cryptography package. This metadata check
  did not independently download every wheel.
- **Intel source build:** fixed source and Maturin size/SHA-256 checks precede
  use; extraction rejects traversal, links and special members and applies size
  and entry limits; the source must request locked Cargo use; external Cargo
  dependencies must be checksummed registry entries. Cargo fetch is locked;
  compilation is then locked/offline, limited to two workers and timed out.
  The build environment removes inherited compiler/index overrides. Local
  compiler/Rust/OpenSSL installations remain explicit prerequisites, not bytes
  authenticated by the source wheel manifest. No new confirmed dependency-trust
  bypass was found within that stated boundary.
- **AI adversarial inputs:** these installers use fixed commands and reviewed
  artifact metadata. No model response or external explanatory text selects
  commands or grants privileged action authority in the reviewed paths.

## Validation and prior closure

Ran `tests/test_native_installers.py` with the checkout's existing virtualenv and
this worktree's `src` on `PYTHONPATH`: **14 passed, 1 skipped in 2.09 seconds**.
The skipped case requires a native POSIX shell and deliberately tests download
failure without networking. A separate stdlib metadata check validated all
three source lock/manifest pairs. None of these results prove macOS Intel
compilation, native GUI usability or a successful native installer run; those
remain the native CI/acceptance lane's responsibility.

Two prior fixes were re-read in current source:

| Prior finding | Source verification | Status |
|---|---|---|
| D23-R2-01 semantic induced work | LSASS/ShadowCopy branch on exact execution scope; semantic-only observations have no active flag/response authority; narrow historical rule preserves corroboration and uncertain process identity | Resolved |
| D23-R2-02 endpoint attestation | Listener admission uses the pinned literal address, rejects applicable wildcard ambiguity, and transport attests the same literal it sends to | Resolved |

The earlier 13-case endpoint gate and patch agent's 102-case classification gate
are recorded in the round2 reports; they were not rerun solely for this report.
Linux Qt/prerequisite/bootstrap changes were already assigned to the installer
worker and are not duplicated as security findings here. The VMware helper
remediation has been re-read as described above. No UAC/service action was
performed by this reviewer.

| New severity / prior disposition | Count |
|---|---:|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 1 |
| LOW / INFO | 0 |
| Prior findings verified resolved in this pass | 2 |
| Prior findings verified still open in this pass | 0 |

## Final bounded follow-up — installer prerequisites and optional VMware setup

The coordinator subsequently requested a final read-only review of the Linux Qt
helper, native installer/CI integration, late Ollama cancellation, retirement of
Lab readiness, and the new optional VMware setup flow. **No additional confirmed
security finding was identified.** This does not add a finding to the table above.

- `tools/check_native_gui.py` uses fixed library/package names and argument
  lists. A read-only prerequisite check does not install packages; the guided
  launcher asks before requesting package-manager elevation. The native GUI
  probe runs in an isolated, offscreen child with a 40-second timeout and no
  core dumps. Its failure precedes launcher publication. CI exercises that
  installer path on Linux, ARM macOS and Intel macOS; this Windows review does
  not stand in for those native jobs.
- Ollama's post-verification callback checks cancellation before daemon launch.
  The existing post-inventory checks prevent cancelled work from publishing
  100-percent readiness. Model readiness remains separate from daemon readiness.
- `check_runtime()` writes a failed selfcheck receipt before an explicit native
  recheck and publishes success only after both fixed analyzer fixtures pass.
  The receipt digest now includes the supervisor profile and exact generated
  VMX configuration, retiring pre-custody success receipts. The configuration
  seal remains intact. VMware's observed inability to open that sealed profile
  remains a fail-closed native compatibility limit, not a successful Lab result.
- `core/analysis_vmware_setup.py` requires explicit selection of a local
  Workstation installer, a valid allowlisted VMware/Broadcom publisher, expected
  product metadata, a bounded regular single-link file, and stable held/path
  identity. Parent-directory handles and the file's no-write/no-delete seal are
  retained through installer exit. The selected path travels as environment
  data to fixed code. The UAC installer stays interactive for license prompts;
  there is no automatic download or silent license acceptance.
- Optional service configuration preflights the installed VMware images and
  uses an embedded fixed service script through `EncodedCommand`, not a mutable
  temporary/repository script path. It retains the previously reviewed service
  registration/signature checks. Only the named Authorization Service is set to
  Manual and started; this action starts no VM and grants no Lab readiness.
- `gui/analysis_vmware_setup.py` and the setup-wizard action remain optional.
  Opening the dialog performs no installation/elevation. Installation and service
  configuration each require explicit confirmation with No selected by default.
  A single bounded worker and separate bounded progress/completion queues keep
  the GUI responsive; closing is refused while the native prompt/installer owns
  the verified-file handoff. Setup results are rendered as plain text and the
  known Lab compatibility limit remains visible.

Executed the final prerequisite/startup/readiness selection:
`test_native_installers`, `test_ollama_startup`, and
`test_analysis_lab_readiness_retirement`: **58 passed, 1 native-shell skip in
5.35 seconds**. The optional setup implementation was reviewed after the patch
agent announced it ready; that agent owns its new inert tests and acceptance
report. No native installer, service, VM, elevation or product edit was performed
by this reviewer. The selected vendor installer's exact ProductName and native
installer behavior still need a separately authorized native acceptance check;
unrecognized metadata is refused rather than treated as trusted.
