# Cycle 19 Red-Team Audit — Passes 2–7

Audit date: 2026-08-21  
Scope: public-repository privacy, extension/import and command boundaries,
install/update/release supply chain, credential custody, local IPC/auth/replay,
and compound breach chains. The live dirty workspace was reviewed as-is; no
product source or runtime state was changed.

## Outcome

One new vulnerability was confirmed: a **Medium** POSIX supply-chain regression.
No new Critical or High finding was found. The Windows release/source bootstrap
remains hash locked. Two IPC/mobile issues are recorded below as theoretical
hardening, not inflated into vulnerabilities because no attacker path across the
documented deployment boundary was demonstrated.

| Severity | New findings |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 0 |

## C19-RT-01 — POSIX installers and native release builds execute unhashed index dependencies

- **Severity:** MEDIUM
- **Classification:** confirmed vulnerability; new POSIX extension of the
  previously fixed Windows supply-chain finding C7-R1-05
- **Components:** `install-angerona.sh:57-67`;
  `.github/workflows/release.yml:220-227,248-297,325-333`;
  `pyproject.toml:1-3`; `constraints-release.txt:1-2`;
  `tests/test_release_hash_lock.py:42-62`
- **Status:** FIXED — target-specific wheel locks/manifests now gate Linux x86-64
  and macOS arm64; macOS Intel fails closed because no current safe upstream
  cryptography wheel exists. See `supply_remediation.md`.

### Exploit preconditions

An upstream package account/artifact, package index response, or dependency
delivery path must be compromised when either (a) a Linux/macOS user runs the
source installer or (b) a tagged Linux/macOS release job executes. The user must
then run the resulting source install or native artifact. POSIX installation is
deliberately per-user and refuses root, so this is not rated High.

### Evidence

`install-angerona.sh` creates a virtual environment, installs `pip==26.2.1`, and
then installs the editable project plus platform extras using only
`--constraint constraints-release.txt`. It does not use `--require-hashes`,
`--no-deps`, or a preverified offline wheelhouse. The build-system requirements
are also floating (`setuptools>=68` and `wheel`), so editable/build isolation can
resolve code outside the reviewed lock.

The native POSIX release matrix repeats that boundary: it installs the project,
PyInstaller, CycloneDX, pip-audit, and pytest using a constraints file but no
artifact hashes, then executes those tools to test and freeze the application.
Checksums and GitHub provenance are produced only after dependency code has
already executed; a poisoned build can therefore become a correctly
checksummed and provenance-attested Angerona release.

The current regression gate has a scope blind spot. It asserts that
`--require-hashes --no-deps` occurs somewhere in `release.yml`, which the secure
Windows job satisfies, but it never isolates and validates the `build-posix`
job or `install-angerona.sh`. The focused test file consequently passed **7/7**
during this audit while the POSIX path remained unhashed.

### Impact

A dependency-delivery compromise can execute during a local installation or
native release build and ship a backdoored Linux/macOS Angerona artifact. That
code would run with the signed-in user's access to telemetry, configuration,
and optional Keychain/Secret Service credentials. In CI it can alter artifacts
before the separate publish job gives them legitimate checksums and provenance.

### Existing mitigations

All GitHub Actions are commit-SHA pinned; release jobs have scoped permissions;
versions are constrained; POSIX installation refuses root; releases publish
checksums, SBOMs, and build provenance. The Windows dependency lock and Inno
Setup digest verification at `.github/workflows/release.yml:29-41,131-163`
remain sound. These controls reduce exploitability but do not bind POSIX package
bytes before execution.

### Safe reproduction / regression idea

Do not contact an index or substitute a real package. Add a static policy test
that extracts the `build-posix` job and each POSIX installer command separately,
then fails unless every third-party installation is either:

1. `--no-index --find-links <verified-wheelhouse> --require-hashes --no-deps`, or
2. a local project install using `--no-build-isolation --no-deps` after the
   complete hashed environment is present.

Also assert that the build-system dependencies are present in the platform lock
and that a one-byte wheel mutation fails before pip runs.

### Smallest remediation

Generate reviewed CPython 3.12 lock/wheelhouse manifests for Linux x86-64, macOS
x86-64, and macOS arm64, including build tooling and every transitive platform
dependency. Verify filename, size, and SHA-256 before installation; install with
`--no-index --find-links --require-hashes --no-deps`; install Angerona itself
with `--no-build-isolation --no-deps`. Make `install-angerona.sh` consume the
matching verified wheelhouse or clearly remain a development-only path. Extend
the test at `tests/test_release_hash_lock.py:42-62` to inspect each matrix job and
installer independently.

## Pass results without a new finding

### Pass 2 — Public repository privacy and secrets

- Current tracked text contains no live API-token/private-key pattern, real
  operator-profile path, or committed runtime database/log/crash artifact. `.gitignore`
  explicitly excludes secrets, settings, databases, logs, diagnostics, runtime
  IPC, and local document-render workspaces (`.gitignore:8-34,61-84,107-115`).
- All tracked DOCX core metadata inspected in this pass has blank creator and
  last-modifier values; no user-home path was found in DOCX XML.
- **Known residue, not refiled:** Git history still contains
  `Ag3nt47 <lukelucas1901@gmail.com>`. Publishing the current tree does not remove
  it; history rewrite or GitHub account-level email privacy remains necessary if
  the owner considers that address private.

### Pass 3 — Import and plugin trust boundary

- Built-ins use fixed package imports. External Python is disabled unless
  `ANGERONA_EXTERNAL_MODULES` is explicitly enabled
  (`core/module_manager.py:190-218`). Admission rejects symlinks/reparse points,
  opens one bounded regular file with no-follow/inode checks, and returns the
  exact SHA-256-bound byte snapshot (`core/capability_manifest.py:208-289`). Only
  that verified snapshot is compiled/executed (`core/module_manager.py:225-239`).
- No verify-then-swap or unsigned-default regression was found.
- Declared plugin permissions remain review metadata rather than an OS/runtime
  sandbox. A trusted publisher can execute with the full Angerona token. This is
  documented architecture/hardening debt, not a signature bypass.

### Pass 4 — Command-execution boundary

- Flagged `cmd /c` and `sh -c` sites use integer PIDs or generated UUID-only
  markers (`engines/forensics.py:110-117`, `modules/canary_drill.py:271-293`,
  `shark/red_team.py:495-525`); no attacker-controlled shell interpolation was
  confirmed.
- Direct Native custom PowerShell intentionally runs operator-supplied script
  (`modules/posture_hardening.py:797-821`). Other remaining
  `-ExecutionPolicy Bypass` sites are fixed command bodies or fall under known
  open finding A-06. This pass did not identify a new untrusted data flow into
  those commands.

### Pass 6 — Credentials, local IPC, authentication, and replay

- Windows DPAPI, macOS Keychain, and Linux Secret Service protect credentials at
  rest and Linux passes secrets on stdin rather than argv
  (`core/secure_store.py:95-219`, `platforms/linux/secret_service.py:28-66`).
- Fleet HTTP remains loopback-only with HMAC authentication, tenant/device
  authorization, bounded parsing, timestamps, and durable replay rejection. No
  cross-tenant, unauthenticated, or request-replay bypass was confirmed.
- **Theoretical hardening, not filed:** stand-down and restart command verifiers
  check HMAC and maximum age but have no consumed-nonce ledger and do not reject
  timestamps too far in the future (`resilience/shutdown_token.py:108-141`;
  `resilience/supervisor.py:539-594`). Replaying a captured file requires read and
  write access inside the protected data root; on POSIX that is already same-user
  authority capable of terminating the suite. Add an absolute clock-skew bound
  and a bounded consumed-nonce cache as defense in depth.
- **Theoretical hardening, not filed:** the Signal bridge's authorization helper
  accepts a message if parsed sender identity is empty
  (`modules/mobile_bridge.py:145-170,262-266`). The main loop requires a configured
  destination (`:437-448`), and no normal remote signal-cli envelope capable of
  producing an empty sender with a data message was demonstrated. Canonicalize
  phone/ACI/PNI identities and fail closed on absent/ambiguous identity; use
  `secrets` for tokens and rate-limit PIN failures.

## Pass 7 — Compound breach chains

### Confirmed exposure chain (new supply-chain finding)

Unhashed POSIX dependency -> code execution in native build -> modified frozen
application -> legitimate archive checksum/provenance -> user install -> access
to local telemetry and OS credential-store-backed integrations. This chain is
the reason C19-RT-01 is a vulnerability rather than generic reproducibility
advice.

### Known open Windows bootstrap chain (not new)

Hostile inherited environment -> UAC relaunch before sanitization
(`__main__.py:6-16`, `core/privilege.py:21-43`) -> inherited `SystemRoot` selects
an elevated PowerShell path (`core/data_paths.py:125-147`) -> arbitrary elevated
execution -> global protected credentials are available in `os.environ` and
inherited by sidecars/shells (`core/secure_store.py:273-308`,
`resilience/supervisor.py:56-81`, `gui/upgrade_console.py:475-503`) -> optional
first fleet migration can persist an attacker-selected operator key
(`app.py:453-486`, `core/fleet_credentials.py:624-720`). This combines prior
R4-01, R4-04, and R4-02; it remains the highest-priority known chain.

### Theoretical publisher compromise chain

Trusted plugin publisher key compromise -> correctly signed malicious module ->
in-process execution with the full suite token -> credential/telemetry access.
No local signature bypass was found. Runtime isolation and enforceable capability
permissions would reduce blast radius but are an architectural upgrade, not a
small remediation.

## Prior-finding verification

Verified resolved in current code (**4**): R4-03 (local HTTP is numeric-loopback
pinned and proxy-disabled at `core/url_policy.py:144-235`); C7-R1-01 (remote PID/
path action keys stripped and transport-owned observe authority at
`modules/remote_bridge.py:411-449`); C7-R3-01 (Evolution rejects observe-only
remote events at `modules/evolution_engine.py:169-179`); and the Windows portion
of C7-R1-05 (hash lock plus independently verified Inno compiler at
`.github/workflows/release.yml:29-41,131-163`).

Verified still open (**5**): R4-01 (privileged inherited environment), R4-02
(first fleet migration can accept inherited legacy key), R4-04 (protected
credentials republished globally/inherited by children), R4-05 (generated fleet
credentials have zero fixed expiry and principal expiry rolls forward at
`fleet_credentials.py:111-160,681-695` and `app.py:539-555`), and A-06 (broad
PowerShell execution surface). The historical author email is separately known
privacy residue rather than a product vulnerability.
