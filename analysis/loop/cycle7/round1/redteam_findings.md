# Cycle 7 / Round 1 — Red-Team Findings

Audit date: 2026-08-20  
Audited snapshot: `478e65e28cd8` (`codex/enterprise-cycle7`)  
Deployment model: elevated, local-first Windows EDR/NDR/SOAR; optional Remote
Bridge and fleet integrations; public GitHub release workflow

This was a read-only product audit. No product source, configuration, runtime
state, or host policy was changed. Six new weaknesses were confirmed: one High
and five Medium. The newly added Qt close guard was manually reviewed and did
not expose a new trust-boundary bypass. The only fresh Windows crash remains the
18:09:42 `Qt6Core.dll` `0xc0000409` event that predates commit `478e65e`; no
post-fix crash event exists yet, so soak validation remains required.

## C7-R1-01 — Authenticated Remote Bridge telemetry can trigger destructive local SOAR response

- **Severity:** HIGH
- **Component:** `src/angerona/modules/remote_bridge.py:411-435`;
  `src/angerona/core/eventbus.py:226-230`;
  `src/angerona/modules/soar.py:67-75,94-106,112-131,158-183,203-225`
- **Status:** OPEN

### Description

Remote Bridge authenticates and decrypts a peer correctly, but the receiver then
accepts the peer-controlled `module`, `severity`, and `details` fields and
republishes them as an ordinary local Event. EventBus signs that newly created
event with the receiver's own authority. The default-enabled SOAR active-defense
path does not distinguish remote evidence from local process telemetry: it uses
the supplied `details.pid`, counts attacker-selected module names as independent
corroboration, and treats a burst across two supplied PIDs as a local attack.

A compromised but legitimately paired sensor can therefore send four HIGH+
events across two PIDs, then two CRITICAL events with distinct module names for
one receiver-local PID. The receiver will suspend that local process and can kill
it on repeat. PIDs have only host-local meaning and must never cross this boundary
as response authority.

### Impact

A compromised Remote Bridge peer possessing the configured shared key can turn
the elevated receiver into a process-control confused deputy. It can suspend or
terminate arbitrary non-protected user applications and add the associated
network-isolation rule without compromising the receiver's EventBus key.

### Existing mitigations and proof

Remote Bridge is off by default, uses mutual authentication and AES-GCM, and the
SOAR protected-process list blocks a limited set of Windows process names. Those
controls stop unauthenticated LAN injection but do not constrain an authenticated
peer's authority. A safe in-memory harness submitted the sequence above, verified
that every republished event had a valid receiver HMAC, and observed the mocked
containment callback for receiver PID 333 from the second remote module.

### Recommendation

Mark remote evidence with a non-overridable transport origin outside peer-supplied
details. Response engines must reject all non-local events by default. If remote
response is later desired, map a stable endpoint identity plus remote process
generation to a typed fleet action addressed back to that endpoint; never apply a
remote numeric PID to the receiver. Corroboration identities must come from a
trusted module registry, not the event's free-form `module` string. Add an
integration test proving a fully authenticated malicious peer cannot cause local
`suspend`, `kill`, or firewall mutation.

## C7-R1-02 — Threat Intel reports staged proposals as executed fixes

- **Severity:** MEDIUM
- **Component:** `src/angerona/core/cve_fix_advisor.py:336-378`;
  `src/angerona/gui/threat_intel_page.py:457-503`;
  `README.md:106`
- **Status:** OPEN

### Description

`apply_fix()` was correctly hardened to write model-authored PowerShell to a
`.ps1.txt` review file and returns `executed=False`. The GUI still labels the
action “Confirm & Run fix”, warns that commands “will run”, then treats any
`ok=True` staging result as “Fix applied” and says the fix “ran successfully”.
The README likewise advertises confirm-then-execute and one-click revert.

### Impact

An operator can leave a host-applicable KEV vulnerability unpatched while the
security UI explicitly reports successful remediation. This is a false-assurance
failure in the remediation evidence chain and directly explains why remediation
can remain at zero despite apparent successful button presses.

### Recommendation

Rename this workflow to **Stage proposal**, display `staged/executed/verified` as
separate states, and never use “applied”, “ran”, “fixed”, or “revert” unless a
registered typed operation returns a passed postcondition and authenticated
receipt. Update README claims. Add a UI contract test asserting that
`executed=False` can only render “staged, not executed”.

## C7-R1-03 — “No fix” and AI outage are treated as permission to hide real KEVs

- **Severity:** MEDIUM
- **Component:** `src/angerona/gui/threat_intel_page.py:420-455`;
  `src/angerona/core/cve_ignore.py:62-85,105-114`;
  `src/angerona/modules/intel_sync.py:365-385`
- **Status:** OPEN

### Description

Mass Flag & Ignore automatically excludes every CVE for which the local model
returns `fix_available=False`. If Ollama is unavailable, the same control offers
to ignore every active CVE. “No scriptable fix”, model failure, or model absence
does not mean the vulnerability is a false positive, but the ignore store removes
those applicable CISA KEVs from threat-level calculation and can restore the
module to 100% health.

### Impact

A model error, poisoned prompt input, or ordinary Ollama outage can guide an
operator into suppressing genuine exploited vulnerabilities. The findings remain
listed, but the main posture and alerting semantics become materially misleading.

### Recommendation

Separate **false positive**, **risk accepted**, **mitigated by compensating
control**, and **no vendor fix** states. Only a validated applicability failure may
leave threat scoring. No-fix CVEs should remain active with an explicit
“unremediated/compensating control required” state. Remove AI-driven bulk ignore;
require per-CVE reason, expiry, approver identity, and periodic revalidation.

## C7-R1-04 — Sandbox self-tests can leave every detector stopped indefinitely

- **Severity:** MEDIUM
- **Component:** `src/angerona/gui/sandbox_editor.py:99-126,180-183,302-354,388-405`;
  `src/angerona/gui/thread_lifecycle.py:25-67`
- **Status:** OPEN

### Description

Opening the Sandbox Editor immediately stops every live module and replaces the
process-global EventBus publisher with a no-op. “Run Isolated Test” then calls the
selected module's arbitrary `self_test()` inside an elevated QThread in the live
Angerona process. It is not a process, token, filesystem, network, or CPU sandbox.
The new crash guard correctly refuses to destroy a running QThread, but
`requestInterruption()` cannot stop a `self_test()` that blocks or ignores it.
Closing the hidden window therefore waits forever and never reaches the code that
restores EventBus publishing and restarts sensors.

### Impact

A hung built-in test, unsafe model-assisted edit, or hostile extension test can
produce an indefinite, low-observability detection blackout while the core and
watchdog remain alive. The watchdog has no reason to restart a healthy core, so
the outage can persist until the whole suite is restarted.

### Recommendation

Run tests in a separate restricted process with a hard deadline, memory/CPU
limits, sanitized environment, no production EventBus authority, and an isolated
temporary data root. Do not stop all production modules merely to open an editor.
Make restoration independent of worker completion, and publish an out-of-band
critical health state while any sensor pause is active. Add a never-returning
self-test regression and prove sensors/EventBus recover within a fixed deadline.

## C7-R1-05 — Release builds trust version pins without artifact hashes

- **Severity:** MEDIUM
- **Component:** `.github/workflows/release.yml:26-39`;
  `constraints-release.txt:1-73`;
  `start-angerona.bat:76-80`;
  `Install-Angerona.bat:83-104`
- **Status:** OPEN

### Description

The release and source installers pin versions and restrict most downloads to
binary wheels, but the lock file contains no SHA-256 hashes and pip is never run
with `--require-hashes`. The GitHub attestation and published checksums describe
whatever the workflow built; they do not prove that downloaded wheels match a
separately reviewed dependency set. The Inno compiler is also discovered from
the mutable `windows-latest` runner image rather than pinned or independently
verified.

### Impact

A compromised package index, upstream distribution account/artifact, or runner
tool image can execute during the release build and become a correctly
checksummed and provenance-attested elevated EDR installer. Version pinning and
PyPI filename immutability lower exploitability, but the resulting impact is
administrator-level supply-chain compromise.

### Recommendation

Generate a Windows/CPython-specific wheelhouse manifest containing URL, filename,
size, and SHA-256 for every wheel; install offline with `--no-index --find-links
--require-hashes`. Pin and verify the Inno Setup installer/compiler digest, or use
a controlled runner image. Produce the SBOM from the packaged artifact/wheelhouse
rather than the ambient build environment and fail release on any unlisted file.

## C7-R1-06 — One-click Setup accepts silent rollback to an older vulnerable build

- **Severity:** MEDIUM
- **Component:** `installer/Angerona.iss:12-34,36-44`;
  `.github/workflows/release.yml:127-145`
- **Status:** OPEN

### Description

Every release uses the same Inno `AppId`, but Setup has no downgrade gate or
minimum accepted version. Both executable entries use `ignoreversion`, so an
older authentic installer can overwrite a newer installation after UAC consent.
The installer is currently unsigned, making publisher-based rollback controls
unavailable as well.

### Impact

A social-engineering attacker can direct an operator to an older genuine release
and reintroduce fixed vulnerabilities and crash paths while retaining the same
shortcuts and runtime state. Checksums and build attestations prove the old build
is genuine; they do not prove it is current.

### Recommendation

Persist a protected monotonic installed-version/release-identity record and abort
when Setup is older. Permit rollback only through a separately labeled recovery
flow that requires explicit confirmation and records an audit receipt. Add
Authenticode signing, validate the signer in upgrade logic, and test
newer-to-older install rejection in CI.

## Expanded evidence for a known open finding — inherited data root is destructive

This is **not counted as a new finding** because it is another concrete impact of
open finding R4-01 (privileged startup trusts inherited environment). The current
source launcher preserves an inherited `ANGERONA_DATA` at
`start-angerona.bat:17-26`, elevates, and passes it to
`tools/protect-key-custody.ps1:83-136`. That script can take ownership, protect
the root DACL, and recursively reset every descendant DACL. It does not constrain
the path to the canonical Angerona data directory or reject reparse points in
ancestor components. A caller-selected existing directory can therefore become
an elevated ACL-rewrite target after the expected Angerona UAC prompt.

The bounded fix is to overwrite, not preserve, security-sensitive launch
variables before elevation; pass a canonical data root through a protected
post-elevation channel; resolve and reject every reparse ancestor; require the
exact approved leaf name/volume policy; and make custody migration operate only
on a root carrying a valid Angerona creation marker or through a separately
confirmed migration UI. A regression should seed an arbitrary existing tree and
prove no ACL is changed.

## Areas checked without a new finding

- The Qt lifecycle helper hides and retains each closeable owner until all known
  QThreads finish, closes the signal-connect race, and avoids blocking the GUI.
- Local URL calls now pin a numeric loopback address and explicitly disable
  inherited HTTP proxies, resolving prior R4-03.
- Current tracked screenshots are synthetic/sanitized. No tracked secret prefix,
  private-key block, live username, or local user path was found in the public
  tree. Historical personal author email and removed live screenshots remain the
  already-known Git-history publication residue.
- Actions are commit-SHA pinned, job permissions are scoped, release archives and
  Setup receive checksums/provenance, and the Black Box digest is embedded in the
  main executable.

## Prior-finding reconciliation

For the ten most recent enumerated findings (Round 4 plus Cycle 6):

- **Verified resolved (5):** R4-03; C6-R2-01; C6-R2-02; C6-R3-01; C6-R3-02.
- **Still open (5):** R4-01; R4-02; R4-04; R4-05; C6-R2-03.

Older documented boundaries around editable elevated source deployments,
non-enforced extension permission declarations, broad PowerShell surface, and
Git-history privacy were not relabeled as new findings.

## Severity summary

| Severity | New findings |
|---|---:|
| Critical | 0 |
| High | 1 |
| Medium | 5 |
| Low | 0 |
| Info | 0 |

