# Round 4 Red-Team Findings

Audit date: 2026-08-01  
Audited snapshot: `158ef4bad161` (`codex/enterprise-cycle7`), plus the live
uncommitted fleet/provider/performance work present during the audit  
Deployment model: local-first Windows endpoint, normally elevated after User
Account Control (UAC) consent; fleet service is opt-in and loopback-only

This was a read-only product audit. No product source, configuration, runtime
data, host policy, or credentials were changed. Five new findings were
confirmed: three High and two Medium. No Critical finding was identified.

## R4-01 - Privileged startup trusts inherited environment before hardening

- **Severity:** HIGH
- **Component:** `src/angerona/core/privilege.py:21-42`;
  `src/angerona/__main__.py:6-15`;
  `src/angerona/core/data_paths.py:42-50,92-115,179-229`;
  `src/angerona/app.py:383-397`;
  `src/angerona/resilience/manager.py:135-158`;
  `src/angerona/resilience/watchdog.py:87-121`;
  `src/angerona/resilience/supervisor.py:56-81`;
  `start-angerona.bat:17-35,103-126`
- **Status:** OPEN

### Description

`ensure_admin()` relaunches the legitimate executable/interpreter through
`ShellExecuteW(..., "runas", ...)`, but Angerona never reconstructs a trusted
environment after elevation. The elevated instance immediately calls
`configure_runtime_environment()` before process mitigations. During that call,
`_admin_acl_valid()` builds the supposedly trusted PowerShell path from
`os.environ["SystemRoot"]`, checks only that the resulting path is a file, and
executes it elevated.

The same trust pattern exists for other Windows tools in release-integrity,
executable-trust, hardening, autostart, and secure-store code. Windows process
creation uses the caller's environment when no replacement environment block is
provided; ShellExecute routes elevation through CreateProcess and the
Application Information service. Angerona supplies no clean block and performs
no post-elevation scrub.

Resilience has a second consequence of the same trust failure:

- `ANGERONA_RESILIENCE=0` disables all in-process supervision.
- `ANGERONA_EXTERNAL_WATCHDOG=1` suppresses the peer watchdog without proving
  that a signed external watchdog exists.
- `ANGERONA_CORE_CMD` and `ANGERONA_PY` are installed with `setdefault`, so a
  caller-selected value survives and is parsed/executed by the elevated
  watchdog on a later core restart.
- The source launcher sets several safe values but does not clear or overwrite
  these four security-sensitive variables when the signed Go watchdog is absent.

### Impact

A medium-integrity process able to launch Angerona with a chosen environment can
cause a user-approved elevated instance to execute a user-controlled executable
from a fake `SystemRoot` tree before mitigations are applied. Independently, it
can silently disable watchdog coverage or replace the command the elevated peer
watchdog uses to resurrect the core. This crosses the desktop-to-administrator
trust boundary and also weakens crash recovery.

### Existing mitigations

The frozen data directory is created with an Administrator/SYSTEM discretionary
access control list (DACL), reparse points are rejected, the signed external
watchdog is Authenticode-checked when present, and the installed release has a
stronger trust root than the editable source checkout. Those controls are
valuable, but they run after or rely on the inherited values described above.

### Proof / safe reproduction

1. In an integration virtual machine, create a benign recorder executable at
   `<user-writable>\fakewin\System32\WindowsPowerShell\v1.0\powershell.exe`.
   It should only record its integrity level and arguments, then exit nonzero.
2. From a non-elevated harness, set `SystemRoot` to that fake tree and launch the
   genuine packaged Angerona executable. Consent to the expected UAC prompt.
3. The current static path is
   `ensure_admin -> configure_runtime_environment -> data_dir ->
   _harden_frozen_data_root -> _admin_acl_valid -> subprocess.run(fake path)`.
   The recorder executing at high integrity confirms the boundary crossing.
4. Separately seed `ANGERONA_RESILIENCE=0`, or seed
   `ANGERONA_EXTERNAL_WATCHDOG=1` while no signed watchdog exists, and confirm
   that the manager starts without its peer watchdog. Seed a benign
   `ANGERONA_CORE_CMD` recorder and exercise authenticated core restart to
   demonstrate command replacement without performing any destructive action.

### Recommendation

Make a privileged bootstrap sanitizer the first operation after elevation and
before all path, storage, logging, Qt, or subprocess work. Obtain the Windows and
system directories from `GetWindowsDirectoryW` / `GetSystemDirectoryW`, not the
environment. Reconstruct a minimal allowlisted environment and discard all
security-sensitive `ANGERONA_*`, proxy, Python, and path-control variables unless
they came from protected post-elevation configuration. Derive the canonical core
argv from a verified executable every time; do not deliver it through the
environment. Treat an external watchdog as present only after signature, PID,
parent/session, and nonce attestation.

Regression gates should seed hostile `SystemRoot`, `PATH`, `PYTHON*`,
`ANGERONA_CORE_CMD`, `ANGERONA_PY`, `ANGERONA_EXTERNAL_WATCHDOG`, and
`ANGERONA_RESILIENCE` values across a real elevation boundary and assert that no
user-controlled executable runs, the canonical core command is retained, and
at least one authenticated watchdog remains active.

## R4-02 - First fleet migration accepts an inherited attacker-selected operator key

- **Severity:** HIGH
- **Component:** `src/angerona/core/config.py:353-363`;
  `src/angerona/core/secure_store.py:250-258`;
  `src/angerona/app.py:440-482,530-584`;
  `src/angerona/core/fleet_credentials.py:624-708`;
  `src/angerona/core/fleet_service.py:63-70,998-1050,1097-1124`;
  `src/angerona/gui/pages.py:5452-5474`
- **Status:** OPEN

### Description

The startup comment says only the protected canonical credential store is
loaded, but `load_into_environment()` overwrites protected keys that exist and
does not remove inherited credential names that are absent from the store.
`_start_fleet_service()` reads `ANGERONA_FLEET_SERVICE_KEY` directly from that
environment and passes it as `legacy_secret`.

When no V1 protected bundle and no protected legacy key exist,
`load_or_migrate_local_credentials()` accepts that parameter. It derives the
tenant-operator HMAC key deterministically as SHA-256 of a fixed domain prefix
plus the caller-selected secret, then persists the resulting V1 bundle. The
Settings save path compounds this: it creates a random protected legacy key only
when the environment variable is empty, so a hostile inherited value suppresses
safe generation.

### Impact

On first fleet enable/migration, a same-host medium-integrity process can choose
the elevated loopback service's tenant-operator credential. Knowing the derived
key lets it authenticate as `local-operator`, enumerate devices, read retained
tenant event payloads and ingestion health, and register device inventory. It
does not bypass tenant authorization or replay protection; it takes ownership of
the credential before those controls are established.

### Existing mitigations

Fleet is opt-in, binds only to loopback, enforces signed requests, tenant/device
scope, authorization, audit, bounded bodies, and durable replay protection. A
valid existing V1 bundle always wins, including over a supplied legacy value.
The exposure is therefore limited to first enable/migration or a deliberately
cleared credential bundle.

### Proof / safe reproduction

1. Use a temporary data root with an empty protected credential map.
2. Seed `ANGERONA_FLEET_SERVICE_KEY` with a known 48-character value and enable
   fleet service.
3. Observe `app.py:449,477-482` pass the inherited value into migration.
4. Compute
   `SHA256(b"angerona-fleet-service-v1\0" + known_value.encode())`; it matches
   the persisted `local-operator` secret at `fleet_credentials.py:668-686`.
5. Sign a normal loopback request with that key; the current operator permission
   set authorizes event/device/health reads and device registration.

### Recommendation

Do not accept the general process environment as an automatic elevated legacy
credential source. Migrate only a value read from the protected store, or expose
an explicit one-shot post-elevation import flow with operator confirmation and
provenance. Settings must test the protected store directly, atomically generate
and verify a fresh random key when no protected credential exists, and purge the
inherited legacy name before starting fleet.

Add four gates: hostile environment plus empty store must generate an unrelated
protected key or fail closed; a protected legacy key must still migrate;
existing V1 must always win; and a Settings save with a hostile environment must
still create protected random material.

## R4-03 - Loopback HTTP can be proxied off-host and is vulnerable to resolution TOCTOU

- **Severity:** HIGH
- **Component:** `src/angerona/core/url_policy.py:37-46,66-141,144-181`;
  `src/angerona/engines/ollama_client.py:198-222`;
  `src/angerona/modules/ai_triage.py:55-58,85-108,127-149`;
  additional local-model consumers of `local_service_url()` / `safe_urlopen()`
- **Status:** OPEN

### Description

The local-service policy correctly validates that a destination resolves only
to loopback and revalidates redirects. However, `safe_urlopen()` then calls
`urllib.request.build_opener()` without an explicit `ProxyHandler`. Python adds
its default environment-proxy handler, so validation is performed against the
loopback URL while the actual HTTP connection can be made to an inherited
`HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` endpoint.

The local Ollama transports send prompt bodies over HTTP. A remote proxy therefore
receives the full absolute URL and plaintext body and can return a forged model
response. Validation also resolves a hostname separately from the later urllib
connection, so an attacker-controlled hostname can answer loopback during policy
validation and a different address during connect (DNS time-of-check/time-of-use
rebinding).

### Impact

High-severity endpoint telemetry, analysis prompts, and operator questions that
are advertised as local/offline can leave the host. A malicious proxy can also
inject local-model responses. Most AI triage output is advisory, which limits
direct containment impact, but the privacy boundary and model-trust boundary are
both broken.

### Existing mitigations

URL shape, scheme, credentials, redirects, response sizes, and initial resolved
addresses are bounded. Provider-specific cloud destinations are separately
pinned and use HTTPS. These are strong controls, but they do not bind the
validated destination to the network peer or disable proxies for local HTTP.

### Proof / safe reproduction

No network traffic was needed. On the audited Windows host, an isolated Python
process cleared proxy aliases, set only
`HTTP_PROXY=HTTPS_PROXY=http://203.0.113.77:8080`, and queried urllib's routing:

```text
proxies= {'http': 'http://203.0.113.77:8080', 'https': 'http://203.0.113.77:8080'}
127.0.0.1 bypass= False
localhost bypass= False
::1 bypass= False
```

`safe_urlopen()` builds exactly that default opener after accepting the loopback
URL. A regression test can use a local fake proxy and fake Ollama server and
assert that the proxy receives zero requests. A resolver test should return
loopback for validation and a non-loopback address for a later lookup and assert
that the connection is rejected or remains pinned to the validated peer.

### Recommendation

For `LOCAL_SERVICE_POLICY`, construct an opener with `ProxyHandler({})`. Prefer
literal `127.0.0.1` / `::1`, or resolve once and connect to the validated numeric
address while retaining the expected Host/TLS identity and verifying the socket
peer. Never silently honor inherited proxies in privileged runtime. If enterprise
cloud proxy support is desired, make it an explicit protected setting with a
separate egress policy and audit trail.

## R4-04 - Protected credentials are republished globally and inherited by every child

- **Severity:** MEDIUM
- **Component:** `src/angerona/core/secure_store.py:31-35,136-167,223-229,250-258`;
  `src/angerona/core/provider_credentials.py:36-47,70-106`;
  `src/angerona/resilience/supervisor.py:56-81`;
  `src/angerona/app.py:295-318`;
  `src/angerona/resilience/status_ui.py:157-160`;
  `src/angerona/gui/upgrade_console.py:475-503`;
  `src/angerona/gui/pages.py:5496-5518`
- **Status:** OPEN

### Description

DPAPI/Keychain protects credentials at rest, but every key except those beginning
`ANGERONA_INTERNAL_` is copied into the process-global environment after write
and again during startup. This includes Anthropic, Gemini, Groq, OpenAI, and
OpenRouter keys, the ARIA mailbox password, and the Teams application password.

`spawn_detached()` passes `{**os.environ, ...}` to every resilience sidecar.
BlackBox and the Sandbox Editor inherit by default. The Upgrade Console's
"Open PowerShell" starts an elevated interactive shell with the complete
environment. Consequently, unrelated scanners, watchdogs, crash dumps, plugins,
and shell commands receive plaintext credentials they do not need.

### Impact

Compromise or diagnostic capture of any lower-value sidecar exposes all optional
cloud, mail, and connector credentials, defeating component compartmentalization.
This does not defeat DPAPI against another account by itself, so Medium is the
appropriate rating, but it significantly increases post-compromise blast radius.

### Existing mitigations

Credentials are encrypted at rest and stored behind private ACLs; internal fleet
credentials are explicitly excluded from environment publication; values are
not intentionally logged by provider helpers.

### Proof / safe reproduction

Store sentinel values for one provider key and one mailbox/Teams key in a
temporary protected-store fixture, call `load_into_environment()`, and inspect
`os.environ`: the sentinels are present. Monkeypatch `subprocess.Popen` around
`spawn_detached()`, BlackBox, Sandbox Editor, and Open PowerShell and capture the
effective child environment; each receives those sentinels in the current code.

### Recommendation

Replace global publication with a narrow credential broker or direct
protected-store accessor. Return only the requested secret just in time to the
provider/connector that needs it, then avoid retaining extra copies. Build child
environments from an allowlist of canonical OS, locale, Qt, and Angerona data
variables, explicitly excluding API keys, tokens, passwords, webhooks, mail
credentials, and proxy settings. Open any operator shell with a similarly
sanitized environment.

Regression tests must assert that protected provider/mail credentials are absent
from `os.environ` and from every child environment while the intended provider
or connector can still retrieve exactly its own credential.

## R4-05 - Fleet credentials never expire and principal expiry rolls forward on restart

- **Severity:** MEDIUM
- **Component:** `src/angerona/core/fleet_credentials.py:111-160,624-708`;
  `src/angerona/core/authorization.py:35-48,344-410`;
  `src/angerona/app.py:535-576`
- **Status:** OPEN

### Description

`FleetCredential` supports `not_before`, `expires_at`, and `revoked_at`, and the
registry correctly rejects inactive credentials when these values are set. The
locally generated operator and device credentials set none of them, so their
serialized values remain zero indefinitely.

The application creates service-account principals with an expiry of
`time.time() + 366 days` on every startup. That value is not persisted or bound
to the credential. Restarting Angerona therefore grants the same long-lived key
a fresh 366-day authorization window forever. No operator rotation/revocation
workflow for the protected local V1 bundle was found.

### Impact

A copied local operator or device HMAC remains useful indefinitely unless the
operator manually destroys the protected credential state. Restarting cannot
age it out and actually renews the in-memory principal. Loopback binding and
protected storage reduce exposure, so this is Medium rather than High.

### Existing mitigations

Credential objects and authorization decisions already implement expiry and
revocation checks correctly when populated. Existing V1 state wins over legacy
input and is byte-verified after migration. Request timestamps and durable replay
protection remain enforced.

### Proof / safe reproduction

Migrate a temporary fleet bundle at time `T0`; inspect both serialized credentials
and observe `expires_at == revoked_at == 0`. Start authorization at `T0` and then
simulate a restart after `T0 + 367 days`: `app.py` constructs a new principal
expiry at the later time plus another 366 days, while the same HMAC authenticates.

### Recommendation

Persist fixed issue/not-before/expiry timestamps, credential version, rotation
state, and revocation state. Bind principal validity to the credential's fixed
expiry; never calculate a replacement deadline from each startup. Add explicit
operator/device rotation with a short, bounded overlap and audit record. Refuse
startup or require re-enrollment when protected credentials have expired.

Tests should restart beyond the original expiry and prove the old HMAC remains
expired, rotate/revoke and prove only the new key works, and verify that readiness
reports days-to-expiry without exposing credential identity or material.

## Areas checked with no new bypass found

- The new fleet HTTP service rejects ambiguous framing, duplicate/non-finite
  JSON, unsupported encoding, oversized/incomplete bodies, stale/replayed signed
  requests, and cross-tenant/device authorization attempts. Its loopback binding,
  canonical request signature, durable replay ledger, authorization, and audit
  chain are materially stronger; no request-smuggling, replay, or tenant escape
  was confirmed in this pass.
- External-module admission verifies exact manifest bytes with Ed25519. Declared
  permissions remain review metadata rather than a runtime sandbox, and current
  documentation says so honestly.
- Cloud provider hosts are pinned and redirects are revalidated; Gemini no longer
  places its API key in the query string.
- The self-compiler stages output behind explicit review, and CVE-advisor
  PowerShell is staged/disabled rather than automatically executed.
- A tracked-tree/privacy scan found no live secret, private key, personal Windows
  path, or real endpoint telemetry in the public artifacts. The already-known
  historical non-noreply Git author email remains a repository-history privacy
  residue and was not refiled as a new finding.

## Prior-finding reconciliation

- **Verified resolved (4 recent controls):** Teams development-auth bypass;
  shutdown/EventBus key separation; pre-created key quarantine/custody; persisted
  GUI telemetry HMAC verification.
- **Still open/deferred (3 known technical boundaries):** elevated editable
  source checkout; legacy Remote Bridge unauthenticated/unencrypted telemetry;
  broad PowerShell execution boundary.
- **Known privacy residue (1):** historical Git author email. It requires history
  rewrite or account-level privacy handling and was already documented.

## Severity summary

| Severity | New findings |
|---|---:|
| Critical | 0 |
| High | 3 |
| Medium | 2 |
| Low | 0 |
| Info | 0 |

