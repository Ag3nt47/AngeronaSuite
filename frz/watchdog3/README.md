# Independent native third watchdog

`watchdog3.exe` is a standalone Windows amd64 Go program. It needs no Python
interpreter, Qt, shell, network connection, or background package manager.
It observes and recovers the already installed `AngeronaProtection` service
through the native Windows Service Control Manager (SCM). It never installs,
reconfigures, stops or terminates that service.

## Build and test

Use Windows and Go 1.25 or newer. From the repository root:

```powershell
./tools/Build-AngeronaWatchdog3.ps1
./build/watchdog3/watchdog3.exe --version
```

The builder runs the native tests and `go vet`, then produces a trimmed
`CGO_ENABLED=0` executable, a SHA-256/source-input build record and license
notices under `build/watchdog3/`. `-GoExecutable` and `-OutputPath` can select
a compiler and an artifact directory on D:. Building does not register a
service/task, provision STOP authority, change the firewall, or start supervision.

Protocol fixtures come from the real Python codecs. Go tests verify those
bytes, and `tests/test_watchdog3_interop.py` verifies Go-generated heartbeats
and alert records with the real Python readers. Native tests use disposable
fixtures and harmless helper processes, never the operator's running Angerona.

## Recovery and STOP

- The installed service's registration, exact image/arguments, restricted
  virtual account, process identity, private custody and pinned image are checked.
  Native process handles and creation times bind observations to actual generations.
- Initial startup has 180 seconds of grace. A failed service exit must then
  remain stopped for 20 seconds before recovery. Running, pending, paused or
  uncertain states prevent duplicate starts; this program never kills a frozen
  process. A normal SCM stop (zero Windows exit code) is never auto-restarted,
  including on the supervisor's first observation.
- Administrator-signed STOP and its signed epoch take precedence when the
  control directory exists. The legacy HMAC command is used only on
  unprovisioned hosts. STOP is checked every loop and immediately before launch.
  Invalid authority is a held condition, not a successful stand-down.
- Recovery rechecks the protected registration and STOP immediately before
  calling `StartService` for the fixed installed service, with zero caller
  arguments. SCM owns activation of the pinned `Angerona.exe --engine-service`
  image. No direct executable launch, runtime hash learning, UAC bypass or
  command/environment override is used for installed recovery.
- Failed attempts back off from 1 to 60 seconds without a permanent give-up.
  A bounded authenticated ledger preserves restart pressure between runs.
  Persistence failures hold launches rather than discarding the ledger.
- The process honors termination by its owner/administrator. It has no hidden
  persistence, termination resistance, response actions or firewall authority.

The service graph intentionally does not run the legacy Python resilience pair
or publish their heartbeat files. Service state is reported as native SCM
observation, never fabricated heartbeat progress or proof that sensors work.
Authenticated v2 codecs and the older pair's pure decision tests remain available
for protocol compatibility; they are not installed service recovery authority.

The native supervisor's own heartbeat is `heartbeats/watchdog3.hb`; status is
`diagnostics/status_watchdog3.json`. Authenticated alerts use the separate
`diagnostics/watchdog3-peer-alerts.jsonl` chain. Compatible Python consumers can
verify these as observation-only evidence; the service does not claim a Python
pair or an alert-drain worker it has not started. Output is bounded. A full or invalid outbox reports
an evidence gap; it is not silently cleared to restore a green status.

## Installed deployment

Source checkouts do **not** auto-start this executable. A development build is
unsigned. The existing protected publisher/installer remains the authority for
production signing, registration, startup and removal. This change does not
create a task/service on the development computer.

The exclusive `--service` entry hosts this supervisor through the real Windows
SCM dispatcher as `AngeronaWatchdog3`. It admits only its actual own-process
LocalSystem/Session-0 registration, exact installed image and arguments, type-0
service SID policy and protected custody. A console invocation has no fallback.
SCM stop/shutdown cancels the existing runner and waits for its return before
reporting stopped. SCM running describes the dispatcher, not sensor health or
successful recovery. No engine admission rule is relaxed.

The [Windows service and signing guide](../../docs/enterprise/WINDOWS_SERVICE_ONBOARDING.md)
explains publisher enrollment, the read-only readiness report and the inert
installer review request. A certificate alone does not complete deployment:
MSIX's declarative service account choices cannot express the engine's existing
restricted virtual-account profile. The separate governed installer and signed
clean-VM acceptance remain required; neither is supplied by a manifest edit.

The fixed configuration is selected through the native Windows ProgramData
known-folder API: `Angerona/watchdog3/config.json`. Its directory and file must
be controlled by Administrators/SYSTEM, with read access for the operating
account. It is a closed schema containing exactly:

```json
{
  "schema": 2,
  "data_dir": "D:\\AngeronaWatchdogState",
  "launcher_path": "D:\\ProtectedApps\\Angerona\\Angerona.exe",
  "launcher_sha256": "REPLACE_WITH_THE_REVIEWED_SIGNED_LAUNCHER_SHA256",
  "launcher_args": ["--engine-service"],
  "working_directory": "D:\\ProtectedApps\\Angerona"
}
```

The placeholder is intentionally invalid. The installer supplies the actual
approved digest; the watchdog never discovers one by trusting the current file.
The private data directory belongs to this supervisor, not to the service's
separate `Protection` namespace. The protected installer must provision its
existing `shutdown.key` and private directory custody. The watchdog neither
creates nor repairs authority keys or clears STOP. An absent or incompatible
service/configuration is held, never silently created or repaired.

Run `watchdog3.exe --validate-only` to check the fixed installed configuration
without starting recovery. The installer may use `--config` only for that exact
known-folder path. Other command paths, network/device paths, alternate data
streams and unsupported arguments are rejected.

Before freezing a production Core, the trusted publisher must sign the native
executable and embed its **final signed bytes'** SHA-256 and exact trusted
publisher subject in `WATCHDOG3_SHA256`/`WATCHDOG3_PUBLISHER`. The admission
helper retains both executables and the protected configuration while checking
them. Unsigned or unpinned executables are refused. Signing changes bytes, so a
pre-sign digest is not a valid release pin.

The public release workflow builds an unsigned publisher request and leaves
activation pins empty. A trusted publisher can use the builder's
`-CertificateThumbprint` and `-ExpectedPublisher` with its existing approved
certificate; it must then freeze and authorize the resulting package through
the protected release process. No exportable signing secret is accepted by
repository CI, and no self-signed trust substitute is created.

Installed startup must be independent of the Core's child-process Job. The
installer chooses an account with the explicitly approved `SERVICE_START` and
query permissions; a per-user process is not silently elevated to obtain them.
It must not put this
supervisor in a Job that dies with either Python peer. Python's UI reports
authenticated observation and explicit unavailable/held states, not proof of
installation, publisher trust or successful recovery. The existing package,
SCM dispatcher and service-account admission checks are unchanged.
