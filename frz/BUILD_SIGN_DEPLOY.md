# BL-01 — Build, Sign, Deploy the Out-of-Process Watchdog

The Go watchdog (`angerona_watchdog.go`) is the resilience **parent**: it launches
Angerona, SHA-256-verifies the on-disk binary before every (re)launch, holds the
real process **handle** (a spoofed PID can't fool it), detects forced termination
and thread suspension via the shared heartbeat, relaunches with a crash-loop
throttle, and hardens itself with process-mitigation policies. It is bounded, not
un-killable (a clean shutdown, a `watchdog.stop` file, or a restart storm all stop
it) — an un-killable watchdog would be indistinguishable from a rootkit.

The current `start-angerona.bat` uses verified Safe Startup and the Python peer
watchdog. Placing a Go executable beside the checkout does not select it.
The compiled watchdog remains an explicit deployment/development option: its
command accepts an agent executable and arguments, and it sets
`ANGERONA_EXTERNAL_WATCHDOG=1` for that child. When an external parent is
configured, `resilience/manager.py` skips its internal Python watchdog.

## 1. Build (needs the Go toolchain)

```bat
:: install Go from https://go.dev/dl/ (once), then:
cd AngeronaSuite\frz
go env -w GOOS=windows GOARCH=amd64
go mod init angerona_watchdog 2>nul
go get golang.org/x/sys/windows
go build -ldflags="-s -w" -o ..\angerona_watchdog.exe angerona_watchdog.go
```

Result: `AngeronaSuite\angerona_watchdog.exe`. `-s -w` strips symbols for a lean
binary. (`frz\build-watchdog.bat` automates this.)

## 2. Code-sign (required for real tamper resistance)

An unsigned exe gives resilience but no OS-level trust. For production:

1. Obtain an **EV (or OV) code-signing certificate** from a CA (DigiCert, Sectigo,
   etc.). EV keys live on a hardware token / HSM.
2. Sign with the Windows SDK `signtool`:

```bat
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 ^
    /a AngeronaSuite\angerona_watchdog.exe
signtool verify /pa /v AngeronaSuite\angerona_watchdog.exe
```

Sign `blackbox_recorder.py`'s launcher and any other resilience binaries the same
way if you distribute them.

## 3. Deploy

Build and sign the watchdog before arranging an explicit deployment around a
reviewed agent executable. Its command interface is:

```bat
angerona_watchdog.exe <reviewed-agent.exe> [agent arguments...]
```

Set `ANGERONA_WD_DATADIR` to the approved runtime location and
`ANGERONA_AGENT_SHA256` to the reviewed executable digest. A learned local hash
is continuity information, not publisher authentication. This command does not
enroll a Windows service or integrate a signed package automatically. Keep
using `start-angerona.bat` for source checkout startup; a raw Python command
does not replace that launcher's dependency, recovery and readiness checks.

Watchdog children use hidden console flags. An externally supervised source
custody failure remains held with stderr diagnostics instead of opening a
modal message box. This presentation hint grants no trust, privilege or STOP
resume authority: the first-launch and automatic-recovery STOP rules remain
separate. Validate an isolated deployment's own logs, authenticated heartbeats,
normal STOP and bounded restart behavior before relying on it.

## Out of scope here (needs a driver + Microsoft signing, not a code change)

The remaining, strongest BL-01 controls cannot be done from user-mode Python/Go:

- **PPL / Protected Process Light** (`PsProtectedSignerAntimalware`) — makes the OS
  itself refuse to open/kill/read the process. Requires a Microsoft-signed **ELAM**
  driver and enrollment; you must be a registered anti-malware vendor.
- **Kernel-sourced ETW-TI callbacks** — tamper-proof telemetry from a **kernel
  driver** (WHQL-signed).

These are a driver + certification project, tracked separately. The interpreter-side
detection of the third vector (in-memory monkeypatching) is already shipped as the
`Self-Integrity Monitor` (SINT) module.
```
