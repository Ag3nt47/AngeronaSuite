# BL-01 — Build, Sign, Deploy the Out-of-Process Watchdog

The Go watchdog (`angerona_watchdog.go`) is the resilience **parent**: it launches
Angerona, SHA-256-verifies the on-disk binary before every (re)launch, holds the
real process **handle** (a spoofed PID can't fool it), detects forced termination
and thread suspension via the shared heartbeat, relaunches with a crash-loop
throttle, and hardens itself with process-mitigation policies. It is bounded, not
un-killable (a clean shutdown, a `watchdog.stop` file, or a restart storm all stop
it) — an un-killable watchdog would be indistinguishable from a rootkit.

Angerona already prefers it automatically once it exists:
- `start-angerona.bat` launches via `frz\angerona_watchdog.exe` when present and
  sets `ANGERONA_EXTERNAL_WATCHDOG=1` + `ANGERONA_AGENT_SHA256`.
- `resilience/manager.py` then **skips** its internal Python watchdog, so there is
  no double-supervision.

If the exe is absent, nothing changes — the Python peer watchdog runs as before.

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

Just place the (signed) `angerona_watchdog.exe` at `AngeronaSuite\angerona_watchdog.exe`
and start via `start-angerona.bat`. Verify from the watchdog log:

```
type runtime-data\watchdog.log
```

You should see `mitigation applied`, `integrity baseline learned` (first run) or a
match, and `agent launched pid=…`. Kill Angerona from Task Manager → the log should
show `AGENT TERMINATED` and a relaunch.

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
