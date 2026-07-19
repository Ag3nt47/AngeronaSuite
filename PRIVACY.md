# Privacy and data handling

Angerona is local-first. Runtime databases, logs, diagnostics, settings, drill
artifacts, models, and encrypted credentials are excluded from Git and should
remain on the operator's machine.

## Local data

- Source installs store runtime state under the checkout's `runtime-data/`
  directory (the D: drive in the reference setup).
- Packaged releases store mutable state under `%PROGRAMDATA%\Angerona` and keep
  packaged code read-only.
- Credentials are encrypted with Windows DPAPI for the current user. Angerona no
  longer loads credentials from the working directory.
- Offline speech audio is processed locally and is not retained by the voice
  connector. Microphone listening is off until the operator enables it.

## Optional network egress

Cloud AI fallback, cloud text-to-speech, mailbox triage, Teams, channel push,
research lookups, SIEM forwarding, mobile integration, and Remote Bridge are
optional. Each is off until configured. ARIA cloud fallback sends only a
bounded, redacted question and posture label—not raw alerts, runbooks, local
paths, usernames, or files. SIEM defaults to verified TLS and redacts common
identifiers unless the operator explicitly chooses raw forwarding.

Ollama model and Vosk speech-model downloads occur during the one-click install
or after an explicit setup action. Release builds pin and verify the Vosk model
checksum.

## Before publishing or sharing diagnostics

Use a fresh support bundle and review it manually. Remove usernames, email
addresses, IP addresses, file paths, command lines, hostnames, tokens, and any
business or personal document names. Deleting a file from the current checkout
does not remove it from Git history; scrub history before making a repository
public if an earlier commit contained personal data or secrets.

