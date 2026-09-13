# Ollama and Defender recovery — 2026-09-12

## Corrected behavior

The Ollama listener check now recognizes custom Windows installations recorded
under the official installer's fixed uninstall key. Registry metadata selects a
candidate only: the listening process must still match the executable identity,
the image must have a valid Ollama Inc. Authenticode signature, and every path
component must be local and free of redirection. PATH and arbitrary executable
overrides do not establish trust. Signature cache entries include file identity.

AI triage now distinguishes listener attestation, transport, missing-model, and
approved-model-baseline failures. The source startup assistant preserves only the
two explicitly configured model-directory settings after checking their bounded
local paths. Frozen startup continues to discard these environment overrides.
The model guard still requires authenticated operator approval and fresh byte
verification before inference; choosing a directory does not confer model trust.

The Defender bridge uses EvtQuery/EvtRender against the exact Defender Operational
channel. The former classic OpenEventLog call could silently open Application.
Every modern record must contain the correct channel/provider and bounded record
identity. Existing cursor or outbox authentication failures remain visible and
cannot be bypassed by falling back to PowerShell. A working PowerShell fallback
reports its limited event coverage explicitly.

Retained replay uses pages of at most 256 records. A fully consumed page yields
briefly before reading the next page; idle, error, and unacknowledged delivery
paths retain their normal polling delay. Consecutive filtered records are
validated together and commit one authenticated checkpoint per run, reducing a
256-record filtered page from 256 checkpoint writes to one. Runs flush before a
detection, whose durable outbox and downstream acknowledgement gates remain
unchanged. Failed writes, gaps, and interrupted runs cannot skip records.
The initial unbatched host replay reached its 900-second recovery budget and
closed cleanly. The final reader resumed its authenticated checkpoint and
verified the existing signed archive before continuing; no reset was repeated.

The offline harness can classify a missing approved baseline only when it is
absent from disposable workspace state and AI triage is stopped. Invalid trust
records and timeouts remain failures; the live model guard is unchanged.

## Approved host recovery

The operator explicitly approved both model enrollment and Defender tracking
recovery. All 18 model-store files were verified, including 15 content-addressed
blobs; all three installed manifests matched the official registry exactly.
The approved tags were `llama3:latest`, `llama3.2:3b`, and
`nomic-embed-text:latest`. No models were downloaded or replaced.

The prior Defender cursor referred to a record beyond the actual Defender
channel, and the outbox witness did not match its database. The old database
contained 68 delivered gap notices and no pending detections. The original
custody files, verified copies, and recovery receipts were retained in a private
runtime evidence archive before fresh enrollment. The previous coverage gap
remains historical evidence; this recovery does not certify missing history.
Retained detections are delivered to a signed, flushed recovery archive without
connecting response consumers. Normal monitoring resumes from the resulting
authenticated cursor.

Private keys, baselines, detection details, and runtime evidence are not included
in this repository update.

## Validation

- Ollama registry, signer, listener/process identity, readiness, transport,
  inventory, lifecycle, and Chill regressions: 72 passed.
- Defender modern-reader, filtered replay, cursor, outbox, XML, and delivery
  boundary regressions: initial combined 83 passed; final replay gates 61 passed.
- Startup and launch-boundary regressions: 129 passed, 1 expected skip.
- Controlled offline-harness policy: 22 passed. Final full selfcheck after model
  unload: 26 phases passed, zero failures; 69 module/pipeline passes and 16
  expected skips. Package compilation completed successfully for 384 entries.
- Live signed Ollama listener and approved `llama3` inference succeeded. The cold
  verification/completion took 261 seconds; temporary memory pressure and test
  timeouts during that load are retained in local validation logs. The test
  unloaded the model afterward and confirmed an empty loaded-model list.

Final live recovery passed all three checks: signed event-pipeline delivery,
installed/approved Ollama model attestation, and native Defender health at 100%.
The authenticated cursor reached record 15199, beyond the initial 15197 watermark.
The archive contains 1215 signed events including administrative test/recovery
events; the saved failure report now records three passes and zero failures.
The resumed recovery and final checks completed in 592.11 seconds. All original
custody files and their backup copies still match the reviewed hashes.

## Primary references

- [Ollama Windows documentation](https://docs.ollama.com/windows)
- [Official Ollama installer identity](https://github.com/ollama/ollama/blob/main/app/ollama.iss)
- [Microsoft EvtQuery API](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtquery)
- [Microsoft event-query guidance](https://learn.microsoft.com/en-us/windows/win32/wes/querying-for-events)
