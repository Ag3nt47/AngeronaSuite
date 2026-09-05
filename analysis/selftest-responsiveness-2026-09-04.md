# Self-test responsiveness — 2026-09-04

The operator's live diagnostic report had completed: **74 passed, 3 failed,
8 skipped**. The failures were local Ollama/model availability, a persisted
Defender telemetry continuity gap, and Adversary Combat's recovery hold.
Those results require separate review; restarting modules cannot restore lost
events or establish journal/recovery authority.

GUI watchdog captures then showed the main thread inside the static
`QMessageBox.information` call titled "Self-test needs operator attention" for
21–25 seconds. Earlier captures showed 5–11-second stalls in practice-event
path classification during dashboard refresh and threat-animation updates.

Changes:

- Replace modal completion/recovery prompts with a retained, modeless results
  dialog that opts out of global reveal masks. It contains scrollable plain
  text, specific next steps, full report copying, module details, retry and
  Close/Escape. No nested `exec()` loop runs on completion.
- Require an unchecked approval control before requesting audited restarts;
  revalidate module eligibility and hold the shared self-test lock during the
  lifecycle change. Manual failures and still-running tests are not restarted.
- Convert runner/worker-start errors into visible results with released busy
  controls. Closing a results window or the dashboard tolerates late signals.
- Bound actual active module calls to six process-wide. A timed-out thread
  retains its permit and module lock until it really returns. The inspector
  uses the same bounded check and does not leave its button waiting forever.
- Bound pipeline, progress and event-reporting waits. Blocked callbacks cannot
  create unlimited abandoned reporting threads. Failed delivery is reported
  explicitly and preserved in the diagnostic result instead of hiding failure.
- Avoid practice-path filesystem resolution for ordinary/unregistered events.
  Registered positive candidates still receive fresh resolution outside the
  registry lock, followed by live registration/revocation checks. Unknown
  aliases fail closed.

Validation uses offscreen Qt harnesses, fake modules/callbacks, and disposable
runtime storage. Tests cover responsive parent buttons/timers, Close/Escape,
manual-result guidance, explicit single restart approval, concurrent retry,
worker failures, held callbacks, repeated timeouts, inspector overlap,
registration expiry/revocation and changed reparse targets. No live response
actions, drivers, provider downloads, or journal resets are part of validation.
The final targeted regression run passed **102 tests**. The offline application
self-check passed **26/26**; Ruff, compile and documentation drift checks passed.

Limits: Python cannot safely terminate a stuck in-process module function;
the retained permit prevents duplicate work, while a controlled application
restart may still be needed. A genuinely registered artifact still requires
fresh filesystem verification. The existing kernel-driver result policy was
outside this responsiveness change. The running application must be restarted
to load the updated code.
