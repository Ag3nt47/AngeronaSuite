# September 23 upgrade validation

Package version remains **1.13.0**. This record separates actual native
acceptance, offline regression, module checks and component measurements.
Focused groups overlap and must not be added together as a full-suite total.

## Final regression gate

The final serial suite after code freeze passed: **4,303 passed / 20 skipped /
0 failed** in **478.73 seconds (7:58)**, exit status 0. Local run evidence is
`.tmp/upgrade-20260923-final-tests.log` and its JUnit companion
`.tmp/upgrade-20260923-final-tests.xml`. These local diagnostic artifacts are
not public release assets. This is a complete final run, separate from the
earlier broad run and overlapping focused gates below.

The first broad run reported **4,213 passed / 20 skipped / 6 failed**. Five AI
broker failures occurred while product code was being edited concurrently;
all nine unchanged broker regression tests passed after the final code fix.
Their expectations were not weakened. The sixth failure exposed three missing
alert-retention fields in setup. Those fields were added, and the combined
setup, existing broker and new AI-integrity gate passed 41 tests. These repairs
do not turn that first run into a final full-suite pass.

## Native acceptance

| Path | Evidence | Scope |
| --- | --- | --- |
| Automatic file response | Actual YARA-X scan, live Combat worker, automatic quarantine, signed verified outcome and Undo for inert plain-file/ZIP fixtures; changed-content negative control | No Ollama and no manual response dispatch. Does not prove all Shark steps or field detection efficacy. |
| Detached engine | Separate native Windows process, reconnect and explicit stop, 8.234 s isolated acceptance | All 84 modules were disabled to isolate lifecycle. This is not evidence of active protection coverage. |
| GUI metrics | Actual Qt console timer, ten-second metrics publication and separate two-second smoke run; p95 callback 15.0 ms | Short plumbing check, not a long GUI performance claim. |
| Headless metrics | Authenticated engine metrics and two-second smoke run passed | GUI latency explicitly not applicable. |
| Encrypted recovery | Three files / 1107 bytes restored and hash-verified in 6.485 s; second-process Windows protected-key access and tamper rejection | Local recovery only; no independent/offline/offsite failure domain. |

The previous native QEMU Lab analyzer and end-to-end checks are recorded in
[continuation validation](../continuation-20260923/validation.md). Native
Mac/Linux source-launcher CI belongs to the earlier
[publication follow-up](../deep-review-20260923/publication-followup.md), not
new-service or signed-package acceptance for this upgrade.

## Offline checks

- Final package compile check: **403 Python files passed**. Root `compileall`
  and Ruff checks also passed after code freeze.
- `pip check` exited successfully with no broken requirements. `pip audit`
  reported no known vulnerabilities for the audited packages, but skipped the
  local editable `angerona` metadata (still labelled 1.10.0 in this environment)
  and vendored `srt 0.0.0+angerona.1`, which are not PyPI audit targets. The
  checked-out product version remains 1.13.0. This result does not establish
  vulnerability coverage for those two skipped packages.
- Module import audit: **86 module files imported**, **84 capability classes**.
  Read-only capability export: **84 unique identities**, **9 native contracts**,
  **75 compatibility adapters**, all implementation versions 1.13.0.
- Isolated selfcheck: **26 phases passed / 0 failed**. Its 30-step drill and
  related phases passed with the same 30-second deadline after lifecycle repair.
  Timeout cleanup now stops owned workers before releasing the validation lease;
  mandatory failed steps are failures rather than silent success.
- SelfTestRunner: **66 module passes + 1 separate event-pipeline pass = 67**,
  with **18 explicit module prerequisite/platform skips**. Separately, **31 core
  self-tests and 1 Red Team self-test passed**. These are different populations
  and are not added to pytest totals. Offline passes do not establish live
  privileged sensor readiness.
- Focused YARA automatic-response gate: **27 passed**. AI-integrity/retention
  gate: **85 passed / 2 skipped**. Engine/recovery gate: **61 passed**.
  Detection-quality gate: **26 passed**. Final metrics/engine/soak gate:
  **75 passed**. These selected sets overlap the final suite.
- Native receipt tests reject fabricated signed native fields, substituted
  producer objects, verifier overrides, mutated/re-signed events and prior
  lifecycle generations. The [adversarial review](adversary-review.md) records
  archive, retention, IPC, AI-custody, rollback and path-alias findings.

The [independent bug-hunter report](bug-hunt.md) records the selfcheck repairs,
module/core populations and a separate 70-pass / 2-skip integrity/retention gate.
The documented labelled-replay command was also run successfully: eight
synthetic rows yielded candidate TP=2, FP=1, FN=2 and TN=3. With no thresholds
configured its status was `measured`, not a promotion pass.

## Component measurements

| Measurement | Before | After | Interpretation |
| --- | ---: | ---: | --- |
| Shared process collection across three consumers | 314.210 ms | 99.543 ms | 68.32% less collection time in this component fixture. |
| YARA collection, 48 unchanged files / 6.72 MB | Median 2556.949 ms | Median 66.532 ms | Cached repeat versus uncached content collection, measured during concurrent offline tests. |

[YARA measurement record](yara-cache-benchmark.json). Neither result is a
whole-PC benchmark or a 24-hour/7-day memory/CPU stability result. Process-tree
and fresh queue/GUI measurements are now available for those longer acceptance
runs; missing counters and headless-only timing retain explicit limits.

## Remaining external or unmeasured gates

- Publisher signing and Apple Developer ID/notarization credentials are not
  configured. Trusted Windows installation/SCM protection and Mac package
  acceptance remain unprovisioned.
- Elevated Ollama process acceptance remains pending after the prior cancelled
  UAC request. The earlier ordinary-user cold-start result is separate evidence.
- New per-user service installation, reboot/logoff and visible desktop behavior
  still need native acceptance on each supported Mac/Linux host.
- Representative 24-hour/7-day Chill workloads, sleep/resume, sustained event
  bursts, field false-positive rates and independent comparative detection
  effectiveness have not been established by short or synthetic tests.
- POSIX mapped AI mutations require immutable consumer custody; external AI
  socket enforcement needs a real native adapter. The process-egress guard
  remains observe-only. Independent backup destinations remain a separate
  deployment integration.

GitHub publication and exact-commit CI status belong to the final maintainer
publication step; an earlier green commit does not validate this changed tree.
