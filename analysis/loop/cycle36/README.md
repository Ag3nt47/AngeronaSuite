# Cycle 36 — native drill scoring and selected-sensor responsiveness

Date: 2026-09-26
Release line: **v1.13.0 maintenance follow-up**

Cycle 35 was validated and published to canonical public `main` at
`5feda7322c44bc0d5cc0149b2ef5031573c557fd`. Its exact-commit five-check
gate passed, including **4,353 pytest passes and 20 skips**. Cycle 36 work and
the measurements below are a separate follow-up with their own release gate.

## Scoring and operator display

The current AAR change separates matched simulation evidence from genuine
native analytic detection. For the exact reviewed Red Team plan, it reports
**36 file-marker steps where FIM could observe a file** and **one process
observation-only step**. Opportunity is a plan classification, not proof that
FIM was enabled, ready, fast enough, or that it detected anything. The Red Team
console displays the native count beside the verified simulation-containment
result and marks unavailable or inconsistent score fields as unavailable.

An actual offscreen GUI clickthrough with FIM, Purple Guard, Process Monitor,
and Combat completed **38/38** comprehensive steps. The signed AAR credited
**37/37 exact verified containment responses** and **14/37 native analytic
detections overall**: **14/36 file-marker opportunities**, with the remaining
step being process observation-only rather than a FIM file opportunity. A
separate-process OS witness checked all **36** source-marker removals and
quarantine SHA-256 matches after handle release, plus three tagged process
exits with captured birth identities. Absence alone does not prove termination;
the signed Combat journal and exact response receipts supply containment
credit. A separate concurrent base FIM+Combat test credited **11/12 native
file-marker detections** and **13/13 verified responses**.

These are inert, local drill results. The 37/37 containment score measures
Angerona's signed simulation response contract, and 14/37 describes native
analytic observations in this particular FIM-enabled fixture. Neither is a
general real-attack detection or protection rate. The process-only step is not
counted as a missed FIM file opportunity.

## Chill and Full mode witness

The [performance record](performance_summary.md) used a real offscreen
`MainWindow` with all **84** modules discovered but only Process Monitor, FIM,
and YARA Scanner enabled. FIM and YARA examined **128 benign temporary files**.
Across 120 seconds each in initial Chill, Full, and returned Chill, process CPU
averaged **11.01%, 34.92%, and 8.27% of one logical core**. The 20 ms Qt
heartbeat's maximum slips were **105, 168, and 58 ms** respectively, with
**zero gaps over 250 ms**. RSS ended at **129.727, 137.215, and 137.281 MiB**;
returned Chill changed by about **0.18 MiB**. FIM and YARA completed actual
Full-mode cycles and paused again in Chill; Process Monitor kept running.

The first witness's `QApplication.quit()` exit failed because the app hides to
tray on Close; an independent minimal Qt reproduction confirmed the harness
mistake. A shorter repeat using `QApplication.exit(0)` exited cleanly and
measured synchronous Chill→Full and Full→Chill calls at **16 ms / <1 ms**.
No product scan cadence or response policy was changed for this witness. It
does not establish all-worker, physical-display, concurrent Combat, or all-day
stability; a full-host freeze trace remains a separate acceptance measure.

## Release verification

The targeted results above do not replace an exact-commit full release gate or
guarded GitHub publication. Release status is established by the gate evidence
and publisher for the final commit.

The first exact-commit gate on `0600bcecf79f54af0b25dc99431604c4e3e473db`
passed bytecode, dependency audit, documentation drift, and lint, but full
pytest ended at **4,363 passed / 20 skipped / 3 failed** without a native Qt
abort. The failures were timing assertions in IPC restart, isolated Windows
sandbox startup, and Fleet partial-request shutdown. The sandbox's 3-second
fixture startup cap failed twice even alone; its offline/disposable assertions
remain unchanged with a 20-second fixture cap, while the separate hanging-child
deadline remains 0.25 seconds. Fleet's stop test now allows its documented
graceful-plus-forced drain and still checks replay-ledger release; its six-test
module passed. The IPC case passed 20 fresh-process repetitions before any
edit, so its exact gate assertion is unknown. Its fixture deadlines now allow
the listener's one-second accept timeout and key reload while retaining live
authentication and old-helper retirement checks; the six-test lifecycle module
passed. These are fixture-bound changes, not product timeout or security-policy
relaxations. A new exact-commit gate was required for the combined tree.

The second exact-commit gate on `8be9d125273829500feebf3b60e801a349bafb73`
again passed the four non-pytest checks, then finished **4,365 passed / 20
skipped / 1 failed** without a Qt abort. The sole failure was the read-only
Windows QEMU bootstrap fixture: a PowerShell child exceeded its 20-second
test deadline under that run's load. The focused case and all **33** QEMU setup
module tests pass. Its fixture now allows 60 seconds for cold PowerShell startup
and Program Files ACL inspection; exit status, no-compiler, no-mutation, and
protected-path assertions remain unchanged. No QEMU production code was changed.
A further exact-commit full gate was required for these combined test fixes.
