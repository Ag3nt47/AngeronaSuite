# Hosted CI and secret-scan follow-up

Date: 2026-10-21. Maintenance version remains 1.13.0. Investigated commits:
`306911a931dab28d3ba0234711676f8653cf242f` and
`faadba63a3d6046aeec79233b020a908793e67bd`.

The [local complete-suite record](../timeout-rootcause-2026-10-21/README.md)
passed 5,107 tests with 25 skips. The subsequent hosted runs exposed two
separate issues. Local validation does not substitute for hosted acceptance.

## Hosted failures

The [job snapshot](hosted-failures.json) preserves the reported job outcomes
and failing assertion separately from the corrected commit's acceptance.

The [CI run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39659889736)
failed on Python 3.10, 3.11, 3.12 and 3.13. Each completed its full suite with
5,119 passes, 12 skips and the same one failure: the new sandbox scheduling
fixture's `peer_active_at_result` assertion. Child output success, explicit
normal child/target priority, below-normal parent creation and shared CPU
affinity assertions had already passed. The failure was not the child-output
deadline or descendant-retirement assertion.

That assertion observed the finite CPU peer after the sandbox call completed
its custody and temporary-state cleanup. The scheduling claim concerns CPU
availability during bounded output. The logs did not retain phase timings or
the peer's exit code, so they cannot establish its exact exit timing or cause.
The correction must observe the relevant phase while retaining separate
cleanup and process-ownership checks; it must not increase the child deadline
or turn the check into a skip.

The [Security assurance run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39659889812)
reported 21 `generic-api-key` findings, all in the historical `sources.json`
manifest. Each value was independently verified as the normalized SHA-256 of
its referenced public source file. Filenames containing credential-related
words triggered the heuristic beside their digests; no credential was found
in these 21 findings.

Exact commit/path/rule/line fingerprints retain full-history scanning and
ordinary API-key detection. A broad path or digest-pattern allowlist would
suppress unrelated future findings and is not used. The historical manifest
and its source-freeze evidence remain unchanged.

CodeQL, Scorecard, dependency audit, public README integrity, all three
platform-contract jobs and all three native installer jobs passed in those
same runs. Their success does not erase the five failed jobs.

## First correction and independent challenges

The first correction records the owned peer's process-handle status
immediately after the original bounded-output helper returns complete. It
also captures resume/output/return timing for diagnosis. After the sandbox
returns, the peer must still be running or have exited naturally with code
zero; sandbox cleanup must not terminate its sibling. The original child
success, priority, affinity and three-second descendant-retirement assertions
remain, as do the ten-second output deadline and finite 16-second peer.
No production Python or native code changes.

A controlled probe kept the original output and custody helpers intact and
delayed only post-output cleanup. The old fixture's final peer-alive assertion
failed after successful output, with the peer's natural exit code zero. The
corrected fixture passed its actual assertions in that same situation.
This demonstrates the observation mismatch; it does not reconstruct the
unrecorded hosted phase timings.

The corrected fixture's nine actual assertions passed with output returned
at 4.032 seconds and deliberately delayed return at 16.329 seconds, after
the peer exited naturally. The 51-case resource/custody/security gate passed
with zero skips, failures or errors. [Fixture evidence](sandbox-fixture.json)
records both observations, original limits, the actual test-file hash, the
focused JUnit hash and unchanged production helper hashes.
Compilation of the changed fixture, repository Ruff, documentation drift
and whitespace checks also passed. The prior all-module self-check and
complete local suite remain the dated `306911a` record; no new local
full-suite total is inferred from this focused selection.

## Second hosted attempt and coordinator priority

The first correction's [Security assurance run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39668432650)
passed secret scanning, CodeQL and Scorecard. Its [CI run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39668432468)
passed all eight non-Python jobs, but all four Python jobs failed. The
[second snapshot](hosted-second-attempt.json) retains the outcomes rather than
treating the passing local selection as hosted acceptance.

Python 3.11 recorded the finite peer's natural exit before native child resume
at 16.078 seconds. Python 3.12 and 3.13 completed child output but observed that
the peer had already exited. These logs locate the starvation earlier than
post-output cleanup. They did not record the coordinator's initial priority.

A paired experiment ran the exact test function under a disposable
below-normal driver. With inherited coordinator priority, the coordinator's
initial, saved and restored classes were all BELOW_NORMAL. Native resume
returned at 17.172 seconds and output at 17.922 seconds, after the peer's
natural exit. The actual test failed despite successful child output and
descendant retirement. With explicit NORMAL on outer coordinator creation,
those three readbacks were NORMAL, output completed at 5.063 seconds while
the peer remained active, and the actual test passed. The deliberate
BELOW_NORMAL parent around sandbox child creation remained verified.

This proves an inherited-priority defect in the fixture: the normal CPU peer
can delay the coordinator's native-resume and output phases. The paired probe
does not timestamp the inner ResumeThread call. Its mechanism is consistent
with the hosted phases, but does not reconstruct their unrecorded starting
process classes. [Paired evidence](coordinator-priority.json)
retains both observations and the unchanged 10-second output, 3-second
retirement, 16-second peer and 30-second coordinator budgets.

The correction requests NORMAL for the disposable coordinator and verifies
its initial and restored classes, including immediately before child resume.
The real sandbox child still starts from the temporarily below-normal parent;
child priority, shared CPU affinity, peer activity during output and sibling
ownership checks remain mandatory. No production scheduler or deadline changes.

The final fixture also passed under an actual below-normal driver with output
at 5.313 seconds and the peer active. Its 51-case focused gate passed in
33.13 seconds with zero skips, failures or errors. The proof records the final
test-file and JUnit hashes and confirms that all 414 product Python sources
match the earlier complete local regression's source map.

## Exit diagnostics after a passing summary

In the second attempt, Python 3.10 printed **5,120 passed / 12 skipped** and
then exited with code 1 about 0.402 seconds after its summary, without a
traceback or a reported failed test. This job failed; the passing test count
does not establish successful process shutdown. Its cause is not proved by
that log. The PowerShell step launched only one native command, so an exit
status from the separate custody step cannot explain it.

CI now keeps an independent journal of pytest's session result, unconfigure
boundaries, the actual pytest entry point's SystemExit or exception, and an
interpreter atexit observation. PowerShell records the native exit status
immediately after Python and returns that same status. The observer retains
the real pytest command-line arguments and verdict, with no skip, retry,
timeout increase or conversion of nonzero status into success. Future logs
can distinguish a test verdict from a later entry-point or shutdown failure.

The observer's **15-case gate passed in 35.75 seconds**. It challenges real
test and collection failures, unconfigure exceptions, closed stdout, failed
journal I/O, and a passing pytest exit followed by native shutdown exit 7.
That last challenge retains process exit 7 rather than reporting success.
The exact CI launcher then passed the **51-case resource gate in 22.08
seconds**, with pytest, session and native process exit codes all zero.
Both atexit markers and completed unconfigure were observed. These markers
do not cover every native cleanup operation; the external exit code covers
the process result. [Diagnostic evidence](ci-diagnostics.json) retains the
commands, hashes, limits and the earlier local collection-probe failure
whose original cause could not be recovered. CI diagnostic tails print
curated status fields and omit raw failure/Qt text and parameter values.

## Secret-scanner validation

The same Gitleaks 8.24.3 version used by GitHub reproduced all 21 findings
before the correction and zero afterward. An all-ref historical scan found
one additional older public-source-hash false positive in `a3188df`; it was
independently verified and received its own exact fingerprint. There are
22 new fingerprint exceptions, with no wildcard or rule changes.

The pre-follow-up historical snapshot then passed with zero findings across
200 commits and 24.71 MB. Two isolated positive canaries remained detectable:
a generic API key at the same manifest path and line in a different commit,
and a GitHub token. Both were still detected in history after removal from
the latest fixture tree. No canary credential values are republished here.
[Scanner evidence](gitleaks.json) retains tool provenance, commands, report
hashes, narrow exception scope and the historical snapshot boundary.

Hosted acceptance is separate: the published correction's Python matrix and
security jobs must pass. The current commit's checks are available in
[GitHub Actions](https://github.com/Ag3nt47/AngeronaSuite/actions).
