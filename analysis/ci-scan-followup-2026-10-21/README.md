# Hosted CI and secret-scan follow-up

Date: 2026-10-21. Maintenance version remains 1.13.0. Investigated commit:
`306911a931dab28d3ba0234711676f8653cf242f`.

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

## Corrected observation and independent challenges

The scheduling fixture now records the owned peer's process-handle status
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
