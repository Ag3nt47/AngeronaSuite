# Changelog

## 1.14.0 — focused maintenance review

- Replace Resolve Center's empty-list "Secure" claim with neutral wording that
  keeps exposures and protection readiness separate (GUI-19).
- Apply nonblocking Black Box detail-dialog shutdown while retaining a busy
  worker's owner and dialog result; six actual-QThread controls passed within
  the 148-test focused gate (SIDE-07). This does not identify the historical five-second UI-stall cause.
- Admit calendar-valid dated CISA alerts while retaining existing undated
  categories, URL restrictions, publication freshness and advisory-only output
  (NEWS-02). All 32 new offline cases passed within the focused gate; live CISA
  availability remains unproved.

Prior checkpoint [36dfadf](https://github.com/Ag3nt47/AngeronaSuite/commit/36dfadf1052e5a2e656afa52376b2f310a092446) is published on public main
with all seven README assets verified. Its unsigned archives describe the historical
09c7 source snapshot, not these changed-source files. Exact-head [CI](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39994972951)
and [Security](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39994972961) at 17:33 UTC on
23 October showed Security 3/3 and eight non-Python CI jobs passed; four Python
jobs were still running.

Validation: six full suites passed **148 tests**, no failures/errors/skips, with
exact interpreter retirement and MainThread/no QApplication/zero-widget shutdown.
The unchanged tested code snapshot is 1857/ae402; 09c7 packages are historical.
The held-thread queries are inert, CISA cases offline, and no PowerShell, network,
full regression, selfcheck, signed release or physical-protection proof is claimed.

A later lint scan flagged six F821 references in the new test callbacks. The
callbacks now use weak references; the six affected cases passed separately
with exact retirement. These cases overlap the 148-test cohort. Product code
is unchanged; the initial lint failure and original test receipt are retained.

## 1.14.0 — 2026-10-23 published maintenance

- Read shared HKCU Run/RunOnce keys once, retaining separate HKLM views and
  missing/denied coverage. Original R7 findings remain unadjudicated.
- Bind CVE analyses and cached proposals to exact current records and accepted
  request order. Preserve distinct duplicate rows and retain live or unknown
  workers through startup failure, close and asynchronous retirement.
- Reconcile source-conflict resolutions after process interruption only for the
  same explicit choice and verified owned bytes. Partial, changed, replaced or
  unowned candidates remain held. POSIX retry opens require nonblocking/no-follow
  flags and descriptor checks before stream construction; this does not prove
  power-loss recovery or a universal device-I/O deadline.
- Add bounded release-fixture operation tracing without changing checks or
  deadlines. The hosted 6ead Python 3.11 timeout cause remains UNKNOWN.
- Require lossless native receipt review; corrections are advisory artifacts
  separate from authenticated originals.

Validation: initial **214-test cohort**, final **54-test follow-up**, **1,152 AST
checks** and **29-phase default selfcheck** passed. The test cohorts overlap;
68 module rows passed and 18 were explicitly skipped. Exact retirement was
verified. A **90.140-second pair observation completed with coverage gaps** and
352 status/heartbeat samples; all four exported events had
response_authorized=false. This checkpoint was published as 36dfadf; the
publication proof is separate from the retained test and observation receipts.

The [issue review](analysis/live-debug-2026-10-22/README.md) and
[validation record](analysis/live-debug-2026-10-22/validation.json) retain earlier
results, failures and limits. See the [v1.14 feature notes](docs/releases/v1.14.0.md)
for the wider feature set. Source publication does not grant release trust,
installed enforcement or source-activation authority.
