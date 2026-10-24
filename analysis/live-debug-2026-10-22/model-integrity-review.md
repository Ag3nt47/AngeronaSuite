# Model-integrity reader maintenance

This v1.14.0 maintenance change reduces a manifest read request to the already
admitted file size plus one byte. The extra byte still detects growth; file
identity, exact length, cap, hash, baseline and response rules remain unchanged.
Broader v1.15 work is incomplete. This reference distinguishes tested behavior,
synthetic measurements and remaining source-review gaps.

## Applied change and open findings

| Issue | Current state | Boundary |
| --- | --- | --- |
| PER-19 | Scoped reader change applied and validated | One expression changes the request from the 16 MiB cap plus one to admitted size plus one; no production speed or stronger-security claim |
| SEC-19 | OPEN: lexical alias contract | Canonicalization can erase an original link alias before lower-level no-link checks. Full approved inventory rejects links and pinned manifest/blob digests still apply; no new lower-trust hash or baseline bypass is confirmed |
| SEC-20 | OPEN: parser error normalization | Deep or malformed parser failures are not uniformly normalized by lower-level APIs. Outer callers hold on errors; no runtime denial of service or fail-open bypass was reproduced |
| DBG-18 | Private validation scope repaired and observer guarded | Initial stale grader refusal remains failed. Subsequent fresh full gate and separately controlled observer have their own receipts; private harness fixes are not product protection features |
| OBS-08 | Fresh observations retain gaps | Combined default-profile evidence and the separate synthetic model worker answer different questions; neither adjudicates host alerts or proves complete protection |

The reader still compares device/inode/size. It does not add a final named-path
check, mtime comparison, native file-object lease or atomic resolve/open. No
identical result under every concurrent mutation schedule is asserted. These
existing boundaries and the two OPEN findings are retained for future work.

## Functional validation

The fresh accepted cohort contains 39 suites, 544 function occurrences and
1061 collected cases: 1059 passed, zero failures/errors and two exact Windows
availability skips. All 75 privacy cases, seven named nested regressions and
88 added/adjacent cases are included in that total. The groups are not additive.
Actual collection agrees with the full per-function static counter. The skips
are the unavailable distinct Windows 8.3 filename and unavailable symlink
creation; acceptance is complete while coverage remains incomplete.

The first acceptance attempt is preserved: the tests had 1059 passes and native
exit zero, but the private grader still required 34 suites and rejected the
39-suite scope. That receipt remains FAILED. A corrected private grader was
followed by a new complete run; later success does not rewrite the first result.

Fresh isolated selfcheck passed all 29 phases. Its 86-module inventory reports
68 module PASS plus one Event pipeline PASS, with 18 module SKIP. Five required
origins were loaded; seven configured products loaded in total and five remained
unloaded. This selfcheck did not perform active model attestation and does not
show all 86 modules operating together.

## Fresh observations

The default profile ran its 15 reviewed modules for 600.297 seconds (613.282
seconds total), with 1672 heartbeats and 463 events: one CRITICAL, two HIGH,
428 INFO, 29 LOW and three MEDIUM. There were zero recorded errors, drops or
pending threads. It retained 19 interval gap strings: 18 module strings across
ten modules, plus one global heartbeat gap of 3.531 seconds. C2 and Sysmon ended
at health 100; that does not erase their earlier interval gaps. The model guard
is held in this default profile and was not active in this combined observation.

The longest heartbeat-persistence stage took 3.2106547 seconds. That path already
used durable=False and skipped explicit fsync. Disk latency, API behavior,
descheduling and other causes remain UNKNOWN; this observation identifies no
GUI stall or causal performance fix. Primary-worker CPU coverage is not complete
helper attribution or an exclusive-workload measurement. Historical unretired
read-only diagnostic utility/competing-load uncertainty remains explicit.

A separate 30-second child ran the actual model-integrity worker against a new
private synthetic baseline, key and two-file model tree. It recorded one actual
117-byte manifest return, one reader call/return and one verification call/return
(four ordered profile records), two verified files, 120 snapshots and one event.
There were zero recorded errors or audit denials. The original worker retired;
separate proof covers exactly two outer process generations and their cleanup.
The four configured source origins were loaded. Original module methods, key
provider and cadence were unchanged; no real operator enrollment, production
key custody, model/provider efficacy, GUI behavior or speedup was proved.
It demonstrates normal post-pass sleep cancellation, not cancellation during
blocking filesystem I/O. The 165 parent controls, 70 target controls and actual
optimized-mode refusal are separate harness evidence, outside the 1061 cases.

Additional same-source serial cases completed: SpywareGuard ran for 30.047 s,
with 117 observer heartbeats and three events (two LOW and one MEDIUM); its
preview health was 85 and two coverage gap strings remain retained. The raw
scanner ran for 30.188 s, with 119 observer heartbeats, 31 scanner heartbeats,
18 scanner events and no coverage gaps. Both cases recorded zero errors, drops
or pending threads. Each retired exactly two outer process generations and its
separately admitted core, with genuine zero exits and unchanged frozen inputs.
Scanner worker CPU profiling was incomplete, with no usable segments; these
cases establish no speed, efficacy, GUI or host-clean verdict. SpywareGuard
result: `c11d948e88e9a2960b38ea5c2fc5549b0ee91bceff3bf562ab8b6fda19516cdf`;
raw-scanner result: `dd460eb4e3ac6703477243bb6be021fd01e1fa1243d2f0daec4e09ba41ee7a25`.

The unchanged offline case-map tool processed the selected diagnostic copy:
474 records (463 events plus 11 coverage records) became 203 case groups, with
zero parse omissions, overflow or identity conflicts. Processing is complete;
independent evidence continuity is not verified. Every group remains needs-review,
with no automatic response or original alert status change. Three HIGH/CRITICAL
groups matched source templates for fresh-profile exposure/recovery gaps or
unbound Fleet state; they remain advisory_only with response_authorized=false.
This is source-backed triage context, not a host-clean, actor or false-positive
verdict. Summary receipt a554c059b0ae094202b227b4f5975f630d4bfad726932479c0844cd03ab4816a.

## Synthetic allocation evidence

One 8192-byte synthetic regular file was read 16 times with an admission stand-in:
six timing reads per version and two allocation reads per version. The two
tracked Python allocation peaks were 16,787,510 bytes for the old request and
18,873 bytes for the new request. This is a measured fixture result, not RSS,
native allocation, real-model performance or a whole-product speed gain. It
does not establish the cause of any earlier high kernel CPU or heartbeat delay.

## Receipt index and completion boundary

These private receipt hashes identify the reviewed evidence; raw captures,
process identifiers, host paths and key material are not published here.

| Evidence | SHA-256 |
| --- | --- |
| Tested pre-documentation source map | df99ccc169aa9d5b263ec982ab86b7a25c2c4444523afc839cf19681da353d9a |
| Failed first acceptance, retained | f7a743038087b51e81fb392285777f03de589d01e3fdca4649de9a9b00781d1b |
| Fresh accepted second cohort | f69960e2f2d87ac192a10cbf1664d731d4934e2da204434161a21c62ebf3dd36 |
| Accepted cohort root review | 40088801c6e472138eaedbfe14aed608ca7deb38e2e58bee15e0af1ebb46a0bf |
| Actual collection ledger | b76699d8dec3d331804e997feb0bf2915aa32a879f5d7111bd2abb1a6ac99d3d |
| Full static multiplicity counter | bcfb40a16e818076c770d0cc3c67f13202a320d11435e06bd9f16e687ce21bce |
| Fresh selfcheck | 7038054e194e878c2cf05a15e87cbfd376a06b86bcf81574ffb86f6e0e095be1 |
| Combined 15-module observation | 580b13903cb9e20b076da6e2f6f6db0cc85aefa8d05d2e7bc1e272d053115e83 |
| Combined observation root review | 7498eb80319f964fb822666c8233b46e2c4d1684a9a4f9e99ae443f9638e7d88 |
| Synthetic model-worker observation | a246b6c774a93a3859d386311f4dcbc22444b47a46c4d3e3130af94e79a983b0 |
| Model-worker root review | 9aaeae3edb278e58a62a9744cb2701ca55905673c28b980da6e662bbb3513f44 |
| Synthetic allocation measurement | a5228f3413f2928176bd60ddcbcf4ded60fce20357838f64633e9b2e662e072c |

The reviewed scope is two code/test paths and eight documentation paths, with
two additions: the new reader test and this reference. Final inventory is expected
to contain 1878 source entries and 1165 Python entries; final exact scope/full
source checks remain mandatory. Fresh final-source offline validation and the
unchanged canonical guarded publisher require their own completed proofs; these
receipts do not preclaim publication. Historical cf668016 publication/CI completed
12 CI jobs and three Security jobs; each of its four Python jobs recorded 8381
passes/22 skips. Those results validate that prior revision only.

HOST-03 updater custody, HOST-04 capacity below the requested 2 GiB buffer,
earlier unknown causes and threat/false-positive questions remain unresolved.
Source/origin pins do not attest every imported or cached runtime byte. No
all-86, independent trust-anchor, real enrollment, host-cleanliness, security-
strength or v1.15-completion claim is made. See the [issue register](README.md)
and [interaction map](interaction-map.md) for current and historical scope.
