# Cycle 23 Round 2 — Performance Summary

Date: 2026-08-26  
Scope: Cycle 23 Round 2 changes for independent freshness, audit-log identity,
per-user SSH source custody and client-option parsing, Windows OpenSSH source
recovery, bounded network completeness, Personal Sentinel route binding, live
activity, and Defense Memory.

Independent freshness/authentication, stable reads, audit anchors, source
completeness, pre/post route observation, fail-closed states, privacy bounds,
and every existing polling cadence were treated as invariants. No authority
read, CAS validation, anchor query, route check, retry state, or collection
limit was cached, skipped, or weakened.

## Applied optimization

### One-pass bounded per-user SSH token expansion — APPLIED

- **Component:** `src/angerona/core/ssh_surface.py`,
  `_per_user_source_path()`.
- **Problem:** the Round 2 `%h`/`%u`/`%U`/`%%` grammar accumulated output in
  fragments and recomputed `sum(len(fragment) ...)` after every token. A
  token-dense input at the admitted 4,096-character bound therefore did
  quadratic work. Token-free relative paths were also assembled one character
  at a time.
- **Change:** token-free paths take an exact direct fast path. Token-bearing
  paths scan literal spans and maintain a running output length, so each input
  and output character is accounted for once. The same tokens, ProgramData
  substitution order, account/UID requirements, 4,096-character cap,
  relative-home semantics, path-containment check, and normalized failure
  states are retained.
- **Measured improvement:** in a same-process full-function benchmark, an
  admitted maximum-size `%%` input improved from **213.317 ms to 1.335 ms per
  call (99.4%)**. A mixed token input that expands beyond the cap and fails
  closed improved from **70.783 ms to 0.827 ms (98.8%)**. A randomized
  differential corpus of **2,000** bounded valid/invalid inputs produced
  identical return tuples during implementation; the focused regression suite
  then exercised normal, expanded, missing-UID, conditional, escape, and
  unsupported-token states.
- **Gate:** changed-file `py_compile` PASS; Ruff PASS for the changed production
  file and SSH regression file; SSH Surface Guard `self_test()` PASS; focused
  SSH suite **33 passed, 1 expected host-capability skip, 0 failed**.
- **Status:** **APPLIED**

## Measured proposals retained for a later gated pass

### Exact control-character translation table — PROPOSED

- **Component:** `src/angerona/core/event_log_integrity.py`, `_clean_text()`.
- **Problem/change:** replace the exact per-character Python generator with a
  fixed `str.translate` map while preserving deletion of NUL, replacement of
  disallowed C0 controls, and TAB/LF/CR admission.
- **Measured potential:** an isolated whole-event parse improved from
  **150.68 us to 115.00 us (23.7%)**.
- **Why proposed:** apply only with explicit NUL/control/Unicode/surrogate
  equivalence regressions; no parser admission change was needed to complete
  this round.
- **Status:** **PROPOSED**

### Precomputed provider/Event-ID XPath selector — PROPOSED

- **Component:** `src/angerona/core/windows_event_log.py`,
  `WindowsEventLogSource`.
- **Problem/change:** precompute the already validated immutable selector once
  per fixed source rather than rebuild it for every `read_after()` query.
- **Measured potential:** selector construction improved from **12.810 us to
  0.426 us (96.7%)**, about **12.4 us absolute per query**.
- **Why proposed:** apply with exact XPath-equality gates for all configured
  channels and construction-bypass fixture coverage.
- **Status:** **PROPOSED**

### Exact ASCII UTF-8 bound fast path — PROPOSED

- **Component:** audit XML and WEVT rendered-text admission.
- **Problem/change:** when text length is already within the byte cap and the
  text is ASCII, its UTF-8 byte length is exact without allocating encoded
  bytes; non-ASCII text retains the current encoding check.
- **Measured potential:** **61.3%** faster at 4 KiB and **95.7%** faster at
  64 KiB ASCII inputs.
- **Why proposed:** apply with cap-minus-one/cap/cap-plus-one and multibyte
  boundary regressions so the byte bound remains exact.
- **Status:** **PROPOSED**

### Direct bounded EventData iteration — PROPOSED

- **Component:** `src/angerona/core/event_log_integrity.py`, audit field loop.
- **Problem/change:** iterate the element directly rather than allocate a list;
  retain the same enumerated index and 64-field rejection point.
- **Measured potential:** **2.9%** at three fields and **20.2%** at the declared
  64-field bound.
- **Why proposed:** small absolute benefit; pair with the parser boundary gate
  above in a dedicated change.
- **Status:** **PROPOSED**

### Early missing-record-marker rejection — PROPOSED

- **Component:** `src/angerona/core/windows_event_log.py`,
  `_record_id_from_xml()`.
- **Problem/change:** reject a missing opening marker before searching for its
  closing marker; retain the same normalized exception and no XML disclosure.
- **Measured potential:** malformed 1 MiB input improved from **661.43 us to
  350.51 us (47.0%)**.
- **Why proposed:** low-frequency rejected-input path; retain for a focused
  malformed-record parser gate.
- **Status:** **PROPOSED**

## Reviewed and intentionally retained

- **Independent high-water:** every authority installation check, authenticated
  head read, state-pair digest, previous-head comparison, and CAS echo
  validation remains unchanged. RPC/authentication/CAS cost cannot be cached
  without weakening freshness.
- **Audit guard:** a normal transition may appear to overwrite one oldest-anchor
  observation, but removing it would reduce race/clear coverage. Duplicate
  stable pair reads and transition-stability checks likewise remain intact.
- **Windows OpenSSH recovery:** source reopen backoff, query-failure counters,
  stale-source close, bounded-tail recovery, and honest blind-interval state
  are low-cost state operations; no retry cadence was changed.
- **Network/Personal Sentinel:** overflow accounting and complete pre/post
  route observations are security evidence. No interface, family, competitor,
  nonce/TLS, or post-attestation check was coalesced.
- **Live activity / Defense Memory:** EventBus revision gating and the
  process-cached, digest-pinned bounded memory asset remain the appropriate
  bounded designs; no new hot path or repeated asset read was found.

## Aggregate gates

- Changed production file `py_compile`: **PASS**.
- Ruff on changed production and focused regression files: **PASS**.
- SSH Surface Guard `self_test()`: **PASS**.
- Focused SSH regression suite: **33 passed, 1 expected skip, 0 failed**.

| Optimization | Component | Status | Expected/measured win |
|---|---|---|---|
| One-pass per-user path token expansion | SSH configured-source parser | APPLIED | 99.4% at admitted token bound; 98.8% on bounded rejection |
| Exact control-character translation | Audit event parser | PROPOSED | 23.7% faster whole-event parse |
| Precomputed fixed XPath selector | Windows Event Log adapter | PROPOSED | 96.7%; ~12.4 us/query absolute |
| Exact ASCII byte-bound fast path | Audit/WEVT admission | PROPOSED | 61.3–95.7% faster ASCII bound checks |
| Direct EventData iteration | Audit event parser | PROPOSED | 2.9–20.2% across typical-to-bound rows |
| Early missing-marker rejection | Windows Event Log adapter | PROPOSED | 47.0% on malformed 1 MiB input |

