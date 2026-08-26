# Cycle 23 Round 1 — Performance Summary

Date: 2026-08-26  
Scope: Cycle 23 audit-log integrity, SSH surface, zero-trust network/Personal
Sentinel Gateway, live activity, Defense Memory/ARIA, ModuleManager, and EventBus
integration only.

The review treated evidence freshness, anchor/route revalidation, source
completeness, fail-closed state, and observe-only authority as invariant. It did
not modify the QA-R1-01 paired-state rollback residual, reduce any polling
cadence, cache security evidence, or skip a freshness/anchor/route check.

## Applied optimizations

### 1. Quiescent audit checkpoints verify without durable rotation — APPLIED

- **Component:** `src/angerona/core/event_log_integrity.py` and
  `src/angerona/modules/audit_log_guard.py`
- **Problem:** every four-second poll replaced and `fsync`ed both authenticated
  checkpoint documents even when all channel cursors, terminal anchors, and the
  coverage state were identical. This created two durable replacements per idle
  poll after enrollment.
- **Change:** an unchanged authenticated transition performs the existing
  bounded, stable, link/reparse-aware reads and byte-exact cursor/enrollment
  digest comparison, but does not create a revision whose only change is its
  timestamp. New evidence, cursor movement, coverage changes, first enrollment,
  untrusted recovery, and race rollback still take the durable save path.
  Missing or altered state still returns failure and emits the existing
  untrusted health event.
- **Measured improvement:** on a temporary Windows data root, 30 repeated
  three-channel commits had a **42.189 ms median**; the equivalent authenticated
  no-change verification had a **1.001 ms median** (**97.6% less checkpoint
  time**). At the four-second cadence, a quiescent host avoids up to **43,200
  file replacements/`fsync`s per day** while retaining two integrity reads per
  poll.
- **Gate:** changed-file `py_compile` PASS; Ruff PASS; audit regression suite
  PASS; Audit Log Integrity Guard `self_test()` PASS. A regression proves that
  an idle poll leaves both files/revision unchanged and that subsequent byte
  tampering still fails closed.
- **Status:** **APPLIED**

### 2. SSH command lines are collected only for SSH clients — APPLIED

- **Component:** `src/angerona/core/ssh_surface.py`
- **Problem:** `psutil.process_iter()` requested `cmdline` for every host
  process every 30 seconds, although command-line evidence is consumed only for
  an identified `ssh` client and only to normalize forwarding flags. Server and
  unrelated process command lines were fetched and immediately discarded.
- **Change:** the first process pass requests PID, name, executable, and birth
  time. After the same executable/name role admission, only an admitted SSH
  client receives a bounded `cmdline()` query. Unavailable client arguments
  continue to emit `ssh.runtime.client_arguments_unavailable`; process,
  listener, connection, PID-birth, and forwarding evidence semantics are
  unchanged.
- **Measured improvement:** across 12 live-host samples with no SSH process, the
  process-enumeration phase fell from a **41.050 ms median** to **3.726 ms**
  (**90.9% lower**). The cold first sample was 679.197 ms on the eager path and
  5.931 ms on the selective path; medians are reported to avoid overstating the
  one-time cold-cache effect.
- **Gate:** changed-file `py_compile` PASS; Ruff PASS; SSH regression suite
  PASS; SSH Surface Guard `self_test()` PASS. The focused regression asserts
  that the process iterator is not asked for `cmdline`, a server gets zero
  command-line queries, and an SSH client gets exactly one while its forwarding
  finding remains intact.
- **Status:** **APPLIED**

### 3. Already-untrusted network snapshots avoid immutable rebuilds — APPLIED

- **Component:** `src/angerona/modules/network_trust_monitor.py`
- **Problem:** before checking explicit gateway enrollment, every tick rebuilt
  every immutable link and the containing snapshot even when the normal
  collector had already supplied `gateway_attestation="untrusted"` and no
  route asserted attestation.
- **Change:** every link and every route is still inspected on every tick. The
  monitor rebuilds and strips the snapshot whenever any collector-supplied
  positive label/flag exists; otherwise it retains the already-clean immutable
  snapshot. Explicit enrollment, TLS/pin/nonce/freshness checks, dual-stack
  route selection, and the complete post-exchange route-context observation are
  unchanged.
- **Measured improvement:** at the declared bound of 64 links and 16 routes per
  link, 2,000 iterations improved from a **1,319.25 us median** to **88.70 us**
  (**93.3% lower**, about 1.23 ms absolute per 30-second tick). Real hosts have
  fewer links, so this is primarily allocation/GC reduction rather than a
  latency claim.
- **Gate:** changed-file `py_compile` PASS; Ruff PASS; network and gateway suites
  **74 passed**; Zero-Trust Network Path Monitor `self_test()` PASS. The
  pre-existing forged-attestation regression still proves that any positive
  collector assertion is removed when enrollment is absent.
- **Status:** **APPLIED**

## Proposals retained for security design review

### Fixed-schema Windows inventory coalescing — PROPOSED

One normal Windows network snapshot launches seven bounded child processes:
five PowerShell queries plus fixed `netsh` and `arp` commands. A single fixed,
versioned PowerShell inventory document could reduce the five PowerShell
launches to one while retaining separate per-source completeness fields,
in-flight output limits, timeout/kill behavior, and strict JSON admission. This
was not applied because atomic multi-section failure semantics and the existing
partial-evidence regressions need a dedicated security proof.

### Narrow post-attestation route-context observer — PROPOSED

A configured Personal Sentinel Gateway intentionally takes a complete second
network snapshot after HTTPS attestation. That can repeat all seven Windows
inventory processes even though `_selected_route_context()` consumes only
complete IPv4/IPv6 selected routes, interface index, interface epoch, gateway,
family, and metric. A purpose-built post-check could collect exactly those
inputs, but it must reconstruct the current epoch inputs (including address and
wireless identity) and preserve fail-closed completeness. It remains proposed;
the full second observation is retained today.

### Event-driven WEVT delivery with unchanged anchor cadence — PROPOSED

The audit guard performs bounded point queries and multiple generation-anchor
reads for three channels every four seconds. A persistent `EvtSubscribe`/cursor
adapter could remove empty `read_after` query setup while keeping the current
four-second oldest/newest/admission/terminal anchor verification as an
independent anti-clear control. Handle recovery, overflow, subscription loss,
and clear/refill generation changes need adversarial Windows-native gates, so
the current query path remains unchanged.

## Reviewed and retained

- **Live Defense Activity:** EventBus content is copied only after the
  monotonic revision changes; a static 71-module snapshot costs **60.4 us
  median** (160.4 us p95) and runs on the existing bounded panel cadence. No new
  timer, subscription, stylesheet regeneration, or details parsing was found.
- **Defense Memory / ARIA:** the pinned asset loader is process-cached with
  `lru_cache(maxsize=1)`. Markdown synthesis and RAG replacement occur only at
  startup or an explicit governed rebuild, and cloud reference selection stays
  bounded to the Defense Memory source. No periodic file read or unbounded
  cache was found.
- **ModuleManager / EventBus:** the three new modules use existing managed
  threads and sleep intervals. The activity card uses `revision()` before
  `recent(16)`, EventBus storage remains bounded, and the SSH subscription is
  initialized before enablement and remains inert after stop. No duplicate
  polling thread or new queue growth was found.
- **Security-required repeated work:** audit anchor revalidation, gateway
  nonce/TLS/freshness verification, the full pre/post route-context check, and
  SSH configuration/key stable reads were intentionally not cached or
  throttled.

## Aggregate gates

- Changed production/test file `py_compile`: **PASS**.
- Ruff on all touched production/tests: **PASS**.
- Focused audit + SSH suites: **38 passed, 2 host-capability skips**.
- Focused network + Personal Sentinel Gateway suites: **74 passed**.
- Affected module self-tests: **3 passed, 0 failed**.

| Optimization | Component | Status | Expected/measured win |
|---|---|---|---|
| Verify identical audit state without rotation | Event-log continuity | APPLIED | 97.6%; up to 43,200 durable replacements/day avoided |
| Lazy SSH-client command-line collection | SSH runtime collector | APPLIED | 90.9% lower process-enumeration median on measured host |
| Fast path for already-untrusted snapshots | Network gateway sanitizer | APPLIED | 93.3% at declared maximum; ~1.23 ms/tick absolute |
| Fixed-schema inventory coalescing | Windows network collector | PROPOSED | Reduce normal child launches from seven to three |
| Narrow post-attestation context collection | Personal Sentinel Gateway monitor | PROPOSED | Avoid repeating unrelated DNS/DHCP/profile/neighbor work |
| Event-driven delivery plus periodic anchors | Windows audit adapter | PROPOSED | Avoid empty point-query setup; keep current anti-clear cadence |
