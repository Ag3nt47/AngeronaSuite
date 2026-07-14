# Round 2 — Visionary Summary

Date: 2026-07-14. Scope: local-first defensive advances that reuse Angerona's
EventBus and do not add privileged polling. The runtime-generated
`rules/_active_combined.yar` file was not touched.

## Research basis

Primary/authoritative sources were used; the design conclusions below are
Angerona-specific inferences, not claims made by those sources.

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
  (April 2025) frames incident response as part of cybersecurity risk management
  and emphasizes improving the effectiveness of detection, response, and
  recovery. This supports improving the quality of evidence before escalation.
- [Microsoft Defender XDR alert correlation and incident merging](https://learn.microsoft.com/en-us/defender-xdr/alerts-incidents-correlation)
  describes correlation across sources using common entities, artifacts, time
  frames, and event sequences. This directly supports entity-scoped fusion over
  Angerona's current global time-bucket grouping.
- [Microsoft Defender XDR automatic attack disruption](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption)
  says automatic action is based on high-confidence, high-fidelity signals from
  different sources. Angerona's MVP adopts the multi-source confidence idea but
  deliberately performs no automatic response.
- [MITRE ATT&CK Host Status data component (DC0018)](https://attack.mitre.org/datacomponents/DC0018/)
  identifies missing telemetry and sensor-health monitoring as ways to expose
  failure, tampering, or evasion. This supports the proposed generalized
  telemetry-contract candidate.
- [MITRE D3FEND Process Analysis (D3-PA)](https://d3fend.mitre.org/technique/d3f%3AProcessAnalysis/)
  includes process-lineage analysis using ancestry, timing, and metadata. This
  supports graph-aware future correlation, while code inspection confirmed
  Angerona already has the basic provenance graph.
- [NIST IR 8356, Security and Trust Considerations for Digital Twin Technology](https://csrc.nist.gov/pubs/ir/8356/final)
  defines digital twins as electronic representations of entities and their
  state transitions. It grounds the counterfactual detection-twin proposal, but
  does not by itself prove a safe implementation for Angerona.

## Existing-capability exclusion

Inspection covered `core/incidents.py`, `core/incident_timeline.py`,
`core/eventbus.py`, `core/attack_tracker.py`, `modules/soar.py`,
`modules/provenance_graph.py`, `modules/canary_drill.py`, Round 1 innovation
proposals, and current Round 2 reports.

Angerona already has:

- global time-bucket incident grouping;
- PID-level corroboration before CRITICAL SOAR containment;
- a process/file/network provenance DAG and blast-radius view;
- a fixed process-canary echo plus coarse sensor-silence checks;
- individual-event HMAC integrity and persistent verification;
- attack heat and deterministic red-team replay.

It did **not** have a general entity-scoped engine that promotes otherwise weak
signals only after independent sensor domains agree. The selected MVP therefore
does not duplicate the existing incident, SOAR, provenance, canary, or Round 1
innovation work.

## Candidate scorecard

Scale: novelty, defensive value, and project fit are 1 (low) to 5 (high).
Effort, false-positive risk, privacy burden, and privilege burden are 1 (low) to
5 (high). Lower burden is better.

| Candidate | Novelty | Defensive value | Fit | Effort | FP risk | Privacy | Privilege | Decision |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Entity-scoped **Evidence Lattice Fusion** | 4 | 5 | 5 | 2 | 2 | 1 | 1 | **IMPLEMENTED** |
| Generalized telemetry expectation contracts (event A should produce independent echoes B/C before a deadline) | 4 | 5 | 4 | 3 | 3 | 1 | 1 | PROPOSED |
| Isolated counterfactual detection twin that replays recorded incidents through cloned detector state with every action sink disabled | 5 | 5 | 4 | 5 | 3 | 1 | 1 | PROPOSED |
| Keyed causal ledger checkpoints to expose deletion/reordering in addition to field tampering | 3 | 4 | 5 | 3 | 1 | 1 | 1 | PROPOSED |
| Privacy-preserving local novelty sketches over process/connection behavior | 5 | 4 | 3 | 4 | 4 | 1 | 1 | PROPOSED |

Only Evidence Lattice cleared the bounded-MVP bar. Telemetry contracts overlap
partly with DRILL and need real sensor-rate calibration. A counterfactual twin
needs a provable action-suppression boundary and clone-safe detector lifecycle.
Ledger chaining needs schema/migration and crash-checkpoint design. Novelty
sketches need a representative benign corpus before thresholds can be trusted.

## Selected concept — Evidence Lattice Fusion (ELAT)

The new `modules/evidence_lattice.py` consumes existing EventBus events and:

1. accepts only **MEDIUM** signals, because HIGH/CRITICAL alerts already have
   incident and SOAR paths and LOW/INFO noise is too weak to promote safely;
2. extracts only a structured PID, file hash/path, or IP address — never guesses
   an entity from free text;
3. classifies the source into a process, memory, network, file, identity, or
   defensive sensor domain;
4. holds a bounded 90-second lattice per entity;
5. emits one explainable HIGH finding only after at least **three distinct
   modules across two sensor domains** agree;
6. deduplicates the entity for 180 seconds and performs no response action.

```text
Existing EventBus
      |
      v
MEDIUM-only + structured entity gate
      |
      v
bounded entity buckets (PID/path/hash/IP, 90 s)
      |
      +-- fewer than 3 modules / 2 domains --> retain briefly, then expire
      |
      `-- quorum met --> explainable HIGH Event --> existing incident/triage UI
```

This differs from the current incident correlator, which joins all qualifying
events into one global open time bucket, and from SOAR corroboration, which only
operates after a CRITICAL PID alert and can lead to containment. ELAT is an
evidence-quality layer, not a response engine.

## Privacy and threat model

- All processing is in memory and local. There is no cloud, socket, model call,
  new file, registry read, process scan, or privileged API.
- State is capped at 512 entities and 16 signals per entity. Old evidence
  expires; dedup state is also capped.
- The output repeats only entity data already present on the local EventBus and
  names the contributing modules/domains so the analyst can audit the decision.
- A compromised in-process module can still manufacture signals; module names
  are diversity evidence, not cryptographic identities. This is consistent with
  the EventBus HMAC's documented in-process trust limitation.
- PID reuse or a popular shared path can cause accidental correlation. The
  short time window, three-module/two-domain requirement, structured-data-only
  extraction, exact MEDIUM filter, and dedup reduce but do not eliminate that
  risk.
- Unstructured alerts are intentionally missed. This trades recall for a clear,
  testable false-positive boundary.
- An ELAT HIGH finding does not satisfy the existing CRITICAL auto-containment
  branch, so this MVP cannot suspend, terminate, isolate, or modify the host.

## Implementation diff

- Added `src/angerona/modules/evidence_lattice.py`:
  - pure deterministic `EvidenceLattice` engine;
  - bounded and thread-safe entity state;
  - conservative entity/domain normalization;
  - `BaseModule` integration (`CODE=ELAT`), lifecycle-safe single subscription,
    and recursion guard;
  - deterministic `self_test()` with malicious-looking fusion, duplicate-source,
    low/INFO/strong-alert noise, unrelated-entity, dedup, and expiry controls.
- No existing response, policy, threshold, sensor cadence, persistence, network,
  or YARA code was changed.

## Verification evidence

- `py_compile` for the new module: **PASS**.
- Project `compileall -q src tools`: **PASS**.
- Module discovery: **61 modules**, **0 discovery errors**; ELAT discovered.
- ELAT deterministic self-test: **PASS** — entity fusion, dedup, time-window
  expiry, and false-positive controls.
- Full offscreen `tools/selfcheck.py`: **26 passed, 0 failed, exit 0**.
- Full module runner inside the harness: **47 passed, 15 expected
  stopped/idle/Ollama skips, 0 genuine failures**; ELAT explicitly passed.

## Next experiments and limitations

1. Run ELAT in observe-only production use and measure how often candidate
   lattices expire versus fuse. Do not lower thresholds until benign baselines
   are available.
2. Add an analyst view for the contributing evidence, but reuse existing event
   detail dialogs rather than creating another dashboard.
3. Explore signed module-instance identities if Angerona later separates
   sensors into independent processes; current source diversity is logical, not
   a hardware/process trust boundary.
4. Prototype telemetry expectation contracts only for high-certainty pairs
   learned from the benign DRILL, and keep missing echoes informational until
   platform-specific rates are measured.
5. Design the counterfactual twin only after every detector exposes a pure
   analysis interface and all response sinks can be mechanically replaced with
   no-op audit sinks.

## Final disposition

| Candidate | Novelty / value / effort | Status |
|---|---|---|
| Evidence Lattice Fusion | 4 / 5 / 2 | **IMPLEMENTED** |
| Telemetry expectation contracts | 4 / 5 / 3 | PROPOSED |
| Counterfactual detection twin | 5 / 5 / 5 | PROPOSED |
| Keyed causal ledger checkpoints | 3 / 4 / 3 | PROPOSED |
| Local novelty sketches | 5 / 4 / 4 | PROPOSED |
