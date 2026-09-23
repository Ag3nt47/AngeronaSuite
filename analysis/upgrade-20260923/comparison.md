# Focused comparison and remaining upgrades

Reviewed 2026-09-23 against the working tree, README, llms.txt, capability
summary, and [adversarial findings](adversary-review.md). This is an engineering
comparison, not a comparative detection or whole-PC benchmark. Sources below are
current primary documentation/code; undated pages are not assigned invented
release dates. Recommendations are design judgments from those sources and the
observed implementation.

## What the current upgrade changes

The implementation now contains hash-bound YARA file and ZIP detections wired to
Combat quarantine, independent Shark producer proof, shared rich process
collection, process-tree resource measurements, configurable runtime-alert
retention, an ordinary-user detached engine, configured AI instruction/memory/tool
file integrity, an encrypted restore drill, and a labelled detection-evaluation
CLI. Presence in the working tree is separate from the final release validation;
the parent review owns the aggregate test and native acceptance results.

Existing SOAR, capability contracts, signed response journals, Undo, detection
promotion, ATT&CK views, and local-AI explanation are foundations to extend, not
new features to promise again. Ollama is not required for deterministic response.

| Reference | Concrete comparison | Remaining Angerona work |
| --- | --- | --- |
| [osquery watchdog implementation](https://github.com/osquery/osquery/blob/master/osquery/core/watcher.cpp) | Supervises resource use and applies sustained CPU/memory limits and restart backoff. Angerona has resource controls and now measures its owned process tree. | Prove whole-engine budgets over representative idle and burst workloads; instrument attributable expensive work before adding more polling. |
| [Falco advanced performance tuning](https://falco.org/docs/concepts/event-sources/kernel/tuning/) | Selects inputs needed by enabled rules while retaining events necessary for internal state. Angerona shares snapshots and parks optional work in Chill. | Make collection demand explicit while retaining process lineage, identity, hotplug discovery, and loss reporting. |
| [Wazuh active-response configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html) | Connects configured rules to responses and supports timed reversal. Angerona already has typed policies, exact targets, receipts, and Undo. | Expand real sensor-to-action acceptance across supported target classes and lifecycle changes. More alert labels alone add no response coverage. |
| [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) | Addresses tool permissions, memory integrity, injection, and adversarial regression testing. The new guard protects explicitly enrolled Angerona integrations. | Enforce approved bytes at the consumer boundary on POSIX and add separately privileged egress enforcement for enrolled applications. Arbitrary external agents are not protected merely by enrolling a text file. |

## Ranked remaining work

Ranking favors impact per implementation effort for the reported idle slowdown
and failed containment. S/M/L are relative engineering estimates, not time
promises.

1. **Measured Chill release gate — S code, 24 hours/7 days elapsed evidence.**
   Connect the existing runtime metrics and `tools/run_soak.py` to a reproducible
   owned engine, GUI-open/closed phases, normal desktop activity, and bounded
   event bursts. Include explicitly enrolled Ollama processes when used. Preserve
   CPU, RSS growth, native handles, I/O, queue loss, and latency evidence with
   machine and commit identity; missing counters make the corresponding claim
   incomplete. Fit: core `operational_slo.py`, `runtime_metrics.py`, release
   validation; **Harden/Visualize**. Why now: the user reports degradation over
   time; [osquery's watchdog](https://github.com/osquery/osquery/blob/master/osquery/core/watcher.cpp)
   provides a concrete resource-supervision reference. This measures owned
   processes and never terminates unrelated applications to meet a budget.

2. **Native containment acceptance matrix — M.** Extend the new real YARA
   checks to each actually supported file, process, and network producer/action
   combination, including benign controls, PID reuse, engine restart, sensor
   loss, and receipt eviction. Record detection-to-verified-action latency and
   expose unsupported/unavailable combinations separately from misses. Fit:
   existing detector tests, Combat, Shark AAR, detection-quality tooling;
   **Detect/Respond/Visualize**. Why now: the reported 0/21 run exposed a broken
   detection-to-response chain; [Wazuh's explicit rule/action bindings](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html)
   are a useful comparison. Use inert owned fixtures and loopback peers;
   declaration fields or a synthetic bus event cannot prove native containment.

3. **Sensor demand plan for Chill — M.** Compile enabled detector requirements
   into one collection plan above `telemetry/sensors.py`; retain mandatory
   lifecycle/identity inputs and publish plan revisions and coverage changes.
   Add an equivalence fixture proving that supported detections survive optional
   input removal. Fit: shared telemetry, module capability dependencies, Chill
   controller; **Detect/Harden**. Why now: shared snapshots remove duplicate
   reads but do not themselves express which source fields are necessary.
   [Falco's state-preserving input selection](https://falco.org/docs/concepts/event-sources/kernel/tuning/)
   demonstrates the relevant pattern. Do not classify quiet sensors as unused
   or hide lost observations to reduce the running count.

4. **Independent recovery-copy adapter — M plus external storage.** Extend the
   encrypted drill with one explicitly enrolled removable or backup-provider
   destination, a verified copied-archive digest, exact revision identity, and
   restore back into a new private directory. Feed independently obtained copy
   evidence into the existing recovery-assurance evaluator. Fit:
   `recovery_drill.py`, `backup_restore.py`, `recovery_assurance.py`;
   **Harden/Respond**. Why now: a successful local restore does not survive loss
   of the local disk; [CISA's ransomware guide](https://www.cisa.gov/stopransomware/ransomware-guide)
   calls for offline encrypted copies and tested recovery. Requires an actual
   separate destination; never overwrite live files or describe a same-disk
   drill as offline/offsite recovery.

5. **Immutable POSIX inputs for integrated AI tools — M.** Add an adapter that
   makes the integrated consumer use the exact approved instruction/tool bytes,
   rather than checking a pathname and then allowing it to be reopened. Retain
   the current refusal of mapped mutations until that adapter is present. Fit:
   `agent_integrity.py`, `ai_security_broker.py`, explicit tool adapters;
   **Harden**. Why now: adversarial review found that POSIX read descriptors do
   not prevent subsequent writes; [OWASP agent guidance](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
   supports enforcing permissions and memory integrity outside model reasoning.
   Requires native Mac/Linux acceptance; no arbitrary plugin execution, hidden
   file enrollment, or claim of protection against full local-state rollback.

6. **Trusted service and native package acceptance — L plus credentials/hosts.**
   Provision publisher identity, connect the signed Windows installer to the
   existing SCM entry and protected data root, then test install, reboot,
   GUI-independent protection, update, recovery, and uninstall in a clean VM.
   Separately sign/notarize and test Mac artifacts on Intel and Apple Silicon.
   Fit: `engine_windows_service.py`, package authority, native release tooling;
   **Harden/Respond**. Why now: [Microsoft requires package trust for MSIX deployment](https://learn.microsoft.com/en-us/windows/msix/package/signing-package-overview),
   and [Apple's distribution process requires Developer ID provisioning](https://developer.apple.com/developer-id/).
   Signing identities are not configured. Do not elevate a mutable source
   interpreter or label an ordinary-user daemon as a deployed privileged service.

7. **Native egress policy for enrolled AI applications — L, Windows first.**
   Implement a narrowly scoped WFP adapter for approved application/user identity
   and destination policy, with transactional install, exact rule receipts,
   rollback, and native allow/deny tests covering IPv4/IPv6 and existing flows.
   Fit: `process_egress_guard.py`, existing egress-policy core, privileged broker;
   **Respond/Harden**. Why now: an observing guard cannot stop an external agent
   from opening a socket; [Microsoft ALE](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-)
   provides application/user filtering, while [ALE reauthorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization)
   matters for already open flows. Signed deployed authority and native tests
   precede an enforcement claim. Basic application rules are not per-PID
   isolation; shared interpreters need an explicit identity/isolation design.
   No interception of credentials, offensive traffic, or default whole-host block.

## Acceptance limits to retain

- `process_egress_guard.py` remains **observe-only** without a real enforcing
  adapter. Other configured network controls do not silently grant it authority.
- The detached engine can outlive its console within ordinary-user scope.
  Windows SCM authority remains unprovisioned; reboot/logoff and privilege
  guarantees require native service deployment evidence.
- Source-launcher CI does not prove a trusted signed/notarized installer or
  visible desktop operation on every OS. Credentials and native hosts remain
  external dependencies.
- Short tests and component benchmarks do not establish 24-hour/7-day stability
  or superiority over another project. No such comparative claim was measured.
- The capability summary still identifies v1.12.1/81 modules while README says
  v1.13.0/84 at review time; final documentation must reconcile the generated
  inventory instead of converting catalog size into a protection score.
