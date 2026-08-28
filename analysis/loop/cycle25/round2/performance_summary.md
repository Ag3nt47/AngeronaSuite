# Cycle 25 / Round 2 — Performance and bounded-reliability summary

Date: 2026-08-27

## Applied

- **Revision cursors:** EventBus consumers request only the delta after their
  committed monotonic revision instead of repeatedly scanning/copying already
  processed history. Overflow remains explicit.
- **Drain-stage-drain:** exporters make room before staging and immediately use
  newly staged capacity afterward. This reduces avoidable queue-full paths
  without batching away `synchronous=FULL` durability.
- **External-mutation fast path:** durable outboxes retain the normal
  authenticated-row fast path and force a complete mutable-state sweep when
  SQLite `data_version` or local change state indicates unobserved mutation.
- **Bounded worker ownership:** IPC/Remote helper slots, Intel Sync generations,
  and asynchronous recorder handoff remain bounded and are released on failed
  startup/cancellation.
- **Subscriber SLO metrics:** inline callback deliveries, failures, maximum
  latency, and bounded-budget violations are observable without adding a second
  reordered delivery system.

## Not applied in Round 2

- Durable enqueue/ack batching was not applied because it changes crash-time
  duplicate and replay boundaries.
- Host-adaptation firewall and remote-session probes were not cached because a
  stale negative could authorize a mutation after the host context changed.
- EventBus callbacks were not made asynchronous because ordered synchronous
  observation is part of the current contract.

Round 3 measured and applied the final recorder and GUI refresh optimizations;
see [../round3/performance_summary.md](../round3/performance_summary.md).
