# Cycle 27, Round 1 — Independent High-A Re-audit

Scope was limited to the remediations for `C27-R1-A01`, `C27-R1-A10`, and
`C27-R1-A16`. Validation was defensive and inert: an in-memory EventBus, a fake
Windows event log, and a fake process object were used. No live process was
terminated, no Security log was changed, and no product code was edited.

The dedicated remediation suite passes (`13 passed`), and each fix adds useful
controls. Hostile state-transition tests nevertheless reproduce a residual
fail-open condition in all three high findings, so none is ready to close.

| Original finding | Independent verdict | Residual severity | What held | Residual bypass |
|---|---|---:|---|---|
| `C27-R1-A01` | **REOPENED / PARTIAL** | HIGH | An intent-only restart stays `RECOVERY_REQUIRED`; the new disposition API requires a fresh, exact, HMAC-valid human decision. | A non-reversible effect followed by a post-mutation observation exception is terminalized as `failure`, leaves the circuit armed, and is ignored by restart recovery. |
| `C27-R1-A10` | **REOPENED / PARTIAL** | HIGH | CHAOS-origin, text-only, malformed, stale, practice, and wrong-nonce records are rejected. | EventBus HMAC proves event integrity, not producer identity. Any bound in-process publisher can claim an allowlisted detector name and satisfy a probe; the real detectors do not implement the new receipt schema. |
| `C27-R1-A16` | **REOPENED / PARTIAL** | HIGH | One live instance drains forward in bounded pages, advances only per observed record, and detects live clear/reset/retention gaps. | The bookmark, anchor, generation, and gap are memory-only. A suite restart after channel clear/refill forgets prior continuity and reports 100% after reading the replacement generation. |

## `C27-R1-A01` — Uncertain live termination can still be terminalized and re-arm

### Control credit

- `src/angerona/modules/adversary_combat.py:1990-2004` no longer converts an
  intent-only non-reversible restart into an automatic failure. It trips the
  mutation circuit and retains the action as pending.
- `src/angerona/modules/adversary_combat.py:2136-2251` validates a fresh
  `AuthorizationDecision`, exact action ID/scope/permission, HMAC, and human
  principal before appending a durable `operator_disposition`.

### Residual

`src/angerona/modules/adversary_combat.py:1828-1843` durably records the intent,
invokes `process.kill()`, and then performs fallible wait/postcondition work. A
post-mutation exception enters the broad handler at lines 1841-1843 and calls
`_journal_failure()`. That helper (`1644-1657`) appends a terminal `failure` and
silently swallows append errors. Startup recovery explicitly treats every
`failure` as terminal at `1979-1982`.

An inert fake process set a `killed=True` marker in `kill()` and raised
`RuntimeError` from `is_running()`. The resulting state was:

```text
effect=True
journal=['intent', 'failure']
mutation_blocked=False
health=100
```

No process was touched. This demonstrates the exact dangerous ordering: an
irreversible effect occurred, its postcondition became unknowable, yet the
journal declared a terminal failure and allowed later mutations. If the failure
append itself fails, the durable intent will be recovered only after restart;
the current process still remains armed because the helper suppresses the
write error.

### Impact and recommendation

An access loss, process-object race, or unexpected post-kill error can erase the
uncertainty boundary during the current run and across restart. Once a
non-reversible mutation begins, any exception, non-definitive postcondition, or
accounting failure must call `_trip_mutation_circuit()` and leave the intent
non-terminal. Only a proven pre-mutation failure may be terminalized
automatically. Track an explicit `mutation_started` phase, test every exception
site after that phase, and require the existing authenticated operator
disposition to close uncertainty.

## `C27-R1-A10` — Receipt HMAC does not authenticate the detector producer

### Control credit

`src/angerona/modules/chaos_harness.py:124-179` now enforces a bounded exact
schema, probe kind/ID/challenge equality, an allowlisted module/code/observation
tuple, post-challenge time, non-practice disposition, and a valid EventBus HMAC.
Those checks close the original direct CHAOS/text-only match.

### Residual

The EventBus signs caller-supplied event fields centrally at
`src/angerona/core/eventbus.py:301-305`; it has no producer identity parameter.
Every module receives the same bus object at
`src/angerona/core/module_base.py:327-335`. Consequently, `bus.verify(ev)` at
`chaos_harness.py:153` proves that the shared bus signed the claimed module name,
not that APID/NDRD/FIM/AMSI produced it. The `source_epoch` check at lines
`174-176` is only a public-format regex and is not bound to an enrolled detector
key or lifecycle generation. The probe publishes its nonce and challenge on the
same bus, so a subscriber can answer synchronously.

An unrelated publisher supplied the exact public fields while claiming the
allowlisted APID name. The bus signed it and `_wait_for_echo()` returned:

```text
chaos_arbitrary_publisher_accepted=True
```

Repository-wide search also found `chaos_detector_observation`, `probe_id`, and
`challenge_digest` receipt production only in `chaos_harness.py`; the actual
APID, NDRD, FIM, and AMSI modules do not emit this schema. For example, NDRD's
real self-probe acknowledgement at
`src/angerona/modules/network_protocol_decoder.py:163-170` remains the older
`drill=True` event. Thus a genuine deployment cannot pass the new gate, while an
arbitrary in-process publisher can.

### Impact and recommendation

A compromised or confused sibling can manufacture green pipeline assurance,
and healthy real detectors cannot produce it. Give each enrolled detector a
manager-held, detector-specific receipt authority (or a manager-owned callback
that derives identity from the registered module object, not event text). Bind
the MAC/signature to detector capability ID, lifecycle generation, probe nonce,
challenge, exact observed artifact/target digest, observation time, and one-time
consumption. Implement the producer side in APID/NDRD/FIM/AMSI and add negative
tests where every other module has the challenge and the shared EventBus key but
still cannot satisfy the receipt.

## `C27-R1-A16` — Security continuity is forgotten across process restart

### Control credit

`src/angerona/modules/etw_listener.py:137-249` now reads oldest-first through a
sampled high watermark, applies page/record/time bounds, advances only for the
exact next record, validates the current in-memory anchor, and exposes backlog
or persistent in-process gap health. The live-instance burst/reset tests are
appropriate and pass.

### Residual

All continuity fields are initialized in memory at
`src/angerona/modules/etw_listener.py:58-68`; there is no durable authenticated
bookmark or channel-generation receipt. On a new process `_last_record == 0`,
so lines `171-173` unconditionally treat the currently retained `oldest` record
as the beginning of a new generation without comparing it to the prior run.
After catch-up, lines `242-246` report 100% “continuity verified.”

An inert fake channel was first read as records 50-55 in generation one. A new
`EtwListenerModule` instance then read a cleared/refilled channel containing
records 1-4 in generation two. Its resulting state was:

```text
health=100
note='Security channel continuity verified: generation=1, bookmark=4'
gap=''
replayed=[1, 2, 3, 4]
```

The current records were replayed, but the lost prior-generation interval was
not disclosed. A real service/app restart has the same state reset.

### Impact and recommendation

An attacker who can clear/replace the Security channel and cause or await an
Angerona restart can erase the continuity warning; ordinary downtime plus log
retention can do the same accidentally. Persist an authenticated, atomically
replaced cursor containing channel identity/generation evidence, record number,
record anchor, observed bounds, and last successful timestamp. On enrollment,
distinguish explicit first-ever baseline from prior-state loss. A missing,
unreadable, rolled-back, cleared, or mismatched cursor must remain below 100%
with an exact loss interval/reason until operator acknowledgement; it must not be
converted into a fresh green generation automatically.

## Evidence summary

- Remediation regression suite: `13 passed in 4.46s`.
- Independent inert hostile harness: all three residual assertions reproduced.
- New residuals by severity: **3 HIGH**, 0 MEDIUM, 0 LOW.
- Prior high findings verified fully resolved: **0**; partially remediated but
  still open: **3**.
