# Cycle 27 round 1 — remaining-A third remediation

Date: 2026-08-28
Scope: A02, A03, A07, and A14 only
Disposition: the five stable second-independent-reattack gates are closed

## Outcome

The frozen hostile gate `tests/test_cycle27_remaining_a_second_independent_reattack.py`
was not edited. It moved from **5 failed / 14 passed** before this remediation to
**19 passed** afterward. A13 was already closed and `deception.py` was not edited
by this remediation. All affected module versions remain **1.12.1**.

| Closure ID | Severity | Result | Evidence |
|---|---:|---|---|
| C27-R1-A02-THIRD-01 | HIGH | Closed | `adversary_combat.py:2734-2875` HMAC-authenticates the complete canonical nested cache graph and verifies that the O(1) commit index points to the exact retained record objects. `:4737` deep-copies trusted-action egress. |
| C27-R1-A03-THIRD-01 | MEDIUM | Closed for the frozen NTFS terminal boundary | `adversary_combat.py:3054-3078` invokes the retained exact-object validator from inside the journal writer, after an outer `_append_journal` wrapper has yielded control but before the applied record is constructed or appended. The pinned file/directory custody remains live through this call and append. |
| C27-R1-A07-THIRD-01 | HIGH | Closed | `av_telemetry_bridge.py:271-426` upgrades the independent enrollment marker to an HMAC-authenticated v2 full-row state witness with monotonic generation. Missing witness authority for a pre-existing database and a marker/database digest mismatch fail closed. |
| C27-R1-A07-THIRD-02 | HIGH | Closed | `av_telemetry_bridge.py:870-914, 951-1034` preflights cursor/anchor identity before publication and durably witnesses the lease admission before `emit`. Enqueue, retry, acknowledgement, and close transitions refresh the witness. |
| C27-R1-A14-THIRD-01 | HIGH | Closed across verifier/provider instances in one process | `driver_provenance_guard.py:86-92, 279-313` replaces the verifier-local set with one locked, bounded replay registry keyed by authority, host, install, and boot identity. Concurrent independent verifiers have exactly one winner. |

## Adversarial gates added

`tests/test_cycle27_remaining_a_third_remediation.py` adds eight inert gates:

1. nested cache-authority mutation is authenticated and refused;
2. an equal-content but different-object commit-index swap is refused;
3. the terminal quarantine proof returned to the caller came from the retained writer;
4. an injected enrollment-witness write failure prevents downstream publication;
5. a conflicting cursor anchor queues exactly one non-recursive gap event;
6. a captured older empty SQLite database conflicts with the newer independent witness;
7. deletion of the witness beside a pre-existing database fails closed; and
8. two concurrent verifier instances consuming one valid receipt produce one success and one replay rejection.

All fixtures use pytest temporary directories, generated Ed25519 keys, inert files,
and in-memory event buses. No host Defender, driver, firewall, process, service, or
deception state is changed.

## Validation

- Frozen second independent reattack: **19 passed**.
- New third-remediation gate: **8 passed**.
- Combined remaining-A, Combat, and driver compatibility selection: **109 passed**.
- `compileall`: passed for the three owned modules and new test.
- Ruff: passed for the three owned modules and new test.
- `git diff --check`: passed; Git emitted only the repository's existing Windows
  working-tree LF/CRLF conversion notices.
- Offline self-tests: AV Telemetry Bridge passed; Driver Provenance Guard passed.
  Adversary Combat's standalone `self_test()` returned false solely because a newly
  constructed module has `status=stopped`; it did not report a journal/integrity
  failure. Starting a host-response module merely to turn that status green was not
  appropriate for this inert validation.

## Honest residual boundaries

- Python does not provide a memory-isolation boundary against arbitrary code that
  can read and rewrite both private cache state and its signing key. The closure
  prevents nested egress aliasing, content mutation, and object/index substitution
  within the module's authority contract.
- A retained Windows file handle does not make NTFS hard-link topology and a
  separate JSONL append one atomic kernel transaction. This change retains exact
  object custody and moves the proof inside the final writer boundary exercised by
  the stable NTFS gate. A privileged actor that can mutate namespace topology after
  custody is released remains outside this local user-mode guarantee.
- The outbox database and witness are two durable files. A crash between their
  commits deliberately causes fail-closed recovery (availability loss, not silent
  delivery loss). Coordinated rollback of both files requires an external monotonic
  witness to distinguish from an old complete state.
- Driver receipt replay consumption is shared and atomic across every verifier and
  provider instance in the process, bounded by the signed receipt lifetime. It is
  not a cross-process/reboot ledger; boot binding and issuer-side generation/nonce
  uniqueness remain required across process lifetime boundaries.

No commit or publication was performed.
