# Cycle 27, Round 1 — Seventh High-A Remediation

Scope was limited to the sixth independent re-attack residuals for
`C27-R1-A01` and `C27-R1-A16`. Every reproduction was defensive, inert, and
confined to temporary directories, in-memory protected-store stand-ins, fake
process objects, and an in-memory EventBus. No live process, Security channel,
host policy, credential, or network target was touched. Author validation does
not self-close either finding; another independent hostile re-attack is
required.

## C27-R1-A01 — runtime downgrade refusal and continuous journal custody

Status: **REMEDIATED — PENDING INDEPENDENT RE-ATTACK**.

- `src/angerona/modules/adversary_combat.py:1985-1994` now rejects every
  authenticated schema-1 recovery anchor in the running response module,
  whether the signing-key witness is present or absent. Runtime code never
  rewrites that anchor and never recreates a lowered witness. A legitimate old
  installation must use a separate, explicit, audited operator migration or
  recovery workflow.
- `src/angerona/modules/adversary_combat.py:2150-2269` adds a bounded,
  descriptor-pinned journal session. One regular, single-link, non-reparse
  object and its state-root/parent topology remain pinned for the whole
  transaction. On Windows, the live descriptor also denies delete/replace;
  every platform verifies that the canonical path still names that exact
  object before and after each read/write.
- `src/angerona/modules/adversary_combat.py:2630-2689` reads, appends, fsyncs,
  advances the protected anchor/witness, and rereads through that same open
  object. A between-read/append pathname swap is rejected before the alternate
  object receives signed bytes. The mutation guard retains the same descriptor,
  receipt lock, and installation writer lease through intent, host effect,
  postcondition, and terminal receipt.
- `src/angerona/modules/adversary_combat.py:94-97` and `:2272-2620` impose
  explicit 32 MiB journal, 64 KiB line, 32,768-record, 16-level JSON nesting,
  64-member object, and bounded-container limits. Strict parsing rejects
  unsigned prefixes, duplicate members, non-finite constants, incomplete
  terminal lines, unknown signed fields, and wrong record schemas. Memory,
  recursion, decode, and parse failures become `JournalIntegrityError` and a
  health-0 mutation circuit instead of escaping the worker.
- All seven response mutation entry points now use the continuous custody
  guard: quarantine, process suspend/terminate, remote-IP block, program
  isolation, host isolation, and deception activation.

Exact inert regressions cover witness deletion plus authentic legacy
anchor/journal replay, the 8,002-byte nested prefix, a forced byte budget,
between-read/append and post-final-read swaps, and deletion attempted from the
fake irreversible `kill()` boundary. The alternate sentinel receives no
signed append, and no mutation proceeds after a failed custody check.

## C27-R1-A16 — schema-1 Security authority is never runtime authority

Status: **REMEDIATED — PENDING INDEPENDENT RE-ATTACK**.

- `src/angerona/modules/etw_listener.py:745-755` now rejects every schema-1
  protected Security rollback anchor before witness creation, independent of
  whether the current authority witness exists. The running sensor cannot
  reinterpret witness deletion as a pre-upgrade installation, lower the
  authority revision, or silently suppress the newer channel interval.
- Existing schema-2 first enrollment, full record identity, bounded replay,
  cursor/high-water/anchor/witness commit ordering, live durable-state checks,
  and the state-root writer lease remain unchanged.

The exact inert regression creates a valid legacy authority, advances the
current authority, deletes only its witness, restores the legacy authority,
and proves load fails without changing the anchor or recreating a witness.

## Gates

| Gate | Result |
|---|---|
| New seventh-remediation regressions | `PASS` — `7 passed` |
| New + all directly affected Combat/ETW suites | `PASS` — `99 passed` |
| `py_compile` for both product modules and both remediation tests | `PASS` |
| Ruff for both product modules and both remediation tests | `PASS` |
| Combat armed-state and ETW 4688-decoder `self_test()` | `PASS` — `2/2` |
| `git diff --check` for owned product/test files | `PASS` (line-ending notices only) |
| Independent hostile re-attack | **PENDING — required before closure** |

## Honest residual boundary

Restoring every schema-2 local authority object together with the stable
signing identity remains the disclosed whole-host snapshot boundary. Software
on that same host cannot distinguish it without TPM monotonic state or an
independently administered append-only witness. Windows supplies the
delete-denying journal custody used at live host-mutation boundaries; POSIX
retains and identity-checks the descriptor but cannot claim a kernel-enforced
deny-delete guarantee against a privileged non-cooperating unlink. Journal
budget exhaustion is deliberately fail-closed and requires operator archival
or recovery rather than silently rotating authenticated evidence.
