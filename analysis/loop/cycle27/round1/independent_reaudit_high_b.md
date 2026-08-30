# Cycle 27 Round 1 — Independent High-B Re-audit

Scope: independent, defensive re-attack of only `C27-R1-B07` and
`C27-R1-B09`. Validation used source review and inert/mocked regression cases;
no Signal message, network action, host-policy mutation, or operational
intrusion was performed. Product code was not edited by this re-audit.

## Verdict

| Finding | Verdict | Recreated original bypass? |
|---|---|---:|
| `C27-R1-B07` — basename disables Memory Injection Scanner coverage | **CLOSED** | No |
| `C27-R1-B09` — unpinned credential-inheriting `signal-cli` boundary | **CLOSED** | No |

These verdicts close the two reported High findings, not every possible
evasion of a metadata-only RWX detector or every vulnerability that a trusted
third-party messaging client could contain. Residual limitations are stated
explicitly below.

## C27-R1-B07 — CLOSED

### Re-attack result

The former pre-open basename exclusion is absent. Every enumerated non-self PID
now reaches `_scan_pid`, including `chrome.exe`, `python.exe`, and any renamed
payload (`src/angerona/modules/mem_inject_scanner.py:314-350`). JIT names are
consulted only after a suspicious region has been observed
(`src/angerona/modules/mem_inject_scanner.py:448-460`) and can only lower the
event from HIGH to MEDIUM when an exact policy path and SHA-256 agree
(`src/angerona/modules/mem_inject_scanner.py:600-621`,
`src/angerona/modules/mem_inject_scanner.py:648-702`). Even that damped case
still emits the event (`src/angerona/modules/mem_inject_scanner.py:679-703`).

The enumeration ABI is now explicit and HANDLE-safe: the wide Toolhelp record
uses pointer-width `th32DefaultHeapID` (`src/angerona/modules/mem_inject_scanner.py:86-100`),
and `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`,
`CloseHandle`, `QueryFullProcessImageNameW`, and `GetProcessTimes` have declared
signatures (`src/angerona/modules/mem_inject_scanner.py:192-248`). Snapshot
creation, first-record failure, mid-stream enumeration error, and an empty
inventory are all represented as incomplete rather than swallowed
(`src/angerona/modules/mem_inject_scanner.py:353-391`).

Coverage is derived from a bounded typed receipt containing enumerated, opened,
scanned, denied, failed, skipped, and enumeration-complete fields
(`src/angerona/modules/mem_inject_scanner.py:124-152`). Incomplete enumeration
or zero eligible processes produces health 0; otherwise health is the fraction
actually scanned (`src/angerona/modules/mem_inject_scanner.py:135-151`). An
open denial, a failed VAS query, a non-advancing region, or a scan with no
successful query cannot count as scanned (`src/angerona/modules/mem_inject_scanner.py:393-466`).
The run loop publishes that receipt directly as module health
(`src/angerona/modules/mem_inject_scanner.py:293-312`).

### Inert evidence

- `test_memory_scanner_never_skips_a_jit_basename` supplied three inert process
  records named `chrome.exe`, `python.exe`, and `payload.exe`; all three reached
  the scanner and the receipt reported 3/3 coverage.
- `test_memory_scanner_health_reports_incomplete_coverage` supplied one self,
  one denied, one failed, and one scanned PID; health was 33 with the denial and
  failure visible.
- `test_jit_damper_requires_exact_path_and_digest` rejected basename-only,
  path-only, and missing-digest policy shapes.
- `test_bound_jit_damper_still_emits_an_event` proved that the fully bound JIT
  case still emits a MEDIUM event rather than disappearing.

### Residual limitations (not a reopening of B07)

- Angerona deliberately skips its own PID (`src/angerona/modules/mem_inject_scanner.py:327-330`).
  That is explicit coverage loss, not a hidden basename grant, and is counted in
  the receipt. A future self-protection sensor should cover injection into the
  suite process from an independent trust boundary.
- Alert cooldown remains keyed only by PID for five minutes
  (`src/angerona/modules/mem_inject_scanner.py:288-290`,
  `src/angerona/modules/mem_inject_scanner.py:632-637`). Rapid PID reuse can
  suppress a later process's event even though the later process is still
  scanned. Bind dedup to PID plus process creation time and the observed region
  identity in a follow-up hardening item.
- The process handle binds the queried process, image path, and creation time,
  but `_bound_image_identity` hashes by reopening the resolved pathname through
  `_executable_sha256` (`src/angerona/modules/mem_inject_scanner.py:475-510`).
  This value is only a severity damper and never a scan exclusion, so it does
  not restore B07. A future revision should hash a retained image-file object
  or otherwise prove that the digest belongs to the process image mapping.
- The detector intentionally covers anonymous committed RWX/execute-write-copy
  metadata, not every T1055 variant (`src/angerona/modules/mem_inject_scanner.py:430-438`).
  RW-to-RX transitions, mapped sections, thread context, and call-stack
  telemetry require complementary sensors and should not be implied by this
  finding's closure.

## C27-R1-B09 — CLOSED

### Re-attack result

An enabled bridge can no longer execute a configured pathname alone. The
settings layer requires an absolute CLI path, exact SHA-256, exact
Authenticode subject, and distinct canonical E.164 host/operator identities
(`src/angerona/core/config.py:361-419`). Legacy unpinned settings are loaded
with mobile authority disabled (`src/angerona/core/config.py:808-826`). The
module independently refuses missing pins and non-Windows sealed execution
(`src/angerona/modules/mobile_bridge.py:1577-1588`).

Before launch, the module rejects reparse components, non-fixed volumes, and
owner/DACL paths that grant write/add/delete authority outside SYSTEM,
Administrators, or TrustedInstaller
(`src/angerona/modules/mobile_bridge.py:149-342`). It opens the exact ordinary
`.exe` with read sharing only, rejects multiple hard links, hashes the retained
handle, and verifies both the digest and exact valid Authenticode publisher
before use (`src/angerona/modules/mobile_bridge.py:569-656`). The retained
handle denies write/delete replacement through child completion, after which
object ID, link count, attributes, handle digest, path topology, volume, and ACL
are all revalidated (`src/angerona/modules/mobile_bridge.py:658-676`). Output is
discarded on any identity drift (`src/angerona/modules/mobile_bridge.py:871-925`).

The child starts suspended with a minimal `source={}` environment, no mobile
PIN variable, closed unrelated handles, an exact protected cwd, and a
kill-on-close CPU/memory/process-limited job before its sole main thread is
resumed (`src/angerona/modules/mobile_bridge.py:737-784`; custody implementation
`src/angerona/resilience/_selftest_environment.py:122-197`,
`src/angerona/resilience/_selftest_environment.py:200-261`). Its merged output
is streamed under a 256 KiB cap and hard deadline
(`src/angerona/modules/mobile_bridge.py:678-735`).

The parent records a fresh nonce, purpose, pinned binary digest, return code,
output length/digest, and terminal state under a process-local HMAC
(`src/angerona/modules/mobile_bridge.py:786-857`). Only state `complete`, exit
code zero, unchanged output, unchanged executable identity, and a valid receipt
reach send/receive parsing (`src/angerona/modules/mobile_bridge.py:871-979`).
Failures are retained by purpose (`src/angerona/modules/mobile_bridge.py:860-869`)
and take precedence over later health refreshes
(`src/angerona/modules/mobile_bridge.py:1590-1630`). This prevents a successful
receive from erasing a known send failure.

### Inert evidence

- Missing digest and publisher pins were rejected before launch.
- A real NTFS second hard link to an inert test file was rejected before
  execution.
- A nonzero child exit, altered receipt return code, and output substituted
  after receipt creation were all rejected.
- Parent `ANGERONA_MOBILE_PIN` and `ANGERONA_MOBILE_PIN_DPAPI` values were absent
  from the captured child environment; the captured launch also used closed
  handles and the exact executable directory.
- A recorded send failure survived a successful receive and forced module
  health to 40.
- Configuration persistence tests proved the two pins round-trip and legacy
  unpinned authority loads disabled.

### Residual limitations (not a reopening of B09)

- The job object provides custody and resource ceilings, but `Popen` still uses
  Angerona's Windows access token (`src/angerona/modules/mobile_bridge.py:760-773`).
  The exact pinned executable substantially narrows the original substitution
  attack, yet a future broker should run this network-facing third-party parser
  under a restricted token/AppContainer and expose only narrowly scoped IPC.
- The HMAC receipt is a parent-side authenticated observation, not a signature
  independently produced by `signal-cli`; the nonce is not echoed by the child.
  Synchronous object-retained launch leaves no stale-transcript input in the
  current data flow, so this does not recreate B09, but documentation should not
  describe it as independent child attestation.
- Health 100 proves recent successful sealed CLI execution and preserves known
  per-purpose failures. A receive success alone does not independently prove
  outbound delivery to the configured operator. Capability assurance should
  distinguish local CLI custody from live send/receive transport efficacy.

## Verification gates

- `python -m pytest -q tests/test_cycle27_mobile_pin_integration.py tests/test_cycle27_round1_high_b.py`
  — **14 passed**.
- `python -m py_compile` for both remediated modules and `core/config.py` —
  **passed**.
- Ruff on both modules, `core/config.py`, and the two focused test files —
  **passed**.

## Independent conclusion

Neither renamed-JIT basename authority nor replaceable/inherited-environment
`signal-cli` execution could be recreated. Both original High findings are
therefore **CLOSED**. The residual limitations above should remain visible in
the assurance ledger and later hardening rounds; they are narrower than the
original exploit paths and do not justify retaining either High finding as
open.
