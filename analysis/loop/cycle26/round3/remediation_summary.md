# Cycle 26 round 3 remediation summary

## C26-R3-A01 — FIXED

- **Finding:** release authority policy inspected secret-context access only
  inside parsed jobs; a renamed secret in workflow-level `env` could be
  inherited by release jobs without violating the heuristic secret-name check.
- **Change:** `tools/validate_workflow_policy.py` now walks the complete parsed
  release workflow and rejects every GitHub expression that accesses the
  `secrets` context, including root `env`, defaults, concurrency, and future
  non-job mappings. Duplicate-key rejection and the exact release graph/gate
  checks remain in force.
- **Structural precision:** detection requires a parsed `${{ ... }}`
  expression. YAML comments are absent from the parsed document, and inert
  scalar prose that merely mentions `secrets.NAME` is not treated as context
  access.
- **Regression:** workflow-level fixtures cover renamed dot access and dynamic
  bracket access; a separate comment/inert-prose fixture proves the gate is not
  based on raw-text confusion.
- **Gate:** Python compile PASS; Ruff PASS; checked-in workflow policy validator
  PASS; focused and adjacent workflow/response regression suites PASS.

## C26-R3-A02 — FIXED

- **Finding:** response transaction state and the rollback-failure mutation
  circuit existed only in memory, so a later call or restart could stack a new
  mutation on unresolved host state.
- **Custody:** `src/angerona/core/remediation_log.py` adds one bounded
  transaction table in the existing `flight-recorder.db` custody boundary.
  Records are limited to 64 KiB, fields and states are constrained, unresolved
  rows cannot be pruned, and SQLite `synchronous=FULL` makes successful state
  commits fsync-backed.
- **Fail-closed transitions:** `src/angerona/modules/remediation_actions.py`
  requires exact action-specific prior state/compensation identity, commits
  `PREPARED`, commits `MUTATING` before dispatch, and then commits only
  `APPLIED`, `ROLLED_BACK`, or `RECOVERY_REQUIRED`. Journal absence/failure
  disables all executable actions. A restart safely abandons only a transaction
  that never reached `MUTATING`; interrupted `MUTATING` state becomes persistent
  `RECOVERY_REQUIRED`.
- **Concurrent-call closure:** `prepare_transaction()` now performs the
  unresolved-state query and PREPARED insert inside the same SQLite
  `BEGIN IMMEDIATE` transaction. Any existing `PREPARED`, `MUTATING`, or
  `RECOVERY_REQUIRED` row atomically rejects the new insert. The blocked caller
  reports zero mutation, the blocking transaction IDs, and recovery-required
  circuit semantics without modifying or clearing the live row. The process
  singleton also rejects rebinding to a different canonical database path.
- **Action coverage:** registered service, registry, firewall, suspend, and
  terminate responses retain their exact prior state or exact compensation /
  irreversible postcondition identity before dispatch. A rollback receipt is
  terminal only after the action separately verifies restoration.
- **Governed recovery:** `reconcile_remediation_transaction()` is a separate,
  explicit authorization API. It can clear persistent recovery only after an
  exact verified rollback, or after proving the exact postcondition of an
  irreversible action. No new credential, environment token, or ad hoc secret
  was introduced.
- **Regression:** inert fixtures prove MUTATING is on disk at dispatch, failed
  rollback blocks a second call, the circuit survives a fresh database object /
  process-style restart, unauthorized reconciliation cannot clear it, verified
  reconciliation can, missing DB custody prevents dispatch, and an oversized
  PREPARED record fails before mutation. A synchronized two-thread fixture now
  forces both callers past an empty preflight, holds the winner in MUTATING,
  and proves exactly one dispatch while the second is durably blocked.
- **Gate:** Python compile PASS; Ruff PASS; **126 passed, 1 expected skip** across
  the focused and adjacent remediation/workflow suites; product self-test N/A.

## C26-R3-A03 — FIXED

- **Finding:** broad free-text `t1562` matching swallowed the exact
  `T1562.011` script-block-logging control, while one registry action silently
  hid and chose among multiple internal candidates by table order.
- **Change:** Defender dominance now uses an exact ATT&CK identifier or exact
  typed control ID and explicitly excludes `T1562.011`. Registry hardening uses
  an immutable typed control catalog keyed by exact ATT&CK identifiers and
  optional exact control IDs; arbitrary name/category/detection text never
  selects a registry target.
- **Ambiguity boundary:** registry candidates are enumerated before matching.
  Exactly one technique-consistent candidate is required. Zero candidates,
  conflicting identifiers, mismatched controls, and multi-candidate techniques
  remain manual-review only and cannot produce a verified record for
  `PostureHardening` to mark patched.
- **Regression:** inert cases prove `T1562.011` reaches its unique registry
  control rather than Defender, composite credential/UAC text still selects
  only the exact `T1548.002` control, ambiguous `T1003.001` cannot mutate without
  a matching typed control ID, and mismatched/conflicting identifiers fail
  closed.
- **Gate:** Python compile PASS; Ruff PASS; focused and adjacent response /
  posture regression suites PASS; product self-test N/A.

## Combined gate

- Assigned Python files and focused tests: compile **PASS**.
- Ruff: **PASS**.
- Checked-in workflow validator: **PASS**.
- Focused plus adjacent affected tests: **126 passed, 1 expected skip**.
- Diff hygiene: **PASS**.
- No commit or publication was performed by this remediation slice.

## Release/source authority remediation addendum

### C26-R3-C01 — FIXED

- **Change:** `tools/validate_workflow_policy.py` now treats `release.yml` as a
  closed root/job/runner/timeout/permission/step schema. The exact producer and
  consumer artifact graph rejects every extra upload and every expression-named
  Windows security artifact. The bounded POSIX matrix template is accepted only
  with its exact two-entry matrix.
- **Fail-stop authority:** `.github/workflows/release.yml` still cannot produce
  finalized assets. Its sole authority step now uses an absolute
  `/usr/bin/env -i ... /bin/bash --noprofile --norc ...` shell, so inherited
  `BASH_ENV`, `ENV`, and exported Bash functions never enter Bash startup. A
  future external signer must replace the exact policy with independently bound
  artifact ID, digest, and byte verification before publication can become
  reachable; a name alone grants no authority in the checked-in state.
- **Gate:** compile PASS; Ruff PASS; validator PASS; inert root-defaults,
  startup-control, extra-step, and expression-artifact regressions PASS.

### C26-R3-C02 — FIXED

- **Change:** the parsed-document scan now tokenizes each `${{ ... }}` span and
  rejects `secrets` as a standalone lexical token, regardless of dot, bracket,
  or function syntax. It does not scan YAML comments or prose outside an
  expression.
- **Gate:** workflow-, job-, and step-level `${{ toJSON(secrets) }}` fixtures
  PASS; existing comment/prose precision fixtures PASS; compile/Ruff/validator
  PASS.

### C26-R3-C03 — FIXED

- **Change:** `src/angerona/core/privilege.py` returns immutable typed elevation
  results for every returning path. `src/angerona/__main__.py` now requires the
  typed effective-Administrator state, an independent effective token check,
  and the repeated exact package identity before frozen runtime initialization.
  Cancellation, denial, helper failure, or a missing/false proof exits visibly
  with status 2.
- **Gate:** both product files compile; Ruff PASS; inert cancellation/failure,
  forged-success-without-token, package-recheck, and launcher-boundary tests
  PASS; helper self-test N/A.

### C26-R3-C04 — FIXED

- **Change:** `tools/verify_published_readme_assets.py` resolves one immutable
  commit and reads bounded `README.md`/PNG blobs with `git cat-file`; it proves
  the public README target set and public image bytes against those objects,
  never the mutable worktree. `tools/publish_github_update.py` passes its
  captured HEAD and repeats exact HEAD plus porcelain-clean proof after all
  network checks as the final operation before reporting success.
- **Gate:** both helpers compile; Ruff PASS; a temporary-repository concurrent
  edit fixture proves worktree changes cannot alter verifier expectations and
  the publisher refuses an edit introduced during network verification. A
  read-only live check of the current public commit passed all **4/4** images.

### Addendum gate

- Focused release/source/publication/privilege gate: **52 passed**.
- Python compile, Ruff, workflow policy, JSON parse, and diff hygiene: **PASS**.
- No publish, release, host mutation, UAC request, or secret access occurred.

## Release/source authority post-fix addendum

### C26-R3-C05 — FIXED

- **Change:** `tools/verify_published_readme_assets.py` no longer consults
  inherited `SystemRoot` or copies `os.environ`. It resolves canonical
  `System32` with `GetSystemDirectoryW`, requires the exact resolved
  `WindowsPowerShell/v1.0/powershell.exe` beneath it, and proves stable file
  identity before/after use.
- **Child boundary:** PowerShell receives only WinAPI-derived `SystemRoot` (the
  managed runtime requires it) plus the exact URL/output/timeout inputs. It has
  no inherited PATH, proxy, `PSModulePath`, Python controls, shell-startup
  values, credentials, or unrelated Angerona authority. It retains absolute
  execution, fixed trusted cwd, `-NoProfile`, `-NonInteractive`, bounded timeout,
  and hidden-window execution.
- **Response proof:** both Python and PowerShell require HTTP 200 and canonical
  final `https://raw.githubusercontent.com` coordinates; Python rechecks type
  and size, then the immutable-blob caller rechecks PNG structure and exact
  digest/bytes.
- **Gate:** mocked forged-SystemRoot/PATH/module/proxy/secret regression PASS;
  real bounded System32 PowerShell download PASS (**1,490-byte PNG**); compile
  and Ruff PASS; helper self-test N/A.

### C26-R3-C06 — FIXED

- **Change:** `tools/publish_github_update.py` accepts only remote name `origin`.
  Raw binary `git remote get-url` output for both fetch and push must be exactly
  one `https://github.com/Ag3nt47/AngeronaSuite.git` line. The canonical
  repository argument cannot be overridden; the generic parser is retained
  only behind this byte-exact publication check.
- **Regression:** missing `.git`, extra/trailing/doubled slashes, casing
  variants, and whitespace all fail before any network/push action. The current
  fetch and push configuration each match exactly.
- **Gate:** compile PASS; Ruff PASS; focused publication/release/source gate
  **68 passed**; read-only public asset proof remains **4/4 images PASS**.

### Post-fix addendum safety

- No publication, remote mutation, UAC, secret access, or host-security change
  occurred.

## Runtime/authentication remediation addendum

### C26-R3-B01 — FIXED

- **Change:** `src/angerona/core/windows_auth_extensions.py` now makes complete
  health and ordinary trusted enrollment conditional on stable handle-bound
  digest/file identity, valid embedded-or-catalog signature assurance with a
  signer token, component owner/ACL evidence, and registry-key owner/ACL
  custody. The descriptor/path identity is revalidated after all probes.
- **Fail-closed scope:** no pathname-only signature verifier was invented. The
  production provider currently supplies no genuine handle-bound signature
  probe, so its evidence remains partial and non-enrollable until that
  independently trustworthy capability exists.
- **Gate:** compile PASS; module self-test PASS; Ruff PASS; incomplete,
  invalid, unknown, missing-owner, missing-ACL, and partial-evidence regressions
  PASS.

### C26-R3-B02 — FIXED

- **Change:** `src/angerona/core/windows_auth_extensions.py` now parses
  unauthenticated JSON with bounded integer/float domains and strict object,
  node, depth, collection, key, and string limits. All parse, recursion,
  overflow, schema, and conversion failures are normalized to bounded baseline
  integrity state before HMAC reconstruction.
- **Observer boundary:**
  `src/angerona/modules/authentication_extension_guard.py` converts any
  remaining baseline-boundary failure to tampered/unknown evidence rather than
  allowing the capability to crash.
- **Gate:** compile PASS; module self-test PASS; Ruff PASS; 400-digit integer,
  unbounded exponent, and excessive-depth `observe_once()` regressions PASS at
  health 15/tampered.

### C26-R3-B03 — FIXED

- **Change:** `src/angerona/resilience/_selftest_environment.py` starts from
  `sanitized_child_environment(source={})`, adds only an exact target-specific
  routing map, uses a trusted source working directory and fixed `-I` bootstrap,
  and excludes inherited credentials, proxies, Python controls, and unrelated
  Angerona authority.
- **Custody:** Windows children are created suspended, assigned to a
  kill-on-close job with active-process, CPU, per-process memory, and job-memory
  limits, then exactly one initial thread is resumed. Output is streamed into a
  hard 16 KiB capture ceiling and the child is terminated on overflow. POSIX
  applies safe per-child CPU/file/descriptor/process/address-space ceilings plus
  exact process-group and wall-clock cleanup; it does not overclaim a portable
  perfect process-tree counter.
- **Gate:** compile PASS; all five resilience self-tests PASS; Ruff PASS;
  secret-forwarding, isolated-startup, pre-resume job ordering, output-flood,
  callback-cleanup, and exact-child-chain regressions PASS.

### C26-R3-B04 — FIXED

- **Change:** `src/angerona/core/security_scan_center.py` threads the absolute
  deadline and cancellation token through descriptor reads and checks them
  around each bounded chunk and before/after YARA. Direct-file roots receive
  post-work accounting, and late YARA output is discarded.
- **Truthful limit:** platform reads/YARA are disclosed as cooperative rather
  than claimed hard-interruptible. Any call returning after the deadline is
  `limited` with `timed_out=true`, never `completed`.
- **Gate:** compile PASS; Ruff PASS; late direct-read and late-YARA regressions
  PASS; adjacent Scan Center tests PASS.

### C26-R3-B05 — FIXED

- **Change:** `src/angerona/core/module_base.py` replaces mutable module-global
  declaration searches with an immutable bounded code-object manifest compiled
  from the exact descriptor-bound canonical source bytes. Exact path/line
  evidence requires structural code membership plus matching module file/spec
  identity and the retained source digest.
- **Gate:** compile PASS; Ruff PASS; health-evidence UI tests PASS; an inert
  function dynamically compiled with the trusted filename and inserted into
  the real module dictionary is classified `unverified-callsite` with no path
  or line.

### Runtime/authentication combined gate

- Affected Python compilation: **PASS**.
- Ruff: **PASS**.
- Focused plus adjacent runtime/authentication/Scan Center/resilience gate:
  **88 passed, 2 expected platform skips**.
- Direct affected self-tests: **6/6 passed** (Authentication Extension
  Integrity Guard plus all five resilience wrappers).
- No host security setting, registered authentication component, credential,
  network endpoint, or production baseline was accessed or mutated.

## Response-custody re-attack closure

### C26-R3-A04 — FIXED

- **Change:** `src/angerona/modules/remediation_actions.py` makes ordinary apply
  calls inspect unresolved state without auto-reconciliation. Explicit recovery
  uses `src/angerona/core/remediation_log.py` to atomically claim exactly one
  `RECOVERY_REQUIRED` transaction before compensation, bound to the retained
  record digest. A losing caller performs no compensation; a crashed claim
  remains durably `RECONCILING`; terminal transaction state and its truthful
  proof receipt commit together.
- **Gate:** affected files compile; Ruff PASS; deterministic live-`MUTATING`
  ordinary-call and two-reconciler races PASS with exactly one action dispatch,
  one compensation, and zero compensation by the losing reconciler.

### C26-R3-A05 — FIXED

- **Change:** `src/angerona/core/remediation_log.py` binds SQLite custody to an
  exact canonical fixed-local-disk path and stable parent/database object
  identities. It rejects reparse/symlink traversal, remote/non-fixed drives,
  pre/post-open identity changes, and multi-link main/WAL/SHM/journal objects,
  then revalidates custody before every mutation and reconciliation boundary.
- **Gate:** affected files compile; Ruff PASS; an NTFS hard-link alias is
  rejected before action dispatch, while a same-canonical-path two-connection
  race admits exactly one `PREPARED` row.

### Response-custody combined gate

- Exact A04/A05 regression file: **9 passed**.
- Focused and adjacent response/remediation gate: **63 passed**.
- Direct module/helper self-test: N/A (neither changed module defines one).
- No remediation action touched host state; all new race fixtures are inert.

## Response transaction-owner remediation addendum

### C26-R3-A06 — FIXED

- **Change:** `src/angerona/core/remediation_log.py` now returns an opaque,
  256-bit random owner capability from durable `PREPARED` creation. SQLite
  stores only its domain-separated SHA-256 digest while the transaction is
  live; inspection APIs and action records expose only the non-secret numeric
  transaction ID. A terminal ordinary transition clears the stored digest and
  retires/zeroes the in-memory capability.
- **Fixed graph:** every ordinary transition requires the exact capability and
  derives its predecessor internally from the sole permitted graph:
  `PREPARED -> MUTATING -> APPLIED|ROLLED_BACK|RECOVERY_REQUIRED`. Raw IDs,
  caller-selected expected states, skipped states, invalid targets, stale
  capabilities, and foreign/cross-transaction capabilities fail closed.
  Explicit reconciliation remains on its distinct unique claim ID plus retained
  record-digest path and never accepts the ordinary owner capability.
- **Caller update:** `src/angerona/modules/remediation_actions.py` keeps the
  owner capability local to the runner and places only its numeric transaction
  ID in response/audit records. Every legitimate transition uses the capability.
- **Regression:** the original inert A06 schedule is synchronized with a live
  action paused in `MUTATING`. A foreign capability cannot force `APPLIED`; the
  second ordinary batch remains blocked with zero dispatch, and releasing the
  original runner produces one total dispatch and one truthful terminal row.
- **Gate:** both affected product files and the regression file compile; Ruff
  PASS; exact custody regression **11 passed**; focused plus adjacent response
  and remediation gate **40 passed**; JSON parse and diff hygiene PASS;
  direct module/helper self-test N/A (neither file defines one).
- **Remaining limitation:** possession of the live capability intentionally
  conveys owner authority inside the process. Python cannot isolate arbitrary
  already-admitted code from process memory; this boundary prevents callers
  that have only the public log reference/transaction ID from forging state.
  A crash still conservatively leaves `PREPARED`/`MUTATING` locked for a
  separately governed recovery design; no automatic abandonment was added.

## Authentication-baseline enrollment-lock remediation addendum

### C26-R3-B06 — FIXED

- **Change:** `src/angerona/core/windows_auth_extensions.py` replaces the
  create-exclusive PID sentinel with a retained, inert one-byte rendezvous
  object. On Windows, `CreateFileW` opens it read/write with zero sharing; on
  POSIX, a nonblocking exclusive `flock` owns it. In both cases the operating
  system releases authority on close or process death, so file existence or
  metadata can never assert a live enrollment owner.
- **Custody:** acquisition preserves the protected-root boundary and verifies
  stable parent identity, a regular single-link object, no reparse/symlink
  alias, and exact handle path on Windows or exact named inode on POSIX.
  Malformed/legacy PID contents are normalized only after exclusivity is held.
  Ambiguous open, live owner, hard link, directory, symlink, reparse, or object
  swap conditions fail closed before the authenticated baseline is read or
  promoted.
- **Regression:** `tests/test_cycle26_round3_auth_enrollment_lock.py` exercises
  two-enroller/live-owner exclusion, a real child `os._exit` crash, stale PID
  and malformed metadata, hard-link/non-regular rejection, platform-gated
  symlink/reparse rejection, and exception cleanup/reacquisition. Crash recovery
  still performs the original HMAC, host binding, completeness, provisional
  signature, and exact stable-snapshot checks before trust can be established.
- **Gate:** affected product/test compile PASS; capability self-test PASS; Ruff
  PASS; focused plus adjacent authentication gate **35 passed, 1 expected
  platform skip**; JSON parse and diff hygiene PASS. No registered extension,
  credential, host setting, network endpoint, publication, or commit was
  touched.

## Response finish-authority and atomic-receipt remediation addendum

### C26-R3-A07 — FIXED

- **Change:** `src/angerona/core/remediation_log.py` mints an exact-type,
  non-copyable and non-serializable 256-bit `RecoveryCapability` only for the
  sole successful reconciliation claimant. SQLite retains only its
  domain-separated digest, bound to the exact transaction ID and retained-
  record SHA-256. Atomic finish requires that capability and retires it only
  after commit.
- **Inspection boundary:** `transaction()` and `unresolved_transactions()` now
  expose only the non-authorizing `recovery_active` state. They never return a
  claim ID, capability digest, record digest, or other reconstructible finish
  authority. A crashed winner therefore remains visibly `RECONCILING` and
  fail-closed after restart, while no new caller can reconstruct or reacquire
  its one-use authority.
- **Regression:** synchronized forged-finish, cross-transaction, stale,
  ordinary-owner/recovery-owner crossover, copy/deepcopy/pickle, representation
  redaction, retained-record tamper, sole-winner, and crash/restart schedules
  all fail closed. The paused legitimate compensator remains the only caller
  able to finish, with one compensation and no competing action dispatch.

### C26-R3-A08 — FIXED

- **Change:** ordinary `transition_transaction()` can now perform only
  `PREPARED -> MUTATING`. The owner-only `finish_transaction()` maps a bounded
  result token to fixed state, outcome, verification, and reserved record
  fields, then updates the terminal journal row, clears the owner, and inserts
  the exact bound proof receipt in one `BEGIN IMMEDIATE` SQLite transaction.
  Action title, host-level status, trigger, technique, and action key come from
  immutable PREPARED metadata rather than terminal caller input.
- **Failure semantics:** injected receipt serialization and insert failures
  roll the database transaction back, leave the durable row `MUTATING` with its
  owner digest intact, return `applied=0`, write no terminal receipt, and block
  every later action batch before dispatch. Recovery finish preserves the same
  atomic rollback rule and its one-use capability remains live after a failed
  receipt commit.
- **Gate:** all four affected product/test files compile; Ruff PASS; exact A07/
  A08 plus prior response-custody regression **21 passed**; focused and adjacent
  response/remediation regression **91 passed**; direct helper/module
  `self_test()` N/A. All fixtures are inert; no host control, network endpoint,
  publication, commit, or external action was touched.

## Authentication-baseline alias-custody addendum

### C26-R3-B07 — FIXED

- **Change:** `src/angerona/core/windows_auth_extensions.py` canonicalizes the
  configured baseline beneath a stable protected data-root identity and rejects
  non-fixed Windows volumes, symlink/reparse traversal, non-regular objects,
  and every existing baseline or lock whose link count is not exactly one.
  Baseline reads prove the no-follow handle, named object, parent, root, volume,
  size, and modification identity before accepting authenticated content.
- **Single authority namespace:** enrollment now uses one constant rendezvous
  name per protected data root, never a caller-controlled baseline basename.
  Missing baseline names therefore serialize through the same lock. Windows
  retains root, parent, and zero-share lock handles; POSIX also locks the
  retained root-directory inode, so deleting and recreating the inert lock file
  cannot give a second cooperating process authority.
- **Promotion custody:** root, parent, rendezvous, and baseline identities are
  revalidated at acquisition, before/after each load or create, immediately
  around promotion, and before successful release. POSIX create/replace/unlink
  operations use the retained parent descriptor. A promoted object must match
  the exact temporary-file identity and remain single-link; ambiguous namespace
  replacement fails closed and cannot be reported as a successful enrollment.
- **Regression:** `tests/test_cycle26_round3_auth_enrollment_lock.py` adds
  synchronized hard-linked baseline aliases (zero successful enrollments), two
  missing filename candidates sharing one root lock, baseline symlink/reparse
  rejection, POSIX lock unlink/recreate exclusion, and protected-root/parent
  rename-or-replacement detection. The earlier exact-path, live-owner, stale
  metadata, exception cleanup, and real child-crash recovery schedules remain
  green.
- **Gate:** affected product/test compile PASS; Authentication Extension
  Integrity Guard `self_test()` PASS; Ruff PASS; focused plus adjacent
  authentication regression **39 passed, 3 expected platform skips**; JSON and
  diff hygiene PASS. No host authentication extension, credential, setting,
  network endpoint, publication, or commit was touched.

## Publication transport-authority remediation addendum

### C26-R3-C07 — FIXED

- **Change:** `tools/verify_published_readme_assets.py` deletes the Windows
  PowerShell fallback and its unqualified `Invoke-WebRequest` call. Public
  README/image verification now has exactly one in-process Python HTTPS path,
  so PowerShell module discovery and CurrentUser module autoload are absent.
- **Regression:** a synthetic CurrentUser `Microsoft.PowerShell.Utility` shadow
  remains byte-identical and unexecuted while the in-memory HTTPS path succeeds.

### C26-R3-C08 — FIXED

- **Change:** deleting the external downloader also deletes every temporary
  pathname handoff, closed output descriptor, pathname reopen, and unlink. The
  only downloader reads at most the configured bound directly into memory.
- **Regression:** an inert hard-link alias and separate victim remain unchanged;
  the downloader neither selects the caller's temporary root nor writes a path.

### C26-R3-C09 — FIXED

- **Change:** new `tools/publication_transport.py` resolves Git for Windows only
  from the machine-wide HKLM install root (a root-owned fixed path on POSIX),
  rejects reparse/install escape, binds Git and Git Credential Manager file
  identities, and revalidates both before and after every process. Each process
  receives a fresh allowlisted environment: system/global configuration,
  executable search, Git config injection, proxy/CA/TLS-disable, askpass, SSH,
  alternate-object, and startup inputs from the caller do not cross it.
- **Credential boundary:** the exact identity-bound machine Git Credential
  Manager is the sole helper, restricted to noninteractive retrieval of an
  existing operating-system credential. If that reviewed helper is unavailable,
  a mutating publication fails explicitly; no ambient helper is substituted.
- **HTTPS boundary:** `tools/verify_published_readme_assets.py` constructs a
  request-local opener with `ProxyHandler({})`, strict hostname/certificate
  checks, TLS 1.2 minimum, and newly loaded system trust. Ambient proxy, CA,
  OpenSSL-config, requests/curl CA, and TLS-keylog selectors fail before open.

### C26-R3-C10 — FIXED

- **Change:** `tools/publish_github_update.py` captures the exact no-alias,
  single-link local config path plus device/inode/size/mtime/SHA-256; rejects
  repository include, URL rewrite, HTTP, credential, protocol, SSH, helper, and
  noncanonical remote authority; and repeats raw sole fetch/push URL, config,
  HEAD, and full cleanliness proofs before and after every network operation.
- **Transport:** every default-branch query, ref query, fetch, and atomic
  non-force push receives the literal
  `https://github.com/Ag3nt47/AngeronaSuite.git`; no later operation resolves the
  mutable remote name. Command-priority pins prohibit redirecting that literal.
- **Regression:** a deterministic local-config mutation after the first gate is
  detected before fetch or push. URL rewrite, `GIT_CONFIG_*`, `GIT_EXEC_PATH`,
  `GIT_SSL_NO_VERIFY`, askpass/SSH, ambient proxy/CA/secret/PATH, malformed raw
  origin framing, and nonliteral remote helper fixtures all fail or remain
  outside the child boundary as intended.

### Publication transport gate

- Compile: `publication_transport.py`, `verify_published_readme_assets.py`, and
  `publish_github_update.py` **PASS**.
- Direct helper/module `self_test()`: **N/A** (none of the three defines one).
- Ruff: affected helpers and tests **PASS**.
- Exact publication snapshot/transport regression: **36 passed**.
- Adjacent workflow, signing-boundary, release-setup, and launcher gate:
  **50 passed**.
- Workflow policy validator: **PASS**; findings JSON parse and diff hygiene:
  **PASS**.
- Live read-only proof: canonical GitHub default branch `main` and exact public
  SHA resolved through the isolated Git boundary; immutable README plus all
  **4/4** public images matched through direct no-proxy system-trust HTTPS.
- One broader documentation test remains outside this remediation: README's
  current `modules=80` marker trails the concurrently added 81st module. No
  publication, push, fetch, credential display, host control, or product-state
  mutation occurred.

## Response recovery-orchestration authority addendum

### C26-R3-A09 — FIXED

- **Change:** `src/angerona/core/remediation_log.py` removes the ordinary public
  `claim_reconciliation` and `finish_reconciliation` API. Its private claim,
  proof, and finish boundary now requires the exact random coordinator minted
  once for one `RemediationLog` instance and one immutable action-registry
  snapshot. Finish also requires the winning, digest-bound, one-use
  `RecoveryCapability` and the exact store-issued verified proof.
- **Orchestration:** `src/angerona/modules/remediation_actions.py` owns the sole
  module-private coordinator. The public request selects exactly one bound
  action, calls its real rollback or fail-closed postcondition verifier, and
  only after success requests proof and an atomic terminal-plus-receipt commit.
  The store derives the outcome and terminal record from retained custody;
  callers cannot supply `reconciled_rolled_back` or replace the record. Missing
  actions, exceptions, and failed verifiers leave the durable claim
  `RECONCILING` and prevent another compensation attempt.
- **Boundary:** this is an ordinary in-process API boundary. Arbitrary
  introspective Python already executing with Angerona's token is explicitly
  outside the isolation promise and requires a narrow authenticated helper
  process if hostile extensions are admitted.
- **Regression:** `tests/test_cycle26_round3_response_receipt_authority.py`
  proves public claim/finish absence, fake-assertion denial, exact rollback once,
  verifier-failure lock retention, cross-store/coordinator/capability rejection,
  receipt-failure retry with the same internal proof, A07 secrecy/single-flight,
  and A08 atomic receipt semantics.
- **Gate:** product and affected test compile **PASS**; direct `self_test()`
  **N/A**; Ruff **PASS**; exact A07/A08/A09 and custody gate **24 passed**;
  adjacent response/remediation gate **18 passed**; findings JSON and diff
  hygiene **PASS**. All probes were inert. No host mutation, publication,
  commit, push, or network action occurred.

## Authentication-baseline logical-slot remediation addendum

### C26-R3-B08 — FIXED

- **Authenticated slot binding:** baseline schema v2 bodies now carry an HMAC-
  protected token derived from the canonical protected root, exact normalized
  relative filename, and baseline schema. Every load verifies the token after
  authenticating the body, so a byte copy, surviving hard link, or moved-root
  copy is tampered/provisional outside its original logical slot.
- **One trusted slot:** one fixed-name, bounded, single-link, HMAC-authenticated
  registry under the protected root records the sole trusted logical slot.
  Repeated approval under a different filename fails closed. An explicit
  same-slot approval can finish registry creation after an interrupted commit;
  until then the trusted body is unregistered and observation reports tamper.
- **Promotion postcondition:** Windows retains a share-delete/DELETE handle to
  the provisional object and promotes with `ReplaceFileW`; POSIX retains its
  no-follow descriptor and uses descriptor-relative replacement. Success
  requires the retired object to have zero namespace links and the promoted
  object to be the exact single-link temporary identity. Any alias postcondition
  removes the promoted name and leaves no registered trusted state.
- **Regression:** deterministic hard-link injection at the final replace,
  trusted-byte copy, sequential approved missing names, normalized-path/root-
  move, and interrupted same-slot registration recovery are covered alongside
  the prior B06/B07 schedules.
- **Gate:** affected product/test compile **PASS**; Authentication Extension
  Integrity Guard `self_test()` **PASS**; Ruff **PASS**; focused and adjacent
  authentication gate **44 passed, 3 expected platform skips**; findings JSON
  parse and diff hygiene **PASS**. No host setting, credential, registered
  component, publication, commit, or network endpoint was touched.

## Authentication-baseline fixed-slot remediation addendum

### C26-R3-B09 — FIXED

- **Change:** `src/angerona/core/windows_auth_extensions.py` collapses the
  configurable baseline pathname to the single canonical policy slot
  `<data_root>/baselines/windows_auth_extensions.json`. The constructor rejects
  alternate filenames/directories before observation or enrollment, and root
  custody revalidates the fixed path. Existing HMAC root/name/schema binding,
  retained promotion custody, single-link proofs, and explicit enrollment stay
  intact.
- **Recovery:** registry loss can be repaired only from an authenticated trusted
  body already occupying that fixed slot and matching the reviewed current
  snapshot. Divergent evidence is rejected, so replaying a retained authentic
  registry can name only the same slot and cannot select a trusted fork.
- **Boundary:** baseline freshness remains a local software-clock plus HMAC
  assertion. There is no external high-water, TPM monotonic counter, or other
  rollback-resistant witness, and the implementation does not claim one.
- **Regression:** `tests/test_cycle26_round3_auth_enrollment_lock.py` covers the
  exact enroll-A/save-registry/delete-registry/divergent-B attempt/recover-A/
  replay-saved-registry schedule, alternate relative filenames and directories,
  same-root interrupted registration, and copied/moved roots. Related tests now
  use isolated data roots with the production fixed slot.
- **Gate:** changed product and test files compile **PASS**; Authentication
  Extension Integrity Guard `self_test()` **PASS**; Ruff **PASS**; focused and
  adjacent authentication gate **46 passed, 3 expected platform skips**;
  findings JSON parse and diff hygiene **PASS**. No host setting, credential,
  registry surface, publication, commit, or network endpoint was touched.

## Publication runtime-closure remediation addendum

### C26-R3-C11 — FIXED

- **Pinned closure:** `tools/publication_git_runtime_profile.json` is a closed,
  reviewed profile for Git for Windows `2.55.0.windows.4` (build
  `a93524749d7806870fd2b4b00a3812da1d6e5f4a`). It binds **312 exact files**,
  **191,289,767 bytes**, every relative name/size/SHA-256, and tree digest
  `7151e168c3a919a5b63d42f432d38ebf51c1d05ee3eed821016e8c7349ce2356`.
  The closure includes Git, GCM, `git-remote-https`, runtime DLLs, `sh.exe`,
  and `msys-2.0.dll`; additions, removals, aliases, and digest changes fail.
- **Sealed execution:** `tools/windows_publication_runtime.py` treats the
  writable HKLM installation as discovery input only. No-write/delete source
  handles stabilize every object while exact bytes are copied into an
  atomically created, protected, non-reparse private directory. The staged
  tree is rehashed and retained behind deny-write handles; its DACL grants the
  publisher read/execute only and grants full control only to SYSTEM and
  Administrators. Windows System32 DLLs are the explicit OS trust boundary.
- **Transport/lifecycle:** `tools/publication_transport.py` launches only the
  staged absolute Git image from the private runtime directory, with staged
  `PATH`/`GIT_EXEC_PATH`, a separately private non-code transient directory,
  a fresh allowlist environment, and a correctly shell-quoted absolute GCM
  helper. `tools/publish_github_update.py` and
  `tools/verify_published_readme_assets.py` reuse one retained seal and close
  both private trees before success.
- **Regression:** same-size pre-replaced Git (a nominal platform signature is
  irrelevant), unreviewed DLL/helper additions, source write and replacement
  during copy, staged write/addition, restrictive DACL, exact cleanup, and
  whitespace/metacharacter/apostrophe quoting passed: **7/7** focused checks.
- **Live read-only gates:** staged Git resolved local HEAD
  `26277087f343c73252b8c00b34f73a402e085e9a`; staged GCM reported
  `2.9.0+194ba290ce533465310d50f811684ab180536ae7`; cleanup left **zero**
  `angerona-publish-*` directories and zero gate-process orphans. No credential
  was displayed and no fetch, push, publication, ACL mutation, or repository
  state mutation occurred.
- **Gates:** all affected helper/test files byte-compiled **PASS**; bounded
  affected-file Ruff **PASS**; direct helper `self_test()` is **N/A**. The full
  43-test file rerun is deferred to final cooled-down QA after host AV/disk
  pressure began taking multiple seconds per ordinary Python import;
  faulthandler showed progress in standard `_pytest`/`pluggy`/stdlib reads, not
  a transport deadlock.
  Canonical read-only `ls-remote` through the final seal is also reserved for
  final publication QA; it performs no fetch or mutation.

## Publication profile trust-anchor remediation addendum

### C26-R3-C12 — FIXED

- **Independent authority:** `tools/windows_publication_runtime.py` now embeds
  the reviewed profile's exact 54,008-byte LF SHA-256, Git version/build,
  directory/file counts, total tree bytes, and tree SHA-256 in the already
  loaded module. Exact bytes are authenticated before duplicate-safe JSON
  parsing; an internally consistent replacement document has no authority.
- **One sealed read:** production accepts only the compiled absolute profile
  path on a fixed local volume. A no-follow regular-file handle and its parent
  handle deny write/delete sharing; the file must remain single-link,
  non-reparse, on the parent's volume, and reachable through its exact canonical
  handle name. The bounded profile bytes are read once, then the immutable
  parsed profile and retained identities are revalidated through completion of
  staging without reopening the pathname.
- **Source and process ordering:** every Git source identity and its complete
  reviewed hard-link topology are checked again before the private runtime is
  returned. The staged version/build probe runs through the
  completed `TrustedGitBoundary`; `publish()` binds that boundary before any
  HEAD, status, configuration, or remote Git operation.
- **Regression:** `tests/test_cycle26_publication_profile_anchor.py` proves the
  exact approved profile, same-size mutation, internally consistent addition,
  duplicate-key rejection even under a simulated re-anchor, compiled-constant
  mismatch, alternate-path rejection, no-write/replace/link read races,
  seal revalidation through lightweight staging, zero-launch profile/Git
  substitution, and publisher boundary ordering: **9 passed**.
- **Boundary and gates:** trusted publisher Python already loaded at process
  start is the root of this in-process authority. Pre-start replacement of that
  code and live process-memory compromise remain explicitly outside the claim.
  Changed helpers/tests byte-compile **PASS**; direct helper `self_test()` is
  **N/A**; affected-file Ruff **PASS**; findings/profile JSON and diff hygiene
  **PASS**. No full runtime staging, credential access, network request, fetch,
  push, publish, host setting, or repository state mutation occurred.

## Publication hard-link topology remediation addendum

### C26-R3-C13 — FIXED

- **Change:** `tools/windows_publication_runtime.py` now groups source entries
  by stable Windows volume/file ID and retains one no-write/delete handle per
  identity. A single-link identity must retain its one exact final handle name.
  A multi-link identity is accepted only when Win32 enumeration proves its
  complete canonical alias set exactly equals the reviewed profile group and
  every entry has the same pinned size and SHA-256.
- **Fail-closed cases:** an outside alias, in-root unprofiled alias,
  noncanonical/reparse name, profile disagreement, identity/link-count change,
  or pre/post-copy alias swap aborts staging. There is no blanket `nlink > 1`
  exception. One source read fans out to independent staged files; the existing
  rehash, single-link stage seal, DACL, cleanup, and runtime revalidation remain
  unchanged.
- **Regression:** the five exact inert C13 cases passed **5/5**: reviewed
  hard-link pair, outside alias, unprofiled alias, profile metadata mismatch,
  and alias swap denied or detected. Six adjacent profile/stage checks passed
  **6/6**. A read-only real-host handle probe showed stable link count two and
  exactly `D:\Git\cmd\git.exe` plus `D:\Git\cmd\git-lfs.exe`.
- **Live-stage boundary:** the three formerly blocked publication assertions
  now share one retained runtime fixture so a grouped run performs at most one
  real 191 MB stage. That run was stopped at the agreed eight-minute ceiling
  while known host AV/I/O pressure left pytest responsive but CPU-flat before
  private staging. It yielded no pass/fail result and is **DEFERRED TO FINAL
  RELEASE QA**, not counted as passed. Interruption left zero test processes and
  zero `angerona-publish-*` directories.
- **Gates:** final changed helper/test byte-compilation **PASS**; helper
  `self_test()` **N/A**; bounded Ruff **PASS**; findings JSON parse and diff
  hygiene checked after documentation. No Git/GCM launch, credential access,
  fetch, push, publication, network action, or host/repository mutation was
  performed by this remediation.
