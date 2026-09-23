# Independent final gate — linked-token Ollama launch and VMware service custody

Reviewed the final `core/ollama_windows_token.py`, its integration in
`core/ollama_lifecycle.py`, and the strengthened service ancestry checks in
`core/analysis_vmware_setup.py` / `tools/enable_analysis_lab_vmware.ps1`.
**No new confirmed security finding was identified.**

This was source review plus inert regressions in the September 23 worktree.
The reviewer changed no product files and performed no UAC request, native
Ollama launch, service mutation or VM operation. The coordinator's read-only
current-token adapter check is separate evidence; this review does not claim
an elevated native launch has passed.

## Token and process boundary

- The only token source is the current process and its kernel-linked token.
  There is no alternate account, arbitrary process token, credentials prompt,
  shell handoff or elevated fallback. The parent must be a high-integrity,
  elevated split-token primary token in a nonzero interactive session.
- The linked token and the suspended child's own primary token must both match
  the parent's SID and session, have exact medium integrity and limited elevation
  type, and have neither elevation nor UIAccess. Failure to obtain or verify
  these properties stops automatic startup.
- The public launch helper repeats known-image trust checks and retains
  executable/parent custody. Native creation receives the explicit application
  path and fixed `serve` arguments with suspended, Unicode-environment and hidden
  creation flags. Standard-handle fields remain empty; no privileged standard
  handles are supplied. The child image and token are checked before its primary
  thread resumes.
- Caller environment is rebuilt through the existing allowlist. Only validated
  absolute `OLLAMA_MODELS` storage is extracted from the linked user's profile
  environment; other profile credentials, proxy variables, PATH and Ollama policy
  overrides are not forwarded. Environment entries reject NULs, invalid names
  and non-string values; the serialized environment and command have explicit
  length bounds.
- Deadline and cancellation checks precede creation and resume. A refused child
  is terminated only through the exact process handle returned by this creation.
  Token/thread handles are closed on every path; cleanup continues if an earlier
  termination/close operation fails. The resumed process handle transfers to the
  polling wrapper and is released when that wrapper is discarded. There is no
  retry into elevated `Popen` after a failed medium-token handoff.

The Win32 argument review was checked against Microsoft's
[CreateProcessWithTokenW contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
and [TOKEN_LINKED_TOKEN definition](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_linked_token).
The implementation supplies a full executable path and explicit Unicode
environment, respects primary-token requirements, and verifies matching sessions.
API permission failures are availability failures; no alternate-credential
fallback from documentation is adopted.

## Service ancestry and prior closure

The final GUI service action supplies the already trusted VMware installation
directory as data in its sanitized environment. The standalone administrator
helper clears any inherited expected-directory value and discovers its directory
from the fixed HKLM Workstation key. Both use the same immutable service body.

Before any service change, that body requires the registered executable's parent
to equal the expected installation directory. It traverses ancestors from the
root downward, rejects reparse/non-directory components before and after opening,
and retains directory handles without delete sharing. It then holds the service
executable without write/delete sharing through publisher verification and
startup. This closes the remaining parent-renaming window around the previously
reviewed file seal. Exact service-registration rechecks and rejection of unquoted
whitespace remain present.

**D23-R3-01 remains resolved in source.** The optional setup tests additionally
prove a foreign service directory is rejected and a fixture parent cannot be
renamed while the service body holds custody. Those tests replace service and
signature commands; they do not start or reconfigure a real service. Neither
service success nor optional installation marks Analysis Lab ready, and the
known VMX-custody compatibility refusal remains intact.

## Independent tests and limits

Added `tests/test_ollama_windows_token_boundary.py` with **11 inert cases**:

- invalid, injected and oversized environment blocks never reach native creation;
- an oversized command never reaches native creation;
- a failed native creation call raises rather than returning a process;
- only model storage crosses from a synthetic profile environment;
- conflicting case-insensitive model-storage entries are rejected.

The owner separately added policy and native-marshaling checks. This reviewer ran
the integrated selection of `test_ollama_windows_token_boundary`,
`test_ollama_windows_token`, `test_ollama_startup` and
`test_vmware_optional_setup`: **106 passed in 12.82 seconds**, no skips/failures.
Ruff and whitespace checks passed for the new independent test file. The existing
checkout virtualenv was used with this worktree's `src` on `PYTHONPATH` and the
repository's isolated test runtime.

These gates mock token creation and process creation. They establish policy,
marshaling, cleanup and failure behavior, not successful native operation from
an elevated signed-MSIX launch. That authorized native acceptance test remains
outstanding. A missing linked token, missing API privilege or incompatible host
must remain a visible unavailable result with no elevated parser fallback.

| New severity / prior disposition | Count |
|---|---:|
| CRITICAL / HIGH / MEDIUM / LOW / INFO | 0 |
| Prior findings verified resolved in this pass | 1 |
| Prior findings verified still open in this pass | 0 |
