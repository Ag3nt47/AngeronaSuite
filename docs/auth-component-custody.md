# Authentication-component path custody

This development checkpoint hardens observation of Windows authentication
extension files. It does not load a registered DLL, enroll a new trust baseline,
or grant response authority.

Before addressing a component leaf, the collector requires a fixed local drive
and walks at most 64 ancestors from the filesystem root. It retains plain
directory handles, rejects reparse points, and checks named, opened and final-path
identities before descent and around hashing and assurance probes. Component
guards exclude write and delete sharing. Ordinary enrollment guards retain their
existing read/write sharing policy; both use directory-list access so Windows
sharing checks enforce rename exclusion.

The leaf is checked against its open handle and rechecked after hashing and
metadata probes. A changed name, identity, timestamp or reparse attribute cannot
produce complete evidence. Legitimate hard-linked system components remain
supported. Missing access, incomplete security/signature evidence and expired
cooperative budgets remain explicit unknown or partial results.

The existing per-component/aggregate hashing limits, 45-second cooperative
collection budget, enrollment approvals and response boundaries remain. Native
filesystem and assurance calls cannot be forcibly interrupted by that budget.
These are local user-mode custody checks; they do not establish immunity to an
administrator or compromised kernel, nor a universal no-egress guarantee.

Validation for this isolated checkpoint selects the four unchanged public-base
families `test_windows_auth_extensions.py`,
`test_authentication_extension_guard.py`,
`test_cycle26_round3_runtime_auth.py` and
`test_cycle26_round3_auth_enrollment_lock.py`, plus the new
`test_auth_extension_component_custody.py`. The native gate explicitly enables
its four owned fixtures: inert hard-linked component hashing, component-parent
rename refusal and release, and both omitted-default/explicit-false enrollment
directory rename controls. No real registered component, registry/service change,
network, hardware or policy operation is required.

The clean public-base gate collected **109 cases: 106 passed, 3 skipped**, with
all four mandatory native cases passing. The actual executing Python process
had a retained, raw-creation-time-bound kernel handle: it signaled termination
with native exit zero, alongside normal pytest/atexit journals. All 1,080 frozen
inputs remained unchanged, and all 18 imported product modules resolved to the
clean worktree. The three skips retain their existing platform/fixture limits;
no compatibility skip or assertion weakening was introduced.

The broader private auth review (**226 passed, 3 skipped across 229 cases**) and
working-tree custody review (**563 passed, 8 skipped across 571 cases**) cover
additional, unpublished dependencies and remain separate evidence. The fifth
legacy family in the private auth review, sensor collection/disposition, is
absent from this public base and was not copied into this checkpoint.
An earlier private timed
traceback run ended with `0xC0000005` despite passing JUnit records. Its cause
remains unresolved. A later standard native gate passed; a diagnostic comparison
ended before its timer fired. This checkpoint does not claim to fix that crash.
