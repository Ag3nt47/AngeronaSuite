# GitHub source review implementation

Date: 2026-09-05. Maintenance on v1.13.0; capability count remains 84.

## Delivered behavior

Red Team now has a **GitHub Tools** tab beside the existing simulation, history,
device lab and Sandbox Editor. Its workflow is:

1. Enter a public GitHub repository URL and branch, tag or full commit SHA.
2. Resolve the revision and inspect the full commit and reported license.
3. Import that pinned source archive.
4. Select an import, then browse its files as plain text.
5. Mark the exact import reviewed or permanently revoke it.

Gitleaks and Bandit appear as source URL shortcuts. These actions do not install
an analyzer or execute a repository. Review labels carry no action authority.
Analysis Lab shows an explicit unavailable state and has no execution callback.
The installed source editor retains its copy-only behavior.

## Boundaries and responsiveness

- Acquisition requires a non-administrator/root session and uses fixed GitHub
  API/codeload URLs. Public metadata identity is checked; the resolved full SHA
  selects the downloaded archive. Credentials, cookies, environment proxies,
  setup instructions, Git hooks, submodules and LFS helpers are not used.
- ZIP bytes remain inert in a separate source library. Raw directory entries are
  validated before the platform ZIP reader normalizes filenames. Member count,
  sizes, CRC, compression ratio, unsafe names, links, directory conflicts and
  collisions are checked before an import becomes visible.
- Imports use guarded filesystem operations and an OS file lease. The archive is
  written before the atomic index transaction. Cancelled work can leave an inert,
  unindexed archive; it remains included in the cache budget. A sealed index save
  finishes with accurate UI feedback rather than falsely reporting cancellation.
- Browsing rechecks the saved archive digest. UTF-8 text preview has a 256 KiB
  bound, literal markup and control-character sanitization. Binary and oversized
  files show metadata. Repository prose cannot become application instructions.
- Two background-worker permits bound outstanding operations across panels.
  Hashing, archive reads and network calls do not run on the GUI thread. Closing
  the console or destroying the panel requests cancellation without joining a
  worker on the UI thread. A cancelled result cannot update the preview or plan.
- Reviewed imports with altered bytes cannot be browsed or reapproved. Revocation
  remains available even if an archive is damaged. Reimporting the same bytes does
  not erase an existing revocation.

Default bounds: 32 imports, 512 MiB total cache including interrupted archives,
100 MiB archive download, 250 MiB expanded data, 10,000 members, ratio 512,
120-second phase checks and ten-second network socket timeouts. The ratio bound
allows Bandit's legitimate 65,560-byte generated source fixture while the byte
and deadline budgets continue to bound processing. Excessive-ratio fixtures are
rejected. DNS/OS stalls are not a hard real-time cancellation guarantee; worker
permits remain occupied until those calls actually return.

## Validation

Final full suite: **3,095 passed, 17 expected platform skips** in **213.22 seconds**.
The focused source-review/UI-surface gate passed **56 tests, 1 skip**. The new
skip reflects unavailable symlink-creation permission in this session.
Compilation: **374 source files, 0 failures**. Correctness lint and documentation
drift checks passed. A forced administrator-token check refused acquisition
before constructing a network client. The new UI was rendered and inspected at
normal and compact sizes with public source data; its action row remains reachable.

A real public GitHub import of `PyCQA/bandit` resolved to
`1d3053df070c91fe0fde002a21536c277d67e5d9`: **298 files**, **4,331,346 archive bytes**,
reported Apache-2.0 license, successful README preview and review-only state.
This ran in a temporary development data root. No downloaded source was executed.
Automated boundary tests use synthetic inert archives and fake HTTP responses.

## Remaining implementation

The full design is not yet implemented. This update delivers its independently
shippable source-review slice. A disposable VM execution backend, exact reviewed
executable bundles/adapters, bounded guest output channel, analysis receipts and
history integration remain outstanding. A dedicated unprivileged acquisition
process is also needed to support importing from elevated Protect sessions.

The implementation host has no Windows Sandbox executable or Hyper-V management
tools; its compute service was stopped. Real guest isolation, cancellation and
output-quota validation could not be completed. Installing the Windows feature
alone would not supply the missing backend or executable catalog. Run stays
disabled on every host until that work and the design's acceptance gates pass.

Existing Combat recovery state, live protection policy and detection provenance
are unaffected by this source-review feature. Local source-review metadata is
not a security authority against an administrator who replaces the entire store.
