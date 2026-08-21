# Cycle 19 — POSIX supply-chain remediation

## C19-RT-01 — FIXED

The native POSIX release and source-install paths no longer execute an
index-delivered dependency before its bytes are bound to a reviewed target
lock. Linux x86-64 and macOS arm64 each have a committed CPython 3.12 lock plus
an exact filename/size/SHA-256 manifest for the complete 75-wheel runtime,
voice, test, audit, SBOM, build-backend, and PyInstaller closure.

### Changes

- `release/locks/posix/{linux-x86_64,macos-arm64}.txt` — one exact wheel hash per
  exact-pinned dependency; wheels only.
- `release/locks/posix/*.manifest.json` — exact filename, byte length, SHA-256,
  package, and version for every selected artifact.
- `tools/verify_wheelhouse.py` — stdlib-only fail-closed verification before any
  downloaded package is installed or imported; rejects missing, extra,
  malformed, symlinked, size-mismatched, or digest-mismatched artifacts and a
  lock/manifest mismatch.
- `tools/build_posix_release_locks.py` — offline maintainer tool that rejects an
  incomplete, ambiguous, or extra-artifact wheelhouse when refreshing locks.
- `.github/workflows/release.yml` (`build-posix`) — downloads with
  `--only-binary=:all: --require-hashes --no-deps`, verifies the manifest, then
  installs offline with `--no-index --find-links --require-hashes --no-deps`.
  The local Angerona project is installed with
  `--no-build-isolation --no-deps` after its exact-pinned backend is present.
- `install-angerona.sh` — uses the same target locks and verifier, requires
  CPython 3.12, retains the concurrent `angerona-setup` launcher, and refuses
  unsupported architectures instead of falling back to an sdist or unhashed
  install.
- `pyproject.toml` — exact-pins `setuptools==83.0.0` and `wheel==0.47.0` as the
  local build backend.
- `tests/test_release_hash_lock.py` and `tests/test_release_setup.py` — isolate
  the POSIX job and source installer so a secure Windows command cannot mask a
  POSIX regression; include an actual one-byte artifact mutation rejection.

### macOS Intel safety decision

The current safe cryptography line (`50.0.0`) does not publish a CPython macOS
Intel or universal2 wheel. The older universal2 candidate had nine known
advisories in the audit. macOS Intel was therefore removed from the native
release matrix and its source installer fails closed with an explicit message.
No vulnerable downgrade, unreviewed sdist execution, or misleading support
claim was introduced. Re-enabling Intel requires a separately reviewed,
reproducible artifact pipeline and a clean advisory gate.

### Gate evidence

- Exact manifest verification: **75/75 wheels passed** for Linux x86-64 and
  macOS arm64.
- Offline pip hash-selection proof against the Linux lock: **75/75 passed**;
  the resulting wheelhouse passed the independent manifest verifier.
- Dependency advisory scan (`pip-audit --no-deps -r
  constraints-posix-release.txt`): **0 known vulnerabilities**.
- Focused supply/release policy tests: **17 passed**.
- Supply + setup + Linux platform + documentation regression set:
  **36 passed**.
- One-byte mutation regression: **rejected before pip installation**.
- `py_compile`, Ruff, and release workflow YAML parse: **passed**.
- Native shell execution is gated by GitHub's Ubuntu 24.04 and macOS 15 arm64
  runners; this Windows host has no POSIX shell runtime.

Status: **FIXED**. The vulnerable paths were replaced or removed; there is no
unhashed or advisory-known-vulnerable POSIX release path left enabled.
