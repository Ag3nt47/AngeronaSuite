# Native installer review — 2026-09-23

## Defects and changes

1. Source installation assumed `python3` meant 3.12. Both native launchers now
   discover the matching interpreter and guide prerequisite installation.
2. Intel macOS was rejected unconditionally. The Mac `.command` now detects
   Apple Silicon, Intel, and Rosetta. Intel has an explicit local cryptography
   50 build using a pinned sdist and Maturin wheel, source-authenticated
   Cargo.lock/checksums, isolated Cargo cache, offline compilation, two workers,
   static OpenSSL linkage, wheel hash, AES-GCM smoke check, and build receipt.
   Apple/Xcode, Rust and OpenSSL remain installed native toolchain prerequisites.
3. `venv --clear` destroyed the working installation before dependencies were
   validated. The source installer now builds a new private generation and
   checks `pip check` and module discovery before publishing entry points.
   Download/build/validation failures preserve the previous generation.
4. Generated shell launchers interpolated paths inside double quotes, allowing
   `$()`/backticks in valid filesystem names to execute. Shell arguments now
   use `shlex.quote`; desktop-entry and systemd values use their own escaping,
   including literal percent and dollar handling. Control characters are refused.
5. The service could start before the final discovery check, and unsupported
   macOS headless setup was rejected only after installing packages. Both
   checks now occur before the relevant side effect.
6. Full release-tool locks were incorrectly reused for desktop source installs.
   Metadata review found missing Darwin `pyobjc` (pyttsx3), `macholib`
   (PyInstaller), and Python <3.13 `typing-extensions` (audit dependencies).
   Separate source-runtime locks now contain 23 reviewed packages (22 on Intel,
   with cryptography supplied by the explicit build). All source dependency
   graphs close under Python3.12 and target platform markers. Optional voice
   remains separate and is no longer incorrectly reported as installed.
7. Stage progress is visible. Download/native-build caches are removed after
   success; old validated runtimes remain available for recovery. A per-runtime
   installer lock prevents simultaneous installs. No arbitrary downloaded shell
   script or model-generated command is executed.

## Artifacts

- `Start-Angerona-macOS.command`: native Zsh/Finder entry point and macOS dialogs.
- `Start-Angerona-Linux.sh`: native Bash/terminal entry point.
- `tools/native-quickstart.sh`: guided prerequisites and setup/launch selection.
- `tools/posix_install_support.py`: safe launcher/service publication and cleanup.
- `tools/build_macos_intel_crypto.py`: pinned native Intel dependency build.
- `release/locks/posix/source/`: separate reviewed source-runtime wheel locks.
- `docs/NATIVE_INSTALL.md`: supported OS/CPU matrix, setup and recovery steps.
- CI `native-source-install`: Ubuntu 24.04, macOS 15 arm64, macOS 15 Intel, including
  real native build/install and entry-point validation. No release job authority
  or signing policy was broadened.

## Validation and limits

Local Windows review: **51 passed, 1 skipped** across focused installer, release
setup/hash lock, and workflow policy tests; Python compilation; Bash syntax
checks of all four native scripts;
real cryptography source hash and bounded extraction/Cargo lock verification;
official PyPI dependency metadata closure for all three source target locks.
The POSIX subprocess failure fixture is skipped on Windows and runs in native
test lanes. Full native GUI behavior and Intel compilation still require their
actual OS CI runners; no claim of local native execution is made.

The reviewed YARA wheel requires macOS 14+, so "universal" means one processor-
detecting launcher with Intel and Apple Silicon install paths, not every macOS
version or a notarized universal binary. Linux ARM/musl are outside current
locks. First-time Homebrew installation opens the official instructions; it is
not silently bootstrapped. Native compiler/package-manager versions are local
prerequisites, not reproducible-binary claims.

The existing *full release-build* POSIX locks still have the metadata omissions
listed above. The new source-install CI does not consume them. Repairing full
release packaging, including the complete optional speech framework graph, is
a separate remaining packaging issue; ordinary source installs now avoid it.

## Primary evidence

- [Cryptography changelog](https://cryptography.io/en/latest/changelog/): Intel
  wheel support removed in 49; version 50 fixes CVE-2026-69247. A downgrade is inappropriate.
- [Native cryptography build instructions](https://cryptography.io/en/latest/installation/):
  Xcode/Rust/OpenSSL prerequisites and static linkage.
- [Exact source metadata](https://pypi.org/pypi/cryptography/50.0.0/json):
  source 880201 bytes, SHA256
  `eeac2acb5a20ed25e0ad6d1df9891a520b78b404266b6d11778f25d5d691a6c9`.
- [Maturin 1.14.1 metadata](https://pypi.org/pypi/maturin/1.14.1/json):
  universal macOS wheel SHA256
  `ffe5ad71f21d1e6603c4dd75f7fee34adf5ed5ebcebb692886549888ebb329ed`.
- [Native GitHub runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

Executable permission bits must be retained for `.command`/`.sh` files in the
reviewed Git commit; `.gitattributes` now enforces LF checkout for both types.

## Round 2: native GUI readiness

Added `tools/check_native_gui.py`. Linux setup now detects 24 required native
Qt/graphics/font/XCB library sonames before dependency downloads and offers
fixed apt/dnf package lists through the normal package-manager elevation flow.
Readiness checks never install packages without an explicit installation
request. Ubuntu 24.04 is the reviewed apt target; other distributions receive
the exact missing library names and actionable manual guidance.

Desktop installation now runs an isolated child process with
`QT_QPA_PLATFORM=offscreen`, instantiates a real `QApplication`, renders a label
to a nonempty pixmap, and checks dimensions. On Linux it also loads the actual
installed `libqxcb.so` plugin to catch missing dependencies that an offscreen
plugin alone would overlook. The probe has a 40-second timeout and disables
core dumps; crashes/timeouts fail installation before launchers are changed.
It does not launch sensors or require a visible display. A real user desktop
session remains necessary for visible GUI operation.

Native CI now explicitly installs Linux Qt prerequisites and runs the source
installer's real QApplication rendering gate. Local Windows execution of the
same rendering probe passed. Added tests cover missing libraries, fixed
package arguments, read-only checks, isolated/bounded subprocess configuration,
aborted Qt startup and installer publication ordering.

Round 2 validation: **58 passed, 1 skipped** across the focused native installer,
release setup/hash-lock and workflow tests. Shell syntax, Python compilation,
workflow policy and the real Windows offscreen rendering probe passed.

Full release lock assessment: PyObjC 12.2.2 publishes 324 conditional dependency
entries; its active framework graph has 153 entries on Darwin 23, 156 on Darwin 24,
and 161 on Darwin 25. Completing those full release locks requires separately
reviewed Darwin-version/platform dependency sets rather than blindly appending
one universal package to both Linux and macOS locks. `macholib==1.16.4` and
`typing_extensions==4.16.0` are currently available individual missing pins,
but adding only those does not repair the full macOS release graph. This broad
optional-speech/release-tooling packaging change was not applied to source
runtime locks, which already have a complete reviewed dependency graph.

References: [Qt Linux requirements](https://doc.qt.io/qt-6/linux-requirements.html),
[PyObjC 12.2.2 metadata](https://pypi.org/pypi/pyobjc/12.2.2/json).
