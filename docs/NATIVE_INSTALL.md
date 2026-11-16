# Install and launch on macOS or Linux

Keep the extracted Angerona folder in a permanent location. These source
installers install the application from that folder; moving it afterwards
requires running setup again. Run as your ordinary desktop account.

## macOS: one launcher for Intel and Apple Silicon

Open **Start-Angerona-macOS.command**. It detects your processor, guides
prerequisite setup, installs Angerona, and opens Full Setup. Future launches
offer to open the installed application or repair it. An installed launcher is
also available at `~/Applications/Angerona.command`.

The same launcher stays open while Apple Command Line Tools or Homebrew are
installed, then resumes its checks when you choose **Continue**. On an older
Mac it can open Apple Software Update directly. The supported wheel path requires
that upgrade to finish before installation; the separately labeled Intel Ventura
development exception is described below. Angerona never accepts an unreviewed
runtime or disables Gatekeeper to bypass a prerequisite.

### Intel macOS 13 Ventura unsupported development path

On an Intel Mac running Ventura, the same launcher detects the host version and
offers an explicit compensating source-build path. Accepting the prompt derives
a temporary hash lock from the reviewed Intel lock, omits only the incompatible
macOS 14 YARA-X wheel, and builds the same pinned YARA-X 1.19.0 version from its
exact source commit for macOS 13. It also builds pinned cryptography 50 for the
same deployment target. Both native builds validate checksummed Cargo locks,
fetch dependencies before switching Cargo offline, install through generated
SHA-256 locks, and run inert cryptographic and YARA compile/scan smoke tests.

The launcher first reuses compatible Python, Rust and static OpenSSL components
already present on the host. If they are missing, it prompts for the fixed
Homebrew prerequisites and then resumes. The resulting launchers always export
`ANGERONA_UNSUPPORTED_MACOS_DEV=1` and display an unsupported developer/Observe
warning. This path offers every compatible source-mode protection it can load;
it is not a reviewed/notarized package, does not bypass macOS security controls,
and cannot create or claim installed Protect authority.

For a scripted Ventura development install after prerequisites are present:

```sh
export OPENSSL_DIR="/path/to/static/openssl"
sh install-angerona.sh --build-intel-crypto --unsupported-macos-dev --no-autostart
```

If Finder says the script is not executable, open Terminal in the extracted
folder and run:

```sh
chmod u+x Start-Angerona-macOS.command
./Start-Angerona-macOS.command
```

Do not disable Gatekeeper globally. Follow macOS's normal per-file review flow
for a download you obtained from the canonical Angerona repository.

Requirements:

- macOS **14 Sonoma or newer** for the reviewed wheel path. The GUI dependency
  supports macOS 13; Intel Ventura is available only through the explicit
  unsupported compensating source-build path described above.
- Native **Python 3.12**, selected automatically when installed. If it is
  missing, the guide can use an existing Homebrew installation. Otherwise it
  opens Homebrew's official setup instructions and asks you to rerun afterwards.
- Apple Silicon uses reviewed, hash-locked binary wheels. A Rosetta terminal is
  relaunched as arm64, and mismatched Python architecture is rejected clearly.
- Intel additionally uses Xcode Command Line Tools, Rust and OpenSSL. The guide
  offers the required Homebrew packages and explicitly explains the native build.

Why supported Intel compiles one dependency: cryptography dropped upstream Intel macOS
support in version 49, and version 50 fixes a security issue. Angerona keeps
version 50 and builds it locally from a pinned source archive instead of
downgrading. The build uses pinned Maturin, the source's checksummed Cargo lock,
an isolated dependency cache, two compiler workers, and an offline compilation
step. Its resulting wheel digest and compiler/OpenSSL information are saved in
`crypto-build-receipt.json` next to that runtime generation. This is a local
source build, not an upstream prebuilt or notarized universal application.
The local Xcode/Rust/OpenSSL toolchain is part of the build's trust boundary.
The unsupported Ventura path additionally compiles pinned YARA-X because its
upstream 1.19.0 Intel wheel declares macOS 14 as its minimum target. Separate
`crypto-build-receipt.json` and `yara-build-receipt.json` files record source,
wheel, deployment-target and toolchain evidence beside that runtime generation.

Advanced Intel installation after prerequisites are present:

```sh
export OPENSSL_DIR="$(brew --prefix openssl@3)"
sh install-angerona.sh --build-intel-crypto --no-autostart
```

## Optional macOS support pack

After installation (and on later launches, until you answer), the macOS
launcher offers an optional support pack from
[Ag3nt47/Angerona-macOS-Support](https://github.com/Ag3nt47/Angerona-macOS-Support).
Choosing **Cancel** skips it and is remembered; Angerona is unaffected.

The pack adds seven macOS-specific observe/detect modules (persistence,
security posture, unified-log authentication failures, kernel and system
extensions, authorization plug-ins/PAM/sudoers, code-signature trust and local
snapshot loss) and Mac versions of the Windows maintenance scripts. It does not
change Angerona's own source and never requests administrator rights.

Each file is downloaded from the commit pinned in
`release/macos-support-pack.json` and must match its reviewed SHA-256 before
anything is written. The modules are **unsigned**: at each start Angerona
re-verifies the module folder, and only when it matches the pin exactly does it
enable the unsigned-development override, printing a reduced-security notice.
That override also permits in-app source editing. A changed module or any other
drop-in keeps the override off.

```sh
python3.12 tools/macos_support_pack.py status
python3.12 tools/macos_support_pack.py install
python3.12 tools/macos_support_pack.py disable     # keep files, start normally
python3.12 tools/macos_support_pack.py uninstall
```

Scripts are installed in
`~/Library/Application Support/Angerona/macos-support/current/scripts/`.

## Linux

Run **Start-Angerona-Linux.sh** in a terminal, or choose your file manager's
**Run in Terminal** action. If necessary:

```sh
chmod u+x Start-Angerona-Linux.sh
./Start-Angerona-Linux.sh
```

The reviewed source installation currently targets **x86_64 Linux with Python
3.12 and compatible glibc wheels**. Ubuntu 24.04 is the native CI target. The
guide can request Python/venv packages through `apt` or `dnf`; package
availability depends on your distribution. It never adds an unreviewed package
repository or executes a downloaded shell script. Other architectures and
musl-only distributions are not covered by this wheel lock.

After installation, launch **Angerona Security Suite** from the applications
menu, or run `~/.local/bin/angerona`. Full Setup is available as
`~/.local/bin/angerona-setup` and in the application menu's secondary action.

The launcher checks Qt's native graphics, font and XCB libraries before
downloading Python packages. If libraries are missing, it offers a fixed
`apt` or `dnf` package installation and asks for your administrator password
through the system package manager. The reviewed apt package list targets
Ubuntu 24.04; older distributions may use `libglib2.0-0` instead of
`libglib2.0-0t64`. Other package managers receive a list of the missing library
names and guidance to install their distribution's corresponding packages.

To check or repair these prerequisites manually:

```sh
python3.12 tools/check_native_gui.py --system-libraries
python3.12 tools/check_native_gui.py --install-system-libraries
```

Before publishing a new desktop launcher, setup loads the installed Qt XCB
plugin and renders a small widget with an offscreen `QApplication` in a bounded
child process. This catches missing native libraries and Qt startup failures
without starting Angerona's sensors. It verifies widget rendering and plugin
dependencies; a working X11/Wayland desktop session is still required for the
visible application. Linux headless service installation skips desktop checks.

For the optional current-user Linux sensor service:

```sh
sh install-angerona.sh --headless
systemctl --user status angerona-headless
```

## Progress, repairs, and retained data

The installer displays stage percentages for download, verification, runtime
creation, installation and validation. They describe completed setup stages,
not estimated download time or security coverage. No modules start during the
validation probe. Guided desktop setup leaves startup-at-login to Full Setup.

An update builds a separate runtime and checks dependency consistency and
module discovery before changing launchers. Download, build or validation
failures preserve the previous runtime and launcher. Temporary downloads and
successful native-build caches are removed. Previous validated runtime
generations are retained for recovery; they are removed by the uninstaller.

Source setup uses a minimal reviewed runtime lock in
`release/locks/posix/source/`. Release-building, auditing and test tools are not
installed into the desktop runtime. Optional voice packages are configured
separately; `--voice` does not grant microphone access or silently download an
unreviewed speech stack.

Only one installer runs at a time. If it is forcibly killed, the next run may
report an existing `.install-lock` directory. Close other installers, then
remove only the empty lock directory shown in the error.

To uninstall the runtime while retaining security history:

```sh
sh uninstall-angerona.sh
```

`--purge-data` additionally removes the installation's data directory. Review
that option before using it.

## Validation status and primary references

The repository includes a native installer CI matrix for Linux, Apple Silicon
macOS and Intel macOS, including actual offscreen QApplication rendering.
Windows-based local review verifies locked metadata, shell syntax, path
quoting, extraction limits, failure behavior and the probe's Windows rendering;
it cannot prove Linux/macOS native GUI operation or Intel compilation. Check
the native CI result for the revision you download.

- [Cryptography installation and native build prerequisites](https://cryptography.io/en/latest/installation/)
- [Cryptography 49/50 platform and security changes](https://cryptography.io/en/latest/changelog/)
- [Pinned cryptography 50 source release metadata](https://pypi.org/pypi/cryptography/50.0.0/json)
- [Homebrew installation](https://docs.brew.sh/Installation)
- [GitHub native runner architectures](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [Qt Linux/XCB native requirements](https://doc.qt.io/qt-6/linux-requirements.html)
