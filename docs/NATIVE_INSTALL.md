# Install and launch on macOS or Linux

Keep the extracted Angerona folder in a permanent location. These source
installers install the application from that folder; moving it afterwards
requires running setup again. Run as your ordinary desktop account.

## macOS: one launcher for Intel and Apple Silicon

Open **Start-Angerona-macOS.command**. It detects your processor, guides
prerequisite setup, installs Angerona, and opens Full Setup. Future launches
offer to open the installed application or repair it. An installed launcher is
also available at `~/Applications/Angerona.command`.

If Finder says the script is not executable, open Terminal in the extracted
folder and run:

```sh
chmod u+x Start-Angerona-macOS.command
./Start-Angerona-macOS.command
```

Do not disable Gatekeeper globally. Follow macOS's normal per-file review flow
for a download you obtained from the canonical Angerona repository.

Requirements:

- macOS **14 Sonoma or newer**, required by the reviewed YARA wheel. The GUI
  dependency also requires macOS 13 or newer.
- Native **Python 3.12**, selected automatically when installed. If it is
  missing, the guide can use an existing Homebrew installation. Otherwise it
  opens Homebrew's official setup instructions and asks you to rerun afterwards.
- Apple Silicon uses reviewed, hash-locked binary wheels. A Rosetta terminal is
  relaunched as arm64, and mismatched Python architecture is rejected clearly.
- Intel additionally uses Xcode Command Line Tools, Rust and OpenSSL. The guide
  offers the required Homebrew packages and explicitly explains the native build.

Why Intel compiles one dependency: cryptography dropped upstream Intel macOS
support in version 49, and version 50 fixes a security issue. Angerona keeps
version 50 and builds it locally from a pinned source archive instead of
downgrading. The build uses pinned Maturin, the source's checksummed Cargo lock,
an isolated dependency cache, two compiler workers, and an offline compilation
step. Its resulting wheel digest and compiler/OpenSSL information are saved in
`crypto-build-receipt.json` next to that runtime generation. This is a local
source build, not an upstream prebuilt or notarized universal application.
The local Xcode/Rust/OpenSSL toolchain is part of the build's trust boundary.

Advanced Intel installation after prerequisites are present:

```sh
export OPENSSL_DIR="$(brew --prefix openssl@3)"
sh install-angerona.sh --build-intel-crypto --no-autostart
```

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
