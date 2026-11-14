#!/bin/sh
# Native terminal/dialog front end; no downloaded shell code is executed.
set -eu
EXPECTED=${1:-}
shift
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "${1:-}" = --help ]; then
    printf '%s\n' 'Angerona guided setup and quick launch.' \
        'Launch this file as your normal desktop user. It detects prerequisites and guides installation.' \
        'Advanced unattended options: sh install-angerona.sh --help' \
        'macOS: Intel and Apple Silicon; macOS 14+ and native Python 3.12.' \
        'Intel macOS 13 additionally offers a clearly labeled unsupported developer/Observe build.' \
        'Linux: x86_64 with Python 3.12 and glibc-compatible reviewed wheels.'
    exit 0
fi
OS=$(uname -s)
[ "$OS" = "$EXPECTED" ] || { printf 'This launcher requires %s.\n' "$EXPECTED" >&2; exit 1; }
if [ "$(id -u)" -eq 0 ]; then
    printf '%s\n' 'Run this launcher as your normal desktop account; it requests package-manager elevation only when needed.' >&2
    exit 1
fi
ask() {
    if [ "$OS" = Darwin ]; then
        /usr/bin/osascript - "$1" <<'APPLESCRIPT' >/dev/null 2>&1
on run argv
    display dialog (item 1 of argv) with title "Angerona setup" buttons {"Cancel", "Continue"} default button "Continue" cancel button "Cancel"
end run
APPLESCRIPT
    else
        printf '\n%s [y/N] ' "$1"
        read -r answer
        case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
    fi
}
open_guide() {
    printf '\nSetup guide: %s\n' "$1"
    if [ "$OS" = Darwin ]; then
        /usr/bin/open "$1"
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$1" >/dev/null 2>&1 || true
    fi
}
find_brew() {
    BREW=
    for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
        if [ -x "$candidate" ]; then
            BREW=$candidate
            PATH=$(dirname "$BREW"):$PATH
            export PATH
            return 0
        fi
    done
    return 1
}
wait_for_macos_prerequisite() {
    kind=$1
    description=$2
    while true; do
        case "$kind" in
            command-line-tools) xcode-select -p >/dev/null 2>&1 && return 0 ;;
            homebrew) { [ -x /opt/homebrew/bin/brew ] || [ -x /usr/local/bin/brew ]; } && return 0 ;;
            *) printf 'Unknown prerequisite: %s\n' "$kind" >&2; return 1 ;;
        esac
        ask "Finish installing $description, then choose Continue to resume this same Angerona setup." || return 1
    done
}
find_python() {
    for candidate in "${PYTHON:-python3.12}" /opt/homebrew/bin/python3.12 /usr/local/bin/python3.12 /Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12 python3; do
        if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(sys.version_info[:2] != (3, 12))' 2>/dev/null; then
            PYTHON=$candidate
            export PYTHON
            return 0
        fi
    done
    return 1
}
find_intel_prerequisites() {
    command -v cargo >/dev/null 2>&1 || return 1
    command -v rustc >/dev/null 2>&1 || return 1
    for candidate in "${OPENSSL_DIR:-}" /usr/local/opt/openssl@3 /opt/homebrew/opt/openssl@3; do
        if [ -n "$candidate" ] && [ -f "$candidate/include/openssl/ssl.h" ] && \
                [ -f "$candidate/lib/libcrypto.a" ]; then
            OPENSSL_DIR=$candidate
            export OPENSSL_DIR
            return 0
        fi
    done
    return 1
}

printf '\n%s\n' 'Angerona — guided setup and launch' '[0%] Checking this machine.'
LAUNCHER=$HOME/.local/bin/angerona
if [ -x "$LAUNCHER" ]; then
    if ask 'Launch the installed Angerona? Cancel/No continues to repair or reinstall.'; then
        exec "$LAUNCHER"
    fi
fi
ask 'Install or repair Angerona for this account? Existing security history and validated runtimes are retained.' || exit 0
ARCH=$(uname -m)
INTEL_BUILD=0
UNSUPPORTED_MACOS_DEV=0
if [ "$OS" = Darwin ]; then
    MAC_MAJOR=$(sw_vers -productVersion | cut -d. -f1)
    if [ "$MAC_MAJOR" -lt 14 ]; then
        if [ "$MAC_MAJOR" -eq 13 ] && [ "$ARCH" = x86_64 ]; then
            printf '%s\n' \
                'This Intel Mac cannot use the reviewed macOS 14+ wheel set.' \
                'Angerona can instead build the incompatible components from pinned source for Ventura.' \
                'This remains an unsupported developer/Observe build and cannot claim Protect authority.' >&2
            if ask 'Continue with the unsupported Intel Ventura developer build and retain every compatible protection component?'; then
                UNSUPPORTED_MACOS_DEV=1
            else
                printf '%s\n' 'Angerona did not install or change this Mac.' >&2
                exit 0
            fi
        else
            printf '%s\n' 'macOS 14 Sonoma or newer is required by the reviewed dependencies. Angerona did not install or change this Mac.' >&2
            if ask 'This Mac needs macOS 14 Sonoma or newer for the reviewed Angerona runtime. Open Apple Software Update now?'; then
                /usr/bin/open 'x-apple.systempreferences:com.apple.Software-Update-Settings.extension'
            fi
            exit 1
        fi
    fi
    # A Rosetta terminal on Apple Silicon must use native arm64 Python/wheels.
    if [ "$ARCH" = x86_64 ] && [ "$(sysctl -in sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
        exec /usr/bin/arch -arm64 /bin/sh "$ROOT/tools/native-quickstart.sh" Darwin
    fi
    case "$ARCH" in
        x86_64) INTEL_BUILD=1 ;;
        arm64) ;;
        *) printf 'Unsupported Mac architecture: %s\n' "$ARCH" >&2; exit 1 ;;
    esac
    # Intel's reviewed cryptography build needs Apple's compiler tools. Keep
    # this launcher alive while the normal Apple installer runs so setup can
    # resume without making the user find and open the source folder again.
    if [ "$INTEL_BUILD" -eq 1 ] && ! xcode-select -p >/dev/null 2>&1; then
        xcode-select --install >/dev/null 2>&1 || true
        wait_for_macos_prerequisite command-line-tools 'Apple Command Line Tools' || exit 0
    fi
    find_brew || true
    PYTHON_READY=0
    find_python && PYTHON_READY=1
    INTEL_READY=1
    if [ "$INTEL_BUILD" -eq 1 ] && ! find_intel_prerequisites; then
        INTEL_READY=0
    fi
    if [ "$PYTHON_READY" -ne 1 ] || [ "$INTEL_READY" -ne 1 ]; then
        if [ -z "$BREW" ]; then
            printf '%s\n' 'Homebrew is needed for the reviewed native prerequisites. No remote installer is run automatically.'
            open_guide https://docs.brew.sh/Installation
            wait_for_macos_prerequisite homebrew 'Homebrew from its official guide' || exit 0
            find_brew || { printf '%s\n' 'Homebrew is still unavailable; no Angerona files were installed.' >&2; exit 1; }
        fi
        if [ "$INTEL_BUILD" -eq 1 ]; then
            ask 'Intel needs a native cryptography build. Install Python 3.12, Rust and OpenSSL with Homebrew, then build the pinned source? Compilation may take several minutes.' || exit 0
            "$BREW" install python@3.12 rust openssl@3
            OPENSSL_DIR=$("$BREW" --prefix openssl@3)
            export OPENSSL_DIR
        else
            ask 'Install Python 3.12 using your installed Homebrew package manager?' || exit 0
            "$BREW" install python@3.12
        fi
    fi
else
    case "$ARCH" in x86_64|amd64) ;; *) printf 'No reviewed Linux dependency lock for %s yet.\n' "$ARCH" >&2; exit 1 ;; esac
    if ! find_python; then
        if command -v apt-get >/dev/null 2>&1; then
            ask 'Install Python 3.12 and venv using apt? Ubuntu 24.04 provides these packages; your administrator password may be requested.' || exit 0
            sudo apt-get update
            sudo apt-get install python3.12 python3.12-venv python3-pip
        elif command -v dnf >/dev/null 2>&1; then
            ask 'Install Python 3.12 and pip using dnf? Your administrator password may be requested.' || exit 0
            sudo dnf install python3.12 python3.12-pip
        else
            printf '%s\n' 'Install Python 3.12 with venv/pip using your distribution package manager, then run this launcher again.'
            exit 1
        fi
    fi
fi
find_python || { printf '%s\n' 'Python 3.12 is still unavailable. See docs/NATIVE_INSTALL.md.' >&2; exit 1; }
if [ "$OS" = Linux ] && ! "$PYTHON" "$ROOT/tools/check_native_gui.py" --system-libraries; then
    ask 'Install the missing Qt/XCB desktop libraries with your system package manager? Your administrator password may be requested.' || exit 0
    "$PYTHON" "$ROOT/tools/check_native_gui.py" --install-system-libraries
fi
if [ "$OS" = Darwin ]; then
    PY_ARCH=$("$PYTHON" -c 'import platform; print(platform.machine())')
    [ "$PY_ARCH" = "$ARCH" ] || { printf '%s\n' 'Python must match the native Mac architecture. Use native Homebrew Python 3.12.' >&2; exit 1; }
fi
if [ "$INTEL_BUILD" -eq 1 ]; then
    if [ "$UNSUPPORTED_MACOS_DEV" -eq 1 ]; then
        /bin/sh "$ROOT/install-angerona.sh" --build-intel-crypto \
            --unsupported-macos-dev --no-autostart
    else
        /bin/sh "$ROOT/install-angerona.sh" --build-intel-crypto --no-autostart
    fi
else
    /bin/sh "$ROOT/install-angerona.sh" --no-autostart
fi
printf '%s\n' 'Setup completed. Startup-at-login and optional integrations are available in Full Setup.'
exec "$HOME/.local/bin/angerona-setup"
