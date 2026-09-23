#!/bin/sh
# Hash-locked local-user installer for Linux and macOS source releases.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OS=$(uname -s)
HEADLESS=0
AUTOSTART=1
VOICE=0
INTEL_BUILD=0

for arg in "$@"; do
    case "$arg" in
        --headless) HEADLESS=1 ;;
        --no-autostart) AUTOSTART=0 ;;
        --voice) VOICE=1 ;;
        --build-intel-crypto) INTEL_BUILD=1 ;;
        --help)
            printf '%s\n' "Usage: bash install-angerona.sh [--headless] [--no-autostart] [--voice] [--build-intel-crypto]"
            exit 0
            ;;
        *) printf 'Unknown option: %s\n' "$arg" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -eq 0 ]; then
    printf '%s\n' "Do not run the desktop suite as root. Install it as the account that will use it." >&2
    exit 1
fi

case "$OS" in
    Linux)
        case "$(uname -m)" in
            x86_64|amd64) LOCK_TARGET=linux-x86_64 ;;
            *) printf '%s\n' "No reviewed Linux wheel lock exists for this architecture." >&2; exit 1 ;;
        esac
        DATA_DIR=${ANGERONA_DATA:-${XDG_STATE_HOME:-$HOME/.local/state}/angerona}
        RUNTIME_DIR=${XDG_DATA_HOME:-$HOME/.local/share}/angerona
        ;;
    Darwin)
        case "$(uname -m)" in
            arm64|aarch64) LOCK_TARGET=macos-arm64 ;;
            x86_64|amd64)
                if [ "$INTEL_BUILD" -ne 1 ]; then
                    printf '%s\n' "Intel macOS requires the reviewed native cryptography build. Run Start-Angerona-macOS.command for guided setup, or pass --build-intel-crypto with Xcode tools, Rust and OpenSSL installed." >&2
                    exit 1
                fi
                LOCK_TARGET=macos-x86_64-base
                ;;
            *) printf '%s\n' "No reviewed macOS wheel lock exists for this architecture." >&2; exit 1 ;;
        esac
        DATA_DIR=${ANGERONA_DATA:-$HOME/Library/Application Support/Angerona}
        RUNTIME_DIR=$HOME/Library/Application Support/Angerona/runtime
        ;;
    *)
        printf 'Unsupported operating system: %s\n' "$OS" >&2
        exit 1
        ;;
esac

if [ "$HEADLESS" -eq 1 ] && [ "$OS" != Linux ]; then
    printf '%s\n' "--headless service installation is currently Linux-only." >&2
    exit 1
fi
if [ "$OS" = Darwin ]; then
    MAC_MAJOR=$(sw_vers -productVersion | cut -d. -f1)
    if [ "$MAC_MAJOR" -lt 14 ]; then
        printf '%s\n' "The reviewed GUI/YARA dependencies require macOS 14 Sonoma or newer." >&2
        exit 1
    fi
fi

if [ -z "${PYTHON:-}" ]; then
    for candidate in python3.12 /opt/homebrew/bin/python3.12 /usr/local/bin/python3.12 /Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12 python3; do
        if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(sys.version_info[:2] != (3, 12))' 2>/dev/null; then
            PYTHON=$candidate
            break
        fi
    done
fi
PYTHON=${PYTHON:-python3.12}
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    printf '%s\n' "Python 3.12 is required for the reviewed source installation." >&2
    exit 1
fi
"$PYTHON" - <<'PY'
import sys
if sys.version_info[:2] != (3, 12):
    raise SystemExit("The reviewed POSIX dependency locks require Python 3.12")
PY
if [ "$OS" = Linux ] && [ "$HEADLESS" -eq 0 ]; then
    "$PYTHON" "$ROOT/tools/check_native_gui.py" --system-libraries
fi

mkdir -p "$RUNTIME_DIR" "$DATA_DIR" "$HOME/.local/bin"
chmod 700 "$RUNTIME_DIR" "$DATA_DIR"
LOCK=$ROOT/release/locks/posix/source/$LOCK_TARGET.txt
MANIFEST=$ROOT/release/locks/posix/source/$LOCK_TARGET.manifest.json
if [ ! -f "$LOCK" ] || [ ! -f "$MANIFEST" ]; then
    printf '%s\n' "Reviewed dependency lock is missing; refusing an unhashed install." >&2
    exit 1
fi
if ! "$PYTHON" -m pip --version >/dev/null 2>&1; then
    printf '%s\n' "Python 3.12 must include pip to fetch the reviewed wheel set." >&2
    exit 1
fi

# One installer at a time; existing validated runtime generations stay intact.
INSTALL_GUARD=$RUNTIME_DIR/.install-lock
if ! mkdir "$INSTALL_GUARD" 2>/dev/null; then
    printf 'Another installer is active. If it crashed, remove the empty lock directory: %s\n' "$INSTALL_GUARD" >&2
    exit 1
fi
if ! STAGING=$(mktemp -d "$RUNTIME_DIR/install.XXXXXXXX"); then
    rmdir "$INSTALL_GUARD"
    exit 1
fi
VENV=$STAGING/venv
WHEELHOUSE=$STAGING/wheelhouse
COMMITTED=0
cleanup_install() {
    if [ "$COMMITTED" -eq 0 ]; then
        "$PYTHON" "$ROOT/tools/posix_install_support.py" cleanup --root "$ROOT" \
            --runtime "$RUNTIME_DIR" --staging "$STAGING" --data "$DATA_DIR" --system "$OS" || true
    fi
    rmdir "$INSTALL_GUARD" 2>/dev/null || true
}
trap cleanup_install EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
mkdir "$WHEELHOUSE"
printf '%s\n' '[10%] Downloading exact reviewed dependencies. Your existing runtime is preserved.'

# Downloading wheels does not execute package code. Hash mode binds each byte;
# the stdlib verifier then enforces the exact reviewed filename/size/digest set.
PIP_DISABLE_PIP_VERSION_CHECK=1 "$PYTHON" -m pip download \
    --dest "$WHEELHOUSE" --only-binary=:all: --require-hashes --no-deps \
    -r "$LOCK"
"$PYTHON" "$ROOT/tools/verify_wheelhouse.py" \
    --target "$LOCK_TARGET" --wheelhouse "$WHEELHOUSE" \
    --lock "$LOCK" --manifest "$MANIFEST"

printf '%s\n' '[40%] Dependency hashes verified. Creating a separate runtime.'
"$PYTHON" -m venv "$VENV"
PIP_DISABLE_PIP_VERSION_CHECK=1 "$VENV/bin/python" -m pip install \
    --no-index --find-links "$WHEELHOUSE" --require-hashes --no-deps \
    -r "$LOCK"
if [ "$LOCK_TARGET" = macos-x86_64-base ]; then
    printf '%s\n' '[55%] Building pinned cryptography for Intel; this can take several minutes.'
    "$VENV/bin/python" "$ROOT/tools/build_macos_intel_crypto.py" --work "$STAGING/crypto-build"
fi
printf '%s\n' '[75%] Installing Angerona into the verified runtime.'
PIP_DISABLE_PIP_VERSION_CHECK=1 "$VENV/bin/python" -m pip install \
    --no-index --find-links "$WHEELHOUSE" --no-build-isolation --no-deps \
    -e "$ROOT"
"$VENV/bin/python" -m pip check
"$PYTHON" "$ROOT/tools/posix_install_support.py" clean-wheels --root "$ROOT" \
    --runtime "$RUNTIME_DIR" --staging "$STAGING" --data "$DATA_DIR" --system "$OS"
if [ "$VOICE" -eq 1 ]; then
    printf '%s\n' "Core runtime installed. Optional voice backends are configured separately in angerona-setup; microphone access remains opt-in."
fi

LAUNCHER=$HOME/.local/bin/angerona
SETUP_LAUNCHER=$HOME/.local/bin/angerona-setup
export ANGERONA_DATA=$DATA_DIR
export ANGERONA_HOME=$ROOT
printf '%s\n' '[90%] Checking native GUI and module discovery before changing launchers.'
if [ "$HEADLESS" -eq 0 ]; then
    "$VENV/bin/python" "$ROOT/tools/check_native_gui.py"
fi
"$VENV/bin/python" -c "from angerona.core.module_manager import ModuleManager; from angerona.core.eventbus import EventBus; from angerona.core.config import Config; m=ModuleManager(EventBus(), Config.load()); m.discover(); assert not m.discovery_errors, m.discovery_errors; print(f'Angerona ready: {len(m.modules)} platform capabilities discovered')"
# This generation has passed validation. Never remove it after publishing a launcher.
COMMITTED=1
"$PYTHON" "$ROOT/tools/posix_install_support.py" publish --root "$ROOT" \
    --runtime "$RUNTIME_DIR" --staging "$STAGING" --data "$DATA_DIR" --system "$OS"

if [ "$HEADLESS" -eq 1 ]; then
    UNIT_DIR=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
    UNIT=$UNIT_DIR/angerona-headless.service
    mkdir -p "$UNIT_DIR"
    "$PYTHON" "$ROOT/tools/posix_install_support.py" service --root "$ROOT" \
        --runtime "$RUNTIME_DIR" --staging "$STAGING" --data "$DATA_DIR" --system "$OS" --unit "$UNIT"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --user daemon-reload
        systemctl --user enable --now angerona-headless.service
    else
        printf '%s\n' "systemd user services are unavailable; run 'angerona --headless' manually."
    fi
elif [ "$AUTOSTART" -eq 1 ]; then
    "$VENV/bin/python" -c "from angerona.core.autostart import enable_autostart; raise SystemExit(0 if enable_autostart() else 1)"
fi
printf '\n%s\n' "[100%] Installation complete."
if [ "$HEADLESS" -eq 1 ]; then
    printf '%s\n' "Sensor service: systemctl --user status angerona-headless"
else
    printf '%s\n' "Start Angerona: $LAUNCHER"
    printf '%s\n' "Configure every supported option: $SETUP_LAUNCHER"
fi
if [ "$OS" = Linux ] && ! command -v secret-tool >/dev/null 2>&1; then
    printf '%s\n' "Optional: install libsecret-tools to save connector/API credentials in your desktop keyring."
fi
