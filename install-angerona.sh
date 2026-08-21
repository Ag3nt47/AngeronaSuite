#!/bin/sh
# Hash-locked local-user installer for Linux and macOS source releases.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OS=$(uname -s)
HEADLESS=0
AUTOSTART=1
VOICE=0

for arg in "$@"; do
    case "$arg" in
        --headless) HEADLESS=1 ;;
        --no-autostart) AUTOSTART=0 ;;
        --voice) VOICE=1 ;;
        --help)
            printf '%s\n' "Usage: bash install-angerona.sh [--headless] [--no-autostart] [--voice]"
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
                printf '%s\n' "Intel macOS is not available: a current cryptography wheel is not published for CPython Intel. Refusing an sdist build." >&2
                exit 1
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

PYTHON=${PYTHON:-python3}
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    printf '%s\n' "Python 3.12 is required for the reviewed source installation." >&2
    exit 1
fi
"$PYTHON" - <<'PY'
import sys
if sys.version_info[:2] != (3, 12):
    raise SystemExit("The reviewed POSIX dependency locks require Python 3.12")
PY

VENV=$RUNTIME_DIR/venv
mkdir -p "$RUNTIME_DIR" "$DATA_DIR" "$HOME/.local/bin"
chmod 700 "$RUNTIME_DIR" "$DATA_DIR"
LOCK=$ROOT/release/locks/posix/$LOCK_TARGET.txt
MANIFEST=$ROOT/release/locks/posix/$LOCK_TARGET.manifest.json
if [ ! -f "$LOCK" ] || [ ! -f "$MANIFEST" ]; then
    printf '%s\n' "Reviewed dependency lock is missing; refusing an unhashed install." >&2
    exit 1
fi
if ! "$PYTHON" -m pip --version >/dev/null 2>&1; then
    printf '%s\n' "Python 3.12 must include pip to fetch the reviewed wheel set." >&2
    exit 1
fi

WHEELHOUSE=$(mktemp -d "$RUNTIME_DIR/wheelhouse.XXXXXX")
cleanup_wheelhouse() {
    rm -rf -- "$WHEELHOUSE"
}
trap cleanup_wheelhouse EXIT HUP INT TERM

# Downloading wheels does not execute package code. Hash mode binds each byte;
# the stdlib verifier then enforces the exact reviewed filename/size/digest set.
PIP_DISABLE_PIP_VERSION_CHECK=1 "$PYTHON" -m pip download \
    --dest "$WHEELHOUSE" --only-binary=:all: --require-hashes --no-deps \
    -r "$LOCK"
"$PYTHON" "$ROOT/tools/verify_wheelhouse.py" \
    --target "$LOCK_TARGET" --wheelhouse "$WHEELHOUSE" \
    --lock "$LOCK" --manifest "$MANIFEST"

"$PYTHON" -m venv --clear "$VENV"
PIP_DISABLE_PIP_VERSION_CHECK=1 "$VENV/bin/python" -m pip install \
    --no-index --find-links "$WHEELHOUSE" --require-hashes --no-deps \
    -r "$LOCK"
PIP_DISABLE_PIP_VERSION_CHECK=1 "$VENV/bin/python" -m pip install \
    --no-index --find-links "$WHEELHOUSE" --no-build-isolation --no-deps \
    -e "$ROOT"
"$VENV/bin/python" -m pip check
if [ "$VOICE" -eq 1 ]; then
    printf '%s\n' "Conversational dependencies are installed; finish microphone setup in angerona-setup."
fi

LAUNCHER=$HOME/.local/bin/angerona
printf '#!/bin/sh\nexec "%s" -m angerona "$@"\n' "$VENV/bin/python" > "$LAUNCHER"
chmod 700 "$LAUNCHER"
SETUP_LAUNCHER=$HOME/.local/bin/angerona-setup
printf '#!/bin/sh\nexec "%s" -m angerona --setup "$@"\n' "$VENV/bin/python" > "$SETUP_LAUNCHER"
chmod 700 "$SETUP_LAUNCHER"

export ANGERONA_DATA=$DATA_DIR
export ANGERONA_HOME=$ROOT
if [ "$HEADLESS" -eq 1 ]; then
    if [ "$OS" != Linux ]; then
        printf '%s\n' "--headless service installation is currently Linux-only." >&2
        exit 1
    fi
    UNIT_DIR=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
    UNIT=$UNIT_DIR/angerona-headless.service
    mkdir -p "$UNIT_DIR"
    ROOT=$ROOT VENV=$VENV DATA_DIR=$DATA_DIR UNIT=$UNIT "$VENV/bin/python" - <<'PY'
import os
from pathlib import Path

root = Path(os.environ["ROOT"])
template = (root / "installer/linux/angerona-headless.service").read_text(encoding="utf-8")
values = {
    "@PYTHON@": str(Path(os.environ["VENV"]) / "bin/python"),
    "@WORKDIR@": str(root),
    "@DATA_DIR@": os.environ["DATA_DIR"],
}
for token, value in values.items():
    if not value or any(char in value for char in "\r\n\x00"):
        raise SystemExit(f"unsafe service value for {token}")
    template = template.replace(token, value)
unit = Path(os.environ["UNIT"])
unit.write_text(template, encoding="utf-8")
unit.chmod(0o600)
PY
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --user daemon-reload
        systemctl --user enable --now angerona-headless.service
    else
        printf '%s\n' "systemd user services are unavailable; run 'angerona --headless' manually."
    fi
elif [ "$AUTOSTART" -eq 1 ]; then
    "$VENV/bin/python" -c "from angerona.core.autostart import enable_autostart; raise SystemExit(0 if enable_autostart() else 1)"
fi

"$VENV/bin/python" -c "from angerona.core.module_manager import ModuleManager; from angerona.core.eventbus import EventBus; from angerona.core.config import Config; m=ModuleManager(EventBus(), Config.load()); m.discover(); assert not m.discovery_errors, m.discovery_errors; print(f'Angerona ready: {len(m.modules)} platform capabilities discovered')"

printf '\n%s\n' "Installation complete."
if [ "$HEADLESS" -eq 1 ]; then
    printf '%s\n' "Sensor service: systemctl --user status angerona-headless"
else
    printf '%s\n' "Start Angerona: $LAUNCHER"
    printf '%s\n' "Configure every supported option: $SETUP_LAUNCHER"
fi
if [ "$OS" = Linux ] && ! command -v secret-tool >/dev/null 2>&1; then
    printf '%s\n' "Optional: install libsecret-tools to save connector/API credentials in your desktop keyring."
fi
