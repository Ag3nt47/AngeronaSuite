#!/bin/sh
set -eu

PURGE=0
if [ "${1:-}" = "--purge-data" ]; then
    PURGE=1
elif [ "$#" -gt 0 ]; then
    printf '%s\n' "Usage: bash uninstall-angerona.sh [--purge-data]" >&2
    exit 2
fi

OS=$(uname -s)
case "$OS" in
    Linux)
        DATA_DIR=${ANGERONA_DATA:-${XDG_STATE_HOME:-$HOME/.local/state}/angerona}
        RUNTIME_DIR=${XDG_DATA_HOME:-$HOME/.local/share}/angerona
        UNIT=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/angerona-headless.service
        if command -v systemctl >/dev/null 2>&1; then
            systemctl --user disable --now angerona-headless.service >/dev/null 2>&1 || true
        fi
        rm -f -- "$UNIT" "${XDG_CONFIG_HOME:-$HOME/.config}/autostart/angerona.desktop"
        rm -f -- "${XDG_DATA_HOME:-$HOME/.local/share}/applications/angerona.desktop"
        RELEASE_APP=${XDG_DATA_HOME:-$HOME/.local/share}/angerona/app
        ;;
    Darwin)
        DATA_DIR=${ANGERONA_DATA:-$HOME/Library/Application Support/Angerona}
        RUNTIME_DIR=$HOME/Library/Application Support/Angerona/runtime
        rm -f -- "$HOME/Library/LaunchAgents/org.angerona.security-suite.plist"
        RELEASE_APP=$HOME/Applications/Angerona.app
        ;;
    *) printf 'Unsupported operating system: %s\n' "$OS" >&2; exit 1 ;;
esac

rm -f -- "$HOME/.local/bin/angerona" "$HOME/.local/bin/angerona-setup"
case "$RELEASE_APP" in
    "$HOME"/*/angerona/app|"$HOME/Applications/Angerona.app") rm -rf -- "$RELEASE_APP" ;;
    *) printf 'Refusing unexpected release path: %s\n' "$RELEASE_APP" >&2; exit 1 ;;
esac
case "$RUNTIME_DIR" in
    "$HOME"/*/angerona|"$HOME"/*/Angerona/runtime) rm -rf -- "$RUNTIME_DIR" ;;
    *) printf 'Refusing unexpected runtime path: %s\n' "$RUNTIME_DIR" >&2; exit 1 ;;
esac

if [ "$PURGE" -eq 1 ]; then
    case "$DATA_DIR" in
        "$HOME"/*/angerona|"$HOME"/*/Angerona) rm -rf -- "$DATA_DIR" ;;
        *) printf 'Refusing unexpected data path: %s\n' "$DATA_DIR" >&2; exit 1 ;;
    esac
else
    printf 'Runtime removed. Security history retained at: %s\n' "$DATA_DIR"
fi
