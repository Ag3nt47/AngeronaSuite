#!/bin/sh
# Install a verified Linux/macOS binary release for the current user.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OS=$(uname -s)
LAUNCH=1
if [ "${1:-}" = "--no-launch" ]; then
    LAUNCH=0
elif [ "$#" -gt 0 ]; then
    printf '%s\n' "Usage: bash Install-Angerona-Release.sh [--no-launch]" >&2
    exit 2
fi

if [ "$(id -u)" -eq 0 ]; then
    printf '%s\n' "Install Angerona as the local account that will use it, not root." >&2
    exit 1
fi

case "$OS" in
    Linux)
        SOURCE=$ROOT/Angerona
        INSTALL_ROOT=${XDG_DATA_HOME:-$HOME/.local/share}/angerona/app
        DEST=$INSTALL_ROOT/Angerona
        [ -f "$SOURCE" ] || { printf 'Missing release binary: %s\n' "$SOURCE" >&2; exit 1; }
        mkdir -p "$INSTALL_ROOT" "$HOME/.local/bin" "${XDG_DATA_HOME:-$HOME/.local/share}/applications"
        chmod 700 "$INSTALL_ROOT"
        install -m 0755 "$SOURCE" "$DEST"
        printf '#!/bin/sh\nexec "%s" "$@"\n' "$DEST" > "$HOME/.local/bin/angerona"
        chmod 700 "$HOME/.local/bin/angerona"
        printf '#!/bin/sh\nexec "%s" --setup "$@"\n' "$DEST" > "$HOME/.local/bin/angerona-setup"
        chmod 700 "$HOME/.local/bin/angerona-setup"
        DESKTOP=${XDG_DATA_HOME:-$HOME/.local/share}/applications/angerona.desktop
        {
            printf '%s\n' '[Desktop Entry]' 'Type=Application' 'Version=1.0'
            printf '%s\n' 'Name=Angerona Security Suite' 'Comment=Local-first endpoint security'
            printf 'Exec=%s\n' "$DEST"
            printf '%s\n' 'Terminal=false' 'Categories=System;Security;' 'StartupNotify=true' 'Actions=Setup;'
            printf '%s\n' '' '[Desktop Action Setup]' 'Name=Full Setup'
            printf 'Exec=%s --setup\n' "$DEST"
        } > "$DESKTOP"
        chmod 600 "$DESKTOP"
        printf 'Angerona installed at %s\n' "$DEST"
        if [ "$LAUNCH" -eq 1 ]; then
            nohup "$DEST" --setup >/dev/null 2>&1 &
        fi
        ;;
    Darwin)
        SOURCE=$ROOT/Angerona.app
        DEST=$HOME/Applications/Angerona.app
        [ -d "$SOURCE" ] || { printf 'Missing release application: %s\n' "$SOURCE" >&2; exit 1; }
        mkdir -p "$HOME/Applications"
        if [ -e "$DEST" ] && [ ! -d "$DEST" ]; then
            printf 'Refusing unexpected application path: %s\n' "$DEST" >&2
            exit 1
        fi
        rm -rf -- "$DEST"
        ditto "$SOURCE" "$DEST"
        printf 'Angerona installed at %s\n' "$DEST"
        if [ "$LAUNCH" -eq 1 ]; then
            open "$DEST" --args --setup
        fi
        ;;
    *) printf 'Unsupported operating system: %s\n' "$OS" >&2; exit 1 ;;
esac
