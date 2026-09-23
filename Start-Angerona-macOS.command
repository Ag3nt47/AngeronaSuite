#!/bin/zsh
# Finder/Terminal launcher; supports both Intel and Apple Silicon Macs.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
/bin/sh "$ROOT/tools/native-quickstart.sh" Darwin "$@"
result=$?
if [ "$result" -ne 0 ]; then
    printf '\nSetup stopped with status %s. The explanation is above. Press Return to close.\n' "$result"
    read -r reply
fi
exit "$result"
