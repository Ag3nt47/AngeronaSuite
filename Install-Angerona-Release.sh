#!/bin/sh
# POSIX binary installation is held until archive-to-payload verification exists.
set -eu

if [ "$#" -eq 1 ]; then
    case "$1" in
        --help|-h)
            printf '%s\n' \
                'Angerona Linux/macOS binary installation is currently unavailable.' \
                'The official outer archive must be authenticated and its installed payload bound to those exact bytes.' \
                'That archive-to-payload binding is not implemented by this preview helper.' \
                'No application files, launchers or preferences will be changed, and no application will be launched.' \
                'For reviewed source setup, use install-angerona.sh from the official source checkout.' \
                'Usage: sh Install-Angerona-Release.sh [--help | --no-launch]'
            exit 0
            ;;
    esac
fi

printf '%s\n' \
    'HELD: authenticated Linux/macOS binary installation is not available.' \
    'This helper cannot prove that an unpacked binary or Angerona.app matches the official attested release archive.' \
    'It will not copy a neighboring payload, replace an existing installation or launch code.' \
    'No application files, launchers or preferences were changed.' \
    'Use --help for the supported source-setup route and the current preview limit.' >&2
exit 1
