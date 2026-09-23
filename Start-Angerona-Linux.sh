#!/bin/bash
# Run this file in a terminal, or select "Run in Terminal" in your file manager.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec /bin/sh "$ROOT/tools/native-quickstart.sh" Linux "$@"
