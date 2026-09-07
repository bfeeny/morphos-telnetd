#!/bin/sh
# Host-side tests for the shell-attach packet logic.
#
# These MUST run on the build host and never on MorphOS. The logic under test
# is what decides when it is safe to stop servicing a live Shell's packets;
# getting it wrong on the target takes down the OS, along with whatever every
# other agent on that machine was doing. So it is exercised here, where a
# mistake costs nothing.
#
# See "The testing rule" in the vault (MorphOS/Reaching Morphy.md).

set -e

# Refuse to run on the target, the way amigacode's tests/run.sh does.
if [ -d /MOSSYS ] || [ -d MOSSYS: ] || uname -s 2>/dev/null | grep -qi morphos; then
    echo "tests/run.sh: this is a HOST test suite; refusing to run on MorphOS." >&2
    exit 2
fi

CC="${CC:-cc}"
DIR=`dirname "$0"`
BIN=`mktemp -t console_handler_tests` || exit 1
trap 'rm -f "$BIN"' EXIT INT TERM

$CC -std=c11 -O1 -Wall -Wextra -Werror \
    -o "$BIN" "$DIR/test_console_handler.c" "$DIR/../src/console_handler.c"
"$BIN"

echo
BIN2=`mktemp -t telnet_tests` || exit 1
trap 'rm -f "$BIN" "$BIN2"' EXIT INT TERM
$CC -std=c11 -O1 -Wall -Wextra -Werror \
    -o "$BIN2" "$DIR/test_telnet.c" "$DIR/../src/telnet.c"
"$BIN2"
