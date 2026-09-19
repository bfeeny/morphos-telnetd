#!/bin/sh
# Host-side tests. These MUST run on the build host and never on MorphOS.
#
# The logic under test decides when it is safe to stop servicing a live Shell's
# packets, what a telnet client is allowed to say, and who is allowed in.
# Getting any of that wrong on the target means a crash of unclear origin on a
# machine with no memory protection -- or letting a stranger in. So it is all
# exercised here, where a mistake costs nothing.
#
# THE TESTING RULE: never let the thing under test be the only guard between a
# test and a destroyed machine. To prove something is refused, assert the
# verdict in a unit test -- do not run the destructive command.

set -e

if [ -d /MOSSYS ] || [ -d MOSSYS: ] || uname -s 2>/dev/null | grep -qi morphos; then
    echo "tests/run.sh: this is a HOST test suite; refusing to run on MorphOS." >&2
    exit 2
fi

CC="${CC:-cc}"
DIR=`dirname "$0"`
CFLAGS="-std=c11 -O1 -Wall -Wextra -Werror"

TMPDIR_T=`mktemp -d -t mt_tests` || exit 1
trap 'rm -rf "$TMPDIR_T"' EXIT INT TERM

fail=0

run_suite() {
    name="$1"; shift
    $CC $CFLAGS -o "$TMPDIR_T/$name" "$@" || { fail=1; return; }
    "$TMPDIR_T/$name" || fail=1
    echo
}

run_suite console "$DIR/test_console_handler.c" "$DIR/../src/console_handler.c"
run_suite telnet  "$DIR/test_telnet.c"          "$DIR/../src/telnet.c"
run_suite auth    "$DIR/test_auth.c"            "$DIR/../src/auth.c"

exit $fail
