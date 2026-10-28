#!/bin/sh
set -eu

: "${ADDRESSEE_TEST_TTY:?Set ADDRESSEE_TEST_TTY to the explicitly allocated test terminal}"

exec "${PINENTRY_TTY_PROGRAM:-pinentry-tty}" \
    --ttyname "$ADDRESSEE_TEST_TTY" \
    --ttytype "${ADDRESSEE_TEST_TTY_TYPE:-xterm}" \
    "$@"
