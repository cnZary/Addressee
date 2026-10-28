#!/bin/bash

# SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
# SPDX-License-Identifier: CC0-1.0

# Helper script to manually run an endless loop of one test (currently hardcoded to "import"),
# and stop on the first error:
#
# $ tests/loop.sh tests/ci/virt-opcard-rs.toml

TEST=import

COUNTER=0
while [ true ]; do
  TEST_CONFIG=$1 cargo test --release $TEST -- --ignored --nocapture || exit 1
  let COUNTER++; echo "=== loop counter: $COUNTER ==="
done