#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

command -v gpg >/dev/null
cargo test --manifest-path "$RUST_MANIFEST" \
    --package openpgp-core --test interoperability \
    --release --locked
cargo test --manifest-path "$RUST_MANIFEST" \
    --package openpgp-ffi --features gpg-interop-test \
    --locked --offline
