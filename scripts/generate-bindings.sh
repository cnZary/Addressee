#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

cargo build --manifest-path "$RUST_MANIFEST" --package openpgp-ffi \
    --locked --target aarch64-apple-darwin
mkdir -p "$ROOT_DIR/apps/ios/Generated"
cd "$ROOT_DIR/rust"
cargo run --manifest-path "$RUST_MANIFEST" --package uniffi-bindgen --locked -- \
    generate \
    --library "$CARGO_TARGET_DIR/aarch64-apple-darwin/debug/libopenpgp_ffi.a" \
    --language swift \
    --out-dir "$ROOT_DIR/apps/ios/Generated"
