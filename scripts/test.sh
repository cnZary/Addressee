#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

cargo fmt --manifest-path "$RUST_MANIFEST" --check \
    --package openpgp-core \
    --package openpgp-policy \
    --package openpgp-card-adapter \
    --package openpgp-ffi \
    --package uniffi-bindgen
cargo clippy --manifest-path "$RUST_MANIFEST" --workspace --all-targets \
    --locked -- -D warnings
cargo test --manifest-path "$RUST_MANIFEST" --workspace --locked
python3 "$ROOT_DIR/scripts/audit-dependencies.py"
bash "$ROOT_DIR/scripts/test-interoperability.sh"

for package in apple-smartcard-transport openpgp-apple-se openpgp-key-provider; do
    if [[ -f "$ROOT_DIR/packages/$package/Package.swift" ]]; then
        swift test --package-path "$ROOT_DIR/packages/$package"
    fi
done

if [[ -f "$ROOT_DIR/apps/ios/Addressee.xcodeproj/project.pbxproj" ]]; then
    bash "$ROOT_DIR/scripts/test-ios.sh"
fi
