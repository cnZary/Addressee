#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
    cargo build --manifest-path "$RUST_MANIFEST" --package openpgp-ffi \
        --release --locked --target "$target"
done

OUTPUT="$ROOT_DIR/apps/ios/XCFrameworks"
STAGING="$ROOT_DIR/build/xcframework"
rm -rf "$STAGING"
mkdir -p "$STAGING/device" "$STAGING/simulator"

cp "$CARGO_TARGET_DIR/aarch64-apple-ios/release/libopenpgp_ffi.a" \
    "$STAGING/device/libopenpgp_ffi.a"
lipo -create \
    "$CARGO_TARGET_DIR/aarch64-apple-ios-sim/release/libopenpgp_ffi.a" \
    "$CARGO_TARGET_DIR/x86_64-apple-ios/release/libopenpgp_ffi.a" \
    -output "$STAGING/simulator/libopenpgp_ffi.a"

for slice in device simulator; do
    mkdir -p "$STAGING/$slice/Headers"
    cp "$ROOT_DIR/apps/ios/Generated/openpgp_ffiFFI.h" "$STAGING/$slice/Headers/"
    cp "$ROOT_DIR/apps/ios/Generated/openpgp_ffiFFI.modulemap" \
        "$STAGING/$slice/Headers/module.modulemap"
done

rm -rf "$OUTPUT/AddresseeCore.xcframework"
mkdir -p "$OUTPUT"
xcodebuild -create-xcframework \
    -library "$STAGING/device/libopenpgp_ffi.a" -headers "$STAGING/device/Headers" \
    -library "$STAGING/simulator/libopenpgp_ffi.a" -headers "$STAGING/simulator/Headers" \
    -output "$OUTPUT/AddresseeCore.xcframework"
