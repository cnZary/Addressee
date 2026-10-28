#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

CONFIGURATION="${1:-Debug}"
if [[ "$CONFIGURATION" != "Debug" && "$CONFIGURATION" != "Release" ]]; then
    echo "Usage: bash scripts/build-ios.sh [Debug|Release]" >&2
    exit 2
fi

bash "$ROOT_DIR/scripts/generate-bindings.sh"
bash "$ROOT_DIR/scripts/build-rust.sh"

xcodebuild \
    -project "$ROOT_DIR/apps/ios/Addressee.xcodeproj" \
    -scheme Addressee \
    -configuration "$CONFIGURATION" \
    -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath "$ROOT_DIR/build/DerivedData" \
    CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY="-" \
    build
