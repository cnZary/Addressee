#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

if [[ -z "${SIMULATOR_ID:-}" ]]; then
    SIMULATOR_ID=$(xcrun simctl list devices available -j | python3 "$ROOT_DIR/scripts/select-simulator.py")
fi
export SIMULATOR_ID

RESULT_BUNDLE="$ROOT_DIR/build/TextInputTests.xcresult"
rm -rf "$RESULT_BUNDLE"
xcodebuild -quiet \
    -project "$ROOT_DIR/apps/ios/Addressee.xcodeproj" \
    -scheme Addressee \
    -configuration Debug \
    -destination "platform=iOS Simulator,id=$SIMULATOR_ID" \
    -derivedDataPath "$ROOT_DIR/build/DerivedData" \
    -resultBundlePath "$RESULT_BUNDLE" \
    CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY="-" \
    -only-testing:AddresseeUITests/AddresseeUITests/testLongTextInputsClearAndPaste \
    test
xcrun xcresulttool get test-results tests --path "$RESULT_BUNDLE"
