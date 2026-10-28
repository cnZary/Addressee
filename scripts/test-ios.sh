#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

bash "$ROOT_DIR/scripts/test-apple-platform-apis.sh"

if [[ -z "${SIMULATOR_ID:-}" ]]; then
    SIMULATOR_ID=$(xcrun simctl list devices available -j | python3 "$ROOT_DIR/scripts/select-simulator.py")
fi
export SIMULATOR_ID

bash "$ROOT_DIR/scripts/build-ios.sh"
rm -rf "$ROOT_DIR/build/NativeTests.xcresult"
xcodebuild -quiet \
    -project "$ROOT_DIR/apps/ios/Addressee.xcodeproj" \
    -scheme Addressee \
    -configuration Debug \
    -destination "platform=iOS Simulator,id=$SIMULATOR_ID" \
    -derivedDataPath "$ROOT_DIR/build/DerivedData" \
    -resultBundlePath "$ROOT_DIR/build/NativeTests.xcresult" \
    CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY="-" \
    -skip-testing:AddresseeUITests/AddresseeUITests/testLongTextInputsClearAndPaste \
    -skip-testing:AddresseeUITests/AddresseeUITests/testArmoredTextSignatureCopiesBeforeSharingAndBinaryOutputDoesNotCopy \
    -skip-testing:AddresseeUITests/AddresseeUITests/testArmoredTextEncryptionCopiesBeforeSharing \
    test
xcrun xcresulttool get test-results tests --path "$ROOT_DIR/build/NativeTests.xcresult"
bash "$ROOT_DIR/scripts/test-text-inputs.sh"
bash "$ROOT_DIR/scripts/test-copy-result.sh" signature
bash "$ROOT_DIR/scripts/test-copy-result.sh" encryption
