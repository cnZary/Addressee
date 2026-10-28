#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

if [[ -z "${SIMULATOR_ID:-}" ]]; then
    SIMULATOR_ID=$(xcrun simctl list devices available -j | python3 "$ROOT_DIR/scripts/select-simulator.py")
fi
export SIMULATOR_ID

case "${1:-}" in
    signature)
        TEST_NAME=testArmoredTextSignatureCopiesBeforeSharingAndBinaryOutputDoesNotCopy
        RESULT_NAME=SignatureCopyTests
        ARMOR_HEADER='-----BEGIN PGP SIGNATURE-----'
        ;;
    encryption)
        TEST_NAME=testArmoredTextEncryptionCopiesBeforeSharing
        RESULT_NAME=EncryptionCopyTests
        ARMOR_HEADER='-----BEGIN PGP MESSAGE-----'
        ;;
    *)
        echo "Usage: bash scripts/test-copy-result.sh [signature|encryption]" >&2
        exit 2
        ;;
esac

RESULT_BUNDLE="$ROOT_DIR/build/$RESULT_NAME.xcresult"
rm -rf "$RESULT_BUNDLE"
xcodebuild -quiet \
    -project "$ROOT_DIR/apps/ios/Addressee.xcodeproj" \
    -scheme Addressee \
    -configuration Debug \
    -destination "platform=iOS Simulator,id=$SIMULATOR_ID" \
    -derivedDataPath "$ROOT_DIR/build/DerivedData" \
    -resultBundlePath "$RESULT_BUNDLE" \
    CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY="-" \
    -only-testing:"AddresseeUITests/AddresseeUITests/$TEST_NAME" \
    test
xcrun xcresulttool get test-results tests --path "$RESULT_BUNDLE"

RUNNER_CONTAINER=$(xcrun simctl get_app_container \
    "$SIMULATOR_ID" com.addressee.AddresseeUITests.xctrunner data)
EXPECTED="$RUNNER_CONTAINER/tmp/addressee-copy-expectation"
COPIED="$ROOT_DIR/build/$RESULT_NAME-armor.txt"
if [[ ! -f "$EXPECTED" ]]; then
    echo "The UI test did not save its expected ASCII armor" >&2
    exit 1
fi

xcrun simctl pbpaste "$SIMULATOR_ID" > "$COPIED"
if ! cmp -s "$EXPECTED" "$COPIED"; then
    echo "The simulator clipboard does not match the complete expected ASCII armor" >&2
    exit 1
fi
python3 - "$COPIED" "$ARMOR_HEADER" <<'PY'
from pathlib import Path
import sys

armor = Path(sys.argv[1]).read_bytes()
armor.decode("utf-8")
if not armor.startswith(sys.argv[2].encode("ascii")):
    raise SystemExit("The copied text does not have the expected OpenPGP armor type")
PY
rm -f "$EXPECTED"
echo "Verified the complete copied ASCII armor against the simulator clipboard"
