#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

if [[ -z "${DEVICE_ID:-}" ]]; then
    echo "Set DEVICE_ID to an explicitly selected, unlocked physical iPhone." >&2
    exit 2
fi
if [[ -z "${CARD_READER_NAME:-}" || ${#CARD_READER_NAME} -gt 1024 ]]; then
    echo "CARD_READER_NAME must explicitly select the only current USB reader." >&2
    exit 2
fi
if [[ -z "${CARD_USB_FIXTURE:-}" || ! -f "$CARD_USB_FIXTURE" || ! -s "$CARD_USB_FIXTURE" ]]; then
    echo "CARD_USB_FIXTURE must identify a nonempty public card fixture." >&2
    exit 2
fi
if [[ "$CARD_READER_NAME" == *$'\n'* || "$CARD_READER_NAME" == *$'\r'* ]]; then
    echo "CARD_READER_NAME contains an invalid line break." >&2
    exit 2
fi

RESULT_BUNDLE="${RESULT_BUNDLE:-$ROOT_DIR/build/USBCardDeviceTests-$(date +%Y%m%d-%H%M%S).xcresult}"
OUTPUT="${CARD_USB_OUTPUT:-${RESULT_BUNDLE%.xcresult}-evidence}"
if [[ -e "$RESULT_BUNDLE" || -e "$OUTPUT" ]]; then
    echo "The result bundle and evidence output must be new paths." >&2
    exit 2
fi

ENCODED_CARD_FIXTURE=$(python3 - "$CARD_USB_FIXTURE" <<'PY'
import base64
import json
from pathlib import Path
import sys

fixture = json.loads(Path(sys.argv[1]).read_text())
required = {
    "schemaVersion", "publicCertificate", "identity",
    "signingComponent", "decryptionComponent",
}
if fixture.get("schemaVersion") != 1 or set(fixture) != required:
    raise SystemExit("The USB fixture has an invalid schema")
identity = fixture["identity"]
if not isinstance(identity, dict) or set(identity) != {"manufacturer", "serial", "version"}:
    raise SystemExit("The USB fixture has an invalid card identity")
for name, maximum in (("manufacturer", 65535), ("serial", 4294967295), ("version", 65535)):
    value = identity[name]
    if type(value) is not int or not 0 <= value <= maximum:
        raise SystemExit("The USB fixture has an invalid card identity")
certificate = base64.b64decode(fixture["publicCertificate"], validate=True)
if not 0 < len(certificate) <= 4 * 1024 * 1024:
    raise SystemExit("The USB fixture certificate is empty or too large")
for name in ("signingComponent", "decryptionComponent"):
    value = fixture[name]
    if value is not None and (
        len(value) != 40 or any(character not in "0123456789ABCDEF" for character in value)
    ):
        raise SystemExit("The USB fixture has an invalid component fingerprint")
if fixture["signingComponent"] is None and fixture["decryptionComponent"] is None:
    raise SystemExit("The USB fixture must select at least one public component")
print(base64.b64encode(json.dumps(fixture, separators=(",", ":")).encode()).decode(), end="")
PY
)

xcodebuild \
    -project "$ROOT_DIR/apps/ios/Addressee.xcodeproj" \
    -scheme AddresseeSecureEnclave \
    -configuration Debug \
    -destination 'generic/platform=iOS' \
    -derivedDataPath "$ROOT_DIR/build/DeviceDerivedData" \
    CODE_SIGNING_ALLOWED=YES \
    build-for-testing

SDK_VERSION=$(xcrun --sdk iphoneos --show-sdk-version)
TEST_RUN="$ROOT_DIR/build/DeviceDerivedData/Build/Products/AddresseeSecureEnclave_iphoneos${SDK_VERSION}-arm64.xctestrun"
if [[ ! -f "$TEST_RUN" ]]; then
    echo "The device test-run specification was not generated: $TEST_RUN" >&2
    exit 1
fi
for target in EnvironmentVariables TestingEnvironmentVariables; do
    plutil -replace "AddresseeTests.$target.ADDRESSEE_CARD_USB_TESTS" -string 1 "$TEST_RUN"
    plutil -replace "AddresseeTests.$target.ADDRESSEE_CARD_USB_FIXTURE" -string "$ENCODED_CARD_FIXTURE" "$TEST_RUN"
    plutil -replace "AddresseeTests.$target.ADDRESSEE_CARD_READER_NAME" -string "$CARD_READER_NAME" "$TEST_RUN"
done
plutil -replace AddresseeTests.CommandLineArguments -json '[]' "$TEST_RUN"

xcodebuild test-without-building \
    -xctestrun "$TEST_RUN" \
    -destination "platform=iOS,id=$DEVICE_ID" \
    -destination-timeout 30 \
    -derivedDataPath "$ROOT_DIR/build/DeviceDerivedData" \
    -resultBundlePath "$RESULT_BUNDLE" \
    -only-testing:AddresseeTests/AppleSmartCardDeviceTests/testUSBAssociationAndCleanClose

xcrun xcresulttool get test-results tests --path "$RESULT_BUNDLE" | python3 -c '
import json
import sys

report = json.load(sys.stdin)
if not report.get("devices") or any(device.get("platform") != "iOS" for device in report["devices"]):
    raise SystemExit("The result does not belong to a physical iOS device")
results = []
def visit(node):
    if node.get("nodeType") == "Test Case" and node.get("nodeIdentifier") == (
        "AppleSmartCardDeviceTests/testUSBAssociationAndCleanClose()"
    ):
        results.append(node.get("result"))
    for child in node.get("children", []):
        visit(child)
for node in report.get("testNodes", []):
    visit(node)
if results != ["Passed"]:
    raise SystemExit(f"The physical USB association test did not pass: {results}")
print("The selected physical USB association test passed without a skip.")
'

TEST_ID='AppleSmartCardDeviceTests/testUSBAssociationAndCleanClose()'
xcrun xcresulttool export attachments \
    --path "$RESULT_BUNDLE" \
    --test-id "$TEST_ID" \
    --output-path "$OUTPUT"
python3 - "$OUTPUT" "$CARD_READER_NAME" <<'PY'
import json
from pathlib import Path
import shutil
import sys

output = Path(sys.argv[1])
manifest = json.loads((output / "manifest.json").read_text())
selected = []
for suite in manifest:
    if suite.get("testIdentifier") != "AppleSmartCardDeviceTests/testUSBAssociationAndCleanClose()":
        continue
    for attachment in suite.get("attachments", []):
        name = attachment.get("suggestedHumanReadableName", "")
        if name.startswith("usb-association-result_0_"):
            selected.append(attachment)
if len(selected) != 1:
    raise SystemExit("The physical test must export exactly one USB association observation")
source = (output / selected[0]["exportedFileName"]).resolve()
source.relative_to(output)
if not source.is_file() or source.stat().st_size > 64 * 1024:
    raise SystemExit("The USB association observation is missing or too large")
report = json.loads(source.read_text())
expected = {
    "schemaVersion": 1,
    "transport": "usb",
    "readerName": sys.argv[2],
    "association": "passed",
    "transportOpenCount": 1,
    "transportCloseCompletionCount": 1,
    "successfulTransportCloseCompletionCount": 1,
    "transportFailureCount": 0,
    "pinSupplied": False,
    "privateKeyOperationRequested": False,
    "cardConfigurationWritten": False,
    "privateKeyExportRequested": False,
}
for key, value in expected.items():
    if report.get(key) != value or type(report.get(key)) is not type(value):
        raise SystemExit(f"Invalid USB association observation: {key}")
for key in ("certificateFingerprint", "cardIdentity"):
    if not isinstance(report.get(key), str) or not report[key]:
        raise SystemExit(f"Missing USB association observation: {key}")
shutil.copyfile(source, output / "usb-association-result.json")
print(json.dumps(report, indent=2, sort_keys=True))
print("Only USB association and clean closure passed; no private-key operation was tested.")
PY
