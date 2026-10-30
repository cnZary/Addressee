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
CARD_USB_OPERATION="${CARD_USB_OPERATION:-association}"
case "$CARD_USB_OPERATION" in
    association) ;;
    signing|attached-signing|decryption)
        python3 - <<'PY'
import os
if not 0 < len(os.environ.get("CARD_TEST_PIN", "").encode()) <= 128:
    raise SystemExit("CARD_TEST_PIN must be supplied separately for the authorized test card")
PY
        ;;
    *)
        echo "CARD_USB_OPERATION must be association, signing, attached-signing, or decryption." >&2
        exit 2
        ;;
esac
CARD_USB_PEER_INPUT=local
if [[ -n "${CARD_USB_GPG_MESSAGE:-}" || -n "${CARD_USB_GPG_PLAINTEXT:-}" ]]; then
    if [[ "$CARD_USB_OPERATION" != decryption || -z "${CARD_USB_GPG_MESSAGE:-}" || -z "${CARD_USB_GPG_PLAINTEXT:-}" ]]; then
        echo "GnuPG peer input requires decryption mode and both message and plaintext paths." >&2
        exit 2
    fi
    if [[ ! -f "$CARD_USB_GPG_MESSAGE" || ! -s "$CARD_USB_GPG_MESSAGE" || ! -f "$CARD_USB_GPG_PLAINTEXT" || ! -s "$CARD_USB_GPG_PLAINTEXT" ]]; then
        echo "GnuPG peer input files must exist and be nonempty." >&2
        exit 2
    fi
    ENCODED_PEER_MESSAGE=$(python3 - "$CARD_USB_GPG_MESSAGE" <<'PY'
import base64
from pathlib import Path
import sys
data = Path(sys.argv[1]).read_bytes()
if not 0 < len(data) <= 16 * 1024 * 1024:
    raise SystemExit("The GnuPG peer message is empty or too large")
print(base64.b64encode(data).decode(), end="")
PY
)
    ENCODED_PEER_PLAINTEXT=$(python3 - "$CARD_USB_GPG_PLAINTEXT" <<'PY'
import base64
from pathlib import Path
import sys
data = Path(sys.argv[1]).read_bytes()
if not 0 < len(data) <= 16 * 1024 * 1024:
    raise SystemExit("The GnuPG peer plaintext is empty or too large")
print(base64.b64encode(data).decode(), end="")
PY
)
    CARD_USB_PEER_INPUT=gpg
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
TEST_ID='AppleSmartCardDeviceTests/testUSBAssociationAndCleanClose()'
case "$CARD_USB_OPERATION" in
    signing)
        TEST_ID='AppleSmartCardDeviceTests/testUSBPrivateKeySigning()'
        ;;
    attached-signing)
        TEST_ID='AppleSmartCardDeviceTests/testUSBPrivateKeyAttachedSigning()'
        ;;
    decryption)
        TEST_ID='AppleSmartCardDeviceTests/testUSBPrivateKeyDecryption()'
        ;;
esac
if [[ "$CARD_USB_OPERATION" != association ]]; then
    for target in EnvironmentVariables TestingEnvironmentVariables; do
        plutil -replace "AddresseeTests.$target.ADDRESSEE_CARD_USB_PRIVATE_KEY_TESTS" -string 1 "$TEST_RUN"
    done
    python3 - "$TEST_RUN" <<'PY'
import os
import plistlib
from pathlib import Path
import sys

path = Path(sys.argv[1])
with path.open("rb") as stream:
    document = plistlib.load(stream)
for target in ("EnvironmentVariables", "TestingEnvironmentVariables"):
    document["AddresseeTests"][target]["ADDRESSEE_CARD_TEST_PIN"] = os.environ["CARD_TEST_PIN"]
with path.open("wb") as stream:
    plistlib.dump(document, stream, sort_keys=False)
PY
    trap 'for target in EnvironmentVariables TestingEnvironmentVariables; do plutil -remove "AddresseeTests.$target.ADDRESSEE_CARD_TEST_PIN" "$TEST_RUN" >/dev/null 2>&1 || true; done' EXIT
fi
if [[ "$CARD_USB_PEER_INPUT" == gpg ]]; then
    for target in EnvironmentVariables TestingEnvironmentVariables; do
        plutil -replace "AddresseeTests.$target.ADDRESSEE_CARD_USB_PEER_MESSAGE" -string "$ENCODED_PEER_MESSAGE" "$TEST_RUN"
        plutil -replace "AddresseeTests.$target.ADDRESSEE_CARD_USB_PEER_PLAINTEXT" -string "$ENCODED_PEER_PLAINTEXT" "$TEST_RUN"
    done
fi

xcodebuild test-without-building \
    -xctestrun "$TEST_RUN" \
    -destination "platform=iOS,id=$DEVICE_ID" \
    -destination-timeout 30 \
    -derivedDataPath "$ROOT_DIR/build/DeviceDerivedData" \
    -resultBundlePath "$RESULT_BUNDLE" \
    "-only-testing:AddresseeTests/$TEST_ID"

xcrun xcresulttool get test-results tests --path "$RESULT_BUNDLE" | TEST_ID="$TEST_ID" python3 -c '
import json
import os
import sys

report = json.load(sys.stdin)
if not report.get("devices") or any(device.get("platform") != "iOS" for device in report["devices"]):
    raise SystemExit("The result does not belong to a physical iOS device")
results = []
def visit(node):
    if node.get("nodeType") == "Test Case" and node.get("nodeIdentifier") == os.environ["TEST_ID"]:
        results.append(node.get("result"))
    for child in node.get("children", []):
        visit(child)
for node in report.get("testNodes", []):
    visit(node)
if results != ["Passed"]:
    raise SystemExit(f"The selected physical USB test did not pass: {results}")
print("The selected physical USB test passed without a skip.")
'

xcrun xcresulttool export attachments \
    --path "$RESULT_BUNDLE" \
    --test-id "$TEST_ID" \
    --output-path "$OUTPUT"
python3 - "$OUTPUT" "$CARD_READER_NAME" "$TEST_ID" "$CARD_USB_OPERATION" "$CARD_USB_PEER_INPUT" "${CARD_USB_GPG_MESSAGE:-}" "${CARD_USB_GPG_PLAINTEXT:-}" <<'PY'
import json
from pathlib import Path
import shutil
import sys

output = Path(sys.argv[1])
reader_name = sys.argv[2]
test_id = sys.argv[3]
operation = sys.argv[4]
peer_input = sys.argv[5]
manifest = json.loads((output / "manifest.json").read_text())
selected = []
for suite in manifest:
    if suite.get("testIdentifier") != test_id:
        continue
    for attachment in suite.get("attachments", []):
        name = attachment.get("suggestedHumanReadableName", "")
        if name.startswith(f"usb-{operation}-result_0_"):
            selected.append(attachment)
if len(selected) != 1:
    raise SystemExit("The physical test must export exactly one selected USB observation")
source = (output / selected[0]["exportedFileName"]).resolve()
source.relative_to(output)
if not source.is_file() or source.stat().st_size > 64 * 1024:
    raise SystemExit("The USB observation is missing or too large")
report = json.loads(source.read_text())
if operation == "association":
    expected = {
        "association": "passed",
        "transportOpenCount": 1,
        "transportCloseCompletionCount": 1,
        "successfulTransportCloseCompletionCount": 1,
        "pinSupplied": False,
        "privateKeyOperationRequested": False,
        "privateKeyExportRequested": False,
    }
else:
    expected = {
        "operation": operation,
        "messageSource": peer_input,
        "associationRestored": True,
        "publicInspection": "passed",
        "privateKeyOperation": "passed",
        "transportOpenCount": 3,
        "transportCloseCompletionCount": 3,
        "successfulTransportCloseCompletionCount": 3,
        "pinSupplied": True,
        "privateKeyOperationRequested": True,
        "privateKeyMaterialExported": False,
    }
expected.update({
    "schemaVersion": 1,
    "transport": "usb",
    "readerName": reader_name,
    "transportFailureCount": 0,
    "cardConfigurationWritten": False,
})
for key, value in expected.items():
    if report.get(key) != value or type(report.get(key)) is not type(value):
        raise SystemExit(f"Invalid USB observation: {key}")
for key in ("certificateFingerprint", "cardIdentity"):
    if not isinstance(report.get(key), str) or not report[key]:
        raise SystemExit(f"Missing USB observation: {key}")
if operation != "association" and (
    not isinstance(report.get("componentFingerprint"), str) or not report["componentFingerprint"]
):
    raise SystemExit("The selected USB component fingerprint is missing")
shutil.copyfile(source, output / f"usb-{operation}-result.json")

def export_attachment(prefix, name, maximum):
    matches = []
    for suite in manifest:
        if suite.get("testIdentifier") != test_id:
            continue
        for attachment in suite.get("attachments", []):
            if attachment.get("suggestedHumanReadableName", "").startswith(prefix):
                matches.append(attachment)
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly one {prefix} attachment")
    artifact = (output / matches[0]["exportedFileName"]).resolve()
    artifact.relative_to(output)
    if not artifact.is_file() or not 0 < artifact.stat().st_size <= maximum:
        raise SystemExit(f"Missing or oversized artifact: {name}")
    shutil.copyfile(artifact, output / name)
    return output / name

if operation == "signing":
    payload = export_attachment("usb-signing-payload_0_", "payload.bin", 1024 * 1024)
    export_attachment("usb-signing-signature_0_", "signature.sig", 1024 * 1024)
    if payload.read_bytes() != b"Physical USB short signing session":
        raise SystemExit("The exported USB signing payload does not match the test input")
if operation == "attached-signing":
    payload = export_attachment("usb-attached-signing-payload_0_", "payload.bin", 1024 * 1024)
    export_attachment("usb-attached-signing-message_0_", "attached-message.pgp", 16 * 1024 * 1024)
    export_attachment("usb-attached-signing-tampered_0_", "tampered-attached-message.pgp", 16 * 1024 * 1024)
    if payload.read_bytes() != b"Physical USB attached signing\0\r\nSecond line":
        raise SystemExit("The exported USB attached-signature payload does not match the test input")
if peer_input == "gpg":
    for argument, name in ((6, "gpg-peer-encrypted.pgp"), (7, "gpg-peer-plaintext.bin")):
        peer_file = Path(sys.argv[argument])
        if not peer_file.is_file() or not 0 < peer_file.stat().st_size <= 16 * 1024 * 1024:
            raise SystemExit("The GnuPG peer evidence is missing or too large")
        shutil.copyfile(peer_file, output / name)
print(json.dumps(report, indent=2, sort_keys=True))
if operation == "association":
    print("Only USB association and clean closure passed; no private-key operation was tested.")
else:
    print(f"Only the selected USB {operation} workflow and its public setup and closure passed.")
PY

if [[ "$CARD_USB_OPERATION" == attached-signing ]]; then
    python3 "$ROOT_DIR/scripts/verify-usb-attached-signature.py" "$CARD_USB_FIXTURE" "$OUTPUT"
fi
