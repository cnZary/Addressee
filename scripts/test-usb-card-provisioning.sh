#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

if [[ -z "${DEVICE_ID:-}" || -z "${CARD_READER_NAME:-}" ]]; then
    echo "DEVICE_ID and CARD_READER_NAME must explicitly select the unlocked phone and authorized reader." >&2
    exit 2
fi
if [[ -z "${CARD_USB_FIXTURE:-}" || ! -s "$CARD_USB_FIXTURE" ]]; then
    echo "CARD_USB_FIXTURE must identify the authorized card and a public certificate." >&2
    exit 2
fi
if [[ "${CARD_PROVISION_AUTHORIZATION:-}" != "replace-authorized-canokey-sig-dec" ]]; then
    echo "Set CARD_PROVISION_AUTHORIZATION to the explicit SIG/DEC replacement scope." >&2
    exit 2
fi
python3 - <<'PY'
import os
for name in ("CARD_TEST_PIN", "CARD_TEST_ADMIN_PIN"):
    if not 0 < len(os.environ.get(name, "").encode()) <= 128:
        raise SystemExit(f"{name} must be supplied separately for the authorized test card")
PY

export DEVELOPER_DIR="${DEVELOPER_DIR_OVERRIDE:-/Applications/Xcode.app/Contents/Developer}"
export PATH="$DEVELOPER_DIR/usr/bin:$PATH"
RESULT_BUNDLE="${RESULT_BUNDLE:-$ROOT_DIR/build/USBCardProvisioning-$(date +%Y%m%d-%H%M%S).xcresult}"
OUTPUT="${CARD_PROVISION_OUTPUT:-${RESULT_BUNDLE%.xcresult}-evidence}"
if [[ -e "$RESULT_BUNDLE" || -e "$OUTPUT" ]]; then
    echo "The result bundle and evidence directory must be new paths." >&2
    exit 2
fi

bash "$ROOT_DIR/scripts/build-ios.sh"
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
    echo "The physical test-run specification was not generated." >&2
    exit 1
fi
ENCODED_CARD_FIXTURE=$(python3 - "$CARD_USB_FIXTURE" <<'PY'
import base64
from pathlib import Path
import sys
print(base64.b64encode(Path(sys.argv[1]).read_bytes()).decode(), end="")
PY
)
for target in EnvironmentVariables TestingEnvironmentVariables; do
    plutil -replace "AddresseeTests.$target.ADDRESSEE_CARD_USB_PROVISIONING_TESTS" -string 1 "$TEST_RUN"
    plutil -replace "AddresseeTests.$target.ADDRESSEE_CARD_PROVISION_AUTHORIZATION" -string "$CARD_PROVISION_AUTHORIZATION" "$TEST_RUN"
    plutil -replace "AddresseeTests.$target.ADDRESSEE_CARD_USB_FIXTURE" -string "$ENCODED_CARD_FIXTURE" "$TEST_RUN"
    plutil -replace "AddresseeTests.$target.ADDRESSEE_CARD_READER_NAME" -string "$CARD_READER_NAME" "$TEST_RUN"
done
plutil -replace AddresseeTests.CommandLineArguments -json '[]' "$TEST_RUN"
python3 - "$TEST_RUN" <<'PY'
import os
import plistlib
from pathlib import Path
import sys
path = Path(sys.argv[1])
with path.open("rb") as stream:
    document = plistlib.load(stream)
for target in ("EnvironmentVariables", "TestingEnvironmentVariables"):
    for variable in ("CARD_TEST_PIN", "CARD_TEST_ADMIN_PIN"):
        document["AddresseeTests"][target][f"ADDRESSEE_{variable}"] = os.environ[variable]
with path.open("wb") as stream:
    plistlib.dump(document, stream, sort_keys=False)
PY
trap 'for target in EnvironmentVariables TestingEnvironmentVariables; do for variable in ADDRESSEE_CARD_TEST_PIN ADDRESSEE_CARD_TEST_ADMIN_PIN; do plutil -remove "AddresseeTests.$target.$variable" "$TEST_RUN" >/dev/null 2>&1 || true; done; done' EXIT

TEST_ID='AppleSmartCardDeviceTests/testUSBP256ProvisioningAndCertificate()'
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
    raise SystemExit("Provisioning evidence must come from a physical iOS device")
results = []
def visit(node):
    if node.get("nodeType") == "Test Case" and node.get("nodeIdentifier") == os.environ["TEST_ID"]:
        results.append(node.get("result"))
    for child in node.get("children", []):
        visit(child)
for node in report.get("testNodes", []):
    visit(node)
if results != ["Passed"]:
    raise SystemExit(f"The physical provisioning test did not pass: {results}")
'
xcrun xcresulttool export attachments \
    --path "$RESULT_BUNDLE" \
    --test-id "$TEST_ID" \
    --output-path "$OUTPUT"
TEST_ID="$TEST_ID" python3 - "$OUTPUT" "$CARD_READER_NAME" <<'PY'
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

output = Path(sys.argv[1]).resolve()
reader = sys.argv[2]
test_id = os.environ["TEST_ID"]
manifest = json.loads((output / "manifest.json").read_text())
def export(prefix, name):
    matches = [attachment for suite in manifest if suite.get("testIdentifier") == test_id
               for attachment in suite.get("attachments", [])
               if attachment.get("suggestedHumanReadableName", "").startswith(prefix)]
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly one provisioning artifact: {prefix}")
    source = (output / matches[0]["exportedFileName"]).resolve()
    source.relative_to(output)
    if not source.is_file() or not 0 < source.stat().st_size <= 4 * 1024 * 1024:
        raise SystemExit(f"Invalid provisioning artifact: {prefix}")
    destination = output / name
    shutil.copyfile(source, destination)
    return destination

report_path = export("usb-p256-provisioning-result_0_", "usb-p256-provisioning-result.json")
certificate = export("usb-p256-provisioning-certificate_0_", "public-certificate.pgp")
report = json.loads(report_path.read_text())
expected = {
    "schemaVersion": 1,
    "operation": "p256-provisioning",
    "transport": "usb",
    "readerName": reader,
    "publicInspection": "passed",
    "associationCreated": False,
    "replacementAuthorized": True,
    "pinSupplied": True,
    "privateKeyOperationRequested": False,
    "privateKeyMaterialExported": False,
    "cardConfigurationWritten": True,
    "transportOpenCount": 2,
    "transportCloseCompletionCount": 2,
    "successfulTransportCloseCompletionCount": 2,
    "transportFailureCount": 0,
}
for name, value in expected.items():
    if report.get(name) != value or type(report.get(name)) is not type(value):
        raise SystemExit(f"Invalid provisioning observation: {name}")
if report.get("cardIdentity") != "F1D0-00989ADF":
    raise SystemExit("The provisioning evidence is not bound to the authorized CanoKey")
for name in ("certificateFingerprint", "signingComponent", "decryptionComponent"):
    value = report.get(name)
    if not isinstance(value, str) or len(value) != 40 or any(c not in "0123456789ABCDEF" for c in value):
        raise SystemExit(f"Invalid component fingerprint: {name}")
if report["certificateFingerprint"] != report["signingComponent"]:
    raise SystemExit("The card primary signing component is inconsistent")
with tempfile.TemporaryDirectory(prefix="gpg-", dir=output) as home:
    home_path = Path(home)
    home_path.chmod(0o700)
    (home_path / "gpg-agent.conf").write_text("disable-scdaemon\n")
    (home_path / "gpg.conf").write_text("no-auto-key-retrieve\n")
    environment = os.environ.copy()
    environment["GNUPGHOME"] = home
    subprocess.run(["gpg", "--batch", "--yes", "--import", str(certificate)],
                   env=environment, check=True, capture_output=True, text=True)
    checked = subprocess.run([
        "gpg", "--batch", "--with-colons", "--with-subkey-fingerprint",
        "--check-sigs", report["certificateFingerprint"],
    ], env=environment, check=True, capture_output=True, text=True)
    good_signatures = [line for line in checked.stdout.splitlines()
                       if line.startswith("sig") and line.split(":")[1] == "!"]
    if len(good_signatures) < 2:
        raise SystemExit("GnuPG did not validate the User ID and subkey binding signatures")
verification = {
    "schemaVersion": 1,
    "implementation": "GnuPG 2.5.24",
    "certificateImport": "passed",
    "goodBindingSignatures": len(good_signatures),
    "certificateFingerprint": report["certificateFingerprint"],
    "identityTrust": "not-established",
}
(output / "gpg-verification.json").write_text(json.dumps(verification, indent=2, sort_keys=True) + "\n")
print(json.dumps(report, indent=2, sort_keys=True))
print(json.dumps(verification, indent=2, sort_keys=True))
print("Only physical P-256 provisioning and public-certificate validation passed. No message operation was requested.")
PY
