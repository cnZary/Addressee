#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

if [[ -z "${DEVICE_ID:-}" ]]; then
    echo "Set DEVICE_ID to an explicitly selected, unlocked physical iPhone." >&2
    exit 2
fi

if [[ "${PREPARE_GPG_PEER:-0}" == 1 && -n "${GPG_PEER_FIXTURE:-}" ]]; then
    echo "PREPARE_GPG_PEER and GPG_PEER_FIXTURE belong to separate test phases." >&2
    exit 2
fi
if [[ "${SE_BIOMETRIC_CANCEL:-0}" == 1 && ( "${PREPARE_GPG_PEER:-0}" == 1 || -n "${GPG_PEER_FIXTURE:-}" || -n "${CARD_NFC_FIXTURE:-}" ) ]]; then
    echo "SE_BIOMETRIC_CANCEL is a separate interactive test mode." >&2
    exit 2
fi
if [[ -n "${CARD_NFC_FIXTURE:-}" && ( "${PREPARE_GPG_PEER:-0}" == 1 || -n "${GPG_PEER_FIXTURE:-}" || "${CARD_API_PROBE:-0}" == 1 ) ]]; then
    echo "CARD_NFC_FIXTURE is a separate test mode." >&2
    exit 2
fi
if [[ -n "${CARD_NFC_FIXTURE:-}" ]]; then
    if [[ ! -f "$CARD_NFC_FIXTURE" || ! -s "$CARD_NFC_FIXTURE" ]]; then
        echo "The public NFC test fixture is missing or empty." >&2
        exit 2
    fi
    ENCODED_CARD_FIXTURE=$(python3 - "$CARD_NFC_FIXTURE" <<'PY'
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
    raise SystemExit("The NFC fixture has an invalid schema")
identity = fixture["identity"]
if not isinstance(identity, dict) or set(identity) != {"manufacturer", "serial", "version"}:
    raise SystemExit("The NFC fixture has an invalid card identity")
for name, maximum in (("manufacturer", 65535), ("serial", 4294967295), ("version", 65535)):
    value = identity[name]
    if type(value) is not int or not 0 <= value <= maximum:
        raise SystemExit("The NFC fixture has an invalid card identity")
certificate = base64.b64decode(fixture["publicCertificate"], validate=True)
if not 0 < len(certificate) <= 4 * 1024 * 1024:
    raise SystemExit("The NFC fixture certificate is empty or too large")
for name in ("signingComponent", "decryptionComponent"):
    value = fixture[name]
    if value is not None and (
        len(value) != 40 or any(character not in "0123456789ABCDEF" for character in value)
    ):
        raise SystemExit("The NFC fixture has an invalid component fingerprint")
if fixture["signingComponent"] is None and fixture["decryptionComponent"] is None:
    raise SystemExit("The NFC fixture must select at least one component")
print(base64.b64encode(json.dumps(fixture, separators=(",", ":")).encode()).decode(), end="")
PY
)
    python3 - "${CARD_TEST_PIN:-}" <<'PY'
import sys
if not 0 < len(sys.argv[1].encode()) <= 128:
    raise SystemExit("CARD_TEST_PIN must be supplied separately for the authorized test card")
PY
fi

RESULT_BUNDLE="${RESULT_BUNDLE:-$ROOT_DIR/build/SecureEnclaveDeviceTests-$(date +%Y%m%d-%H%M%S).xcresult}"
if [[ -e "$RESULT_BUNDLE" ]]; then
    echo "The result bundle already exists: $RESULT_BUNDLE" >&2
    exit 2
fi

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
plutil -replace AddresseeTests.EnvironmentVariables.ADDRESSEE_SE_HARDWARE_TESTS -string 1 "$TEST_RUN"
plutil -replace AddresseeTests.TestingEnvironmentVariables.ADDRESSEE_SE_HARDWARE_TESTS -string 1 "$TEST_RUN"
plutil -replace AddresseeTests.CommandLineArguments -json '["--secure-enclave-hardware-tests"]' "$TEST_RUN"
if [[ "${SE_BIOMETRIC_CANCEL:-0}" == 1 ]]; then
    plutil -replace AddresseeTests.CommandLineArguments -json \
        '["--secure-enclave-hardware-tests", "--secure-enclave-biometric-cancel-tests"]' "$TEST_RUN"
fi
if [[ "${PREPARE_GPG_PEER:-0}" == 1 ]]; then
    plutil -replace AddresseeTests.CommandLineArguments -json \
        '["--secure-enclave-hardware-tests", "--prepare-gpg-peer"]' "$TEST_RUN"
fi

if [[ -n "${GPG_PEER_FIXTURE:-}" ]]; then
    if [[ ! -f "$GPG_PEER_FIXTURE" ]]; then
        echo "The GnuPG peer fixture does not exist: $GPG_PEER_FIXTURE" >&2
        exit 2
    fi
    ENCODED_FIXTURE=$(python3 - "$GPG_PEER_FIXTURE" <<'PY'
import base64
import json
from pathlib import Path
import sys

fixture = json.loads(Path(sys.argv[1]).read_text())
required = {
    "version", "recipientCertificateFingerprint", "encryptionComponentFingerprint",
    "signerFingerprint", "peerPublicCertificate", "unsignedMessage",
    "unsignedPlaintext", "combinedMessage", "combinedPlaintext",
}
if fixture.get("version") != 1 or set(fixture) != required:
    raise SystemExit("The GnuPG peer fixture has an invalid schema")
for key in ("recipientCertificateFingerprint", "encryptionComponentFingerprint", "signerFingerprint"):
    value = fixture[key]
    if len(value) != 40 or any(character not in "0123456789ABCDEF" for character in value):
        raise SystemExit("The GnuPG peer fixture contains an invalid fingerprint")
for key in required - {"version", "recipientCertificateFingerprint", "encryptionComponentFingerprint", "signerFingerprint"}:
    if not base64.b64decode(fixture[key], validate=True):
        raise SystemExit(f"The GnuPG peer fixture has an empty {key}")
encoded = base64.b64encode(json.dumps(fixture, separators=(",", ":")).encode()).decode()
if len(encoded) > 1_000_000:
    raise SystemExit("The GnuPG peer fixture is too large")
print(encoded, end="")
PY
)
    for target in EnvironmentVariables TestingEnvironmentVariables; do
        plutil -replace "AddresseeTests.$target.ADDRESSEE_SE_GPG_PEER_FIXTURE" -string "$ENCODED_FIXTURE" "$TEST_RUN"
    done
    plutil -replace AddresseeTests.CommandLineArguments -json \
        '["--secure-enclave-hardware-tests", "--require-gpg-peer-fixture"]' "$TEST_RUN"
fi

status=0
ONLY_TESTING=(-only-testing:AddresseeTests/SecureEnclaveDeviceTests)
if [[ "${CARD_API_PROBE:-0}" == 1 ]]; then
    for target in EnvironmentVariables TestingEnvironmentVariables; do
        plutil -replace "AddresseeTests.$target.ADDRESSEE_CARD_API_TESTS" -string 1 "$TEST_RUN"
    done
    ONLY_TESTING+=(-only-testing:AddresseeTests/AppleSmartCardDeviceTests)
fi
if [[ -n "${CARD_NFC_FIXTURE:-}" ]]; then
    ONLY_TESTING=(-only-testing:AddresseeTests/AppleSmartCardDeviceTests)
    for target in EnvironmentVariables TestingEnvironmentVariables; do
        plutil -replace "AddresseeTests.$target.ADDRESSEE_CARD_NFC_TESTS" -string 1 "$TEST_RUN"
        plutil -replace "AddresseeTests.$target.ADDRESSEE_CARD_NFC_FIXTURE" -string "$ENCODED_CARD_FIXTURE" "$TEST_RUN"
        plutil -replace "AddresseeTests.$target.ADDRESSEE_CARD_TEST_PIN" -string "$CARD_TEST_PIN" "$TEST_RUN"
    done
fi
xcodebuild test-without-building \
    -xctestrun "$TEST_RUN" \
    -destination "platform=iOS,id=$DEVICE_ID" \
    -destination-timeout 30 \
    -derivedDataPath "$ROOT_DIR/build/DeviceDerivedData" \
    -resultBundlePath "$RESULT_BUNDLE" \
    "${ONLY_TESTING[@]}" || status=$?

if [[ ! -d "$RESULT_BUNDLE" ]]; then
    echo "No device test result bundle was produced." >&2
    if (( status == 0 )); then
        status=1
    fi
    exit "$status"
fi

validation_status=0
xcrun xcresulttool get test-results tests --path "$RESULT_BUNDLE" |
    CARD_API_PROBE="${CARD_API_PROBE:-0}" CARD_NFC_MODE="${CARD_NFC_FIXTURE:+1}" \
    SE_BIOMETRIC_CANCEL="${SE_BIOMETRIC_CANCEL:-0}" python3 -c '
import json
import os
import sys

report = json.load(sys.stdin)
if not report.get("devices") or any(device.get("platform") != "iOS" for device in report["devices"]):
    raise SystemExit("The result does not belong to a physical iOS device.")
results = {}
def visit(node):
    if node.get("nodeType") == "Test Case":
        results[node["name"]] = node.get("result")
    for child in node.get("children", []):
        visit(child)
for test in report.get("testNodes", []):
    visit(test)
if os.environ["CARD_NFC_MODE"] == "1":
    required = {"testNFCAssociationAndShortPrivateKeySessions()"}
else:
    required = {
        "testBiometricPrivateKeyOperations()",
        "testECDHMatchesCryptoKitSoftwarePeer()",
        "testExplicitIdentifiersRestoreAndDeleteAcrossProviders()",
        "testNativeOpenPGPSigningAndDecryptionUseSecureEnclaveSubkeys()",
        "testSHA256DigestSignatureMatchesCryptoKit()",
        "testTamperedPublicReferenceIsRejected()",
    }
if os.environ["SE_BIOMETRIC_CANCEL"] == "1":
    required.add("testBiometricCancellationDoesNotFallBackToSoftware()")
if os.environ["CARD_API_PROBE"] == "1":
    required.add("testReadOnlyTransportAvailability()")
missing = required - results.keys()
if missing:
    raise SystemExit(f"Required physical tests were not executed: {sorted(missing)}")
not_passed = {name: results[name] for name in required if results[name] != "Passed"}
if not_passed:
    raise SystemExit(f"Physical tests failed or were skipped: {not_passed}")
print(f"All {len(required)} selected physical tests passed without skips.")
' || validation_status=$?

if [[ "${CARD_API_PROBE:-0}" == 1 ]]; then
    CARD_PROBE_OUTPUT="${CARD_PROBE_OUTPUT:-${RESULT_BUNDLE%.xcresult}-card-api}"
    python3 "$ROOT_DIR/scripts/export-apple-card-api-probe.py" \
        "$RESULT_BUNDLE" "$CARD_PROBE_OUTPUT" || validation_status=$?
fi

if (( validation_status != 0 )); then
    exit "$validation_status"
fi
exit "$status"
