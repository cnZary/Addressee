#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
mkdir -p "$ROOT_DIR/build"
WORK_DIR=$(mktemp -d "$ROOT_DIR/build/apple-platform-api-probe.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT

swiftc \
    -parse-as-library \
    -emit-library \
    -emit-module \
    -module-name AppleSmartCardTransport \
    -target arm64-apple-ios16.0 \
    -sdk "$SDK" \
    -framework CryptoTokenKit \
    -framework CoreNFC \
    "$ROOT_DIR"/packages/apple-smartcard-transport/Sources/AppleSmartCardTransport/*.swift \
    -emit-module-path "$WORK_DIR/AppleSmartCardTransport.swiftmodule" \
    -o "$WORK_DIR/libAppleSmartCardTransport.dylib"

file "$WORK_DIR/libAppleSmartCardTransport.dylib"
plutil -lint \
    "$ROOT_DIR/apps/ios/Addressee/Addressee.entitlements" \
    "$ROOT_DIR/apps/ios/Addressee/Resources/Info.plist"

python3 - "$ROOT_DIR" "$WORK_DIR/libAppleSmartCardTransport.dylib" <<'PY'
import plistlib
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1])
library = sys.argv[2]
with (root / "apps/ios/Addressee/Addressee.entitlements").open("rb") as stream:
    entitlements = plistlib.load(stream)
with (root / "apps/ios/Addressee/Resources/Info.plist").open("rb") as stream:
    info = plistlib.load(stream)

assert entitlements.get("com.apple.security.smartcard") is True
assert info.get("NSFaceIDUsageDescription")
assert "TAG" in entitlements.get("com.apple.developer.nfc.readersession.formats", [])
assert "D27600012401" in info.get(
    "com.apple.developer.nfc.readersession.iso7816.select-identifiers", []
)
linked = subprocess.run(
    ["xcrun", "otool", "-L", library],
    check=True,
    capture_output=True,
    text=True,
).stdout
for framework in (
    "CryptoTokenKit.framework/CryptoTokenKit",
    "CoreNFC.framework/CoreNFC",
):
    assert framework in linked, f"missing framework linkage: {framework}"

print("ARM64 iOS 16 transport compilation and framework linking passed.")
print("NFC and smart-card declarations passed; device support is not inferred.")
PY
