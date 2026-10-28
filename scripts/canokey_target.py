#!/usr/bin/env python3
"""Read-only USB evidence collection for the authorized CanoKey test target."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
from dataclasses import dataclass

CANOKEY_USB_VENDOR_ID = 0x20A0
CANOKEY_USB_PRODUCT_ID = 0x42D4
CANOKEY_USB_MANUFACTURER = "canokeys.org"


class TargetError(Exception):
    """The requested target cannot be identified without ambiguity."""


@dataclass(frozen=True)
class UsbDevice:
    vendor_id: int
    product_id: int
    manufacturer: str
    product: str
    serial: str
    bcd_device: int


@dataclass(frozen=True)
class CanokeyTarget:
    reader: str
    openpgp_serial: str
    usb: UsbDevice

    def as_dict(self) -> dict[str, object]:
        return {
            "reader": self.reader,
            "openpgpSerial": self.openpgp_serial,
            "usb": {
                "vendorId": f"0x{self.usb.vendor_id:04X}",
                "productId": f"0x{self.usb.product_id:04X}",
                "manufacturer": self.usb.manufacturer,
                "product": self.usb.product,
                "serial": self.usb.serial,
                "bcdDevice": f"0x{self.usb.bcd_device:04X}",
            },
        }


def canonical_serial(value: str, label: str) -> str:
    if len(value) != 8 or any(character not in "0123456789abcdefABCDEF" for character in value):
        raise TargetError(f"{label} must contain exactly eight hexadecimal digits")
    return value.upper()


def parse_usb_devices(plist: bytes) -> list[UsbDevice]:
    try:
        entries = plistlib.loads(plist)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise TargetError("I/O Registry returned invalid property-list data") from error
    if not isinstance(entries, list):
        raise TargetError("I/O Registry USB enumeration is not a list")

    devices = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise TargetError("I/O Registry returned a non-dictionary USB entry")
        if entry.get("idVendor") != CANOKEY_USB_VENDOR_ID:
            continue
        required = {
            "idProduct": int,
            "USB Vendor Name": str,
            "USB Product Name": str,
            "USB Serial Number": str,
            "bcdDevice": int,
        }
        values = {}
        for key, expected_type in required.items():
            value = entry.get(key)
            if type(value) is not expected_type:
                raise TargetError(f"CanoKey USB evidence is missing or has an invalid {key}")
            values[key] = value
        devices.append(
            UsbDevice(
                vendor_id=CANOKEY_USB_VENDOR_ID,
                product_id=values["idProduct"],
                manufacturer=values["USB Vendor Name"],
                product=values["USB Product Name"],
                serial=values["USB Serial Number"],
                bcd_device=values["bcdDevice"],
            )
        )
    return devices


def read_usb_devices() -> list[UsbDevice]:
    try:
        result = subprocess.run(
            ["/usr/sbin/ioreg", "-r", "-c", "IOUSBHostDevice", "-a"],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise TargetError("cannot enumerate USB devices through I/O Registry") from error
    return parse_usb_devices(result.stdout)


def select_canokey(devices: list[UsbDevice], usb_serial: str) -> UsbDevice:
    expected_serial = canonical_serial(usb_serial, "USB serial")
    matches = [
        device
        for device in devices
        if device.product_id == CANOKEY_USB_PRODUCT_ID
        and device.manufacturer == CANOKEY_USB_MANUFACTURER
        and device.product.startswith("CanoKey ")
        and device.serial.upper() == expected_serial
    ]
    if len(matches) != 1:
        raise TargetError(
            f"expected exactly one authorized CanoKey with USB serial {expected_serial}; found {len(matches)}"
        )
    return matches[0]


def verify_target(reader: str, openpgp_serial: str, usb_serial: str) -> CanokeyTarget:
    if not reader or any(character in reader for character in ("\0", "\r", "\n")):
        raise TargetError("the exact PC/SC reader name is empty or contains a control character")
    serial = canonical_serial(openpgp_serial, "OpenPGP serial")
    usb = select_canokey(read_usb_devices(), usb_serial)
    return CanokeyTarget(reader=reader, openpgp_serial=serial, usb=usb)


def inspect_target(target: CanokeyTarget) -> None:
    root = Path(__file__).resolve().parent.parent
    environment = os.environ.copy()
    environment.setdefault("CARGO_TARGET_DIR", str(root / "build" / "rust-target"))
    command = [
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        str(root / "rust" / "Cargo.toml"),
        "--locked",
        "-p",
        "openpgp-card-adapter",
        "--features",
        "pcsc",
        "--bin",
        "inspect-canokey",
        "--",
        "--reader",
        target.reader,
        "--serial",
        target.openpgp_serial,
    ]
    try:
        subprocess.run(command, cwd=root, env=environment, check=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as error:
        raise TargetError("the read-only OpenPGP identity inspection failed") from error


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify USB evidence for one explicit CanoKey and optionally perform read-only OpenPGP inspection."
    )
    parser.add_argument("--reader", required=True, help="exact PC/SC reader name")
    parser.add_argument("--serial", required=True, help="expected eight-digit OpenPGP serial")
    parser.add_argument("--usb-serial", required=True, help="expected eight-digit USB serial")
    parser.add_argument(
        "--inspect",
        action="store_true",
        help="also select the OpenPGP application and verify its manufacturer and serial read-only",
    )
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    options = parse_args(arguments)
    try:
        target = verify_target(options.reader, options.serial, options.usb_serial)
        print(json.dumps(target.as_dict(), indent=2, sort_keys=True))
        if options.inspect:
            inspect_target(target)
        return 0
    except TargetError as error:
        print(f"CanoKey target verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
