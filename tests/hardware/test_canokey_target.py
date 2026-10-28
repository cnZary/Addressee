import importlib.util
from pathlib import Path
import plistlib
import sys
import unittest


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "canokey_target.py"
SPEC = importlib.util.spec_from_file_location("canokey_target", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CanokeyTargetTests(unittest.TestCase):
    def device(self, **overrides):
        values = {
            "vendor_id": MODULE.CANOKEY_USB_VENDOR_ID,
            "product_id": MODULE.CANOKEY_USB_PRODUCT_ID,
            "manufacturer": MODULE.CANOKEY_USB_MANUFACTURER,
            "product": "CanoKey Canary",
            "serial": "00989ADF",
            "bcd_device": 0x0310,
        }
        values.update(overrides)
        return MODULE.UsbDevice(**values)

    def test_accepts_only_the_complete_requested_identity(self):
        selected = MODULE.select_canokey([self.device()], "00989adf")
        self.assertEqual(selected.serial, "00989ADF")
        self.assertEqual(selected.bcd_device, 0x0310)

    def test_does_not_fall_back_to_a_yubikey_or_another_device(self):
        yubikey = self.device(vendor_id=0x1050, manufacturer="Yubico", product="YubiKey")
        other = self.device(serial="12345678")
        with self.assertRaises(MODULE.TargetError):
            MODULE.select_canokey([yubikey, other], "00989ADF")

    def test_duplicate_matching_devices_are_ambiguous(self):
        with self.assertRaises(MODULE.TargetError):
            MODULE.select_canokey([self.device(), self.device()], "00989ADF")

    def test_manufacturer_and_product_are_not_inferred_from_vid_pid(self):
        for overrides in (
            {"manufacturer": "Yubico"},
            {"product": "Generic CCID Token"},
            {"product_id": 0x1234},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(MODULE.TargetError):
                    MODULE.select_canokey([self.device(**overrides)], "00989ADF")

    def test_serial_syntax_and_length_are_strict(self):
        for serial in ("", "ABCD", "0x00989ADF", "00989ADG"):
            with self.subTest(serial=serial):
                with self.assertRaises(MODULE.TargetError):
                    MODULE.select_canokey([self.device()], serial)

    def test_structured_usb_data_requires_complete_canokey_evidence(self):
        entry = {
            "idVendor": MODULE.CANOKEY_USB_VENDOR_ID,
            "idProduct": MODULE.CANOKEY_USB_PRODUCT_ID,
            "USB Vendor Name": MODULE.CANOKEY_USB_MANUFACTURER,
            "USB Product Name": "CanoKey Canary",
            "USB Serial Number": "00989ADF",
            "bcdDevice": 0x0310,
        }
        encoded = plistlib.dumps([entry])
        self.assertEqual(MODULE.parse_usb_devices(encoded), [self.device()])
        del entry["USB Serial Number"]
        with self.assertRaises(MODULE.TargetError):
            MODULE.parse_usb_devices(plistlib.dumps([entry]))


if __name__ == "__main__":
    unittest.main()
