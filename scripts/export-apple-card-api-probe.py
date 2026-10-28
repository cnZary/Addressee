#!/usr/bin/env python3
"""Export and validate read-only Apple smart card API observations."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

TEST_ID = "AppleSmartCardDeviceTests/testReadOnlyTransportAvailability()"
ARTIFACT_PREFIX = "apple-card-api-probe_0_"


def require_passed_physical_test(result_bundle):
    completed = subprocess.run(
        [
            "xcrun", "xcresulttool", "get", "test-results", "tests",
            "--path", os.fspath(result_bundle),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    report = json.loads(completed.stdout)
    devices = report.get("devices", [])
    if not devices or any(device.get("platform") != "iOS" for device in devices):
        raise RuntimeError("The API observation must come from a physical iOS device")
    results = []

    def visit(node):
        if node.get("nodeType") == "Test Case" and node.get("nodeIdentifier") == TEST_ID:
            results.append(node.get("result"))
        for child in node.get("children", []):
            visit(child)

    for node in report.get("testNodes", []):
        visit(node)
    if results != ["Passed"]:
        raise RuntimeError(f"The read-only API observation did not pass: {results}")


def main(arguments):
    if len(arguments) != 2:
        raise SystemExit("Usage: export-apple-card-api-probe.py <result-bundle> <new-output-directory>")
    result_bundle = Path(arguments[0]).resolve()
    output = Path(arguments[1]).resolve()
    if not result_bundle.is_dir() or output.exists():
        raise SystemExit("The result bundle must exist and the output directory must be new")
    os.environ["DEVELOPER_DIR"] = os.environ.get(
        "DEVELOPER_DIR_OVERRIDE", "/Applications/Xcode.app/Contents/Developer"
    )
    require_passed_physical_test(result_bundle)
    subprocess.run(
        [
            "xcrun", "xcresulttool", "export", "attachments",
            "--path", os.fspath(result_bundle), "--test-id", TEST_ID,
            "--output-path", os.fspath(output),
        ],
        check=True,
    )
    manifest = json.loads((output / "manifest.json").read_text())
    selected = []
    for suite in manifest:
        if suite.get("testIdentifier") != TEST_ID:
            continue
        for attachment in suite.get("attachments", []):
            if attachment.get("suggestedHumanReadableName", "").startswith(ARTIFACT_PREFIX):
                selected.append(attachment)
    if len(selected) != 1:
        raise RuntimeError("The physical test must export exactly one read-only API observation")
    source = (output / selected[0]["exportedFileName"]).resolve()
    source.relative_to(output)
    if not source.is_file() or source.stat().st_size > 64 * 1024:
        raise RuntimeError("The API observation is missing or too large")
    report = json.loads(source.read_text())
    if report.get("schemaVersion") != 1:
        raise RuntimeError("The API observation schema is unsupported")
    if report.get("observationOnly") is not True:
        raise RuntimeError("The test did not establish its read-only scope")
    if report.get("nfcSessionStarted") is not False or report.get("apduTransmitted") is not False:
        raise RuntimeError("The observation attempted a card session or APDU")
    for name in ("nfcReaderAvailable", "cryptoTokenKitManagerAvailable"):
        if type(report.get(name)) is not bool:
            raise RuntimeError(f"Missing boolean observation: {name}")
    if "readerNames" not in report and "readerError" not in report:
        raise RuntimeError("The CryptoTokenKit reader enumeration outcome is missing")
    if "readerNames" in report:
        readers = report["readerNames"]
        if not isinstance(readers, list) or not all(isinstance(name, str) for name in readers):
            raise RuntimeError("The reader list is malformed")
        if report.get("readerCount") != len(readers):
            raise RuntimeError("The reader count is inconsistent")
    shutil.copyfile(source, output / "probe.json")
    (output / "probe.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    print("These are API observations only; no NFC or USB card operation is claimed.")
    print(f"Read-only API evidence: {output}")


if __name__ == "__main__":
    main(sys.argv[1:])
