#!/usr/bin/env python3
"""Verify public artifacts from the physical Secure Enclave test with GnuPG."""

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

TEST_ID = "SecureEnclaveDeviceTests/testNativeOpenPGPSigningAndDecryptionUseSecureEnclaveSubkeys()"
ARTIFACT_NAMES = {
    "payload": "payload.bin",
    "public": "public.pgp",
    "detached": "detached.sig",
    "attached": "attached.asc",
    "cleartext": "cleartext.asc",
}
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024


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
        raise RuntimeError("The interoperability evidence must come from a physical iOS device")
    results = []

    def visit(node):
        if node.get("nodeType") == "Test Case" and node.get("nodeIdentifier") == TEST_ID:
            results.append(node.get("result"))
        for child in node.get("children", []):
            visit(child)

    for node in report.get("testNodes", []):
        visit(node)
    if results != ["Passed"]:
        raise RuntimeError(f"The physical evidence-producing test did not pass: {results}")


def collect_attachments(value):
    if isinstance(value, dict):
        if "suggestedHumanReadableName" in value and "exportedFileName" in value:
            yield value
        for child in value.values():
            yield from collect_attachments(child)
    elif isinstance(value, list):
        for child in value:
            yield from collect_attachments(child)


def export_artifacts(result_bundle, root, require_peer=False, require_preparation=False):
    require_passed_physical_test(result_bundle)
    exported = root / "attachments"
    subprocess.run(
        [
            "xcrun", "xcresulttool", "export", "attachments",
            "--path", os.fspath(result_bundle),
            "--test-id", TEST_ID,
            "--output-path", os.fspath(exported),
        ],
        check=True,
    )
    names = dict(ARTIFACT_NAMES)
    if require_peer:
        names.update({
            "gpg-encrypted": "gpg-encrypted.pgp",
            "gpg-signed-encrypted": "gpg-signed-encrypted.pgp",
            "gpg-peer-result": "gpg-peer-result.json",
        })
    if require_preparation:
        names["gpg-peer-preparation"] = "gpg-peer-preparation.json"
    manifest = json.loads((exported / "manifest.json").read_text())
    selected = {}
    for attachment in collect_attachments(manifest):
        suggested = attachment["suggestedHumanReadableName"]
        prefix = suggested.split("_0_", 1)[0]
        if prefix not in names:
            continue
        if prefix in selected:
            raise RuntimeError(f"Duplicate public artifact: {prefix}")
        source = (exported / attachment["exportedFileName"]).resolve()
        source.relative_to(exported.resolve())
        if not source.is_file() or source.stat().st_size > MAX_ARTIFACT_BYTES:
            raise RuntimeError(f"Invalid public artifact size: {prefix}")
        destination = root / names[prefix]
        with source.open("rb") as input_file, destination.open("xb") as output_file:
            shutil.copyfileobj(input_file, output_file)
        selected[prefix] = destination
    missing = names.keys() - selected.keys()
    if missing:
        raise RuntimeError(f"Missing public Secure Enclave artifacts: {sorted(missing)}")
    return selected


class GpgHome:
    def __init__(self, root):
        self.program = shutil.which("gpg")
        if not self.program:
            raise RuntimeError("GnuPG is required for independent verification")
        self.gpgconf = shutil.which("gpgconf")
        self.root = root
        self.home = Path(tempfile.mkdtemp(prefix="addressee-se-gpg-"))
        (self.home / "gpg-agent.conf").write_text("disable-scdaemon\n")
        self.environment = os.environ.copy()
        self.environment.update(GNUPGHOME=os.fspath(self.home), LC_ALL="C")
        self.base = [
            self.program,
            "--no-options",
            "--batch",
            "--yes",
            "--no-tty",
            "--pinentry-mode", "loopback",
            "--no-auto-key-retrieve",
            "--homedir", os.fspath(self.home),
            "--trust-model", "always",
            "--status-fd", "1",
        ]

    def run(self, name, arguments, expected_status=0):
        result = subprocess.run(
            self.base + [os.fspath(argument) for argument in arguments],
            env=self.environment,
            capture_output=True,
        )
        for stream, contents in (("stdout", result.stdout), ("stderr", result.stderr)):
            with (self.root / f"gpg-{name}.{stream}").open("xb") as output:
                output.write(contents)
        if result.returncode != expected_status:
            raise RuntimeError(
                f"GnuPG {name} returned {result.returncode}, expected {expected_status}"
            )
        return result.stdout

    def close(self):
        if self.gpgconf:
            subprocess.run(
                [self.gpgconf, "--homedir", os.fspath(self.home), "--kill", "all"],
                env=self.environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        shutil.rmtree(self.home)


def certificate_fingerprints(gpg, certificate, name):
    shown = gpg.run(name, ["--with-colons", "--show-keys", certificate])
    algorithms = []
    fingerprints = []
    for line in shown.decode("utf-8").splitlines():
        fields = line.split(":")
        if fields[0] in {"pub", "sub"}:
            algorithms.append(int(fields[3]))
        elif fields[0] == "fpr":
            fingerprints.append(fields[9].upper())
    if algorithms != [19, 19, 18] or len(fingerprints) != 3:
        raise RuntimeError("The certificate is not the expected P-256 hybrid certificate")
    return fingerprints


def require_expected_signature(output, fingerprint, operation):
    valid = []
    for line in output.decode("utf-8").splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[:2] == ["[GNUPG:]", "VALIDSIG"]:
            valid.append(fields[2])
    if valid != [fingerprint]:
        raise RuntimeError(f"Unexpected signer in {operation}: {valid}")


def peer_certificate(gpg, root):
    identity = "Secure Enclave Peer <se-peer@example.invalid>"
    config = root / "peer-keygen.conf"
    config.write_text(
        "Key-Type: EDDSA\nKey-Curve: ed25519\nKey-Usage: sign\n"
        "Name-Real: Secure Enclave Peer\nName-Email: se-peer@example.invalid\n"
        "Expire-Date: 0\n%no-protection\n%commit\n"
    )
    gpg.run("generate-peer", ["--generate-key", config])
    public = root / "peer-public.pgp"
    gpg.run("export-peer", ["--output", public, "--export", identity])
    listed = gpg.run("list-peer", ["--with-colons", "--list-keys", identity])
    fingerprints = [
        fields[9].upper()
        for line in listed.decode("utf-8").splitlines()
        if (fields := line.split(":"))[0] == "fpr"
    ]
    if len(fingerprints) != 1 or len(fingerprints[0]) != 40:
        raise RuntimeError("The disposable GnuPG signing certificate is invalid")
    return public, fingerprints[0]


def prepare_peer_messages(root, artifacts):
    gpg = GpgHome(root)
    try:
        recipient, _, encryption = certificate_fingerprints(gpg, artifacts["public"], "show-keys")
        preparation = json.loads(artifacts["gpg-peer-preparation"].read_text())
        if preparation != {
            "schemaVersion": 1,
            "certificateFingerprint": recipient,
            "retainedForGnuPGPeer": True,
            "privateKeyMaterialExported": False,
        }:
            raise RuntimeError("The device did not retain the matching disposable peer key")
        gpg.run("import-recipient", ["--import", artifacts["public"]])
        public, signer = peer_certificate(gpg, root)
        unsigned = root / "peer-unsigned.txt"
        combined = root / "peer-combined.txt"
        unsigned.write_bytes(b"GnuPG to physical Secure Enclave\r\n")
        combined.write_bytes(b"GnuPG signed and encrypted to physical Secure Enclave\r\n")
        encrypted = root / "gpg-encrypted.pgp"
        signed_encrypted = root / "gpg-signed-encrypted.pgp"
        common = ["--no-encrypt-to", "--compress-algo", "none"]
        gpg.run("encrypt-peer", common + [
            "--recipient", encryption + "!", "--output", encrypted, "--encrypt", unsigned,
        ])
        gpg.run("sign-encrypt-peer", common + [
            "--digest-algo", "SHA256",
            "--local-user", signer, "--recipient", encryption + "!",
            "--output", signed_encrypted, "--sign", "--encrypt", combined,
        ])
        fixture = {
            "version": 1,
            "recipientCertificateFingerprint": recipient,
            "encryptionComponentFingerprint": encryption,
            "signerFingerprint": signer,
            "peerPublicCertificate": base64.b64encode(public.read_bytes()).decode("ascii"),
            "unsignedMessage": base64.b64encode(encrypted.read_bytes()).decode("ascii"),
            "unsignedPlaintext": base64.b64encode(unsigned.read_bytes()).decode("ascii"),
            "combinedMessage": base64.b64encode(signed_encrypted.read_bytes()).decode("ascii"),
            "combinedPlaintext": base64.b64encode(combined.read_bytes()).decode("ascii"),
        }
        path = root / "gpg-peer-fixture.json"
        path.write_text(json.dumps(fixture, indent=2) + "\n")
        print(f"GnuPG peer fixture: {path}")
        print("Pass this public fixture to test-secure-enclave-device.sh with GPG_PEER_FIXTURE.")
    finally:
        gpg.close()


def verify(root, artifacts):
    gpg = GpgHome(root)
    try:
        version = gpg.run("version", ["--version"]).decode("utf-8").splitlines()[0]
        _, signing_fingerprint, _ = certificate_fingerprints(gpg, artifacts["public"], "show-keys")
        imported = gpg.run("import", ["--import", artifacts["public"]])
        if b"[GNUPG:] IMPORT_OK 1 " not in imported:
            raise RuntimeError("GnuPG did not import the Secure Enclave certificate")
        checks = []
        for name, arguments in (
            ("verify-detached", ["--verify", artifacts["detached"], artifacts["payload"]]),
            ("verify-attached", ["--verify", artifacts["attached"]]),
            ("verify-cleartext", ["--verify", artifacts["cleartext"]]),
        ):
            output = gpg.run(name, arguments)
            require_expected_signature(output, signing_fingerprint, name)
            checks.append(name)
        tampered = root / "tampered.bin"
        tampered.write_bytes(artifacts["payload"].read_bytes() + b"tampered")
        rejected = gpg.run(
            "reject-tampered",
            ["--verify", artifacts["detached"], tampered],
            expected_status=1,
        )
        if b"[GNUPG:] BADSIG" not in rejected:
            raise RuntimeError("GnuPG did not report BADSIG for the modified payload")
        checks.append("reject-tampered")
        peer = json.loads(artifacts["gpg-peer-result"].read_text())
        expected = {
            "version": 1,
            "recipientCertificateFingerprint": certificate_fingerprints(
                gpg, artifacts["public"], "confirm-certificate"
            )[0],
            "unsignedDecryption": "passed",
            "combinedDecryptionAndVerification": "passed",
        }
        if any(peer.get(key) != value for key, value in expected.items()):
            raise RuntimeError("The physical device did not validate both GnuPG messages")
        if artifacts["gpg-encrypted"].stat().st_size == 0 or artifacts["gpg-signed-encrypted"].stat().st_size == 0:
            raise RuntimeError("A GnuPG message attachment is empty")
        checks.extend(["gpg-encrypt-device-decrypt", "gpg-sign-encrypt-device-decrypt-verify"])
        report = {
            "gpgVersion": version,
            "signingComponentFingerprint": signing_fingerprint,
            "checks": checks,
            "gpgMessageDecryptionBySecureEnclave": "passed",
            "gpgSignedMessageDecryptionAndVerificationBySecureEnclave": "passed",
            "identityTrust": "notEstablished",
        }
        (root / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"{version}: all three physical Secure Enclave signature forms verified.")
        print("A modified payload was rejected by GnuPG.")
        print("The physical Secure Enclave decrypted and verified both GnuPG message forms.")
    finally:
        gpg.close()


def main(arguments):
    usage = "Usage: test-secure-enclave-interoperability.py [--prepare-peer-message] <result-bundle> [new-artifact-directory]"
    prepare = arguments[:1] == ["--prepare-peer-message"]
    if prepare:
        arguments = arguments[1:]
    if len(arguments) not in {1, 2}:
        raise SystemExit(usage)
    result_bundle = Path(arguments[0]).resolve()
    if not result_bundle.is_dir():
        raise SystemExit("The physical test result bundle does not exist")
    if len(arguments) == 2:
        root = Path(arguments[1]).resolve()
    else:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        suffix = "peer" if prepare else "interoperability"
        root = Path(__file__).resolve().parents[1] / "build" / f"secure-enclave-{suffix}-{timestamp}"
    if root.exists():
        raise SystemExit("The artifact directory must not already exist")
    root.mkdir(parents=True)
    os.environ["DEVELOPER_DIR"] = os.environ.get(
        "DEVELOPER_DIR_OVERRIDE", "/Applications/Xcode.app/Contents/Developer"
    )
    artifacts = export_artifacts(
        result_bundle,
        root,
        require_peer=not prepare,
        require_preparation=prepare,
    )
    if prepare:
        prepare_peer_messages(root, artifacts)
    else:
        verify(root, artifacts)
    print(f"Public interoperability evidence: {root}")


if __name__ == "__main__":
    main(sys.argv[1:])
