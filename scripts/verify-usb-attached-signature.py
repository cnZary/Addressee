#!/usr/bin/env python3
import base64
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def run_gpg(gpg, home, arguments, **kwargs):
    return subprocess.run(
        [
            gpg,
            "--no-options",
            "--batch",
            "--yes",
            "--no-tty",
            "--no-autostart",
            "--no-auto-key-retrieve",
            "--homedir",
            str(home),
            "--trust-model",
            "always",
            *arguments,
        ],
        check=False,
        capture_output=True,
        **kwargs,
    )


def status_lines(result):
    return (result.stdout + b"\n" + result.stderr).decode("utf-8", errors="replace")


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: verify-usb-attached-signature.py FIXTURE EVIDENCE_DIRECTORY")
    fixture_path = Path(sys.argv[1])
    evidence = Path(sys.argv[2])
    fixture = json.loads(fixture_path.read_text())
    certificate = base64.b64decode(fixture["publicCertificate"], validate=True)
    signer = fixture["signingComponent"]
    if not isinstance(signer, str) or len(signer) != 40:
        raise SystemExit("The attached-signature fixture has no valid signing component")
    payload = (evidence / "payload.bin").read_bytes()
    message = evidence / "attached-message.pgp"
    tampered = evidence / "tampered-attached-message.pgp"
    for path in (message, tampered):
        if not path.is_file() or not 0 < path.stat().st_size <= 16 * 1024 * 1024:
            raise SystemExit(f"Missing or oversized attached-signature artifact: {path.name}")
    gpg = shutil.which("gpg")
    if gpg is None:
        raise SystemExit("GnuPG is required for independent attached-signature verification")

    with tempfile.TemporaryDirectory(prefix="addressee-usb-attached-gpg-") as temporary:
        home = Path(temporary)
        home.chmod(0o700)
        (home / "gpg-agent.conf").write_text("disable-scdaemon\n")
        imported = run_gpg(gpg, home, ["--import", "-"], input=certificate)
        if imported.returncode != 0:
            raise SystemExit("GnuPG could not import the public card certificate")

        recovered = home / "recovered.bin"
        verified = run_gpg(
            gpg,
            home,
            ["--status-fd", "1", "--output", str(recovered), "--verify", str(message)],
        )
        valid_output = status_lines(verified)
        (evidence / "gpg-valid-status.txt").write_text(valid_output)
        valid_signers = [
            line.split()[2]
            for line in valid_output.splitlines()
            if len(line.split()) >= 3 and line.split()[:2] == ["[GNUPG:]", "VALIDSIG"]
        ]
        if verified.returncode != 0 or valid_signers != [signer]:
            raise SystemExit("GnuPG did not validate the expected attached-signature component")
        if not recovered.is_file() or recovered.read_bytes() != payload:
            raise SystemExit("GnuPG did not recover the exact attached-signature payload")

        rejected = run_gpg(
            gpg,
            home,
            [
                "--status-fd",
                "1",
                "--output",
                str(home / "rejected.bin"),
                "--verify",
                str(tampered),
            ],
        )
        rejected_output = status_lines(rejected)
        (evidence / "gpg-tampered-status.txt").write_text(rejected_output)
        if rejected.returncode == 0 or "[GNUPG:] BADSIG" not in rejected_output:
            raise SystemExit("GnuPG did not reject the tampered attached message with BADSIG")

    version = subprocess.run(
        [gpg, "--version"], check=True, capture_output=True, text=True
    ).stdout.splitlines()[0]
    report = {
        "schemaVersion": 1,
        "implementation": version,
        "signatureContainer": "attached",
        "goodSignature": True,
        "exactPlaintextRecovered": True,
        "tamperedArtifactRejected": True,
        "signerFingerprint": signer,
        "identityTrust": "notEstablished",
    }
    (evidence / "gpg-verification.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
