use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use openpgp_core::{DecryptionStatus, FullFingerprint, RemotePrivateKeyResolver};
use pgp::{
    composed::{Deserializable as _, SignedPublicKey},
    ser::Serialize as _,
};
use thiserror::Error;

use crate::workflow_test::{
    WorkflowError, decrypt_v4_test_message, v4_component_fingerprints,
    verify_detached_test_signature,
};

const MAX_PUBLIC_CERTIFICATE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TEST_MESSAGE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum GpgError {
    #[error("GnuPG test I/O failed: {0}")]
    Io(#[from] io::Error),

    #[error("the public certificate supplied to GnuPG does not match the test certificate")]
    CertificateMismatch,

    #[error("GnuPG failed during {operation}, exit code {exit_code:?}; diagnostics were retained")]
    CommandFailed {
        operation: &'static str,
        exit_code: Option<i32>,
    },

    #[error("GnuPG did not report a valid signature for the expected signing component")]
    SignatureRejected,

    #[error(
        "unexpected embedded signature result: status {status:?}, cryptographic validity {cryptographic_validity:?}, signers {signers:?}, hash algorithms {hash_algorithms:?}"
    )]
    UnexpectedEmbeddedSignature {
        status: DecryptionStatus,
        cryptographic_validity: Vec<Option<bool>>,
        signers: Vec<Option<FullFingerprint>>,
        hash_algorithms: Vec<Option<openpgp_policy::HashAlgorithm>>,
    },

    #[error("GnuPG produced an invalid status response")]
    InvalidStatus,

    #[error("GnuPG decryption status or authenticated payload did not match the expected result")]
    UnexpectedDecryption,

    #[error("public certificate armor must be valid UTF-8")]
    InvalidCertificateEncoding,

    #[error(transparent)]
    Workflow(#[from] WorkflowError),

    #[error("GnuPG certificate parsing failed: {0}")]
    Rpgp(#[from] pgp::errors::Error),
}

pub fn parse_public_certificate(input: &[u8]) -> Result<SignedPublicKey, GpgError> {
    if input.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Ok(SignedPublicKey::from_bytes(input)?);
    }
    let armored = std::str::from_utf8(input).map_err(|_| GpgError::InvalidCertificateEncoding)?;
    Ok(SignedPublicKey::from_string(armored)?.0)
}

pub fn exercise_gpg_interop(
    certificate: &SignedPublicKey,
    public_certificate: &[u8],
    resolver: &dyn RemotePrivateKeyResolver,
    private_key: Option<(&[u8], &str)>,
    artifact_directory: &Path,
    gpg_program: &Path,
) -> Result<(), GpgError> {
    let supplied = parse_public_certificate(public_certificate)?;
    if supplied.to_bytes()? != certificate.to_bytes()? {
        return Err(GpgError::CertificateMismatch);
    }
    let (recipient, signing, _) = v4_component_fingerprints(certificate)?;
    let gpg = GpgHome::new(gpg_program, artifact_directory)?;
    if let Some((protected, password)) = private_key {
        gpg.import_private(protected, password)?;
    }
    let public_path = gpg.write("public.asc", public_certificate)?;
    gpg.success("import", &[OsStr::new("--import"), public_path.as_os_str()])?;

    let payload = artifact_directory.join("payload.bin");
    let detached = artifact_directory.join("payload.bin.sig");
    verify_signature(
        &gpg,
        "verify-detached",
        &[
            OsStr::new("--verify"),
            detached.as_os_str(),
            payload.as_os_str(),
        ],
        &signing,
    )?;
    for (operation, option, name) in [
        ("verify-attached", "--verify", "payload-attached.asc"),
        ("verify-cleartext", "--verify", "cleartext.txt.asc"),
    ] {
        let path = artifact_directory.join(name);
        verify_signature(
            &gpg,
            operation,
            &[OsStr::new(option), path.as_os_str()],
            &signing,
        )?;
    }

    let encrypted_path = artifact_directory.join("gpg-encrypted.asc");
    gpg.success(
        "encrypt",
        &[
            OsStr::new("--armor"),
            OsStr::new("--encrypt"),
            OsStr::new("--recipient"),
            OsStr::new(recipient.as_str()),
            OsStr::new("--output"),
            encrypted_path.as_os_str(),
            payload.as_os_str(),
        ],
    )?;
    let ciphertext = read_bounded(&encrypted_path, MAX_TEST_MESSAGE_BYTES)?;
    let report = decrypt_v4_test_message(certificate, resolver, &ciphertext, &[])?;
    if report.status != DecryptionStatus::Unsigned {
        return Err(GpgError::UnexpectedDecryption);
    }

    if let Some((_, password)) = private_key {
        for (operation, name, signed) in [
            ("decrypt-encrypted", "encrypted.pgp", false),
            ("decrypt-signed-encrypted", "signed-encrypted.pgp", true),
        ] {
            let output = decrypt(
                &gpg,
                operation,
                &artifact_directory.join(name),
                &artifact_directory.join(format!("gpg-{operation}.bin")),
                password,
            )?;
            if signed && !has_valid_signature(&output, signing.as_str()) {
                return Err(GpgError::SignatureRejected);
            }
        }
    }
    exercise_gpg_signed_encryption(&gpg, certificate, resolver, &payload, recipient)
}

fn exercise_gpg_signed_encryption(
    gpg: &GpgHome,
    certificate: &SignedPublicKey,
    resolver: &dyn RemotePrivateKeyResolver,
    payload: &Path,
    recipient: FullFingerprint,
) -> Result<(), GpgError> {
    const USER_ID: &str = "Addressee disposable GnuPG interoperability <interop@example.test>";
    let created = gpg.success(
        "generate-primary",
        &[
            OsStr::new("--pinentry-mode"),
            OsStr::new("loopback"),
            OsStr::new("--passphrase"),
            OsStr::new(""),
            OsStr::new("--quick-generate-key"),
            OsStr::new(USER_ID),
            OsStr::new("ed25519"),
            OsStr::new("cert"),
            OsStr::new("never"),
        ],
    )?;
    let fingerprint = created_fingerprint(&created)?;
    for (operation, algorithm, usage) in [
        ("generate-signing", "ed25519", "sign"),
        ("generate-decryption", "cv25519", "encr"),
    ] {
        gpg.success(
            operation,
            &[
                OsStr::new("--pinentry-mode"),
                OsStr::new("loopback"),
                OsStr::new("--passphrase"),
                OsStr::new(""),
                OsStr::new("--quick-add-key"),
                OsStr::new(&fingerprint),
                OsStr::new(algorithm),
                OsStr::new(usage),
                OsStr::new("never"),
            ],
        )?;
    }
    let expected_certificate =
        FullFingerprint::from_hex(&fingerprint).map_err(|_| GpgError::InvalidStatus)?;
    let public_path = gpg.diagnostics.join("gpg-signer-public.pgp");
    gpg.success(
        "export-signer",
        &[
            OsStr::new("--export"),
            OsStr::new("--output"),
            public_path.as_os_str(),
            OsStr::new(&fingerprint),
        ],
    )?;
    let signer_public = read_bounded(&public_path, MAX_PUBLIC_CERTIFICATE_BYTES)?;
    let signer = SignedPublicKey::from_bytes(signer_public.as_slice())?;
    signer.verify_bindings()?;
    let detached_path = gpg.diagnostics.join("gpg-detached.sig");
    gpg.success(
        "sign-detached",
        &[
            OsStr::new("--digest-algo"),
            OsStr::new("SHA256"),
            OsStr::new("--detach-sign"),
            OsStr::new("--local-user"),
            OsStr::new(&fingerprint),
            OsStr::new("--output"),
            detached_path.as_os_str(),
            payload.as_os_str(),
        ],
    )?;
    let detached = read_bounded(&detached_path, MAX_TEST_MESSAGE_BYTES)?;
    let detached_outcome = verify_detached_test_signature(&detached, &[signer_public.as_slice()])?;
    if detached_outcome.status != openpgp_core::VerificationStatus::Valid
        || detached_outcome.signatures.len() != 1
        || detached_outcome.signatures[0].hash_algorithm
            != Some(openpgp_policy::HashAlgorithm::Sha256)
        || detached_outcome.signatures[0]
            .certificate_fingerprint
            .as_ref()
            != Some(&expected_certificate)
    {
        return Err(GpgError::SignatureRejected);
    }
    let encrypted_path = gpg.diagnostics.join("gpg-signed-encrypted.pgp");
    gpg.success(
        "sign-and-encrypt",
        &[
            OsStr::new("--digest-algo"),
            OsStr::new("SHA256"),
            OsStr::new("--sign"),
            OsStr::new("--encrypt"),
            OsStr::new("--local-user"),
            OsStr::new(&fingerprint),
            OsStr::new("--recipient"),
            OsStr::new(recipient.as_str()),
            OsStr::new("--output"),
            encrypted_path.as_os_str(),
            payload.as_os_str(),
        ],
    )?;
    let ciphertext = read_bounded(&encrypted_path, MAX_TEST_MESSAGE_BYTES)?;
    let report = decrypt_v4_test_message(
        certificate,
        resolver,
        &ciphertext,
        &[signer_public.as_slice()],
    )?;
    if report.status != DecryptionStatus::Valid
        || report.signatures.len() != 1
        || report.signatures[0].hash_algorithm != Some(openpgp_policy::HashAlgorithm::Sha256)
    {
        return Err(GpgError::UnexpectedEmbeddedSignature {
            status: report.status,
            cryptographic_validity: report
                .signatures
                .iter()
                .map(|signature| signature.cryptographically_valid)
                .collect(),
            signers: report
                .signatures
                .iter()
                .map(|signature| signature.signer_fingerprint.clone())
                .collect(),
            hash_algorithms: report
                .signatures
                .iter()
                .map(|signature| signature.hash_algorithm)
                .collect(),
        });
    }
    let signature = &report.signatures[0];
    if signature.signer_fingerprint.is_none()
        || signature.certificate_fingerprint.as_ref() != Some(&expected_certificate)
    {
        return Err(GpgError::SignatureRejected);
    }
    Ok(())
}

fn created_fingerprint(output: &Output) -> Result<String, GpgError> {
    let status = std::str::from_utf8(&output.stdout).map_err(|_| GpgError::InvalidStatus)?;
    status
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next() == Some("[GNUPG:]")
                && fields.next() == Some("KEY_CREATED")
                && matches!(fields.next(), Some("P" | "B"))
            {
                fields.next().map(str::to_owned)
            } else {
                None
            }
        })
        .ok_or(GpgError::InvalidStatus)
}

fn decrypt(
    gpg: &GpgHome,
    operation: &'static str,
    ciphertext: &Path,
    plaintext: &Path,
    password: &str,
) -> Result<Output, GpgError> {
    let output = gpg.success_with_input(
        operation,
        &[
            OsStr::new("--pinentry-mode"),
            OsStr::new("loopback"),
            OsStr::new("--passphrase-fd"),
            OsStr::new("0"),
            OsStr::new("--decrypt"),
            OsStr::new("--output"),
            plaintext.as_os_str(),
            ciphertext.as_os_str(),
        ],
        password.as_bytes(),
    )?;
    if !has_status(&output, "DECRYPTION_OKAY")
        || read_bounded(plaintext, MAX_TEST_MESSAGE_BYTES)? != crate::workflow_test::TEST_PAYLOAD
    {
        return Err(GpgError::UnexpectedDecryption);
    }
    Ok(output)
}

fn has_status(output: &Output, name: &str) -> bool {
    output.stdout.split(|byte| *byte == b'\n').any(|line| {
        let mut fields = line.split(|byte| byte.is_ascii_whitespace());
        fields.next() == Some(b"[GNUPG:]".as_slice()) && fields.next() == Some(name.as_bytes())
    })
}

fn has_valid_signature(output: &Output, expected: &str) -> bool {
    output.stdout.split(|byte| *byte == b'\n').any(|line| {
        let Ok(line) = std::str::from_utf8(line) else {
            return false;
        };
        let mut fields = line.split_whitespace();
        fields.next() == Some("[GNUPG:]")
            && fields.next() == Some("VALIDSIG")
            && fields
                .next()
                .is_some_and(|fingerprint| fingerprint.eq_ignore_ascii_case(expected))
    })
}

fn verify_signature(
    gpg: &GpgHome,
    operation: &'static str,
    arguments: &[&OsStr],
    expected: &FullFingerprint,
) -> Result<(), GpgError> {
    let output = gpg.success(operation, arguments)?;
    if has_valid_signature(&output, expected.as_str()) {
        Ok(())
    } else {
        Err(GpgError::SignatureRejected)
    }
}

pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, GpgError> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input exceeds the test size limit",
        )
        .into());
    }
    Ok(bytes)
}

pub fn read_public_certificate(path: &Path) -> Result<Vec<u8>, GpgError> {
    read_bounded(path, MAX_PUBLIC_CERTIFICATE_BYTES)
}

struct GpgHome {
    path: PathBuf,
    program: PathBuf,
    gpgconf: PathBuf,
    diagnostics: PathBuf,
}

impl GpgHome {
    fn new(program: &Path, diagnostics: &Path) -> Result<Self, GpgError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        #[cfg(unix)]
        let base = PathBuf::from("/tmp");
        #[cfg(not(unix))]
        let base = std::env::temp_dir();
        let path = base.join(format!("oc-card-{}-{nonce}", std::process::id()));
        fs::create_dir(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
        let gpgconf = program
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(|parent| parent.join("gpgconf"))
            .unwrap_or_else(|| PathBuf::from("gpgconf"));
        let mut agent_configuration = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path.join("gpg-agent.conf"))?;
        agent_configuration.write_all(b"disable-scdaemon\n")?;
        agent_configuration.sync_all()?;
        drop(agent_configuration);
        Ok(Self {
            path,
            program: program.to_owned(),
            gpgconf,
            diagnostics: diagnostics.to_owned(),
        })
    }

    fn write(&self, name: &str, contents: &[u8]) -> Result<PathBuf, GpgError> {
        let path = self.path.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        Ok(path)
    }

    fn import_private(&self, protected: &[u8], password: &str) -> Result<(), GpgError> {
        let path = self.path.join("protected-recipient-key.pgp");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        file.write_all(protected)?;
        file.sync_all()?;
        drop(file);
        let result = self.success_with_input(
            "import-private",
            &[
                OsStr::new("--pinentry-mode"),
                OsStr::new("loopback"),
                OsStr::new("--passphrase-fd"),
                OsStr::new("0"),
                OsStr::new("--import"),
                path.as_os_str(),
            ],
            password.as_bytes(),
        );
        let cleanup = fs::remove_file(&path);
        result?;
        cleanup?;
        Ok(())
    }

    fn success(&self, operation: &'static str, arguments: &[&OsStr]) -> Result<Output, GpgError> {
        self.run(operation, arguments, None)
    }

    fn success_with_input(
        &self,
        operation: &'static str,
        arguments: &[&OsStr],
        input: &[u8],
    ) -> Result<Output, GpgError> {
        self.run(operation, arguments, Some(input))
    }

    fn run(
        &self,
        operation: &'static str,
        arguments: &[&OsStr],
        input: Option<&[u8]>,
    ) -> Result<Output, GpgError> {
        let mut command = Command::new(&self.program);
        command
            .arg("--no-options")
            .arg("--batch")
            .arg("--yes")
            .arg("--no-tty")
            .arg("--status-fd")
            .arg("1")
            .arg("--homedir")
            .arg(&self.path)
            .arg("--trust-model")
            .arg("always")
            .args(arguments)
            .env("GNUPGHOME", &self.path)
            .env("LC_ALL", "C")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = if let Some(input) = input {
            let mut child = command.stdin(Stdio::piped()).spawn()?;
            if let Some(mut stdin) = child.stdin.take()
                && let Err(error) = stdin.write_all(input)
            {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
            child.wait_with_output()?
        } else {
            command.stdin(Stdio::null()).output()?
        };
        for (stream, contents) in [
            ("stdout", output.stdout.as_slice()),
            ("stderr", output.stderr.as_slice()),
        ] {
            let path = self.diagnostics.join(format!("gpg-{operation}.{stream}"));
            let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
            file.write_all(contents)?;
            file.sync_all()?;
        }
        if output.status.success() {
            Ok(output)
        } else {
            Err(GpgError::CommandFailed {
                operation,
                exit_code: output.status.code(),
            })
        }
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        let _ = Command::new(&self.gpgconf)
            .arg("--homedir")
            .arg(&self.path)
            .arg("--kill")
            .arg("all")
            .env("GNUPGHOME", &self.path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use openpgp_policy::GenerationProfile;

    use super::*;
    use crate::hardware_test::DisposableCertificate;

    #[test]
    fn public_certificate_parser_accepts_binary_and_ascii_armor() {
        let certificate = DisposableCertificate::generate(&GenerationProfile::nist_p256_v4())
            .expect("disposable certificate");
        let expected = certificate
            .public_certificate()
            .expect("public certificate");
        for encoded in [
            expected.to_bytes().expect("binary public certificate"),
            certificate
                .public_armor()
                .expect("armored public certificate"),
        ] {
            let parsed = parse_public_certificate(&encoded).expect("supported public encoding");
            parsed
                .verify_bindings()
                .expect("valid certificate bindings");
            assert_eq!(parsed, expected);
        }
    }
}
