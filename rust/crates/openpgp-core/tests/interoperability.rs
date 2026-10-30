#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use openpgp_core::{
    AeadMode, EncryptionConfig, ExportFormat, MessageCipher, MessageError, MessageFormat,
    MessageService, PrivateExportPolicy, SoftwareKeyStore, VerificationStatus,
};
use openpgp_policy::{
    Algorithm, CompatibilityAcknowledgement, GenerationProfile, Operation, SecurityPolicy,
};
use pgp::types::Timestamp;

const PASSWORD: &str = "old correct horse battery staple";
const NEW_PASSWORD: &str = "new correct horse battery staple";
static HOME_COUNTER: AtomicU64 = AtomicU64::new(0);

type TestResult = Result<(), String>;

#[test]
fn rsa_2048_bidirectional() -> TestResult {
    application_to_gpg(rsa_profile(Algorithm::Rsa2048))?;
    gpg_to_application(GpgProfile::Rsa(2048))
}

#[test]
fn rsa_3072_bidirectional() -> TestResult {
    application_to_gpg(rsa_profile(Algorithm::Rsa3072))?;
    gpg_to_application(GpgProfile::Rsa(3072))
}

#[test]
fn rsa_4096_bidirectional() -> TestResult {
    application_to_gpg(rsa_profile(Algorithm::Rsa4096))?;
    gpg_to_application(GpgProfile::Rsa(4096))
}

#[test]
fn nist_p256_bidirectional() -> TestResult {
    application_to_gpg(GenerationProfile::nist_p256_v4())?;
    gpg_to_application(GpgProfile::NistP256)
}

#[test]
fn nist_p384_bidirectional() -> TestResult {
    application_to_gpg(GenerationProfile::nist_p384_v4())?;
    gpg_to_application(GpgProfile::NistP384)
}

#[test]
fn nist_p521_bidirectional() -> TestResult {
    application_to_gpg(GenerationProfile::nist_p521_v4())?;
    gpg_to_application(GpgProfile::NistP521)
}

#[test]
fn legacy_curve25519_bidirectional() -> TestResult {
    application_to_gpg(
        GenerationProfile::legacy_curve25519_v4(CompatibilityAcknowledgement::acknowledged())
            .unwrap(),
    )?;
    gpg_to_application(GpgProfile::LegacyCurve25519)
}

#[test]
fn imported_dsa_and_elgamal_operations_fail_closed() -> TestResult {
    let home = GpgHome::new()?;
    let user_id = "Legacy Policy <legacy@example.test>";
    home.success(
        &[
            "--passphrase",
            "",
            "--quick-generate-key",
            user_id,
            "rsa2048",
            "cert",
            "never",
        ],
        None,
    )?;
    let listing = home.success(&["--with-colons", "--list-secret-keys", user_id], None)?;
    let fingerprint = String::from_utf8_lossy(&listing.stdout)
        .lines()
        .find(|line| line.starts_with("fpr:"))
        .and_then(|line| line.split(':').nth(9))
        .filter(|fingerprint| fingerprint.len() == 40)
        .ok_or_else(|| "GnuPG did not return the legacy test fingerprint".to_owned())?
        .to_owned();
    for (algorithm, usage) in [("dsa2048", "sign"), ("elg2048", "encrypt")] {
        home.success(
            &[
                "--passphrase",
                "",
                "--quick-add-key",
                &fingerprint,
                algorithm,
                usage,
                "never",
            ],
            None,
        )?;
    }
    let private_path = home.path.join("legacy-private.asc");
    home.success(
        &[
            "--output",
            path_str(&private_path)?,
            "--armor",
            "--export-secret-keys",
            user_id,
        ],
        None,
    )?;
    let private = fs::read(&private_path).map_err(|error| error.to_string())?;
    let mut store = SoftwareKeyStore::new();
    let imported = store
        .import_private(&private, None, NEW_PASSWORD, PrivateExportPolicy::Allowed)
        .map_err(|error| format!("legacy private-key import failed: {error}"))?;
    for algorithm in [Algorithm::Dsa, Algorithm::ElGamal] {
        if !imported
            .metadata
            .subkeys
            .iter()
            .any(|key| key.algorithm.policy_algorithm == Some(algorithm))
        {
            return Err(format!("imported certificate is missing {algorithm:?}"));
        }
    }
    let fingerprint = imported.metadata.fingerprint;
    let service = MessageService::new(&store, SecurityPolicy::default());
    let now = evaluation_time();
    let payload = b"legacy algorithm policy payload\r\n";
    match service.sign_detached(
        &fingerprint,
        NEW_PASSWORD,
        now,
        &payload[..],
        Vec::new(),
        MessageFormat::Binary,
    ) {
        Err(MessageError::CapabilityDisabled {
            algorithm: Algorithm::Dsa,
            operation: Operation::Sign,
            ..
        }) => {}
        other => return Err(format!("DSA signing was not policy-rejected: {other:?}")),
    }

    let data_path = home.write("legacy-payload.bin", payload)?;
    let detached_path = home.path.join("legacy-detached.sig");
    home.success(
        &[
            "--local-user",
            fingerprint.as_str(),
            "--detach-sign",
            "--output",
            path_str(&detached_path)?,
            path_str(&data_path)?,
        ],
        None,
    )?;
    let detached = fs::read(&detached_path).map_err(|error| error.to_string())?;
    let verified = service
        .verify_detached(&payload[..], &detached, now)
        .map_err(|error| format!("legacy detached verification failed: {error}"))?;
    if verified.status != VerificationStatus::Invalid
        || verified.signatures.len() != 1
        || !verified.signatures[0].capability_rejected
        || verified.signatures[0].cryptographically_valid.is_some()
    {
        return Err(format!(
            "DSA verification did not fail closed before cryptographic evaluation: {verified:?}"
        ));
    }

    let mut encrypted = Vec::new();
    match service.encrypt(
        std::slice::from_ref(&fingerprint),
        now,
        EncryptionConfig::SeipdV1 {
            cipher: MessageCipher::Aes256,
        },
        &payload[..],
        &mut encrypted,
        MessageFormat::Binary,
    ) {
        Err(MessageError::CapabilityDisabled {
            algorithm: Algorithm::ElGamal,
            operation: Operation::Encrypt,
            ..
        }) => {}
        other => {
            return Err(format!(
                "ElGamal encryption was not policy-rejected: {other:?}"
            ));
        }
    }
    if !encrypted.is_empty() {
        return Err("policy-rejected ElGamal encryption produced an artifact".into());
    }

    let encrypted_path = home.path.join("legacy-encrypted.pgp");
    home.success(
        &[
            "--trust-model",
            "always",
            "--encrypt",
            "--recipient",
            fingerprint.as_str(),
            "--output",
            path_str(&encrypted_path)?,
            path_str(&data_path)?,
        ],
        None,
    )?;
    let encrypted = fs::read(&encrypted_path).map_err(|error| error.to_string())?;
    match service.decrypt(
        &fingerprint,
        NEW_PASSWORD,
        now,
        std::io::Cursor::new(&encrypted),
    ) {
        Err(MessageError::CapabilityDisabled {
            algorithm: Algorithm::ElGamal,
            operation: Operation::Decrypt,
            ..
        }) => Ok(()),
        other => Err(format!(
            "ElGamal decryption was not policy-rejected: {other:?}"
        )),
    }
}

#[ignore = "GnuPG 2.5.24 rejects native v6 Ed25519 with public-key algorithm 27 during public import"]
#[test]
fn modern_v6_application_to_gpg() -> TestResult {
    application_to_gpg(GenerationProfile::modern_v6())
}

#[ignore = "GnuPG 2.5.24 rejects Ed448/X448 with public-key algorithm 28 during public import"]
#[test]
fn curve448_application_to_gpg() -> TestResult {
    application_to_gpg(GenerationProfile::curve448_v6())
}

fn application_to_gpg(profile: GenerationProfile) -> TestResult {
    let home = GpgHome::new()?;
    let mut store = SoftwareKeyStore::new();
    let generated = store
        .generate(
            &profile,
            "Application Interop <application@example.test>",
            PASSWORD,
            PrivateExportPolicy::Allowed,
        )
        .map_err(|error| format!("application key generation failed: {error}"))?;
    let fingerprint = generated.metadata.fingerprint;
    let service = MessageService::new(&store, SecurityPolicy::default());
    let now = evaluation_time();
    let public = store
        .export_public(&fingerprint, ExportFormat::Armored)
        .map_err(|error| error.to_string())?;
    let private = store
        .export_private(&fingerprint, ExportFormat::Armored)
        .map_err(|error| error.to_string())?;
    let public_path = home.write("application-public.asc", &public)?;
    let private_path = home.write("application-private.asc", &private)?;
    let data_path = home.write("payload.bin", b"application to GnuPG\r\n")?;
    home.success(&["--import", path_str(&public_path)?], None)?;

    let mut detached = Vec::new();
    service
        .sign_detached(
            &fingerprint,
            PASSWORD,
            now,
            &b"application to GnuPG\r\n"[..],
            &mut detached,
            MessageFormat::Armored,
        )
        .map_err(|error| format!("application detached signing failed: {error}"))?;
    let detached_path = home.write("application-detached.sig", &detached)?;
    home.success(
        &["--verify", path_str(&detached_path)?, path_str(&data_path)?],
        None,
    )?;

    let mut attached = Vec::new();
    service
        .sign_attached(
            &fingerprint,
            PASSWORD,
            now,
            &b"application to GnuPG\r\n"[..],
            &mut attached,
            MessageFormat::Armored,
        )
        .map_err(|error| format!("application attached signing failed: {error}"))?;
    let attached_path = home.write("application-attached.asc", &attached)?;
    home.success(&["--verify", path_str(&attached_path)?], None)?;

    let mut cleartext = Vec::new();
    service
        .sign_cleartext(
            &fingerprint,
            PASSWORD,
            now,
            "application to GnuPG\n",
            &mut cleartext,
        )
        .map_err(|error| format!("application cleartext signing failed: {error}"))?;
    let cleartext_path = home.write("application-cleartext.asc", &cleartext)?;
    home.success(&["--verify", path_str(&cleartext_path)?], None)?;

    home.success(
        &["--import", "--passphrase-fd", "0", path_str(&private_path)?],
        Some(format!("{PASSWORD}\n").as_bytes()),
    )?;
    let agent_signature_path = home.path.join("agent-signing-check.sig");
    home.success(
        &[
            "--detach-sign",
            "--local-user",
            fingerprint.as_str(),
            "--output",
            path_str(&agent_signature_path)?,
            "--passphrase-fd",
            "0",
            path_str(&data_path)?,
        ],
        Some(format!("{PASSWORD}\n{PASSWORD}\n{PASSWORD}\n").as_bytes()),
    )?;
    let config = peer_encryption_config(&profile);
    let mut encrypted = Vec::new();
    service
        .encrypt(
            std::slice::from_ref(&fingerprint),
            now,
            config,
            &b"application encrypted payload"[..],
            &mut encrypted,
            MessageFormat::Binary,
        )
        .map_err(|error| format!("application encryption failed: {error}"))?;
    let encrypted_path = home.write("application-encrypted.pgp", &encrypted)?;
    let plaintext_path = home.path.join("application-plaintext.bin");
    home.success(
        &[
            "--decrypt",
            "--output",
            path_str(&plaintext_path)?,
            "--passphrase-fd",
            "0",
            path_str(&encrypted_path)?,
        ],
        Some(format!("{PASSWORD}\n{PASSWORD}\n{PASSWORD}\n").as_bytes()),
    )?;
    let plaintext = fs::read(&plaintext_path).map_err(|error| error.to_string())?;
    if plaintext != b"application encrypted payload" {
        return Err("GnuPG returned different encrypt-only plaintext".into());
    }

    let mut signed_encrypted = Vec::new();
    service
        .sign_and_encrypt(
            openpgp_core::SigningKeyRequest::new(&fingerprint, PASSWORD),
            openpgp_core::EncryptionRequest::new(std::slice::from_ref(&fingerprint), now, config),
            &b"application signed encrypted payload"[..],
            &mut signed_encrypted,
            MessageFormat::Binary,
        )
        .map_err(|error| format!("application sign+encrypt failed: {error}"))?;
    let signed_encrypted_path =
        home.write("application-signed-encrypted.pgp", &signed_encrypted)?;
    let signed_plaintext_path = home.path.join("application-signed-plaintext.bin");
    let verification = home.success(
        &[
            "--decrypt",
            "--output",
            path_str(&signed_plaintext_path)?,
            "--passphrase-fd",
            "0",
            path_str(&signed_encrypted_path)?,
        ],
        Some(format!("{PASSWORD}\n{PASSWORD}\n{PASSWORD}\n").as_bytes()),
    )?;
    let plaintext = fs::read(&signed_plaintext_path).map_err(|error| error.to_string())?;
    if plaintext != b"application signed encrypted payload" {
        return Err("GnuPG returned different sign+encrypt plaintext".into());
    }
    let stderr = String::from_utf8_lossy(&verification.stderr);
    if !stderr.contains("Good signature") {
        return Err(format!(
            "GnuPG did not report a good embedded signature: {stderr}"
        ));
    }
    Ok(())
}

fn gpg_to_application(profile: GpgProfile) -> TestResult {
    let home = GpgHome::new()?;
    let keygen_path = home.write("peer-keygen.conf", profile.keygen().as_bytes())?;
    home.success(&["--generate-key", path_str(&keygen_path)?], None)?;
    let public_path = home.path.join("peer-public.asc");
    let private_path = home.path.join("peer-private.asc");
    home.success(
        &[
            "--output",
            path_str(&public_path)?,
            "--armor",
            "--export",
            "Peer Interop <peer@example.test>",
        ],
        None,
    )?;
    home.success(
        &[
            "--output",
            path_str(&private_path)?,
            "--armor",
            "--export-secret-keys",
            "Peer Interop <peer@example.test>",
        ],
        None,
    )?;

    let private = fs::read(&private_path).map_err(|error| error.to_string())?;
    let mut store = SoftwareKeyStore::new();
    let imported = store
        .import_private(&private, None, NEW_PASSWORD, PrivateExportPolicy::Allowed)
        .map_err(|error| format!("application peer-key import failed: {error}"))?;
    let fingerprint = imported.metadata.fingerprint;
    let service = MessageService::new(&store, SecurityPolicy::default());
    let data_path = home.write("peer-payload.bin", b"GnuPG to application\r\n")?;

    let detached_path = home.path.join("peer-detached.sig");
    home.success(
        &[
            "--detach-sign",
            "--output",
            path_str(&detached_path)?,
            path_str(&data_path)?,
        ],
        None,
    )?;
    let detached = fs::read(&detached_path).map_err(|error| error.to_string())?;
    let verified = service
        .verify_detached(
            &b"GnuPG to application\r\n"[..],
            &detached,
            evaluation_time(),
        )
        .map_err(|error| format!("application detached verification failed: {error}"))?;
    if verified.status != openpgp_core::VerificationStatus::Valid {
        return Err(format!(
            "application rejected GnuPG detached signature: {verified:?}"
        ));
    }

    let attached_path = home.path.join("peer-attached.pgp");
    home.success(
        &[
            "--sign",
            "--output",
            path_str(&attached_path)?,
            path_str(&data_path)?,
        ],
        None,
    )?;
    let attached = fs::read(&attached_path).map_err(|error| error.to_string())?;
    let mut plaintext = Vec::new();
    let verified = service
        .verify_attached(
            std::io::Cursor::new(&attached),
            &mut plaintext,
            evaluation_time(),
        )
        .map_err(|error| format!("application attached verification failed: {error}"))?;
    if verified.status != openpgp_core::VerificationStatus::Valid
        || plaintext != b"GnuPG to application\r\n"
    {
        return Err(format!(
            "application rejected GnuPG attached signature: {verified:?}"
        ));
    }

    let cleartext_path = home.path.join("peer-cleartext.asc");
    home.success(
        &[
            "--clearsign",
            "--output",
            path_str(&cleartext_path)?,
            path_str(&data_path)?,
        ],
        None,
    )?;
    let cleartext = fs::read(&cleartext_path).map_err(|error| error.to_string())?;
    let verified = service
        .verify_cleartext(&cleartext, evaluation_time())
        .map_err(|error| format!("application cleartext verification failed: {error}"))?;
    if verified.outcome.status != openpgp_core::VerificationStatus::Valid {
        return Err(format!(
            "application rejected GnuPG cleartext signature: {verified:?}"
        ));
    }

    let encrypted_path = home.path.join("peer-encrypted.pgp");
    home.success(
        &[
            "--trust-model",
            "always",
            "--encrypt",
            "--recipient",
            fingerprint.as_str(),
            "--output",
            path_str(&encrypted_path)?,
            path_str(&data_path)?,
        ],
        None,
    )?;
    let encrypted = fs::read(&encrypted_path).map_err(|error| error.to_string())?;
    let decrypted = service
        .decrypt(
            &fingerprint,
            NEW_PASSWORD,
            evaluation_time(),
            std::io::Cursor::new(&encrypted),
        )
        .map_err(|error| format!("application decryption failed: {error}"))?;
    if decrypted.report.status != openpgp_core::DecryptionStatus::Unsigned
        || decrypted.plaintext.as_deref() != Some(&b"GnuPG to application\r\n"[..])
    {
        return Err(format!(
            "application rejected GnuPG encryption: {decrypted:?}"
        ));
    }

    let signed_encrypted_path = home.path.join("peer-signed-encrypted.pgp");
    home.success(
        &[
            "--trust-model",
            "always",
            "--sign",
            "--encrypt",
            "--recipient",
            fingerprint.as_str(),
            "--output",
            path_str(&signed_encrypted_path)?,
            path_str(&data_path)?,
        ],
        None,
    )?;
    let signed_encrypted = fs::read(&signed_encrypted_path).map_err(|error| error.to_string())?;
    let decrypted = service
        .decrypt(
            &fingerprint,
            NEW_PASSWORD,
            evaluation_time(),
            std::io::Cursor::new(&signed_encrypted),
        )
        .map_err(|error| format!("application sign+encrypt decryption failed: {error}"))?;
    if decrypted.report.status != openpgp_core::DecryptionStatus::Valid
        || decrypted.plaintext.as_deref() != Some(&b"GnuPG to application\r\n"[..])
    {
        return Err(format!(
            "application rejected GnuPG sign+encrypt: {decrypted:?}"
        ));
    }
    Ok(())
}

fn rsa_profile(algorithm: Algorithm) -> GenerationProfile {
    GenerationProfile::legacy_rsa_v4(algorithm, CompatibilityAcknowledgement::acknowledged())
        .unwrap()
}

fn peer_encryption_config(profile: &GenerationProfile) -> EncryptionConfig {
    match profile.key_version {
        openpgp_policy::KeyVersion::V4 => EncryptionConfig::SeipdV1 {
            cipher: MessageCipher::Aes256,
        },
        openpgp_policy::KeyVersion::V6 => EncryptionConfig::SeipdV2 {
            cipher: MessageCipher::Aes256,
            mode: AeadMode::Ocb,
        },
    }
}

fn evaluation_time() -> u64 {
    u64::from(Timestamp::now().as_secs())
}

#[derive(Clone, Copy)]
enum GpgProfile {
    Rsa(u16),
    NistP256,
    NistP384,
    NistP521,
    LegacyCurve25519,
}

impl GpgProfile {
    fn keygen(self) -> String {
        let algorithm = match self {
            Self::Rsa(bits) => {
                format!(
                    "Key-Type: RSA\nKey-Length: {bits}\nSubkey-Type: RSA\nSubkey-Length: {bits}\n"
                )
            }
            Self::NistP256 => {
                "Key-Type: ECDSA\nKey-Curve: nistp256\nSubkey-Type: ECDH\nSubkey-Curve: nistp256\n"
                    .to_owned()
            }
            Self::NistP384 => {
                "Key-Type: ECDSA\nKey-Curve: nistp384\nSubkey-Type: ECDH\nSubkey-Curve: nistp384\n"
                    .to_owned()
            }
            Self::NistP521 => {
                "Key-Type: ECDSA\nKey-Curve: nistp521\nSubkey-Type: ECDH\nSubkey-Curve: nistp521\n"
                    .to_owned()
            }
            Self::LegacyCurve25519 => {
                "Key-Type: EDDSA\nKey-Curve: ed25519\nSubkey-Type: ECDH\nSubkey-Curve: cv25519\n"
                    .to_owned()
            }
        };
        format!(
            "{algorithm}Name-Real: Peer Interop\nName-Email: peer@example.test\nExpire-Date: 0\n%no-protection\n%commit\n"
        )
    }
}

struct GpgHome {
    path: PathBuf,
}

impl GpgHome {
    fn new() -> Result<Self, String> {
        let counter = HOME_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos();
        let path =
            PathBuf::from("/tmp").join(format!("oc-i-{}-{counter}-{nanos}", std::process::id(),));
        fs::create_dir(&path).map_err(|error| error.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
            let mode = fs::metadata(&path)
                .map_err(|error| error.to_string())?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o700 {
                return Err(format!(
                    "temporary GNUPGHOME has mode {mode:o}, expected 700"
                ));
            }
        }
        let home = Self { path };
        fs::write(home.path.join("gpg-agent.conf"), b"disable-scdaemon\n")
            .map_err(|error| format!("failed to isolate the temporary GnuPG agent: {error}"))?;
        Ok(home)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
        let path = self.path.join(name);
        fs::write(&path, bytes).map_err(|error| error.to_string())?;
        Ok(path)
    }

    fn success(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, String> {
        eprintln!("gpg {args:?}");
        let output = self.command(args, stdin)?;
        if output.status.success() {
            Ok(output)
        } else {
            Err(format!(
                "gpg {args:?} failed with {:?}\nstdout: {}\nstderr: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ))
        }
    }

    fn command(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, String> {
        let mut child = Command::new("gpg")
            .arg("--no-options")
            .arg("--batch")
            .arg("--yes")
            .arg("--pinentry-mode")
            .arg("loopback")
            .arg("--homedir")
            .arg(&self.path)
            .args(args)
            .env("GNUPGHOME", &self.path)
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| error.to_string())?;
        if let Some(input) = stdin {
            child
                .stdin
                .as_mut()
                .ok_or_else(|| "failed to open gpg stdin".to_owned())?
                .write_all(input)
                .map_err(|error| error.to_string())?;
        }
        drop(child.stdin.take());
        child.wait_with_output().map_err(|error| error.to_string())
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
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

fn path_str(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()))
}
