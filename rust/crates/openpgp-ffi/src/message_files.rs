use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read as _},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use openpgp_core::{
    EncryptionRequest, FullFingerprint, MessageError, SigningKeyRequest, VerificationStatus,
};
use zeroize::Zeroizing;

use crate::{
    AddresseeError, DecryptionReportFfi, EncryptionConfigFfi, MessageFormatFfi,
    SignatureMetadataFfi, VerificationOutcomeFfi,
};

use super::OpenPgpEngine;

#[derive(Clone, Debug, uniffi::Record)]
pub struct SignEncryptFileRequestFfi {
    pub signing_key: String,
    pub password: String,
    pub recipients: Vec<String>,
    pub at_unix_seconds: u64,
    pub config: EncryptionConfigFfi,
    pub input_path: String,
    pub output_path: String,
    pub format: MessageFormatFfi,
}

#[uniffi::export]
impl OpenPgpEngine {
    pub fn sign_detached_file(
        &self,
        signing_key: String,
        password: String,
        at_unix_seconds: u64,
        input_path: String,
        output_path: String,
        format: MessageFormatFfi,
    ) -> Result<SignatureMetadataFfi, AddresseeError> {
        let fingerprint = FullFingerprint::from_hex(&signing_key)?;
        let password = Zeroizing::new(password);
        let input = open_input(&input_path)?;
        let mut output = create_output(&output_path)?;
        let metadata = self.with_service(|service| {
            service.sign_detached(
                &fingerprint,
                &password,
                at_unix_seconds,
                input,
                &mut output,
                format.into(),
            )
        })??;
        Ok(metadata.into())
    }

    pub fn sign_attached_file(
        &self,
        signing_key: String,
        password: String,
        at_unix_seconds: u64,
        input_path: String,
        output_path: String,
        format: MessageFormatFfi,
    ) -> Result<SignatureMetadataFfi, AddresseeError> {
        let fingerprint = FullFingerprint::from_hex(&signing_key)?;
        let password = Zeroizing::new(password);
        let input = open_input(&input_path)?;
        let mut output = create_output(&output_path)?;
        let metadata = self.with_service(|service| {
            service.sign_attached(
                &fingerprint,
                &password,
                at_unix_seconds,
                input,
                &mut output,
                format.into(),
            )
        })??;
        Ok(metadata.into())
    }

    pub fn verify_detached_file(
        &self,
        data_path: String,
        signature_path: String,
        at_unix_seconds: u64,
    ) -> Result<VerificationOutcomeFfi, AddresseeError> {
        let limit = self.with_service(|service| service.limits().max_signature_bytes)?;
        let signature = read_signature(&signature_path, limit)?;
        let data = open_input(&data_path)?;
        let outcome = self
            .with_service(|service| service.verify_detached(data, &signature, at_unix_seconds))??;
        Ok(outcome.into())
    }

    pub fn verify_attached_file(
        &self,
        input_path: String,
        output_path: String,
        at_unix_seconds: u64,
    ) -> Result<VerificationOutcomeFfi, AddresseeError> {
        let input = open_input(&input_path)?;
        let mut output = create_output(&output_path)?;
        let outcome = self.with_service(|service| {
            service.verify_attached(input, &mut output, at_unix_seconds)
        })??;
        // The core commits plaintext only for unsigned or valid messages. Remove
        // the empty artifact for every other outcome so unauthenticated content
        // never remains at a caller-chosen destination.
        if !matches!(
            outcome.status,
            VerificationStatus::Unsigned | VerificationStatus::Valid
        ) {
            drop(output);
            let _ = fs::remove_file(checked_path(&output_path)?);
        }
        Ok(outcome.into())
    }

    pub fn encrypt_file(
        &self,
        recipients: Vec<String>,
        at_unix_seconds: u64,
        config: EncryptionConfigFfi,
        input_path: String,
        output_path: String,
        format: MessageFormatFfi,
    ) -> Result<(), AddresseeError> {
        let recipients = parse_recipients(recipients)?;
        let input = open_input(&input_path)?;
        let mut output = create_output(&output_path)?;
        self.with_service(|service| {
            service.encrypt(
                &recipients,
                at_unix_seconds,
                config.into(),
                input,
                &mut output,
                format.into(),
            )
        })??;
        Ok(())
    }

    pub fn sign_and_encrypt_file(
        &self,
        request: SignEncryptFileRequestFfi,
    ) -> Result<SignatureMetadataFfi, AddresseeError> {
        let SignEncryptFileRequestFfi {
            signing_key,
            password,
            recipients,
            at_unix_seconds,
            config,
            input_path,
            output_path,
            format,
        } = request;
        let signing_key = FullFingerprint::from_hex(&signing_key)?;
        let password = Zeroizing::new(password);
        let recipients = parse_recipients(recipients)?;
        let input = open_input(&input_path)?;
        let mut output = create_output(&output_path)?;
        let metadata = self.with_service(|service| {
            service.sign_and_encrypt(
                SigningKeyRequest::new(&signing_key, &password),
                EncryptionRequest::new(&recipients, at_unix_seconds, config.into()),
                input,
                &mut output,
                format.into(),
            )
        })??;
        Ok(metadata.into())
    }

    /// Decrypts a file through a staging artifact next to the requested output.
    /// The staging file is renamed into place only when the report allows committing;
    /// otherwise it is deleted so failed or unauthenticated plaintext never persists.
    pub fn decrypt_file(
        &self,
        decryption_key: String,
        password: String,
        at_unix_seconds: u64,
        input_path: String,
        output_path: String,
    ) -> Result<DecryptionReportFfi, AddresseeError> {
        let fingerprint = FullFingerprint::from_hex(&decryption_key)?;
        let password = Zeroizing::new(password);
        let input = open_input(&input_path)?;
        let output_path = checked_path(&output_path)?;
        let staging_path = staging_path(output_path)?;
        let mut staging = create_staging(&staging_path)?;
        let result = self.with_service(|service| {
            service.decrypt_into(
                &fingerprint,
                &password,
                at_unix_seconds,
                input,
                &mut staging,
            )
        });
        drop(staging);
        match result {
            Ok(Ok(report)) => {
                if report.may_commit_staging() {
                    fs::rename(&staging_path, output_path).map_err(io_error)?;
                } else {
                    let _ = fs::remove_file(&staging_path);
                }
                Ok(report.into())
            }
            Ok(Err(error)) => {
                let _ = fs::remove_file(&staging_path);
                Err(error.into())
            }
            Err(error) => {
                let _ = fs::remove_file(&staging_path);
                Err(error)
            }
        }
    }
}

fn checked_path(path: &str) -> Result<&Path, AddresseeError> {
    if path.is_empty() {
        return Err(AddresseeError::InvalidInput);
    }
    Ok(Path::new(path))
}

fn open_input(path: &str) -> Result<BufReader<File>, AddresseeError> {
    File::open(checked_path(path)?)
        .map(BufReader::new)
        .map_err(io_error)
}

fn create_output(path: &str) -> Result<BufWriter<File>, AddresseeError> {
    File::create(checked_path(path)?)
        .map(BufWriter::new)
        .map_err(io_error)
}

fn create_staging(path: &Path) -> Result<BufWriter<File>, AddresseeError> {
    File::create_new(path).map(BufWriter::new).map_err(io_error)
}

fn read_signature(path: &str, limit: usize) -> Result<Vec<u8>, AddresseeError> {
    let file = File::open(checked_path(path)?).map_err(io_error)?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    Ok(bytes)
}

fn parse_recipients(recipients: Vec<String>) -> Result<Vec<FullFingerprint>, AddresseeError> {
    recipients
        .into_iter()
        .map(|recipient| FullFingerprint::from_hex(&recipient).map_err(Into::into))
        .collect()
}

fn staging_path(output: &Path) -> Result<PathBuf, AddresseeError> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(AddresseeError::InvalidInput)?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AddresseeError::InternalFailure)?
        .as_nanos();
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    let staging_name = format!(
        ".{file_name}.staging-{}-{nanos}-{sequence}",
        std::process::id()
    );
    Ok(output.with_file_name(staging_name))
}

fn io_error(error: std::io::Error) -> AddresseeError {
    AddresseeError::from(MessageError::Io(error))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::{
        AeadModeFfi, DecryptionStatusFfi, ExportPolicyFfi, GenerationProfileFfi, MessageCipherFfi,
        VerificationStatusFfi,
    };

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after the Unix epoch")
                .as_nanos();
            let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "addressee-ffi-files-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create test directory");
            Self(path)
        }

        fn path(&self, name: &str) -> String {
            self.0.join(name).to_string_lossy().into_owned()
        }

        fn entries(&self) -> usize {
            fs::read_dir(&self.0).expect("list test directory").count()
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_secs()
    }

    fn payload() -> Vec<u8> {
        (0..(128 * 1024)).map(|index| (index % 251) as u8).collect()
    }

    fn generate(engine: &OpenPgpEngine, user_id: &str, password: &str) -> crate::GeneratedKeyFfi {
        engine
            .generate_key(
                GenerationProfileFfi::ModernV6,
                user_id.to_owned(),
                password.to_owned(),
                ExportPolicyFfi::Disabled,
            )
            .unwrap()
    }

    fn test_config() -> EncryptionConfigFfi {
        EncryptionConfigFfi::SeipdV2 {
            cipher: MessageCipherFfi::Aes256,
            mode: AeadModeFfi::Ocb,
        }
    }

    #[test]
    fn file_operations_roundtrip_and_reject_tampering() {
        let engine = OpenPgpEngine::new();
        let signer = generate(
            &engine,
            "File Signer <files@example.invalid>",
            "file-signer",
        );
        let at = now();
        let fingerprint = signer.summary.fingerprint.clone();
        let password = "file-signer".to_owned();
        let directory = TestDirectory::new();
        let data = payload();
        let input = directory.path("payload.bin");
        fs::write(&input, &data).unwrap();

        let detached = directory.path("payload.bin.asc");
        engine
            .sign_detached_file(
                fingerprint.clone(),
                password.clone(),
                at,
                input.clone(),
                detached.clone(),
                MessageFormatFfi::Armored,
            )
            .unwrap();
        let verified = engine
            .verify_detached_file(input.clone(), detached.clone(), at)
            .unwrap();
        assert!(matches!(verified.status, VerificationStatusFfi::Valid));

        let tampered = directory.path("tampered.bin");
        fs::write(&tampered, b"different contents").unwrap();
        let invalid = engine.verify_detached_file(tampered, detached, at).unwrap();
        assert!(matches!(invalid.status, VerificationStatusFfi::Invalid));

        let attached = directory.path("payload-signed.pgp");
        engine
            .sign_attached_file(
                fingerprint.clone(),
                password.clone(),
                at,
                input.clone(),
                attached.clone(),
                MessageFormatFfi::Binary,
            )
            .unwrap();
        let verified_output = directory.path("verified.bin");
        let attached_outcome = engine
            .verify_attached_file(attached.clone(), verified_output.clone(), at)
            .unwrap();
        assert!(matches!(
            attached_outcome.status,
            VerificationStatusFfi::Valid
        ));
        assert_eq!(fs::read(&verified_output).unwrap(), data);

        let unknown_output = directory.path("unknown.bin");
        let unknown = OpenPgpEngine::new();
        let unknown_outcome = unknown
            .verify_attached_file(attached, unknown_output.clone(), at)
            .unwrap();
        assert!(matches!(
            unknown_outcome.status,
            VerificationStatusFfi::UnknownSigner
        ));
        assert!(!Path::new(&unknown_output).exists());

        let encrypted = directory.path("payload.pgp");
        engine
            .sign_and_encrypt_file(SignEncryptFileRequestFfi {
                signing_key: fingerprint.clone(),
                password: password.clone(),
                recipients: vec![fingerprint.clone()],
                at_unix_seconds: at,
                config: test_config(),
                input_path: input.clone(),
                output_path: encrypted.clone(),
                format: MessageFormatFfi::Binary,
            })
            .unwrap();
        let decrypted = directory.path("decrypted.bin");
        let report = engine
            .decrypt_file(
                fingerprint.clone(),
                password.clone(),
                at,
                encrypted.clone(),
                decrypted.clone(),
            )
            .unwrap();
        assert_eq!(report.status, DecryptionStatusFfi::Valid);
        assert_eq!(fs::read(&decrypted).unwrap(), data);

        let unsigned = directory.path("unsigned.pgp");
        engine
            .encrypt_file(
                vec![fingerprint.clone()],
                at,
                test_config(),
                input.clone(),
                unsigned.clone(),
                MessageFormatFfi::Armored,
            )
            .unwrap();
        let unsigned_output = directory.path("unsigned.bin");
        let unsigned_report = engine
            .decrypt_file(fingerprint, password, at, unsigned, unsigned_output.clone())
            .unwrap();
        assert_eq!(unsigned_report.status, DecryptionStatusFfi::Unsigned);
        assert_eq!(fs::read(&unsigned_output).unwrap(), data);
    }

    #[test]
    fn decrypt_file_discards_staging_for_non_recipient() {
        let engine = OpenPgpEngine::new();
        let recipient = generate(
            &engine,
            "File Recipient <recipient@example.invalid>",
            "file-recipient",
        );
        let outsider = generate(
            &engine,
            "File Outsider <outsider@example.invalid>",
            "file-outsider",
        );
        let at = now();
        let directory = TestDirectory::new();
        let input = directory.path("payload.bin");
        fs::write(&input, payload()).unwrap();
        let encrypted = directory.path("payload.pgp");
        engine
            .encrypt_file(
                vec![recipient.summary.fingerprint.clone()],
                at,
                test_config(),
                input,
                encrypted.clone(),
                MessageFormatFfi::Binary,
            )
            .unwrap();

        let output = directory.path("should-not-exist.bin");
        let report = engine
            .decrypt_file(
                outsider.summary.fingerprint.clone(),
                "file-outsider".to_owned(),
                at,
                encrypted,
                output.clone(),
            )
            .unwrap();
        assert_eq!(report.status, DecryptionStatusFfi::DecryptionFailed);
        assert!(!report.may_commit_staging);
        assert!(!Path::new(&output).exists());
        assert_eq!(directory.entries(), 2);
    }

    #[test]
    fn legacy_hash_policy_is_preserved_and_rejected_file_plaintext_is_discarded() {
        let engine = OpenPgpEngine::new();
        let password = "legacy-file-test-only";
        let signer = engine
            .generate_key(
                GenerationProfileFfi::Rsa2048V4,
                "Legacy File Signer <legacy-files@example.invalid>".to_owned(),
                password.to_owned(),
                ExportPolicyFfi::Allowed,
            )
            .unwrap();
        let fingerprint = signer.summary.fingerprint.clone();
        let secret = engine
            .export_private_key(fingerprint.clone(), crate::ExportFormatFfi::Binary)
            .unwrap();
        let public = signer.public_certificate;
        let at = now();
        let directory = TestDirectory::new();
        let payload = b"legacy signed and encrypted file payload";

        for (algorithm, identifier, may_commit) in [
            (pgp::crypto::hash::HashAlgorithm::Md5, "md5", false),
            (pgp::crypto::hash::HashAlgorithm::Sha1, "sha1", true),
        ] {
            let encrypted =
                legacy_signed_encrypted(&secret, &public, password, algorithm, at, payload);
            let decrypted = engine
                .decrypt(
                    fingerprint.clone(),
                    password.to_owned(),
                    at,
                    encrypted.clone(),
                )
                .unwrap();
            assert_eq!(decrypted.report.may_commit_staging, may_commit);
            assert_eq!(decrypted.plaintext.is_some(), may_commit);
            assert_eq!(
                decrypted.report.signatures[0].hash_algorithm.as_deref(),
                Some(identifier)
            );
            assert_eq!(
                decrypted.report.signatures[0]
                    .legacy_decision
                    .warning
                    .as_ref()
                    .map(|warning| warning.algorithm.as_str()),
                Some(identifier)
            );

            let input = directory.path(&format!("{identifier}.pgp"));
            let output = directory.path(&format!("{identifier}.bin"));
            fs::write(&input, encrypted).unwrap();
            let report = engine
                .decrypt_file(
                    fingerprint.clone(),
                    password.to_owned(),
                    at,
                    input,
                    output.clone(),
                )
                .unwrap();
            assert_eq!(report.may_commit_staging, may_commit);
            assert_eq!(Path::new(&output).exists(), may_commit);
            assert_eq!(directory.entries(), if may_commit { 3 } else { 1 });
            if may_commit {
                assert_eq!(fs::read(&output).unwrap(), payload);
            }
        }
    }

    fn legacy_signed_encrypted(
        secret: &[u8],
        public: &[u8],
        password: &str,
        algorithm: pgp::crypto::hash::HashAlgorithm,
        at: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        use pgp::{
            composed::{Deserializable as _, SubpacketConfig},
            packet::{Subpacket, SubpacketData},
            types::{KeyDetails as _, Timestamp},
        };

        let secret =
            pgp::composed::SignedSecretKey::from_bytes(std::io::Cursor::new(secret)).unwrap();
        let public =
            pgp::composed::SignedPublicKey::from_bytes(std::io::Cursor::new(public)).unwrap();
        let signing_key = &secret.secret_subkeys[0].key;
        let hashed = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                at.try_into().unwrap(),
            )))
            .unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(signing_key.fingerprint()))
                .unwrap(),
        ];
        let unhashed = vec![
            Subpacket::regular(SubpacketData::IssuerKeyId(signing_key.legacy_key_id())).unwrap(),
        ];
        let mut rng = rand::thread_rng();
        let mut builder =
            pgp::composed::MessageBuilder::from_bytes("payload.bin", payload.to_vec())
                .seipd_v1(&mut rng, pgp::crypto::sym::SymmetricKeyAlgorithm::AES256);
        builder
            .encrypt_to_key(&mut rng, &public.public_subkeys[1])
            .unwrap();
        builder.sign_with_subpackets(
            signing_key,
            password.into(),
            algorithm,
            SubpacketConfig::UserDefined { hashed, unhashed },
        );
        builder.to_vec(&mut rng).unwrap()
    }
}
