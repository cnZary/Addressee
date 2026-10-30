use std::{
    fs::{self, OpenOptions},
    io::{self, Cursor, Write as _},
    path::Path,
};

use openpgp_core::{
    DecryptionReport, DecryptionStatus, EncryptionConfig, EncryptionRequest, FullFingerprint,
    KeyError, MessageCipher, MessageError, MessageFormat, MessageService, RemotePrivateKeyResolver,
    SigningKeyRequest, SoftwareKeyStore, VerificationStatus,
};
use openpgp_policy::SecurityPolicy as Policy;
use pgp::{
    composed::SignedPublicKey,
    ser::Serialize as _,
    types::{KeyDetails, KeyVersion, Timestamp},
};
use thiserror::Error;

pub const TEST_PAYLOAD: &[u8] = b"Addressee disposable card payload\0\r\nsecond line\r\n";
pub const TEST_CLEARTEXT: &str = "Disposable card cleartext\r\nSecond line\r\n";

#[derive(Debug, Error)]
pub enum WorkflowError {
    #[error("public certificate handling failed: {0}")]
    Key(#[from] KeyError),

    #[error("OpenPGP message operation failed: {0}")]
    Message(#[from] MessageError),

    #[error("OpenPGP certificate parsing failed: {0}")]
    Rpgp(#[from] pgp::errors::Error),

    #[error("the test certificate does not contain the expected v4 signing and encryption subkeys")]
    CertificateStructure,

    #[error("workflow check failed: {0}")]
    UnexpectedResult(&'static str),

    #[error("combined decryption and verification returned an unexpected public report: {0:?}")]
    UnexpectedSignature(DecryptionReport),

    #[error("test artifact output failed: {0}")]
    Output(#[from] io::Error),
}

pub struct WorkflowArtifacts {
    pub detached_signature: Vec<u8>,
    pub attached_message: Vec<u8>,
    pub cleartext_message: Vec<u8>,
    pub encrypted_message: Vec<u8>,
    pub signed_encrypted_message: Vec<u8>,
}

impl WorkflowArtifacts {
    pub fn write_to(&self, directory: &Path) -> Result<(), WorkflowError> {
        fs::create_dir(directory)?;
        for (name, bytes) in [
            ("payload.bin", TEST_PAYLOAD),
            ("payload.bin.sig", self.detached_signature.as_slice()),
            ("payload-attached.asc", self.attached_message.as_slice()),
            ("cleartext.txt.asc", self.cleartext_message.as_slice()),
            ("encrypted.pgp", self.encrypted_message.as_slice()),
            (
                "signed-encrypted.pgp",
                self.signed_encrypted_message.as_slice(),
            ),
        ] {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join(name))?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        Ok(())
    }
}

pub fn exercise_v4_workflows(
    certificate: &SignedPublicKey,
    resolver: &dyn RemotePrivateKeyResolver,
) -> Result<WorkflowArtifacts, WorkflowError> {
    let (store, fingerprint, signing, decryption) = test_store(certificate)?;
    let service = MessageService::new(&store, Policy::default()).with_remote_resolver(resolver);
    let now = u64::from(Timestamp::now().as_secs());
    let mut artifacts = WorkflowArtifacts {
        detached_signature: Vec::new(),
        attached_message: Vec::new(),
        cleartext_message: Vec::new(),
        encrypted_message: Vec::new(),
        signed_encrypted_message: Vec::new(),
    };

    let signature = service.sign_detached(
        &fingerprint,
        "",
        now,
        TEST_PAYLOAD,
        &mut artifacts.detached_signature,
        MessageFormat::Binary,
    )?;
    if signature.signer_fingerprint != signing {
        return Err(WorkflowError::UnexpectedResult(
            "detached signature used the wrong component",
        ));
    }
    let verified = service.verify_detached(TEST_PAYLOAD, &artifacts.detached_signature, now)?;
    require_verification(verified.status, "detached signature did not verify")?;
    if verified.signatures.len() != 1
        || verified.signatures[0].signer_fingerprint.as_ref() != Some(&signing)
    {
        return Err(WorkflowError::UnexpectedResult(
            "detached verification returned the wrong signer",
        ));
    }
    let tampered = service.verify_detached(
        &b"different payload"[..],
        &artifacts.detached_signature,
        now,
    )?;
    if tampered.status != VerificationStatus::Invalid {
        return Err(WorkflowError::UnexpectedResult(
            "a modified payload was not rejected",
        ));
    }
    let empty_store = SoftwareKeyStore::new();
    let unknown = MessageService::new(&empty_store, Policy::default()).verify_detached(
        TEST_PAYLOAD,
        &artifacts.detached_signature,
        now,
    )?;
    if unknown.status != VerificationStatus::UnknownSigner {
        return Err(WorkflowError::UnexpectedResult(
            "an unknown signer was not distinguished from a valid signature",
        ));
    }

    service.sign_attached(
        &fingerprint,
        "",
        now,
        TEST_PAYLOAD,
        &mut artifacts.attached_message,
        MessageFormat::Armored,
    )?;
    let mut attached_plaintext = Vec::new();
    let verified = service.verify_attached(
        Cursor::new(&artifacts.attached_message),
        &mut attached_plaintext,
        now,
    )?;
    require_verification(verified.status, "attached signature did not verify")?;
    if attached_plaintext != TEST_PAYLOAD {
        return Err(WorkflowError::UnexpectedResult(
            "attached verification changed the payload",
        ));
    }

    service.sign_cleartext(
        &fingerprint,
        "",
        now,
        TEST_CLEARTEXT,
        &mut artifacts.cleartext_message,
    )?;
    let verified = service.verify_cleartext(&artifacts.cleartext_message, now)?;
    require_verification(
        verified.outcome.status,
        "cleartext signature did not verify",
    )?;
    if verified.text.as_deref() != Some(TEST_CLEARTEXT) {
        return Err(WorkflowError::UnexpectedResult(
            "cleartext verification changed the text",
        ));
    }

    let recipients = std::slice::from_ref(&fingerprint);
    let encryption = EncryptionRequest::new(
        recipients,
        now,
        EncryptionConfig::SeipdV1 {
            cipher: MessageCipher::Aes256,
        },
    );
    service.encrypt(
        recipients,
        now,
        encryption.config,
        TEST_PAYLOAD,
        &mut artifacts.encrypted_message,
        MessageFormat::Binary,
    )?;
    let report = decrypt_checked(&service, &fingerprint, &artifacts.encrypted_message, now)?;
    if report.status != DecryptionStatus::Unsigned {
        return Err(WorkflowError::UnexpectedResult(
            "encrypt-only output was not reported as unsigned",
        ));
    }

    service.sign_and_encrypt(
        SigningKeyRequest::new(&fingerprint, ""),
        encryption,
        TEST_PAYLOAD,
        &mut artifacts.signed_encrypted_message,
        MessageFormat::Binary,
    )?;
    let report = decrypt_checked(
        &service,
        &fingerprint,
        &artifacts.signed_encrypted_message,
        now,
    )?;
    if report.status != DecryptionStatus::Valid
        || report.signatures.len() != 1
        || report.signatures[0].signer_fingerprint.as_ref() != Some(&signing)
    {
        return Err(WorkflowError::UnexpectedSignature(report));
    }
    let _ = decryption;
    Ok(artifacts)
}

pub fn decrypt_v4_test_message(
    certificate: &SignedPublicKey,
    resolver: &dyn RemotePrivateKeyResolver,
    ciphertext: &[u8],
    additional_certificates: &[&[u8]],
) -> Result<DecryptionReport, WorkflowError> {
    let (mut store, fingerprint, _, _) = test_store(certificate)?;
    for additional in additional_certificates {
        store.import_public(additional)?;
    }
    let service = MessageService::new(&store, Policy::default()).with_remote_resolver(resolver);
    decrypt_checked(
        &service,
        &fingerprint,
        ciphertext,
        u64::from(Timestamp::now().as_secs()),
    )
}

pub fn verify_detached_test_signature(
    signature: &[u8],
    certificates: &[&[u8]],
) -> Result<openpgp_core::VerificationOutcome, WorkflowError> {
    let mut store = SoftwareKeyStore::new();
    for certificate in certificates {
        store.import_public(certificate)?;
    }
    MessageService::new(&store, Policy::default())
        .verify_detached(
            TEST_PAYLOAD,
            signature,
            u64::from(Timestamp::now().as_secs()),
        )
        .map_err(Into::into)
}

fn decrypt_checked(
    service: &MessageService<'_>,
    fingerprint: &FullFingerprint,
    ciphertext: &[u8],
    now: u64,
) -> Result<DecryptionReport, WorkflowError> {
    let decrypted = service.decrypt(fingerprint, "", now, Cursor::new(ciphertext))?;
    if decrypted.plaintext.as_deref() != Some(TEST_PAYLOAD) {
        return Err(WorkflowError::UnexpectedResult(
            "decryption did not return the authenticated test payload",
        ));
    }
    if !decrypted.report.may_commit_staging() {
        return Err(WorkflowError::UnexpectedResult(
            "message integrity verification failed",
        ));
    }
    Ok(decrypted.report)
}

fn require_verification(
    status: VerificationStatus,
    message: &'static str,
) -> Result<(), WorkflowError> {
    if status == VerificationStatus::Valid {
        Ok(())
    } else {
        Err(WorkflowError::UnexpectedResult(message))
    }
}

pub fn v4_component_fingerprints(
    certificate: &SignedPublicKey,
) -> Result<(FullFingerprint, FullFingerprint, FullFingerprint), WorkflowError> {
    certificate.verify_bindings()?;
    if certificate.primary_key.version() != KeyVersion::V4 {
        return Err(WorkflowError::CertificateStructure);
    }
    let [signing, decryption] = certificate.public_subkeys.as_slice() else {
        return Err(WorkflowError::CertificateStructure);
    };
    fn convert(key: &dyn KeyDetails) -> Result<FullFingerprint, WorkflowError> {
        FullFingerprint::from_hex(&format!("{:X}", key.fingerprint()))
            .map_err(|_| WorkflowError::CertificateStructure)
    }
    Ok((
        convert(&certificate.primary_key)?,
        convert(&signing.key)?,
        convert(&decryption.key)?,
    ))
}

fn test_store(
    certificate: &SignedPublicKey,
) -> Result<
    (
        SoftwareKeyStore,
        FullFingerprint,
        FullFingerprint,
        FullFingerprint,
    ),
    WorkflowError,
> {
    let (fingerprint, signing, decryption) = v4_component_fingerprints(certificate)?;
    let mut store = SoftwareKeyStore::new();
    store.import_public(&certificate.to_bytes()?)?;
    let metadata = store.metadata(&fingerprint)?;
    if metadata.subkeys.len() != 2
        || metadata.subkeys[0].fingerprint != signing
        || metadata.subkeys[1].fingerprint != decryption
    {
        return Err(WorkflowError::CertificateStructure);
    }
    Ok((store, fingerprint, signing, decryption))
}

#[cfg(test)]
mod tests {
    use openpgp_core::PrivateExportPolicy;
    use openpgp_policy::GenerationProfile;
    use pgp::{
        composed::Deserializable as _,
        packet::SecretSubkey,
        types::{DecryptionKey, SigningKey},
    };

    use super::*;

    struct SoftwareResolver {
        certificate: FullFingerprint,
        signing_fingerprint: FullFingerprint,
        decryption_fingerprint: FullFingerprint,
        signing: SecretSubkey,
        decryption: SecretSubkey,
    }

    impl RemotePrivateKeyResolver for SoftwareResolver {
        fn backend(
            &self,
            _certificate: &FullFingerprint,
            _component: &FullFingerprint,
        ) -> Option<openpgp_core::Backend> {
            Some(openpgp_core::Backend::Software)
        }

        fn signing_key(
            &self,
            certificate: &FullFingerprint,
            component: &FullFingerprint,
        ) -> pgp::errors::Result<Option<&dyn SigningKey>> {
            if certificate == &self.certificate && component == &self.signing_fingerprint {
                Ok(Some(&self.signing))
            } else {
                Ok(None)
            }
        }

        fn decryption_key(
            &self,
            certificate: &FullFingerprint,
            component: &FullFingerprint,
        ) -> pgp::errors::Result<Option<&dyn DecryptionKey>> {
            if certificate == &self.certificate && component == &self.decryption_fingerprint {
                Ok(Some(&self.decryption))
            } else {
                Ok(None)
            }
        }
    }

    fn software_fixture() -> (
        SignedPublicKey,
        Vec<u8>,
        SoftwareResolver,
        zeroize::Zeroizing<Vec<u8>>,
        zeroize::Zeroizing<String>,
    ) {
        const PASSWORD: &str = "test-only software protection password";
        let mut store = SoftwareKeyStore::new();
        let generated = store
            .generate(
                &GenerationProfile::nist_p256_v4(),
                "Workflow Test <workflow@example.test>",
                PASSWORD,
                PrivateExportPolicy::Allowed,
            )
            .expect("generate P-256 test certificate");
        let fingerprint = generated.metadata.fingerprint;
        let exported = zeroize::Zeroizing::new(
            store
                .export_private(&fingerprint, openpgp_core::ExportFormat::Binary)
                .expect("export protected test key"),
        );
        let secret = pgp::composed::SignedSecretKey::from_bytes(exported.as_slice())
            .expect("parse protected test key");
        let mut signing = secret.secret_subkeys[0].key.clone();
        let mut decryption = secret.secret_subkeys[1].key.clone();
        signing
            .remove_password(&pgp::types::Password::from(PASSWORD))
            .expect("unlock signing test component");
        decryption
            .remove_password(&pgp::types::Password::from(PASSWORD))
            .expect("unlock decryption test component");
        let resolver = SoftwareResolver {
            certificate: fingerprint.clone(),
            signing_fingerprint: generated.metadata.subkeys[0].fingerprint.clone(),
            decryption_fingerprint: generated.metadata.subkeys[1].fingerprint.clone(),
            signing,
            decryption,
        };
        assert!(
            resolver
                .signing_key(&fingerprint, &resolver.decryption_fingerprint)
                .expect("resolve another component")
                .is_none()
        );
        let certificate = SignedPublicKey::from_bytes(generated.public_certificate.as_slice())
            .expect("parse generated public certificate");
        (
            certificate,
            generated.public_certificate,
            resolver,
            exported,
            zeroize::Zeroizing::new(PASSWORD.to_owned()),
        )
    }

    #[test]
    fn workflows_use_real_software_cryptography_without_a_card() {
        let (certificate, _, resolver, _, _) = software_fixture();
        let artifacts = exercise_v4_workflows(&certificate, &resolver)
            .expect("real software message workflows must pass");
        assert!(!artifacts.detached_signature.is_empty());
        assert!(!artifacts.attached_message.is_empty());
        assert!(!artifacts.cleartext_message.is_empty());
        assert!(!artifacts.encrypted_message.is_empty());
        assert!(!artifacts.signed_encrypted_message.is_empty());
    }

    struct TestDirectory(std::path::PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if std::thread::panicking() {
                eprintln!("Retaining public test artifacts at {}", self.0.display());
            } else {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn gpg_and_application_interoperate_in_both_directions() {
        let (certificate, public, resolver, protected, password) = software_fixture();
        let artifacts = exercise_v4_workflows(&certificate, &resolver)
            .expect("real software message workflows must pass");
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = TestDirectory(std::env::temp_dir().join(format!(
            "addressee-workflow-test-{}-{nonce}",
            std::process::id()
        )));
        fs::create_dir(&root.0).expect("create temporary test directory");
        let directory = root.0.join("artifacts");
        artifacts
            .write_to(&directory)
            .expect("write public test artifacts");
        crate::workflow_gpg::exercise_gpg_interop(
            &certificate,
            &public,
            &resolver,
            Some((protected.as_slice(), password.as_str())),
            &directory,
            Path::new("gpg"),
        )
        .expect("GnuPG interoperability");
    }
}
