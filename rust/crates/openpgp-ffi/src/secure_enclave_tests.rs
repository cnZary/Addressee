use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use pgp::types::KeyDetails as _;

use crate::{
    AddresseeError, DecryptionStatusFfi, EncryptionConfigFfi, ExportFormatFfi, ExportPolicyFfi,
    GenerationProfileFfi, KeyStorageFfi, MessageCipherFfi, MessageFormatFfi, OpenPgpEngine,
    SecureEnclaveErrorFfi, SecureEnclaveGeneratedKeyFfi, SecureEnclaveOperations,
    SecureEnclaveReferenceFfi, SecureEnclaveUsageFfi, SignEncryptRequestFfi, VerificationStatusFfi,
};

const PASSWORD: &str = "test-only-software-primary-protection";
const PAYLOAD: &[u8] = b"Secure Enclave protocol test\0\r\nsecond line\r\n";

#[derive(Clone, Copy)]
enum Fault {
    None,
    Cancelled,
    InvalidResponse,
    Malformed,
}

struct TestP256Provider {
    certification: p256::ecdsa::SigningKey,
    signing: p256::ecdsa::SigningKey,
    encryption: p256::SecretKey,
    fault: Mutex<Fault>,
    digests: Mutex<Vec<Vec<u8>>>,
}

impl TestP256Provider {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            certification: p256::ecdsa::SigningKey::random(&mut rng),
            signing: p256::ecdsa::SigningKey::random(&mut rng),
            encryption: p256::SecretKey::random(&mut rng),
            fault: Mutex::new(Fault::None),
            digests: Mutex::new(Vec::new()),
        }
    }

    fn certification_reference(&self) -> SecureEnclaveReferenceFfi {
        SecureEnclaveReferenceFfi {
            id: "test-certification-primary".to_owned(),
            usage: SecureEnclaveUsageFfi::Signing,
            public_key_x963: self
                .certification
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        }
    }

    fn references(&self) -> (SecureEnclaveReferenceFfi, SecureEnclaveReferenceFfi) {
        (
            SecureEnclaveReferenceFfi {
                id: "test-signing-component".to_owned(),
                usage: SecureEnclaveUsageFfi::Signing,
                public_key_x963: self
                    .signing
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
            },
            SecureEnclaveReferenceFfi {
                id: "test-encryption-component".to_owned(),
                usage: SecureEnclaveUsageFfi::KeyAgreement,
                public_key_x963: self
                    .encryption
                    .public_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
            },
        )
    }

    fn signing_key(
        &self,
        reference: &SecureEnclaveReferenceFfi,
    ) -> Result<&p256::ecdsa::SigningKey, SecureEnclaveErrorFfi> {
        if reference.id == self.certification_reference().id {
            Ok(&self.certification)
        } else if reference.id == self.references().0.id {
            Ok(&self.signing)
        } else {
            Err(SecureEnclaveErrorFfi::InvalidReference)
        }
    }

    fn fault(&self, fault: Fault) {
        *self.fault.lock().unwrap() = fault;
    }

    fn check_fault(&self) -> Result<(), SecureEnclaveErrorFfi> {
        match *self.fault.lock().unwrap() {
            Fault::None => Ok(()),
            Fault::Cancelled => Err(SecureEnclaveErrorFfi::Cancelled),
            Fault::InvalidResponse => Err(SecureEnclaveErrorFfi::InvalidResponse),
            Fault::Malformed => Ok(()),
        }
    }

    fn validate(&self, reference: &SecureEnclaveReferenceFfi) -> Result<(), SecureEnclaveErrorFfi> {
        let (signing, encryption) = self.references();
        if (reference.usage == SecureEnclaveUsageFfi::Signing
            && [signing.id, self.certification_reference().id].contains(&reference.id))
            || (reference.usage == SecureEnclaveUsageFfi::KeyAgreement
                && reference.id == encryption.id)
        {
            Ok(())
        } else {
            Err(SecureEnclaveErrorFfi::InvalidReference)
        }
    }
}

impl SecureEnclaveOperations for TestP256Provider {
    fn public_key(
        &self,
        reference: SecureEnclaveReferenceFfi,
    ) -> Result<Vec<u8>, SecureEnclaveErrorFfi> {
        self.validate(&reference)?;
        match reference.usage {
            SecureEnclaveUsageFfi::Signing => Ok(self
                .signing_key(&reference)?
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec()),
            SecureEnclaveUsageFfi::KeyAgreement => Ok(self.references().1.public_key_x963),
        }
    }

    fn sign_sha256(
        &self,
        reference: SecureEnclaveReferenceFfi,
        digest: Vec<u8>,
    ) -> Result<Vec<u8>, SecureEnclaveErrorFfi> {
        self.validate(&reference)?;
        let signing = self.signing_key(&reference)?;
        if reference.public_key_x963 != signing.verifying_key().to_encoded_point(false).as_bytes() {
            return Err(SecureEnclaveErrorFfi::InvalidReference);
        }
        self.check_fault()?;
        if digest.len() != 32 {
            return Err(SecureEnclaveErrorFfi::InvalidResponse);
        }
        self.digests.lock().unwrap().push(digest.clone());
        if matches!(*self.fault.lock().unwrap(), Fault::Malformed) {
            return Ok(vec![0; 63]);
        }
        let signature: p256::ecdsa::Signature = signing
            .sign_prehash(&digest)
            .map_err(|_| SecureEnclaveErrorFfi::InvalidResponse)?;
        Ok(signature.to_bytes().to_vec())
    }

    fn ecdh(
        &self,
        reference: SecureEnclaveReferenceFfi,
        peer_public_key: Vec<u8>,
    ) -> Result<Vec<u8>, SecureEnclaveErrorFfi> {
        self.validate(&reference)?;
        if reference.public_key_x963 != self.references().1.public_key_x963 {
            return Err(SecureEnclaveErrorFfi::InvalidReference);
        }
        self.check_fault()?;
        if matches!(*self.fault.lock().unwrap(), Fault::Malformed) {
            return Ok(vec![0; 31]);
        }
        let peer = p256::PublicKey::from_sec1_bytes(&peer_public_key)
            .map_err(|_| SecureEnclaveErrorFfi::InvalidReference)?;
        let secret =
            p256::ecdh::diffie_hellman(self.encryption.to_nonzero_scalar(), peer.as_affine());
        Ok(secret.raw_secret_bytes().to_vec())
    }
}

fn fixture() -> (
    OpenPgpEngine,
    SecureEnclaveGeneratedKeyFfi,
    Arc<TestP256Provider>,
) {
    let engine = OpenPgpEngine::new();
    let provider = Arc::new(TestP256Provider::new());
    let (signing, encryption) = provider.references();
    let generated = engine
        .generate_secure_enclave_key(
            "Secure Enclave FFI <se-ffi@example.invalid>".to_owned(),
            provider.certification_reference(),
            signing,
            encryption,
            provider.clone(),
        )
        .unwrap();
    (engine, generated, provider)
}

fn legacy_fixture() -> (
    OpenPgpEngine,
    SecureEnclaveGeneratedKeyFfi,
    Arc<TestP256Provider>,
) {
    let engine = OpenPgpEngine::new();
    let provider = Arc::new(TestP256Provider::new());
    let (signing, encryption) = provider.references();
    let (_, signing_key, encryption_key, operations) = crate::secure_enclave::new_components(
        provider.certification_reference(),
        signing,
        encryption,
        provider.clone(),
    )
    .unwrap();
    let generated = engine
        .lock()
        .unwrap()
        .generate_external_p256(
            "Legacy hybrid FFI <legacy-hybrid@example.invalid>",
            &signing_key,
            &encryption_key,
        )
        .unwrap();
    let binding = crate::SecureEnclaveBindingFfi {
        certificate_fingerprint: generated.metadata.fingerprint.to_string(),
        public_certificate: generated.public_certificate.clone(),
        signing_component_fingerprint: format!("{:X}", signing_key.public_key().fingerprint()),
        encryption_component_fingerprint: format!(
            "{:X}",
            encryption_key.public_key().fingerprint()
        ),
        signing: operations.signing.clone(),
        encryption: operations.encryption.clone(),
        certification: None,
    };
    engine
        .register_secure_enclave(binding.clone(), provider.clone())
        .unwrap();
    (
        engine,
        SecureEnclaveGeneratedKeyFfi {
            generated: generated.into(),
            binding,
        },
        provider,
    )
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 1
}

fn config() -> EncryptionConfigFfi {
    EncryptionConfigFfi::SeipdV1 {
        cipher: MessageCipherFfi::Aes256,
    }
}

#[test]
fn real_p256_callbacks_cover_all_signature_formats_without_a_primary_password() {
    let (engine, generated, provider) = fixture();
    let fingerprint = generated.generated.summary.fingerprint.clone();
    assert_eq!(generated.generated.summary.subkeys.len(), 2);
    assert_eq!(
        generated.generated.summary.primary.storage,
        KeyStorageFfi::PublicOnly
    );
    assert_eq!(
        generated.binding.certification,
        Some(provider.certification_reference())
    );
    assert!(
        generated
            .generated
            .summary
            .subkeys
            .iter()
            .all(|key| { key.storage == KeyStorageFfi::PublicOnly })
    );
    let snapshot = engine.storage_snapshot().unwrap();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].protected_secret, None);
    assert_eq!(
        engine.export_private_key(fingerprint.clone(), ExportFormatFfi::Binary),
        Err(AddresseeError::PublicKeyOnly)
    );

    let detached = engine
        .sign_detached(
            fingerprint.clone(),
            "not-the-primary-password".to_owned(),
            now(),
            PAYLOAD.to_vec(),
            MessageFormatFfi::Binary,
        )
        .unwrap();
    assert_eq!(
        detached.metadata.signer_fingerprint,
        generated.binding.signing_component_fingerprint
    );
    assert_eq!(
        engine
            .verify_detached(PAYLOAD.to_vec(), detached.artifact.clone(), now())
            .unwrap()
            .status,
        VerificationStatusFfi::Valid
    );
    let detached_gpg = engine
        .sign_detached(
            fingerprint.clone(),
            String::new(),
            now(),
            PAYLOAD.to_vec(),
            MessageFormatFfi::Armored,
        )
        .unwrap();
    assert!(
        detached_gpg
            .artifact
            .starts_with(b"-----BEGIN PGP SIGNATURE-----")
    );

    let attached = engine
        .sign_attached(
            fingerprint.clone(),
            String::new(),
            now(),
            PAYLOAD.to_vec(),
            MessageFormatFfi::Armored,
        )
        .unwrap();
    let verified = engine.verify_attached(attached.artifact, now()).unwrap();
    assert_eq!(verified.outcome.status, VerificationStatusFfi::Valid);
    assert_eq!(verified.plaintext.as_deref(), Some(PAYLOAD));

    let cleartext = engine
        .sign_cleartext(
            fingerprint,
            String::new(),
            now(),
            "first line\r\nsecond line\r\n".to_owned(),
        )
        .unwrap();
    let verified = engine.verify_cleartext(cleartext.artifact, now()).unwrap();
    assert_eq!(verified.outcome.status, VerificationStatusFfi::Valid);
    assert_eq!(
        verified.text.as_deref(),
        Some("first line\r\nsecond line\r\n")
    );
    assert_eq!(provider.digests.lock().unwrap().len(), 8);
    assert!(
        provider
            .digests
            .lock()
            .unwrap()
            .iter()
            .all(|digest| digest.len() == 32)
    );
}

#[test]
fn hardware_ecdh_covers_multiple_recipients_and_combined_messages() {
    let (engine, generated, _) = fixture();
    let fingerprint = generated.generated.summary.fingerprint.clone();
    let software_engine = OpenPgpEngine::new();
    let software = software_engine
        .generate_key(
            GenerationProfileFfi::NistP256V4,
            "Second recipient <recipient@example.invalid>".to_owned(),
            "test-only-second-recipient".to_owned(),
            ExportPolicyFfi::Disabled,
        )
        .unwrap();
    engine
        .import_public_key(software.public_certificate.clone())
        .unwrap();
    let recipients = vec![fingerprint.clone(), software.summary.fingerprint.clone()];
    let encrypted = engine
        .encrypt(
            recipients.clone(),
            now(),
            config(),
            b"multi-recipient".to_vec(),
            MessageFormatFfi::Armored,
        )
        .unwrap();
    let decrypted = engine
        .decrypt_text(fingerprint.clone(), String::new(), now(), encrypted.clone())
        .unwrap();
    assert_eq!(decrypted.report.status, DecryptionStatusFfi::Unsigned);
    assert_eq!(decrypted.text.as_deref(), Some("multi-recipient"));
    let other = software_engine
        .decrypt_text(
            software.summary.fingerprint.clone(),
            "test-only-second-recipient".to_owned(),
            now(),
            encrypted,
        )
        .unwrap();
    assert_eq!(other.text.as_deref(), Some("multi-recipient"));

    let encrypted = engine
        .sign_and_encrypt(SignEncryptRequestFfi {
            signing_key: fingerprint.clone(),
            password: String::new(),
            recipients,
            at_unix_seconds: now(),
            config: config(),
            data: PAYLOAD.to_vec(),
            format: MessageFormatFfi::Binary,
        })
        .unwrap();
    let decrypted = engine
        .decrypt(
            fingerprint,
            String::new(),
            now(),
            encrypted.artifact.clone(),
        )
        .unwrap();
    assert_eq!(decrypted.report.status, DecryptionStatusFfi::Valid);
    assert_eq!(decrypted.plaintext.as_deref(), Some(PAYLOAD));
    let other = software_engine
        .decrypt(
            software.summary.fingerprint,
            "test-only-second-recipient".to_owned(),
            now(),
            encrypted.artifact,
        )
        .unwrap();
    assert_eq!(other.report.status, DecryptionStatusFfi::UnknownSigner);
    assert_eq!(other.plaintext.as_deref(), Some(PAYLOAD));
}

#[test]
fn snapshot_restore_requires_rebinding_the_same_device_public_keys() {
    let (engine, generated, provider) = fixture();
    let fingerprint = generated.generated.summary.fingerprint.clone();
    let snapshot = engine.storage_snapshot().unwrap();
    assert_eq!(snapshot.len(), 1);
    assert!(snapshot[0].protected_secret.is_none());
    assert_eq!(snapshot[0].export_policy, None);
    assert_eq!(
        engine.secure_enclave_registrations().unwrap(),
        vec![generated.binding.clone()]
    );

    let restored = OpenPgpEngine::new();
    restored.restore_storage(snapshot.clone()).unwrap();
    let unavailable = restored.sign_detached(
        fingerprint.clone(),
        PASSWORD.to_owned(),
        now(),
        PAYLOAD.to_vec(),
        MessageFormatFfi::Binary,
    );
    assert_eq!(unavailable.unwrap_err(), AddresseeError::PublicKeyOnly);
    restored
        .register_secure_enclave(generated.binding.clone(), provider.clone())
        .unwrap();
    let signature = restored
        .sign_detached(
            fingerprint.clone(),
            String::new(),
            now(),
            PAYLOAD.to_vec(),
            MessageFormatFfi::Binary,
        )
        .unwrap();
    assert_eq!(
        restored
            .verify_detached(PAYLOAD.to_vec(), signature.artifact, now())
            .unwrap()
            .status,
        VerificationStatusFfi::Valid
    );
    let detached = restored.detach_secure_enclave(fingerprint).unwrap();
    assert_eq!(detached, generated.binding);
    assert!(restored.secure_enclave_registrations().unwrap().is_empty());
    let mut tampered = snapshot.clone();
    tampered[0].public_certificate.pop();
    assert!(restored.restore_storage(tampered).is_err());
    restored.restore_storage(snapshot).unwrap();
    assert_eq!(restored.list_keys().unwrap().len(), 1);
}

#[test]
fn public_only_binding_restoration_does_not_require_software_secret_material() {
    let (_, generated, provider) = fixture();
    let engine = OpenPgpEngine::new();
    engine
        .import_public_key(generated.binding.public_certificate.clone())
        .unwrap();
    let snapshot = engine.storage_snapshot().unwrap();
    assert_eq!(snapshot.len(), 1);
    assert!(snapshot[0].protected_secret.is_none());

    let restored = OpenPgpEngine::new();
    restored.restore_storage(snapshot).unwrap();
    let fingerprint = generated.generated.summary.fingerprint;
    assert_eq!(
        restored
            .sign_detached(
                fingerprint.clone(),
                PASSWORD.to_owned(),
                now(),
                PAYLOAD.to_vec(),
                MessageFormatFfi::Binary,
            )
            .unwrap_err(),
        AddresseeError::PublicKeyOnly
    );
    restored
        .register_secure_enclave(generated.binding.clone(), provider)
        .unwrap();
    let metadata = restored.key_metadata(fingerprint).unwrap();
    assert_eq!(metadata.storage, KeyStorageFfi::PublicOnly);
    assert_eq!(
        metadata.private_export_policy,
        ExportPolicyFfi::NotApplicable
    );
    let signature = restored
        .sign_detached(
            generated.binding.certificate_fingerprint,
            String::new(),
            now(),
            PAYLOAD.to_vec(),
            MessageFormatFfi::Binary,
        )
        .unwrap();
    assert_eq!(
        restored
            .verify_detached(PAYLOAD.to_vec(), signature.artifact, now())
            .unwrap()
            .status,
        VerificationStatusFfi::Valid
    );
}

#[test]
fn legacy_hybrid_certificates_restore_and_use_only_their_hardware_subkeys() {
    let (engine, generated, provider) = legacy_fixture();
    let fingerprint = generated.generated.summary.fingerprint.clone();
    assert_eq!(generated.binding.certification, None);
    assert_eq!(
        generated.generated.summary.primary.storage,
        KeyStorageFfi::SoftwareSecret
    );
    assert_eq!(
        engine.export_private_key(fingerprint.clone(), ExportFormatFfi::Binary),
        Err(AddresseeError::ExportDisabled)
    );
    let snapshot = engine.storage_snapshot().unwrap();
    assert!(snapshot[0].protected_secret.is_some());
    assert_eq!(snapshot[0].export_policy, Some(ExportPolicyFfi::Disabled));
    let encrypted = engine
        .encrypt(
            vec![fingerprint.clone()],
            now(),
            config(),
            PAYLOAD.to_vec(),
            MessageFormatFfi::Binary,
        )
        .unwrap();

    let restored = OpenPgpEngine::new();
    restored.restore_storage(snapshot).unwrap();
    restored
        .register_secure_enclave(generated.binding, provider)
        .unwrap();
    let signature = restored
        .sign_detached(
            fingerprint.clone(),
            String::new(),
            now(),
            PAYLOAD.to_vec(),
            MessageFormatFfi::Binary,
        )
        .unwrap();
    assert_eq!(
        restored
            .verify_detached(PAYLOAD.to_vec(), signature.artifact, now())
            .unwrap()
            .status,
        VerificationStatusFfi::Valid
    );
    let decrypted = restored
        .decrypt(fingerprint, String::new(), now(), encrypted)
        .unwrap();
    assert_eq!(decrypted.report.status, DecryptionStatusFfi::Unsigned);
    assert_eq!(decrypted.plaintext.as_deref(), Some(PAYLOAD));
}

#[test]
fn export_allowed_software_primaries_cannot_be_registered_as_secure_enclave() {
    let (engine, generated, provider) = legacy_fixture();
    assert_eq!(generated.binding.certification, None);
    assert_eq!(
        generated.generated.summary.primary.storage,
        KeyStorageFfi::SoftwareSecret
    );
    let mut snapshot = engine.storage_snapshot().unwrap();
    assert!(snapshot[0].protected_secret.is_some());
    snapshot[0].export_policy = Some(ExportPolicyFfi::Allowed);
    let restored = OpenPgpEngine::new();
    restored.restore_storage(snapshot).unwrap();
    assert_eq!(
        restored
            .register_secure_enclave(generated.binding, provider)
            .unwrap_err(),
        AddresseeError::AmbiguousPrivateKeyStorage
    );
}

#[test]
fn snapshot_restore_allows_an_unrelated_public_signer() {
    let (engine, generated, provider) = fixture();
    let peer_engine = OpenPgpEngine::new();
    let peer = peer_engine
        .generate_key(
            GenerationProfileFfi::ModernV6,
            "Unrelated public signer <peer@example.invalid>".to_owned(),
            PASSWORD.to_owned(),
            ExportPolicyFfi::Disabled,
        )
        .unwrap();
    engine
        .import_public_key(
            peer_engine
                .export_public_key(peer.summary.fingerprint, ExportFormatFfi::Binary)
                .unwrap(),
        )
        .unwrap();
    let snapshot = engine.storage_snapshot().unwrap();
    assert_eq!(snapshot.len(), 2);

    let restored = OpenPgpEngine::new();
    restored.restore_storage(snapshot).unwrap();
    restored
        .register_secure_enclave(generated.binding, provider)
        .unwrap();
    assert_eq!(restored.list_keys().unwrap().len(), 2);
    assert_eq!(restored.secure_enclave_registrations().unwrap().len(), 1);
}

#[test]
fn cancelled_unavailable_and_malformed_provider_results_do_not_fall_back_to_software() {
    let (engine, generated, provider) = fixture();
    let fingerprint = generated.generated.summary.fingerprint.clone();
    let sign = || {
        engine.sign_detached(
            fingerprint.clone(),
            PASSWORD.to_owned(),
            now(),
            PAYLOAD.to_vec(),
            MessageFormatFfi::Binary,
        )
    };
    for fault in [Fault::Cancelled, Fault::InvalidResponse, Fault::Malformed] {
        provider.fault(fault);
        assert!(sign().is_err());
    }
    provider.fault(Fault::Cancelled);
    assert_eq!(sign().unwrap_err(), AddresseeError::OperationCancelled);
    let encrypted = engine
        .encrypt(
            vec![fingerprint.clone()],
            now(),
            config(),
            b"no fallback".to_vec(),
            MessageFormatFfi::Binary,
        )
        .unwrap();
    assert_eq!(
        engine
            .decrypt_text(
                fingerprint.clone(),
                PASSWORD.to_owned(),
                now(),
                encrypted.clone()
            )
            .unwrap_err(),
        AddresseeError::OperationCancelled
    );
    provider.fault(Fault::InvalidResponse);
    assert_eq!(
        engine
            .decrypt_text(fingerprint.clone(), String::new(), now(), encrypted.clone())
            .unwrap_err(),
        AddresseeError::RemoteKeyUnavailable
    );
    provider.fault(Fault::Malformed);
    assert!(
        engine
            .decrypt_text(fingerprint, String::new(), now(), encrypted)
            .is_err()
    );
}

#[test]
fn invalid_references_certificates_and_component_bindings_are_rejected() {
    let engine = OpenPgpEngine::new();
    let provider = Arc::new(TestP256Provider::new());
    let (mut signing, encryption) = provider.references();
    signing.id = "unknown-device-key".to_owned();
    assert_eq!(
        engine
            .generate_secure_enclave_key(
                "Invalid reference <invalid@example.invalid>".to_owned(),
                provider.certification_reference(),
                signing,
                encryption,
                provider.clone(),
            )
            .unwrap_err(),
        AddresseeError::UnsupportedOperation
    );

    let (engine, generated, provider) = fixture();
    let mut binding = generated.binding.clone();
    binding.certification = Some(binding.signing.clone());
    assert_eq!(
        engine
            .register_secure_enclave(binding, provider.clone())
            .unwrap_err(),
        AddresseeError::ConflictingCertificate
    );
    let mut binding = generated.binding.clone();
    binding.signing.public_key_x963 = Arc::new(TestP256Provider::new())
        .references()
        .0
        .public_key_x963;
    assert_eq!(
        engine
            .register_secure_enclave(binding, provider.clone())
            .unwrap_err(),
        AddresseeError::ConflictingCertificate
    );
    let mut binding = generated.binding.clone();
    std::mem::swap(
        &mut binding.signing_component_fingerprint,
        &mut binding.encryption_component_fingerprint,
    );
    assert_eq!(
        engine
            .register_secure_enclave(binding, provider.clone())
            .unwrap_err(),
        AddresseeError::ConflictingCertificate
    );
    let mut binding = generated.binding.clone();
    binding.public_certificate.push(0);
    assert!(engine.register_secure_enclave(binding, provider).is_err());

    let software = OpenPgpEngine::new();
    let generated_software = software
        .generate_key(
            GenerationProfileFfi::ModernV6,
            "Independent software key <software@example.invalid>".to_owned(),
            PASSWORD.to_owned(),
            ExportPolicyFfi::Allowed,
        )
        .unwrap();
    let protected = software
        .export_private_key(
            generated_software.summary.fingerprint,
            ExportFormatFfi::Binary,
        )
        .unwrap();
    assert_eq!(
        engine
            .import_private_key(
                protected,
                Some("incorrect-current-password".to_owned()),
                "another-test-only-password".to_owned(),
                ExportPolicyFfi::Disabled,
            )
            .unwrap_err(),
        AddresseeError::InvalidPassword
    );
}

#[cfg(all(feature = "gpg-interop-test", not(target_os = "ios")))]
#[test]
fn p256_provider_messages_interoperate_with_gpg_without_card_access() {
    use openpgp_card_adapter::workflow_gpg::{exercise_gpg_interop, parse_public_certificate};
    use openpgp_card_adapter::workflow_test::exercise_v4_workflows;
    use pgp::ser::Serialize as _;

    let (_engine, generated, provider) = fixture();
    let certificate = parse_public_certificate(&generated.binding.public_certificate).unwrap();
    assert_eq!(
        certificate.to_bytes().unwrap(),
        generated.binding.public_certificate
    );
    let (_, resolver) = crate::secure_enclave::validated_resolver(
        certificate.clone(),
        &generated.binding,
        provider,
    )
    .unwrap();
    let directory = TestDirectory::new();
    let artifacts = directory.path.join("artifacts");
    exercise_v4_workflows(&certificate, &resolver)
        .unwrap()
        .write_to(&artifacts)
        .unwrap();
    let gpg = std::env::var_os("ADDRESSEE_GPG").unwrap_or_else(|| "gpg".into());
    exercise_gpg_interop(
        &certificate,
        &generated.binding.public_certificate,
        &resolver,
        None,
        &artifacts,
        std::path::Path::new(&gpg),
    )
    .unwrap();
}

#[cfg(all(feature = "gpg-interop-test", not(target_os = "ios")))]
struct TestDirectory {
    path: std::path::PathBuf,
}

#[cfg(all(feature = "gpg-interop-test", not(target_os = "ios")))]
impl TestDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../build/secure-enclave-tests")
            .join(format!("{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self { path }
    }
}

#[cfg(all(feature = "gpg-interop-test", not(target_os = "ios")))]
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
