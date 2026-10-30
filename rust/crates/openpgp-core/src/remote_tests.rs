#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{
    cell::{Cell, RefCell},
    error::Error as _,
    io::Cursor,
};

use openpgp_policy::{Backend, GenerationProfile, SecurityPolicy};
use pgp::{
    composed::{
        Deserializable as _, DetachedSignature, MessageBuilder, PlainSessionKey, SignedSecretKey,
    },
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::{
        RevocationCode, SecretSubkey, SignatureConfig, SignatureType, Subpacket, SubpacketData,
    },
    ser::Serialize as _,
    types::{
        DecryptionKey, Duration, EskType, Fingerprint, KeyDetails, KeyId, KeyVersion, Password,
        PkeskBytes, PublicParams, SignatureBytes, SigningKey, Timestamp,
    },
};

use crate::{
    AeadMode, CertificateMetadata, DecryptionStatus, EncryptionConfig, EncryptionRequest,
    FullFingerprint, KeyStorage, KeyVersion as MetadataKeyVersion, MessageCipher, MessageError,
    MessageFormat, MessageOperation, MessageService, PrivateExportPolicy, RemotePrivateKeyResolver,
    SignatureMetadata, SigningKeyRequest, SoftwareKeyStore, VerificationStatus,
};

const PASSWORD: &str = "software password that must not become a remote PIN";
const PROVIDER_DETAIL: &str = "sensitive provider detail and a synthetic credential marker";

#[test]
fn remote_operations_cover_v4_and_v6_with_public_only_records() {
    exercise_remote_operations(GenerationProfile::nist_p256_v4());
    exercise_remote_operations(GenerationProfile::modern_v6());
}

#[test]
fn software_keys_keep_their_password_path_with_a_resolver_installed() {
    let fixture = Fixture::new(GenerationProfile::nist_p256_v4());
    let fingerprint = &fixture.metadata.fingerprint;
    let now = evaluation_time();
    let service = MessageService::new(&fixture.software_store, SecurityPolicy::default())
        .with_remote_resolver(&fixture.resolver);

    let mut detached = Vec::new();
    service
        .sign_detached(
            fingerprint,
            PASSWORD,
            now,
            &b"software payload"[..],
            &mut detached,
            MessageFormat::Binary,
        )
        .unwrap();
    assert_eq!(
        service
            .verify_detached(&b"software payload"[..], &detached, now)
            .unwrap()
            .status,
        VerificationStatus::Valid
    );
    assert!(
        service
            .sign_detached(
                fingerprint,
                "wrong software password",
                now,
                &b"software payload"[..],
                Vec::new(),
                MessageFormat::Binary,
            )
            .is_err()
    );

    let mut encrypted = Vec::new();
    service
        .sign_and_encrypt(
            SigningKeyRequest::new(fingerprint, PASSWORD),
            EncryptionRequest::new(std::slice::from_ref(fingerprint), now, fixture.config),
            &b"software encrypted payload"[..],
            &mut encrypted,
            MessageFormat::Binary,
        )
        .unwrap();
    let decrypted = service
        .decrypt(fingerprint, PASSWORD, now, Cursor::new(&encrypted))
        .unwrap();
    assert_eq!(decrypted.report.status, DecryptionStatus::Valid);
    assert_eq!(
        decrypted.plaintext.as_deref(),
        Some(&b"software encrypted payload"[..])
    );
    let wrong = service
        .decrypt(
            fingerprint,
            "wrong software password",
            now,
            Cursor::new(&encrypted),
        )
        .unwrap();
    assert_eq!(wrong.report.status, DecryptionStatus::DecryptionFailed);
    assert_eq!(wrong.plaintext, None);

    assert!(fixture.resolver.signing_resolutions.borrow().is_empty());
    assert!(fixture.resolver.decryption_resolutions.borrow().is_empty());
    assert!(fixture.resolver.signing.sign_calls.borrow().is_empty());
    assert!(
        fixture
            .resolver
            .decryption
            .decrypt_calls
            .borrow()
            .is_empty()
    );
}

#[test]
fn decryption_resolution_is_lazy_cached_and_component_scoped() {
    let fixture = Fixture::new(GenerationProfile::nist_p256_v4());
    let fingerprint = &fixture.metadata.fingerprint;
    let now = evaluation_time();
    let service = MessageService::new(&fixture.public_store, SecurityPolicy::default())
        .with_remote_resolver(&fixture.resolver);

    let malformed = service
        .decrypt(
            fingerprint,
            PASSWORD,
            now,
            Cursor::new(&b"not an OpenPGP message"[..]),
        )
        .unwrap();
    assert_eq!(malformed.report.status, DecryptionStatus::DecryptionFailed);
    assert!(fixture.resolver.decryption_resolutions.borrow().is_empty());

    let certificate = fixture.public_store.rpgp_public_key(fingerprint).unwrap();
    let encryption_component = &fixture.metadata.subkeys[1].fingerprint;
    let encryption_key = certificate
        .public_subkeys
        .iter()
        .find(|subkey| {
            FullFingerprint::from_rpgp(&subkey.key.fingerprint()) == *encryption_component
        })
        .unwrap();
    let mut rng = rand::thread_rng();
    let mut builder = MessageBuilder::from_bytes("payload.bin", &b"two PKESK packets"[..])
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    builder.encrypt_to_key(&mut rng, encryption_key).unwrap();
    builder.encrypt_to_key(&mut rng, encryption_key).unwrap();
    let encrypted = builder.to_vec(&mut rng).unwrap();

    fixture.resolver.decline_decryption.set(true);
    let error = service
        .decrypt(fingerprint, PASSWORD, now, Cursor::new(&encrypted))
        .unwrap_err();
    assert_no_usable_key(Err::<(), _>(error), MessageOperation::Decrypt);
    assert_eq!(fixture.resolver.decryption_resolutions.borrow().len(), 1);
    assert!(
        fixture
            .resolver
            .decryption
            .decrypt_calls
            .borrow()
            .is_empty()
    );

    fixture.resolver.decline_decryption.set(false);
    let decrypted = service
        .decrypt(fingerprint, PASSWORD, now, Cursor::new(&encrypted))
        .unwrap();
    assert_eq!(decrypted.report.status, DecryptionStatus::Unsigned);
    assert_eq!(
        decrypted.plaintext.as_deref(),
        Some(&b"two PKESK packets"[..])
    );
    assert_eq!(fixture.resolver.decryption_resolutions.borrow().len(), 2);
    assert!(
        fixture
            .resolver
            .decryption_resolutions
            .borrow()
            .iter()
            .all(|(certificate, component)| certificate == fingerprint
                && component == encryption_component)
    );
    assert_eq!(fixture.resolver.decryption.decrypt_calls.borrow().len(), 1);

    fixture.resolver.mismatch_signing.set(true);
    let error = service
        .sign_detached(
            fingerprint,
            PASSWORD,
            now,
            &b"must not use the encryption component"[..],
            Vec::new(),
            MessageFormat::Binary,
        )
        .unwrap_err();
    assert_remote_error(error, MessageOperation::Sign);
    assert!(fixture.resolver.signing.sign_calls.borrow().is_empty());
    assert_eq!(fixture.resolver.signing_resolutions.borrow().len(), 1);
    assert_eq!(
        fixture.resolver.signing_resolutions.borrow()[0],
        (
            fingerprint.clone(),
            fixture.metadata.subkeys[0].fingerprint.clone()
        )
    );
}

#[test]
fn invalid_or_unavailable_components_do_not_resolve_remote_keys() {
    let fixture = Fixture::new(GenerationProfile::nist_p256_v4());
    let fingerprint = &fixture.metadata.fingerprint;
    let now = evaluation_time();
    let no_resolver = MessageService::new(&fixture.public_store, SecurityPolicy::default());
    assert_public_only(no_resolver.sign_detached(
        fingerprint,
        PASSWORD,
        now,
        &b"payload"[..],
        Vec::new(),
        MessageFormat::Binary,
    ));
    assert_public_only(no_resolver.decrypt(fingerprint, PASSWORD, now, Cursor::new(Vec::new())));

    let secret = fixture.software_store.rpgp_secret_key(fingerprint).unwrap();
    let mut encryption_only = secret.clone();
    encryption_only.secret_subkeys.retain(|subkey| {
        FullFingerprint::from_rpgp(&subkey.key.fingerprint())
            == fixture.metadata.subkeys[1].fingerprint
    });
    let encryption_only = public_certificate(&encryption_only);
    let expired = expired_certificate(secret);
    let revoked = revoked_certificate(secret);

    let created = u64::from(secret.primary_key.created_at().as_secs());
    for (certificate, at, check_decryption) in [
        (encryption_only, now, false),
        (expired, created + 101, true),
        (revoked, created + 75, true),
    ] {
        let mut store = SoftwareKeyStore::new();
        store.import_public(&certificate).unwrap();
        let service = MessageService::new(&store, SecurityPolicy::default())
            .with_remote_resolver(&fixture.resolver);
        assert_no_usable_key(
            service.sign_detached(
                fingerprint,
                PASSWORD,
                at,
                &b"payload"[..],
                Vec::new(),
                MessageFormat::Binary,
            ),
            MessageOperation::Sign,
        );
        if check_decryption {
            assert_no_usable_key(
                service.decrypt(fingerprint, PASSWORD, at, Cursor::new(Vec::new())),
                MessageOperation::Decrypt,
            );
        }
    }
    assert!(fixture.resolver.signing_resolutions.borrow().is_empty());
    assert!(fixture.resolver.decryption_resolutions.borrow().is_empty());
}

#[test]
fn provider_failures_are_sanitized_and_not_validity_reports() {
    let fixture = Fixture::new(GenerationProfile::nist_p256_v4());
    let fingerprint = &fixture.metadata.fingerprint;
    let now = evaluation_time();
    let service = MessageService::new(&fixture.public_store, SecurityPolicy::default())
        .with_remote_resolver(&fixture.resolver);

    fixture.resolver.fail_signing_resolution.set(true);
    let error = service
        .sign_detached(
            fingerprint,
            PASSWORD,
            now,
            &b"payload"[..],
            Vec::new(),
            MessageFormat::Binary,
        )
        .unwrap_err();
    assert_remote_error(error, MessageOperation::Sign);
    fixture.resolver.fail_signing_resolution.set(false);

    fixture.resolver.signing.fail.set(true);
    let error = service
        .sign_detached(
            fingerprint,
            PASSWORD,
            now,
            &b"payload"[..],
            Vec::new(),
            MessageFormat::Binary,
        )
        .unwrap_err();
    assert_remote_error(error, MessageOperation::Sign);
    fixture.resolver.signing.fail.set(false);

    let mut encrypted = Vec::new();
    service
        .encrypt(
            std::slice::from_ref(fingerprint),
            now,
            fixture.config,
            &b"encrypted payload"[..],
            &mut encrypted,
            MessageFormat::Binary,
        )
        .unwrap();

    fixture.resolver.fail_decryption_resolution.set(true);
    let error = service
        .decrypt(fingerprint, PASSWORD, now, Cursor::new(&encrypted))
        .unwrap_err();
    assert_remote_error(error, MessageOperation::Decrypt);
    fixture.resolver.fail_decryption_resolution.set(false);

    fixture.resolver.decryption.fail.set(true);
    let error = service
        .decrypt(fingerprint, PASSWORD, now, Cursor::new(&encrypted))
        .unwrap_err();
    assert_remote_error(error, MessageOperation::Decrypt);
    fixture.resolver.decryption.fail.set(false);

    fixture.resolver.decryption.fail_inner.set(true);
    let error = service
        .decrypt(fingerprint, PASSWORD, now, Cursor::new(&encrypted))
        .unwrap_err();
    assert_remote_error(error, MessageOperation::Decrypt);
    let calls = fixture.resolver.decryption.decrypt_calls.borrow();
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|(password_len, _)| *password_len == 0));
}

#[test]
fn remote_backend_and_runtime_discovery_are_enforced_before_resolution() {
    let mut fixture = Fixture::new(GenerationProfile::nist_p256_v4());
    let fingerprint = &fixture.metadata.fingerprint;
    let now = evaluation_time();

    fixture.resolver.backend = None;
    let service = MessageService::new(&fixture.public_store, SecurityPolicy::default())
        .with_remote_resolver(&fixture.resolver);
    assert!(matches!(
        service.sign_detached(
            fingerprint,
            PASSWORD,
            now,
            &b"unknown backend"[..],
            Vec::new(),
            MessageFormat::Binary,
        ),
        Err(MessageError::UnregisteredCapability {
            operation: openpgp_policy::Operation::Sign,
        })
    ));
    assert!(fixture.resolver.signing_resolutions.borrow().is_empty());

    fixture.resolver.backend = Some(Backend::OpenPgpCard);
    let service = MessageService::new(&fixture.public_store, SecurityPolicy::default())
        .with_remote_resolver(&fixture.resolver);
    assert!(matches!(
        service.sign_detached(
            fingerprint,
            PASSWORD,
            now,
            &b"undiscovered card"[..],
            Vec::new(),
            MessageFormat::Binary,
        ),
        Err(MessageError::CapabilityDisabled {
            algorithm: openpgp_policy::Algorithm::NistP256Ecdsa,
            backend: Backend::OpenPgpCard,
            operation: openpgp_policy::Operation::Sign,
            ..
        })
    ));
    let mut encrypted = Vec::new();
    service
        .encrypt(
            std::slice::from_ref(fingerprint),
            now,
            fixture.config,
            &b"public encryption remains local"[..],
            &mut encrypted,
            MessageFormat::Binary,
        )
        .unwrap();
    assert!(matches!(
        service.decrypt(fingerprint, PASSWORD, now, Cursor::new(&encrypted)),
        Err(MessageError::CapabilityDisabled {
            algorithm: openpgp_policy::Algorithm::NistP256Ecdh,
            backend: Backend::OpenPgpCard,
            operation: openpgp_policy::Operation::Decrypt,
            ..
        })
    ));
    assert!(fixture.resolver.signing_resolutions.borrow().is_empty());
    assert!(fixture.resolver.decryption_resolutions.borrow().is_empty());
    assert!(fixture.resolver.signing.sign_calls.borrow().is_empty());
    assert!(
        fixture
            .resolver
            .decryption
            .decrypt_calls
            .borrow()
            .is_empty()
    );

    fixture.resolver.runtime_capabilities_verified = true;
    let service = MessageService::new(&fixture.public_store, SecurityPolicy::default())
        .with_remote_resolver(&fixture.resolver);
    service
        .sign_detached(
            fingerprint,
            PASSWORD,
            now,
            &b"discovered card"[..],
            Vec::new(),
            MessageFormat::Binary,
        )
        .unwrap();
    let decrypted = service
        .decrypt(fingerprint, PASSWORD, now, Cursor::new(&encrypted))
        .unwrap();
    assert_eq!(
        decrypted.plaintext.as_deref(),
        Some(&b"public encryption remains local"[..])
    );
    assert_eq!(fixture.resolver.signing_resolutions.borrow().len(), 1);
    assert_eq!(fixture.resolver.decryption_resolutions.borrow().len(), 1);
    assert_eq!(fixture.resolver.signing.sign_calls.borrow().len(), 1);
    assert_eq!(fixture.resolver.decryption.decrypt_calls.borrow().len(), 1);
}

fn exercise_remote_operations(profile: GenerationProfile) {
    let fixture = Fixture::new(profile);
    let fingerprint = &fixture.metadata.fingerprint;
    let signing_component = &fixture.metadata.subkeys[0];
    let encryption_component = &fixture.metadata.subkeys[1].fingerprint;
    let now = evaluation_time();
    let service = MessageService::new(&fixture.public_store, SecurityPolicy::default())
        .with_remote_resolver(&fixture.resolver);
    assert_eq!(
        fixture.public_store.metadata(fingerprint).unwrap().storage,
        KeyStorage::PublicOnly
    );

    let payload = b"remote detached payload\0\r\n";
    let mut detached = Vec::new();
    let detached_metadata = service
        .sign_detached(
            fingerprint,
            PASSWORD,
            now,
            &payload[..],
            &mut detached,
            MessageFormat::Binary,
        )
        .unwrap();
    assert_signature_metadata(&detached_metadata, &fixture.metadata);
    let verified = service
        .verify_detached(&payload[..], &detached, now)
        .unwrap();
    assert_eq!(verified.status, VerificationStatus::Valid);
    assert_eq!(
        verified.signatures[0].signer_fingerprint.as_ref(),
        Some(&signing_component.fingerprint)
    );
    let parsed = DetachedSignature::from_bytes_many(Cursor::new(&detached))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let expected_signature_version = match fixture.metadata.key_version {
        MetadataKeyVersion::V4 => 4,
        MetadataKeyVersion::V6 => 6,
        other => panic!("unexpected test key version {other:?}"),
    };
    assert_eq!(
        u8::from(parsed.signature.version()),
        expected_signature_version
    );

    let mut attached = Vec::new();
    let attached_metadata = service
        .sign_attached(
            fingerprint,
            PASSWORD,
            now,
            &payload[..],
            &mut attached,
            MessageFormat::Binary,
        )
        .unwrap();
    assert_signature_metadata(&attached_metadata, &fixture.metadata);
    let mut attached_plaintext = Vec::new();
    let attached_verification = service
        .verify_attached(Cursor::new(&attached), &mut attached_plaintext, now)
        .unwrap();
    assert_eq!(attached_verification.status, VerificationStatus::Valid);
    assert_eq!(attached_plaintext, payload);

    let mut cleartext = Vec::new();
    let cleartext_metadata = service
        .sign_cleartext(
            fingerprint,
            PASSWORD,
            now,
            "remote first line\r\nremote second line\r\n",
            &mut cleartext,
        )
        .unwrap();
    assert_signature_metadata(&cleartext_metadata, &fixture.metadata);
    let cleartext_verification = service.verify_cleartext(&cleartext, now).unwrap();
    assert_eq!(
        cleartext_verification.outcome.status,
        VerificationStatus::Valid
    );
    assert_eq!(
        cleartext_verification.text.as_deref(),
        Some("remote first line\r\nremote second line\r\n")
    );

    let encrypted_payload = b"remote signed and encrypted payload";
    let mut encrypted = Vec::new();
    let encrypted_metadata = service
        .sign_and_encrypt(
            SigningKeyRequest::new(fingerprint, PASSWORD),
            EncryptionRequest::new(std::slice::from_ref(fingerprint), now, fixture.config),
            &encrypted_payload[..],
            &mut encrypted,
            MessageFormat::Binary,
        )
        .unwrap();
    assert_signature_metadata(&encrypted_metadata, &fixture.metadata);
    let decrypted = service
        .decrypt(fingerprint, PASSWORD, now, Cursor::new(&encrypted))
        .unwrap();
    assert_eq!(decrypted.report.status, DecryptionStatus::Valid);
    assert!(decrypted.report.may_commit_staging());
    assert_eq!(decrypted.plaintext.as_deref(), Some(&encrypted_payload[..]));
    assert_eq!(decrypted.report.signatures.len(), 1);
    assert_eq!(
        decrypted.report.signatures[0].signer_fingerprint.as_ref(),
        Some(&signing_component.fingerprint)
    );

    assert_eq!(fixture.resolver.signing_resolutions.borrow().len(), 4);
    assert!(
        fixture
            .resolver
            .signing_resolutions
            .borrow()
            .iter()
            .all(|(certificate, component)| certificate == fingerprint
                && component == &signing_component.fingerprint)
    );
    assert_eq!(fixture.resolver.decryption_resolutions.borrow().len(), 1);
    assert_eq!(
        fixture.resolver.decryption_resolutions.borrow()[0],
        (fingerprint.clone(), encryption_component.clone())
    );
    let sign_calls = fixture.resolver.signing.sign_calls.borrow();
    assert_eq!(sign_calls.len(), 4);
    assert!(sign_calls.iter().all(|password_len| *password_len == 0));
    let decrypt_calls = fixture.resolver.decryption.decrypt_calls.borrow();
    assert_eq!(decrypt_calls.len(), 1);
    assert_eq!(decrypt_calls[0].0, 0);
    match fixture.metadata.key_version {
        MetadataKeyVersion::V4 => assert!(matches!(decrypt_calls[0].1, EskType::V3_4)),
        MetadataKeyVersion::V6 => assert!(matches!(decrypt_calls[0].1, EskType::V6)),
        other => panic!("unexpected test key version {other:?}"),
    }
}

fn assert_signature_metadata(actual: &SignatureMetadata, certificate: &CertificateMetadata) {
    assert_eq!(actual.certificate_fingerprint, certificate.fingerprint);
    assert_eq!(
        actual.signer_fingerprint,
        certificate.subkeys[0].fingerprint
    );
    assert_eq!(actual.algorithm, certificate.subkeys[0].algorithm);
    assert!(actual.created_at.is_some());
}

fn assert_public_only<T>(result: Result<T, MessageError>) {
    assert!(matches!(
        result,
        Err(MessageError::Key(crate::KeyError::SecretKeyRequired { .. }))
    ));
}

fn assert_no_usable_key<T>(result: Result<T, MessageError>, operation: MessageOperation) {
    assert!(matches!(
        result,
        Err(MessageError::NoUsableKey {
            operation: actual,
            ..
        }) if actual == operation
    ));
}

fn assert_remote_error(error: MessageError, operation: MessageOperation) {
    assert!(matches!(
        &error,
        MessageError::RemoteKey {
            operation: actual,
            ..
        } if *actual == operation
    ));
    assert!(!error.to_string().contains(PROVIDER_DETAIL));
    assert!(error.source().is_none());
}

struct Fixture {
    software_store: SoftwareKeyStore,
    public_store: SoftwareKeyStore,
    resolver: TestResolver,
    metadata: CertificateMetadata,
    config: EncryptionConfig,
}

impl Fixture {
    fn new(profile: GenerationProfile) -> Self {
        let config = match profile.key_version {
            openpgp_policy::KeyVersion::V4 => EncryptionConfig::SeipdV1 {
                cipher: MessageCipher::Aes256,
            },
            openpgp_policy::KeyVersion::V6 => EncryptionConfig::SeipdV2 {
                cipher: MessageCipher::Aes256,
                mode: AeadMode::Ocb,
            },
        };
        let mut software_store = SoftwareKeyStore::new();
        let generated = software_store
            .generate(
                &profile,
                "Remote Test <remote@example.test>",
                PASSWORD,
                PrivateExportPolicy::Allowed,
            )
            .unwrap();
        let metadata = generated.metadata;
        let mut remote_secret = software_store
            .rpgp_secret_key(&metadata.fingerprint)
            .unwrap()
            .clone();
        for subkey in &mut remote_secret.secret_subkeys {
            subkey
                .key
                .remove_password(&Password::from(PASSWORD))
                .unwrap();
        }
        let resolver = TestResolver::new(&remote_secret, &metadata);
        let mut public_store = SoftwareKeyStore::new();
        public_store
            .import_public(&generated.public_certificate)
            .unwrap();
        Self {
            software_store,
            public_store,
            resolver,
            metadata,
            config,
        }
    }
}

struct TestResolver {
    certificate_fingerprint: FullFingerprint,
    signing_fingerprint: FullFingerprint,
    decryption_fingerprint: FullFingerprint,
    signing: TestRemoteKey,
    decryption: TestRemoteKey,
    backend: Option<Backend>,
    runtime_capabilities_verified: bool,
    signing_resolutions: RefCell<Vec<(FullFingerprint, FullFingerprint)>>,
    decryption_resolutions: RefCell<Vec<(FullFingerprint, FullFingerprint)>>,
    fail_signing_resolution: Cell<bool>,
    fail_decryption_resolution: Cell<bool>,
    decline_decryption: Cell<bool>,
    mismatch_signing: Cell<bool>,
}

impl TestResolver {
    fn new(secret: &SignedSecretKey, metadata: &CertificateMetadata) -> Self {
        Self {
            certificate_fingerprint: metadata.fingerprint.clone(),
            signing_fingerprint: metadata.subkeys[0].fingerprint.clone(),
            decryption_fingerprint: metadata.subkeys[1].fingerprint.clone(),
            signing: TestRemoteKey::new(component(secret, &metadata.subkeys[0].fingerprint)),
            decryption: TestRemoteKey::new(component(secret, &metadata.subkeys[1].fingerprint)),
            backend: Some(Backend::Software),
            runtime_capabilities_verified: false,
            signing_resolutions: RefCell::new(Vec::new()),
            decryption_resolutions: RefCell::new(Vec::new()),
            fail_signing_resolution: Cell::new(false),
            fail_decryption_resolution: Cell::new(false),
            decline_decryption: Cell::new(false),
            mismatch_signing: Cell::new(false),
        }
    }
}

impl RemotePrivateKeyResolver for TestResolver {
    fn backend(
        &self,
        _certificate_fingerprint: &FullFingerprint,
        _component_fingerprint: &FullFingerprint,
    ) -> Option<Backend> {
        self.backend
    }

    fn runtime_capabilities_verified(
        &self,
        _certificate_fingerprint: &FullFingerprint,
        _component_fingerprint: &FullFingerprint,
    ) -> bool {
        self.runtime_capabilities_verified
    }

    fn signing_key(
        &self,
        certificate_fingerprint: &FullFingerprint,
        component_fingerprint: &FullFingerprint,
    ) -> pgp::errors::Result<Option<&dyn SigningKey>> {
        self.signing_resolutions.borrow_mut().push((
            certificate_fingerprint.clone(),
            component_fingerprint.clone(),
        ));
        if self.fail_signing_resolution.get() {
            return Err(PROVIDER_DETAIL.to_owned().into());
        }
        if certificate_fingerprint != &self.certificate_fingerprint
            || component_fingerprint != &self.signing_fingerprint
        {
            return Ok(None);
        }
        if self.mismatch_signing.get() {
            return Ok(Some(&self.decryption));
        }
        Ok(Some(&self.signing))
    }

    fn decryption_key(
        &self,
        certificate_fingerprint: &FullFingerprint,
        component_fingerprint: &FullFingerprint,
    ) -> pgp::errors::Result<Option<&dyn DecryptionKey>> {
        self.decryption_resolutions.borrow_mut().push((
            certificate_fingerprint.clone(),
            component_fingerprint.clone(),
        ));
        if self.fail_decryption_resolution.get() {
            return Err(PROVIDER_DETAIL.to_owned().into());
        }
        if self.decline_decryption.get()
            || certificate_fingerprint != &self.certificate_fingerprint
            || component_fingerprint != &self.decryption_fingerprint
        {
            return Ok(None);
        }
        Ok(Some(&self.decryption))
    }
}

#[derive(Debug)]
struct TestRemoteKey {
    key: SecretSubkey,
    sign_calls: RefCell<Vec<usize>>,
    decrypt_calls: RefCell<Vec<(usize, EskType)>>,
    fail: Cell<bool>,
    fail_inner: Cell<bool>,
}

impl TestRemoteKey {
    fn new(key: SecretSubkey) -> Self {
        Self {
            key,
            sign_calls: RefCell::new(Vec::new()),
            decrypt_calls: RefCell::new(Vec::new()),
            fail: Cell::new(false),
            fail_inner: Cell::new(false),
        }
    }
}

impl KeyDetails for TestRemoteKey {
    fn version(&self) -> KeyVersion {
        self.key.version()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.key.legacy_key_id()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.key.fingerprint()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.key.algorithm()
    }

    fn created_at(&self) -> Timestamp {
        self.key.created_at()
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.key.legacy_v3_expiration_days()
    }

    fn public_params(&self) -> &PublicParams {
        self.key.public_params()
    }
}

impl SigningKey for TestRemoteKey {
    fn sign(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<SignatureBytes> {
        self.sign_calls.borrow_mut().push(key_pw.read().len());
        if self.fail.get() {
            return Err(PROVIDER_DETAIL.to_owned().into());
        }
        SigningKey::sign(&self.key, key_pw, hash, data)
    }

    fn hash_alg(&self) -> HashAlgorithm {
        self.key.public_params().hash_alg()
    }
}

impl DecryptionKey for TestRemoteKey {
    fn decrypt(
        &self,
        key_pw: &Password,
        values: &PkeskBytes,
        typ: EskType,
    ) -> pgp::errors::Result<pgp::errors::Result<PlainSessionKey>> {
        self.decrypt_calls
            .borrow_mut()
            .push((key_pw.read().len(), typ));
        if self.fail.get() {
            return Err(PROVIDER_DETAIL.to_owned().into());
        }
        if self.fail_inner.get() {
            return Ok(Err(PROVIDER_DETAIL.to_owned().into()));
        }
        DecryptionKey::decrypt(&self.key, key_pw, values, typ)
    }
}

fn component(secret: &SignedSecretKey, fingerprint: &FullFingerprint) -> SecretSubkey {
    secret
        .secret_subkeys
        .iter()
        .find(|subkey| FullFingerprint::from_rpgp(&subkey.key.fingerprint()) == *fingerprint)
        .unwrap()
        .key
        .clone()
}

fn public_certificate(secret: &SignedSecretKey) -> Vec<u8> {
    let public = secret.to_public_key();
    public.verify_bindings().unwrap();
    public.to_bytes().unwrap()
}

fn expired_certificate(secret: &SignedSecretKey) -> Vec<u8> {
    let mut secret = secret.clone();
    let created = secret.primary_key.created_at();
    let mut rng = rand::thread_rng();
    let mut direct =
        SignatureConfig::from_key(&mut rng, &secret.primary_key, SignatureType::Key).unwrap();
    direct.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created)).unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            secret.primary_key.fingerprint(),
        ))
        .unwrap(),
        Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(100))).unwrap(),
    ];
    let direct = direct
        .sign_key(
            &secret.primary_key,
            &Password::from(PASSWORD),
            secret.primary_key.public_key(),
        )
        .unwrap();
    secret.details.direct_signatures.push(direct);
    public_certificate(&secret)
}

fn revoked_certificate(secret: &SignedSecretKey) -> Vec<u8> {
    let mut secret = secret.clone();
    let created = Timestamp::from_secs(secret.primary_key.created_at().as_secs() + 50);
    let mut rng = rand::thread_rng();
    let mut revocation =
        SignatureConfig::from_key(&mut rng, &secret.primary_key, SignatureType::KeyRevocation)
            .unwrap();
    revocation.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created)).unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            secret.primary_key.fingerprint(),
        ))
        .unwrap(),
        Subpacket::regular(SubpacketData::RevocationReason(
            RevocationCode::KeyRetired,
            b"revoked for remote resolver testing".as_slice().into(),
        ))
        .unwrap(),
    ];
    let revocation = revocation
        .sign_key(
            &secret.primary_key,
            &Password::from(PASSWORD),
            secret.primary_key.public_key(),
        )
        .unwrap();
    secret.details.revocation_signatures.push(revocation);
    public_certificate(&secret)
}

fn evaluation_time() -> u64 {
    u64::from(Timestamp::now().as_secs())
}
