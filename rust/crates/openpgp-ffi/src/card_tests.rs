use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use openpgp_core::{
    ExportFormat, FullFingerprint, PrivateExportPolicy, RemoteKeyFailure, RemotePrivateKeyResolver,
    SoftwareKeyStore,
};
use openpgp_policy::GenerationProfile;
use pgp::{
    composed::{Deserializable as _, PlainSessionKey, SignedSecretKey},
    crypto::hash::HashAlgorithm,
    packet::SecretSubkey,
    types::{
        DecryptionKey, EskType, Fingerprint, KeyDetails, KeyId, KeyVersion, Password, PkeskBytes,
        PublicParams, SignatureBytes, SigningKey, Timestamp,
    },
};

use crate::{
    AddresseeError, DecryptionStatusFfi, EncryptionConfigFfi, ExportFormatFfi, ExportPolicyFfi,
    MessageCipherFfi, MessageFormatFfi, OpenPgpCardSession, OpenPgpEngine,
    SignEncryptFileRequestFfi, SignEncryptTextRequestFfi, VerificationStatusFfi,
};

const PASSWORD: &str = "synthetic-ffi-software-password";

#[test]
fn public_only_remote_workflows_cover_signing_encryption_and_files() {
    let fixture = Fixture::new();
    let (engine, _) = fixture.connected();
    let fingerprint = fixture.fingerprint.clone();
    let payload = b"remote binary payload\0\r\n";

    let detached = engine
        .sign_detached(
            fingerprint.clone(),
            PASSWORD.to_owned(),
            fixture.at,
            payload.to_vec(),
            MessageFormatFfi::Binary,
        )
        .unwrap();
    assert_eq!(
        engine
            .verify_detached(payload.to_vec(), detached.artifact, fixture.at)
            .unwrap()
            .status,
        VerificationStatusFfi::Valid
    );

    let attached = engine
        .sign_attached(
            fingerprint.clone(),
            String::new(),
            fixture.at,
            payload.to_vec(),
            MessageFormatFfi::Binary,
        )
        .unwrap();
    let verified = engine
        .verify_attached(attached.artifact, fixture.at)
        .unwrap();
    assert_eq!(verified.outcome.status, VerificationStatusFfi::Valid);
    assert_eq!(verified.plaintext.as_deref(), Some(payload.as_slice()));

    let cleartext = engine
        .sign_cleartext(
            fingerprint.clone(),
            String::new(),
            fixture.at,
            "first line\r\nsecond line\r\n".to_owned(),
        )
        .unwrap();
    assert_eq!(
        engine
            .verify_cleartext(cleartext.artifact, fixture.at)
            .unwrap()
            .outcome
            .status,
        VerificationStatusFfi::Valid
    );

    let encrypted = engine
        .sign_and_encrypt_text(SignEncryptTextRequestFfi {
            signing_key: fingerprint.clone(),
            password: String::new(),
            recipients: vec![fingerprint.clone()],
            at_unix_seconds: fixture.at,
            config: v4_config(),
            text: "remote signed and encrypted".to_owned(),
            format: MessageFormatFfi::Binary,
        })
        .unwrap();
    let decrypted = engine
        .decrypt_text(
            fingerprint,
            PASSWORD.to_owned(),
            fixture.at,
            encrypted.artifact,
        )
        .unwrap();
    assert_eq!(decrypted.report.status, DecryptionStatusFfi::Valid);
    assert_eq!(
        decrypted.text.as_deref(),
        Some("remote signed and encrypted")
    );
    assert!(
        fixture
            .resolver
            .failure
            .password_lengths
            .lock()
            .unwrap()
            .len()
            >= 5
    );
    assert!(
        fixture
            .resolver
            .failure
            .password_lengths
            .lock()
            .unwrap()
            .iter()
            .all(|length| *length == 0)
    );

    let directory = TestDirectory::new();
    let input = directory.path("payload.bin");
    let signature = directory.path("payload.bin.sig");
    let encrypted = directory.path("payload.pgp");
    let output = directory.path("decrypted.bin");
    fs::write(&input, payload).unwrap();
    engine
        .sign_detached_file(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            input.clone(),
            signature.clone(),
            MessageFormatFfi::Binary,
        )
        .unwrap();
    assert_eq!(
        engine
            .verify_detached_file(input.clone(), signature, fixture.at)
            .unwrap()
            .status,
        VerificationStatusFfi::Valid
    );
    engine
        .sign_and_encrypt_file(SignEncryptFileRequestFfi {
            signing_key: fixture.fingerprint.clone(),
            password: String::new(),
            recipients: vec![fixture.fingerprint.clone()],
            at_unix_seconds: fixture.at,
            config: v4_config(),
            input_path: input,
            output_path: encrypted.clone(),
            format: MessageFormatFfi::Binary,
        })
        .unwrap();
    let report = engine
        .decrypt_file(
            fixture.fingerprint,
            String::new(),
            fixture.at,
            encrypted,
            output.clone(),
        )
        .unwrap();
    assert_eq!(report.status, DecryptionStatusFfi::Valid);
    assert_eq!(fs::read(output).unwrap(), payload);
}

#[test]
fn card_v4_nist_p256_provider_workflow() {
    card_provider_workflow(GenerationProfile::nist_p256_v4());
}

#[test]
fn card_v4_nist_p384_provider_workflow() {
    card_provider_workflow(GenerationProfile::nist_p384_v4());
}

#[test]
fn card_v4_nist_p521_provider_workflow() {
    card_provider_workflow(GenerationProfile::nist_p521_v4());
}

#[test]
fn card_v4_rsa2048_provider_workflow() {
    card_provider_workflow(card_rsa_profile(openpgp_policy::Algorithm::Rsa2048));
}

#[test]
fn card_v4_rsa3072_provider_workflow() {
    card_provider_workflow(card_rsa_profile(openpgp_policy::Algorithm::Rsa3072));
}

#[test]
fn card_v4_rsa4096_provider_workflow() {
    card_provider_workflow(card_rsa_profile(openpgp_policy::Algorithm::Rsa4096));
}

#[test]
fn card_v4_legacy_curve25519_provider_workflow() {
    card_provider_workflow(
        GenerationProfile::legacy_curve25519_v4(
            openpgp_policy::CompatibilityAcknowledgement::acknowledged(),
        )
        .unwrap(),
    );
}

fn card_rsa_profile(algorithm: openpgp_policy::Algorithm) -> GenerationProfile {
    GenerationProfile::legacy_rsa_v4(
        algorithm,
        openpgp_policy::CompatibilityAcknowledgement::acknowledged(),
    )
    .unwrap()
}

fn card_provider_workflow(profile: GenerationProfile) {
    let algorithm = profile.primary_key.algorithm;
    let fixture = Fixture::with_profile(profile);
    let (engine, _) = fixture.connected();
    let metadata = engine.key_metadata(fixture.fingerprint.clone()).unwrap();
    let signing_metadata = metadata
        .subkeys
        .iter()
        .find(|key| key.fingerprint == fixture.resolver.signing_fingerprint.as_str())
        .unwrap();
    assert!(signing_metadata.key_flags.sign, "{signing_metadata:?}");
    let certificate_fingerprint =
        FullFingerprint::from_hex(&fixture.fingerprint).expect("test certificate fingerprint");
    let validity = engine
        .lock()
        .unwrap()
        .evaluate_validity(&certificate_fingerprint, fixture.at)
        .unwrap();
    assert!(validity.subkey_is_valid(0).unwrap(), "{validity:?}");
    let providers = engine.lock_remote_read().unwrap();
    assert!(providers.runtime_capabilities_verified(
        &certificate_fingerprint,
        &fixture.resolver.signing_fingerprint,
    ));
    assert!(
        providers
            .signing_key(
                &certificate_fingerprint,
                &fixture.resolver.signing_fingerprint
            )
            .unwrap()
            .is_some()
    );
    drop(providers);
    let payload = format!("synthetic card workflow {algorithm:?}");
    let signature = engine
        .sign_detached(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            payload.as_bytes().to_vec(),
            MessageFormatFfi::Binary,
        )
        .unwrap_or_else(|error| panic!("{algorithm:?} subkey signing: {error:?}"));
    assert_eq!(
        engine
            .verify_detached(payload.as_bytes().to_vec(), signature.artifact, fixture.at)
            .unwrap()
            .status,
        VerificationStatusFfi::Valid,
        "{algorithm:?} subkey verification"
    );
    let encrypted = engine
        .encrypt_text(
            vec![fixture.fingerprint.clone()],
            fixture.at,
            v4_config(),
            payload.clone(),
            MessageFormatFfi::Binary,
        )
        .unwrap_or_else(|error| panic!("{algorithm:?} encryption: {error:?}"));
    let decrypted = engine
        .decrypt_text(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            encrypted,
        )
        .unwrap_or_else(|error| panic!("{algorithm:?} subkey decryption: {error:?}"));
    assert_eq!(decrypted.report.status, DecryptionStatusFfi::Unsigned);
    assert_eq!(decrypted.text.as_deref(), Some(payload.as_str()));

    let (primary, _) = fixture.primary_connected();
    let primary_signature = primary
        .sign_detached(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            payload.as_bytes().to_vec(),
            MessageFormatFfi::Binary,
        )
        .unwrap_or_else(|error| panic!("{algorithm:?} primary signing: {error:?}"));
    assert_eq!(
        primary_signature.metadata.signer_fingerprint,
        fixture.fingerprint
    );
    assert_eq!(
        primary
            .verify_detached(payload.into_bytes(), primary_signature.artifact, fixture.at,)
            .unwrap()
            .status,
        VerificationStatusFfi::Valid,
        "{algorithm:?} primary verification"
    );
    assert!(
        fixture
            .resolver
            .failure
            .password_lengths
            .lock()
            .unwrap()
            .iter()
            .all(|length| *length == 0)
    );
}

#[test]
fn cancellation_and_provider_failures_are_typed_and_sanitized() {
    let fixture = Fixture::new();
    let (engine, _) = fixture.connected();
    let sign = || {
        engine.sign_detached(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            b"must not complete".to_vec(),
            MessageFormatFfi::Binary,
        )
    };

    fixture.resolver.fail(RemoteKeyFailure::Cancelled, false);
    assert!(matches!(sign(), Err(AddresseeError::OperationCancelled)));
    fixture.resolver.fail(RemoteKeyFailure::Cancelled, true);
    assert!(matches!(sign(), Err(AddresseeError::OperationCancelled)));

    let encrypted = engine
        .encrypt(
            vec![fixture.fingerprint.clone()],
            fixture.at,
            v4_config(),
            b"remote cancellation".to_vec(),
            MessageFormatFfi::Binary,
        )
        .unwrap();
    assert!(matches!(
        engine.decrypt_text(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            encrypted,
        ),
        Err(AddresseeError::OperationCancelled)
    ));

    fixture.resolver.fail(RemoteKeyFailure::Unavailable, true);
    let error = sign().unwrap_err();
    assert_eq!(error, AddresseeError::RemoteKeyUnavailable);
    assert!(!error.to_string().contains("sensitive provider detail"));
}

#[test]
fn session_lifecycle_and_storage_rules_cannot_be_bypassed() {
    let fixture = Fixture::new();
    let engine = OpenPgpEngine::new();
    engine
        .import_public_key(fixture.public_certificate.clone())
        .unwrap();
    let session = fixture.session();
    let registration = engine.attach_card_session(session.clone()).unwrap();
    assert_eq!(registration.certificate_fingerprint, fixture.fingerprint);
    assert_eq!(registration.identity.manufacturer, 0xFFFF);
    assert_eq!(registration.components.len(), 2);
    assert_eq!(engine.card_registrations().unwrap(), vec![registration]);
    assert_eq!(
        engine.attach_card_session(session),
        Err(AddresseeError::CardRegistrationConflict)
    );
    assert_eq!(
        engine.export_private_key(fixture.fingerprint.clone(), ExportFormatFfi::Binary),
        Err(AddresseeError::PublicKeyOnly)
    );
    assert!(matches!(
        engine.import_private_key(
            fixture.private_key.clone(),
            Some(PASSWORD.to_owned()),
            "another-test-password".to_owned(),
            ExportPolicyFfi::Disabled,
        ),
        Err(AddresseeError::AmbiguousPrivateKeyStorage)
    ));

    let mut records = engine.storage_snapshot().unwrap();
    assert_eq!(records.len(), 1);
    records[0].protected_secret = Some(vec![0x55]);
    assert_eq!(
        engine.restore_storage(records),
        Err(AddresseeError::AmbiguousPrivateKeyStorage)
    );
    engine
        .detach_card_session(fixture.fingerprint.clone())
        .unwrap();
    assert!(engine.card_registrations().unwrap().is_empty());
    assert_eq!(
        engine.detach_card_session(fixture.fingerprint.clone()),
        Err(AddresseeError::CardSessionUnavailable)
    );
    assert!(matches!(
        engine.sign_detached(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            b"detached".to_vec(),
            MessageFormatFfi::Binary,
        ),
        Err(AddresseeError::PublicKeyOnly)
    ));

    engine.attach_card_session(fixture.session()).unwrap();
    engine.remove_key(fixture.fingerprint.clone()).unwrap();
    assert!(engine.card_registrations().unwrap().is_empty());
    assert_eq!(
        engine.remove_key(fixture.fingerprint),
        Err(AddresseeError::KeyNotFound)
    );
}

#[test]
fn offline_card_reservations_preserve_storage_rules_without_a_live_session() {
    let fixture = Fixture::new();
    let engine = OpenPgpEngine::new();
    engine
        .import_public_key(fixture.public_certificate.clone())
        .unwrap();
    let session = fixture.session();
    let registration = session.registration();
    engine
        .reserve_card_binding(registration.clone(), fixture.public_certificate.clone())
        .unwrap();
    assert!(engine.card_registrations().unwrap().is_empty());
    assert!(matches!(
        engine.sign_detached(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            b"reserved but disconnected".to_vec(),
            MessageFormatFfi::Binary,
        ),
        Err(AddresseeError::RemoteKeyUnavailable)
    ));
    assert!(
        fixture
            .resolver
            .failure
            .password_lengths
            .lock()
            .unwrap()
            .is_empty()
    );
    let import_private = || {
        engine.import_private_key(
            fixture.private_key.clone(),
            Some(PASSWORD.to_owned()),
            "new-software-test-password".to_owned(),
            ExportPolicyFfi::Disabled,
        )
    };
    assert!(matches!(
        import_private(),
        Err(AddresseeError::AmbiguousPrivateKeyStorage)
    ));

    let mut mismatched = registration.clone();
    mismatched.identity.serial ^= 1;
    assert_eq!(
        engine.reserve_card_binding(mismatched, fixture.public_certificate.clone()),
        Err(AddresseeError::CardRegistrationConflict)
    );
    assert!(!engine.list_keys().unwrap()[0].primary.key_flags.sign);
    let mut non_signing_primary = registration.clone();
    non_signing_primary.components[0].component_fingerprint = fixture.fingerprint.clone();
    assert_eq!(
        engine.reserve_card_binding(non_signing_primary, fixture.public_certificate.clone()),
        Err(AddresseeError::UnsupportedOperation)
    );
    let mut missing_component = registration.clone();
    missing_component.components[0].component_fingerprint = "00".repeat(20);
    assert_eq!(
        engine.reserve_card_binding(missing_component, fixture.public_certificate.clone()),
        Err(AddresseeError::InvalidCertificate)
    );

    engine.attach_card_session(session).unwrap();
    engine
        .detach_card_session(fixture.fingerprint.clone())
        .unwrap();
    assert!(matches!(
        import_private(),
        Err(AddresseeError::AmbiguousPrivateKeyStorage)
    ));
    engine
        .release_card_binding(fixture.fingerprint.clone())
        .unwrap();
    import_private().unwrap();
    assert_eq!(
        engine.reserve_card_binding(registration, fixture.public_certificate.clone()),
        Err(AddresseeError::AmbiguousPrivateKeyStorage)
    );
}

#[test]
fn an_existing_software_certificate_cannot_become_hardware_backed() {
    let fixture = Fixture::new();
    let engine = OpenPgpEngine::new();
    engine
        .import_private_key(
            fixture.private_key.clone(),
            Some(PASSWORD.to_owned()),
            "new-software-test-password".to_owned(),
            ExportPolicyFfi::Disabled,
        )
        .unwrap();
    assert_eq!(
        engine.attach_card_session(fixture.session()),
        Err(AddresseeError::AmbiguousPrivateKeyStorage)
    );
    let signature = engine
        .sign_detached(
            fixture.fingerprint.clone(),
            "new-software-test-password".to_owned(),
            fixture.at,
            b"software remains software".to_vec(),
            MessageFormatFfi::Binary,
        )
        .unwrap();
    assert_eq!(
        engine
            .verify_detached(
                b"software remains software".to_vec(),
                signature.artifact,
                fixture.at,
            )
            .unwrap()
            .status,
        VerificationStatusFfi::Valid
    );
    assert!(
        fixture
            .resolver
            .failure
            .password_lengths
            .lock()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_signing_primary_can_be_reserved_with_a_public_decryption_subkey() {
    let fixture = Fixture::new();
    let (mut secret, _) = SignedSecretKey::from_string(
        std::str::from_utf8(&fixture.private_key).expect("armored test private key"),
    )
    .expect("parse test private key");
    let mut flags = pgp::packet::KeyFlags::default();
    flags.set_certify(true);
    flags.set_sign(true);
    let mut direct = pgp::packet::SignatureConfig::from_key(
        rand::thread_rng(),
        &secret.primary_key,
        pgp::packet::SignatureType::Key,
    )
    .unwrap();
    direct.hashed_subpackets = vec![
        pgp::packet::Subpacket::regular(pgp::packet::SubpacketData::SignatureCreationTime(
            secret.primary_key.created_at(),
        ))
        .unwrap(),
        pgp::packet::Subpacket::regular(pgp::packet::SubpacketData::KeyFlags(flags)).unwrap(),
    ];
    let signature = direct
        .sign_key(
            &secret.primary_key,
            &Password::from(PASSWORD),
            secret.primary_key.public_key(),
        )
        .unwrap();
    secret.details.direct_signatures = vec![signature];
    secret.public_subkeys = vec![secret.secret_subkeys[1].signed_public_key()];
    secret.secret_subkeys.clear();
    let public = pgp::ser::Serialize::to_bytes(&secret.to_public_key()).unwrap();
    let engine = OpenPgpEngine::new();
    engine.import_public_key(public.clone()).unwrap();
    let registration = crate::CardRegistrationFfi {
        certificate_fingerprint: fixture.fingerprint.clone(),
        identity: crate::CardIdentityFfi {
            manufacturer: 0xF1D0,
            serial: 0x0123ABCD,
            version: 0x0304,
        },
        components: vec![
            crate::CardComponentBindingFfi {
                slot: crate::CardSlot::Signing,
                component_fingerprint: fixture.fingerprint.clone(),
            },
            crate::CardComponentBindingFfi {
                slot: crate::CardSlot::Decryption,
                component_fingerprint: fixture.resolver.decryption_fingerprint.to_string(),
            },
        ],
    };
    engine
        .reserve_card_binding(registration.clone(), public.clone())
        .unwrap();
    assert!(engine.card_registrations().unwrap().is_empty());
    assert!(
        engine
            .sign_detached(
                fixture.fingerprint.clone(),
                String::new(),
                fixture.at,
                b"offline card reservation".to_vec(),
                MessageFormatFfi::Binary,
            )
            .is_err()
    );
    engine
        .reserve_card_binding(registration, public.clone())
        .unwrap();
    engine
        .release_card_binding(fixture.fingerprint.clone())
        .unwrap();
    assert!(matches!(
        engine.sign_detached(
            fixture.fingerprint,
            String::new(),
            fixture.at,
            b"reservation was released".to_vec(),
            MessageFormatFfi::Binary,
        ),
        Err(AddresseeError::PublicKeyOnly)
    ));
}

#[test]
fn detaching_waits_for_an_in_flight_message_operation() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<OpenPgpEngine>();
    assert_send_sync::<OpenPgpCardSession>();

    let fixture = Fixture::new();
    let (engine, session) = fixture.connected();
    let engine = Arc::new(engine);
    let gate = fixture.resolver.pause_next_operation();
    let worker = {
        let engine = Arc::clone(&engine);
        let fingerprint = fixture.fingerprint.clone();
        let at = fixture.at;
        std::thread::spawn(move || {
            engine.sign_detached(
                fingerprint,
                String::new(),
                at,
                b"serialized remote operation".to_vec(),
                MessageFormatFfi::Binary,
            )
        })
    };
    gate.wait();
    assert!(matches!(
        engine.store.try_lock(),
        Err(std::sync::TryLockError::WouldBlock)
    ));
    let detacher = {
        let engine = Arc::clone(&engine);
        let fingerprint = fixture.fingerprint.clone();
        std::thread::spawn(move || engine.detach_card_session(fingerprint))
    };
    gate.wait();
    assert_eq!(
        worker
            .join()
            .unwrap()
            .unwrap()
            .metadata
            .certificate_fingerprint,
        fixture.fingerprint
    );
    detacher.join().unwrap().unwrap();
    assert!(engine.card_registrations().unwrap().is_empty());
    assert!(matches!(
        engine.sign_detached(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            b"detached".to_vec(),
            MessageFormatFfi::Binary,
        ),
        Err(AddresseeError::PublicKeyOnly)
    ));
    drop(session);
}

struct Fixture {
    fingerprint: String,
    public_certificate: Vec<u8>,
    private_key: Vec<u8>,
    resolver: Arc<TestResolver>,
    at: u64,
}

impl Fixture {
    fn new() -> Self {
        Self::with_profile(GenerationProfile::nist_p256_v4())
    }

    fn with_profile(profile: GenerationProfile) -> Self {
        let mut store = SoftwareKeyStore::new();
        let generated = store
            .generate(
                &profile,
                "Synthetic Card FFI <card@example.invalid>",
                PASSWORD,
                PrivateExportPolicy::Allowed,
            )
            .unwrap();
        let fingerprint = generated.metadata.fingerprint.clone();
        let signing_fingerprint = generated.metadata.subkeys[0].fingerprint.clone();
        let decryption_fingerprint = generated.metadata.subkeys[1].fingerprint.clone();
        let private_key = store
            .export_private(&fingerprint, ExportFormat::Armored)
            .unwrap();
        let (mut secret, _) = SignedSecretKey::from_string(
            std::str::from_utf8(&private_key).expect("armored test private key"),
        )
        .expect("parse test private key");
        for subkey in &mut secret.secret_subkeys {
            subkey
                .key
                .remove_password(&Password::from(PASSWORD))
                .unwrap();
        }
        let failure = Arc::new(Failure::default());
        let resolver = Arc::new(TestResolver {
            certificate_fingerprint: fingerprint.clone(),
            signing_fingerprint,
            decryption_fingerprint,
            signing: TestRemoteKey::new(
                component(&secret, &generated.metadata.subkeys[0].fingerprint),
                Arc::clone(&failure),
            ),
            decryption: TestRemoteKey::new(
                component(&secret, &generated.metadata.subkeys[1].fingerprint),
                Arc::clone(&failure),
            ),
            failure,
            fail_resolution: AtomicBool::new(false),
        });
        let at = u64::from(Timestamp::now().as_secs());
        Self {
            fingerprint: fingerprint.to_string(),
            public_certificate: generated.public_certificate,
            private_key,
            resolver,
            at,
        }
    }

    fn session(&self) -> Arc<OpenPgpCardSession> {
        Arc::new(
            OpenPgpCardSession::from_resolver_for_tests(
                &self.public_certificate,
                self.resolver.clone(),
            )
            .unwrap(),
        )
    }

    fn connected(&self) -> (OpenPgpEngine, Arc<OpenPgpCardSession>) {
        let engine = OpenPgpEngine::new();
        engine
            .import_public_key(self.public_certificate.clone())
            .unwrap();
        let session = self.session();
        engine.attach_card_session(session.clone()).unwrap();
        (engine, session)
    }

    fn primary_connected(&self) -> (OpenPgpEngine, Arc<OpenPgpCardSession>) {
        let (mut secret, _) = SignedSecretKey::from_string(
            std::str::from_utf8(&self.private_key).expect("armored test private key"),
        )
        .expect("parse test private key");
        let mut flags = pgp::packet::KeyFlags::default();
        flags.set_certify(true);
        flags.set_sign(true);
        let mut direct = pgp::packet::SignatureConfig::from_key(
            rand::thread_rng(),
            &secret.primary_key,
            pgp::packet::SignatureType::Key,
        )
        .unwrap();
        direct.hashed_subpackets = vec![
            pgp::packet::Subpacket::regular(pgp::packet::SubpacketData::SignatureCreationTime(
                secret.primary_key.created_at(),
            ))
            .unwrap(),
            pgp::packet::Subpacket::regular(pgp::packet::SubpacketData::KeyFlags(flags)).unwrap(),
        ];
        let signature = direct
            .sign_key(
                &secret.primary_key,
                &Password::from(PASSWORD),
                secret.primary_key.public_key(),
            )
            .unwrap();
        secret.details.direct_signatures = vec![signature];
        secret
            .primary_key
            .remove_password(&Password::from(PASSWORD))
            .unwrap();
        let public = pgp::ser::Serialize::to_bytes(&secret.to_public_key()).unwrap();
        let fingerprint = FullFingerprint::from_hex(&self.fingerprint).unwrap();
        let failure = Arc::new(Failure::default());
        let resolver = Arc::new(TestResolver {
            certificate_fingerprint: fingerprint.clone(),
            signing_fingerprint: fingerprint.clone(),
            decryption_fingerprint: fingerprint,
            signing: TestRemoteKey::new_primary(secret.primary_key.clone(), Arc::clone(&failure)),
            decryption: TestRemoteKey::new_primary(secret.primary_key, Arc::clone(&failure)),
            failure,
            fail_resolution: AtomicBool::new(false),
        });
        let engine = OpenPgpEngine::new();
        let session = Arc::new(
            OpenPgpCardSession::from_primary_resolver_for_tests(&public, resolver).unwrap(),
        );
        engine.import_public_key(public).unwrap();
        engine.attach_card_session(session.clone()).unwrap();
        (engine, session)
    }
}

#[derive(Debug, Default)]
struct Failure {
    kind: AtomicU8,
    during_operation: AtomicBool,
    password_lengths: Mutex<Vec<usize>>,
    operation_gate: Mutex<Option<Arc<std::sync::Barrier>>>,
}

struct TestResolver {
    certificate_fingerprint: FullFingerprint,
    signing_fingerprint: FullFingerprint,
    decryption_fingerprint: FullFingerprint,
    signing: TestRemoteKey,
    decryption: TestRemoteKey,
    failure: Arc<Failure>,
    fail_resolution: AtomicBool,
}

impl TestResolver {
    fn fail(&self, kind: RemoteKeyFailure, during_operation: bool) {
        self.failure.kind.store(
            match kind {
                RemoteKeyFailure::Unavailable => 0,
                RemoteKeyFailure::Cancelled => 1,
            },
            Ordering::SeqCst,
        );
        self.failure
            .during_operation
            .store(during_operation, Ordering::SeqCst);
        self.fail_resolution
            .store(!during_operation, Ordering::SeqCst);
    }

    fn pause_next_operation(&self) -> Arc<std::sync::Barrier> {
        let gate = Arc::new(std::sync::Barrier::new(2));
        *self.failure.operation_gate.lock().unwrap() = Some(Arc::clone(&gate));
        gate
    }
}

impl RemotePrivateKeyResolver for TestResolver {
    fn backend(
        &self,
        _certificate: &FullFingerprint,
        _component: &FullFingerprint,
    ) -> Option<openpgp_policy::Backend> {
        Some(openpgp_policy::Backend::OpenPgpCard)
    }

    fn runtime_capabilities_verified(
        &self,
        _certificate: &FullFingerprint,
        _component: &FullFingerprint,
    ) -> bool {
        true
    }

    fn signing_key(
        &self,
        certificate: &FullFingerprint,
        component: &FullFingerprint,
    ) -> pgp::errors::Result<Option<&dyn SigningKey>> {
        if self.fail_resolution.load(Ordering::SeqCst) {
            return Err("sensitive provider detail".to_owned().into());
        }
        Ok(
            (certificate == &self.certificate_fingerprint
                && component == &self.signing_fingerprint)
                .then_some(&self.signing as &dyn SigningKey),
        )
    }

    fn decryption_key(
        &self,
        certificate: &FullFingerprint,
        component: &FullFingerprint,
    ) -> pgp::errors::Result<Option<&dyn DecryptionKey>> {
        if self.fail_resolution.load(Ordering::SeqCst) {
            return Err("sensitive provider detail".to_owned().into());
        }
        Ok((certificate == &self.certificate_fingerprint
            && component == &self.decryption_fingerprint)
            .then_some(&self.decryption as &dyn DecryptionKey))
    }

    fn failure_kind(
        &self,
        _certificate: &FullFingerprint,
        _component: &FullFingerprint,
        _operation: openpgp_core::MessageOperation,
    ) -> RemoteKeyFailure {
        match self.failure.kind.load(Ordering::SeqCst) {
            1 => RemoteKeyFailure::Cancelled,
            _ => RemoteKeyFailure::Unavailable,
        }
    }
}

enum TestRemoteKeyMaterial {
    Primary(pgp::packet::SecretKey),
    Subkey(SecretSubkey),
}

struct TestRemoteKey {
    key: TestRemoteKeyMaterial,
    failure: Arc<Failure>,
}

impl std::fmt::Debug for TestRemoteKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TestRemoteKey")
            .field("fingerprint", &self.key_details().fingerprint())
            .finish_non_exhaustive()
    }
}

impl TestRemoteKey {
    fn new(key: SecretSubkey, failure: Arc<Failure>) -> Self {
        Self {
            key: TestRemoteKeyMaterial::Subkey(key),
            failure,
        }
    }

    fn new_primary(key: pgp::packet::SecretKey, failure: Arc<Failure>) -> Self {
        Self {
            key: TestRemoteKeyMaterial::Primary(key),
            failure,
        }
    }

    fn key_details(&self) -> &dyn KeyDetails {
        match &self.key {
            TestRemoteKeyMaterial::Primary(key) => key,
            TestRemoteKeyMaterial::Subkey(key) => key,
        }
    }

    fn record_password(&self, password: &Password) -> pgp::errors::Result<()> {
        self.failure
            .password_lengths
            .lock()
            .unwrap()
            .push(password.read().len());
        if self.failure.during_operation.load(Ordering::SeqCst) {
            return Err("sensitive provider detail".to_owned().into());
        }
        let gate = self.failure.operation_gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate.wait();
            gate.wait();
        }
        Ok(())
    }
}

impl KeyDetails for TestRemoteKey {
    fn version(&self) -> KeyVersion {
        self.key_details().version()
    }
    fn legacy_key_id(&self) -> KeyId {
        self.key_details().legacy_key_id()
    }
    fn fingerprint(&self) -> Fingerprint {
        self.key_details().fingerprint()
    }
    fn algorithm(&self) -> pgp::crypto::public_key::PublicKeyAlgorithm {
        self.key_details().algorithm()
    }
    fn created_at(&self) -> Timestamp {
        self.key_details().created_at()
    }
    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.key_details().legacy_v3_expiration_days()
    }
    fn public_params(&self) -> &PublicParams {
        self.key_details().public_params()
    }
}

impl SigningKey for TestRemoteKey {
    fn sign(
        &self,
        password: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<SignatureBytes> {
        self.record_password(password)?;
        match &self.key {
            TestRemoteKeyMaterial::Primary(key) => SigningKey::sign(key, password, hash, data),
            TestRemoteKeyMaterial::Subkey(key) => SigningKey::sign(key, password, hash, data),
        }
    }

    fn hash_alg(&self) -> HashAlgorithm {
        self.key_details().public_params().hash_alg()
    }
}

impl DecryptionKey for TestRemoteKey {
    fn decrypt(
        &self,
        password: &Password,
        values: &PkeskBytes,
        typ: EskType,
    ) -> pgp::errors::Result<pgp::errors::Result<PlainSessionKey>> {
        self.record_password(password)?;
        match &self.key {
            TestRemoteKeyMaterial::Primary(key) => {
                DecryptionKey::decrypt(key, password, values, typ)
            }
            TestRemoteKeyMaterial::Subkey(key) => {
                DecryptionKey::decrypt(key, password, values, typ)
            }
        }
    }
}

fn component(secret: &SignedSecretKey, fingerprint: &FullFingerprint) -> SecretSubkey {
    secret
        .secret_subkeys
        .iter()
        .find(|subkey| {
            FullFingerprint::from_hex(&format!("{:X}", subkey.key.fingerprint())).unwrap()
                == *fingerprint
        })
        .unwrap()
        .key
        .clone()
}

fn v4_config() -> EncryptionConfigFfi {
    EncryptionConfigFfi::SeipdV1 {
        cipher: MessageCipherFfi::Aes256,
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "addressee-card-ffi-{}-{unique}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
