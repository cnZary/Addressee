#![allow(clippy::expect_used, clippy::unwrap_used)]

use openpgp_policy::{GenerationProfile, SecurityPolicy};
use pgp::{
    composed::{KeyType, SecretKeyParamsBuilder},
    ser::Serialize as _,
    types::{KeyDetails as _, Timestamp},
};

use crate::{
    DecryptionStatus, EncryptionConfig, ExportFormat, FullFingerprint, GeneratedKey, KeyError,
    MessageFormat, MessageService, PrivateExportPolicy, SecretComponent, SoftwareKeyStore,
    StorageRecord, VerificationStatus,
};

const PASSWORD: &str = "storage test password";

fn generate(
    store: &mut SoftwareKeyStore,
    profile: GenerationProfile,
    user_id: &str,
    export_policy: PrivateExportPolicy,
) -> GeneratedKey {
    store
        .generate(&profile, user_id, PASSWORD, export_policy)
        .unwrap()
}

fn modern_key(export_policy: PrivateExportPolicy) -> (SoftwareKeyStore, GeneratedKey) {
    let mut store = SoftwareKeyStore::new();
    let generated = generate(
        &mut store,
        GenerationProfile::modern_v6(),
        "Storage <storage@example.test>",
        export_policy,
    );
    (store, generated)
}

fn evaluation_time() -> u64 {
    u64::from(Timestamp::now().as_secs())
}

#[test]
fn snapshot_restore_preserves_protection_policy_and_operations() {
    let (mut store, disabled) = modern_key(PrivateExportPolicy::Disabled);
    let allowed = generate(
        &mut store,
        GenerationProfile::nist_p256_v4(),
        "Allowed <allowed@example.test>",
        PrivateExportPolicy::Allowed,
    );
    let (public_store, public_only) = modern_key(PrivateExportPolicy::Disabled);
    store
        .import_public(&public_only.public_certificate)
        .unwrap();
    drop(public_store);

    let snapshot = store.storage_snapshot().unwrap();
    assert_eq!(snapshot.len(), 3);
    let mut restored = SoftwareKeyStore::new();
    restored.restore_storage(snapshot.clone()).unwrap();
    assert_eq!(
        restored.list_metadata().unwrap(),
        store.list_metadata().unwrap()
    );

    assert!(matches!(
        restored.export_private(&disabled.metadata.fingerprint, ExportFormat::Binary),
        Err(KeyError::PrivateExportDisabled { .. })
    ));
    restored
        .export_private(&allowed.metadata.fingerprint, ExportFormat::Binary)
        .unwrap();
    assert!(matches!(
        restored.export_private(&public_only.metadata.fingerprint, ExportFormat::Binary),
        Err(KeyError::SecretKeyRequired { .. })
    ));

    let service = MessageService::new(&restored, SecurityPolicy::default());
    let now = evaluation_time();
    let fingerprint = disabled.metadata.fingerprint.clone();
    let mut signature = Vec::new();
    service
        .sign_detached(
            &fingerprint,
            PASSWORD,
            now,
            &b"restored payload"[..],
            &mut signature,
            MessageFormat::Binary,
        )
        .unwrap();
    let verified = service
        .verify_detached(&b"restored payload"[..], &signature, now)
        .unwrap();
    assert_eq!(verified.status, VerificationStatus::Valid);
    assert!(
        service
            .sign_detached(
                &fingerprint,
                "wrong password",
                now,
                &b"restored payload"[..],
                &mut Vec::new(),
                MessageFormat::Binary,
            )
            .is_err()
    );

    let mut encrypted = Vec::new();
    service
        .encrypt(
            std::slice::from_ref(&fingerprint),
            now,
            EncryptionConfig::SeipdV2 {
                cipher: crate::MessageCipher::Aes256,
                mode: crate::AeadMode::Ocb,
            },
            &b"restored secret"[..],
            &mut encrypted,
            MessageFormat::Binary,
        )
        .unwrap();
    let decrypted = service
        .decrypt(
            &fingerprint,
            PASSWORD,
            now,
            std::io::Cursor::new(&encrypted),
        )
        .unwrap();
    assert_eq!(decrypted.report.status, DecryptionStatus::Unsigned);
    assert_eq!(
        decrypted.plaintext.as_deref(),
        Some(&b"restored secret"[..])
    );

    restored.restore_storage(snapshot).unwrap();
    assert_eq!(restored.len(), store.len());
}

#[test]
fn restore_rejects_tampered_and_mismatched_records() {
    let (store, _) = modern_key(PrivateExportPolicy::Allowed);
    let snapshot = store.storage_snapshot().unwrap();
    assert_eq!(snapshot.len(), 1);

    // OpenPGP secret-key ciphertext has no authentication of its own, so a flipped
    // byte inside encrypted payload is not guaranteed to be detected here. Tamper
    // evidence belongs to the outer authenticated storage envelope. Structural
    // corruption such as truncation must always fail.
    let mut truncated = snapshot.clone();
    let secret = truncated[0].protected_secret.as_mut().unwrap();
    secret.truncate(secret.len() - 8);
    assert!(SoftwareKeyStore::new().restore_storage(truncated).is_err());

    let (_, other) = modern_key(PrivateExportPolicy::Allowed);
    let mut mismatched = snapshot.clone();
    mismatched[0].fingerprint = other.metadata.fingerprint.clone();
    assert!(matches!(
        SoftwareKeyStore::new().restore_storage(mismatched),
        Err(KeyError::ConflictingCertificate { .. })
    ));

    let mut wrong_public = snapshot.clone();
    wrong_public[0].public_certificate = other.public_certificate.clone();
    assert!(matches!(
        SoftwareKeyStore::new().restore_storage(wrong_public),
        Err(KeyError::ConflictingCertificate { .. })
    ));

    let mut missing_policy = snapshot.clone();
    missing_policy[0].export_policy = None;
    assert!(matches!(
        SoftwareKeyStore::new().restore_storage(missing_policy),
        Err(KeyError::InvalidParameters(_))
    ));

    let mut restored = SoftwareKeyStore::new();
    restored.restore_storage(snapshot).unwrap();
    assert!(matches!(
        restored.export_private(&other.metadata.fingerprint, ExportFormat::Binary),
        Err(KeyError::KeyNotFound { .. })
    ));
}

#[test]
fn restore_rejects_unprotected_secret_material() {
    let mut rng = rand::thread_rng();
    let params = SecretKeyParamsBuilder::default()
        .version(pgp::types::KeyVersion::V4)
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .primary_user_id("Unprotected <unprotected@example.test>".to_owned())
        .passphrase(None)
        .s2k(None)
        .build()
        .unwrap();
    let secret = params.generate(&mut rng).unwrap();
    let public = secret.to_public_key();
    let record = StorageRecord {
        fingerprint: FullFingerprint::from_rpgp(&public.fingerprint()),
        protected_secret: Some(secret.to_bytes().unwrap()),
        public_certificate: public.to_bytes().unwrap(),
        export_policy: Some(PrivateExportPolicy::Allowed),
    };
    assert!(matches!(
        SoftwareKeyStore::new().restore_storage(vec![record]),
        Err(KeyError::UnprotectedSecret {
            component: SecretComponent::Primary
        })
    ));
}

#[test]
fn public_only_restore_never_downgrades_secret_records() {
    let (store, generated) = modern_key(PrivateExportPolicy::Disabled);
    let fingerprint = generated.metadata.fingerprint.clone();
    let mut public_record = store.storage_snapshot().unwrap().remove(0);
    public_record.protected_secret = None;
    public_record.export_policy = None;

    let mut public_store = SoftwareKeyStore::new();
    public_store
        .restore_storage(vec![public_record.clone()])
        .unwrap();
    assert_eq!(public_store.len(), 1);
    assert!(matches!(
        public_store.export_private(&fingerprint, ExportFormat::Binary),
        Err(KeyError::SecretKeyRequired { .. })
    ));

    let mut secret_store = store;
    secret_store.restore_storage(vec![public_record]).unwrap();
    assert!(matches!(
        secret_store.export_private(&fingerprint, ExportFormat::Binary),
        Err(KeyError::PrivateExportDisabled { .. })
    ));
    assert_eq!(secret_store.len(), 1);
}
