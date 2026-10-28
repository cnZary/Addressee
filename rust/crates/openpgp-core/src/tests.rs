#![allow(clippy::expect_used, clippy::unwrap_used)]

use openpgp_policy::{
    Algorithm, CompatibilityAcknowledgement, GenerationProfile, KeyVersion as PolicyKeyVersion,
};
use pgp::{
    composed::SignedSecretKey,
    crypto::public_key::PublicKeyAlgorithm,
    packet::{KeyFlags, RevocationCode, SignatureConfig, SignatureType, Subpacket, SubpacketData},
    ser::Serialize as _,
    types::{
        Duration, KeyDetails as _, Password, PublicParams, S2kParams, SecretParams, Timestamp,
    },
};

use crate::{
    ExportFormat, FullFingerprint, ImportOutcome, KeyError, KeyStorage, KeyUsage, KeyVersion,
    PrivateExportPolicy, SoftwareKeyStore, metadata,
};

const OLD_PASSWORD: &str = "old correct horse battery staple";
const NEW_PASSWORD: &str = "new correct horse battery staple";
const THIRD_PASSWORD: &str = "third correct horse battery staple";

#[test]
fn modern_v6_full_lifecycle() {
    exercise_profile(GenerationProfile::modern_v6());
}

#[test]
fn curve448_v6_full_lifecycle() {
    exercise_profile(GenerationProfile::curve448_v6());
}

#[test]
fn legacy_curve25519_v4_full_lifecycle() {
    exercise_profile(
        GenerationProfile::legacy_curve25519_v4(CompatibilityAcknowledgement::acknowledged())
            .unwrap(),
    );
}

#[test]
fn nist_p256_v4_full_lifecycle() {
    exercise_profile(GenerationProfile::nist_p256_v4());
}

#[test]
fn nist_p384_v4_full_lifecycle() {
    exercise_profile(GenerationProfile::nist_p384_v4());
}

#[test]
fn nist_p521_v4_full_lifecycle() {
    exercise_profile(GenerationProfile::nist_p521_v4());
}

#[test]
fn rsa_2048_v4_full_lifecycle() {
    exercise_profile(rsa_profile(Algorithm::Rsa2048));
}

#[test]
fn rsa_3072_v4_full_lifecycle() {
    exercise_profile(rsa_profile(Algorithm::Rsa3072));
}

#[test]
fn rsa_4096_v4_full_lifecycle() {
    exercise_profile(rsa_profile(Algorithm::Rsa4096));
}

#[test]
fn modern_v4_native_curve25519_remains_policy_gated() {
    let result = GenerationProfile::new(
        PolicyKeyVersion::V4,
        Algorithm::Ed25519,
        Algorithm::Ed25519,
        Algorithm::X25519,
        CompatibilityAcknowledgement::not_acknowledged(),
    );
    assert!(result.is_err());
}

#[test]
fn generated_export_disabled_is_enforced() {
    let mut store = SoftwareKeyStore::new();
    let generated = store
        .generate(
            &GenerationProfile::nist_p256_v4(),
            "Alice <alice@example.test>",
            OLD_PASSWORD,
            PrivateExportPolicy::Disabled,
        )
        .unwrap();
    let fingerprint = generated.metadata.fingerprint.clone();
    assert_eq!(
        generated.metadata.private_export_policy,
        Some(PrivateExportPolicy::Disabled)
    );
    assert_all_protected(&store, &fingerprint);
    assert!(matches!(
        store.export_private(&fingerprint, ExportFormat::Binary),
        Err(KeyError::PrivateExportDisabled { .. })
    ));
    assert!(matches!(
        store.export_private(&fingerprint, ExportFormat::Armored),
        Err(KeyError::PrivateExportDisabled { .. })
    ));
    assert!(
        store
            .export_public(&fingerprint, ExportFormat::Binary)
            .is_ok()
    );
}

#[test]
fn wrong_missing_and_empty_passwords_are_rejected() {
    let (store, generated) = generate(GenerationProfile::modern_v6());
    let fingerprint = generated.metadata.fingerprint.clone();
    let private = store
        .export_private(&fingerprint, ExportFormat::Binary)
        .unwrap();

    let mut imported = SoftwareKeyStore::new();
    assert!(matches!(
        imported.import_private(&private, None, NEW_PASSWORD, PrivateExportPolicy::Allowed),
        Err(KeyError::PasswordRequired)
    ));
    assert!(matches!(
        imported.import_private(
            &private,
            Some("wrong password"),
            NEW_PASSWORD,
            PrivateExportPolicy::Allowed
        ),
        Err(KeyError::InvalidPassword { .. })
    ));
    assert!(matches!(
        imported.import_private(
            &private,
            Some(OLD_PASSWORD),
            "",
            PrivateExportPolicy::Allowed
        ),
        Err(KeyError::EmptyPassword)
    ));
    assert!(imported.is_empty());

    let mut generated_empty = SoftwareKeyStore::new();
    assert!(matches!(
        generated_empty.generate(
            &GenerationProfile::modern_v6(),
            "Alice <alice@example.test>",
            "",
            PrivateExportPolicy::Allowed
        ),
        Err(KeyError::EmptyPassword)
    ));
    assert!(generated_empty.is_empty());
}

#[test]
fn unprotected_and_mixed_private_inputs_are_reprotected() {
    let (store, generated) = generate(GenerationProfile::nist_p256_v4());
    let fingerprint = generated.metadata.fingerprint.clone();

    let unprotected = unprotected_export(&store, &fingerprint, OLD_PASSWORD, None);
    let mut unprotected_store = SoftwareKeyStore::new();
    unprotected_store
        .import_private(
            &unprotected,
            None,
            NEW_PASSWORD,
            PrivateExportPolicy::Allowed,
        )
        .unwrap();
    assert_all_protected(&unprotected_store, &fingerprint);
    let reexported = unprotected_store
        .export_private(&fingerprint, ExportFormat::Binary)
        .unwrap();
    let mut check = SoftwareKeyStore::new();
    check
        .import_private(
            &reexported,
            Some(NEW_PASSWORD),
            THIRD_PASSWORD,
            PrivateExportPolicy::Allowed,
        )
        .unwrap();

    let mixed = unprotected_export(&store, &fingerprint, OLD_PASSWORD, Some(0));
    let mut mixed_store = SoftwareKeyStore::new();
    mixed_store
        .import_private(
            &mixed,
            Some(OLD_PASSWORD),
            NEW_PASSWORD,
            PrivateExportPolicy::Allowed,
        )
        .unwrap();
    assert_all_protected(&mixed_store, &fingerprint);
}

#[test]
fn tampered_trailing_multiple_and_mixed_inputs_are_rejected() {
    let (store, generated) = generate(GenerationProfile::nist_p256_v4());
    let fingerprint = generated.metadata.fingerprint.clone();
    let public = store
        .export_public(&fingerprint, ExportFormat::Binary)
        .unwrap();
    let private = store
        .export_private(&fingerprint, ExportFormat::Binary)
        .unwrap();

    let mut tampered = public.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(SoftwareKeyStore::new().import_public(&tampered).is_err());

    let mut trailing = public.clone();
    trailing.push(0);
    assert!(SoftwareKeyStore::new().import_public(&trailing).is_err());

    let mut multiple = public.clone();
    multiple.extend_from_slice(&public);
    assert!(matches!(
        SoftwareKeyStore::new().import_public(&multiple),
        Err(KeyError::MultipleCertificates)
    ));

    let mut public_then_private = public.clone();
    public_then_private.extend_from_slice(&private);
    assert!(matches!(
        SoftwareKeyStore::new().import_public(&public_then_private),
        Err(KeyError::MixedKeyring)
    ));

    let mut private_then_public = private.clone();
    private_then_public.extend_from_slice(&public);
    assert!(matches!(
        SoftwareKeyStore::new().import_private(
            &private_then_public,
            Some(OLD_PASSWORD),
            NEW_PASSWORD,
            PrivateExportPolicy::Allowed
        ),
        Err(KeyError::MixedKeyring)
    ));

    let mut armored = store
        .export_public(&fingerprint, ExportFormat::Armored)
        .unwrap();
    armored.extend_from_slice(b"trailing data");
    assert!(matches!(
        SoftwareKeyStore::new().import_public(&armored),
        Err(KeyError::TrailingData)
    ));
}

#[test]
fn duplicates_do_not_replace_records_or_export_policy() {
    let (mut store, generated) = generate(GenerationProfile::nist_p256_v4());
    let fingerprint = generated.metadata.fingerprint.clone();
    let public = store
        .export_public(&fingerprint, ExportFormat::Binary)
        .unwrap();
    let private = store
        .export_private(&fingerprint, ExportFormat::Binary)
        .unwrap();

    let duplicate = store.import_public(&public).unwrap();
    assert_eq!(duplicate.outcome, ImportOutcome::Duplicate);
    assert_eq!(store.len(), 1);
    assert_eq!(
        store.metadata(&fingerprint).unwrap().storage,
        KeyStorage::SoftwareSecret
    );

    let duplicate = store
        .import_private(
            &private,
            Some(OLD_PASSWORD),
            THIRD_PASSWORD,
            PrivateExportPolicy::Disabled,
        )
        .unwrap();
    assert_eq!(duplicate.outcome, ImportOutcome::Duplicate);
    assert_eq!(
        store.metadata(&fingerprint).unwrap().private_export_policy,
        Some(PrivateExportPolicy::Allowed)
    );
    assert!(
        store
            .export_private(&fingerprint, ExportFormat::Binary)
            .is_ok()
    );

    let mut reordered = store.rpgp_public_key(&fingerprint).unwrap().clone();
    reordered.public_subkeys.swap(0, 1);
    let conflicting = reordered.to_bytes().unwrap();
    assert!(matches!(
        store.import_public(&conflicting),
        Err(KeyError::ConflictingCertificate { .. })
    ));
    assert_eq!(
        store.metadata(&fingerprint).unwrap().subkeys[0]
            .algorithm
            .policy_algorithm,
        Some(Algorithm::NistP256Ecdsa)
    );
}

#[test]
fn expiration_and_revocation_are_evaluated_at_supplied_time() {
    let (store, generated) = generate(GenerationProfile::nist_p256_v4());
    let fingerprint = generated.metadata.fingerprint.clone();
    let mut secret = store.rpgp_secret_key(&fingerprint).unwrap().clone();
    let created = secret.primary_key.created_at();
    let created_secs = u64::from(created.as_secs());
    let encryption = &secret.secret_subkeys[1];
    let encryption_created_secs = u64::from(encryption.key.created_at().as_secs());
    let original_binding_created = u64::from(encryption.signatures[0].created().unwrap().as_secs());
    let reference_secs = created_secs
        .max(encryption_created_secs)
        .max(original_binding_created)
        .saturating_add(1);
    let direct_created = Timestamp::from_secs(reference_secs.try_into().unwrap());
    let binding_created = Timestamp::from_secs(direct_created.as_secs().saturating_add(1));
    let revocation_time = Timestamp::from_secs(direct_created.as_secs().saturating_add(50));
    let expires_at = reference_secs + 100;
    let mut rng = rand::thread_rng();

    let mut primary_flags = KeyFlags::default();
    primary_flags.set_certify(true);
    let mut direct =
        SignatureConfig::from_key(&mut rng, &secret.primary_key, SignatureType::Key).unwrap();
    direct.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(direct_created)).unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            secret.primary_key.fingerprint(),
        ))
        .unwrap(),
        Subpacket::regular(SubpacketData::KeyFlags(primary_flags)).unwrap(),
        Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(
            (expires_at - created_secs).try_into().unwrap(),
        )))
        .unwrap(),
    ];
    let direct = direct
        .sign_key(
            &secret.primary_key,
            &Password::from(OLD_PASSWORD),
            secret.primary_key.public_key(),
        )
        .unwrap();
    secret.details.direct_signatures.push(direct);

    let mut encryption_flags = KeyFlags::default();
    encryption_flags.set_encrypt_comms(true);
    encryption_flags.set_encrypt_storage(true);
    let mut binding =
        SignatureConfig::from_key(&mut rng, &secret.primary_key, SignatureType::SubkeyBinding)
            .unwrap();
    binding.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(binding_created)).unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            secret.primary_key.fingerprint(),
        ))
        .unwrap(),
        Subpacket::regular(SubpacketData::KeyFlags(encryption_flags)).unwrap(),
        Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(
            (expires_at - encryption_created_secs).try_into().unwrap(),
        )))
        .unwrap(),
    ];
    let binding = binding
        .sign_subkey_binding(
            &secret.primary_key,
            secret.primary_key.public_key(),
            &Password::from(OLD_PASSWORD),
            encryption.key.public_key(),
        )
        .unwrap();
    secret.secret_subkeys[1].signatures.push(binding);

    let mut revocation =
        SignatureConfig::from_key(&mut rng, &secret.primary_key, SignatureType::KeyRevocation)
            .unwrap();
    revocation.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(revocation_time)).unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            secret.primary_key.fingerprint(),
        ))
        .unwrap(),
        Subpacket::regular(SubpacketData::RevocationReason(
            RevocationCode::KeyRetired,
            b"retired for testing".as_slice().into(),
        ))
        .unwrap(),
    ];
    let revocation = revocation
        .sign_key(
            &secret.primary_key,
            &Password::from(OLD_PASSWORD),
            secret.primary_key.public_key(),
        )
        .unwrap();
    secret.details.revocation_signatures.push(revocation);

    secret.verify_bindings().unwrap();
    secret.to_public_key().verify_bindings().unwrap();
    let encoded = secret.to_bytes().unwrap();
    let mut evaluated = SoftwareKeyStore::new();
    evaluated
        .import_private(
            &encoded,
            Some(OLD_PASSWORD),
            NEW_PASSWORD,
            PrivateExportPolicy::Allowed,
        )
        .unwrap();

    let before_revocation = evaluated
        .evaluate_validity(&fingerprint, reference_secs + 10)
        .unwrap();
    assert!(before_revocation.primary.is_valid());
    assert!(!before_revocation.primary.revoked);
    assert_eq!(before_revocation.primary.expires_at, Some(expires_at));
    assert_eq!(before_revocation.subkeys[1].expires_at, Some(expires_at));
    assert!(before_revocation.subkey_is_valid(1).unwrap());

    let after_revocation = evaluated
        .evaluate_validity(&fingerprint, reference_secs + 75)
        .unwrap();
    assert!(after_revocation.primary.revoked);
    assert!(!after_revocation.primary.expired);
    assert!(!after_revocation.subkey_is_valid(1).unwrap());
    assert_eq!(
        evaluated
            .metadata(&fingerprint)
            .unwrap()
            .primary
            .revocations[0]
            .reason_code,
        Some(3)
    );

    let after_expiration = evaluated
        .evaluate_validity(&fingerprint, expires_at)
        .unwrap();
    assert!(after_expiration.primary.expired);
    assert!(after_expiration.subkeys[1].expired);

    let metadata = evaluated.metadata(&fingerprint).unwrap();
    assert_eq!(metadata.primary.expires_at, Some(expires_at));
    assert_eq!(metadata.subkeys[1].expires_at, Some(expires_at));
}

#[test]
fn unknown_algorithms_are_not_mapped_to_supported_policy_algorithms() {
    let metadata = metadata::algorithm_metadata(
        PublicKeyAlgorithm::Unknown(99),
        &PublicParams::Unknown {
            data: pgp::bytes::Bytes::from_static(b"opaque"),
        },
    )
    .unwrap();
    assert_eq!(metadata.id, 99);
    assert_eq!(metadata.policy_algorithm, None);
    assert_eq!(metadata.bit_size, None);
    assert_eq!(metadata.curve, None);

    let fingerprint = FullFingerprint::from_hex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .unwrap();
    assert_eq!(fingerprint.as_str().len(), 64);
    assert!(FullFingerprint::from_hex("abcd").is_err());
    let json = serde_json::to_string(&fingerprint).unwrap();
    assert_eq!(json, format!("\"{fingerprint}\""));
    let decoded: FullFingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, fingerprint);
}

fn exercise_profile(profile: GenerationProfile) {
    let (mut store, generated) = generate(profile.clone());
    let metadata = generated.metadata;
    let fingerprint = metadata.fingerprint.clone();
    let expected_fingerprint_len = match profile.key_version {
        PolicyKeyVersion::V4 => 40,
        PolicyKeyVersion::V6 => 64,
    };
    assert_eq!(fingerprint.as_str().len(), expected_fingerprint_len);
    assert_eq!(metadata.key_id.len(), 16);
    assert_eq!(metadata.primary.fingerprint, fingerprint);
    assert_eq!(metadata.storage, KeyStorage::SoftwareSecret);
    assert_eq!(
        metadata.private_export_policy,
        Some(PrivateExportPolicy::Allowed)
    );
    assert_eq!(metadata.user_ids.len(), 1);
    assert_eq!(
        metadata.user_ids[0].utf8.as_deref(),
        Some("Alice <alice@example.test>")
    );
    assert!(metadata.user_ids[0].is_primary);
    assert_eq!(metadata.subkeys.len(), 2);
    assert_eq!(
        metadata.primary.algorithm.policy_algorithm,
        Some(profile.primary_key.algorithm)
    );
    assert_eq!(
        metadata.subkeys[0].algorithm.policy_algorithm,
        Some(profile.signing_subkey.algorithm)
    );
    assert_eq!(
        metadata.subkeys[1].algorithm.policy_algorithm,
        Some(profile.encryption_subkey.algorithm)
    );
    assert_eq!(
        metadata.key_version,
        match profile.key_version {
            PolicyKeyVersion::V4 => KeyVersion::V4,
            PolicyKeyVersion::V6 => KeyVersion::V6,
        }
    );
    assert!(metadata.primary.key_flags.certify);
    assert!(!metadata.primary.key_flags.sign);
    assert!(metadata.subkeys[0].key_flags.sign);
    assert!(metadata.subkeys[1].key_flags.encrypt_communications);
    assert!(metadata.subkeys[1].key_flags.encrypt_storage);
    assert!(metadata.subkeys.iter().all(|subkey| {
        subkey.fingerprint != fingerprint && subkey.storage == KeyStorage::SoftwareSecret
    }));
    if profile.primary_key.algorithm.is_rsa() {
        let expected_bits = match profile.primary_key.algorithm {
            Algorithm::Rsa2048 => 2048,
            Algorithm::Rsa3072 => 3072,
            Algorithm::Rsa4096 => 4096,
            _ => unreachable!(),
        };
        assert_eq!(metadata.primary.algorithm.bit_size, Some(expected_bits));
        assert_eq!(metadata.subkeys[0].algorithm.bit_size, Some(expected_bits));
        assert_eq!(metadata.subkeys[1].algorithm.bit_size, Some(expected_bits));
    }
    assert_all_protected(&store, &fingerprint);

    let created = metadata.primary.created_at;
    let now = u64::from(Timestamp::now().as_secs());
    let validity = store.evaluate_validity(&fingerprint, now).unwrap();
    assert!(validity.primary.is_valid_for(KeyUsage::Certify));
    assert!(validity.subkey_is_valid(0).unwrap());
    assert!(validity.subkey_is_valid(1).unwrap());
    assert!(validity.user_id_is_valid(0).unwrap());
    if created > 0 {
        let before = store.evaluate_validity(&fingerprint, created - 1).unwrap();
        assert!(before.primary.not_yet_valid);
        assert!(!before.primary.is_valid());
    }

    let public_binary = store
        .export_public(&fingerprint, ExportFormat::Binary)
        .unwrap();
    assert_eq!(public_binary, generated.public_certificate);
    let public_armored = store
        .export_public(&fingerprint, ExportFormat::Armored)
        .unwrap();
    assert!(public_armored.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    if profile.key_version == PolicyKeyVersion::V6 {
        assert!(
            !public_armored
                .split(|byte| *byte == b'\n')
                .any(|line| line.starts_with(b"="))
        );
    }

    let duplicate = store.import_public(&public_binary).unwrap();
    assert_eq!(duplicate.outcome, ImportOutcome::Duplicate);
    assert_eq!(duplicate.metadata.storage, KeyStorage::SoftwareSecret);

    let mut public_store = SoftwareKeyStore::new();
    let imported = public_store.import_public(&public_binary).unwrap();
    assert_eq!(imported.outcome, ImportOutcome::Inserted);
    assert_eq!(imported.metadata.storage, KeyStorage::PublicOnly);
    assert_eq!(imported.metadata.private_export_policy, None);
    assert!(matches!(
        public_store.export_private(&fingerprint, ExportFormat::Binary),
        Err(KeyError::SecretKeyRequired { .. })
    ));
    let duplicate = public_store.import_public(&public_binary).unwrap();
    assert_eq!(duplicate.outcome, ImportOutcome::Duplicate);
    assert_eq!(public_store.len(), 1);

    let mut armored_public_store = SoftwareKeyStore::new();
    let imported = armored_public_store.import_public(&public_armored).unwrap();
    assert_eq!(imported.metadata.storage, KeyStorage::PublicOnly);
    assert_eq!(imported.metadata.fingerprint, fingerprint);

    let private_binary = store
        .export_private(&fingerprint, ExportFormat::Binary)
        .unwrap();
    let private_armored = store
        .export_private(&fingerprint, ExportFormat::Armored)
        .unwrap();
    assert!(private_armored.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----"));
    if profile.key_version == PolicyKeyVersion::V6 {
        assert!(
            !private_armored
                .split(|byte| *byte == b'\n')
                .any(|line| line.starts_with(b"="))
        );
    }

    let upgraded = public_store
        .import_private(
            &private_binary,
            Some(OLD_PASSWORD),
            NEW_PASSWORD,
            PrivateExportPolicy::Allowed,
        )
        .unwrap();
    assert_eq!(upgraded.outcome, ImportOutcome::UpgradedToSecret);
    assert_eq!(upgraded.metadata.storage, KeyStorage::SoftwareSecret);
    assert_all_protected(&public_store, &fingerprint);

    let mut disabled_store = SoftwareKeyStore::new();
    disabled_store
        .import_private(
            &private_binary,
            Some(OLD_PASSWORD),
            NEW_PASSWORD,
            PrivateExportPolicy::Disabled,
        )
        .unwrap();
    assert!(matches!(
        disabled_store.export_private(&fingerprint, ExportFormat::Binary),
        Err(KeyError::PrivateExportDisabled { .. })
    ));
    assert!(matches!(
        disabled_store.export_private(&fingerprint, ExportFormat::Armored),
        Err(KeyError::PrivateExportDisabled { .. })
    ));
    assert!(
        disabled_store
            .export_public(&fingerprint, ExportFormat::Binary)
            .is_ok()
    );
    assert_all_protected(&disabled_store, &fingerprint);

    let mut armored_private_store = SoftwareKeyStore::new();
    armored_private_store
        .import_private(
            &private_armored,
            Some(OLD_PASSWORD),
            NEW_PASSWORD,
            PrivateExportPolicy::Allowed,
        )
        .unwrap();
    assert_all_protected(&armored_private_store, &fingerprint);
    let reexported = armored_private_store
        .export_private(&fingerprint, ExportFormat::Binary)
        .unwrap();
    let mut final_store = SoftwareKeyStore::new();
    final_store
        .import_private(
            &reexported,
            Some(NEW_PASSWORD),
            THIRD_PASSWORD,
            PrivateExportPolicy::Allowed,
        )
        .unwrap();
    assert_all_protected(&final_store, &fingerprint);

    crate::message_tests::exercise_message_profile(&store, &metadata, &profile);
}

fn generate(profile: GenerationProfile) -> (SoftwareKeyStore, crate::GeneratedKey) {
    let mut store = SoftwareKeyStore::new();
    let generated = store
        .generate(
            &profile,
            "Alice <alice@example.test>",
            OLD_PASSWORD,
            PrivateExportPolicy::Allowed,
        )
        .unwrap();
    (store, generated)
}

fn rsa_profile(algorithm: Algorithm) -> GenerationProfile {
    GenerationProfile::legacy_rsa_v4(algorithm, CompatibilityAcknowledgement::acknowledged())
        .unwrap()
}

fn assert_all_protected(store: &SoftwareKeyStore, fingerprint: &FullFingerprint) {
    let secret = store.rpgp_secret_key(fingerprint).unwrap();
    let mut parameters = Vec::new();
    match secret.primary_key.secret_params() {
        SecretParams::Encrypted(encrypted) => {
            parameters.push(encrypted.string_to_key_params());
        }
        SecretParams::Plain(_) => panic!("primary secret material is unprotected"),
    }
    for subkey in &secret.secret_subkeys {
        match subkey.key.secret_params() {
            SecretParams::Encrypted(encrypted) => {
                parameters.push(encrypted.string_to_key_params());
            }
            SecretParams::Plain(_) => panic!("subkey secret material is unprotected"),
        }
    }
    assert_eq!(parameters.len(), 3);
    for (index, left) in parameters.iter().enumerate() {
        for right in parameters.iter().skip(index + 1) {
            assert_ne!(left, right, "S2K salt or nonce was reused");
        }
        if secret.primary_key.version() == pgp::types::KeyVersion::V6 {
            assert!(matches!(left, S2kParams::Aead { .. }));
        } else {
            assert!(matches!(left, S2kParams::Cfb { .. }));
        }
    }
}

fn unprotected_export(
    store: &SoftwareKeyStore,
    fingerprint: &FullFingerprint,
    password: &str,
    only_subkey: Option<usize>,
) -> Vec<u8> {
    let mut secret: SignedSecretKey = store.rpgp_secret_key(fingerprint).unwrap().clone();
    if only_subkey.is_none() {
        secret
            .primary_key
            .remove_password(&Password::from(password))
            .unwrap();
    }
    for (index, subkey) in secret.secret_subkeys.iter_mut().enumerate() {
        if only_subkey.is_none() || only_subkey == Some(index) {
            subkey
                .key
                .remove_password(&Password::from(password))
                .unwrap();
        }
    }
    secret.to_bytes().unwrap()
}
