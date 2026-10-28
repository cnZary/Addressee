#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Cursor;

use openpgp_policy::{Algorithm, GenerationProfile, HashAlgorithm, SecurityPolicy};
use pgp::{
    packet::{RevocationCode, SignatureConfig, SignatureType, Subpacket, SubpacketData},
    ser::Serialize as _,
    types::{KeyDetails as _, Password, Timestamp},
};

use crate::{
    AeadMode, CertificateMetadata, DecryptionStatus, EncryptionConfig, FullFingerprint,
    GeneratedKey, IdentityTrust, MessageCipher, MessageError, MessageFormat, MessageService,
    PrivateExportPolicy, SoftwareKeyStore, VerificationStatus,
};

const PASSWORD: &str = "old correct horse battery staple";
const OTHER_PASSWORD: &str = "other correct horse battery staple";

pub(crate) fn exercise_message_profile(
    store: &SoftwareKeyStore,
    metadata: &CertificateMetadata,
    profile: &GenerationProfile,
) {
    let service = MessageService::new(store, SecurityPolicy::default());
    let fingerprint = &metadata.fingerprint;
    let now = evaluation_time();
    let payload = b"binary\0message\r\nwith multiple lines\n";

    for format in [MessageFormat::Binary, MessageFormat::Armored] {
        let mut signature = Vec::new();
        let signature_metadata = service
            .sign_detached(
                fingerprint,
                PASSWORD,
                now,
                &payload[..],
                &mut signature,
                format,
            )
            .unwrap();
        assert_eq!(
            signature_metadata.signer_fingerprint,
            metadata.subkeys[0].fingerprint
        );
        assert_eq!(
            signature_metadata.hash_algorithm,
            expected_hash(profile.signing_subkey.algorithm)
        );
        assert!(signature_metadata.created_at.is_some());
        let verified = service
            .verify_detached(&payload[..], &signature, now)
            .unwrap();
        assert_eq!(verified.status, VerificationStatus::Valid);
        assert_eq!(verified.signatures.len(), 1);
        assert_eq!(
            verified.signatures[0].signer_fingerprint.as_ref(),
            Some(&metadata.subkeys[0].fingerprint)
        );
        assert_eq!(verified.signatures[0].trust, IdentityTrust::Unknown);
        if format == MessageFormat::Binary {
            let wrong = service
                .verify_detached(&b"different original"[..], &signature, now)
                .unwrap();
            assert_eq!(wrong.status, VerificationStatus::Invalid);
        }
    }

    let config = profile_encryption(profile);
    let mut encrypted = Vec::new();
    service
        .encrypt(
            std::slice::from_ref(fingerprint),
            now,
            config,
            &payload[..],
            &mut encrypted,
            MessageFormat::Binary,
        )
        .unwrap();
    let decrypted = service
        .decrypt(fingerprint, PASSWORD, now, Cursor::new(&encrypted))
        .unwrap();
    assert_eq!(decrypted.report.status, DecryptionStatus::Unsigned);
    assert!(decrypted.report.may_commit_staging());
    assert_eq!(decrypted.plaintext.as_deref(), Some(&payload[..]));

    let mut encrypted = Vec::new();
    service
        .sign_and_encrypt(
            crate::SigningKeyRequest::new(fingerprint, PASSWORD),
            crate::EncryptionRequest::new(std::slice::from_ref(fingerprint), now, config),
            &payload[..],
            &mut encrypted,
            MessageFormat::Armored,
        )
        .unwrap();
    let mut staged = Vec::new();
    let report = service
        .decrypt_into(
            fingerprint,
            PASSWORD,
            now,
            Cursor::new(&encrypted),
            &mut staged,
        )
        .unwrap();
    assert_eq!(report.status, DecryptionStatus::Valid);
    assert!(report.may_commit_staging());
    assert_eq!(staged, payload);
    assert_eq!(report.signatures.len(), 1);
    assert_eq!(
        report.signatures[0].signer_fingerprint.as_ref(),
        Some(&metadata.subkeys[0].fingerprint)
    );
}

#[test]
fn signing_uses_the_supplied_timestamp_without_wall_clock_races() {
    let (store, generated) = generate(GenerationProfile::nist_p256_v4());
    let fingerprint = generated.metadata.fingerprint;
    let service = MessageService::new(&store, SecurityPolicy::default());
    let at = evaluation_time();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let payload = b"timestamp regression payload";

    let mut detached = Vec::new();
    let metadata = service
        .sign_detached(
            &fingerprint,
            PASSWORD,
            at,
            &payload[..],
            &mut detached,
            MessageFormat::Binary,
        )
        .unwrap();
    assert_eq!(metadata.created_at, Some(at));
    let verified = service
        .verify_detached(&payload[..], &detached, at)
        .unwrap();
    assert_eq!(verified.status, VerificationStatus::Valid);
    assert_eq!(verified.signatures[0].created_at, Some(at));
    let premature = service
        .verify_detached(&payload[..], &detached, at - 1)
        .unwrap();
    assert_eq!(premature.status, VerificationStatus::Invalid);
    assert_eq!(premature.signatures[0].cryptographically_valid, Some(true));

    let mut attached = Vec::new();
    let metadata = service
        .sign_attached(
            &fingerprint,
            PASSWORD,
            at,
            &payload[..],
            &mut attached,
            MessageFormat::Binary,
        )
        .unwrap();
    assert_eq!(metadata.created_at, Some(at));
    let mut plaintext = Vec::new();
    let verified = service
        .verify_attached(Cursor::new(&attached), &mut plaintext, at)
        .unwrap();
    assert_eq!(verified.status, VerificationStatus::Valid);
    assert_eq!(verified.signatures[0].created_at, Some(at));
    assert_eq!(plaintext, payload);

    let mut cleartext = Vec::new();
    let metadata = service
        .sign_cleartext(
            &fingerprint,
            PASSWORD,
            at,
            "Explicit timestamp\r\n",
            &mut cleartext,
        )
        .unwrap();
    assert_eq!(metadata.created_at, Some(at));
    let verified = service.verify_cleartext(&cleartext, at).unwrap();
    assert_eq!(verified.outcome.status, VerificationStatus::Valid);
    assert_eq!(verified.outcome.signatures[0].created_at, Some(at));
    assert_eq!(verified.text.as_deref(), Some("Explicit timestamp\r\n"));

    let mut encrypted = Vec::new();
    let metadata = service
        .sign_and_encrypt(
            crate::SigningKeyRequest::new(&fingerprint, PASSWORD),
            crate::EncryptionRequest::new(
                std::slice::from_ref(&fingerprint),
                at,
                EncryptionConfig::SeipdV1 {
                    cipher: MessageCipher::Aes256,
                },
            ),
            &payload[..],
            &mut encrypted,
            MessageFormat::Binary,
        )
        .unwrap();
    assert_eq!(metadata.created_at, Some(at));
    let decrypted = service
        .decrypt(&fingerprint, PASSWORD, at, Cursor::new(&encrypted))
        .unwrap();
    assert_eq!(decrypted.report.status, DecryptionStatus::Valid);
    assert_eq!(decrypted.report.signatures[0].created_at, Some(at));
    assert_eq!(decrypted.plaintext.as_deref(), Some(&payload[..]));

    let invalid_time = u64::from(u32::MAX) + 1;
    assert!(matches!(
        service.sign_detached(
            &fingerprint,
            PASSWORD,
            invalid_time,
            &payload[..],
            Vec::new(),
            MessageFormat::Binary,
        ),
        Err(MessageError::TimestampOutOfRange { at_unix_seconds }) if at_unix_seconds == invalid_time
    ));
}

#[test]
fn attached_and_cleartext_cover_v4_and_v6_at_current_time() {
    for (label, profile) in [
        ("v6", GenerationProfile::modern_v6()),
        ("v4-p256", GenerationProfile::nist_p256_v4()),
    ] {
        let (store, generated) = generate(profile.clone());
        let fingerprint = generated.metadata.fingerprint;
        let service = MessageService::new(&store, SecurityPolicy::default());
        let now = evaluation_time();
        let payload = b"binary\0payload\r\nwith text";
        let mut attached = Vec::new();
        let metadata = service
            .sign_attached(
                &fingerprint,
                PASSWORD,
                now,
                &payload[..],
                &mut attached,
                MessageFormat::Binary,
            )
            .unwrap();
        assert_eq!(metadata.created_at, Some(now), "{label} attached");
        let mut plaintext = Vec::new();
        let verified = service
            .verify_attached(Cursor::new(&attached), &mut plaintext, now)
            .unwrap();
        assert_eq!(
            verified.status,
            VerificationStatus::Valid,
            "{label} attached"
        );
        assert_eq!(plaintext, payload, "{label} attached");

        let mut cleartext = Vec::new();
        let metadata = service
            .sign_cleartext(
                &fingerprint,
                PASSWORD,
                now,
                "First line\r\nSecond line\r\n",
                &mut cleartext,
            )
            .unwrap();
        assert_eq!(metadata.created_at, Some(now), "{label} cleartext");
        let cleartext_result = service.verify_cleartext(&cleartext, now).unwrap();
        assert_eq!(
            cleartext_result.outcome.status,
            VerificationStatus::Valid,
            "{label} cleartext"
        );
        assert_eq!(
            cleartext_result.text.as_deref(),
            Some("First line\r\nSecond line\r\n"),
            "{label} cleartext"
        );
    }
}

#[test]
fn attached_and_cleartext_require_complete_validation() {
    let (store, generated) = generate(GenerationProfile::nist_p256_v4());
    let fingerprint = generated.metadata.fingerprint;
    let service = MessageService::new(&store, SecurityPolicy::default());
    let now = evaluation_time();
    let payload = b"attached binary payload\0\r\n";

    for format in [MessageFormat::Binary, MessageFormat::Armored] {
        let mut attached = Vec::new();
        service
            .sign_attached(
                &fingerprint,
                PASSWORD,
                now,
                &payload[..],
                &mut attached,
                format,
            )
            .unwrap();
        let mut plaintext = Vec::new();
        let verified = service
            .verify_attached(Cursor::new(&attached), &mut plaintext, now)
            .unwrap();
        assert_eq!(verified.status, VerificationStatus::Valid);
        assert_eq!(plaintext, payload);

        let mut truncated = attached.clone();
        truncated.truncate(truncated.len() - 4);
        let mut rejected_output = Vec::new();
        let result = service.verify_attached(Cursor::new(&truncated), &mut rejected_output, now);
        assert!(result.is_err() || result.unwrap().status != VerificationStatus::Valid);
        assert!(rejected_output.is_empty());

        let mut trailing = attached.clone();
        trailing.extend_from_slice(&attached);
        let mut rejected_output = Vec::new();
        let result = service.verify_attached(Cursor::new(&trailing), &mut rejected_output, now);
        assert!(result.is_err() || result.unwrap().status != VerificationStatus::Valid);
        assert!(rejected_output.is_empty());
    }

    let mut cleartext = Vec::new();
    service
        .sign_cleartext(
            &fingerprint,
            PASSWORD,
            now,
            "hello\n-dash escaped\n",
            &mut cleartext,
        )
        .unwrap();
    let verified = service.verify_cleartext(&cleartext, now).unwrap();
    assert_eq!(verified.outcome.status, VerificationStatus::Valid);
    assert_eq!(verified.text.as_deref(), Some("hello\r\n-dash escaped\r\n"));

    let position = cleartext
        .windows(5)
        .position(|window| window == b"hello")
        .unwrap();
    cleartext[position] = b'j';
    let invalid = service.verify_cleartext(&cleartext, now).unwrap();
    assert_eq!(invalid.outcome.status, VerificationStatus::Invalid);
    assert_eq!(invalid.text, None);

    let empty_store = SoftwareKeyStore::new();
    let unknown_service = MessageService::new(&empty_store, SecurityPolicy::default());
    let mut cleartext = Vec::new();
    service
        .sign_cleartext(
            &fingerprint,
            PASSWORD,
            now,
            "unknown signer\n",
            &mut cleartext,
        )
        .unwrap();
    let unknown = unknown_service.verify_cleartext(&cleartext, now).unwrap();
    assert_eq!(unknown.outcome.status, VerificationStatus::UnknownSigner);
    assert_eq!(unknown.text, None);

    let mut detached = Vec::new();
    service
        .sign_detached(
            &fingerprint,
            PASSWORD,
            now,
            &b"unknown detached signer"[..],
            &mut detached,
            MessageFormat::Binary,
        )
        .unwrap();
    let unknown = unknown_service
        .verify_detached(&b"unknown detached signer"[..], &detached, now)
        .unwrap();
    assert_eq!(unknown.status, VerificationStatus::UnknownSigner);
}

#[test]
fn multiple_recipients_wrong_password_and_tampering() {
    let (mut store, first) = generate(GenerationProfile::nist_p256_v4());
    let first = first.metadata.fingerprint;
    let second = store
        .generate(
            &GenerationProfile::nist_p256_v4(),
            "Bob <bob@example.test>",
            OTHER_PASSWORD,
            PrivateExportPolicy::Allowed,
        )
        .unwrap()
        .metadata
        .fingerprint;
    let service = MessageService::new(&store, SecurityPolicy::default());
    let now = evaluation_time();
    let recipients = vec![first.clone(), second.clone()];
    let mut encrypted = Vec::new();
    service
        .sign_and_encrypt(
            crate::SigningKeyRequest::new(&first, PASSWORD),
            crate::EncryptionRequest::new(
                &recipients,
                now,
                EncryptionConfig::SeipdV2 {
                    cipher: MessageCipher::Aes256,
                    mode: AeadMode::Ocb,
                },
            ),
            &b"multi-recipient payload"[..],
            &mut encrypted,
            MessageFormat::Binary,
        )
        .unwrap();

    for (recipient, password) in [(&first, PASSWORD), (&second, OTHER_PASSWORD)] {
        let decrypted = service
            .decrypt(recipient, password, now, Cursor::new(&encrypted))
            .unwrap();
        assert_eq!(decrypted.report.status, DecryptionStatus::Valid);
        assert_eq!(
            decrypted.plaintext.as_deref(),
            Some(&b"multi-recipient payload"[..])
        );
    }

    let wrong = service
        .decrypt(&first, "wrong password", now, Cursor::new(&encrypted))
        .unwrap();
    assert_eq!(wrong.report.status, DecryptionStatus::DecryptionFailed);
    assert_eq!(wrong.plaintext, None);
    assert!(!wrong.report.may_commit_staging());
    assert!(
        service
            .sign_detached(
                &first,
                "wrong password",
                now,
                &b"payload"[..],
                Vec::new(),
                MessageFormat::Binary,
            )
            .is_err()
    );

    let mut tampered = encrypted.clone();
    let tampered_index = tampered.len() - 8;
    tampered[tampered_index] ^= 0x40;
    let tampered_result = service.decrypt(&first, PASSWORD, now, Cursor::new(&tampered));
    if let Ok(decrypted) = tampered_result {
        assert_eq!(decrypted.report.status, DecryptionStatus::IntegrityFailed);
        assert_eq!(decrypted.plaintext, None);
        assert!(!decrypted.report.may_commit_staging());
    }

    assert!(matches!(
        service.encrypt(
            &[],
            now,
            EncryptionConfig::SeipdV1 {
                cipher: MessageCipher::Aes256,
            },
            &b"payload"[..],
            Vec::new(),
            MessageFormat::Binary,
        ),
        Err(MessageError::EmptyRecipients)
    ));
}

#[test]
fn text_encryption_and_decryption() {
    let (store, generated) = generate(GenerationProfile::nist_p256_v4());
    let fingerprint = generated.metadata.fingerprint;
    let service = MessageService::new(&store, SecurityPolicy::default());
    let now = evaluation_time();
    let text = "first line\r\nsecond line\r\n";

    for config in [
        EncryptionConfig::SeipdV1 {
            cipher: MessageCipher::Aes128,
        },
        EncryptionConfig::SeipdV2 {
            cipher: MessageCipher::Aes192,
            mode: AeadMode::Eax,
        },
        EncryptionConfig::SeipdV2 {
            cipher: MessageCipher::Aes256,
            mode: AeadMode::Gcm,
        },
    ] {
        let mut encrypted = Vec::new();
        service
            .sign_and_encrypt_text(
                crate::SigningKeyRequest::new(&fingerprint, PASSWORD),
                crate::EncryptionRequest::new(std::slice::from_ref(&fingerprint), now, config),
                text,
                &mut encrypted,
                MessageFormat::Armored,
            )
            .unwrap();
        let decrypted = service
            .decrypt_text(&fingerprint, PASSWORD, now, Cursor::new(&encrypted))
            .unwrap();
        assert_eq!(
            decrypted.report.status,
            DecryptionStatus::Valid,
            "{:?}",
            decrypted.report
        );
        assert_eq!(decrypted.text.as_deref(), Some(text));
    }

    assert!(matches!(
        service.encrypt_text(
            std::slice::from_ref(&fingerprint),
            now,
            EncryptionConfig::SeipdV1 {
                cipher: MessageCipher::Aes256,
            },
            "bare LF\n",
            Vec::new(),
            MessageFormat::Binary,
        ),
        Err(MessageError::InvalidTextLineEnding)
    ));
}

const THIRD_PASSWORD: &str = "third correct horse battery staple";

#[test]
fn unknown_and_revoked_signers_are_distinct() {
    let (mut store, signer) = generate(GenerationProfile::nist_p256_v4());
    let signer = signer.metadata.fingerprint;
    let recipient = store
        .generate(
            &GenerationProfile::nist_p256_v4(),
            "Recipient <recipient@example.test>",
            OTHER_PASSWORD,
            PrivateExportPolicy::Allowed,
        )
        .unwrap()
        .metadata
        .fingerprint;
    let service = MessageService::new(&store, SecurityPolicy::default());
    let signed_at = evaluation_time();
    let mut encrypted = Vec::new();
    service
        .sign_and_encrypt(
            crate::SigningKeyRequest::new(&signer, PASSWORD),
            crate::EncryptionRequest::new(
                std::slice::from_ref(&recipient),
                signed_at,
                EncryptionConfig::SeipdV1 {
                    cipher: MessageCipher::Aes256,
                },
            ),
            &b"signed ciphertext"[..],
            &mut encrypted,
            MessageFormat::Binary,
        )
        .unwrap();
    let recipient_private = store
        .export_private(&recipient, crate::ExportFormat::Binary)
        .unwrap();
    let revoked_signer = revoked_certificate(&store, &signer);
    let now = evaluation_time();

    let mut decryption_store = SoftwareKeyStore::new();
    decryption_store
        .import_private(
            &recipient_private,
            Some(OTHER_PASSWORD),
            THIRD_PASSWORD,
            PrivateExportPolicy::Allowed,
        )
        .unwrap();
    {
        let decryption_service = MessageService::new(&decryption_store, SecurityPolicy::default());
        let unknown = decryption_service
            .decrypt(&recipient, THIRD_PASSWORD, now, Cursor::new(&encrypted))
            .unwrap();
        assert_eq!(unknown.report.status, DecryptionStatus::UnknownSigner);
        assert!(unknown.plaintext.is_some());
        assert!(unknown.report.may_commit_staging());
        assert_eq!(unknown.report.trust, IdentityTrust::Unknown);
    }

    decryption_store.import_public(&revoked_signer).unwrap();
    let decryption_service = MessageService::new(&decryption_store, SecurityPolicy::default());
    let invalid = decryption_service
        .decrypt(&recipient, THIRD_PASSWORD, now, Cursor::new(&encrypted))
        .unwrap();
    assert_eq!(invalid.report.status, DecryptionStatus::Invalid);
    assert!(invalid.plaintext.is_some());
    assert!(invalid.report.may_commit_staging());
    assert_eq!(invalid.report.signatures.len(), 1);
    assert_eq!(
        invalid.report.signatures[0].cryptographically_valid,
        Some(true)
    );
    assert_eq!(invalid.report.signatures[0].trust, IdentityTrust::Unknown);
}

#[test]
fn signing_and_encryption_roles_are_not_substituted() {
    let (store, generated) = generate(GenerationProfile::nist_p256_v4());
    let fingerprint = generated.metadata.fingerprint;
    let secret = store.rpgp_secret_key(&fingerprint).unwrap();
    let now = evaluation_time();

    let mut signing_only = secret.clone();
    signing_only.secret_subkeys.retain(|subkey| {
        FullFingerprint::from_rpgp(&subkey.key.fingerprint())
            == generated.metadata.subkeys[0].fingerprint
    });
    let mut signing_store = SoftwareKeyStore::new();
    signing_store
        .import_private(
            &signing_only.to_bytes().unwrap(),
            Some(PASSWORD),
            OTHER_PASSWORD,
            PrivateExportPolicy::Allowed,
        )
        .unwrap();
    let signing_service = MessageService::new(&signing_store, SecurityPolicy::default());
    signing_service
        .sign_detached(
            &fingerprint,
            OTHER_PASSWORD,
            now,
            &b"payload"[..],
            Vec::new(),
            MessageFormat::Binary,
        )
        .unwrap();
    assert!(matches!(
        signing_service.encrypt(
            std::slice::from_ref(&fingerprint),
            now,
            EncryptionConfig::SeipdV1 {
                cipher: MessageCipher::Aes256,
            },
            &b"payload"[..],
            Vec::new(),
            MessageFormat::Binary,
        ),
        Err(MessageError::NoUsableKey {
            operation: crate::MessageOperation::Encrypt,
            ..
        })
    ));

    let mut encryption_only = secret.clone();
    encryption_only.secret_subkeys.retain(|subkey| {
        FullFingerprint::from_rpgp(&subkey.key.fingerprint())
            == generated.metadata.subkeys[1].fingerprint
    });
    let mut encryption_store = SoftwareKeyStore::new();
    encryption_store
        .import_private(
            &encryption_only.to_bytes().unwrap(),
            Some(PASSWORD),
            OTHER_PASSWORD,
            PrivateExportPolicy::Allowed,
        )
        .unwrap();
    let encryption_service = MessageService::new(&encryption_store, SecurityPolicy::default());
    assert!(matches!(
        encryption_service.sign_detached(
            &fingerprint,
            OTHER_PASSWORD,
            now,
            &b"payload"[..],
            Vec::new(),
            MessageFormat::Binary,
        ),
        Err(MessageError::NoUsableKey {
            operation: crate::MessageOperation::Sign,
            ..
        })
    ));
    encryption_service
        .encrypt(
            std::slice::from_ref(&fingerprint),
            now,
            EncryptionConfig::SeipdV1 {
                cipher: MessageCipher::Aes256,
            },
            &b"payload"[..],
            Vec::new(),
            MessageFormat::Binary,
        )
        .unwrap();
}

#[test]
fn compressed_messages_are_decompressed() {
    let (store, generated) = generate(GenerationProfile::nist_p256_v4());
    let fingerprint = generated.metadata.fingerprint;
    let certificate = store.rpgp_public_key(&fingerprint).unwrap();
    let encryption_key = &certificate.public_subkeys[1];
    let payload = b"compressed payload compressed payload compressed payload";
    let mut rng = rand::thread_rng();
    let mut builder = pgp::composed::MessageBuilder::from_bytes("payload.bin", payload.to_vec())
        .seipd_v1(&mut rng, pgp::crypto::sym::SymmetricKeyAlgorithm::AES256);
    builder.compression(pgp::types::CompressionAlgorithm::ZLIB);
    builder.encrypt_to_key(&mut rng, encryption_key).unwrap();
    let encrypted = builder.to_vec(&mut rng).unwrap();

    let service = MessageService::new(&store, SecurityPolicy::default());
    let decrypted = service
        .decrypt(
            &fingerprint,
            PASSWORD,
            evaluation_time(),
            Cursor::new(&encrypted),
        )
        .unwrap();
    assert_eq!(decrypted.report.status, DecryptionStatus::Unsigned);
    assert_eq!(decrypted.plaintext.as_deref(), Some(&payload[..]));
}

#[test]
fn message_limits_are_enforced() {
    let (store, generated) = generate(GenerationProfile::nist_p256_v4());
    let fingerprint = generated.metadata.fingerprint;
    let normal = MessageService::new(&store, SecurityPolicy::default());
    let now = evaluation_time();
    let limits = crate::MessageLimits {
        max_text_bytes: 4,
        max_cleartext_bytes: 32,
        max_signature_bytes: 8,
        max_plaintext_bytes: 4,
        max_compression_layers: 4,
    };
    let limited = MessageService::with_limits(&store, SecurityPolicy::default(), limits);

    assert!(matches!(
        limited.sign_cleartext(&fingerprint, PASSWORD, now, "too long", Vec::new(),),
        Err(MessageError::TextLimitExceeded { limit: 4 })
    ));

    let mut signature = Vec::new();
    normal
        .sign_detached(
            &fingerprint,
            PASSWORD,
            now,
            &b"payload"[..],
            &mut signature,
            MessageFormat::Binary,
        )
        .unwrap();
    assert!(matches!(
        limited.verify_detached(&b"payload"[..], &signature, now),
        Err(MessageError::SignatureLimitExceeded { limit: 8 })
    ));

    let mut cleartext = Vec::new();
    normal
        .sign_cleartext(&fingerprint, PASSWORD, now, "valid text", &mut cleartext)
        .unwrap();
    assert!(matches!(
        limited.verify_cleartext(&cleartext, now),
        Err(MessageError::CleartextLimitExceeded { limit: 32 })
    ));

    let mut attached = Vec::new();
    normal
        .sign_attached(
            &fingerprint,
            PASSWORD,
            now,
            &b"more than four"[..],
            &mut attached,
            MessageFormat::Binary,
        )
        .unwrap();
    let mut output = Vec::new();
    assert!(matches!(
        limited.verify_attached(Cursor::new(&attached), &mut output, now),
        Err(MessageError::PlaintextLimitExceeded { limit: 4 })
    ));
    assert!(output.is_empty());

    let mut encrypted = Vec::new();
    normal
        .encrypt(
            std::slice::from_ref(&fingerprint),
            now,
            EncryptionConfig::SeipdV1 {
                cipher: MessageCipher::Aes256,
            },
            &b"more than four"[..],
            &mut encrypted,
            MessageFormat::Binary,
        )
        .unwrap();
    assert!(matches!(
        limited.decrypt(&fingerprint, PASSWORD, now, Cursor::new(&encrypted)),
        Err(MessageError::PlaintextLimitExceeded { limit: 4 })
    ));
}

fn revoked_certificate(store: &SoftwareKeyStore, fingerprint: &FullFingerprint) -> Vec<u8> {
    let mut secret = store.rpgp_secret_key(fingerprint).unwrap().clone();
    let created = Timestamp::now();
    let mut rng = rand::thread_rng();
    let mut config =
        SignatureConfig::from_key(&mut rng, &secret.primary_key, SignatureType::KeyRevocation)
            .unwrap();
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created)).unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            secret.primary_key.fingerprint(),
        ))
        .unwrap(),
        Subpacket::regular(SubpacketData::RevocationReason(
            RevocationCode::KeyRetired,
            b"revoked for message testing".as_slice().into(),
        ))
        .unwrap(),
    ];
    let revocation = config
        .sign_key(
            &secret.primary_key,
            &Password::from(PASSWORD),
            secret.primary_key.public_key(),
        )
        .unwrap();
    secret.details.revocation_signatures.push(revocation);
    let public = secret.to_public_key();
    public.verify_bindings().unwrap();
    public.to_bytes().unwrap()
}

fn generate(profile: GenerationProfile) -> (SoftwareKeyStore, GeneratedKey) {
    let mut store = SoftwareKeyStore::new();
    let generated = store
        .generate(
            &profile,
            "Alice <alice@example.test>",
            PASSWORD,
            PrivateExportPolicy::Allowed,
        )
        .unwrap();
    (store, generated)
}

fn expected_hash(algorithm: Algorithm) -> HashAlgorithm {
    match algorithm {
        Algorithm::Ed448 => HashAlgorithm::Sha3_512,
        Algorithm::NistP384Ecdsa => HashAlgorithm::Sha384,
        Algorithm::NistP521Ecdsa => HashAlgorithm::Sha512,
        _ => HashAlgorithm::Sha256,
    }
}

fn profile_encryption(profile: &GenerationProfile) -> EncryptionConfig {
    match profile.signing_subkey.algorithm {
        Algorithm::Ed25519 => EncryptionConfig::SeipdV2 {
            cipher: MessageCipher::Aes256,
            mode: AeadMode::Ocb,
        },
        Algorithm::Ed448 => EncryptionConfig::SeipdV2 {
            cipher: MessageCipher::Aes192,
            mode: AeadMode::Eax,
        },
        Algorithm::LegacyEd25519 => EncryptionConfig::SeipdV1 {
            cipher: MessageCipher::Aes128,
        },
        Algorithm::NistP256Ecdsa => EncryptionConfig::SeipdV2 {
            cipher: MessageCipher::Aes128,
            mode: AeadMode::Gcm,
        },
        Algorithm::NistP384Ecdsa => EncryptionConfig::SeipdV1 {
            cipher: MessageCipher::Aes192,
        },
        Algorithm::NistP521Ecdsa | Algorithm::Rsa4096 => EncryptionConfig::SeipdV1 {
            cipher: MessageCipher::Aes256,
        },
        Algorithm::Rsa2048 => EncryptionConfig::SeipdV1 {
            cipher: MessageCipher::Aes128,
        },
        Algorithm::Rsa3072 => EncryptionConfig::SeipdV1 {
            cipher: MessageCipher::Aes192,
        },
        _ => unreachable!("unexpected test profile"),
    }
}

fn evaluation_time() -> u64 {
    u64::from(Timestamp::now().as_secs())
}
