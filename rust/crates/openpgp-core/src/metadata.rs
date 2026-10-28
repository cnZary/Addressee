use openpgp_policy::Algorithm;
use pgp::{
    composed::{SignedPublicKey, SignedPublicSubKey},
    crypto::{ecc_curve::ECCCurve, public_key::PublicKeyAlgorithm},
    packet::{KeyFlags, Signature, SignatureType},
    ser::Serialize,
    types::{
        EcdhPublicParams, EcdsaPublicParams, EddsaLegacyPublicParams, KeyDetails as _,
        PublicParams, SignedUser,
    },
};

use crate::{
    AlgorithmMetadata, BindingValidity, CertificateMetadata, CertificateValidity, CurveMetadata,
    FullFingerprint, KeyError, KeyMetadata, KeyStorage, KeyUsageFlags, KeyValidity,
    PrivateExportPolicy, RevocationMetadata, UserIdMetadata, UserIdValidity,
};

pub(crate) fn certificate_metadata(
    certificate: &SignedPublicKey,
    storage: KeyStorage,
    export_policy: Option<PrivateExportPolicy>,
    secret_subkeys: usize,
) -> Result<CertificateMetadata, KeyError> {
    let primary = key_metadata(
        &certificate.primary_key,
        primary_signature(certificate, None),
        &certificate.details.revocation_signatures,
        storage,
    )?;
    let secret_start = certificate
        .public_subkeys
        .len()
        .saturating_sub(secret_subkeys);
    let subkeys = certificate
        .public_subkeys
        .iter()
        .enumerate()
        .map(|(index, subkey)| {
            subkey_metadata(
                subkey,
                if index >= secret_start {
                    KeyStorage::SoftwareSecret
                } else {
                    KeyStorage::PublicOnly
                },
                None,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let user_ids = certificate
        .details
        .users
        .iter()
        .map(user_id_metadata)
        .collect();

    Ok(CertificateMetadata {
        fingerprint: FullFingerprint::from_rpgp(&certificate.fingerprint()),
        key_id: key_id(&certificate),
        key_version: certificate.version().into(),
        user_ids,
        primary,
        subkeys,
        storage,
        private_export_policy: export_policy,
        binding_validity: BindingValidity::Verified,
    })
}

pub(crate) fn certificate_validity(
    certificate: &SignedPublicKey,
    evaluated_at: u64,
) -> Result<CertificateValidity, KeyError> {
    let at = Some(evaluated_at);
    let primary_signature = primary_signature(certificate, at);
    let primary = key_validity(
        &certificate.primary_key,
        primary_signature,
        &certificate.details.revocation_signatures,
        evaluated_at,
        certificate.version() <= pgp::types::KeyVersion::V3,
    )?;
    let subkeys = certificate
        .public_subkeys
        .iter()
        .map(|subkey| {
            let binding = latest_signature(
                subkey
                    .signatures
                    .iter()
                    .filter(|signature| signature.typ() == Some(SignatureType::SubkeyBinding)),
                at,
            );
            key_validity(
                &subkey.key,
                binding,
                &subkey.signatures,
                evaluated_at,
                false,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let user_ids = certificate
        .details
        .users
        .iter()
        .map(|user| {
            let certification = user_certification(user, at);
            Ok(UserIdValidity {
                is_primary: certification.is_some_and(Signature::is_primary),
                revoked: has_current_revocation(&user.signatures, evaluated_at),
                has_current_certification: certification.is_some(),
            })
        })
        .collect::<Result<Vec<_>, KeyError>>()?;

    Ok(CertificateValidity {
        evaluated_at,
        binding_validity: BindingValidity::Verified,
        primary,
        subkeys,
        user_ids,
    })
}

fn key_metadata<K>(
    key: &K,
    binding: Option<&Signature>,
    revocations: &[Signature],
    storage: KeyStorage,
) -> Result<KeyMetadata, KeyError>
where
    K: pgp::types::KeyDetails,
{
    let created_at = u64::from(key.created_at().as_secs());
    let expires_at =
        legacy_v3_expiration(key).or_else(|| expiration_from_signature(created_at, binding));
    Ok(KeyMetadata {
        fingerprint: FullFingerprint::from_rpgp(&key.fingerprint()),
        key_id: key_id(key),
        key_version: key.version().into(),
        algorithm: algorithm_metadata(key.algorithm(), key.public_params())?,
        key_flags: binding.map_or_else(|| Ok(KeyUsageFlags::default()), usage_flags)?,
        created_at,
        expires_at,
        revocations: revocations
            .iter()
            .filter(|signature| is_key_revocation(signature.typ()))
            .map(revocation_metadata)
            .collect(),
        storage,
    })
}

fn subkey_metadata(
    subkey: &SignedPublicSubKey,
    storage: KeyStorage,
    at: Option<u64>,
) -> Result<KeyMetadata, KeyError> {
    let binding = latest_signature(
        subkey
            .signatures
            .iter()
            .filter(|signature| signature.typ() == Some(SignatureType::SubkeyBinding)),
        at,
    );
    key_metadata(&subkey.key, binding, &subkey.signatures, storage)
}

fn key_validity<K>(
    key: &K,
    binding: Option<&Signature>,
    revocations: &[Signature],
    evaluated_at: u64,
    legacy_without_binding: bool,
) -> Result<KeyValidity, KeyError>
where
    K: pgp::types::KeyDetails,
{
    let created_at = u64::from(key.created_at().as_secs());
    let expires_at =
        legacy_v3_expiration(key).or_else(|| expiration_from_signature(created_at, binding));
    Ok(KeyValidity {
        fingerprint: FullFingerprint::from_rpgp(&key.fingerprint()),
        not_yet_valid: evaluated_at < created_at,
        expired: expires_at.is_some_and(|expiration| evaluated_at >= expiration),
        revoked: has_current_revocation(revocations, evaluated_at),
        has_current_binding: binding.is_some() || legacy_without_binding,
        key_flags: binding.map_or_else(|| Ok(KeyUsageFlags::default()), usage_flags)?,
        expires_at,
    })
}

fn user_id_metadata(user: &SignedUser) -> UserIdMetadata {
    UserIdMetadata {
        raw: user.id.id().to_vec(),
        utf8: user.id.as_str().map(str::to_owned),
        is_primary: user
            .signatures
            .iter()
            .filter(|signature| signature.typ() != Some(SignatureType::CertRevocation))
            .any(Signature::is_primary),
        revocations: user
            .signatures
            .iter()
            .filter(|signature| signature.typ() == Some(SignatureType::CertRevocation))
            .map(revocation_metadata)
            .collect(),
    }
}

fn primary_signature(certificate: &SignedPublicKey, at: Option<u64>) -> Option<&Signature> {
    let direct = latest_signature(
        certificate
            .details
            .direct_signatures
            .iter()
            .filter(|signature| signature.typ() == Some(SignatureType::Key)),
        at,
    );
    if certificate.version() == pgp::types::KeyVersion::V6 {
        return direct;
    }
    direct.or_else(|| primary_user(certificate, at).and_then(|user| user_certification(user, at)))
}

fn primary_user(certificate: &SignedPublicKey, at: Option<u64>) -> Option<&SignedUser> {
    certificate
        .details
        .users
        .iter()
        .find(|user| user_certification(user, at).is_some_and(Signature::is_primary))
        .or_else(|| {
            certificate
                .details
                .users
                .iter()
                .find(|user| user_certification(user, at).is_some())
        })
}

fn user_certification(user: &SignedUser, at: Option<u64>) -> Option<&Signature> {
    latest_signature(
        user.signatures
            .iter()
            .filter(|signature| signature.typ() != Some(SignatureType::CertRevocation)),
        at,
    )
}

fn latest_signature<'a>(
    signatures: impl IntoIterator<Item = &'a Signature>,
    at: Option<u64>,
) -> Option<&'a Signature> {
    signatures
        .into_iter()
        .filter(|signature| at.is_none_or(|at| signature_is_current(signature, at)))
        .max_by_key(|signature| {
            signature
                .created()
                .map_or(0, |created| u64::from(created.as_secs()))
        })
}

fn signature_is_current(signature: &Signature, at: u64) -> bool {
    let Some(created) = signature.created() else {
        return false;
    };
    let created = u64::from(created.as_secs());
    if created > at {
        return false;
    }
    signature
        .signature_expiration_time()
        .is_none_or(|duration| {
            duration.as_secs() == 0 || at < created.saturating_add(u64::from(duration.as_secs()))
        })
}

fn expiration_from_signature(created_at: u64, signature: Option<&Signature>) -> Option<u64> {
    signature
        .and_then(Signature::key_expiration_time)
        .filter(|duration| duration.as_secs() != 0)
        .map(|duration| created_at.saturating_add(u64::from(duration.as_secs())))
}

fn legacy_v3_expiration<K>(key: &K) -> Option<u64>
where
    K: pgp::types::KeyDetails,
{
    if key.version() > pgp::types::KeyVersion::V3 {
        return None;
    }
    key.legacy_v3_expiration_days()
        .filter(|days| *days != 0)
        .map(|days| {
            u64::from(key.created_at().as_secs())
                .saturating_add(u64::from(days).saturating_mul(86_400))
        })
}

fn has_current_revocation(signatures: &[Signature], at: u64) -> bool {
    signatures
        .iter()
        .any(|signature| is_key_revocation(signature.typ()) && signature_is_current(signature, at))
}

fn is_key_revocation(typ: Option<SignatureType>) -> bool {
    matches!(
        typ,
        Some(
            SignatureType::KeyRevocation
                | SignatureType::SubkeyRevocation
                | SignatureType::CertRevocation
        )
    )
}

fn revocation_metadata(signature: &Signature) -> RevocationMetadata {
    RevocationMetadata {
        created_at: signature
            .created()
            .map(|created| u64::from(created.as_secs())),
        reason_code: signature
            .revocation_reason_code()
            .map(|code| u8::from(*code)),
        reason: signature
            .revocation_reason_string()
            .map(|reason| reason.to_vec()),
    }
}

fn usage_flags(flags: &Signature) -> Result<KeyUsageFlags, KeyError> {
    Ok(KeyUsageFlags::try_from(flags.key_flags())?)
}

impl TryFrom<KeyFlags> for KeyUsageFlags {
    type Error = pgp::errors::Error;

    fn try_from(flags: KeyFlags) -> Result<Self, Self::Error> {
        Ok(Self {
            certify: flags.certify(),
            sign: flags.sign(),
            encrypt_communications: flags.encrypt_comms(),
            encrypt_storage: flags.encrypt_storage(),
            authentication: flags.authentication(),
            shared: flags.shared(),
            group: flags.group(),
            timestamping: flags.timestamping(),
            additional_decryption_subkey: flags.adsk(),
            forwarded_decryption: flags.draft_decrypt_forwarded(),
            encoded: flags.to_bytes()?,
        })
    }
}

pub(crate) fn algorithm_metadata(
    algorithm: PublicKeyAlgorithm,
    params: &PublicParams,
) -> Result<AlgorithmMetadata, KeyError> {
    let mut policy_algorithm = None;
    let mut bit_size = None;
    let mut curve = None;

    match params {
        PublicParams::RSA(rsa) => {
            bit_size = first_mpi_bit_size(rsa)?;
            if algorithm == PublicKeyAlgorithm::RSA {
                policy_algorithm = match bit_size {
                    Some(2048) => Some(Algorithm::Rsa2048),
                    Some(3072) => Some(Algorithm::Rsa3072),
                    Some(4096) => Some(Algorithm::Rsa4096),
                    _ => None,
                };
            }
        }
        PublicParams::DSA(dsa) => {
            bit_size = first_mpi_bit_size(dsa)?;
            policy_algorithm = Some(Algorithm::Dsa);
        }
        PublicParams::Elgamal(elgamal) => {
            bit_size = first_mpi_bit_size(elgamal)?;
            policy_algorithm = Some(Algorithm::ElGamal);
        }
        PublicParams::ECDSA(ecdsa) => {
            let ecc = ecdsa.curve();
            curve = Some(curve_metadata(&ecc));
            bit_size = curve.as_ref().and_then(|curve| curve.bit_size);
            policy_algorithm = match ecdsa {
                EcdsaPublicParams::P256 { .. } => Some(Algorithm::NistP256Ecdsa),
                EcdsaPublicParams::P384 { .. } => Some(Algorithm::NistP384Ecdsa),
                EcdsaPublicParams::P521 { .. } => Some(Algorithm::NistP521Ecdsa),
                EcdsaPublicParams::Secp256k1 { .. } => None,
                EcdsaPublicParams::Unsupported { curve, .. } => brainpool_ecdsa(curve),
            };
        }
        PublicParams::ECDH(ecdh) => {
            let ecc = ecdh.curve();
            curve = Some(curve_metadata(&ecc));
            bit_size = curve.as_ref().and_then(|curve| curve.bit_size);
            policy_algorithm = match ecdh {
                EcdhPublicParams::Curve25519Legacy { .. } => Some(Algorithm::LegacyCurve25519Ecdh),
                EcdhPublicParams::P256 { .. } => Some(Algorithm::NistP256Ecdh),
                EcdhPublicParams::P384 { .. } => Some(Algorithm::NistP384Ecdh),
                EcdhPublicParams::P521 { .. } => Some(Algorithm::NistP521Ecdh),
                EcdhPublicParams::Brainpool256 { .. } => Some(Algorithm::BrainpoolP256Ecdh),
                EcdhPublicParams::Brainpool384 { .. } => Some(Algorithm::BrainpoolP384Ecdh),
                EcdhPublicParams::Brainpool512 { .. } => Some(Algorithm::BrainpoolP512Ecdh),
                EcdhPublicParams::Unsupported { .. } => None,
            };
        }
        PublicParams::EdDSALegacy(eddsa) => {
            let ecc = eddsa.curve();
            curve = Some(curve_metadata(&ecc));
            bit_size = curve.as_ref().and_then(|curve| curve.bit_size);
            if matches!(eddsa, EddsaLegacyPublicParams::Ed25519 { .. }) {
                policy_algorithm = Some(Algorithm::LegacyEd25519);
            }
        }
        PublicParams::Ed25519(_) => {
            policy_algorithm = Some(Algorithm::Ed25519);
            bit_size = Some(255);
        }
        PublicParams::X25519(_) => {
            policy_algorithm = Some(Algorithm::X25519);
            bit_size = Some(255);
        }
        PublicParams::Ed448(_) => {
            policy_algorithm = Some(Algorithm::Ed448);
            bit_size = Some(448);
        }
        PublicParams::X448(_) => {
            policy_algorithm = Some(Algorithm::X448);
            bit_size = Some(448);
        }
        PublicParams::Unknown { .. } => {}
    }

    Ok(AlgorithmMetadata {
        id: u8::from(algorithm),
        name: format!("{algorithm:?}"),
        policy_algorithm,
        bit_size,
        curve,
    })
}

fn brainpool_ecdsa(curve: &ECCCurve) -> Option<Algorithm> {
    match curve {
        ECCCurve::BrainpoolP256r1 => Some(Algorithm::BrainpoolP256Ecdsa),
        ECCCurve::BrainpoolP384r1 => Some(Algorithm::BrainpoolP384Ecdsa),
        ECCCurve::BrainpoolP512r1 => Some(Algorithm::BrainpoolP512Ecdsa),
        _ => None,
    }
}

fn curve_metadata(curve: &ECCCurve) -> CurveMetadata {
    CurveMetadata {
        name: curve.name().to_owned(),
        oid: curve.oid_str(),
        bit_size: match curve.nbits() {
            0 => None,
            bits => Some(u32::from(bits)),
        },
    }
}

fn first_mpi_bit_size<T>(params: &T) -> Result<Option<u32>, KeyError>
where
    T: Serialize,
{
    let encoded = params.to_bytes()?;
    Ok(encoded
        .get(..2)
        .map(|length| u32::from(u16::from_be_bytes([length[0], length[1]]))))
}

fn key_id<K>(key: &K) -> String
where
    K: pgp::types::KeyDetails,
{
    uppercase_hex(key.legacy_key_id().as_ref())
}

fn uppercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
