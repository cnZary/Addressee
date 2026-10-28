// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use openpgp_card::ocard::{
    KeyType,
    algorithm::{AlgorithmAttributes, Curve},
    crypto::{EccType, PublicKeyMaterial},
    data::{Fingerprint, KeyGenerationTime},
};
use pgp::{
    composed::{SignedKeyDetails, SignedPublicKey, SignedPublicSubKey},
    crypto::{
        ecc_curve::ECCCurve,
        hash::HashAlgorithm,
        public_key::PublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::{
        Features,
        KeyFlags,
        PacketHeader,
        PacketTrait,
        PubKeyInner,
        PublicKey,
        PublicSubkey,
        SignatureConfig,
        SignatureType,
        Subpacket,
        SubpacketData,
        UserId,
    },
    types::{
        EcdhKdfType,
        EcdhPublicParams,
        EcdsaPublicParams,
        EddsaLegacyPublicParams,
        KeyDetails,
        KeyVersion,
        PacketHeaderVersion,
        Password,
        PublicParams,
        RsaPublicParams,
        SignedUser,
        SigningKey,
        Tag,
        Timestamp,
    },
};
use rsa::RsaPublicKey;
use secrecy::SecretString;

use crate::{CardSlot, Error};

/// value pairs that we'll consider in ECDH parameter auto-detection
const ECDH_PARAM: &[(Option<HashAlgorithm>, Option<SymmetricKeyAlgorithm>)] = &[
    (
        Some(HashAlgorithm::Sha256),
        Some(SymmetricKeyAlgorithm::AES128),
    ),
    (
        Some(HashAlgorithm::Sha512),
        Some(SymmetricKeyAlgorithm::AES256),
    ),
    (
        Some(HashAlgorithm::Sha384),
        Some(SymmetricKeyAlgorithm::AES256),
    ),
    (
        Some(HashAlgorithm::Sha384),
        Some(SymmetricKeyAlgorithm::AES192),
    ),
    (
        Some(HashAlgorithm::Sha256),
        Some(SymmetricKeyAlgorithm::AES256),
    ),
];

fn pubkey(
    algo: PublicKeyAlgorithm,
    created: Timestamp,
    param: PublicParams,
) -> Result<PublicKey, Error> {
    Ok(PublicKey::from_inner(PubKeyInner::new(
        KeyVersion::V4, // FIXME: handle other OpenPGP key versions, later
        algo,
        created,
        None,
        param,
    )?)?)
}

fn map_curve(c: &Curve) -> Result<ECCCurve, Error> {
    Ok(match c {
        Curve::NistP256r1 => ECCCurve::P256,
        Curve::NistP384r1 => ECCCurve::P384,
        Curve::NistP521r1 => ECCCurve::P521,
        Curve::BrainpoolP256r1 => ECCCurve::BrainpoolP256r1,
        Curve::BrainpoolP384r1 => ECCCurve::BrainpoolP384r1,
        Curve::BrainpoolP512r1 => ECCCurve::BrainpoolP512r1,
        Curve::Ed25519 => ECCCurve::Ed25519Legacy,
        Curve::Curve25519 => ECCCurve::Curve25519Legacy,

        _ => return Err(Error::Message(format!("Can't map curve {c:?}"))),
    })
}

/// Get PublicKey for an openpgp-card PublicKeyMaterial, KeyGenerationTime and Fingerprint.
///
/// For ECC decryption keys, possible values for the parameters `hash` and `alg_sym` will be tested.
/// If a key with matching fingerprint is found in this way, it is considered the correct key,
/// and returned.
///
/// The Fingerprint of the retrieved PublicKey is always validated against the `Fingerprint` as
/// stored on the card. If the fingerprints don't match, an Error is returned.
pub fn public_key_material_and_fp_to_key(
    pkm: &PublicKeyMaterial,
    key_type: KeyType,
    created: &KeyGenerationTime,
    fingerprint: &Fingerprint,
) -> Result<PublicKey, Error> {
    // Possible hash/sym parameters based on statistics over 2019-12 SKS dump:
    // https://gitlab.com/sequoia-pgp/sequoia/-/issues/838#note_909813463

    let param: &[_] = match (pkm, key_type) {
        (PublicKeyMaterial::E(_), KeyType::Decryption) => ECDH_PARAM,
        _ => &[(None, None)],
    };

    for (hash, alg_sym) in param {
        if let Ok(key) = public_key_material_to_key(pkm, key_type, created, *hash, *alg_sym) {
            // check FP
            if key.fingerprint().as_bytes() == fingerprint.as_bytes() {
                // return if match
                return Ok(key);
            }
        }
    }

    Err(Error::Message(
        "Couldn't find key with matching fingerprint".to_string(),
    ))
}

/// Transform an openpgp-card `PublicKeyMaterial` and `KeyGenerationTime`
///  into an rpgp `PublicKey` representation.
///
/// For ECDH decryption keys, `hash` and `alg_sym` can be optionally specified.
///
/// If `hash` and `alg_sym` are required, and the caller passes `None`,
///  curve-specific default parameters are used.
pub fn public_key_material_to_key(
    pkm: &PublicKeyMaterial,
    key_type: KeyType,
    created: &KeyGenerationTime,
    hash: Option<HashAlgorithm>,
    alg_sym: Option<SymmetricKeyAlgorithm>,
) -> Result<PublicKey, Error> {
    #[allow(clippy::expect_used)]
    let created = created.get();

    match pkm {
        PublicKeyMaterial::R(rsa) => pubkey(
            PublicKeyAlgorithm::RSA,
            Timestamp::from_secs(created),
            PublicParams::RSA(RsaPublicParams {
                key: RsaPublicKey::new(
                    rsa::BigUint::from_bytes_be(rsa.n()),
                    rsa::BigUint::from_bytes_be(rsa.v()),
                )?,
            }),
        ),

        PublicKeyMaterial::E(ecc) => match ecc.algo() {
            AlgorithmAttributes::Ecc(ecc_attr) => {
                let typ = ecc_attr.ecc_type();

                let curve = map_curve(ecc_attr.curve())?;

                let (pka, pp) = match typ {
                    EccType::ECDH => {
                        if key_type != KeyType::Decryption {
                            return Err(Error::Message(format!(
                                "ECDH is unsupported in key slot {key_type:?}"
                            )));
                        }

                        let hash = hash.unwrap_or(curve.hash_algo()?);
                        let alg_sym = alg_sym.unwrap_or(curve.sym_algo()?);

                        let ecdh_pp = match curve {
                            ECCCurve::Curve25519Legacy => {
                                if ecc.data().len() != 32 {
                                    return Err(Error::Message(format!(
                                        "x25519 public key unexpected length {}",
                                        ecc.data().len()
                                    )));
                                }

                                let mut public_key_arr = [0u8; 32];
                                public_key_arr[..].copy_from_slice(ecc.data());

                                let p = x25519_dalek::PublicKey::from(public_key_arr);
                                EcdhPublicParams::Curve25519Legacy {
                                    p,
                                    hash,
                                    alg_sym,
                                    ecdh_kdf_type: EcdhKdfType::Native,
                                }
                            }
                            ECCCurve::P256 => {
                                let p = p256::PublicKey::from_sec1_bytes(ecc.data())?;
                                EcdhPublicParams::P256 { p, hash, alg_sym }
                            }
                            ECCCurve::P384 => {
                                let p = p384::PublicKey::from_sec1_bytes(ecc.data())?;
                                EcdhPublicParams::P384 { p, hash, alg_sym }
                            }
                            ECCCurve::P521 => {
                                let p = p521::PublicKey::from_sec1_bytes(ecc.data())?;
                                EcdhPublicParams::P521 { p, hash, alg_sym }
                            }
                            _ => {
                                return Err(Error::Message(format!(
                                    "Unsupported curve {:?} for ecdh",
                                    curve.name()
                                )));
                            }
                        };

                        (PublicKeyAlgorithm::ECDH, PublicParams::ECDH(ecdh_pp))
                    }

                    EccType::ECDSA => {
                        let ecdsa_pp = match curve {
                            ECCCurve::P256 => {
                                let key = p256::PublicKey::from_sec1_bytes(ecc.data())?;
                                EcdsaPublicParams::P256 { key }
                            }
                            ECCCurve::P384 => {
                                let key = p384::PublicKey::from_sec1_bytes(ecc.data())?;
                                EcdsaPublicParams::P384 { key }
                            }
                            ECCCurve::P521 => {
                                let key = p521::PublicKey::from_sec1_bytes(ecc.data())?;
                                EcdsaPublicParams::P521 { key }
                            }
                            // FIXME: brainpool
                            _ => {
                                return Err(Error::Message(format!(
                                    "Unsupported curve {:?} for ecdsa",
                                    curve.name()
                                )));
                            }
                        };

                        (PublicKeyAlgorithm::ECDSA, PublicParams::ECDSA(ecdsa_pp))
                    }

                    EccType::EdDSA => {
                        if curve != ECCCurve::Ed25519Legacy {
                            return Err(Error::Message(format!(
                                "Inconsistent curve {} for EdDSA",
                                curve.name()
                            )));
                        }

                        let key: ed25519_dalek::VerifyingKey = ecc.data().try_into()?;

                        (
                            PublicKeyAlgorithm::EdDSALegacy,
                            PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { key }),
                        )
                    }
                };

                pubkey(pka, Timestamp::from_secs(created), pp)
            }

            _ => Err(Error::Message(format!(
                "Unexpected AlgorithmAttributes type in Ecc {:?}",
                ecc.algo(),
            ))),
        },
    }
}

pub(crate) fn pubkey_from_card(
    tx: &mut openpgp_card::Card<openpgp_card::state::Transaction>,
    key_type: KeyType,
) -> Result<PublicKey, Error> {
    let pkm = tx.public_key_material(key_type)?;

    let Some(created) = tx.key_generation_time(key_type)? else {
        // KeyGenerationTime is None
        return Err(Error::Message(format!(
            "No creation time set for OpenPGP card key type {key_type:?}",
        )));
    };

    let Some(fingerprint) = tx.fingerprint(key_type)? else {
        // Fingerprint is None
        return Err(Error::Message(format!(
            "No fingerprint found for key slot {key_type:?}"
        )));
    };

    public_key_material_and_fp_to_key(&pkm, key_type, &created, &fingerprint)
}

/// Calculate the `Fingerprint` for `PublicKeyMaterial` and `KeyGenerationTime`
pub fn public_to_fingerprint(
    pkm: &PublicKeyMaterial,
    kgt: KeyGenerationTime,
    kt: KeyType,
) -> Result<Fingerprint, openpgp_card::Error> {
    let key = public_key_material_to_key(pkm, kt, &kgt, None, None).map_err(|e| {
        openpgp_card::Error::InternalError(format!("public_key_material_to_key: {e}"))
    })?;

    let fp = key.fingerprint();

    openpgp_card::ocard::data::Fingerprint::try_from(fp.as_bytes())
}

// FIXME: upstream?
fn pri_to_sub(pubkey: PublicKey) -> pgp::errors::Result<PublicSubkey> {
    // FIXME: this is a bit of a hack

    let header = PacketHeader::from_parts(
        pubkey.packet_header().version(),
        Tag::PublicSubkey,
        pubkey.packet_header().packet_length(),
    )?;

    PublicSubkey::new_with_header(
        header,
        pubkey.version(),
        pubkey.algorithm(),
        pubkey.created_at(),
        pubkey.legacy_v3_expiration_days(),
        pubkey.public_params().clone(),
    )
}

/// Bind the component keys on a card into a `SignedPublicKey`.
///
/// NOTE: This function makes a number of assumptions that don't apply to all OpenPGP keys!
/// The resulting OpenPGP public key object may be unfit for purpose!
///
/// This function assumes that the signing slot of the card serves as the
/// primary key, and uses it to issue binding self-signatures.
///
/// This function sets the certification- and data-signature key flags on the `sig` component ke.
///
/// At least one User ID is required. The first User ID is marked as "primary user id".
///
///
/// If `user_pin` is None, pinpad verification is attempted.
/// `pinpad_prompt` is called to notify the user when pinpad input (of the
///  User PIN) is required.
///
/// `touch_prompt` is called to notify the user when touch confirmation is
/// required on the card for a signing operation.
///
/// FIXME: Accept optional metadata for user_id binding(s)?
#[allow(clippy::too_many_arguments)]
pub fn bind_into_certificate(
    tx: &mut openpgp_card::Card<openpgp_card::state::Transaction>,
    sig: PublicKey,
    dec: Option<PublicKey>,
    aut: Option<PublicKey>,
    user_ids: &[String],
    user_pin: Option<SecretString>,
    pinpad_prompt: &dyn Fn(),
    touch_prompt: &(dyn Fn() + Send + Sync),
) -> Result<SignedPublicKey, Error> {
    let primary = sig;

    if user_ids.is_empty() {
        return Err(Error::Message(
            "At least one User ID must be added to create a valid certificate".to_string(),
        ));
    }

    // helper: use the card to perform a signing operation
    let verify_signing_pin =
        |txx: &mut openpgp_card::Card<openpgp_card::state::Transaction>|
         -> Result<(), openpgp_card::Error> {
            // Allow signing on the card
            if let Some(pw1) = user_pin.clone() {
                txx.verify_user_signing_pin(pw1)?;
            } else {
                txx.verify_user_signing_pinpad(pinpad_prompt)?;
            }
            Ok(())
        };

    let mut subkeys = vec![];

    if let Some(dec) = dec {
        // add decryption key as subkey
        let key = pri_to_sub(dec)?;

        verify_signing_pin(tx)?;

        // make binding signature, sign with cs
        let cs = CardSlot::with_public_key(tx, KeyType::Signing, primary.clone(), touch_prompt)?;

        let mut kf = KeyFlags::default();
        kf.set_encrypt_comms(true);
        kf.set_encrypt_storage(true);

        let mut config =
            SignatureConfig::v4(SignatureType::SubkeyBinding, cs.algorithm(), cs.hash_alg());

        config.hashed_subpackets = vec![
            Subpacket::critical(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
            Subpacket::critical(SubpacketData::KeyFlags(kf))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(cs.fingerprint()))?,
        ];
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            cs.legacy_key_id(),
        ))?];

        let sig = config.sign_subkey_binding(&cs, cs.public_key(), &Password::empty(), &key)?;

        let sps = SignedPublicSubKey {
            key,
            signatures: vec![sig],
        };

        subkeys.push(sps);
    }

    if let Some(aut) = aut {
        // add decryption key as subkey
        let key = pri_to_sub(aut)?;

        verify_signing_pin(tx)?;

        // make binding signature, sign with cs
        let cs = CardSlot::with_public_key(tx, KeyType::Signing, primary.clone(), touch_prompt)?;

        let mut kf = KeyFlags::default();
        kf.set_authentication(true);

        let mut config =
            SignatureConfig::v4(SignatureType::SubkeyBinding, cs.algorithm(), cs.hash_alg());

        config.hashed_subpackets = vec![
            Subpacket::critical(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
            Subpacket::critical(SubpacketData::KeyFlags(kf))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(cs.fingerprint()))?,
        ];
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            cs.legacy_key_id(),
        ))?];

        let sig = config.sign_subkey_binding(&cs, &cs.public_key(), &Password::empty(), &key)?;

        let sps = SignedPublicSubKey {
            key,
            signatures: vec![sig],
        };

        subkeys.push(sps);
    }

    let mut users = vec![];

    // add `user_ids`.
    for (n, uid) in user_ids.iter().enumerate() {
        let uid = UserId::from_str(PacketHeaderVersion::New, uid)?;

        let mut kf = KeyFlags::default();
        kf.set_certify(true);
        kf.set_sign(true);

        verify_signing_pin(tx)?;

        let cs = CardSlot::with_public_key(tx, KeyType::Signing, primary.clone(), touch_prompt)?;
        let mut config =
            SignatureConfig::v4(SignatureType::CertPositive, cs.algorithm(), cs.hash_alg());

        config.hashed_subpackets = vec![
            // make this primary user id binding valid at certificate creation time
            Subpacket::critical(SubpacketData::SignatureCreationTime(primary.created_at()))?,
            Subpacket::critical(SubpacketData::KeyFlags(kf))?,
            // the first user id is marked as primary
            Subpacket::regular(SubpacketData::IsPrimary(n == 0))?,
            // SEIPDv1
            Subpacket::regular(SubpacketData::Features(Features::from(&[0x01][..])))?,
        ];
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            cs.legacy_key_id(),
        ))?];

        let sig =
            config.sign_certification(&cs, cs.public_key(), &Password::empty(), uid.tag(), &uid)?;

        let suid = SignedUser::new(uid, vec![sig]);

        users.push(suid);
    }

    // TODO: consider generating a direct key signature?

    let details = SignedKeyDetails::new(vec![], vec![], users, vec![]);

    let spk = SignedPublicKey::new(primary, details, subkeys);

    Ok(spk)
}
