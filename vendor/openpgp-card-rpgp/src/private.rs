// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use openpgp_card::{
    Error,
    ocard::{
        crypto::{CardUploadableKey, EccKey, EccType, PrivateKeyMaterial, RSAKey},
        data::{Fingerprint, KeyGenerationTime},
    },
};
use pgp::{
    crypto::{ecc_curve::ECCCurve, eddsa_legacy},
    types::{
        EcdhPublicParams,
        EcdsaPublicParams,
        EddsaLegacyPublicParams,
        KeyDetails,
        PlainSecretParams,
        PublicParams,
        SecretParams,
    },
};
use rsa::{
    BigUint,
    traits::{PrivateKeyParts, PublicKeyParts},
};

/// Shared type for rPGP "secret key" packets (primary or subkey)
enum Sec {
    Key(pgp::packet::SecretKey),
    SubKey(pgp::packet::SecretSubkey),
}

impl Sec {
    fn public_params(&self) -> &PublicParams {
        match self {
            Sec::Key(sk) => sk.public_key().public_params(),
            Sec::SubKey(ssk) => ssk.public_key().public_params(),
        }
    }

    fn secret_params(&self) -> &SecretParams {
        match self {
            Sec::Key(sk) => sk.secret_params(),
            Sec::SubKey(ssk) => ssk.secret_params(),
        }
    }
}

/// Private key material that can be uploaded to a card slot.
///
/// The data in an `UploadableKey` corresponds to an OpenPGP secret key packet.
pub struct UploadableKey {
    key: Sec,
    unlocked: Option<PlainSecretParams>,
}

impl From<pgp::packet::SecretKey> for UploadableKey {
    fn from(value: pgp::packet::SecretKey) -> Self {
        Self {
            key: Sec::Key(value),
            unlocked: None,
        }
    }
}

impl From<pgp::packet::SecretSubkey> for UploadableKey {
    fn from(value: pgp::packet::SecretSubkey) -> Self {
        Self {
            key: Sec::SubKey(value),
            unlocked: None,
        }
    }
}

impl UploadableKey {
    pub fn is_locked(&self) -> bool {
        match self.key.secret_params() {
            SecretParams::Plain(_) => false,
            SecretParams::Encrypted(_) => true,
        }
    }

    /// Returns:
    /// - `Ok(false)` for keys that are not password protected
    /// - `Ok(true)` for protected keys that were successfully unlocked
    /// - `Err` when the password did not unlock the key (in this case, the key cannot be imported
    ///   to a card).
    pub fn try_unlock(&mut self, pw: &str) -> Result<bool, Error> {
        match self.key.secret_params() {
            SecretParams::Plain(_) => Ok(false),
            SecretParams::Encrypted(esp) => {
                match &self.key {
                    // FIXME: this duplication is unfortunate
                    Sec::Key(sk) => {
                        if let Ok(psp) = esp.unlock(&pw.into(), sk.public_key(), None) {
                            self.unlocked = Some(psp);
                            return Ok(true);
                        }
                    }
                    Sec::SubKey(ssk) => {
                        if let Ok(psp) = esp.unlock(&pw.into(), ssk.public_key(), None) {
                            self.unlocked = Some(psp);
                            return Ok(true);
                        }
                    }
                }

                Err(Error::InternalError("Could not unlock key".to_string()))
            }
        }
    }
}

impl CardUploadableKey for UploadableKey {
    fn private_key(&self) -> Result<PrivateKeyMaterial, Error> {
        fn to_privatekeymaterial(
            psp: &PlainSecretParams,
            pp: &PublicParams,
        ) -> Result<PrivateKeyMaterial, Error> {
            match (psp, pp) {
                (PlainSecretParams::RSA(secret), PublicParams::RSA(public)) => {
                    let (d, p, q, _u) = secret.to_bytes();

                    let rsa_key = Rsa::new(
                        public.key.e().to_bytes_be().into(),
                        d.into(),
                        public.key.n().to_bytes_be().into(),
                        p.into(),
                        q.into(),
                    )?;
                    Ok(PrivateKeyMaterial::R(Box::new(rsa_key)))
                }
                (PlainSecretParams::ECDSA(s), PublicParams::ECDSA(p)) => {
                    let (curve, public, private) = match (p, s) {
                        (
                            EcdsaPublicParams::P256 { key },
                            pgp::crypto::ecdsa::SecretKey::P256(secret),
                        ) => (
                            ECCCurve::P256,
                            key.to_sec1_bytes(),
                            secret.to_bytes().to_vec(),
                        ),
                        (
                            EcdsaPublicParams::P384 { key },
                            pgp::crypto::ecdsa::SecretKey::P384(secret),
                        ) => (
                            ECCCurve::P384,
                            key.to_sec1_bytes(),
                            secret.to_bytes().to_vec(),
                        ),
                        (
                            EcdsaPublicParams::P521 { key },
                            pgp::crypto::ecdsa::SecretKey::P521(secret),
                        ) => (
                            ECCCurve::P521,
                            key.to_sec1_bytes(),
                            secret.to_bytes().to_vec(),
                        ),
                        (
                            EcdsaPublicParams::Secp256k1 { .. },
                            pgp::crypto::ecdsa::SecretKey::Secp256k1(_),
                        ) => {
                            return Err(Error::UnsupportedAlgo(
                                "ECDSA with curve Secp256k1 is unsupported".to_string(),
                            ));
                        }
                        _ => {
                            return Err(Error::UnsupportedAlgo(format!(
                                "ECDSA with unsupported algorithm(s) {p:?} / {s:?}"
                            )));
                        }
                    };

                    let ecc = Ecc::new(curve, private.into(), public, EccType::ECDSA);
                    Ok(PrivateKeyMaterial::E(Box::new(ecc)))
                }
                (
                    PlainSecretParams::EdDSALegacy(eddsa_legacy::SecretKey::Ed25519(m)),
                    PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { key }),
                ) => {
                    let mut public = Vec::with_capacity(33);
                    public.push(0x40);
                    public.extend_from_slice(key.as_bytes());

                    let ecc = Ecc::new(
                        ECCCurve::Ed25519Legacy.clone(),
                        m.as_bytes().to_vec().into(),
                        public.into(),
                        EccType::EdDSA,
                    );
                    Ok(PrivateKeyMaterial::E(Box::new(ecc)))
                }
                (
                    PlainSecretParams::ECDH(pgp::crypto::ecdh::SecretKey::Curve25519Legacy(secret)),
                    PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { p, .. }),
                ) => {
                    // Behold: the sad reversed x25519 wire format in OpenPGP
                    let reversed_private = secret.to_bytes_rev();

                    let mut public = Vec::with_capacity(33);
                    public.push(0x40);
                    public.extend_from_slice(p.as_ref());

                    let ecc = Ecc::new(
                        ECCCurve::Curve25519Legacy.clone(),
                        reversed_private.to_vec().into(),
                        public.to_vec().into(),
                        EccType::ECDH,
                    );
                    Ok(PrivateKeyMaterial::E(Box::new(ecc)))
                }
                (
                    PlainSecretParams::ECDH(pgp::crypto::ecdh::SecretKey::P256 { secret }),
                    PublicParams::ECDH(EcdhPublicParams::P256 { p, .. }),
                ) => {
                    let ecc = Ecc::new(
                        ECCCurve::P256.clone(),
                        secret.to_bytes().to_vec().into(),
                        p.to_sec1_bytes().to_vec().into(),
                        EccType::ECDH,
                    );
                    Ok(PrivateKeyMaterial::E(Box::new(ecc)))
                }
                (
                    PlainSecretParams::ECDH(pgp::crypto::ecdh::SecretKey::P384 { secret }),
                    PublicParams::ECDH(EcdhPublicParams::P384 { p, .. }),
                ) => {
                    let ecc = Ecc::new(
                        ECCCurve::P384.clone(),
                        secret.to_bytes().to_vec().into(),
                        p.to_sec1_bytes().to_vec().into(),
                        EccType::ECDH,
                    );
                    Ok(PrivateKeyMaterial::E(Box::new(ecc)))
                }
                (
                    PlainSecretParams::ECDH(pgp::crypto::ecdh::SecretKey::P521 { secret }),
                    PublicParams::ECDH(EcdhPublicParams::P521 { p, .. }),
                ) => {
                    let ecc = Ecc::new(
                        ECCCurve::P521.clone(),
                        secret.to_bytes().to_vec().into(),
                        p.to_sec1_bytes().to_vec().into(),
                        EccType::ECDH,
                    );
                    Ok(PrivateKeyMaterial::E(Box::new(ecc)))
                }

                _ => Err(Error::UnsupportedAlgo(format!(
                    "Unsupported key material {pp:?}"
                ))),
            }
        }

        let pp = self.key.public_params();

        let psp = match self.key.secret_params() {
            SecretParams::Plain(psp) => psp,
            SecretParams::Encrypted(_) => {
                if let Some(psp) = &self.unlocked {
                    psp
                } else {
                    return Err(Error::InternalError(
                        "Secret key packet wasn't unlocked".to_string(),
                    ));
                }
            }
        };

        to_privatekeymaterial(psp, pp)
    }

    fn timestamp(&self) -> KeyGenerationTime {
        let ts = match &self.key {
            Sec::Key(sk) => sk.public_key().created_at(),
            Sec::SubKey(ssk) => ssk.public_key().created_at(),
        };

        ts.as_secs().into()
    }

    fn fingerprint(&self) -> Result<Fingerprint, Error> {
        let fp = match &self.key {
            Sec::Key(sk) => sk.fingerprint(),
            Sec::SubKey(ssk) => ssk.fingerprint(),
        };

        Fingerprint::try_from(fp.as_bytes())
    }
}

struct Rsa {
    e: Box<[u8]>,
    n: Box<[u8]>,
    p: Box<[u8]>,
    q: Box<[u8]>,
    pq: Box<[u8]>,
    dp1: Box<[u8]>,
    dq1: Box<[u8]>,
}

impl Rsa {
    fn new(
        e: Box<[u8]>,
        d: Box<[u8]>,
        n: Box<[u8]>,
        p: Box<[u8]>,
        q: Box<[u8]>,
    ) -> Result<Self, Error> {
        let key = rsa::RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&n),
            BigUint::from_bytes_be(&e),
            BigUint::from_bytes_be(&d),
            vec![BigUint::from_bytes_be(&p), BigUint::from_bytes_be(&q)],
        )
        .map_err(|e| Error::InternalError(format!("rsa error {e:?}")))?;

        let pq = key
            .qinv()
            .ok_or_else(|| Error::InternalError("pq value missing".into()))?
            .to_biguint()
            .ok_or_else(|| Error::InternalError("conversion to bigunit failed".into()))?
            .to_bytes_be()
            .into();

        let dp1 = key
            .dp()
            .ok_or_else(|| Error::InternalError("dp1 value missing".into()))?
            .to_bytes_be()
            .into();

        let dq1 = key
            .dq()
            .ok_or_else(|| Error::InternalError("dq1 value missing".into()))?
            .to_bytes_be()
            .into();

        Ok(Self {
            e,
            n,
            p,
            q,
            pq,
            dp1,
            dq1,
        })
    }
}

impl RSAKey for Rsa {
    fn e(&self) -> &[u8] {
        &self.e
    }

    fn p(&self) -> &[u8] {
        &self.p
    }

    fn q(&self) -> &[u8] {
        &self.q
    }

    fn pq(&self) -> &[u8] {
        &self.pq
    }

    fn dp1(&self) -> &[u8] {
        &self.dp1
    }

    fn dq1(&self) -> &[u8] {
        &self.dq1
    }

    fn n(&self) -> &[u8] {
        &self.n
    }
}

/// ECC-specific data-structure to hold private (sub)key material for upload
/// with the `openpgp-card` crate.
struct Ecc {
    ecc_type: EccType,
    oid: Box<[u8]>,

    private: Box<[u8]>,
    public: Box<[u8]>,
}

impl Ecc {
    fn new(curve: ECCCurve, private: Box<[u8]>, public: Box<[u8]>, ecc_type: EccType) -> Self {
        let oid = curve.oid().into();

        let private = match curve {
            ECCCurve::P256 | ECCCurve::Curve25519Legacy | ECCCurve::Ed25519Legacy => {
                pad(private.into(), 0x20)
            }
            ECCCurve::P384 => pad(private.into(), 0x30),
            ECCCurve::P521 => pad(private.into(), 0x42),

            // FIXME: error out here?
            _ => private.into(),
        }
        .into();

        Ecc {
            private,
            public,
            ecc_type,
            oid,
        }
    }
}

fn pad(mut v: Vec<u8>, len: usize) -> Vec<u8> {
    while v.len() < len {
        v.insert(0, 0)
    }

    v
}

impl EccKey for Ecc {
    fn oid(&self) -> &[u8] {
        &self.oid
    }

    fn private(&self) -> &[u8] {
        &self.private
    }

    fn public(&self) -> &[u8] {
        &self.public
    }

    fn ecc_type(&self) -> EccType {
        self.ecc_type
    }
}
