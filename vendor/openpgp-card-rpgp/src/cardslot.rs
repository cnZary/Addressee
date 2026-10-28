// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
    fmt::{Debug, Formatter},
    sync::Mutex,
};

use openpgp_card::{
    Card,
    ocard::{
        KeyType,
        crypto::{HashAlgo, SigningAlgo},
    },
    state::Transaction,
};
use pgp::{
    composed::{Esk, Message, PlainSessionKey},
    crypto::{
        checksum,
        ecc_curve::ECCCurve,
        hash::HashAlgorithm,
        public_key::PublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::{PublicKey, Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData},
    types::{
        DecryptionKey,
        EcdhPublicParams,
        EcdsaPublicParams,
        EskType,
        Fingerprint,
        KeyDetails,
        KeyId,
        KeyVersion,
        Mpi,
        Password,
        PkeskBytes,
        PublicParams,
        SignatureBytes,
        SigningKey,
        Timestamp,
    },
};
use rand::thread_rng;
use rsa::traits::PublicKeyParts;
use secrecy::zeroize::Zeroizing;

use crate::Error;

/// An individual OpenPGP card key slot, which can be used for private key operations.
pub struct CardSlot<'cs, 't> {
    tx: Mutex<&'cs mut Card<Transaction<'t>>>,

    // Which key slot does this OpenPGP card operate on
    key_type: KeyType,

    // The public key material that corresponds to the key slot of this signer
    //
    // The distinction between primary and subkey is irrelevant here, but we have to use some type.
    // So we model the key data as a public primary key packet.
    public_key: PublicKey,

    touch_prompt: &'cs (dyn Fn() + Send + Sync),
}

impl<'cs, 't> CardSlot<'cs, 't> {
    /// Set up a CardSlot for the card behind `tx`, using the key slot for `key_type`.
    ///
    /// Initializes the CardSlot based on public key information obtained from `public_key`.
    pub fn with_public_key(
        tx: &'cs mut Card<Transaction<'t>>,
        key_type: KeyType,
        public_key: PublicKey,
        touch_prompt: &'cs (dyn Fn() + Send + Sync),
    ) -> Result<Self, crate::Error> {
        // FIXME: compare the fingerprint between card slot and public_key?

        Ok(Self {
            tx: Mutex::new(tx),
            public_key,
            key_type,
            touch_prompt,
        })
    }

    /// Set up a CardSlot for the card behind `tx`, using the key slot for `key_type`.
    ///
    /// Initializes the CardSlot based on public key information obtained from the card.
    pub fn init_from_card(
        tx: &'cs mut Card<Transaction<'t>>,
        key_type: KeyType,
        touch_prompt: &'cs (dyn Fn() + Send + Sync),
    ) -> Result<Self, crate::Error> {
        let pk = crate::rpgp::pubkey_from_card(tx, key_type)?;

        Self::with_public_key(tx, key_type, pk, touch_prompt)
    }
}

impl CardSlot<'_, '_> {
    /// The OpenPGP public key material that corresponds to the key in this CardSlot
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The card slot that this CardSlot uses
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    fn touch_required(&self, tx: &mut Card<Transaction<'_>>) -> bool {
        // Touch is required if:
        // - the card supports the feature
        // - and the policy is set to a value other than 'Off'
        if let Ok(Some(uif)) = tx.user_interaction_flag(self.key_type) {
            uif.touch_policy().touch_required()
        } else {
            false
        }
    }

    /// Try to unwrap an encryption layer by decrypting one of the PKESK in message
    pub fn decrypt_message<'a>(&self, message: Message<'a>) -> Result<Message<'a>, Error> {
        let Message::Encrypted { esk, mut edata, .. } = message else {
            return Err(Error::Message(
                "message must be Message::Encrypted".to_string(),
            ));
        };

        // try to decrypt all pkesk
        let mut sk = None;

        for e in &esk {
            if let Esk::PublicKeyEncryptedSessionKey(pkesk) = e
                && let Ok(v) = pkesk.values()
            {
                // FIXME: match id?
                if let Ok(psk) = self
                    .decrypt(&Password::empty(), v, EskType::V3_4)
                    .map_err(|e| Error::Message(e.to_string()))?
                {
                    sk = Some(psk);
                    break;
                }
            }
        }

        match sk {
            Some(plain_session_key) => {
                edata.decrypt(&plain_session_key)?;

                Ok(Message::from_bytes(edata)?)
            }
            None => Err(Error::Message(
                "Failed to decrypt any PublicKeyEncryptedSessionKey".to_string(),
            )),
        }
    }

    pub fn sign_data(
        &self,
        data: &[u8],
        text_mode: bool,
        key_pw: &Password,
        hash_algorithm: HashAlgorithm,
    ) -> Result<Signature, Error> {
        // FIXME: is there an API for this upstream?

        let algorithm = self.algorithm();

        let rng = thread_rng();

        let typ = if text_mode {
            SignatureType::Text
        } else {
            SignatureType::Binary
        };

        let mut config = match self.version() {
            KeyVersion::V4 => SignatureConfig::v4(typ, algorithm, hash_algorithm),
            KeyVersion::V6 => SignatureConfig::v6(rng, typ, algorithm, hash_algorithm)?,
            v => return Err(Error::Message(format!("Unsupported key version {v:?}"))),
        };
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(self.fingerprint()))?,
            Subpacket::critical(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
        ];
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            self.legacy_key_id(),
        ))?];

        let signature = config.sign(self, key_pw, data)?;

        Ok(signature)
    }
}

impl DecryptionKey for CardSlot<'_, '_> {
    fn decrypt(
        &self,
        _password: &Password,
        values: &PkeskBytes,
        _esktype: EskType,
    ) -> Result<Result<PlainSessionKey, pgp::errors::Error>, pgp::errors::Error> {
        #[allow(clippy::unwrap_used)]
        let mut tx = self.tx.lock().unwrap();

        let mut ecdh = |public_point: &[u8],
                        encrypted_session_key: &[u8],
                        hash: HashAlgorithm,
                        alg_sym: SymmetricKeyAlgorithm,
                        curve|
         -> Result<Zeroizing<Vec<u8>>, pgp::errors::Error> {
            let ciphertext = match curve {
                ECCCurve::Curve25519Legacy => &public_point[1..],
                _ => public_point,
            };

            let cryptogram = openpgp_card::ocard::crypto::Cryptogram::ECDH(ciphertext);

            if self.touch_required(&mut tx) {
                (self.touch_prompt)();
            }

            let shared_secret: Vec<u8> = tx.card().decipher(cryptogram).map_err(|e| {
                Error::Message(format!("ECDH decipher operation on card failed {e}"))
            })?;

            let encrypted_key_len = encrypted_session_key.len();

            let decrypted_key = pgp::crypto::ecdh::derive_session_key(
                &shared_secret,
                encrypted_session_key,
                encrypted_key_len,
                curve,
                hash,
                alg_sym,
                self.public_key.fingerprint().as_bytes(),
            )?;

            Ok(decrypted_key)
        };

        let decrypted_key = match (self.public_key.public_params(), values) {
            (PublicParams::RSA(public), PkeskBytes::Rsa { mpi }) => {
                let mut ciphertext = mpi.as_ref().to_vec();

                // RSA modulus length. We use this length to pad the ciphertext, in case it was
                // zero truncated.
                //
                // FIXME: There might be a problematic corner case when the modulus itself is
                // zero-stripped, and as a consequence we don't pad enough?
                // (We might want to use rounding to "round" to a typical RSA modulus size?)
                let modulus_len = public.key.n().to_bytes_be().len();

                // Left zero-pad `ciphertext` to the length of the RSA modulus
                // (that is: if the ciphertext was zero-stripped, undo that stripping).
                //
                // This padding is not required in most cases. Typically, the ciphertext and
                // modulus should be the same length. However, there is a 1:256 likelihood that
                // the ciphertext happens to start with a 0x0 byte, which OpenPGP will truncate.
                while modulus_len > ciphertext.len() {
                    ciphertext.insert(0, 0u8);
                }

                let cryptogram = openpgp_card::ocard::crypto::Cryptogram::RSA(&ciphertext);

                if self.touch_required(&mut tx) {
                    (self.touch_prompt)();
                }

                tx.card()
                    .decipher(cryptogram)
                    .map_err(|e| {
                        Error::Message(format!("RSA decipher operation on card failed: {e}"))
                    })?
                    .into()
            }

            (
                PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy {
                    p: _p,
                    alg_sym,
                    hash,
                    ..
                }),
                PkeskBytes::Ecdh {
                    public_point,
                    encrypted_session_key,
                },
            ) => ecdh(
                public_point.as_ref(),
                encrypted_session_key,
                *hash,
                *alg_sym,
                ECCCurve::Curve25519Legacy.clone(),
            )?,

            (
                PublicParams::ECDH(EcdhPublicParams::P256 {
                    p: _p,
                    alg_sym,
                    hash,
                    ..
                }),
                PkeskBytes::Ecdh {
                    public_point,
                    encrypted_session_key,
                },
            ) => ecdh(
                public_point.as_ref(),
                encrypted_session_key,
                *hash,
                *alg_sym,
                ECCCurve::P256.clone(),
            )?,

            (
                PublicParams::ECDH(EcdhPublicParams::P384 {
                    p: _p,
                    alg_sym,
                    hash,
                    ..
                }),
                PkeskBytes::Ecdh {
                    public_point,
                    encrypted_session_key,
                },
            ) => ecdh(
                public_point.as_ref(),
                encrypted_session_key,
                *hash,
                *alg_sym,
                ECCCurve::P384.clone(),
            )?,

            (
                PublicParams::ECDH(EcdhPublicParams::P521 {
                    p: _p,
                    alg_sym,
                    hash,
                    ..
                }),
                PkeskBytes::Ecdh {
                    public_point,
                    encrypted_session_key,
                },
            ) => ecdh(
                public_point.as_ref(),
                encrypted_session_key,
                *hash,
                *alg_sym,
                ECCCurve::P521.clone(),
            )?,

            pp => {
                return Err(format!("decrypt: Unsupported key type  {pp:?}").into());
            }
        };

        // strip off the leading session key algorithm octet, and the two trailing checksum octets
        let dec_len = decrypted_key.len();
        let (sessionkey, checksum) = (
            &decrypted_key[1..dec_len - 2],
            &decrypted_key[dec_len - 2..],
        );

        // ... check the checksum, while we have it at hand
        checksum::simple(
            #[allow(clippy::expect_used)]
            checksum.try_into().expect("this is two bytes long"),
            sessionkey,
        )
        .map_err(|_| Error::Message("checksum mismatch while decrypting".to_string()))?;

        let session_key_algorithm = decrypted_key[0].into();
        Ok(Ok(PlainSessionKey::V3_4 {
            key: sessionkey.into(),
            sym_alg: session_key_algorithm,
        }))
    }
}

impl Debug for CardSlot<'_, '_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // FIXME: also show card identifier
        write!(f, "CardSlot for {:?}", self.public_key)?;

        Ok(())
    }
}

impl KeyDetails for CardSlot<'_, '_> {
    fn version(&self) -> KeyVersion {
        KeyVersion::V4 // FIXME?
    }

    fn fingerprint(&self) -> Fingerprint {
        self.public_key.fingerprint()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.public_key.legacy_key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.public_key.algorithm()
    }

    fn created_at(&self) -> Timestamp {
        self.public_key.created_at()
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        None
    }

    fn public_params(&self) -> &PublicParams {
        self.public_key.public_params()
    }
}

impl SigningKey for CardSlot<'_, '_> {
    fn sign(
        &self,
        _key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<SignatureBytes> {
        #[allow(clippy::unwrap_used)]
        let mut tx = self.tx.lock().unwrap();

        let (sign_algo, digest) = match self.public_key.algorithm() {
            PublicKeyAlgorithm::RSA => {
                let h = match hash {
                    HashAlgorithm::Sha1 => HashAlgo::SHA1,
                    HashAlgorithm::Sha256 => HashAlgo::SHA256,
                    HashAlgorithm::Sha384 => HashAlgo::SHA384,
                    HashAlgorithm::Sha512 => HashAlgo::SHA512,
                    _ => {
                        return Err(
                            Error::Message(format!("Unsupported hash algorithm {hash:?}")).into(),
                        );
                    }
                };

                (SigningAlgo::RSA(h), data)
            }

            // ECDSA: Based on curve size, check for minimum digest len, and shorten to max len
            PublicKeyAlgorithm::ECDSA => match self.public_key.public_params() {
                PublicParams::ECDSA(EcdsaPublicParams::P256 { .. }) => {
                    if data.len() < 32 {
                        return Err(Error::Message("hash too short for P256".to_string()).into());
                    }

                    (SigningAlgo::ECC, &data[..32])
                }
                PublicParams::ECDSA(EcdsaPublicParams::P384 { .. }) => {
                    if data.len() < 48 {
                        return Err(Error::Message("hash too short for P384".to_string()).into());
                    }

                    (SigningAlgo::ECC, &data[..48])
                }
                PublicParams::ECDSA(EcdsaPublicParams::P521 { .. }) => {
                    if data.len() < 64 {
                        return Err(Error::Message("hash too short for P521".to_string()).into());
                    }

                    (SigningAlgo::ECC, &data[..64])
                }
                _ => (SigningAlgo::ECC, data),
            },

            PublicKeyAlgorithm::EdDSALegacy => (SigningAlgo::ECC, data),

            _ => {
                return Err(Error::Message(format!(
                    "Unsupported PublicKeyAlgorithm for signature creation: {:?}",
                    self.public_key.algorithm()
                ))
                .into());
            }
        };

        if self.touch_required(&mut tx) {
            (self.touch_prompt)();
        }

        let sig = match self.key_type {
            KeyType::Signing => tx
                .card()
                .signature_for_hash(sign_algo, digest)
                .map_err(|e| Error::Message(format!("openpgp-card error: {e:?}")))?,
            KeyType::Authentication => tx
                .card()
                .authenticate_for_hash(sign_algo, digest)
                .map_err(|e| Error::Message(format!("openpgp-card error: {e:?}")))?,
            _ => {
                return Err(Error::Message(format!(
                    "Unsupported KeyType for signature creation: {:?}",
                    self.key_type
                ))
                .into());
            }
        };

        let mpis = match self.public_key.algorithm() {
            PublicKeyAlgorithm::RSA => vec![Mpi::from_slice(&sig)],

            PublicKeyAlgorithm::ECDSA => {
                let mid = sig.len() / 2;

                vec![Mpi::from_slice(&sig[..mid]), Mpi::from_slice(&sig[mid..])]
            }
            PublicKeyAlgorithm::EdDSALegacy => {
                // FIXME: check curve?
                if sig.len() != 64 {
                    return Err(Error::Message(format!(
                        "Unexpected signature length {} for EdDSA",
                        sig.len()
                    ))
                    .into());
                }

                vec![Mpi::from_slice(&sig[..32]), Mpi::from_slice(&sig[32..])]
            }

            alg => {
                return Err(Error::Message(format!(
                    "Unsupported algorithm for signature creation: {alg:?}"
                ))
                .into());
            }
        };

        Ok(SignatureBytes::Mpis(mpis))
    }

    fn hash_alg(&self) -> HashAlgorithm {
        self.public_key.public_params().hash_alg()
    }
}
