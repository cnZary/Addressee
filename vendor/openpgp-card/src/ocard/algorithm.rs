// SPDX-FileCopyrightText: 2021-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Data structures that specify algorithms to use on an OpenPGP card.
//!
//! [`AlgorithmAttributes`] (and its components) model "Algorithm Attributes"
//! as described in the OpenPGP card specification.
//!
//! [`AlgoSimple`] offers a shorthand for specifying an algorithm,
//! specifically for key generation on the card.

use std::{convert::TryFrom, fmt};

use crate::{
    Error,
    ocard::{KeyType, Transaction, crypto::EccType, keys, oid},
};

/// A shorthand way to specify algorithms (e.g. for key generation).
#[derive(Clone, Copy, Debug)]
pub enum AlgoSimple {
    RSA1k,
    RSA2k,
    RSA3k,
    RSA4k,
    NIST256,
    NIST384,
    NIST521,
    Curve25519,
}

impl TryFrom<&str> for AlgoSimple {
    type Error = Error;

    fn try_from(algo: &str) -> Result<Self, Self::Error> {
        use AlgoSimple::*;

        Ok(match algo {
            "RSA1k" => RSA1k,
            "RSA2k" => RSA2k,
            "RSA3k" => RSA3k,
            "RSA4k" => RSA4k,
            "NIST256" => NIST256,
            "NIST384" => NIST384,
            "NIST521" => NIST521,
            "Curve25519" => Curve25519,
            _ => return Err(Error::UnsupportedAlgo(format!("unexpected algo {algo}"))),
        })
    }
}

impl AlgoSimple {
    /// Get algorithm attributes for slot `key_type` from this AlgoSimple.
    ///
    /// AlgoSimple doesn't specify card specific details (such as bit-size
    /// of e for RSA, and import format).
    /// This function determines these values based on information from the
    /// card behind `tx`.
    pub fn matching_algorithm_attributes(
        &self,
        tx: &mut Transaction,
        key_type: KeyType,
    ) -> Result<AlgorithmAttributes, Error> {
        let ard = tx.application_related_data()?;
        let algorithm_attributes = ard.algorithm_attributes(key_type)?;

        let algo_info = tx.algorithm_information_cached().ok().flatten();

        self.determine_algo_attributes(key_type, algorithm_attributes, algo_info)
    }

    /// Get corresponding EccType by KeyType (except for Curve25519)
    fn ecc_type(key_type: KeyType) -> EccType {
        match key_type {
            KeyType::Signing | KeyType::Authentication | KeyType::Attestation => EccType::ECDSA,
            KeyType::Decryption => EccType::ECDH,
        }
    }

    /// Get corresponding EccType by KeyType for Curve25519
    fn ecc_type_25519(key_type: KeyType) -> EccType {
        match key_type {
            KeyType::Signing | KeyType::Authentication | KeyType::Attestation => EccType::EdDSA,
            KeyType::Decryption => EccType::ECDH,
        }
    }

    /// Get corresponding Curve by KeyType for 25519 (Ed25519 vs Cv25519)
    fn curve_for_25519(key_type: KeyType) -> Curve {
        match key_type {
            KeyType::Signing | KeyType::Authentication | KeyType::Attestation => Curve::Ed25519,
            KeyType::Decryption => Curve::Curve25519,
        }
    }

    /// Return the appropriate Algo for this AlgoSimple.
    ///
    /// This mapping depends on the actual card in use
    /// (e.g.: the size of "e", in RSA can differ;
    /// or a different `import_format` can be selected).
    ///
    /// These card-specific settings are derived from `algorithm_attributes` and `algo_info`.
    pub(crate) fn determine_algo_attributes(
        &self,
        key_type: KeyType,
        algorithm_attributes: AlgorithmAttributes,
        algo_info: Option<AlgorithmInformation>,
    ) -> Result<AlgorithmAttributes, Error> {
        let algo = match self {
            Self::RSA1k => AlgorithmAttributes::Rsa(keys::determine_rsa_attrs(
                1024,
                key_type,
                algorithm_attributes,
                algo_info,
            )?),
            Self::RSA2k => AlgorithmAttributes::Rsa(keys::determine_rsa_attrs(
                2048,
                key_type,
                algorithm_attributes,
                algo_info,
            )?),
            Self::RSA3k => AlgorithmAttributes::Rsa(keys::determine_rsa_attrs(
                3072,
                key_type,
                algorithm_attributes,
                algo_info,
            )?),
            Self::RSA4k => AlgorithmAttributes::Rsa(keys::determine_rsa_attrs(
                4096,
                key_type,
                algorithm_attributes,
                algo_info,
            )?),
            Self::NIST256 => AlgorithmAttributes::Ecc(keys::determine_ecc_attrs(
                Curve::NistP256r1.oid(),
                Self::ecc_type(key_type),
                key_type,
                algo_info,
            )?),
            Self::NIST384 => AlgorithmAttributes::Ecc(keys::determine_ecc_attrs(
                Curve::NistP384r1.oid(),
                Self::ecc_type(key_type),
                key_type,
                algo_info,
            )?),
            Self::NIST521 => AlgorithmAttributes::Ecc(keys::determine_ecc_attrs(
                Curve::NistP521r1.oid(),
                Self::ecc_type(key_type),
                key_type,
                algo_info,
            )?),
            Self::Curve25519 => AlgorithmAttributes::Ecc(keys::determine_ecc_attrs(
                Self::curve_for_25519(key_type).oid(),
                Self::ecc_type_25519(key_type),
                key_type,
                algo_info,
            )?),
        };

        Ok(algo)
    }
}

/// "Algorithm Information" enumerates which algorithms the current card supports
/// [Spec section 4.4.3.11]
///
/// Modern OpenPGP cards (starting with version v3.4) provide a list of
/// algorithms they support for each key slot.
/// The Algorithm Information list specifies which [`AlgorithmAttributes`]
/// can be used on that card (for key generation or key import).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AlgorithmInformation(pub(crate) Vec<(KeyType, AlgorithmAttributes)>);

/// Algorithm Attributes [Spec section 4.4.3.9]
///
/// [`AlgorithmAttributes`] describes the algorithm settings for a key on the card.
///
/// This setting specifies the data format of:
/// - Key import
/// - Key generation
/// - Export of public key data from the card (e.g. after key generation)
#[derive(Clone, Eq, PartialEq)]
pub enum AlgorithmAttributes {
    Rsa(RsaAttributes),
    Ecc(EccAttributes),
    Unknown(Vec<u8>),
}

impl fmt::Debug for AlgorithmAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa(rsa) => {
                write!(
                    f,
                    "RSA {} [e {}{}]",
                    rsa.len_n,
                    rsa.len_e,
                    if rsa.import_format != 0 {
                        format!(", format {}", rsa.import_format)
                    } else {
                        "".to_string()
                    }
                )
            }
            Self::Ecc(ecc) => {
                write!(
                    f,
                    "{:?} ({:?}){}",
                    ecc.ecc_type,
                    ecc.curve,
                    if ecc.import_format == Some(0xff) {
                        " with pub"
                    } else {
                        ""
                    }
                )
            }
            Self::Unknown(u) => {
                write!(f, "Unknown: {u:?}")
            }
        }
    }
}

impl fmt::Display for AlgorithmAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa(rsa) => {
                write!(f, "RSA {}", rsa.len_n)
            }
            Self::Ecc(ecc) => {
                write!(f, "{:?} ({:?})", ecc.ecc_type, ecc.curve)
            }
            Self::Unknown(u) => {
                write!(f, "Unknown: {u:?}")
            }
        }
    }
}

impl AlgorithmAttributes {
    /// Get a DO representation of the Algo, for setting algorithm
    /// attributes on the card.
    pub(crate) fn to_data_object(&self) -> Result<Vec<u8>, Error> {
        match self {
            AlgorithmAttributes::Rsa(rsa) => Self::rsa_algo_attrs(rsa),
            AlgorithmAttributes::Ecc(ecc) => Self::ecc_algo_attrs(ecc.oid(), ecc.ecc_type()),
            _ => Err(Error::UnsupportedAlgo(format!("Unexpected Algo {self:?}"))),
        }
    }

    /// Helper: generate `data` for algorithm attributes with RSA
    fn rsa_algo_attrs(algo_attrs: &RsaAttributes) -> Result<Vec<u8>, Error> {
        // Algorithm ID (01 = RSA (Encrypt or Sign))
        let mut algo_attributes = vec![0x01];

        // Length of modulus n in bit
        algo_attributes.extend(algo_attrs.len_n().to_be_bytes());

        // Length of public exponent e in bit
        algo_attributes.push(0x00);
        algo_attributes.push(algo_attrs.len_e() as u8);

        algo_attributes.push(algo_attrs.import_format());

        Ok(algo_attributes)
    }

    /// Helper: generate `data` for algorithm attributes with ECC
    fn ecc_algo_attrs(oid: &[u8], ecc_type: EccType) -> Result<Vec<u8>, Error> {
        let algo_id = match ecc_type {
            EccType::EdDSA => 0x16,
            EccType::ECDH => 0x12,
            EccType::ECDSA => 0x13,
        };

        let mut algo_attributes = vec![algo_id];
        algo_attributes.extend(oid);
        // Leave Import-Format unset, for default (pg. 35)

        Ok(algo_attributes)
    }
}

/// RSA specific attributes of [`AlgorithmAttributes`]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RsaAttributes {
    len_n: u16,
    len_e: u16,
    import_format: u8,
}

impl RsaAttributes {
    pub fn new(len_n: u16, len_e: u16, import_format: u8) -> Self {
        Self {
            len_n,
            len_e,
            import_format,
        }
    }

    pub fn len_n(&self) -> u16 {
        self.len_n
    }

    pub fn len_e(&self) -> u16 {
        self.len_e
    }

    pub fn import_format(&self) -> u8 {
        self.import_format
    }
}

/// ECC specific attributes of [`AlgorithmAttributes`]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EccAttributes {
    ecc_type: EccType,
    curve: Curve,
    import_format: Option<u8>,
}

impl EccAttributes {
    pub fn new(ecc_type: EccType, curve: Curve, import_format: Option<u8>) -> Self {
        Self {
            ecc_type,
            curve,
            import_format,
        }
    }

    pub fn ecc_type(&self) -> EccType {
        self.ecc_type
    }

    pub fn curve(&self) -> &Curve {
        &self.curve
    }

    pub fn oid(&self) -> &[u8] {
        self.curve.oid()
    }

    pub fn import_format(&self) -> Option<u8> {
        self.import_format
    }
}

/// Enum for naming ECC curves, and mapping them to/from their OIDs.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Curve {
    NistP256r1,
    NistP384r1,
    NistP521r1,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
    Secp256k1,
    Ed25519,
    Curve25519,
    Ed448,
    X448,

    Unknown(Vec<u8>),
}

impl Curve {
    pub fn oid(&self) -> &[u8] {
        use Curve::*;
        match self {
            NistP256r1 => oid::NIST_P256R1,
            NistP384r1 => oid::NIST_P384R1,
            NistP521r1 => oid::NIST_P521R1,
            BrainpoolP256r1 => oid::BRAINPOOL_P256R1,
            BrainpoolP384r1 => oid::BRAINPOOL_P384R1,
            BrainpoolP512r1 => oid::BRAINPOOL_P512R1,
            Secp256k1 => oid::SECP256K1,
            Ed25519 => oid::ED25519,
            Curve25519 => oid::CV25519,
            Ed448 => oid::ED448,
            X448 => oid::X448,

            Unknown(oid) => oid,
        }
    }
}

impl TryFrom<&[u8]> for Curve {
    type Error = Error;

    fn try_from(oid: &[u8]) -> Result<Self, Self::Error> {
        use Curve::*;

        let curve = match oid {
            oid::NIST_P256R1 => NistP256r1,
            oid::NIST_P384R1 => NistP384r1,
            oid::NIST_P521R1 => NistP521r1,

            oid::BRAINPOOL_P256R1 => BrainpoolP256r1,
            oid::BRAINPOOL_P384R1 => BrainpoolP384r1,
            oid::BRAINPOOL_P512R1 => BrainpoolP512r1,

            oid::SECP256K1 => Secp256k1,

            oid::ED25519 => Ed25519,
            oid::CV25519 => Curve25519,

            oid::ED448 => Ed448,
            oid::X448 => X448,

            _ => Unknown(oid.to_vec()),
        };

        Ok(curve)
    }
}
