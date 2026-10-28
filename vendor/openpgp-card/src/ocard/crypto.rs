// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Data structures for cryptographic material:
//! Private key data, public key data, cryptograms for decryption, hash
//! data for signing.

use crate::{
    Error,
    ocard::{
        algorithm::AlgorithmAttributes,
        data::{Fingerprint, KeyGenerationTime},
        oid,
    },
};

#[derive(Debug)]
pub enum HashAlgo {
    // FIXME: add SHA3, later
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}

impl HashAlgo {
    pub(crate) fn oid(&self) -> &[u8] {
        match self {
            Self::SHA1 => oid::SHA1,
            Self::SHA256 => oid::SHA256,
            Self::SHA384 => oid::SHA384,
            Self::SHA512 => oid::SHA512,
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::SHA1 => 0x14,
            Self::SHA256 => 0x20,
            Self::SHA384 => 0x30,
            Self::SHA512 => 0x40,
        }
    }
}

#[derive(Debug)]
pub enum SigningAlgo {
    RSA(HashAlgo),
    ECC,
}

/// Data that can be decrypted on the card.
pub enum Cryptogram<'a> {
    // message/ciphertext
    RSA(&'a [u8]),

    // ephemeral
    ECDH(&'a [u8]),
}

// ---------

/// A PGP-implementation-agnostic wrapper for private key data, to upload
/// to an OpenPGP card
pub trait CardUploadableKey {
    /// private key data
    fn private_key(&self) -> Result<PrivateKeyMaterial, Error>;

    /// timestamp of (sub)key creation
    fn timestamp(&self) -> KeyGenerationTime;

    /// fingerprint
    fn fingerprint(&self) -> Result<Fingerprint, Error>;
}

/// Algorithm-independent container for private key material to upload to
/// an OpenPGP card
pub enum PrivateKeyMaterial {
    R(Box<dyn RSAKey>),
    E(Box<dyn EccKey>),
}

/// RSA-specific container for private key material to upload to an OpenPGP
/// card.
pub trait RSAKey {
    fn e(&self) -> &[u8];
    fn p(&self) -> &[u8];
    fn q(&self) -> &[u8];

    fn pq(&self) -> &[u8];
    fn dp1(&self) -> &[u8];
    fn dq1(&self) -> &[u8];

    fn n(&self) -> &[u8];
}

/// ECC-specific container for private key material to upload to an OpenPGP
/// card.
pub trait EccKey {
    fn oid(&self) -> &[u8];
    fn private(&self) -> &[u8];
    fn public(&self) -> &[u8];
    fn ecc_type(&self) -> EccType;
}

/// Algorithm-independent container for public key material retrieved from
/// an OpenPGP card
#[derive(Debug)]
pub enum PublicKeyMaterial {
    R(RSAPub),
    E(EccPub),
}

impl std::fmt::Display for PublicKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use hex_slice::AsHex;

        match self {
            Self::R(rsa) => {
                write!(
                    f,
                    "RSA, n: {:02X}, e: {:02X}",
                    rsa.n.plain_hex(false),
                    rsa.v.plain_hex(false)
                )
            }
            Self::E(ecc) => {
                write!(
                    f,
                    "ECC [{}], data: {:02X}",
                    ecc.algo(),
                    ecc.data.plain_hex(false)
                )
            }
        }
    }
}

/// RSA-specific container for public key material from an OpenPGP card.
#[derive(Debug)]
pub struct RSAPub {
    /// Modulus (a number denoted as n coded on x bytes)
    n: Vec<u8>,

    /// Public exponent (a number denoted as v, e.g. 65537 dec.)
    v: Vec<u8>,
}

impl RSAPub {
    pub fn new(n: Vec<u8>, v: Vec<u8>) -> Self {
        Self { n, v }
    }

    pub fn n(&self) -> &[u8] {
        &self.n
    }

    pub fn v(&self) -> &[u8] {
        &self.v
    }
}

/// ECC-specific container for public key material from an OpenPGP card.
#[derive(Debug)]
pub struct EccPub {
    data: Vec<u8>,
    algo: AlgorithmAttributes,
}

impl EccPub {
    pub fn new(data: Vec<u8>, algo: AlgorithmAttributes) -> Self {
        Self { data, algo }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub fn algo(&self) -> &AlgorithmAttributes {
        &self.algo
    }
}

/// A marker to distinguish between elliptic curve algorithms (ECDH, ECDSA,
/// EdDSA)
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum EccType {
    ECDH,
    ECDSA,
    EdDSA,
}
