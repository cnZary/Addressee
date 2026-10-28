// SPDX-FileCopyrightText: 2021-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::ocard::tlv::tag::Tag;

/// Tags, as specified and used in the OpenPGP card 3.4.1 spec.
/// All tags in OpenPGP card are either 1 or 2 bytes long.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum Tags {
    // BER identifiers
    OctetString,
    Null,
    ObjectIdentifier,
    Sequence,

    // GET DATA
    PrivateUse1,
    PrivateUse2,
    PrivateUse3,
    PrivateUse4,
    ApplicationIdentifier,
    LoginData,
    Url,
    HistoricalBytes,
    CardholderRelatedData,
    Name,
    LanguagePref,
    Sex,
    ApplicationRelatedData,
    ExtendedLengthInformation,
    GeneralFeatureManagement,
    DiscretionaryDataObjects,
    ExtendedCapabilities,
    AlgorithmAttributesSignature,
    AlgorithmAttributesDecryption,
    AlgorithmAttributesAuthentication,
    PWStatusBytes,
    Fingerprints,
    CaFingerprints,
    GenerationTimes,
    KeyInformation,
    UifSig,
    UifDec,
    UifAuth,
    UifAttestation,
    SecuritySupportTemplate,
    DigitalSignatureCounter,
    CardholderCertificate,
    AlgorithmAttributesAttestation,
    FingerprintAttestation,
    CaFingerprintAttestation,
    GenerationTimeAttestation,
    KdfDo,
    AlgorithmInformation,
    CertificateSecureMessaging,
    AttestationCertificate,

    // PUT DATA (additional Tags that don't get used for GET DATA)
    FingerprintSignature,
    FingerprintDecryption,
    FingerprintAuthentication,
    CaFingerprint1,
    CaFingerprint2,
    CaFingerprint3,
    GenerationTimeSignature,
    GenerationTimeDecryption,
    GenerationTimeAuthentication,
    // FIXME: +D1, D2
    ResettingCode,
    PsoEncDecKey,

    // OTHER
    // 4.4.3.12 Private Key Template
    ExtendedHeaderList,
    CardholderPrivateKeyTemplate,
    ConcatenatedKeyData,
    CrtKeySignature,
    CrtKeyConfidentiality,
    CrtKeyAuthentication,
    PrivateKeyDataRsaPublicExponent,
    PrivateKeyDataRsaPrime1,
    PrivateKeyDataRsaPrime2,
    PrivateKeyDataRsaPq,
    PrivateKeyDataRsaDp1,
    PrivateKeyDataRsaDq1,
    PrivateKeyDataRsaModulus,
    PrivateKeyDataEccPrivateKey,
    PrivateKeyDataEccPublicKey,

    // 7.2.14 GENERATE ASYMMETRIC KEY PAIR
    PublicKey,
    PublicKeyDataRsaModulus,
    PublicKeyDataRsaExponent,
    PublicKeyDataEccPoint,

    // 7.2.11 PSO: DECIPHER
    Cipher,
    ExternalPublicKey,

    // 7.2.5 SELECT DATA
    GeneralReference,
    TagList,
}

impl From<Tags> for Vec<u8> {
    fn from(t: Tags) -> Self {
        ShortTag::from(t).into()
    }
}

impl From<Tags> for Tag {
    fn from(t: Tags) -> Self {
        ShortTag::from(t).into()
    }
}

impl From<Tags> for ShortTag {
    fn from(t: Tags) -> Self {
        match t {
            // BER identifiers https://en.wikipedia.org/wiki/X.690#BER_encoding
            Tags::OctetString => [0x04].into(),
            Tags::Null => [0x05].into(),
            Tags::ObjectIdentifier => [0x06].into(),
            Tags::Sequence => [0x30].into(),

            // GET DATA
            Tags::PrivateUse1 => [0x01, 0x01].into(),
            Tags::PrivateUse2 => [0x01, 0x02].into(),
            Tags::PrivateUse3 => [0x01, 0x03].into(),
            Tags::PrivateUse4 => [0x01, 0x04].into(),
            Tags::ApplicationIdentifier => [0x4f].into(),
            Tags::LoginData => [0x5e].into(),
            Tags::Url => [0x5f, 0x50].into(),
            Tags::HistoricalBytes => [0x5f, 0x52].into(),
            Tags::CardholderRelatedData => [0x65].into(),
            Tags::Name => [0x5b].into(),
            Tags::LanguagePref => [0x5f, 0x2d].into(),
            Tags::Sex => [0x5f, 0x35].into(),
            Tags::ApplicationRelatedData => [0x6e].into(),
            Tags::ExtendedLengthInformation => [0x7f, 0x66].into(),
            Tags::GeneralFeatureManagement => [0x7f, 0x74].into(),
            Tags::DiscretionaryDataObjects => [0x73].into(),
            Tags::ExtendedCapabilities => [0xc0].into(),
            Tags::AlgorithmAttributesSignature => [0xc1].into(),
            Tags::AlgorithmAttributesDecryption => [0xc2].into(),
            Tags::AlgorithmAttributesAuthentication => [0xc3].into(),
            Tags::PWStatusBytes => [0xc4].into(),
            Tags::Fingerprints => [0xc5].into(),
            Tags::CaFingerprints => [0xc6].into(),
            Tags::GenerationTimes => [0xcd].into(),
            Tags::KeyInformation => [0xde].into(),
            Tags::UifSig => [0xd6].into(),
            Tags::UifDec => [0xd7].into(),
            Tags::UifAuth => [0xd8].into(),
            Tags::UifAttestation => [0xd9].into(),
            Tags::SecuritySupportTemplate => [0x7a].into(),
            Tags::DigitalSignatureCounter => [0x93].into(),
            Tags::CardholderCertificate => [0x7f, 0x21].into(),
            Tags::AlgorithmAttributesAttestation => [0xda].into(),
            Tags::FingerprintAttestation => [0xdb].into(),
            Tags::CaFingerprintAttestation => [0xdc].into(),
            Tags::GenerationTimeAttestation => [0xdd].into(),
            Tags::KdfDo => [0xf9].into(),
            Tags::AlgorithmInformation => [0xfa].into(),
            Tags::CertificateSecureMessaging => [0xfb].into(),
            Tags::AttestationCertificate => [0xfc].into(),

            // PUT DATA
            Tags::FingerprintSignature => [0xc7].into(),
            Tags::FingerprintDecryption => [0xc8].into(),
            Tags::FingerprintAuthentication => [0xc9].into(),
            Tags::CaFingerprint1 => [0xca].into(),
            Tags::CaFingerprint2 => [0xcb].into(),
            Tags::CaFingerprint3 => [0xcc].into(),
            Tags::GenerationTimeSignature => [0xce].into(),
            Tags::GenerationTimeDecryption => [0xcf].into(),
            Tags::GenerationTimeAuthentication => [0xd0].into(),
            Tags::ResettingCode => [0xd3].into(),
            Tags::PsoEncDecKey => [0xd5].into(),

            // OTHER
            // 4.4.3.12 Private Key Template
            Tags::ExtendedHeaderList => [0x4d].into(),
            Tags::CardholderPrivateKeyTemplate => [0x7f, 0x48].into(),
            Tags::ConcatenatedKeyData => [0x5f, 0x48].into(),
            Tags::CrtKeySignature => [0xb6].into(),
            Tags::CrtKeyConfidentiality => [0xb8].into(),
            Tags::CrtKeyAuthentication => [0xa4].into(),
            Tags::PrivateKeyDataRsaPublicExponent => [0x91].into(),
            Tags::PrivateKeyDataRsaPrime1 => [0x92].into(), // Note: value reused!
            Tags::PrivateKeyDataRsaPrime2 => [0x93].into(),
            Tags::PrivateKeyDataRsaPq => [0x94].into(),
            Tags::PrivateKeyDataRsaDp1 => [0x95].into(),
            Tags::PrivateKeyDataRsaDq1 => [0x96].into(),
            Tags::PrivateKeyDataRsaModulus => [0x97].into(),
            Tags::PrivateKeyDataEccPrivateKey => [0x92].into(), // Note: value reused!
            Tags::PrivateKeyDataEccPublicKey => [0x99].into(),

            // 7.2.14 GENERATE ASYMMETRIC KEY PAIR
            Tags::PublicKey => [0x7f, 0x49].into(),
            Tags::PublicKeyDataRsaModulus => [0x81].into(),
            Tags::PublicKeyDataRsaExponent => [0x82].into(),
            Tags::PublicKeyDataEccPoint => [0x86].into(),

            // 7.2.11 PSO: DECIPHER
            Tags::Cipher => [0xa6].into(),
            Tags::ExternalPublicKey => [0x86].into(),

            // 7.2.5 SELECT DATA
            Tags::GeneralReference => [0x60].into(),
            Tags::TagList => [0x5c].into(),
        }
    }
}

/// A ShortTag is a Tlv tag that is guaranteed to be either 1 or 2 bytes long.
///
/// This covers any tag that can be used in the OpenPGP card context (the spec doesn't describe how
/// longer tags might be used.)
///
/// (The type tlv::Tag will usually/always contain 1 or 2 byte long tags, in this library.
/// But its length is not guaranteed by the type system)
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ShortTag {
    One(u8),
    Two(u8, u8),
}

impl From<ShortTag> for Tag {
    fn from(n: ShortTag) -> Self {
        match n {
            ShortTag::One(t0) => [t0].into(),
            ShortTag::Two(t0, t1) => [t0, t1].into(),
        }
    }
}

impl From<[u8; 1]> for ShortTag {
    fn from(v: [u8; 1]) -> Self {
        ShortTag::One(v[0])
    }
}

impl From<[u8; 2]> for ShortTag {
    fn from(v: [u8; 2]) -> Self {
        ShortTag::Two(v[0], v[1])
    }
}

impl From<ShortTag> for Vec<u8> {
    fn from(t: ShortTag) -> Self {
        match t {
            ShortTag::One(t0) => vec![t0],
            ShortTag::Two(t0, t1) => vec![t0, t1],
        }
    }
}
