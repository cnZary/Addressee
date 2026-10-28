// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! 4.4.3.9 Algorithm Attributes

use std::convert::TryFrom;

use nom::{
    branch,
    branch::alt,
    bytes::{complete as bytes, complete::tag},
    combinator::map,
    number::complete as number,
};

use crate::ocard::{
    algorithm::{AlgorithmAttributes, Curve, EccAttributes, RsaAttributes},
    crypto::EccType,
    data::complete,
};

fn parse_oid_cv25519(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::Curve25519.oid()), |_| Curve::Curve25519)(input)
}

fn parse_oid_ed25519(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::Ed25519.oid()), |_| Curve::Ed25519)(input)
}

fn parse_oid_secp256k1(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::Secp256k1.oid()), |_| Curve::Secp256k1)(input)
}

fn parse_oid_nist256(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::NistP256r1.oid()), |_| Curve::NistP256r1)(input)
}

fn parse_oid_nist384(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::NistP384r1.oid()), |_| Curve::NistP384r1)(input)
}

fn parse_oid_nist521(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::NistP521r1.oid()), |_| Curve::NistP521r1)(input)
}

fn parse_oid_brainpool_p256r1(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::BrainpoolP256r1.oid()), |_| {
        Curve::BrainpoolP256r1
    })(input)
}

fn parse_oid_brainpool_p384r1(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::BrainpoolP384r1.oid()), |_| {
        Curve::BrainpoolP384r1
    })(input)
}

fn parse_oid_brainpool_p512r1(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::BrainpoolP512r1.oid()), |_| {
        Curve::BrainpoolP512r1
    })(input)
}

fn parse_oid_ed448(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::Ed448.oid()), |_| Curve::Ed448)(input)
}

fn parse_oid_x448(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::X448.oid()), |_| Curve::X448)(input)
}

fn parse_oid(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    alt((
        parse_oid_nist256,
        parse_oid_nist384,
        parse_oid_nist521,
        parse_oid_brainpool_p256r1,
        parse_oid_brainpool_p384r1,
        parse_oid_brainpool_p512r1,
        parse_oid_secp256k1,
        parse_oid_ed25519,
        parse_oid_cv25519,
        parse_oid_ed448,
        parse_oid_x448,
    ))(input)
}

fn parse_rsa(input: &[u8]) -> nom::IResult<&[u8], AlgorithmAttributes> {
    let (input, _) = bytes::tag([0x01])(input)?;

    let (input, len_n) = number::be_u16(input)?;
    let (input, len_e) = number::be_u16(input)?;
    let (input, import_format) = number::u8(input)?;

    Ok((
        input,
        AlgorithmAttributes::Rsa(RsaAttributes::new(len_n, len_e, import_format)),
    ))
}

fn parse_import_format(input: &[u8]) -> nom::IResult<&[u8], Option<u8>> {
    let (input, b) = bytes::take(1usize)(input)?;
    Ok((input, Some(b[0])))
}

fn default_import_format(input: &[u8]) -> nom::IResult<&[u8], Option<u8>> {
    Ok((input, None))
}

fn parse_ecdh(input: &[u8]) -> nom::IResult<&[u8], AlgorithmAttributes> {
    let (input, _) = bytes::tag([0x12])(input)?;
    let (input, curve) = parse_oid(input)?;

    let (input, import_format) = alt((parse_import_format, default_import_format))(input)?;

    Ok((
        input,
        AlgorithmAttributes::Ecc(EccAttributes::new(EccType::ECDH, curve, import_format)),
    ))
}

fn parse_ecdsa(input: &[u8]) -> nom::IResult<&[u8], AlgorithmAttributes> {
    let (input, _) = bytes::tag([0x13])(input)?;
    let (input, curve) = parse_oid(input)?;

    let (input, import_format) = alt((parse_import_format, default_import_format))(input)?;

    Ok((
        input,
        AlgorithmAttributes::Ecc(EccAttributes::new(EccType::ECDSA, curve, import_format)),
    ))
}

fn parse_eddsa(input: &[u8]) -> nom::IResult<&[u8], AlgorithmAttributes> {
    let (input, _) = bytes::tag([0x16])(input)?;
    let (input, curve) = parse_oid(input)?;

    let (input, import_format) = alt((parse_import_format, default_import_format))(input)?;

    Ok((
        input,
        AlgorithmAttributes::Ecc(EccAttributes::new(EccType::EdDSA, curve, import_format)),
    ))
}

pub(crate) fn parse(input: &[u8]) -> nom::IResult<&[u8], AlgorithmAttributes> {
    branch::alt((parse_rsa, parse_ecdsa, parse_eddsa, parse_ecdh))(input)
}

impl TryFrom<&[u8]> for AlgorithmAttributes {
    type Error = crate::Error;

    fn try_from(data: &[u8]) -> Result<Self, crate::Error> {
        complete(parse(data))
    }
}

// Tests in algo_info cover this module
