// SPDX-FileCopyrightText: 2021-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Algorithm Information [Spec section 4.4.3.11]

use std::{convert::TryFrom, fmt};

use nom::{
    branch, branch::alt, bytes::complete as bytes, combinator, combinator::map, multi, sequence,
};

use crate::ocard::{
    algorithm::{AlgorithmAttributes, AlgorithmInformation},
    data::{algo_attrs, complete},
    tlv, KeyType,
};

impl AlgorithmInformation {
    pub fn for_keytype(&self, kt: KeyType) -> Vec<&AlgorithmAttributes> {
        self.0
            .iter()
            .filter(|(k, _)| *k == kt)
            .map(|(_, a)| a)
            .collect()
    }
}

impl fmt::Display for AlgorithmInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (kt, a) in &self.0 {
            let kt = match kt {
                KeyType::Signing => "SIG",
                KeyType::Decryption => "DEC",
                KeyType::Authentication => "AUT",
                KeyType::Attestation => "ATT",
            };
            writeln!(f, "{kt}: {a:?} ")?;
        }
        Ok(())
    }
}

fn key_type(input: &[u8]) -> nom::IResult<&[u8], KeyType> {
    alt((
        map(bytes::tag([0xc1]), |_| KeyType::Signing),
        map(bytes::tag([0xc2]), |_| KeyType::Decryption),
        map(bytes::tag([0xc3]), |_| KeyType::Authentication),
        map(bytes::tag([0xda]), |_| KeyType::Attestation),
    ))(input)
}

fn unknown(input: &[u8]) -> nom::IResult<&[u8], AlgorithmAttributes> {
    Ok((&[], AlgorithmAttributes::Unknown(input.to_vec())))
}

fn parse_one(input: &[u8]) -> nom::IResult<&[u8], AlgorithmAttributes> {
    let (input, a) = combinator::map(
        combinator::flat_map(tlv::length::length, bytes::take),
        |i| alt((combinator::all_consuming(algo_attrs::parse), unknown))(i),
    )(input)?;

    Ok((input, a?.1))
}

fn parse_list(input: &[u8]) -> nom::IResult<&[u8], Vec<(KeyType, AlgorithmAttributes)>> {
    multi::many0(sequence::pair(key_type, parse_one))(input)
}

fn parse_tl_list(input: &[u8]) -> nom::IResult<&[u8], Vec<(KeyType, AlgorithmAttributes)>> {
    let (input, (_, _, list)) =
        sequence::tuple((bytes::tag([0xfa]), tlv::length::length, parse_list))(input)?;

    Ok((input, list))
}

fn parse(input: &[u8]) -> nom::IResult<&[u8], Vec<(KeyType, AlgorithmAttributes)>> {
    // Handle two variations of input format:
    // a) TLV format (e.g. YubiKey 5)
    // b) Plain list (e.g. Gnuk, FOSS-Store Smartcard 3.4)

    // -- Gnuk: do_alg_info (uint16_t tag, int with_tag)

    branch::alt((
        combinator::all_consuming(parse_list),
        combinator::all_consuming(parse_tl_list),
    ))(input)
}

impl TryFrom<&[u8]> for AlgorithmInformation {
    type Error = crate::Error;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        Ok(AlgorithmInformation(complete(parse(input))?))
    }
}

// test

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use crate::ocard::{
        algorithm::{
            AlgorithmAttributes::*, AlgorithmInformation, Curve::*, EccAttributes, RsaAttributes,
        },
        crypto::EccType::*,
        KeyType::*,
    };

    #[test]
    fn test_gnuk() {
        let data = [
            0xc1, 0x6, 0x1, 0x8, 0x0, 0x0, 0x20, 0x0, 0xc1, 0x6, 0x1, 0x10, 0x0, 0x0, 0x20, 0x0,
            0xc1, 0x9, 0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0xc1, 0x6, 0x13, 0x2b,
            0x81, 0x4, 0x0, 0xa, 0xc1, 0xa, 0x16, 0x2b, 0x6, 0x1, 0x4, 0x1, 0xda, 0x47, 0xf, 0x1,
            0xc2, 0x6, 0x1, 0x8, 0x0, 0x0, 0x20, 0x0, 0xc2, 0x6, 0x1, 0x10, 0x0, 0x0, 0x20, 0x0,
            0xc2, 0x9, 0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0xc2, 0x6, 0x13, 0x2b,
            0x81, 0x4, 0x0, 0xa, 0xc2, 0xb, 0x12, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x97, 0x55, 0x1, 0x5,
            0x1, 0xc3, 0x6, 0x1, 0x8, 0x0, 0x0, 0x20, 0x0, 0xc3, 0x6, 0x1, 0x10, 0x0, 0x0, 0x20,
            0x0, 0xc3, 0x9, 0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0xc3, 0x6, 0x13,
            0x2b, 0x81, 0x4, 0x0, 0xa, 0xc3, 0xa, 0x16, 0x2b, 0x6, 0x1, 0x4, 0x1, 0xda, 0x47, 0xf,
            0x1,
        ];

        let ai = AlgorithmInformation::try_from(&data[..]).unwrap();

        assert_eq!(
            ai,
            AlgorithmInformation(vec![
                (Signing, Rsa(RsaAttributes::new(2048, 32, 0))),
                (Signing, Rsa(RsaAttributes::new(4096, 32, 0))),
                (Signing, Ecc(EccAttributes::new(ECDSA, NistP256r1, None))),
                (Signing, Ecc(EccAttributes::new(ECDSA, Secp256k1, None))),
                (Signing, Ecc(EccAttributes::new(EdDSA, Ed25519, None))),
                (Decryption, Rsa(RsaAttributes::new(2048, 32, 0))),
                (Decryption, Rsa(RsaAttributes::new(4096, 32, 0))),
                (Decryption, Ecc(EccAttributes::new(ECDSA, NistP256r1, None))),
                (Decryption, Ecc(EccAttributes::new(ECDSA, Secp256k1, None))),
                (Decryption, Ecc(EccAttributes::new(ECDH, Curve25519, None))),
                (Authentication, Rsa(RsaAttributes::new(2048, 32, 0))),
                (Authentication, Rsa(RsaAttributes::new(4096, 32, 0))),
                (
                    Authentication,
                    Ecc(EccAttributes::new(ECDSA, NistP256r1, None))
                ),
                (
                    Authentication,
                    Ecc(EccAttributes::new(ECDSA, Secp256k1, None))
                ),
                (
                    Authentication,
                    Ecc(EccAttributes::new(EdDSA, Ed25519, None))
                )
            ])
        );
    }

    #[test]
    fn test_opgp_card_34() {
        let data = [
            0xc1, 0x6, 0x1, 0x8, 0x0, 0x0, 0x20, 0x0, 0xc1, 0x6, 0x1, 0xc, 0x0, 0x0, 0x20, 0x0,
            0xc1, 0x6, 0x1, 0x10, 0x0, 0x0, 0x20, 0x0, 0xc1, 0x9, 0x13, 0x2a, 0x86, 0x48, 0xce,
            0x3d, 0x3, 0x1, 0x7, 0xc1, 0x6, 0x13, 0x2b, 0x81, 0x4, 0x0, 0x22, 0xc1, 0x6, 0x13,
            0x2b, 0x81, 0x4, 0x0, 0x23, 0xc1, 0xa, 0x13, 0x2b, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1,
            0x7, 0xc1, 0xa, 0x13, 0x2b, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0xb, 0xc1, 0xa, 0x13,
            0x2b, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0xd, 0xc2, 0x6, 0x1, 0x8, 0x0, 0x0, 0x20,
            0x0, 0xc2, 0x6, 0x1, 0xc, 0x0, 0x0, 0x20, 0x0, 0xc2, 0x6, 0x1, 0x10, 0x0, 0x0, 0x20,
            0x0, 0xc2, 0x9, 0x12, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0xc2, 0x6, 0x12,
            0x2b, 0x81, 0x4, 0x0, 0x22, 0xc2, 0x6, 0x12, 0x2b, 0x81, 0x4, 0x0, 0x23, 0xc2, 0xa,
            0x12, 0x2b, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0x7, 0xc2, 0xa, 0x12, 0x2b, 0x24, 0x3,
            0x3, 0x2, 0x8, 0x1, 0x1, 0xb, 0xc2, 0xa, 0x12, 0x2b, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1,
            0x1, 0xd, 0xc3, 0x6, 0x1, 0x8, 0x0, 0x0, 0x20, 0x0, 0xc3, 0x6, 0x1, 0xc, 0x0, 0x0,
            0x20, 0x0, 0xc3, 0x6, 0x1, 0x10, 0x0, 0x0, 0x20, 0x0, 0xc3, 0x9, 0x13, 0x2a, 0x86,
            0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0xc3, 0x6, 0x13, 0x2b, 0x81, 0x4, 0x0, 0x22, 0xc3,
            0x6, 0x13, 0x2b, 0x81, 0x4, 0x0, 0x23, 0xc3, 0xa, 0x13, 0x2b, 0x24, 0x3, 0x3, 0x2, 0x8,
            0x1, 0x1, 0x7, 0xc3, 0xa, 0x13, 0x2b, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0xb, 0xc3,
            0xa, 0x13, 0x2b, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0xd,
        ];

        let ai = AlgorithmInformation::try_from(&data[..]).unwrap();

        assert_eq!(
            ai,
            AlgorithmInformation(vec![
                (Signing, Rsa(RsaAttributes::new(2048, 32, 0))),
                (Signing, Rsa(RsaAttributes::new(3072, 32, 0))),
                (Signing, Rsa(RsaAttributes::new(4096, 32, 0))),
                (Signing, Ecc(EccAttributes::new(ECDSA, NistP256r1, None))),
                (Signing, Ecc(EccAttributes::new(ECDSA, NistP384r1, None))),
                (Signing, Ecc(EccAttributes::new(ECDSA, NistP521r1, None))),
                (
                    Signing,
                    Ecc(EccAttributes::new(ECDSA, BrainpoolP256r1, None))
                ),
                (
                    Signing,
                    Ecc(EccAttributes::new(ECDSA, BrainpoolP384r1, None))
                ),
                (
                    Signing,
                    Ecc(EccAttributes::new(ECDSA, BrainpoolP512r1, None))
                ),
                (Decryption, Rsa(RsaAttributes::new(2048, 32, 0))),
                (Decryption, Rsa(RsaAttributes::new(3072, 32, 0))),
                (Decryption, Rsa(RsaAttributes::new(4096, 32, 0))),
                (Decryption, Ecc(EccAttributes::new(ECDH, NistP256r1, None))),
                (Decryption, Ecc(EccAttributes::new(ECDH, NistP384r1, None))),
                (Decryption, Ecc(EccAttributes::new(ECDH, NistP521r1, None))),
                (
                    Decryption,
                    Ecc(EccAttributes::new(ECDH, BrainpoolP256r1, None))
                ),
                (
                    Decryption,
                    Ecc(EccAttributes::new(ECDH, BrainpoolP384r1, None))
                ),
                (
                    Decryption,
                    Ecc(EccAttributes::new(ECDH, BrainpoolP512r1, None))
                ),
                (Authentication, Rsa(RsaAttributes::new(2048, 32, 0))),
                (Authentication, Rsa(RsaAttributes::new(3072, 32, 0))),
                (Authentication, Rsa(RsaAttributes::new(4096, 32, 0))),
                (
                    Authentication,
                    Ecc(EccAttributes::new(ECDSA, NistP256r1, None))
                ),
                (
                    Authentication,
                    Ecc(EccAttributes::new(ECDSA, NistP384r1, None))
                ),
                (
                    Authentication,
                    Ecc(EccAttributes::new(ECDSA, NistP521r1, None))
                ),
                (
                    Authentication,
                    Ecc(EccAttributes::new(ECDSA, BrainpoolP256r1, None))
                ),
                (
                    Authentication,
                    Ecc(EccAttributes::new(ECDSA, BrainpoolP384r1, None))
                ),
                (
                    Authentication,
                    Ecc(EccAttributes::new(ECDSA, BrainpoolP512r1, None))
                )
            ])
        );
    }

    #[test]
    fn test_yk5() {
        let data = [
            0xfa, 0x82, 0x1, 0xe2, 0xc1, 0x6, 0x1, 0x8, 0x0, 0x0, 0x11, 0x0, 0xc1, 0x6, 0x1, 0xc,
            0x0, 0x0, 0x11, 0x0, 0xc1, 0x6, 0x1, 0x10, 0x0, 0x0, 0x11, 0x0, 0xc1, 0x9, 0x13, 0x2a,
            0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0xc1, 0x6, 0x13, 0x2b, 0x81, 0x4, 0x0, 0x22,
            0xc1, 0x6, 0x13, 0x2b, 0x81, 0x4, 0x0, 0x23, 0xc1, 0x6, 0x13, 0x2b, 0x81, 0x4, 0x0,
            0xa, 0xc1, 0xa, 0x13, 0x2b, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0x7, 0xc1, 0xa, 0x13,
            0x2b, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0xb, 0xc1, 0xa, 0x13, 0x2b, 0x24, 0x3, 0x3,
            0x2, 0x8, 0x1, 0x1, 0xd, 0xc1, 0xa, 0x16, 0x2b, 0x6, 0x1, 0x4, 0x1, 0xda, 0x47, 0xf,
            0x1, 0xc1, 0xb, 0x16, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x97, 0x55, 0x1, 0x5, 0x1, 0xc2, 0x6,
            0x1, 0x8, 0x0, 0x0, 0x11, 0x0, 0xc2, 0x6, 0x1, 0xc, 0x0, 0x0, 0x11, 0x0, 0xc2, 0x6,
            0x1, 0x10, 0x0, 0x0, 0x11, 0x0, 0xc2, 0x9, 0x12, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3,
            0x1, 0x7, 0xc2, 0x6, 0x12, 0x2b, 0x81, 0x4, 0x0, 0x22, 0xc2, 0x6, 0x12, 0x2b, 0x81,
            0x4, 0x0, 0x23, 0xc2, 0x6, 0x12, 0x2b, 0x81, 0x4, 0x0, 0xa, 0xc2, 0xa, 0x12, 0x2b,
            0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0x7, 0xc2, 0xa, 0x12, 0x2b, 0x24, 0x3, 0x3, 0x2,
            0x8, 0x1, 0x1, 0xb, 0xc2, 0xa, 0x12, 0x2b, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0xd,
            0xc2, 0xa, 0x16, 0x2b, 0x6, 0x1, 0x4, 0x1, 0xda, 0x47, 0xf, 0x1, 0xc2, 0xb, 0x16, 0x2b,
            0x6, 0x1, 0x4, 0x1, 0x97, 0x55, 0x1, 0x5, 0x1, 0xc3, 0x6, 0x1, 0x8, 0x0, 0x0, 0x11,
            0x0, 0xc3, 0x6, 0x1, 0xc, 0x0, 0x0, 0x11, 0x0, 0xc3, 0x6, 0x1, 0x10, 0x0, 0x0, 0x11,
            0x0, 0xc3, 0x9, 0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0xc3, 0x6, 0x13,
            0x2b, 0x81, 0x4, 0x0, 0x22, 0xc3, 0x6, 0x13, 0x2b, 0x81, 0x4, 0x0, 0x23, 0xc3, 0x6,
            0x13, 0x2b, 0x81, 0x4, 0x0, 0xa, 0xc3, 0xa, 0x13, 0x2b, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1,
            0x1, 0x7, 0xc3, 0xa, 0x13, 0x2b, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0xb, 0xc3, 0xa,
            0x13, 0x2b, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0xd, 0xc3, 0xa, 0x16, 0x2b, 0x6, 0x1,
            0x4, 0x1, 0xda, 0x47, 0xf, 0x1, 0xc3, 0xb, 0x16, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x97, 0x55,
            0x1, 0x5, 0x1, 0xda, 0x6, 0x1, 0x8, 0x0, 0x0, 0x11, 0x0, 0xda, 0x6, 0x1, 0xc, 0x0, 0x0,
            0x11, 0x0, 0xda, 0x6, 0x1, 0x10, 0x0, 0x0, 0x11, 0x0, 0xda, 0x9, 0x13, 0x2a, 0x86,
            0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0xda, 0x6, 0x13, 0x2b, 0x81, 0x4, 0x0, 0x22, 0xda,
            0x6, 0x13, 0x2b, 0x81, 0x4, 0x0, 0x23, 0xda, 0x6, 0x13, 0x2b, 0x81, 0x4, 0x0, 0xa,
            0xda, 0xa, 0x13, 0x2b, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0x7, 0xda, 0xa, 0x13, 0x2b,
            0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0xb, 0xda, 0xa, 0x13, 0x2b, 0x24, 0x3, 0x3, 0x2,
            0x8, 0x1, 0x1, 0xd, 0xda, 0xa, 0x16, 0x2b, 0x6, 0x1, 0x4, 0x1, 0xda, 0x47, 0xf, 0x1,
            0xda, 0xb, 0x16, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x97, 0x55, 0x1, 0x5, 0x1,
        ];

        let ai = AlgorithmInformation::try_from(&data[..]).unwrap();

        assert_eq!(
            ai,
            AlgorithmInformation(vec![
                (Signing, Rsa(RsaAttributes::new(2048, 17, 0))),
                (Signing, Rsa(RsaAttributes::new(3072, 17, 0))),
                (Signing, Rsa(RsaAttributes::new(4096, 17, 0))),
                (Signing, Ecc(EccAttributes::new(ECDSA, NistP256r1, None))),
                (Signing, Ecc(EccAttributes::new(ECDSA, NistP384r1, None))),
                (Signing, Ecc(EccAttributes::new(ECDSA, NistP521r1, None))),
                (Signing, Ecc(EccAttributes::new(ECDSA, Secp256k1, None))),
                (
                    Signing,
                    Ecc(EccAttributes::new(ECDSA, BrainpoolP256r1, None))
                ),
                (
                    Signing,
                    Ecc(EccAttributes::new(ECDSA, BrainpoolP384r1, None))
                ),
                (
                    Signing,
                    Ecc(EccAttributes::new(ECDSA, BrainpoolP512r1, None))
                ),
                (Signing, Ecc(EccAttributes::new(EdDSA, Ed25519, None))),
                (Signing, Ecc(EccAttributes::new(EdDSA, Curve25519, None))),
                (Decryption, Rsa(RsaAttributes::new(2048, 17, 0))),
                (Decryption, Rsa(RsaAttributes::new(3072, 17, 0))),
                (Decryption, Rsa(RsaAttributes::new(4096, 17, 0))),
                (Decryption, Ecc(EccAttributes::new(ECDH, NistP256r1, None))),
                (Decryption, Ecc(EccAttributes::new(ECDH, NistP384r1, None))),
                (Decryption, Ecc(EccAttributes::new(ECDH, NistP521r1, None))),
                (Decryption, Ecc(EccAttributes::new(ECDH, Secp256k1, None))),
                (
                    Decryption,
                    Ecc(EccAttributes::new(ECDH, BrainpoolP256r1, None))
                ),
                (
                    Decryption,
                    Ecc(EccAttributes::new(ECDH, BrainpoolP384r1, None))
                ),
                (
                    Decryption,
                    Ecc(EccAttributes::new(ECDH, BrainpoolP512r1, None))
                ),
                (Decryption, Ecc(EccAttributes::new(EdDSA, Ed25519, None))),
                (Decryption, Ecc(EccAttributes::new(EdDSA, Curve25519, None))),
                (Authentication, Rsa(RsaAttributes::new(2048, 17, 0))),
                (Authentication, Rsa(RsaAttributes::new(3072, 17, 0))),
                (Authentication, Rsa(RsaAttributes::new(4096, 17, 0))),
                (
                    Authentication,
                    Ecc(EccAttributes::new(ECDSA, NistP256r1, None))
                ),
                (
                    Authentication,
                    Ecc(EccAttributes::new(ECDSA, NistP384r1, None))
                ),
                (
                    Authentication,
                    Ecc(EccAttributes::new(ECDSA, NistP521r1, None))
                ),
                (
                    Authentication,
                    Ecc(EccAttributes::new(ECDSA, Secp256k1, None))
                ),
                (
                    Authentication,
                    Ecc(EccAttributes::new(ECDSA, BrainpoolP256r1, None))
                ),
                (
                    Authentication,
                    Ecc(EccAttributes::new(ECDSA, BrainpoolP384r1, None))
                ),
                (
                    Authentication,
                    Ecc(EccAttributes::new(ECDSA, BrainpoolP512r1, None))
                ),
                (
                    Authentication,
                    Ecc(EccAttributes::new(EdDSA, Ed25519, None))
                ),
                (
                    Authentication,
                    Ecc(EccAttributes::new(EdDSA, Curve25519, None))
                ),
                (Attestation, Rsa(RsaAttributes::new(2048, 17, 0))),
                (Attestation, Rsa(RsaAttributes::new(3072, 17, 0))),
                (Attestation, Rsa(RsaAttributes::new(4096, 17, 0))),
                (
                    Attestation,
                    Ecc(EccAttributes::new(ECDSA, NistP256r1, None))
                ),
                (
                    Attestation,
                    Ecc(EccAttributes::new(ECDSA, NistP384r1, None))
                ),
                (
                    Attestation,
                    Ecc(EccAttributes::new(ECDSA, NistP521r1, None))
                ),
                (Attestation, Ecc(EccAttributes::new(ECDSA, Secp256k1, None))),
                (
                    Attestation,
                    Ecc(EccAttributes::new(ECDSA, BrainpoolP256r1, None))
                ),
                (
                    Attestation,
                    Ecc(EccAttributes::new(ECDSA, BrainpoolP384r1, None))
                ),
                (
                    Attestation,
                    Ecc(EccAttributes::new(ECDSA, BrainpoolP512r1, None))
                ),
                (Attestation, Ecc(EccAttributes::new(EdDSA, Ed25519, None))),
                (
                    Attestation,
                    Ecc(EccAttributes::new(EdDSA, Curve25519, None))
                )
            ])
        );
    }
}
