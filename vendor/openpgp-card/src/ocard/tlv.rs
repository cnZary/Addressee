// SPDX-FileCopyrightText: 2021-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

pub(crate) mod length;
pub(crate) mod tag;
pub(crate) mod value;

use std::convert::TryFrom;

use nom::{bytes::complete as bytes, combinator};

use crate::ocard::{
    data::complete,
    tlv::{length::tlv_encode_length, tag::Tag, value::Value},
};

/// TLV (Tag-Length-Value) data structure.
///
/// Many DOs (data objects) on OpenPGP cards are stored in TLV format.
/// This struct handles serializing and deserializing TLV.
#[derive(Debug, Eq, PartialEq)]
pub struct Tlv {
    tag: Tag,
    value: Value,
}

impl Tlv {
    pub fn new<T: Into<Tag>>(tag: T, value: Value) -> Self {
        let tag = tag.into();
        Self { tag, value }
    }

    /// Find the first occurrence of `tag` and return its value (if any)
    pub fn find<T: Clone + Into<Tag>>(&self, tag: T) -> Option<&Value> {
        let t: Tag = tag.clone().into();
        if self.tag == t {
            Some(&self.value)
        } else {
            if let Value::C(inner) = &self.value {
                for tlv in inner {
                    if let Some(found) = tlv.find(tag.clone()) {
                        return Some(found);
                    }
                }
            }
            None
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let value = self.value.serialize();
        let length = tlv_encode_length(value.len() as u16);

        let mut ser = Vec::new();
        ser.extend(self.tag.get().iter());
        ser.extend(length.iter());
        ser.extend(value.iter());
        ser
    }

    fn parse(input: &[u8]) -> nom::IResult<&[u8], Tlv> {
        // Read the tag byte(s)
        let (input, tag) = tag::tag(input)?;

        // Read the length field and get the corresponding number of bytes,
        // which contain the value of this tlv
        let (input, value) = combinator::flat_map(length::length, bytes::take)(input)?;

        // Parse the value bytes, as "simple" or "constructed", depending
        // on the tag.
        let (_, v) = Value::parse(value, tag.is_constructed())?;

        Ok((input, Self::new(tag, v)))
    }
}

impl TryFrom<&[u8]> for Tlv {
    type Error = crate::Error;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        complete(Tlv::parse(input))
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use hex_literal::hex;

    use super::{Tlv, Value};
    use crate::{Error, ocard::tags::Tags};

    #[test]
    fn test_tlv0() {
        let cpkt = Tlv::new(
            Tags::CardholderPrivateKeyTemplate,
            Value::S(vec![
                0x91, 0x03, 0x92, 0x82, 0x01, 0x00, 0x93, 0x82, 0x01, 0x00,
            ]),
        );

        assert_eq!(
            cpkt.serialize(),
            vec![
                0x7F, 0x48, 0x0A, 0x91, 0x03, 0x92, 0x82, 0x01, 0x00, 0x93, 0x82, 0x01, 0x00,
            ]
        );
    }
    #[test]
    fn test_tlv() -> Result<(), Error> {
        // From OpenPGP card spec § 7.2.6
        let data = hex!("5B0B546573743C3C54657374695F2D0264655F350131").to_vec();

        let (input, tlv) = Tlv::parse(&data).unwrap();

        assert_eq!(
            tlv,
            Tlv::new(
                Tags::Name,
                Value::S(hex!("546573743C3C5465737469").to_vec())
            )
        );

        let (input, tlv) = Tlv::parse(input).unwrap();

        assert_eq!(
            tlv,
            Tlv::new(Tags::LanguagePref, Value::S(hex!("6465").to_vec()))
        );

        let (input, tlv) = Tlv::parse(input).unwrap();

        assert_eq!(tlv, Tlv::new(Tags::Sex, Value::S(hex!("31").to_vec())));

        assert!(input.is_empty());

        Ok(())
    }

    #[test]
    fn test_tlv_yubi5() -> Result<(), Error> {
        // 'YubiKey 5 NFC' output for GET DATA on "Application Related Data"
        let data = hex!(
            "6e8201374f10d27600012401030400061601918000005f520800730000e00590007f740381012073820110c00a7d000bfe080000ff0000c106010800001100c206010800001100c306010800001100da06010800001100c407ff7f7f7f030003c5500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c6500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cd1000000000000000000000000000000000de0801000200030081027f660802020bfe02020bfed6020020d7020020d8020020d9020020"
        );
        let tlv = Tlv::try_from(&data[..])?;

        // check that after re-serializing, the data is still the same
        let serialized = tlv.serialize();
        assert_eq!(serialized, data.to_vec());

        // outermost layer contains all bytes as value
        let value = tlv.find(Tags::ApplicationRelatedData).unwrap();
        assert_eq!(
            value.serialize(),
            hex!(
                "4f10d27600012401030400061601918000005f520800730000e00590007f740381012073820110c00a7d000bfe080000ff0000c106010800001100c206010800001100c306010800001100da06010800001100c407ff7f7f7f030003c5500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c6500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cd1000000000000000000000000000000000de0801000200030081027f660802020bfe02020bfed6020020d7020020d8020020d9020020"
            )
        );

        // get and verify data for ecap tag
        let value = tlv.find(Tags::ExtendedCapabilities).unwrap();
        assert_eq!(value.serialize(), hex!("7d000bfe080000ff0000"));

        let value = tlv.find(Tags::ApplicationIdentifier).unwrap();
        assert_eq!(value.serialize(), hex!("d2760001240103040006160191800000"));

        let value = tlv.find(Tags::HistoricalBytes).unwrap();
        assert_eq!(value.serialize(), hex!("00730000e0059000"));

        let value = tlv.find(Tags::GeneralFeatureManagement).unwrap();
        assert_eq!(value.serialize(), hex!("810120"));

        let value = tlv.find(Tags::DiscretionaryDataObjects).unwrap();
        assert_eq!(
            value.serialize(),
            hex!(
                "c00a7d000bfe080000ff0000c106010800001100c206010800001100c306010800001100da06010800001100c407ff7f7f7f030003c5500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c6500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cd1000000000000000000000000000000000de0801000200030081027f660802020bfe02020bfed6020020d7020020d8020020d9020020"
            )
        );

        let value = tlv.find(Tags::ExtendedCapabilities).unwrap();
        assert_eq!(value.serialize(), hex!("7d000bfe080000ff0000"));

        let value = tlv.find(Tags::AlgorithmAttributesSignature).unwrap();
        assert_eq!(value.serialize(), hex!("010800001100"));

        let value = tlv.find(Tags::AlgorithmAttributesDecryption).unwrap();
        assert_eq!(value.serialize(), hex!("010800001100"));

        let value = tlv.find(Tags::AlgorithmAttributesAuthentication).unwrap();
        assert_eq!(value.serialize(), hex!("010800001100"));

        let value = tlv.find(Tags::AlgorithmAttributesAttestation).unwrap();
        assert_eq!(value.serialize(), hex!("010800001100"));

        let value = tlv.find(Tags::PWStatusBytes).unwrap();
        assert_eq!(value.serialize(), hex!("ff7f7f7f030003"));

        let value = tlv.find(Tags::Fingerprints).unwrap();
        assert_eq!(
            value.serialize(),
            hex!(
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );

        let value = tlv.find(Tags::CaFingerprints).unwrap();
        assert_eq!(
            value.serialize(),
            hex!(
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );

        let value = tlv.find(Tags::GenerationTimes).unwrap();
        assert_eq!(value.serialize(), hex!("00000000000000000000000000000000"));

        let value = tlv.find(Tags::KeyInformation).unwrap();
        assert_eq!(value.serialize(), hex!("0100020003008102"));

        let value = tlv.find(Tags::ExtendedLengthInformation).unwrap();
        assert_eq!(value.serialize(), hex!("02020bfe02020bfe"));

        let value = tlv.find(Tags::UifSig).unwrap();
        assert_eq!(value.serialize(), hex!("0020"));

        let value = tlv.find(Tags::UifDec).unwrap();
        assert_eq!(value.serialize(), hex!("0020"));

        let value = tlv.find(Tags::UifAuth).unwrap();
        assert_eq!(value.serialize(), hex!("0020"));

        let value = tlv.find(Tags::UifAttestation).unwrap();
        assert_eq!(value.serialize(), hex!("0020"));

        Ok(())
    }

    #[test]
    fn test_tlv_builder() {
        // NOTE: The data used in this example is similar to key upload,
        // but has been abridged and changed. It does not represent a
        // complete valid OpenPGP card DO!

        let a = Tlv::new(
            Tags::CardholderPrivateKeyTemplate,
            Value::S(vec![0x92, 0x03]),
        );

        let b = Tlv::new(Tags::ConcatenatedKeyData, Value::S(vec![0x1, 0x2, 0x3]));

        let tlv = Tlv::new(Tags::ExtendedHeaderList, Value::C(vec![a, b]));

        assert_eq!(
            tlv.serialize(),
            &[
                0x4d, 0xb, 0x7f, 0x48, 0x2, 0x92, 0x3, 0x5f, 0x48, 0x3, 0x1, 0x2, 0x3
            ]
        );
    }
}
