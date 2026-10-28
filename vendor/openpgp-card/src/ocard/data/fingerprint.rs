// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fingerprint for a single key slot

use std::{
    convert::{TryFrom, TryInto},
    fmt,
};

use nom::{bytes::complete as bytes, combinator, sequence};

use crate::{
    Error,
    ocard::data::{Fingerprint, KeySet},
};

impl From<[u8; 20]> for Fingerprint {
    fn from(data: [u8; 20]) -> Self {
        Self(data)
    }
}

impl TryFrom<&[u8]> for Fingerprint {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        log::trace!("Fingerprint from input: {:x?}, len {}", input, input.len());

        if input.len() == 20 {
            #[allow(clippy::expect_used)]
            let array: [u8; 20] = input.try_into().expect("checked");
            Ok(array.into())
        } else {
            Err(Error::ParseError(format!(
                "Unexpected fingerprint length {}",
                input.len()
            )))
        }
    }
}

impl Fingerprint {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:X}")
    }
}

impl fmt::UpperHex for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Fingerprint")
            .field(&self.to_string())
            .finish()
    }
}

fn fingerprint(input: &[u8]) -> nom::IResult<&[u8], Option<Fingerprint>> {
    combinator::map(bytes::take(20u8), |i: &[u8]| {
        if i.iter().any(|&c| c > 0) {
            // We requested 20 bytes, so we can expect here
            #[allow(clippy::expect_used)]
            let i: [u8; 20] = i.try_into().expect("20 taken");
            Some(i.into())
        } else {
            None
        }
    })(input)
}

fn fingerprints(input: &[u8]) -> nom::IResult<&[u8], KeySet<Fingerprint>> {
    combinator::into(sequence::tuple((fingerprint, fingerprint, fingerprint)))(input)
}

impl TryFrom<&[u8]> for KeySet<Fingerprint> {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        log::trace!("Fingerprint from input: {:x?}, len {}", input, input.len());

        // The input may be longer than 3 fingerprint, don't fail if it hasn't
        // been completely consumed.
        self::fingerprints(input)
            .map(|res| res.1)
            .map_err(|_err| Error::ParseError("Parsing failed".into()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        let data3 = [
            0xb7, 0xcd, 0x9f, 0x76, 0x37, 0x1e, 0x7, 0x7f, 0x76, 0x1c, 0x82, 0x65, 0x55, 0x54,
            0x3e, 0x6d, 0x65, 0x6d, 0x1d, 0x80, 0x62, 0xd7, 0x34, 0x22, 0x65, 0xd2, 0xef, 0x33,
            0x64, 0xe3, 0x79, 0x52, 0xd9, 0x5e, 0x94, 0x20, 0x5f, 0x4c, 0xce, 0x8b, 0x3f, 0x9,
            0x7a, 0xf2, 0xfd, 0x76, 0xa5, 0xa7, 0x57, 0x9b, 0x51, 0x1f, 0xf, 0x44, 0x9a, 0x25,
            0x80, 0x2d, 0xb2, 0xb8,
        ];

        let fp_set: KeySet<Fingerprint> = (&data3[..])
            .try_into()
            .expect("failed to parse fingerprint set");

        assert_eq!(
            format!("{}", fp_set.signature().unwrap()),
            "B7CD9F76371E077F761C826555543E6D656D1D80"
        );
        assert_eq!(
            format!("{}", fp_set.decryption().unwrap()),
            "62D7342265D2EF3364E37952D95E94205F4CCE8B"
        );
        assert_eq!(
            format!("{}", fp_set.authentication().unwrap()),
            "3F097AF2FD76A5A7579B511F0F449A25802DB2B8"
        );

        let data1 = [
            0xb7, 0xcd, 0x9f, 0x76, 0x37, 0x1e, 0x7, 0x7f, 0x76, 0x1c, 0x82, 0x65, 0x55, 0x54,
            0x3e, 0x6d, 0x65, 0x6d, 0x1d, 0x80,
        ];

        let fp = Fingerprint::try_from(&data1[..]).expect("failed to parse fingerprint");

        assert_eq!(format!("{fp}"), "B7CD9F76371E077F761C826555543E6D656D1D80");
    }
}
