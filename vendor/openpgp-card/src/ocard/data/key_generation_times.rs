// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generation date/time of key pair (see spec pg. 24)

use std::{
    convert::TryFrom,
    time::{Duration, SystemTime},
};

use nom::{combinator, number::complete as number, sequence};

use crate::{
    Error,
    ocard::data::{KeyGenerationTime, KeySet},
};

impl From<&KeyGenerationTime> for SystemTime {
    fn from(kg: &KeyGenerationTime) -> Self {
        SystemTime::UNIX_EPOCH + Duration::from_secs(kg.0 as u64)
    }
}

impl From<&KeyGenerationTime> for u32 {
    fn from(kg: &KeyGenerationTime) -> Self {
        kg.0
    }
}

impl From<u32> for KeyGenerationTime {
    fn from(data: u32) -> Self {
        Self(data)
    }
}

fn gen_time(input: &[u8]) -> nom::IResult<&[u8], u32> {
    (number::be_u32)(input)
}

fn key_generation(input: &[u8]) -> nom::IResult<&[u8], Option<KeyGenerationTime>> {
    combinator::map(gen_time, |kg| match kg {
        0 => None,
        kg => Some(KeyGenerationTime(kg)),
    })(input)
}

fn key_generation_set(input: &[u8]) -> nom::IResult<&[u8], KeySet<KeyGenerationTime>> {
    combinator::into(sequence::tuple((
        key_generation,
        key_generation,
        key_generation,
    )))(input)
}

impl TryFrom<&[u8]> for KeySet<KeyGenerationTime> {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        // List of generation dates/times of key pairs, binary.
        // 4 bytes, Big Endian each for Sig, Dec and Aut. Each
        // value shall be seconds since Jan 1, 1970. Default
        // value is 00000000 (not specified).

        log::trace!(
            "Key generation times from input: {:x?}, len {}",
            input,
            input.len()
        );

        // The input may be longer than 3 key generation times, don't fail if it
        // hasn't been completely consumed.
        self::key_generation_set(input)
            .map(|res| res.1)
            .map_err(|_err| Error::ParseError("Parsing failed".to_string()))
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryInto;

    use super::*;

    #[test]
    fn test() {
        let data3 = [
            0x60, 0xf3, 0xff, 0x71, 0x60, 0xf3, 0xff, 0x72, 0x60, 0xf3, 0xff, 0x83,
        ];

        let fp_set: KeySet<KeyGenerationTime> = (&data3[..])
            .try_into()
            .expect("failed to parse KeyGenerationTime set");

        assert_eq!(fp_set.signature().unwrap().get(), 0x60f3ff71);
        assert_eq!(fp_set.decryption().unwrap().get(), 0x60f3ff72);
        assert_eq!(fp_set.authentication().unwrap().get(), 0x60f3ff83);
    }
}
