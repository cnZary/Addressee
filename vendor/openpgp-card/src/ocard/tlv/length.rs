// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Length in a TLV data structure

/// Helper fn to encode length fields in TLV structures (see spec 4.4.4)
pub(crate) fn tlv_encode_length(len: u16) -> Vec<u8> {
    if len > 255 {
        vec![0x82, (len >> 8) as u8, (len & 255) as u8]
    } else if len > 127 {
        vec![0x81, len as u8]
    } else {
        vec![len as u8]
    }
}

use nom::{branch, bytes::complete as bytes, combinator, number::complete as number, sequence};

fn length1(input: &[u8]) -> nom::IResult<&[u8], u8> {
    combinator::verify(number::u8, |&c| c < 0x80)(input)
}

fn length2(input: &[u8]) -> nom::IResult<&[u8], u8> {
    sequence::preceded(bytes::tag(&[0x81]), number::u8)(input)
}

fn length3(input: &[u8]) -> nom::IResult<&[u8], u16> {
    sequence::preceded(bytes::tag(&[0x82]), number::be_u16)(input)
}

pub(crate) fn length(input: &[u8]) -> nom::IResult<&[u8], u16> {
    branch::alt((
        combinator::into(length1),
        combinator::into(length2),
        length3,
    ))(input)
}
