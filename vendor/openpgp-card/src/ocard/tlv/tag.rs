// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tag in a TLV data structure.
//!
//! A Tag can span multiple octets, in the OpenPGP card context, only Tags spanning 1 or 2 octets
//! should come up. However, this type can deal with arbitrary length Tags.
//!
//! (The `ShortTag` type models tags that are exactly 1 or 2 octets long)
//!
//! <https://en.wikipedia.org/wiki/X.690#Encoding>

use nom::{branch, bytes::complete as bytes, combinator, number::complete as number, sequence};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tag(Vec<u8>);

impl Tag {
    pub fn is_constructed(&self) -> bool {
        if self.0.is_empty() {
            false
        } else {
            self.0[0] & 0x20 != 0
        }
    }

    pub fn get(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for Tag {
    fn from(t: &[u8]) -> Self {
        Tag(t.to_vec())
    }
}

impl From<[u8; 1]> for Tag {
    fn from(t: [u8; 1]) -> Self {
        Tag(t.to_vec())
    }
}

impl From<[u8; 2]> for Tag {
    fn from(t: [u8; 2]) -> Self {
        Tag(t.to_vec())
    }
}

fn multi_byte_tag(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    combinator::recognize(sequence::pair(multi_byte_tag_first, multi_byte_tag_rest))(input)
}

fn multi_byte_tag_first(input: &[u8]) -> nom::IResult<&[u8], u8> {
    combinator::verify(number::u8, is_multi_byte_tag_first)(input)
}

fn is_multi_byte_tag_first(c: &u8) -> bool {
    c.trailing_ones() >= 5
}

fn multi_byte_tag_rest(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    fn is_first(c: &u8) -> bool {
        c.trailing_zeros() < 7
    }

    fn is_last(c: &u8) -> bool {
        c.leading_ones() == 0
    }

    fn single_byte_rest(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
        combinator::verify(bytes::take(1u8), |c: &[u8]| {
            c.len() == 1 && is_first(&c[0]) && is_last(&c[0])
        })(input)
    }

    fn multi_byte_rest(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
        combinator::recognize(sequence::tuple((
            combinator::verify(number::u8, |c| is_first(c) && !is_last(c)),
            bytes::take_while(|c| !is_last(&c)),
            combinator::verify(number::u8, is_last),
        )))(input)
    }

    branch::alt((single_byte_rest, multi_byte_rest))(input)
}

fn single_byte_tag(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    combinator::verify(bytes::take(1u8), |c: &[u8]| {
        c.len() == 1 && !is_multi_byte_tag_first(&c[0])
    })(input)
}

pub(crate) fn tag(input: &[u8]) -> nom::IResult<&[u8], Tag> {
    combinator::map(branch::alt((multi_byte_tag, single_byte_tag)), Tag::from)(input)
}

#[cfg(test)]
mod test {
    use super::tag;

    #[test]
    fn test_tag() {
        let (_, t) = tag(&[0x0f]).unwrap();
        assert_eq!(t.0, &[0x0f]);
        let (_, t) = tag(&[0x0f, 0x4f]).unwrap();
        assert_eq!(t.0, &[0x0f]);
        let (_, t) = tag(&[0x4f]).unwrap();
        assert_eq!(t.0, &[0x4f]);
        let (_, t) = tag(&[0x5f, 0x1f]).unwrap();
        assert_eq!(t.0, &[0x5f, 0x1f]);
        let (_, t) = tag(&[0x5f, 0x2d]).unwrap();
        assert_eq!(t.0, &[0x5f, 0x2d]);
        let (_, t) = tag(&[0x5f, 0x35]).unwrap();
        assert_eq!(t.0, &[0x5f, 0x35]);
        let (_, t) = tag(&[0x5f, 0x35, 0x35]).unwrap();
        assert_eq!(t.0, &[0x5f, 0x35]);
        let (_, t) = tag(&[0x5f, 0x35, 0x2d]).unwrap();
        assert_eq!(t.0, &[0x5f, 0x35]);
        assert!(tag(&[0x5f]).is_err());
    }
}
