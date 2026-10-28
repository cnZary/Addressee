// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Value in a TLV data structure

use crate::ocard::{data::complete, tlv::Tlv};

/// A TLV "value"
#[derive(Debug, Eq, PartialEq)]
pub enum Value {
    /// A "constructed" value, consisting of a list of Tlv
    C(Vec<Tlv>),

    /// A "simple" value, consisting of binary data
    S(Vec<u8>),
}

impl Value {
    pub(crate) fn parse(data: &[u8], constructed: bool) -> nom::IResult<&[u8], Self> {
        match constructed {
            false => Ok((&[], Value::S(data.to_vec()))),
            true => {
                let mut c = vec![];
                let mut input = data;

                while !input.is_empty() {
                    let (rest, tlv) = Tlv::parse(input)?;
                    input = rest;
                    c.push(tlv);
                }

                Ok((&[], Value::C(c)))
            }
        }
    }

    pub fn from(data: &[u8], constructed: bool) -> Result<Self, crate::Error> {
        complete(Self::parse(data, constructed))
    }

    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Value::S(data) => data.clone(),
            Value::C(data) => {
                let mut s = vec![];
                for t in data {
                    s.extend(&t.serialize());
                }
                s
            }
        }
    }
}
