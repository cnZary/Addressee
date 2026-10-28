// SPDX-FileCopyrightText: 2024 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::TryFrom;

use crate::{
    Error,
    ocard::{
        data::KdfDo,
        tags::Tags,
        tlv::{Tlv, tag::Tag, value::Value},
    },
};

impl TryFrom<&[u8]> for KdfDo {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let tlv = Tlv::new(Tags::KdfDo, Value::from(value, true)?);

        if let Some(Value::S(data)) = tlv.find(Tag::from([0x81])) {
            let kdf_algo: u8 = if data.len() == 1 {
                data[0]
            } else {
                return Err(Error::ParseError(
                    "couldn't parse kdf algorithm field in KDF DO".to_string(),
                ));
            };

            let hash_algo: Option<u8> = tlv.find(Tag::from([0x82])).and_then(|v| match v {
                Value::S(data) => {
                    if data.len() == 1 {
                        Some(data[0])
                    } else {
                        None
                    }
                }
                _ => None,
            });

            let iter_count: Option<u32> = tlv.find(Tag::from([0x83])).and_then(|v| match v {
                Value::S(data) => match &data[..] {
                    [a, b, c, d] => Some(u32::from_be_bytes([*a, *b, *c, *d])),
                    _ => None,
                },
                _ => None,
            });

            let salt_pw1: Option<Vec<u8>> = tlv.find(Tag::from([0x84])).and_then(|v| match v {
                Value::S(data) => Some(data.to_vec()),
                _ => None,
            });

            let salt_rc: Option<Vec<u8>> = tlv.find(Tag::from([0x85])).and_then(|v| match v {
                Value::S(data) => Some(data.to_vec()),
                _ => None,
            });

            let salt_pw3: Option<Vec<u8>> = tlv.find(Tag::from([0x86])).and_then(|v| match v {
                Value::S(data) => Some(data.to_vec()),
                _ => None,
            });

            let initial_hash_pw1: Option<Vec<u8>> =
                tlv.find(Tag::from([0x87])).and_then(|v| match v {
                    Value::S(data) => Some(data.to_vec()),
                    _ => None,
                });

            let initial_hash_pw3: Option<Vec<u8>> =
                tlv.find(Tag::from([0x88])).and_then(|v| match v {
                    Value::S(data) => Some(data.to_vec()),
                    _ => None,
                });

            Ok(Self {
                kdf_algo,
                hash_algo,
                iter_count,
                salt_pw1,
                salt_rc,
                salt_pw3,
                initial_hash_pw1,
                initial_hash_pw3,
            })
        } else {
            Err(Error::ParseError("couldn't parse KDF DO".to_string()))
        }
    }
}

impl KdfDo {
    pub fn kdf_algo(&self) -> u8 {
        self.kdf_algo
    }

    pub fn hash_algo(&self) -> Option<u8> {
        self.hash_algo
    }

    pub fn iter_count(&self) -> Option<u32> {
        self.iter_count
    }

    pub fn salt_pw1(&self) -> Option<&[u8]> {
        self.salt_pw1.as_deref()
    }

    pub fn salt_rc(&self) -> Option<&[u8]> {
        self.salt_rc.as_deref()
    }

    pub fn salt_pw3(&self) -> Option<&[u8]> {
        self.salt_pw3.as_deref()
    }

    pub fn initial_hash_pw1(&self) -> Option<&[u8]> {
        self.initial_hash_pw1.as_deref()
    }

    pub fn initial_hash_pw3(&self) -> Option<&[u8]> {
        self.initial_hash_pw3.as_deref()
    }
}
