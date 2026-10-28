// SPDX-FileCopyrightText: 2024 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Handle transformation of user-provided PINs according to the KDF configuration on the card,
//! if any.

use secrecy::{ExposeSecret, SecretBox, SecretString};
use sha2::Digest;

use crate::{Error, PinType, ocard::data::KdfDo};

trait Hasher {
    /// Update the hash with the given value.
    fn update(&mut self, _: &[u8]);

    /// Finalize the hash and return the result.
    fn finish(self: Box<Self>) -> Vec<u8>;
}

#[derive(Default)]
pub struct Sha2_256 {
    inner: sha2::Sha256,
}

impl Hasher for Sha2_256 {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finish(self: Box<Self>) -> Vec<u8> {
        self.inner.finalize().as_slice().to_vec()
    }
}

#[derive(Default)]
pub struct Sha2_512 {
    inner: sha2::Sha512,
}

impl Hasher for crate::ocard::kdf::Sha2_512 {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finish(self: Box<Self>) -> Vec<u8> {
        self.inner.finalize().as_slice().to_vec()
    }
}

/// Map user-provided pw/pin value to a `SecretVec<u8>`.
///
/// This performs a KDF transformation, if the KDF mode is enabled on the card.
pub(crate) fn map_pin(
    pw: SecretString,
    pin_type: PinType,
    kdf_do: Option<&KdfDo>,
) -> Result<SecretBox<[u8]>, Error> {
    match kdf_do {
        None => {
            // KDF DO is not set at all -> use the raw pw bytes as PIN
            Ok(pw.expose_secret().as_bytes().to_vec().into())
        }
        Some(kdf) if kdf.kdf_algo() == 0 => {
            //  KDF algo is "0" -> use the raw pw bytes as PIN
            Ok(pw.expose_secret().as_bytes().to_vec().into())
        }
        Some(kdf) => {
            // KDF transformation needs to be applied to PIN

            match kdf.kdf_algo() {
                3 => Ok(itersalt(
                    pw.expose_secret(),
                    kdf.hash_algo(),
                    kdf.iter_count(),
                    match pin_type {
                        PinType::Pw1 => kdf.salt_pw1(),
                        PinType::Rc => kdf.salt_rc(),
                        PinType::Pw3 => kdf.salt_pw3(),
                    },
                )?
                .into()),
                _ => Err(Error::UnsupportedFeature(
                    "The KDF mode on the card is currently unsupported".to_string(),
                )),
            }
        }
    }
}

/// see https://www.rfc-editor.org/rfc/rfc4880.html#section-3.7.1.3
pub(crate) fn itersalt(
    pw: &str,
    hash_algo: Option<u8>,
    count: Option<u32>,
    salt: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let hash_algo = match hash_algo {
        Some(hash_algo) => hash_algo,
        None => {
            return Err(Error::InternalError(
                "No KDF hash algorithm setting found".to_string(),
            ));
        }
    };

    // number of bytes that should be hashed
    let mut count = match count {
        Some(count) => count,
        None => {
            return Err(Error::InternalError(
                "No KDF iteration count setting found".to_string(),
            ));
        }
    } as usize;

    let salt = match salt {
        Some(salt) => salt,
        None => {
            return Err(Error::InternalError(
                "No KDF salt setting found".to_string(),
            ));
        }
    };

    // set up hasher
    let mut hasher: Box<dyn Hasher> = match hash_algo {
        0x08 => Box::<Sha2_256>::default(),
        0x0A => Box::<Sha2_512>::default(),
        _ => {
            return Err(Error::InternalError(
                "KDF: unsupported hash algorithm setting".to_string(),
            ));
        }
    };

    if count < salt.len() + pw.len() {
        return Err(Error::InternalError(
            "KDF: dubiously small count".to_string(),
        ));
    }

    // salt and pw must be hashed complete, at least once
    hasher.update(salt);
    count -= salt.len();

    hasher.update(pw.as_bytes());
    count -= pw.len();

    loop {
        if count >= salt.len() {
            hasher.update(salt);
            count -= salt.len();
        } else {
            hasher.update(&salt[0..count]);
            break;
        }

        if count >= pw.len() {
            hasher.update(pw.as_bytes());
            count -= pw.len();
        } else {
            hasher.update(&pw.as_bytes()[0..count]);
            break;
        }
    }

    Ok(hasher.finish())
}

#[test]
fn test_itersalt() {
    // Examples from OpenPGP card 3.4.1 "Functional Specification" pdf, page 20

    let user = itersalt(
        "123456",
        Some(0x8),
        Some(100000),
        Some(&[0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37]),
    )
    .expect("itersalt");
    assert_eq!(
        user,
        vec![
            0x77, 0x37, 0x84, 0xA6, 0x02, 0xB6, 0xC8, 0x1E, 0x3F, 0x09, 0x2F, 0x4D, 0x7D, 0x00,
            0xE1, 0x7C, 0xC8, 0x22, 0xD8, 0x8F, 0x73, 0x60, 0xFC, 0xF2, 0xD2, 0xEF, 0x2D, 0x9D,
            0x90, 0x1F, 0x44, 0xB6
        ]
    );

    let admin = itersalt(
        "12345678",
        Some(0x8),
        Some(100000),
        Some(&[0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48]),
    )
    .expect("itersalt");
    assert_eq!(
        admin,
        vec![
            0x26, 0x75, 0xD6, 0x16, 0x4A, 0x0D, 0x48, 0x27, 0xD1, 0xD0, 0x0C, 0x7E, 0xEA, 0x62,
            0x0D, 0x01, 0x5C, 0x00, 0x03, 0x0A, 0x1C, 0xAB, 0x38, 0xB4, 0xD0, 0xDD, 0x60, 0x0B,
            0x27, 0xDC, 0x96, 0x30
        ]
    );
}
