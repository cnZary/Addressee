// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::TryFrom;

use card_backend::SmartcardError;

use crate::{ocard::data::KdfDo, ocard::StatusBytes, verification_kdf, Error};

#[test]
fn raw_pin_requires_an_explicit_configuration_or_missing_data_status() {
    let raw = KdfDo::try_from(&[0x81, 0x01, 0x00][..]).expect("valid raw KDF configuration");
    assert_eq!(
        verification_kdf(Ok(raw))
            .expect("raw mode")
            .unwrap()
            .kdf_algo(),
        0
    );
    for status in [
        StatusBytes::ReferencedDataNotFound,
        StatusBytes::FileOrApplicationNotFound,
    ] {
        assert!(verification_kdf(Err(Error::CardStatus(status)))
            .expect("explicitly absent KDF")
            .is_none());
    }
}

#[test]
fn pin_verification_never_turns_read_failures_into_raw_pin() {
    for error in [
        Error::CardStatus(StatusBytes::INSNotSupported),
        Error::CardStatus(StatusBytes::SecurityStatusNotSatisfied),
        Error::ParseError("synthetic malformed KDF".to_owned()),
        Error::Smartcard(SmartcardError::Error(
            "synthetic transport failure".to_owned(),
        )),
    ] {
        assert!(verification_kdf(Err(error)).is_err());
    }
}
