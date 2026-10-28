// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! This is a crate for using
//! [OpenPGP card devices](https://en.wikipedia.org/wiki/OpenPGP_card) with
//! the [`rPGP`](https://crates.io/crates/pgp) OpenPGP library.
//!
//! In fact, this crate is a supplement for the
//! [`openpgp-card`](https://crates.io/crates/openpgp-card) crate.
//! This crate, `openpgp-card-rpgp`, enables performing OpenPGP-specific
//! operations on cards, by leveraging both the `rPGP` library and `openpgp-card`.
//! If you want to use this crate, you will probably also want to use
//! `openpgp-card` itself:
//!
//! Much of the functionality of an OpenPGP card device doesn't actually
//! involve the OpenPGP format. All of that functionality is available in
//! `openpgp-card`, without requiring support for the OpenPGP format.
//!
//! This crate implements additional support for operations that *do* require
//! handling the OpenPGP format:
//!
//! - Creating OpenPGP signatures
//! - Decryption of OpenPGP data
//! - Import of OpenPGP private key material
//!
//! See this project's "examples" for some pointers on how to use this crate.

mod cardslot;
mod private;
mod rpgp;

use std::fmt::Debug;

pub use cardslot::CardSlot;
pub use private::UploadableKey;
pub use rpgp::{
    bind_into_certificate,
    public_key_material_and_fp_to_key,
    public_key_material_to_key,
    public_to_fingerprint,
};

/// Enum wrapper for the error types of this crate
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("rPGP error: {0}")]
    Rpgp(pgp::errors::Error),

    #[error("OpenPGP card error: {0}")]
    Ocard(openpgp_card::Error),

    #[error("Internal error: {0}")]
    Message(String),
}

impl From<Error> for pgp::errors::Error {
    fn from(value: Error) -> Self {
        pgp::errors::Error::Message {
            message: format!("openpgp-card-rpgp error: {value:?}"),
            backtrace: None,
        }
    }
}

impl From<pgp::errors::Error> for Error {
    fn from(value: pgp::errors::Error) -> Self {
        Error::Rpgp(value)
    }
}

impl From<openpgp_card::Error> for Error {
    fn from(value: openpgp_card::Error) -> Self {
        Error::Ocard(value)
    }
}

impl From<rsa::Error> for Error {
    fn from(value: rsa::Error) -> Self {
        Error::Message(format!("rsa error: {value:?}"))
    }
}

impl From<p256::elliptic_curve::Error> for Error {
    fn from(value: p256::elliptic_curve::Error) -> Self {
        Error::Message(format!("elliptic_curve error: {value:?}"))
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(value: ed25519_dalek::ed25519::Error) -> Self {
        Error::Message(format!("ed25519_dalek error: {value:?}"))
    }
}
