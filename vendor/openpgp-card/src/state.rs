// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0
// This file contains Addressee local modifications; see ADDRESSEE-PROVENANCE.md.

//! States of a card are modeled by the types `Open`, `Transaction`, `User`, `Sign`, `Admin`.

use crate::{
    ocard::data::{ApplicationRelatedData, KdfDo},
    Cached, Card,
};

/// States that a `Card` can be in.
///
/// See the implementations for more detail.
pub trait State {}

impl State for Open {}
impl State for Transaction<'_> {}
impl State for User<'_, '_> {}
impl State for Sign<'_, '_> {}
impl State for Admin<'_, '_> {}

/// An OpenPGP card in its base state, no transaction has been started.
///
/// A transaction can be started on the card, in this state.
pub struct Open {
    pub(crate) pgp: crate::ocard::OpenPGP,
}

/// State of an OpenPGP card once a transaction has been started.
///
/// The cards is in its base state, base authorization applies.
/// Card-Operations that don't require PIN validation can be performed in this state.
/// This includes many read-operations from the card.
///
/// (Note that a factory-reset can be performed in this base state.)
pub struct Transaction<'a> {
    pub(crate) opt: crate::ocard::Transaction<'a>,

    // Cache of "application related data".
    //
    // FIXME: Should be automatically invalidated when changing data on the card!
    // (e.g. uploading keys, etc)
    ard: Cached<ApplicationRelatedData>,

    // Cache of the card's KdfDo
    // FIXME: invalidate when changed!
    kdf_do: Cached<KdfDo>,

    // verify status of pw1
    // FIXME: this mechanism needs more thought
    pub(crate) pw1: bool,

    // verify status of pw1 for signing
    // FIXME: this mechanism needs more thought
    pub(crate) pw1_sign: bool,

    // verify status of pw3
    // FIXME: this mechanism needs more thought
    pub(crate) pw3: bool,
}

impl<'a> Transaction<'a> {
    pub(crate) fn new(opt: crate::ocard::Transaction<'a>, ard: ApplicationRelatedData) -> Self {
        Transaction {
            opt,
            ard: Cached::Value(ard),
            kdf_do: Cached::Uncached,
            pw1: false,
            pw1_sign: false,
            pw3: false,
        }
    }

    pub(crate) fn ard(&mut self) -> &ApplicationRelatedData {
        if matches!(self.ard, Cached::Uncached) {
            match self.opt.application_related_data() {
                Ok(ard) => {
                    self.ard = Cached::Value(ard);
                }
                Err(_) => {
                    self.ard = Cached::None;
                }
            }
        }

        match &self.ard {
            Cached::Value(ard) => ard,
            Cached::Uncached => unreachable!(),
            Cached::None => unreachable!(),
        }
    }

    pub(crate) fn kdf_do(&mut self) -> Result<Option<&KdfDo>, crate::Error> {
        if matches!(self.kdf_do, Cached::Uncached) {
            self.kdf_do = Cached::Value(self.opt.kdf_do()?);
        }

        Ok(match &self.kdf_do {
            Cached::None => None,
            Cached::Value(kdf) => Some(kdf),
            Cached::Uncached => unreachable!(),
        })
    }

    pub(crate) fn invalidate_cache(&mut self) {
        self.invalidate_cache_ard();
        self.invalidate_cache_kdf_do();
    }

    pub(crate) fn invalidate_cache_ard(&mut self) {
        self.ard = Cached::Uncached;
    }

    pub(crate) fn invalidate_cache_kdf_do(&mut self) {
        self.kdf_do = Cached::Uncached;
    }
}

/// State of an OpenPGP card after successfully verifying the User PIN
/// (this verification allow user operations other than signing).
///
/// In this state, e.g. decryption operations and authentication operations can be performed.
pub struct User<'app, 'open> {
    pub(crate) tx: &'open mut Card<Transaction<'app>>,
}

/// State of an OpenPGP card after successfully verifying PW1 for signing.
///
/// In this state, signatures can be issued.
pub struct Sign<'app, 'open> {
    pub(crate) tx: &'open mut Card<Transaction<'app>>,
}

/// State of an OpenPGP card after successful verification the Admin PIN.
///
/// In this state, the card can be configured, e.g.: importing key material onto the card,
/// or setting the cardholder name.
pub struct Admin<'app, 'open> {
    pub(crate) tx: &'open mut Card<Transaction<'app>>,
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use card_backend::{CardBackend, CardCaps, CardTransaction, PinType, SmartcardError};
    use hex_literal::hex;

    use super::*;

    struct MockCard {
        responses: VecDeque<Result<Vec<u8>, SmartcardError>>,
        commands: Vec<Vec<u8>>,
    }

    struct MockTransaction<'a>(&'a mut MockCard);

    impl CardBackend for MockCard {
        fn limit_card_caps(&self, card_caps: CardCaps) -> CardCaps {
            card_caps
        }

        fn transaction(
            &mut self,
            _reselect_application: Option<&[u8]>,
        ) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, SmartcardError> {
            Ok(Box::new(MockTransaction(self)))
        }
    }

    impl CardTransaction for MockTransaction<'_> {
        fn transmit(&mut self, cmd: &[u8], _buf_size: usize) -> Result<Vec<u8>, SmartcardError> {
            self.0.commands.push(cmd.to_vec());
            self.0
                .responses
                .pop_front()
                .unwrap_or_else(|| Err(SmartcardError::Error("unexpected command".to_owned())))
        }

        fn feature_pinpad_verify(&self) -> bool {
            false
        }

        fn feature_pinpad_modify(&self) -> bool {
            false
        }

        fn pinpad_verify(
            &mut self,
            _pin: PinType,
            _card_caps: &Option<CardCaps>,
        ) -> Result<Vec<u8>, SmartcardError> {
            Err(SmartcardError::Error(
                "unexpected PIN-pad operation".to_owned(),
            ))
        }

        fn pinpad_modify(
            &mut self,
            _pin: PinType,
            _card_caps: &Option<CardCaps>,
        ) -> Result<Vec<u8>, SmartcardError> {
            Err(SmartcardError::Error(
                "unexpected PIN-pad operation".to_owned(),
            ))
        }

        fn was_reset(&self) -> bool {
            false
        }
    }

    #[test]
    fn kdf_read_failures_are_not_reclassified_as_missing() {
        let mut ard = hex!(
            "6e8201374f10d27600012401030400061601918000005f520800730000e00590007f740381012073820110c00a7d000bfe080000ff0000c106010800001100c206010800001100c306010800001100da06010800001100c407ff7f7f7f030003c5500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c6500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cd1000000000000000000000000000000000de0801000200030081027f660802020bfe02020bfed6020020d7020020d8020020d9020020"
        )
        .to_vec();
        ard.extend_from_slice(&[0x90, 0x00]);
        let backend: Box<dyn CardBackend + Send + Sync> = Box::new(MockCard {
            responses: [
                Ok(vec![0x90, 0x00]),
                Ok(ard.clone()),
                Ok(ard),
                Err(SmartcardError::Error("KDF transport failed".to_owned())),
            ]
            .into(),
            commands: Vec::new(),
        });
        let mut card = Card::<Open>::new(backend).expect("valid scripted card initialization");
        let mut transaction = card.transaction().expect("scripted transaction");
        let error = transaction
            .kdf_do()
            .expect_err("the transport error must be preserved");
        assert!(matches!(
            error,
            crate::Error::Smartcard(SmartcardError::Error(ref message))
                if message == "KDF transport failed"
        ));
        drop(transaction);
        let backend = card.into_backend();
        let _ = backend;
    }
}
