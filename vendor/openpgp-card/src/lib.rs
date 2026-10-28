// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0
// This file contains Addressee local modifications; see ADDRESSEE-PROVENANCE.md.

//! Client library for
//! [OpenPGP card](https://en.wikipedia.org/wiki/OpenPGP_card)
//! devices (such as Gnuk, Nitrokey, YubiKey, or Java smartcards running an
//! OpenPGP card application).
//!
//! This library aims to offer
//! - low-level access to all features in the OpenPGP [card specification](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf)
//!   via the [crate::ocard] package,
//! - without relying on a particular [OpenPGP implementation](https://www.openpgp.org/software/developer/).
//!
//! The library exposes two modes of access to cards:
//! - low-level, unmediated, access to card functionality (see [crate::ocard]), and
//! - a more opinionated, typed wrapper API that performs some amount of caching [Card].
//!
//! Note that this library can't directly access cards by itself.
//! Instead, users need to supply a backend that implements the
//! [`card_backend::CardBackend`] and [`card_backend::CardTransaction`] traits.
//! For example [card-backend-pcsc](https://crates.io/crates/card-backend-pcsc)
//! offers a backend implementation that uses [PC/SC](https://en.wikipedia.org/wiki/PC/SC) to
//! communicate with Smart Cards.
//!
//! See the [architecture diagram](https://codeberg.org/openpgp-card/openpgp-card#architecture)
//! for an overview of the ecosystem around this crate.

extern crate core;

mod errors;
pub mod ocard;
pub mod state;

use card_backend::{CardBackend, SmartcardError};
use secrecy::SecretString;

pub use crate::errors::Error;
use crate::{
    ocard::{
        algorithm::{AlgoSimple, AlgorithmAttributes, AlgorithmInformation},
        crypto::{CardUploadableKey, PublicKeyMaterial},
        data::{
            ApplicationIdentifier, CardholderRelatedData, ExtendedCapabilities, ExtendedLengthInfo,
            Fingerprint, HistoricalBytes, KdfDo, KeyGenerationTime, KeyInformation, KeySet, Lang,
            PWStatusBytes, Sex, TouchPolicy, UserInteractionFlag,
        },
        kdf::map_pin,
        KeyType,
    },
    state::{Admin, Open, Sign, State, Transaction, User},
};

/// For caching DOs in a Transaction
enum Cached<T> {
    Uncached,
    None,
    Value(T),
}

/// A PIN in an OpenPGP card application.
///
/// - Pw1 is the "User PIN"
/// - Rc is the "Resetting Code"
/// - Pw3 is the "Admin PIN"
pub(crate) enum PinType {
    Pw1,
    Rc,
    Pw3,
}

fn verification_kdf(kdf: Result<KdfDo, Error>) -> Result<Option<KdfDo>, Error> {
    match kdf {
        Ok(kdf) => Ok(Some(kdf)),
        Err(Error::CardStatus(
            crate::ocard::StatusBytes::ReferencedDataNotFound
            | crate::ocard::StatusBytes::FileOrApplicationNotFound,
        )) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Optional PIN, used as a parameter to `Card<Transaction>::into_*_card`.
///
/// Effectively acts like a `Option<SecretString>`, but with a number of `From`
/// implementations for convenience.
pub struct OptionalPin(Option<SecretString>);

impl From<Option<SecretString>> for OptionalPin {
    fn from(value: Option<SecretString>) -> Self {
        OptionalPin(value)
    }
}

impl From<SecretString> for OptionalPin {
    fn from(value: SecretString) -> Self {
        OptionalPin(Some(value))
    }
}

/// Representation of an OpenPGP card.
///
/// A card transitions between [`State`]s by starting a transaction (that groups together a number
/// of operations into an atomic sequence) and via PIN presentation.
///
/// Depending on the [`State`] of the card and the access privileges that are associated with that
/// state, different operations can be performed. In many cases, client software will want to
/// transition between states while performing one workflow for the user.
pub struct Card<S>
where
    S: State,
{
    state: S,
}

impl Card<Open> {
    /// Takes an iterator over [`CardBackend`]s, tries to SELECT the OpenPGP card
    /// application on each of them, and checks if its application id matches
    /// `ident`.
    /// Returns a [`Card<Open>`] for the first match, if any.
    pub fn open_by_ident(
        cards: impl Iterator<Item = Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>>,
        ident: &str,
    ) -> Result<Self, Error> {
        for b in cards.filter_map(|c| c.ok()) {
            let mut card = Self::new(b)?;

            let aid = {
                let mut tx = card.transaction()?;
                tx.state.ard().application_id()?
            };

            if aid.ident() == ident.to_ascii_uppercase() {
                return Ok(card);
            }
        }

        Err(Error::InternalError(format!(
            "Couldn't find card {}",
            ident
        )))
    }

    /// Returns a [`Card<Open>`] based on `backend` (after SELECTing the
    /// OpenPGP card application).
    pub fn new<B>(backend: B) -> Result<Self, Error>
    where
        B: Into<Box<dyn CardBackend + Send + Sync>>,
    {
        let pgp = crate::ocard::OpenPGP::new(backend)?;

        Ok(Card::<Open> {
            state: Open { pgp },
        })
    }

    /// Starts a transaction on the underlying backend (if the backend
    /// implementation supports transactions, otherwise the backend
    /// will operate without transaction guarantees).
    ///
    /// The resulting [`Card<Transaction>`] object allows performing
    /// operations on the card.
    pub fn transaction(&mut self) -> Result<Card<Transaction<'_>>, Error> {
        let opt = self.state.pgp.transaction()?;

        Card::<Transaction>::new(opt)
    }

    /// Retrieve the underlying [`CardBackend`].
    ///
    /// This is useful to take the card object into a different context
    /// (e.g. to perform operations on the card with the `yubikey-management`
    /// crate, without closing the connection to the card).
    pub fn into_backend(self) -> Box<dyn CardBackend + Send + Sync> {
        self.state.pgp.into_card()
    }
}

impl<'a> Card<Transaction<'a>> {
    /// Internal constructor
    fn new(mut opt: crate::ocard::Transaction<'a>) -> Result<Self, Error> {
        let ard = opt.application_related_data()?;

        Ok(Self {
            state: Transaction::new(opt, ard),
        })
    }

    // FIXME: remove later?
    pub fn card(&mut self) -> &mut crate::ocard::Transaction<'a> {
        &mut self.state.opt
    }

    /// Drop cached "application related data" and "kdf do" in this [Card] instance.
    ///
    /// This is necessary e.g. after importing or generating keys on a card, to
    /// drop the now obsolete cached [`crate::ocard::data::ApplicationRelatedData`] and [`KdfDo`].
    pub fn invalidate_cache(&mut self) -> Result<(), Error> {
        self.state.invalidate_cache();
        Ok(())
    }

    /// True if the reader for this card supports PIN verification with a pin pad.
    pub fn feature_pinpad_verify(&mut self) -> bool {
        self.state.opt.feature_pinpad_verify()
    }

    /// True if the reader for this card supports PIN modification with a pin pad.
    pub fn feature_pinpad_modify(&mut self) -> bool {
        self.state.opt.feature_pinpad_modify()
    }

    /// Verify the User PIN (for operations such as decryption)
    pub fn verify_user_pin(&mut self, pin: SecretString) -> Result<(), Error> {
        let kdf = verification_kdf(self.state.opt.kdf_do())?;
        let pin = map_pin(pin, PinType::Pw1, kdf.as_ref())?;

        self.state.opt.verify_pw1_user(pin)?;
        self.state.pw1 = true;

        self.state.invalidate_cache_ard();
        Ok(())
    }

    /// Verify the User PIN with a physical PIN pad (if available,
    /// see [`Self::feature_pinpad_verify`]).
    pub fn verify_user_pinpad(&mut self, pinpad_prompt: &dyn Fn()) -> Result<(), Error> {
        pinpad_prompt();

        self.state.opt.verify_pw1_user_pinpad()?;
        self.state.pw1 = true;

        self.state.invalidate_cache_ard();
        Ok(())
    }

    /// Verify the User PIN for signing operations.
    ///
    /// (Note that depending on the configuration of the card, this may enable
    /// performing just one signing operation, or an unlimited amount of
    /// signing operations).
    pub fn verify_user_signing_pin(&mut self, pin: SecretString) -> Result<(), Error> {
        let kdf = verification_kdf(self.state.opt.kdf_do())?;
        let pin = map_pin(pin, PinType::Pw1, kdf.as_ref())?;

        self.state.opt.verify_pw1_sign(pin)?;

        // FIXME: depending on card mode, pw1_sign is only usable once
        self.state.pw1_sign = true;

        self.state.invalidate_cache_ard();
        Ok(())
    }

    /// Verify the User PIN for signing operations with a physical PIN pad
    /// (if available, see [`Self::feature_pinpad_verify`]).
    pub fn verify_user_signing_pinpad(&mut self, pinpad_prompt: &dyn Fn()) -> Result<(), Error> {
        pinpad_prompt();

        self.state.opt.verify_pw1_sign_pinpad()?;

        // FIXME: depending on card mode, pw1_sign is only usable once
        self.state.pw1_sign = true;

        self.state.invalidate_cache_ard();
        Ok(())
    }

    /// Verify the Admin PIN.
    pub fn verify_admin_pin(&mut self, pin: SecretString) -> Result<(), Error> {
        let kdf = verification_kdf(self.state.opt.kdf_do())?;
        let pin = map_pin(pin, PinType::Pw3, kdf.as_ref())?;

        self.state.opt.verify_pw3(pin)?;
        self.state.pw3 = true;

        self.state.invalidate_cache_ard();
        Ok(())
    }

    /// Verify the Admin PIN with a physical PIN pad
    /// (if available, see [`Self::feature_pinpad_verify`]).
    pub fn verify_admin_pinpad(&mut self, pinpad_prompt: &dyn Fn()) -> Result<(), Error> {
        pinpad_prompt();

        self.state.opt.verify_pw3_pinpad()?;
        self.state.pw3 = true;

        self.state.invalidate_cache_ard();
        Ok(())
    }

    /// Ask the card if the user password has been successfully verified.
    ///
    /// NOTE: on some cards this functionality seems broken and may decrease
    /// the pin's error count!
    pub fn check_user_verified(&mut self) -> Result<(), Error> {
        self.state.opt.check_pw1_user()
    }

    /// Ask the card if the admin password has been successfully verified.
    ///
    /// NOTE: on some cards this functionality seems broken and may decrease
    /// the pin's error count!
    pub fn check_admin_verified(&mut self) -> Result<(), Error> {
        self.state.opt.check_pw3()
    }

    /// Change the User PIN, based on the old User PIN.
    pub fn change_user_pin(&mut self, old: SecretString, new: SecretString) -> Result<(), Error> {
        let kdf = verification_kdf(self.state.opt.kdf_do())?;
        let old = map_pin(old, PinType::Pw1, kdf.as_ref())?;
        let new = map_pin(new, PinType::Pw1, kdf.as_ref())?;

        self.state.opt.change_pw1(old, new)?;

        self.state.invalidate_cache_ard();
        Ok(())
    }

    /// Change the User PIN, based on the old User PIN, with a physical PIN
    /// pad (if available, see [`Self::feature_pinpad_modify`]).
    pub fn change_user_pin_pinpad(&mut self, pinpad_prompt: &dyn Fn()) -> Result<(), Error> {
        pinpad_prompt();
        self.state.opt.change_pw1_pinpad()?;

        self.state.invalidate_cache_ard();
        Ok(())
    }

    /// Change the User PIN, based on the resetting code `rst`.
    pub fn reset_user_pin(&mut self, rst: SecretString, new: SecretString) -> Result<(), Error> {
        let rst = map_pin(rst, PinType::Rc, self.state.kdf_do()?)?;
        let new = map_pin(new, PinType::Pw1, self.state.kdf_do()?)?;

        self.state.opt.reset_retry_counter_pw1(new, Some(rst))?;

        self.state.invalidate_cache_ard();
        Ok(())
    }

    /// Change the Admin PIN, based on the old Admin PIN.
    pub fn change_admin_pin(&mut self, old: SecretString, new: SecretString) -> Result<(), Error> {
        let kdf = verification_kdf(self.state.opt.kdf_do())?;
        let old = map_pin(old, PinType::Pw3, kdf.as_ref())?;
        let new = map_pin(new, PinType::Pw3, kdf.as_ref())?;

        self.state.opt.change_pw3(old, new)?;

        self.state.invalidate_cache_ard();
        Ok(())
    }

    /// Change the Admin PIN, based on the old Admin PIN, with a physical PIN
    /// pad (if available, see [`Self::feature_pinpad_modify`]).
    pub fn change_admin_pin_pinpad(&mut self, pinpad_prompt: &dyn Fn()) -> Result<(), Error> {
        pinpad_prompt();
        self.state.opt.change_pw3_pinpad()?;

        self.state.invalidate_cache_ard();
        Ok(())
    }

    /// Get a view of the card in the [`Card<User>`] state, and authenticate
    /// for that state with `pin`, if available.
    ///
    /// If `pin` is not None, `verify_user` is called with that pin.
    pub fn as_user_card<'b, P>(&'b mut self, pin: P) -> Result<Card<User<'a, 'b>>, Error>
    where
        P: Into<OptionalPin>,
    {
        let pin: OptionalPin = pin.into();

        if let Some(pin) = pin.0 {
            self.verify_user_pin(pin)?;
        }

        Ok(Card::<User> {
            state: User { tx: self },
        })
    }

    /// Get a view of the card in the [`Card<Sign>`] state, and authenticate
    /// for that state with `pin`, if available.
    ///
    /// If `pin` is not None, `verify_user_for_signing` is called with that pin.
    pub fn as_signing_card<'b, P>(&'b mut self, pin: P) -> Result<Card<Sign<'a, 'b>>, Error>
    where
        P: Into<OptionalPin>,
    {
        let pin: OptionalPin = pin.into();

        if let Some(pin) = pin.0 {
            self.verify_user_signing_pin(pin)?;
        }

        Ok(Card::<Sign> {
            state: Sign { tx: self },
        })
    }

    /// Get a view of the card in the [`Card<Admin>`] state, and authenticate
    /// for that state with `pin`, if available.
    ///
    /// If `pin` is not None, `verify_admin` is called with that pin.
    pub fn as_admin_card<'b, P>(&'b mut self, pin: P) -> Result<Card<Admin<'a, 'b>>, Error>
    where
        P: Into<OptionalPin>,
    {
        let pin: OptionalPin = pin.into();

        if let Some(pin) = pin.0 {
            self.verify_admin_pin(pin)?;
        }

        Ok(Card::<Admin> {
            state: Admin { tx: self },
        })
    }

    // --- application data ---

    /// The Application Identifier is unique for each card.
    /// It includes a manufacturer code and serial number.
    ///
    /// (This is an immutable field on the card. The value is cached in the
    /// underlying Card object. It can be retrieved without incurring a call
    /// to the card)
    pub fn application_identifier(&self) -> Result<ApplicationIdentifier, Error> {
        // Use immutable data cache from underlying Card object
        self.state.opt.application_identifier()
    }

    /// The "Extended Capabilities" data object describes features of a card
    /// to the caller.
    /// This includes the availability and length of various data fields.
    ///
    /// (This is an immutable field on the card. The value is cached in the
    /// underlying Card object. It can be retrieved without incurring a call
    /// to the card)
    pub fn extended_capabilities(&self) -> Result<ExtendedCapabilities, Error> {
        // Use immutable data cache from underlying Card object
        self.state.opt.extended_capabilities()
    }

    /// The "Historical Bytes" data object describes features of a card
    /// to the caller.
    /// The information in this field is probably not relevant for most
    /// users of this library, however, some of it is used for the internal
    /// operation of the `openpgp-card` library.
    ///
    /// (This is an immutable field on the card. The value is cached in the
    /// underlying Card object. It can be retrieved without incurring a call
    /// to the card)
    pub fn historical_bytes(&self) -> Result<HistoricalBytes, Error> {
        // Use immutable data cache from underlying Card object
        match self.state.opt.historical_bytes()? {
            Some(hb) => Ok(hb),
            None => Err(Error::NotFound(
                "Card doesn't have historical bytes DO".to_string(),
            )),
        }
    }

    /// The "Extended Length Information" data object was introduced in
    /// version 3.0 of the OpenPGP card standard.
    ///
    /// The information in this field should not be relevant for
    /// users of this library.
    /// However, it is used for the internal operation of the `openpgp-card`
    /// library.
    ///
    /// (This is an immutable field on the card. The value is cached in the
    /// underlying Card object. It can be retrieved without incurring a call
    /// to the card)
    pub fn extended_length_information(&self) -> Result<Option<ExtendedLengthInfo>, Error> {
        // Use immutable data cache from underlying Card object
        self.state.opt.extended_length_info()
    }

    // fn general_feature_management() -> Option<bool> {
    //     unimplemented!()
    // }

    // fn discretionary_data_objects() {
    //     unimplemented!()
    // }

    /// PW Status Bytes
    pub fn pw_status_bytes(&mut self) -> Result<PWStatusBytes, Error> {
        self.state.ard().pw_status_bytes()
    }

    /// Get algorithm attributes for a key slot.
    pub fn algorithm_attributes(
        &mut self,
        key_type: KeyType,
    ) -> Result<AlgorithmAttributes, Error> {
        self.state.ard().algorithm_attributes(key_type)
    }

    /// Get the Fingerprints for the three basic [`KeyType`]s.
    ///
    /// (The fingerprints for the three basic key slots are stored in a
    /// shared field on the card, thus they can be retrieved in one go)
    pub fn fingerprints(&mut self) -> Result<KeySet<Fingerprint>, Error> {
        self.state.ard().fingerprints()
    }

    /// Get the Fingerprint for one [`KeyType`].
    ///
    /// This function allows retrieval for all slots, including
    /// [`KeyType::Attestation`], if available.
    pub fn fingerprint(&mut self, key_type: KeyType) -> Result<Option<Fingerprint>, Error> {
        let fp = match key_type {
            KeyType::Signing => self.fingerprints()?.signature().cloned(),
            KeyType::Decryption => self.fingerprints()?.decryption().cloned(),
            KeyType::Authentication => self.fingerprints()?.authentication().cloned(),
            KeyType::Attestation => self.state.ard().attestation_key_fingerprint()?,
        };

        Ok(fp)
    }

    /// Get the Key Creation Times for the three basic [`KeyType`]s.
    ///
    /// (The creation time for the three basic key slots are stored in a
    /// shared field on the card, thus they can be retrieved in one go)
    pub fn key_generation_times(&mut self) -> Result<KeySet<KeyGenerationTime>, Error> {
        self.state.ard().key_generation_times()
    }

    /// Get the Key Creation Time for one [`KeyType`].
    ///
    /// This function allows retrieval for all slots, including
    /// [`KeyType::Attestation`], if available.
    pub fn key_generation_time(
        &mut self,
        key_type: KeyType,
    ) -> Result<Option<KeyGenerationTime>, Error> {
        let ts = match key_type {
            KeyType::Signing => self.key_generation_times()?.signature().cloned(),
            KeyType::Decryption => self.key_generation_times()?.decryption().cloned(),
            KeyType::Authentication => self.key_generation_times()?.authentication().cloned(),
            KeyType::Attestation => self.state.ard().attestation_key_generation_time()?,
        };

        Ok(ts)
    }

    pub fn key_information(&mut self) -> Result<Option<KeyInformation>, Error> {
        self.state.ard().key_information()
    }

    /// Get the [`UserInteractionFlag`] for a key slot.
    /// This includes the [`TouchPolicy`], if the card supports touch
    /// confirmation.
    pub fn user_interaction_flag(
        &mut self,
        key_type: KeyType,
    ) -> Result<Option<UserInteractionFlag>, Error> {
        match key_type {
            KeyType::Signing => self.state.ard().uif_pso_cds(),
            KeyType::Decryption => self.state.ard().uif_pso_dec(),
            KeyType::Authentication => self.state.ard().uif_pso_aut(),
            KeyType::Attestation => self.state.ard().uif_attestation(),
        }
    }

    /// List of CA-Fingerprints of “Ultimately Trusted Keys”.
    /// May be used to verify Public Keys from servers.
    pub fn ca_fingerprints(&mut self) -> Result<[Option<Fingerprint>; 3], Error> {
        self.state.ard().ca_fingerprints()
    }

    /// Get optional "Private use" data from the card.
    ///
    /// The presence and maximum length of these DOs is announced
    /// in [`ExtendedCapabilities`].
    ///
    /// If available, there are 4 data fields for private use:
    ///
    /// - `1`: read accessible without PIN verification
    /// - `2`: read accessible without PIN verification
    /// - `3`: read accessible with User PIN verification
    /// - `4`: read accessible with Admin PIN verification
    pub fn private_use_do(&mut self, num: u8) -> Result<Vec<u8>, Error> {
        self.state.opt.private_use_do(num)
    }

    /// Login Data
    ///
    /// This DO can be used to store any information used for the Log-In
    /// process in a client/server authentication (e.g. user name of a
    /// network).
    /// The maximum length of this DO is announced in Extended Capabilities.
    pub fn login_data(&mut self) -> Result<Vec<u8>, Error> {
        self.state.opt.login_data()
    }

    // --- URL (5f50) ---

    /// Get "cardholder" URL from the card.
    ///
    /// "The URL should contain a link to a set of public keys in OpenPGP format, related to
    /// the card."
    pub fn url(&mut self) -> Result<String, Error> {
        Ok(String::from_utf8_lossy(&self.state.opt.url()?).to_string())
    }

    /// Cardholder related data (contains the fields: Name, Language preferences and Sex)
    pub fn cardholder_related_data(&mut self) -> Result<CardholderRelatedData, Error> {
        self.state.opt.cardholder_related_data()
    }

    // Unicode codepoints are a superset of iso-8859-1 characters
    fn latin1_to_string(s: &[u8]) -> String {
        s.iter().map(|&c| c as char).collect()
    }

    /// Get cardholder name.
    ///
    /// This is an ISO 8859-1 (Latin 1) String of up to 39 characters.
    ///
    /// Note that the standard specifies that this field should be encoded
    /// according to ISO/IEC 7501-1:
    ///
    /// "The data element consists of surname (e. g. family name and given
    /// name(s)) and forename(s) (including name suffix, e. g., Jr. and number).
    /// Each item is separated by a ´<´ filler character (3C), the family- and
    /// fore-name(s) are separated by two ´<<´ filler characters."
    ///
    /// This library doesn't perform this encoding.
    pub fn cardholder_name(&mut self) -> Result<String, Error> {
        let crd = self.state.opt.cardholder_related_data()?;

        match crd.name() {
            Some(name) => Ok(Self::latin1_to_string(name)),
            None => Ok("".to_string()),
        }
    }

    /// Get the current digital signature count (how many signatures have been issued by the card)
    pub fn digital_signature_count(&mut self) -> Result<u32, Error> {
        Ok(self
            .state
            .opt
            .security_support_template()?
            .signature_count())
    }

    /// SELECT DATA ("select a DO in the current template").
    pub fn select_data(&mut self, num: u8, tag: &[u8]) -> Result<(), Error> {
        self.state.opt.select_data(num, tag)
    }

    /// Get cardholder certificate.
    ///
    /// Call select_data() before calling this fn to select a particular
    /// certificate (if the card supports multiple certificates).
    pub fn cardholder_certificate(&mut self) -> Result<Vec<u8>, Error> {
        self.state.opt.cardholder_certificate()
    }

    /// "GET NEXT DATA" for the DO cardholder certificate.
    ///
    /// Cardholder certificate data for multiple slots can be read from the card by first calling
    /// cardholder_certificate(), followed by up to two calls to  next_cardholder_certificate().
    pub fn next_cardholder_certificate(&mut self) -> Result<Vec<u8>, Error> {
        self.state.opt.next_cardholder_certificate()
    }

    /// Get KDF DO configuration (from cache).
    pub fn kdf_do(&mut self) -> Result<KdfDo, Error> {
        if let Some(kdf) = self.state.kdf_do()? {
            Ok(kdf.clone())
        } else {
            Err(Error::NotFound("No KDF DO found".to_string()))
        }
    }

    /// Algorithm Information (list of supported Algorithm attributes).
    pub fn algorithm_information(&mut self) -> Result<Option<AlgorithmInformation>, Error> {
        // The DO "Algorithm Information" (Tag FA) shall be present if
        // Algorithm attributes can be changed
        let ec = self.extended_capabilities()?;
        if !ec.algo_attrs_changeable() {
            // Algorithm attributes can not be changed,
            // list_supported_algo is not supported
            return Ok(None);
        }

        self.state.opt.algorithm_information()
    }

    /// "MANAGE SECURITY ENVIRONMENT".
    /// Make `key_ref` usable for the operation normally done by the key
    /// designated by `for_operation`
    pub fn manage_security_environment(
        &mut self,
        for_operation: KeyType,
        key_ref: KeyType,
    ) -> Result<(), Error> {
        self.state
            .opt
            .manage_security_environment(for_operation, key_ref)
    }

    // ----------

    /// Get "Attestation Certificate (Yubico)"
    pub fn attestation_certificate(&mut self) -> Result<Vec<u8>, Error> {
        self.state.opt.attestation_certificate()
    }

    /// Firmware Version, YubiKey specific (?)
    pub fn firmware_version(&mut self) -> Result<Vec<u8>, Error> {
        self.state.opt.firmware_version()
    }

    /// Set "identity", Nitrokey Start specific (possible values: 0, 1, 2).
    /// <https://docs.nitrokey.com/start/windows/multiple-identities.html>
    ///
    /// A Nitrokey Start can present as 3 different virtual OpenPGP cards.
    /// This command enables one of those virtual cards.
    ///
    /// Each virtual card identity behaves like a separate, independent OpenPGP card.
    pub fn set_identity(&mut self, id: u8) -> Result<(), Error> {
        // FIXME: what is in the returned data - is it ever useful?
        let _ = self.state.opt.set_identity(id)?;

        Ok(())
    }

    // ----------

    /// Get the raw public key material for a key slot on the card
    pub fn public_key_material(&mut self, key_type: KeyType) -> Result<PublicKeyMaterial, Error> {
        self.state.opt.public_key(key_type)
    }

    // ----------

    /// Reset all state on this OpenPGP card
    pub fn factory_reset(&mut self) -> Result<(), Error> {
        match self.state.opt.factory_reset() {
            Ok(()) => {
                self.state.invalidate_cache();
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

impl<'app> Card<User<'app, '_>> {
    /// Helper fn to easily access underlying openpgp_card object
    fn card(&mut self) -> &mut crate::ocard::Transaction<'app> {
        &mut self.state.tx.state.opt
    }

    // FIXME

    // pub fn decryptor(
    //     &mut self,
    //     touch_prompt: &'open (dyn Fn() + Send + Sync),
    // ) -> Result<CardDecryptor<'_, 'app>, Error> {
    //     let pk = self
    //         .state
    //         .tx
    //         .public_key(KeyType::Decryption)?
    //         .expect("Couldn't get decryption pubkey from card");
    //
    //     Ok(CardDecryptor::with_pubkey(self.card(), pk, touch_prompt))
    // }
    //
    // pub fn decryptor_from_public(
    //     &mut self,
    //     pubkey: PublicKey,
    //     touch_prompt: &'open (dyn Fn() + Send + Sync),
    // ) -> CardDecryptor<'_, 'app> {
    //     CardDecryptor::with_pubkey(self.card(), pubkey, touch_prompt)
    // }
    //
    // pub fn authenticator(
    //     &mut self,
    //     touch_prompt: &'open (dyn Fn() + Send + Sync),
    // ) -> Result<CardSigner<'_, 'app>, Error> {
    //     let pk = self
    //         .state
    //         .tx
    //         .public_key(KeyType::Authentication)?
    //         .expect("Couldn't get authentication pubkey from card");
    //
    //     Ok(CardSigner::with_pubkey_for_auth(
    //         self.card(),
    //         pk,
    //         touch_prompt,
    //     ))
    // }
    // pub fn authenticator_from_public(
    //     &mut self,
    //     pubkey: PublicKey,
    //     touch_prompt: &'open (dyn Fn() + Send + Sync),
    // ) -> CardSigner<'_, 'app> {
    //     CardSigner::with_pubkey_for_auth(self.card(), pubkey, touch_prompt)
    // }

    /// Set optional "Private use" data on the card.
    ///
    /// The presence and maximum length of these DOs is announced
    /// in [`ExtendedCapabilities`].
    ///
    /// If available, there are 4 data fields for private use:
    ///
    /// - `1`: write accessible with User PIN verification
    /// - `2`: write accessible with Admin PIN verification
    /// - `3`: write accessible with User PIN verification
    /// - `4`: write accessible with Admin PIN verification
    pub fn set_private_use_do(&mut self, num: u8, data: Vec<u8>) -> Result<(), Error> {
        self.card().set_private_use_do(num, data)
    }
}

impl<'app, 'open> Card<Sign<'app, 'open>> {
    /// Helper fn to easily access underlying openpgp_card object
    fn card(&mut self) -> &mut crate::ocard::Transaction<'app> {
        &mut self.state.tx.state.opt
    }

    // FIXME

    // pub fn signer(
    //     &mut self,
    //     touch_prompt: &'open (dyn Fn() + Send + Sync),
    // ) -> Result<CardSigner<'_, 'app>, Error> {
    //     // FIXME: depending on the setting in "PW1 Status byte", only one
    //     // signature can be made after verification for signing
    //
    //     let pk = self
    //         .state
    //         .tx
    //         .public_key(KeyType::Signing)?
    //         .expect("Couldn't get signing pubkey from card");
    //
    //     Ok(CardSigner::with_pubkey(self.card(), pk, touch_prompt))
    // }
    //
    // pub fn signer_from_public(
    //     &mut self,
    //     pubkey: PublicKey,
    //     touch_prompt: &'open (dyn Fn() + Send + Sync),
    // ) -> CardSigner<'_, 'app> {
    //     // FIXME: depending on the setting in "PW1 Status byte", only one
    //     // signature can be made after verification for signing
    //
    //     CardSigner::with_pubkey(self.card(), pubkey, touch_prompt)
    // }

    /// Generate Attestation (Yubico)
    pub fn generate_attestation(
        &mut self,
        key_type: KeyType,
        touch_prompt: &'open (dyn Fn() + Send + Sync),
    ) -> Result<(), Error> {
        // Touch is required if:
        // - the card supports the feature
        // - and the policy is set to a value other than 'Off'
        if let Some(uif) = self.state.tx.state.ard().uif_attestation()? {
            if uif.touch_policy().touch_required() {
                (touch_prompt)();
            }
        }

        self.card().generate_attestation(key_type)
    }
}

impl<'app> Card<Admin<'app, '_>> {
    pub fn as_transaction(&'_ mut self) -> &mut Card<Transaction<'app>> {
        self.state.tx
    }

    /// Helper fn to easily access underlying openpgp_card object
    fn card(&mut self) -> &mut crate::ocard::Transaction<'app> {
        &mut self.state.tx.state.opt
    }
}

impl Card<Admin<'_, '_>> {
    /// Set cardholder name.
    ///
    /// This is an ISO 8859-1 (Latin 1) String of max. 39 characters.
    ///
    /// Note that the standard specifies that this field should be encoded according
    /// to ISO/IEC 7501-1:
    ///
    /// "The data element consists of surname (e. g. family name and given
    /// name(s)) and forename(s) (including name suffix, e. g., Jr. and number).
    /// Each item is separated by a ´<´ filler character (3C), the family- and
    /// fore-name(s) are separated by two ´<<´ filler characters."
    ///
    /// This library doesn't perform this encoding.
    pub fn set_cardholder_name(&mut self, name: &str) -> Result<(), Error> {
        // All chars must be in ASCII7
        if !name.is_ascii() {
            return Err(Error::InternalError("Invalid char in name".into()));
        };

        // FIXME: encode spaces and do ordering

        if name.len() >= 40 {
            return Err(Error::InternalError("name too long".into()));
        }

        self.card().set_name(name.as_bytes())
    }

    pub fn set_lang(&mut self, lang: &[Lang]) -> Result<(), Error> {
        if lang.len() > 8 {
            return Err(Error::InternalError("lang too long".into()));
        }

        self.card().set_lang(lang)
    }

    pub fn set_sex(&mut self, sex: Sex) -> Result<(), Error> {
        self.card().set_sex(sex)
    }

    /// Set optional "Private use" data on the card.
    ///
    /// The presence and maximum length of these DOs is announced
    /// in [`ExtendedCapabilities`].
    ///
    /// If available, there are 4 data fields for private use:
    ///
    /// - `1`: write accessible with User PIN verification
    /// - `2`: write accessible with Admin PIN verification
    /// - `3`: write accessible with User PIN verification
    /// - `4`: write accessible with Admin PIN verification
    pub fn set_private_use_do(&mut self, num: u8, data: Vec<u8>) -> Result<(), Error> {
        self.card().set_private_use_do(num, data)
    }

    pub fn set_login_data(&mut self, login_data: &[u8]) -> Result<(), Error> {
        self.card().set_login(login_data)
    }

    /// Set "cardholder" URL on the card.
    ///
    /// "The URL should contain a link to a set of public keys in OpenPGP format, related to
    /// the card."
    pub fn set_url(&mut self, url: &str) -> Result<(), Error> {
        if !url.is_ascii() {
            return Err(Error::InternalError("Invalid char in url".into()));
        }

        // Check for max len
        let ec = self.state.tx.extended_capabilities()?;

        if url.len() <= ec.max_len_special_do().unwrap_or(u16::MAX) as usize {
            // If we don't know the max length for URL ("special DO"),
            // or if it's within the acceptable length:
            // send the url update to the card.

            self.card().set_url(url.as_bytes())
        } else {
            Err(Error::InternalError("URL too long".into()))
        }
    }

    /// Set PW Status Bytes.
    ///
    /// According to the spec, length information should not be changed.
    ///
    /// If `long` is false, sends 1 byte to the card, otherwise 4.
    ///
    /// So, effectively, with `long == false` the setting `pw1_cds_multi`
    /// can be changed.
    /// With `long == true`, the settings `pw1_pin_block` and `pw3_pin_block`
    /// can also be changed.
    pub fn set_pw_status_bytes(
        &mut self,
        pw_status: &PWStatusBytes,
        long: bool,
    ) -> Result<(), Error> {
        self.card().set_pw_status_bytes(pw_status, long)?;

        self.state.tx.state.invalidate_cache_ard();
        Ok(())
    }

    /// Configure the "only valid for one PSO:CDS" setting in PW Status Bytes.
    ///
    /// If `once` is `true`, the User PIN must be verified before each
    /// signing operation on the card.
    /// If `once` is `false`, one User PIN verification is good for an
    /// unlimited number of signing operations.
    pub fn set_user_pin_signing_validity(&mut self, once: bool) -> Result<(), Error> {
        let mut pws = self.as_transaction().pw_status_bytes()?;
        pws.set_pw1_cds_valid_once(once);

        self.set_pw_status_bytes(&pws, false)
    }

    /// Set the touch policy for a key slot (if the card supports this
    /// feature).
    ///
    /// Note that the current touch policy setting (if available) can be read
    /// via [`Card<Transaction>::user_interaction_flag`].
    ///
    /// (Caution: Setting the touch policy of the "Attestation" slot on YubiKey 5 devices
    /// to a variation of "Fixed" is permanent for the lifetime of the hardware device!
    /// It can't be undone with a factory reset!)
    pub fn set_touch_policy(&mut self, key: KeyType, policy: TouchPolicy) -> Result<(), Error> {
        let uif = match key {
            KeyType::Signing => self.state.tx.state.ard().uif_pso_cds()?,
            KeyType::Decryption => self.state.tx.state.ard().uif_pso_dec()?,
            KeyType::Authentication => self.state.tx.state.ard().uif_pso_aut()?,
            KeyType::Attestation => self.state.tx.state.ard().uif_attestation()?,
        };

        if let Some(mut uif) = uif {
            uif.set_touch_policy(policy);

            match key {
                KeyType::Signing => self.card().set_uif_pso_cds(&uif)?,
                KeyType::Decryption => self.card().set_uif_pso_dec(&uif)?,
                KeyType::Authentication => self.card().set_uif_pso_aut(&uif)?,
                KeyType::Attestation => self.card().set_uif_attestation(&uif)?,
            }
        } else {
            return Err(Error::UnsupportedFeature(
                "User Interaction Flag not available".into(),
            ));
        };

        self.state.tx.state.invalidate_cache_ard();
        Ok(())
    }

    /// Set the User PIN on the card (also resets the User PIN error count)
    pub fn reset_user_pin(&mut self, new: SecretString) -> Result<(), Error> {
        let new = map_pin(new, PinType::Pw1, self.state.tx.state.kdf_do()?)?;

        self.card().reset_retry_counter_pw1(new, None)?;

        self.state.tx.state.invalidate_cache_ard();
        Ok(())
    }

    /// Define the "resetting code" on the card
    pub fn set_resetting_code(&mut self, pin: SecretString) -> Result<(), Error> {
        let pin = map_pin(pin, PinType::Rc, self.state.tx.state.kdf_do()?)?;

        self.card().set_resetting_code(pin)?;

        self.state.tx.state.invalidate_cache_ard();
        Ok(())
    }

    /// Set optional AES encryption/decryption key
    /// (32 bytes for AES256, or 16 bytes for AES128),
    /// if the card supports this feature.
    ///
    /// The availability of this feature is announced in
    /// [`Card<Transaction>::extended_capabilities`].
    pub fn set_pso_enc_dec_key(&mut self, key: &[u8]) -> Result<(), Error> {
        self.card().set_pso_enc_dec_key(key)
    }

    /// Import a private key to the card into a specific key slot.
    ///
    /// (The caller needs to make sure that the content of `key` is suitable for `key_type`)
    pub fn import_key(
        &mut self,
        key: &dyn CardUploadableKey,
        key_type: KeyType,
    ) -> Result<(), Error> {
        self.card().key_import(key, key_type)?;

        self.state.tx.state.invalidate_cache_ard();
        Ok(())
    }

    /// Configure the `algorithm_attributes` for key slot `key_type` based on
    /// the algorithm `algo`.
    /// This can be useful in preparation for [`Self::generate_key`].
    ///
    /// This is a convenience wrapper for [`Self::set_algorithm_attributes`]
    /// that determines the exact appropriate [`AlgorithmAttributes`] by
    /// reading information from the card.
    pub fn set_algorithm(&mut self, key_type: KeyType, algo: AlgoSimple) -> Result<(), Error> {
        let attr = algo.matching_algorithm_attributes(self.card(), key_type)?;
        self.set_algorithm_attributes(key_type, &attr)
    }

    /// Configure the key slot `key_type` to `algorithm_attributes`.
    /// This can be useful in preparation for [`Self::generate_key`].
    ///
    /// Note that legal values for [`AlgorithmAttributes`] are card-specific.
    /// Different OpenPGP card implementations may support different
    /// algorithms, sometimes with differing requirements for the encoding
    /// (e.g. field sizes)
    ///
    /// See [`Self::set_algorithm`] for a convenience function that sets
    /// the algorithm attributes based on an [`AlgoSimple`].
    pub fn set_algorithm_attributes(
        &mut self,
        key_type: KeyType,
        algorithm_attributes: &AlgorithmAttributes,
    ) -> Result<(), Error> {
        self.card()
            .set_algorithm_attributes(key_type, algorithm_attributes)?;

        self.state.tx.state.invalidate_cache_ard();
        Ok(())
    }

    /// Generate a new cryptographic key in slot `key_type`, with the currently
    /// configured cryptographic algorithm
    /// (see [`Self::set_algorithm`] for changing the algorithm setting).
    pub fn generate_key(
        &mut self,
        fp_from_pub: fn(
            &PublicKeyMaterial,
            KeyGenerationTime,
            KeyType,
        ) -> Result<Fingerprint, Error>,
        key_type: KeyType,
    ) -> Result<(PublicKeyMaterial, KeyGenerationTime), Error> {
        let res = self.card().generate_key(fp_from_pub, key_type)?;

        self.state.tx.state.invalidate_cache_ard();
        Ok(res)
    }
}

#[cfg(test)]
mod verification_tests;
