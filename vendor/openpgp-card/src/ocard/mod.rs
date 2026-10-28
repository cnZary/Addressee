// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Low-level access to an OpenPGP card application

use std::convert::{TryFrom, TryInto};

use card_backend::{CardBackend, CardCaps, CardTransaction, PinType, SmartcardError};
use crypto::{HashAlgo, SigningAlgo};
use secrecy::{ExposeSecret, SecretBox};

use crate::{
    ocard::{
        algorithm::{AlgorithmAttributes, AlgorithmInformation},
        apdu::{command::Command, response::RawResponse},
        crypto::{CardUploadableKey, Cryptogram, PublicKeyMaterial},
        data::{
            ApplicationIdentifier, ApplicationRelatedData, CardholderRelatedData,
            ExtendedCapabilities, ExtendedLengthInfo, Fingerprint, HistoricalBytes, KdfDo,
            KeyGenerationTime, Lang, PWStatusBytes, SecuritySupportTemplate, Sex,
            UserInteractionFlag,
        },
        tags::{ShortTag, Tags},
        tlv::{value::Value, Tlv},
    },
    Error,
};

pub mod algorithm;
pub(crate) mod apdu;
mod commands;
pub mod crypto;
pub mod data;
pub mod kdf;
mod keys;
pub(crate) mod oid;
pub(crate) mod tags;
pub(crate) mod tlv;

pub(crate) const OPENPGP_APPLICATION: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

/// Identify a Key slot on an OpenPGP card
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum KeyType {
    Signing,
    Decryption,
    Authentication,

    /// Attestation is a Yubico proprietary key slot
    Attestation,
}

impl KeyType {
    /// Get C1/C2/C3/DA values for this KeyTypes, to use as Tag
    pub(crate) fn algorithm_tag(&self) -> ShortTag {
        match self {
            Self::Signing => Tags::AlgorithmAttributesSignature,
            Self::Decryption => Tags::AlgorithmAttributesDecryption,
            Self::Authentication => Tags::AlgorithmAttributesAuthentication,
            Self::Attestation => Tags::AlgorithmAttributesAttestation,
        }
        .into()
    }

    /// Get C7/C8/C9/DB values for this KeyTypes, to use as Tag.
    ///
    /// (NOTE: these Tags are only used for "PUT DO", but GETting
    /// fingerprint information from the card uses the combined Tag C5)
    fn fingerprint_put_tag(&self) -> ShortTag {
        match self {
            Self::Signing => Tags::FingerprintSignature,
            Self::Decryption => Tags::FingerprintDecryption,
            Self::Authentication => Tags::FingerprintAuthentication,
            Self::Attestation => Tags::FingerprintAttestation,
        }
        .into()
    }

    /// Get CE/CF/D0/DD values for this KeyTypes, to use as Tag.
    ///
    /// (NOTE: these Tags are only used for "PUT DO", but GETting
    /// timestamp information from the card uses the combined Tag CD)
    fn timestamp_put_tag(&self) -> ShortTag {
        match self {
            Self::Signing => Tags::GenerationTimeSignature,
            Self::Decryption => Tags::GenerationTimeDecryption,
            Self::Authentication => Tags::GenerationTimeAuthentication,
            Self::Attestation => Tags::GenerationTimeAttestation,
        }
        .into()
    }
}

/// A struct to cache immutable information of a card.
/// Some of the data is stored during [`OpenPGP::new`].
/// Other information can optionally be cached later (e.g. `ai`)
#[derive(Debug)]
struct CardImmutable {
    aid: ApplicationIdentifier,
    ec: ExtendedCapabilities,
    hb: Option<HistoricalBytes>,     // new in v2.0
    eli: Option<ExtendedLengthInfo>, // new in v3.0

    // First `Option` layer encodes if this cache field has been initialized,
    // if `Some`, then the second `Option` layer encodes if the field exists on the card.
    ai: Option<Option<AlgorithmInformation>>, // new in v3.4
}

/// An OpenPGP card object (backed by a CardBackend implementation).
///
/// Most users will probably want to use the `PcscCard` backend from the `card-backend-pcsc` crate.
///
/// Users of this crate can keep a long-lived [`OpenPGP`] object, including in long-running
/// programs. All operations must be performed on a [`Transaction`] (which must be short-lived).
pub struct OpenPGP {
    /// A connection to the smart card
    card: Box<dyn CardBackend + Send + Sync>,

    /// Capabilites of the card, determined from hints by the Backend,
    /// as well as the Application Related Data
    card_caps: Option<CardCaps>,

    /// A cache data structure for information that is immutable on OpenPGP cards.
    /// Some of the information gets initialized when connecting to the card.
    /// Other information may be cached on first read.
    immutable: Option<CardImmutable>,
}

impl OpenPGP {
    /// Turn a [`CardBackend`] into a [`OpenPGP`] object:
    ///
    /// The OpenPGP application is `SELECT`ed, and the card capabilities
    /// of the card are retrieved from the "Application Related Data".
    pub fn new<B>(backend: B) -> Result<Self, Error>
    where
        B: Into<Box<dyn CardBackend + Send + Sync>>,
    {
        let card: Box<dyn CardBackend + Send + Sync> = backend.into();

        let mut op = Self {
            card,
            card_caps: None,
            immutable: None,
        };

        let (caps, imm) = {
            let mut tx = op.transaction()?;
            tx.select()?;

            // Init card_caps
            let ard = tx.application_related_data()?;

            // Determine chaining/extended length support from card
            // metadata and cache this information in the CardTransaction
            // implementation (as a CardCaps)
            let mut ext_support = false;
            let mut chaining_support = false;

            if let Ok(hist) = ard.historical_bytes() {
                if let Some(cc) = hist.card_capabilities() {
                    chaining_support = cc.command_chaining();
                    ext_support = cc.extended_lc_le();
                }
            }

            let ext_cap = ard.extended_capabilities()?;

            // Get max command/response byte sizes from card
            let (max_cmd_bytes, max_rsp_bytes) = if let Ok(Some(eli)) =
                ard.extended_length_information()
            {
                // In card 3.x, max lengths come from ExtendedLengthInfo
                (eli.max_command_bytes(), eli.max_response_bytes())
            } else if let (Some(cmd), Some(rsp)) = (ext_cap.max_cmd_len(), ext_cap.max_resp_len()) {
                // In card 2.x, max lengths come from ExtendedCapabilities
                (cmd, rsp)
            } else {
                // Fallback: use 255 if we have no information from the card
                (255, 255)
            };

            let pw_status = ard.pw_status_bytes()?;
            let pw1_max = pw_status.pw1_max_len();
            let pw3_max = pw_status.pw3_max_len();

            let caps = CardCaps::new(
                ext_support,
                chaining_support,
                max_cmd_bytes,
                max_rsp_bytes,
                pw1_max,
                pw3_max,
            );

            let imm = CardImmutable {
                aid: ard.application_id()?,
                ec: ard.extended_capabilities()?,
                hb: Some(ard.historical_bytes()?),
                eli: ard.extended_length_information()?,
                ai: None, // FIXME: initialize elsewhere?
            };

            drop(tx);

            // General mechanism to ask the backend for amendments to
            // the CardCaps (e.g. to change support for "extended length")
            //
            // Also see https://blog.apdu.fr/posts/2011/05/extended-apdu-status-per-reader/
            let caps = op.card.limit_card_caps(caps);

            (caps, imm)
        };

        log::trace!("set card_caps to: {:x?}", caps);
        op.card_caps = Some(caps);

        log::trace!("set immutable card state to: {:x?}", imm);
        op.immutable = Some(imm);

        Ok(op)
    }

    /// Get the internal `CardBackend`.
    ///
    /// This is useful to perform operations on the card with a different crate,
    /// e.g. `yubikey-management`.
    pub fn into_card(self) -> Box<dyn CardBackend + Send + Sync> {
        self.card
    }

    /// Start a transaction on the underlying CardBackend.
    /// The resulting [Transaction] object allows performing commands on the card.
    ///
    /// Note: Transactions on the Card cannot be long running.
    /// They may be reset by the smart card subsystem within seconds, when idle.
    pub fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        let card_caps = &mut self.card_caps;
        let immutable = &mut self.immutable; // FIXME: unwrap

        let tx = self.card.transaction(Some(OPENPGP_APPLICATION))?;

        if tx.was_reset() {
            // FIXME: Signal state invalidation to the library user?
            // (E.g.: PIN verifications may have been lost.)
        }

        Ok(Transaction {
            tx,
            card_caps,
            immutable,
        })
    }
}

/// To perform commands on a [`OpenPGP`], a [`Transaction`] must be started.
/// This struct offers low-level access to OpenPGP card functionality.
///
/// On backends that support transactions, operations are grouped together in transaction, while
/// an object of this type lives.
///
/// A [`Transaction`] on typical underlying card subsystems must be short lived.
/// (Typically, smart cards can't be kept open for longer than a few seconds,
/// before they are automatically closed.)
pub struct Transaction<'a> {
    tx: Box<dyn CardTransaction + Send + Sync + 'a>,
    card_caps: &'a Option<CardCaps>,
    immutable: &'a mut Option<CardImmutable>,
}

impl Transaction<'_> {
    pub(crate) fn tx(&mut self) -> &mut dyn CardTransaction {
        self.tx.as_mut()
    }

    pub(crate) fn send_command(
        &mut self,
        cmd: Command,
        expect_reply: bool,
    ) -> Result<RawResponse, Error> {
        apdu::send_command(&mut *self.tx, cmd, *self.card_caps, expect_reply)
    }

    // SELECT

    /// Select the OpenPGP card application
    pub fn select(&mut self) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: select");

        self.send_command(commands::select_openpgp()?, false)?
            .try_into()
    }

    // TERMINATE DF

    /// 7.2.16 TERMINATE DF
    pub fn terminate_df(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: terminate_df");

        self.send_command(commands::terminate_df()?, false)?;
        Ok(())
    }

    // ACTIVATE FILE

    /// 7.2.17 ACTIVATE FILE
    pub fn activate_file(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: activate_file");

        self.send_command(commands::activate_file()?, false)?;
        Ok(())
    }

    // --- pinpad ---

    /// Does the reader support FEATURE_VERIFY_PIN_DIRECT?
    pub fn feature_pinpad_verify(&self) -> bool {
        self.tx.feature_pinpad_verify()
    }

    /// Does the reader support FEATURE_MODIFY_PIN_DIRECT?
    pub fn feature_pinpad_modify(&self) -> bool {
        self.tx.feature_pinpad_modify()
    }

    // --- get data ---

    /// Get the "application related data" from the card.
    ///
    /// (This data should probably be cached in a higher layer. Some parts of
    /// it are needed regularly, and it does not usually change during
    /// normal use of a card.)
    pub fn application_related_data(&mut self) -> Result<ApplicationRelatedData, Error> {
        log::info!("OpenPgpTransaction: application_related_data");

        let resp = self.send_command(commands::application_related_data()?, true)?;
        let value = Value::from(resp.data()?, true)?;

        log::trace!(" ARD value: {:02x?}", value);

        Ok(ApplicationRelatedData(Tlv::new(
            Tags::ApplicationRelatedData,
            value,
        )))
    }

    // -- cached card data --

    /// Get read access to cached immutable card information
    fn card_immutable(&self) -> Result<&CardImmutable, Error> {
        if let Some(imm) = &self.immutable {
            Ok(imm)
        } else {
            // We expect that self.immutable has been initialized here
            Err(Error::InternalError(
                "Unexpected state of immutable cache".to_string(),
            ))
        }
    }

    /// Application Identifier.
    ///
    /// This function returns data that is cached during initialization.
    /// Calling it doesn't require sending a command to the card.
    pub fn application_identifier(&self) -> Result<ApplicationIdentifier, Error> {
        Ok(self.card_immutable()?.aid)
    }

    /// Extended capabilities.
    ///
    /// This function returns data that is cached during initialization.
    /// Calling it doesn't require sending a command to the card.
    pub fn extended_capabilities(&self) -> Result<ExtendedCapabilities, Error> {
        Ok(self.card_immutable()?.ec)
    }

    /// Historical Bytes (if available).
    ///
    /// This function returns data that is cached during initialization.
    /// Calling it doesn't require sending a command to the card.
    pub fn historical_bytes(&self) -> Result<Option<HistoricalBytes>, Error> {
        Ok(self.card_immutable()?.hb)
    }

    /// Extended length info (if available).
    ///
    /// This function returns data that is cached during initialization.
    /// Calling it doesn't require sending a command to the card.
    pub fn extended_length_info(&self) -> Result<Option<ExtendedLengthInfo>, Error> {
        Ok(self.card_immutable()?.eli)
    }

    #[allow(dead_code)]
    pub(crate) fn algorithm_information_cached(
        &mut self,
    ) -> Result<Option<AlgorithmInformation>, Error> {
        // FIXME: merge this fn with the regular/public `algorithm_information()` fn?

        // We expect that self.immutable has been initialized here
        match &self.immutable {
            Some(ci) => {
                // We have a cached copy of the data and return it
                if let Some(ai) = &ci.ai {
                    return Ok(ai.clone());
                }
            }
            None => {
                return Err(Error::InternalError(
                    "Unexpected state of immutable cache".to_string(),
                ));
            }
        }

        // Cached AlgorithmInformation is unset in self.immutable, initialize it now
        let ai = self.algorithm_information()?;

        match self.immutable {
            Some(ci) => {
                ci.ai = Some(ai.clone());
                Ok(ai)
            }
            None => Err(Error::InternalError(
                "Unexpected state of immutable cache".to_string(),
            )),
        }
    }

    // --- login data (5e) ---

    /// Get URL (5f50)
    pub fn url(&mut self) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: url");

        self.send_command(commands::url()?, true)?.try_into()
    }

    /// Get Login Data (5e)
    pub fn login_data(&mut self) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: login_data");

        self.send_command(commands::login_data()?, true)?.try_into()
    }

    /// Get cardholder related data (65)
    pub fn cardholder_related_data(&mut self) -> Result<CardholderRelatedData, Error> {
        log::info!("OpenPgpTransaction: cardholder_related_data");

        let resp = self.send_command(commands::cardholder_related_data()?, true)?;

        resp.data()?.try_into()
    }

    /// Get security support template (7a)
    pub fn security_support_template(&mut self) -> Result<SecuritySupportTemplate, Error> {
        log::info!("OpenPgpTransaction: security_support_template");

        let resp = self.send_command(commands::security_support_template()?, true)?;

        let tlv = Tlv::try_from(resp.data()?)?;

        let dst = tlv.find(Tags::DigitalSignatureCounter).ok_or_else(|| {
            Error::NotFound("Couldn't get DigitalSignatureCounter DO".to_string())
        })?;

        if let Value::S(data) = dst {
            let data = match &data[..] {
                // the signature counter should be a three byte value
                [a, b, c] => [0, *a, *b, *c],
                _ => {
                    return Err(Error::ParseError(format!(
                        "Unexpected length {} for DigitalSignatureCounter DO",
                        data.len()
                    )));
                }
            };

            let dsc: u32 = u32::from_be_bytes(data);
            Ok(SecuritySupportTemplate { dsc })
        } else {
            Err(Error::NotFound(
                "Failed to process SecuritySupportTemplate".to_string(),
            ))
        }
    }

    /// Get cardholder certificate (each for AUT, DEC and SIG).
    ///
    /// Call select_data() before calling this fn to select a particular
    /// certificate (if the card supports multiple certificates).
    ///
    /// According to the OpenPGP card specification:
    ///
    /// The cardholder certificate DOs are designed to store a certificate (e. g. X.509)
    /// for the keys in the card. They can be used to identify the card in a client-server
    /// authentication, where specific non-OpenPGP-certificates are needed, for S-MIME and
    /// other x.509 related functions.
    ///
    /// (See <https://support.nitrokey.com/t/nitrokey-pro-and-pkcs-11-support-on-linux/160/4>
    /// for some discussion of the `cardholder certificate` OpenPGP card feature)
    #[allow(dead_code)]
    pub fn cardholder_certificate(&mut self) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: cardholder_certificate");

        self.send_command(commands::cardholder_certificate()?, true)?
            .try_into()
    }

    /// Call "GET NEXT DATA" for the DO cardholder certificate.
    ///
    /// Cardholder certificate data for multiple slots can be read from the card by first calling
    /// cardholder_certificate(), followed by up to two calls to  next_cardholder_certificate().
    pub fn next_cardholder_certificate(&mut self) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: next_cardholder_certificate");

        self.send_command(commands::get_next_cardholder_certificate()?, true)?
            .try_into()
    }

    /// Get "KDF-DO" (announced in Extended Capabilities)
    pub fn kdf_do(&mut self) -> Result<KdfDo, Error> {
        log::info!("OpenPgpTransaction: kdf_do");

        let kdf_do = self
            .send_command(commands::kdf_do()?, true)?
            .data()?
            .try_into()?;

        log::trace!(" KDF DO value: {:02x?}", kdf_do);

        Ok(kdf_do)
    }

    /// Get "Algorithm Information"
    pub fn algorithm_information(&mut self) -> Result<Option<AlgorithmInformation>, Error> {
        log::info!("OpenPgpTransaction: algorithm_information");

        let resp = self.send_command(commands::algo_info()?, true)?;

        let ai = resp.data()?.try_into()?;
        Ok(Some(ai))
    }

    /// Get "Attestation Certificate (Yubico)"
    pub fn attestation_certificate(&mut self) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: attestation_certificate");

        self.send_command(commands::attestation_certificate()?, true)?
            .try_into()
    }

    /// Firmware Version (YubiKey specific (?))
    pub fn firmware_version(&mut self) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: firmware_version");

        self.send_command(commands::firmware_version()?, true)?
            .try_into()
    }

    /// Set identity (Nitrokey Start specific (?)).
    /// [see:
    /// <https://docs.nitrokey.com/start/linux/multiple-identities.html>
    /// <https://github.com/Nitrokey/nitrokey-start-firmware/pull/33/>]
    pub fn set_identity(&mut self, id: u8) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: set_identity");

        let resp = self.send_command(commands::set_identity(id)?, false);

        // Apparently it's normal to get "NotTransacted" from pcsclite when
        // the identity switch was successful.
        if let Err(Error::Smartcard(SmartcardError::NotTransacted)) = resp {
            Ok(vec![])
        } else {
            resp?.try_into()
        }
    }

    /// SELECT DATA ("select a DO in the current template").
    ///
    /// This command currently only applies to
    /// [`cardholder_certificate`](Transaction::cardholder_certificate) and
    /// [`set_cardholder_certificate`](Transaction::set_cardholder_certificate)
    /// in OpenPGP card.
    ///
    /// (This library leaves it up to consumers to decide on a strategy for dealing with this
    /// issue. Possible strategies include:
    /// - asking the card for its [`Transaction::firmware_version`] and using the workaround if
    ///   version <=5.4.3
    /// - trying this command first without the workaround, then with workaround if the card returns
    ///   [`StatusBytes::IncorrectParametersCommandDataField`]
    /// - for read operations: using [`Transaction::next_cardholder_certificate`] instead of SELECT
    ///   DATA)
    pub fn select_data(&mut self, num: u8, tag: &[u8]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: select_data");

        let tlv = Tlv::new(
            Tags::GeneralReference,
            Value::C(vec![Tlv::new(Tags::TagList, Value::S(tag.to_vec()))]),
        );

        let mut data = tlv.serialize();

        // YubiKey 5 up to (and including) firmware version 5.4.3 need a workaround
        // for this command.
        //
        // When sending the SELECT DATA command as defined in the card spec, without enabling the
        // workaround, bad YubiKey firmware versions (<= 5.4.3) return
        // `StatusBytes::IncorrectParametersCommandDataField`
        //
        // FIXME: caching for `firmware_version`?
        if let Ok(version) = self.firmware_version() {
            if version.len() == 3
                && version[0] == 5
                && (version[1] < 4 || (version[1] == 4 && version[2] <= 3))
            {
                // Workaround for YubiKey 5.
                // This hack is needed <= 5.4.3 according to ykman sources
                // (see _select_certificate() in ykman/openpgp.py).

                // Catch blatant misuse: tags are 1-2 bytes long
                if data.len() > 255 {
                    return Err(Error::InternalError(format!(
                        "select_data: exceedingly long data: {}",
                        data.len()
                    )));
                }

                data.insert(0, data.len() as u8);
            }
        }

        let cmd = commands::select_data(num, data)?;

        // Possible response data (Control Parameter = CP) don't need to be evaluated by the
        // application (See "7.2.5 SELECT DATA")
        self.send_command(cmd, true)?.check_ok()?;

        Ok(())
    }

    // --- optional private DOs (0101 - 0104) ---

    /// Get data from "private use" DO.
    ///
    /// `num` must be between 1 and 4.
    pub fn private_use_do(&mut self, num: u8) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: private_use_do");

        let tag = match num {
            1 => Tags::PrivateUse1,
            2 => Tags::PrivateUse2,
            3 => Tags::PrivateUse3,
            4 => Tags::PrivateUse4,
            _ => {
                return Err(Error::UnsupportedFeature(format!(
                    "Illegal Private Use DO num '{}'",
                    num,
                )));
            }
        };

        let cmd = commands::get_data(tag)?;
        self.send_command(cmd, true)?.try_into()
    }

    // ----------

    /// Reset all state on this OpenPGP card.
    ///
    /// Note: the "factory reset" operation is not directly offered by the
    /// card spec. It is implemented as a series of OpenPGP card commands:
    /// - send 4 bad requests to verify pw1,
    /// - send 4 bad requests to verify pw3,
    /// - terminate_df,
    /// - activate_file.
    ///
    /// With most cards, this sequence of operations causes the card
    /// to revert to a "blank" state.
    ///
    /// (However, e.g. vanilla Gnuk doesn't support this functionality.
    /// Gnuk needs to be built with the `--enable-factory-reset`
    /// option to the `configure` script to enable this functionality).
    pub fn factory_reset(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: factory_reset");

        let mut bad_pw_len = 8;

        // In KDF mode, the "bad password" we try must have the correct length for the KDF hash
        // algorithm. Otherwise, the PIN retry counter doesn't decrement, and don't lock the card
        // (which means we don't get to do a reset).
        if let Ok(kdf_do) = self.kdf_do() {
            if kdf_do.hash_algo() == Some(0x08) {
                bad_pw_len = 0x20;
            } else if kdf_do.hash_algo() == Some(0x0a) {
                bad_pw_len = 0x40;
            }
        }

        let bad_pw: Vec<_> = std::iter::repeat_n(0x40, bad_pw_len).collect();

        // send 4 bad requests to verify pw1
        for _ in 0..4 {
            let resp = self.verify_pw1_sign(bad_pw.clone().into());

            if !(matches!(
                resp,
                Err(Error::CardStatus(StatusBytes::SecurityStatusNotSatisfied))
                    | Err(Error::CardStatus(StatusBytes::AuthenticationMethodBlocked))
                    | Err(Error::CardStatus(
                        StatusBytes::ExecutionErrorNonVolatileMemoryUnchanged
                    ))
                    | Err(Error::CardStatus(StatusBytes::PasswordNotChecked(_)))
                    | Err(Error::CardStatus(StatusBytes::ConditionOfUseNotSatisfied))
            )) {
                return Err(Error::InternalError(
                    "Unexpected status for reset, at pw1.".into(),
                ));
            }
        }

        // send 4 bad requests to verify pw3
        for _ in 0..4 {
            let resp = self.verify_pw3(bad_pw.clone().into());

            if !(matches!(
                resp,
                Err(Error::CardStatus(StatusBytes::SecurityStatusNotSatisfied))
                    | Err(Error::CardStatus(StatusBytes::AuthenticationMethodBlocked))
                    | Err(Error::CardStatus(
                        StatusBytes::ExecutionErrorNonVolatileMemoryUnchanged
                    ))
                    | Err(Error::CardStatus(StatusBytes::PasswordNotChecked(_)))
                    | Err(Error::CardStatus(StatusBytes::ConditionOfUseNotSatisfied))
            )) {
                return Err(Error::InternalError(
                    "Unexpected status for reset, at pw3.".into(),
                ));
            }
        }

        self.terminate_df()?;
        self.activate_file()?;

        Ok(())
    }

    // --- verify/modify ---

    /// Verify pw1 (user) for signing operation (mode 81).
    ///
    /// Depending on the PW1 status byte (see Extended Capabilities) this
    /// access condition is only valid for one PSO:CDS command or remains
    /// valid for several attempts.
    pub fn verify_pw1_sign(&mut self, pin: SecretBox<[u8]>) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: verify_pw1_sign");

        let cmd = commands::verify_pw1_81(pin)?;

        self.send_command(cmd, false)?.try_into()
    }

    /// Verify pw1 (user) for signing operation (mode 81) using a
    /// pinpad on the card reader. If no usable pinpad is found, an error
    /// is returned.
    ///
    /// Depending on the PW1 status byte (see Extended Capabilities) this
    /// access condition is only valid for one PSO:CDS command or remains
    /// valid for several attempts.
    pub fn verify_pw1_sign_pinpad(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: verify_pw1_sign_pinpad");

        let cc = *self.card_caps;

        let res = self.tx().pinpad_verify(PinType::Sign, &cc)?;
        RawResponse::try_from(res)?.try_into()
    }

    /// Check the current access of PW1 for signing (mode 81).
    ///
    /// If verification is not required, an empty Ok Response is returned.
    ///
    /// (Note:
    /// - some cards don't correctly implement this feature, e.g. YubiKey 5
    /// - some cards that don't support this instruction may decrease the pin's error count,
    ///   eventually requiring the user to reset the pin)
    pub fn check_pw1_sign(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: check_pw1_sign");

        let verify = commands::verify_pw1_81(vec![].into())?;
        self.send_command(verify, false)?.try_into()
    }

    /// Verify PW1 (user).
    /// (For operations except signing, mode 82).
    pub fn verify_pw1_user(&mut self, pin: SecretBox<[u8]>) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: verify_pw1_user");

        let verify = commands::verify_pw1_82(pin)?;
        self.send_command(verify, false)?.try_into()
    }

    /// Verify PW1 (user) for operations except signing (mode 82),
    /// using a pinpad on the card reader. If no usable pinpad is found,
    /// an error is returned.
    pub fn verify_pw1_user_pinpad(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: verify_pw1_user_pinpad");

        let cc = *self.card_caps;

        let res = self.tx().pinpad_verify(PinType::User, &cc)?;
        RawResponse::try_from(res)?.try_into()
    }

    /// Check the current access of PW1.
    /// (For operations except signing, mode 82).
    ///
    /// If verification is not required, an empty Ok Response is returned.
    ///
    /// (Note:
    /// - some cards don't correctly implement this feature, e.g. YubiKey 5
    /// - some cards that don't support this instruction may decrease the pin's error count,
    ///   eventually requiring the user to reset the pin)
    pub fn check_pw1_user(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: check_pw1_user");

        let verify = commands::verify_pw1_82(vec![].into())?;
        self.send_command(verify, false)?.try_into()
    }

    /// Verify PW3 (admin).
    pub fn verify_pw3(&mut self, pin: SecretBox<[u8]>) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: verify_pw3");

        let verify = commands::verify_pw3(pin)?;
        self.send_command(verify, false)?.try_into()
    }

    /// Verify PW3 (admin) using a pinpad on the card reader. If no usable
    /// pinpad is found, an error is returned.
    pub fn verify_pw3_pinpad(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: verify_pw3_pinpad");

        let cc = *self.card_caps;

        let res = self.tx().pinpad_verify(PinType::Admin, &cc)?;
        RawResponse::try_from(res)?.try_into()
    }

    /// Check the current access of PW3 (admin).
    ///
    /// If verification is not required, an empty Ok Response is returned.
    ///
    /// (Note:
    /// - some cards don't correctly implement this feature, e.g. YubiKey 5
    /// - some cards that don't support this instruction may decrease the pin's error count,
    ///   eventually requiring the user to factory reset the card)
    pub fn check_pw3(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: check_pw3");

        let verify = commands::verify_pw3(vec![].into())?;
        self.send_command(verify, false)?.try_into()
    }

    /// Change the value of PW1 (user password).
    ///
    /// The current value of PW1 must be presented in `old` for authorization.
    pub fn change_pw1(&mut self, old: SecretBox<[u8]>, new: SecretBox<[u8]>) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: change_pw1");

        let mut data = vec![];
        data.extend(old.expose_secret());
        data.extend(new.expose_secret());

        let change = commands::change_pw1(data.into())?;
        self.send_command(change, false)?.try_into()
    }

    /// Change the value of PW1 (0x81) using a pinpad on the
    /// card reader. If no usable pinpad is found, an error is returned.
    pub fn change_pw1_pinpad(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: change_pw1_pinpad");

        let cc = *self.card_caps;

        // Note: for change PW, only 0x81 and 0x83 are used!
        // 0x82 is implicitly the same as 0x81.
        let res = self.tx().pinpad_modify(PinType::Sign, &cc)?;
        RawResponse::try_from(res)?.try_into()
    }

    /// Change the value of PW3 (admin password).
    ///
    /// The current value of PW3 must be presented in `old` for authorization.
    pub fn change_pw3(&mut self, old: SecretBox<[u8]>, new: SecretBox<[u8]>) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: change_pw3");

        let mut data = vec![];
        data.extend(old.expose_secret());
        data.extend(new.expose_secret());

        let change = commands::change_pw3(data.into())?;
        self.send_command(change, false)?.try_into()
    }

    /// Change the value of PW3 (admin password) using a pinpad on the
    /// card reader. If no usable pinpad is found, an error is returned.
    pub fn change_pw3_pinpad(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: change_pw3_pinpad");

        let cc = *self.card_caps;

        let res = self.tx().pinpad_modify(PinType::Admin, &cc)?;
        RawResponse::try_from(res)?.try_into()
    }

    /// Reset the error counter for PW1 (user password) and set a new value
    /// for PW1.
    ///
    /// For authorization, either:
    /// - PW3 must have been verified previously,
    /// - secure messaging must be currently used,
    /// - the resetting_code must be presented.
    pub fn reset_retry_counter_pw1(
        &mut self,
        new_pw1: SecretBox<[u8]>,
        resetting_code: Option<SecretBox<[u8]>>,
    ) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: reset_retry_counter_pw1");

        let cmd = commands::reset_retry_counter_pw1(resetting_code, new_pw1)?;
        self.send_command(cmd, false)?.try_into()
    }

    // --- decrypt ---

    /// Decrypt the ciphertext in `dm`, on the card.
    ///
    /// (This is a wrapper around the low-level pso_decipher
    /// operation, it builds the required `data` field from `dm`)
    pub fn decipher(&mut self, dm: Cryptogram) -> Result<Vec<u8>, Error> {
        match dm {
            Cryptogram::RSA(message) => {
                // "Padding indicator byte (00) for RSA" (pg. 69)
                let mut data = vec![0x0];
                data.extend_from_slice(message);

                // Call the card to decrypt `data`
                self.pso_decipher(data)
            }
            Cryptogram::ECDH(eph) => {
                // "In case of ECDH the card supports a partial decrypt
                // only. The input is a cipher DO with the following data:"
                // A6 xx Cipher DO
                //  -> 7F49 xx Public Key DO
                //    -> 86 xx External Public Key

                // External Public Key
                let epk = Tlv::new(Tags::ExternalPublicKey, Value::S(eph.to_vec()));

                // Public Key DO
                let pkdo = Tlv::new(Tags::PublicKey, Value::C(vec![epk]));

                // Cipher DO
                let cdo = Tlv::new(Tags::Cipher, Value::C(vec![pkdo]));

                self.pso_decipher(cdo.serialize())
            }
        }
    }

    /// Run decryption operation on the smartcard (low level operation)
    /// (7.2.11 PSO: DECIPHER)
    ///
    /// (consider using the [`Self::decipher`] method if you don't want to create
    /// the data field manually)
    pub fn pso_decipher(&mut self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: pso_decipher");

        // The OpenPGP card is already connected and PW1 82 has been verified
        let dec_cmd = commands::decryption(data)?;
        let resp = self.send_command(dec_cmd, true)?;

        Ok(resp.data()?.to_vec())
    }

    /// Set the key to be used for the pso_decipher and the internal_authenticate commands.
    ///
    /// Valid until next reset of of the card or the next call to `select`
    /// The only keys that can be configured by this command are the `Decryption` and
    /// `Authentication` keys.
    ///
    /// The following first sets the *Authentication* key to be used for [`Self::pso_decipher`]
    /// and then sets the *Decryption* key to be used for [`Self::internal_authenticate`].
    ///
    /// ```no_run
    /// # use openpgp_card::ocard::{KeyType, Transaction};
    /// # let mut tx: Transaction<'static> = panic!();
    /// tx.manage_security_environment(KeyType::Decryption, KeyType::Authentication)?;
    /// tx.manage_security_environment(KeyType::Authentication, KeyType::Decryption)?;
    /// # Result::<(), openpgp_card::Error>::Ok(())
    /// ```
    pub fn manage_security_environment(
        &mut self,
        for_operation: KeyType,
        key_ref: KeyType,
    ) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: manage_security_environment");

        if !matches!(for_operation, KeyType::Authentication | KeyType::Decryption)
            || !matches!(key_ref, KeyType::Authentication | KeyType::Decryption)
        {
            return Err(Error::UnsupportedAlgo("Only Decryption and Authentication keys can be manipulated by manage_security_environment".to_string()));
        }

        let cmd = commands::manage_security_environment(for_operation, key_ref)?;
        let resp = self.send_command(cmd, false)?;
        resp.check_ok()?;
        Ok(())
    }

    // --- sign ---

    /// Sign `hash`, on the card.
    ///
    /// This is a wrapper around the low-level
    /// pso_compute_digital_signature operation.
    /// It builds the required `data` field from `hash`.
    ///
    /// For RSA, this means a "DigestInfo" data structure is generated.
    /// (see 7.2.10.2 DigestInfo for RSA).
    ///
    /// With ECC the hash data is processed as is, using
    /// [`Self::pso_compute_digital_signature`].
    pub fn signature_for_hash(
        &mut self,
        algo: SigningAlgo,
        digest: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let data = match algo {
            SigningAlgo::ECC => digest.into(),
            SigningAlgo::RSA(hash_algo) => digestinfo(digest, hash_algo)?,
        };

        self.pso_compute_digital_signature(data)
    }

    /// Run signing operation on the smartcard (low level operation)
    /// (7.2.10 PSO: COMPUTE DIGITAL SIGNATURE)
    ///
    /// (consider using the [`Self::signature_for_hash`] method if you don't
    /// want to create the data field manually)
    pub fn pso_compute_digital_signature(&mut self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: pso_compute_digital_signature");

        let cds_cmd = commands::signature(data)?;
        let resp = self.send_command(cds_cmd, true)?;

        Ok(resp.data().map(|d| d.to_vec())?)
    }

    // --- internal authenticate ---

    /// Auth-sign `hash`, on the card.
    ///
    /// This is a wrapper around the low-level
    /// internal_authenticate operation.
    /// It builds the required `data` field from `hash`.
    ///
    /// For RSA, this means a "DigestInfo" data structure is generated.
    /// (see 7.2.10.2 DigestInfo for RSA).
    ///
    /// With ECC the hash data is processed as is.
    pub fn authenticate_for_hash(
        &mut self,
        algo: SigningAlgo,
        digest: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let data = match algo {
            SigningAlgo::ECC => digest.into(),
            SigningAlgo::RSA(hash_algo) => digestinfo(digest, hash_algo)?,
        };

        self.internal_authenticate(data)
    }

    /// Run signing operation on the smartcard (low level operation)
    /// (7.2.13 INTERNAL AUTHENTICATE)
    ///
    /// (consider using the `authenticate_for_hash()` method if you don't
    /// want to create the data field manually)
    pub fn internal_authenticate(&mut self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: internal_authenticate");

        let ia_cmd = commands::internal_authenticate(data)?;
        let resp = self.send_command(ia_cmd, true)?;

        Ok(resp.data().map(|d| d.to_vec())?)
    }

    // --- PUT DO ---

    /// Set data of "private use" DO.
    ///
    /// `num` must be between 1 and 4.
    ///
    /// Access condition:
    /// - 1/3 need PW1 (82)
    /// - 2/4 need PW3
    pub fn set_private_use_do(&mut self, num: u8, data: Vec<u8>) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_private_use_do");

        let tag = match num {
            1 => Tags::PrivateUse1,
            2 => Tags::PrivateUse2,
            3 => Tags::PrivateUse3,
            4 => Tags::PrivateUse4,
            _ => {
                return Err(Error::UnsupportedFeature(format!(
                    "Illegal Private Use DO num '{}'",
                    num,
                )));
            }
        };

        let cmd = commands::put_data(tag, data)?;
        self.send_command(cmd, true)?.try_into()
    }

    pub fn set_login(&mut self, login: &[u8]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_login");

        let cmd = commands::put_login_data(login.to_vec())?;
        self.send_command(cmd, false)?.try_into()
    }

    pub fn set_name(&mut self, name: &[u8]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_name");

        let cmd = commands::put_name(name.to_vec())?;
        self.send_command(cmd, false)?.try_into()
    }

    pub fn set_lang(&mut self, lang: &[Lang]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_lang");

        let bytes: Vec<_> = lang.iter().flat_map(|&l| Vec::<u8>::from(l)).collect();

        let cmd = commands::put_lang(bytes)?;
        self.send_command(cmd, false)?.try_into()
    }

    pub fn set_sex(&mut self, sex: Sex) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_sex");

        let cmd = commands::put_sex((&sex).into())?;
        self.send_command(cmd, false)?.try_into()
    }

    pub fn set_url(&mut self, url: &[u8]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_url");

        let cmd = commands::put_url(url.to_vec())?;
        self.send_command(cmd, false)?.try_into()
    }

    /// Set cardholder certificate (for AUT, DEC or SIG).
    ///
    /// Call select_data() before calling this fn to select a particular
    /// certificate (if the card supports multiple certificates).
    pub fn set_cardholder_certificate(&mut self, data: Vec<u8>) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_cardholder_certificate");

        let cmd = commands::put_cardholder_certificate(data)?;
        self.send_command(cmd, false)?.try_into()
    }

    /// Set algorithm attributes for a key slot (4.4.3.9 Algorithm Attributes)
    ///
    /// Note: `algorithm_attributes` needs to precisely specify the
    /// RSA bit-size of e (if applicable), and import format, with values
    /// that the current card supports.
    pub fn set_algorithm_attributes(
        &mut self,
        key_type: KeyType,
        algorithm_attributes: &AlgorithmAttributes,
    ) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_algorithm_attributes");

        // Don't set algorithm if the feature is not available?
        let ecap = self.extended_capabilities()?;
        if !ecap.algo_attrs_changeable() {
            // Don't change the algorithm attributes, if the card doesn't support change
            // FIXME: Compare current and requested setting and return an error, if they differ?

            return Ok(());
        }

        // Command to PUT the algorithm attributes
        let cmd = commands::put_data(
            key_type.algorithm_tag(),
            algorithm_attributes.to_data_object()?,
        )?;

        self.send_command(cmd, false)?.try_into()
    }

    /// Set PW Status Bytes.
    ///
    /// If `long` is false, send 1 byte to the card, otherwise 4.
    /// According to the spec, length information should not be changed.
    ///
    /// So, effectively, with 'long == false' the setting `pw1_cds_multi`
    /// can be changed.
    /// With 'long == true', the settings `pw1_pin_block` and `pw3_pin_block`
    /// can also be changed.
    ///
    /// (See OpenPGP card spec, pg. 28)
    pub fn set_pw_status_bytes(
        &mut self,
        pw_status: &PWStatusBytes,
        long: bool,
    ) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_pw_status_bytes");

        let data = pw_status.serialize_for_put(long);

        let cmd = commands::put_pw_status(data)?;
        self.send_command(cmd, false)?.try_into()
    }

    pub fn set_fingerprint(&mut self, fp: Fingerprint, key_type: KeyType) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_fingerprint");

        let cmd = commands::put_data(key_type.fingerprint_put_tag(), fp.as_bytes().to_vec())?;

        self.send_command(cmd, false)?.try_into()
    }

    pub fn set_ca_fingerprint_1(&mut self, fp: Fingerprint) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_ca_fingerprint_1");

        let cmd = commands::put_data(Tags::CaFingerprint1, fp.as_bytes().to_vec())?;
        self.send_command(cmd, false)?.try_into()
    }

    pub fn set_ca_fingerprint_2(&mut self, fp: Fingerprint) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_ca_fingerprint_2");

        let cmd = commands::put_data(Tags::CaFingerprint2, fp.as_bytes().to_vec())?;
        self.send_command(cmd, false)?.try_into()
    }

    pub fn set_ca_fingerprint_3(&mut self, fp: Fingerprint) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_ca_fingerprint_3");

        let cmd = commands::put_data(Tags::CaFingerprint3, fp.as_bytes().to_vec())?;
        self.send_command(cmd, false)?.try_into()
    }

    pub fn set_creation_time(
        &mut self,
        time: KeyGenerationTime,
        key_type: KeyType,
    ) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_creation_time");

        // Timestamp update
        let time_value: Vec<u8> = time.get().to_be_bytes().to_vec();

        let cmd = commands::put_data(key_type.timestamp_put_tag(), time_value)?;

        self.send_command(cmd, false)?.try_into()
    }

    // FIXME: optional DO SM-Key-ENC

    // FIXME: optional DO SM-Key-MAC

    /// Set resetting code
    /// (4.3.4 Resetting Code)
    pub fn set_resetting_code(&mut self, resetting_code: SecretBox<[u8]>) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_resetting_code");

        let cmd = commands::put_data(Tags::ResettingCode, resetting_code)?;
        self.send_command(cmd, false)?.try_into()
    }

    /// Set AES key for symmetric decryption/encryption operations.
    ///
    /// Optional DO (announced in Extended Capabilities) for
    /// PSO:ENC/DEC with AES (32 bytes dec. in case of
    /// AES256, 16 bytes dec. in case of AES128).
    pub fn set_pso_enc_dec_key(&mut self, key: &[u8]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_pso_enc_dec_key");

        let cmd = commands::put_data(Tags::PsoEncDecKey, key.to_vec())?;
        self.send_command(cmd, false)?.try_into()
    }

    /// Set UIF for PSO:CDS
    pub fn set_uif_pso_cds(&mut self, uif: &UserInteractionFlag) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_uif_pso_cds");

        let cmd = commands::put_data(Tags::UifSig, uif.as_bytes().to_vec())?;
        self.send_command(cmd, false)?.try_into()
    }

    /// Set UIF for PSO:DEC
    pub fn set_uif_pso_dec(&mut self, uif: &UserInteractionFlag) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_uif_pso_dec");

        let cmd = commands::put_data(Tags::UifDec, uif.as_bytes().to_vec())?;
        self.send_command(cmd, false)?.try_into()
    }

    /// Set UIF for PSO:AUT
    pub fn set_uif_pso_aut(&mut self, uif: &UserInteractionFlag) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_uif_pso_aut");

        let cmd = commands::put_data(Tags::UifAuth, uif.as_bytes().to_vec())?;
        self.send_command(cmd, false)?.try_into()
    }

    /// Set UIF for Attestation key
    ///
    /// (Caution: Setting the touch policy of the Attestation slot on YubiKey 5 devices
    /// to a variation of "Fixed" is permanent for the lifetime of the hardware device!
    ///
    /// It can't be undone with a factory reset!
    ///
    /// However, a "fixed" attestation key touch policy can be cleared by overwriting the
    /// attestation key.
    ///
    /// Related/relevant: Overwriting the original Yubico CA attestation key is also permanent.
    /// It can't be restored with a factory reset either.)
    pub fn set_uif_attestation(&mut self, uif: &UserInteractionFlag) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_uif_attestation");

        let cmd = commands::put_data(Tags::UifAttestation, uif.as_bytes().to_vec())?;
        self.send_command(cmd, false)?.try_into()
    }

    /// Generate Attestation (Yubico)
    pub fn generate_attestation(&mut self, key_type: KeyType) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: generate_attestation");

        let key = match key_type {
            KeyType::Signing => 0x01,
            KeyType::Decryption => 0x02,
            KeyType::Authentication => 0x03,
            _ => return Err(Error::InternalError("Unexpected KeyType".to_string())),
        };

        let cmd = commands::generate_attestation(key)?;
        self.send_command(cmd, false)?.try_into()
    }

    // FIXME: Attestation key algo attr, FP, CA-FP, creation time

    // FIXME: SM keys (ENC and MAC) with Tags D1 and D2

    /// Set KDF DO attributes
    pub fn set_kdf_do(&mut self, kdf_do: &KdfDo) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_kdf_do");

        let cmd = commands::put_data(Tags::KdfDo, kdf_do.serialize())?;
        self.send_command(cmd, false)?.try_into()
    }

    // FIXME: certificate used with secure messaging

    // FIXME: Attestation Certificate (Yubico)

    // -----------------

    /// Import an existing private key to the card.
    /// (This implicitly sets the algorithm attributes, fingerprint and timestamp)
    pub fn key_import(
        &mut self,
        key: &dyn CardUploadableKey,
        key_type: KeyType,
    ) -> Result<(), Error> {
        keys::key_import(self, key, key_type)
    }

    /// Generate a key on the card.
    /// (7.2.14 GENERATE ASYMMETRIC KEY PAIR)
    pub fn generate_key(
        &mut self,
        fp_from_pub: fn(
            &PublicKeyMaterial,
            KeyGenerationTime,
            KeyType,
        ) -> Result<Fingerprint, Error>,
        key_type: KeyType,
    ) -> Result<(PublicKeyMaterial, KeyGenerationTime), Error> {
        // get current (possibly updated) state of algorithm_attributes
        let ard = self.application_related_data()?; // no caching, here!
        let cur_algo = ard.algorithm_attributes(key_type)?;

        keys::gen_key_set_metadata(self, fp_from_pub, &cur_algo, key_type)
    }

    /// Get public key material from the card.
    ///
    /// Note: this fn returns a set of raw public key data (not an
    /// OpenPGP data structure).
    ///
    /// Note also that the information from the card is insufficient to
    /// reconstruct a pre-existing OpenPGP public key that corresponds to
    /// the private key on the card.
    pub fn public_key(&mut self, key_type: KeyType) -> Result<PublicKeyMaterial, Error> {
        keys::public_key(self, key_type)
    }
}

/// Used for RSA signatures
///
/// TODO: unit test
fn digestinfo(digest: &[u8], hash_algo: HashAlgo) -> Result<Vec<u8>, Error> {
    if hash_algo.len() != digest.len() {
        return Err(Error::InternalError(format!(
            "Unexpected hash length {} for digestinfo with hash_algo {:?}",
            digest.len(),
            hash_algo
        )));
    }

    let tlv = Tlv::new(
        Tags::Sequence,
        Value::C(vec![
            Tlv::new(
                Tags::Sequence,
                Value::C(vec![
                    Tlv::new(Tags::ObjectIdentifier, Value::S(hash_algo.oid().to_vec())),
                    Tlv::new(Tags::Null, Value::S(vec![])),
                ]),
            ),
            Tlv::new(Tags::OctetString, Value::S(digest.into())),
        ]),
    );

    Ok(tlv.serialize())
}

/// OpenPGP card "Status Bytes" (ok statuses and errors)
#[derive(thiserror::Error, Debug, PartialEq, Eq, Copy, Clone)]
#[non_exhaustive]
pub enum StatusBytes {
    #[error("Command correct")]
    Ok,

    #[error("Command correct, [{0}] bytes available in response")]
    OkBytesAvailable(u8),

    #[error("Selected file or DO in termination state")]
    TerminationState,

    #[error("Password not checked, {0} allowed retries")]
    PasswordNotChecked(u8),

    #[error("Execution error with non-volatile memory unchanged")]
    ExecutionErrorNonVolatileMemoryUnchanged,

    #[error("Triggering by the card {0}")]
    TriggeringByCard(u8),

    #[error("Memory failure")]
    MemoryFailure,

    #[error("Security-related issues (reserved for UIF in this application)")]
    SecurityRelatedIssues,

    #[error("Wrong length (Lc and/or Le)")]
    WrongLength,

    #[error("Logical channel not supported")]
    LogicalChannelNotSupported,

    #[error("Secure messaging not supported")]
    SecureMessagingNotSupported,

    #[error("Last command of the chain expected")]
    LastCommandOfChainExpected,

    #[error("Command chaining not supported")]
    CommandChainingNotSupported,

    #[error("Security status not satisfied")]
    SecurityStatusNotSatisfied,

    #[error("Authentication method blocked")]
    AuthenticationMethodBlocked,

    #[error("Condition of use not satisfied")]
    ConditionOfUseNotSatisfied,

    #[error("Expected secure messaging DOs missing (e. g. SM-key)")]
    ExpectedSecureMessagingDOsMissing,

    #[error("SM data objects incorrect (e. g. wrong TLV-structure in command data)")]
    SMDataObjectsIncorrect,

    #[error("Incorrect parameters in the command data field")]
    IncorrectParametersCommandDataField,

    #[error("File or application not found")]
    FileOrApplicationNotFound,

    #[error("Referenced data, reference data or DO not found")]
    ReferencedDataNotFound,

    #[error("Wrong parameters P1-P2")]
    WrongParametersP1P2,

    #[error("Instruction code (INS) not supported or invalid")]
    INSNotSupported,

    #[error("Class (CLA) not supported")]
    CLANotSupported,

    #[error("No precise diagnosis")]
    NoPreciseDiagnosis,

    #[error("Unknown OpenPGP card status: [{0:x}, {1:x}]")]
    UnknownStatus(u8, u8),
}

impl From<(u8, u8)> for StatusBytes {
    fn from(status: (u8, u8)) -> Self {
        match (status.0, status.1) {
            (0x90, 0x00) => StatusBytes::Ok,
            (0x61, bytes) => StatusBytes::OkBytesAvailable(bytes),

            (0x62, 0x85) => StatusBytes::TerminationState,
            (0x63, 0xC0..=0xCF) => StatusBytes::PasswordNotChecked(status.1 & 0xf),
            (0x64, 0x00) => StatusBytes::ExecutionErrorNonVolatileMemoryUnchanged,
            (0x64, 0x02..=0x80) => StatusBytes::TriggeringByCard(status.1),
            (0x65, 0x01) => StatusBytes::MemoryFailure,
            (0x66, 0x00) => StatusBytes::SecurityRelatedIssues,
            (0x67, 0x00) => StatusBytes::WrongLength,
            (0x68, 0x81) => StatusBytes::LogicalChannelNotSupported,
            (0x68, 0x82) => StatusBytes::SecureMessagingNotSupported,
            (0x68, 0x83) => StatusBytes::LastCommandOfChainExpected,
            (0x68, 0x84) => StatusBytes::CommandChainingNotSupported,
            (0x69, 0x82) => StatusBytes::SecurityStatusNotSatisfied,
            (0x69, 0x83) => StatusBytes::AuthenticationMethodBlocked,
            (0x69, 0x85) => StatusBytes::ConditionOfUseNotSatisfied,
            (0x69, 0x87) => StatusBytes::ExpectedSecureMessagingDOsMissing,
            (0x69, 0x88) => StatusBytes::SMDataObjectsIncorrect,
            (0x6A, 0x80) => StatusBytes::IncorrectParametersCommandDataField,
            (0x6A, 0x82) => StatusBytes::FileOrApplicationNotFound,
            (0x6A, 0x88) => StatusBytes::ReferencedDataNotFound,
            (0x6B, 0x00) => StatusBytes::WrongParametersP1P2,
            (0x6D, 0x00) => StatusBytes::INSNotSupported,
            (0x6E, 0x00) => StatusBytes::CLANotSupported,
            (0x6F, 0x00) => StatusBytes::NoPreciseDiagnosis,
            _ => StatusBytes::UnknownStatus(status.0, status.1),
        }
    }
}
