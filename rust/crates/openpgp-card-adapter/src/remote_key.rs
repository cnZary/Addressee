use std::{
    fmt,
    sync::{Arc, Mutex},
};

use openpgp_card::{
    Card,
    ocard::{
        KeyType, StatusBytes,
        crypto::{Cryptogram, HashAlgo, PublicKeyMaterial, SigningAlgo},
        data::{KdfDo, KeyGenerationTime, TouchPolicy},
    },
    state::Transaction,
};
use openpgp_core::RemoteKeyFailure;
use pgp::{
    composed::PlainSessionKey,
    crypto::{
        checksum, ecc_curve::ECCCurve, ecdh, hash::HashAlgorithm, public_key::PublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    errors,
    packet::{PubKeyInner, PublicKey},
    ser::Serialize as _,
    types::{
        DecryptionKey, EcdhKdfType, EcdhPublicParams, EcdsaPublicParams, EddsaLegacyPublicParams,
        EskType, Fingerprint, KeyDetails, KeyId, KeyVersion, Password, PkeskBytes, PublicParams,
        RsaPublicParams, SignatureBytes, SigningKey, Timestamp,
    },
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    CardIdentity, ExpectedSerial,
    interaction::{CardInteractionError, PinProvider, PinPurpose, TouchPrompt},
    pcsc::{PcscContext, PcscError, require_exact_reader},
    transport::{RawCardTransport, TransportCardBackend, TransportError},
};

#[derive(Debug, Error)]
pub enum RemoteKeyError {
    #[error("PC/SC error: {0}")]
    Pcsc(#[from] PcscError),

    #[error("card transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("OpenPGP card operation failed: {0}")]
    Card(#[from] openpgp_card::Error),

    #[error("PIN or touch interaction failed: {0}")]
    Interaction(#[from] CardInteractionError),

    #[error("OpenPGP serial mismatch: expected {expected:08X}, card reported {actual:08X}")]
    SerialMismatch { expected: u32, actual: u32 },

    #[error("the OpenPGP application identity changed")]
    IdentityMismatch,

    #[error("the card operation session is unavailable after a poisoned lock")]
    SessionPoisoned,

    #[error("unsupported key version {0:?}; only V4 card components are supported")]
    UnsupportedKeyVersion(KeyVersion),

    #[error("unsupported algorithm {algorithm:?} for the {slot:?} slot")]
    UnsupportedAlgorithm {
        slot: KeyType,
        algorithm: PublicKeyAlgorithm,
    },

    #[error("unsupported public-key parameters: {0}")]
    UnsupportedPublicKey(&'static str),

    #[error("unsupported hash algorithm {0:?}")]
    UnsupportedHash(HashAlgorithm),

    #[error("new signatures must not use weak hash algorithm {0:?}")]
    WeakHash(HashAlgorithm),

    #[error("unsupported ECDH key-wrap algorithm {0:?}")]
    UnsupportedSymmetricAlgorithm(SymmetricKeyAlgorithm),

    #[error("the card slot has no {0}")]
    MissingSlotData(&'static str),

    #[error("the card slot does not match the certificate component: {0}")]
    SlotBinding(&'static str),

    #[error("public-key conversion failed: {0}")]
    PublicMaterial(String),

    #[error("rPGP rejected the public component: {0}")]
    Rpgp(String),

    #[error("the operation is not valid for this card slot: {0}")]
    InvalidOperation(&'static str),

    #[error("invalid digest length {actual}; expected {expected} bytes")]
    InvalidDigestLength { expected: usize, actual: usize },

    #[error("invalid PKESK input: {0}")]
    InvalidCiphertext(&'static str),

    #[error("malformed card response: expected {expected} bytes, got {actual}")]
    MalformedResponse { expected: usize, actual: usize },

    #[error("invalid decrypted session-key framing: {0}")]
    InvalidSessionKey(&'static str),

    #[error("unsupported card KDF algorithm {0}")]
    UnsupportedKdf(u8),

    #[error("invalid card KDF parameters: {0}")]
    InvalidKdf(&'static str),

    #[error("PIN is empty; no verification command was sent")]
    EmptyPin,

    #[error(
        "PIN length {actual} is outside the {minimum}..={maximum}-byte limit; no VERIFY was sent"
    )]
    InvalidPinLength {
        minimum: usize,
        maximum: usize,
        actual: usize,
    },

    #[error(
        "only {remaining_retries} PIN retries remain; no PIN was requested and no VERIFY was sent"
    )]
    PinRetriesUnavailable { remaining_retries: u8 },

    #[error("wrong PIN; {remaining_retries} retries remain; no automatic retry was attempted")]
    WrongPin { remaining_retries: u8 },

    #[error("the card connector returned an unexpected result")]
    UnexpectedTransactionResult,
}

impl From<RemoteKeyError> for errors::Error {
    fn from(error: RemoteKeyError) -> Self {
        error.to_string().into()
    }
}

#[derive(Clone)]
pub struct CardSession {
    inner: Arc<SessionInner>,
}

struct SessionInner {
    identity: CardIdentity,
    pin_provider: Arc<dyn PinProvider>,
    touch_prompt: Arc<dyn TouchPrompt>,
    state: Mutex<SessionState>,
    last_failure: Mutex<RemoteKeyFailure>,
}

struct SessionState {
    connector: Box<dyn CardConnector>,
}

impl CardSession {
    pub fn connect(
        reader: &str,
        expected_serial: ExpectedSerial,
        pin_provider: Arc<dyn PinProvider>,
        touch_prompt: Arc<dyn TouchPrompt>,
    ) -> Result<Self, RemoteKeyError> {
        let mut connector = PcscConnector {
            reader: reader.to_owned(),
        };
        let identity = match connector.transact(Box::new(|transaction| {
            Ok(TransactionOutput::Identity(transaction.identity()?))
        }))? {
            TransactionOutput::Identity(identity) => identity,
            _ => return Err(RemoteKeyError::UnexpectedTransactionResult),
        };
        if identity.serial() != expected_serial.get() {
            return Err(RemoteKeyError::SerialMismatch {
                expected: expected_serial.get(),
                actual: identity.serial(),
            });
        }
        Ok(Self::from_connector(
            identity,
            Box::new(connector),
            pin_provider,
            touch_prompt,
        ))
    }

    pub fn identify_with_transport(
        transport: Arc<dyn RawCardTransport>,
    ) -> Result<CardIdentity, RemoteKeyError> {
        let mut connector = TransportConnector { transport };
        let result = identify_connector(&mut connector);
        if result.is_err() && connector.transport.failure_kind() == RemoteKeyFailure::Cancelled {
            return Err(TransportError::Cancelled.into());
        }
        result
    }

    pub fn connect_with_transport(
        expected_identity: CardIdentity,
        transport: Arc<dyn RawCardTransport>,
        pin_provider: Arc<dyn PinProvider>,
        touch_prompt: Arc<dyn TouchPrompt>,
    ) -> Result<Self, RemoteKeyError> {
        let mut connector = TransportConnector { transport };
        let result = identify_connector(&mut connector);
        if result.is_err() && connector.transport.failure_kind() == RemoteKeyFailure::Cancelled {
            return Err(TransportError::Cancelled.into());
        }
        let identity = result?;
        if identity != expected_identity {
            return Err(RemoteKeyError::IdentityMismatch);
        }
        Ok(Self::from_connector(
            identity,
            Box::new(connector),
            pin_provider,
            touch_prompt,
        ))
    }

    fn from_connector(
        identity: CardIdentity,
        connector: Box<dyn CardConnector>,
        pin_provider: Arc<dyn PinProvider>,
        touch_prompt: Arc<dyn TouchPrompt>,
    ) -> Self {
        Self {
            inner: Arc::new(SessionInner {
                identity,
                pin_provider,
                touch_prompt,
                state: Mutex::new(SessionState { connector }),
                last_failure: Mutex::new(RemoteKeyFailure::Unavailable),
            }),
        }
    }

    pub fn identity(&self) -> CardIdentity {
        self.inner.identity
    }

    pub fn failure_kind(&self) -> RemoteKeyFailure {
        self.inner
            .last_failure
            .lock()
            .map_or(RemoteKeyFailure::Unavailable, |failure| *failure)
    }

    fn set_failure(&self, failure: RemoteKeyFailure) {
        if let Ok(mut last_failure) = self.inner.last_failure.lock() {
            *last_failure = failure;
        }
    }

    fn record_failure(
        &self,
        result: &Result<TransactionOutput, RemoteKeyError>,
        connector: &dyn CardConnector,
    ) {
        let failure = match result {
            Ok(_) => RemoteKeyFailure::Unavailable,
            Err(RemoteKeyError::Interaction(CardInteractionError::Cancelled))
            | Err(RemoteKeyError::Transport(TransportError::Cancelled)) => {
                RemoteKeyFailure::Cancelled
            }
            Err(_) => connector.failure_kind(),
        };
        self.set_failure(failure);
    }

    pub fn bind(
        &self,
        slot: KeyType,
        component: &dyn KeyDetails,
    ) -> Result<RemoteCardKey, RemoteKeyError> {
        self.set_failure(RemoteKeyFailure::Unavailable);
        let public = copy_and_validate_component(slot, component)?;
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| RemoteKeyError::SessionPoisoned)?;
        let result = state.connector.transact(Box::new(|transaction| {
            let metadata = transaction.read_slot(slot, &public)?;
            validate_fresh_binding(self.inner.identity, &public, &metadata)?;
            Ok(TransactionOutput::Slot)
        }));
        self.record_failure(&result, state.connector.as_ref());
        match result? {
            TransactionOutput::Slot => Ok(RemoteCardKey {
                session: self.clone(),
                slot,
                public,
            }),
            _ => Err(RemoteKeyError::UnexpectedTransactionResult),
        }
    }

    fn authorization_requirements(
        &self,
        slot: KeyType,
        public: &PublicKey,
    ) -> Result<OperationAuthorization, RemoteKeyError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| RemoteKeyError::SessionPoisoned)?;
        self.set_failure(RemoteKeyFailure::Unavailable);
        let identity = self.inner.identity;
        let result = state.connector.transact(Box::new(|transaction| {
            let metadata = transaction.read_slot(slot, public)?;
            validate_fresh_binding(identity, public, &metadata)?;
            validate_pin_policy(transaction, &metadata)?;
            Ok(TransactionOutput::Authorization(OperationAuthorization {
                slot,
                pin_purpose: if slot == KeyType::Signing {
                    PinPurpose::Signing
                } else {
                    PinPurpose::User
                },
                minimum_pin_length: 6,
                maximum_pin_length: metadata.user_pin_max_length,
                remaining_pin_retries: metadata.user_retries,
                touch_policy: metadata.touch_policy,
            }))
        }));
        self.record_failure(&result, state.connector.as_ref());
        match result? {
            TransactionOutput::Authorization(authorization) => Ok(authorization),
            _ => Err(RemoteKeyError::UnexpectedTransactionResult),
        }
    }

    fn operate(
        &self,
        slot: KeyType,
        public: &PublicKey,
        verification: PinPurpose,
        operation: impl FnOnce(&mut dyn CardTransaction) -> Result<Vec<u8>, RemoteKeyError>,
    ) -> Result<Vec<u8>, RemoteKeyError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| RemoteKeyError::SessionPoisoned)?;
        self.set_failure(RemoteKeyFailure::Unavailable);
        let pin_provider = Arc::clone(&self.inner.pin_provider);
        let touch_prompt = Arc::clone(&self.inner.touch_prompt);
        let identity = self.inner.identity;
        let result = state.connector.transact(Box::new(|transaction| {
            let metadata = transaction.read_slot(slot, public)?;
            validate_fresh_binding(identity, public, &metadata)?;
            verify_pin(
                transaction,
                &metadata,
                verification,
                identity,
                pin_provider.as_ref(),
            )?;
            if metadata
                .touch_policy
                .is_some_and(|policy| policy.touch_required())
            {
                touch_prompt.request_touch(slot)?;
            }
            Ok(TransactionOutput::Bytes(operation(transaction)?))
        }));
        self.record_failure(&result, state.connector.as_ref());
        #[cfg(feature = "hardware-test")]
        if let Err(error) = &result {
            eprintln!(
                "Card {slot:?} operation failed before completion: {}.",
                hardware_error_category(error)
            );
        }
        match result? {
            TransactionOutput::Bytes(bytes) => Ok(bytes),
            _ => Err(RemoteKeyError::UnexpectedTransactionResult),
        }
    }
}

#[cfg(feature = "hardware-test")]
fn hardware_error_category(error: &RemoteKeyError) -> String {
    match error {
        RemoteKeyError::Card(openpgp_card::Error::CardStatus(status)) => {
            format!("card status {status:?}")
        }
        RemoteKeyError::Card(openpgp_card::Error::CommandTooLong(_)) => {
            "command too long".to_owned()
        }
        RemoteKeyError::Card(openpgp_card::Error::ResponseLength(_)) => {
            "unexpected response length".to_owned()
        }
        RemoteKeyError::Card(openpgp_card::Error::NotFound(_)) => "data not found".to_owned(),
        RemoteKeyError::Card(openpgp_card::Error::ParseError(_)) => "data parse error".to_owned(),
        RemoteKeyError::Card(openpgp_card::Error::UnsupportedAlgo(_)) => {
            "unsupported algorithm".to_owned()
        }
        RemoteKeyError::Card(openpgp_card::Error::UnsupportedFeature(_)) => {
            "unsupported feature".to_owned()
        }
        RemoteKeyError::Card(openpgp_card::Error::InternalError(_)) => {
            "card library internal error".to_owned()
        }
        RemoteKeyError::Card(openpgp_card::Error::Smartcard(_)) => "smartcard I/O error".to_owned(),
        RemoteKeyError::Pcsc(_) => "PC/SC error".to_owned(),
        RemoteKeyError::Transport(_) => "transport error".to_owned(),
        RemoteKeyError::Interaction(_) => "interaction error".to_owned(),
        RemoteKeyError::SlotBinding(reason) => format!("slot binding: {reason}"),
        other => format!("{other:?}"),
    }
}

fn identify_connector(connector: &mut dyn CardConnector) -> Result<CardIdentity, RemoteKeyError> {
    match connector.transact(Box::new(|transaction| {
        Ok(TransactionOutput::Identity(transaction.identity()?))
    }))? {
        TransactionOutput::Identity(identity) => Ok(identity),
        _ => Err(RemoteKeyError::UnexpectedTransactionResult),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationAuthorization {
    pub slot: KeyType,
    pub pin_purpose: PinPurpose,
    pub minimum_pin_length: u8,
    pub maximum_pin_length: u8,
    pub remaining_pin_retries: u8,
    pub touch_policy: Option<TouchPolicy>,
}

pub struct RemoteCardKey {
    session: CardSession,
    slot: KeyType,
    public: PublicKey,
}

impl RemoteCardKey {
    pub const fn slot(&self) -> KeyType {
        self.slot
    }

    pub const fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn authorization_requirements(&self) -> Result<OperationAuthorization, RemoteKeyError> {
        self.session
            .authorization_requirements(self.slot, &self.public)
    }

    pub(crate) fn failure_kind(&self) -> RemoteKeyFailure {
        self.session.failure_kind()
    }

    fn sign_digest(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<SignatureBytes, RemoteKeyError> {
        if self.slot == KeyType::Decryption {
            return Err(RemoteKeyError::InvalidOperation(
                "a decryption slot cannot create signatures",
            ));
        }
        if matches!(hash, HashAlgorithm::Md5 | HashAlgorithm::Sha1) {
            return Err(RemoteKeyError::WeakHash(hash));
        }
        let digest_length = hash
            .digest_size()
            .ok_or(RemoteKeyError::UnsupportedHash(hash))?;
        if data.len() != digest_length {
            return Err(RemoteKeyError::InvalidDigestLength {
                expected: digest_length,
                actual: data.len(),
            });
        }
        let (algorithm, digest, response) = match self.public.public_params() {
            PublicParams::RSA(rsa) => {
                let algorithm = match hash {
                    HashAlgorithm::Sha256 => HashAlgo::SHA256,
                    HashAlgorithm::Sha384 => HashAlgo::SHA384,
                    HashAlgorithm::Sha512 => HashAlgo::SHA512,
                    _ => return Err(RemoteKeyError::UnsupportedHash(hash)),
                };
                (
                    SigningAlgo::RSA(algorithm),
                    data.to_vec(),
                    SignatureResponse::Rsa(rsa_layout(rsa)?.modulus_width),
                )
            }
            PublicParams::ECDSA(ecdsa) => {
                let (digest_width, signature_width) = ecdsa_widths(ecdsa)?;
                if data.len() < digest_width {
                    return Err(RemoteKeyError::InvalidDigestLength {
                        expected: digest_width,
                        actual: data.len(),
                    });
                }
                (
                    SigningAlgo::ECC,
                    data[..digest_width].to_vec(),
                    SignatureResponse::Pair(signature_width),
                )
            }
            PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { .. }) => {
                (SigningAlgo::ECC, data.to_vec(), SignatureResponse::Pair(64))
            }
            _ => {
                return Err(RemoteKeyError::UnsupportedPublicKey(
                    "supported signatures are RSA, NIST ECDSA, and legacy Ed25519",
                ));
            }
        };
        let raw = self.session.operate(
            self.slot,
            &self.public,
            if self.slot == KeyType::Signing {
                PinPurpose::Signing
            } else {
                PinPurpose::User
            },
            |transaction| transaction.sign(self.slot, algorithm, &digest),
        )?;
        match response {
            SignatureResponse::Rsa(expected) => {
                if raw.len() != expected {
                    return Err(RemoteKeyError::MalformedResponse {
                        expected,
                        actual: raw.len(),
                    });
                }
                Ok(SignatureBytes::Mpis(vec![pgp::types::Mpi::from_slice(
                    &raw,
                )]))
            }
            SignatureResponse::Pair(expected) => {
                if raw.len() != expected {
                    return Err(RemoteKeyError::MalformedResponse {
                        expected,
                        actual: raw.len(),
                    });
                }
                let middle = expected / 2;
                Ok(SignatureBytes::Mpis(vec![
                    pgp::types::Mpi::from_slice(&raw[..middle]),
                    pgp::types::Mpi::from_slice(&raw[middle..]),
                ]))
            }
        }
    }

    fn decrypt_session_key(
        &self,
        values: &PkeskBytes,
        typ: EskType,
    ) -> Result<PlainSessionKey, RemoteKeyError> {
        if self.slot != KeyType::Decryption {
            return Err(RemoteKeyError::InvalidOperation(
                "only the decryption slot can decrypt PKESK values",
            ));
        }
        match (self.public.public_params(), values) {
            (PublicParams::RSA(rsa), PkeskBytes::Rsa { mpi }) => self.decrypt_rsa(rsa, mpi, typ),
            (
                PublicParams::ECDH(parameters),
                PkeskBytes::Ecdh {
                    public_point,
                    encrypted_session_key,
                },
            ) => self.decrypt_ecdh(parameters, public_point, encrypted_session_key, typ),
            (PublicParams::RSA(_), _) => Err(RemoteKeyError::InvalidCiphertext(
                "the PKESK algorithm does not match the RSA recipient",
            )),
            (PublicParams::ECDH(_), _) => Err(RemoteKeyError::InvalidCiphertext(
                "the PKESK algorithm does not match the ECDH recipient",
            )),
            _ => Err(RemoteKeyError::UnsupportedPublicKey(
                "only RSA and legacy ECDH card decryption are supported",
            )),
        }
    }

    fn decrypt_rsa(
        &self,
        rsa: &RsaPublicParams,
        ciphertext: &pgp::types::Mpi,
        typ: EskType,
    ) -> Result<PlainSessionKey, RemoteKeyError> {
        let width = rsa_layout(rsa)?.modulus_width;
        let ciphertext = ciphertext.as_ref();
        if ciphertext.len() > width {
            return Err(RemoteKeyError::InvalidCiphertext(
                "RSA ciphertext exceeds the recipient modulus width",
            ));
        }
        let mut padded = Vec::with_capacity(width);
        padded.resize(width - ciphertext.len(), 0);
        padded.extend_from_slice(ciphertext);
        let raw =
            self.session
                .operate(self.slot, &self.public, PinPurpose::User, |transaction| {
                    transaction.decrypt(Cryptogram::RSA(&padded))
                })?;
        parse_session_key(Zeroizing::new(raw), typ)
    }

    fn decrypt_ecdh(
        &self,
        parameters: &EcdhPublicParams,
        public_point: &pgp::types::Mpi,
        encrypted_session_key: &[u8],
        typ: EskType,
    ) -> Result<PlainSessionKey, RemoteKeyError> {
        let operation = ecdh_operation(parameters)?;
        let point = public_point.as_ref();
        if point.len() != operation.point_length || point.first() != Some(&operation.point_prefix) {
            return Err(RemoteKeyError::InvalidCiphertext(
                "the ECDH ephemeral point has the wrong length or encoding prefix",
            ));
        }
        if encrypted_session_key.len() < 16 || !encrypted_session_key.len().is_multiple_of(8) {
            return Err(RemoteKeyError::InvalidCiphertext(
                "the AES-wrapped session key has an invalid length",
            ));
        }
        let ephemeral = if operation.legacy_curve25519 {
            point[1..].to_vec()
        } else {
            point.to_vec()
        };
        let raw =
            self.session
                .operate(self.slot, &self.public, PinPurpose::User, |transaction| {
                    transaction.decrypt(Cryptogram::ECDH(&ephemeral))
                })?;
        let shared_secret = Zeroizing::new(raw);
        if shared_secret.len() != operation.shared_secret_length {
            return Err(RemoteKeyError::MalformedResponse {
                expected: operation.shared_secret_length,
                actual: shared_secret.len(),
            });
        }
        let fingerprint = self.public.fingerprint();
        let plain = ecdh::derive_session_key(
            shared_secret.as_slice(),
            encrypted_session_key,
            encrypted_session_key.len(),
            operation.curve,
            operation.hash,
            operation.alg_sym,
            fingerprint.as_bytes(),
        )
        .map_err(|_| RemoteKeyError::InvalidSessionKey("ECDH KDF or AES unwrap failed"))?;
        parse_session_key(plain, typ)
    }
}

enum SignatureResponse {
    Rsa(usize),
    Pair(usize),
}

struct EcdhOperation {
    curve: ECCCurve,
    hash: HashAlgorithm,
    alg_sym: SymmetricKeyAlgorithm,
    point_length: usize,
    point_prefix: u8,
    shared_secret_length: usize,
    legacy_curve25519: bool,
}

fn ecdsa_widths(parameters: &EcdsaPublicParams) -> Result<(usize, usize), RemoteKeyError> {
    match parameters {
        EcdsaPublicParams::P256 { .. } => Ok((32, 64)),
        EcdsaPublicParams::P384 { .. } => Ok((48, 96)),
        EcdsaPublicParams::P521 { .. } => Ok((64, 132)),
        _ => Err(RemoteKeyError::UnsupportedPublicKey(
            "ECDSA supports only NIST P-256, P-384, and P-521",
        )),
    }
}

fn ecdh_operation(parameters: &EcdhPublicParams) -> Result<EcdhOperation, RemoteKeyError> {
    let (curve, hash, alg_sym, point_length, point_prefix, shared_secret_length, legacy) =
        match parameters {
            EcdhPublicParams::Curve25519Legacy {
                hash,
                alg_sym,
                ecdh_kdf_type,
                ..
            } => {
                if *ecdh_kdf_type != EcdhKdfType::Native {
                    return Err(RemoteKeyError::UnsupportedPublicKey(
                        "Curve25519 ECDH requires the native fingerprint KDF",
                    ));
                }
                (
                    ECCCurve::Curve25519Legacy,
                    *hash,
                    *alg_sym,
                    33,
                    0x40,
                    32,
                    true,
                )
            }
            EcdhPublicParams::P256 { hash, alg_sym, .. } => {
                (ECCCurve::P256, *hash, *alg_sym, 65, 0x04, 32, false)
            }
            EcdhPublicParams::P384 { hash, alg_sym, .. } => {
                (ECCCurve::P384, *hash, *alg_sym, 97, 0x04, 48, false)
            }
            EcdhPublicParams::P521 { hash, alg_sym, .. } => {
                (ECCCurve::P521, *hash, *alg_sym, 133, 0x04, 66, false)
            }
            _ => {
                return Err(RemoteKeyError::UnsupportedPublicKey(
                    "ECDH supports only NIST curves and legacy Curve25519",
                ));
            }
        };
    validate_ecdh_parameters(hash, alg_sym)?;
    Ok(EcdhOperation {
        curve,
        hash,
        alg_sym,
        point_length,
        point_prefix,
        shared_secret_length,
        legacy_curve25519: legacy,
    })
}

impl fmt::Debug for RemoteCardKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteCardKey")
            .field("slot", &self.slot)
            .field("fingerprint", &self.public.fingerprint())
            .finish()
    }
}

impl KeyDetails for RemoteCardKey {
    fn version(&self) -> KeyVersion {
        self.public.version()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.public.legacy_key_id()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.public.fingerprint()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.public.algorithm()
    }

    fn created_at(&self) -> Timestamp {
        self.public.created_at()
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.public.legacy_v3_expiration_days()
    }

    fn public_params(&self) -> &PublicParams {
        self.public.public_params()
    }
}

impl SigningKey for RemoteCardKey {
    fn sign(
        &self,
        _key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> errors::Result<SignatureBytes> {
        self.session.set_failure(RemoteKeyFailure::Unavailable);
        self.sign_digest(hash, data).map_err(Into::into)
    }

    fn hash_alg(&self) -> HashAlgorithm {
        self.public.public_params().hash_alg()
    }
}

impl DecryptionKey for RemoteCardKey {
    fn decrypt(
        &self,
        _key_pw: &Password,
        values: &PkeskBytes,
        typ: EskType,
    ) -> errors::Result<errors::Result<PlainSessionKey>> {
        self.session.set_failure(RemoteKeyFailure::Unavailable);
        self.decrypt_session_key(values, typ)
            .map(Ok)
            .map_err(Into::into)
    }
}

struct RsaLayout {
    modulus_width: usize,
    modulus_bits: u16,
    exponent_bits: u16,
}

fn rsa_layout(rsa: &RsaPublicParams) -> Result<RsaLayout, RemoteKeyError> {
    fn mpi(input: &[u8], offset: usize) -> Result<(u16, usize, usize), RemoteKeyError> {
        let header = offset
            .checked_add(2)
            .filter(|end| *end <= input.len())
            .ok_or(RemoteKeyError::UnsupportedPublicKey(
                "truncated RSA public parameters",
            ))?;
        let bits = u16::from_be_bytes([input[offset], input[offset + 1]]);
        let width = usize::from(bits).div_ceil(8);
        let end = header
            .checked_add(width)
            .filter(|end| *end <= input.len())
            .ok_or(RemoteKeyError::UnsupportedPublicKey(
                "truncated RSA public parameter body",
            ))?;
        Ok((bits, width, end))
    }

    let encoded = rsa
        .to_bytes()
        .map_err(|error| RemoteKeyError::Rpgp(error.to_string()))?;
    let (modulus_bits, modulus_width, exponent_offset) = mpi(&encoded, 0)?;
    let (exponent_bits, _, end) = mpi(&encoded, exponent_offset)?;
    if end != encoded.len() || modulus_width == 0 || exponent_bits == 0 {
        return Err(RemoteKeyError::UnsupportedPublicKey(
            "invalid or trailing RSA public parameters",
        ));
    }
    Ok(RsaLayout {
        modulus_width,
        modulus_bits,
        exponent_bits,
    })
}

fn copy_and_validate_component(
    slot: KeyType,
    component: &dyn KeyDetails,
) -> Result<PublicKey, RemoteKeyError> {
    if slot == KeyType::Attestation {
        return Err(RemoteKeyError::InvalidOperation(
            "attestation keys are outside the generic remote-key interface",
        ));
    }
    if component.version() != KeyVersion::V4 {
        return Err(RemoteKeyError::UnsupportedKeyVersion(component.version()));
    }
    if component.fingerprint().as_bytes().len() != 20 {
        return Err(RemoteKeyError::UnsupportedPublicKey(
            "the card binding requires a 20-byte V4 fingerprint",
        ));
    }
    match (component.algorithm(), component.public_params()) {
        (PublicKeyAlgorithm::RSA, PublicParams::RSA(_))
            if matches!(
                slot,
                KeyType::Signing | KeyType::Decryption | KeyType::Authentication
            ) => {}
        (PublicKeyAlgorithm::ECDSA, PublicParams::ECDSA(parameters))
            if matches!(slot, KeyType::Signing | KeyType::Authentication) =>
        {
            ecdsa_widths(parameters)?;
        }
        (
            PublicKeyAlgorithm::EdDSALegacy,
            PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { .. }),
        ) if matches!(slot, KeyType::Signing | KeyType::Authentication) => {}
        (PublicKeyAlgorithm::ECDH, PublicParams::ECDH(parameters))
            if slot == KeyType::Decryption =>
        {
            ecdh_operation(parameters)?;
        }
        (PublicKeyAlgorithm::ECDSA, PublicParams::ECDSA(_))
        | (PublicKeyAlgorithm::ECDH, PublicParams::ECDH(_))
        | (PublicKeyAlgorithm::EdDSALegacy, PublicParams::EdDSALegacy(_)) => {
            return Err(RemoteKeyError::UnsupportedPublicKey(
                "unsupported curve, native KDF, or key/slot combination",
            ));
        }
        (algorithm, _) => {
            return Err(RemoteKeyError::UnsupportedAlgorithm { slot, algorithm });
        }
    }
    let inner = PubKeyInner::new(
        component.version(),
        component.algorithm(),
        component.created_at(),
        component.legacy_v3_expiration_days(),
        component.public_params().clone(),
    )
    .map_err(|error| RemoteKeyError::Rpgp(error.to_string()))?;
    PublicKey::from_inner(inner).map_err(|error| RemoteKeyError::Rpgp(error.to_string()))
}

fn validate_ecdh_parameters(
    hash: HashAlgorithm,
    alg_sym: SymmetricKeyAlgorithm,
) -> Result<(), RemoteKeyError> {
    if !matches!(
        hash,
        HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512
    ) {
        return Err(RemoteKeyError::UnsupportedHash(hash));
    }
    if !matches!(
        alg_sym,
        SymmetricKeyAlgorithm::AES128
            | SymmetricKeyAlgorithm::AES192
            | SymmetricKeyAlgorithm::AES256
    ) {
        return Err(RemoteKeyError::UnsupportedSymmetricAlgorithm(alg_sym));
    }
    Ok(())
}

struct SlotMetadata {
    identity: CardIdentity,
    public: PublicKey,
    stored_fingerprint: [u8; 20],
    created: u32,
    kdf_advertised: bool,
    touch_policy: Option<TouchPolicy>,
    user_retries: u8,
    user_pin_max_length: u8,
}

fn validate_fresh_binding(
    identity: CardIdentity,
    expected: &PublicKey,
    metadata: &SlotMetadata,
) -> Result<(), RemoteKeyError> {
    if metadata.identity != identity {
        return Err(RemoteKeyError::IdentityMismatch);
    }
    if metadata.created != expected.created_at().as_secs() {
        return Err(RemoteKeyError::SlotBinding("creation time differs"));
    }
    if metadata.stored_fingerprint.as_slice() != expected.fingerprint().as_bytes() {
        return Err(RemoteKeyError::SlotBinding(
            "the stored fingerprint differs from the certificate component",
        ));
    }
    if metadata.public.fingerprint().as_bytes() != metadata.stored_fingerprint {
        return Err(RemoteKeyError::SlotBinding(
            "the public material does not produce the stored fingerprint",
        ));
    }
    if !key_details_equal(expected, &metadata.public) {
        return Err(RemoteKeyError::SlotBinding(
            "the reconstructed public component differs",
        ));
    }
    Ok(())
}

fn key_details_equal(expected: &dyn KeyDetails, actual: &dyn KeyDetails) -> bool {
    expected.version() == actual.version()
        && expected.legacy_key_id() == actual.legacy_key_id()
        && expected.fingerprint() == actual.fingerprint()
        && expected.algorithm() == actual.algorithm()
        && expected.created_at() == actual.created_at()
        && expected.legacy_v3_expiration_days() == actual.legacy_v3_expiration_days()
        && expected.public_params() == actual.public_params()
}

fn parse_session_key(
    plain: Zeroizing<Vec<u8>>,
    typ: EskType,
) -> Result<PlainSessionKey, RemoteKeyError> {
    match typ {
        EskType::V3_4 => {
            if plain.len() < 3 {
                return Err(RemoteKeyError::InvalidSessionKey(
                    "V3 framing is shorter than an algorithm octet and checksum",
                ));
            }
            let sym_alg = SymmetricKeyAlgorithm::from(plain[0]);
            if matches!(
                sym_alg,
                SymmetricKeyAlgorithm::Plaintext
                    | SymmetricKeyAlgorithm::Private10
                    | SymmetricKeyAlgorithm::Other(_)
            ) {
                return Err(RemoteKeyError::InvalidSessionKey(
                    "plaintext, private, and unknown symmetric algorithms are not session keys",
                ));
            }
            let key_size = sym_alg.key_size();
            if plain.len() != key_size + 3 {
                return Err(RemoteKeyError::InvalidSessionKey(
                    "V3 session-key length does not match its symmetric algorithm",
                ));
            }
            let key = &plain[1..=key_size];
            let checksum_bytes = [plain[key_size + 1], plain[key_size + 2]];
            checksum::simple(checksum_bytes, key)
                .map_err(|_| RemoteKeyError::InvalidSessionKey("checksum mismatch"))?;
            Ok(PlainSessionKey::V3_4 {
                key: key.into(),
                sym_alg,
            })
        }
        EskType::V6 => {
            if plain.len() < 3 {
                return Err(RemoteKeyError::InvalidSessionKey(
                    "V6 framing must contain a non-empty key and checksum",
                ));
            }
            let key_end = plain.len() - 2;
            let key = &plain[..key_end];
            let checksum_bytes = [plain[key_end], plain[key_end + 1]];
            checksum::simple(checksum_bytes, key)
                .map_err(|_| RemoteKeyError::InvalidSessionKey("checksum mismatch"))?;
            Ok(PlainSessionKey::V6 { key: key.into() })
        }
    }
}

fn verify_pin(
    transaction: &mut dyn CardTransaction,
    metadata: &SlotMetadata,
    purpose: PinPurpose,
    identity: CardIdentity,
    provider: &dyn PinProvider,
) -> Result<(), RemoteKeyError> {
    if purpose == PinPurpose::Admin {
        return Err(RemoteKeyError::InvalidOperation(
            "admin verification is not a private-key operation",
        ));
    }
    validate_pin_policy(transaction, metadata)?;
    let pin = provider.request_pin(purpose, &identity)?;
    if pin.is_empty() {
        return Err(RemoteKeyError::EmptyPin);
    }
    let maximum = usize::from(metadata.user_pin_max_length);
    if !(6..=maximum).contains(&pin.len()) {
        return Err(RemoteKeyError::InvalidPinLength {
            minimum: 6,
            maximum,
            actual: pin.len(),
        });
    }
    transaction
        .verify(purpose, pin)
        .map_err(|error| match error {
            RemoteKeyError::Card(openpgp_card::Error::CardStatus(
                StatusBytes::PasswordNotChecked(remaining_retries),
            )) => RemoteKeyError::WrongPin { remaining_retries },
            other => other,
        })
}

fn validate_pin_policy(
    transaction: &mut dyn CardTransaction,
    metadata: &SlotMetadata,
) -> Result<(), RemoteKeyError> {
    let kdf = match transaction.kdf_do() {
        Ok(kdf) => Some(kdf),
        Err(RemoteKeyError::Card(openpgp_card::Error::CardStatus(status)))
            if !metadata.kdf_advertised
                && matches!(
                    status,
                    StatusBytes::ReferencedDataNotFound | StatusBytes::FileOrApplicationNotFound
                ) =>
        {
            None
        }
        Err(RemoteKeyError::Card(openpgp_card::Error::NotFound(_))) if !metadata.kdf_advertised => {
            None
        }
        Err(error) => return Err(error),
    };
    if let Some(kdf) = kdf {
        validate_kdf(&kdf)?;
    }
    if metadata.user_retries < 2 {
        return Err(RemoteKeyError::PinRetriesUnavailable {
            remaining_retries: metadata.user_retries,
        });
    }
    Ok(())
}

pub fn validate_kdf(kdf: &KdfDo) -> Result<(), RemoteKeyError> {
    match kdf.kdf_algo() {
        0 => {
            if kdf.hash_algo().is_some()
                || kdf.iter_count().is_some()
                || [
                    kdf.salt_pw1(),
                    kdf.salt_rc(),
                    kdf.salt_pw3(),
                    kdf.initial_hash_pw1(),
                    kdf.initial_hash_pw3(),
                ]
                .iter()
                .any(Option::is_some)
            {
                return Err(RemoteKeyError::InvalidKdf(
                    "raw PIN mode forbids KDF hash, iteration, salt, or initial-hash fields",
                ));
            }
            Ok(())
        }
        3 => {
            if !matches!(kdf.hash_algo(), Some(0x08 | 0x0A)) {
                return Err(RemoteKeyError::InvalidKdf(
                    "iterated-salted KDF requires SHA-256 or SHA-512",
                ));
            }
            if kdf.iter_count().is_none_or(|count| count == 0) {
                return Err(RemoteKeyError::InvalidKdf(
                    "iterated-salted KDF requires a nonzero iteration count",
                ));
            }
            if kdf.salt_pw1().is_none_or(|salt| salt.is_empty()) {
                return Err(RemoteKeyError::InvalidKdf(
                    "iterated-salted KDF requires a PW1 salt",
                ));
            }
            Ok(())
        }
        algorithm => Err(RemoteKeyError::UnsupportedKdf(algorithm)),
    }
}

enum TransactionOutput {
    Identity(CardIdentity),
    Slot,
    Authorization(OperationAuthorization),
    Bytes(Vec<u8>),
}

type TransactionOperation<'a> =
    Box<dyn FnOnce(&mut dyn CardTransaction) -> Result<TransactionOutput, RemoteKeyError> + 'a>;

trait CardConnector: Send {
    fn transact(
        &mut self,
        operation: TransactionOperation<'_>,
    ) -> Result<TransactionOutput, RemoteKeyError>;

    fn failure_kind(&self) -> RemoteKeyFailure {
        RemoteKeyFailure::Unavailable
    }
}

trait CardTransaction {
    fn identity(&mut self) -> Result<CardIdentity, RemoteKeyError>;

    fn read_slot(
        &mut self,
        slot: KeyType,
        expected: &PublicKey,
    ) -> Result<SlotMetadata, RemoteKeyError>;

    fn kdf_do(&mut self) -> Result<KdfDo, RemoteKeyError>;

    fn verify(&mut self, purpose: PinPurpose, pin: Zeroizing<String>)
    -> Result<(), RemoteKeyError>;

    fn sign(
        &mut self,
        slot: KeyType,
        algorithm: SigningAlgo,
        digest: &[u8],
    ) -> Result<Vec<u8>, RemoteKeyError>;

    fn decrypt(&mut self, cryptogram: Cryptogram<'_>) -> Result<Vec<u8>, RemoteKeyError>;
}

struct TransportConnector {
    transport: Arc<dyn RawCardTransport>,
}

impl CardConnector for TransportConnector {
    fn transact(
        &mut self,
        operation: TransactionOperation<'_>,
    ) -> Result<TransactionOutput, RemoteKeyError> {
        let backend = TransportCardBackend::new(Arc::clone(&self.transport))?;
        let backend: Box<dyn card_backend::CardBackend + Send + Sync> = Box::new(backend);
        let mut card = Card::new(backend)?;
        let transaction = card.transaction()?;
        let mut transaction = ConcreteTransaction { transaction };
        operation(&mut transaction)
    }

    fn failure_kind(&self) -> RemoteKeyFailure {
        self.transport.failure_kind()
    }
}

struct PcscConnector {
    reader: String,
}

impl CardConnector for PcscConnector {
    fn transact(
        &mut self,
        operation: TransactionOperation<'_>,
    ) -> Result<TransactionOutput, RemoteKeyError> {
        let mut context = PcscContext::establish()?;
        let readers = context.list_readers()?;
        let reader = require_exact_reader(&readers, &self.reader)?;
        let backend = context.connect(reader)?;
        let backend: Box<dyn card_backend::CardBackend + Send + Sync> = Box::new(backend);
        let mut card = Card::new(backend)?;
        let transaction = card.transaction()?;
        let mut transaction = ConcreteTransaction { transaction };
        operation(&mut transaction)
    }
}

struct ConcreteTransaction<'a> {
    transaction: Card<Transaction<'a>>,
}

impl ConcreteTransaction<'_> {
    fn fresh_ard(
        &mut self,
    ) -> Result<openpgp_card::ocard::data::ApplicationRelatedData, RemoteKeyError> {
        self.transaction
            .card()
            .application_related_data()
            .map_err(Into::into)
    }
}

impl CardTransaction for ConcreteTransaction<'_> {
    fn identity(&mut self) -> Result<CardIdentity, RemoteKeyError> {
        let ard = self.fresh_ard()?;
        Ok(CardIdentity::from_application_identifier(
            &ard.application_id()?,
        ))
    }

    fn read_slot(
        &mut self,
        slot: KeyType,
        expected: &PublicKey,
    ) -> Result<SlotMetadata, RemoteKeyError> {
        let ard = self.fresh_ard()?;
        let identity = CardIdentity::from_application_identifier(&ard.application_id()?);
        let fingerprints = ard.fingerprints()?;
        let stored = match slot {
            KeyType::Signing => fingerprints.signature(),
            KeyType::Decryption => fingerprints.decryption(),
            KeyType::Authentication => fingerprints.authentication(),
            KeyType::Attestation => None,
        }
        .ok_or(RemoteKeyError::MissingSlotData("fingerprint"))?;
        let stored_fingerprint: [u8; 20] = stored
            .as_bytes()
            .try_into()
            .map_err(|_| RemoteKeyError::SlotBinding("the card fingerprint is not 20 bytes"))?;
        let times = ard.key_generation_times()?;
        let created: KeyGenerationTime = *match slot {
            KeyType::Signing => times.signature(),
            KeyType::Decryption => times.decryption(),
            KeyType::Authentication => times.authentication(),
            KeyType::Attestation => None,
        }
        .ok_or(RemoteKeyError::MissingSlotData("creation time"))?;
        let attributes = ard.algorithm_attributes(slot)?;
        let material = self.transaction.public_key_material(slot)?;
        match (&material, &attributes) {
            (PublicKeyMaterial::E(ecc), _) if ecc.algo() == &attributes => {}
            (
                PublicKeyMaterial::R(_),
                openpgp_card::ocard::algorithm::AlgorithmAttributes::Rsa(_),
            ) => {}
            _ => {
                return Err(RemoteKeyError::SlotBinding(
                    "algorithm attributes and public material disagree",
                ));
            }
        }
        let (hash, alg_sym) = match expected.public_params() {
            PublicParams::ECDH(parameters) => {
                let operation = ecdh_operation(parameters)?;
                (Some(operation.hash), Some(operation.alg_sym))
            }
            _ => (None, None),
        };
        let public =
            openpgp_card_rpgp::public_key_material_to_key(&material, slot, &created, hash, alg_sym)
                .map_err(|error| RemoteKeyError::PublicMaterial(error.to_string()))?;
        if let (
            openpgp_card::ocard::algorithm::AlgorithmAttributes::Rsa(attributes),
            PublicParams::RSA(rsa),
        ) = (&attributes, public.public_params())
        {
            let layout = rsa_layout(rsa)?;
            if attributes.len_n() != layout.modulus_bits
                || attributes.len_e() != layout.exponent_bits
            {
                return Err(RemoteKeyError::SlotBinding(
                    "RSA algorithm attribute widths do not match the public key",
                ));
            }
        }
        let kdf_advertised = ard.extended_capabilities()?.kdf_do();
        let uif = match slot {
            KeyType::Signing => ard.uif_pso_cds()?,
            KeyType::Decryption => ard.uif_pso_dec()?,
            KeyType::Authentication => ard.uif_pso_aut()?,
            KeyType::Attestation => {
                return Err(RemoteKeyError::InvalidOperation(
                    "attestation is unsupported",
                ));
            }
        };
        let password_status = ard.pw_status_bytes()?;
        Ok(SlotMetadata {
            identity,
            public,
            stored_fingerprint,
            created: created.get(),
            kdf_advertised,
            touch_policy: uif.map(|flag| flag.touch_policy()),
            user_retries: password_status.err_count_pw1(),
            user_pin_max_length: password_status.pw1_max_len(),
        })
    }

    fn kdf_do(&mut self) -> Result<KdfDo, RemoteKeyError> {
        self.transaction.kdf_do().map_err(Into::into)
    }

    fn verify(
        &mut self,
        purpose: PinPurpose,
        pin: Zeroizing<String>,
    ) -> Result<(), RemoteKeyError> {
        let owned = pin.as_str().to_owned();
        match purpose {
            PinPurpose::Signing => self.transaction.verify_user_signing_pin(owned.into())?,
            PinPurpose::User => self.transaction.verify_user_pin(owned.into())?,
            PinPurpose::Admin => {
                return Err(RemoteKeyError::InvalidOperation(
                    "admin verification is not used by remote private-key operations",
                ));
            }
        }
        Ok(())
    }

    fn sign(
        &mut self,
        slot: KeyType,
        algorithm: SigningAlgo,
        digest: &[u8],
    ) -> Result<Vec<u8>, RemoteKeyError> {
        match slot {
            KeyType::Signing => self
                .transaction
                .card()
                .signature_for_hash(algorithm, digest)
                .map_err(Into::into),
            KeyType::Authentication => self
                .transaction
                .card()
                .authenticate_for_hash(algorithm, digest)
                .map_err(Into::into),
            _ => Err(RemoteKeyError::InvalidOperation(
                "PSO:CDS and INTERNAL AUTHENTICATE require their respective slots",
            )),
        }
    }

    fn decrypt(&mut self, cryptogram: Cryptogram<'_>) -> Result<Vec<u8>, RemoteKeyError> {
        self.transaction
            .card()
            .decipher(cryptogram)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use pgp::{
        composed::{Deserializable as _, SignedSecretKey},
        types::Mpi,
    };

    use super::*;

    const IDENTITY: CardIdentity = CardIdentity::new(0xF1D0, 0x0123ABCD, 0x0304);

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Event {
        Metadata(KeyType),
        Kdf,
        Pin(PinPurpose),
        Verify(PinPurpose),
        Touch(KeyType),
        Sign(KeyType, usize),
        Decrypt(usize),
    }

    struct MockState {
        identity: CardIdentity,
        card_key: Option<PublicKey>,
        stored_fingerprint: Option<[u8; 20]>,
        created: Option<u32>,
        kdf_advertised: bool,
        kdf_missing: bool,
        kdf_failure: bool,
        pin_retries: u8,
        pin_max_length: u8,
        wrong_pin: bool,
        touch_required: bool,
        sign_response: Vec<u8>,
        decrypt_response: Vec<u8>,
        events: Vec<Event>,
        connections: usize,
    }

    impl Default for MockState {
        fn default() -> Self {
            Self {
                identity: IDENTITY,
                card_key: None,
                stored_fingerprint: None,
                created: None,
                kdf_advertised: false,
                kdf_missing: true,
                kdf_failure: false,
                pin_retries: 3,
                pin_max_length: 64,
                wrong_pin: false,
                touch_required: false,
                sign_response: (1_u8..=64).collect(),
                decrypt_response: vec![0x11; 32],
                events: Vec::new(),
                connections: 0,
            }
        }
    }

    struct MockConnector {
        state: Arc<Mutex<MockState>>,
    }

    impl CardConnector for MockConnector {
        fn transact(
            &mut self,
            operation: TransactionOperation<'_>,
        ) -> Result<TransactionOutput, RemoteKeyError> {
            self.state.lock().expect("mock state").connections += 1;
            let mut transaction = MockTransaction {
                state: Arc::clone(&self.state),
            };
            operation(&mut transaction)
        }
    }

    struct MockTransaction {
        state: Arc<Mutex<MockState>>,
    }

    impl CardTransaction for MockTransaction {
        fn identity(&mut self) -> Result<CardIdentity, RemoteKeyError> {
            Ok(self.state.lock().expect("mock state").identity)
        }

        fn read_slot(
            &mut self,
            slot: KeyType,
            expected: &PublicKey,
        ) -> Result<SlotMetadata, RemoteKeyError> {
            let mut state = self.state.lock().expect("mock state");
            state.events.push(Event::Metadata(slot));
            let stored_fingerprint = state.stored_fingerprint.unwrap_or_else(|| {
                expected
                    .fingerprint()
                    .as_bytes()
                    .try_into()
                    .expect("V4 test fingerprint")
            });
            Ok(SlotMetadata {
                identity: state.identity,
                public: state.card_key.clone().unwrap_or_else(|| expected.clone()),
                stored_fingerprint,
                created: state
                    .created
                    .unwrap_or_else(|| expected.created_at().as_secs()),
                kdf_advertised: state.kdf_advertised,
                touch_policy: state.touch_required.then_some(TouchPolicy::On),
                user_retries: state.pin_retries,
                user_pin_max_length: state.pin_max_length,
            })
        }

        fn kdf_do(&mut self) -> Result<KdfDo, RemoteKeyError> {
            let mut state = self.state.lock().expect("mock state");
            state.events.push(Event::Kdf);
            if state.kdf_failure {
                return Err(openpgp_card::Error::ParseError(
                    "synthetic KDF read failure".to_owned(),
                )
                .into());
            }
            if state.kdf_missing {
                return Err(if state.kdf_advertised {
                    openpgp_card::Error::CardStatus(StatusBytes::ReferencedDataNotFound).into()
                } else {
                    openpgp_card::Error::NotFound("No KDF DO found".to_owned()).into()
                });
            }
            KdfDo::try_from(&[0x81, 0x01, 0x00][..]).map_err(Into::into)
        }

        fn verify(
            &mut self,
            purpose: PinPurpose,
            _pin: Zeroizing<String>,
        ) -> Result<(), RemoteKeyError> {
            let mut state = self.state.lock().expect("mock state");
            state.events.push(Event::Verify(purpose));
            if state.wrong_pin {
                Err(openpgp_card::Error::CardStatus(StatusBytes::PasswordNotChecked(2)).into())
            } else {
                Ok(())
            }
        }

        fn sign(
            &mut self,
            slot: KeyType,
            _algorithm: SigningAlgo,
            digest: &[u8],
        ) -> Result<Vec<u8>, RemoteKeyError> {
            let mut state = self.state.lock().expect("mock state");
            state.events.push(Event::Sign(slot, digest.len()));
            Ok(state.sign_response.clone())
        }

        fn decrypt(&mut self, cryptogram: Cryptogram<'_>) -> Result<Vec<u8>, RemoteKeyError> {
            let mut state = self.state.lock().expect("mock state");
            let input_length = match cryptogram {
                Cryptogram::RSA(ciphertext) => ciphertext.len(),
                Cryptogram::ECDH(point) => point.len(),
            };
            state.events.push(Event::Decrypt(input_length));
            Ok(state.decrypt_response.clone())
        }
    }

    struct TestInteraction {
        state: Arc<Mutex<MockState>>,
        pin_requests: AtomicUsize,
        touch_requests: AtomicUsize,
    }

    impl TestInteraction {
        fn new(state: Arc<Mutex<MockState>>) -> Self {
            Self {
                state,
                pin_requests: AtomicUsize::new(0),
                touch_requests: AtomicUsize::new(0),
            }
        }
    }

    impl PinProvider for TestInteraction {
        fn request_pin(
            &self,
            purpose: PinPurpose,
            identity: &CardIdentity,
        ) -> Result<Zeroizing<String>, CardInteractionError> {
            assert_eq!(*identity, IDENTITY);
            self.pin_requests.fetch_add(1, Ordering::Relaxed);
            self.state
                .lock()
                .expect("mock state")
                .events
                .push(Event::Pin(purpose));
            Ok(Zeroizing::new("synthetic-test-pin".to_owned()))
        }
    }

    impl TouchPrompt for TestInteraction {
        fn request_touch(&self, slot: KeyType) -> Result<(), CardInteractionError> {
            self.touch_requests.fetch_add(1, Ordering::Relaxed);
            self.state
                .lock()
                .expect("mock state")
                .events
                .push(Event::Touch(slot));
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum TestFixture {
        Nist256,
        Nist384,
        Nist521,
        Rsa2048,
        Legacy25519,
    }

    impl TestFixture {
        fn armored_key(self) -> &'static str {
            match self {
                Self::Nist256 => {
                    include_str!("../../../../vendor/openpgp-card-rpgp/tests/keys/nist256.tsk")
                }
                Self::Nist384 => {
                    include_str!("../../../../vendor/openpgp-card-rpgp/tests/keys/nist384.tsk")
                }
                Self::Nist521 => {
                    include_str!("../../../../vendor/openpgp-card-rpgp/tests/keys/nist521.tsk")
                }
                Self::Rsa2048 => {
                    include_str!("../../../../vendor/openpgp-card-rpgp/tests/keys/rsa2k.tsk")
                }
                Self::Legacy25519 => {
                    include_str!("../../../../vendor/openpgp-card-rpgp/tests/keys/25519.tsk")
                }
            }
        }
    }

    fn public_component_from(
        fixture: TestFixture,
        algorithm: PublicKeyAlgorithm,
    ) -> pgp::packet::PublicSubkey {
        let (secret, _) = SignedSecretKey::from_string(fixture.armored_key())
            .expect("parse the public test fixture");
        secret
            .to_public_key()
            .public_subkeys
            .into_iter()
            .find(|subkey| subkey.key.algorithm() == algorithm)
            .expect("fixture component")
            .key
    }

    fn public_component(algorithm: PublicKeyAlgorithm) -> pgp::packet::PublicSubkey {
        public_component_from(TestFixture::Nist256, algorithm)
    }

    fn recreated_component(
        component: &dyn KeyDetails,
        version: KeyVersion,
        created: u32,
    ) -> PublicKey {
        PublicKey::from_inner(
            PubKeyInner::new(
                version,
                component.algorithm(),
                Timestamp::from_secs(created),
                component.legacy_v3_expiration_days(),
                component.public_params().clone(),
            )
            .expect("valid recreated test component"),
        )
        .expect("valid recreated public key")
    }

    fn mock_session() -> (CardSession, Arc<Mutex<MockState>>, Arc<TestInteraction>) {
        let state = Arc::new(Mutex::new(MockState::default()));
        let interaction = Arc::new(TestInteraction::new(Arc::clone(&state)));
        let connector = MockConnector {
            state: Arc::clone(&state),
        };
        (
            CardSession::from_connector(
                IDENTITY,
                Box::new(connector),
                interaction.clone(),
                interaction.clone(),
            ),
            state,
            interaction,
        )
    }

    fn bound_component(
        component: &dyn KeyDetails,
        slot: KeyType,
    ) -> (RemoteCardKey, Arc<Mutex<MockState>>, Arc<TestInteraction>) {
        let (session, state, interaction) = mock_session();
        let key = session.bind(slot, component).expect("bound test key");
        {
            let mut state = state.lock().expect("mock state");
            state.events.clear();
            state.connections = 0;
        }
        (key, state, interaction)
    }

    fn bound_fixture(
        fixture: TestFixture,
        algorithm: PublicKeyAlgorithm,
        slot: KeyType,
    ) -> (RemoteCardKey, Arc<Mutex<MockState>>, Arc<TestInteraction>) {
        bound_component(&public_component_from(fixture, algorithm), slot)
    }

    fn bound_key(
        algorithm: PublicKeyAlgorithm,
        slot: KeyType,
    ) -> (RemoteCardKey, Arc<Mutex<MockState>>, Arc<TestInteraction>) {
        bound_component(&public_component(algorithm), slot)
    }

    #[test]
    fn authorization_preparation_reads_policy_without_pin_touch_or_pso() {
        let (key, state, interaction) = bound_key(PublicKeyAlgorithm::ECDSA, KeyType::Signing);
        state.lock().expect("mock state").touch_required = true;
        let authorization = key
            .authorization_requirements()
            .expect("read-only authorization requirements");
        assert_eq!(authorization.slot, KeyType::Signing);
        assert_eq!(authorization.pin_purpose, PinPurpose::Signing);
        assert_eq!(authorization.minimum_pin_length, 6);
        assert_eq!(authorization.maximum_pin_length, 64);
        assert_eq!(authorization.remaining_pin_retries, 3);
        assert_eq!(authorization.touch_policy, Some(TouchPolicy::On));
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 0);
        assert_eq!(interaction.touch_requests.load(Ordering::Relaxed), 0);
        assert_eq!(
            state.lock().expect("mock state").events,
            [Event::Metadata(KeyType::Signing), Event::Kdf]
        );
    }

    #[test]
    fn authorization_preparation_refuses_low_retries_before_requesting_a_pin() {
        let (key, state, interaction) = bound_key(PublicKeyAlgorithm::ECDH, KeyType::Decryption);
        state.lock().expect("mock state").pin_retries = 1;
        assert!(matches!(
            key.authorization_requirements(),
            Err(RemoteKeyError::PinRetriesUnavailable {
                remaining_retries: 1
            })
        ));
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 0);
        assert_eq!(interaction.touch_requests.load(Ordering::Relaxed), 0);
        assert_eq!(
            state.lock().expect("mock state").events,
            [Event::Metadata(KeyType::Decryption), Event::Kdf]
        );
    }

    #[test]
    fn p256_signing_uses_real_rpgp_metadata_and_one_signing_pin() {
        let (key, state, interaction) = bound_key(PublicKeyAlgorithm::ECDSA, KeyType::Signing);
        state.lock().expect("mock state").touch_required = true;
        let signature = key
            .sign(&Password::empty(), HashAlgorithm::Sha512, &[0xA5; 64])
            .expect("mock P-256 signature");
        let SignatureBytes::Mpis(mpis) = signature else {
            panic!("legacy ECDSA must use MPIs")
        };
        assert_eq!(mpis.len(), 2);
        assert_eq!(mpis[0].as_ref(), &(1_u8..=32).collect::<Vec<_>>());
        assert_eq!(mpis[1].as_ref(), &(33_u8..=64).collect::<Vec<_>>());
        assert_eq!(key.version(), KeyVersion::V4);
        assert_eq!(key.hash_alg(), HashAlgorithm::Sha256);
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 1);
        assert_eq!(interaction.touch_requests.load(Ordering::Relaxed), 1);
        assert_eq!(
            state.lock().expect("mock state").events,
            [
                Event::Metadata(KeyType::Signing),
                Event::Kdf,
                Event::Pin(PinPurpose::Signing),
                Event::Verify(PinPurpose::Signing),
                Event::Touch(KeyType::Signing),
                Event::Sign(KeyType::Signing, 32),
            ]
        );
    }

    #[test]
    fn authentication_uses_pw1_mode_82_and_internal_authenticate() {
        let (key, state, interaction) =
            bound_key(PublicKeyAlgorithm::ECDSA, KeyType::Authentication);
        key.sign(&Password::empty(), HashAlgorithm::Sha256, &[0x5A; 32])
            .expect("mock authentication signature");
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 1);
        assert!(
            state
                .lock()
                .expect("mock state")
                .events
                .contains(&Event::Verify(PinPurpose::User))
        );
        assert!(
            state
                .lock()
                .expect("mock state")
                .events
                .contains(&Event::Sign(KeyType::Authentication, 32))
        );
    }

    #[test]
    fn identity_change_is_rejected_before_pin_or_touch() {
        let component = public_component(PublicKeyAlgorithm::ECDSA);
        let (session, state, interaction) = mock_session();
        state.lock().expect("mock state").identity =
            CardIdentity::new(IDENTITY.manufacturer(), IDENTITY.serial(), 0x0305);
        assert!(matches!(
            session.bind(KeyType::Signing, &component),
            Err(RemoteKeyError::IdentityMismatch)
        ));
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 0);
        assert_eq!(interaction.touch_requests.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn wrong_public_material_and_stored_fingerprint_are_rejected() {
        let component = public_component(PublicKeyAlgorithm::ECDSA);
        let (session, state, _) = mock_session();
        state.lock().expect("mock state").card_key = Some(recreated_component(
            &component,
            KeyVersion::V4,
            component.created_at().as_secs() + 1,
        ));
        assert!(matches!(
            session.bind(KeyType::Signing, &component),
            Err(RemoteKeyError::SlotBinding(_))
        ));

        let (session, state, interaction) = mock_session();
        state.lock().expect("mock state").stored_fingerprint = Some([0x55; 20]);
        assert!(matches!(
            session.bind(KeyType::Signing, &component),
            Err(RemoteKeyError::SlotBinding(_))
        ));
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn v6_components_are_explicitly_unsupported_without_card_access() {
        let component = public_component(PublicKeyAlgorithm::ECDSA);
        let v6 = recreated_component(&component, KeyVersion::V6, component.created_at().as_secs());
        let (session, state, interaction) = mock_session();
        assert!(matches!(
            session.bind(KeyType::Signing, &v6),
            Err(RemoteKeyError::UnsupportedKeyVersion(KeyVersion::V6))
        ));
        assert_eq!(state.lock().expect("mock state").connections, 0);
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn kdf_read_failure_never_requests_or_verifies_a_pin() {
        let (key, state, interaction) = bound_key(PublicKeyAlgorithm::ECDSA, KeyType::Signing);
        state.lock().expect("mock state").kdf_failure = true;
        assert!(key.sign_digest(HashAlgorithm::Sha256, &[0x5A; 32]).is_err());
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 0);
        let state = state.lock().expect("mock state");
        assert_eq!(
            state.events,
            [Event::Metadata(KeyType::Signing), Event::Kdf]
        );
        assert!(!state.events.iter().any(|event| matches!(
            event,
            Event::Verify(_) | Event::Sign(_, _) | Event::Touch(_)
        )));
    }

    #[test]
    fn wrong_pin_is_reported_once_without_touch_or_pso() {
        let (key, state, interaction) = bound_key(PublicKeyAlgorithm::ECDSA, KeyType::Signing);
        state.lock().expect("mock state").wrong_pin = true;
        state.lock().expect("mock state").touch_required = true;
        assert!(matches!(
            key.sign_digest(HashAlgorithm::Sha256, &[0x5A; 32]),
            Err(RemoteKeyError::WrongPin {
                remaining_retries: 2
            })
        ));
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 1);
        assert_eq!(interaction.touch_requests.load(Ordering::Relaxed), 0);
        assert_eq!(
            state.lock().expect("mock state").events,
            [
                Event::Metadata(KeyType::Signing),
                Event::Kdf,
                Event::Pin(PinPurpose::Signing),
                Event::Verify(PinPurpose::Signing),
            ]
        );
    }

    #[test]
    fn malformed_digest_is_rejected_before_a_new_connection() {
        let (key, state, interaction) = bound_key(PublicKeyAlgorithm::ECDSA, KeyType::Signing);
        assert!(matches!(
            key.sign_digest(HashAlgorithm::Sha256, &[0x5A; 31]),
            Err(RemoteKeyError::InvalidDigestLength {
                expected: 32,
                actual: 31
            })
        ));
        assert_eq!(state.lock().expect("mock state").connections, 0);
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn malformed_ecdh_point_is_rejected_before_pin_or_pso() {
        let (key, state, interaction) = bound_key(PublicKeyAlgorithm::ECDH, KeyType::Decryption);
        let values = PkeskBytes::Ecdh {
            public_point: Mpi::from_slice(&[0x04; 64]),
            encrypted_session_key: vec![0x22; 16].into(),
        };
        assert!(matches!(
            key.decrypt_session_key(&values, EskType::V3_4),
            Err(RemoteKeyError::InvalidCiphertext(_))
        ));
        assert_eq!(state.lock().expect("mock state").connections, 0);
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 0);
    }

    fn framed_session_key(typ: EskType, key: &[u8]) -> Vec<u8> {
        let mut framed = Vec::new();
        if matches!(typ, EskType::V3_4) {
            framed.push(u8::from(SymmetricKeyAlgorithm::AES256));
        }
        framed.extend_from_slice(key);
        framed.extend_from_slice(&checksum::calculate_simple(key).to_be_bytes());
        framed
    }

    fn ecdh_point(parameters: &EcdhPublicParams) -> Vec<u8> {
        let encoded = parameters.to_bytes().expect("serialize ECDH parameters");
        let oid_length = encoded[0] as usize;
        let mpi = 1 + oid_length;
        let bits = u16::from_be_bytes([encoded[mpi], encoded[mpi + 1]]) as usize;
        let bytes = bits.div_ceil(8);
        encoded[mpi + 2..mpi + 2 + bytes].to_vec()
    }

    fn wrapped_session_key(public: &PublicKey, shared_secret: &[u8], plain: &[u8]) -> Vec<u8> {
        let PublicParams::ECDH(parameters) = public.public_params() else {
            panic!("ECDH test key required")
        };
        let operation = ecdh_operation(parameters).expect("supported test ECDH parameters");
        let fingerprint = public.fingerprint();
        let parameter = ecdh::build_ecdh_param(
            &operation.curve.oid(),
            operation.alg_sym,
            operation.hash,
            fingerprint.as_bytes(),
        );
        let kek = ecdh::kdf(
            operation.hash,
            shared_secret,
            operation.alg_sym.key_size(),
            &parameter,
        )
        .expect("test ECDH KDF");
        let padding = 8 - plain.len() % 8;
        let mut padded = plain.to_vec();
        padded.resize(plain.len() + padding, padding as u8);
        pgp::crypto::aes_kw::wrap(&kek, &padded).expect("wrap test session key")
    }

    fn decrypt_p256(typ: EskType) -> (PlainSessionKey, Vec<u8>) {
        let (key, state, _) = bound_key(PublicKeyAlgorithm::ECDH, KeyType::Decryption);
        let session_key = vec![0x42; 32];
        let plain = framed_session_key(typ, &session_key);
        let shared_secret = vec![0x11; 32];
        let encrypted = wrapped_session_key(key.public_key(), &shared_secret, &plain);
        let PublicParams::ECDH(parameters) = key.public_params() else {
            panic!("ECDH test key required")
        };
        let values = PkeskBytes::Ecdh {
            public_point: Mpi::from_slice(&ecdh_point(parameters)),
            encrypted_session_key: encrypted.into(),
        };
        state.lock().expect("mock state").decrypt_response = shared_secret;
        let decrypted = key
            .decrypt(&Password::empty(), &values, typ)
            .expect("remote decryption trait call")
            .expect("decrypted session key");
        (decrypted, session_key)
    }

    #[test]
    fn p256_ecdh_decrypts_v3_session_key_through_real_rpgp_traits() {
        let (decrypted, expected) = decrypt_p256(EskType::V3_4);
        let PlainSessionKey::V3_4 { ref key, sym_alg } = decrypted else {
            panic!("V3 session key required")
        };
        assert_eq!(sym_alg, SymmetricKeyAlgorithm::AES256);
        assert_eq!(key.as_ref(), expected);
    }

    #[test]
    fn p256_ecdh_decrypts_v6_session_key_without_algorithm_octet() {
        let (decrypted, expected) = decrypt_p256(EskType::V6);
        let PlainSessionKey::V6 { ref key } = decrypted else {
            panic!("V6 session key required")
        };
        assert_eq!(key.as_ref(), expected);
    }

    #[test]
    fn malformed_session_key_checksum_and_shared_secret_length_are_rejected() {
        assert!(matches!(
            parse_session_key(Zeroizing::new(vec![0]), EskType::V3_4),
            Err(RemoteKeyError::InvalidSessionKey(_))
        ));
        let mut bad_checksum = framed_session_key(EskType::V3_4, &[0x42; 32]);
        let last = bad_checksum.last_mut().expect("checksum");
        *last ^= 1;
        assert!(matches!(
            parse_session_key(Zeroizing::new(bad_checksum), EskType::V3_4),
            Err(RemoteKeyError::InvalidSessionKey("checksum mismatch"))
        ));

        let (key, state, _) = bound_key(PublicKeyAlgorithm::ECDH, KeyType::Decryption);
        let PublicParams::ECDH(parameters) = key.public_params() else {
            panic!("ECDH test key required")
        };
        let values = PkeskBytes::Ecdh {
            public_point: Mpi::from_slice(&ecdh_point(parameters)),
            encrypted_session_key: vec![0x22; 16].into(),
        };
        state.lock().expect("mock state").decrypt_response = vec![0x11; 31];
        assert!(matches!(
            key.decrypt_session_key(&values, EskType::V6),
            Err(RemoteKeyError::MalformedResponse {
                expected: 32,
                actual: 31
            })
        ));
    }

    #[test]
    fn pw1_mode_82_is_verified_for_each_new_connection() {
        let (key, state, interaction) = bound_key(PublicKeyAlgorithm::ECDH, KeyType::Decryption);
        let session_key = vec![0x42; 32];
        let plain = framed_session_key(EskType::V3_4, &session_key);
        let shared_secret = vec![0x11; 32];
        let encrypted = wrapped_session_key(key.public_key(), &shared_secret, &plain);
        let PublicParams::ECDH(parameters) = key.public_params() else {
            panic!("ECDH test key required")
        };
        let values = PkeskBytes::Ecdh {
            public_point: Mpi::from_slice(&ecdh_point(parameters)),
            encrypted_session_key: encrypted.into(),
        };
        state.lock().expect("mock state").decrypt_response = shared_secret;
        for _ in 0..2 {
            key.decrypt(&Password::empty(), &values, EskType::V3_4)
                .expect("remote decryption trait call")
                .expect("session key");
        }
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 2);
        let state = state.lock().expect("mock state");
        assert_eq!(state.connections, 2);
        assert_eq!(
            state
                .events
                .iter()
                .filter(|event| matches!(event, Event::Verify(PinPurpose::User)))
                .count(),
            2
        );
        assert_eq!(
            state
                .events
                .iter()
                .filter(|event| matches!(event, Event::Decrypt(65)))
                .count(),
            2
        );
    }

    #[test]
    fn pin_retries_and_length_are_checked_without_verify_or_pso() {
        let (key, state, interaction) = bound_key(PublicKeyAlgorithm::ECDSA, KeyType::Signing);
        state.lock().expect("mock state").pin_retries = 1;
        assert!(matches!(
            key.sign_digest(HashAlgorithm::Sha256, &[0x5A; 32]),
            Err(RemoteKeyError::PinRetriesUnavailable {
                remaining_retries: 1
            })
        ));
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 0);
        {
            let mut state = state.lock().expect("mock state");
            state.pin_retries = 3;
            state.pin_max_length = 5;
            state.events.clear();
        }
        let error = key
            .sign_digest(HashAlgorithm::Sha256, &[0x5A; 32])
            .expect_err("an overlong synthetic PIN must not reach VERIFY");
        assert!(matches!(
            error,
            RemoteKeyError::InvalidPinLength {
                minimum: 6,
                maximum: 5,
                actual,
            } if actual > 5
        ));
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 1);
        assert!(
            !state
                .lock()
                .expect("mock state")
                .events
                .iter()
                .any(|event| matches!(
                    event,
                    Event::Verify(_) | Event::Sign(_, _) | Event::Touch(_)
                ))
        );
    }

    #[test]
    fn missing_advertised_kdf_never_requests_or_verifies_a_pin() {
        let (key, state, interaction) = bound_key(PublicKeyAlgorithm::ECDSA, KeyType::Signing);
        {
            let mut state = state.lock().expect("mock state");
            state.kdf_advertised = true;
            state.kdf_missing = true;
        }
        assert!(matches!(
            key.sign_digest(HashAlgorithm::Sha256, &[0x5A; 32]),
            Err(RemoteKeyError::Card(openpgp_card::Error::CardStatus(
                StatusBytes::ReferencedDataNotFound
            )))
        ));
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 0);
        assert_eq!(
            state.lock().expect("mock state").events,
            [Event::Metadata(KeyType::Signing), Event::Kdf]
        );
    }

    #[test]
    fn absent_unadvertised_kdf_uses_raw_pin_mode() {
        let (key, state, interaction) = bound_key(PublicKeyAlgorithm::ECDSA, KeyType::Signing);
        key.sign_digest(HashAlgorithm::Sha256, &[0x5A; 32])
            .expect("an absent unadvertised KDF DO selects raw PIN mode");
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 1);
        assert_eq!(
            state.lock().expect("mock state").events,
            [
                Event::Metadata(KeyType::Signing),
                Event::Kdf,
                Event::Pin(PinPurpose::Signing),
                Event::Verify(PinPurpose::Signing),
                Event::Sign(KeyType::Signing, 32),
            ]
        );
    }

    #[test]
    fn weak_hashes_never_start_card_signing() {
        let (key, state, interaction) = bound_fixture(
            TestFixture::Rsa2048,
            PublicKeyAlgorithm::RSA,
            KeyType::Signing,
        );
        for hash in [HashAlgorithm::Md5, HashAlgorithm::Sha1] {
            assert!(matches!(
                key.sign_digest(hash, &[0x5A; 20]),
                Err(RemoteKeyError::WeakHash(actual)) if actual == hash
            ));
        }
        assert_eq!(state.lock().expect("mock state").connections, 0);
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rsa_signing_checks_hash_response_width_and_digest_length() {
        let (key, state, _) = bound_fixture(
            TestFixture::Rsa2048,
            PublicKeyAlgorithm::RSA,
            KeyType::Signing,
        );
        let PublicParams::RSA(rsa) = key.public_params() else {
            panic!("RSA test key required")
        };
        let width = rsa_layout(rsa).expect("RSA layout").modulus_width;
        state.lock().expect("mock state").sign_response = vec![0x6A; width];
        let signature = key
            .sign(&Password::empty(), HashAlgorithm::Sha256, &[0x5A; 32])
            .expect("mock RSA signature");
        let SignatureBytes::Mpis(mpis) = signature else {
            panic!("RSA must use one MPI")
        };
        assert_eq!(mpis.len(), 1);
        assert_eq!(mpis[0].len(), width);
        assert!(
            state
                .lock()
                .expect("mock state")
                .events
                .contains(&Event::Sign(KeyType::Signing, 32))
        );

        let connections = state.lock().expect("mock state").connections;
        assert!(matches!(
            key.sign_digest(HashAlgorithm::Sha224, &[0x5A; 28]),
            Err(RemoteKeyError::UnsupportedHash(HashAlgorithm::Sha224))
        ));
        assert!(matches!(
            key.sign_digest(HashAlgorithm::Sha256, &[0x5A; 31]),
            Err(RemoteKeyError::InvalidDigestLength { .. })
        ));
        assert_eq!(state.lock().expect("mock state").connections, connections);

        state.lock().expect("mock state").sign_response = vec![0x6A; width - 1];
        assert!(matches!(
            key.sign_digest(HashAlgorithm::Sha256, &[0x5A; 32]),
            Err(RemoteKeyError::MalformedResponse { expected, actual })
                if expected == width && actual == width - 1
        ));
    }

    #[test]
    fn rsa_decryption_left_pads_and_rejects_oversized_ciphertext() {
        let (key, state, interaction) = bound_fixture(
            TestFixture::Rsa2048,
            PublicKeyAlgorithm::RSA,
            KeyType::Decryption,
        );
        let PublicParams::RSA(rsa) = key.public_params() else {
            panic!("RSA test key required")
        };
        let width = rsa_layout(rsa).expect("RSA layout").modulus_width;
        let session_key = vec![0x42; 32];
        state.lock().expect("mock state").decrypt_response =
            framed_session_key(EskType::V3_4, &session_key);
        let values = PkeskBytes::Rsa {
            mpi: Mpi::from_slice(&[0x01, 0x02, 0x03]),
        };
        let decrypted = key
            .decrypt(&Password::empty(), &values, EskType::V3_4)
            .expect("remote RSA decryption")
            .expect("session key");
        let PlainSessionKey::V3_4 {
            key: ref decrypted_key,
            ..
        } = decrypted
        else {
            panic!("V3 session key required")
        };
        assert_eq!(decrypted_key.as_ref(), session_key);
        assert!(
            state
                .lock()
                .expect("mock state")
                .events
                .contains(&Event::Decrypt(width))
        );
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 1);

        let connections = state.lock().expect("mock state").connections;
        let oversized = PkeskBytes::Rsa {
            mpi: Mpi::from_slice(&vec![0x55; width + 1]),
        };
        assert!(matches!(
            key.decrypt_session_key(&oversized, EskType::V3_4),
            Err(RemoteKeyError::InvalidCiphertext(_))
        ));
        assert_eq!(state.lock().expect("mock state").connections, connections);
        assert_eq!(interaction.pin_requests.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn p384_and_p521_signatures_use_curve_specific_widths() {
        for (fixture, digest_width, signature_width) in [
            (TestFixture::Nist384, 48, 96),
            (TestFixture::Nist521, 64, 132),
        ] {
            let (key, state, _) =
                bound_fixture(fixture, PublicKeyAlgorithm::ECDSA, KeyType::Signing);
            state.lock().expect("mock state").sign_response = vec![0x6A; signature_width];
            let signature = key
                .sign(&Password::empty(), HashAlgorithm::Sha512, &[0x5A; 64])
                .expect("mock NIST ECDSA signature");
            let SignatureBytes::Mpis(mpis) = signature else {
                panic!("ECDSA must use two MPIs")
            };
            assert_eq!(mpis.len(), 2);
            assert_eq!(mpis[0].len(), signature_width / 2);
            assert_eq!(mpis[1].len(), signature_width / 2);
            assert!(
                state
                    .lock()
                    .expect("mock state")
                    .events
                    .contains(&Event::Sign(KeyType::Signing, digest_width))
            );
        }
    }

    #[test]
    fn legacy_ed25519_returns_exactly_two_32_byte_mpis() {
        let (key, _, _) = bound_fixture(
            TestFixture::Legacy25519,
            PublicKeyAlgorithm::EdDSALegacy,
            KeyType::Signing,
        );
        let signature = key
            .sign(&Password::empty(), HashAlgorithm::Sha256, &[0x5A; 32])
            .expect("mock legacy Ed25519 signature");
        let SignatureBytes::Mpis(mpis) = signature else {
            panic!("legacy Ed25519 must use MPIs")
        };
        assert_eq!(mpis.len(), 2);
        assert_eq!(mpis[0].len(), 32);
        assert_eq!(mpis[1].len(), 32);
    }

    #[test]
    fn ecdh_variants_validate_point_and_shared_secret_widths() {
        for (fixture, shared_width, card_point_width) in [
            (TestFixture::Nist384, 48, 97),
            (TestFixture::Nist521, 66, 133),
            (TestFixture::Legacy25519, 32, 32),
        ] {
            let (key, state, _) =
                bound_fixture(fixture, PublicKeyAlgorithm::ECDH, KeyType::Decryption);
            let session_key = vec![0x42; 32];
            let plain = framed_session_key(EskType::V3_4, &session_key);
            let shared_secret = vec![0x11; shared_width];
            let encrypted = wrapped_session_key(key.public_key(), &shared_secret, &plain);
            let PublicParams::ECDH(parameters) = key.public_params() else {
                panic!("ECDH test key required")
            };
            let values = PkeskBytes::Ecdh {
                public_point: Mpi::from_slice(&ecdh_point(parameters)),
                encrypted_session_key: encrypted.into(),
            };
            state.lock().expect("mock state").decrypt_response = shared_secret;
            key.decrypt(&Password::empty(), &values, EskType::V3_4)
                .expect("remote ECDH decryption")
                .expect("session key");
            assert!(
                state
                    .lock()
                    .expect("mock state")
                    .events
                    .contains(&Event::Decrypt(card_point_width))
            );
        }
    }

    #[test]
    fn attestation_and_invalid_session_algorithms_fail_closed() {
        let component = public_component(PublicKeyAlgorithm::ECDSA);
        let (session, state, _) = mock_session();
        assert!(matches!(
            session.bind(KeyType::Attestation, &component),
            Err(RemoteKeyError::InvalidOperation(_))
        ));
        assert_eq!(state.lock().expect("mock state").connections, 0);

        let mut plaintext = framed_session_key(EskType::V3_4, &[0x42; 32]);
        plaintext[0] = u8::from(SymmetricKeyAlgorithm::Plaintext);
        assert!(matches!(
            parse_session_key(Zeroizing::new(plaintext), EskType::V3_4),
            Err(RemoteKeyError::InvalidSessionKey(_))
        ));
        assert!(matches!(
            parse_session_key(Zeroizing::new(vec![0, 0]), EskType::V6),
            Err(RemoteKeyError::InvalidSessionKey(_))
        ));
    }
}
