use std::sync::Arc;

use openpgp_card::ocard::{KeyType, data::TouchPolicy};
use openpgp_card_adapter::{
    CardIdentity,
    interaction::{CardInteractionError, PinProvider, PinPurpose, TouchPrompt},
    remote_key::{CardSession, OperationAuthorization, RemoteKeyError},
    resolver::{CardKeyResolver, ResolverError},
    transport::{RawCardTransport, TransportCapabilities, TransportError as AdapterTransportError},
};
use openpgp_core::FullFingerprint;
use pgp::{
    composed::{Deserializable as _, SignedPublicKey},
    ser::Serialize as _,
    types::{KeyDetails as _, KeyVersion},
};
use zeroize::Zeroizing;

use crate::{AddresseeError, remote_registry::SharedRemoteResolver as SharedCardResolver};

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Record)]
pub struct CardIdentityFfi {
    pub manufacturer: u16,
    pub serial: u32,
    pub version: u16,
}

impl From<CardIdentityFfi> for CardIdentity {
    fn from(value: CardIdentityFfi) -> Self {
        Self::new(value.manufacturer, value.serial, value.version)
    }
}

impl From<CardIdentity> for CardIdentityFfi {
    fn from(value: CardIdentity) -> Self {
        Self {
            manufacturer: value.manufacturer(),
            serial: value.serial(),
            version: value.version(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum CardSlot {
    Signing,
    Decryption,
    Authentication,
}

impl From<CardSlot> for KeyType {
    fn from(value: CardSlot) -> Self {
        match value {
            CardSlot::Signing => Self::Signing,
            CardSlot::Decryption => Self::Decryption,
            CardSlot::Authentication => Self::Authentication,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct CardComponentBindingFfi {
    pub slot: CardSlot,
    pub component_fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct CardRegistrationFfi {
    pub certificate_fingerprint: String,
    pub identity: CardIdentityFfi,
    pub components: Vec<CardComponentBindingFfi>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Record)]
pub struct CardTransportCapabilities {
    pub supports_extended_length: bool,
    pub supports_command_chaining: bool,
    pub maximum_command_length: u32,
    pub maximum_command_data_length: u32,
    pub maximum_response_length: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error, uniffi::Error)]
pub enum CardTransportError {
    #[error("The card transport is unavailable")]
    Unavailable,
    #[error("The card operation was cancelled")]
    Cancelled,
    #[error("The card operation timed out")]
    Timeout,
    #[error("The card disconnected")]
    Disconnected,
    #[error("The card transport failed")]
    Failure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error, uniffi::Error)]
pub enum CardInteractionErrorFfi {
    #[error("The card interaction was cancelled")]
    Cancelled,
    #[error("The card interaction is unavailable")]
    Unavailable,
}

#[uniffi::export(with_foreign)]
pub trait CardTransport: Send + Sync {
    fn capabilities(&self) -> CardTransportCapabilities;

    fn transmit(
        &self,
        command: Vec<u8>,
        response_buffer_size: u32,
    ) -> Result<Vec<u8>, CardTransportError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum CardPinPurpose {
    Signing,
    User,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum CardTouchRequirementFfi {
    NotRequired,
    Required,
    Possible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Record)]
pub struct CardOperationAuthorizationFfi {
    pub slot: CardSlot,
    pub pin_purpose: CardPinPurpose,
    pub minimum_pin_length: u8,
    pub maximum_pin_length: u8,
    pub remaining_pin_retries: u8,
    pub touch_requirement: CardTouchRequirementFfi,
}

impl From<OperationAuthorization> for CardOperationAuthorizationFfi {
    fn from(value: OperationAuthorization) -> Self {
        let touch_requirement = match value.touch_policy {
            None | Some(TouchPolicy::Off) => CardTouchRequirementFfi::NotRequired,
            Some(TouchPolicy::On | TouchPolicy::Fixed) => CardTouchRequirementFfi::Required,
            Some(TouchPolicy::Cached | TouchPolicy::CachedFixed | TouchPolicy::Unknown(_)) => {
                CardTouchRequirementFfi::Possible
            }
        };
        Self {
            slot: match value.slot {
                KeyType::Signing => CardSlot::Signing,
                KeyType::Decryption => CardSlot::Decryption,
                KeyType::Authentication => CardSlot::Authentication,
                KeyType::Attestation => unreachable!("attestation cannot be registered"),
            },
            pin_purpose: match value.pin_purpose {
                PinPurpose::Signing => CardPinPurpose::Signing,
                PinPurpose::User | PinPurpose::Admin => CardPinPurpose::User,
            },
            minimum_pin_length: value.minimum_pin_length,
            maximum_pin_length: value.maximum_pin_length,
            remaining_pin_retries: value.remaining_pin_retries,
            touch_requirement,
        }
    }
}

#[uniffi::export(with_foreign)]
pub trait CardPinProvider: Send + Sync {
    fn request_pin(
        &self,
        purpose: CardPinPurpose,
        identity: CardIdentityFfi,
    ) -> Result<String, CardInteractionErrorFfi>;
}

#[uniffi::export(with_foreign)]
pub trait CardTouchPrompt: Send + Sync {
    fn request_touch(&self, slot: CardSlot) -> Result<(), CardInteractionErrorFfi>;
}

pub(crate) struct FfiTransport {
    transport: Arc<dyn CardTransport>,
    failure: std::sync::Mutex<openpgp_core::RemoteKeyFailure>,
}

pub(crate) fn ffi_transport(transport: Arc<dyn CardTransport>) -> Arc<FfiTransport> {
    Arc::new(FfiTransport {
        transport,
        failure: std::sync::Mutex::new(openpgp_core::RemoteKeyFailure::Unavailable),
    })
}

impl RawCardTransport for FfiTransport {
    fn capabilities(&self) -> TransportCapabilities {
        let capabilities = self.transport.capabilities();
        TransportCapabilities {
            supports_extended_length: capabilities.supports_extended_length,
            supports_command_chaining: capabilities.supports_command_chaining,
            maximum_command_length: capabilities.maximum_command_length as usize,
            maximum_command_data_length: capabilities.maximum_command_data_length as usize,
            maximum_response_length: capabilities.maximum_response_length as usize,
        }
    }

    fn transmit(
        &self,
        command: &[u8],
        response_buffer_size: usize,
    ) -> Result<Vec<u8>, AdapterTransportError> {
        let response_buffer_size = u32::try_from(response_buffer_size)
            .map_err(|_| AdapterTransportError::InvalidCapabilities("invalid response hint"))?;
        let result = self
            .transport
            .transmit(command.to_vec(), response_buffer_size)
            .map_err(AdapterTransportError::from);
        let failure = if matches!(&result, Err(AdapterTransportError::Cancelled)) {
            openpgp_core::RemoteKeyFailure::Cancelled
        } else {
            openpgp_core::RemoteKeyFailure::Unavailable
        };
        *self
            .failure
            .lock()
            .map_err(|_| AdapterTransportError::Failure)? = failure;
        result
    }

    fn failure_kind(&self) -> openpgp_core::RemoteKeyFailure {
        self.failure
            .lock()
            .map_or(openpgp_core::RemoteKeyFailure::Unavailable, |failure| {
                *failure
            })
    }
}

impl From<CardTransportError> for AdapterTransportError {
    fn from(value: CardTransportError) -> Self {
        match value {
            CardTransportError::Unavailable => Self::Unavailable,
            CardTransportError::Cancelled => Self::Cancelled,
            CardTransportError::Timeout => Self::Timeout,
            CardTransportError::Disconnected => Self::Disconnected,
            CardTransportError::Failure => Self::Failure,
        }
    }
}

struct FfiPinProvider(Arc<dyn CardPinProvider>);

impl PinProvider for FfiPinProvider {
    fn request_pin(
        &self,
        purpose: PinPurpose,
        identity: &CardIdentity,
    ) -> Result<Zeroizing<String>, CardInteractionError> {
        let purpose = match purpose {
            PinPurpose::Signing => CardPinPurpose::Signing,
            PinPurpose::User => CardPinPurpose::User,
            PinPurpose::Admin => {
                return Err(CardInteractionError::Unavailable(
                    "Admin PIN is not available in the private-key flow".to_owned(),
                ));
            }
        };
        self.0
            .request_pin(purpose, (*identity).into())
            .map(Zeroizing::new)
            .map_err(Into::into)
    }
}

struct FfiTouchPrompt(Arc<dyn CardTouchPrompt>);

impl TouchPrompt for FfiTouchPrompt {
    fn request_touch(&self, slot: KeyType) -> Result<(), CardInteractionError> {
        let slot = match slot {
            KeyType::Signing => CardSlot::Signing,
            KeyType::Decryption => CardSlot::Decryption,
            KeyType::Authentication => CardSlot::Authentication,
            KeyType::Attestation => {
                return Err(CardInteractionError::Unavailable(
                    "Attestation is not available in the private-key flow".to_owned(),
                ));
            }
        };
        self.0.request_touch(slot).map_err(Into::into)
    }
}

impl From<CardInteractionErrorFfi> for CardInteractionError {
    fn from(value: CardInteractionErrorFfi) -> Self {
        match value {
            CardInteractionErrorFfi::Cancelled => Self::Cancelled,
            CardInteractionErrorFfi::Unavailable => {
                Self::Unavailable("PIN or touch interaction is unavailable".to_owned())
            }
        }
    }
}

#[uniffi::export]
pub fn read_card_identity(
    transport: Arc<dyn CardTransport>,
) -> Result<CardIdentityFfi, AddresseeError> {
    let transport = ffi_transport(transport);
    CardSession::identify_with_transport(Arc::clone(&transport) as Arc<dyn RawCardTransport>)
        .map(Into::into)
        .map_err(|error| {
            if transport.failure_kind() == openpgp_core::RemoteKeyFailure::Cancelled {
                AddresseeError::OperationCancelled
            } else {
                map_card_error(error)
            }
        })
}

#[derive(uniffi::Object)]
pub struct OpenPgpCardSession {
    pub(crate) certificate_fingerprint: FullFingerprint,
    public_certificate: Vec<u8>,
    identity: CardIdentityFfi,
    bindings: Vec<CardComponentBindingFfi>,
    operation_resolver: Option<Arc<CardKeyResolver>>,
    pub(crate) resolver: Arc<dyn SharedCardResolver>,
}

#[uniffi::export]
impl OpenPgpCardSession {
    #[uniffi::constructor]
    pub fn connect(
        identity: CardIdentityFfi,
        public_certificate: Vec<u8>,
        signing_component: Option<String>,
        decryption_component: Option<String>,
        transport: Arc<dyn CardTransport>,
        pin_provider: Arc<dyn CardPinProvider>,
        touch_prompt: Arc<dyn CardTouchPrompt>,
    ) -> Result<Self, AddresseeError> {
        if signing_component.is_none() && decryption_component.is_none() {
            return Err(AddresseeError::UnsupportedOperation);
        }
        let certificate = parse_certificate(&public_certificate)?;
        let transport = ffi_transport(transport);
        let session = CardSession::connect_with_transport(
            identity.into(),
            Arc::clone(&transport) as Arc<dyn RawCardTransport>,
            Arc::new(FfiPinProvider(pin_provider)),
            Arc::new(FfiTouchPrompt(touch_prompt)),
        )
        .map_err(|error| {
            if transport.failure_kind() == openpgp_core::RemoteKeyFailure::Cancelled {
                AddresseeError::OperationCancelled
            } else {
                map_card_error(error)
            }
        })?;
        let mut resolver = CardKeyResolver::new(session);
        let mut bindings = Vec::new();
        for (slot, component) in [
            (CardSlot::Signing, signing_component),
            (CardSlot::Decryption, decryption_component),
        ] {
            if let Some(component) = component {
                let component = FullFingerprint::from_hex(&component)?;
                let registered = resolver
                    .register(&certificate, slot.into(), &component)
                    .map_err(|error| {
                        if resolver.session().failure_kind()
                            == openpgp_core::RemoteKeyFailure::Cancelled
                        {
                            AddresseeError::OperationCancelled
                        } else {
                            map_resolver_error(error)
                        }
                    })?;
                bindings.push(CardComponentBindingFfi {
                    slot,
                    component_fingerprint: registered.to_string(),
                });
            }
        }
        let resolver = Arc::new(resolver);
        let mut session = Self::new(certificate, identity, bindings, resolver.clone())?;
        session.operation_resolver = Some(resolver);
        Ok(session)
    }

    pub fn identity(&self) -> CardIdentityFfi {
        self.identity
    }

    pub fn certificate_fingerprint(&self) -> String {
        self.certificate_fingerprint.to_string()
    }

    pub fn registration(&self) -> CardRegistrationFfi {
        CardRegistrationFfi {
            certificate_fingerprint: self.certificate_fingerprint.to_string(),
            identity: self.identity,
            components: self.bindings.clone(),
        }
    }

    pub fn authorization_requirements(
        &self,
        slot: CardSlot,
    ) -> Result<CardOperationAuthorizationFfi, AddresseeError> {
        let resolver = self
            .operation_resolver
            .as_ref()
            .ok_or(AddresseeError::UnsupportedOperation)?;
        resolver
            .authorization_requirements(&self.certificate_fingerprint, slot.into())
            .map(Into::into)
            .map_err(map_resolver_error)
    }
}

impl OpenPgpCardSession {
    fn new(
        certificate: SignedPublicKey,
        identity: CardIdentityFfi,
        bindings: Vec<CardComponentBindingFfi>,
        resolver: Arc<dyn SharedCardResolver>,
    ) -> Result<Self, AddresseeError> {
        if certificate.primary_key.version() != KeyVersion::V4 {
            return Err(AddresseeError::UnsupportedOperation);
        }
        let fingerprint = certificate.primary_key.fingerprint();
        let certificate_fingerprint = FullFingerprint::from_hex(&format!("{fingerprint:X}"))?;
        Ok(Self {
            certificate_fingerprint,
            public_certificate: certificate.to_bytes().map_err(|error| {
                let _ = error;
                AddresseeError::InvalidCertificate
            })?,
            identity,
            bindings,
            operation_resolver: None,
            resolver,
        })
    }

    pub(crate) fn public_certificate(&self) -> &[u8] {
        &self.public_certificate
    }

    #[cfg(test)]
    pub(crate) fn from_resolver_for_tests(
        public_certificate: &[u8],
        resolver: Arc<dyn SharedCardResolver>,
    ) -> Result<Self, AddresseeError> {
        let certificate = parse_certificate(public_certificate)?;
        let bindings = certificate
            .public_subkeys
            .iter()
            .take(2)
            .enumerate()
            .map(|(index, component)| {
                let fingerprint = component.key.fingerprint();
                Ok(CardComponentBindingFfi {
                    slot: if index == 0 {
                        CardSlot::Signing
                    } else {
                        CardSlot::Decryption
                    },
                    component_fingerprint: FullFingerprint::from_hex(&format!("{fingerprint:X}"))?
                        .to_string(),
                })
            })
            .collect::<Result<Vec<_>, AddresseeError>>()?;
        Self::new(
            certificate,
            CardIdentityFfi {
                manufacturer: 0xFFFF,
                serial: 0x01020304,
                version: 0x0304,
            },
            bindings,
            resolver,
        )
    }
}

fn parse_certificate(input: &[u8]) -> Result<SignedPublicKey, AddresseeError> {
    let certificate = SignedPublicKey::from_bytes(input).map_err(|error| {
        let _ = error;
        AddresseeError::InvalidCertificate
    })?;
    certificate.verify_bindings().map_err(|error| {
        let _ = error;
        AddresseeError::InvalidCertificate
    })?;
    Ok(certificate)
}

fn map_resolver_error(error: ResolverError) -> AddresseeError {
    match error {
        ResolverError::Card(error) => map_card_error(error),
        ResolverError::DuplicateComponent => AddresseeError::CardRegistrationConflict,
        ResolverError::InvalidCertificate
        | ResolverError::ComponentNotFound
        | ResolverError::Certificate(_) => AddresseeError::InvalidCertificate,
    }
}

pub(crate) fn map_card_error(error: RemoteKeyError) -> AddresseeError {
    match error {
        RemoteKeyError::Interaction(CardInteractionError::Cancelled)
        | RemoteKeyError::Transport(AdapterTransportError::Cancelled) => {
            AddresseeError::OperationCancelled
        }
        RemoteKeyError::WrongPin { .. } => AddresseeError::InvalidPassword,
        RemoteKeyError::IdentityMismatch
        | RemoteKeyError::SerialMismatch { .. }
        | RemoteKeyError::SlotBinding(_)
        | RemoteKeyError::MissingSlotData(_)
        | RemoteKeyError::PublicMaterial(_)
        | RemoteKeyError::Rpgp(_) => AddresseeError::ConflictingCertificate,
        RemoteKeyError::UnsupportedKeyVersion(_)
        | RemoteKeyError::UnsupportedAlgorithm { .. }
        | RemoteKeyError::UnsupportedPublicKey(_)
        | RemoteKeyError::UnsupportedHash(_)
        | RemoteKeyError::WeakHash(_)
        | RemoteKeyError::UnsupportedSymmetricAlgorithm(_)
        | RemoteKeyError::UnsupportedKdf(_)
        | RemoteKeyError::InvalidKdf(_)
        | RemoteKeyError::InvalidOperation(_) => AddresseeError::UnsupportedOperation,
        RemoteKeyError::EmptyPin | RemoteKeyError::InvalidPinLength { .. } => {
            AddresseeError::InvalidInput
        }
        RemoteKeyError::SessionPoisoned => AddresseeError::CardSessionUnavailable,
        RemoteKeyError::InvalidDigestLength { .. } | RemoteKeyError::InvalidCiphertext(_) => {
            AddresseeError::InvalidInput
        }
        RemoteKeyError::Pcsc(_)
        | RemoteKeyError::Transport(_)
        | RemoteKeyError::Card(_)
        | RemoteKeyError::Interaction(_)
        | RemoteKeyError::MalformedResponse { .. }
        | RemoteKeyError::InvalidSessionKey(_)
        | RemoteKeyError::PinRetriesUnavailable { .. }
        | RemoteKeyError::UnexpectedTransactionResult => AddresseeError::RemoteKeyUnavailable,
    }
}
