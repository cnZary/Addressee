use std::{collections::BTreeMap, sync::Arc};

use openpgp_core::{FullFingerprint, MessageOperation, RemoteKeyFailure, RemotePrivateKeyResolver};
use pgp::types::{DecryptionKey, SigningKey};

use crate::{AddresseeError, OpenPgpCardSession};

pub(crate) trait SharedRemoteResolver: RemotePrivateKeyResolver + Send + Sync {}

impl<T> SharedRemoteResolver for T where T: RemotePrivateKeyResolver + Send + Sync {}

pub(crate) struct RemoteRegistration {
    pub(crate) public_certificate: Vec<u8>,
    pub(crate) resolver: Arc<dyn SharedRemoteResolver>,
    pub(crate) secure_enclave_binding: Option<crate::SecureEnclaveBindingFfi>,
}

struct CardReservation {
    registration: crate::CardRegistrationFfi,
    public_certificate: Vec<u8>,
}

#[derive(Default)]
pub(crate) struct RemoteRegistry {
    cards: BTreeMap<FullFingerprint, Arc<OpenPgpCardSession>>,
    reservations: BTreeMap<FullFingerprint, CardReservation>,
    providers: BTreeMap<FullFingerprint, RemoteRegistration>,
}

impl RemoteRegistry {
    pub(crate) fn is_empty(&self) -> bool {
        self.cards.is_empty() && self.reservations.is_empty() && self.providers.is_empty()
    }

    pub(crate) fn contains(&self, fingerprint: &FullFingerprint) -> bool {
        self.cards.contains_key(fingerprint)
            || self.reservations.contains_key(fingerprint)
            || self.providers.contains_key(fingerprint)
    }

    pub(crate) fn public_certificate(&self, fingerprint: &FullFingerprint) -> Option<&[u8]> {
        self.cards
            .get(fingerprint)
            .map(|session| session.public_certificate())
            .or_else(|| {
                self.reservations
                    .get(fingerprint)
                    .map(|reservation| reservation.public_certificate.as_slice())
            })
            .or_else(|| {
                self.providers
                    .get(fingerprint)
                    .map(|registration| registration.public_certificate.as_slice())
            })
    }

    pub(crate) fn reserve_card(
        &mut self,
        fingerprint: FullFingerprint,
        registration: crate::CardRegistrationFfi,
        public_certificate: Vec<u8>,
    ) -> Result<(), AddresseeError> {
        if self.providers.contains_key(&fingerprint)
            || self.reservations.get(&fingerprint).is_some_and(|current| {
                current.registration != registration
                    || current.public_certificate != public_certificate
            })
            || self.cards.get(&fingerprint).is_some_and(|session| {
                session.registration() != registration
                    || session.public_certificate() != public_certificate
            })
        {
            return Err(AddresseeError::CardRegistrationConflict);
        }
        self.reservations.insert(
            fingerprint,
            CardReservation {
                registration,
                public_certificate,
            },
        );
        Ok(())
    }

    pub(crate) fn insert_card(
        &mut self,
        session: Arc<OpenPgpCardSession>,
    ) -> Result<(), AddresseeError> {
        let fingerprint = session.certificate_fingerprint.clone();
        if self.cards.contains_key(&fingerprint) || self.providers.contains_key(&fingerprint) {
            return Err(AddresseeError::CardRegistrationConflict);
        }
        if self
            .reservations
            .get(&fingerprint)
            .is_some_and(|reservation| {
                reservation.registration != session.registration()
                    || reservation.public_certificate != session.public_certificate()
            })
        {
            return Err(AddresseeError::CardRegistrationConflict);
        }
        self.cards.insert(fingerprint, session);
        Ok(())
    }

    pub(crate) fn insert_provider(
        &mut self,
        fingerprint: FullFingerprint,
        registration: RemoteRegistration,
    ) -> Result<(), AddresseeError> {
        if self.contains(&fingerprint) {
            return Err(AddresseeError::CardRegistrationConflict);
        }
        self.providers.insert(fingerprint, registration);
        Ok(())
    }

    pub(crate) fn remove(&mut self, fingerprint: &FullFingerprint) -> Result<(), AddresseeError> {
        let card = self.cards.remove(fingerprint);
        let reservation = self.reservations.remove(fingerprint);
        let provider = self.providers.remove(fingerprint);
        if card.is_none() && reservation.is_none() && provider.is_none() {
            return Err(AddresseeError::CardSessionUnavailable);
        }
        Ok(())
    }

    pub(crate) fn remove_card(
        &mut self,
        fingerprint: &FullFingerprint,
    ) -> Result<(), AddresseeError> {
        self.cards
            .remove(fingerprint)
            .map(|_| ())
            .ok_or(AddresseeError::CardSessionUnavailable)
    }

    pub(crate) fn remove_card_binding(
        &mut self,
        fingerprint: &FullFingerprint,
    ) -> Result<(), AddresseeError> {
        let card = self.cards.remove(fingerprint);
        let reservation = self.reservations.remove(fingerprint);
        if card.is_none() && reservation.is_none() {
            return Err(AddresseeError::CardSessionUnavailable);
        }
        Ok(())
    }

    pub(crate) fn allows_protected_primary(&self, fingerprint: &FullFingerprint) -> bool {
        self.providers
            .get(fingerprint)
            .is_some_and(|registration| registration.secure_enclave_binding.is_some())
    }

    pub(crate) fn secure_enclave_registrations(&self) -> Vec<crate::SecureEnclaveBindingFfi> {
        self.providers
            .values()
            .filter_map(|registration| registration.secure_enclave_binding.clone())
            .collect()
    }

    pub(crate) fn remove_secure_enclave(
        &mut self,
        fingerprint: &FullFingerprint,
    ) -> Result<crate::SecureEnclaveBindingFfi, AddresseeError> {
        self.providers
            .remove(fingerprint)
            .and_then(|registration| registration.secure_enclave_binding)
            .ok_or(AddresseeError::CardSessionUnavailable)
    }

    pub(crate) fn registrations(&self) -> Vec<crate::CardRegistrationFfi> {
        self.cards
            .values()
            .map(|session| session.registration())
            .collect()
    }

    fn resolver(&self, fingerprint: &FullFingerprint) -> Option<&dyn SharedRemoteResolver> {
        if let Some(session) = self.cards.get(fingerprint) {
            return Some(session.resolver.as_ref());
        }
        if let Some(registration) = self.providers.get(fingerprint) {
            return Some(registration.resolver.as_ref());
        }
        if self.reservations.contains_key(fingerprint) {
            return Some(&DISCONNECTED_CARD_RESOLVER);
        }
        None
    }
}

struct DisconnectedCardResolver;

static DISCONNECTED_CARD_RESOLVER: DisconnectedCardResolver = DisconnectedCardResolver;

impl RemotePrivateKeyResolver for DisconnectedCardResolver {
    fn backend(
        &self,
        _certificate_fingerprint: &FullFingerprint,
        _component_fingerprint: &FullFingerprint,
    ) -> Option<openpgp_policy::Backend> {
        Some(openpgp_policy::Backend::OpenPgpCard)
    }

    fn runtime_capabilities_verified(
        &self,
        _certificate_fingerprint: &FullFingerprint,
        _component_fingerprint: &FullFingerprint,
    ) -> bool {
        true
    }

    fn signing_key(
        &self,
        _certificate_fingerprint: &FullFingerprint,
        _component_fingerprint: &FullFingerprint,
    ) -> pgp::errors::Result<Option<&dyn SigningKey>> {
        Err(
            openpgp_card_adapter::remote_key::RemoteKeyError::InvalidOperation(
                "the associated card has no active private-key session",
            )
            .into(),
        )
    }

    fn decryption_key(
        &self,
        _certificate_fingerprint: &FullFingerprint,
        _component_fingerprint: &FullFingerprint,
    ) -> pgp::errors::Result<Option<&dyn DecryptionKey>> {
        Err(
            openpgp_card_adapter::remote_key::RemoteKeyError::InvalidOperation(
                "the associated card has no active private-key session",
            )
            .into(),
        )
    }
}

impl RemotePrivateKeyResolver for RemoteRegistry {
    fn backend(
        &self,
        certificate_fingerprint: &FullFingerprint,
        component_fingerprint: &FullFingerprint,
    ) -> Option<openpgp_policy::Backend> {
        self.resolver(certificate_fingerprint)?
            .backend(certificate_fingerprint, component_fingerprint)
    }

    fn runtime_capabilities_verified(
        &self,
        certificate_fingerprint: &FullFingerprint,
        component_fingerprint: &FullFingerprint,
    ) -> bool {
        self.resolver(certificate_fingerprint)
            .is_some_and(|resolver| {
                resolver
                    .runtime_capabilities_verified(certificate_fingerprint, component_fingerprint)
            })
    }

    fn signing_key(
        &self,
        certificate_fingerprint: &FullFingerprint,
        component_fingerprint: &FullFingerprint,
    ) -> pgp::errors::Result<Option<&dyn SigningKey>> {
        let Some(resolver) = self.resolver(certificate_fingerprint) else {
            return Ok(None);
        };
        resolver.signing_key(certificate_fingerprint, component_fingerprint)
    }

    fn decryption_key(
        &self,
        certificate_fingerprint: &FullFingerprint,
        component_fingerprint: &FullFingerprint,
    ) -> pgp::errors::Result<Option<&dyn DecryptionKey>> {
        let Some(resolver) = self.resolver(certificate_fingerprint) else {
            return Ok(None);
        };
        resolver.decryption_key(certificate_fingerprint, component_fingerprint)
    }

    fn failure_kind(
        &self,
        certificate_fingerprint: &FullFingerprint,
        component_fingerprint: &FullFingerprint,
        operation: MessageOperation,
    ) -> RemoteKeyFailure {
        self.resolver(certificate_fingerprint)
            .map_or(RemoteKeyFailure::Unavailable, |resolver| {
                resolver.failure_kind(certificate_fingerprint, component_fingerprint, operation)
            })
    }
}
