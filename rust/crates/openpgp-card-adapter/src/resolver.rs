use openpgp_card::ocard::KeyType;
use openpgp_core::{Backend, FullFingerprint, RemotePrivateKeyResolver};
use pgp::{
    composed::SignedPublicKey,
    types::{DecryptionKey, Fingerprint, KeyDetails as _, SigningKey},
};
use thiserror::Error;

use crate::remote_key::{CardSession, OperationAuthorization, RemoteCardKey, RemoteKeyError};

pub struct CardKeyResolver {
    session: CardSession,
    keys: Vec<RegisteredKey>,
}

struct RegisteredKey {
    certificate: FullFingerprint,
    component: FullFingerprint,
    key: RemoteCardKey,
}

#[derive(Debug, Error)]
pub enum ResolverError {
    #[error("the certificate or requested component is invalid")]
    InvalidCertificate,

    #[error("the certificate does not contain the requested subkey")]
    ComponentNotFound,

    #[error("this certificate component is already registered")]
    DuplicateComponent,

    #[error("certificate validation failed: {0}")]
    Certificate(#[from] pgp::errors::Error),

    #[error("card binding failed: {0}")]
    Card(#[from] RemoteKeyError),
}

impl CardKeyResolver {
    pub const fn new(session: CardSession) -> Self {
        Self {
            session,
            keys: Vec::new(),
        }
    }

    pub const fn session(&self) -> &CardSession {
        &self.session
    }

    pub fn register(
        &mut self,
        certificate: &SignedPublicKey,
        slot: KeyType,
        component: &FullFingerprint,
    ) -> Result<FullFingerprint, ResolverError> {
        certificate.verify_bindings()?;
        let certificate_fingerprint = full_fingerprint(&certificate.primary_key.fingerprint())?;
        let component_key = certificate
            .public_subkeys
            .iter()
            .find(|subkey| {
                full_fingerprint(&subkey.key.fingerprint())
                    .is_ok_and(|fingerprint| fingerprint == *component)
            })
            .ok_or(ResolverError::ComponentNotFound)?;
        if self.keys.iter().any(|registered| {
            registered.certificate == certificate_fingerprint && registered.component == *component
        }) {
            return Err(ResolverError::DuplicateComponent);
        }
        let key = self.session.bind(slot, &component_key.key)?;
        self.keys.push(RegisteredKey {
            certificate: certificate_fingerprint,
            component: component.clone(),
            key,
        });
        Ok(component.clone())
    }

    pub fn authorization_requirements(
        &self,
        certificate: &FullFingerprint,
        slot: KeyType,
    ) -> Result<OperationAuthorization, ResolverError> {
        let registered = self
            .keys
            .iter()
            .find(|key| key.certificate == *certificate && key.key.slot() == slot)
            .ok_or(ResolverError::ComponentNotFound)?;
        Ok(registered.key.authorization_requirements()?)
    }

    fn find(
        &self,
        certificate: &FullFingerprint,
        component: &FullFingerprint,
    ) -> Option<&RegisteredKey> {
        self.keys
            .iter()
            .find(|key| key.certificate == *certificate && key.component == *component)
    }
}

impl RemotePrivateKeyResolver for CardKeyResolver {
    fn backend(
        &self,
        certificate_fingerprint: &FullFingerprint,
        component_fingerprint: &FullFingerprint,
    ) -> Option<Backend> {
        self.find(certificate_fingerprint, component_fingerprint)
            .map(|_| Backend::OpenPgpCard)
    }

    fn runtime_capabilities_verified(
        &self,
        certificate_fingerprint: &FullFingerprint,
        component_fingerprint: &FullFingerprint,
    ) -> bool {
        self.find(certificate_fingerprint, component_fingerprint)
            .is_some()
    }

    fn signing_key(
        &self,
        certificate_fingerprint: &FullFingerprint,
        component_fingerprint: &FullFingerprint,
    ) -> pgp::errors::Result<Option<&dyn SigningKey>> {
        Ok(self
            .find(certificate_fingerprint, component_fingerprint)
            .filter(|registered| registered.key.slot() != KeyType::Decryption)
            .map(|registered| &registered.key as &dyn SigningKey))
    }

    fn decryption_key(
        &self,
        certificate_fingerprint: &FullFingerprint,
        component_fingerprint: &FullFingerprint,
    ) -> pgp::errors::Result<Option<&dyn DecryptionKey>> {
        Ok(self
            .find(certificate_fingerprint, component_fingerprint)
            .filter(|registered| registered.key.slot() == KeyType::Decryption)
            .map(|registered| &registered.key as &dyn DecryptionKey))
    }

    fn failure_kind(
        &self,
        certificate_fingerprint: &FullFingerprint,
        component_fingerprint: &FullFingerprint,
        _operation: openpgp_core::MessageOperation,
    ) -> openpgp_core::RemoteKeyFailure {
        self.find(certificate_fingerprint, component_fingerprint)
            .map_or(openpgp_core::RemoteKeyFailure::Unavailable, |registered| {
                registered.key.failure_kind()
            })
    }
}

fn full_fingerprint(fingerprint: &Fingerprint) -> Result<FullFingerprint, ResolverError> {
    FullFingerprint::from_hex(&format!("{fingerprint:X}"))
        .map_err(|_| ResolverError::InvalidCertificate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_uses_the_real_core_contract() {
        fn assert_contract<T: RemotePrivateKeyResolver>() {}
        assert_contract::<CardKeyResolver>();
    }
}
