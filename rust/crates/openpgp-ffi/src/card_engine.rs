use std::sync::Arc;

use openpgp_core::{ExportFormat, FullFingerprint, KeyError, KeyStorage, SoftwareKeyStore};

use crate::{AddresseeError, CardRegistrationFfi, CardSlot, OpenPgpCardSession, OpenPgpEngine};

#[uniffi::export]
impl OpenPgpEngine {
    pub fn reserve_card_binding(
        &self,
        registration: CardRegistrationFfi,
        public_certificate: Vec<u8>,
    ) -> Result<(), AddresseeError> {
        let mut temporary = SoftwareKeyStore::new();
        temporary.import_public(&public_certificate)?;
        let metadata = temporary.list_metadata()?;
        crate::policy::validate_certificate_operation(
            &metadata,
            openpgp_policy::Operation::Import,
        )?;
        let certificate = metadata.first().ok_or(AddresseeError::InvalidCertificate)?;
        let fingerprint = FullFingerprint::from_hex(&registration.certificate_fingerprint)?;
        if certificate.fingerprint != fingerprint
            || certificate.key_version != openpgp_core::KeyVersion::V4
        {
            return Err(AddresseeError::CardRegistrationConflict);
        }
        if registration.components.is_empty() || registration.components.len() > 2 {
            return Err(AddresseeError::InvalidCertificate);
        }
        let mut registration = registration;
        registration.certificate_fingerprint = fingerprint.to_string();
        let mut components = std::collections::BTreeSet::new();
        for binding in &mut registration.components {
            let component = FullFingerprint::from_hex(&binding.component_fingerprint)?;
            let Some(subkey) = certificate
                .subkeys
                .iter()
                .find(|subkey| subkey.fingerprint == component)
            else {
                return Err(AddresseeError::InvalidCertificate);
            };
            let valid = match binding.slot {
                CardSlot::Signing => subkey.key_flags.sign,
                CardSlot::Decryption => {
                    subkey.key_flags.encrypt_communications || subkey.key_flags.encrypt_storage
                }
                CardSlot::Authentication => false,
            };
            if !valid {
                return Err(AddresseeError::UnsupportedOperation);
            }
            if !components.insert(component.clone()) {
                return Err(AddresseeError::CardRegistrationConflict);
            }
            binding.component_fingerprint = component.to_string();
        }
        let public = temporary.export_public(&fingerprint, ExportFormat::Binary)?;
        let mut keys = self.lock()?;
        match keys.metadata(&fingerprint) {
            Ok(metadata) => {
                if metadata.storage != KeyStorage::PublicOnly {
                    return Err(AddresseeError::AmbiguousPrivateKeyStorage);
                }
                if keys.export_public(&fingerprint, ExportFormat::Binary)? != public {
                    return Err(AddresseeError::CardRegistrationConflict);
                }
            }
            Err(KeyError::KeyNotFound { .. }) => {
                keys.import_public(&public)?;
            }
            Err(error) => return Err(error.into()),
        }
        self.lock_remote_write()?
            .reserve_card(fingerprint, registration, public)
    }

    pub fn release_card_binding(
        &self,
        certificate_fingerprint: String,
    ) -> Result<(), AddresseeError> {
        let fingerprint = FullFingerprint::from_hex(&certificate_fingerprint)?;
        let _keys = self.lock()?;
        self.lock_remote_write()?.remove_card_binding(&fingerprint)
    }

    pub fn attach_card_session(
        &self,
        session: Arc<OpenPgpCardSession>,
    ) -> Result<CardRegistrationFfi, AddresseeError> {
        let public = session.public_certificate().to_vec();
        let mut temporary = SoftwareKeyStore::new();
        temporary.import_public(&public)?;
        crate::policy::validate_certificate_operation(
            &temporary.list_metadata()?,
            openpgp_policy::Operation::Import,
        )?;

        let mut keys = self.lock()?;
        let mut cards = self.lock_remote_write()?;
        match keys.metadata(&session.certificate_fingerprint) {
            Ok(metadata) => {
                if metadata.storage != KeyStorage::PublicOnly {
                    return Err(AddresseeError::AmbiguousPrivateKeyStorage);
                }
                let stored = keys.export_public(&metadata.fingerprint, ExportFormat::Binary)?;
                if stored != public {
                    return Err(AddresseeError::CardRegistrationConflict);
                }
            }
            Err(KeyError::KeyNotFound { .. }) => {
                keys.import_public(&public)?;
            }
            Err(error) => return Err(error.into()),
        }
        cards.insert_card(Arc::clone(&session))?;
        Ok(session.registration())
    }

    pub fn detach_card_session(
        &self,
        certificate_fingerprint: String,
    ) -> Result<(), AddresseeError> {
        let fingerprint = FullFingerprint::from_hex(&certificate_fingerprint)?;
        let _keys = self.lock()?;
        self.lock_remote_write()?.remove_card(&fingerprint)
    }

    pub fn card_registrations(&self) -> Result<Vec<CardRegistrationFfi>, AddresseeError> {
        let _keys = self.lock()?;
        Ok(self.lock_remote_read()?.registrations())
    }
}
