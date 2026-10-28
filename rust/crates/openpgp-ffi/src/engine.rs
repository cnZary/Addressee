use std::sync::{Mutex, RwLock};

use openpgp_core::{FullFingerprint, PrivateExportPolicy, SoftwareKeyStore};
use zeroize::Zeroizing;

use crate::{
    AddresseeError, CertificateSummary, ExportFormatFfi, ExportPolicyFfi, GeneratedKeyFfi,
    GenerationProfileFfi, ImportResultFfi,
};

use super::remote_registry::RemoteRegistry;

#[derive(uniffi::Object)]
pub struct OpenPgpEngine {
    pub(crate) store: Mutex<SoftwareKeyStore>,
    pub(crate) remote: RwLock<RemoteRegistry>,
    pub(crate) message_operations: Mutex<()>,
}

impl Default for OpenPgpEngine {
    fn default() -> Self {
        Self {
            store: Mutex::new(SoftwareKeyStore::new()),
            remote: RwLock::new(RemoteRegistry::default()),
            message_operations: Mutex::new(()),
        }
    }
}

#[uniffi::export]
impl OpenPgpEngine {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn generate_key(
        &self,
        profile: GenerationProfileFfi,
        user_id: String,
        password: String,
        export_policy: ExportPolicyFfi,
    ) -> Result<GeneratedKeyFfi, AddresseeError> {
        let password = Zeroizing::new(password);
        let export_policy = match export_policy {
            ExportPolicyFfi::Allowed => PrivateExportPolicy::Allowed,
            ExportPolicyFfi::Disabled | ExportPolicyFfi::NotApplicable => {
                PrivateExportPolicy::Disabled
            }
        };
        let profile = profile
            .into_profile()
            .map_err(|_| AddresseeError::UnsupportedOperation)?;
        crate::policy::validate_generation_profile(&profile)?;
        let generated = self
            .lock()?
            .generate(&profile, &user_id, &password, export_policy)?;
        Ok(generated.into())
    }

    pub fn import_public_key(&self, input: Vec<u8>) -> Result<ImportResultFfi, AddresseeError> {
        let mut temporary = SoftwareKeyStore::new();
        temporary.import_public(&input)?;
        let metadata = temporary.list_metadata()?;
        crate::policy::validate_certificate_operation(
            &metadata,
            openpgp_policy::Operation::Import,
        )?;
        let fingerprint = metadata
            .first()
            .map(|metadata| metadata.fingerprint.clone())
            .ok_or(AddresseeError::InvalidCertificate)?;
        let normalized =
            temporary.export_public(&fingerprint, openpgp_core::ExportFormat::Binary)?;
        let mut keys = self.lock()?;
        let remote = self.lock_remote_read()?;
        if let Some(expected) = remote.public_certificate(&fingerprint) {
            let stored = keys.export_public(&fingerprint, openpgp_core::ExportFormat::Binary)?;
            if stored != expected || normalized != expected {
                return Err(AddresseeError::CardRegistrationConflict);
            }
        }
        let result = keys.import_public(&input)?;
        Ok(result.into())
    }

    pub fn import_private_key(
        &self,
        input: Vec<u8>,
        current_password: Option<String>,
        new_password: String,
        export_policy: ExportPolicyFfi,
    ) -> Result<ImportResultFfi, AddresseeError> {
        let current_password = current_password.map(Zeroizing::new);
        let new_password = Zeroizing::new(new_password);
        let export_policy = match export_policy {
            ExportPolicyFfi::Allowed => PrivateExportPolicy::Allowed,
            ExportPolicyFfi::Disabled | ExportPolicyFfi::NotApplicable => {
                PrivateExportPolicy::Disabled
            }
        };
        let mut temporary = SoftwareKeyStore::new();
        temporary.import_private(
            &input,
            current_password.as_ref().map(|value| value.as_str()),
            &new_password,
            PrivateExportPolicy::Disabled,
        )?;
        let metadata = temporary.list_metadata()?;
        crate::policy::validate_certificate_operation(
            &metadata,
            openpgp_policy::Operation::Import,
        )?;
        let fingerprint = metadata
            .first()
            .map(|metadata| metadata.fingerprint.clone())
            .ok_or(AddresseeError::InvalidCertificate)?;
        let mut keys = self.lock()?;
        let remote = self.lock_remote_read()?;
        if remote.contains(&fingerprint) {
            return Err(AddresseeError::AmbiguousPrivateKeyStorage);
        }
        let result = keys.import_private(
            &input,
            current_password.as_ref().map(|value| value.as_str()),
            &new_password,
            export_policy,
        )?;
        Ok(result.into())
    }

    pub fn list_keys(&self) -> Result<Vec<CertificateSummary>, AddresseeError> {
        let metadata = self.lock()?.list_metadata()?;
        Ok(metadata.into_iter().map(Into::into).collect())
    }

    pub fn key_metadata(&self, fingerprint: String) -> Result<CertificateSummary, AddresseeError> {
        let fingerprint = FullFingerprint::from_hex(&fingerprint)?;
        let metadata = self.lock()?.metadata(&fingerprint)?;
        Ok(metadata.into())
    }

    pub fn export_public_key(
        &self,
        fingerprint: String,
        format: ExportFormatFfi,
    ) -> Result<Vec<u8>, AddresseeError> {
        let fingerprint = FullFingerprint::from_hex(&fingerprint)?;
        let metadata = self.lock()?.metadata(&fingerprint)?;
        crate::policy::validate_certificate_operation(
            std::slice::from_ref(&metadata),
            openpgp_policy::Operation::ExportPublic,
        )?;
        let output = self.lock()?.export_public(&fingerprint, format.into())?;
        Ok(output)
    }

    pub fn export_private_key(
        &self,
        fingerprint: String,
        format: ExportFormatFfi,
    ) -> Result<Vec<u8>, AddresseeError> {
        let fingerprint = FullFingerprint::from_hex(&fingerprint)?;
        let metadata = self.lock()?.metadata(&fingerprint)?;
        crate::policy::validate_certificate_operation(
            std::slice::from_ref(&metadata),
            openpgp_policy::Operation::ExportPrivate,
        )?;
        let output = self.lock()?.export_private(&fingerprint, format.into())?;
        Ok(output)
    }
}

impl OpenPgpEngine {
    pub(crate) fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, SoftwareKeyStore>, AddresseeError> {
        self.store
            .lock()
            .map_err(|_| AddresseeError::InternalFailure)
    }

    pub(crate) fn lock_remote_read(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, RemoteRegistry>, AddresseeError> {
        self.remote
            .read()
            .map_err(|_| AddresseeError::InternalFailure)
    }

    pub(crate) fn lock_remote_write(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, RemoteRegistry>, AddresseeError> {
        self.remote
            .write()
            .map_err(|_| AddresseeError::InternalFailure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_generation_and_export_policy_use_the_real_core() {
        let engine = OpenPgpEngine::new();
        let generated = engine
            .generate_key(
                GenerationProfileFfi::ModernV6,
                "FFI Test <ffi@example.invalid>".to_owned(),
                "ffi-test-only".to_owned(),
                ExportPolicyFfi::Disabled,
            )
            .unwrap();
        assert_eq!(generated.summary.fingerprint.len(), 64);
        assert_eq!(generated.summary.subkeys.len(), 2);
        assert!(matches!(
            generated.summary.private_export_policy,
            ExportPolicyFfi::Disabled
        ));
        assert_eq!(
            engine.export_private_key(
                generated.summary.fingerprint.clone(),
                ExportFormatFfi::Armored
            ),
            Err(AddresseeError::ExportDisabled)
        );
        let public = engine
            .export_public_key(
                generated.summary.fingerprint.clone(),
                ExportFormatFfi::Armored,
            )
            .unwrap();
        let second = OpenPgpEngine::new();
        second.import_public_key(public).unwrap();
        assert_eq!(second.list_keys().unwrap().len(), 1);
    }

    #[test]
    fn empty_password_is_rejected() {
        let engine = OpenPgpEngine::new();
        assert!(matches!(
            engine.generate_key(
                GenerationProfileFfi::ModernV6,
                "FFI Test".to_owned(),
                String::new(),
                ExportPolicyFfi::Disabled,
            ),
            Err(AddresseeError::EmptyPassword)
        ));
    }
}
