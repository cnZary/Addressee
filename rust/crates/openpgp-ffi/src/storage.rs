use openpgp_core::{FullFingerprint, PrivateExportPolicy, SoftwareKeyStore, StorageRecord};

use crate::{AddresseeError, ExportPolicyFfi};

use super::OpenPgpEngine;

/// Sealed-storage representation of one certificate. Protected secret material
/// keeps its original password protection and is not an OpenPGP export format.
#[derive(Clone, Debug, uniffi::Record)]
pub struct StorageRecordFfi {
    pub fingerprint: String,
    pub protected_secret: Option<Vec<u8>>,
    pub public_certificate: Vec<u8>,
    pub export_policy: Option<ExportPolicyFfi>,
}

impl From<StorageRecord> for StorageRecordFfi {
    fn from(value: StorageRecord) -> Self {
        Self {
            fingerprint: value.fingerprint.to_string(),
            protected_secret: value.protected_secret,
            public_certificate: value.public_certificate,
            export_policy: value.export_policy.map(|policy| match policy {
                PrivateExportPolicy::Allowed => ExportPolicyFfi::Allowed,
                PrivateExportPolicy::Disabled => ExportPolicyFfi::Disabled,
            }),
        }
    }
}

impl TryFrom<StorageRecordFfi> for StorageRecord {
    type Error = AddresseeError;

    fn try_from(value: StorageRecordFfi) -> Result<Self, Self::Error> {
        Ok(Self {
            fingerprint: FullFingerprint::from_hex(&value.fingerprint)?,
            protected_secret: value.protected_secret,
            public_certificate: value.public_certificate,
            export_policy: value.export_policy.map(|policy| match policy {
                ExportPolicyFfi::Allowed => PrivateExportPolicy::Allowed,
                ExportPolicyFfi::Disabled | ExportPolicyFfi::NotApplicable => {
                    PrivateExportPolicy::Disabled
                }
            }),
        })
    }
}

#[uniffi::export]
impl OpenPgpEngine {
    /// Returns records for sealed on-device storage. Private export policy is
    /// unchanged: this is not an OpenPGP private-key export path.
    pub fn storage_snapshot(&self) -> Result<Vec<StorageRecordFfi>, AddresseeError> {
        let snapshot = self.lock()?.storage_snapshot()?;
        Ok(snapshot.into_iter().map(Into::into).collect())
    }

    /// Restores sealed-storage records without requiring any password. Original
    /// password protection and export policy are preserved.
    pub fn restore_storage(&self, records: Vec<StorageRecordFfi>) -> Result<(), AddresseeError> {
        let records: Vec<StorageRecord> = records
            .into_iter()
            .map(StorageRecord::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let mut keys = self.lock()?;
        let providers = self.lock_remote_read()?;
        for record in &records {
            let Some(expected) = providers.public_certificate(&record.fingerprint) else {
                continue;
            };
            if expected != record.public_certificate {
                return Err(AddresseeError::CardRegistrationConflict);
            }
            if record.protected_secret.is_none() {
                continue;
            }
            if !providers.allows_protected_primary(&record.fingerprint)
                || record.export_policy != Some(PrivateExportPolicy::Disabled)
            {
                return Err(AddresseeError::AmbiguousPrivateKeyStorage);
            }
            let mut temporary = SoftwareKeyStore::new();
            temporary.restore_storage(vec![record.clone()])?;
            if !temporary
                .software_subkey_fingerprints(&record.fingerprint)?
                .is_empty()
            {
                return Err(AddresseeError::AmbiguousPrivateKeyStorage);
            }
        }
        keys.restore_storage(records)?;
        Ok(())
    }

    pub fn remove_key(&self, fingerprint: String) -> Result<(), AddresseeError> {
        let fingerprint = FullFingerprint::from_hex(&fingerprint)?;
        let mut keys = self.lock()?;
        let mut providers = self.lock_remote_write()?;
        keys.remove(&fingerprint)?;
        if providers.contains(&fingerprint) {
            providers.remove(&fingerprint)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GenerationProfileFfi, MessageFormatFfi, VerificationStatusFfi};

    #[test]
    fn storage_roundtrip_preserves_operations_and_policy() {
        let engine = OpenPgpEngine::new();
        let generated = engine
            .generate_key(
                GenerationProfileFfi::ModernV6,
                "FFI Storage <storage@example.invalid>".to_owned(),
                "storage-test-only".to_owned(),
                ExportPolicyFfi::Disabled,
            )
            .unwrap();
        let fingerprint = generated.summary.fingerprint.clone();
        let snapshot = engine.storage_snapshot().unwrap();
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot[0].protected_secret.is_some());

        let restored = OpenPgpEngine::new();
        restored.restore_storage(snapshot.clone()).unwrap();
        restored.restore_storage(snapshot).unwrap();
        assert_eq!(restored.list_keys().unwrap().len(), 1);
        assert!(matches!(
            restored.export_private_key(fingerprint.clone(), crate::ExportFormatFfi::Binary),
            Err(AddresseeError::ExportDisabled)
        ));

        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signature = restored
            .sign_detached(
                fingerprint.clone(),
                "storage-test-only".to_owned(),
                at,
                b"restored".to_vec(),
                MessageFormatFfi::Binary,
            )
            .unwrap();
        let verified = restored
            .verify_detached(b"restored".to_vec(), signature.artifact, at)
            .unwrap();
        assert!(matches!(verified.status, VerificationStatusFfi::Valid));

        restored.remove_key(fingerprint.clone()).unwrap();
        assert!(restored.list_keys().unwrap().is_empty());
        assert!(matches!(
            restored.remove_key(fingerprint),
            Err(AddresseeError::KeyNotFound)
        ));
    }
}
