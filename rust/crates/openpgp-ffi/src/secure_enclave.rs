use std::sync::{Arc, Mutex};

use openpgp_core::{
    FullFingerprint, P256Operations, P256RemoteKey, PrivateExportPolicy, RemoteKeyFailure,
    RemotePrivateKeyResolver, SoftwareKeyStore,
};
use pgp::{
    composed::{Deserializable as _, SignedPublicKey},
    ser::Serialize as _,
    types::{DecryptionKey, KeyDetails, KeyVersion, SigningKey},
};
use zeroize::Zeroizing;

use crate::{
    AddresseeError, GeneratedKeyFfi, OpenPgpEngine,
    remote_registry::{RemoteRegistration, SharedRemoteResolver},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum SecureEnclaveUsageFfi {
    Signing,
    KeyAgreement,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct SecureEnclaveReferenceFfi {
    pub id: String,
    pub usage: SecureEnclaveUsageFfi,
    pub public_key_x963: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct SecureEnclaveBindingFfi {
    pub certificate_fingerprint: String,
    pub public_certificate: Vec<u8>,
    pub signing_component_fingerprint: String,
    pub encryption_component_fingerprint: String,
    pub signing: SecureEnclaveReferenceFfi,
    pub encryption: SecureEnclaveReferenceFfi,
    pub certification: Option<SecureEnclaveReferenceFfi>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SecureEnclaveGeneratedKeyFfi {
    pub generated: GeneratedKeyFfi,
    pub binding: SecureEnclaveBindingFfi,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error, uniffi::Error)]
pub enum SecureEnclaveErrorFfi {
    #[error("The Secure Enclave provider is unavailable")]
    Unavailable,
    #[error("The Secure Enclave operation was cancelled")]
    Cancelled,
    #[error("The Secure Enclave key reference is invalid")]
    InvalidReference,
    #[error("The Secure Enclave provider returned an invalid response")]
    InvalidResponse,
}

#[uniffi::export(with_foreign)]
pub trait SecureEnclaveOperations: Send + Sync {
    fn public_key(
        &self,
        reference: SecureEnclaveReferenceFfi,
    ) -> Result<Vec<u8>, SecureEnclaveErrorFfi>;

    fn sign_sha256(
        &self,
        reference: SecureEnclaveReferenceFfi,
        digest: Vec<u8>,
    ) -> Result<Vec<u8>, SecureEnclaveErrorFfi>;

    fn ecdh(
        &self,
        reference: SecureEnclaveReferenceFfi,
        peer_public_key: Vec<u8>,
    ) -> Result<Vec<u8>, SecureEnclaveErrorFfi>;
}

pub(crate) struct FfiP256Operations {
    pub(crate) signing: SecureEnclaveReferenceFfi,
    pub(crate) encryption: SecureEnclaveReferenceFfi,
    certification: Option<SecureEnclaveReferenceFfi>,
    provider: Arc<dyn SecureEnclaveOperations>,
}

impl FfiP256Operations {
    fn reference(
        &self,
        id: &str,
        usage: SecureEnclaveUsageFfi,
    ) -> Result<SecureEnclaveReferenceFfi, RemoteKeyFailure> {
        let reference = match usage {
            SecureEnclaveUsageFfi::Signing => &self.signing,
            SecureEnclaveUsageFfi::KeyAgreement => &self.encryption,
        };
        if reference.id != id {
            return Err(RemoteKeyFailure::Unavailable);
        }
        Ok(reference.clone())
    }

    fn signing_reference(&self, id: &str) -> Result<SecureEnclaveReferenceFfi, RemoteKeyFailure> {
        if self.signing.id == id {
            return Ok(self.signing.clone());
        }
        self.certification
            .as_ref()
            .filter(|reference| reference.id == id)
            .cloned()
            .ok_or(RemoteKeyFailure::Unavailable)
    }
}

impl P256Operations for FfiP256Operations {
    fn sign_sha256(&self, reference: &str, digest: &[u8]) -> Result<Vec<u8>, RemoteKeyFailure> {
        let reference = self.signing_reference(reference)?;
        self.provider
            .sign_sha256(reference, digest.to_vec())
            .map_err(Into::into)
    }

    fn ecdh(
        &self,
        reference: &str,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RemoteKeyFailure> {
        let reference = self.reference(reference, SecureEnclaveUsageFfi::KeyAgreement)?;
        self.provider
            .ecdh(reference, peer_public_key.to_vec())
            .map(Zeroizing::new)
            .map_err(Into::into)
    }
}

impl From<SecureEnclaveErrorFfi> for RemoteKeyFailure {
    fn from(error: SecureEnclaveErrorFfi) -> Self {
        match error {
            SecureEnclaveErrorFfi::Cancelled => Self::Cancelled,
            SecureEnclaveErrorFfi::Unavailable
            | SecureEnclaveErrorFfi::InvalidReference
            | SecureEnclaveErrorFfi::InvalidResponse => Self::Unavailable,
        }
    }
}

pub(crate) struct SecureEnclaveResolver {
    certificate: FullFingerprint,
    signing_fingerprint: FullFingerprint,
    encryption_fingerprint: FullFingerprint,
    signing: P256RemoteKey,
    encryption: P256RemoteKey,
}

impl SecureEnclaveResolver {
    fn binding(&self) -> &FullFingerprint {
        &self.certificate
    }
}

impl RemotePrivateKeyResolver for SecureEnclaveResolver {
    fn signing_key(
        &self,
        certificate: &FullFingerprint,
        component: &FullFingerprint,
    ) -> pgp::errors::Result<Option<&dyn SigningKey>> {
        if certificate == self.binding() && component == &self.signing_fingerprint {
            Ok(Some(&self.signing))
        } else {
            Ok(None)
        }
    }

    fn decryption_key(
        &self,
        certificate: &FullFingerprint,
        component: &FullFingerprint,
    ) -> pgp::errors::Result<Option<&dyn DecryptionKey>> {
        if certificate == self.binding() && component == &self.encryption_fingerprint {
            Ok(Some(&self.encryption))
        } else {
            Ok(None)
        }
    }

    fn failure_kind(
        &self,
        certificate: &FullFingerprint,
        component: &FullFingerprint,
        _operation: openpgp_core::MessageOperation,
    ) -> RemoteKeyFailure {
        if certificate != self.binding() {
            return RemoteKeyFailure::Unavailable;
        }
        if component == &self.signing_fingerprint {
            self.signing.failure_kind()
        } else if component == &self.encryption_fingerprint {
            self.encryption.failure_kind()
        } else {
            RemoteKeyFailure::Unavailable
        }
    }
}

#[uniffi::export]
impl OpenPgpEngine {
    pub fn generate_secure_enclave_key(
        &self,
        user_id: String,
        certification: SecureEnclaveReferenceFfi,
        signing: SecureEnclaveReferenceFfi,
        encryption: SecureEnclaveReferenceFfi,
        provider: Arc<dyn SecureEnclaveOperations>,
    ) -> Result<SecureEnclaveGeneratedKeyFfi, AddresseeError> {
        let (certification_key, signing_key, encryption_key, operations) =
            new_components(certification, signing, encryption, provider)?;
        let signing_public = signing_key
            .public_subkey()
            .map_err(|_| AddresseeError::InvalidCertificate)?;
        let encryption_public = encryption_key
            .public_subkey()
            .map_err(|_| AddresseeError::InvalidCertificate)?;
        let signing_fingerprint = fingerprint(&signing_public)?;
        let encryption_fingerprint = fingerprint(&encryption_public)?;
        let mut keys = self.lock()?;
        let mut providers = self.lock_remote_write()?;
        let generated = keys.generate_external_p256_hardware(
            &user_id,
            &certification_key,
            &signing_key,
            &encryption_key,
        )?;
        let expected_fingerprint = fingerprint(certification_key.public_key())?;
        let fingerprint = generated.metadata.fingerprint.clone();
        if fingerprint != expected_fingerprint {
            keys.remove(&fingerprint)?;
            return Err(AddresseeError::InvalidCertificate);
        }
        if providers.contains(&fingerprint) {
            keys.remove(&fingerprint)?;
            return Err(AddresseeError::CardRegistrationConflict);
        }
        let binding = SecureEnclaveBindingFfi {
            certificate_fingerprint: fingerprint.to_string(),
            public_certificate: generated.public_certificate.clone(),
            signing_component_fingerprint: signing_fingerprint.to_string(),
            encryption_component_fingerprint: encryption_fingerprint.to_string(),
            signing: operations.signing.clone(),
            encryption: operations.encryption.clone(),
            certification: operations.certification.clone(),
        };
        let resolver = SecureEnclaveResolver {
            certificate: fingerprint.clone(),
            signing_fingerprint,
            encryption_fingerprint,
            signing: signing_key,
            encryption: encryption_key,
        };
        let registration = RemoteRegistration {
            public_certificate: generated.public_certificate.clone(),
            resolver: Arc::new(resolver) as Arc<dyn SharedRemoteResolver>,
            secure_enclave_binding: Some(binding.clone()),
        };
        if let Err(error) = providers.insert_provider(fingerprint.clone(), registration) {
            keys.remove(&fingerprint)?;
            return Err(error);
        }
        Ok(SecureEnclaveGeneratedKeyFfi {
            generated: generated.into(),
            binding,
        })
    }

    pub fn register_secure_enclave(
        &self,
        binding: SecureEnclaveBindingFfi,
        provider: Arc<dyn SecureEnclaveOperations>,
    ) -> Result<SecureEnclaveBindingFfi, AddresseeError> {
        let certificate = parse_certificate(&binding.public_certificate)?;
        let (fingerprint, resolver) = validated_resolver(certificate, &binding, provider)?;
        let public = binding.public_certificate.clone();
        let mut temporary = SoftwareKeyStore::new();
        temporary.import_public(&public)?;
        crate::policy::validate_certificate_operation(
            &temporary.list_metadata()?,
            openpgp_policy::Operation::Import,
        )?;
        let mut keys = self.lock()?;
        let mut providers = self.lock_remote_write()?;
        match keys.metadata(&fingerprint) {
            Ok(metadata) => {
                if (metadata.storage == openpgp_core::KeyStorage::SoftwareSecret
                    && metadata.private_export_policy != Some(PrivateExportPolicy::Disabled))
                    || !keys.software_subkey_fingerprints(&fingerprint)?.is_empty()
                {
                    return Err(AddresseeError::AmbiguousPrivateKeyStorage);
                }
                let stored =
                    keys.export_public(&fingerprint, openpgp_core::ExportFormat::Binary)?;
                if stored != public {
                    return Err(AddresseeError::CardRegistrationConflict);
                }
            }
            Err(openpgp_core::KeyError::KeyNotFound { .. }) => {
                keys.import_public(&public)?;
            }
            Err(error) => return Err(error.into()),
        }
        providers.insert_provider(
            fingerprint,
            RemoteRegistration {
                public_certificate: public,
                resolver: Arc::new(resolver) as Arc<dyn SharedRemoteResolver>,
                secure_enclave_binding: Some(binding.clone()),
            },
        )?;
        Ok(binding)
    }

    pub fn secure_enclave_registrations(
        &self,
    ) -> Result<Vec<SecureEnclaveBindingFfi>, AddresseeError> {
        let _keys = self.lock()?;
        Ok(self.lock_remote_read()?.secure_enclave_registrations())
    }

    pub fn detach_secure_enclave(
        &self,
        certificate_fingerprint: String,
    ) -> Result<SecureEnclaveBindingFfi, AddresseeError> {
        let fingerprint = FullFingerprint::from_hex(&certificate_fingerprint)?;
        let _keys = self.lock()?;
        self.lock_remote_write()?
            .remove_secure_enclave(&fingerprint)
    }
}

pub(crate) fn new_components(
    certification: SecureEnclaveReferenceFfi,
    signing: SecureEnclaveReferenceFfi,
    encryption: SecureEnclaveReferenceFfi,
    provider: Arc<dyn SecureEnclaveOperations>,
) -> Result<
    (
        P256RemoteKey,
        P256RemoteKey,
        P256RemoteKey,
        Arc<FfiP256Operations>,
    ),
    AddresseeError,
> {
    validate_reference(
        &certification,
        SecureEnclaveUsageFfi::Signing,
        provider.as_ref(),
    )?;
    validate_reference(&signing, SecureEnclaveUsageFfi::Signing, provider.as_ref())?;
    validate_reference(
        &encryption,
        SecureEnclaveUsageFfi::KeyAgreement,
        provider.as_ref(),
    )?;
    if certification.id == signing.id
        || certification.id == encryption.id
        || signing.id == encryption.id
    {
        return Err(AddresseeError::UnsupportedOperation);
    }
    let certification_reference = certification.clone();
    let operations = Arc::new(FfiP256Operations {
        signing,
        encryption,
        certification: Some(certification),
        provider,
    });
    let now = u64::from(pgp::types::Timestamp::now().as_secs());
    let certification = P256RemoteKey::new_signing(
        certification_reference.id,
        &certification_reference.public_key_x963,
        now,
        operations.clone(),
        Arc::new(Mutex::new(RemoteKeyFailure::Unavailable)),
    )
    .map_err(map_p256_error)?;
    let signing = P256RemoteKey::new_signing(
        operations.signing.id.clone(),
        &operations.signing.public_key_x963,
        now,
        operations.clone(),
        Arc::new(Mutex::new(RemoteKeyFailure::Unavailable)),
    )
    .map_err(map_p256_error)?;
    let encryption = P256RemoteKey::new_encryption(
        operations.encryption.id.clone(),
        &operations.encryption.public_key_x963,
        now,
        operations.clone(),
        Arc::new(Mutex::new(RemoteKeyFailure::Unavailable)),
    )
    .map_err(map_p256_error)?;
    Ok((certification, signing, encryption, operations))
}

fn validate_reference(
    reference: &SecureEnclaveReferenceFfi,
    expected_usage: SecureEnclaveUsageFfi,
    provider: &dyn SecureEnclaveOperations,
) -> Result<(), AddresseeError> {
    if reference.usage != expected_usage || reference.id.is_empty() || reference.id.len() > 1024 {
        return Err(AddresseeError::UnsupportedOperation);
    }
    let actual = provider
        .public_key(reference.clone())
        .map_err(|error| match error {
            SecureEnclaveErrorFfi::Cancelled => AddresseeError::OperationCancelled,
            SecureEnclaveErrorFfi::InvalidReference => AddresseeError::UnsupportedOperation,
            _ => AddresseeError::RemoteKeyUnavailable,
        })?;
    if actual != reference.public_key_x963 {
        return Err(AddresseeError::ConflictingCertificate);
    }
    Ok(())
}

pub(crate) fn validated_resolver(
    certificate: SignedPublicKey,
    binding: &SecureEnclaveBindingFfi,
    provider: Arc<dyn SecureEnclaveOperations>,
) -> Result<(FullFingerprint, SecureEnclaveResolver), AddresseeError> {
    if certificate.primary_key.version() != KeyVersion::V4 {
        return Err(AddresseeError::UnsupportedOperation);
    }
    let certificate_fingerprint = fingerprint(&certificate.primary_key)?;
    if certificate_fingerprint.to_string() != binding.certificate_fingerprint {
        return Err(AddresseeError::CardRegistrationConflict);
    }
    let [signing_component, encryption_component] = certificate.public_subkeys.as_slice() else {
        return Err(AddresseeError::InvalidCertificate);
    };
    let signing_fingerprint = fingerprint(&signing_component.key)?;
    let encryption_fingerprint = fingerprint(&encryption_component.key)?;
    if signing_fingerprint.to_string() != binding.signing_component_fingerprint
        || encryption_fingerprint.to_string() != binding.encryption_component_fingerprint
    {
        return Err(AddresseeError::ConflictingCertificate);
    }
    if let Some(reference) = &binding.certification {
        validate_reference(reference, SecureEnclaveUsageFfi::Signing, provider.as_ref())?;
        let primary = P256RemoteKey::new_signing(
            reference.id.clone(),
            &reference.public_key_x963,
            u64::from(certificate.primary_key.created_at().as_secs()),
            operations_for(binding, provider.clone()),
            Arc::new(Mutex::new(RemoteKeyFailure::Unavailable)),
        )
        .map_err(map_p256_error)?;
        if primary.public_key().fingerprint() != certificate.primary_key.fingerprint()
            || !primary.has_public_key(&reference.public_key_x963)
        {
            return Err(AddresseeError::ConflictingCertificate);
        }
    }
    let signing = P256RemoteKey::from_signing_component(
        binding.signing.id.clone(),
        &signing_component.key,
        operations_for(binding, provider.clone()),
        Arc::new(Mutex::new(RemoteKeyFailure::Unavailable)),
    )
    .map_err(map_p256_error)?;
    let encryption = P256RemoteKey::from_encryption_component(
        binding.encryption.id.clone(),
        &encryption_component.key,
        operations_for(binding, provider.clone()),
        Arc::new(Mutex::new(RemoteKeyFailure::Unavailable)),
    )
    .map_err(map_p256_error)?;
    if signing.public_key().fingerprint() != signing_component.key.fingerprint()
        || encryption.public_key().fingerprint() != encryption_component.key.fingerprint()
    {
        return Err(AddresseeError::ConflictingCertificate);
    }
    validate_reference(
        &binding.signing,
        SecureEnclaveUsageFfi::Signing,
        provider.as_ref(),
    )?;
    validate_reference(
        &binding.encryption,
        SecureEnclaveUsageFfi::KeyAgreement,
        provider.as_ref(),
    )?;
    if binding.signing.id == binding.encryption.id
        || binding.certification.as_ref().is_some_and(|reference| {
            reference.id == binding.signing.id || reference.id == binding.encryption.id
        })
    {
        return Err(AddresseeError::UnsupportedOperation);
    }
    if !signing.has_public_key(&binding.signing.public_key_x963)
        || !encryption.has_public_key(&binding.encryption.public_key_x963)
    {
        return Err(AddresseeError::ConflictingCertificate);
    }
    Ok((
        certificate_fingerprint.clone(),
        SecureEnclaveResolver {
            certificate: certificate_fingerprint,
            signing_fingerprint,
            encryption_fingerprint,
            signing,
            encryption,
        },
    ))
}

fn operations_for(
    binding: &SecureEnclaveBindingFfi,
    provider: Arc<dyn SecureEnclaveOperations>,
) -> Arc<FfiP256Operations> {
    Arc::new(FfiP256Operations {
        signing: binding.signing.clone(),
        encryption: binding.encryption.clone(),
        certification: binding.certification.clone(),
        provider,
    })
}

fn fingerprint(key: &dyn KeyDetails) -> Result<FullFingerprint, AddresseeError> {
    FullFingerprint::from_hex(&format!("{:X}", key.fingerprint())).map_err(Into::into)
}

fn parse_certificate(input: &[u8]) -> Result<SignedPublicKey, AddresseeError> {
    let certificate =
        SignedPublicKey::from_bytes(input).map_err(|_| AddresseeError::InvalidCertificate)?;
    certificate
        .verify_bindings()
        .map_err(|_| AddresseeError::InvalidCertificate)?;
    if certificate
        .to_bytes()
        .map_err(|_| AddresseeError::InvalidCertificate)?
        != input
    {
        return Err(AddresseeError::InvalidCertificate);
    }
    Ok(certificate)
}

fn map_p256_error(error: openpgp_core::P256RemoteError) -> AddresseeError {
    match error {
        openpgp_core::P256RemoteError::Provider(RemoteKeyFailure::Cancelled) => {
            AddresseeError::OperationCancelled
        }
        openpgp_core::P256RemoteError::Provider(RemoteKeyFailure::Unavailable) => {
            AddresseeError::RemoteKeyUnavailable
        }
        _ => AddresseeError::UnsupportedOperation,
    }
}
