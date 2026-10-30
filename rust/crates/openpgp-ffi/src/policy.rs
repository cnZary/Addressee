use std::sync::OnceLock;

use openpgp_core::{CertificateMetadata, KeyVersion as CoreKeyVersion};
use openpgp_policy::{Backend, CapabilityRegistry, GenerationProfile, KeyVersion, Operation};

use crate::AddresseeError;

static REGISTRY: OnceLock<CapabilityRegistry> = OnceLock::new();

pub(crate) fn registry() -> &'static CapabilityRegistry {
    REGISTRY.get_or_init(CapabilityRegistry::baseline)
}

pub fn validate_generation_profile(profile: &GenerationProfile) -> Result<(), AddresseeError> {
    profile
        .validate()
        .map_err(|_| AddresseeError::UnsupportedOperation)?;
    let version = profile.key_version;
    for (algorithm, operation) in [
        (profile.primary_key.algorithm, Operation::Generate),
        (profile.primary_key.algorithm, Operation::UseAsPrimaryKey),
        (profile.signing_subkey.algorithm, Operation::Generate),
        (
            profile.signing_subkey.algorithm,
            Operation::UseAsSigningSubkey,
        ),
        (profile.encryption_subkey.algorithm, Operation::Generate),
        (
            profile.encryption_subkey.algorithm,
            Operation::UseAsEncryptionSubkey,
        ),
    ] {
        validate_algorithm(algorithm, version, operation)?;
    }
    Ok(())
}

pub fn validate_certificate_operation(
    certificates: &[CertificateMetadata],
    operation: Operation,
) -> Result<(), AddresseeError> {
    for certificate in certificates {
        for key in std::iter::once(&certificate.primary).chain(certificate.subkeys.iter()) {
            let algorithm = key
                .algorithm
                .policy_algorithm
                .ok_or(AddresseeError::UnsupportedOperation)?;
            let version = match key.key_version {
                CoreKeyVersion::V4 => KeyVersion::V4,
                CoreKeyVersion::V6 => KeyVersion::V6,
                _ => return Err(AddresseeError::UnsupportedOperation),
            };
            validate_algorithm(algorithm, version, operation)?;
        }
    }
    Ok(())
}

fn validate_algorithm(
    algorithm: openpgp_policy::Algorithm,
    version: KeyVersion,
    operation: Operation,
) -> Result<(), AddresseeError> {
    if registry().is_operation_enabled(algorithm, Backend::Software, version, operation) {
        Ok(())
    } else {
        Err(AddresseeError::UnsupportedOperation)
    }
}
