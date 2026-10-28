#![forbid(unsafe_code)]

//! OpenPGP algorithm policy and evidence-gated capability data.
//!
//! The registry separates library and platform API candidates from Addressee implementation,
//! unit-test, independent-interoperability, and physical-hardware evidence. Lifecycle operations
//! verified by the software key tests are marked accordingly; untested operations remain disabled.

mod algorithm;
mod capability;
mod profile;
mod security;
#[cfg(test)]
mod tests;

pub use algorithm::{Algorithm, Backend, KeyRole, KeyVersion, Operation};
pub use capability::{
    CAPABILITY_SCHEMA_VERSION, CapabilityEntry, CapabilityRegistry, ImplementationStatus,
    LibraryClaim, OperationEvidence, TestStatus,
};
pub use profile::{
    CompatibilityAcknowledgement, GenerationProfile, KeyGenerationSpec, ProfileError,
};
pub use security::{
    HashAlgorithm, LegacyAlgorithmWarning, LegacyDisposition, LegacyPolicyDecision, SecurityPolicy,
    SecurityPolicyError, SymmetricAlgorithm,
};

/// Serializes the baseline with stable ordering, two-space indentation, and one trailing newline.
pub fn algorithm_capabilities_json() -> Result<String, serde_json::Error> {
    let mut json = serde_json::to_string_pretty(&CapabilityRegistry::baseline())?;
    json.push('\n');
    Ok(json)
}
