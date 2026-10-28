#![forbid(unsafe_code)]

mod card;
mod card_engine;
mod card_management;
#[cfg(test)]
mod card_management_tests;
#[cfg(test)]
mod card_tests;
#[cfg(test)]
mod card_transport_tests;
mod engine;
mod error;
mod message;
mod message_files;
mod message_types;
mod policy;
mod remote_registry;
mod secure_enclave;
#[cfg(test)]
mod secure_enclave_tests;
mod storage;
mod types;

pub use card::*;
pub use card_management::*;
pub use engine::OpenPgpEngine;
pub use error::AddresseeError;
pub use message_files::*;
pub use message_types::*;
pub use secure_enclave::*;
pub use storage::*;
pub use types::*;

uniffi::setup_scaffolding!();

#[uniffi::export]
pub fn algorithm_capabilities_json() -> Result<String, AddresseeError> {
    openpgp_policy::algorithm_capabilities_json()
        .map_err(|_| AddresseeError::CapabilityRegistryUnavailable)
}

#[cfg(test)]
mod tests {
    #[test]
    fn registry_is_available_through_the_public_contract() {
        let json = super::algorithm_capabilities_json().unwrap();
        assert!(json.contains("\"schemaVersion\": 1"));
        assert!(json.ends_with('\n'));
    }
}
