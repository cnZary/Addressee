#![forbid(unsafe_code)]

//! OpenPGP key generation, import, protected storage, export, validity metadata, and message
//! operations with software or explicitly resolved remote private keys.
//!
//! Binding verification and time-dependent validity are separate. This crate does not evaluate
//! identity trust or Web-of-Trust results, and software keys are never described as hardware-backed.

mod error;
mod external;
mod import;
mod message;
mod message_error;
#[cfg(test)]
mod message_tests;
mod message_types;
mod metadata;
mod p256_remote;
mod remote;
#[cfg(test)]
mod remote_tests;
#[cfg(test)]
mod storage_tests;
mod store;
#[cfg(test)]
mod tests;
mod types;

pub use error::KeyError;
pub use message::MessageService;
pub use message_error::MessageError;
pub use message_types::{
    AeadMode, CleartextVerification, DecryptedMessage, DecryptedText, DecryptionReport,
    DecryptionStatus, EncryptionConfig, EncryptionRequest, IdentityTrust, MessageCipher,
    MessageFormat, MessageLimits, MessageOperation, SignatureMetadata, SignatureVerification,
    SigningKeyRequest, VerificationOutcome, VerificationStatus,
};
pub use openpgp_policy::Backend;
pub use p256_remote::{P256Operations, P256RemoteError, P256RemoteKey};
pub use remote::{RemoteKeyFailure, RemotePrivateKeyResolver};
pub use store::SoftwareKeyStore;
pub use types::{
    AlgorithmMetadata, BindingValidity, CertificateMetadata, CertificateValidity, CurveMetadata,
    ExportFormat, FingerprintError, FullFingerprint, GeneratedKey, ImportOutcome, ImportResult,
    KeyMetadata, KeyStorage, KeyUsage, KeyUsageFlags, KeyValidity, KeyVersion, PrivateExportPolicy,
    RevocationMetadata, SecretComponent, StorageRecord, UserIdMetadata, UserIdValidity,
};
