use std::fmt::{self, Display, Formatter};

use openpgp_core::{FingerprintError, KeyError};

#[derive(Debug, Eq, PartialEq, uniffi::Error)]
pub enum AddresseeError {
    CapabilityRegistryUnavailable,
    EmptyPassword,
    EmptyUserId,
    AuthenticationRequired,
    InvalidPassword,
    InvalidFingerprint,
    KeyNotFound,
    PublicKeyOnly,
    ExportDisabled,
    ConflictingCertificate,
    InvalidCertificate,
    UnsupportedOperation,
    InvalidInput,
    ResourceLimit,
    NotEncrypted,
    RemoteKeyUnavailable,
    CardRegistrationConflict,
    CardSessionUnavailable,
    AmbiguousPrivateKeyStorage,
    OperationCancelled,
    InternalFailure,
}

impl Display for AddresseeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::CapabilityRegistryUnavailable => {
                "The algorithm capability registry is unavailable"
            }
            Self::EmptyPassword => "The software protection password must not be empty",
            Self::EmptyUserId => "The user ID must not be empty",
            Self::AuthenticationRequired => "The current password is required",
            Self::InvalidPassword => "The supplied password is incorrect",
            Self::InvalidFingerprint => "The full fingerprint is invalid",
            Self::KeyNotFound => "The requested key was not found",
            Self::PublicKeyOnly => "The requested record contains only a public key",
            Self::ExportDisabled => "Private-key export is disabled for this record",
            Self::ConflictingCertificate => {
                "A different certificate with this fingerprint already exists"
            }
            Self::InvalidCertificate => "The certificate or its protection parameters are invalid",
            Self::UnsupportedOperation => "The requested operation is unsupported by policy",
            Self::InvalidInput => "The OpenPGP input is invalid",
            Self::ResourceLimit => "The configured resource limit was exceeded",
            Self::NotEncrypted => "The input is not an encrypted OpenPGP message",
            Self::RemoteKeyUnavailable => {
                "The private-key provider could not complete the operation"
            }
            Self::CardRegistrationConflict => {
                "The card session conflicts with an existing key or card binding"
            }
            Self::CardSessionUnavailable => "The required card session is not connected",
            Self::AmbiguousPrivateKeyStorage => {
                "A certificate cannot use both software and hardware private keys"
            }
            Self::OperationCancelled => "The operation was cancelled",
            Self::InternalFailure => "The OpenPGP operation failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AddresseeError {}

impl From<KeyError> for AddresseeError {
    fn from(error: KeyError) -> Self {
        match error {
            KeyError::EmptyPassword => Self::EmptyPassword,
            KeyError::EmptyUserId => Self::EmptyUserId,
            KeyError::PasswordRequired => Self::AuthenticationRequired,
            KeyError::InvalidPassword { .. } => Self::InvalidPassword,
            KeyError::KeyNotFound { .. } => Self::KeyNotFound,
            KeyError::PrivateExportDisabled { .. } => Self::ExportDisabled,
            KeyError::SecretKeyRequired { .. } => Self::PublicKeyOnly,
            KeyError::ConflictingCertificate { .. } => Self::ConflictingCertificate,
            KeyError::UnsupportedGenerationAlgorithm { .. } | KeyError::Profile(_) => {
                Self::UnsupportedOperation
            }
            KeyError::MultipleCertificates
            | KeyError::MixedKeyring
            | KeyError::TrailingData
            | KeyError::LeadingData
            | KeyError::UnexpectedPacket { .. }
            | KeyError::MissingBinding { .. }
            | KeyError::EmptyInput
            | KeyError::SecretMaterialMismatch { .. }
            | KeyError::UnprotectedSecret { .. }
            | KeyError::OpenPgp(_) => Self::InvalidCertificate,
            KeyError::InvalidParameters(_) => Self::UnsupportedOperation,
            KeyError::Io(_) => Self::InternalFailure,
        }
    }
}

impl From<FingerprintError> for AddresseeError {
    fn from(_: FingerprintError) -> Self {
        Self::InvalidFingerprint
    }
}
