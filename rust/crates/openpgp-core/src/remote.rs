use pgp::types::{DecryptionKey, SigningKey};

use crate::{FullFingerprint, MessageOperation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteKeyFailure {
    Unavailable,
    Cancelled,
}

/// Resolves private-key operations for public certificate components held outside the software
/// store.
///
/// Implementations may authenticate a component while resolving it. Message operations pass both
/// the certificate fingerprint and the exact component fingerprint selected from validated public
/// metadata. Returning `None` declines that component. Returned key metadata must match the
/// requested component; the message service rejects mismatches before invoking the key.
///
/// Resolver errors and remote callback errors are converted to sanitized message errors. Remote
/// callbacks receive an empty OpenPGP password, never the software protection password.
/// `failure_kind` reports only the public error category for the last failed operation on the
/// requested component. It must not expose credentials or provider error details.
pub trait RemotePrivateKeyResolver {
    fn signing_key(
        &self,
        certificate_fingerprint: &FullFingerprint,
        component_fingerprint: &FullFingerprint,
    ) -> pgp::errors::Result<Option<&dyn SigningKey>>;

    fn decryption_key(
        &self,
        certificate_fingerprint: &FullFingerprint,
        component_fingerprint: &FullFingerprint,
    ) -> pgp::errors::Result<Option<&dyn DecryptionKey>>;

    fn failure_kind(
        &self,
        _certificate_fingerprint: &FullFingerprint,
        _component_fingerprint: &FullFingerprint,
        _operation: MessageOperation,
    ) -> RemoteKeyFailure {
        RemoteKeyFailure::Unavailable
    }
}
