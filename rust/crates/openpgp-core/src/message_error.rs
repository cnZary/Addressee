use openpgp_policy::SecurityPolicyError;
use thiserror::Error;

use crate::{FullFingerprint, KeyError, MessageOperation, RemoteKeyFailure};

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("at least one recipient certificate is required")]
    EmptyRecipients,
    #[error("input is empty")]
    EmptyInput,
    #[error("input contains trailing data")]
    TrailingData,
    #[error("input contains leading data")]
    LeadingData,
    #[error("input has an unexpected artifact type")]
    MixedKeyring,
    #[error("message is not encrypted")]
    NotEncrypted,
    #[error("no usable key for {operation:?} in certificate {fingerprint}")]
    NoUsableKey {
        fingerprint: FullFingerprint,
        operation: MessageOperation,
    },
    #[error(
        "remote private-key operation {operation:?} failed for component {component_fingerprint} in certificate {fingerprint}"
    )]
    RemoteKey {
        fingerprint: FullFingerprint,
        component_fingerprint: FullFingerprint,
        operation: MessageOperation,
        failure: RemoteKeyFailure,
    },
    #[error("signature timestamp {at_unix_seconds} exceeds the OpenPGP 32-bit time range")]
    TimestampOutOfRange { at_unix_seconds: u64 },
    #[error("signature issuer does not identify one unambiguous stored key")]
    AmbiguousSigner,
    #[error("text input exceeds the configured {limit}-byte limit")]
    TextLimitExceeded { limit: usize },
    #[error("cleartext input exceeds the configured {limit}-byte limit")]
    CleartextLimitExceeded { limit: usize },
    #[error("signature input exceeds the configured {limit}-byte limit")]
    SignatureLimitExceeded { limit: usize },
    #[error("plaintext exceeds the configured {limit}-byte limit")]
    PlaintextLimitExceeded { limit: usize },
    #[error("message has more than {limit} compression layers")]
    CompressionLimitExceeded { limit: usize },
    #[error("text message contains non-CRLF line endings")]
    InvalidTextLineEnding,
    #[error("decrypted text is not valid UTF-8")]
    InvalidUtf8,
    #[error("unsupported hash algorithm ID {0}")]
    UnsupportedHashAlgorithm(u8),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    SecurityPolicy(#[from] SecurityPolicyError),
    #[error(transparent)]
    OpenPgp(#[from] pgp::errors::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
