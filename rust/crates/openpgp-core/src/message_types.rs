use openpgp_policy::{HashAlgorithm, LegacyDisposition, LegacyPolicyDecision, SymmetricAlgorithm};
use serde::{Deserialize, Serialize};

use crate::{AlgorithmMetadata, FullFingerprint, KeyValidity};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MessageFormat {
    Binary,
    Armored,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MessageCipher {
    Aes128,
    Aes192,
    Aes256,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AeadMode {
    Ocb,
    Eax,
    Gcm,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "container")]
pub enum EncryptionConfig {
    SeipdV1 {
        cipher: MessageCipher,
    },
    SeipdV2 {
        cipher: MessageCipher,
        mode: AeadMode,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageLimits {
    pub max_text_bytes: usize,
    pub max_cleartext_bytes: usize,
    pub max_signature_bytes: usize,
    pub max_plaintext_bytes: usize,
    pub max_compression_layers: usize,
}

impl Default for MessageLimits {
    fn default() -> Self {
        Self {
            max_text_bytes: 1024 * 1024,
            max_cleartext_bytes: 4 * 1024 * 1024,
            max_signature_bytes: 1024 * 1024,
            max_plaintext_bytes: 64 * 1024 * 1024,
            max_compression_layers: 4,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureMetadata {
    pub certificate_fingerprint: FullFingerprint,
    pub signer_fingerprint: FullFingerprint,
    pub algorithm: AlgorithmMetadata,
    pub hash_algorithm: HashAlgorithm,
    pub created_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VerificationStatus {
    Unsigned,
    Valid,
    Invalid,
    UnknownSigner,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IdentityTrust {
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureVerification {
    pub status: VerificationStatus,
    pub cryptographically_valid: Option<bool>,
    pub certificate_fingerprint: Option<FullFingerprint>,
    pub signer_fingerprint: Option<FullFingerprint>,
    pub signer_key_id: Option<String>,
    pub algorithm: Option<AlgorithmMetadata>,
    pub hash_algorithm: Option<HashAlgorithm>,
    pub legacy_decision: LegacyPolicyDecision,
    pub created_at: Option<u64>,
    pub key_validity: Option<KeyValidity>,
    pub trust: IdentityTrust,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationOutcome {
    pub status: VerificationStatus,
    pub signatures: Vec<SignatureVerification>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleartextVerification {
    pub outcome: VerificationOutcome,
    pub text: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DecryptionStatus {
    Unsigned,
    Valid,
    Invalid,
    UnknownSigner,
    DecryptionFailed,
    IntegrityFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptionReport {
    pub status: DecryptionStatus,
    pub signatures: Vec<SignatureVerification>,
    pub trust: IdentityTrust,
    pub symmetric_algorithm: Option<SymmetricAlgorithm>,
    pub legacy_decision: LegacyPolicyDecision,
    pub detail: Option<String>,
}

impl DecryptionReport {
    /// Ordinary invalid or unknown signatures do not establish identity trust, but only a
    /// legacy-policy rejection or failed decryption or integrity check blocks plaintext release.
    pub fn may_commit_staging(&self) -> bool {
        !matches!(
            self.status,
            DecryptionStatus::DecryptionFailed | DecryptionStatus::IntegrityFailed
        ) && self.legacy_decision.disposition != LegacyDisposition::Reject
            && self
                .signatures
                .iter()
                .all(|signature| signature.legacy_decision.disposition != LegacyDisposition::Reject)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptedMessage {
    pub report: DecryptionReport,
    pub plaintext: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptedText {
    pub report: DecryptionReport,
    pub text: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MessageOperation {
    Sign,
    Encrypt,
    Decrypt,
}

#[derive(Clone, Copy, Debug)]
pub struct SigningKeyRequest<'a> {
    pub fingerprint: &'a FullFingerprint,
    pub password: &'a str,
}

impl<'a> SigningKeyRequest<'a> {
    pub fn new(fingerprint: &'a FullFingerprint, password: &'a str) -> Self {
        Self {
            fingerprint,
            password,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EncryptionRequest<'a> {
    pub recipients: &'a [FullFingerprint],
    pub at_unix_seconds: u64,
    pub config: EncryptionConfig,
}

impl<'a> EncryptionRequest<'a> {
    pub fn new(
        recipients: &'a [FullFingerprint],
        at_unix_seconds: u64,
        config: EncryptionConfig,
    ) -> Self {
        Self {
            recipients,
            at_unix_seconds,
            config,
        }
    }
}
