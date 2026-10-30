use openpgp_core::{
    AeadMode, CleartextVerification, DecryptedMessage as CoreDecryptedMessage, DecryptedText,
    DecryptionReport, DecryptionStatus, EncryptionConfig, IdentityTrust, KeyValidity,
    MessageCipher, MessageFormat, SignatureMetadata, SignatureVerification, VerificationOutcome,
    VerificationStatus,
};
use openpgp_policy::{
    HashAlgorithm, LegacyAlgorithmWarning, LegacyDisposition, LegacyPolicyDecision,
    SymmetricAlgorithm,
};

use crate::{AlgorithmSummary, KeyUsageSummary};

#[derive(Clone, Debug, uniffi::Enum)]
pub enum MessageFormatFfi {
    Binary,
    Armored,
}

impl From<MessageFormatFfi> for MessageFormat {
    fn from(value: MessageFormatFfi) -> Self {
        match value {
            MessageFormatFfi::Binary => Self::Binary,
            MessageFormatFfi::Armored => Self::Armored,
        }
    }
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum MessageCipherFfi {
    Aes128,
    Aes192,
    Aes256,
}

impl From<MessageCipherFfi> for MessageCipher {
    fn from(value: MessageCipherFfi) -> Self {
        match value {
            MessageCipherFfi::Aes128 => Self::Aes128,
            MessageCipherFfi::Aes192 => Self::Aes192,
            MessageCipherFfi::Aes256 => Self::Aes256,
        }
    }
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum AeadModeFfi {
    Ocb,
    Eax,
    Gcm,
}

impl From<AeadModeFfi> for AeadMode {
    fn from(value: AeadModeFfi) -> Self {
        match value {
            AeadModeFfi::Ocb => Self::Ocb,
            AeadModeFfi::Eax => Self::Eax,
            AeadModeFfi::Gcm => Self::Gcm,
        }
    }
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum EncryptionConfigFfi {
    SeipdV1 {
        cipher: MessageCipherFfi,
    },
    SeipdV2 {
        cipher: MessageCipherFfi,
        mode: AeadModeFfi,
    },
}

impl From<EncryptionConfigFfi> for EncryptionConfig {
    fn from(value: EncryptionConfigFfi) -> Self {
        match value {
            EncryptionConfigFfi::SeipdV1 { cipher } => Self::SeipdV1 {
                cipher: cipher.into(),
            },
            EncryptionConfigFfi::SeipdV2 { cipher, mode } => Self::SeipdV2 {
                cipher: cipher.into(),
                mode: mode.into(),
            },
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SignatureMetadataFfi {
    pub certificate_fingerprint: String,
    pub signer_fingerprint: String,
    pub algorithm: AlgorithmSummary,
    pub hash_algorithm: String,
    pub created_at: Option<u64>,
}

impl From<SignatureMetadata> for SignatureMetadataFfi {
    fn from(value: SignatureMetadata) -> Self {
        Self {
            certificate_fingerprint: value.certificate_fingerprint.to_string(),
            signer_fingerprint: value.signer_fingerprint.to_string(),
            algorithm: value.algorithm.into(),
            hash_algorithm: hash_algorithm_identifier(value.hash_algorithm).to_owned(),
            created_at: value.created_at,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SignatureArtifactFfi {
    pub metadata: SignatureMetadataFfi,
    pub artifact: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum VerificationStatusFfi {
    Unsigned,
    Valid,
    Invalid,
    UnknownSigner,
}

impl From<VerificationStatus> for VerificationStatusFfi {
    fn from(value: VerificationStatus) -> Self {
        match value {
            VerificationStatus::Unsigned => Self::Unsigned,
            VerificationStatus::Valid => Self::Valid,
            VerificationStatus::Invalid => Self::Invalid,
            VerificationStatus::UnknownSigner => Self::UnknownSigner,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum LegacyDispositionFfi {
    Allow,
    AllowWithWarning,
    Reject,
}

impl From<LegacyDisposition> for LegacyDispositionFfi {
    fn from(value: LegacyDisposition) -> Self {
        match value {
            LegacyDisposition::Allow => Self::Allow,
            LegacyDisposition::AllowWithWarning => Self::AllowWithWarning,
            LegacyDisposition::Reject => Self::Reject,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum LegacyWarningKindFfi {
    WeakSignatureHash,
    LegacySymmetricCipher,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct LegacyAlgorithmWarningFfi {
    pub kind: LegacyWarningKindFfi,
    pub algorithm: String,
}

impl From<LegacyAlgorithmWarning> for LegacyAlgorithmWarningFfi {
    fn from(value: LegacyAlgorithmWarning) -> Self {
        match value {
            LegacyAlgorithmWarning::WeakSignatureHash(algorithm) => Self {
                kind: LegacyWarningKindFfi::WeakSignatureHash,
                algorithm: hash_algorithm_identifier(algorithm).to_owned(),
            },
            LegacyAlgorithmWarning::LegacySymmetricCipher(algorithm) => Self {
                kind: LegacyWarningKindFfi::LegacySymmetricCipher,
                algorithm: symmetric_algorithm_identifier(algorithm).to_owned(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct LegacyPolicyDecisionFfi {
    pub disposition: LegacyDispositionFfi,
    pub warning: Option<LegacyAlgorithmWarningFfi>,
}

impl From<LegacyPolicyDecision> for LegacyPolicyDecisionFfi {
    fn from(value: LegacyPolicyDecision) -> Self {
        Self {
            disposition: value.disposition.into(),
            warning: value.warning.map(Into::into),
        }
    }
}

fn hash_algorithm_identifier(algorithm: HashAlgorithm) -> &'static str {
    match algorithm {
        HashAlgorithm::Md5 => "md5",
        HashAlgorithm::Sha1 => "sha1",
        HashAlgorithm::Ripemd160 => "ripemd160",
        HashAlgorithm::Sha224 => "sha224",
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Sha384 => "sha384",
        HashAlgorithm::Sha512 => "sha512",
        HashAlgorithm::Sha3_256 => "sha3-256",
        HashAlgorithm::Sha3_512 => "sha3-512",
    }
}

fn symmetric_algorithm_identifier(algorithm: SymmetricAlgorithm) -> &'static str {
    match algorithm {
        SymmetricAlgorithm::Idea => "idea",
        SymmetricAlgorithm::TripleDes => "triple-des",
        SymmetricAlgorithm::Cast5 => "cast5",
        SymmetricAlgorithm::Blowfish => "blowfish",
        SymmetricAlgorithm::Aes128 => "aes-128",
        SymmetricAlgorithm::Aes192 => "aes-192",
        SymmetricAlgorithm::Aes256 => "aes-256",
        SymmetricAlgorithm::Twofish => "twofish",
        SymmetricAlgorithm::Camellia128 => "camellia-128",
        SymmetricAlgorithm::Camellia192 => "camellia-192",
        SymmetricAlgorithm::Camellia256 => "camellia-256",
    }
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum IdentityTrustFfi {
    Unknown,
}

impl From<IdentityTrust> for IdentityTrustFfi {
    fn from(value: IdentityTrust) -> Self {
        match value {
            IdentityTrust::Unknown => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct KeyValidityFfi {
    pub fingerprint: String,
    pub not_yet_valid: bool,
    pub expired: bool,
    pub revoked: bool,
    pub has_current_binding: bool,
    pub key_flags: KeyUsageSummary,
    pub expires_at: Option<u64>,
}

impl From<KeyValidity> for KeyValidityFfi {
    fn from(value: KeyValidity) -> Self {
        Self {
            fingerprint: value.fingerprint.to_string(),
            not_yet_valid: value.not_yet_valid,
            expired: value.expired,
            revoked: value.revoked,
            has_current_binding: value.has_current_binding,
            key_flags: value.key_flags.into(),
            expires_at: value.expires_at,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SignatureVerificationFfi {
    pub status: VerificationStatusFfi,
    pub cryptographically_valid: Option<bool>,
    pub capability_rejected: bool,
    pub certificate_fingerprint: Option<String>,
    pub signer_fingerprint: Option<String>,
    pub signer_key_id: Option<String>,
    pub algorithm: Option<AlgorithmSummary>,
    pub hash_algorithm: Option<String>,
    pub legacy_decision: LegacyPolicyDecisionFfi,
    pub created_at: Option<u64>,
    pub key_validity: Option<KeyValidityFfi>,
    pub trust: IdentityTrustFfi,
}

impl From<SignatureVerification> for SignatureVerificationFfi {
    fn from(value: SignatureVerification) -> Self {
        Self {
            status: value.status.into(),
            cryptographically_valid: value.cryptographically_valid,
            capability_rejected: value.capability_rejected,
            certificate_fingerprint: value
                .certificate_fingerprint
                .map(|fingerprint| fingerprint.to_string()),
            signer_fingerprint: value
                .signer_fingerprint
                .map(|fingerprint| fingerprint.to_string()),
            signer_key_id: value.signer_key_id,
            algorithm: value.algorithm.map(Into::into),
            hash_algorithm: value
                .hash_algorithm
                .map(|algorithm| hash_algorithm_identifier(algorithm).to_owned()),
            legacy_decision: value.legacy_decision.into(),
            created_at: value.created_at,
            key_validity: value.key_validity.map(Into::into),
            trust: value.trust.into(),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct VerificationOutcomeFfi {
    pub status: VerificationStatusFfi,
    pub signatures: Vec<SignatureVerificationFfi>,
}

impl From<VerificationOutcome> for VerificationOutcomeFfi {
    fn from(value: VerificationOutcome) -> Self {
        Self {
            status: value.status.into(),
            signatures: value.signatures.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct VerificationResultFfi {
    pub outcome: VerificationOutcomeFfi,
    pub plaintext: Option<Vec<u8>>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct CleartextVerificationFfi {
    pub outcome: VerificationOutcomeFfi,
    pub text: Option<String>,
}

impl From<CleartextVerification> for CleartextVerificationFfi {
    fn from(value: CleartextVerification) -> Self {
        Self {
            outcome: value.outcome.into(),
            text: value.text,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DecryptionStatusFfi {
    Unsigned,
    Valid,
    Invalid,
    UnknownSigner,
    DecryptionFailed,
    IntegrityFailed,
}

impl From<DecryptionStatus> for DecryptionStatusFfi {
    fn from(value: DecryptionStatus) -> Self {
        match value {
            DecryptionStatus::Unsigned => Self::Unsigned,
            DecryptionStatus::Valid => Self::Valid,
            DecryptionStatus::Invalid => Self::Invalid,
            DecryptionStatus::UnknownSigner => Self::UnknownSigner,
            DecryptionStatus::DecryptionFailed => Self::DecryptionFailed,
            DecryptionStatus::IntegrityFailed => Self::IntegrityFailed,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct DecryptionReportFfi {
    pub status: DecryptionStatusFfi,
    pub signatures: Vec<SignatureVerificationFfi>,
    pub trust: IdentityTrustFfi,
    pub symmetric_algorithm: Option<String>,
    pub legacy_decision: LegacyPolicyDecisionFfi,
    pub detail: Option<String>,
    pub may_commit_staging: bool,
}

impl From<DecryptionReport> for DecryptionReportFfi {
    fn from(value: DecryptionReport) -> Self {
        Self {
            may_commit_staging: value.may_commit_staging(),
            status: value.status.into(),
            signatures: value.signatures.into_iter().map(Into::into).collect(),
            trust: value.trust.into(),
            symmetric_algorithm: value
                .symmetric_algorithm
                .map(|algorithm| symmetric_algorithm_identifier(algorithm).to_owned()),
            legacy_decision: value.legacy_decision.into(),
            detail: value.detail,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct DecryptedMessageFfi {
    pub report: DecryptionReportFfi,
    pub plaintext: Option<Vec<u8>>,
}

impl From<CoreDecryptedMessage> for DecryptedMessageFfi {
    fn from(value: CoreDecryptedMessage) -> Self {
        Self {
            report: value.report.into(),
            plaintext: value.plaintext,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct DecryptedTextFfi {
    pub report: DecryptionReportFfi,
    pub text: Option<String>,
}

impl From<DecryptedText> for DecryptedTextFfi {
    fn from(value: DecryptedText) -> Self {
        Self {
            report: value.report.into(),
            text: value.text,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SignEncryptRequestFfi {
    pub signing_key: String,
    pub password: String,
    pub recipients: Vec<String>,
    pub at_unix_seconds: u64,
    pub config: EncryptionConfigFfi,
    pub data: Vec<u8>,
    pub format: MessageFormatFfi,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SignEncryptTextRequestFfi {
    pub signing_key: String,
    pub password: String,
    pub recipients: Vec<String>,
    pub at_unix_seconds: u64,
    pub config: EncryptionConfigFfi,
    pub text: String,
    pub format: MessageFormatFfi,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_policy_mapping_preserves_structured_decisions_and_commit_rules() {
        let signature = SignatureVerification {
            status: VerificationStatus::Invalid,
            cryptographically_valid: Some(true),
            capability_rejected: false,
            certificate_fingerprint: None,
            signer_fingerprint: None,
            signer_key_id: None,
            algorithm: None,
            hash_algorithm: Some(HashAlgorithm::Md5),
            legacy_decision: LegacyPolicyDecision {
                disposition: LegacyDisposition::Reject,
                warning: Some(LegacyAlgorithmWarning::WeakSignatureHash(
                    HashAlgorithm::Md5,
                )),
            },
            created_at: None,
            key_validity: None,
            trust: IdentityTrust::Unknown,
        };
        let report = DecryptionReportFfi::from(DecryptionReport {
            status: DecryptionStatus::Invalid,
            signatures: vec![signature],
            trust: IdentityTrust::Unknown,
            symmetric_algorithm: Some(SymmetricAlgorithm::Cast5),
            legacy_decision: LegacyPolicyDecision {
                disposition: LegacyDisposition::AllowWithWarning,
                warning: Some(LegacyAlgorithmWarning::LegacySymmetricCipher(
                    SymmetricAlgorithm::Cast5,
                )),
            },
            detail: None,
        });
        assert!(!report.may_commit_staging);
        assert_eq!(report.symmetric_algorithm.as_deref(), Some("cast5"));
        assert_eq!(
            report.legacy_decision.disposition,
            LegacyDispositionFfi::AllowWithWarning
        );
        assert_eq!(
            report.legacy_decision.warning,
            Some(LegacyAlgorithmWarningFfi {
                kind: LegacyWarningKindFfi::LegacySymmetricCipher,
                algorithm: "cast5".to_owned(),
            })
        );
        assert_eq!(report.signatures[0].hash_algorithm.as_deref(), Some("md5"));
        assert_eq!(
            report.signatures[0].legacy_decision.disposition,
            LegacyDispositionFfi::Reject
        );
        assert_eq!(
            report.signatures[0].legacy_decision.warning,
            Some(LegacyAlgorithmWarningFfi {
                kind: LegacyWarningKindFfi::WeakSignatureHash,
                algorithm: "md5".to_owned(),
            })
        );
    }
}
