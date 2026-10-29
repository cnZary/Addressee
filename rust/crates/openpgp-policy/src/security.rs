use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum HashAlgorithm {
    #[serde(rename = "md5")]
    Md5,
    #[serde(rename = "sha1")]
    Sha1,
    #[serde(rename = "ripemd160")]
    Ripemd160,
    #[serde(rename = "sha224")]
    Sha224,
    #[serde(rename = "sha256")]
    Sha256,
    #[serde(rename = "sha384")]
    Sha384,
    #[serde(rename = "sha512")]
    Sha512,
    #[serde(rename = "sha3-256")]
    Sha3_256,
    #[serde(rename = "sha3-512")]
    Sha3_512,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SymmetricAlgorithm {
    #[serde(rename = "idea")]
    Idea,
    #[serde(rename = "triple-des")]
    TripleDes,
    #[serde(rename = "cast5")]
    Cast5,
    #[serde(rename = "blowfish")]
    Blowfish,
    #[serde(rename = "aes-128")]
    Aes128,
    #[serde(rename = "aes-192")]
    Aes192,
    #[serde(rename = "aes-256")]
    Aes256,
    #[serde(rename = "twofish")]
    Twofish,
    #[serde(rename = "camellia-128")]
    Camellia128,
    #[serde(rename = "camellia-192")]
    Camellia192,
    #[serde(rename = "camellia-256")]
    Camellia256,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LegacyDisposition {
    Allow,
    AllowWithWarning,
    Reject,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "algorithm", rename_all = "camelCase")]
pub enum LegacyAlgorithmWarning {
    WeakSignatureHash(HashAlgorithm),
    LegacySymmetricCipher(SymmetricAlgorithm),
}

/// A legacy-processing decision that is separate from cryptographic validity and identity trust.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyPolicyDecision {
    pub disposition: LegacyDisposition,
    pub warning: Option<LegacyAlgorithmWarning>,
}

impl Default for LegacyPolicyDecision {
    fn default() -> Self {
        Self {
            disposition: LegacyDisposition::Allow,
            warning: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityPolicy {
    pub default_signature_hash: HashAlgorithm,
    pub default_symmetric_algorithm: SymmetricAlgorithm,
    pub legacy_md5_verification: LegacyDisposition,
    pub legacy_sha1_verification: LegacyDisposition,
    pub legacy_idea_decryption: LegacyDisposition,
    pub legacy_triple_des_decryption: LegacyDisposition,
    pub legacy_cast5_decryption: LegacyDisposition,
    pub legacy_blowfish_decryption: LegacyDisposition,
}

impl SecurityPolicy {
    /// MD5 and SHA-1 are rejected for every new signature, regardless of legacy policy.
    pub const fn validate_new_signature(
        &self,
        algorithm: HashAlgorithm,
    ) -> Result<(), SecurityPolicyError> {
        match algorithm {
            HashAlgorithm::Md5 | HashAlgorithm::Sha1 => {
                Err(SecurityPolicyError::WeakSignatureHash { algorithm })
            }
            _ => Ok(()),
        }
    }

    /// Legacy ciphers are never selected or accepted for new encryption by this policy.
    pub const fn validate_new_encryption(
        &self,
        algorithm: SymmetricAlgorithm,
    ) -> Result<(), SecurityPolicyError> {
        match algorithm {
            SymmetricAlgorithm::Idea
            | SymmetricAlgorithm::TripleDes
            | SymmetricAlgorithm::Cast5
            | SymmetricAlgorithm::Blowfish => {
                Err(SecurityPolicyError::LegacySymmetricAlgorithm { algorithm })
            }
            _ => Ok(()),
        }
    }

    pub const fn legacy_verification(&self, algorithm: HashAlgorithm) -> LegacyPolicyDecision {
        match algorithm {
            HashAlgorithm::Md5 => LegacyPolicyDecision {
                disposition: self.legacy_md5_verification,
                warning: Some(LegacyAlgorithmWarning::WeakSignatureHash(algorithm)),
            },
            HashAlgorithm::Sha1 => LegacyPolicyDecision {
                disposition: self.legacy_sha1_verification,
                warning: Some(LegacyAlgorithmWarning::WeakSignatureHash(algorithm)),
            },
            _ => LegacyPolicyDecision {
                disposition: LegacyDisposition::Allow,
                warning: None,
            },
        }
    }

    pub const fn legacy_decryption(&self, algorithm: SymmetricAlgorithm) -> LegacyPolicyDecision {
        let disposition = match algorithm {
            SymmetricAlgorithm::Idea => self.legacy_idea_decryption,
            SymmetricAlgorithm::TripleDes => self.legacy_triple_des_decryption,
            SymmetricAlgorithm::Cast5 => self.legacy_cast5_decryption,
            SymmetricAlgorithm::Blowfish => self.legacy_blowfish_decryption,
            _ => {
                return LegacyPolicyDecision {
                    disposition: LegacyDisposition::Allow,
                    warning: None,
                };
            }
        };
        LegacyPolicyDecision {
            disposition,
            warning: Some(LegacyAlgorithmWarning::LegacySymmetricCipher(algorithm)),
        }
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            default_signature_hash: HashAlgorithm::Sha256,
            default_symmetric_algorithm: SymmetricAlgorithm::Aes256,
            legacy_md5_verification: LegacyDisposition::Reject,
            legacy_sha1_verification: LegacyDisposition::AllowWithWarning,
            legacy_idea_decryption: LegacyDisposition::AllowWithWarning,
            legacy_triple_des_decryption: LegacyDisposition::AllowWithWarning,
            legacy_cast5_decryption: LegacyDisposition::AllowWithWarning,
            legacy_blowfish_decryption: LegacyDisposition::AllowWithWarning,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SecurityPolicyError {
    #[error("{algorithm:?} is forbidden for new signatures")]
    WeakSignatureHash { algorithm: HashAlgorithm },
    #[error("{algorithm:?} is forbidden for new encryption")]
    LegacySymmetricAlgorithm { algorithm: SymmetricAlgorithm },
}
