use std::{fmt, str::FromStr};

use openpgp_policy::Algorithm;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FullFingerprint(String);

impl FullFingerprint {
    pub fn from_hex(value: &str) -> Result<Self, FingerprintError> {
        if !matches!(value.len(), 32 | 40 | 64) {
            return Err(FingerprintError::InvalidLength(value.len()));
        }
        if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(FingerprintError::InvalidHex);
        }
        Ok(Self(value.to_ascii_uppercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => unreachable!("validated hexadecimal fingerprint"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    pub(crate) fn from_rpgp(value: &pgp::types::Fingerprint) -> Self {
        Self(format!("{value:X}"))
    }
}

impl fmt::Display for FullFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for FullFingerprint {
    type Err = FingerprintError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_hex(value)
    }
}

impl Serialize for FullFingerprint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for FullFingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum FingerprintError {
    #[error("a full fingerprint must contain 32, 40, or 64 hexadecimal characters, got {0}")]
    InvalidLength(usize),
    #[error("a fingerprint must contain only hexadecimal characters")]
    InvalidHex,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyVersion {
    V2,
    V3,
    V4,
    V5,
    V6,
    Other(u8),
}

impl From<pgp::types::KeyVersion> for KeyVersion {
    fn from(value: pgp::types::KeyVersion) -> Self {
        match value {
            pgp::types::KeyVersion::V2 => Self::V2,
            pgp::types::KeyVersion::V3 => Self::V3,
            pgp::types::KeyVersion::V4 => Self::V4,
            pgp::types::KeyVersion::V5 => Self::V5,
            pgp::types::KeyVersion::V6 => Self::V6,
            pgp::types::KeyVersion::Other(version) => Self::Other(version),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CurveMetadata {
    pub name: String,
    pub oid: String,
    pub bit_size: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmMetadata {
    pub id: u8,
    pub name: String,
    pub policy_algorithm: Option<Algorithm>,
    pub bit_size: Option<u32>,
    pub curve: Option<CurveMetadata>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyUsageFlags {
    pub certify: bool,
    pub sign: bool,
    pub encrypt_communications: bool,
    pub encrypt_storage: bool,
    pub authentication: bool,
    pub shared: bool,
    pub group: bool,
    pub timestamping: bool,
    pub additional_decryption_subkey: bool,
    pub forwarded_decryption: bool,
    pub encoded: Vec<u8>,
}

impl KeyUsageFlags {
    pub fn allows(&self, usage: KeyUsage) -> bool {
        match usage {
            KeyUsage::Certify => self.certify,
            KeyUsage::Sign => self.sign,
            KeyUsage::EncryptCommunication => self.encrypt_communications,
            KeyUsage::EncryptStorage => self.encrypt_storage,
            KeyUsage::Authenticate => self.authentication,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyUsage {
    Certify,
    Sign,
    EncryptCommunication,
    EncryptStorage,
    Authenticate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationMetadata {
    pub created_at: Option<u64>,
    pub reason_code: Option<u8>,
    pub reason: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserIdMetadata {
    pub raw: Vec<u8>,
    pub utf8: Option<String>,
    pub is_primary: bool,
    pub revocations: Vec<RevocationMetadata>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyStorage {
    PublicOnly,
    SoftwareSecret,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivateExportPolicy {
    Allowed,
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BindingValidity {
    Verified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyMetadata {
    pub fingerprint: FullFingerprint,
    pub key_id: String,
    pub key_version: KeyVersion,
    pub algorithm: AlgorithmMetadata,
    pub key_flags: KeyUsageFlags,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub revocations: Vec<RevocationMetadata>,
    pub storage: KeyStorage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateMetadata {
    pub fingerprint: FullFingerprint,
    pub key_id: String,
    pub key_version: KeyVersion,
    pub user_ids: Vec<UserIdMetadata>,
    pub primary: KeyMetadata,
    pub subkeys: Vec<KeyMetadata>,
    pub storage: KeyStorage,
    pub private_export_policy: Option<PrivateExportPolicy>,
    pub binding_validity: BindingValidity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyValidity {
    pub fingerprint: FullFingerprint,
    pub not_yet_valid: bool,
    pub expired: bool,
    pub revoked: bool,
    pub has_current_binding: bool,
    pub key_flags: KeyUsageFlags,
    pub expires_at: Option<u64>,
}

impl KeyValidity {
    pub const fn is_valid(&self) -> bool {
        !self.not_yet_valid && !self.expired && !self.revoked && self.has_current_binding
    }

    pub fn is_valid_for(&self, usage: KeyUsage) -> bool {
        self.is_valid() && self.key_flags.allows(usage)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserIdValidity {
    pub is_primary: bool,
    pub revoked: bool,
    pub has_current_certification: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateValidity {
    pub evaluated_at: u64,
    pub binding_validity: BindingValidity,
    pub primary: KeyValidity,
    pub subkeys: Vec<KeyValidity>,
    pub user_ids: Vec<UserIdValidity>,
}

impl CertificateValidity {
    pub fn subkey_is_valid(&self, index: usize) -> Option<bool> {
        self.subkeys
            .get(index)
            .map(|subkey| self.primary.is_valid() && subkey.is_valid())
    }

    pub fn user_id_is_valid(&self, index: usize) -> Option<bool> {
        self.user_ids
            .get(index)
            .map(|user| self.primary.is_valid() && !user.revoked && user.has_current_certification)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ExportFormat {
    Binary,
    Armored,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedKey {
    pub metadata: CertificateMetadata,
    pub public_certificate: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ImportOutcome {
    Inserted,
    Duplicate,
    UpgradedToSecret,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub metadata: CertificateMetadata,
    pub outcome: ImportOutcome,
}

/// A storage snapshot of one certificate. `protected_secret` contains the
/// original password-protected OpenPGP secret material; it is intended only for
/// sealed on-device storage, never as an alternative private-key export path.
#[derive(Clone)]
pub struct StorageRecord {
    pub fingerprint: FullFingerprint,
    pub protected_secret: Option<Vec<u8>>,
    pub public_certificate: Vec<u8>,
    pub export_policy: Option<PrivateExportPolicy>,
}

impl fmt::Debug for StorageRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageRecord")
            .field("fingerprint", &self.fingerprint)
            .field(
                "protected_secret",
                &self.protected_secret.as_ref().map(Vec::len),
            )
            .field("public_certificate", &self.public_certificate.len())
            .field("export_policy", &self.export_policy)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SecretComponent {
    Primary,
    Subkey(usize),
}

impl fmt::Display for SecretComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Primary => formatter.write_str("primary key"),
            Self::Subkey(index) => write!(formatter, "secret subkey {index}"),
        }
    }
}
