use openpgp_core::{
    AlgorithmMetadata, BindingValidity, CertificateMetadata, CurveMetadata, ExportFormat,
    GeneratedKey, ImportOutcome, ImportResult, KeyMetadata, KeyStorage, KeyUsageFlags, KeyVersion,
    PrivateExportPolicy, RevocationMetadata, UserIdMetadata,
};
use openpgp_policy::{Algorithm, CompatibilityAcknowledgement, GenerationProfile};

#[derive(Clone, Debug, uniffi::Record)]
pub struct CurveSummary {
    pub name: String,
    pub oid: String,
    pub bit_size: Option<u32>,
}

impl From<CurveMetadata> for CurveSummary {
    fn from(value: CurveMetadata) -> Self {
        Self {
            name: value.name,
            oid: value.oid,
            bit_size: value.bit_size,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AlgorithmSummary {
    pub id: u8,
    pub name: String,
    pub policy_algorithm: Option<String>,
    pub bit_size: Option<u32>,
    pub curve: Option<CurveSummary>,
}

impl From<AlgorithmMetadata> for AlgorithmSummary {
    fn from(value: AlgorithmMetadata) -> Self {
        Self {
            id: value.id,
            name: value.name,
            policy_algorithm: value.policy_algorithm.map(policy_algorithm_id),
            bit_size: value.bit_size,
            curve: value.curve.map(CurveSummary::from),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct KeyUsageSummary {
    pub certify: bool,
    pub sign: bool,
    pub encrypt_communications: bool,
    pub encrypt_storage: bool,
    pub authentication: bool,
    pub shared: bool,
    pub group: bool,
    pub timestamping: bool,
    pub additional_decryption_subkey: bool,
    pub encoded: Vec<u8>,
}

impl From<KeyUsageFlags> for KeyUsageSummary {
    fn from(value: KeyUsageFlags) -> Self {
        Self {
            certify: value.certify,
            sign: value.sign,
            encrypt_communications: value.encrypt_communications,
            encrypt_storage: value.encrypt_storage,
            authentication: value.authentication,
            shared: value.shared,
            group: value.group,
            timestamping: value.timestamping,
            additional_decryption_subkey: value.additional_decryption_subkey,
            encoded: value.encoded,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RevocationSummary {
    pub reason_code: Option<u8>,
    pub reason: Option<Vec<u8>>,
}

impl From<RevocationMetadata> for RevocationSummary {
    fn from(value: RevocationMetadata) -> Self {
        Self {
            reason_code: value.reason_code,
            reason: value.reason,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum KeyStorageFfi {
    PublicOnly,
    SoftwareSecret,
}

impl From<KeyStorage> for KeyStorageFfi {
    fn from(value: KeyStorage) -> Self {
        match value {
            KeyStorage::PublicOnly => Self::PublicOnly,
            KeyStorage::SoftwareSecret => Self::SoftwareSecret,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum ExportPolicyFfi {
    Allowed,
    Disabled,
    NotApplicable,
}

impl From<PrivateExportPolicy> for ExportPolicyFfi {
    fn from(value: PrivateExportPolicy) -> Self {
        match value {
            PrivateExportPolicy::Allowed => Self::Allowed,
            PrivateExportPolicy::Disabled => Self::Disabled,
        }
    }
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum KeyVersionFfi {
    V2,
    V3,
    V4,
    V5,
    V6,
    Other(u8),
}

impl From<KeyVersion> for KeyVersionFfi {
    fn from(value: KeyVersion) -> Self {
        match value {
            KeyVersion::V2 => Self::V2,
            KeyVersion::V3 => Self::V3,
            KeyVersion::V4 => Self::V4,
            KeyVersion::V5 => Self::V5,
            KeyVersion::V6 => Self::V6,
            KeyVersion::Other(version) => Self::Other(version),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct KeyMetadataSummary {
    pub fingerprint: String,
    pub key_id: String,
    pub key_version: KeyVersionFfi,
    pub algorithm: AlgorithmSummary,
    pub key_flags: KeyUsageSummary,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub revocations: Vec<RevocationSummary>,
    pub storage: KeyStorageFfi,
}

impl From<KeyMetadata> for KeyMetadataSummary {
    fn from(value: KeyMetadata) -> Self {
        Self {
            fingerprint: value.fingerprint.to_string(),
            key_id: value.key_id,
            key_version: value.key_version.into(),
            algorithm: value.algorithm.into(),
            key_flags: value.key_flags.into(),
            created_at: value.created_at,
            expires_at: value.expires_at,
            revocations: value.revocations.into_iter().map(Into::into).collect(),
            storage: value.storage.into(),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct UserIdSummary {
    pub raw: Vec<u8>,
    pub utf8: Option<String>,
    pub is_primary: bool,
    pub revocations: Vec<RevocationSummary>,
}

impl From<UserIdMetadata> for UserIdSummary {
    fn from(value: UserIdMetadata) -> Self {
        Self {
            raw: value.raw,
            utf8: value.utf8,
            is_primary: value.is_primary,
            revocations: value.revocations.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct CertificateSummary {
    pub fingerprint: String,
    pub key_id: String,
    pub key_version: KeyVersionFfi,
    pub user_ids: Vec<UserIdSummary>,
    pub primary: KeyMetadataSummary,
    pub subkeys: Vec<KeyMetadataSummary>,
    pub storage: KeyStorageFfi,
    pub private_export_policy: ExportPolicyFfi,
    pub binding_verified: bool,
}

impl From<CertificateMetadata> for CertificateSummary {
    fn from(value: CertificateMetadata) -> Self {
        Self {
            fingerprint: value.fingerprint.to_string(),
            key_id: value.key_id,
            key_version: value.key_version.into(),
            user_ids: value.user_ids.into_iter().map(Into::into).collect(),
            primary: value.primary.into(),
            subkeys: value.subkeys.into_iter().map(Into::into).collect(),
            storage: value.storage.into(),
            private_export_policy: value
                .private_export_policy
                .map(Into::into)
                .unwrap_or(ExportPolicyFfi::NotApplicable),
            binding_verified: matches!(value.binding_validity, BindingValidity::Verified),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GeneratedKeyFfi {
    pub summary: CertificateSummary,
    pub public_certificate: Vec<u8>,
}

impl From<GeneratedKey> for GeneratedKeyFfi {
    fn from(value: GeneratedKey) -> Self {
        Self {
            summary: value.metadata.into(),
            public_certificate: value.public_certificate,
        }
    }
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum ImportOutcomeFfi {
    Inserted,
    Duplicate,
    UpgradedToSecret,
}

impl From<ImportOutcome> for ImportOutcomeFfi {
    fn from(value: ImportOutcome) -> Self {
        match value {
            ImportOutcome::Inserted => Self::Inserted,
            ImportOutcome::Duplicate => Self::Duplicate,
            ImportOutcome::UpgradedToSecret => Self::UpgradedToSecret,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportResultFfi {
    pub summary: CertificateSummary,
    pub outcome: ImportOutcomeFfi,
}

impl From<ImportResult> for ImportResultFfi {
    fn from(value: ImportResult) -> Self {
        Self {
            summary: value.metadata.into(),
            outcome: value.outcome.into(),
        }
    }
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum GenerationProfileFfi {
    ModernV6,
    Curve448V6,
    LegacyCurve25519V4,
    NistP256V4,
    NistP384V4,
    NistP521V4,
    Rsa2048V4,
    Rsa3072V4,
    Rsa4096V4,
}

impl GenerationProfileFfi {
    pub(crate) fn into_profile(self) -> Result<GenerationProfile, openpgp_policy::ProfileError> {
        Ok(match self {
            Self::ModernV6 => GenerationProfile::modern_v6(),
            Self::Curve448V6 => GenerationProfile::curve448_v6(),
            Self::LegacyCurve25519V4 => GenerationProfile::legacy_curve25519_v4(
                CompatibilityAcknowledgement::acknowledged(),
            )?,
            Self::NistP256V4 => GenerationProfile::nist_p256_v4(),
            Self::NistP384V4 => GenerationProfile::nist_p384_v4(),
            Self::NistP521V4 => GenerationProfile::nist_p521_v4(),
            Self::Rsa2048V4 => GenerationProfile::legacy_rsa_v4(
                Algorithm::Rsa2048,
                CompatibilityAcknowledgement::acknowledged(),
            )?,
            Self::Rsa3072V4 => GenerationProfile::legacy_rsa_v4(
                Algorithm::Rsa3072,
                CompatibilityAcknowledgement::acknowledged(),
            )?,
            Self::Rsa4096V4 => GenerationProfile::legacy_rsa_v4(
                Algorithm::Rsa4096,
                CompatibilityAcknowledgement::acknowledged(),
            )?,
        })
    }
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum ExportFormatFfi {
    Binary,
    Armored,
}

impl From<ExportFormatFfi> for ExportFormat {
    fn from(value: ExportFormatFfi) -> Self {
        match value {
            ExportFormatFfi::Binary => Self::Binary,
            ExportFormatFfi::Armored => Self::Armored,
        }
    }
}

fn policy_algorithm_id(algorithm: Algorithm) -> String {
    match algorithm {
        Algorithm::Rsa2048 => "rsa-2048",
        Algorithm::Rsa3072 => "rsa-3072",
        Algorithm::Rsa4096 => "rsa-4096",
        Algorithm::Ed25519 => "ed25519",
        Algorithm::X25519 => "x25519",
        Algorithm::Ed448 => "ed448",
        Algorithm::X448 => "x448",
        Algorithm::NistP256Ecdsa => "nist-p256-ecdsa",
        Algorithm::NistP256Ecdh => "nist-p256-ecdh",
        Algorithm::NistP384Ecdsa => "nist-p384-ecdsa",
        Algorithm::NistP384Ecdh => "nist-p384-ecdh",
        Algorithm::NistP521Ecdsa => "nist-p521-ecdsa",
        Algorithm::NistP521Ecdh => "nist-p521-ecdh",
        Algorithm::BrainpoolP256Ecdsa => "brainpool-p256-ecdsa",
        Algorithm::BrainpoolP256Ecdh => "brainpool-p256-ecdh",
        Algorithm::BrainpoolP384Ecdsa => "brainpool-p384-ecdsa",
        Algorithm::BrainpoolP384Ecdh => "brainpool-p384-ecdh",
        Algorithm::BrainpoolP512Ecdsa => "brainpool-p512-ecdsa",
        Algorithm::BrainpoolP512Ecdh => "brainpool-p512-ecdh",
        Algorithm::LegacyEd25519 => "legacy-ed25519",
        Algorithm::LegacyCurve25519Ecdh => "legacy-curve25519-ecdh",
        Algorithm::Dsa => "dsa",
        Algorithm::ElGamal => "elgamal",
    }
    .to_owned()
}
