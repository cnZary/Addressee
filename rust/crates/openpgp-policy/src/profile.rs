use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Algorithm, KeyRole, KeyVersion};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompatibilityAcknowledgement {
    acknowledged: bool,
}

impl CompatibilityAcknowledgement {
    pub const fn acknowledged() -> Self {
        Self { acknowledged: true }
    }

    pub const fn not_acknowledged() -> Self {
        Self {
            acknowledged: false,
        }
    }

    pub const fn is_acknowledged(self) -> bool {
        self.acknowledged
    }
}

impl Default for CompatibilityAcknowledgement {
    fn default() -> Self {
        Self::not_acknowledged()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenerationSpec {
    pub algorithm: Algorithm,
}

impl From<Algorithm> for KeyGenerationSpec {
    fn from(algorithm: Algorithm) -> Self {
        Self { algorithm }
    }
}

/// A software-key structure. Backend availability must be checked separately per operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerationProfile {
    pub key_version: KeyVersion,
    pub primary_key: KeyGenerationSpec,
    pub signing_subkey: KeyGenerationSpec,
    pub encryption_subkey: KeyGenerationSpec,
    pub compatibility_acknowledgement: CompatibilityAcknowledgement,
}

impl GenerationProfile {
    pub fn new(
        key_version: KeyVersion,
        primary_key: Algorithm,
        signing_subkey: Algorithm,
        encryption_subkey: Algorithm,
        compatibility_acknowledgement: CompatibilityAcknowledgement,
    ) -> Result<Self, ProfileError> {
        let profile = Self::from_algorithms(
            key_version,
            primary_key,
            signing_subkey,
            encryption_subkey,
            compatibility_acknowledgement,
        );
        profile.validate()?;
        Ok(profile)
    }

    pub fn modern_v6() -> Self {
        Self::from_algorithms(
            KeyVersion::V6,
            Algorithm::Ed25519,
            Algorithm::Ed25519,
            Algorithm::X25519,
            CompatibilityAcknowledgement::not_acknowledged(),
        )
    }

    pub fn curve448_v6() -> Self {
        Self::from_algorithms(
            KeyVersion::V6,
            Algorithm::Ed448,
            Algorithm::Ed448,
            Algorithm::X448,
            CompatibilityAcknowledgement::not_acknowledged(),
        )
    }

    pub fn legacy_curve25519_v4(
        acknowledgement: CompatibilityAcknowledgement,
    ) -> Result<Self, ProfileError> {
        Self::new(
            KeyVersion::V4,
            Algorithm::LegacyEd25519,
            Algorithm::LegacyEd25519,
            Algorithm::LegacyCurve25519Ecdh,
            acknowledgement,
        )
    }

    pub fn nist_p256_v4() -> Self {
        Self::nist_v4(Algorithm::NistP256Ecdsa, Algorithm::NistP256Ecdh)
    }

    pub fn nist_p384_v4() -> Self {
        Self::nist_v4(Algorithm::NistP384Ecdsa, Algorithm::NistP384Ecdh)
    }

    pub fn nist_p521_v4() -> Self {
        Self::nist_v4(Algorithm::NistP521Ecdsa, Algorithm::NistP521Ecdh)
    }

    /// Uses general-purpose RSA for all three roles; restricted RSA identifiers do not exist here.
    pub fn legacy_rsa_v4(
        algorithm: Algorithm,
        acknowledgement: CompatibilityAcknowledgement,
    ) -> Result<Self, ProfileError> {
        if !algorithm.is_rsa() {
            return Err(ProfileError::RsaAlgorithmRequired { algorithm });
        }
        Self::new(
            KeyVersion::V4,
            algorithm,
            algorithm,
            algorithm,
            acknowledgement,
        )
    }

    pub fn validate(&self) -> Result<(), ProfileError> {
        for (role, key) in self.keys() {
            let algorithm = key.algorithm;
            if !algorithm.supports_role(role) {
                return Err(ProfileError::InvalidKeyRole { algorithm, role });
            }
            if self.key_version == KeyVersion::V6 && algorithm.is_legacy_curve25519() {
                return Err(ProfileError::LegacyIdentifierInV6 { algorithm });
            }
            if self.key_version == KeyVersion::V6 && algorithm.is_rsa() {
                return Err(ProfileError::RsaV6Generation { algorithm });
            }
            if !algorithm
                .generation_key_versions()
                .contains(&self.key_version)
            {
                if algorithm.generation_key_versions().is_empty() {
                    return Err(ProfileError::GenerationNotAllowed { algorithm });
                }
                return Err(ProfileError::UnsupportedKeyVersion {
                    algorithm,
                    key_version: self.key_version,
                });
            }
        }

        if !self.compatibility_acknowledgement.is_acknowledged() {
            let mut algorithms = Vec::new();
            for (_, key) in self.keys() {
                let algorithm = key.algorithm;
                if algorithm.requires_compatibility_acknowledgement()
                    && !algorithms.contains(&algorithm)
                {
                    algorithms.push(algorithm);
                }
            }
            if !algorithms.is_empty() {
                return Err(ProfileError::CompatibilityAcknowledgementRequired { algorithms });
            }
        }
        Ok(())
    }

    fn nist_v4(signing: Algorithm, encryption: Algorithm) -> Self {
        Self::from_algorithms(
            KeyVersion::V4,
            signing,
            signing,
            encryption,
            CompatibilityAcknowledgement::not_acknowledged(),
        )
    }

    fn from_algorithms(
        key_version: KeyVersion,
        primary_key: Algorithm,
        signing_subkey: Algorithm,
        encryption_subkey: Algorithm,
        compatibility_acknowledgement: CompatibilityAcknowledgement,
    ) -> Self {
        Self {
            key_version,
            primary_key: primary_key.into(),
            signing_subkey: signing_subkey.into(),
            encryption_subkey: encryption_subkey.into(),
            compatibility_acknowledgement,
        }
    }

    fn keys(&self) -> [(KeyRole, &KeyGenerationSpec); 3] {
        [
            (KeyRole::Primary, &self.primary_key),
            (KeyRole::SigningSubkey, &self.signing_subkey),
            (KeyRole::EncryptionSubkey, &self.encryption_subkey),
        ]
    }
}

impl Default for GenerationProfile {
    fn default() -> Self {
        Self::modern_v6()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProfileError {
    #[error("{algorithm:?} cannot be used as {role:?}")]
    InvalidKeyRole { algorithm: Algorithm, role: KeyRole },
    #[error("{algorithm:?} generation is not allowed by policy")]
    GenerationNotAllowed { algorithm: Algorithm },
    #[error("{algorithm:?} generation does not allow {key_version:?} keys")]
    UnsupportedKeyVersion {
        algorithm: Algorithm,
        key_version: KeyVersion,
    },
    #[error("legacy Curve25519 identifier {algorithm:?} is forbidden in v6 keys")]
    LegacyIdentifierInV6 { algorithm: Algorithm },
    #[error("RSA v6 generation is forbidden by policy: {algorithm:?}")]
    RsaV6Generation { algorithm: Algorithm },
    #[error("explicit compatibility acknowledgement is required for {algorithms:?}")]
    CompatibilityAcknowledgementRequired { algorithms: Vec<Algorithm> },
    #[error("the RSA profile requires a general-purpose RSA algorithm, not {algorithm:?}")]
    RsaAlgorithmRequired { algorithm: Algorithm },
}
