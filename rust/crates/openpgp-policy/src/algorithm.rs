use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Algorithm {
    #[serde(rename = "rsa-2048")]
    Rsa2048,
    #[serde(rename = "rsa-3072")]
    Rsa3072,
    #[serde(rename = "rsa-4096")]
    Rsa4096,
    #[serde(rename = "ed25519")]
    Ed25519,
    #[serde(rename = "x25519")]
    X25519,
    #[serde(rename = "ed448")]
    Ed448,
    #[serde(rename = "x448")]
    X448,
    #[serde(rename = "nist-p256-ecdsa")]
    NistP256Ecdsa,
    #[serde(rename = "nist-p256-ecdh")]
    NistP256Ecdh,
    #[serde(rename = "nist-p384-ecdsa")]
    NistP384Ecdsa,
    #[serde(rename = "nist-p384-ecdh")]
    NistP384Ecdh,
    #[serde(rename = "nist-p521-ecdsa")]
    NistP521Ecdsa,
    #[serde(rename = "nist-p521-ecdh")]
    NistP521Ecdh,
    #[serde(rename = "brainpool-p256-ecdsa")]
    BrainpoolP256Ecdsa,
    #[serde(rename = "brainpool-p256-ecdh")]
    BrainpoolP256Ecdh,
    #[serde(rename = "brainpool-p384-ecdsa")]
    BrainpoolP384Ecdsa,
    #[serde(rename = "brainpool-p384-ecdh")]
    BrainpoolP384Ecdh,
    #[serde(rename = "brainpool-p512-ecdsa")]
    BrainpoolP512Ecdsa,
    #[serde(rename = "brainpool-p512-ecdh")]
    BrainpoolP512Ecdh,
    #[serde(rename = "legacy-ed25519")]
    LegacyEd25519,
    #[serde(rename = "legacy-curve25519-ecdh")]
    LegacyCurve25519Ecdh,
    #[serde(rename = "dsa")]
    Dsa,
    #[serde(rename = "elgamal")]
    ElGamal,
}

impl Algorithm {
    pub const ALL: [Self; 23] = [
        Self::Rsa2048,
        Self::Rsa3072,
        Self::Rsa4096,
        Self::Ed25519,
        Self::X25519,
        Self::Ed448,
        Self::X448,
        Self::NistP256Ecdsa,
        Self::NistP256Ecdh,
        Self::NistP384Ecdsa,
        Self::NistP384Ecdh,
        Self::NistP521Ecdsa,
        Self::NistP521Ecdh,
        Self::BrainpoolP256Ecdsa,
        Self::BrainpoolP256Ecdh,
        Self::BrainpoolP384Ecdsa,
        Self::BrainpoolP384Ecdh,
        Self::BrainpoolP512Ecdsa,
        Self::BrainpoolP512Ecdh,
        Self::LegacyEd25519,
        Self::LegacyCurve25519Ecdh,
        Self::Dsa,
        Self::ElGamal,
    ];

    /// Versions accepted for existing-key policy evaluation, not a support claim.
    pub const fn usage_key_versions(self) -> &'static [KeyVersion] {
        match self {
            Self::LegacyEd25519 | Self::LegacyCurve25519Ecdh | Self::Dsa | Self::ElGamal => {
                &[KeyVersion::V4]
            }
            _ => &[KeyVersion::V4, KeyVersion::V6],
        }
    }

    /// Versions permitted for new software keys by policy, before evidence gates.
    pub const fn generation_key_versions(self) -> &'static [KeyVersion] {
        match self {
            Self::Rsa2048
            | Self::Rsa3072
            | Self::Rsa4096
            | Self::NistP256Ecdsa
            | Self::NistP256Ecdh
            | Self::NistP384Ecdsa
            | Self::NistP384Ecdh
            | Self::NistP521Ecdsa
            | Self::NistP521Ecdh
            | Self::LegacyEd25519
            | Self::LegacyCurve25519Ecdh => &[KeyVersion::V4],
            Self::Ed25519 | Self::X25519 | Self::Ed448 | Self::X448 => &[KeyVersion::V6],
            Self::BrainpoolP256Ecdsa
            | Self::BrainpoolP256Ecdh
            | Self::BrainpoolP384Ecdsa
            | Self::BrainpoolP384Ecdh
            | Self::BrainpoolP512Ecdsa
            | Self::BrainpoolP512Ecdh
            | Self::Dsa
            | Self::ElGamal => &[],
        }
    }

    pub const fn is_rsa(self) -> bool {
        matches!(self, Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096)
    }

    pub const fn is_legacy_curve25519(self) -> bool {
        matches!(self, Self::LegacyEd25519 | Self::LegacyCurve25519Ecdh)
    }

    pub const fn is_deprecated(self) -> bool {
        matches!(
            self,
            Self::LegacyEd25519 | Self::LegacyCurve25519Ecdh | Self::Dsa | Self::ElGamal
        )
    }

    pub const fn is_generation_deprecated(self) -> bool {
        self.is_rsa() || self.is_deprecated()
    }

    pub const fn requires_compatibility_acknowledgement(self) -> bool {
        self.is_rsa() || self.is_legacy_curve25519()
    }

    pub const fn supports_role(self, role: KeyRole) -> bool {
        match role {
            KeyRole::Primary | KeyRole::SigningSubkey => self.is_signing_algorithm(),
            KeyRole::EncryptionSubkey => self.is_encryption_algorithm(),
        }
    }

    pub(crate) const fn is_signing_algorithm(self) -> bool {
        matches!(
            self,
            Self::Rsa2048
                | Self::Rsa3072
                | Self::Rsa4096
                | Self::Ed25519
                | Self::Ed448
                | Self::NistP256Ecdsa
                | Self::NistP384Ecdsa
                | Self::NistP521Ecdsa
                | Self::BrainpoolP256Ecdsa
                | Self::BrainpoolP384Ecdsa
                | Self::BrainpoolP512Ecdsa
                | Self::LegacyEd25519
                | Self::Dsa
        )
    }

    pub(crate) const fn is_encryption_algorithm(self) -> bool {
        matches!(
            self,
            Self::Rsa2048
                | Self::Rsa3072
                | Self::Rsa4096
                | Self::X25519
                | Self::X448
                | Self::NistP256Ecdh
                | Self::NistP384Ecdh
                | Self::NistP521Ecdh
                | Self::BrainpoolP256Ecdh
                | Self::BrainpoolP384Ecdh
                | Self::BrainpoolP512Ecdh
                | Self::LegacyCurve25519Ecdh
                | Self::ElGamal
        )
    }

    pub const fn is_brainpool(self) -> bool {
        matches!(
            self,
            Self::BrainpoolP256Ecdsa
                | Self::BrainpoolP256Ecdh
                | Self::BrainpoolP384Ecdsa
                | Self::BrainpoolP384Ecdh
                | Self::BrainpoolP512Ecdsa
                | Self::BrainpoolP512Ecdh
        )
    }

    pub(crate) const fn is_recommended_algorithm(self) -> bool {
        matches!(
            self,
            Self::Ed25519 | Self::X25519 | Self::Ed448 | Self::X448
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Backend {
    #[serde(rename = "software")]
    Software,
    #[serde(rename = "secure-enclave")]
    SecureEnclave,
    #[serde(rename = "openpgp-card")]
    OpenPgpCard,
}

impl Backend {
    pub const ALL: [Self; 3] = [Self::Software, Self::SecureEnclave, Self::OpenPgpCard];

    pub const fn is_hardware(self) -> bool {
        matches!(self, Self::SecureEnclave | Self::OpenPgpCard)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum KeyVersion {
    #[serde(rename = "v4")]
    V4,
    #[serde(rename = "v6")]
    V6,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Operation {
    Generate,
    Import,
    ExportPublic,
    ExportPrivate,
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    UseAsPrimaryKey,
    UseAsSigningSubkey,
    UseAsEncryptionSubkey,
}

impl Operation {
    pub const ALL: [Self; 11] = [
        Self::Generate,
        Self::Import,
        Self::ExportPublic,
        Self::ExportPrivate,
        Self::Sign,
        Self::Verify,
        Self::Encrypt,
        Self::Decrypt,
        Self::UseAsPrimaryKey,
        Self::UseAsSigningSubkey,
        Self::UseAsEncryptionSubkey,
    ];
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyRole {
    Primary,
    SigningSubkey,
    EncryptionSubkey,
}
