use std::{collections::BTreeMap, fmt};

use openpgp_policy::{Algorithm, GenerationProfile};
use pgp::{
    composed::{
        ArmorOptions, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey,
        SignedSecretKey, SubkeyParamsBuilder,
    },
    crypto::ecc_curve::ECCCurve,
    ser::Serialize as _,
    types::{KeyDetails as _, S2kParams},
};

use crate::{
    CertificateMetadata, CertificateValidity, ExportFormat, FullFingerprint, GeneratedKey,
    ImportOutcome, ImportResult, KeyError, KeyStorage, PrivateExportPolicy, StorageRecord, import,
    metadata,
};

#[derive(Default)]
pub struct SoftwareKeyStore {
    records: BTreeMap<FullFingerprint, KeyRecord>,
}

impl SoftwareKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn contains(&self, fingerprint: &FullFingerprint) -> bool {
        self.records.contains_key(fingerprint)
    }

    pub fn generate(
        &mut self,
        profile: &GenerationProfile,
        user_id: &str,
        protection_password: &str,
        export_policy: PrivateExportPolicy,
    ) -> Result<GeneratedKey, KeyError> {
        profile.validate()?;
        if user_id.is_empty() {
            return Err(KeyError::EmptyUserId);
        }
        if protection_password.is_empty() {
            return Err(KeyError::EmptyPassword);
        }

        let version = match profile.key_version {
            openpgp_policy::KeyVersion::V4 => pgp::types::KeyVersion::V4,
            openpgp_policy::KeyVersion::V6 => pgp::types::KeyVersion::V6,
        };
        let primary_type = generation_key_type(profile.primary_key.algorithm)?;
        let signing_type = generation_key_type(profile.signing_subkey.algorithm)?;
        let encryption_type = generation_key_type(profile.encryption_subkey.algorithm)?;
        let mut rng = rand::thread_rng();
        let primary_s2k = S2kParams::new_default(&mut rng, version);
        let signing_s2k = S2kParams::new_default(&mut rng, version);
        let encryption_s2k = S2kParams::new_default(&mut rng, version);

        let signing = SubkeyParamsBuilder::default()
            .version(version)
            .key_type(signing_type)
            .can_sign(true)
            .passphrase(Some(protection_password.to_owned()))
            .s2k(Some(signing_s2k))
            .build()
            .map_err(|error| KeyError::InvalidParameters(error.to_string()))?;
        let encryption = SubkeyParamsBuilder::default()
            .version(version)
            .key_type(encryption_type)
            .can_encrypt(EncryptionCaps::All)
            .passphrase(Some(protection_password.to_owned()))
            .s2k(Some(encryption_s2k))
            .build()
            .map_err(|error| KeyError::InvalidParameters(error.to_string()))?;
        let params = SecretKeyParamsBuilder::default()
            .version(version)
            .key_type(primary_type)
            .can_certify(true)
            .can_sign(false)
            .primary_user_id(user_id.to_owned())
            .feature_seipd_v2(version == pgp::types::KeyVersion::V6)
            .passphrase(Some(protection_password.to_owned()))
            .s2k(Some(primary_s2k))
            .subkeys(vec![signing, encryption])
            .build()
            .map_err(|error| KeyError::InvalidParameters(error.to_string()))?;
        let mut secret = params.generate(&mut rng)?;
        if profile.primary_key.algorithm.is_rsa() {
            import::reprotect(&mut secret, Some(protection_password), protection_password)?;
        }
        secret.verify_bindings()?;
        let public = secret.to_public_key();
        public.verify_bindings()?;
        import::ensure_exportable(&secret)?;

        let fingerprint = FullFingerprint::from_rpgp(&public.fingerprint());
        if self.records.contains_key(&fingerprint) {
            return Err(KeyError::ConflictingCertificate { fingerprint });
        }
        let record = KeyRecord::from_secret(secret, export_policy);
        let metadata = record.metadata()?;
        let public_certificate = record.public.to_bytes()?;
        self.records.insert(fingerprint, record);
        Ok(GeneratedKey {
            metadata,
            public_certificate,
        })
    }

    pub fn import_public(&mut self, input: &[u8]) -> Result<ImportResult, KeyError> {
        let certificate = import::parse_public(input)?;
        let fingerprint = FullFingerprint::from_rpgp(&certificate.fingerprint());
        if let Some(existing) = self.records.get(&fingerprint) {
            if existing.public != certificate {
                return Err(KeyError::ConflictingCertificate { fingerprint });
            }
            return Ok(ImportResult {
                metadata: existing.metadata()?,
                outcome: ImportOutcome::Duplicate,
            });
        }

        let record = KeyRecord::from_public(certificate);
        let metadata = record.metadata()?;
        self.records.insert(fingerprint, record);
        Ok(ImportResult {
            metadata,
            outcome: ImportOutcome::Inserted,
        })
    }

    pub fn import_private(
        &mut self,
        input: &[u8],
        current_password: Option<&str>,
        new_protection_password: &str,
        export_policy: PrivateExportPolicy,
    ) -> Result<ImportResult, KeyError> {
        let secret = import::parse_secret(input, current_password, new_protection_password)?;
        let public = secret.to_public_key();
        let fingerprint = FullFingerprint::from_rpgp(&public.fingerprint());

        if let Some(existing) = self.records.get(&fingerprint)
            && existing.secret.is_some()
        {
            if existing.public != public || !same_secret_coverage(existing.secret.as_ref(), &secret)
            {
                return Err(KeyError::ConflictingCertificate { fingerprint });
            }
            return Ok(ImportResult {
                metadata: existing.metadata()?,
                outcome: ImportOutcome::Duplicate,
            });
        }

        let outcome = if self.records.contains_key(&fingerprint) {
            ImportOutcome::UpgradedToSecret
        } else {
            ImportOutcome::Inserted
        };
        let record = KeyRecord::from_secret(secret, export_policy);
        let metadata = record.metadata()?;
        self.records.insert(fingerprint, record);
        Ok(ImportResult { metadata, outcome })
    }

    pub fn metadata(&self, fingerprint: &FullFingerprint) -> Result<CertificateMetadata, KeyError> {
        self.record(fingerprint)?.metadata()
    }

    pub fn list_metadata(&self) -> Result<Vec<CertificateMetadata>, KeyError> {
        self.records
            .values()
            .map(KeyRecord::metadata)
            .collect::<Result<Vec<_>, _>>()
    }

    pub fn evaluate_validity(
        &self,
        fingerprint: &FullFingerprint,
        at_unix_seconds: u64,
    ) -> Result<CertificateValidity, KeyError> {
        metadata::certificate_validity(&self.record(fingerprint)?.public, at_unix_seconds)
    }

    pub fn export_public(
        &self,
        fingerprint: &FullFingerprint,
        format: ExportFormat,
    ) -> Result<Vec<u8>, KeyError> {
        let certificate = &self.record(fingerprint)?.public;
        match format {
            ExportFormat::Binary => Ok(certificate.to_bytes()?),
            ExportFormat::Armored => {
                Ok(certificate.to_armored_bytes(armor_options(certificate.version()))?)
            }
        }
    }

    pub fn export_private(
        &self,
        fingerprint: &FullFingerprint,
        format: ExportFormat,
    ) -> Result<Vec<u8>, KeyError> {
        let record = self.record(fingerprint)?;
        let secret = record
            .secret
            .as_ref()
            .ok_or_else(|| KeyError::SecretKeyRequired {
                fingerprint: fingerprint.clone(),
            })?;
        if record.export_policy != Some(PrivateExportPolicy::Allowed) {
            return Err(KeyError::PrivateExportDisabled {
                fingerprint: fingerprint.clone(),
            });
        }
        import::ensure_exportable(secret)?;
        match format {
            ExportFormat::Binary => Ok(secret.to_bytes()?),
            ExportFormat::Armored => Ok(secret.to_armored_bytes(armor_options(secret.version()))?),
        }
    }

    /// Returns a snapshot for sealed on-device storage. Protected secret material
    /// keeps its original password protection. This is not an OpenPGP export API:
    /// private export policy is preserved and applies to OpenPGP export only.
    pub fn storage_snapshot(&self) -> Result<Vec<StorageRecord>, KeyError> {
        self.records
            .iter()
            .map(|(fingerprint, record)| {
                Ok(StorageRecord {
                    fingerprint: fingerprint.clone(),
                    protected_secret: record
                        .secret
                        .as_ref()
                        .map(pgp::ser::Serialize::to_bytes)
                        .transpose()?,
                    public_certificate: record.public.to_bytes()?,
                    export_policy: record.export_policy,
                })
            })
            .collect()
    }

    /// Restores records produced by `storage_snapshot` without requiring any
    /// password. Secret material stays encrypted with its original password, and
    /// export policy is preserved. Fingerprints are re-derived from the key
    /// material and must match the supplied values.
    pub fn restore_storage(&mut self, records: Vec<StorageRecord>) -> Result<(), KeyError> {
        for record in records {
            if let Some(protected_secret) = record.protected_secret {
                let secret = import::parse_protected_secret(&protected_secret)?;
                let public = secret.to_public_key();
                let fingerprint = FullFingerprint::from_rpgp(&public.fingerprint());
                if fingerprint != record.fingerprint
                    || public.to_bytes()? != record.public_certificate
                {
                    return Err(KeyError::ConflictingCertificate {
                        fingerprint: record.fingerprint,
                    });
                }
                let export_policy = record.export_policy.ok_or_else(|| {
                    KeyError::InvalidParameters(
                        "secret storage record is missing an export policy".to_owned(),
                    )
                })?;
                if let Some(existing) = self.records.get(&fingerprint) {
                    if existing.public != public {
                        return Err(KeyError::ConflictingCertificate { fingerprint });
                    }
                    if existing.secret.is_some() {
                        if !same_secret_coverage(existing.secret.as_ref(), &secret) {
                            return Err(KeyError::ConflictingCertificate { fingerprint });
                        }
                        continue;
                    }
                }
                self.records
                    .insert(fingerprint, KeyRecord::from_secret(secret, export_policy));
            } else {
                let certificate = import::parse_public(&record.public_certificate)?;
                let fingerprint = FullFingerprint::from_rpgp(&certificate.fingerprint());
                if fingerprint != record.fingerprint {
                    return Err(KeyError::ConflictingCertificate {
                        fingerprint: record.fingerprint,
                    });
                }
                if let Some(existing) = self.records.get(&fingerprint) {
                    if existing.public != certificate {
                        return Err(KeyError::ConflictingCertificate { fingerprint });
                    }
                    // Never downgrade an existing secret record to public-only.
                    continue;
                }
                self.records
                    .insert(fingerprint, KeyRecord::from_public(certificate));
            }
        }
        Ok(())
    }

    pub(crate) fn insert_external_certificate(
        &mut self,
        secret: SignedSecretKey,
        export_policy: PrivateExportPolicy,
    ) -> Result<GeneratedKey, KeyError> {
        if export_policy != PrivateExportPolicy::Disabled
            || !secret.secret_subkeys.is_empty()
            || secret.public_subkeys.len() != 2
        {
            return Err(KeyError::InvalidParameters(
                "external certificates require two public subkeys and disabled private export"
                    .to_owned(),
            ));
        }
        secret.verify_bindings()?;
        let public = secret.to_public_key();
        public.verify_bindings()?;
        import::ensure_exportable(&secret)?;
        let fingerprint = FullFingerprint::from_rpgp(&public.fingerprint());
        if self.records.contains_key(&fingerprint) {
            return Err(KeyError::ConflictingCertificate { fingerprint });
        }
        let record = KeyRecord::from_secret(secret, export_policy);
        let metadata = record.metadata()?;
        let public_certificate = record.public.to_bytes()?;
        self.records.insert(fingerprint, record);
        Ok(GeneratedKey {
            metadata,
            public_certificate,
        })
    }

    pub fn remove(&mut self, fingerprint: &FullFingerprint) -> Result<(), KeyError> {
        self.records
            .remove(fingerprint)
            .map(|_| ())
            .ok_or_else(|| KeyError::KeyNotFound {
                fingerprint: fingerprint.clone(),
            })
    }

    #[allow(dead_code)]
    pub(crate) fn rpgp_public_key(
        &self,
        fingerprint: &FullFingerprint,
    ) -> Result<&SignedPublicKey, KeyError> {
        Ok(&self.record(fingerprint)?.public)
    }

    #[allow(dead_code)]
    pub(crate) fn rpgp_secret_key(
        &self,
        fingerprint: &FullFingerprint,
    ) -> Result<&SignedSecretKey, KeyError> {
        self.record(fingerprint)?
            .secret
            .as_ref()
            .ok_or_else(|| KeyError::SecretKeyRequired {
                fingerprint: fingerprint.clone(),
            })
    }

    pub fn software_subkey_fingerprints(
        &self,
        fingerprint: &FullFingerprint,
    ) -> Result<Vec<FullFingerprint>, KeyError> {
        Ok(self
            .record(fingerprint)?
            .secret
            .as_ref()
            .map(|secret| {
                secret
                    .secret_subkeys
                    .iter()
                    .map(|subkey| FullFingerprint::from_rpgp(&subkey.key.fingerprint()))
                    .collect()
            })
            .unwrap_or_default())
    }

    pub(crate) fn rpgp_secret_subkey(
        &self,
        certificate_fingerprint: &FullFingerprint,
        component_fingerprint: &pgp::types::Fingerprint,
    ) -> Result<Option<&pgp::composed::SignedSecretSubKey>, KeyError> {
        Ok(self
            .record(certificate_fingerprint)?
            .secret
            .as_ref()
            .and_then(|secret| {
                secret
                    .secret_subkeys
                    .iter()
                    .find(|subkey| subkey.key.fingerprint() == *component_fingerprint)
            }))
    }

    fn record(&self, fingerprint: &FullFingerprint) -> Result<&KeyRecord, KeyError> {
        self.records
            .get(fingerprint)
            .ok_or_else(|| KeyError::KeyNotFound {
                fingerprint: fingerprint.clone(),
            })
    }
}

impl fmt::Debug for SoftwareKeyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut keys = formatter.debug_map();
        for (fingerprint, record) in &self.records {
            keys.entry(fingerprint, &record.storage());
        }
        keys.finish()
    }
}

struct KeyRecord {
    public: SignedPublicKey,
    secret: Option<SignedSecretKey>,
    export_policy: Option<PrivateExportPolicy>,
}

impl KeyRecord {
    fn from_public(public: SignedPublicKey) -> Self {
        Self {
            public,
            secret: None,
            export_policy: None,
        }
    }

    fn from_secret(secret: SignedSecretKey, export_policy: PrivateExportPolicy) -> Self {
        Self {
            public: secret.to_public_key(),
            secret: Some(secret),
            export_policy: Some(export_policy),
        }
    }

    fn storage(&self) -> KeyStorage {
        if self.secret.is_some() {
            KeyStorage::SoftwareSecret
        } else {
            KeyStorage::PublicOnly
        }
    }

    fn secret_subkey_count(&self) -> usize {
        self.secret
            .as_ref()
            .map_or(0, |secret| secret.secret_subkeys.len())
    }

    fn metadata(&self) -> Result<CertificateMetadata, KeyError> {
        metadata::certificate_metadata(
            &self.public,
            self.storage(),
            self.export_policy,
            self.secret_subkey_count(),
        )
    }
}

fn same_secret_coverage(existing: Option<&SignedSecretKey>, imported: &SignedSecretKey) -> bool {
    let Some(existing) = existing else {
        return false;
    };
    existing.secret_subkeys.len() == imported.secret_subkeys.len()
        && existing
            .secret_subkeys
            .iter()
            .zip(&imported.secret_subkeys)
            .all(|(left, right)| left.key.fingerprint() == right.key.fingerprint())
}

fn generation_key_type(algorithm: Algorithm) -> Result<KeyType, KeyError> {
    match algorithm {
        Algorithm::Rsa2048 => Ok(KeyType::Rsa(2048)),
        Algorithm::Rsa3072 => Ok(KeyType::Rsa(3072)),
        Algorithm::Rsa4096 => Ok(KeyType::Rsa(4096)),
        Algorithm::Ed25519 => Ok(KeyType::Ed25519),
        Algorithm::X25519 => Ok(KeyType::X25519),
        Algorithm::Ed448 => Ok(KeyType::Ed448),
        Algorithm::X448 => Ok(KeyType::X448),
        Algorithm::NistP256Ecdsa => Ok(KeyType::ECDSA(ECCCurve::P256)),
        Algorithm::NistP256Ecdh => Ok(KeyType::ECDH(ECCCurve::P256)),
        Algorithm::NistP384Ecdsa => Ok(KeyType::ECDSA(ECCCurve::P384)),
        Algorithm::NistP384Ecdh => Ok(KeyType::ECDH(ECCCurve::P384)),
        Algorithm::NistP521Ecdsa => Ok(KeyType::ECDSA(ECCCurve::P521)),
        Algorithm::NistP521Ecdh => Ok(KeyType::ECDH(ECCCurve::P521)),
        Algorithm::LegacyEd25519 => Ok(KeyType::Ed25519Legacy),
        Algorithm::LegacyCurve25519Ecdh => Ok(KeyType::ECDH(ECCCurve::Curve25519Legacy)),
        Algorithm::BrainpoolP256Ecdsa
        | Algorithm::BrainpoolP256Ecdh
        | Algorithm::BrainpoolP384Ecdsa
        | Algorithm::BrainpoolP384Ecdh
        | Algorithm::BrainpoolP512Ecdsa
        | Algorithm::BrainpoolP512Ecdh
        | Algorithm::Dsa
        | Algorithm::ElGamal => Err(KeyError::UnsupportedGenerationAlgorithm { algorithm }),
    }
}

fn armor_options(version: pgp::types::KeyVersion) -> ArmorOptions<'static> {
    ArmorOptions {
        headers: None,
        include_checksum: version != pgp::types::KeyVersion::V6,
    }
}
