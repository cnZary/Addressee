use serde::{Deserialize, Serialize};

use crate::{Algorithm, Backend, KeyVersion, Operation, SecurityPolicy};

pub const CAPABILITY_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LibraryClaim {
    Claimed,
    NotClaimed,
    RuntimeDiscoveryRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ImplementationStatus {
    NotImplemented,
    Implemented,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TestStatus {
    NotRun,
    Passed,
    Failed,
    NotApplicable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationEvidence {
    pub operation: Operation,
    pub library_claim: LibraryClaim,
    pub implementation: ImplementationStatus,
    pub unit_tests: TestStatus,
    pub independent_interoperability_tests: TestStatus,
    pub physical_hardware_tests: TestStatus,
}

impl OperationEvidence {
    fn baseline(
        backend: Backend,
        claimed: bool,
        operation: Operation,
        locally_validated: bool,
    ) -> Self {
        if !claimed {
            return Self {
                operation,
                library_claim: LibraryClaim::NotClaimed,
                implementation: ImplementationStatus::NotApplicable,
                unit_tests: TestStatus::NotApplicable,
                independent_interoperability_tests: TestStatus::NotApplicable,
                physical_hardware_tests: TestStatus::NotApplicable,
            };
        }

        Self {
            operation,
            library_claim: if backend == Backend::OpenPgpCard {
                LibraryClaim::RuntimeDiscoveryRequired
            } else {
                LibraryClaim::Claimed
            },
            implementation: if locally_validated {
                ImplementationStatus::Implemented
            } else {
                ImplementationStatus::NotImplemented
            },
            unit_tests: if locally_validated {
                TestStatus::Passed
            } else {
                TestStatus::NotRun
            },
            independent_interoperability_tests: TestStatus::NotRun,
            physical_hardware_tests: if backend.is_hardware() {
                TestStatus::NotRun
            } else {
                TestStatus::NotApplicable
            },
        }
    }
}

/// The `can*` fields are library/API candidates, not Addressee support claims.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityEntry {
    pub algorithm: Algorithm,
    pub backend: Backend,
    pub key_version: KeyVersion,
    pub can_generate: bool,
    pub can_import: bool,
    pub can_export_public: bool,
    pub can_export_private: bool,
    pub can_sign: bool,
    pub can_verify: bool,
    pub can_encrypt: bool,
    pub can_decrypt: bool,
    pub can_use_as_primary_key: bool,
    pub can_use_as_signing_subkey: bool,
    pub can_use_as_encryption_subkey: bool,
    pub is_hardware_backed: bool,
    pub is_hardware_non_exportable: bool,
    pub is_deprecated: bool,
    pub is_generation_deprecated: bool,
    pub is_recommended_for_new_keys: bool,
    pub requires_runtime_discovery: bool,
    pub evidence: Vec<OperationEvidence>,
}

impl CapabilityEntry {
    pub fn can(&self, operation: Operation) -> bool {
        match operation {
            Operation::Generate => self.can_generate,
            Operation::Import => self.can_import,
            Operation::ExportPublic => self.can_export_public,
            Operation::ExportPrivate => self.can_export_private,
            Operation::Sign => self.can_sign,
            Operation::Verify => self.can_verify,
            Operation::Encrypt => self.can_encrypt,
            Operation::Decrypt => self.can_decrypt,
            Operation::UseAsPrimaryKey => self.can_use_as_primary_key,
            Operation::UseAsSigningSubkey => self.can_use_as_signing_subkey,
            Operation::UseAsEncryptionSubkey => self.can_use_as_encryption_subkey,
        }
    }

    pub fn evidence(&self, operation: Operation) -> Option<&OperationEvidence> {
        self.evidence
            .iter()
            .find(|evidence| evidence.operation == operation)
    }

    /// UI enablement requires an implementation and passing relevant tests, never just a claim.
    pub fn is_operation_enabled(&self, operation: Operation) -> bool {
        if !self.can(operation) {
            return false;
        }
        let Some(evidence) = self.evidence(operation) else {
            return false;
        };
        if evidence.library_claim != LibraryClaim::Claimed
            || evidence.implementation != ImplementationStatus::Implemented
            || evidence.unit_tests != TestStatus::Passed
        {
            return false;
        }
        !self.backend.is_hardware() || evidence.physical_hardware_tests == TestStatus::Passed
    }

    /// Full support adds independent interoperability and, for hardware, physical-device evidence.
    pub fn is_fully_supported(&self, operation: Operation) -> bool {
        if !self.is_operation_enabled(operation) {
            return false;
        }
        let Some(evidence) = self.evidence(operation) else {
            return false;
        };
        evidence.independent_interoperability_tests == TestStatus::Passed
            && (!self.backend.is_hardware()
                || evidence.physical_hardware_tests == TestStatus::Passed)
    }

    fn baseline(
        algorithm: Algorithm,
        backend: Backend,
        key_version: KeyVersion,
        capabilities: CapabilityFlags,
        claims: CapabilityFlags,
    ) -> Self {
        Self {
            algorithm,
            backend,
            key_version,
            can_generate: capabilities.can_generate,
            can_import: capabilities.can_import,
            can_export_public: capabilities.can_export_public,
            can_export_private: capabilities.can_export_private,
            can_sign: capabilities.can_sign,
            can_verify: capabilities.can_verify,
            can_encrypt: capabilities.can_encrypt,
            can_decrypt: capabilities.can_decrypt,
            can_use_as_primary_key: capabilities.can_use_as_primary_key,
            can_use_as_signing_subkey: capabilities.can_use_as_signing_subkey,
            can_use_as_encryption_subkey: capabilities.can_use_as_encryption_subkey,
            is_hardware_backed: backend.is_hardware(),
            is_hardware_non_exportable: backend.is_hardware(),
            is_deprecated: algorithm.is_deprecated(),
            is_generation_deprecated: algorithm.is_generation_deprecated(),
            is_recommended_for_new_keys: backend == Backend::Software
                && key_version == KeyVersion::V6
                && algorithm.is_recommended_algorithm(),
            requires_runtime_discovery: backend == Backend::OpenPgpCard,
            evidence: Operation::ALL
                .into_iter()
                .map(|operation| {
                    // Key lifecycle evidence comes from the generation-profile
                    // tests; message evidence comes from `exercise_message_profile`
                    // and the attached/cleartext tests, which cover every
                    // generatable software algorithm's sign, verify, encrypt,
                    // and decrypt operations.
                    let lifecycle_validated = backend == Backend::Software
                        && algorithm.generation_key_versions().contains(&key_version)
                        && matches!(
                            operation,
                            Operation::Generate
                                | Operation::Import
                                | Operation::ExportPublic
                                | Operation::ExportPrivate
                                | Operation::UseAsPrimaryKey
                                | Operation::UseAsSigningSubkey
                                | Operation::UseAsEncryptionSubkey
                        );
                    let message_validated = backend == Backend::Software
                        && algorithm.generation_key_versions().contains(&key_version)
                        && matches!(
                            operation,
                            Operation::Sign
                                | Operation::Verify
                                | Operation::Encrypt
                                | Operation::Decrypt
                        );
                    let card_validated = backend == Backend::OpenPgpCard
                        && tested_card_operations(algorithm, key_version, operation);
                    let secure_enclave_validated = backend == Backend::SecureEnclave
                        && tested_secure_enclave_operations(algorithm, key_version, operation);
                    let mut evidence = OperationEvidence::baseline(
                        backend,
                        claims.get(operation),
                        operation,
                        lifecycle_validated
                            || message_validated
                            || card_validated
                            || secure_enclave_validated,
                    );
                    if backend == Backend::Software
                        && evidence.independent_interoperability_tests == TestStatus::NotRun
                        && independent_interop_passed(algorithm, key_version, operation)
                    {
                        evidence.independent_interoperability_tests = TestStatus::Passed;
                    }
                    if card_validated {
                        evidence.independent_interoperability_tests = TestStatus::Passed;
                        evidence.physical_hardware_tests = TestStatus::Passed;
                    }
                    if secure_enclave_validated {
                        evidence.physical_hardware_tests = TestStatus::Passed;
                        if secure_enclave_interop_passed(algorithm, key_version, operation) {
                            evidence.independent_interoperability_tests = TestStatus::Passed;
                        }
                    }
                    evidence
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityRegistry {
    pub schema_version: u32,
    pub entries: Vec<CapabilityEntry>,
    pub security_policy: SecurityPolicy,
}

impl CapabilityRegistry {
    pub fn baseline() -> Self {
        let mut entries = Vec::new();
        for algorithm in Algorithm::ALL {
            for &key_version in algorithm.usage_key_versions() {
                let claims = software_claims(algorithm, key_version);
                entries.push(CapabilityEntry::baseline(
                    algorithm,
                    Backend::Software,
                    key_version,
                    claims,
                    claims,
                ));

                if let Some(claims) = secure_enclave_claims(algorithm, key_version) {
                    entries.push(CapabilityEntry::baseline(
                        algorithm,
                        Backend::SecureEnclave,
                        key_version,
                        claims,
                        claims,
                    ));
                }

                entries.push(CapabilityEntry::baseline(
                    algorithm,
                    Backend::OpenPgpCard,
                    key_version,
                    CapabilityFlags::default(),
                    card_claims(algorithm, key_version),
                ));
            }
        }
        Self {
            schema_version: CAPABILITY_SCHEMA_VERSION,
            entries,
            security_policy: SecurityPolicy::default(),
        }
    }

    pub fn entries(&self) -> &[CapabilityEntry] {
        &self.entries
    }

    pub fn entry(
        &self,
        algorithm: Algorithm,
        backend: Backend,
        key_version: KeyVersion,
    ) -> Option<&CapabilityEntry> {
        self.entries.iter().find(|entry| {
            entry.algorithm == algorithm
                && entry.backend == backend
                && entry.key_version == key_version
        })
    }

    pub fn is_operation_enabled(
        &self,
        algorithm: Algorithm,
        backend: Backend,
        key_version: KeyVersion,
        operation: Operation,
    ) -> bool {
        self.entry(algorithm, backend, key_version)
            .is_some_and(|entry| entry.is_operation_enabled(operation))
    }

    pub fn is_fully_supported(
        &self,
        algorithm: Algorithm,
        backend: Backend,
        key_version: KeyVersion,
        operation: Operation,
    ) -> bool {
        self.entry(algorithm, backend, key_version)
            .is_some_and(|entry| entry.is_fully_supported(operation))
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::baseline()
    }
}

/// Independent GnuPG interoperability evidence recorded by
/// `openpgp-core/tests/interoperability.rs` against GnuPG 2.5.24 with an isolated
/// `GNUPGHOME`. Only operations exercised by that suite may be marked `Passed`.
///
/// - RSA-2048/3072/4096, NIST P-256/P-384/P-521, and legacy Curve25519 are
///   bidirectional: GnuPG imports application-generated public and private keys,
///   verifies detached/attached/cleartext signatures, decrypts application
///   messages, and GnuPG-generated keys and messages are imported, verified, and
///   decrypted by the application.
/// - v6 Ed25519/X25519 and Curve448 have no independent evidence: the peer
///   rejects public-key algorithm identifiers 27 and 28 during import, and those
///   tests remain explicitly ignored rather than passing.
pub(crate) fn independent_interop_passed(
    algorithm: Algorithm,
    key_version: KeyVersion,
    operation: Operation,
) -> bool {
    use Operation::{
        Decrypt, Encrypt, ExportPrivate, ExportPublic, Generate, Import, Sign, Verify,
    };

    if key_version != KeyVersion::V4 {
        return false;
    }
    match algorithm {
        Algorithm::Rsa2048 | Algorithm::Rsa3072 | Algorithm::Rsa4096 => matches!(
            operation,
            Generate | Import | ExportPublic | ExportPrivate | Sign | Verify | Encrypt | Decrypt
        ),
        Algorithm::NistP256Ecdsa
        | Algorithm::NistP384Ecdsa
        | Algorithm::NistP521Ecdsa
        | Algorithm::LegacyEd25519 => matches!(
            operation,
            Generate | Import | ExportPublic | ExportPrivate | Sign | Verify
        ),
        Algorithm::NistP256Ecdh
        | Algorithm::NistP384Ecdh
        | Algorithm::NistP521Ecdh
        | Algorithm::LegacyCurve25519Ecdh => matches!(
            operation,
            Generate | Import | ExportPublic | ExportPrivate | Encrypt | Decrypt
        ),
        _ => false,
    }
}

/// Host-CLI evidence from the identified CanoKey P-256 tests on 2026-10-26 and 2026-10-27.
/// Runtime discovery remains mandatory, and this is not iOS transport evidence.
fn tested_card_operations(
    algorithm: Algorithm,
    key_version: KeyVersion,
    operation: Operation,
) -> bool {
    if key_version != KeyVersion::V4 {
        return false;
    }
    match algorithm {
        Algorithm::NistP256Ecdsa => matches!(
            operation,
            Operation::Sign | Operation::ExportPublic | Operation::UseAsSigningSubkey
        ),
        Algorithm::NistP256Ecdh => matches!(
            operation,
            Operation::Decrypt | Operation::ExportPublic | Operation::UseAsEncryptionSubkey
        ),
        _ => false,
    }
}

/// Physical iPhone evidence covers only device-bound P-256 subkeys. The hybrid
/// certificate's primary key is protected software key material, not an SE key.
fn tested_secure_enclave_operations(
    algorithm: Algorithm,
    key_version: KeyVersion,
    operation: Operation,
) -> bool {
    if key_version != KeyVersion::V4 {
        return false;
    }
    match algorithm {
        Algorithm::NistP256Ecdsa => matches!(
            operation,
            Operation::Generate
                | Operation::ExportPublic
                | Operation::Sign
                | Operation::UseAsSigningSubkey
        ),
        Algorithm::NistP256Ecdh => matches!(
            operation,
            Operation::Generate
                | Operation::ExportPublic
                | Operation::Decrypt
                | Operation::UseAsEncryptionSubkey
        ),
        _ => false,
    }
}

/// Independent GnuPG 2.5.24 evidence covers all three signature forms, tamper
/// rejection, device decryption of GnuPG-encrypted messages, and verification of
/// an embedded GnuPG signature after decryption. Identity trust is not established.
fn secure_enclave_interop_passed(
    algorithm: Algorithm,
    key_version: KeyVersion,
    operation: Operation,
) -> bool {
    if key_version != KeyVersion::V4 {
        return false;
    }
    match algorithm {
        Algorithm::NistP256Ecdsa => matches!(
            operation,
            Operation::Generate
                | Operation::ExportPublic
                | Operation::Sign
                | Operation::UseAsSigningSubkey
        ),
        Algorithm::NistP256Ecdh => matches!(
            operation,
            Operation::Generate
                | Operation::ExportPublic
                | Operation::Decrypt
                | Operation::UseAsEncryptionSubkey
        ),
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct CapabilityFlags {
    can_generate: bool,
    can_import: bool,
    can_export_public: bool,
    can_export_private: bool,
    can_sign: bool,
    can_verify: bool,
    can_encrypt: bool,
    can_decrypt: bool,
    can_use_as_primary_key: bool,
    can_use_as_signing_subkey: bool,
    can_use_as_encryption_subkey: bool,
}

impl CapabilityFlags {
    fn get(self, operation: Operation) -> bool {
        match operation {
            Operation::Generate => self.can_generate,
            Operation::Import => self.can_import,
            Operation::ExportPublic => self.can_export_public,
            Operation::ExportPrivate => self.can_export_private,
            Operation::Sign => self.can_sign,
            Operation::Verify => self.can_verify,
            Operation::Encrypt => self.can_encrypt,
            Operation::Decrypt => self.can_decrypt,
            Operation::UseAsPrimaryKey => self.can_use_as_primary_key,
            Operation::UseAsSigningSubkey => self.can_use_as_signing_subkey,
            Operation::UseAsEncryptionSubkey => self.can_use_as_encryption_subkey,
        }
    }

    fn parsing_only() -> Self {
        Self {
            can_import: true,
            can_export_public: true,
            ..Self::default()
        }
    }

    fn signing() -> Self {
        Self {
            can_import: true,
            can_export_public: true,
            can_export_private: true,
            can_sign: true,
            can_verify: true,
            can_use_as_primary_key: true,
            can_use_as_signing_subkey: true,
            ..Self::default()
        }
    }

    fn encryption() -> Self {
        Self {
            can_import: true,
            can_export_public: true,
            can_export_private: true,
            can_encrypt: true,
            can_decrypt: true,
            can_use_as_encryption_subkey: true,
            ..Self::default()
        }
    }

    fn general_purpose_rsa() -> Self {
        Self {
            can_import: true,
            can_export_public: true,
            can_export_private: true,
            can_sign: true,
            can_verify: true,
            can_encrypt: true,
            can_decrypt: true,
            can_use_as_primary_key: true,
            can_use_as_signing_subkey: true,
            can_use_as_encryption_subkey: true,
            ..Self::default()
        }
    }
}

fn software_claims(algorithm: Algorithm, key_version: KeyVersion) -> CapabilityFlags {
    let mut claims = match algorithm {
        Algorithm::Rsa2048 | Algorithm::Rsa3072 | Algorithm::Rsa4096 => {
            CapabilityFlags::general_purpose_rsa()
        }
        Algorithm::Ed25519
        | Algorithm::Ed448
        | Algorithm::NistP256Ecdsa
        | Algorithm::NistP384Ecdsa
        | Algorithm::NistP521Ecdsa
        | Algorithm::LegacyEd25519 => CapabilityFlags::signing(),
        Algorithm::X25519
        | Algorithm::X448
        | Algorithm::NistP256Ecdh
        | Algorithm::NistP384Ecdh
        | Algorithm::NistP521Ecdh
        | Algorithm::LegacyCurve25519Ecdh => CapabilityFlags::encryption(),
        Algorithm::BrainpoolP256Ecdsa
        | Algorithm::BrainpoolP256Ecdh
        | Algorithm::BrainpoolP384Ecdsa
        | Algorithm::BrainpoolP384Ecdh
        | Algorithm::BrainpoolP512Ecdsa
        | Algorithm::BrainpoolP512Ecdh => CapabilityFlags::parsing_only(),
        Algorithm::Dsa => CapabilityFlags {
            can_verify: true,
            ..CapabilityFlags::parsing_only()
        },
        Algorithm::ElGamal => CapabilityFlags::parsing_only(),
    };
    claims.can_generate = algorithm.generation_key_versions().contains(&key_version);
    claims
}

fn secure_enclave_claims(algorithm: Algorithm, key_version: KeyVersion) -> Option<CapabilityFlags> {
    if key_version != KeyVersion::V4 {
        return None;
    }
    match algorithm {
        Algorithm::NistP256Ecdsa => Some(CapabilityFlags {
            can_generate: true,
            can_export_public: true,
            can_sign: true,
            can_use_as_signing_subkey: true,
            ..CapabilityFlags::default()
        }),
        Algorithm::NistP256Ecdh => Some(CapabilityFlags {
            can_generate: true,
            can_export_public: true,
            can_decrypt: true,
            can_use_as_encryption_subkey: true,
            ..CapabilityFlags::default()
        }),
        _ => None,
    }
}

fn card_claims(algorithm: Algorithm, key_version: KeyVersion) -> CapabilityFlags {
    let signing = algorithm.is_signing_algorithm() && algorithm != Algorithm::Dsa;
    let encryption = algorithm.is_encryption_algorithm();
    CapabilityFlags {
        can_generate: algorithm.generation_key_versions().contains(&key_version),
        can_import: true,
        can_export_public: true,
        can_sign: signing,
        can_decrypt: encryption,
        can_use_as_primary_key: signing,
        can_use_as_signing_subkey: signing,
        can_use_as_encryption_subkey: encryption,
        ..CapabilityFlags::default()
    }
}
