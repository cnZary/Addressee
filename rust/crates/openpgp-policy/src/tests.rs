use std::collections::BTreeSet;

use crate::{
    Algorithm, Backend, CAPABILITY_SCHEMA_VERSION, CapabilityEntry, CapabilityRegistry,
    CompatibilityAcknowledgement, GenerationProfile, HashAlgorithm, ImplementationStatus, KeyRole,
    KeyVersion, LegacyAlgorithmWarning, LegacyDisposition, LibraryClaim, Operation,
    OperationEvidence, ProfileError, SecurityPolicy, SecurityPolicyError, SymmetricAlgorithm,
    TestStatus, algorithm_capabilities_json,
};

const CHECKED_IN_JSON: &str = include_str!("../../../../docs/algorithm-capabilities.json");

fn evidence_mut(entry: &mut CapabilityEntry, operation: Operation) -> &mut OperationEvidence {
    entry
        .evidence
        .iter_mut()
        .find(|evidence| evidence.operation == operation)
        .expect("every operation has evidence")
}

fn pass_implementation_and_unit_tests(entry: &mut CapabilityEntry, operation: Operation) {
    let evidence = evidence_mut(entry, operation);
    evidence.implementation = ImplementationStatus::Implemented;
    evidence.unit_tests = TestStatus::Passed;
}

#[test]
fn independent_interop_evidence_matches_executed_gnupg_tests() {
    let registry = CapabilityRegistry::baseline();
    let status = |algorithm, version, operation| {
        registry
            .entry(algorithm, Backend::Software, version)
            .and_then(|entry| entry.evidence(operation))
            .map(|evidence| evidence.independent_interoperability_tests)
            .expect("evidence exists for every registry operation")
    };

    for algorithm in [Algorithm::Rsa2048, Algorithm::Rsa3072, Algorithm::Rsa4096] {
        for operation in [
            Operation::Generate,
            Operation::Import,
            Operation::ExportPublic,
            Operation::ExportPrivate,
            Operation::Sign,
            Operation::Verify,
            Operation::Encrypt,
            Operation::Decrypt,
        ] {
            assert_eq!(
                status(algorithm, KeyVersion::V4, operation),
                TestStatus::Passed,
                "{algorithm:?} {operation:?} is covered bidirectionally"
            );
        }
        for operation in [
            Operation::UseAsPrimaryKey,
            Operation::UseAsSigningSubkey,
            Operation::UseAsEncryptionSubkey,
        ] {
            assert_eq!(
                status(algorithm, KeyVersion::V4, operation),
                TestStatus::NotRun,
                "{algorithm:?} {operation:?} has no role-specific independent evidence"
            );
        }
    }

    for (signing, encryption) in [
        (Algorithm::NistP256Ecdsa, Algorithm::NistP256Ecdh),
        (Algorithm::NistP384Ecdsa, Algorithm::NistP384Ecdh),
        (Algorithm::NistP521Ecdsa, Algorithm::NistP521Ecdh),
        (Algorithm::LegacyEd25519, Algorithm::LegacyCurve25519Ecdh),
    ] {
        for operation in [Operation::Sign, Operation::Verify] {
            assert_eq!(
                status(signing, KeyVersion::V4, operation),
                TestStatus::Passed
            );
        }
        for operation in [Operation::Encrypt, Operation::Decrypt] {
            assert_eq!(
                status(encryption, KeyVersion::V4, operation),
                TestStatus::Passed
            );
        }
        assert_eq!(
            status(signing, KeyVersion::V4, Operation::Encrypt),
            TestStatus::NotApplicable
        );
        assert_eq!(
            status(encryption, KeyVersion::V4, Operation::Sign),
            TestStatus::NotApplicable
        );
    }

    for (algorithm, version) in [
        (Algorithm::Ed25519, KeyVersion::V6),
        (Algorithm::X25519, KeyVersion::V6),
        (Algorithm::Ed448, KeyVersion::V6),
        (Algorithm::X448, KeyVersion::V6),
    ] {
        for operation in Operation::ALL {
            assert_ne!(
                status(algorithm, version, operation),
                TestStatus::Passed,
                "{algorithm:?} {operation:?} has no independent evidence because the peer rejects the key import"
            );
        }
    }
}

#[test]
fn registry_is_complete_and_separates_lifecycle_evidence_from_other_operations() {
    let registry = CapabilityRegistry::baseline();
    let expected_entries = Algorithm::ALL
        .iter()
        .map(|algorithm| algorithm.usage_key_versions().len() * 2)
        .sum::<usize>()
        + 2;
    assert_eq!(registry.schema_version, CAPABILITY_SCHEMA_VERSION);
    assert_eq!(registry.entries().len(), expected_entries);

    for algorithm in Algorithm::ALL {
        for &key_version in algorithm.usage_key_versions() {
            let software = registry
                .entry(algorithm, Backend::Software, key_version)
                .unwrap();
            assert_eq!(
                software.can_generate,
                algorithm.generation_key_versions().contains(&key_version)
            );
            for operation in Operation::ALL {
                let generation_supported =
                    algorithm.generation_key_versions().contains(&key_version);
                let expected_lifecycle = software.can(operation)
                    && generation_supported
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
                let expected_message = software.can(operation)
                    && generation_supported
                    && matches!(
                        operation,
                        Operation::Sign
                            | Operation::Verify
                            | Operation::Encrypt
                            | Operation::Decrypt
                    );
                let expected_validated = expected_lifecycle || expected_message;
                let evidence = software.evidence(operation).unwrap();
                assert_eq!(
                    evidence.implementation == ImplementationStatus::Implemented,
                    expected_validated
                );
                assert_eq!(
                    evidence.unit_tests == TestStatus::Passed,
                    expected_validated
                );
                assert_eq!(software.is_operation_enabled(operation), expected_validated);
                let expected_independent = software.can(operation)
                    && crate::capability::independent_interop_passed(
                        algorithm,
                        key_version,
                        operation,
                    );
                assert_eq!(
                    evidence.independent_interoperability_tests == TestStatus::Passed,
                    expected_independent,
                    "{algorithm:?} {key_version:?} {operation:?} independent evidence"
                );
                let expected_full = expected_validated && expected_independent;
                assert_eq!(software.is_fully_supported(operation), expected_full);
                assert_eq!(
                    registry.is_fully_supported(
                        algorithm,
                        Backend::Software,
                        key_version,
                        operation
                    ),
                    expected_full
                );
            }

            let card = registry
                .entry(algorithm, Backend::OpenPgpCard, key_version)
                .expect("card entries cover every usage version");
            for operation in Operation::ALL {
                assert!(!card.is_operation_enabled(operation));
                assert!(!card.is_fully_supported(operation));
                let evidence = card.evidence(operation).unwrap();
                if evidence.physical_hardware_tests == TestStatus::Passed {
                    assert_eq!(evidence.implementation, ImplementationStatus::Implemented);
                    assert_eq!(evidence.unit_tests, TestStatus::Passed);
                    assert_eq!(
                        evidence.independent_interoperability_tests,
                        TestStatus::Passed
                    );
                } else {
                    assert_ne!(evidence.implementation, ImplementationStatus::Implemented);
                    assert_ne!(evidence.unit_tests, TestStatus::Passed);
                }
            }
        }
    }
}

#[test]
fn json_schema_is_stable() {
    let value = serde_json::to_value(CapabilityRegistry::baseline()).unwrap();
    let top_level = value.as_object().unwrap();
    assert_eq!(
        top_level
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        ["entries", "schemaVersion", "securityPolicy"]
            .into_iter()
            .collect()
    );
    assert_eq!(value["schemaVersion"], CAPABILITY_SCHEMA_VERSION);
    assert!(value.get("generatedAt").is_none());

    let first = value["entries"][0].as_object().unwrap();
    let expected_entry_fields = [
        "algorithm",
        "backend",
        "keyVersion",
        "canGenerate",
        "canImport",
        "canExportPublic",
        "canExportPrivate",
        "canSign",
        "canVerify",
        "canEncrypt",
        "canDecrypt",
        "canUseAsPrimaryKey",
        "canUseAsSigningSubkey",
        "canUseAsEncryptionSubkey",
        "isHardwareBacked",
        "isHardwareNonExportable",
        "isDeprecated",
        "isGenerationDeprecated",
        "isRecommendedForNewKeys",
        "requiresRuntimeDiscovery",
        "evidence",
    ];
    assert_eq!(
        first.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        expected_entry_fields.into_iter().collect()
    );
    assert_eq!(first["algorithm"], "rsa-2048");
    assert_eq!(first["backend"], "software");
    assert_eq!(first["keyVersion"], "v4");

    let evidence = first["evidence"][0].as_object().unwrap();
    assert_eq!(
        evidence.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        [
            "operation",
            "libraryClaim",
            "implementation",
            "unitTests",
            "independentInteroperabilityTests",
            "physicalHardwareTests",
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(evidence["operation"], "generate");
    assert_eq!(evidence["libraryClaim"], "claimed");
    assert_eq!(evidence["implementation"], "implemented");
    assert_eq!(evidence["unitTests"], "passed");
    assert_eq!(evidence["independentInteroperabilityTests"], "passed");
    assert_eq!(evidence["physicalHardwareTests"], "notApplicable");

    let policy = value["securityPolicy"].as_object().unwrap();
    assert_eq!(
        policy.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        [
            "defaultSignatureHash",
            "defaultSymmetricAlgorithm",
            "legacyMd5Verification",
            "legacySha1Verification",
            "legacyIdeaDecryption",
            "legacyTripleDesDecryption",
            "legacyCast5Decryption",
            "legacyBlowfishDecryption",
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(policy["defaultSignatureHash"], "sha256");
    assert_eq!(policy["defaultSymmetricAlgorithm"], "aes-256");

    let identifiers = Algorithm::ALL
        .into_iter()
        .map(|algorithm| {
            serde_json::to_value(algorithm)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        identifiers,
        [
            "rsa-2048",
            "rsa-3072",
            "rsa-4096",
            "ed25519",
            "x25519",
            "ed448",
            "x448",
            "nist-p256-ecdsa",
            "nist-p256-ecdh",
            "nist-p384-ecdsa",
            "nist-p384-ecdh",
            "nist-p521-ecdsa",
            "nist-p521-ecdh",
            "brainpool-p256-ecdsa",
            "brainpool-p256-ecdh",
            "brainpool-p384-ecdsa",
            "brainpool-p384-ecdh",
            "brainpool-p512-ecdsa",
            "brainpool-p512-ecdh",
            "legacy-ed25519",
            "legacy-curve25519-ecdh",
            "dsa",
            "elgamal",
        ]
    );
}

#[test]
fn checked_in_json_exactly_matches_the_rust_registry() {
    assert_eq!(CHECKED_IN_JSON, algorithm_capabilities_json().unwrap());
    assert_eq!(
        algorithm_capabilities_json().unwrap(),
        algorithm_capabilities_json().unwrap()
    );
    assert!(CHECKED_IN_JSON.ends_with('\n'));
}

#[test]
fn software_ui_and_full_support_have_distinct_evidence_gates() {
    let registry = CapabilityRegistry::baseline();
    let mut entry = registry
        .entry(Algorithm::Ed25519, Backend::Software, KeyVersion::V6)
        .unwrap()
        .clone();

    assert!(entry.can_sign);
    // Start from a cleared evidence state so each gate is exercised independently
    // of the baseline's recorded message-operation test results.
    {
        let evidence = evidence_mut(&mut entry, Operation::Sign);
        evidence.implementation = ImplementationStatus::NotImplemented;
        evidence.unit_tests = TestStatus::NotRun;
        evidence.independent_interoperability_tests = TestStatus::NotRun;
    }
    assert!(!entry.is_operation_enabled(Operation::Sign));
    evidence_mut(&mut entry, Operation::Sign).implementation = ImplementationStatus::Implemented;
    assert!(!entry.is_operation_enabled(Operation::Sign));

    evidence_mut(&mut entry, Operation::Sign).unit_tests = TestStatus::Passed;
    assert!(entry.is_operation_enabled(Operation::Sign));
    assert!(!entry.is_fully_supported(Operation::Sign));

    evidence_mut(&mut entry, Operation::Sign).independent_interoperability_tests =
        TestStatus::Passed;
    assert!(entry.is_fully_supported(Operation::Sign));
}

#[test]
fn failed_or_not_applicable_tests_and_false_claims_never_enable_operations() {
    let registry = CapabilityRegistry::baseline();
    let mut entry = registry
        .entry(Algorithm::Ed25519, Backend::Software, KeyVersion::V6)
        .unwrap()
        .clone();
    {
        let evidence = evidence_mut(&mut entry, Operation::Sign);
        evidence.implementation = ImplementationStatus::Implemented;
        evidence.unit_tests = TestStatus::Failed;
        evidence.independent_interoperability_tests = TestStatus::Passed;
    }
    assert!(!entry.is_operation_enabled(Operation::Sign));
    assert!(!entry.is_fully_supported(Operation::Sign));

    evidence_mut(&mut entry, Operation::Sign).unit_tests = TestStatus::NotApplicable;
    assert!(!entry.is_operation_enabled(Operation::Sign));

    let mut encryption_only = registry
        .entry(Algorithm::X25519, Backend::Software, KeyVersion::V6)
        .unwrap()
        .clone();
    let evidence = evidence_mut(&mut encryption_only, Operation::Sign);
    evidence.library_claim = LibraryClaim::Claimed;
    evidence.implementation = ImplementationStatus::Implemented;
    evidence.unit_tests = TestStatus::Passed;
    evidence.independent_interoperability_tests = TestStatus::Passed;
    assert!(!encryption_only.is_operation_enabled(Operation::Sign));
    assert!(!encryption_only.is_fully_supported(Operation::Sign));
}

#[test]
fn card_operations_require_runtime_discovery_without_relaxing_other_evidence() {
    let registry = CapabilityRegistry::baseline();
    let p256_sign = (
        Algorithm::NistP256Ecdsa,
        Backend::OpenPgpCard,
        KeyVersion::V4,
        Operation::Sign,
    );
    assert!(!registry.is_operation_enabled(p256_sign.0, p256_sign.1, p256_sign.2, p256_sign.3));
    assert!(
        registry.is_operation_enabled_with_runtime_discovery(
            p256_sign.0,
            p256_sign.1,
            p256_sign.2,
            p256_sign.3,
            true,
        ),
        "{:?}",
        registry.entry(p256_sign.0, p256_sign.1, p256_sign.2),
    );
    assert!(!registry.is_fully_supported(p256_sign.0, p256_sign.1, p256_sign.2, p256_sign.3,));

    for (algorithm, operation) in [
        (Algorithm::NistP256Ecdsa, Operation::Verify),
        (Algorithm::NistP384Ecdsa, Operation::Sign),
        (Algorithm::NistP256Ecdh, Operation::Sign),
        (Algorithm::Dsa, Operation::Sign),
    ] {
        assert!(!registry.is_operation_enabled_with_runtime_discovery(
            algorithm,
            Backend::OpenPgpCard,
            KeyVersion::V4,
            operation,
            true,
        ));
    }
}

#[test]
fn hardware_requires_physical_and_independent_evidence_for_full_support() {
    let registry = CapabilityRegistry::baseline();
    let mut entry = registry
        .entry(
            Algorithm::NistP256Ecdsa,
            Backend::SecureEnclave,
            KeyVersion::V4,
        )
        .unwrap()
        .clone();
    evidence_mut(&mut entry, Operation::Sign).physical_hardware_tests = TestStatus::NotRun;
    evidence_mut(&mut entry, Operation::Sign).independent_interoperability_tests =
        TestStatus::NotRun;
    pass_implementation_and_unit_tests(&mut entry, Operation::Sign);
    evidence_mut(&mut entry, Operation::Sign).independent_interoperability_tests =
        TestStatus::Passed;

    assert!(!entry.is_operation_enabled(Operation::Sign));
    assert!(!entry.is_fully_supported(Operation::Sign));
    evidence_mut(&mut entry, Operation::Sign).physical_hardware_tests = TestStatus::Failed;
    assert!(!entry.is_operation_enabled(Operation::Sign));

    evidence_mut(&mut entry, Operation::Sign).physical_hardware_tests = TestStatus::Passed;
    assert!(entry.is_operation_enabled(Operation::Sign));
    assert!(entry.is_fully_supported(Operation::Sign));

    evidence_mut(&mut entry, Operation::Sign).independent_interoperability_tests =
        TestStatus::NotRun;
    assert!(entry.is_operation_enabled(Operation::Sign));
    assert!(!entry.is_fully_supported(Operation::Sign));
}

#[test]
fn secure_enclave_evidence_is_limited_to_executed_p256_operations() {
    let registry = CapabilityRegistry::baseline();
    for entry in registry
        .entries()
        .iter()
        .filter(|entry| entry.backend == Backend::SecureEnclave)
    {
        for operation in Operation::ALL {
            let physically_validated = matches!(
                (entry.algorithm, operation),
                (
                    Algorithm::NistP256Ecdsa,
                    Operation::Generate
                        | Operation::ExportPublic
                        | Operation::Sign
                        | Operation::UseAsSigningSubkey
                ) | (
                    Algorithm::NistP256Ecdh,
                    Operation::Generate
                        | Operation::ExportPublic
                        | Operation::Decrypt
                        | Operation::UseAsEncryptionSubkey
                )
            );
            let locally_validated = physically_validated
                || (entry.algorithm == Algorithm::NistP256Ecdsa
                    && operation == Operation::UseAsPrimaryKey);
            let independent = matches!(
                (entry.algorithm, operation),
                (
                    Algorithm::NistP256Ecdsa,
                    Operation::Generate
                        | Operation::ExportPublic
                        | Operation::Sign
                        | Operation::UseAsPrimaryKey
                        | Operation::UseAsSigningSubkey
                ) | (
                    Algorithm::NistP256Ecdh,
                    Operation::Generate
                        | Operation::ExportPublic
                        | Operation::Decrypt
                        | Operation::UseAsEncryptionSubkey
                )
            );
            let evidence = entry.evidence(operation).unwrap();
            assert_eq!(
                evidence.implementation == ImplementationStatus::Implemented,
                locally_validated,
                "{:?} {operation:?}",
                entry.algorithm
            );
            assert_eq!(evidence.unit_tests == TestStatus::Passed, locally_validated);
            assert_eq!(
                evidence.physical_hardware_tests == TestStatus::Passed,
                physically_validated
            );
            assert_eq!(
                evidence.independent_interoperability_tests == TestStatus::Passed,
                independent
            );
            assert_eq!(entry.is_operation_enabled(operation), physically_validated);
            assert_eq!(
                entry.is_fully_supported(operation),
                physically_validated && independent
            );
        }
    }
}

#[test]
fn hardware_backends_are_non_exportable_and_secure_enclave_is_narrow() {
    let registry = CapabilityRegistry::baseline();
    let secure_enclave = registry
        .entries()
        .iter()
        .filter(|entry| entry.backend == Backend::SecureEnclave)
        .collect::<Vec<_>>();
    assert_eq!(secure_enclave.len(), 2);
    assert!(secure_enclave.iter().all(|entry| {
        entry.key_version == KeyVersion::V4
            && entry.is_hardware_backed
            && entry.is_hardware_non_exportable
            && !entry.can_import
            && !entry.can_export_private
    }));

    let signing = registry
        .entry(
            Algorithm::NistP256Ecdsa,
            Backend::SecureEnclave,
            KeyVersion::V4,
        )
        .unwrap();
    assert!(signing.can_generate && signing.can_export_public && signing.can_sign);
    assert!(signing.can_use_as_primary_key && signing.can_use_as_signing_subkey);
    assert!(!signing.can_use_as_encryption_subkey);
    assert!(!signing.can_verify && !signing.can_encrypt && !signing.can_decrypt);

    let agreement = registry
        .entry(
            Algorithm::NistP256Ecdh,
            Backend::SecureEnclave,
            KeyVersion::V4,
        )
        .unwrap();
    assert!(agreement.can_generate && agreement.can_export_public && agreement.can_decrypt);
    assert!(!agreement.can_sign && !agreement.can_verify && !agreement.can_encrypt);

    for algorithm in Algorithm::ALL {
        for key_version in [KeyVersion::V4, KeyVersion::V6] {
            if !matches!(
                (algorithm, key_version),
                (Algorithm::NistP256Ecdsa, KeyVersion::V4)
                    | (Algorithm::NistP256Ecdh, KeyVersion::V4)
            ) {
                assert!(
                    registry
                        .entry(algorithm, Backend::SecureEnclave, key_version)
                        .is_none()
                );
            }
        }
    }

    for entry in registry
        .entries()
        .iter()
        .filter(|entry| entry.backend == Backend::OpenPgpCard)
    {
        assert!(entry.requires_runtime_discovery);
        assert!(entry.is_hardware_non_exportable);
        assert!(!entry.can_export_private);
        assert!(
            Operation::ALL
                .into_iter()
                .all(|operation| !entry.can(operation))
        );
    }
    assert!(registry.entries().iter().all(|entry| {
        entry.backend != Backend::Software
            || (!entry.is_hardware_backed && !entry.is_hardware_non_exportable)
    }));
}

#[test]
fn physical_card_evidence_is_limited_to_executed_p256_operations() {
    let registry = CapabilityRegistry::baseline();
    for (algorithm, operation) in [
        (Algorithm::NistP256Ecdsa, Operation::Sign),
        (Algorithm::NistP256Ecdsa, Operation::ExportPublic),
        (Algorithm::NistP256Ecdsa, Operation::UseAsSigningSubkey),
        (Algorithm::NistP256Ecdh, Operation::Decrypt),
        (Algorithm::NistP256Ecdh, Operation::ExportPublic),
        (Algorithm::NistP256Ecdh, Operation::UseAsEncryptionSubkey),
    ] {
        let entry = registry
            .entry(algorithm, Backend::OpenPgpCard, KeyVersion::V4)
            .unwrap();
        let evidence = entry.evidence(operation).unwrap();
        assert_eq!(evidence.implementation, ImplementationStatus::Implemented);
        assert_eq!(evidence.unit_tests, TestStatus::Passed);
        assert_eq!(
            evidence.independent_interoperability_tests,
            TestStatus::Passed
        );
        assert_eq!(evidence.physical_hardware_tests, TestStatus::Passed);
        assert_eq!(
            evidence.library_claim,
            LibraryClaim::RuntimeDiscoveryRequired
        );
        assert!(!entry.is_operation_enabled(operation));
        assert!(!entry.is_fully_supported(operation));
    }

    for entry in registry.entries().iter().filter(|entry| {
        entry.backend == Backend::OpenPgpCard
            && !matches!(
                entry.algorithm,
                Algorithm::NistP256Ecdsa | Algorithm::NistP256Ecdh
            )
    }) {
        assert!(entry.evidence.iter().all(|evidence| {
            evidence.physical_hardware_tests != TestStatus::Passed
                && evidence.independent_interoperability_tests != TestStatus::Passed
        }));
    }
    for algorithm in [Algorithm::NistP256Ecdsa, Algorithm::NistP256Ecdh] {
        let entry = registry
            .entry(algorithm, Backend::OpenPgpCard, KeyVersion::V4)
            .unwrap();
        for operation in [
            Operation::Generate,
            Operation::Import,
            Operation::UseAsPrimaryKey,
        ] {
            let evidence = entry.evidence(operation).unwrap();
            if evidence.library_claim == LibraryClaim::RuntimeDiscoveryRequired {
                assert_eq!(
                    evidence.implementation,
                    ImplementationStatus::NotImplemented
                );
                assert_eq!(evidence.unit_tests, TestStatus::NotRun);
                assert_eq!(evidence.physical_hardware_tests, TestStatus::NotRun);
                assert_eq!(
                    evidence.independent_interoperability_tests,
                    TestStatus::NotRun
                );
            } else {
                assert_eq!(evidence.implementation, ImplementationStatus::NotApplicable);
                assert_eq!(evidence.unit_tests, TestStatus::NotApplicable);
                assert_eq!(evidence.physical_hardware_tests, TestStatus::NotApplicable);
                assert_eq!(
                    evidence.independent_interoperability_tests,
                    TestStatus::NotApplicable
                );
            }
        }
    }
}

#[test]
fn modern_default_and_curve448_profiles_are_v6() {
    let default = GenerationProfile::default();
    assert_eq!(default, GenerationProfile::modern_v6());
    assert_eq!(default.key_version, KeyVersion::V6);
    assert_eq!(default.primary_key.algorithm, Algorithm::Ed25519);
    assert_eq!(default.signing_subkey.algorithm, Algorithm::Ed25519);
    assert_eq!(default.encryption_subkey.algorithm, Algorithm::X25519);
    default.validate().unwrap();

    let curve448 = GenerationProfile::curve448_v6();
    assert_eq!(curve448.key_version, KeyVersion::V6);
    assert_eq!(curve448.primary_key.algorithm, Algorithm::Ed448);
    assert_eq!(curve448.signing_subkey.algorithm, Algorithm::Ed448);
    assert_eq!(curve448.encryption_subkey.algorithm, Algorithm::X448);
    curve448.validate().unwrap();

    let registry = CapabilityRegistry::baseline();
    for algorithm in [
        Algorithm::Ed25519,
        Algorithm::X25519,
        Algorithm::Ed448,
        Algorithm::X448,
    ] {
        assert!(
            registry
                .entry(algorithm, Backend::Software, KeyVersion::V6)
                .unwrap()
                .is_recommended_for_new_keys
        );
        assert!(
            !registry
                .entry(algorithm, Backend::Software, KeyVersion::V4)
                .unwrap()
                .is_recommended_for_new_keys
        );
    }
}

#[test]
fn compatibility_profiles_validate_their_versions_and_acknowledgements() {
    let missing =
        GenerationProfile::legacy_curve25519_v4(CompatibilityAcknowledgement::not_acknowledged());
    assert!(matches!(
        missing,
        Err(ProfileError::CompatibilityAcknowledgementRequired { algorithms })
            if algorithms == vec![Algorithm::LegacyEd25519, Algorithm::LegacyCurve25519Ecdh]
    ));
    let legacy =
        GenerationProfile::legacy_curve25519_v4(CompatibilityAcknowledgement::acknowledged())
            .unwrap();
    assert_eq!(legacy.key_version, KeyVersion::V4);
    legacy.validate().unwrap();

    for profile in [
        GenerationProfile::nist_p256_v4(),
        GenerationProfile::nist_p384_v4(),
        GenerationProfile::nist_p521_v4(),
    ] {
        assert_eq!(profile.key_version, KeyVersion::V4);
        assert_eq!(
            profile.primary_key.algorithm,
            profile.signing_subkey.algorithm
        );
        profile.validate().unwrap();
    }
}

#[test]
fn rsa_generation_requires_v4_and_acknowledgement_but_existing_use_remains_available() {
    for algorithm in [Algorithm::Rsa2048, Algorithm::Rsa3072, Algorithm::Rsa4096] {
        assert!(matches!(
            GenerationProfile::legacy_rsa_v4(
                algorithm,
                CompatibilityAcknowledgement::not_acknowledged()
            ),
            Err(ProfileError::CompatibilityAcknowledgementRequired { algorithms })
                if algorithms == vec![algorithm]
        ));
        let profile = GenerationProfile::legacy_rsa_v4(
            algorithm,
            CompatibilityAcknowledgement::acknowledged(),
        )
        .unwrap();
        assert_eq!(profile.key_version, KeyVersion::V4);
        profile.validate().unwrap();

        assert!(matches!(
            GenerationProfile::new(
                KeyVersion::V6,
                algorithm,
                algorithm,
                algorithm,
                CompatibilityAcknowledgement::acknowledged()
            ),
            Err(ProfileError::RsaV6Generation { algorithm: actual }) if actual == algorithm
        ));

        let registry = CapabilityRegistry::baseline();
        let v4 = registry
            .entry(algorithm, Backend::Software, KeyVersion::V4)
            .unwrap();
        let v6 = registry
            .entry(algorithm, Backend::Software, KeyVersion::V6)
            .unwrap();
        assert!(v4.can_generate && !v6.can_generate);
        for entry in [v4, v6] {
            assert!(entry.can_sign && entry.can_verify && entry.can_encrypt && entry.can_decrypt);
            assert!(!entry.is_deprecated);
            assert!(entry.is_generation_deprecated);
            assert!(!entry.is_recommended_for_new_keys);
        }
    }

    assert!(matches!(
        GenerationProfile::legacy_rsa_v4(
            Algorithm::Ed25519,
            CompatibilityAcknowledgement::acknowledged()
        ),
        Err(ProfileError::RsaAlgorithmRequired {
            algorithm: Algorithm::Ed25519
        })
    ));
}

#[test]
fn invalid_key_roles_return_structured_errors() {
    let cases = [
        (
            KeyVersion::V6,
            Algorithm::X25519,
            Algorithm::Ed25519,
            Algorithm::X25519,
            Algorithm::X25519,
            KeyRole::Primary,
        ),
        (
            KeyVersion::V6,
            Algorithm::Ed448,
            Algorithm::X448,
            Algorithm::X448,
            Algorithm::X448,
            KeyRole::SigningSubkey,
        ),
        (
            KeyVersion::V6,
            Algorithm::Ed25519,
            Algorithm::Ed25519,
            Algorithm::Ed25519,
            Algorithm::Ed25519,
            KeyRole::EncryptionSubkey,
        ),
        (
            KeyVersion::V4,
            Algorithm::NistP256Ecdsa,
            Algorithm::NistP256Ecdsa,
            Algorithm::NistP256Ecdsa,
            Algorithm::NistP256Ecdsa,
            KeyRole::EncryptionSubkey,
        ),
        (
            KeyVersion::V4,
            Algorithm::NistP256Ecdh,
            Algorithm::NistP256Ecdsa,
            Algorithm::NistP256Ecdh,
            Algorithm::NistP256Ecdh,
            KeyRole::Primary,
        ),
    ];
    for (version, primary, signing, encryption, invalid, role) in cases {
        assert!(matches!(
            GenerationProfile::new(
                version,
                primary,
                signing,
                encryption,
                CompatibilityAcknowledgement::default()
            ),
            Err(ProfileError::InvalidKeyRole { algorithm, role: actual })
                if algorithm == invalid && actual == role
        ));
    }
}

#[test]
fn legacy_curve25519_identifiers_are_rejected_in_every_v6_role() {
    assert!(matches!(
        GenerationProfile::new(
            KeyVersion::V6,
            Algorithm::LegacyEd25519,
            Algorithm::Ed25519,
            Algorithm::X25519,
            CompatibilityAcknowledgement::acknowledged()
        ),
        Err(ProfileError::LegacyIdentifierInV6 {
            algorithm: Algorithm::LegacyEd25519
        })
    ));
    assert!(matches!(
        GenerationProfile::new(
            KeyVersion::V6,
            Algorithm::Ed25519,
            Algorithm::LegacyEd25519,
            Algorithm::X25519,
            CompatibilityAcknowledgement::acknowledged()
        ),
        Err(ProfileError::LegacyIdentifierInV6 {
            algorithm: Algorithm::LegacyEd25519
        })
    ));
    assert!(matches!(
        GenerationProfile::new(
            KeyVersion::V6,
            Algorithm::Ed25519,
            Algorithm::Ed25519,
            Algorithm::LegacyCurve25519Ecdh,
            CompatibilityAcknowledgement::acknowledged()
        ),
        Err(ProfileError::LegacyIdentifierInV6 {
            algorithm: Algorithm::LegacyCurve25519Ecdh
        })
    ));
}

#[test]
fn unsupported_generation_and_conservative_versions_are_rejected() {
    assert!(matches!(
        GenerationProfile::new(
            KeyVersion::V4,
            Algorithm::Ed25519,
            Algorithm::Ed25519,
            Algorithm::X25519,
            CompatibilityAcknowledgement::default()
        ),
        Err(ProfileError::UnsupportedKeyVersion {
            algorithm: Algorithm::Ed25519,
            key_version: KeyVersion::V4
        })
    ));
    assert!(matches!(
        GenerationProfile::new(
            KeyVersion::V6,
            Algorithm::NistP256Ecdsa,
            Algorithm::NistP256Ecdsa,
            Algorithm::NistP256Ecdh,
            CompatibilityAcknowledgement::default()
        ),
        Err(ProfileError::UnsupportedKeyVersion {
            algorithm: Algorithm::NistP256Ecdsa,
            key_version: KeyVersion::V6
        })
    ));

    for (primary, signing, encryption, invalid) in [
        (
            Algorithm::BrainpoolP256Ecdsa,
            Algorithm::BrainpoolP256Ecdsa,
            Algorithm::BrainpoolP256Ecdh,
            Algorithm::BrainpoolP256Ecdsa,
        ),
        (
            Algorithm::Dsa,
            Algorithm::Dsa,
            Algorithm::Rsa2048,
            Algorithm::Dsa,
        ),
        (
            Algorithm::Rsa2048,
            Algorithm::Rsa2048,
            Algorithm::ElGamal,
            Algorithm::ElGamal,
        ),
    ] {
        assert!(matches!(
            GenerationProfile::new(
                KeyVersion::V4,
                primary,
                signing,
                encryption,
                CompatibilityAcknowledgement::acknowledged()
            ),
            Err(ProfileError::GenerationNotAllowed { algorithm }) if algorithm == invalid
        ));
    }
}

#[test]
fn weak_algorithm_policy_is_explicit_and_cannot_be_silently_relaxed() {
    let policy = SecurityPolicy::default();
    assert_eq!(policy.default_signature_hash, HashAlgorithm::Sha256);
    assert_eq!(
        policy.default_symmetric_algorithm,
        SymmetricAlgorithm::Aes256
    );
    assert_eq!(
        policy.validate_new_signature(HashAlgorithm::Md5),
        Err(SecurityPolicyError::WeakSignatureHash {
            algorithm: HashAlgorithm::Md5
        })
    );
    assert_eq!(
        policy.validate_new_signature(HashAlgorithm::Sha1),
        Err(SecurityPolicyError::WeakSignatureHash {
            algorithm: HashAlgorithm::Sha1
        })
    );
    policy
        .validate_new_signature(HashAlgorithm::Sha256)
        .unwrap();

    for algorithm in [
        SymmetricAlgorithm::Idea,
        SymmetricAlgorithm::TripleDes,
        SymmetricAlgorithm::Cast5,
        SymmetricAlgorithm::Blowfish,
    ] {
        assert_eq!(
            policy.validate_new_encryption(algorithm),
            Err(SecurityPolicyError::LegacySymmetricAlgorithm { algorithm })
        );
        let decision = policy.legacy_decryption(algorithm);
        assert_eq!(decision.disposition, LegacyDisposition::AllowWithWarning);
        assert_eq!(
            decision.warning,
            Some(LegacyAlgorithmWarning::LegacySymmetricCipher(algorithm))
        );
    }
    policy
        .validate_new_encryption(SymmetricAlgorithm::Aes256)
        .unwrap();

    for (algorithm, disposition) in [
        (HashAlgorithm::Md5, LegacyDisposition::Reject),
        (HashAlgorithm::Sha1, LegacyDisposition::AllowWithWarning),
    ] {
        let decision = policy.legacy_verification(algorithm);
        assert_eq!(decision.disposition, disposition);
        assert_eq!(
            decision.warning,
            Some(LegacyAlgorithmWarning::WeakSignatureHash(algorithm))
        );
    }

    let mut explicitly_changed = policy.clone();
    explicitly_changed.legacy_sha1_verification = LegacyDisposition::Allow;
    let decision = explicitly_changed.legacy_verification(HashAlgorithm::Sha1);
    assert_eq!(decision.disposition, LegacyDisposition::Allow);
    assert!(decision.warning.is_some());
    explicitly_changed.legacy_sha1_verification = LegacyDisposition::Reject;
    let decision = explicitly_changed.legacy_verification(HashAlgorithm::Sha1);
    assert_eq!(decision.disposition, LegacyDisposition::Reject);
    assert!(decision.warning.is_some());
}

#[test]
fn brainpool_dsa_and_elgamal_are_conservative_legacy_or_parsing_candidates() {
    let registry = CapabilityRegistry::baseline();
    for algorithm in Algorithm::ALL
        .into_iter()
        .filter(|algorithm| algorithm.is_brainpool())
    {
        let entry = registry
            .entry(algorithm, Backend::Software, KeyVersion::V4)
            .unwrap();
        assert!(entry.can_import && entry.can_export_public);
        assert!(!entry.can_generate && !entry.can_export_private);
        assert!(!entry.can_sign && !entry.can_verify && !entry.can_encrypt && !entry.can_decrypt);
    }

    let dsa = registry
        .entry(Algorithm::Dsa, Backend::Software, KeyVersion::V4)
        .unwrap();
    assert!(dsa.can_verify && !dsa.can_sign && !dsa.can_generate);
    assert!(dsa.is_deprecated && dsa.is_generation_deprecated);

    let elgamal = registry
        .entry(Algorithm::ElGamal, Backend::Software, KeyVersion::V4)
        .unwrap();
    assert!(elgamal.can_import && elgamal.can_export_public);
    assert!(!elgamal.can_decrypt && !elgamal.can_encrypt && !elgamal.can_generate);
    assert!(!elgamal.can_use_as_encryption_subkey && elgamal.is_deprecated);
}
