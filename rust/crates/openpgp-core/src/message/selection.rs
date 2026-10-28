use std::cell::Cell;

use openpgp_policy::HashAlgorithm as PolicyHashAlgorithm;
use pgp::{
    composed::{SignedPublicSubKey, SignedSecretSubKey},
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    types::{
        DecryptionKey, Fingerprint, KeyDetails, KeyId, KeyVersion, Password, PublicParams,
        SignatureBytes, SigningKey, Timestamp,
    },
};

use crate::{
    AlgorithmMetadata, CertificateValidity, FullFingerprint, KeyUsage, KeyValidity, MessageError,
    MessageOperation, MessageService, RemoteKeyFailure, RemotePrivateKeyResolver, metadata,
};

#[derive(Debug)]
enum SigningPrivateKey<'a> {
    Software(&'a SignedSecretSubKey),
    Remote(&'a dyn SigningKey),
}

pub(crate) struct SigningSelection<'a> {
    pub certificate_fingerprint: FullFingerprint,
    pub key: &'a SignedPublicSubKey,
    private: SigningPrivateKey<'a>,
    remote_resolver: Option<&'a dyn RemotePrivateKeyResolver>,
    remote_failed: Cell<bool>,
    pub algorithm: AlgorithmMetadata,
    pub hash_algorithm: HashAlgorithm,
    pub policy_hash_algorithm: PolicyHashAlgorithm,
}

impl std::fmt::Debug for SigningSelection<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SigningSelection")
            .field("certificate_fingerprint", &self.certificate_fingerprint)
            .field("key", &self.key)
            .field("private", &self.private)
            .field("algorithm", &self.algorithm)
            .field("hash_algorithm", &self.hash_algorithm)
            .field("policy_hash_algorithm", &self.policy_hash_algorithm)
            .finish_non_exhaustive()
    }
}

impl SigningSelection<'_> {
    pub fn password(&self, software_password: &str) -> Password {
        match self.private {
            SigningPrivateKey::Software(_) => super::password_value(software_password),
            SigningPrivateKey::Remote(_) => Password::empty(),
        }
    }

    pub fn map_signing_error(&self, error: impl Into<MessageError>) -> MessageError {
        if self.remote_failed.get() {
            self.remote_error()
        } else {
            error.into()
        }
    }

    fn remote_error(&self) -> MessageError {
        let component = FullFingerprint::from_rpgp(&self.key.fingerprint());
        let failure = self
            .remote_resolver
            .map_or(RemoteKeyFailure::Unavailable, |resolver| {
                resolver.failure_kind(
                    &self.certificate_fingerprint,
                    &component,
                    MessageOperation::Sign,
                )
            });
        remote_failure(
            &self.certificate_fingerprint,
            &component,
            MessageOperation::Sign,
            failure,
        )
    }
}

impl KeyDetails for SigningSelection<'_> {
    fn version(&self) -> KeyVersion {
        self.key.version()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.key.legacy_key_id()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.key.fingerprint()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.key.algorithm()
    }

    fn created_at(&self) -> Timestamp {
        self.key.created_at()
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.key.legacy_v3_expiration_days()
    }

    fn public_params(&self) -> &PublicParams {
        self.key.public_params()
    }
}

impl SigningKey for SigningSelection<'_> {
    fn sign(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<SignatureBytes> {
        match &self.private {
            SigningPrivateKey::Software(key) => SigningKey::sign(&key.key, key_pw, hash, data),
            SigningPrivateKey::Remote(key) => {
                let result = key.sign(key_pw, hash, data);
                if result.is_err() {
                    self.remote_failed.set(true);
                }
                result
            }
        }
    }

    fn hash_alg(&self) -> HashAlgorithm {
        self.hash_algorithm
    }
}

pub(crate) struct EncryptionSelection<'a> {
    pub key: &'a SignedPublicSubKey,
}

enum DecryptionPrivateKey<'a> {
    Software(&'a SignedSecretSubKey),
    Remote(RemoteDecryption<'a>),
}

struct RemoteDecryption<'a> {
    resolver: &'a dyn RemotePrivateKeyResolver,
    resolved: Option<Option<&'a dyn DecryptionKey>>,
}

pub(crate) enum DecryptionKeySource<'a> {
    Software(&'a SignedSecretSubKey),
    Remote(&'a dyn DecryptionKey),
}

pub(crate) struct DecryptionSelection<'a> {
    pub certificate_fingerprint: FullFingerprint,
    pub key: &'a SignedPublicSubKey,
    private: DecryptionPrivateKey<'a>,
}

impl<'a> DecryptionSelection<'a> {
    pub fn resolve(&mut self) -> Result<Option<DecryptionKeySource<'a>>, MessageError> {
        let certificate_fingerprint = self.certificate_fingerprint.clone();
        let component_fingerprint = FullFingerprint::from_rpgp(&self.key.fingerprint());
        match &mut self.private {
            DecryptionPrivateKey::Software(key) => Ok(Some(DecryptionKeySource::Software(key))),
            DecryptionPrivateKey::Remote(remote) => {
                if remote.resolved.is_none() {
                    let resolved = remote
                        .resolver
                        .decryption_key(&certificate_fingerprint, &component_fingerprint)
                        .map_err(|_| {
                            remote_failure(
                                &certificate_fingerprint,
                                &component_fingerprint,
                                MessageOperation::Decrypt,
                                remote.resolver.failure_kind(
                                    &certificate_fingerprint,
                                    &component_fingerprint,
                                    MessageOperation::Decrypt,
                                ),
                            )
                        })?;
                    if resolved.is_some_and(|key| !key_details_match(self.key, key)) {
                        return Err(remote_error(
                            &certificate_fingerprint,
                            &component_fingerprint,
                            MessageOperation::Decrypt,
                        ));
                    }
                    remote.resolved = Some(resolved);
                }
                Ok(remote
                    .resolved
                    .unwrap_or(None)
                    .map(DecryptionKeySource::Remote))
            }
        }
    }

    pub fn is_remote(&self) -> bool {
        matches!(self.private, DecryptionPrivateKey::Remote(_))
    }

    pub fn remote_error(&self) -> MessageError {
        let component = FullFingerprint::from_rpgp(&self.key.fingerprint());
        let failure = match &self.private {
            DecryptionPrivateKey::Software(_) => RemoteKeyFailure::Unavailable,
            DecryptionPrivateKey::Remote(remote) => remote.resolver.failure_kind(
                &self.certificate_fingerprint,
                &component,
                MessageOperation::Decrypt,
            ),
        };
        remote_failure(
            &self.certificate_fingerprint,
            &component,
            MessageOperation::Decrypt,
            failure,
        )
    }
}

pub(crate) fn signing_key<'a>(
    service: &MessageService<'a>,
    fingerprint: &FullFingerprint,
    at: u64,
) -> Result<SigningSelection<'a>, MessageError> {
    let certificate = service.keys.rpgp_public_key(fingerprint)?;
    let validity = service.keys.evaluate_validity(fingerprint, at)?;
    let mut remote_candidates = Vec::new();
    if validity.primary.is_valid() {
        for subkey in &certificate.public_subkeys {
            if !signing_valid(&validity, subkey) {
                continue;
            }
            if let Some(secret) = service
                .keys
                .rpgp_secret_subkey(fingerprint, &subkey.key.fingerprint())?
            {
                return signing_selection(service, fingerprint, subkey, secret);
            }
            remote_candidates.push(subkey);
        }
        let has_public_candidates = !remote_candidates.is_empty();
        if let Some(resolver) = service.remote_resolver {
            for subkey in remote_candidates {
                let component_fingerprint = FullFingerprint::from_rpgp(&subkey.key.fingerprint());
                let Some(key) = resolver
                    .signing_key(fingerprint, &component_fingerprint)
                    .map_err(|_| {
                        remote_failure(
                            fingerprint,
                            &component_fingerprint,
                            MessageOperation::Sign,
                            resolver.failure_kind(
                                fingerprint,
                                &component_fingerprint,
                                MessageOperation::Sign,
                            ),
                        )
                    })?
                else {
                    continue;
                };
                if !key_details_match(subkey, key) {
                    return Err(remote_error(
                        fingerprint,
                        &component_fingerprint,
                        MessageOperation::Sign,
                    ));
                }
                return remote_signing_selection(service, fingerprint, subkey, key);
            }
        }
        if has_public_candidates
            && service.remote_resolver.is_none()
            && service.keys.metadata(fingerprint)?.storage == crate::KeyStorage::PublicOnly
        {
            return Err(crate::KeyError::SecretKeyRequired {
                fingerprint: fingerprint.clone(),
            }
            .into());
        }
    }
    Err(MessageError::NoUsableKey {
        fingerprint: fingerprint.clone(),
        operation: MessageOperation::Sign,
    })
}

fn signing_valid(validity: &CertificateValidity, subkey: &SignedPublicSubKey) -> bool {
    component_validity(validity, &subkey.key.fingerprint()).is_some_and(|validity| {
        subkey.key.algorithm().can_sign() && validity.is_valid_for(KeyUsage::Sign)
    })
}

fn signing_selection<'a>(
    service: &MessageService<'a>,
    certificate_fingerprint: &FullFingerprint,
    key: &'a SignedPublicSubKey,
    secret: &'a SignedSecretSubKey,
) -> Result<SigningSelection<'a>, MessageError> {
    make_signing_selection(
        service,
        certificate_fingerprint,
        key,
        SigningPrivateKey::Software(secret),
    )
}

fn remote_signing_selection<'a>(
    service: &MessageService<'a>,
    certificate_fingerprint: &FullFingerprint,
    key: &'a SignedPublicSubKey,
    remote: &'a dyn SigningKey,
) -> Result<SigningSelection<'a>, MessageError> {
    make_signing_selection(
        service,
        certificate_fingerprint,
        key,
        SigningPrivateKey::Remote(remote),
    )
}

fn make_signing_selection<'a>(
    service: &MessageService<'a>,
    certificate_fingerprint: &FullFingerprint,
    key: &'a SignedPublicSubKey,
    private: SigningPrivateKey<'a>,
) -> Result<SigningSelection<'a>, MessageError> {
    let hash_algorithm = key.key.public_params().hash_alg();
    let policy_hash_algorithm = new_hash_algorithm(hash_algorithm)?;
    service
        .security_policy
        .validate_new_signature(policy_hash_algorithm)?;
    let remote_resolver = match private {
        SigningPrivateKey::Software(_) => None,
        SigningPrivateKey::Remote(_) => service.remote_resolver,
    };
    Ok(SigningSelection {
        certificate_fingerprint: certificate_fingerprint.clone(),
        key,
        private,
        remote_resolver,
        remote_failed: Cell::new(false),
        algorithm: metadata::algorithm_metadata(key.key.algorithm(), key.key.public_params())?,
        hash_algorithm,
        policy_hash_algorithm,
    })
}

pub(crate) fn encryption_key<'a>(
    service: &MessageService<'a>,
    fingerprint: &FullFingerprint,
    at: u64,
) -> Result<EncryptionSelection<'a>, MessageError> {
    let certificate = service.keys.rpgp_public_key(fingerprint)?;
    let validity = service.keys.evaluate_validity(fingerprint, at)?;
    if validity.primary.is_valid() {
        for subkey in &certificate.public_subkeys {
            let subkey_fingerprint = subkey.key.fingerprint();
            let Some(subkey_validity) = component_validity(&validity, &subkey_fingerprint) else {
                continue;
            };
            if encryption_valid(subkey_validity) && subkey.key.algorithm().can_encrypt() {
                return Ok(EncryptionSelection { key: subkey });
            }
        }
    }
    Err(MessageError::NoUsableKey {
        fingerprint: fingerprint.clone(),
        operation: MessageOperation::Encrypt,
    })
}

pub(crate) fn decryption_keys<'a>(
    service: &MessageService<'a>,
    fingerprint: &FullFingerprint,
    at: u64,
) -> Result<Vec<DecryptionSelection<'a>>, MessageError> {
    let certificate = service.keys.rpgp_public_key(fingerprint)?;
    let validity = service.keys.evaluate_validity(fingerprint, at)?;
    let mut software = Vec::new();
    let mut remote = Vec::new();
    let mut missing_private = false;
    if validity.primary.is_valid() {
        for subkey in &certificate.public_subkeys {
            let subkey_fingerprint = subkey.key.fingerprint();
            let Some(subkey_validity) = component_validity(&validity, &subkey_fingerprint) else {
                continue;
            };
            if !encryption_valid(subkey_validity) || !subkey.key.algorithm().can_encrypt() {
                continue;
            }
            if let Some(secret) = service
                .keys
                .rpgp_secret_subkey(fingerprint, &subkey_fingerprint)?
            {
                software.push(DecryptionSelection {
                    certificate_fingerprint: fingerprint.clone(),
                    key: subkey,
                    private: DecryptionPrivateKey::Software(secret),
                });
            } else {
                missing_private = true;
                if let Some(resolver) = service.remote_resolver {
                    remote.push(DecryptionSelection {
                        certificate_fingerprint: fingerprint.clone(),
                        key: subkey,
                        private: DecryptionPrivateKey::Remote(RemoteDecryption {
                            resolver,
                            resolved: None,
                        }),
                    });
                }
            }
        }
    }
    software.extend(remote);
    if software.is_empty() {
        if missing_private
            && service.remote_resolver.is_none()
            && service.keys.metadata(fingerprint)?.storage == crate::KeyStorage::PublicOnly
        {
            return Err(crate::KeyError::SecretKeyRequired {
                fingerprint: fingerprint.clone(),
            }
            .into());
        }
        return Err(MessageError::NoUsableKey {
            fingerprint: fingerprint.clone(),
            operation: MessageOperation::Decrypt,
        });
    }
    Ok(software)
}

fn key_details_match<E, A>(expected: &E, actual: &A) -> bool
where
    E: KeyDetails,
    A: KeyDetails + ?Sized,
{
    expected.version() == actual.version()
        && expected.legacy_key_id() == actual.legacy_key_id()
        && expected.fingerprint() == actual.fingerprint()
        && expected.algorithm() == actual.algorithm()
        && expected.created_at() == actual.created_at()
        && expected.legacy_v3_expiration_days() == actual.legacy_v3_expiration_days()
        && expected.public_params() == actual.public_params()
}

pub(crate) fn component_validity<'a>(
    validity: &'a CertificateValidity,
    fingerprint: &Fingerprint,
) -> Option<&'a KeyValidity> {
    validity
        .subkeys
        .iter()
        .find(|subkey| subkey.fingerprint == FullFingerprint::from_rpgp(fingerprint))
}

fn encryption_valid(validity: &KeyValidity) -> bool {
    validity.is_valid()
        && (validity.key_flags.encrypt_communications || validity.key_flags.encrypt_storage)
}

fn remote_error(
    certificate_fingerprint: &FullFingerprint,
    component_fingerprint: &FullFingerprint,
    operation: MessageOperation,
) -> MessageError {
    remote_failure(
        certificate_fingerprint,
        component_fingerprint,
        operation,
        RemoteKeyFailure::Unavailable,
    )
}

fn remote_failure(
    certificate_fingerprint: &FullFingerprint,
    component_fingerprint: &FullFingerprint,
    operation: MessageOperation,
    failure: RemoteKeyFailure,
) -> MessageError {
    MessageError::RemoteKey {
        fingerprint: certificate_fingerprint.clone(),
        component_fingerprint: component_fingerprint.clone(),
        operation,
        failure,
    }
}

pub(crate) fn new_hash_algorithm(
    algorithm: HashAlgorithm,
) -> Result<PolicyHashAlgorithm, MessageError> {
    policy_hash_algorithm(algorithm)
        .ok_or_else(|| MessageError::UnsupportedHashAlgorithm(u8::from(algorithm)))
}

pub(crate) fn policy_hash_algorithm(algorithm: HashAlgorithm) -> Option<PolicyHashAlgorithm> {
    match algorithm {
        HashAlgorithm::Md5 => Some(PolicyHashAlgorithm::Md5),
        HashAlgorithm::Sha1 => Some(PolicyHashAlgorithm::Sha1),
        HashAlgorithm::Ripemd160 => Some(PolicyHashAlgorithm::Ripemd160),
        HashAlgorithm::Sha224 => Some(PolicyHashAlgorithm::Sha224),
        HashAlgorithm::Sha256 => Some(PolicyHashAlgorithm::Sha256),
        HashAlgorithm::Sha384 => Some(PolicyHashAlgorithm::Sha384),
        HashAlgorithm::Sha512 => Some(PolicyHashAlgorithm::Sha512),
        HashAlgorithm::Sha3_256 => Some(PolicyHashAlgorithm::Sha3_256),
        HashAlgorithm::Sha3_512 => Some(PolicyHashAlgorithm::Sha3_512),
        _ => None,
    }
}
