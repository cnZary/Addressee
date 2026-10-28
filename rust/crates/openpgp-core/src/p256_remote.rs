use std::{
    fmt,
    sync::{Arc, Mutex},
};

use pgp::{
    composed::PlainSessionKey,
    crypto::{
        checksum, ecc_curve::ECCCurve, ecdh, hash::HashAlgorithm, public_key::PublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::{PubKeyInner, PublicKey, PublicSubkey},
    types::{
        DecryptionKey, EcdhPublicParams, EcdsaPublicParams, EskType, Fingerprint, KeyDetails,
        KeyId, KeyVersion, Password, PkeskBytes, PublicParams, SignatureBytes, SigningKey,
        Timestamp,
    },
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::RemoteKeyFailure;

pub trait P256Operations: Send + Sync {
    fn sign_sha256(&self, reference: &str, digest: &[u8]) -> Result<Vec<u8>, RemoteKeyFailure>;

    fn ecdh(
        &self,
        reference: &str,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RemoteKeyFailure>;
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum P256RemoteError {
    #[error("the remote key reference is invalid")]
    InvalidReference,
    #[error("the key creation time is outside the OpenPGP timestamp range")]
    InvalidCreationTime,
    #[error("the P-256 public point is invalid")]
    InvalidPublicKey,
    #[error("only the matching v4 P-256 component role is supported")]
    UnsupportedComponent,
    #[error("P-256 hardware signing requires SHA-256")]
    UnsupportedHash,
    #[error("the SHA-256 digest must contain exactly 32 bytes")]
    InvalidDigestLength,
    #[error("the remote operation is not valid for this component role")]
    InvalidOperation,
    #[error("the provider did not return a valid raw P-256 ECDSA signature")]
    InvalidSignature,
    #[error("the PKESK input does not match the v4 P-256 recipient")]
    InvalidCiphertext,
    #[error("the provider did not return a 32-byte P-256 shared secret")]
    InvalidSharedSecret,
    #[error("the recovered session-key framing is invalid")]
    InvalidSessionKey,
    #[error("the remote P-256 operation failed")]
    Provider(RemoteKeyFailure),
}

impl From<P256RemoteError> for pgp::errors::Error {
    fn from(error: P256RemoteError) -> Self {
        error.to_string().into()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ComponentRole {
    Signing,
    Encryption,
}

pub struct P256RemoteKey {
    reference: String,
    public: PublicKey,
    role: ComponentRole,
    operations: Arc<dyn P256Operations>,
    failure: Arc<Mutex<RemoteKeyFailure>>,
}

impl P256RemoteKey {
    pub fn new_signing(
        reference: String,
        public_key_x963: &[u8],
        created_at: u64,
        operations: Arc<dyn P256Operations>,
        failure: Arc<Mutex<RemoteKeyFailure>>,
    ) -> Result<Self, P256RemoteError> {
        let key = p256::PublicKey::from_sec1_bytes(public_key_x963)
            .map_err(|_| P256RemoteError::InvalidPublicKey)?;
        let public = public_key(
            PublicKeyAlgorithm::ECDSA,
            PublicParams::ECDSA(EcdsaPublicParams::P256 { key }),
            created_at,
        )?;
        Self::from_public(
            reference,
            public,
            ComponentRole::Signing,
            operations,
            failure,
        )
    }

    pub fn new_encryption(
        reference: String,
        public_key_x963: &[u8],
        created_at: u64,
        operations: Arc<dyn P256Operations>,
        failure: Arc<Mutex<RemoteKeyFailure>>,
    ) -> Result<Self, P256RemoteError> {
        let p = p256::PublicKey::from_sec1_bytes(public_key_x963)
            .map_err(|_| P256RemoteError::InvalidPublicKey)?;
        let public = public_key(
            PublicKeyAlgorithm::ECDH,
            PublicParams::ECDH(EcdhPublicParams::P256 {
                p,
                hash: HashAlgorithm::Sha256,
                alg_sym: SymmetricKeyAlgorithm::AES128,
            }),
            created_at,
        )?;
        Self::from_public(
            reference,
            public,
            ComponentRole::Encryption,
            operations,
            failure,
        )
    }

    pub fn from_signing_component(
        reference: String,
        component: &PublicSubkey,
        operations: Arc<dyn P256Operations>,
        failure: Arc<Mutex<RemoteKeyFailure>>,
    ) -> Result<Self, P256RemoteError> {
        let public = copy_component(component)?;
        Self::from_public(
            reference,
            public,
            ComponentRole::Signing,
            operations,
            failure,
        )
    }

    pub fn from_encryption_component(
        reference: String,
        component: &PublicSubkey,
        operations: Arc<dyn P256Operations>,
        failure: Arc<Mutex<RemoteKeyFailure>>,
    ) -> Result<Self, P256RemoteError> {
        let public = copy_component(component)?;
        Self::from_public(
            reference,
            public,
            ComponentRole::Encryption,
            operations,
            failure,
        )
    }

    fn from_public(
        reference: String,
        public: PublicKey,
        role: ComponentRole,
        operations: Arc<dyn P256Operations>,
        failure: Arc<Mutex<RemoteKeyFailure>>,
    ) -> Result<Self, P256RemoteError> {
        if reference.is_empty() || reference.len() > 1024 {
            return Err(P256RemoteError::InvalidReference);
        }
        if public.version() != KeyVersion::V4 {
            return Err(P256RemoteError::UnsupportedComponent);
        }
        match (role, public.algorithm(), public.public_params()) {
            (
                ComponentRole::Signing,
                PublicKeyAlgorithm::ECDSA,
                PublicParams::ECDSA(EcdsaPublicParams::P256 { .. }),
            ) => {}
            (
                ComponentRole::Encryption,
                PublicKeyAlgorithm::ECDH,
                PublicParams::ECDH(EcdhPublicParams::P256 { hash, alg_sym, .. }),
            ) => {
                if !matches!(
                    hash,
                    HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512
                ) || !matches!(
                    alg_sym,
                    SymmetricKeyAlgorithm::AES128
                        | SymmetricKeyAlgorithm::AES192
                        | SymmetricKeyAlgorithm::AES256
                ) {
                    return Err(P256RemoteError::UnsupportedComponent);
                }
            }
            _ => return Err(P256RemoteError::UnsupportedComponent),
        }
        Ok(Self {
            reference,
            public,
            role,
            operations,
            failure,
        })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }

    pub fn has_public_key(&self, public_key_x963: &[u8]) -> bool {
        let Ok(actual) = p256::PublicKey::from_sec1_bytes(public_key_x963) else {
            return false;
        };
        match (self.role, self.public.public_params()) {
            (ComponentRole::Signing, PublicParams::ECDSA(EcdsaPublicParams::P256 { key })) => {
                *key == actual
            }
            (ComponentRole::Encryption, PublicParams::ECDH(EcdhPublicParams::P256 { p, .. })) => {
                *p == actual
            }
            _ => false,
        }
    }

    pub fn public_subkey(&self) -> pgp::errors::Result<PublicSubkey> {
        PublicSubkey::from_inner(PubKeyInner::new(
            self.public.version(),
            self.public.algorithm(),
            self.public.created_at(),
            self.public.legacy_v3_expiration_days(),
            self.public.public_params().clone(),
        )?)
    }

    pub fn failure_kind(&self) -> RemoteKeyFailure {
        self.failure
            .lock()
            .map_or(RemoteKeyFailure::Unavailable, |failure| *failure)
    }

    fn begin_operation(&self) {
        if let Ok(mut failure) = self.failure.lock() {
            *failure = RemoteKeyFailure::Unavailable;
        }
    }

    fn fail<T>(&self, failure: RemoteKeyFailure) -> Result<T, P256RemoteError> {
        if let Ok(mut current) = self.failure.lock() {
            *current = failure;
        }
        Err(P256RemoteError::Provider(failure))
    }

    fn sign_digest(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<SignatureBytes, P256RemoteError> {
        self.begin_operation();
        if self.role != ComponentRole::Signing {
            return Err(P256RemoteError::InvalidOperation);
        }
        if hash != HashAlgorithm::Sha256 {
            return Err(P256RemoteError::UnsupportedHash);
        }
        if data.len() != 32 {
            return Err(P256RemoteError::InvalidDigestLength);
        }
        let raw = match self.operations.sign_sha256(&self.reference, data) {
            Ok(signature) => signature,
            Err(failure) => return self.fail(failure),
        };
        let signature = p256::ecdsa::Signature::from_slice(&raw)
            .map_err(|_| P256RemoteError::InvalidSignature)?;
        let raw = signature.to_bytes();
        let (r, s) = raw.split_at(32);
        Ok(SignatureBytes::Mpis(vec![
            pgp::types::Mpi::from_slice(r),
            pgp::types::Mpi::from_slice(s),
        ]))
    }

    fn decrypt_session_key(
        &self,
        values: &PkeskBytes,
        typ: EskType,
    ) -> Result<PlainSessionKey, P256RemoteError> {
        self.begin_operation();
        if self.role != ComponentRole::Encryption || !matches!(typ, EskType::V3_4) {
            return Err(P256RemoteError::InvalidOperation);
        }
        let PublicParams::ECDH(EcdhPublicParams::P256 { hash, alg_sym, .. }) =
            self.public.public_params()
        else {
            return Err(P256RemoteError::UnsupportedComponent);
        };
        let PkeskBytes::Ecdh {
            public_point,
            encrypted_session_key,
        } = values
        else {
            return Err(P256RemoteError::InvalidCiphertext);
        };
        let point = public_point.as_ref();
        if point.len() != 65 || point.first() != Some(&0x04) {
            return Err(P256RemoteError::InvalidCiphertext);
        }
        p256::PublicKey::from_sec1_bytes(point).map_err(|_| P256RemoteError::InvalidCiphertext)?;
        if encrypted_session_key.len() < 16 || !encrypted_session_key.len().is_multiple_of(8) {
            return Err(P256RemoteError::InvalidCiphertext);
        }
        let secret = match self.operations.ecdh(&self.reference, point) {
            Ok(secret) => secret,
            Err(failure) => return self.fail(failure),
        };
        if secret.len() != 32 {
            return Err(P256RemoteError::InvalidSharedSecret);
        }
        let plain = ecdh::derive_session_key(
            secret.as_slice(),
            encrypted_session_key,
            encrypted_session_key.len(),
            ECCCurve::P256,
            *hash,
            *alg_sym,
            self.public.fingerprint().as_bytes(),
        )
        .map_err(|_| P256RemoteError::InvalidSessionKey)?;
        if plain.len() < 3 {
            return Err(P256RemoteError::InvalidSessionKey);
        }
        let sym_alg = SymmetricKeyAlgorithm::from(plain[0]);
        if matches!(
            sym_alg,
            SymmetricKeyAlgorithm::Plaintext
                | SymmetricKeyAlgorithm::Private10
                | SymmetricKeyAlgorithm::Other(_)
        ) {
            return Err(P256RemoteError::InvalidSessionKey);
        }
        let key_size = sym_alg.key_size();
        if plain.len() != key_size + 3 {
            return Err(P256RemoteError::InvalidSessionKey);
        }
        let key = &plain[1..=key_size];
        checksum::simple([plain[key_size + 1], plain[key_size + 2]], key)
            .map_err(|_| P256RemoteError::InvalidSessionKey)?;
        Ok(PlainSessionKey::V3_4 {
            key: key.into(),
            sym_alg,
        })
    }
}

fn public_key(
    algorithm: PublicKeyAlgorithm,
    parameters: PublicParams,
    created_at: u64,
) -> Result<PublicKey, P256RemoteError> {
    let created_at = u32::try_from(created_at).map_err(|_| P256RemoteError::InvalidCreationTime)?;
    let inner = PubKeyInner::new(
        KeyVersion::V4,
        algorithm,
        Timestamp::from_secs(created_at),
        None,
        parameters,
    )
    .map_err(|_| P256RemoteError::InvalidPublicKey)?;
    PublicKey::from_inner(inner).map_err(|_| P256RemoteError::InvalidPublicKey)
}

fn copy_component(component: &PublicSubkey) -> Result<PublicKey, P256RemoteError> {
    let inner = PubKeyInner::new(
        component.version(),
        component.algorithm(),
        component.created_at(),
        component.legacy_v3_expiration_days(),
        component.public_params().clone(),
    )
    .map_err(|_| P256RemoteError::InvalidPublicKey)?;
    PublicKey::from_inner(inner).map_err(|_| P256RemoteError::InvalidPublicKey)
}

impl fmt::Debug for P256RemoteKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("P256RemoteKey")
            .field("role", &self.role)
            .field("fingerprint", &self.public.fingerprint())
            .finish_non_exhaustive()
    }
}

impl KeyDetails for P256RemoteKey {
    fn version(&self) -> KeyVersion {
        self.public.version()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.public.legacy_key_id()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.public.fingerprint()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.public.algorithm()
    }

    fn created_at(&self) -> Timestamp {
        self.public.created_at()
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.public.legacy_v3_expiration_days()
    }

    fn public_params(&self) -> &PublicParams {
        self.public.public_params()
    }
}

impl SigningKey for P256RemoteKey {
    fn sign(
        &self,
        _key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<SignatureBytes> {
        self.sign_digest(hash, data).map_err(Into::into)
    }

    fn hash_alg(&self) -> HashAlgorithm {
        self.public.public_params().hash_alg()
    }
}

impl DecryptionKey for P256RemoteKey {
    fn decrypt(
        &self,
        _key_pw: &Password,
        values: &PkeskBytes,
        typ: EskType,
    ) -> pgp::errors::Result<pgp::errors::Result<PlainSessionKey>> {
        self.decrypt_session_key(values, typ)
            .map(Ok)
            .map_err(Into::into)
    }
}
