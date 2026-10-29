use std::io::Cursor;

use openpgp_core::{
    EncryptionRequest, FullFingerprint, MessageError, MessageService, SigningKeyRequest,
};
use openpgp_policy::SecurityPolicy;
use zeroize::Zeroizing;

use crate::{
    AddresseeError, CleartextVerificationFfi, DecryptedMessageFfi, DecryptedTextFfi,
    EncryptionConfigFfi, MessageFormatFfi, SignEncryptRequestFfi, SignEncryptTextRequestFfi,
    SignatureArtifactFfi, VerificationOutcomeFfi, VerificationResultFfi,
};

use super::OpenPgpEngine;

#[uniffi::export]
impl OpenPgpEngine {
    pub fn sign_detached(
        &self,
        signing_key: String,
        password: String,
        at_unix_seconds: u64,
        data: Vec<u8>,
        format: MessageFormatFfi,
    ) -> Result<SignatureArtifactFfi, AddresseeError> {
        let fingerprint = FullFingerprint::from_hex(&signing_key)?;
        let password = Zeroizing::new(password);
        let mut artifact = Vec::new();
        let metadata = self.with_service(|service| {
            service.sign_detached(
                &fingerprint,
                &password,
                at_unix_seconds,
                Cursor::new(data),
                &mut artifact,
                format.into(),
            )
        })??;
        Ok(SignatureArtifactFfi {
            metadata: metadata.into(),
            artifact,
        })
    }

    pub fn sign_attached(
        &self,
        signing_key: String,
        password: String,
        at_unix_seconds: u64,
        data: Vec<u8>,
        format: MessageFormatFfi,
    ) -> Result<SignatureArtifactFfi, AddresseeError> {
        let fingerprint = FullFingerprint::from_hex(&signing_key)?;
        let password = Zeroizing::new(password);
        let mut artifact = Vec::new();
        let metadata = self.with_service(|service| {
            service.sign_attached(
                &fingerprint,
                &password,
                at_unix_seconds,
                Cursor::new(data),
                &mut artifact,
                format.into(),
            )
        })??;
        Ok(SignatureArtifactFfi {
            metadata: metadata.into(),
            artifact,
        })
    }

    pub fn sign_cleartext(
        &self,
        signing_key: String,
        password: String,
        at_unix_seconds: u64,
        text: String,
    ) -> Result<SignatureArtifactFfi, AddresseeError> {
        let fingerprint = FullFingerprint::from_hex(&signing_key)?;
        let password = Zeroizing::new(password);
        let mut artifact = Vec::new();
        let metadata = self.with_service(|service| {
            service.sign_cleartext(
                &fingerprint,
                &password,
                at_unix_seconds,
                &text,
                &mut artifact,
            )
        })??;
        Ok(SignatureArtifactFfi {
            metadata: metadata.into(),
            artifact,
        })
    }

    pub fn verify_detached(
        &self,
        data: Vec<u8>,
        signature: Vec<u8>,
        at_unix_seconds: u64,
    ) -> Result<VerificationOutcomeFfi, AddresseeError> {
        let outcome = self.with_service(|service| {
            service.verify_detached(Cursor::new(data), &signature, at_unix_seconds)
        })??;
        Ok(outcome.into())
    }

    pub fn verify_attached(
        &self,
        input: Vec<u8>,
        at_unix_seconds: u64,
    ) -> Result<VerificationResultFfi, AddresseeError> {
        let mut plaintext = Vec::new();
        let outcome = self.with_service(|service| {
            service.verify_attached(Cursor::new(input), &mut plaintext, at_unix_seconds)
        })??;
        let may_release = matches!(
            outcome.status,
            openpgp_core::VerificationStatus::Unsigned | openpgp_core::VerificationStatus::Valid
        );
        Ok(VerificationResultFfi {
            outcome: outcome.into(),
            plaintext: may_release.then_some(plaintext),
        })
    }

    pub fn verify_cleartext(
        &self,
        input: Vec<u8>,
        at_unix_seconds: u64,
    ) -> Result<CleartextVerificationFfi, AddresseeError> {
        let outcome =
            self.with_service(|service| service.verify_cleartext(&input, at_unix_seconds))??;
        Ok(outcome.into())
    }

    pub fn encrypt(
        &self,
        recipients: Vec<String>,
        at_unix_seconds: u64,
        config: EncryptionConfigFfi,
        data: Vec<u8>,
        format: MessageFormatFfi,
    ) -> Result<Vec<u8>, AddresseeError> {
        let recipients = parse_fingerprints(recipients)?;
        let mut output = Vec::new();
        self.with_service(|service| {
            service.encrypt(
                &recipients,
                at_unix_seconds,
                config.into(),
                Cursor::new(data),
                &mut output,
                format.into(),
            )
        })??;
        Ok(output)
    }

    pub fn sign_and_encrypt(
        &self,
        request: SignEncryptRequestFfi,
    ) -> Result<SignatureArtifactFfi, AddresseeError> {
        let SignEncryptRequestFfi {
            signing_key,
            password,
            recipients,
            at_unix_seconds,
            config,
            data,
            format,
        } = request;
        let signing_key = FullFingerprint::from_hex(&signing_key)?;
        let password = Zeroizing::new(password);
        let recipients = parse_fingerprints(recipients)?;
        let mut artifact = Vec::new();
        let metadata = self.with_service(|service| {
            service.sign_and_encrypt(
                SigningKeyRequest::new(&signing_key, &password),
                EncryptionRequest::new(&recipients, at_unix_seconds, config.into()),
                Cursor::new(data),
                &mut artifact,
                format.into(),
            )
        })??;
        Ok(SignatureArtifactFfi {
            metadata: metadata.into(),
            artifact,
        })
    }

    pub fn encrypt_text(
        &self,
        recipients: Vec<String>,
        at_unix_seconds: u64,
        config: EncryptionConfigFfi,
        text: String,
        format: MessageFormatFfi,
    ) -> Result<Vec<u8>, AddresseeError> {
        let recipients = parse_fingerprints(recipients)?;
        let mut output = Vec::new();
        self.with_service(|service| {
            service.encrypt_text(
                &recipients,
                at_unix_seconds,
                config.into(),
                &text,
                &mut output,
                format.into(),
            )
        })??;
        Ok(output)
    }

    pub fn sign_and_encrypt_text(
        &self,
        request: SignEncryptTextRequestFfi,
    ) -> Result<SignatureArtifactFfi, AddresseeError> {
        let SignEncryptTextRequestFfi {
            signing_key,
            password,
            recipients,
            at_unix_seconds,
            config,
            text,
            format,
        } = request;
        let signing_key = FullFingerprint::from_hex(&signing_key)?;
        let password = Zeroizing::new(password);
        let recipients = parse_fingerprints(recipients)?;
        let mut artifact = Vec::new();
        let metadata = self.with_service(|service| {
            service.sign_and_encrypt_text(
                SigningKeyRequest::new(&signing_key, &password),
                EncryptionRequest::new(&recipients, at_unix_seconds, config.into()),
                &text,
                &mut artifact,
                format.into(),
            )
        })??;
        Ok(SignatureArtifactFfi {
            metadata: metadata.into(),
            artifact,
        })
    }

    pub fn decrypt(
        &self,
        decryption_key: String,
        password: String,
        at_unix_seconds: u64,
        input: Vec<u8>,
    ) -> Result<DecryptedMessageFfi, AddresseeError> {
        let decryption_key = FullFingerprint::from_hex(&decryption_key)?;
        let password = Zeroizing::new(password);
        let decrypted = self.with_service(|service| {
            service.decrypt(
                &decryption_key,
                &password,
                at_unix_seconds,
                Cursor::new(input),
            )
        })??;
        Ok(decrypted.into())
    }

    pub fn decrypt_text(
        &self,
        decryption_key: String,
        password: String,
        at_unix_seconds: u64,
        input: Vec<u8>,
    ) -> Result<DecryptedTextFfi, AddresseeError> {
        let decryption_key = FullFingerprint::from_hex(&decryption_key)?;
        let password = Zeroizing::new(password);
        let decrypted = self.with_service(|service| {
            service.decrypt_text(
                &decryption_key,
                &password,
                at_unix_seconds,
                Cursor::new(input),
            )
        })??;
        Ok(decrypted.into())
    }
}

impl OpenPgpEngine {
    pub(crate) fn with_service<R>(
        &self,
        operation: impl FnOnce(MessageService<'_>) -> R,
    ) -> Result<R, AddresseeError> {
        let keys = self.lock()?;
        let providers = self.lock_remote_read()?;
        let _operation = self
            .message_operations
            .lock()
            .map_err(|_| AddresseeError::InternalFailure)?;
        let service = MessageService::new(&keys, SecurityPolicy::default());
        let service = if providers.is_empty() {
            service
        } else {
            service.with_remote_resolver(&*providers)
        };
        Ok(operation(service))
    }
}

fn parse_fingerprints(recipients: Vec<String>) -> Result<Vec<FullFingerprint>, AddresseeError> {
    recipients
        .into_iter()
        .map(|recipient| FullFingerprint::from_hex(&recipient).map_err(Into::into))
        .collect()
}

impl From<MessageError> for AddresseeError {
    fn from(error: MessageError) -> Self {
        match error {
            MessageError::EmptyRecipients
            | MessageError::EmptyInput
            | MessageError::TrailingData
            | MessageError::LeadingData
            | MessageError::MixedKeyring
            | MessageError::TimestampOutOfRange { .. }
            | MessageError::AmbiguousSigner
            | MessageError::InvalidTextLineEnding
            | MessageError::InvalidUtf8
            | MessageError::OpenPgp(_) => Self::InvalidInput,
            MessageError::NotEncrypted => Self::NotEncrypted,
            MessageError::NoUsableKey { .. } => Self::UnsupportedOperation,
            MessageError::RemoteKey {
                failure: openpgp_core::RemoteKeyFailure::Cancelled,
                ..
            } => Self::OperationCancelled,
            MessageError::RemoteKey { .. } => Self::RemoteKeyUnavailable,
            MessageError::TextLimitExceeded { .. }
            | MessageError::CleartextLimitExceeded { .. }
            | MessageError::SignatureLimitExceeded { .. }
            | MessageError::PlaintextLimitExceeded { .. }
            | MessageError::CompressionLimitExceeded { .. } => Self::ResourceLimit,
            MessageError::UnsupportedHashAlgorithm(_)
            | MessageError::UnsupportedSymmetricAlgorithm(_)
            | MessageError::UnidentifiedSymmetricAlgorithm => Self::UnsupportedOperation,
            MessageError::Key(error) => error.into(),
            MessageError::SecurityPolicy(_) => Self::UnsupportedOperation,
            MessageError::Io(_) => Self::InternalFailure,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::{
        DecryptionStatusFfi, ExportPolicyFfi, GenerationProfileFfi, IdentityTrustFfi,
        VerificationStatusFfi,
    };

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_secs()
    }

    #[test]
    fn remote_provider_failures_have_a_distinct_public_error() {
        let fingerprint = FullFingerprint::from_hex("0123456789ABCDEF0123456789ABCDEF01234567")
            .expect("synthetic fingerprint");
        let error = AddresseeError::from(MessageError::RemoteKey {
            fingerprint: fingerprint.clone(),
            component_fingerprint: fingerprint,
            operation: openpgp_core::MessageOperation::Sign,
            failure: openpgp_core::RemoteKeyFailure::Unavailable,
        });
        assert_eq!(error, AddresseeError::RemoteKeyUnavailable);
        assert_eq!(
            error.to_string(),
            "The private-key provider could not complete the operation"
        );
    }

    #[test]
    fn message_roundtrip_distinguishes_valid_unknown_and_missing_keys() {
        let signer = OpenPgpEngine::new();
        let signer_key = signer
            .generate_key(
                GenerationProfileFfi::ModernV6,
                "FFI Signer <signer@example.invalid>".to_owned(),
                "signer-test-only".to_owned(),
                ExportPolicyFfi::Disabled,
            )
            .unwrap();
        let recipient = OpenPgpEngine::new();
        let recipient_key = recipient
            .generate_key(
                GenerationProfileFfi::ModernV6,
                "FFI Recipient <recipient@example.invalid>".to_owned(),
                "recipient-test-only".to_owned(),
                ExportPolicyFfi::Disabled,
            )
            .unwrap();
        let at = now();
        let data = b"FFI signed and encrypted message";
        let password = "signer-test-only";
        let fingerprint = signer_key.summary.fingerprint.clone();

        let detached = signer
            .sign_detached(
                fingerprint.clone(),
                password.to_owned(),
                at,
                data.to_vec(),
                MessageFormatFfi::Armored,
            )
            .unwrap();
        assert!(matches!(
            signer
                .verify_detached(data.to_vec(), detached.artifact.clone(), at)
                .unwrap()
                .status,
            VerificationStatusFfi::Valid
        ));
        assert!(matches!(
            recipient
                .verify_detached(data.to_vec(), detached.artifact, at)
                .unwrap()
                .status,
            VerificationStatusFfi::UnknownSigner
        ));

        signer
            .import_public_key(recipient_key.public_certificate)
            .unwrap();
        let encrypted = signer
            .sign_and_encrypt(SignEncryptRequestFfi {
                signing_key: fingerprint.clone(),
                password: password.to_owned(),
                recipients: vec![
                    recipient_key.summary.fingerprint.clone(),
                    fingerprint.clone(),
                ],
                at_unix_seconds: at,
                config: EncryptionConfigFfi::SeipdV2 {
                    cipher: crate::MessageCipherFfi::Aes256,
                    mode: crate::AeadModeFfi::Ocb,
                },
                data: data.to_vec(),
                format: MessageFormatFfi::Armored,
            })
            .unwrap();
        let valid = signer
            .decrypt_text(
                fingerprint.clone(),
                password.to_owned(),
                at,
                encrypted.artifact.clone(),
            )
            .unwrap();
        assert_eq!(valid.report.status, DecryptionStatusFfi::Valid);
        assert_eq!(
            valid.text.as_deref(),
            Some("FFI signed and encrypted message")
        );

        let unknown = recipient
            .decrypt_text(
                recipient_key.summary.fingerprint.clone(),
                "recipient-test-only".to_owned(),
                at,
                encrypted.artifact.clone(),
            )
            .unwrap();
        assert!(matches!(
            unknown.report.status,
            DecryptionStatusFfi::UnknownSigner
        ));
        assert!(unknown.report.may_commit_staging);
        assert_eq!(
            unknown.text.as_deref(),
            Some("FFI signed and encrypted message")
        );
        assert!(matches!(unknown.report.trust, IdentityTrustFfi::Unknown));

        let eavesdropper = OpenPgpEngine::new();
        let eavesdropper_key = eavesdropper
            .generate_key(
                GenerationProfileFfi::ModernV6,
                "FFI Eavesdropper <eavesdropper@example.invalid>".to_owned(),
                "eavesdropper-test-only".to_owned(),
                ExportPolicyFfi::Disabled,
            )
            .unwrap();
        let missing = eavesdropper
            .decrypt_text(
                eavesdropper_key.summary.fingerprint.clone(),
                "eavesdropper-test-only".to_owned(),
                now(),
                encrypted.artifact.clone(),
            )
            .unwrap();
        assert!(matches!(
            missing.report.status,
            DecryptionStatusFfi::DecryptionFailed
        ));
        assert!(!missing.report.may_commit_staging);
        assert!(missing.text.is_none());

        let public_only = signer.decrypt_text(
            recipient_key.summary.fingerprint.clone(),
            "recipient-test-only".to_owned(),
            at,
            encrypted.artifact,
        );
        assert!(matches!(public_only, Err(AddresseeError::PublicKeyOnly)));
    }
}
