mod decryption;
mod selection;
mod verification;

use std::{
    collections::BTreeSet,
    io::{Read, Write},
    sync::OnceLock,
};

use openpgp_policy::{CapabilityRegistry, SecurityPolicy, SymmetricAlgorithm};
use pgp::{
    composed::{
        ArmorOptions, CleartextSignedMessage, DetachedSignature, Encryption, MessageBuilder,
        SubpacketConfig,
    },
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        sym::SymmetricKeyAlgorithm,
    },
    packet::{DataMode, SignatureConfig, SignatureType, Subpacket, SubpacketData},
    ser::Serialize as _,
    types::{KeyDetails as _, KeyVersion, Password, Timestamp},
};
use zeroize::Zeroizing;

use crate::{
    AeadMode, EncryptionConfig, FullFingerprint, MessageCipher, MessageError, MessageFormat,
    MessageLimits, RemotePrivateKeyResolver, SignatureMetadata, SoftwareKeyStore,
};

use self::selection::SigningSelection;

fn default_capability_registry() -> &'static CapabilityRegistry {
    static REGISTRY: OnceLock<CapabilityRegistry> = OnceLock::new();
    REGISTRY.get_or_init(CapabilityRegistry::baseline)
}

pub struct MessageService<'a> {
    pub(crate) keys: &'a SoftwareKeyStore,
    pub(crate) security_policy: SecurityPolicy,
    pub(crate) capabilities: &'a CapabilityRegistry,
    pub(crate) limits: MessageLimits,
    pub(crate) remote_resolver: Option<&'a dyn RemotePrivateKeyResolver>,
}

impl<'a> MessageService<'a> {
    pub fn new(keys: &'a SoftwareKeyStore, security_policy: SecurityPolicy) -> Self {
        Self {
            keys,
            security_policy,
            capabilities: default_capability_registry(),
            limits: MessageLimits::default(),
            remote_resolver: None,
        }
    }

    pub fn with_limits(
        keys: &'a SoftwareKeyStore,
        security_policy: SecurityPolicy,
        limits: MessageLimits,
    ) -> Self {
        Self {
            keys,
            security_policy,
            capabilities: default_capability_registry(),
            limits,
            remote_resolver: None,
        }
    }

    pub fn with_capability_registry(mut self, capabilities: &'a CapabilityRegistry) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Enables remote private-key operations for this service instance only.
    ///
    /// Software-backed components continue to use the supplied software password. Public-only
    /// components may use the resolver, whose callbacks receive an empty OpenPGP password.
    pub fn with_remote_resolver(mut self, resolver: &'a dyn RemotePrivateKeyResolver) -> Self {
        self.remote_resolver = Some(resolver);
        self
    }

    pub fn limits(&self) -> &MessageLimits {
        &self.limits
    }

    pub fn sign_detached<R: Read, W: Write>(
        &self,
        signing_key: &FullFingerprint,
        password: &str,
        at_unix_seconds: u64,
        data: R,
        signature_output: W,
        format: MessageFormat,
    ) -> Result<SignatureMetadata, MessageError> {
        let selection = selection::signing_key(self, signing_key, at_unix_seconds)?;
        let password = selection.password(password);
        let signature = DetachedSignature::sign_binary_data_with_subpackets(
            rand::thread_rng(),
            &selection,
            &password,
            selection.hash_algorithm,
            data,
            signature_subpacket_config(&selection, at_unix_seconds)?,
        )
        .map_err(|error| selection.map_signing_error(error))?;
        let mut output = signature_output;
        match format {
            MessageFormat::Binary => signature.to_writer(&mut output)?,
            MessageFormat::Armored => signature.to_armored_writer(
                &mut output,
                armor_options(selection.key.version() != pgp::types::KeyVersion::V6),
            )?,
        }
        Ok(signature_metadata(
            &selection,
            signature.signature.created(),
        ))
    }

    pub fn sign_attached<R: Read, W: Write>(
        &self,
        signing_key: &FullFingerprint,
        password: &str,
        at_unix_seconds: u64,
        data: R,
        message_output: W,
        format: MessageFormat,
    ) -> Result<SignatureMetadata, MessageError> {
        let selection = selection::signing_key(self, signing_key, at_unix_seconds)?;
        let password = selection.password(password);
        let mut builder = MessageBuilder::from_reader("payload.bin", data);
        builder.sign_with_subpackets(
            &selection,
            password,
            selection.hash_algorithm,
            signature_subpacket_config(&selection, at_unix_seconds)?,
        );
        let created_at = signature_timestamp(at_unix_seconds)?;
        write_builder(
            builder,
            message_output,
            format,
            selection.key.version() != pgp::types::KeyVersion::V6,
        )
        .map_err(|error| selection.map_signing_error(error))?;
        Ok(signature_metadata(&selection, Some(created_at)))
    }

    pub fn sign_cleartext<W: Write>(
        &self,
        signing_key: &FullFingerprint,
        password: &str,
        at_unix_seconds: u64,
        text: &str,
        output: W,
    ) -> Result<SignatureMetadata, MessageError> {
        if text.len() > self.limits.max_text_bytes {
            return Err(MessageError::TextLimitExceeded {
                limit: self.limits.max_text_bytes,
            });
        }
        let selection = selection::signing_key(self, signing_key, at_unix_seconds)?;
        let password = selection.password(password);
        let (hashed_subpackets, unhashed_subpackets) =
            signature_subpackets(&selection, at_unix_seconds)?;
        let mut config =
            SignatureConfig::from_key(rand::thread_rng(), &selection, SignatureType::Text)?;
        config.hashed_subpackets = hashed_subpackets;
        config.unhashed_subpackets = unhashed_subpackets;
        let cleartext = CleartextSignedMessage::new(text, config, &selection, &password)
            .map_err(|error| selection.map_signing_error(error))?;
        let created_at = cleartext
            .signatures()
            .first()
            .and_then(|signature| signature.created());
        let mut output = output;
        cleartext.to_armored_writer(
            &mut output,
            armor_options(selection.key.version() != pgp::types::KeyVersion::V6),
        )?;
        Ok(signature_metadata(&selection, created_at))
    }

    pub fn encrypt<R: Read, W: Write>(
        &self,
        recipients: &[FullFingerprint],
        at_unix_seconds: u64,
        config: EncryptionConfig,
        data: R,
        output: W,
        format: MessageFormat,
    ) -> Result<(), MessageError> {
        self.encrypt_internal(
            None,
            crate::EncryptionRequest::new(recipients, at_unix_seconds, config),
            data,
            output,
            format,
            DataMode::Binary,
        )
        .map(|_| ())
    }

    pub fn sign_and_encrypt<R: Read, W: Write>(
        &self,
        signing: crate::SigningKeyRequest<'_>,
        encryption: crate::EncryptionRequest<'_>,
        data: R,
        output: W,
        format: MessageFormat,
    ) -> Result<SignatureMetadata, MessageError> {
        self.encrypt_internal(
            Some(signing),
            encryption,
            data,
            output,
            format,
            DataMode::Binary,
        )?
        .ok_or_else(|| MessageError::NoUsableKey {
            fingerprint: signing.fingerprint.clone(),
            operation: crate::MessageOperation::Sign,
        })
    }

    pub fn encrypt_text<W: Write>(
        &self,
        recipients: &[FullFingerprint],
        at_unix_seconds: u64,
        config: EncryptionConfig,
        text: &str,
        output: W,
        format: MessageFormat,
    ) -> Result<(), MessageError> {
        self.validate_text(text)?;
        self.encrypt_internal(
            None,
            crate::EncryptionRequest::new(recipients, at_unix_seconds, config),
            text.as_bytes(),
            output,
            format,
            DataMode::Utf8,
        )
        .map(|_| ())
    }

    pub fn sign_and_encrypt_text<W: Write>(
        &self,
        signing: crate::SigningKeyRequest<'_>,
        encryption: crate::EncryptionRequest<'_>,
        text: &str,
        output: W,
        format: MessageFormat,
    ) -> Result<SignatureMetadata, MessageError> {
        self.validate_text(text)?;
        self.encrypt_internal(
            Some(signing),
            encryption,
            text.as_bytes(),
            output,
            format,
            DataMode::Utf8,
        )?
        .ok_or_else(|| MessageError::NoUsableKey {
            fingerprint: signing.fingerprint.clone(),
            operation: crate::MessageOperation::Sign,
        })
    }

    fn encrypt_internal<R: Read, W: Write>(
        &self,
        signer: Option<crate::SigningKeyRequest<'_>>,
        encryption: crate::EncryptionRequest<'_>,
        data: R,
        output: W,
        format: MessageFormat,
        data_mode: DataMode,
    ) -> Result<Option<SignatureMetadata>, MessageError> {
        let crate::EncryptionRequest {
            recipients,
            at_unix_seconds,
            config,
        } = encryption;
        if recipients.is_empty() {
            return Err(MessageError::EmptyRecipients);
        }
        let mut unique = BTreeSet::new();
        for recipient in recipients {
            if !unique.insert(recipient.clone()) {
                return Err(MessageError::NoUsableKey {
                    fingerprint: recipient.clone(),
                    operation: crate::MessageOperation::Encrypt,
                });
            }
        }
        let recipient_keys = recipients
            .iter()
            .map(|fingerprint| selection::encryption_key(self, fingerprint, at_unix_seconds))
            .collect::<Result<Vec<_>, _>>()?;
        let signer = signer
            .map(|request| {
                let selection = selection::signing_key(self, request.fingerprint, at_unix_seconds)?;
                Ok::<_, MessageError>((selection, request.password))
            })
            .transpose()?;
        let (cipher, policy_cipher) = cipher(config);
        self.security_policy
            .validate_new_encryption(policy_cipher)?;
        let mut rng = rand::thread_rng();
        let builder = MessageBuilder::from_reader("payload.bin", data);
        let include_checksum = match config {
            EncryptionConfig::SeipdV1 { .. } => signer
                .as_ref()
                .is_none_or(|(selection, _)| selection.key.version() != pgp::types::KeyVersion::V6),
            EncryptionConfig::SeipdV2 { .. } => false,
        };
        let signature_metadata = signer
            .as_ref()
            .map(|(selection, _)| {
                signature_timestamp(at_unix_seconds)
                    .map(|created_at| signature_metadata(selection, Some(created_at)))
            })
            .transpose()?;

        match config {
            EncryptionConfig::SeipdV1 { .. } => {
                let mut builder = builder.seipd_v1(&mut rng, cipher);
                for recipient in &recipient_keys {
                    builder.encrypt_to_key(&mut rng, recipient.key)?;
                }
                if let Some((selection, password)) = &signer {
                    builder.sign_with_subpackets(
                        selection,
                        selection.password(password),
                        selection.hash_algorithm,
                        signature_subpacket_config(selection, at_unix_seconds)?,
                    );
                }
                if data_mode == DataMode::Utf8 {
                    builder.data_mode(data_mode)?;
                    builder.sign_text();
                }
                let result = write_builder(builder, output, format, include_checksum);
                if let Some((selection, _)) = &signer {
                    result.map_err(|error| selection.map_signing_error(error))?;
                } else {
                    result?;
                }
            }
            EncryptionConfig::SeipdV2 { mode, .. } => {
                let mut builder =
                    builder.seipd_v2(&mut rng, cipher, aead(mode), ChunkSize::default());
                for recipient in &recipient_keys {
                    builder.encrypt_to_key(&mut rng, recipient.key)?;
                }
                if let Some((selection, password)) = &signer {
                    builder.sign_with_subpackets(
                        selection,
                        selection.password(password),
                        selection.hash_algorithm,
                        signature_subpacket_config(selection, at_unix_seconds)?,
                    );
                }
                if data_mode == DataMode::Utf8 {
                    builder.data_mode(data_mode)?;
                    builder.sign_text();
                }
                let result = write_builder(builder, output, format, include_checksum);
                if let Some((selection, _)) = &signer {
                    result.map_err(|error| selection.map_signing_error(error))?;
                } else {
                    result?;
                }
            }
        }
        Ok(signature_metadata)
    }

    fn validate_text(&self, text: &str) -> Result<(), MessageError> {
        if text.len() > self.limits.max_text_bytes {
            return Err(MessageError::TextLimitExceeded {
                limit: self.limits.max_text_bytes,
            });
        }
        let bytes = text.as_bytes();
        for (index, byte) in bytes.iter().enumerate() {
            if (*byte == b'\n' && (index == 0 || bytes[index - 1] != b'\r'))
                || (*byte == b'\r' && bytes.get(index + 1) != Some(&b'\n'))
            {
                return Err(MessageError::InvalidTextLineEnding);
            }
        }
        Ok(())
    }
}

fn write_builder<R: Read, E: Encryption, W: Write>(
    builder: MessageBuilder<'_, R, E>,
    mut output: W,
    format: MessageFormat,
    include_checksum: bool,
) -> Result<(), MessageError> {
    match format {
        MessageFormat::Binary => builder.to_writer(rand::thread_rng(), &mut output)?,
        MessageFormat::Armored => builder.to_armored_writer(
            rand::thread_rng(),
            armor_options(include_checksum),
            &mut output,
        )?,
    }
    Ok(())
}

fn cipher(config: EncryptionConfig) -> (SymmetricKeyAlgorithm, SymmetricAlgorithm) {
    let cipher = match config {
        EncryptionConfig::SeipdV1 { cipher } | EncryptionConfig::SeipdV2 { cipher, .. } => cipher,
    };
    match cipher {
        MessageCipher::Aes128 => (SymmetricKeyAlgorithm::AES128, SymmetricAlgorithm::Aes128),
        MessageCipher::Aes192 => (SymmetricKeyAlgorithm::AES192, SymmetricAlgorithm::Aes192),
        MessageCipher::Aes256 => (SymmetricKeyAlgorithm::AES256, SymmetricAlgorithm::Aes256),
    }
}

fn aead(mode: AeadMode) -> AeadAlgorithm {
    match mode {
        AeadMode::Ocb => AeadAlgorithm::Ocb,
        AeadMode::Eax => AeadAlgorithm::Eax,
        AeadMode::Gcm => AeadAlgorithm::Gcm,
    }
}

fn signature_subpacket_config(
    selection: &SigningSelection<'_>,
    at_unix_seconds: u64,
) -> Result<SubpacketConfig, MessageError> {
    let (hashed, unhashed) = signature_subpackets(selection, at_unix_seconds)?;
    Ok(SubpacketConfig::UserDefined { hashed, unhashed })
}

fn signature_subpackets(
    selection: &SigningSelection<'_>,
    at_unix_seconds: u64,
) -> Result<(Vec<Subpacket>, Vec<Subpacket>), MessageError> {
    let hashed = vec![
        Subpacket::regular(SubpacketData::IssuerFingerprint(selection.fingerprint()))?,
        Subpacket::regular(SubpacketData::SignatureCreationTime(signature_timestamp(
            at_unix_seconds,
        )?))?,
    ];
    let unhashed = if selection.key.version() <= KeyVersion::V4 {
        vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            selection.legacy_key_id(),
        ))?]
    } else {
        Vec::new()
    };
    Ok((hashed, unhashed))
}

fn signature_timestamp(at_unix_seconds: u64) -> Result<Timestamp, MessageError> {
    u32::try_from(at_unix_seconds)
        .map(Timestamp::from_secs)
        .map_err(|_| MessageError::TimestampOutOfRange { at_unix_seconds })
}

fn password_value(password: &str) -> Password {
    let password = Zeroizing::new(password.to_owned());
    Password::from(password.as_str())
}

fn armor_options(include_checksum: bool) -> ArmorOptions<'static> {
    ArmorOptions {
        headers: None,
        include_checksum,
    }
}

fn signature_metadata(
    selection: &SigningSelection<'_>,
    created_at: Option<pgp::types::Timestamp>,
) -> SignatureMetadata {
    SignatureMetadata {
        certificate_fingerprint: selection.certificate_fingerprint.clone(),
        signer_fingerprint: FullFingerprint::from_rpgp(&selection.key.key.fingerprint()),
        algorithm: selection.algorithm.clone(),
        hash_algorithm: selection.policy_hash_algorithm,
        created_at: created_at.map(|created| u64::from(created.as_secs())),
    }
}
