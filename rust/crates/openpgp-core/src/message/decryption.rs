use std::{
    error::Error as _,
    io::{self, BufReader, Read, Write},
};

use pgp::{
    composed::{DecryptionOptions, Esk, Message},
    types::{DecryptionKey as _, EskType, Password, PkeskVersion},
};
use zeroize::Zeroize as _;

use crate::{
    DecryptedMessage, DecryptedText, DecryptionReport, DecryptionStatus, FullFingerprint,
    IdentityTrust, MessageError, MessageService, VerificationStatus,
};

use super::{
    selection::DecryptionSelection,
    verification::{decompress_message, verify_message},
};

impl MessageService<'_> {
    pub fn decrypt<R: Read + std::fmt::Debug + Send>(
        &self,
        decryption_key: &FullFingerprint,
        password: &str,
        at_unix_seconds: u64,
        input: R,
    ) -> Result<DecryptedMessage, MessageError> {
        let mut plaintext = Vec::new();
        let report = self.decrypt_stream(
            decryption_key,
            password,
            at_unix_seconds,
            input,
            &mut plaintext,
            Some(self.limits.max_plaintext_bytes),
        )?;
        let plaintext = if report.may_commit_staging() {
            Some(plaintext)
        } else {
            plaintext.zeroize();
            None
        };
        Ok(DecryptedMessage { report, plaintext })
    }

    pub fn decrypt_text<R: Read + std::fmt::Debug + Send>(
        &self,
        decryption_key: &FullFingerprint,
        password: &str,
        at_unix_seconds: u64,
        input: R,
    ) -> Result<DecryptedText, MessageError> {
        let DecryptedMessage { report, plaintext } =
            self.decrypt(decryption_key, password, at_unix_seconds, input)?;
        let text = plaintext
            .map(|plaintext| {
                if plaintext.len() > self.limits.max_text_bytes {
                    return Err(MessageError::TextLimitExceeded {
                        limit: self.limits.max_text_bytes,
                    });
                }
                String::from_utf8(plaintext).map_err(|_| MessageError::InvalidUtf8)
            })
            .transpose()?;
        Ok(DecryptedText { report, text })
    }

    /// Decrypts into caller-provided staging output.
    ///
    /// The output may contain uncommitted plaintext before embedded-signature processing finishes.
    /// Callers must discard it unless `DecryptionReport::may_commit_staging()` returns true.
    /// That check covers decryption and integrity, not signer trust. Invalid and unknown signers
    /// must still be shown with their distinct warnings rather than treated as trusted identities.
    /// SEIPDv1 uses rPGP's default check-first mode and its 1 GiB ciphertext buffer limit.
    pub fn decrypt_into<R: Read + std::fmt::Debug + Send, W: Write>(
        &self,
        decryption_key: &FullFingerprint,
        password: &str,
        at_unix_seconds: u64,
        input: R,
        staging_output: W,
    ) -> Result<DecryptionReport, MessageError> {
        self.decrypt_stream(
            decryption_key,
            password,
            at_unix_seconds,
            input,
            staging_output,
            None,
        )
    }

    fn decrypt_stream<R: Read + std::fmt::Debug + Send, W: Write>(
        &self,
        decryption_key: &FullFingerprint,
        password: &str,
        at_unix_seconds: u64,
        input: R,
        mut staging_output: W,
        output_limit: Option<usize>,
    ) -> Result<DecryptionReport, MessageError> {
        let mut candidates =
            super::selection::decryption_keys(self, decryption_key, at_unix_seconds)?;
        let password = super::password_value(password);
        let encrypted = match Message::from_reader(BufReader::new(
            super::verification::TrailingArmorGuard::new(input),
        )) {
            Ok((message, _)) => message,
            Err(error) => return Ok(failure(DecryptionStatus::DecryptionFailed, error)),
        };
        let mut message = match decrypt_message(encrypted, &mut candidates, &password) {
            Ok(message) => message,
            Err(DecryptFailure::Pgp(error)) => {
                return Ok(failure(status_for_pgp_error(&error), error));
            }
            Err(DecryptFailure::Message(error)) => return Err(error),
        };
        message = match decompress_message(self, message) {
            Ok(message) => message,
            Err(MessageError::CompressionLimitExceeded { limit }) => {
                return Err(MessageError::CompressionLimitExceeded { limit });
            }
            Err(error) => return Ok(failure(DecryptionStatus::DecryptionFailed, error)),
        };

        match stage_plaintext(self, &mut message, &mut staging_output, output_limit) {
            Ok(()) => {}
            Err(StageError::Read(error)) => {
                let status = if io_error_is_integrity(&error) {
                    DecryptionStatus::IntegrityFailed
                } else {
                    DecryptionStatus::DecryptionFailed
                };
                return Ok(failure(status, error));
            }
            Err(StageError::Write(error)) => return Err(error.into()),
            Err(StageError::Limit(limit)) => {
                return Err(MessageError::PlaintextLimitExceeded { limit });
            }
        }

        let verification = verify_message(self, &message, at_unix_seconds)?;
        let status = match verification.status {
            VerificationStatus::Unsigned => DecryptionStatus::Unsigned,
            VerificationStatus::Valid => DecryptionStatus::Valid,
            VerificationStatus::Invalid => DecryptionStatus::Invalid,
            VerificationStatus::UnknownSigner => DecryptionStatus::UnknownSigner,
        };
        Ok(DecryptionReport {
            status,
            signatures: verification.signatures,
            trust: IdentityTrust::Unknown,
            detail: None,
        })
    }
}

fn decrypt_message<'a>(
    message: Message<'a>,
    candidates: &mut [DecryptionSelection<'_>],
    password: &Password,
) -> Result<Message<'a>, DecryptFailure> {
    use super::selection::DecryptionKeySource;

    let Message::Encrypted {
        esk,
        mut edata,
        is_nested: _,
    } = message
    else {
        return Err(DecryptFailure::Message(MessageError::NotEncrypted));
    };
    let remote_password = Password::empty();
    let mut remote_declined = false;
    let mut last_error = None;
    for encrypted_session_key in &esk {
        let Esk::PublicKeyEncryptedSessionKey(encrypted_session_key) = encrypted_session_key else {
            continue;
        };
        let esk_type = match encrypted_session_key.version() {
            PkeskVersion::V3 => EskType::V3_4,
            PkeskVersion::V6 => EskType::V6,
            PkeskVersion::Other(_) => continue,
        };
        let values = encrypted_session_key.values()?;
        for candidate in candidates.iter_mut() {
            if !encrypted_session_key.match_identity(candidate.key) {
                continue;
            }
            let result = match candidate.resolve().map_err(DecryptFailure::Message)? {
                Some(DecryptionKeySource::Software(key)) => {
                    key.key.decrypt(password, values, esk_type)
                }
                Some(DecryptionKeySource::Remote(key)) => {
                    key.decrypt(&remote_password, values, esk_type)
                }
                None => {
                    remote_declined = true;
                    continue;
                }
            };
            match result {
                Ok(Ok(session_key)) => {
                    // GnuPG AEAD is authenticated; unauthenticated legacy SED remains disabled.
                    edata.decrypt_with_options(
                        &session_key,
                        DecryptionOptions::new().enable_gnupg_aead(),
                    )?;
                    return Ok(Message::from_bytes(edata)?);
                }
                Ok(Err(_)) | Err(_) if candidate.is_remote() => {
                    return Err(DecryptFailure::Message(candidate.remote_error()));
                }
                Ok(Err(error)) | Err(error) => last_error = Some(error),
            }
        }
    }
    if let Some(error) = last_error {
        return Err(error.into());
    }
    if remote_declined && let Some(candidate) = candidates.first() {
        return Err(DecryptFailure::Message(MessageError::NoUsableKey {
            fingerprint: candidate.certificate_fingerprint.clone(),
            operation: crate::MessageOperation::Decrypt,
        }));
    }
    Err(pgp::errors::Error::MissingKey.into())
}

fn stage_plaintext<W: Write>(
    service: &MessageService<'_>,
    message: &mut Message<'_>,
    output: &mut W,
    output_limit: Option<usize>,
) -> Result<(), StageError> {
    let mut total = 0usize;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = message.read(&mut buffer).map_err(StageError::Read)?;
        if read == 0 {
            return Ok(());
        }
        total = total.saturating_add(read);
        if output_limit.is_some_and(|limit| total > limit) {
            return Err(StageError::Limit(
                output_limit.unwrap_or(service.limits.max_plaintext_bytes),
            ));
        }
        output
            .write_all(&buffer[..read])
            .map_err(StageError::Write)?;
    }
}

fn failure(status: DecryptionStatus, error: impl std::fmt::Display) -> DecryptionReport {
    DecryptionReport {
        status,
        signatures: Vec::new(),
        trust: IdentityTrust::Unknown,
        detail: Some(error.to_string()),
    }
}

fn status_for_pgp_error(error: &pgp::errors::Error) -> DecryptionStatus {
    if pgp_error_is_integrity(error) {
        DecryptionStatus::IntegrityFailed
    } else {
        DecryptionStatus::DecryptionFailed
    }
}

fn pgp_error_is_integrity(error: &pgp::errors::Error) -> bool {
    match error {
        pgp::errors::Error::MdcError
        | pgp::errors::Error::Aead { .. }
        | pgp::errors::Error::ChecksumMissmatch { .. }
        | pgp::errors::Error::Sha1HashCollision { .. }
        | pgp::errors::Error::InvalidChecksum => true,
        pgp::errors::Error::IO { source, .. } => io_error_is_integrity(source),
        pgp::errors::Error::InvalidPacketContent { source } => pgp_error_is_integrity(source),
        _ => false,
    }
}

fn io_error_is_integrity(error: &io::Error) -> bool {
    if let Some(inner) = error.get_ref() {
        if let Some(pgp_error) = inner.downcast_ref::<pgp::errors::Error>()
            && pgp_error_is_integrity(pgp_error)
        {
            return true;
        }
        if matches!(
            inner.downcast_ref::<pgp::crypto::aead::Error>(),
            Some(pgp::crypto::aead::Error::Decrypt { .. })
        ) {
            return true;
        }
    }
    let mut current = error.source();
    while let Some(error) = current {
        if let Some(pgp_error) = error.downcast_ref::<pgp::errors::Error>()
            && pgp_error_is_integrity(pgp_error)
        {
            return true;
        }
        if matches!(
            error.downcast_ref::<pgp::crypto::aead::Error>(),
            Some(pgp::crypto::aead::Error::Decrypt { .. })
        ) {
            return true;
        }
        current = error.source();
    }
    false
}

enum StageError {
    Read(io::Error),
    Write(io::Error),
    Limit(usize),
}

#[derive(Debug)]
enum DecryptFailure {
    Pgp(pgp::errors::Error),
    Message(MessageError),
}

impl From<pgp::errors::Error> for DecryptFailure {
    fn from(error: pgp::errors::Error) -> Self {
        Self::Pgp(error)
    }
}
