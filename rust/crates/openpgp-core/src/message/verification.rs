use std::{
    io,
    io::{BufReader, Cursor, Read, Write},
};

use pgp::{
    armor::{BlockType, Dearmor},
    composed::{
        CleartextSignedMessage, Deserializable as _, DetachedSignature, Message, SignedPublicSubKey,
    },
    packet::{PublicKey, Signature},
    ser::Serialize as _,
    types::{KeyDetails as _, VerifyingKey},
};

use openpgp_policy::{
    HashAlgorithm as PolicyHashAlgorithm, LegacyDisposition, LegacyPolicyDecision, SecurityPolicy,
};

use crate::{
    AlgorithmMetadata, CleartextVerification, FullFingerprint, IdentityTrust, KeyUsage,
    KeyValidity, MessageError, MessageService, SignatureVerification, VerificationOutcome,
    VerificationStatus,
};

use super::selection::policy_hash_algorithm;

impl MessageService<'_> {
    pub fn verify_detached<R: Read>(
        &self,
        data: R,
        signature: &[u8],
        at_unix_seconds: u64,
    ) -> Result<VerificationOutcome, MessageError> {
        if signature.len() > self.limits.max_signature_bytes {
            return Err(MessageError::SignatureLimitExceeded {
                limit: self.limits.max_signature_bytes,
            });
        }
        let signature = parse_detached(signature)?;
        let candidates = verification_candidates(self, &signature.signature, at_unix_seconds)?;
        let Some(candidate) = candidates.first() else {
            return Ok(VerificationOutcome {
                status: VerificationStatus::UnknownSigner,
                signatures: vec![unknown_signer(&self.security_policy, &signature.signature)],
            });
        };
        if candidates.len() != 1 {
            return Err(MessageError::AmbiguousSigner);
        }
        let cryptographically_valid =
            verify_signature(candidate, &signature.signature, data).is_ok();
        let verification = assess_signature(
            &self.security_policy,
            &signature.signature,
            candidate,
            cryptographically_valid,
            at_unix_seconds,
        );
        Ok(VerificationOutcome {
            status: verification.status,
            signatures: vec![verification],
        })
    }

    pub fn verify_attached<R: Read + std::fmt::Debug + Send, W: Write>(
        &self,
        input: R,
        mut plaintext_output: W,
        at_unix_seconds: u64,
    ) -> Result<VerificationOutcome, MessageError> {
        let (message, _) = Message::from_reader(BufReader::new(TrailingArmorGuard::new(input)))?;
        let mut message = decompress_message(self, message)?;
        let plaintext = read_bounded(self, &mut message)?;
        let outcome = verify_message(self, &message, at_unix_seconds)?;
        if matches!(
            outcome.status,
            VerificationStatus::Unsigned | VerificationStatus::Valid
        ) {
            plaintext_output.write_all(&plaintext)?;
        }
        Ok(outcome)
    }

    pub fn verify_cleartext(
        &self,
        input: &[u8],
        at_unix_seconds: u64,
    ) -> Result<CleartextVerification, MessageError> {
        if input.len() > self.limits.max_cleartext_bytes {
            return Err(MessageError::CleartextLimitExceeded {
                limit: self.limits.max_cleartext_bytes,
            });
        }
        let (cleartext, _) = CleartextSignedMessage::from_armor(Cursor::new(input))?;
        let signed_text = cleartext.signed_text();
        if signed_text.len() > self.limits.max_text_bytes {
            return Err(MessageError::TextLimitExceeded {
                limit: self.limits.max_text_bytes,
            });
        }
        let mut verifications = Vec::new();
        for signature in cleartext.signatures() {
            let candidates = verification_candidates(self, signature, at_unix_seconds)?;
            verifications.push(verify_with_candidates(
                &self.security_policy,
                signature,
                &candidates,
                at_unix_seconds,
                |signature, candidate| {
                    verify_signature(candidate, signature, signed_text.as_bytes()).is_ok()
                },
            ));
        }
        let outcome = aggregate(verifications);
        let text = (outcome.status == VerificationStatus::Valid).then_some(signed_text);
        Ok(CleartextVerification { outcome, text })
    }
}

struct Candidate<'a> {
    certificate_fingerprint: FullFingerprint,
    signer_fingerprint: FullFingerprint,
    signer_key_id: String,
    algorithm: AlgorithmMetadata,
    key_validity: KeyValidity,
    primary_valid: bool,
    key: CandidateKey<'a>,
}

enum CandidateKey<'a> {
    Primary(&'a PublicKey),
    Subkey(&'a SignedPublicSubKey),
}

impl Candidate<'_> {
    fn key(&self) -> &dyn VerifyingKey {
        match &self.key {
            CandidateKey::Primary(key) => *key,
            CandidateKey::Subkey(key) => *key,
        }
    }
}

fn verify_signature<R: Read>(
    candidate: &Candidate<'_>,
    signature: &Signature,
    data: R,
) -> pgp::errors::Result<()> {
    match &candidate.key {
        CandidateKey::Primary(key) => signature.verify(*key, data),
        CandidateKey::Subkey(key) => signature.verify(*key, data),
    }
}

fn verification_candidates<'a>(
    service: &MessageService<'a>,
    signature: &Signature,
    at: u64,
) -> Result<Vec<Candidate<'a>>, MessageError> {
    let mut candidates = Vec::new();
    for certificate_metadata in service.keys.list_metadata()? {
        let fingerprint = certificate_metadata.fingerprint.clone();
        let certificate = service.keys.rpgp_public_key(&fingerprint)?;
        let validity = service.keys.evaluate_validity(&fingerprint, at)?;
        if certificate.primary_key.algorithm().can_sign()
            && issuer_matches(signature, &certificate.primary_key)
        {
            candidates.push(Candidate {
                certificate_fingerprint: fingerprint.clone(),
                signer_fingerprint: certificate_metadata.primary.fingerprint.clone(),
                signer_key_id: certificate_metadata.primary.key_id.clone(),
                algorithm: certificate_metadata.primary.algorithm.clone(),
                key_validity: validity.primary.clone(),
                primary_valid: validity.primary.is_valid(),
                key: CandidateKey::Primary(&certificate.primary_key),
            });
        }
        for (index, subkey) in certificate.public_subkeys.iter().enumerate() {
            if !subkey.key.algorithm().can_sign() || !issuer_matches(signature, &subkey.key) {
                continue;
            }
            let Some(key_validity) = validity.subkeys.get(index) else {
                continue;
            };
            let Some(key_metadata) = certificate_metadata.subkeys.get(index) else {
                continue;
            };
            candidates.push(Candidate {
                certificate_fingerprint: fingerprint.clone(),
                signer_fingerprint: key_metadata.fingerprint.clone(),
                signer_key_id: key_metadata.key_id.clone(),
                algorithm: key_metadata.algorithm.clone(),
                key_validity: key_validity.clone(),
                primary_valid: validity.primary.is_valid(),
                key: CandidateKey::Subkey(subkey),
            });
        }
    }
    Ok(candidates)
}

fn issuer_matches<K>(signature: &Signature, key: &K) -> bool
where
    K: pgp::types::KeyDetails,
{
    let fingerprints = signature.issuer_fingerprint();
    let key_ids = signature.issuer_key_id();
    if fingerprints.is_empty() && key_ids.is_empty() {
        return true;
    }
    fingerprints.iter().any(|fp| **fp == key.fingerprint())
        || key_ids.iter().any(|id| **id == key.legacy_key_id())
}

fn verify_with_candidates<F>(
    policy: &SecurityPolicy,
    signature: &Signature,
    candidates: &[Candidate<'_>],
    at: u64,
    mut verify: F,
) -> SignatureVerification
where
    F: FnMut(&Signature, &Candidate<'_>) -> bool,
{
    let mut first_invalid = None;
    for candidate in candidates {
        let cryptographically_valid = verify(signature, candidate);
        if cryptographically_valid {
            return assess_signature(policy, signature, candidate, true, at);
        }
        if first_invalid.is_none() {
            first_invalid = Some(assess_signature(policy, signature, candidate, false, at));
        }
    }
    first_invalid.unwrap_or_else(|| unknown_signer(policy, signature))
}

fn assess_signature(
    policy: &SecurityPolicy,
    signature: &Signature,
    candidate: &Candidate<'_>,
    cryptographically_valid: bool,
    at: u64,
) -> SignatureVerification {
    let hash_algorithm = signature.hash_alg().and_then(policy_hash_algorithm);
    let legacy_decision = legacy_verification_decision(policy, hash_algorithm);
    let valid = cryptographically_valid
        && legacy_decision.disposition != LegacyDisposition::Reject
        && signature_current(signature, at)
        && candidate.primary_valid
        && candidate.key_validity.is_valid_for(KeyUsage::Sign);
    SignatureVerification {
        status: if valid {
            VerificationStatus::Valid
        } else {
            VerificationStatus::Invalid
        },
        cryptographically_valid: Some(cryptographically_valid),
        certificate_fingerprint: Some(candidate.certificate_fingerprint.clone()),
        signer_fingerprint: Some(candidate.signer_fingerprint.clone()),
        signer_key_id: Some(candidate.signer_key_id.clone()),
        algorithm: Some(candidate.algorithm.clone()),
        hash_algorithm,
        legacy_decision,
        created_at: signature_created(signature),
        key_validity: Some(candidate.key_validity.clone()),
        trust: IdentityTrust::Unknown,
    }
}

fn unknown_signer(policy: &SecurityPolicy, signature: &Signature) -> SignatureVerification {
    let hash_algorithm = signature.hash_alg().and_then(policy_hash_algorithm);
    SignatureVerification {
        status: VerificationStatus::UnknownSigner,
        cryptographically_valid: None,
        certificate_fingerprint: None,
        signer_fingerprint: signature
            .issuer_fingerprint()
            .first()
            .map(|fingerprint| FullFingerprint::from_rpgp(fingerprint)),
        signer_key_id: signature
            .issuer_key_id()
            .first()
            .map(|key_id| uppercase_hex(key_id.as_ref())),
        algorithm: None,
        hash_algorithm,
        legacy_decision: legacy_verification_decision(policy, hash_algorithm),
        created_at: signature_created(signature),
        key_validity: None,
        trust: IdentityTrust::Unknown,
    }
}

fn legacy_verification_decision(
    policy: &SecurityPolicy,
    algorithm: Option<PolicyHashAlgorithm>,
) -> LegacyPolicyDecision {
    algorithm.map_or(
        LegacyPolicyDecision {
            disposition: LegacyDisposition::Reject,
            warning: None,
        },
        |algorithm| policy.legacy_verification(algorithm),
    )
}

pub(crate) fn verify_message(
    service: &MessageService<'_>,
    message: &Message<'_>,
    at: u64,
) -> Result<VerificationOutcome, MessageError> {
    let Message::Signed { reader, .. } = message else {
        return Ok(aggregate(Vec::new()));
    };
    let mut verifications = Vec::new();
    for index in 0..reader.num_signatures() {
        let Some(signature) = reader.signature(index) else {
            return Ok(aggregate(vec![unknown_signature()]));
        };
        let candidates = verification_candidates(service, signature, at)?;
        verifications.push(verify_with_candidates(
            &service.security_policy,
            signature,
            &candidates,
            at,
            |_, candidate| {
                message
                    .verify_nested_explicit(index, candidate.key())
                    .is_ok()
            },
        ));
    }
    Ok(aggregate(verifications))
}

pub(crate) fn aggregate(signatures: Vec<SignatureVerification>) -> VerificationOutcome {
    let status = if signatures.is_empty() {
        VerificationStatus::Unsigned
    } else if signatures
        .iter()
        .any(|signature| signature.status == VerificationStatus::Invalid)
    {
        VerificationStatus::Invalid
    } else if signatures
        .iter()
        .any(|signature| signature.status == VerificationStatus::UnknownSigner)
    {
        VerificationStatus::UnknownSigner
    } else {
        VerificationStatus::Valid
    };
    VerificationOutcome { status, signatures }
}

pub(crate) fn decompress_message<'a>(
    service: &MessageService<'_>,
    mut message: Message<'a>,
) -> Result<Message<'a>, MessageError> {
    let mut layers = 0;
    while message.is_compressed() {
        if layers >= service.limits.max_compression_layers {
            return Err(MessageError::CompressionLimitExceeded {
                limit: service.limits.max_compression_layers,
            });
        }
        message = message.decompress()?;
        layers += 1;
    }
    Ok(message)
}

pub(crate) fn read_bounded(
    service: &MessageService<'_>,
    message: &mut Message<'_>,
) -> Result<Vec<u8>, MessageError> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = message.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > service.limits.max_plaintext_bytes {
            return Err(MessageError::PlaintextLimitExceeded {
                limit: service.limits.max_plaintext_bytes,
            });
        }
        output.extend_from_slice(&buffer[..read]);
    }
    Ok(output)
}

fn parse_detached(input: &[u8]) -> Result<DetachedSignature, MessageError> {
    let binary = decode_artifact(input)?;
    let mut signatures = DetachedSignature::from_bytes_many(Cursor::new(binary.clone()))?;
    let signature = signatures
        .next()
        .ok_or(MessageError::EmptyInput)?
        .map_err(MessageError::from)?;
    if signatures.next().is_some() {
        return Err(MessageError::TrailingData);
    }
    if signature.to_bytes()?.len() != binary.len() {
        return Err(MessageError::TrailingData);
    }
    Ok(signature)
}

fn decode_artifact(input: &[u8]) -> Result<Vec<u8>, MessageError> {
    let Some(first) = input.first() else {
        return Err(MessageError::EmptyInput);
    };
    if first & 0x80 != 0 {
        return Ok(input.to_vec());
    }
    let (block_type, _headers, leading, cursor) =
        Dearmor::new(Cursor::new(input)).read_only_header()?;
    if leading {
        return Err(MessageError::LeadingData);
    }
    if block_type != BlockType::Signature {
        return Err(MessageError::MixedKeyring);
    }
    let mut dearmor =
        Dearmor::after_header(block_type, Default::default(), cursor, input.len().max(1));
    let mut binary = Vec::new();
    dearmor.read_to_end(&mut binary)?;
    let (_typ, _headers, _checksum, mut remainder) = dearmor.into_parts();
    let mut trailing = Vec::new();
    remainder.read_to_end(&mut trailing)?;
    if trailing.iter().any(|byte| !byte.is_ascii_whitespace()) {
        return Err(MessageError::TrailingData);
    }
    Ok(binary)
}

fn signature_created(signature: &Signature) -> Option<u64> {
    signature
        .created()
        .map(|created| u64::from(created.as_secs()))
}

fn signature_current(signature: &Signature, at: u64) -> bool {
    let Some(created) = signature.created() else {
        return false;
    };
    let created = u64::from(created.as_secs());
    if created > at {
        return false;
    }
    signature
        .signature_expiration_time()
        .is_none_or(|duration| {
            duration.as_secs() == 0 || at < created.saturating_add(u64::from(duration.as_secs()))
        })
}

fn unknown_signature() -> SignatureVerification {
    SignatureVerification {
        status: VerificationStatus::Invalid,
        cryptographically_valid: Some(false),
        certificate_fingerprint: None,
        signer_fingerprint: None,
        signer_key_id: None,
        algorithm: None,
        hash_algorithm: None,
        legacy_decision: LegacyPolicyDecision::default(),
        created_at: None,
        key_validity: None,
        trust: IdentityTrust::Unknown,
    }
}

fn uppercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub(crate) struct TrailingArmorGuard<R> {
    inner: R,
    checked_start: bool,
    armored: bool,
    footer_match: usize,
    in_footer: bool,
    footer_complete: bool,
    rejected: bool,
}

impl<R: Read> TrailingArmorGuard<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            checked_start: false,
            armored: false,
            footer_match: 0,
            in_footer: false,
            footer_complete: false,
            rejected: false,
        }
    }

    fn inspect(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.rejected {
            return Err(trailing_armor_error());
        }
        for (index, byte) in bytes.iter().copied().enumerate() {
            if !self.checked_start {
                self.armored = byte & 0x80 == 0;
                self.checked_start = true;
            }
            if !self.armored {
                continue;
            }
            if self.footer_complete {
                if !byte.is_ascii_whitespace() {
                    self.rejected = true;
                    return Err(trailing_armor_error());
                }
                continue;
            }
            if self.in_footer {
                if byte == b'\n' {
                    self.footer_complete = true;
                    self.in_footer = false;
                }
                continue;
            }
            const FOOTER: &[u8] = b"-----END PGP ";
            if byte == FOOTER[self.footer_match] {
                self.footer_match += 1;
                if self.footer_match == FOOTER.len() {
                    self.footer_match = 0;
                    self.in_footer = true;
                }
            } else {
                self.footer_match = usize::from(byte == FOOTER[0]);
            }
            if index + 1 == bytes.len() && self.rejected {
                return Err(trailing_armor_error());
            }
        }
        Ok(())
    }
}

impl<R: Read> Read for TrailingArmorGuard<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(output)?;
        self.inspect(&output[..read])?;
        Ok(read)
    }
}

impl<R: Read> std::fmt::Debug for TrailingArmorGuard<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("TrailingArmorGuard").finish()
    }
}

fn trailing_armor_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "trailing data after ASCII armor",
    )
}
