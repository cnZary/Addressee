use std::{
    cell::Cell,
    io::{self, BufRead, Cursor, Read},
    rc::Rc,
};

use pgp::{
    armor::{BlockType, Dearmor},
    composed::{Deserializable as _, SignedPublicKey, SignedSecretKey},
    crypto::public_key::PublicKeyAlgorithm,
    packet::{
        Packet, PacketParser, PacketTrait as _, PublicKey, PublicSubkey, SecretKey, SecretSubkey,
        SignatureType,
    },
    ser::Serialize as _,
    types::{
        EcdhPublicParams, EcdsaPublicParams, KeyDetails as _, Mpi, Password, PlainSecretParams,
        PublicParams, S2kParams, SecretParams,
    },
};
use zeroize::Zeroizing;

use crate::{KeyError, SecretComponent};

#[derive(Clone, Copy)]
enum CertificateKind {
    Public,
    Secret,
}

pub(crate) fn parse_public(input: &[u8]) -> Result<SignedPublicKey, KeyError> {
    let binary = decode(input, CertificateKind::Public)?;
    let packets = parse_packets(&binary)?;
    validate_packet_sequence(&packets, CertificateKind::Public)?;
    let mut compositions = SignedPublicKey::from_packets(
        packets
            .into_iter()
            .map(Ok)
            .collect::<Vec<_>>()
            .into_iter()
            .peekable(),
    );
    let certificate = compositions
        .next()
        .ok_or(KeyError::UnexpectedPacket { index: 0 })??;
    if compositions.next().is_some() {
        return Err(KeyError::MultipleCertificates);
    }
    certificate.verify_bindings()?;
    Ok(certificate)
}

/// Parses a password-protected secret certificate for storage restoration.
/// The original protection is preserved: no password is required and no
/// re-encryption happens. Bindings and public self-signatures must verify, and
/// every secret component must remain encrypted.
pub(crate) fn parse_protected_secret(input: &[u8]) -> Result<SignedSecretKey, KeyError> {
    let binary = decode(input, CertificateKind::Secret)?;
    let packets = parse_packets(&binary)?;
    validate_packet_sequence(&packets, CertificateKind::Secret)?;
    let mut compositions = SignedSecretKey::from_packets(
        packets
            .into_iter()
            .map(Ok)
            .collect::<Vec<_>>()
            .into_iter()
            .peekable(),
    );
    let secret = compositions
        .next()
        .ok_or(KeyError::UnexpectedPacket { index: 0 })??;
    if compositions.next().is_some() {
        return Err(KeyError::MultipleCertificates);
    }
    secret.verify_bindings()?;
    secret.to_public_key().verify_bindings()?;
    ensure_all_protected(&secret)?;
    Ok(secret)
}

pub(crate) fn parse_secret(
    input: &[u8],
    current_password: Option<&str>,
    new_password: &str,
) -> Result<SignedSecretKey, KeyError> {
    if new_password.is_empty() {
        return Err(KeyError::EmptyPassword);
    }
    let binary = decode(input, CertificateKind::Secret)?;
    let packets = parse_packets(&binary)?;
    validate_packet_sequence(&packets, CertificateKind::Secret)?;
    let mut compositions = SignedSecretKey::from_packets(
        packets
            .into_iter()
            .map(Ok)
            .collect::<Vec<_>>()
            .into_iter()
            .peekable(),
    );
    let mut secret = compositions
        .next()
        .ok_or(KeyError::UnexpectedPacket { index: 0 })??;
    if compositions.next().is_some() {
        return Err(KeyError::MultipleCertificates);
    }
    if secret.verify_bindings().is_ok() {
        secret.to_public_key().verify_bindings()?;
    }
    reprotect(&mut secret, current_password, new_password)?;
    secret.verify_bindings()?;
    secret.to_public_key().verify_bindings()?;
    Ok(secret)
}

fn decode(input: &[u8], kind: CertificateKind) -> Result<Vec<u8>, KeyError> {
    let Some(first) = input.first() else {
        return Err(KeyError::EmptyInput);
    };
    if first & 0x80 != 0 {
        return Ok(input.to_vec());
    }

    let cursor = Cursor::new(input);
    let (block_type, _headers, has_leading_data, cursor) =
        Dearmor::new(cursor).read_only_header()?;
    if has_leading_data {
        return Err(KeyError::LeadingData);
    }
    let expected_type = match kind {
        CertificateKind::Public => BlockType::PublicKey,
        CertificateKind::Secret => BlockType::PrivateKey,
    };
    if block_type != expected_type {
        return Err(KeyError::MixedKeyring);
    }

    let mut dearmor =
        Dearmor::after_header(block_type, Default::default(), cursor, input.len().max(1));
    let mut binary = Vec::new();
    dearmor.read_to_end(&mut binary)?;
    let (_typ, _headers, _checksum, mut remainder) = dearmor.into_parts();
    let mut trailing = Vec::new();
    remainder.read_to_end(&mut trailing)?;
    if trailing.iter().any(|byte| !byte.is_ascii_whitespace()) {
        return Err(KeyError::TrailingData);
    }
    Ok(binary)
}

fn parse_packets(binary: &[u8]) -> Result<Vec<Packet>, KeyError> {
    if binary.is_empty() {
        return Err(KeyError::EmptyInput);
    }
    let position = Rc::new(Cell::new(0));
    let reader = PositionReader::new(binary, Rc::clone(&position));
    let mut parser = PacketParser::new(reader);
    let mut packets = Vec::new();
    let mut last_packet_end = 0;
    loop {
        match parser.next() {
            Some(Ok(packet)) => {
                packets.push(packet);
                last_packet_end = position.get();
            }
            Some(Err(error)) => return Err(error.into()),
            None => break,
        }
    }
    if packets.is_empty() {
        return Err(KeyError::UnexpectedPacket { index: 0 });
    }
    if last_packet_end != binary.len() {
        return Err(KeyError::TrailingData);
    }
    Ok(packets)
}

fn validate_packet_sequence(packets: &[Packet], kind: CertificateKind) -> Result<(), KeyError> {
    let expected_primary = match kind {
        CertificateKind::Public => pgp::types::Tag::PublicKey,
        CertificateKind::Secret => pgp::types::Tag::SecretKey,
    };
    if packets[0].tag() != expected_primary {
        return match packets[0].tag() {
            pgp::types::Tag::PublicKey | pgp::types::Tag::SecretKey => Err(KeyError::MixedKeyring),
            _ => Err(KeyError::UnexpectedPacket { index: 0 }),
        };
    }

    let mut index = 1;
    while packets
        .get(index)
        .is_some_and(|packet| packet.tag() == pgp::types::Tag::Signature)
    {
        let Packet::Signature(signature) = &packets[index] else {
            unreachable!("tag checked")
        };
        if !matches!(
            signature.typ(),
            Some(SignatureType::Key | SignatureType::KeyRevocation)
        ) {
            return Err(KeyError::UnexpectedPacket { index });
        }
        index += 1;
    }

    while packets.get(index).is_some_and(|packet| {
        matches!(
            packet.tag(),
            pgp::types::Tag::UserId | pgp::types::Tag::UserAttribute
        )
    }) {
        index += 1;
        let binding_start = index;
        while packets
            .get(index)
            .is_some_and(|packet| packet.tag() == pgp::types::Tag::Signature)
        {
            let Packet::Signature(signature) = &packets[index] else {
                unreachable!("tag checked")
            };
            if !signature.is_certification() {
                return Err(KeyError::UnexpectedPacket { index });
            }
            index += 1;
        }
        if index == binding_start {
            return Err(KeyError::MissingBinding {
                index: binding_start - 1,
            });
        }
    }

    while packets.get(index).is_some_and(|packet| {
        packet.tag() == pgp::types::Tag::PublicSubkey
            || (matches!(kind, CertificateKind::Secret)
                && packet.tag() == pgp::types::Tag::SecretSubkey)
    }) {
        index += 1;
        let binding_start = index;
        while packets
            .get(index)
            .is_some_and(|packet| packet.tag() == pgp::types::Tag::Signature)
        {
            let Packet::Signature(signature) = &packets[index] else {
                unreachable!("tag checked")
            };
            if !matches!(
                signature.typ(),
                Some(SignatureType::SubkeyBinding | SignatureType::SubkeyRevocation)
            ) {
                return Err(KeyError::UnexpectedPacket { index });
            }
            index += 1;
        }
        if index == binding_start {
            return Err(KeyError::MissingBinding {
                index: binding_start - 1,
            });
        }
    }

    if index == packets.len() {
        return Ok(());
    }
    match packets[index].tag() {
        pgp::types::Tag::PublicKey | pgp::types::Tag::SecretKey => {
            if packets[index].tag() == expected_primary {
                Err(KeyError::MultipleCertificates)
            } else {
                Err(KeyError::MixedKeyring)
            }
        }
        _ => Err(KeyError::UnexpectedPacket { index }),
    }
}

pub(crate) fn reprotect(
    secret: &mut SignedSecretKey,
    current_password: Option<&str>,
    new_password: &str,
) -> Result<(), KeyError> {
    let requires_password = secret.primary_key.secret_params().is_encrypted()
        || secret
            .secret_subkeys
            .iter()
            .any(|subkey| subkey.key.secret_params().is_encrypted());
    if requires_password && current_password.is_none() {
        return Err(KeyError::PasswordRequired);
    }

    let current_password = Zeroizing::new(current_password.unwrap_or_default().to_owned());
    let current_password = Password::from(current_password.as_str());
    if secret.primary_key.secret_params().is_encrypted() {
        secret
            .primary_key
            .remove_password(&current_password)
            .map_err(|source| KeyError::InvalidPassword {
                component: SecretComponent::Primary,
                source,
            })?;
    }
    for (index, subkey) in secret.secret_subkeys.iter_mut().enumerate() {
        if subkey.key.secret_params().is_encrypted() {
            subkey
                .key
                .remove_password(&current_password)
                .map_err(|source| KeyError::InvalidPassword {
                    component: SecretComponent::Subkey(index),
                    source,
                })?;
        }
    }

    normalize_rsa_primary(&mut secret.primary_key)?;
    for subkey in &mut secret.secret_subkeys {
        normalize_rsa_subkey(&mut subkey.key)?;
    }
    validate_secret_material(secret)?;
    let new_password = Zeroizing::new(new_password.to_owned());
    let new_password = Password::from(new_password.as_str());
    let mut rng = rand::thread_rng();
    let primary_s2k = S2kParams::new_default(&mut rng, secret.primary_key.version());
    secret
        .primary_key
        .set_password_with_s2k(&new_password, primary_s2k)?;
    for subkey in &mut secret.secret_subkeys {
        let subkey_s2k = S2kParams::new_default(&mut rng, subkey.key.version());
        subkey
            .key
            .set_password_with_s2k(&new_password, subkey_s2k)?;
    }
    ensure_all_protected(secret)
}

fn normalize_rsa_primary(key: &mut SecretKey) -> Result<(), KeyError> {
    if !matches!(
        key.algorithm(),
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::RSASign
    ) {
        return Ok(());
    }
    let version = key.version();
    let algorithm = key.algorithm();
    let normalized = key.unlock(&Password::empty(), |public, plain| {
        normalized_rsa_plain(version, algorithm, public, plain)
    })??;
    if let Some(normalized) = normalized {
        *key = SecretKey::new(key.public_key().clone(), SecretParams::Plain(normalized))?;
    }
    Ok(())
}

fn normalize_rsa_subkey(key: &mut SecretSubkey) -> Result<(), KeyError> {
    if !matches!(
        key.algorithm(),
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::RSASign
    ) {
        return Ok(());
    }
    let version = key.version();
    let algorithm = key.algorithm();
    let normalized = key.unlock(&Password::empty(), |public, plain| {
        normalized_rsa_plain(version, algorithm, public, plain)
    })??;
    if let Some(normalized) = normalized {
        *key = SecretSubkey::new(key.public_key().clone(), SecretParams::Plain(normalized))?;
    }
    Ok(())
}

fn normalized_rsa_plain(
    version: pgp::types::KeyVersion,
    algorithm: PublicKeyAlgorithm,
    public_params: &PublicParams,
    plain: &PlainSecretParams,
) -> pgp::errors::Result<Option<PlainSecretParams>> {
    let PlainSecretParams::RSA(rsa) = plain else {
        return Ok(None);
    };
    let (d, p, q, u) = rsa.to_bytes();
    if p <= q {
        return Ok(None);
    }
    let mut encoded = Vec::new();
    for value in [&d, &q, &p, &u] {
        Mpi::from_slice(value).to_writer(&mut encoded)?;
    }
    let normalized = PlainSecretParams::try_from_reader_no_checksum(
        &encoded[..],
        version,
        algorithm,
        public_params,
    )?;
    Ok(Some(normalized))
}

fn validate_secret_material(secret: &mut SignedSecretKey) -> Result<(), KeyError> {
    validate_primary(&mut secret.primary_key)?;
    for (index, subkey) in secret.secret_subkeys.iter_mut().enumerate() {
        validate_subkey(&mut subkey.key, index)?;
    }
    Ok(())
}

fn validate_primary(key: &mut SecretKey) -> Result<(), KeyError> {
    let matches = key.unlock(&Password::empty(), |public, plain| {
        let derived = PublicParams::try_from(plain)?;
        Ok(public_material_matches(&derived, public))
    })??;
    if matches {
        return Ok(());
    }
    let repaired = key.unlock(&Password::empty(), repair_ecdsa_public)??;
    if let Some(repaired) = repaired {
        let public = PublicKey::new_with_header(
            *key.packet_header(),
            key.version(),
            key.algorithm(),
            key.created_at(),
            key.legacy_v3_expiration_days(),
            repaired,
        )?;
        *key = SecretKey::new(public, key.secret_params().clone())?;
        return Ok(());
    }
    Err(KeyError::SecretMaterialMismatch {
        component: SecretComponent::Primary,
    })
}

fn validate_subkey(key: &mut SecretSubkey, index: usize) -> Result<(), KeyError> {
    let matches = key.unlock(&Password::empty(), |public, plain| {
        let derived = PublicParams::try_from(plain)?;
        Ok(public_material_matches(&derived, public))
    })??;
    if matches {
        return Ok(());
    }
    let repaired = key.unlock(&Password::empty(), repair_ecdsa_public)??;
    if let Some(repaired) = repaired {
        let public = PublicSubkey::new_with_header(
            *key.packet_header(),
            key.version(),
            key.algorithm(),
            key.created_at(),
            key.legacy_v3_expiration_days(),
            repaired,
        )?;
        *key = SecretSubkey::new(public, key.secret_params().clone())?;
        return Ok(());
    }
    Err(KeyError::SecretMaterialMismatch {
        component: SecretComponent::Subkey(index),
    })
}

fn repair_ecdsa_public(
    public: &PublicParams,
    plain: &PlainSecretParams,
) -> pgp::errors::Result<Option<PublicParams>> {
    let derived = PublicParams::try_from(plain)?;
    if public_material_matches(&derived, public) {
        return Ok(None);
    }
    let shifted = match (&derived, public) {
        (PublicParams::ECDSA(derived), PublicParams::ECDSA(parsed)) => {
            shifted_ecdsa_point(derived, parsed)?
        }
        _ => false,
    };
    Ok(shifted.then_some(derived))
}

fn public_material_matches(derived: &PublicParams, public: &PublicParams) -> bool {
    if derived == public {
        return true;
    }
    match (derived, public) {
        (
            PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { p: derived, .. }),
            PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { p: parsed, .. }),
        ) => derived == parsed,
        (
            PublicParams::ECDH(EcdhPublicParams::P256 { p: derived, .. }),
            PublicParams::ECDH(EcdhPublicParams::P256 { p: parsed, .. }),
        ) => derived == parsed,
        (
            PublicParams::ECDH(EcdhPublicParams::P384 { p: derived, .. }),
            PublicParams::ECDH(EcdhPublicParams::P384 { p: parsed, .. }),
        ) => derived == parsed,
        (
            PublicParams::ECDH(EcdhPublicParams::P521 { p: derived, .. }),
            PublicParams::ECDH(EcdhPublicParams::P521 { p: parsed, .. }),
        ) => derived == parsed,
        (
            PublicParams::ECDH(EcdhPublicParams::Brainpool256 { p: derived, .. }),
            PublicParams::ECDH(EcdhPublicParams::Brainpool256 { p: parsed, .. }),
        )
        | (
            PublicParams::ECDH(EcdhPublicParams::Brainpool384 { p: derived, .. }),
            PublicParams::ECDH(EcdhPublicParams::Brainpool384 { p: parsed, .. }),
        )
        | (
            PublicParams::ECDH(EcdhPublicParams::Brainpool512 { p: derived, .. }),
            PublicParams::ECDH(EcdhPublicParams::Brainpool512 { p: parsed, .. }),
        ) => derived == parsed,
        (
            PublicParams::ECDH(EcdhPublicParams::Unsupported {
                curve: derived_curve,
                opaque: derived_opaque,
                ..
            }),
            PublicParams::ECDH(EcdhPublicParams::Unsupported {
                curve: parsed_curve,
                opaque: parsed_opaque,
                ..
            }),
        ) => derived_curve == parsed_curve && derived_opaque == parsed_opaque,
        _ => false,
    }
}

fn shifted_ecdsa_point(
    derived: &EcdsaPublicParams,
    parsed: &EcdsaPublicParams,
) -> pgp::errors::Result<bool> {
    let derived = ecdsa_point_bytes(derived)?;
    let parsed = ecdsa_point_bytes(parsed)?;
    if derived.len() != parsed.len() {
        return Ok(false);
    }
    for shift in 1..derived.len() {
        if derived[..shift].iter().all(|byte| *byte == 0)
            && parsed[derived.len() - shift..]
                .iter()
                .all(|byte| *byte == 0)
            && parsed[..derived.len() - shift] == derived[shift..]
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ecdsa_point_bytes(params: &EcdsaPublicParams) -> pgp::errors::Result<Vec<u8>> {
    let encoded = params.to_bytes()?;
    let Some(oid_len) = encoded.first().map(|length| usize::from(*length)) else {
        return Ok(Vec::new());
    };
    let start = 1 + oid_len + 2;
    Ok(encoded.get(start..).unwrap_or(&[]).to_vec())
}

fn ensure_all_protected(secret: &SignedSecretKey) -> Result<(), KeyError> {
    if !secret.primary_key.secret_params().is_encrypted() {
        return Err(KeyError::UnprotectedSecret {
            component: SecretComponent::Primary,
        });
    }
    for (index, subkey) in secret.secret_subkeys.iter().enumerate() {
        if !subkey.key.secret_params().is_encrypted() {
            return Err(KeyError::UnprotectedSecret {
                component: SecretComponent::Subkey(index),
            });
        }
    }
    Ok(())
}

pub(crate) fn ensure_exportable(secret: &SignedSecretKey) -> Result<(), KeyError> {
    ensure_all_protected(secret)
}

struct PositionReader<'a> {
    input: &'a [u8],
    offset: usize,
    shared_offset: Rc<Cell<usize>>,
}

impl<'a> PositionReader<'a> {
    fn new(input: &'a [u8], shared_offset: Rc<Cell<usize>>) -> Self {
        Self {
            input,
            offset: 0,
            shared_offset,
        }
    }

    fn advance(&mut self, amount: usize) {
        self.offset = self.offset.saturating_add(amount).min(self.input.len());
        self.shared_offset.set(self.offset);
    }
}

impl Read for PositionReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let remaining = &self.input[self.offset..];
        let amount = remaining.len().min(output.len());
        output[..amount].copy_from_slice(&remaining[..amount]);
        self.advance(amount);
        Ok(amount)
    }
}

impl BufRead for PositionReader<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Ok(&self.input[self.offset..])
    }

    fn consume(&mut self, amount: usize) {
        self.advance(amount);
    }
}
