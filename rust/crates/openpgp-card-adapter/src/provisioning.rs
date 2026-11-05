use openpgp_card::{
    Card,
    ocard::{
        KeyType, StatusBytes,
        algorithm::{AlgorithmAttributes, Curve},
        crypto::EccType,
        data::KeyStatus,
    },
    state::Transaction,
};
use openpgp_card_rpgp::{
    bind_into_certificate, public_key_material_and_fp_to_key, public_to_fingerprint,
};
use pgp::{composed::SignedPublicKey, packet::PublicKey, types::KeyDetails as _};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    CardIdentity,
    remote_key::{RemoteKeyError, validate_kdf},
};

#[derive(Debug, Error)]
pub enum ProvisioningError {
    #[error("the user ID is empty or too long")]
    InvalidUserId,
    #[error("a PIN is outside the card's byte-length limits; no VERIFY was sent")]
    InvalidPin,
    #[error("fewer than two PIN retries remain; no PIN was requested and no write was sent")]
    PinRetriesUnavailable,
    #[error("the signing or decryption slot is occupied; replacement was not authorized")]
    SlotNotEmpty,
    #[error("the card does not provide reliable slot metadata")]
    MissingSlotData,
    #[error("the card does not advertise the required P-256 slot configuration")]
    UnsupportedAlgorithm,
    #[error("the card identity changed or does not match the selected card")]
    IdentityMismatch,
    #[error("the generated public components or certificate bindings are inconsistent")]
    BindingMismatch,
    #[error("OpenPGP Card operation failed: {0}")]
    Card(#[from] openpgp_card::Error),
    #[error("card public-key conversion failed: {0}")]
    Conversion(#[from] openpgp_card_rpgp::Error),
    #[error("OpenPGP certificate encoding failed: {0}")]
    Certificate(#[from] pgp::errors::Error),
    #[error("card PIN protection policy was rejected: {0}")]
    Kdf(#[from] RemoteKeyError),
}

pub fn generate_p256_certificate(
    transaction: &mut Card<Transaction<'_>>,
    expected_identity: CardIdentity,
    user_id: &str,
    user_pin: Zeroizing<String>,
    admin_pin: Zeroizing<String>,
    replace_existing: bool,
) -> Result<SignedPublicKey, ProvisioningError> {
    if user_id.is_empty() || user_id.len() > 4096 {
        return Err(ProvisioningError::InvalidUserId);
    }
    require_identity(transaction, expected_identity)?;
    validate_kdf_mode(transaction)?;
    let password = transaction
        .card()
        .application_related_data()?
        .pw_status_bytes()?;
    if password.err_count_pw1() < 2 || password.err_count_pw3() < 2 {
        return Err(ProvisioningError::PinRetriesUnavailable);
    }
    if !(6..=usize::from(password.pw1_max_len())).contains(&user_pin.len())
        || !(8..=usize::from(password.pw3_max_len())).contains(&admin_pin.len())
    {
        return Err(ProvisioningError::InvalidPin);
    }

    let algorithms = [
        (KeyType::Signing, EccType::ECDSA),
        (KeyType::Decryption, EccType::ECDH),
    ]
    .into_iter()
    .map(|(slot, operation)| {
        p256_attributes(transaction, slot, operation).map(|attributes| (slot, attributes))
    })
    .collect::<Result<Vec<_>, ProvisioningError>>()?;
    let attributes_changeable = transaction.extended_capabilities()?.algo_attrs_changeable();
    if !attributes_changeable {
        let ard = transaction.card().application_related_data()?;
        for (slot, expected) in &algorithms {
            if &ard.algorithm_attributes(*slot)? != expected {
                return Err(ProvisioningError::UnsupportedAlgorithm);
            }
        }
    }
    require_identity(transaction, expected_identity)?;
    require_slots(transaction, replace_existing)?;

    {
        let mut admin = transaction.as_admin_card(Some(admin_pin.as_str().into()))?;
        if attributes_changeable {
            for (slot, attributes) in &algorithms {
                admin.set_algorithm_attributes(*slot, attributes)?;
            }
        }
        for (slot, _) in &algorithms {
            admin.generate_key(public_to_fingerprint, *slot)?;
        }
    }
    require_identity(transaction, expected_identity)?;
    let primary = read_public_component(transaction, KeyType::Signing)?;
    let decryption = read_public_component(transaction, KeyType::Decryption)?;
    let pinpad_prompt = || {};
    let touch_prompt = || {};
    let certificate = bind_into_certificate(
        transaction,
        primary,
        Some(decryption),
        None,
        &[user_id.to_owned()],
        Some(user_pin.as_str().into()),
        &pinpad_prompt,
        &touch_prompt,
    )?;
    certificate.verify_bindings()?;
    require_identity(transaction, expected_identity)?;
    let signing = read_public_component(transaction, KeyType::Signing)?;
    let decryption = read_public_component(transaction, KeyType::Decryption)?;
    if signing.fingerprint() != certificate.primary_key.fingerprint()
        || certificate.public_subkeys.len() != 1
        || decryption.fingerprint() != certificate.public_subkeys[0].key.fingerprint()
    {
        return Err(ProvisioningError::BindingMismatch);
    }
    Ok(certificate)
}

fn require_identity(
    transaction: &mut Card<Transaction<'_>>,
    expected: CardIdentity,
) -> Result<(), ProvisioningError> {
    let actual = transaction
        .card()
        .application_related_data()
        .and_then(|ard| ard.application_id())
        .map(|aid| CardIdentity::from_application_identifier(&aid))?;
    if actual == expected {
        Ok(())
    } else {
        Err(ProvisioningError::IdentityMismatch)
    }
}

fn validate_kdf_mode(transaction: &mut Card<Transaction<'_>>) -> Result<(), ProvisioningError> {
    let advertised = transaction.extended_capabilities()?.kdf_do();
    match transaction.kdf_do() {
        Ok(kdf) => validate_kdf(&kdf).map_err(ProvisioningError::Kdf),
        Err(openpgp_card::Error::CardStatus(
            StatusBytes::ReferencedDataNotFound | StatusBytes::FileOrApplicationNotFound,
        )) if !advertised => Ok(()),
        Err(openpgp_card::Error::NotFound(_)) if !advertised => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn require_slots(
    transaction: &mut Card<Transaction<'_>>,
    replace_existing: bool,
) -> Result<(), ProvisioningError> {
    let ard = transaction.card().application_related_data()?;
    let information = ard
        .key_information()?
        .ok_or(ProvisioningError::MissingSlotData)?;
    let fingerprints = ard.fingerprints()?;
    let times = ard.key_generation_times()?;
    if !replace_existing {
        for (status, fingerprint, time) in [
            (
                information.sig_status(),
                fingerprints.signature(),
                times.signature(),
            ),
            (
                information.dec_status(),
                fingerprints.decryption(),
                times.decryption(),
            ),
        ] {
            if status != KeyStatus::NotPresent || fingerprint.is_some() || time.is_some() {
                return Err(ProvisioningError::SlotNotEmpty);
            }
        }
    }
    Ok(())
}

fn p256_attributes(
    transaction: &mut Card<Transaction<'_>>,
    slot: KeyType,
    operation: EccType,
) -> Result<AlgorithmAttributes, ProvisioningError> {
    let advertised = match transaction.algorithm_information() {
        Ok(Some(information)) => Some(information),
        Err(openpgp_card::Error::CardStatus(
            StatusBytes::ReferencedDataNotFound | StatusBytes::FileOrApplicationNotFound,
        )) => None,
        Err(openpgp_card::Error::NotFound(_)) => None,
        Err(error) => return Err(error.into()),
        Ok(None) => None,
    };
    if let Some(information) = advertised {
        return information
            .for_keytype(slot)
            .into_iter()
            .find(|attributes| is_p256(attributes, operation))
            .cloned()
            .ok_or(ProvisioningError::UnsupportedAlgorithm);
    }
    let attributes = transaction
        .card()
        .application_related_data()?
        .algorithm_attributes(slot)?;
    if is_p256(&attributes, operation) {
        Ok(attributes)
    } else {
        Err(ProvisioningError::UnsupportedAlgorithm)
    }
}

fn is_p256(attributes: &AlgorithmAttributes, operation: EccType) -> bool {
    matches!(
        attributes,
        AlgorithmAttributes::Ecc(attributes)
            if attributes.ecc_type() == operation && *attributes.curve() == Curve::NistP256r1
    )
}

fn read_public_component(
    transaction: &mut Card<Transaction<'_>>,
    slot: KeyType,
) -> Result<PublicKey, ProvisioningError> {
    let material = transaction.public_key_material(slot)?;
    let created = transaction
        .key_generation_time(slot)?
        .ok_or(ProvisioningError::MissingSlotData)?;
    let fingerprint = transaction
        .fingerprint(slot)?
        .ok_or(ProvisioningError::MissingSlotData)?;
    let public = public_key_material_and_fp_to_key(&material, slot, &created, &fingerprint)?;
    if public.fingerprint().as_bytes() != fingerprint.as_bytes() {
        return Err(ProvisioningError::BindingMismatch);
    }
    Ok(public)
}
