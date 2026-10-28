use openpgp_card::{
    Card,
    ocard::{
        KeyType, StatusBytes,
        algorithm::{AlgorithmAttributes, Curve},
        crypto::{CardUploadableKey as _, EccType},
        data::KeyStatus,
    },
};
use openpgp_card_rpgp::public_key_material_to_key;
use openpgp_core::FullFingerprint;
use pgp::{
    crypto::public_key::PublicKeyAlgorithm,
    types::{EcdhPublicParams, EcdsaPublicParams, KeyDetails as _, KeyVersion, PublicParams},
};
use thiserror::Error;

use crate::{
    CardIdentity, ExpectedSerial, HardwareTestError,
    hardware_test::{DisposableCertificate, DisposableSlot},
    identity::{CanokeyIdentity, IdentityError},
    interaction::{CardInteractionError, PinProvider, PinPurpose},
    pcsc::{PcscContext, PcscError, require_exact_reader},
};

pub const DISPOSABLE_UPLOAD_AUTHORIZATION: &str = "authorize-disposable-p256-upload";

#[derive(Clone, Copy, Debug)]
pub struct DisposableUploadAuthorization {
    serial: ExpectedSerial,
}

impl DisposableUploadAuthorization {
    pub fn new(serial: ExpectedSerial, confirmation: &str) -> Result<Self, UploadError> {
        if confirmation != DISPOSABLE_UPLOAD_AUTHORIZATION {
            return Err(UploadError::AuthorizationRequired);
        }
        Ok(Self { serial })
    }
}

#[derive(Debug, Error)]
pub enum UploadError {
    #[error("explicit disposable-test authorization is required")]
    AuthorizationRequired,

    #[error("only v4 P-256 disposable signing and encryption subkeys are accepted by this test")]
    UnsupportedTestProfile,

    #[error("KDF configuration is present; this raw-PIN test must stop instead of downgrading")]
    UnsupportedKdf,

    #[error("KDF DO could not be read reliably: {0}")]
    Kdf(openpgp_card::Error),

    #[error("card KDF policy was rejected: {0}")]
    KdfPolicy(crate::remote_key::RemoteKeyError),

    #[error("the card does not advertise P-256 {0:?} support through a usable attribute source")]
    UnsupportedCardAlgorithm(DisposableSlot),

    #[error("the card does not advertise private-key import")]
    KeyImportUnavailable,

    #[error("the PIN is empty, too short, or exceeds the card limit; no VERIFY was sent")]
    InvalidPin,

    #[error("fewer than two Admin PIN retries remain; no VERIFY was sent")]
    PinRetriesUnavailable,

    #[error("the OpenPGP identity changed during the operation")]
    IdentityChanged,

    #[error("key information is unavailable, so the slot cannot be proven empty")]
    MissingKeyInformation,

    #[error("the requested {0:?} slot is not empty or retains key metadata")]
    SlotNotEmpty(DisposableSlot),

    #[error("the imported public key, fingerprint, creation time, or attributes do not match")]
    BindingMismatch,

    #[error("disposable certificate preparation failed: {0}")]
    Certificate(#[from] HardwareTestError),

    #[error("PC/SC failed: {0}")]
    Pcsc(#[from] PcscError),

    #[error("device identity validation failed: {0}")]
    Identity(#[from] IdentityError),

    #[error("PIN interaction failed: {0}")]
    Interaction(#[from] CardInteractionError),

    #[error("OpenPGP Card operation failed: {0}")]
    Card(#[from] openpgp_card::Error),

    #[error("card public-key conversion failed: {0}")]
    Conversion(#[from] openpgp_card_rpgp::Error),
}

pub fn upload_disposable_p256(
    authorization: &DisposableUploadAuthorization,
    reader: &str,
    certificate: &DisposableCertificate,
    slot: DisposableSlot,
    pins: &dyn PinProvider,
) -> Result<FullFingerprint, UploadError> {
    let component = certificate.public_component(slot)?;
    let imported = upload_components(
        authorization,
        reader,
        certificate,
        &[(slot, component)],
        pins,
    )?;
    imported
        .first()
        .cloned()
        .ok_or(UploadError::BindingMismatch)
}

pub fn upload_disposable_p256_pair(
    authorization: &DisposableUploadAuthorization,
    reader: &str,
    certificate: &DisposableCertificate,
    pins: &dyn PinProvider,
) -> Result<[FullFingerprint; 2], UploadError> {
    let components = [
        (
            DisposableSlot::Signing,
            certificate.public_component(DisposableSlot::Signing)?,
        ),
        (
            DisposableSlot::Decryption,
            certificate.public_component(DisposableSlot::Decryption)?,
        ),
    ];
    upload_components(authorization, reader, certificate, &components, pins)?
        .try_into()
        .map_err(|_| UploadError::BindingMismatch)
}

fn upload_components(
    authorization: &DisposableUploadAuthorization,
    reader: &str,
    certificate: &DisposableCertificate,
    components: &[(DisposableSlot, pgp::packet::PublicSubkey)],
    pins: &dyn PinProvider,
) -> Result<Vec<FullFingerprint>, UploadError> {
    for (slot, component) in components {
        validate_test_component(component, *slot)?;
    }

    let mut context = PcscContext::establish()?;
    let readers = context.list_readers()?;
    require_exact_reader(&readers, reader)?;
    let backend: Box<dyn card_backend::CardBackend + Send + Sync> =
        Box::new(context.connect(reader)?);
    let mut openpgp = Card::<openpgp_card::state::Open>::new(backend)?;
    let mut transaction = openpgp.transaction()?;
    let identity = revalidate_identity(&mut transaction, authorization.serial)?;

    for (slot, _) in components {
        require_empty_slot(&mut transaction, *slot)?;
        require_p256_support(transaction.card(), *slot)?;
    }
    require_raw_pin_mode(transaction.card())?;
    let password_status = transaction
        .card()
        .application_related_data()?
        .pw_status_bytes()?;
    if password_status.err_count_pw3() < 2 {
        return Err(UploadError::PinRetriesUnavailable);
    }

    let pin = pins.request_pin(PinPurpose::Admin, &identity)?;
    if pin.len() < 8 || pin.len() > usize::from(password_status.pw3_max_len()) {
        return Err(UploadError::InvalidPin);
    }
    transaction
        .card()
        .verify_pw3(pin.as_bytes().to_vec().into())?;
    drop(pin);

    if revalidate_identity(&mut transaction, authorization.serial)? != identity {
        return Err(UploadError::IdentityChanged);
    }
    for (slot, _) in components {
        require_empty_slot(&mut transaction, *slot)?;
    }

    let mut imported = Vec::with_capacity(components.len());
    for (slot, component) in components {
        let uploadable = certificate.uploadable_key(*slot)?;
        validate_uploadable(&uploadable, component)?;
        transaction
            .card()
            .key_import(&uploadable, card_slot(*slot))?;

        if revalidate_identity(&mut transaction, authorization.serial)? != identity {
            return Err(UploadError::IdentityChanged);
        }
        verify_imported_component(transaction.card(), component, *slot)?;
        imported.push(
            FullFingerprint::from_hex(&hex_uppercase(component.fingerprint().as_bytes()))
                .map_err(|_| UploadError::BindingMismatch)?,
        );
    }
    Ok(imported)
}

fn validate_test_component(
    component: &pgp::packet::PublicSubkey,
    slot: DisposableSlot,
) -> Result<(), UploadError> {
    let supported = component.version() == KeyVersion::V4
        && matches!(
            (slot, component.algorithm(), component.public_params()),
            (
                DisposableSlot::Signing,
                PublicKeyAlgorithm::ECDSA,
                PublicParams::ECDSA(EcdsaPublicParams::P256 { .. })
            ) | (
                DisposableSlot::Decryption,
                PublicKeyAlgorithm::ECDH,
                PublicParams::ECDH(EcdhPublicParams::P256 { .. })
            )
        );
    if supported {
        Ok(())
    } else {
        Err(UploadError::UnsupportedTestProfile)
    }
}

fn validate_uploadable(
    uploadable: &openpgp_card_rpgp::UploadableKey,
    component: &pgp::packet::PublicSubkey,
) -> Result<(), UploadError> {
    let fingerprint = uploadable.fingerprint()?;
    let creation_time = uploadable.timestamp().get();
    if fingerprint.as_bytes() == component.fingerprint().as_bytes()
        && creation_time == component.created_at().as_secs()
    {
        Ok(())
    } else {
        Err(UploadError::BindingMismatch)
    }
}

fn revalidate_identity(
    transaction: &mut Card<openpgp_card::state::Transaction<'_>>,
    serial: ExpectedSerial,
) -> Result<CardIdentity, UploadError> {
    let ard = transaction.card().application_related_data()?;
    let identity = CanokeyIdentity::verify(ard.application_id()?, serial)?;
    Ok(CardIdentity::from_application_identifier(identity.aid()))
}

fn require_empty_slot(
    transaction: &mut Card<openpgp_card::state::Transaction<'_>>,
    slot: DisposableSlot,
) -> Result<(), UploadError> {
    let ard = transaction.card().application_related_data()?;
    let information = ard
        .key_information()?
        .ok_or(UploadError::MissingKeyInformation)?;
    let status = match slot {
        DisposableSlot::Signing => information.sig_status(),
        DisposableSlot::Decryption => information.dec_status(),
    };
    let fingerprints = ard.fingerprints()?;
    let fingerprint = match slot {
        DisposableSlot::Signing => fingerprints.signature(),
        DisposableSlot::Decryption => fingerprints.decryption(),
    };
    let times = ard.key_generation_times()?;
    let time = match slot {
        DisposableSlot::Signing => times.signature(),
        DisposableSlot::Decryption => times.decryption(),
    };
    if status == KeyStatus::NotPresent && fingerprint.is_none() && time.is_none() {
        Ok(())
    } else {
        Err(UploadError::SlotNotEmpty(slot))
    }
}

fn require_p256_support(
    transaction: &mut OpenPGPTransaction<'_>,
    slot: DisposableSlot,
) -> Result<(), UploadError> {
    let key_type = card_slot(slot);
    let ecc_type = match slot {
        DisposableSlot::Signing => EccType::ECDSA,
        DisposableSlot::Decryption => EccType::ECDH,
    };
    let capabilities = transaction.extended_capabilities()?;
    if !capabilities.key_import() {
        return Err(UploadError::KeyImportUnavailable);
    }
    if !capabilities.algo_attrs_changeable() {
        let attributes = transaction
            .application_related_data()?
            .algorithm_attributes(key_type)?;
        return if is_p256_attribute(&attributes, ecc_type) {
            Ok(())
        } else {
            Err(UploadError::UnsupportedCardAlgorithm(slot))
        };
    }
    let information = transaction
        .algorithm_information()?
        .ok_or(UploadError::UnsupportedCardAlgorithm(slot))?;
    if information
        .for_keytype(key_type)
        .iter()
        .any(|attributes| is_p256_attribute(attributes, ecc_type))
    {
        Ok(())
    } else {
        Err(UploadError::UnsupportedCardAlgorithm(slot))
    }
}

fn is_p256_attribute(attributes: &AlgorithmAttributes, ecc_type: EccType) -> bool {
    matches!(
        attributes,
        AlgorithmAttributes::Ecc(attributes)
            if attributes.ecc_type() == ecc_type
                && matches!(attributes.curve(), Curve::NistP256r1)
    )
}

fn require_raw_pin_mode(transaction: &mut OpenPGPTransaction<'_>) -> Result<(), UploadError> {
    let kdf_advertised = transaction.extended_capabilities()?.kdf_do();
    match transaction.kdf_do() {
        Ok(kdf) => {
            crate::remote_key::validate_kdf(&kdf).map_err(UploadError::KdfPolicy)?;
            if kdf.kdf_algo() == 0 {
                Ok(())
            } else {
                Err(UploadError::UnsupportedKdf)
            }
        }
        Err(openpgp_card::Error::CardStatus(
            StatusBytes::ReferencedDataNotFound | StatusBytes::FileOrApplicationNotFound,
        )) if !kdf_advertised => Ok(()),
        Err(error) => Err(UploadError::Kdf(error)),
    }
}

type OpenPGPTransaction<'a> = openpgp_card::ocard::Transaction<'a>;

fn verify_imported_component(
    transaction: &mut OpenPGPTransaction<'_>,
    expected: &pgp::packet::PublicSubkey,
    slot: DisposableSlot,
) -> Result<(), UploadError> {
    let ard = transaction.application_related_data()?;
    let key_type = card_slot(slot);
    let fingerprints = ard.fingerprints()?;
    let card_fingerprint = match slot {
        DisposableSlot::Signing => fingerprints.signature(),
        DisposableSlot::Decryption => fingerprints.decryption(),
    }
    .ok_or(UploadError::BindingMismatch)?;
    let generation_times = ard.key_generation_times()?;
    let creation_time = match slot {
        DisposableSlot::Signing => generation_times.signature(),
        DisposableSlot::Decryption => generation_times.decryption(),
    }
    .ok_or(UploadError::BindingMismatch)?;
    if card_fingerprint.as_bytes() != expected.fingerprint().as_bytes()
        || creation_time.get() != expected.created_at().as_secs()
    {
        return Err(UploadError::BindingMismatch);
    }

    let (hash, symmetric) = match expected.public_params() {
        PublicParams::ECDH(EcdhPublicParams::P256 { hash, alg_sym, .. }) => {
            (Some(*hash), Some(*alg_sym))
        }
        _ => (None, None),
    };
    let material = transaction.public_key(key_type)?;
    let actual = public_key_material_to_key(&material, key_type, creation_time, hash, symmetric)?;
    if actual.version() == expected.version()
        && actual.fingerprint() == expected.fingerprint()
        && actual.algorithm() == expected.algorithm()
        && actual.created_at() == expected.created_at()
        && actual.public_params() == expected.public_params()
    {
        Ok(())
    } else {
        Err(UploadError::BindingMismatch)
    }
}

const fn card_slot(slot: DisposableSlot) -> KeyType {
    match slot {
        DisposableSlot::Signing => KeyType::Signing,
        DisposableSlot::Decryption => KeyType::Decryption,
    }
}

fn hex_uppercase(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            let _ = write!(output, "{byte:02X}");
            output
        },
    )
}

#[cfg(test)]
mod tests {
    use openpgp_policy::GenerationProfile;

    use super::*;

    struct NoPin;

    impl PinProvider for NoPin {
        fn request_pin(
            &self,
            _purpose: PinPurpose,
            _identity: &CardIdentity,
        ) -> Result<zeroize::Zeroizing<String>, CardInteractionError> {
            panic!("PIN entry must not be reached for an invalid test profile")
        }
    }

    #[test]
    fn authorization_requires_an_explicit_test_scope() {
        let serial = "1234ABCD".parse().expect("synthetic serial");
        assert!(matches!(
            DisposableUploadAuthorization::new(serial, "not-authorized"),
            Err(UploadError::AuthorizationRequired)
        ));
        assert!(
            DisposableUploadAuthorization::new(serial, DISPOSABLE_UPLOAD_AUTHORIZATION).is_ok()
        );
    }

    #[test]
    fn non_p256_v4_profiles_are_rejected_before_connecting_or_requesting_a_pin() {
        let certificate = DisposableCertificate::generate(&GenerationProfile::modern_v6())
            .expect("disposable certificate");
        let authorization = DisposableUploadAuthorization::new(
            "1234ABCD".parse().expect("synthetic serial"),
            DISPOSABLE_UPLOAD_AUTHORIZATION,
        )
        .expect("explicit test authorization");
        let result = upload_disposable_p256(
            &authorization,
            "",
            &certificate,
            DisposableSlot::Signing,
            &NoPin,
        );
        assert!(matches!(result, Err(UploadError::UnsupportedTestProfile)));
    }
}
