use std::{io, path::Path, process::Command};

use openpgp_card_rpgp::UploadableKey;
use openpgp_core::{
    ExportFormat, FullFingerprint, KeyError, PrivateExportPolicy, SoftwareKeyStore,
};
use openpgp_policy::GenerationProfile;
use pgp::{
    composed::{Deserializable as _, SignedPublicKey, SignedSecretKey},
    packet::PublicSubkey,
};
use rand::RngCore as _;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{CANOKEYS_MANUFACTURER, CardIdentity, ExpectedSerial};

pub const DISPOSABLE_CRYPTO_AUTHORIZATION: &str = "authorize-disposable-p256-crypto";

#[derive(Clone, Copy, Debug)]
pub struct CanokeyCryptoAuthorization {
    serial: ExpectedSerial,
}

impl CanokeyCryptoAuthorization {
    pub fn new(serial: ExpectedSerial, confirmation: &str) -> Result<Self, HardwareTestError> {
        if confirmation != DISPOSABLE_CRYPTO_AUTHORIZATION {
            return Err(HardwareTestError::AuthorizationRequired);
        }
        Ok(Self { serial })
    }

    pub fn validate_identity(self, identity: CardIdentity) -> Result<(), HardwareTestError> {
        if identity.manufacturer() == CANOKEYS_MANUFACTURER
            && identity.serial() == self.serial.get()
        {
            Ok(())
        } else {
            Err(HardwareTestError::UnexpectedDevice)
        }
    }
}

pub fn validate_usb_identity(
    reader: &str,
    serial: ExpectedSerial,
    usb_serial: ExpectedSerial,
) -> Result<(), HardwareTestError> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../scripts/canokey_target.py");
    let output = Command::new("python3")
        .arg(script)
        .arg("--reader")
        .arg(reader)
        .arg("--serial")
        .arg(format!("{:08X}", serial.get()))
        .arg("--usb-serial")
        .arg(format!("{:08X}", usb_serial.get()))
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(HardwareTestError::UsbIdentityRejected)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisposableSlot {
    Signing,
    Decryption,
}

impl DisposableSlot {
    const fn subkey_index(self) -> usize {
        match self {
            Self::Signing => 0,
            Self::Decryption => 1,
        }
    }
}

#[derive(Debug, Error)]
pub enum HardwareTestError {
    #[error("disposable certificate generation failed: {0}")]
    Key(#[from] KeyError),

    #[error("disposable certificate encoding failed: {0}")]
    Rpgp(#[from] pgp::errors::Error),

    #[error("disposable key conversion failed: {0}")]
    Card(#[from] openpgp_card::Error),

    #[error("the disposable certificate unexpectedly contains an unprotected private key")]
    UnprotectedPrivateKey,

    #[error("USB evidence collection failed: {0}")]
    UsbEvidence(#[from] io::Error),

    #[error("live USB identity validation failed; no card connection was attempted")]
    UsbIdentityRejected,

    #[error("explicit disposable cryptographic-test authorization is required")]
    AuthorizationRequired,

    #[error("the OpenPGP card is not the explicitly authorized CanoKey test device")]
    UnexpectedDevice,
}

pub struct DisposableCertificate {
    store: SoftwareKeyStore,
    fingerprint: FullFingerprint,
    protection_password: Zeroizing<String>,
}

impl DisposableCertificate {
    pub fn generate(profile: &GenerationProfile) -> Result<Self, HardwareTestError> {
        let protection_password = random_protection_password();
        let mut store = SoftwareKeyStore::new();
        let generated = store.generate(
            profile,
            "Addressee disposable card test; not a production identity",
            protection_password.as_str(),
            PrivateExportPolicy::Allowed,
        )?;
        Ok(Self {
            store,
            fingerprint: generated.metadata.fingerprint,
            protection_password,
        })
    }

    pub fn fingerprint(&self) -> &FullFingerprint {
        &self.fingerprint
    }

    pub fn public_certificate(&self) -> Result<SignedPublicKey, HardwareTestError> {
        let bytes = self
            .store
            .export_public(&self.fingerprint, ExportFormat::Binary)?;
        let certificate = SignedPublicKey::from_bytes(bytes.as_slice())?;
        certificate.verify_bindings()?;
        Ok(certificate)
    }

    pub fn public_component(
        &self,
        slot: DisposableSlot,
    ) -> Result<PublicSubkey, HardwareTestError> {
        Ok(self
            .public_certificate()?
            .public_subkeys
            .into_iter()
            .nth(slot.subkey_index())
            .expect("the standard generation profile has two subkeys")
            .key)
    }

    pub fn public_armor(&self) -> Result<Vec<u8>, HardwareTestError> {
        Ok(self
            .store
            .export_public(&self.fingerprint, ExportFormat::Armored)?)
    }

    pub fn import_public_into(
        &self,
        store: &mut SoftwareKeyStore,
    ) -> Result<(), HardwareTestError> {
        store.import_public(&self.public_armor()?)?;
        Ok(())
    }

    pub fn uploadable_key(&self, slot: DisposableSlot) -> Result<UploadableKey, HardwareTestError> {
        let exported = Zeroizing::new(
            self.store
                .export_private(&self.fingerprint, ExportFormat::Binary)?,
        );
        let secret = SignedSecretKey::from_bytes(exported.as_slice())?;
        secret.verify_bindings()?;
        secret.to_public_key().verify_bindings()?;
        let component = secret
            .secret_subkeys
            .into_iter()
            .nth(slot.subkey_index())
            .expect("the standard generation profile has two subkeys")
            .key;
        let mut uploadable = UploadableKey::from(component);
        if !uploadable.is_locked() {
            return Err(HardwareTestError::UnprotectedPrivateKey);
        }
        if !uploadable.try_unlock(self.protection_password.as_str())? {
            return Err(HardwareTestError::UnprotectedPrivateKey);
        }
        Ok(uploadable)
    }
}

fn random_protection_password() -> Zeroizing<String> {
    let mut random = Zeroizing::new([0_u8; 32]);
    rand::thread_rng().fill_bytes(random.as_mut_slice());
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut password = String::with_capacity(random.len() * 2);
    for byte in random.iter() {
        password.push(HEX[(byte >> 4) as usize] as char);
        password.push(HEX[(byte & 0x0F) as usize] as char);
    }
    Zeroizing::new(password)
}

#[cfg(test)]
mod tests {
    use openpgp_core::KeyStorage;
    use openpgp_policy::{Algorithm, CompatibilityAcknowledgement, GenerationProfile};
    use pgp::{crypto::public_key::PublicKeyAlgorithm, types::KeyDetails as _};

    use super::*;

    #[test]
    fn p256_test_components_are_bound_and_initially_password_protected() {
        let certificate = DisposableCertificate::generate(&GenerationProfile::nist_p256_v4())
            .expect("disposable P-256 certificate");
        let public = certificate
            .public_certificate()
            .expect("public certificate");
        assert_eq!(public.version(), pgp::types::KeyVersion::V4);
        assert_eq!(public.public_subkeys.len(), 2);
        assert_eq!(
            certificate
                .public_component(DisposableSlot::Signing)
                .expect("signing component")
                .algorithm(),
            PublicKeyAlgorithm::ECDSA
        );
        assert_eq!(
            certificate
                .public_component(DisposableSlot::Decryption)
                .expect("decryption component")
                .algorithm(),
            PublicKeyAlgorithm::ECDH
        );
        let _signing = certificate
            .uploadable_key(DisposableSlot::Signing)
            .expect("protected signing key must unlock for authorized upload");
        let _decryption = certificate
            .uploadable_key(DisposableSlot::Decryption)
            .expect("protected decryption key must unlock for authorized upload");

        let mut public_only = SoftwareKeyStore::new();
        certificate
            .import_public_into(&mut public_only)
            .expect("public-only import");
        let metadata = public_only
            .metadata(certificate.fingerprint())
            .expect("public metadata");
        assert_eq!(metadata.storage, KeyStorage::PublicOnly);
    }

    #[test]
    fn legacy_rsa_requires_an_explicit_compatibility_acknowledgement() {
        assert!(
            GenerationProfile::legacy_rsa_v4(
                Algorithm::Rsa2048,
                CompatibilityAcknowledgement::not_acknowledged(),
            )
            .is_err()
        );
    }

    #[test]
    fn cryptographic_tests_require_the_explicit_device_and_scope() {
        let serial = "1234ABCD".parse().expect("synthetic serial");
        assert!(matches!(
            CanokeyCryptoAuthorization::new(serial, "unrelated-operation"),
            Err(HardwareTestError::AuthorizationRequired)
        ));
        let authorization =
            CanokeyCryptoAuthorization::new(serial, DISPOSABLE_CRYPTO_AUTHORIZATION)
                .expect("authorized test scope");
        assert!(
            authorization
                .validate_identity(CardIdentity::new(CANOKEYS_MANUFACTURER, 0x1234ABCD, 0x0304))
                .is_ok()
        );
        assert!(matches!(
            authorization.validate_identity(CardIdentity::new(0x0006, 0x1234ABCD, 0x0304)),
            Err(HardwareTestError::UnexpectedDevice)
        ));
        assert!(matches!(
            authorization.validate_identity(CardIdentity::new(
                CANOKEYS_MANUFACTURER,
                0x0000ABCD,
                0x0304,
            )),
            Err(HardwareTestError::UnexpectedDevice)
        ));
    }
}
