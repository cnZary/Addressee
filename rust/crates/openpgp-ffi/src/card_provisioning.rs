use openpgp_card_adapter::provisioning::{ProvisioningError, generate_p256_certificate};
use pgp::{ser::Serialize as _, types::KeyDetails as _};
use zeroize::Zeroizing;

use crate::{
    AddresseeError, CardIdentityFfi, OpenPgpCardManagementSession, card::map_card_error,
    card_management::map_management_card_error,
};

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct CardGeneratedCertificateFfi {
    pub identity: CardIdentityFfi,
    pub certificate_fingerprint: String,
    pub signing_component: String,
    pub decryption_component: String,
    pub public_certificate: Vec<u8>,
}

#[uniffi::export]
impl OpenPgpCardManagementSession {
    pub fn generate_p256_key(
        &self,
        user_id: String,
        user_pin: String,
        admin_pin: String,
        replace_existing: bool,
    ) -> Result<CardGeneratedCertificateFfi, AddresseeError> {
        crate::policy::validate_card_p256_generation()?;
        let mut card = self.card()?;
        let mut transaction = card.transaction().map_err(|error| self.map_error(error))?;
        let certificate = generate_p256_certificate(
            &mut transaction,
            self.identity().into(),
            &user_id,
            Zeroizing::new(user_pin),
            Zeroizing::new(admin_pin),
            replace_existing,
        )
        .map_err(|error| self.map_provisioning_error(error))?;
        let public_certificate = certificate
            .to_bytes()
            .map_err(|_| AddresseeError::CardProvisioningIncomplete)?;
        let [decryption] = certificate.public_subkeys.as_slice() else {
            return Err(AddresseeError::CardProvisioningIncomplete);
        };
        Ok(CardGeneratedCertificateFfi {
            identity: self.identity(),
            certificate_fingerprint: format!("{:X}", certificate.primary_key.fingerprint()),
            signing_component: format!("{:X}", certificate.primary_key.fingerprint()),
            decryption_component: format!("{:X}", decryption.key.fingerprint()),
            public_certificate,
        })
    }
}

impl OpenPgpCardManagementSession {
    fn map_provisioning_error(&self, error: ProvisioningError) -> AddresseeError {
        match error {
            ProvisioningError::InvalidUserId | ProvisioningError::InvalidPin => {
                AddresseeError::InvalidInput
            }
            ProvisioningError::PinRetriesUnavailable => AddresseeError::RemoteKeyUnavailable,
            ProvisioningError::SlotNotEmpty => AddresseeError::CardSlotNotEmpty,
            ProvisioningError::UnsupportedAlgorithm => AddresseeError::UnsupportedOperation,
            ProvisioningError::IdentityMismatch => AddresseeError::CardRegistrationConflict,
            ProvisioningError::MissingSlotData
            | ProvisioningError::BindingMismatch
            | ProvisioningError::Conversion(_)
            | ProvisioningError::Certificate(_) => AddresseeError::CardProvisioningIncomplete,
            ProvisioningError::Card(error) => map_management_card_error(self.transport(), error),
            ProvisioningError::Kdf(error) => map_card_error(error),
        }
    }
}
