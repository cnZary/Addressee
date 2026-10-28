use std::sync::Arc;

use openpgp_card::{
    Card,
    ocard::{
        KeyType, StatusBytes,
        data::{KeyInformation, KeyStatus, TouchPolicy},
    },
    state::{Open, Transaction},
};
use openpgp_card_adapter::{
    CardIdentity,
    remote_key::{CardSession, RemoteKeyError, validate_kdf},
    transport::{RawCardTransport, TransportCardBackend},
};
use zeroize::Zeroizing;

use crate::{
    AddresseeError, CardIdentityFfi, CardSlot, CardTransport,
    card::{FfiTransport, ffi_transport, map_card_error},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum CardPinKind {
    User,
    Admin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum CardTouchPolicyFfi {
    Off,
    On,
}

impl From<CardTouchPolicyFfi> for TouchPolicy {
    fn from(value: CardTouchPolicyFfi) -> Self {
        match value {
            CardTouchPolicyFfi::Off => Self::Off,
            CardTouchPolicyFfi::On => Self::On,
        }
    }
}

fn card_slot(slot: KeyType) -> Result<CardSlot, AddresseeError> {
    match slot {
        KeyType::Signing => Ok(CardSlot::Signing),
        KeyType::Decryption => Ok(CardSlot::Decryption),
        KeyType::Authentication => Ok(CardSlot::Authentication),
        KeyType::Attestation => Err(AddresseeError::UnsupportedOperation),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct CardSlotInformationFfi {
    pub slot: CardSlot,
    pub algorithm_attributes: String,
    pub advertised_algorithms: Vec<String>,
    pub fingerprint: Option<String>,
    pub created_at: Option<u64>,
    pub key_reference: Option<u8>,
    pub key_present: Option<bool>,
    pub touch_policy: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct CardInformationFfi {
    pub identity: CardIdentityFfi,
    pub user_pin_retries: u8,
    pub reset_code_retries: u8,
    pub admin_pin_retries: u8,
    pub user_pin_max_length: u8,
    pub admin_pin_max_length: u8,
    pub signature_pin_valid_once: bool,
    pub key_import_advertised: bool,
    pub algorithm_attributes_changeable: bool,
    pub password_status_changeable: bool,
    pub slots: Vec<CardSlotInformationFfi>,
}

#[derive(uniffi::Object)]
pub struct OpenPgpCardManagementSession {
    identity: CardIdentityFfi,
    transport: Arc<FfiTransport>,
    card: std::sync::Mutex<Card<Open>>,
}

#[uniffi::export]
impl OpenPgpCardManagementSession {
    #[uniffi::constructor]
    pub fn connect(
        identity: CardIdentityFfi,
        transport: Arc<dyn CardTransport>,
    ) -> Result<Self, AddresseeError> {
        let transport = ffi_transport(transport);
        let raw: Arc<dyn RawCardTransport> = transport.clone();
        let actual = CardSession::identify_with_transport(raw)
            .map_err(|error| map_management_error(&transport, error))?;
        if CardIdentityFfi::from(actual) != identity {
            return Err(AddresseeError::ConflictingCertificate);
        }
        let backend = TransportCardBackend::new(transport.clone())
            .map_err(|error| map_management_error(&transport, RemoteKeyError::Transport(error)))?;
        let backend: Box<dyn card_backend::CardBackend + Send + Sync> = Box::new(backend);
        let card = Card::<Open>::new(backend)
            .map_err(|error| map_management_card_error(&transport, error))?;
        Ok(Self {
            identity,
            transport,
            card: std::sync::Mutex::new(card),
        })
    }

    pub fn inspect(&self) -> Result<CardInformationFfi, AddresseeError> {
        let mut card = self.card()?;
        let mut transaction = card.transaction().map_err(|error| self.map_error(error))?;
        let identity = self.fresh_identity(&mut transaction)?;
        let ard = transaction
            .card()
            .application_related_data()
            .map_err(|error| self.map_error(error))?;
        let capabilities = ard
            .extended_capabilities()
            .map_err(|error| self.map_error(error))?;
        let password = ard
            .pw_status_bytes()
            .map_err(|error| self.map_error(error))?;
        let algorithms = if capabilities.algo_attrs_changeable() {
            transaction
                .algorithm_information()
                .map_err(|error| self.map_error(error))?
        } else {
            None
        };
        let slots = [
            KeyType::Signing,
            KeyType::Decryption,
            KeyType::Authentication,
        ]
        .into_iter()
        .map(|slot| {
            let attributes = ard
                .algorithm_attributes(slot)
                .map_err(|error| self.map_error(error))?;
            let fingerprints = ard.fingerprints().map_err(|error| self.map_error(error))?;
            let fingerprint = match slot {
                KeyType::Signing => fingerprints.signature(),
                KeyType::Decryption => fingerprints.decryption(),
                KeyType::Authentication => fingerprints.authentication(),
                KeyType::Attestation => None,
            }
            .map(|fingerprint| hexadecimal(fingerprint.as_bytes()));
            let times = ard
                .key_generation_times()
                .map_err(|error| self.map_error(error))?;
            let created_at = match slot {
                KeyType::Signing => times.signature(),
                KeyType::Decryption => times.decryption(),
                KeyType::Authentication => times.authentication(),
                KeyType::Attestation => None,
            }
            .map(|time| u64::from(time.get()));
            let information = ard
                .key_information()
                .map_err(|error| self.map_error(error))?;
            let status = information
                .as_ref()
                .and_then(|information| slot_status(information, slot));
            let (key_reference, key_present) = status
                .map(|(reference, status)| {
                    let present = match status {
                        KeyStatus::NotPresent => Some(false),
                        KeyStatus::Generated | KeyStatus::Imported => Some(true),
                        KeyStatus::Unknown(_) => None,
                    };
                    (reference, present)
                })
                .unzip();
            let key_present = key_present.flatten();
            let touch_policy = transaction
                .user_interaction_flag(slot)
                .map_err(|error| self.map_error(error))?
                .map(|flag| format!("{:?}", flag.touch_policy()));
            let advertised_algorithms = algorithms.as_ref().map_or_else(Vec::new, |information| {
                information
                    .for_keytype(slot)
                    .iter()
                    .map(|attributes| format!("{attributes:?}"))
                    .collect()
            });
            Ok(CardSlotInformationFfi {
                slot: card_slot(slot)?,
                algorithm_attributes: format!("{attributes:?}"),
                advertised_algorithms,
                fingerprint,
                created_at,
                key_reference,
                key_present,
                touch_policy,
            })
        })
        .collect::<Result<Vec<_>, AddresseeError>>()?;
        Ok(CardInformationFfi {
            identity,
            user_pin_retries: password.err_count_pw1(),
            reset_code_retries: password.err_count_rc(),
            admin_pin_retries: password.err_count_pw3(),
            user_pin_max_length: password.pw1_max_len(),
            admin_pin_max_length: password.pw3_max_len(),
            signature_pin_valid_once: password.pw1_cds_valid_once(),
            key_import_advertised: capabilities.key_import(),
            algorithm_attributes_changeable: capabilities.algo_attrs_changeable(),
            password_status_changeable: capabilities.pw_status_change(),
            slots,
        })
    }

    pub fn change_pin(
        &self,
        kind: CardPinKind,
        current: String,
        new: String,
    ) -> Result<(), AddresseeError> {
        let current = Zeroizing::new(current);
        let new = Zeroizing::new(new);
        if current.as_str() == new.as_str() {
            return Err(AddresseeError::InvalidInput);
        }
        let mut card = self.card()?;
        let mut transaction = card.transaction().map_err(|error| self.map_error(error))?;
        self.fresh_identity(&mut transaction)?;
        let password = transaction
            .card()
            .application_related_data()
            .and_then(|ard| ard.pw_status_bytes())
            .map_err(|error| self.map_error(error))?;
        let (minimum, maximum, retries) = match kind {
            CardPinKind::User => (6, password.pw1_max_len(), password.err_count_pw1()),
            CardPinKind::Admin => (8, password.pw3_max_len(), password.err_count_pw3()),
        };
        if retries < 2 {
            return Err(map_card_error(RemoteKeyError::PinRetriesUnavailable {
                remaining_retries: retries,
            }));
        }
        let maximum = usize::from(maximum);
        for pin in [&current, &new] {
            if !(minimum..=maximum).contains(&pin.len()) {
                return Err(AddresseeError::InvalidInput);
            }
        }
        self.validate_kdf(&mut transaction)?;
        match kind {
            CardPinKind::User => {
                transaction.change_user_pin(current.as_str().into(), new.as_str().into())
            }
            CardPinKind::Admin => {
                transaction.change_admin_pin(current.as_str().into(), new.as_str().into())
            }
        }
        .map_err(|error| self.map_error(error))?;
        self.fresh_identity(&mut transaction)?;
        Ok(())
    }

    pub fn set_touch_policy(
        &self,
        slot: CardSlot,
        policy: CardTouchPolicyFfi,
        admin_pin: String,
    ) -> Result<(), AddresseeError> {
        let slot = KeyType::from(slot);
        let policy = TouchPolicy::from(policy);
        let admin_pin = Zeroizing::new(admin_pin);
        let mut card = self.card()?;
        let mut transaction = card.transaction().map_err(|error| self.map_error(error))?;
        self.fresh_identity(&mut transaction)?;
        let flag = transaction
            .user_interaction_flag(slot)
            .map_err(|error| self.map_error(error))?
            .ok_or(AddresseeError::UnsupportedOperation)?;
        let current = flag.touch_policy();
        if matches!(
            current,
            TouchPolicy::Fixed | TouchPolicy::CachedFixed | TouchPolicy::Unknown(_)
        ) {
            return Err(AddresseeError::UnsupportedOperation);
        }
        if current == policy {
            return Err(AddresseeError::InvalidInput);
        }
        let password = transaction
            .card()
            .application_related_data()
            .and_then(|ard| ard.pw_status_bytes())
            .map_err(|error| self.map_error(error))?;
        if password.err_count_pw3() < 2 {
            return Err(map_card_error(RemoteKeyError::PinRetriesUnavailable {
                remaining_retries: password.err_count_pw3(),
            }));
        }
        if !(8..=usize::from(password.pw3_max_len())).contains(&admin_pin.len()) {
            return Err(AddresseeError::InvalidInput);
        }
        self.validate_kdf(&mut transaction)?;
        {
            let mut admin = transaction
                .as_admin_card(Some(admin_pin.as_str().into()))
                .map_err(|error| self.map_error(error))?;
            admin
                .set_touch_policy(slot, policy)
                .map_err(|error| self.map_error(error))?;
        }
        self.fresh_identity(&mut transaction)?;
        Ok(())
    }
}

impl OpenPgpCardManagementSession {
    fn card(&self) -> Result<std::sync::MutexGuard<'_, Card<Open>>, AddresseeError> {
        self.card
            .lock()
            .map_err(|_| AddresseeError::CardSessionUnavailable)
    }

    fn fresh_identity(
        &self,
        transaction: &mut Card<Transaction<'_>>,
    ) -> Result<CardIdentityFfi, AddresseeError> {
        let identity = transaction
            .card()
            .application_related_data()
            .and_then(|ard| ard.application_id())
            .map(|aid| CardIdentity::from_application_identifier(&aid))
            .map(CardIdentityFfi::from)
            .map_err(|error| self.map_error(error))?;
        if identity != self.identity {
            return Err(AddresseeError::ConflictingCertificate);
        }
        Ok(identity)
    }

    fn validate_kdf(&self, transaction: &mut Card<Transaction<'_>>) -> Result<(), AddresseeError> {
        let advertised = transaction
            .extended_capabilities()
            .map_err(|error| self.map_error(error))?
            .kdf_do();
        match transaction.kdf_do() {
            Ok(kdf) => validate_kdf(&kdf).map_err(map_card_error),
            Err(openpgp_card::Error::CardStatus(
                StatusBytes::ReferencedDataNotFound | StatusBytes::FileOrApplicationNotFound,
            )) if !advertised => Ok(()),
            Err(openpgp_card::Error::NotFound(_)) if !advertised => Ok(()),
            Err(error) => Err(self.map_error(error)),
        }
    }

    fn map_error(&self, error: openpgp_card::Error) -> AddresseeError {
        map_management_card_error(&self.transport, error)
    }
}

fn map_management_error(transport: &FfiTransport, error: RemoteKeyError) -> AddresseeError {
    if transport.failure_kind() == openpgp_core::RemoteKeyFailure::Cancelled {
        AddresseeError::OperationCancelled
    } else {
        map_card_error(error)
    }
}

fn map_management_card_error(
    transport: &FfiTransport,
    error: openpgp_card::Error,
) -> AddresseeError {
    match error {
        openpgp_card::Error::CardStatus(StatusBytes::PasswordNotChecked(_)) => {
            AddresseeError::InvalidPassword
        }
        openpgp_card::Error::UnsupportedFeature(_) => AddresseeError::UnsupportedOperation,
        error => map_management_error(transport, RemoteKeyError::Card(error)),
    }
}

fn slot_status(information: &KeyInformation, slot: KeyType) -> Option<(u8, KeyStatus)> {
    match slot {
        KeyType::Signing => Some((information.sig_ref(), information.sig_status())),
        KeyType::Decryption => Some((information.dec_ref(), information.dec_status())),
        KeyType::Authentication => Some((information.aut_ref(), information.aut_status())),
        KeyType::Attestation => None,
    }
}

fn hexadecimal(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            let _ = write!(output, "{byte:02X}");
            output
        },
    )
}
