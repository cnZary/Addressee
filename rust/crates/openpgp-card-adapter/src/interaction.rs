use openpgp_card::ocard::KeyType;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::CardIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinPurpose {
    Signing,
    User,
    Admin,
}

#[derive(Debug, Error)]
pub enum CardInteractionError {
    #[error("PIN entry was cancelled")]
    Cancelled,

    #[error("PIN entry is unavailable: {0}")]
    Unavailable(String),

    #[error("PIN entry protocol failed: {0}")]
    Protocol(&'static str),

    #[error("PIN entry returned an error code: {0:?}")]
    Rejected(Option<u32>),

    #[error("PIN is not valid UTF-8")]
    InvalidEncoding,

    #[error("PIN length {actual} exceeds the {maximum}-byte limit")]
    InvalidLength { actual: usize, maximum: usize },

    #[error("PIN is empty; no verification command was sent")]
    EmptyPin,

    #[error("touch confirmation failed: {0}")]
    TouchFailed(String),
}

pub trait PinProvider: Send + Sync {
    fn request_pin(
        &self,
        purpose: PinPurpose,
        identity: &CardIdentity,
    ) -> Result<Zeroizing<String>, CardInteractionError>;
}

pub trait TouchPrompt: Send + Sync {
    fn request_touch(&self, slot: KeyType) -> Result<(), CardInteractionError>;
}

pub struct StderrTouchPrompt;

impl TouchPrompt for StderrTouchPrompt {
    fn request_touch(&self, slot: KeyType) -> Result<(), CardInteractionError> {
        eprintln!("Touch the OpenPGP card to authorize the {slot:?} operation.");
        Ok(())
    }
}
