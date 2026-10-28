use std::marker::PhantomData;

use super::{PcscError, Protocol};

pub struct PcscContext;

pub struct PcscCard;

pub struct PcscTransaction<'card> {
    _card: PhantomData<&'card mut PcscCard>,
}

impl PcscContext {
    pub fn establish() -> Result<Self, PcscError> {
        Err(PcscError::UnsupportedPlatform)
    }

    pub fn list_readers(&mut self) -> Result<Vec<String>, PcscError> {
        Err(PcscError::UnsupportedPlatform)
    }

    pub fn connect(self, _reader_name: &str) -> Result<PcscCard, PcscError> {
        Err(PcscError::UnsupportedPlatform)
    }

    pub fn release(self) -> Result<(), PcscError> {
        Err(PcscError::UnsupportedPlatform)
    }
}

impl PcscCard {
    pub fn protocol(&self) -> Result<Protocol, PcscError> {
        Err(PcscError::UnsupportedPlatform)
    }

    pub fn begin_transaction(&mut self) -> Result<PcscTransaction<'_>, PcscError> {
        Err(PcscError::UnsupportedPlatform)
    }

    pub fn disconnect(self) -> Result<(), PcscError> {
        Err(PcscError::UnsupportedPlatform)
    }
}

impl PcscTransaction<'_> {
    pub fn transmit_apdu(&mut self, _command: &[u8]) -> Result<Vec<u8>, PcscError> {
        Err(PcscError::UnsupportedPlatform)
    }

    pub fn end(self) -> Result<(), PcscError> {
        Err(PcscError::UnsupportedPlatform)
    }
}
