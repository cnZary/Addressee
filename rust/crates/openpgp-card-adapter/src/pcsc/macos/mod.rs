use std::ffi::CString;

use super::{
    PcscError, Protocol, RESPONSE_BUFFER_LEN, parse_reader_list, validate_command_length,
    validate_reader_name, validate_response_length,
};

mod ffi;

pub struct PcscContext {
    handle: Option<i32>,
}

impl PcscContext {
    pub fn establish() -> Result<Self, PcscError> {
        Ok(Self {
            handle: Some(ffi::establish_context()?),
        })
    }

    pub fn list_readers(&mut self) -> Result<Vec<String>, PcscError> {
        parse_reader_list(&ffi::list_readers(self.handle()?)?)
    }

    pub fn connect(self, reader_name: &str) -> Result<PcscCard, PcscError> {
        validate_reader_name(reader_name)?;
        let reader_name =
            CString::new(reader_name.as_bytes()).map_err(|_| PcscError::InvalidReaderName)?;
        let (card_handle, raw_protocol) = ffi::connect(self.handle()?, &reader_name)?;
        let protocol = match Protocol::from_raw(raw_protocol) {
            Ok(protocol) => protocol,
            Err(error) => {
                let _ = ffi::disconnect(card_handle);
                return Err(error);
            }
        };

        Ok(PcscCard {
            _context: self,
            card_handle: Some(card_handle),
            protocol,
            transaction_active: false,
        })
    }

    pub fn release(mut self) -> Result<(), PcscError> {
        let handle = self
            .handle
            .take()
            .ok_or(PcscError::InvalidState("context already released"))?;
        ffi::release_context(handle)
    }

    fn handle(&self) -> Result<i32, PcscError> {
        self.handle
            .ok_or(PcscError::InvalidState("context already released"))
    }
}

impl Drop for PcscContext {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = ffi::release_context(handle);
        }
    }
}

pub struct PcscCard {
    _context: PcscContext,
    card_handle: Option<i32>,
    protocol: Protocol,
    transaction_active: bool,
}

impl PcscCard {
    pub fn protocol(&self) -> Result<Protocol, PcscError> {
        Ok(self.protocol)
    }

    pub fn begin_transaction(&mut self) -> Result<PcscTransaction<'_>, PcscError> {
        if self.transaction_active {
            return Err(PcscError::InvalidState("transaction already active"));
        }

        let handle = self.card_handle()?;
        ffi::begin_transaction(handle)?;
        self.transaction_active = true;
        Ok(PcscTransaction {
            card: self,
            active: true,
        })
    }

    pub fn disconnect(mut self) -> Result<(), PcscError> {
        let handle = self.card_handle()?;
        if self.transaction_active {
            ffi::end_transaction(handle)?;
            self.transaction_active = false;
        }
        self.card_handle = None;
        ffi::disconnect(handle)
    }

    fn card_handle(&self) -> Result<i32, PcscError> {
        self.card_handle
            .ok_or(PcscError::InvalidState("card already disconnected"))
    }
}

impl Drop for PcscCard {
    fn drop(&mut self) {
        if self.transaction_active {
            if let Some(handle) = self.card_handle {
                let _ = ffi::end_transaction(handle);
            }
            self.transaction_active = false;
        }
        if let Some(handle) = self.card_handle.take() {
            let _ = ffi::disconnect(handle);
        }
    }
}

/// An owned PC/SC transaction that exclusively borrows its card.
///
/// Safe code cannot disconnect the card or start another transaction until
/// this value is ended or dropped. Every operation that calls PC/SC requires
/// `&mut self` or consumes the value, so moving it between threads does not
/// permit concurrent calls.
pub struct PcscTransaction<'card> {
    card: &'card mut PcscCard,
    active: bool,
}

impl PcscTransaction<'_> {
    pub fn transmit_apdu(&mut self, command: &[u8]) -> Result<Vec<u8>, PcscError> {
        validate_command_length(command.len())?;
        if !self.active {
            return Err(PcscError::InvalidState("transaction already ended"));
        }

        let mut response = vec![0; RESPONSE_BUFFER_LEN];
        let reported = ffi::transmit(
            self.card.card_handle()?,
            self.card.protocol,
            command,
            &mut response,
        )?;
        let response_len = validate_response_length(reported, response.len())?;
        response.truncate(response_len);
        Ok(response)
    }

    pub fn end(mut self) -> Result<(), PcscError> {
        if !self.active {
            return Err(PcscError::InvalidState("transaction already ended"));
        }

        let handle = self.card.card_handle()?;
        let result = ffi::end_transaction(handle);
        if result.is_ok() {
            self.active = false;
            self.card.transaction_active = false;
        }
        result
    }
}

impl Drop for PcscTransaction<'_> {
    fn drop(&mut self) {
        if self.active {
            if let Some(handle) = self.card.card_handle {
                let _ = ffi::end_transaction(handle);
            }
            self.active = false;
            self.card.transaction_active = false;
        }
    }
}
