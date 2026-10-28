use std::sync::Arc;

use card_backend::{CardBackend, CardCaps, CardTransaction, PinType, SmartcardError};
use thiserror::Error;

pub const MAX_COMMAND_LENGTH: usize = 65_544;
pub const MAX_RESPONSE_LENGTH: usize = 65_538;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportCapabilities {
    pub supports_extended_length: bool,
    pub supports_command_chaining: bool,
    pub maximum_command_length: usize,
    pub maximum_command_data_length: usize,
    pub maximum_response_length: usize,
}

impl TransportCapabilities {
    pub const fn short_only() -> Self {
        Self {
            supports_extended_length: false,
            supports_command_chaining: true,
            maximum_command_length: 261,
            maximum_command_data_length: 255,
            maximum_response_length: MAX_RESPONSE_LENGTH,
        }
    }

    fn validate(self) -> Result<Self, TransportError> {
        if !(4..=MAX_COMMAND_LENGTH).contains(&self.maximum_command_length)
            || !self.supports_extended_length && self.maximum_command_length > 261
        {
            return Err(TransportError::InvalidCapabilities(
                "invalid whole-command limit",
            ));
        }
        if self.maximum_command_data_length == 0
            || self.maximum_command_data_length > 65_535
            || !self.supports_extended_length && self.maximum_command_data_length > 255
        {
            return Err(TransportError::InvalidCapabilities(
                "invalid command-data limit",
            ));
        }
        if !(2..=MAX_RESPONSE_LENGTH).contains(&self.maximum_response_length) {
            return Err(TransportError::InvalidCapabilities(
                "invalid response limit",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("invalid transport capabilities: {0}")]
    InvalidCapabilities(&'static str),

    #[error("command length {actual} exceeds the transport limit {maximum}")]
    InvalidCommandLength { actual: usize, maximum: usize },

    #[error("response length {actual} is outside the transport limit 2..={maximum}")]
    InvalidResponseLength { actual: usize, maximum: usize },

    #[error("the card transport is unavailable")]
    Unavailable,

    #[error("the card transport operation was cancelled")]
    Cancelled,

    #[error("the card transport operation timed out")]
    Timeout,

    #[error("the card transport disconnected")]
    Disconnected,

    #[error("the card transport failed")]
    Failure,
}

/// A raw encoded-APDU transport. It does not select applications or process status words.
pub trait RawCardTransport: Send + Sync {
    fn capabilities(&self) -> TransportCapabilities;

    fn transmit(
        &self,
        command: &[u8],
        response_buffer_size: usize,
    ) -> Result<Vec<u8>, TransportError>;

    fn failure_kind(&self) -> openpgp_core::RemoteKeyFailure {
        openpgp_core::RemoteKeyFailure::Unavailable
    }
}

pub struct TransportCardBackend {
    transport: Arc<dyn RawCardTransport>,
    capabilities: TransportCapabilities,
}

impl TransportCardBackend {
    pub fn new(transport: Arc<dyn RawCardTransport>) -> Result<Self, TransportError> {
        let capabilities = transport.capabilities().validate()?;
        Ok(Self {
            transport,
            capabilities,
        })
    }
}

impl CardBackend for TransportCardBackend {
    fn limit_card_caps(&self, card_caps: CardCaps) -> CardCaps {
        CardCaps::new(
            card_caps.ext_support() && self.capabilities.supports_extended_length,
            card_caps.chaining_support() && self.capabilities.supports_command_chaining,
            card_caps
                .max_cmd_bytes()
                .min(self.capabilities.maximum_command_data_length as u16),
            card_caps.max_rsp_bytes().min(
                self.capabilities
                    .maximum_response_length
                    .saturating_sub(2)
                    .min(usize::from(u16::MAX)) as u16,
            ),
            card_caps.pw1_max_len(),
            card_caps.pw3_max_len(),
        )
    }

    fn transaction(
        &mut self,
        reselect_application: Option<&[u8]>,
    ) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, SmartcardError> {
        let mut transaction = TransportCardTransaction {
            transport: self.transport.as_ref(),
            capabilities: self.capabilities,
        };
        if let Some(application) = reselect_application {
            let _ = CardTransaction::select(&mut transaction, application)?;
        }
        Ok(Box::new(transaction))
    }
}

struct TransportCardTransaction<'a> {
    transport: &'a dyn RawCardTransport,
    capabilities: TransportCapabilities,
}

impl CardTransaction for TransportCardTransaction<'_> {
    fn transmit(&mut self, command: &[u8], buf_size: usize) -> Result<Vec<u8>, SmartcardError> {
        if command.len() < 4 || command.len() > self.capabilities.maximum_command_length {
            return Err(TransportError::InvalidCommandLength {
                actual: command.len(),
                maximum: self.capabilities.maximum_command_length,
            }
            .into());
        }
        let response = self.transport.transmit(command, buf_size)?;
        let maximum = self
            .capabilities
            .maximum_response_length
            .min(if buf_size >= 2 {
                buf_size
            } else {
                self.capabilities.maximum_response_length
            });
        if response.len() < 2 || response.len() > maximum {
            return Err(TransportError::InvalidResponseLength {
                actual: response.len(),
                maximum,
            }
            .into());
        }
        Ok(response)
    }

    fn max_cmd_len(&self) -> Option<usize> {
        Some(self.capabilities.maximum_command_length)
    }

    fn feature_pinpad_verify(&self) -> bool {
        false
    }

    fn feature_pinpad_modify(&self) -> bool {
        false
    }

    fn pinpad_verify(
        &mut self,
        _pin: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        Err(SmartcardError::Error(
            "PIN-pad verification is unsupported; no command was sent".to_owned(),
        ))
    }

    fn pinpad_modify(
        &mut self,
        _pin: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        Err(SmartcardError::Error(
            "PIN-pad modification is unsupported; no command was sent".to_owned(),
        ))
    }

    fn was_reset(&self) -> bool {
        false
    }
}

impl From<TransportError> for SmartcardError {
    fn from(error: TransportError) -> Self {
        SmartcardError::Error(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Mutex};

    use super::*;

    struct ScriptedTransport {
        capabilities: TransportCapabilities,
        responses: Mutex<VecDeque<Vec<u8>>>,
        commands: Mutex<Vec<(Vec<u8>, usize)>>,
    }

    impl ScriptedTransport {
        fn new(capabilities: TransportCapabilities, responses: &[&[u8]]) -> Self {
            Self {
                capabilities,
                responses: Mutex::new(responses.iter().map(|response| response.to_vec()).collect()),
                commands: Mutex::new(Vec::new()),
            }
        }
    }

    impl RawCardTransport for ScriptedTransport {
        fn capabilities(&self) -> TransportCapabilities {
            self.capabilities
        }

        fn transmit(
            &self,
            command: &[u8],
            response_buffer_size: usize,
        ) -> Result<Vec<u8>, TransportError> {
            self.commands
                .lock()
                .expect("scripted commands")
                .push((command.to_vec(), response_buffer_size));
            self.responses
                .lock()
                .expect("scripted responses")
                .pop_front()
                .ok_or(TransportError::Failure)
        }
    }

    fn backend(
        capabilities: TransportCapabilities,
        responses: &[&[u8]],
    ) -> (TransportCardBackend, Arc<ScriptedTransport>) {
        let transport = Arc::new(ScriptedTransport::new(capabilities, responses));
        let backend = TransportCardBackend::new(transport.clone()).expect("valid capabilities");
        (backend, transport)
    }

    #[test]
    fn raw_status_words_are_not_retried_by_the_transport() {
        let first = [0x01, 0x02, 0x61, 0x02];
        let second = [0x6C, 0x20];
        let (mut backend, transport) =
            backend(TransportCapabilities::short_only(), &[&first, &second]);
        let mut transaction = backend.transaction(None).expect("transaction");
        assert_eq!(
            transaction
                .transmit(&[0x00, 0xCA, 0x00, 0x6E, 0x00], 264)
                .expect("first raw response"),
            first
        );
        assert_eq!(
            transaction
                .transmit(&[0x00, 0xCA, 0x00, 0x6E, 0x00], 264)
                .expect("second raw response"),
            second
        );
        assert_eq!(transport.commands.lock().expect("commands").len(), 2);
    }

    #[test]
    fn card_and_transport_capabilities_are_intersected() {
        let capabilities = TransportCapabilities {
            supports_command_chaining: false,
            ..TransportCapabilities::short_only()
        };
        let (mut backend, _) = backend(capabilities, &[]);
        let card = CardCaps::new(true, true, 4096, 4096, 32, 64);
        let limited = backend.limit_card_caps(card);
        assert!(!limited.ext_support());
        assert!(!limited.chaining_support());
        assert_eq!(limited.max_cmd_bytes(), 255);
        assert_eq!(limited.max_rsp_bytes(), 4096);
        assert_eq!(limited.pw1_max_len(), 32);
        assert_eq!(limited.pw3_max_len(), 64);
        assert_eq!(
            backend
                .transaction(None)
                .expect("transaction")
                .max_cmd_len(),
            Some(261)
        );
    }

    #[test]
    fn invalid_capabilities_fail_before_transmission() {
        for capabilities in [
            TransportCapabilities {
                maximum_command_length: 3,
                ..TransportCapabilities::short_only()
            },
            TransportCapabilities {
                maximum_command_data_length: 0,
                ..TransportCapabilities::short_only()
            },
            TransportCapabilities {
                maximum_command_data_length: 256,
                ..TransportCapabilities::short_only()
            },
            TransportCapabilities {
                maximum_command_length: 262,
                ..TransportCapabilities::short_only()
            },
            TransportCapabilities {
                maximum_response_length: 1,
                ..TransportCapabilities::short_only()
            },
            TransportCapabilities {
                maximum_response_length: MAX_RESPONSE_LENGTH + 1,
                ..TransportCapabilities::short_only()
            },
        ] {
            let transport = Arc::new(ScriptedTransport::new(capabilities, &[]));
            assert!(TransportCardBackend::new(transport).is_err());
        }
    }

    #[test]
    fn command_and_response_limits_never_truncate() {
        let capabilities = TransportCapabilities {
            maximum_command_length: 12,
            maximum_response_length: 6,
            ..TransportCapabilities::short_only()
        };
        let response = [0xAA; 8];
        let short = [0x90];
        let (mut backend, transport) = backend(capabilities, &[&response, &short]);
        let mut transaction = backend.transaction(None).expect("transaction");
        assert!(matches!(
            transaction.transmit(&[0; 13], 264),
            Err(SmartcardError::Error(_))
        ));
        assert!(transport.commands.lock().expect("commands").is_empty());
        assert!(transaction.transmit(&[0; 4], 264).is_err());
        assert!(transaction.transmit(&[0; 4], 264).is_err());
        assert_eq!(transport.commands.lock().expect("commands").len(), 2);
    }

    #[test]
    fn response_hints_cannot_expand_transport_limits() {
        let capabilities = TransportCapabilities {
            maximum_response_length: 6,
            ..TransportCapabilities::short_only()
        };
        let valid = [0xAA, 0xBB, 0xCC, 0xDD, 0x90, 0x00];
        let oversized = [0xAA; 7];
        let (mut backend, transport) = backend(capabilities, &[&valid, &oversized]);
        let mut transaction = backend.transaction(None).expect("transaction");
        assert_eq!(
            transaction
                .transmit(&[0; 4], 0)
                .expect("ignored short hint"),
            valid
        );
        assert!(transaction.transmit(&[0; 4], usize::MAX).is_err());
        assert_eq!(transport.commands.lock().expect("commands").len(), 2);
        assert_eq!(
            transport.failure_kind(),
            openpgp_core::RemoteKeyFailure::Unavailable
        );
    }

    #[test]
    fn selection_is_forwarded_without_interpreting_its_status() {
        let (mut backend, transport) =
            backend(TransportCapabilities::short_only(), &[&[0x6A, 0x82]]);
        let mut transaction = backend.transaction(None).expect("transaction");
        assert_eq!(
            transaction
                .select(&[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])
                .expect("raw selection response"),
            [0x6A, 0x82]
        );
        let commands = transport.commands.lock().expect("commands");
        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0].0,
            [
                0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00,
            ]
        );
    }

    #[test]
    fn pinpad_operations_are_explicitly_unsupported() {
        let (mut backend, transport) = backend(TransportCapabilities::short_only(), &[]);
        let mut transaction = backend.transaction(None).expect("transaction");
        assert!(!transaction.feature_pinpad_verify());
        assert!(!transaction.feature_pinpad_modify());
        assert!(transaction.pinpad_verify(PinType::User, &None).is_err());
        assert!(transaction.pinpad_modify(PinType::Admin, &None).is_err());
        assert!(!transaction.was_reset());
        assert!(transport.commands.lock().expect("commands").is_empty());
    }
}
