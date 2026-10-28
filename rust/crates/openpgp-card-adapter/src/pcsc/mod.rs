use std::fmt;

use card_backend::{CardBackend, CardCaps, CardTransaction, PinType, SmartcardError};
use thiserror::Error;

pub const MAX_COMMAND_LEN: usize = 65_544;
pub const RESPONSE_BUFFER_LEN: usize = 65_538;

#[cfg(any(all(feature = "pcsc", target_os = "macos"), test))]
const MIN_COMMAND_LEN: usize = 4;
const SCARD_E_NOT_TRANSACTED: u32 = 0x8010_0016;

#[cfg(all(feature = "pcsc", target_os = "macos"))]
mod macos;
#[cfg(all(feature = "pcsc", target_os = "macos"))]
pub use macos::{PcscCard, PcscContext, PcscTransaction};

#[cfg(not(all(feature = "pcsc", target_os = "macos")))]
mod unsupported;
#[cfg(not(all(feature = "pcsc", target_os = "macos")))]
pub use unsupported::{PcscCard, PcscContext, PcscTransaction};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    T0,
    T1,
}

#[cfg(all(feature = "pcsc", target_os = "macos"))]
impl Protocol {
    fn from_raw(value: u32) -> Result<Self, PcscError> {
        match value {
            1 => Ok(Self::T0),
            2 => Ok(Self::T1),
            other => Err(PcscError::UnsupportedProtocol(other)),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::T0 => write!(f, "T=0"),
            Self::T1 => write!(f, "T=1"),
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PcscError {
    #[error("PC/SC transport is unsupported: build on macOS and enable the `pcsc` feature")]
    UnsupportedPlatform,

    #[error("PC/SC {operation} failed: {reason} (0x{code:08X})")]
    Pcsc {
        operation: &'static str,
        code: u32,
        reason: &'static str,
    },

    #[error("invalid PC/SC reader list: {0}")]
    InvalidReaderList(String),

    #[error("PC/SC reader list changed repeatedly; retry the request")]
    ReaderListChanged,

    #[error("reader name must be non-empty UTF-8 without NUL characters")]
    InvalidReaderName,

    #[error("exact PC/SC reader was not found: {0}")]
    ReaderNotFound(String),

    #[error("exact PC/SC reader name is ambiguous: {0}")]
    AmbiguousReader(String),

    #[error("unsupported active PC/SC protocol value {0}")]
    UnsupportedProtocol(u32),

    #[error("APDU command length {actual} is outside 4..={MAX_COMMAND_LEN} bytes")]
    InvalidCommandLength { actual: usize },

    #[error("PC/SC reported response length {reported}, exceeding its {capacity}-byte buffer")]
    InvalidResponseLength { reported: usize, capacity: usize },

    #[error("PC/SC returned a {actual}-byte response without complete SW1/SW2 status bytes")]
    ResponseTooShort { actual: usize },

    #[error("invalid PC/SC transport state: {0}")]
    InvalidState(&'static str),
}

#[cfg(all(feature = "pcsc", target_os = "macos"))]
impl PcscError {
    fn from_status(operation: &'static str, status: i32) -> Self {
        let code = status as u32;
        Self::Pcsc {
            operation,
            code,
            reason: status_name(code),
        }
    }
}

pub fn require_exact_reader<'a>(
    readers: &'a [String],
    requested: &str,
) -> Result<&'a str, PcscError> {
    validate_reader_name(requested)?;

    let mut matches = readers.iter().filter(|reader| reader.as_str() == requested);
    let reader = matches
        .next()
        .ok_or_else(|| PcscError::ReaderNotFound(requested.to_owned()))?;
    if matches.next().is_some() {
        return Err(PcscError::AmbiguousReader(requested.to_owned()));
    }

    Ok(reader)
}

fn validate_reader_name(reader: &str) -> Result<(), PcscError> {
    if reader.is_empty() || reader.as_bytes().contains(&0) {
        Err(PcscError::InvalidReaderName)
    } else {
        Ok(())
    }
}

#[cfg(any(all(feature = "pcsc", target_os = "macos"), test))]
fn parse_reader_list(bytes: &[u8]) -> Result<Vec<String>, PcscError> {
    if bytes == [0] || bytes == [0, 0] {
        return Ok(Vec::new());
    }
    if bytes.len() < 2 || !bytes.ends_with(&[0, 0]) {
        return Err(PcscError::InvalidReaderList(
            "missing the final empty string terminator".to_owned(),
        ));
    }

    let content = &bytes[..bytes.len() - 2];
    let mut readers = Vec::new();
    for name in content.split(|byte| *byte == 0) {
        if name.is_empty() {
            return Err(PcscError::InvalidReaderList(
                "empty reader name or data after the final terminator".to_owned(),
            ));
        }
        let name = std::str::from_utf8(name).map_err(|error| {
            PcscError::InvalidReaderList(format!(
                "reader name is not UTF-8 at relative byte {}",
                error.valid_up_to()
            ))
        })?;
        readers.push(name.to_owned());
    }
    Ok(readers)
}

#[cfg(any(all(feature = "pcsc", target_os = "macos"), test))]
fn validate_command_length(length: usize) -> Result<(), PcscError> {
    if (MIN_COMMAND_LEN..=MAX_COMMAND_LEN).contains(&length) {
        Ok(())
    } else {
        Err(PcscError::InvalidCommandLength { actual: length })
    }
}

#[cfg(any(all(feature = "pcsc", target_os = "macos"), test))]
fn validate_response_length(reported: usize, capacity: usize) -> Result<usize, PcscError> {
    if reported > capacity {
        return Err(PcscError::InvalidResponseLength { reported, capacity });
    }
    if reported < 2 {
        return Err(PcscError::ResponseTooShort { actual: reported });
    }
    Ok(reported)
}

impl CardBackend for PcscCard {
    fn limit_card_caps(&self, card_caps: CardCaps) -> CardCaps {
        card_caps
    }

    fn transaction(
        &mut self,
        reselect_application: Option<&[u8]>,
    ) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, SmartcardError> {
        let mut transaction = self.begin_transaction().map_err(into_smartcard_error)?;
        if let Some(application) = reselect_application {
            // Do not interpret SW1/SW2 in the transport. The OpenPGP layer
            // performs checked selection and validates all response statuses.
            let _ = CardTransaction::select(&mut transaction, application)?;
        }
        Ok(Box::new(transaction))
    }
}

impl CardTransaction for PcscTransaction<'_> {
    fn transmit(&mut self, cmd: &[u8], _buf_size: usize) -> Result<Vec<u8>, SmartcardError> {
        self.transmit_apdu(cmd).map_err(into_smartcard_error)
    }

    fn max_cmd_len(&self) -> Option<usize> {
        Some(MAX_COMMAND_LEN)
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

fn into_smartcard_error(error: PcscError) -> SmartcardError {
    if matches!(
        &error,
        PcscError::Pcsc {
            code: SCARD_E_NOT_TRANSACTED,
            ..
        }
    ) {
        SmartcardError::NotTransacted
    } else {
        SmartcardError::Error(error.to_string())
    }
}

#[cfg(all(feature = "pcsc", target_os = "macos"))]
fn status_name(code: u32) -> &'static str {
    match code {
        0x8010_0001 => "internal error",
        0x8010_0002 => "cancelled",
        0x8010_0003 => "invalid handle",
        0x8010_0004 => "invalid parameter",
        0x8010_0006 => "insufficient memory",
        0x8010_0008 => "insufficient buffer; response was not returned",
        0x8010_0009 => "unknown reader",
        0x8010_000A => "timeout",
        0x8010_000B => "sharing violation",
        0x8010_000C => "no smart card",
        0x8010_000F => "protocol mismatch",
        0x8010_0010 => "reader or card not ready",
        0x8010_0013 => "communication error",
        0x8010_0016 => "not transacted",
        0x8010_0017 => "reader unavailable",
        0x8010_0018 => "service shutdown",
        0x8010_001D => "PC/SC service unavailable",
        0x8010_001E => "PC/SC service stopped",
        0x8010_002E => "no readers available",
        0x8010_002F => "communication data lost",
        0x8010_0065 => "unsupported card",
        0x8010_0066 => "unresponsive card",
        0x8010_0067 => "unpowered card",
        0x8010_0068 => "card was reset",
        0x8010_0069 => "card was removed",
        _ => "unrecognized PC/SC status",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiple_exact_reader_names() {
        let readers = parse_reader_list(b"Reader One\0Reader Two\0\0").expect("valid multi-sz");
        assert_eq!(readers, ["Reader One", "Reader Two"]);
        assert_eq!(
            require_exact_reader(&readers, "Reader Two").expect("exact reader"),
            "Reader Two"
        );
    }

    #[test]
    fn parses_empty_reader_lists() {
        assert!(parse_reader_list(&[0]).expect("empty multi-sz").is_empty());
        assert!(
            parse_reader_list(&[0, 0])
                .expect("empty multi-sz")
                .is_empty()
        );
    }

    #[test]
    fn rejects_malformed_reader_lists() {
        for bytes in [
            &b""[..],
            &b"Reader\0"[..],
            &b"Reader\0\0Trailing\0\0"[..],
            &b"Reader\0\0\0"[..],
            &b"\xFF\0\0"[..],
        ] {
            assert!(parse_reader_list(bytes).is_err(), "accepted {bytes:?}");
        }
    }

    #[test]
    fn exact_reader_matching_never_falls_back_or_normalizes() {
        let readers = vec!["Reader One".to_owned(), "Reader Two".to_owned()];
        assert!(matches!(
            require_exact_reader(&readers, "reader one"),
            Err(PcscError::ReaderNotFound(_))
        ));
        assert!(matches!(
            require_exact_reader(&readers, "missing"),
            Err(PcscError::ReaderNotFound(_))
        ));
    }

    #[test]
    fn duplicate_exact_reader_names_are_ambiguous() {
        let readers = vec!["Same".to_owned(), "Same".to_owned()];
        assert!(matches!(
            require_exact_reader(&readers, "Same"),
            Err(PcscError::AmbiguousReader(_))
        ));
    }

    #[test]
    fn command_length_checks_cover_transport_boundaries() {
        assert!(validate_command_length(4).is_ok());
        assert!(validate_command_length(MAX_COMMAND_LEN).is_ok());
        assert!(validate_command_length(3).is_err());
        assert!(validate_command_length(MAX_COMMAND_LEN + 1).is_err());
    }

    #[test]
    fn response_length_checks_reject_truncation_and_missing_status() {
        assert_eq!(validate_response_length(2, RESPONSE_BUFFER_LEN), Ok(2));
        assert!(matches!(
            validate_response_length(RESPONSE_BUFFER_LEN + 1, RESPONSE_BUFFER_LEN),
            Err(PcscError::InvalidResponseLength { .. })
        ));
        assert!(matches!(
            validate_response_length(1, RESPONSE_BUFFER_LEN),
            Err(PcscError::ResponseTooShort { .. })
        ));
    }

    #[cfg(not(all(feature = "pcsc", target_os = "macos")))]
    #[test]
    fn unavailable_transport_fails_without_calling_pcsc() {
        assert!(matches!(
            PcscContext::establish(),
            Err(PcscError::UnsupportedPlatform)
        ));
    }
}
