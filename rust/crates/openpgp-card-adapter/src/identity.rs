use std::str::FromStr;

use openpgp_card::ocard::data::ApplicationIdentifier;
use thiserror::Error;

pub const CANOKEYS_MANUFACTURER: u16 = 0xF1D0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CardIdentity {
    manufacturer: u16,
    serial: u32,
    version: u16,
}

impl CardIdentity {
    pub const fn new(manufacturer: u16, serial: u32, version: u16) -> Self {
        Self {
            manufacturer,
            serial,
            version,
        }
    }

    pub fn from_application_identifier(aid: &ApplicationIdentifier) -> Self {
        Self::new(aid.manufacturer(), aid.serial(), aid.version())
    }

    pub const fn manufacturer(self) -> u16 {
        self.manufacturer
    }

    pub const fn serial(self) -> u32 {
        self.serial
    }

    pub const fn version(self) -> u16 {
        self.version
    }

    pub fn matches(self, aid: &ApplicationIdentifier) -> bool {
        self == Self::from_application_identifier(aid)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedSerial(u32);

impl ExpectedSerial {
    pub fn get(self) -> u32 {
        self.0
    }
}

impl FromStr for ExpectedSerial {
    type Err = IdentityError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.len() != 8 {
            return Err(IdentityError::InvalidSerialLength {
                actual: input.len(),
            });
        }

        if let Some((index, _)) = input
            .bytes()
            .enumerate()
            .find(|(_, b)| !b.is_ascii_hexdigit())
        {
            return Err(IdentityError::InvalidSerialCharacter { index });
        }

        let serial = u32::from_str_radix(input, 16)
            .map_err(|_| IdentityError::InvalidSerialCharacter { index: 0 })?;
        Ok(Self(serial))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanokeyIdentity {
    aid: ApplicationIdentifier,
}

impl CanokeyIdentity {
    pub fn verify(
        aid: ApplicationIdentifier,
        expected_serial: ExpectedSerial,
    ) -> Result<Self, IdentityError> {
        if aid.manufacturer() != CANOKEYS_MANUFACTURER {
            return Err(IdentityError::UnexpectedManufacturer {
                actual: aid.manufacturer(),
            });
        }

        if aid.serial() != expected_serial.get() {
            return Err(IdentityError::SerialMismatch {
                expected: expected_serial.get(),
                actual: aid.serial(),
            });
        }

        Ok(Self { aid })
    }

    pub fn aid(&self) -> &ApplicationIdentifier {
        &self.aid
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum IdentityError {
    #[error(
        "expected OpenPGP serial must contain exactly 8 hexadecimal digits, not {actual} bytes"
    )]
    InvalidSerialLength { actual: usize },

    #[error("expected OpenPGP serial contains a non-hexadecimal character at byte {index}")]
    InvalidSerialCharacter { index: usize },

    #[error(
        "unexpected OpenPGP manufacturer 0x{actual:04X}; required CanoKeys manufacturer 0xF1D0"
    )]
    UnexpectedManufacturer { actual: u16 },

    #[error("OpenPGP serial mismatch: expected {expected:08X}, card reported {actual:08X}")]
    SerialMismatch { expected: u32, actual: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_aid(manufacturer: u16, serial: u32) -> ApplicationIdentifier {
        let mut bytes = vec![0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04];
        bytes.extend_from_slice(&manufacturer.to_be_bytes());
        bytes.extend_from_slice(&serial.to_be_bytes());
        bytes.extend_from_slice(&[0x00, 0x00]);
        ApplicationIdentifier::try_from(bytes.as_slice()).expect("synthetic AID must be valid")
    }

    fn expected(serial: &str) -> ExpectedSerial {
        serial.parse().expect("synthetic serial must be valid")
    }

    #[test]
    fn accepts_exact_canokey_identity() {
        let aid = synthetic_aid(CANOKEYS_MANUFACTURER, 0x0123ABCD);
        let verified = CanokeyIdentity::verify(aid, expected("0123ABCD"))
            .expect("exact synthetic identity must match");

        assert_eq!(verified.aid(), &aid);
        assert_eq!(verified.aid().version(), 0x0304);
        assert_eq!(
            "0123abcd".parse::<ExpectedSerial>(),
            Ok(expected("0123ABCD"))
        );
    }

    #[test]
    fn rejects_yubikey_manufacturer_even_with_matching_serial() {
        let aid = synthetic_aid(0x0006, 0x0123ABCD);

        assert_eq!(
            CanokeyIdentity::verify(aid, expected("0123ABCD")),
            Err(IdentityError::UnexpectedManufacturer { actual: 0x0006 })
        );
    }

    #[test]
    fn serial_match_uses_all_32_bits() {
        let aid = synthetic_aid(CANOKEYS_MANUFACTURER, 0x0000ABCD);

        assert_eq!(
            CanokeyIdentity::verify(aid, expected("1234ABCD")),
            Err(IdentityError::SerialMismatch {
                expected: 0x1234ABCD,
                actual: 0x0000ABCD,
            })
        );
    }

    #[test]
    fn rejects_short_long_and_prefixed_serial_aliases() {
        for serial in ["ABCD", "0000ABCD00", "0x0123ABCD"] {
            assert!(matches!(
                serial.parse::<ExpectedSerial>(),
                Err(IdentityError::InvalidSerialLength { .. })
            ));
        }
    }

    #[test]
    fn rejects_non_hexadecimal_serial() {
        assert_eq!(
            "0123ABCZ".parse::<ExpectedSerial>(),
            Err(IdentityError::InvalidSerialCharacter { index: 7 })
        );
    }
}
