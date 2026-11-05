// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! 4.2.1 Application Identifier (AID)

use std::convert::TryFrom;

use nom::{bytes::complete as bytes, number::complete as number};

use crate::ocard::data::{complete, ApplicationIdentifier};

fn parse(input: &[u8]) -> nom::IResult<&[u8], ApplicationIdentifier> {
    let (input, _) = bytes::tag([0xd2, 0x76, 0x0, 0x1, 0x24])(input)?;

    let (input, application) = number::u8(input)?;
    let (input, version) = number::be_u16(input)?;
    let (input, manufacturer) = number::be_u16(input)?;
    let (input, serial) = number::be_u32(input)?;

    let (input, _) = nom::combinator::all_consuming(bytes::tag([0x0, 0x0]))(input)?;

    Ok((
        input,
        ApplicationIdentifier {
            application,
            version,
            manufacturer,
            serial,
        },
    ))
}

impl TryFrom<&[u8]> for ApplicationIdentifier {
    type Error = crate::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        complete(parse(data))
    }
}

impl ApplicationIdentifier {
    pub fn application(&self) -> u8 {
        self.application
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn manufacturer(&self) -> u16 {
        self.manufacturer
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    /// Mapping of manufacturer id to a name, data from:
    /// <https://en.wikipedia.org/wiki/OpenPGP_card> [2022-04-07]
    ///
    /// Also see:
    /// <https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=scd/app-openpgp.c;hb=HEAD#l292>
    pub fn manufacturer_name(&self) -> &'static str {
        match self.manufacturer {
            0x0000 => "Testcard",
            0x0001 => "PPC Card Systems",
            0x0002 => "Prism Payment Technologies",
            0x0003 => "OpenFortress Digital signatures",
            0x0004 => "Wewid AB",
            0x0005 => "ZeitControl cardsystems GmbH",
            0x0006 => "Yubico AB",
            0x0007 => "OpenKMS",
            0x0008 => "LogoEmail",
            0x0009 => "Fidesmo AB",
            0x000A => "Dangerous Things",
            0x000F => "Nitrokey GmbH",
            0x000B => "Feitian Technologies",
            0x002A => "Magrathea",
            0x0042 => "GnuPG e.V.",
            0x1337 => "Warsaw Hackerspace",
            0x2342 => "warpzone e.V.",
            0x4354 => "Confidential Technologies",
            0x5443 => "TIF-IT e.V.",
            0x63AF => "Trustica s.r.o",
            0xBA53 => "c-base e.V.",
            0xBD0E => "Paranoidlabs",
            0xF1D0 => "CanoKeys",
            0xF517 => "Free Software Initiative of Japan",
            0xF5EC => "F-Secure",
            0xFF00..=0xFFFE => "Range reserved for randomly assigned serial numbers.",
            0xFFFF => "Testcard",
            _ => "Unknown",
        }
    }

    /// This ident is constructed as the concatenation of manufacturer
    /// id, a colon, and the card serial (in hexadecimal representation,
    /// with uppercase hex digits).
    ///
    /// It is a more easily human-readable, shorter form of the full
    /// 16-byte AID ("Application Identifier").
    ///
    /// Example: "1234:5678ABCD".
    pub fn ident(&self) -> String {
        format!("{:04X}:{:08X}", self.manufacturer, self.serial)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_gnuk() {
        let data = [
            0xd2, 0x76, 0x0, 0x1, 0x24, 0x1, 0x2, 0x0, 0xff, 0xfe, 0x43, 0x19, 0x42, 0x40, 0x0, 0x0,
        ];

        let aid =
            ApplicationIdentifier::try_from(&data[..]).expect("failed to parse application id");

        assert_eq!(
            aid,
            ApplicationIdentifier {
                application: 0x1,
                version: 0x200,
                manufacturer: 0xfffe,
                serial: 0x43194240,
            }
        );
    }
}
