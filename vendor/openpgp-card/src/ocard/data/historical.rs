// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! 6 Historical Bytes

use std::convert::TryFrom;

use crate::{
    Error,
    ocard::data::{CardCapabilities, CardServiceData, HistoricalBytes},
};

impl CardCapabilities {
    pub fn command_chaining(&self) -> bool {
        self.command_chaining
    }

    pub fn extended_lc_le(&self) -> bool {
        self.extended_lc_le
    }

    pub fn extended_length_information(&self) -> bool {
        self.extended_length_information
    }
}

impl From<[u8; 3]> for CardCapabilities {
    fn from(data: [u8; 3]) -> Self {
        let byte3 = data[2];

        let command_chaining = byte3 & 0x80 != 0;
        let extended_lc_le = byte3 & 0x40 != 0;
        let extended_length_information = byte3 & 0x20 != 0;

        Self {
            command_chaining,
            extended_lc_le,
            extended_length_information,
        }
    }
}

impl From<u8> for CardServiceData {
    fn from(data: u8) -> Self {
        let select_by_full_df_name = data & 0x80 != 0;
        let select_by_partial_df_name = data & 0x40 != 0;
        let dos_available_in_ef_dir = data & 0x20 != 0;
        let dos_available_in_ef_atr_info = data & 0x10 != 0;
        let access_services = [data & 0x8 != 0, data & 0x4 != 0, data & 0x2 != 0];
        let mf = data & 0x1 != 0;

        Self {
            select_by_full_df_name,
            select_by_partial_df_name,
            dos_available_in_ef_dir,
            dos_available_in_ef_atr_info,
            access_services,
            mf,
        }
    }
}

/// Split a compact-tlv "TL" (tag + length) into a 4-bit 'tag' and 4-bit
/// 'length'.
///
/// The COMPACT-TLV format has a Tag in the first nibble of a byte (bit
/// 5-8) and a length in the second nibble (bit 1-4).
fn split_tl(tl: u8) -> (u8, u8) {
    let tag = (tl & 0xf0) >> 4;
    let len = tl & 0x0f;

    (tag, len)
}

impl HistoricalBytes {
    pub fn card_capabilities(&self) -> Option<&CardCapabilities> {
        self.cc.as_ref()
    }

    pub fn card_service_data(&self) -> Option<&CardServiceData> {
        self.csd.as_ref()
    }
}

impl TryFrom<&[u8]> for HistoricalBytes {
    type Error = crate::Error;

    fn try_from(mut data: &[u8]) -> Result<Self, Self::Error> {
        // workaround-hack for "ledger" with zero-padded historical bytes
        #[allow(clippy::expect_used)] // the suffix strip expect is ok
        if data.ends_with(&[0x90, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]) {
            data = data
                .strip_suffix(&[0x0, 0x0, 0x0, 0x0, 0x0])
                .expect("checked");
        }

        // workaround-hack for "ledger": fix status indicator byte 7
        if data == [0x0, 0x31, 0xc5, 0x73, 0xc0, 0x1, 0x80, 0x7, 0x90, 0x0] {
            data = &[0x0, 0x31, 0xc5, 0x73, 0xc0, 0x1, 0x80, 0x5, 0x90, 0x0];
        }

        let len = data.len();

        if len < 4 {
            // historical bytes cannot be this short

            return Err(Error::ParseError(format!(
                "Historical bytes too short ({len} bytes), must be >= 4"
            )));
        }

        if data[0] != 0 {
            // The OpenPGP application assumes a category indicator byte
            // set to '00' (o-card 3.4.1, pg 44)

            return Err(Error::ParseError(
                "Unexpected category indicator in historical bytes".into(),
            ));
        }

        // category indicator byte
        let cib = data[0];

        // Card service data byte
        let mut csd = None;

        // Card capabilities
        let mut cc = None;

        // get information from "COMPACT-TLV data objects" [ISO 12.1.1.2]
        let mut ctlv = data[1..len - 3].to_vec();
        while !ctlv.is_empty() {
            let (t, l) = split_tl(ctlv[0]);

            // ctlv must still contain at least 1 + l bytes
            // (1 byte for the tl, plus `l` bytes of data for this ctlv)
            // (e.g. len = 4 -> tl + 3byte data)
            if ctlv.len() < (1 + l as usize) {
                return Err(Error::ParseError(format!(
                    "Illegal length value in Historical Bytes TL {} len {} l {}",
                    ctlv[0],
                    ctlv.len(),
                    l
                )));
            }

            match (t, l) {
                (0x3, 0x1) => {
                    csd = Some(ctlv[1]);
                    ctlv.drain(0..2);
                }
                (0x7, 0x3) => {
                    cc = Some([ctlv[1], ctlv[2], ctlv[3]]);
                    ctlv.drain(0..4);
                }
                (_, _) => {
                    // Log other unexpected CTLV entries.

                    // (e.g. yubikey neo returns historical bytes as:
                    // "[0, 73, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]")
                    log::trace!("historical bytes: ignored (tag {}, len {})", t, l);
                    ctlv.drain(0..(l as usize + 1));
                }
            }
        }

        // status indicator byte
        let sib = match data[len - 3] {
            0 => {
                // Card does not offer life cycle management, commands
                // TERMINATE DF and ACTIVATE FILE are not supported
                0
            }
            3 => {
                // Initialisation state
                // OpenPGP application can be reset to default values with
                // an ACTIVATE FILE command
                3
            }
            5 => {
                // Operational state (activated)
                // Card supports life cycle management, commands TERMINATE
                // DF and ACTIVATE FILE are available
                5
            }
            _ => {
                return Err(Error::ParseError(
                    "unexpected status indicator in historical bytes".into(),
                ));
            }
        };

        // Ignore final two (status) bytes:
        // according to the spec, they 'normally' show [0x90, 0x0] - but
        // YubiKey Neo shows [0x0, 0x0].
        // It's unclear if these status bytes are ever useful to process?

        let cc = cc.map(CardCapabilities::from);
        let csd = csd.map(CardServiceData::from);

        Ok(Self { cib, csd, cc, sib })
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryInto;

    use super::*;

    #[test]
    fn test_split_tl() {
        assert_eq!(split_tl(0x31), (3, 1));
        assert_eq!(split_tl(0x73), (7, 3));
        assert_eq!(split_tl(0x00), (0, 0));
        assert_eq!(split_tl(0xff), (0xf, 0xf));
    }

    #[test]
    fn test_gnuk() -> Result<(), Error> {
        // gnuk 1.2 stable
        let data: &[u8] = &[0x0, 0x31, 0x84, 0x73, 0x80, 0x1, 0x80, 0x5, 0x90, 0x0];
        let hist: HistoricalBytes = data.try_into()?;

        assert_eq!(
            hist,
            HistoricalBytes {
                cib: 0,
                csd: Some(CardServiceData {
                    select_by_full_df_name: true,
                    select_by_partial_df_name: false,
                    dos_available_in_ef_dir: false,
                    dos_available_in_ef_atr_info: false,
                    access_services: [false, true, false,],
                    mf: false,
                }),
                cc: Some(CardCapabilities {
                    command_chaining: true,
                    extended_lc_le: false,
                    extended_length_information: false,
                }),
                sib: 5
            }
        );

        Ok(())
    }

    #[test]
    fn test_floss34() -> Result<(), Error> {
        // floss shop openpgp smartcard 3.4
        let data: &[u8] = &[0x0, 0x31, 0xf5, 0x73, 0xc0, 0x1, 0x60, 0x5, 0x90, 0x0];
        let hist: HistoricalBytes = data.try_into()?;

        assert_eq!(
            hist,
            HistoricalBytes {
                cib: 0,
                csd: Some(CardServiceData {
                    select_by_full_df_name: true,
                    select_by_partial_df_name: true,
                    dos_available_in_ef_dir: true,
                    dos_available_in_ef_atr_info: true,
                    access_services: [false, true, false,],
                    mf: true,
                },),
                cc: Some(CardCapabilities {
                    command_chaining: false,
                    extended_lc_le: true,
                    extended_length_information: true,
                },),
                sib: 5,
            }
        );

        Ok(())
    }

    #[test]
    fn test_yk5() -> Result<(), Error> {
        // yubikey 5
        let data: &[u8] = &[0x0, 0x73, 0x0, 0x0, 0xe0, 0x5, 0x90, 0x0];
        let hist: HistoricalBytes = data.try_into()?;

        assert_eq!(
            hist,
            HistoricalBytes {
                cib: 0,
                csd: None,
                cc: Some(CardCapabilities {
                    command_chaining: true,
                    extended_lc_le: true,
                    extended_length_information: true,
                },),
                sib: 5,
            }
        );

        Ok(())
    }

    #[test]
    fn test_yk4() -> Result<(), Error> {
        // yubikey 4
        let data: &[u8] = &[0x0, 0x73, 0x0, 0x0, 0x80, 0x5, 0x90, 0x0];
        let hist: HistoricalBytes = data.try_into()?;

        assert_eq!(
            hist,
            HistoricalBytes {
                cib: 0,
                csd: None,
                cc: Some(CardCapabilities {
                    command_chaining: true,
                    extended_lc_le: false,
                    extended_length_information: false,
                },),
                sib: 5,
            }
        );

        Ok(())
    }

    #[test]
    fn test_yk_neo() -> Result<(), Error> {
        // yubikey neo
        let data: &[u8] = &[
            0x0, 0x73, 0x0, 0x0, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];
        let hist: HistoricalBytes = data.try_into()?;

        assert_eq!(
            hist,
            HistoricalBytes {
                cib: 0,
                csd: None,
                cc: Some(CardCapabilities {
                    command_chaining: true,
                    extended_lc_le: false,
                    extended_length_information: false
                }),
                sib: 0
            }
        );

        Ok(())
    }

    #[test]
    fn test_ledger_nano_s() -> Result<(), Error> {
        let data: &[u8] = &[
            0x0, 0x31, 0xc5, 0x73, 0xc0, 0x1, 0x80, 0x7, 0x90, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];
        let hist: HistoricalBytes = data.try_into()?;

        assert_eq!(
            hist,
            HistoricalBytes {
                cib: 0,
                csd: Some(CardServiceData {
                    select_by_full_df_name: true,
                    select_by_partial_df_name: true,
                    dos_available_in_ef_dir: false,
                    dos_available_in_ef_atr_info: false,
                    access_services: [false, true, false],
                    mf: true
                }),
                cc: Some(CardCapabilities {
                    command_chaining: true,
                    extended_lc_le: false,
                    extended_length_information: false
                }),
                sib: 5
            }
        );

        Ok(())
    }
}
