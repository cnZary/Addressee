// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! PW status Bytes (see spec page 23)

use std::convert::TryFrom;

use crate::{Error, ocard::data::PWStatusBytes};

impl PWStatusBytes {
    /// PUT DO for PW Status Bytes accepts either 1 or 4 bytes of data.
    /// This method generates the 1 byte version for 'long==false' and the
    /// 4 bytes version for 'long==true'.
    ///
    /// (See OpenPGP card spec, pg. 28)
    pub(crate) fn serialize_for_put(&self, long: bool) -> Vec<u8> {
        let mut data = vec![];

        // 0 if "valid once", 1 otherwise
        data.push(u8::from(!self.pw1_cds_valid_once));

        if long {
            let mut b2 = self.pw1_len_format;
            if self.pw1_pin_block {
                b2 |= 0x80;
            }
            data.push(b2);

            data.push(self.rc_len);

            let mut b4 = self.pw3_len_format;
            if self.pw3_pin_block {
                b4 |= 0x80;
            }
            data.push(b4);
        }

        data
    }
}

impl TryFrom<&[u8]> for PWStatusBytes {
    type Error = crate::Error;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        if input.len() == 7 {
            let pw1_cds_valid_once = input[0] == 0x00;
            let pw1_pin_block = input[1] & 0x80 != 0;
            let pw1_len = input[1] & 0x7f;
            let rc_len = input[2];
            let pw3_pin_block = input[3] & 0x80 != 0;
            let pw3_len = input[3] & 0x7f;
            let err_count_pw1 = input[4];
            let err_count_rst = input[5];
            let err_count_pw3 = input[6];

            Ok(Self {
                pw1_cds_valid_once,
                pw1_pin_block,
                pw1_len_format: pw1_len,
                rc_len,
                pw3_pin_block,
                pw3_len_format: pw3_len,
                err_count_pw1,
                err_count_rst,
                err_count_pw3,
            })
        } else {
            Err(Error::ParseError(format!(
                "Unexpected length of PW Status Bytes: {}",
                input.len()
            )))
        }
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryInto;

    use super::*;

    #[test]
    fn test() {
        let data = [0x0, 0x40, 0x40, 0x40, 0x3, 0x0, 0x3];

        let pws: PWStatusBytes = (&data[..]).try_into().expect("failed to parse PWStatus");

        assert_eq!(
            pws,
            PWStatusBytes {
                pw1_cds_valid_once: true,
                pw1_pin_block: false,
                pw1_len_format: 0x40,
                rc_len: 0x40,
                pw3_pin_block: false,
                pw3_len_format: 0x40,
                err_count_pw1: 3,
                err_count_rst: 0,
                err_count_pw3: 3
            }
        );
    }
}
