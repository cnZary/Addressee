// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::{TryFrom, TryInto};

use crate::{Error, ocard::StatusBytes};

/// Response from the card to a command.
///
/// This object contains pure payload, without the status bytes.
/// Creating a `Response` object is only possible when the response from
/// the card showed an "ok" status code (if the status bytes were no ok,
/// you will receive an Error, never a Response).
#[derive(Debug)]
struct Response {
    data: Vec<u8>,
}

/// "Raw" APDU Response, including the status bytes.
///
/// This type is used for processing inside the openpgp-card crate
/// (raw responses with a non-ok status sometimes need to be processed,
/// e.g. when a card sends a response in "chained" format).
#[allow(unused)]
#[derive(Clone, Debug)]
pub(crate) struct RawResponse {
    data: Vec<u8>,
    status: StatusBytes,
}

/// Try to consume a `RawResponse` into `()`.
impl TryFrom<RawResponse> for () {
    type Error = Error;

    fn try_from(value: RawResponse) -> Result<Self, Self::Error> {
        let value: Response = value.try_into()?;

        if !value.data.is_empty() {
            Err(Error::InternalError(
                "Unexpected: RawResponse contained data".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

impl TryFrom<RawResponse> for Vec<u8> {
    type Error = Error;

    fn try_from(value: RawResponse) -> Result<Self, Self::Error> {
        let value: Response = value.try_into()?;
        Ok(value.data)
    }
}

impl TryFrom<RawResponse> for Response {
    type Error = Error;

    fn try_from(value: RawResponse) -> Result<Self, Self::Error> {
        if value.is_ok() {
            Ok(Response { data: value.data })
        } else {
            Err(value.status().into())
        }
    }
}

impl RawResponse {
    pub fn check_ok(&self) -> Result<(), StatusBytes> {
        if !self.is_ok() {
            Err(self.status())
        } else {
            Ok(())
        }
    }

    pub fn data(&self) -> Result<&[u8], StatusBytes> {
        self.check_ok()?;
        Ok(&self.data)
    }

    /// access data even if the result status is an error status
    pub(crate) fn raw_data(&self) -> &[u8] {
        &self.data
    }

    pub(crate) fn raw_mut_data(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    pub(crate) fn set_status(&mut self, new_status: StatusBytes) {
        self.status = new_status;
    }

    pub fn status(&self) -> StatusBytes {
        self.status
    }

    /// Is the response status "ok"? (0x90, 0x00)
    pub fn is_ok(&self) -> bool {
        self.status() == StatusBytes::Ok
    }
}

impl TryFrom<Vec<u8>> for RawResponse {
    type Error = Error;

    fn try_from(mut data: Vec<u8>) -> Result<Self, Self::Error> {
        let sw2 = data.pop().ok_or(Error::ResponseLength(data.len()))?;
        let sw1 = data.pop().ok_or(Error::ResponseLength(data.len()))?;

        let status = (sw1, sw2).into();

        Ok(RawResponse { data, status })
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use crate::ocard::apdu::response::RawResponse;

    #[test]
    fn test_two_bytes_data_response() {
        let res = RawResponse::try_from(vec![0x01, 0x02, 0x90, 0x00]).unwrap();
        assert!(res.is_ok());
        assert_eq!(res.data, vec![0x01, 0x02]);
    }

    #[test]
    fn test_no_data_response() {
        let res = RawResponse::try_from(vec![0x90, 0x00]).unwrap();
        assert!(res.is_ok());
        assert_eq!(res.data, vec![]);
    }

    #[test]
    fn test_more_data_response() {
        let res = RawResponse::try_from(vec![0xAB, 0x61, 0x02]).unwrap();
        assert!(!res.is_ok());
        assert_eq!(res.data, vec![0xAB]);
    }
}
