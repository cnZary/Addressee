// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0
// This file contains Addressee local modifications; see ADDRESSEE-PROVENANCE.md.

//! APDU "Application Protocol Data Unit"
//! Commands and responses to commands

pub(crate) mod command;
pub mod response;

use std::convert::TryFrom;

use card_backend::{CardCaps, CardTransaction};
use secrecy::ExposeSecret as _;

use crate::{
    ocard::{
        apdu::{
            command::{Command, Data, Expect},
            response::RawResponse,
        },
        commands, StatusBytes,
    },
    Error,
};

/// "Maximum amount of bytes in a short APDU command or response" (from pcsc)
const MAX_BUFFER_SIZE: usize = 264;
const MAX_RESPONSE_BYTES: usize = 65_536;
const MAX_RESPONSE_CONTINUATIONS: usize = 32;

fn max_command_data_bytes(card_caps: Option<CardCaps>) -> usize {
    let max_cmd_bytes = card_caps.map_or(255, |caps| caps.max_cmd_bytes() as usize);
    let ext_support = card_caps.is_some_and(|caps| caps.ext_support());

    if ext_support && max_cmd_bytes > 0xff {
        max_cmd_bytes
    } else {
        max_cmd_bytes.min(0xff)
    }
}

fn use_extended_length(cmd: &Command, card_caps: Option<CardCaps>) -> bool {
    cmd.data().len() > 0xff && max_command_data_bytes(card_caps) > 0xff
}

fn command_requires_chaining(cmd: &Command, card_caps: Option<CardCaps>) -> bool {
    !cmd.data().is_empty() && cmd.data().len() > max_command_data_bytes(card_caps)
}

fn command_supports_chaining(cmd: &Command) -> bool {
    match cmd.ins() {
        0xda | 0xdb => true,
        0x2a => cmd.p1() == 0x80 && cmd.p2() == 0x86,
        _ => false,
    }
}

fn check_response_size(current: usize, additional: usize) -> Result<(), Error> {
    let total = current
        .checked_add(additional)
        .ok_or(Error::ResponseLength(usize::MAX))?;
    if total > MAX_RESPONSE_BYTES {
        Err(Error::ResponseLength(total))
    } else {
        Ok(())
    }
}

fn check_transport_command_length<C>(card_tx: &C, length: usize) -> Result<(), Error>
where
    C: CardTransaction + ?Sized,
{
    if card_tx.max_cmd_len().is_some_and(|max| length > max) {
        Err(Error::CommandTooLong(length))
    } else {
        Ok(())
    }
}

/// Send a Command and return the result as a Response.
///
/// If the reply is truncated, this fn assembles all the parts and returns
/// them as one aggregated Response.
pub(crate) fn send_command<C>(
    card_tx: &mut C,
    cmd: Command,
    card_caps: Option<CardCaps>,
    expect_reply: bool,
) -> Result<RawResponse, Error>
where
    C: CardTransaction + ?Sized,
{
    log::debug!(" -> full APDU command: {:02x?}", cmd);

    let ext_len = use_extended_length(&cmd, card_caps);
    let chained = command_requires_chaining(&cmd, card_caps)
        && card_caps.is_some_and(|caps| caps.chaining_support());
    let expect_response = if expect_reply {
        Expect::Some
    } else {
        Expect::Empty
    };
    let mut resp = RawResponse::try_from(send_command_low_level(
        card_tx,
        &cmd,
        card_caps,
        ext_len,
        expect_response,
    )?)?;
    check_response_size(0, resp.raw_data().len())?;

    if expect_reply && !chained {
        if let StatusBytes::UnknownStatus(0x6c, size) = resp.status() {
            resp = RawResponse::try_from(send_command_low_level(
                card_tx,
                &cmd,
                card_caps,
                ext_len,
                Expect::Short(size),
            )?)?;
            check_response_size(0, resp.raw_data().len())?;
        }
    }

    let mut continuation_rounds = 0;
    while let StatusBytes::OkBytesAvailable(bytes) = resp.status() {
        if continuation_rounds == MAX_RESPONSE_CONTINUATIONS {
            return Err(Error::InternalError(
                "APDU response continuation limit exceeded".to_string(),
            ));
        }
        continuation_rounds += 1;

        // More data is available for this command from the card
        log::trace!(" chained response, getting more data");

        // Get next chunk of data
        let next = RawResponse::try_from(send_command_low_level(
            card_tx,
            &commands::get_response()?,
            card_caps,
            ext_len,
            Expect::Short(bytes),
        )?)?;

        match next.status() {
            StatusBytes::OkBytesAvailable(_) | StatusBytes::Ok => {
                log::trace!(" appending {} bytes to response", next.raw_data().len());
                check_response_size(resp.raw_data().len(), next.raw_data().len())?;

                // Append new data to resp.data and overwrite status.
                resp.raw_mut_data().extend_from_slice(next.raw_data());
                resp.set_status(next.status());
            }
            error => return Err(error.into()),
        }
    }

    log::debug!(
        " <- APDU response [len {}, status {:?}]",
        resp.raw_data().len(),
        resp.status()
    );

    Ok(resp)
}

/// Send the given Command (chained, if required) to the card and
/// return the response as a vector of `u8`.
///
/// If the response is chained, this fn only returns one chunk, the caller
/// needs to re-assemble the chained response-parts.
fn send_command_low_level<C>(
    card_tx: &mut C,
    cmd: &Command,
    card_caps: Option<CardCaps>,
    ext_len: bool,
    expect_response: Expect,
) -> Result<Vec<u8>, Error>
where
    C: CardTransaction + ?Sized,
{
    let (ext_support, chaining_support, max_cmd_bytes, max_rsp_bytes) =
        if let Some(caps) = card_caps {
            log::trace!("found card caps data!");

            (
                caps.ext_support(),
                caps.chaining_support(),
                caps.max_cmd_bytes() as usize,
                caps.max_rsp_bytes() as usize,
            )
        } else {
            log::trace!("found NO card caps data!");

            // default settings
            (false, false, 255, 255)
        };

    log::trace!(
        "ext le/lc {}, chaining {}, max cmd {}, max rsp {}",
        ext_support,
        chaining_support,
        max_cmd_bytes,
        max_rsp_bytes
    );

    let buf_size = if ext_len {
        max_rsp_bytes + 2
    } else {
        MAX_BUFFER_SIZE
    };

    log::trace!("buf_size {}", buf_size);

    if command_requires_chaining(cmd, card_caps) {
        if !chaining_support || !command_supports_chaining(cmd) {
            return Err(Error::CommandTooLong(cmd.data().len()));
        }

        log::trace!("chained command mode");

        let cmd_chunk_size = max_command_data_bytes(card_caps);
        if cmd_chunk_size == 0 {
            return Err(Error::CommandTooLong(cmd.data().len()));
        }

        // Break up payload into chunks that fit into one command, each
        let (secret, chunks) = match cmd.data() {
            Data::Plain(vec) => (false, vec.chunks(cmd_chunk_size)),
            Data::Sensitive(sensitive) => (true, sensitive.expose_secret().chunks(cmd_chunk_size)),
        };

        let len = chunks.len();

        for (i, d) in chunks.enumerate() {
            let last = i == len - 1;

            let cla = if last { 0x00 } else { 0x10 };
            let partial = Command::new(cla, cmd.ins(), cmd.p1(), cmd.p2(), d.to_vec())?;
            let expect_partial_response = if last { expect_response } else { Expect::Empty };
            let serialized = partial.serialize(ext_len, expect_partial_response)?;
            check_transport_command_length(card_tx, serialized.len())?;

            if secret {
                log::trace!(" -> chained APDU command: hidden due to secret data");
            } else {
                log::trace!(" -> chained APDU command: {:02x?}", serialized);
            }

            let resp = card_tx.transmit(&serialized, buf_size)?;

            log::trace!(" <- APDU response [len {}]", resp.len());

            if resp.len() < 2 {
                return Err(Error::ResponseLength(resp.len()));
            }

            if !last {
                if resp.len() != 2 {
                    return Err(Error::ResponseLength(resp.len()));
                }

                let status = StatusBytes::from((resp[0], resp[1]));

                // ISO: "If SW1-SW2 is set to '6883', then the last
                // command of the chain is expected."
                if !(status == StatusBytes::Ok || status == StatusBytes::LastCommandOfChainExpected)
                {
                    // Unexpected status for a non-final chunked response
                    return Err(status.into());
                }

                // ISO: "If SW1-SW2 is set to '6884', then command
                // chaining is not supported."
            } else {
                // this is the last Response in the chain -> return
                return Ok(resp);
            }
        }

        Err(Error::InternalError(
            "Command chaining produced no commands".to_string(),
        ))
    } else {
        let serialized = cmd.serialize(ext_len, expect_response)?;
        check_transport_command_length(card_tx, serialized.len())?;

        if matches!(cmd.data(), Data::Sensitive(_)) {
            log::trace!(" -> APDU command: hidden due to secret data");
        } else {
            log::trace!(" -> APDU command: {:02x?}", serialized);
        }

        let resp = card_tx.transmit(&serialized, buf_size)?;

        log::trace!(" <- APDU response [len {}]", resp.len());

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use card_backend::{PinType, SmartcardError};

    use super::*;

    struct ScriptedCard {
        responses: VecDeque<Vec<u8>>,
        commands: Vec<Vec<u8>>,
        buffer_sizes: Vec<usize>,
        transport_max_cmd_len: Option<usize>,
    }

    impl ScriptedCard {
        fn new(responses: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                commands: Vec::new(),
                buffer_sizes: Vec::new(),
                transport_max_cmd_len: None,
            }
        }

        fn with_max_cmd_len(mut self, max_cmd_len: usize) -> Self {
            self.transport_max_cmd_len = Some(max_cmd_len);
            self
        }
    }

    impl CardTransaction for ScriptedCard {
        fn transmit(&mut self, cmd: &[u8], buf_size: usize) -> Result<Vec<u8>, SmartcardError> {
            self.commands.push(cmd.to_vec());
            self.buffer_sizes.push(buf_size);
            self.responses.pop_front().ok_or_else(|| {
                SmartcardError::Error("no scripted response is available".to_string())
            })
        }

        fn max_cmd_len(&self) -> Option<usize> {
            self.transport_max_cmd_len
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
                "PIN-pad verification is not scripted".to_string(),
            ))
        }

        fn pinpad_modify(
            &mut self,
            _pin: PinType,
            _card_caps: &Option<CardCaps>,
        ) -> Result<Vec<u8>, SmartcardError> {
            Err(SmartcardError::Error(
                "PIN-pad modification is not scripted".to_string(),
            ))
        }

        fn was_reset(&self) -> bool {
            false
        }
    }

    fn response(data: impl AsRef<[u8]>, sw1: u8, sw2: u8) -> Vec<u8> {
        let mut response = data.as_ref().to_vec();
        response.extend_from_slice(&[sw1, sw2]);
        response
    }

    fn successful() -> Vec<u8> {
        vec![0x90, 0x00]
    }

    fn caps(
        ext_support: bool,
        chaining_support: bool,
        max_cmd_bytes: u16,
        max_rsp_bytes: u16,
    ) -> Option<CardCaps> {
        Some(CardCaps::new(
            ext_support,
            chaining_support,
            max_cmd_bytes,
            max_rsp_bytes,
            64,
            64,
        ))
    }

    fn command(ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Result<Command, Error> {
        Command::new(0x00, ins, p1, p2, data)
    }

    #[test]
    fn ordinary_commands_remain_short_and_unchained() -> Result<(), Error> {
        let mut card = ScriptedCard::new([successful(), successful()]);
        let capabilities = caps(true, true, 2048, 2048);

        send_command(
            &mut card,
            command(0xca, 0x00, 0x6e, vec![])?,
            capabilities,
            true,
        )?;
        send_command(
            &mut card,
            command(0xda, 0x00, 0x5e, vec![1, 2, 3])?,
            capabilities,
            false,
        )?;

        assert_eq!(
            card.commands,
            [
                vec![0x00, 0xca, 0x00, 0x6e, 0x00],
                vec![0x00, 0xda, 0x00, 0x5e, 0x03, 1, 2, 3],
            ]
        );
        Ok(())
    }

    #[test]
    fn length_mode_and_command_data_limits_are_independent() -> Result<(), Error> {
        let mut card = ScriptedCard::new([successful(), successful(), successful()]);

        send_command(
            &mut card,
            command(0xdb, 0x3f, 0xff, vec![0xa5; 255])?,
            caps(true, true, 2048, 2048),
            false,
        )?;
        send_command(
            &mut card,
            command(0xdb, 0x3f, 0xff, vec![0xa5; 255])?,
            caps(false, false, 255, 255),
            false,
        )?;
        send_command(
            &mut card,
            command(0xdb, 0x3f, 0xff, vec![0xa5; 256])?,
            caps(true, true, 2048, 2048),
            false,
        )?;

        assert_eq!(card.commands.len(), 3);
        assert_eq!(card.commands[0].len(), 260);
        assert_eq!(card.commands[0][4], 255);
        assert_eq!(card.commands[1].len(), 260);
        assert_eq!(card.commands[1][4], 255);
        assert_eq!(
            &card.commands[2][..7],
            &[0x00, 0xdb, 0x3f, 0xff, 0x00, 0x01, 0x00]
        );
        assert_eq!(card.commands[2].len(), 263);
        assert_eq!(card.buffer_sizes, [264, 264, 2050]);
        Ok(())
    }

    #[test]
    fn oversized_and_unsupported_commands_fail_before_transmission() -> Result<(), Error> {
        let mut card = ScriptedCard::new(Vec::new());

        let result = send_command(
            &mut card,
            command(0xdb, 0x3f, 0xff, vec![0; 256])?,
            caps(false, false, 255, 255),
            false,
        );
        assert!(matches!(result, Err(Error::CommandTooLong(256))));

        let result = send_command(
            &mut card,
            command(0xdb, 0x3f, 0xff, vec![0; 2049])?,
            caps(true, false, 2048, 2048),
            false,
        );
        assert!(matches!(result, Err(Error::CommandTooLong(2049))));

        let result = send_command(
            &mut card,
            command(0x2a, 0x9e, 0x9a, vec![0; 600])?,
            caps(false, true, 255, 255),
            true,
        );
        assert!(matches!(result, Err(Error::CommandTooLong(600))));

        let result = send_command(
            &mut card,
            command(0x88, 0x00, 0x00, vec![0; 600])?,
            caps(false, true, 255, 255),
            true,
        );
        assert!(matches!(result, Err(Error::CommandTooLong(600))));

        let result = send_command(
            &mut card,
            command(0xda, 0x00, 0x01, vec![1])?,
            caps(false, true, 0, 255),
            false,
        );
        assert!(matches!(result, Err(Error::CommandTooLong(1))));
        assert!(card.commands.is_empty());
        Ok(())
    }

    #[test]
    fn transport_command_limit_is_enforced_before_transmission() -> Result<(), Error> {
        let mut card = ScriptedCard::new(Vec::new()).with_max_cmd_len(20);
        let result = send_command(
            &mut card,
            command(0xda, 0x00, 0x01, vec![0; 20])?,
            caps(false, false, 255, 255),
            false,
        );

        assert!(matches!(result, Err(Error::CommandTooLong(25))));
        assert!(card.commands.is_empty());
        Ok(())
    }

    #[test]
    fn eligible_oversized_decipher_uses_required_short_chaining() -> Result<(), Error> {
        let payload = vec![0x5a; 600];
        let mut card = ScriptedCard::new([successful(), response([], 0x68, 0x83), successful()]);

        send_command(
            &mut card,
            command(0x2a, 0x80, 0x86, payload.clone())?,
            caps(false, true, 255, 255),
            true,
        )?;

        assert_eq!(card.commands.len(), 3);
        assert_eq!(card.commands[0][0], 0x10);
        assert_eq!(card.commands[1][0], 0x10);
        assert_eq!(card.commands[2][0], 0x00);
        assert_eq!(card.commands[0].len(), 260);
        assert_eq!(card.commands[1].len(), 260);
        assert_eq!(card.commands[2].len(), 96);
        assert_eq!(&card.commands[0][5..], &payload[..255]);
        assert_eq!(&card.commands[1][5..], &payload[255..510]);
        assert_eq!(&card.commands[2][5..95], &payload[510..]);
        assert_eq!(card.commands[2][95], 0x00);
        Ok(())
    }

    #[test]
    fn extended_chaining_preserves_the_operation_length_mode() -> Result<(), Error> {
        let mut card = ScriptedCard::new([successful(), successful()]);

        send_command(
            &mut card,
            command(0xdb, 0x3f, 0xff, vec![0x5a; 1100])?,
            caps(true, true, 1024, 1024),
            true,
        )?;

        assert_eq!(card.commands.len(), 2);
        assert_eq!(card.commands[0].len(), 1031);
        assert_eq!(
            &card.commands[0][..7],
            &[0x10, 0xdb, 0x3f, 0xff, 0x00, 0x04, 0x00]
        );
        assert_eq!(card.commands[1].len(), 85);
        assert_eq!(
            &card.commands[1][..7],
            &[0x00, 0xdb, 0x3f, 0xff, 0x00, 0x00, 0x4c]
        );
        assert_eq!(&card.commands[1][83..], &[0x00, 0x00]);
        Ok(())
    }

    #[test]
    fn short_apdu_rsa4096_public_key_response_is_not_truncated() -> Result<(), Error> {
        let mut public_key = vec![0x7f, 0x49, 0x82, 0x02, 0x09, 0x81, 0x82, 0x02, 0x00];
        public_key.extend_from_slice(&[0x55; 512]);
        public_key.extend_from_slice(&[0x82, 0x03, 0x01, 0x00, 0x01]);
        assert_eq!(public_key.len(), 526);

        let mut card = ScriptedCard::new([
            response(&public_key[..256], 0x61, 0x00),
            response(&public_key[256..512], 0x61, 0x0e),
            response(&public_key[512..], 0x90, 0x00),
        ]);
        let resp = send_command(
            &mut card,
            commands::get_pub_key(vec![0xb6, 0x00])?,
            caps(false, true, 255, 255),
            true,
        )?;

        assert_eq!(resp.raw_data(), public_key.as_slice());
        assert_eq!(
            card.commands,
            [
                vec![0x00, 0x47, 0x81, 0x00, 0x02, 0xb6, 0x00, 0x00],
                vec![0x00, 0xc0, 0x00, 0x00, 0x00],
                vec![0x00, 0xc0, 0x00, 0x00, 0x0e],
            ]
        );
        Ok(())
    }

    #[test]
    fn extended_get_response_uses_extended_le() -> Result<(), Error> {
        let mut card = ScriptedCard::new([
            response([], 0x61, 0x02),
            response([1, 2], 0x61, 0x00),
            response(vec![3; 256], 0x90, 0x00),
        ]);

        let resp = send_command(
            &mut card,
            command(0xdb, 0x3f, 0xff, vec![0xa5; 256])?,
            caps(true, false, 1024, 1024),
            true,
        )?;

        assert_eq!(resp.raw_data().len(), 258);
        assert_eq!(&resp.raw_data()[..2], &[1, 2]);
        assert_eq!(
            card.commands[1],
            vec![0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x02]
        );
        assert_eq!(
            card.commands[2],
            vec![0x00, 0xc0, 0x00, 0x00, 0x00, 0x01, 0x00]
        );
        assert_eq!(card.buffer_sizes, [1026, 1026, 1026]);
        Ok(())
    }

    #[test]
    fn short_length_correction_is_applied_only_once() -> Result<(), Error> {
        let mut corrected = ScriptedCard::new([
            response([], 0x6c, 0x20),
            response(vec![0xaa; 32], 0x90, 0x00),
        ]);
        let resp = send_command(
            &mut corrected,
            command(0xca, 0x00, 0x6e, vec![])?,
            caps(true, false, 2048, 2048),
            true,
        )?;

        assert_eq!(resp.raw_data().len(), 32);
        assert_eq!(
            corrected.commands,
            [
                vec![0x00, 0xca, 0x00, 0x6e, 0x00],
                vec![0x00, 0xca, 0x00, 0x6e, 0x20],
            ]
        );

        let mut repeated = ScriptedCard::new([response([], 0x6c, 0x20), response([], 0x6c, 0x20)]);
        let resp = send_command(
            &mut repeated,
            command(0xca, 0x00, 0x6e, vec![])?,
            caps(false, false, 255, 255),
            true,
        )?;
        assert!(matches!(
            resp.status(),
            StatusBytes::UnknownStatus(0x6c, 0x20)
        ));
        assert_eq!(repeated.commands.len(), 2);
        Ok(())
    }

    #[test]
    fn extended_length_correction_uses_extended_le() -> Result<(), Error> {
        let mut card = ScriptedCard::new([
            response([], 0x6c, 0x00),
            response(vec![0xaa; 256], 0x90, 0x00),
        ]);

        let resp = send_command(
            &mut card,
            command(0xdb, 0x3f, 0xff, vec![0xa5; 256])?,
            caps(true, false, 1024, 1024),
            true,
        )?;

        assert_eq!(resp.raw_data().len(), 256);
        assert_eq!(card.commands.len(), 2);
        assert_eq!(&card.commands[0][263..], &[0x00, 0x00]);
        assert_eq!(&card.commands[1][263..], &[0x01, 0x00]);
        Ok(())
    }

    #[test]
    fn length_correction_does_not_repeat_chains_or_commands_without_le() -> Result<(), Error> {
        let mut chained = ScriptedCard::new([successful(), successful(), response([], 0x6c, 0x20)]);
        let resp = send_command(
            &mut chained,
            command(0x2a, 0x80, 0x86, vec![0; 600])?,
            caps(false, true, 255, 255),
            true,
        )?;
        assert!(matches!(
            resp.status(),
            StatusBytes::UnknownStatus(0x6c, 0x20)
        ));
        assert_eq!(chained.commands.len(), 3);

        let mut without_le = ScriptedCard::new([response([], 0x6c, 0x20)]);
        let resp = send_command(
            &mut without_le,
            command(0xda, 0x00, 0x01, vec![1, 2, 3])?,
            caps(false, false, 255, 255),
            false,
        )?;
        assert!(matches!(
            resp.status(),
            StatusBytes::UnknownStatus(0x6c, 0x20)
        ));
        assert_eq!(without_le.commands.len(), 1);
        Ok(())
    }

    #[test]
    fn continuation_limit_stops_unending_responses() -> Result<(), Error> {
        let responses = (0..=MAX_RESPONSE_CONTINUATIONS)
            .map(|_| response([1], 0x61, 0x01))
            .collect::<Vec<_>>();
        let mut card = ScriptedCard::new(responses);

        let result = send_command(
            &mut card,
            command(0xca, 0x00, 0x6e, vec![])?,
            caps(false, false, 255, 255),
            true,
        );

        assert!(matches!(result, Err(Error::InternalError(_))));
        assert_eq!(card.commands.len(), MAX_RESPONSE_CONTINUATIONS + 1);
        Ok(())
    }

    #[test]
    fn oversized_responses_are_rejected_without_truncation() -> Result<(), Error> {
        let mut single = ScriptedCard::new([response(vec![0; MAX_RESPONSE_BYTES + 1], 0x90, 0x00)]);
        let result = send_command(
            &mut single,
            command(0xca, 0x00, 0x6e, vec![])?,
            caps(false, false, 255, 255),
            true,
        );
        assert!(matches!(
            result,
            Err(Error::ResponseLength(length)) if length == MAX_RESPONSE_BYTES + 1
        ));

        let mut aggregate = ScriptedCard::new([
            response(vec![0; MAX_RESPONSE_BYTES], 0x61, 0x01),
            response([1], 0x90, 0x00),
        ]);
        let result = send_command(
            &mut aggregate,
            command(0xca, 0x00, 0x6e, vec![])?,
            caps(false, false, 255, 255),
            true,
        );
        assert!(matches!(
            result,
            Err(Error::ResponseLength(length)) if length == MAX_RESPONSE_BYTES + 1
        ));
        Ok(())
    }

    #[test]
    fn malformed_responses_fail_without_panicking() -> Result<(), Error> {
        let mut short = ScriptedCard::new([vec![0x90]]);
        let result = send_command(
            &mut short,
            command(0xca, 0x00, 0x6e, vec![])?,
            caps(false, false, 255, 255),
            true,
        );
        assert!(matches!(result, Err(Error::ResponseLength(_))));

        let mut chained = ScriptedCard::new([response([0xaa], 0x90, 0x00)]);
        let result = send_command(
            &mut chained,
            command(0x2a, 0x80, 0x86, vec![0; 600])?,
            caps(false, true, 255, 255),
            true,
        );
        assert!(matches!(result, Err(Error::ResponseLength(3))));
        assert_eq!(chained.commands.len(), 1);
        Ok(())
    }
}
