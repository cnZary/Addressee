#![allow(unsafe_code)]

//! Minimal macOS PC/SC FFI boundary.
//!
//! Safety invariants:
//! - Only the parent RAII module supplies handles, and each handle comes from
//!   a successful corresponding PC/SC open call.
//! - The parent gives each PC/SC call exclusive access to its handle. A card
//!   transaction ends before disconnect, and disconnect precedes context release.
//! - Every pointer passed to PC/SC is null where permitted by the API, or points
//!   to live Rust storage for the complete call and its declared length.
//! - Lengths are checked before conversion to `uint32_t`; returned lengths are
//!   checked before any Rust slice is shortened or returned.
//! - The framework-owned PCI statics have static lifetime and immutable contents.
//!   They are passed by pointer only, using the pointer for the active protocol.

use std::{
    ffi::{CStr, c_char, c_void},
    mem::{align_of, size_of},
    ptr::{addr_of, null, null_mut},
};

use super::super::{PcscError, Protocol, validate_command_length};

const SCARD_SCOPE_SYSTEM: u32 = 2;
const SCARD_SHARE_SHARED: u32 = 2;
const SCARD_PROTOCOL_T0: u32 = 1;
const SCARD_PROTOCOL_T1: u32 = 2;
const SCARD_LEAVE_CARD: u32 = 0;
const SCARD_E_INSUFFICIENT_BUFFER: u32 = 0x8010_0008;
const SCARD_E_NO_READERS_AVAILABLE: u32 = 0x8010_002E;
const MAX_READER_LIST_BYTES: usize = 1024 * 1024;
const LIST_READERS_ATTEMPTS: usize = 4;

#[repr(C, packed)]
struct ScardIoRequest {
    protocol: u32,
    pci_length: u32,
}

const _: [(); 8] = [(); size_of::<ScardIoRequest>()];
const _: [(); 1] = [(); align_of::<ScardIoRequest>()];

#[link(name = "PCSC", kind = "framework")]
unsafe extern "C" {
    #[link_name = "g_rgSCardT0Pci"]
    static SCARD_T0_PCI: ScardIoRequest;
    #[link_name = "g_rgSCardT1Pci"]
    static SCARD_T1_PCI: ScardIoRequest;

    #[link_name = "SCardEstablishContext"]
    fn establish_context_raw(
        scope: u32,
        reserved1: *const c_void,
        reserved2: *const c_void,
        context: *mut i32,
    ) -> i32;
    #[link_name = "SCardReleaseContext"]
    fn release_context_raw(context: i32) -> i32;
    #[link_name = "SCardListReaders"]
    fn list_readers_raw(
        context: i32,
        groups: *const c_char,
        readers: *mut c_char,
        readers_len: *mut u32,
    ) -> i32;
    #[link_name = "SCardConnect"]
    fn connect_raw(
        context: i32,
        reader: *const c_char,
        share_mode: u32,
        preferred_protocols: u32,
        card: *mut i32,
        active_protocol: *mut u32,
    ) -> i32;
    #[link_name = "SCardDisconnect"]
    fn disconnect_raw(card: i32, disposition: u32) -> i32;
    #[link_name = "SCardBeginTransaction"]
    fn begin_transaction_raw(card: i32) -> i32;
    #[link_name = "SCardEndTransaction"]
    fn end_transaction_raw(card: i32, disposition: u32) -> i32;
    #[link_name = "SCardTransmit"]
    fn transmit_raw(
        card: i32,
        send_pci: *const ScardIoRequest,
        send_buffer: *const u8,
        send_length: u32,
        receive_pci: *mut ScardIoRequest,
        receive_buffer: *mut u8,
        receive_length: *mut u32,
    ) -> i32;
}

pub(super) fn establish_context() -> Result<i32, PcscError> {
    let mut context = 0;
    // SAFETY: Both reserved pointers are null as required. `context` points to
    // live, aligned i32 storage that PC/SC may initialize during this call.
    let status = unsafe { establish_context_raw(SCARD_SCOPE_SYSTEM, null(), null(), &mut context) };
    check("SCardEstablishContext", status)?;
    Ok(context)
}

pub(super) fn release_context(context: i32) -> Result<(), PcscError> {
    // SAFETY: The parent owns this established context and calls release only
    // after dependent cards and transactions have been closed.
    let status = unsafe { release_context_raw(context) };
    check("SCardReleaseContext", status)
}

pub(super) fn list_readers(context: i32) -> Result<Vec<u8>, PcscError> {
    for _ in 0..LIST_READERS_ATTEMPTS {
        let mut required = 0_u32;
        // SAFETY: The context is valid and exclusively borrowed. Null groups
        // requests all groups; null readers requests the required buffer size.
        // `required` is valid writable uint32 storage.
        let status = unsafe { list_readers_raw(context, null(), null_mut(), &mut required) };
        let code = status as u32;
        if code == SCARD_E_NO_READERS_AVAILABLE {
            return Ok(vec![0]);
        }
        if status != 0 && code != SCARD_E_INSUFFICIENT_BUFFER {
            return Err(PcscError::from_status("SCardListReaders", status));
        }
        if required == 0 {
            return Ok(vec![0]);
        }
        if required as usize > MAX_READER_LIST_BYTES {
            return Err(PcscError::InvalidReaderList(format!(
                "required buffer of {required} bytes exceeds the {MAX_READER_LIST_BYTES}-byte limit"
            )));
        }

        let mut readers = vec![0_u8; required as usize];
        let mut actual = required;
        // SAFETY: The context is valid and exclusively borrowed. The output
        // pointer addresses `readers`, whose initialized allocation is exactly
        // `actual` bytes. Both length pointers refer to live uint32 storage.
        let status = unsafe {
            list_readers_raw(
                context,
                null(),
                readers.as_mut_ptr().cast::<c_char>(),
                &mut actual,
            )
        };
        let code = status as u32;
        if code == SCARD_E_INSUFFICIENT_BUFFER {
            continue;
        }
        if code == SCARD_E_NO_READERS_AVAILABLE {
            return Ok(vec![0]);
        }
        check("SCardListReaders", status)?;
        if actual == 0 {
            return Ok(vec![0]);
        }
        if actual as usize > readers.len() {
            return Err(PcscError::InvalidReaderList(format!(
                "reported length {} exceeds the allocated {} bytes",
                actual,
                readers.len()
            )));
        }
        readers.truncate(actual as usize);
        return Ok(readers);
    }

    Err(PcscError::ReaderListChanged)
}

pub(super) fn connect(context: i32, reader: &CStr) -> Result<(i32, u32), PcscError> {
    let mut card = 0;
    let mut protocol = 0;
    // SAFETY: The context is valid. `reader` is NUL-terminated and lives through
    // the call. Both output pointers refer to live, aligned writable storage.
    let status = unsafe {
        connect_raw(
            context,
            reader.as_ptr(),
            SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
            &mut card,
            &mut protocol,
        )
    };
    check("SCardConnect", status)?;
    Ok((card, protocol))
}

pub(super) fn disconnect(card: i32) -> Result<(), PcscError> {
    // SAFETY: The parent owns this connected card and guarantees that its owned
    // transaction has ended. LEAVE_CARD avoids reset, power-down, and ejection.
    let status = unsafe { disconnect_raw(card, SCARD_LEAVE_CARD) };
    check("SCardDisconnect", status)
}

pub(super) fn begin_transaction(card: i32) -> Result<(), PcscError> {
    // SAFETY: The parent exclusively borrows this connected card for the
    // transaction, preventing concurrent calls through safe Rust.
    let status = unsafe { begin_transaction_raw(card) };
    check("SCardBeginTransaction", status)
}

pub(super) fn end_transaction(card: i32) -> Result<(), PcscError> {
    // SAFETY: The parent calls this only for its active transaction and before
    // disconnect. LEAVE_CARD avoids reset, power-down, and ejection.
    let status = unsafe { end_transaction_raw(card, SCARD_LEAVE_CARD) };
    check("SCardEndTransaction", status)
}

pub(super) fn transmit(
    card: i32,
    protocol: Protocol,
    command: &[u8],
    receive_buffer: &mut [u8],
) -> Result<usize, PcscError> {
    validate_command_length(command.len())?;
    let send_length = u32::try_from(command.len())
        .map_err(|_| PcscError::InvalidState("command length exceeds PC/SC uint32"))?;
    let mut received = u32::try_from(receive_buffer.len())
        .map_err(|_| PcscError::InvalidState("receive length exceeds PC/SC uint32"))?;

    // SAFETY: The parent holds the active transaction exclusively. `command`
    // and `receive_buffer` are live for their declared lengths, which fit u32.
    // The receive PCI is null as permitted. `received` is valid writable u32
    // storage. Each PCI pointer addresses the corresponding immutable static
    // supplied by the PCSC framework for the duration of the process.
    let status = unsafe {
        let send_pci = match protocol {
            Protocol::T0 => addr_of!(SCARD_T0_PCI),
            Protocol::T1 => addr_of!(SCARD_T1_PCI),
        };
        transmit_raw(
            card,
            send_pci,
            command.as_ptr(),
            send_length,
            null_mut(),
            receive_buffer.as_mut_ptr(),
            &mut received,
        )
    };
    check("SCardTransmit", status)?;
    Ok(received as usize)
}

fn check(operation: &'static str, status: i32) -> Result<(), PcscError> {
    if status == 0 {
        Ok(())
    } else {
        Err(PcscError::from_status(operation, status))
    }
}
