use std::sync::{Arc, Mutex};

use crate::{
    AddresseeError, CardIdentityFfi, CardPinKind, CardSlot, CardTouchPolicyFfi, CardTransport,
    CardTransportCapabilities, CardTransportError, OpenPgpCardManagementSession,
};

const IDENTITY: CardIdentityFfi = CardIdentityFfi {
    manufacturer: 0xFFFF,
    serial: 0x0102_0304,
    version: 0x0304,
};
const USER_PIN: &[u8] = b"synthetic-old-user";
const NEW_USER_PIN: &[u8] = b"synthetic-new-user";
const ADMIN_PIN: &[u8] = b"synthetic-old-admin";
const NEW_ADMIN_PIN: &[u8] = b"synthetic-new-admin";
const P256_OID: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

#[test]
fn inspection_reads_identity_slots_and_advertised_algorithms_without_private_operations() {
    let fixture = Fixture::new();
    let session = fixture.session(IDENTITY);
    fixture.transport.clear_commands();

    let information = session.inspect().unwrap();
    assert_eq!(information.identity, IDENTITY);
    assert_eq!(information.user_pin_retries, 3);
    assert_eq!(information.admin_pin_retries, 3);
    assert_eq!(information.user_pin_max_length, 64);
    assert_eq!(information.admin_pin_max_length, 64);
    assert!(information.signature_pin_valid_once);
    assert!(information.key_import_advertised);
    assert!(information.algorithm_attributes_changeable);
    assert!(information.password_status_changeable);
    assert_eq!(information.slots.len(), 3);
    assert_eq!(information.slots[0].slot, CardSlot::Signing);
    assert_eq!(
        information.slots[0].fingerprint.as_deref(),
        Some("1111111111111111111111111111111111111111")
    );
    assert_eq!(information.slots[0].key_reference, Some(1));
    assert_eq!(information.slots[0].key_present, Some(true));
    assert_eq!(information.slots[1].key_present, Some(true));
    assert_eq!(information.slots[2].key_present, Some(false));
    assert_eq!(information.slots[0].created_at, Some(0x0102_0304));
    assert_eq!(information.slots[0].touch_policy.as_deref(), Some("Off"));
    assert_eq!(information.slots[0].advertised_algorithms.len(), 2);
    assert_eq!(information.slots[1].advertised_algorithms.len(), 1);
    assert_eq!(information.slots[2].advertised_algorithms.len(), 1);
    assert_read_only(&fixture.transport.commands());
}

#[test]
fn initial_and_later_identity_changes_are_rejected_before_pin_or_write_commands() {
    let fixture = Fixture::new();
    assert!(matches!(
        OpenPgpCardManagementSession::connect(
            CardIdentityFfi {
                serial: IDENTITY.serial + 1,
                ..IDENTITY
            },
            fixture.transport.clone(),
        ),
        Err(AddresseeError::CardRegistrationConflict)
    ));
    assert_read_only(&fixture.transport.commands());

    let session = fixture.session(IDENTITY);
    fixture.transport.set_identity(CardIdentityFfi {
        serial: IDENTITY.serial + 1,
        ..IDENTITY
    });
    fixture.transport.clear_commands();
    assert!(matches!(
        session.change_pin(
            CardPinKind::User,
            String::from_utf8(USER_PIN.to_vec()).unwrap(),
            String::from_utf8(NEW_USER_PIN.to_vec()).unwrap(),
        ),
        Err(AddresseeError::CardRegistrationConflict)
    ));
    assert_read_only(&fixture.transport.commands());
}

#[test]
fn raw_pin_mode_changes_user_and_admin_pins_with_exact_commands() {
    for kind in [CardPinKind::User, CardPinKind::Admin] {
        let fixture = Fixture::new();
        let session = fixture.session(IDENTITY);
        fixture.transport.clear_commands();
        let (current, new, reference) = match kind {
            CardPinKind::User => (USER_PIN, NEW_USER_PIN, 0x81),
            CardPinKind::Admin => (ADMIN_PIN, NEW_ADMIN_PIN, 0x83),
        };
        session
            .change_pin(
                kind,
                String::from_utf8(current.to_vec()).unwrap(),
                String::from_utf8(new.to_vec()).unwrap(),
            )
            .unwrap();

        let expected = apdu(0x24, 0x00, reference, &[current, new].concat());
        let changes = commands_with_instruction(&fixture.transport.commands(), 0x24);
        assert_eq!(changes, [expected]);
        assert!(commands_with_instruction(&fixture.transport.commands(), 0x20).is_empty());
        assert_read_only_except_management_changes(&fixture.transport.commands());
    }
}

#[test]
fn absent_unadvertised_kdf_does_not_break_raw_pin_changes() {
    let fixture = Fixture::new();
    fixture.transport.set_raw_kdf_availability(false);
    let session = fixture.session(IDENTITY);
    session
        .change_pin(
            CardPinKind::User,
            String::from_utf8(USER_PIN.to_vec()).unwrap(),
            String::from_utf8(NEW_USER_PIN.to_vec()).unwrap(),
        )
        .unwrap();
    assert_eq!(
        commands_with_instruction(&fixture.transport.commands(), 0x24).len(),
        1
    );
}

#[test]
fn low_retries_stop_before_pin_commands_for_every_management_operation() {
    let fixture = Fixture::new();
    fixture.transport.set_retries(1, 1);
    let session = fixture.session(IDENTITY);
    fixture.transport.clear_commands();

    assert!(matches!(
        session.change_pin(
            CardPinKind::User,
            String::from_utf8(USER_PIN.to_vec()).unwrap(),
            String::from_utf8(NEW_USER_PIN.to_vec()).unwrap(),
        ),
        Err(AddresseeError::RemoteKeyUnavailable)
    ));
    assert!(matches!(
        session.change_pin(
            CardPinKind::Admin,
            String::from_utf8(ADMIN_PIN.to_vec()).unwrap(),
            String::from_utf8(NEW_ADMIN_PIN.to_vec()).unwrap(),
        ),
        Err(AddresseeError::RemoteKeyUnavailable)
    ));
    assert!(matches!(
        session.set_touch_policy(
            CardSlot::Signing,
            CardTouchPolicyFfi::On,
            String::from_utf8(ADMIN_PIN.to_vec()).unwrap(),
        ),
        Err(AddresseeError::RemoteKeyUnavailable)
    ));
    assert_read_only(&fixture.transport.commands());
}

#[test]
fn wrong_pin_is_not_retried_and_never_writes_touch_policy() {
    let fixture = Fixture::new();
    let session = fixture.session(IDENTITY);
    fixture.transport.clear_commands();
    assert!(matches!(
        session.change_pin(
            CardPinKind::User,
            "incorrect-synthetic-user".to_owned(),
            String::from_utf8(NEW_USER_PIN.to_vec()).unwrap(),
        ),
        Err(AddresseeError::InvalidPassword)
    ));
    assert_eq!(
        commands_with_instruction(&fixture.transport.commands(), 0x24).len(),
        1
    );
    let information = session.inspect().unwrap();
    assert_eq!(information.user_pin_retries, 2);

    fixture.transport.clear_commands();
    assert!(matches!(
        session.set_touch_policy(
            CardSlot::Signing,
            CardTouchPolicyFfi::On,
            "incorrect-synthetic-admin".to_owned(),
        ),
        Err(AddresseeError::InvalidPassword)
    ));
    assert_eq!(
        commands_with_instruction(&fixture.transport.commands(), 0x20).len(),
        1
    );
    assert!(commands_with_instruction(&fixture.transport.commands(), 0xDA).is_empty());
    assert_eq!(session.inspect().unwrap().admin_pin_retries, 2);
}

#[test]
fn touch_change_requires_admin_and_writes_only_the_requested_reversible_flag() {
    let fixture = Fixture::new();
    let session = fixture.session(IDENTITY);
    fixture.transport.clear_commands();
    session
        .set_touch_policy(
            CardSlot::Signing,
            CardTouchPolicyFfi::On,
            String::from_utf8(ADMIN_PIN.to_vec()).unwrap(),
        )
        .unwrap();

    let commands = fixture.transport.commands();
    let writes = commands_with_instruction(&commands, 0xDA);
    assert_eq!(writes, [vec![0x00, 0xDA, 0x00, 0xD6, 0x02, 0x01, 0x20]]);
    assert_eq!(commands_with_instruction(&commands, 0x20).len(), 1);
    let information = session.inspect().unwrap();
    assert_eq!(information.slots[0].touch_policy.as_deref(), Some("On"));
    assert_eq!(information.slots[1].touch_policy.as_deref(), Some("Off"));
    assert_read_only_except_management_changes(&fixture.transport.commands());
}

#[test]
fn fixed_or_unknown_touch_policy_is_never_changed_after_a_pin_attempt() {
    for policy in [0x02, 0x04, 0xFF] {
        let fixture = Fixture::new();
        fixture.transport.state.lock().unwrap().touch_policies[0] = policy;
        let session = fixture.session(IDENTITY);
        fixture.transport.clear_commands();

        assert!(matches!(
            session.set_touch_policy(
                CardSlot::Signing,
                CardTouchPolicyFfi::On,
                String::from_utf8(ADMIN_PIN.to_vec()).unwrap(),
            ),
            Err(AddresseeError::UnsupportedOperation)
        ));
        assert_read_only(&fixture.transport.commands());
    }
}

#[test]
fn unknown_key_status_is_not_reported_as_present() {
    let fixture = Fixture::new();
    fixture
        .transport
        .set_key_information(Some(vec![0x01, 0xFF, 0x02, 0x01, 0x03, 0x00]));
    let session = fixture.session(IDENTITY);

    let information = session.inspect().unwrap();
    assert_eq!(information.slots[0].key_present, None);
    assert_eq!(information.slots[1].key_present, Some(true));
    assert_read_only(&fixture.transport.commands());
}

#[test]
fn malformed_key_information_is_an_error_not_a_memory_safety_failure() {
    let fixture = Fixture::new();
    fixture.transport.set_key_information(Some(vec![0x01]));
    let session = fixture.session(IDENTITY);
    fixture.transport.clear_commands();

    assert!(matches!(
        session.inspect(),
        Err(AddresseeError::RemoteKeyUnavailable)
    ));
    assert_read_only(&fixture.transport.commands());
}

#[test]
fn kdf_read_failure_stops_before_pin_verification_or_management_writes() {
    let fixture = Fixture::new();
    fixture.transport.state.lock().unwrap().kdf_failure = true;
    let session = fixture.session(IDENTITY);
    fixture.transport.clear_commands();

    assert!(matches!(
        session.change_pin(
            CardPinKind::User,
            String::from_utf8(USER_PIN.to_vec()).unwrap(),
            String::from_utf8(NEW_USER_PIN.to_vec()).unwrap(),
        ),
        Err(AddresseeError::RemoteKeyUnavailable)
    ));
    assert!(matches!(
        session.set_touch_policy(
            CardSlot::Signing,
            CardTouchPolicyFfi::On,
            String::from_utf8(ADMIN_PIN.to_vec()).unwrap(),
        ),
        Err(AddresseeError::RemoteKeyUnavailable)
    ));
    assert_read_only(&fixture.transport.commands());
}

struct Fixture {
    transport: Arc<ManagementTransport>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            transport: Arc::new(ManagementTransport::default()),
        }
    }

    fn session(&self, identity: CardIdentityFfi) -> OpenPgpCardManagementSession {
        OpenPgpCardManagementSession::connect(identity, self.transport.clone()).unwrap()
    }
}

#[derive(Default)]
struct ManagementTransport {
    state: Mutex<TransportState>,
}

struct TransportState {
    identity: CardIdentityFfi,
    user_pin: Vec<u8>,
    admin_pin: Vec<u8>,
    user_retries: u8,
    admin_retries: u8,
    touch_policies: [u8; 3],
    key_information: Option<Vec<u8>>,
    raw_kdf_available: bool,
    kdf_advertised: bool,
    kdf_failure: bool,
    admin_authorized: bool,
    commands: Vec<Vec<u8>>,
}

impl Default for TransportState {
    fn default() -> Self {
        Self {
            identity: IDENTITY,
            user_pin: USER_PIN.to_vec(),
            admin_pin: ADMIN_PIN.to_vec(),
            user_retries: 3,
            admin_retries: 3,
            touch_policies: [0; 3],
            key_information: Some(vec![0x01, 0x01, 0x02, 0x01, 0x03, 0x00]),
            raw_kdf_available: true,
            kdf_advertised: true,
            kdf_failure: false,
            admin_authorized: false,
            commands: Vec::new(),
        }
    }
}

impl ManagementTransport {
    fn commands(&self) -> Vec<Vec<u8>> {
        self.state.lock().unwrap().commands.clone()
    }

    fn clear_commands(&self) {
        self.state.lock().unwrap().commands.clear();
    }

    fn set_identity(&self, identity: CardIdentityFfi) {
        self.state.lock().unwrap().identity = identity;
    }

    fn set_retries(&self, user: u8, admin: u8) {
        let mut state = self.state.lock().unwrap();
        state.user_retries = user;
        state.admin_retries = admin;
    }

    fn set_raw_kdf_availability(&self, available: bool) {
        let mut state = self.state.lock().unwrap();
        state.raw_kdf_available = available;
        state.kdf_advertised = available;
    }

    fn set_key_information(&self, information: Option<Vec<u8>>) {
        self.state.lock().unwrap().key_information = information;
    }
}

impl CardTransport for ManagementTransport {
    fn capabilities(&self) -> CardTransportCapabilities {
        CardTransportCapabilities {
            supports_extended_length: false,
            supports_command_chaining: true,
            maximum_command_length: 261,
            maximum_command_data_length: 255,
            maximum_response_length: 65_538,
        }
    }

    fn transmit(
        &self,
        command: Vec<u8>,
        _response_buffer_size: u32,
    ) -> Result<Vec<u8>, CardTransportError> {
        let mut state = self.state.lock().unwrap();
        state.commands.push(command.clone());
        let state = &mut *state;
        if command.len() < 4 || !valid_short_apdu(&command) {
            return Err(CardTransportError::Failure);
        }
        match command[..4] {
            [0x00, 0xA4, 0x04, 0x00] if select_openpgp(&command) => {
                state.admin_authorized = false;
                Ok(success(&[]))
            }
            [0x00, 0xCA, 0x00, 0x6E] if command.len() == 5 => Ok(success(&state.ard())),
            [0x00, 0xCA, 0x00, 0xFA] if command.len() == 5 && state.kdf_advertised => {
                Ok(success(&algorithm_information()))
            }
            [0x00, 0xCA, 0x00, 0xF9] if command.len() == 5 => {
                if state.kdf_failure {
                    Err(CardTransportError::Failure)
                } else if state.raw_kdf_available {
                    Ok(success(&[0x81, 0x01, 0x00]))
                } else {
                    Ok(vec![0x6A, 0x88])
                }
            }
            [0x00, 0x20, 0x00, 0x83] => {
                if command.get(5..) == Some(state.admin_pin.as_slice()) {
                    state.admin_authorized = true;
                    Ok(success(&[]))
                } else {
                    Ok(wrong_pin(&mut state.admin_retries))
                }
            }
            [0x00, 0x24, 0x00, reference @ (0x81 | 0x83)] => {
                let (current, retries, replacement) = if reference == 0x81 {
                    (&mut state.user_pin, &mut state.user_retries, NEW_USER_PIN)
                } else {
                    (
                        &mut state.admin_pin,
                        &mut state.admin_retries,
                        NEW_ADMIN_PIN,
                    )
                };
                let expected = [current.as_slice(), replacement].concat();
                if command.get(5..) == Some(expected.as_slice()) {
                    *current = replacement.to_vec();
                    Ok(success(&[]))
                } else {
                    Ok(wrong_pin(retries))
                }
            }
            [0x00, 0xDA, 0x00, tag @ (0xD6..=0xD8)] if state.admin_authorized => {
                if command.len() != 7 || command[5] > 1 || command[6] != 0x20 {
                    return Ok(vec![0x6A, 0x80]);
                }
                state.touch_policies[usize::from(tag - 0xD6)] = command[5];
                Ok(success(&[]))
            }
            [0x00, 0xDA, _, _] => Ok(vec![0x69, 0x82]),
            _ => Err(CardTransportError::Failure),
        }
    }
}

impl TransportState {
    fn ard(&self) -> Vec<u8> {
        let mut aid = vec![0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
        aid.extend_from_slice(&self.identity.version.to_be_bytes());
        aid.extend_from_slice(&self.identity.manufacturer.to_be_bytes());
        aid.extend_from_slice(&self.identity.serial.to_be_bytes());
        aid.extend_from_slice(&[0x00, 0x00]);
        let capabilities = if self.kdf_advertised { 0x37 } else { 0x36 };
        let pw_status = [
            0x00,
            0x40,
            0x40,
            0x40,
            self.user_retries,
            0x00,
            self.admin_retries,
        ];
        let signing = [0x13].into_iter().chain(P256_OID).collect::<Vec<_>>();
        let decryption = [0x12].into_iter().chain(P256_OID).collect::<Vec<_>>();
        let mut fields = vec![
            tlv(&[0x4F], &aid),
            tlv(
                &[0x5F, 0x52],
                &[0x00, 0x73, 0x00, 0x00, 0x80, 0x05, 0x90, 0x00],
            ),
            tlv(&[0xC0], &[capabilities, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            tlv(&[0xC1], &signing),
            tlv(&[0xC2], &decryption),
            tlv(&[0xC3], &signing),
            tlv(&[0xC4], &pw_status),
            tlv(&[0xC5], &[[0x11; 20], [0x22; 20], [0x00; 20]].concat()),
            tlv(
                &[0xCD],
                &[0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x05, 0, 0, 0, 0],
            ),
            tlv(&[0xD6], &[self.touch_policies[0], 0x20]),
            tlv(&[0xD7], &[self.touch_policies[1], 0x20]),
            tlv(&[0xD8], &[self.touch_policies[2], 0x20]),
        ];
        if let Some(information) = &self.key_information {
            fields.push(tlv(&[0xDE], information));
        }
        tlv(&[0x6E], &fields.concat())
    }
}

fn algorithm_information() -> Vec<u8> {
    let signing = [0x13].into_iter().chain(P256_OID).collect::<Vec<_>>();
    let decryption = [0x12].into_iter().chain(P256_OID).collect::<Vec<_>>();
    [
        tlv(&[0xC1], &signing),
        tlv(&[0xC1], &[0x01, 0x08, 0x00, 0x00, 0x20, 0x00]),
        tlv(&[0xC2], &decryption),
        tlv(&[0xC3], &signing),
    ]
    .concat()
}

fn valid_short_apdu(command: &[u8]) -> bool {
    match command.len() {
        4 | 5 => true,
        6..=261 => {
            command[4] as usize == command.len() - 5 || command[4] as usize == command.len() - 6
        }
        _ => false,
    }
}

fn select_openpgp(command: &[u8]) -> bool {
    let aid = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
    command.len() == 11 && command[4] == 6 && command[5..] == aid
        || command.len() == 12 && command[4] == 6 && command[5..11] == aid && command[11] == 0
}

fn apdu(instruction: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut command = vec![0x00, instruction, p1, p2, data.len() as u8];
    command.extend_from_slice(data);
    command
}

fn commands_with_instruction(commands: &[Vec<u8>], instruction: u8) -> Vec<Vec<u8>> {
    commands
        .iter()
        .filter(|command| command.get(1) == Some(&instruction))
        .cloned()
        .collect()
}

fn assert_read_only(commands: &[Vec<u8>]) {
    assert!(
        commands
            .iter()
            .all(|command| matches!(command.get(1), Some(0xA4 | 0xCA | 0xC0))),
        "a read-only management operation sent a command outside SELECT/GET DATA/GET RESPONSE"
    );
}

fn assert_read_only_except_management_changes(commands: &[Vec<u8>]) {
    assert!(
        commands.iter().all(|command| matches!(
            command.get(1),
            Some(0xA4 | 0xCA | 0xC0 | 0x20 | 0x24 | 0xDA)
        )),
        "an unexpected private-key or configuration command was sent"
    );
}

fn wrong_pin(retries: &mut u8) -> Vec<u8> {
    if *retries == 0 {
        return vec![0x69, 0x83];
    }
    *retries -= 1;
    vec![0x63, 0xC0 | *retries]
}

fn success(data: &[u8]) -> Vec<u8> {
    [data, &[0x90, 0x00]].concat()
}

fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut encoded = tag.to_vec();
    match value.len() {
        0..=127 => encoded.push(value.len() as u8),
        128..=255 => encoded.extend_from_slice(&[0x81, value.len() as u8]),
        256..=65_535 => {
            encoded.push(0x82);
            encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        _ => panic!("test data object is too large"),
    }
    encoded.extend_from_slice(value);
    encoded
}
