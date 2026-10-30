use std::sync::{Arc, Mutex};

use openpgp_core::{ExportFormat, FullFingerprint, PrivateExportPolicy, SoftwareKeyStore};
use openpgp_policy::GenerationProfile;
use pgp::{
    composed::{Deserializable as _, SignedSecretKey},
    crypto::hash::HashAlgorithm,
    packet::SecretSubkey,
    types::{
        EcdhPublicParams, EcdsaPublicParams, KeyDetails as _, Password, PublicParams,
        SignatureBytes, SigningKey,
    },
};

use crate::{
    AddresseeError, CardComponentBindingFfi, CardIdentityFfi, CardInteractionErrorFfi,
    CardPinProvider, CardPinPurpose, CardRegistrationFfi, CardSlot, CardTouchPrompt, CardTransport,
    CardTransportCapabilities, CardTransportError, EncryptionConfigFfi, MessageCipherFfi,
    MessageFormatFfi, OpenPgpCardSession, OpenPgpEngine, VerificationStatusFfi,
};

const IDENTITY: CardIdentityFfi = CardIdentityFfi {
    manufacturer: 0xFFFF,
    serial: 0x0102_0304,
    version: 0x0304,
};
const SOFTWARE_PASSWORD: &str = "synthetic-card-transport-software-password";
const SYNTHETIC_PIN: &str = "synthetic-pin";
const P256_OID: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

#[test]
fn real_binding_and_scripted_p256_signature_verify_through_the_ffi() {
    let fixture = Fixture::new();
    let engine = OpenPgpEngine::new();
    let session = Arc::new(fixture.connect(IDENTITY).unwrap());
    assert_eq!(session.identity(), IDENTITY);
    assert_eq!(fixture.pins.requests().len(), 0);
    assert!(fixture.touches.requests().is_empty());
    assert_no_private_operations(&fixture.transport.commands());

    let registration = engine.attach_card_session(session).unwrap();
    assert_eq!(registration.certificate_fingerprint, fixture.fingerprint);
    assert_eq!(registration.identity, IDENTITY);
    assert_eq!(
        registration.components,
        vec![
            CardComponentBindingFfi {
                slot: CardSlot::Signing,
                component_fingerprint: fixture.signing_fingerprint.clone(),
            },
            CardComponentBindingFfi {
                slot: CardSlot::Decryption,
                component_fingerprint: fixture.decryption_fingerprint.clone(),
            },
        ]
    );

    let payload = b"scripted transport with a real P-256 test signature\0\r\n";
    let signature = engine
        .sign_detached(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            payload.to_vec(),
            MessageFormatFfi::Binary,
        )
        .unwrap_or_else(|error| {
            panic!(
                "signing failed: {error:?}; APDUs={:?}; PINs={:?}",
                fixture.transport.commands(),
                fixture.pins.requests()
            )
        });
    assert_eq!(
        signature.metadata.certificate_fingerprint,
        fixture.fingerprint
    );
    assert_eq!(
        engine
            .verify_detached(payload.to_vec(), signature.artifact, fixture.at)
            .unwrap()
            .status,
        VerificationStatusFfi::Valid
    );

    assert_eq!(
        fixture.pins.requests(),
        vec![(CardPinPurpose::Signing, IDENTITY)]
    );
    assert_eq!(fixture.touches.requests(), vec![CardSlot::Signing]);
    let commands = fixture.transport.commands();
    assert_eq!(command_count(&commands, ApduOperation::Sign), 1);
    assert_eq!(
        command_count(&commands, ApduOperation::Verify(CardPinPurpose::Signing)),
        1
    );
    assert_eq!(command_count(&commands, ApduOperation::PublicSigning), 2);
    assert_eq!(command_count(&commands, ApduOperation::PublicDecryption), 1);
    assert_eq!(fixture.transport.completed_signatures(), 1);
}

#[test]
fn authorization_requirements_are_operation_specific_and_read_only() {
    let fixture = Fixture::new();
    let session = fixture.connect(IDENTITY).unwrap();

    let signing = session
        .authorization_requirements(CardSlot::Signing)
        .unwrap();
    assert_eq!(signing.slot, CardSlot::Signing);
    assert_eq!(signing.pin_purpose, CardPinPurpose::Signing);
    assert_eq!(signing.minimum_pin_length, 6);
    assert_eq!(signing.maximum_pin_length, 64);
    assert_eq!(signing.remaining_pin_retries, 3);
    assert_eq!(
        signing.touch_requirement,
        crate::CardTouchRequirementFfi::Required
    );
    let decryption = session
        .authorization_requirements(CardSlot::Decryption)
        .unwrap();
    assert_eq!(decryption.slot, CardSlot::Decryption);
    assert_eq!(decryption.pin_purpose, CardPinPurpose::User);

    assert!(fixture.pins.requests().is_empty());
    assert!(fixture.touches.requests().is_empty());
    let commands = fixture.transport.commands();
    assert_eq!(command_count(&commands, ApduOperation::PublicSigning), 2);
    assert_eq!(command_count(&commands, ApduOperation::PublicDecryption), 2);
    assert_no_private_operations(&commands);
}

#[test]
fn identity_discovery_is_read_only_and_does_not_bind_or_request_pin() {
    let fixture = Fixture::new();

    assert_eq!(
        crate::read_card_identity(fixture.transport.clone()).unwrap(),
        IDENTITY
    );
    assert!(fixture.pins.requests().is_empty());
    assert!(fixture.touches.requests().is_empty());
    let commands = fixture.transport.commands();
    assert_eq!(command_count(&commands, ApduOperation::PublicSigning), 0);
    assert_eq!(command_count(&commands, ApduOperation::PublicDecryption), 0);
    assert_no_private_operations(&commands);
}

#[test]
fn initial_identity_mismatch_is_typed_and_never_requests_pin() {
    let fixture = Fixture::new();
    let expected = CardIdentityFfi {
        serial: IDENTITY.serial + 1,
        ..IDENTITY
    };

    assert!(matches!(
        fixture.connect(expected),
        Err(AddresseeError::CardRegistrationConflict)
    ));
    assert!(fixture.pins.requests().is_empty());
    assert!(fixture.touches.requests().is_empty());
    let commands = fixture.transport.commands();
    assert!(!commands.is_empty());
    assert_eq!(command_count(&commands, ApduOperation::PublicSigning), 0);
    assert_no_private_operations(&commands);
}

#[test]
fn wrong_public_material_rejects_registration_before_pin_or_private_operation() {
    let fixture = Fixture::new();
    fixture.transport.substitute_signing_public_key();

    assert!(matches!(
        fixture.connect(IDENTITY),
        Err(AddresseeError::CardRegistrationConflict)
    ));
    assert!(fixture.pins.requests().is_empty());
    assert!(fixture.touches.requests().is_empty());
    let commands = fixture.transport.commands();
    assert_eq!(command_count(&commands, ApduOperation::PublicSigning), 1);
    assert_eq!(command_count(&commands, ApduOperation::PublicDecryption), 0);
    assert_no_private_operations(&commands);
}

#[test]
fn scripted_p256_decryption_and_combined_verification_use_real_message_processing() {
    let fixture = Fixture::new();
    let (engine, _) = fixture.connected();
    let payload = b"scripted P-256 decryption with real OpenPGP message processing\0\r\n";
    let encrypted = engine
        .encrypt(
            vec![fixture.fingerprint.clone()],
            fixture.at,
            v4_config(),
            payload.to_vec(),
            MessageFormatFfi::Binary,
        )
        .unwrap();
    fixture.transport.prepare_decryption(&encrypted);
    let decrypted = engine
        .decrypt(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            encrypted,
        )
        .unwrap_or_else(|error| {
            panic!(
                "decryption failed: {error:?}; APDUs={:?}; PINs={:?}",
                fixture.transport.commands(),
                fixture.pins.requests()
            )
        });
    assert_eq!(
        decrypted.report.status,
        crate::DecryptionStatusFfi::Unsigned
    );
    assert_eq!(decrypted.plaintext.as_deref(), Some(payload.as_slice()));

    let text = "scripted card-backed sign-then-encrypt and decrypt-then-verify";
    let combined = engine
        .sign_and_encrypt_text(crate::SignEncryptTextRequestFfi {
            signing_key: fixture.fingerprint.clone(),
            password: String::new(),
            recipients: vec![fixture.fingerprint.clone()],
            at_unix_seconds: fixture.at,
            config: v4_config(),
            text: text.to_owned(),
            format: MessageFormatFfi::Binary,
        })
        .unwrap();
    fixture.transport.prepare_decryption(&combined.artifact);
    let verified = engine
        .decrypt_text(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            combined.artifact,
        )
        .unwrap();
    assert_eq!(verified.report.status, crate::DecryptionStatusFfi::Valid);
    assert_eq!(verified.text.as_deref(), Some(text));
    assert_eq!(verified.report.signatures.len(), 1);
    assert_eq!(
        verified.report.signatures[0].signer_fingerprint.as_deref(),
        Some(fixture.signing_fingerprint.as_str())
    );
    assert_eq!(
        command_count(&fixture.transport.commands(), ApduOperation::Sign),
        1
    );
    assert_eq!(
        command_count(&fixture.transport.commands(), ApduOperation::Decrypt),
        2
    );
    assert_eq!(
        fixture.pins.requests(),
        vec![
            (CardPinPurpose::User, IDENTITY),
            (CardPinPurpose::Signing, IDENTITY),
            (CardPinPurpose::User, IDENTITY),
        ]
    );
    assert_eq!(fixture.touches.requests(), vec![CardSlot::Signing]);
}

#[test]
fn signing_and_decryption_transport_cancellation_use_real_resolver_without_retries() {
    let fixture = Fixture::new();
    let (engine, _) = fixture.connected();
    fixture.transport.cancel_on(ApduOperation::Sign);

    assert!(matches!(
        engine.sign_detached(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            b"cancel scripted signing".to_vec(),
            MessageFormatFfi::Binary,
        ),
        Err(AddresseeError::OperationCancelled)
    ));
    assert_eq!(fixture.transport.completed_signatures(), 0);
    assert_eq!(
        command_count(&fixture.transport.commands(), ApduOperation::Sign),
        1
    );

    let encrypted = engine
        .encrypt(
            vec![fixture.fingerprint.clone()],
            fixture.at,
            v4_config(),
            b"cancel scripted decryption".to_vec(),
            MessageFormatFfi::Binary,
        )
        .unwrap();
    fixture.transport.cancel_on(ApduOperation::Decrypt);
    assert!(matches!(
        engine.decrypt(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            encrypted,
        ),
        Err(AddresseeError::OperationCancelled)
    ));

    assert_eq!(
        fixture.pins.requests(),
        vec![
            (CardPinPurpose::Signing, IDENTITY),
            (CardPinPurpose::User, IDENTITY),
        ]
    );
    assert_eq!(fixture.touches.requests(), vec![CardSlot::Signing]);
    let commands = fixture.transport.commands();
    assert_eq!(command_count(&commands, ApduOperation::Sign), 1);
    assert_eq!(command_count(&commands, ApduOperation::Decrypt), 1);
    assert_eq!(
        command_count(&commands, ApduOperation::Verify(CardPinPurpose::Signing)),
        1
    );
    assert_eq!(
        command_count(&commands, ApduOperation::Verify(CardPinPurpose::User)),
        1
    );
}

#[test]
fn pin_provider_cancellation_stops_before_verify_touch_or_pso() {
    let fixture = Fixture::new();
    let (engine, _) = fixture.connected();
    fixture.pins.cancel_requests();

    assert!(matches!(
        engine.sign_detached(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            b"cancel PIN interaction".to_vec(),
            MessageFormatFfi::Binary,
        ),
        Err(AddresseeError::OperationCancelled)
    ));
    assert_eq!(
        fixture.pins.requests(),
        vec![(CardPinPurpose::Signing, IDENTITY)]
    );
    assert!(fixture.touches.requests().is_empty());
    let commands = fixture.transport.commands();
    assert_eq!(command_count(&commands, ApduOperation::Kdf), 1);
    assert_no_private_operations(&commands);
}

#[test]
fn low_pin_retries_stop_before_pin_request_or_verify() {
    let fixture = Fixture::new();
    fixture.transport.set_pin_retries(1);
    let (engine, _) = fixture.connected();

    assert!(matches!(
        engine.sign_detached(
            fixture.fingerprint.clone(),
            String::new(),
            fixture.at,
            b"do not request a PIN".to_vec(),
            MessageFormatFfi::Binary,
        ),
        Err(AddresseeError::RemoteKeyUnavailable)
    ));
    assert!(fixture.pins.requests().is_empty());
    assert!(fixture.touches.requests().is_empty());
    let commands = fixture.transport.commands();
    assert_eq!(command_count(&commands, ApduOperation::Kdf), 1);
    assert_no_private_operations(&commands);
}

struct Fixture {
    fingerprint: String,
    signing_fingerprint: String,
    decryption_fingerprint: String,
    public_certificate: Vec<u8>,
    at: u64,
    transport: Arc<ScriptedTransport>,
    pins: Arc<RecordingPinProvider>,
    touches: Arc<RecordingTouchPrompt>,
}

impl Fixture {
    fn new() -> Self {
        let mut store = SoftwareKeyStore::new();
        let generated = store
            .generate(
                &GenerationProfile::nist_p256_v4(),
                "Synthetic Card Transport <card-transport@example.invalid>",
                SOFTWARE_PASSWORD,
                PrivateExportPolicy::Allowed,
            )
            .unwrap();
        let private = store
            .export_private(&generated.metadata.fingerprint, ExportFormat::Armored)
            .unwrap();
        let (mut secret, _) = SignedSecretKey::from_string(
            std::str::from_utf8(&private).expect("armored synthetic test key"),
        )
        .expect("parse synthetic test key");
        for subkey in &mut secret.secret_subkeys {
            subkey
                .key
                .remove_password(&Password::from(SOFTWARE_PASSWORD))
                .unwrap();
        }
        let signing = component(&secret, &generated.metadata.subkeys[0].fingerprint);
        let decryption = component(&secret, &generated.metadata.subkeys[1].fingerprint);
        let at = u64::from(secret.primary_key.created_at().as_secs()) + 60;
        Self {
            fingerprint: generated.metadata.fingerprint.to_string(),
            signing_fingerprint: generated.metadata.subkeys[0].fingerprint.to_string(),
            decryption_fingerprint: generated.metadata.subkeys[1].fingerprint.to_string(),
            public_certificate: generated.public_certificate,
            at,
            transport: Arc::new(ScriptedTransport::new(signing, decryption)),
            pins: Arc::new(RecordingPinProvider::default()),
            touches: Arc::new(RecordingTouchPrompt::default()),
        }
    }

    fn connect(&self, identity: CardIdentityFfi) -> Result<OpenPgpCardSession, AddresseeError> {
        OpenPgpCardSession::connect(
            identity,
            self.public_certificate.clone(),
            Some(self.signing_fingerprint.clone()),
            Some(self.decryption_fingerprint.clone()),
            self.transport.clone(),
            self.pins.clone(),
            self.touches.clone(),
        )
    }

    fn connected(&self) -> (OpenPgpEngine, CardRegistrationFfi) {
        let engine = OpenPgpEngine::new();
        let registration = engine
            .attach_card_session(Arc::new(self.connect(IDENTITY).unwrap()))
            .unwrap();
        (engine, registration)
    }
}

fn component(secret: &SignedSecretKey, fingerprint: &FullFingerprint) -> SecretSubkey {
    secret
        .secret_subkeys
        .iter()
        .find(|subkey| {
            FullFingerprint::from_hex(&format!("{:X}", subkey.key.fingerprint())).unwrap()
                == *fingerprint
        })
        .expect("generated component")
        .key
        .clone()
}

fn v4_config() -> EncryptionConfigFfi {
    EncryptionConfigFfi::SeipdV1 {
        cipher: MessageCipherFfi::Aes256,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApduOperation {
    Select,
    Ard,
    PublicSigning,
    PublicDecryption,
    Kdf,
    Verify(CardPinPurpose),
    Sign,
    Decrypt,
}

struct ScriptedTransport {
    state: Mutex<TransportState>,
}

struct TransportState {
    identity: CardIdentityFfi,
    signing_key: SecretSubkey,
    decryption_key: SecretSubkey,
    signing_fingerprint: [u8; 20],
    decryption_fingerprint: [u8; 20],
    signing_created: u32,
    decryption_created: u32,
    signing_point: Vec<u8>,
    decryption_point: Vec<u8>,
    decryption_ephemeral: Vec<u8>,
    substitute_signing_point: bool,
    pin_retries: u8,
    cancel_on: Option<ApduOperation>,
    commands: Vec<Vec<u8>>,
    completed_signatures: usize,
}

impl ScriptedTransport {
    fn new(signing_key: SecretSubkey, decryption_key: SecretSubkey) -> Self {
        let state = TransportState {
            identity: IDENTITY,
            signing_fingerprint: fingerprint_bytes(&signing_key),
            decryption_fingerprint: fingerprint_bytes(&decryption_key),
            signing_created: signing_key.created_at().as_secs(),
            decryption_created: decryption_key.created_at().as_secs(),
            signing_point: p256_point(&signing_key),
            decryption_point: p256_point(&decryption_key),
            decryption_ephemeral: Vec::new(),
            signing_key,
            decryption_key,
            substitute_signing_point: false,
            pin_retries: 3,
            cancel_on: None,
            commands: Vec::new(),
            completed_signatures: 0,
        };
        Self {
            state: Mutex::new(state),
        }
    }

    fn commands(&self) -> Vec<Vec<u8>> {
        self.state.lock().unwrap().commands.clone()
    }

    fn prepare_decryption(&self, input: &[u8]) {
        let message = pgp::composed::Message::from_bytes(input)
            .expect("parse the real encrypted test message");
        let pgp::composed::Message::Encrypted { esk, .. } = message else {
            panic!("encrypted test message required")
        };
        let [pgp::composed::Esk::PublicKeyEncryptedSessionKey(packet)] = esk.as_slice() else {
            panic!("one public-key encrypted session key required")
        };
        let pgp::types::PkeskBytes::Ecdh {
            public_point,
            encrypted_session_key,
        } = packet.values().expect("ECDH test parameters")
        else {
            panic!("P-256 ECDH test parameters required")
        };
        assert_eq!(encrypted_session_key.len(), 48);
        self.state.lock().unwrap().decryption_ephemeral = public_point.as_ref().to_vec();
    }

    fn completed_signatures(&self) -> usize {
        self.state.lock().unwrap().completed_signatures
    }

    fn substitute_signing_public_key(&self) {
        self.state.lock().unwrap().substitute_signing_point = true;
    }

    fn cancel_on(&self, operation: ApduOperation) {
        self.state.lock().unwrap().cancel_on = Some(operation);
    }

    fn set_pin_retries(&self, retries: u8) {
        self.state.lock().unwrap().pin_retries = retries;
    }
}

impl CardTransport for ScriptedTransport {
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
        let operation = classify(&command);
        let mut state = self.state.lock().unwrap();
        state.commands.push(command.clone());
        if state.cancel_on == Some(operation) {
            return Err(CardTransportError::Cancelled);
        }
        match operation {
            ApduOperation::Select => Ok(success([])),
            ApduOperation::Ard => Ok(success(state.ard())),
            ApduOperation::PublicSigning => {
                let point = if state.substitute_signing_point {
                    &state.decryption_point
                } else {
                    &state.signing_point
                };
                Ok(success(public_key_response(point)))
            }
            ApduOperation::PublicDecryption => {
                Ok(success(public_key_response(&state.decryption_point)))
            }
            ApduOperation::Kdf => Ok(success([0x81, 0x01, 0x00])),
            ApduOperation::Verify(_) => Ok(success([])),
            ApduOperation::Sign => {
                let signature = SigningKey::sign(
                    &state.signing_key,
                    &Password::empty(),
                    HashAlgorithm::Sha256,
                    &command[5..37],
                )
                .expect("sign the exact scripted digest with the synthetic test key");
                state.completed_signatures += 1;
                Ok(success(raw_p256_signature(signature)))
            }
            ApduOperation::Decrypt => Ok(success(state.decryption_response())),
        }
    }
}

impl TransportState {
    fn decryption_response(&self) -> Vec<u8> {
        let command = self.commands.last().expect("recorded decryption APDU");
        assert_eq!(classify(command), ApduOperation::Decrypt);
        assert_eq!(
            &command[12..77],
            self.decryption_ephemeral.as_slice(),
            "the card must receive the actual ephemeral point"
        );
        let ephemeral = p256::PublicKey::from_sec1_bytes(&self.decryption_ephemeral)
            .expect("the real message must contain a valid P-256 ephemeral point");
        let pgp::types::SecretParams::Plain(pgp::types::PlainSecretParams::ECDH(
            pgp::crypto::ecdh::SecretKey::P256 { secret },
        )) = self.decryption_key.secret_params()
        else {
            panic!("an unlocked P-256 test key is required")
        };
        p256::ecdh::diffie_hellman(&secret.to_nonzero_scalar(), ephemeral.as_affine())
            .raw_secret_bytes()
            .to_vec()
    }

    fn ard(&self) -> Vec<u8> {
        let mut aid = vec![0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
        aid.extend_from_slice(&self.identity.version.to_be_bytes());
        aid.extend_from_slice(&self.identity.manufacturer.to_be_bytes());
        aid.extend_from_slice(&self.identity.serial.to_be_bytes());
        aid.extend_from_slice(&[0x00, 0x00]);

        let mut fingerprints = Vec::new();
        fingerprints.extend_from_slice(&self.signing_fingerprint);
        fingerprints.extend_from_slice(&self.decryption_fingerprint);
        fingerprints.extend_from_slice(&[0x00; 20]);

        let mut times = Vec::new();
        times.extend_from_slice(&self.signing_created.to_be_bytes());
        times.extend_from_slice(&self.decryption_created.to_be_bytes());
        times.extend_from_slice(&[0x00; 4]);

        let signing_attributes = algorithm_attributes(0x13);
        let decryption_attributes = algorithm_attributes(0x12);
        let authentication_attributes = algorithm_attributes(0x13);
        let pw_status = [0x00, 0x40, 0x40, 0x40, self.pin_retries, 0x00, 0x03];
        let extended_capabilities = [0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let historical = [0x00, 0x73, 0x00, 0x00, 0x80, 0x05, 0x90, 0x00];

        let mut ard = Vec::new();
        for (tag, value) in [
            (&[0x4F][..], aid),
            (&[0x5F, 0x52][..], historical.to_vec()),
            (&[0xC0][..], extended_capabilities.to_vec()),
            (&[0xC1][..], signing_attributes),
            (&[0xC2][..], decryption_attributes),
            (&[0xC3][..], authentication_attributes),
            (&[0xC4][..], pw_status.to_vec()),
            (&[0xC5][..], fingerprints),
            (&[0xCD][..], times),
            (&[0xD6][..], vec![0x01, 0x20]),
            (&[0xD7][..], vec![0x00, 0x20]),
        ] {
            ard.extend_from_slice(&tlv(tag, &value));
        }
        tlv(&[0x6E], &ard)
    }
}

fn algorithm_attributes(algorithm: u8) -> Vec<u8> {
    let mut attributes = vec![algorithm];
    attributes.extend_from_slice(&P256_OID);
    attributes
}

fn fingerprint_bytes(key: &SecretSubkey) -> [u8; 20] {
    key.fingerprint()
        .as_bytes()
        .try_into()
        .expect("v4 component fingerprint")
}

fn p256_point(key: &SecretSubkey) -> Vec<u8> {
    match key.public_params() {
        PublicParams::ECDSA(EcdsaPublicParams::P256 { key }) => key.to_sec1_bytes().to_vec(),
        PublicParams::ECDH(EcdhPublicParams::P256 { p, .. }) => p.to_sec1_bytes().to_vec(),
        _ => panic!("the generated test components must use P-256"),
    }
}

fn raw_p256_signature(signature: SignatureBytes) -> Vec<u8> {
    let SignatureBytes::Mpis(mpis) = signature else {
        panic!("legacy P-256 ECDSA must produce two MPIs")
    };
    assert_eq!(mpis.len(), 2);
    let mut raw = Vec::with_capacity(64);
    for mpi in mpis {
        let bytes = mpi.as_ref();
        assert!(bytes.len() <= 32);
        raw.resize(raw.len() + 32 - bytes.len(), 0);
        raw.extend_from_slice(bytes);
    }
    assert_eq!(raw.len(), 64);
    raw
}

fn public_key_response(point: &[u8]) -> Vec<u8> {
    assert_eq!(point.len(), 65);
    assert_eq!(point[0], 0x04);
    tlv(&[0x7F, 0x49], &tlv(&[0x86], point))
}

fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(tag);
    match value.len() {
        0..=127 => encoded.push(value.len() as u8),
        128..=255 => {
            encoded.push(0x81);
            encoded.push(value.len() as u8);
        }
        256..=65_535 => {
            encoded.push(0x82);
            encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        _ => panic!("test TLV is too large"),
    }
    encoded.extend_from_slice(value);
    encoded
}

fn success(data: impl AsRef<[u8]>) -> Vec<u8> {
    let mut response = data.as_ref().to_vec();
    response.extend_from_slice(&[0x90, 0x00]);
    response
}

fn classify(command: &[u8]) -> ApduOperation {
    const SELECT_WITHOUT_LE: [u8; 11] = [
        0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
    ];
    const SELECT_WITH_LE: [u8; 12] = [
        0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00,
    ];
    const DECRYPTION_PREFIX: [u8; 12] = [
        0x00, 0x2A, 0x80, 0x86, 0x48, 0xA6, 0x46, 0x7F, 0x49, 0x43, 0x86, 0x41,
    ];

    if command == SELECT_WITHOUT_LE || command == SELECT_WITH_LE {
        ApduOperation::Select
    } else if command == [0x00, 0xCA, 0x00, 0x6E, 0x00] {
        ApduOperation::Ard
    } else if command == [0x00, 0x47, 0x81, 0x00, 0x02, 0xB6, 0x00, 0x00] {
        ApduOperation::PublicSigning
    } else if command == [0x00, 0x47, 0x81, 0x00, 0x02, 0xB8, 0x00, 0x00] {
        ApduOperation::PublicDecryption
    } else if command == [0x00, 0xCA, 0x00, 0xF9, 0x00] {
        ApduOperation::Kdf
    } else if command.len() == 5 + SYNTHETIC_PIN.len()
        && command[..4] == [0x00, 0x20, 0x00, 0x81]
        && command[4] as usize == SYNTHETIC_PIN.len()
        && &command[5..] == SYNTHETIC_PIN.as_bytes()
    {
        ApduOperation::Verify(CardPinPurpose::Signing)
    } else if command.len() == 5 + SYNTHETIC_PIN.len()
        && command[..4] == [0x00, 0x20, 0x00, 0x82]
        && command[4] as usize == SYNTHETIC_PIN.len()
        && &command[5..] == SYNTHETIC_PIN.as_bytes()
    {
        ApduOperation::Verify(CardPinPurpose::User)
    } else if command.len() == 38
        && command[..5] == [0x00, 0x2A, 0x9E, 0x9A, 0x20]
        && command[37] == 0x00
    {
        ApduOperation::Sign
    } else if command.len() == 78
        && command[..12] == DECRYPTION_PREFIX
        && command[12] == 0x04
        && command[77] == 0x00
    {
        ApduOperation::Decrypt
    } else {
        panic!("unexpected scripted APDU: {command:?}")
    }
}

fn command_count(commands: &[Vec<u8>], operation: ApduOperation) -> usize {
    commands
        .iter()
        .filter(|command| classify(command) == operation)
        .count()
}

fn assert_no_private_operations(commands: &[Vec<u8>]) {
    assert!(
        commands.iter().all(|command| {
            !matches!(
                classify(command),
                ApduOperation::Verify(_) | ApduOperation::Sign | ApduOperation::Decrypt
            )
        }),
        "unexpected private-key APDU in {commands:?}"
    );
}

#[derive(Default)]
struct RecordingPinProvider {
    state: Mutex<PinState>,
}

#[derive(Default)]
struct PinState {
    requests: Vec<(CardPinPurpose, CardIdentityFfi)>,
    cancelled: bool,
}

impl RecordingPinProvider {
    fn requests(&self) -> Vec<(CardPinPurpose, CardIdentityFfi)> {
        self.state.lock().unwrap().requests.clone()
    }

    fn cancel_requests(&self) {
        self.state.lock().unwrap().cancelled = true;
    }
}

impl CardPinProvider for RecordingPinProvider {
    fn request_pin(
        &self,
        purpose: CardPinPurpose,
        identity: CardIdentityFfi,
    ) -> Result<String, CardInteractionErrorFfi> {
        let mut state = self.state.lock().unwrap();
        state.requests.push((purpose, identity));
        if state.cancelled {
            Err(CardInteractionErrorFfi::Cancelled)
        } else {
            Ok(SYNTHETIC_PIN.to_owned())
        }
    }
}

#[derive(Default)]
struct RecordingTouchPrompt {
    requests: Mutex<Vec<CardSlot>>,
}

impl RecordingTouchPrompt {
    fn requests(&self) -> Vec<CardSlot> {
        self.requests.lock().unwrap().clone()
    }
}

impl CardTouchPrompt for RecordingTouchPrompt {
    fn request_touch(&self, slot: CardSlot) -> Result<(), CardInteractionErrorFfi> {
        self.requests.lock().unwrap().push(slot);
        Ok(())
    }
}
