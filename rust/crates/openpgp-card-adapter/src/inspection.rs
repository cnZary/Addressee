use std::fmt::Write as _;

use openpgp_card::ocard::{
    KeyType, OpenPGP,
    crypto::PublicKeyMaterial,
    data::{ApplicationIdentifier, KeyInformation, KeyStatus},
};
use thiserror::Error;

use crate::{
    CANOKEYS_MANUFACTURER, ExpectedSerial, IdentityError,
    pcsc::{PcscContext, PcscError, require_exact_reader},
};

const BASIC_SLOTS: [KeyType; 3] = [
    KeyType::Signing,
    KeyType::Decryption,
    KeyType::Authentication,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityRequirement {
    Discover,
    Serial(ExpectedSerial),
    AuthorizedCanokey(ExpectedSerial),
}

#[derive(Debug, Error)]
pub enum InspectionError {
    #[error("PC/SC error: {0}")]
    Pcsc(#[from] PcscError),

    #[error("identity verification failed: {0}")]
    Identity(#[from] IdentityError),

    #[error("OpenPGP read failed: {0}")]
    OpenPgp(#[from] openpgp_card::Error),

    #[error("the OpenPGP application identity changed during inspection")]
    IdentityChanged,
}

pub fn inspect_reader(
    reader: &str,
    requirement: IdentityRequirement,
) -> Result<String, InspectionError> {
    let mut context = PcscContext::establish()?;
    let readers = context.list_readers()?;
    require_exact_reader(&readers, reader)?;

    let card = context.connect(reader)?;
    let protocol = card.protocol()?;
    let backend: Box<dyn card_backend::CardBackend + Send + Sync> = Box::new(card);
    let mut openpgp = OpenPGP::new(backend)?;
    let mut transaction = openpgp.transaction()?;
    let _ = transaction.select()?;
    let aid = transaction.application_identifier()?;
    verify_identity(&aid, requirement)?;

    let ard = transaction.application_related_data()?;
    let refreshed_aid = ard.application_id()?;
    verify_identity(&refreshed_aid, requirement)?;
    if refreshed_aid != aid {
        return Err(InspectionError::IdentityChanged);
    }

    let mut output = String::new();
    writeln!(
        output,
        "Read-only inspection: no PINs, cardholder data, certificates, or state-changing commands."
    )
    .expect("String formatting is infallible");
    writeln!(output, "PC/SC readers:").expect("String formatting is infallible");
    if readers.is_empty() {
        writeln!(output, "  <none>").expect("String formatting is infallible");
    } else {
        for reader in &readers {
            writeln!(output, "  {reader}").expect("String formatting is infallible");
        }
    }
    writeln!(output, "Connected reader: {reader}").expect("String formatting is infallible");
    writeln!(output, "Active protocol: {protocol}").expect("String formatting is infallible");
    writeln!(
        output,
        "OpenPGP identity: manufacturer 0x{:04X}, serial {:08X}, version {}.{}",
        aid.manufacturer(),
        aid.serial(),
        aid.version() >> 8,
        aid.version() & 0xFF
    )
    .expect("String formatting is infallible");
    match requirement {
        IdentityRequirement::Discover => writeln!(
            output,
            "Identity policy: read-only discovery; no manufacturer or serial restriction."
        ),
        IdentityRequirement::Serial(_) => writeln!(
            output,
            "Identity policy: exact OpenPGP serial matched; no manufacturer restriction."
        ),
        IdentityRequirement::AuthorizedCanokey(_) => writeln!(
            output,
            "Identity policy: CanoKeys manufacturer and exact OpenPGP serial matched. USB evidence is still required for destructive authorization."
        ),
    }
    .expect("String formatting is infallible");

    let capabilities = ard.extended_capabilities()?;
    writeln!(output, "Capabilities:").expect("String formatting is infallible");
    writeln!(
        output,
        "  secure messaging: {}",
        capabilities.secure_messaging()
    )
    .expect("String formatting is infallible");
    writeln!(output, "  GET CHALLENGE: {}", capabilities.get_challenge())
        .expect("String formatting is infallible");
    writeln!(
        output,
        "  key import advertised: {}",
        capabilities.key_import()
    )
    .expect("String formatting is infallible");
    writeln!(
        output,
        "  algorithm attributes changeable: {}",
        capabilities.algo_attrs_changeable()
    )
    .expect("String formatting is infallible");
    writeln!(output, "  AES advertised: {}", capabilities.aes())
        .expect("String formatting is infallible");
    writeln!(output, "  KDF DO advertised: {}", capabilities.kdf_do())
        .expect("String formatting is infallible");
    writeln!(
        output,
        "  private-use DOs: {}",
        capabilities.private_use_dos()
    )
    .expect("String formatting is infallible");
    writeln!(
        output,
        "  PW status changeable: {}",
        capabilities.pw_status_change()
    )
    .expect("String formatting is infallible");
    if let Some(mse) = capabilities.mse_command_support() {
        writeln!(output, "  MSE for DEC/AUT: {mse}").expect("String formatting is infallible");
    }

    let historical = ard.historical_bytes()?;
    if let Some(card_capabilities) = historical.card_capabilities() {
        writeln!(
            output,
            "  command chaining: {}",
            card_capabilities.command_chaining()
        )
        .expect("String formatting is infallible");
        writeln!(
            output,
            "  extended Lc/Le: {}",
            card_capabilities.extended_lc_le()
        )
        .expect("String formatting is infallible");
        writeln!(
            output,
            "  extended length information: {}",
            card_capabilities.extended_length_information()
        )
        .expect("String formatting is infallible");
    }
    if let Some(lengths) = ard.extended_length_information()? {
        writeln!(
            output,
            "  maximum command bytes: {}",
            lengths.max_command_bytes()
        )
        .expect("String formatting is infallible");
        writeln!(
            output,
            "  maximum response bytes: {}",
            lengths.max_response_bytes()
        )
        .expect("String formatting is infallible");
    }

    let pw_status = ard.pw_status_bytes()?;
    writeln!(
        output,
        "Password status (no password values read or accepted):"
    )
    .expect("String formatting is infallible");
    writeln!(
        output,
        "  PW1: {} retries remaining, maximum length {}",
        pw_status.err_count_pw1(),
        pw_status.pw1_max_len()
    )
    .expect("String formatting is infallible");
    writeln!(
        output,
        "  resetting code: {} retries remaining, maximum length {}",
        pw_status.err_count_rc(),
        pw_status.rc_max_len()
    )
    .expect("String formatting is infallible");
    writeln!(
        output,
        "  PW3: {} retries remaining, maximum length {}",
        pw_status.err_count_pw3(),
        pw_status.pw3_max_len()
    )
    .expect("String formatting is infallible");
    writeln!(
        output,
        "  PW1 signing validity: {}",
        if pw_status.pw1_cds_valid_once() {
            "one signature"
        } else {
            "multiple signatures"
        }
    )
    .expect("String formatting is infallible");

    if capabilities.algo_attrs_changeable() {
        match transaction.algorithm_information() {
            Ok(Some(information)) => {
                writeln!(output, "Supported algorithm information:")
                    .expect("String formatting is infallible");
                for slot in BASIC_SLOTS {
                    for attributes in information.for_keytype(slot) {
                        writeln!(output, "  {}: {attributes:?}", slot_name(slot))
                            .expect("String formatting is infallible");
                    }
                }
            }
            Ok(None) => writeln!(output, "Supported algorithm information: not available")
                .expect("String formatting is infallible"),
            Err(error) => writeln!(
                output,
                "Supported algorithm information: read failed: {error}"
            )
            .expect("String formatting is infallible"),
        }
    } else {
        writeln!(
            output,
            "Supported algorithm information: not advertised; attributes are fixed"
        )
        .expect("String formatting is infallible");
    }

    let fingerprints = ard.fingerprints()?;
    let key_information = ard.key_information()?;
    for slot in BASIC_SLOTS {
        writeln!(output, "{} slot:", slot_name(slot)).expect("String formatting is infallible");
        writeln!(output, "  algorithm: {:?}", ard.algorithm_attributes(slot)?)
            .expect("String formatting is infallible");

        let status = key_information
            .as_ref()
            .and_then(|information| basic_key_status(information, slot));
        if let Some((reference, status)) = status {
            writeln!(output, "  key information: reference {reference}, {status}")
                .expect("String formatting is infallible");
        } else {
            writeln!(output, "  key information: not available")
                .expect("String formatting is infallible");
        }

        let fingerprint_present = match slot {
            KeyType::Signing => fingerprints.signature().is_some(),
            KeyType::Decryption => fingerprints.decryption().is_some(),
            KeyType::Authentication => fingerprints.authentication().is_some(),
            KeyType::Attestation => false,
        };
        writeln!(
            output,
            "  fingerprint: {}",
            if fingerprint_present {
                "present"
            } else {
                "absent"
            }
        )
        .expect("String formatting is infallible");

        let key_info_present = status
            .map(|(_, status)| status != KeyStatus::NotPresent)
            .unwrap_or(false);
        if fingerprint_present || key_info_present {
            match transaction.public_key(slot) {
                Ok(public_key) => write_public_key_status(&mut output, &public_key),
                Err(error) => writeln!(output, "  public key: read failed: {error}")
                    .expect("String formatting is infallible"),
            }
        } else {
            writeln!(output, "  public key: not requested; slot appears empty")
                .expect("String formatting is infallible");
        }
    }

    Ok(output)
}

fn verify_identity(
    aid: &ApplicationIdentifier,
    requirement: IdentityRequirement,
) -> Result<(), IdentityError> {
    let expected = match requirement {
        IdentityRequirement::Discover => return Ok(()),
        IdentityRequirement::Serial(expected) => expected,
        IdentityRequirement::AuthorizedCanokey(expected) => {
            if aid.manufacturer() != CANOKEYS_MANUFACTURER {
                return Err(IdentityError::UnexpectedManufacturer {
                    actual: aid.manufacturer(),
                });
            }
            expected
        }
    };
    if aid.serial() != expected.get() {
        return Err(IdentityError::SerialMismatch {
            expected: expected.get(),
            actual: aid.serial(),
        });
    }
    Ok(())
}

fn basic_key_status(information: &KeyInformation, slot: KeyType) -> Option<(u8, KeyStatus)> {
    match slot {
        KeyType::Signing => Some((information.sig_ref(), information.sig_status())),
        KeyType::Decryption => Some((information.dec_ref(), information.dec_status())),
        KeyType::Authentication => Some((information.aut_ref(), information.aut_status())),
        KeyType::Attestation => None,
    }
}

fn slot_name(slot: KeyType) -> &'static str {
    match slot {
        KeyType::Signing => "signing",
        KeyType::Decryption => "decryption",
        KeyType::Authentication => "authentication",
        KeyType::Attestation => "attestation",
    }
}

fn write_public_key_status(output: &mut String, public_key: &PublicKeyMaterial) {
    match public_key {
        PublicKeyMaterial::R(rsa) => writeln!(
            output,
            "  public key: readable (RSA modulus {} bytes, exponent {} bytes; material not printed)",
            rsa.n().len(),
            rsa.v().len()
        ),
        PublicKeyMaterial::E(ecc) => writeln!(
            output,
            "  public key: readable ({:?}, public point {} bytes; material not printed)",
            ecc.algo(),
            ecc.data().len()
        ),
    }
    .expect("String formatting is infallible");
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

    #[test]
    fn discovery_does_not_apply_a_vendor_filter() {
        for manufacturer in [0x0006, 0xF1D0, 0xFFFF] {
            let aid = synthetic_aid(manufacturer, 0x1234ABCD);
            verify_identity(&aid, IdentityRequirement::Discover)
                .expect("read-only discovery must accept any valid OpenPGP manufacturer");
        }
    }

    #[test]
    fn generic_serial_matching_does_not_restrict_manufacturer() {
        let expected: ExpectedSerial = "1234ABCD".parse().expect("synthetic serial must be valid");
        let aid = synthetic_aid(0x0006, expected.get());
        verify_identity(&aid, IdentityRequirement::Serial(expected))
            .expect("generic read-only matching must support non-CanoKey devices");
    }

    #[test]
    fn destructive_canokey_identity_still_rejects_other_manufacturers() {
        let expected: ExpectedSerial = "1234ABCD".parse().expect("synthetic serial must be valid");
        let aid = synthetic_aid(0x0006, expected.get());
        assert!(matches!(
            verify_identity(&aid, IdentityRequirement::AuthorizedCanokey(expected)),
            Err(IdentityError::UnexpectedManufacturer { actual: 0x0006 })
        ));
    }

    #[test]
    fn all_identity_policies_except_discovery_require_the_full_serial() {
        let expected: ExpectedSerial = "1234ABCD".parse().expect("synthetic serial must be valid");
        let aid = synthetic_aid(CANOKEYS_MANUFACTURER, 0x0000ABCD);
        for requirement in [
            IdentityRequirement::Serial(expected),
            IdentityRequirement::AuthorizedCanokey(expected),
        ] {
            assert!(matches!(
                verify_identity(&aid, requirement),
                Err(IdentityError::SerialMismatch { .. })
            ));
        }
    }
}
