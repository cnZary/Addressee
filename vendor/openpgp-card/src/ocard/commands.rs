// SPDX-FileCopyrightText: 2021-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pre-defined `Command` values for the OpenPGP card application

use secrecy::{ExposeSecret, SecretBox};

use crate::{
    ocard::{
        apdu::command::{Command, Data},
        tags::{ShortTag, Tags},
        KeyType, OPENPGP_APPLICATION,
    },
    Error,
};

/// 7.2.1 SELECT
/// (select the OpenPGP application on the card)
pub(crate) fn select_openpgp() -> Result<Command, Error> {
    Command::new(0x00, 0xA4, 0x04, 0x00, OPENPGP_APPLICATION.to_vec())
}

/// 7.2.6 GET DATA
pub(crate) fn get_data<T: Into<ShortTag>>(tag: T) -> Result<Command, Error> {
    match tag.into() {
        ShortTag::One(tag0) => Command::new(0x00, 0xCA, 0, tag0, vec![]),
        ShortTag::Two(tag0, tag1) => Command::new(0x00, 0xCA, tag0, tag1, vec![]),
    }
}

/// GET DO "Application related data"
pub(crate) fn application_related_data() -> Result<Command, Error> {
    get_data(Tags::ApplicationRelatedData)
}

/// GET DO "Uniform resource locator"
pub(crate) fn url() -> Result<Command, Error> {
    get_data(Tags::Url)
}

/// GET DO "Login Data"
pub(crate) fn login_data() -> Result<Command, Error> {
    get_data(Tags::LoginData)
}

/// GET DO "Cardholder related data"
pub(crate) fn cardholder_related_data() -> Result<Command, Error> {
    get_data(Tags::CardholderRelatedData)
}

/// GET DO "Security support template"
pub(crate) fn security_support_template() -> Result<Command, Error> {
    get_data(Tags::SecuritySupportTemplate)
}

/// GET DO "Cardholder certificate"
pub(crate) fn cardholder_certificate() -> Result<Command, Error> {
    get_data(Tags::CardholderCertificate)
}

/// GET NEXT DATA for DO "Cardholder certificate"
pub(crate) fn get_next_cardholder_certificate() -> Result<Command, Error> {
    Command::new(0x00, 0xCC, 0x7f, 0x21, vec![])
}

/// GET DO "Algorithm Information"
pub(crate) fn algo_info() -> Result<Command, Error> {
    get_data(Tags::AlgorithmInformation)
}

/// GET DO "KDF DO"
pub(crate) fn kdf_do() -> Result<Command, Error> {
    get_data(Tags::KdfDo)
}

/// GET DO "Attestation Certificate (Yubico)"
pub(crate) fn attestation_certificate() -> Result<Command, Error> {
    get_data(Tags::AttestationCertificate)
}

/// GET Firmware Version (yubikey specific?)
pub(crate) fn firmware_version() -> Result<Command, Error> {
    Command::new(0x00, 0xF1, 0x00, 0x00, vec![])
}

/// Set identity [0-2] (NitroKey Start specific(?))
pub(crate) fn set_identity(id: u8) -> Result<Command, Error> {
    Command::new(0x00, 0x85, 0x00, id, vec![])
}

/// GET RESPONSE
pub(crate) fn get_response() -> Result<Command, Error> {
    Command::new(0x00, 0xC0, 0x00, 0x00, vec![])
}

/// SELECT DATA
pub(crate) fn select_data(num: u8, data: Vec<u8>) -> Result<Command, Error> {
    Command::new(0x00, 0xA5, num, 0x04, data)
}

/// VERIFY pin for PW1 (81)
pub(crate) fn verify_pw1_81(pin: SecretBox<[u8]>) -> Result<Command, Error> {
    Command::new(0x00, 0x20, 0x00, 0x81, pin)
}

/// VERIFY pin for PW1 (82)
pub(crate) fn verify_pw1_82(pin: SecretBox<[u8]>) -> Result<Command, Error> {
    Command::new(0x00, 0x20, 0x00, 0x82, pin)
}

/// VERIFY pin for PW3 (83)
pub(crate) fn verify_pw3(pin: SecretBox<[u8]>) -> Result<Command, Error> {
    Command::new(0x00, 0x20, 0x00, 0x83, pin)
}

/// 7.2.8 PUT DATA,
pub(crate) fn put_data<T: Into<ShortTag>, D: Into<Data>>(
    tag: T,
    data: D,
) -> Result<Command, Error> {
    let data: Data = data.into();

    match tag.into() {
        ShortTag::One(tag0) => Command::new(0x00, 0xda, 0, tag0, data),
        ShortTag::Two(tag0, tag1) => Command::new(0x00, 0xda, tag0, tag1, data),
    }
}

/// PUT DO Login Data
pub(crate) fn put_login_data(login_data: Vec<u8>) -> Result<Command, Error> {
    put_data(Tags::LoginData, login_data)
}

/// PUT DO Name
pub(crate) fn put_name(name: Vec<u8>) -> Result<Command, Error> {
    put_data(Tags::Name, name)
}

/// PUT DO Language preferences
pub(crate) fn put_lang(lang: Vec<u8>) -> Result<Command, Error> {
    put_data(Tags::LanguagePref, lang)
}

/// PUT DO Sex
pub(crate) fn put_sex(sex: u8) -> Result<Command, Error> {
    put_data(Tags::Sex, vec![sex])
}

/// PUT DO Uniform resource locator (URL)
pub(crate) fn put_url(url: Vec<u8>) -> Result<Command, Error> {
    put_data(Tags::Url, url)
}

/// PUT DO "PW status bytes"
pub(crate) fn put_pw_status(data: Vec<u8>) -> Result<Command, Error> {
    put_data(Tags::PWStatusBytes, data)
}

/// PUT DO "Cardholder certificate"
pub(crate) fn put_cardholder_certificate(data: Vec<u8>) -> Result<Command, Error> {
    put_data(Tags::CardholderCertificate, data)
}

/// "RESET RETRY COUNTER" (PW1, user pin)
/// Reset the counter of PW1 and set a new pin.
pub(crate) fn reset_retry_counter_pw1(
    resetting_code: Option<SecretBox<[u8]>>,
    new_pin: SecretBox<[u8]>,
) -> Result<Command, Error> {
    if let Some(resetting_code) = resetting_code {
        // Present the Resetting Code (DO D3) in the command data (P1 = 00)

        // Data field: Resetting Code + New PW
        let mut data = vec![];
        data.extend(resetting_code.expose_secret());
        data.extend(new_pin.expose_secret());

        Command::new(0x00, 0x2C, 0x00, 0x81, SecretBox::new(data.into()))
    } else {
        // Use after correct verification of PW3 (P1 = 02)
        // (Usage of secure messaging is equivalent to PW3)
        Command::new(0x00, 0x2C, 0x02, 0x81, new_pin)
    }
}

/// "CHANGE REFERENCE DATA" - change PW1 (user pin)
pub(crate) fn change_pw1(data: SecretBox<[u8]>) -> Result<Command, Error> {
    Command::new(0x00, 0x24, 0x00, 0x81, data)
}

/// "CHANGE REFERENCE DATA" - change PW3 (admin pin)
pub(crate) fn change_pw3(data: SecretBox<[u8]>) -> Result<Command, Error> {
    Command::new(0x00, 0x24, 0x00, 0x83, data)
}

/// 7.2.10 PSO: COMPUTE DIGITAL SIGNATURE
pub(crate) fn signature(data: Vec<u8>) -> Result<Command, Error> {
    Command::new(0x00, 0x2A, 0x9e, 0x9a, data)
}

/// 7.2.11 PSO: DECIPHER (decryption)
pub(crate) fn decryption(data: Vec<u8>) -> Result<Command, Error> {
    Command::new(0x00, 0x2A, 0x80, 0x86, data)
}

/// 7.2.13 PSO: INTERNAL AUTHENTICATE
pub(crate) fn internal_authenticate(data: Vec<u8>) -> Result<Command, Error> {
    Command::new(0x00, 0x88, 0x00, 0x00, data)
}

/// 7.2.14 GENERATE ASYMMETRIC KEY PAIR
pub(crate) fn gen_key(data: Vec<u8>) -> Result<Command, Error> {
    Command::new(0x00, 0x47, 0x80, 0x00, data)
}

/// Read public key template (see 7.2.14)
pub(crate) fn get_pub_key(data: Vec<u8>) -> Result<Command, Error> {
    Command::new(0x00, 0x47, 0x81, 0x00, data)
}

/// key import (see 4.4.3.12, 7.2.8)
pub(crate) fn key_import(data: Vec<u8>) -> Result<Command, Error> {
    // The key import uses a PUT DATA command with odd INS (DB) and an
    // Extended header list (DO 4D) as described in ISO 7816-8

    Command::new(0x00, 0xDB, 0x3F, 0xFF, data)
}

/// Generate attestation (Yubico)
///
/// key: 0x01 (SIG), 0x02 (DEC), 0x03 (AUT)
///
/// https://developers.yubico.com/PGP/Attestation.html
pub(crate) fn generate_attestation(key: u8) -> Result<Command, Error> {
    Command::new(0x80, 0xFB, key, 0x00, vec![])
}

/// 7.2.16 TERMINATE DF
pub(crate) fn terminate_df() -> Result<Command, Error> {
    Command::new(0x00, 0xe6, 0x00, 0x00, vec![])
}

/// 7.2.17 ACTIVATE FILE
pub(crate) fn activate_file() -> Result<Command, Error> {
    Command::new(0x00, 0x44, 0x00, 0x00, vec![])
}

/// 7.2.18 MANAGE SECURITY ENVIRONMENT
pub(crate) fn manage_security_environment(
    for_operation: KeyType,
    key_ref: KeyType,
) -> Result<Command, Error> {
    let p2 = match for_operation {
        KeyType::Authentication => 0xA4,
        KeyType::Decryption => 0xB8,
        _ => unreachable!(), //FIXME
    };
    let data = match key_ref {
        KeyType::Decryption => vec![0x83, 0x01, 0x02],
        KeyType::Authentication => vec![0x83, 0x01, 0x03],
        _ => unreachable!(),
    };

    Command::new(0, 0x22, 0x41, p2, data)
}
