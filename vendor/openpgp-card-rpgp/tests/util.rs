// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::panic, clippy::expect_used)]

use std::{convert::TryFrom, string::FromUtf8Error};

use anyhow::{Result, anyhow};
use openpgp_card::{
    Card,
    Error,
    ocard::{
        KeyType,
        StatusBytes,
        algorithm::AlgoSimple,
        crypto::CardUploadableKey,
        data::{KeyGenerationTime, Sex},
    },
    state::{Admin, Open, Transaction},
};
use openpgp_card_rpgp::{
    CardSlot,
    UploadableKey,
    bind_into_certificate,
    public_key_material_and_fp_to_key,
    public_key_material_to_key,
};
use pgp::{
    composed::{
        ArmorOptions,
        Deserializable,
        DetachedSignature,
        Message,
        MessageBuilder,
        PublicOrSecret,
        SignedPublicKey,
        SignedSecretKey,
    },
    crypto::sym::SymmetricKeyAlgorithm,
    packet::PublicSubkey,
    ser::Serialize,
    types::{Password, SigningKey},
};
use rand::thread_rng;

#[derive(Debug)]
pub enum TestResult {
    Status(StatusBytes),
    StatusOk,
    Text(String),
}

type TestOutput = Vec<TestResult>;

#[derive(thiserror::Error, Debug)]
pub enum TestError {
    #[error("Failed to upload key {0} ({1})")]
    KeyUploadError(String, anyhow::Error),

    #[error(transparent)]
    Opgp(#[from] Error),

    #[error(transparent)]
    OCard(#[from] StatusBytes),

    #[error(transparent)]
    Other(#[from] anyhow::Error), // source and Display delegate to anyhow::Error

    #[error(transparent)]
    Utf8Error(#[from] FromUtf8Error),
}

impl From<openpgp_card_rpgp::Error> for TestError {
    fn from(value: openpgp_card_rpgp::Error) -> Self {
        TestError::Other(value.into())
    }
}

/// Run after each "upload keys", if key *was* uploaded (?)
pub fn test_decrypt(tx: &mut Card<Transaction>, param: &[&str]) -> Result<TestOutput, TestError> {
    assert_eq!(
        param.len(),
        2,
        "test_decrypt needs filenames for 'cert' and 'encrypted'"
    );

    let msg = param[1].to_string();

    let _user = tx.as_user_card(Some("123456".to_string().into()))?;

    let (msg, _) = Message::from_reader(msg.as_bytes()).expect("parse message");

    let cs = CardSlot::init_from_card(tx, KeyType::Decryption, &|| {
        eprintln!("touch confirmation required")
    })
    .expect("FIXME");

    let mut decrypted = cs.decrypt_message(msg).expect("FIXME");

    let plain = decrypted.as_data_vec().expect("Message::as_data_vec");
    assert_eq!(plain, "Hello world!\n".as_bytes());

    Ok(vec![])
}

/// Run after each "upload keys", if key *was* uploaded (?)
pub fn test_sign(tx: &mut Card<Transaction>, param: &[&str]) -> Result<TestOutput, TestError> {
    assert_eq!(param.len(), 1, "test_sign needs a filename for 'cert'");

    let _sign = tx
        .as_signing_card(Some("123456".to_string().into()))
        .expect("pin presentation");

    let cleartext = "Hello world, I am signed.";

    let cs = CardSlot::init_from_card(tx, KeyType::Signing, &|| {
        eprintln!("touch confirmation required")
    })
    .expect("FIXME");

    let sig = cs
        .sign_data(
            cleartext.as_bytes(),
            false,
            &Password::empty(),
            cs.hash_alg(),
        )
        .expect("sign on card");

    // validate sig
    let (mut parsed, _) =
        PublicOrSecret::from_armor_many(param[0].as_bytes()).expect("parse key data");

    let spk = match parsed.next().expect("no key found") {
        Ok(PublicOrSecret::Public(p)) => p,
        Ok(PublicOrSecret::Secret(s)) => SignedPublicKey::from(s),
        Err(e) => panic!("parse key data {e}"),
    };

    let sig = DetachedSignature::new(sig);

    assert!(verify_sig(
        &spk,
        cleartext.as_bytes(),
        &sig.to_bytes().expect("serialize signature")
    )?);

    Ok(vec![])
}

fn check_key_upload_metadata(
    admin: &mut Card<Admin>,
    meta: &[(String, KeyGenerationTime)],
) -> Result<()> {
    admin.as_transaction().invalidate_cache()?;

    // check fingerprints
    let card_fp = admin.as_transaction().fingerprints()?;

    let sig = card_fp.signature().expect("signature fingerprint");
    assert_eq!(format!("{sig:X}"), meta[0].0.to_ascii_uppercase());

    let dec = card_fp.decryption().expect("decryption fingerprint");
    assert_eq!(format!("{dec:X}"), meta[1].0.to_ascii_uppercase());

    let auth = card_fp
        .authentication()
        .expect("authentication fingerprint");
    assert_eq!(format!("{auth:X}"), meta[2].0.to_ascii_uppercase());

    // get_key_generation_times
    let card_kg = admin.as_transaction().key_generation_times()?;

    let sig = card_kg.signature().expect("signature creation time");
    assert_eq!(sig, &meta[0].1);

    let dec = card_kg.decryption().expect("decryption creation time");
    assert_eq!(dec, &meta[1].1);

    let auth = card_kg
        .authentication()
        .expect("authentication creation time");
    assert_eq!(auth, &meta[2].1);

    Ok(())
}

fn check_key_upload_algo_attrs() -> Result<()> {
    // get_algorithm_attributes
    // FIXME

    Ok(())
}

pub fn test_print_caps(
    tx: &mut Card<Transaction>,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let ard = tx.card().application_related_data()?;

    let aid = ard.application_id()?;
    println!("aid: {aid:#x?}");

    let hist = ard.historical_bytes()?;
    println!("hist: {hist:#?}");

    let ecap = ard.extended_capabilities()?;
    println!("ecap: {ecap:#?}");

    let eli = ard.extended_length_information()?;
    println!("eli: {eli:#?}");

    Ok(vec![])
}

pub fn test_print_algo_info(
    tx: &mut Card<Transaction>,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let ard = tx.card().application_related_data()?;

    let sig = ard.algorithm_attributes(KeyType::Signing)?;
    println!("Current algorithm for the signing slot: {sig}");

    let dec = ard.algorithm_attributes(KeyType::Decryption)?;
    println!("Current algorithm for the decrypt slot: {dec}");

    let aut = ard.algorithm_attributes(KeyType::Authentication)?;
    println!("Current algorithm for the authentication slot: {aut}");

    println!();

    let algo = tx.card().algorithm_information();
    if let Ok(Some(algo)) = algo {
        println!("Card algorithm list:\n{algo}");
    }

    Ok(vec![])
}

pub fn test_upload_keys(
    tx: &mut Card<Transaction>,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    assert_eq!(
        param.len(),
        1,
        "test_upload_keys needs a filename for 'cert'"
    );

    let key = std::fs::read_to_string(param[0])
        .unwrap_or_else(|_| panic!("load key from {:?}", param[0]));

    let (ssk, _) = SignedSecretKey::from_string(&key).expect("parse tsk");

    let mut admin = tx.as_admin_card(Some("12345678".to_string().into()))?;

    let meta = upload_subkeys(&mut admin, &ssk)
        .map_err(|e| TestError::KeyUploadError(param[0].to_string(), e))?;

    check_key_upload_metadata(&mut admin, &meta)?;

    // FIXME: implement
    check_key_upload_algo_attrs()?;

    Ok(vec![])
}

/// Generate keys for each of the three KeyTypes
pub fn test_keygen(tx: &mut Card<Transaction>, param: &[&str]) -> Result<TestOutput, TestError> {
    let mut admin = tx
        .as_admin_card(Some("12345678".to_string().into()))
        .expect("Couldn't get Admin card");

    // Generate all three subkeys on card
    let algo = param[0];

    let alg = AlgoSimple::try_from(algo)?;

    println!(" Generate subkey for Signing");
    admin.set_algorithm(KeyType::Signing, alg)?;
    let (pkm, ts) =
        admin.generate_key(openpgp_card_rpgp::public_to_fingerprint, KeyType::Signing)?;
    let key_sig =
        public_key_material_to_key(&pkm, KeyType::Signing, &ts, None, None).expect("FIXME");

    println!(" Generate subkey for Decryption");
    admin.set_algorithm(KeyType::Decryption, alg)?;
    let (pkm, ts) = admin.generate_key(
        openpgp_card_rpgp::public_to_fingerprint,
        KeyType::Decryption,
    )?;
    let key_dec =
        public_key_material_to_key(&pkm, KeyType::Decryption, &ts, None, None).expect("FIXME");

    println!(" Generate subkey for Authentication");
    admin.set_algorithm(KeyType::Authentication, alg)?;
    let (pkm, ts) = admin.generate_key(
        openpgp_card_rpgp::public_to_fingerprint,
        KeyType::Authentication,
    )?;
    let key_aut =
        public_key_material_to_key(&pkm, KeyType::Authentication, &ts, None, None).expect("FIXME");

    tx.invalidate_cache()?;

    // Generate a Cert for this set of generated keys
    let cert = bind_into_certificate(
        tx,
        key_sig,
        Some(key_dec),
        Some(key_aut),
        &["cardtest@example.org".to_string()],
        Some("123456".to_string().into()),
        &|| {},
        &|| eprintln!("touch confirmation needed"),
    )?;
    let armored = cert
        .to_armored_string(ArmorOptions::default())
        .expect("FIXME");

    let res = TestResult::Text(armored);

    Ok(vec![res])
}

/// Construct public key based on data from the card
pub fn test_get_pub(
    transaction: &mut Card<Transaction>,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let times = transaction.key_generation_times()?;
    let fps = transaction.fingerprints()?;

    // --

    let sig = transaction.public_key_material(KeyType::Signing)?;
    let ts = times
        .signature()
        .expect("creation time from card")
        .get()
        .into();
    let key = public_key_material_and_fp_to_key(
        &sig,
        KeyType::Signing,
        &ts,
        fps.signature().expect("FIXME"),
    )
    .expect("FIXME");

    println!(" sig key data from card -> {key:x?}");

    // --

    let dec = transaction.public_key_material(KeyType::Decryption)?;
    let ts = times
        .decryption()
        .expect("creation time from card")
        .get()
        .into();
    let key = public_key_material_and_fp_to_key(
        &dec,
        KeyType::Decryption,
        &ts,
        fps.decryption().expect("FIXME"),
    )
    .expect("FIXME");

    println!(" dec key data from card -> {key:x?}");

    // --

    let auth = transaction.public_key_material(KeyType::Authentication)?;
    let ts = times
        .authentication()
        .expect("creation time from card")
        .get()
        .into();
    let key = public_key_material_and_fp_to_key(
        &auth,
        KeyType::Authentication,
        &ts,
        fps.authentication().expect("FIXME"),
    )
    .expect("FIXME");

    println!(" auth key data from card -> {key:x?}");

    Ok(vec![])
}

pub fn test_reset(tx: &mut Card<Transaction>, _param: &[&str]) -> Result<TestOutput, TestError> {
    tx.factory_reset()?;
    Ok(vec![])
}

/// Sets name, lang, sex, url; then reads the fields from the card and
/// compares the values with the expected values.
///
/// Returns an empty TestOutput, throws errors for unexpected Status codes
/// and for unequal field values.
pub fn test_set_user_data(
    tx: &mut Card<Transaction>,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let mut admin = tx.as_admin_card(Some("12345678".to_string().into()))?;

    // name
    admin.set_cardholder_name("Bar<<Foo")?;

    // lang
    admin.set_lang(&[['d', 'e'].into(), ['e', 'n'].into()])?;

    // sex
    admin.set_sex(Sex::Female)?;

    // url
    admin.set_url("https://duckduckgo.com/")?;

    // reload application releated data
    tx.invalidate_cache()?;

    // compare the reloaded fields, expect equal data
    let ch = tx.cardholder_related_data()?;

    assert_eq!(ch.name(), Some("Bar<<Foo".as_bytes()));
    assert_eq!(
        ch.lang().expect("Language setting is None"),
        &[['d', 'e'].into(), ['e', 'n'].into()]
    );
    assert_eq!(ch.sex(), Some(Sex::Female));

    let url = tx.url()?;
    assert_eq!(&url, "https://duckduckgo.com/");

    Ok(vec![])
}

pub fn test_set_login_data(
    tx: &mut Card<Transaction>,
    _params: &[&str],
) -> std::result::Result<TestOutput, TestError> {
    let mut admin = tx.as_admin_card(Some("12345678".to_string().into()))?;

    let test_login = "someone@somewhere.com";
    admin.set_login_data(test_login.as_bytes())?;

    // Read the previously set login data
    let read_login_data = tx.login_data()?;

    assert_eq!(&read_login_data, test_login.as_bytes());

    Ok(vec![])
}

// pub fn test_private_data(mut card: Card<Open>, _param: &[&str]) -> Result<TestOutput, TestError>
// {     let mut transaction = card.transaction()?;
//
//     let out = vec![];
//
//     println!();
//
//     let d = transaction.private_use_do(1)?;
//     println!("data 1 {d:?}");
//
//     transaction.verify_pw1_user("123456")?;
//
//     transaction.set_private_use_do(1, "Foo bar1!".as_bytes().to_vec())?;
//     transaction.set_private_use_do(3, "Foo bar3!".as_bytes().to_vec())?;
//
//     transaction.verify_pw3("12345678")?;
//
//     transaction.set_private_use_do(2, "Foo bar2!".as_bytes().to_vec())?;
//     transaction.set_private_use_do(4, "Foo bar4!".as_bytes().to_vec())?;
//
//     let d = transaction.private_use_do(1)?;
//     println!("data 1 {d:?}");
//     let d = transaction.private_use_do(2)?;
//     println!("data 2 {d:?}");
//     let d = transaction.private_use_do(3)?;
//     println!("data 3 {d:?}");
//     let d = transaction.private_use_do(4)?;
//     println!("data 4 {d:?}");
//
//     Ok(out)
// }

// pub fn test_cardholder_cert(
//     card_tx: &mut CardApp,
//     _param: &[&str],
// ) -> Result<TestOutput, TestError> {
//     let mut out = vec![];
//
//     println!();
//
//     match card_tx.cardholder_certificate() {
//         Ok(res) => {
//             out.push(TestResult::Text(format!("got cert {:x?}", res.data())))
//         }
//         Err(e) => {
//             out.push(TestResult::Text(format!(
//                 "get_cardholder_certificate failed: {:?}",
//                 e
//             )));
//             return Ok(out);
//         }
//     };
//
//     card_tx.verify_pw3("12345678")?;
//
//     let data = "Foo bar baz!".as_bytes();
//
//     match card_tx.set_cardholder_certificate(data.to_vec()) {
//         Ok(_resp) => out.push(TestResult::Text("set cert ok".to_string())),
//         Err(e) => {
//             out.push(TestResult::Text(format!(
//                 "set_cardholder_certificate: {:?}",
//                 e
//             )));
//             return Ok(out);
//         }
//     }
//
//     let res = card_tx.cardholder_certificate()?;
//     out.push(TestResult::Text("get cert ok".to_string()));
//
//     if res.data() != data {
//         out.push(TestResult::Text(format!(
//             "get after set doesn't match original data: {:x?}",
//             data
//         )));
//         return Ok(out);
//     };
//
//     // try using slot 2
//
//     match card_tx.select_data(2, &[0x7F, 0x21]) {
//         Ok(_res) => out.push(TestResult::Text("select_data ok".to_string())),
//         Err(e) => {
//             out.push(TestResult::Text(format!("select_data: {:?}", e)));
//             return Ok(out);
//         }
//     }
//
//     Ok(out)
// }

pub fn test_pw_status(mut card: Card<Open>, _param: &[&str]) -> Result<TestOutput, TestError> {
    let mut transaction = card.transaction()?;

    let out = vec![];

    let mut pws = transaction.pw_status_bytes()?;

    println!("pws {pws:?}");

    let mut admin = transaction.as_admin_card(Some("12345678".to_string().into()))?;

    pws.set_pw1_cds_valid_once(false);
    pws.set_pw1_pin_block(true);

    admin.set_pw_status_bytes(&pws, false)?;

    transaction.invalidate_cache()?;

    let pws = transaction.pw_status_bytes()?;
    println!("pws {pws:?}");

    Ok(out)
}

/// Outputs:
/// - verify pw3 (check) -> Status
/// - verify pw1 (check) -> Status
pub fn test_verify(mut card: Card<Open>, _param: &[&str]) -> Result<TestOutput, TestError> {
    let mut transaction = card.transaction()?;

    // Steps:
    //
    // - try to set name without verify, assert result is not ok
    // - verify pw3 + pin -> Status
    // - verify pw3 (check) -> Status
    // - set name -> Status
    // - get name -> Text(name)
    // - verify pw1 + pin -> Status
    // - verify pw1 (check) -> Status
    // - set name -> Status
    // - get name -> Text(name)

    let mut out = vec![];

    // try to set name without verify, assert result is not ok!
    let mut admin = transaction.as_admin_card(None)?;
    let res = admin.set_cardholder_name("Notverified<<Hello");

    if let Err(Error::CardStatus(s)) = res {
        assert_eq!(s, StatusBytes::SecurityStatusNotSatisfied);
    } else {
        panic!("Status should be 'SecurityStatusNotSatisfied'");
    }

    transaction.verify_admin_pin("12345678".to_string().into())?;

    match transaction.check_admin_verified() {
        Err(Error::CardStatus(s)) => {
            // e.g. yubikey5 returns an error status!
            out.push(TestResult::Status(s));
        }
        Err(_) => {
            panic!("unexpected error");
        }
        Ok(_) => out.push(TestResult::StatusOk),
    }

    let mut admin = transaction.as_admin_card(None)?;

    admin.set_cardholder_name("Admin<<Hello")?;

    transaction.invalidate_cache()?;

    let cardholder = transaction.cardholder_related_data()?;
    assert_eq!(cardholder.name(), Some("Admin<<Hello".as_bytes()));

    transaction.verify_user_pin("123456".to_string().into())?;

    match transaction.check_user_verified() {
        Err(Error::CardStatus(s)) => {
            // e.g. yubikey5 returns an error status!
            out.push(TestResult::Status(s));
        }
        Err(_) => {
            panic!("unexpected error");
        }
        Ok(_) => out.push(TestResult::StatusOk),
    }

    let mut admin = transaction.as_admin_card(None)?;

    admin.set_cardholder_name("There<<Hello")?;

    transaction.invalidate_cache()?;
    let cardholder = transaction.cardholder_related_data()?;
    assert_eq!(cardholder.name(), Some("There<<Hello".as_bytes()));

    Ok(out)
}

pub fn test_change_pw(mut card: Card<Open>, _param: &[&str]) -> Result<TestOutput, TestError> {
    let mut transaction = card.transaction()?;

    let out = vec![];

    // first do admin-less pw1 on gnuk
    // (NOTE: Gnuk requires a key to be loaded before allowing pw changes!)
    println!("change pw1");
    transaction.change_user_pin("123456".to_string().into(), "abcdef00".to_string().into())?;

    // also set admin pw, which means pw1 is now only user-pw again, on gnuk
    println!("change pw3");
    // ca.change_pw3("abcdef00", "abcdefgh")?; // gnuk
    transaction.change_admin_pin("12345678".to_string().into(), "abcdefgh".to_string().into())?;

    println!("change pw1");
    transaction.change_user_pin("abcdef00".to_string().into(), "abcdef".to_string().into())?; // gnuk

    // ca.change_pw1("123456", "abcdef")?;

    println!("verify bad pw1");
    match transaction.verify_user_pin("123456ab".to_string().into()) {
        Err(Error::CardStatus(StatusBytes::SecurityStatusNotSatisfied)) => {
            // this is expected
        }
        Err(_) => {
            panic!("unexpected error");
        }
        Ok(_) => panic!("this value for pw1 should be considered wrong!"),
    }

    println!("verify good pw1");
    transaction.verify_user_pin("abcdef".to_string().into())?;

    println!("verify bad pw3");
    match transaction.verify_admin_pin("00000000".to_string().into()) {
        Err(Error::CardStatus(StatusBytes::SecurityStatusNotSatisfied)) => {
            // this is expected
        }
        Err(_) => {
            panic!("unexpected error");
        }
        Ok(_) => panic!("this value for pw3 should be considered wrong!"),
    }

    println!("verify good pw3");
    transaction.verify_admin_pin("abcdefgh".to_string().into())?;

    println!("change pw3 back to default");
    transaction.change_admin_pin("abcdefgh".to_string().into(), "12345678".to_string().into())?;

    println!("change pw1 back to default");
    transaction.change_user_pin("abcdef".to_string().into(), "123456".to_string().into())?;

    Ok(out)
}

pub fn test_reset_retry_counter(
    mut card: Card<Open>,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let mut transaction = card.transaction()?;

    let out = vec![];

    // set pw3, then pw1 (to bring gnuk into non-admin mode)
    println!("set pw3");
    transaction.change_admin_pin("12345678".to_string().into(), "12345678".to_string().into())?;
    println!("set pw1");
    transaction.change_user_pin("123456".to_string().into(), "123456".to_string().into())?;

    println!("break pw1");
    let _ = transaction.verify_user_pin("wrong0".to_string().into());
    let _ = transaction.verify_user_pin("wrong0".to_string().into());
    let _ = transaction.verify_user_pin("wrong0".to_string().into());
    let res = transaction.verify_user_pin("wrong0".to_string().into());

    match res {
        Err(Error::CardStatus(StatusBytes::AuthenticationMethodBlocked)) => {
            // this is expected
        }
        Err(Error::CardStatus(StatusBytes::IncorrectParametersCommandDataField)) => {
            println!(
                "yk says IncorrectParametersCommandDataField when PW \
            error count is exceeded"
            );
        }
        Err(e) => {
            panic!("unexpected error {e:?}");
        }
        Ok(_) => panic!("use of pw1 should be blocked!"),
    }

    println!("verify pw3");
    transaction.verify_admin_pin("12345678".to_string().into())?;

    println!("set resetting code");
    let mut admin = transaction.as_admin_card(None)?;
    admin.set_resetting_code("abcdefgh".to_string().into())?;

    println!("reset retry counter");
    // ca.reset_retry_counter_pw1("abcdef".as_bytes().to_vec(), None)?;
    let _res =
        transaction.reset_user_pin("abcdef".to_string().into(), "abcdefgh".to_string().into());

    println!("verify good pw1");
    transaction.verify_user_pin("abcdef".to_string().into())?;

    println!("verify bad pw1");
    match transaction.verify_user_pin("00000000".to_string().into()) {
        Err(Error::CardStatus(StatusBytes::SecurityStatusNotSatisfied)) => {
            // this is expected
        }
        Err(_) => {
            panic!("unexpected error");
        }
        Ok(_) => panic!("this value for pw1 should be considered wrong!"),
    }

    Ok(out)
}

pub fn run_test(
    card: &mut Card<Transaction>,
    t: fn(&mut Card<Transaction>, &[&str]) -> Result<TestOutput, TestError>,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    t(card, param)
}

pub(crate) fn upload_subkeys(
    admin: &mut Card<Admin>,
    ssk: &SignedSecretKey,
) -> Result<Vec<(String, KeyGenerationTime)>> {
    let mut out = vec![];

    for kt in &[
        KeyType::Signing,
        KeyType::Decryption,
        KeyType::Authentication,
    ] {
        if let Some(uk) = subkey_by_type(ssk, *kt) {
            // store fingerprint as return-value
            let fp = hex::encode(uk.fingerprint()?.as_bytes());

            // store key creation time as return-value
            let creation = uk.timestamp().get();

            out.push((fp, creation.into()));

            admin.import_key(&uk, *kt)?;
        }
    }

    Ok(out)
}

fn subkey_by_type(ssk: &SignedSecretKey, kt: KeyType) -> Option<UploadableKey> {
    match kt {
        KeyType::Signing => signing_sec_key(ssk).ok(),
        KeyType::Decryption => decryption_sec_key(ssk).ok(),
        KeyType::Authentication => auth_sec_key(ssk).ok(),
        KeyType::Attestation => None,
    }
}

fn signing_sec_key(ssk: &SignedSecretKey) -> Result<UploadableKey> {
    for sk in &ssk.secret_subkeys {
        let binding = sk
            .signatures
            .first() // FIXME: we really want the newest, but for these tests we expect simple keys
            .expect("expecting a binding signature");

        if binding.key_flags().sign() {
            return Ok(sk.key.clone().into());
        }
    }

    // look at primary (NOTE: we're not handling direct signatures here!)
    let binding = ssk
        .details
        .users
        .first() // FIXME: we really want the primary user, but for these tests we expect simple keys
        .expect("expecting a user")
        .signatures
        .first() // FIXME: we really want the newest, but for these tests we expect simple keys
        .expect("expecting a binding signature");

    if binding.key_flags().sign() {
        return Ok(ssk.primary_key.clone().into());
    }

    Err(anyhow!("no key found"))
}

fn auth_sec_key(ssk: &SignedSecretKey) -> Result<UploadableKey> {
    for sk in &ssk.secret_subkeys {
        let binding = sk
            .signatures
            .first() // FIXME: we really want the newest, but for these tests we expect simple keys
            .expect("expecting a binding signature");

        if binding.key_flags().authentication() {
            return Ok(sk.key.clone().into());
        }
    }

    Err(anyhow!("no key found"))
}

fn decryption_sec_key(ssk: &SignedSecretKey) -> Result<UploadableKey> {
    for sk in &ssk.secret_subkeys {
        let binding = sk
            .signatures
            .first() // FIXME: we really want the newest, but for these tests we expect simple keys
            .expect("expecting a binding signature");

        let flags = binding.key_flags();
        if flags.encrypt_comms() || flags.encrypt_storage() {
            return Ok(sk.key.clone().into());
        }
    }

    Err(anyhow!("no key found"))
}

/// NOTE: this function ignores key flags and all validity entirely.
/// It returns `true` if any component key is found that cryptographically validates the signature.
/// This is not ok for production OpenPGP, but sufficient for these tests.
pub fn verify_sig(spk: &SignedPublicKey, data: &[u8], sig: &[u8]) -> Result<bool> {
    let sig = DetachedSignature::from_bytes(sig).expect("signature");

    if sig.verify(&spk.primary_key, data).is_ok() {
        return Ok(true);
    }

    for sk in &spk.public_subkeys {
        if sig.verify(&sk.key, data).is_ok() {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn encrypt_to(plaintext: &str, spk: &SignedPublicKey) -> Result<String> {
    let mut rng = thread_rng();

    let builder = MessageBuilder::from_reader("", plaintext.as_bytes());
    let mut builder = builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128);

    let keys = encryption_capable(spk)?;
    assert_eq!(keys.len(), 1);

    let key = keys[0];
    builder.encrypt_to_key(&mut rng, key)?;

    let enc = builder.to_armored_string(rng, ArmorOptions::default())?;

    Ok(enc)
}

/// NOTE: we don't support encryption capable primaries here.
/// This is a little unfortunate, but for the tests we don't care about that corner case.
fn encryption_capable(spk: &SignedPublicKey) -> Result<Vec<&PublicSubkey>> {
    let mut v = vec![];

    for sk in &spk.public_subkeys {
        let binding = sk
            .signatures
            .first() // FIXME: we really want the newest, but for these tests we expect simple keys
            .expect("expecting a binding signature");

        let flags = binding.key_flags();
        if flags.encrypt_comms() || flags.encrypt_storage() {
            v.push(&sk.key);
        }
    }

    Ok(v)
}
