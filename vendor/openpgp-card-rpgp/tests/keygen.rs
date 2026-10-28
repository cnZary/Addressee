// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::panic, dead_code)]

use std::env;

use anyhow::Result;
use openpgp_card::{Card, state::Open};
use pgp::composed::{Deserializable, SignedPublicKey};

use crate::{
    cards::TestConfig,
    util::{
        TestResult,
        run_test,
        test_decrypt,
        test_keygen,
        test_print_algo_info,
        test_print_caps,
        test_reset,
        test_set_user_data,
        test_sign,
    },
};

mod cards;
mod util;

#[ignore]
#[test]
fn keygen() -> Result<()> {
    env_logger::init();

    let config = match env::var("TEST_CONFIG") {
        Ok(path) => TestConfig::load(&path)?,
        Err(_) => TestConfig::load("config/test-cards.toml")?, // fallback
    };

    let cards = config.into_cardapps();

    for card in cards {
        println!("** Run tests on card {} **", card.get_name());

        let mut c: Card<Open> = card.get_card()?;
        println!(" -> Card opened");
        let mut tx = c.transaction()?;
        println!("    started transaction");

        // println!("Get pubkey");
        // let _ = run_test(&mut tx, test_get_pub, &[])?;

        println!("Caps");
        let _ = run_test(&mut tx, test_print_caps, &[])?;
        // continue; // only print caps

        println!("Reset");
        let _ = run_test(&mut tx, test_reset, &[])?;

        println!("Algo info");
        let _ = run_test(&mut tx, test_print_algo_info, &[])?;

        // Set user data because keygen expects a name (for the user id)
        println!("Set user data");
        let _ = run_test(&mut tx, test_set_user_data, &[])?;

        let algos = {
            let config = card.get_config();
            if let Some(keygen) = &config.keygen {
                keygen.clone()
            } else {
                vec![]
            }
        };

        for algo in algos {
            println!("Generate key [{algo}]");

            let res = run_test(&mut tx, test_keygen, &[&algo])?;

            if let TestResult::Text(cert_str) = &res[0] {
                // sign
                print!("  Sign");
                let sign_out = run_test(&mut tx, test_sign, &[cert_str])?;
                println!(" {sign_out:x?}");

                // decrypt
                let (spk, _) = SignedPublicKey::from_string(cert_str)?;
                let ciphertext = util::encrypt_to("Hello world!\n", &spk)?;

                print!("  Decrypt");
                let dec_out = run_test(&mut tx, test_decrypt, &[cert_str, &ciphertext])?;
                println!(" {dec_out:x?}");
            } else {
                panic!("Didn't get back a Cert from test_keygen");
            };
        }

        println!();
    }

    Ok(())
}
