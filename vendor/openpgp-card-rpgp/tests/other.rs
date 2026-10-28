// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(dead_code)]

use anyhow::Result;
use openpgp_card::{Card, state::Open};

use crate::{
    cards::TestConfig,
    util::{run_test, test_reset},
};

mod cards;
mod util;

#[ignore]
#[test]
fn other() -> Result<()> {
    env_logger::init();

    let config = TestConfig::load("config/test-cards.toml")?;

    let cards = config.into_cardapps();

    for card in cards {
        println!("** Run tests on card '{}' **", card.get_name());

        let mut c: Card<Open> = card.get_card()?;
        let mut tx = c.transaction()?;

        // println!("Caps");
        // let _ = run_test(&mut card, test_print_caps, &[])?;
        // continue; // only print caps

        // println!("Algo info");
        // let _ = run_test(&mut card, test_print_algo_info, &[])?;

        println!("Reset");
        let _ = run_test(&mut tx, test_reset, &[])?;

        // ---

        // // load private key (change pw on gnuk needs existing keys!)
        // println!("load key");
        // run_test(&mut card, test_upload_keys, &["data/rsa2k.sec"])?;

        // println!("Change PW");
        // let _ = run_test(&mut card, test_change_pw, &[])?;

        // println!("reset pw1 retry counter");
        // let _ = run_test(&mut card, test_reset_retry_counter, &[])?;

        // ---

        // println!("Generate key");
        // let _ = run_test(&mut card, test_keygen, &[])?;
        //
        // panic!();

        // println!("Get pubkey");
        // let _ = run_test(&mut card, test_get_pub, &[])?;
        //
        // panic!();

        // ---

        // print!("Verify");
        // let verify_out = run_test(&mut card, test_verify, &[])?;
        // println!(" {:x?}", verify_out);

        // print!("PW Status bytes");
        // let pw_out = run_test(&mut card, test_pw_status, &[])?;
        // println!(" {:x?}", pw_out);

        // print!("Private data");
        // let priv_out = run_test(&mut card, test_private_data, &[])?;
        // println!(" {:x?}", priv_out);

        // print!("Cardholder Cert");
        // let cardh_out = run_test(&mut card, test_cardholder_cert, &[])?;
        // println!(" {:x?}", cardh_out);
        // println!();
    }

    Ok(())
}
