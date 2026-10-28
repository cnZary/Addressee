// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(dead_code)]

use std::env;

use anyhow::Result;
use openpgp_card::{Card, state::Open};
use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};

use crate::{
    cards::TestConfig,
    util::{
        TestError,
        run_test,
        test_decrypt,
        test_reset,
        test_set_login_data,
        test_set_user_data,
        test_sign,
        test_upload_keys,
    },
};

mod cards;
mod util;

#[ignore]
#[test]
fn import() -> Result<()> {
    env_logger::init();

    let config = match env::var("TEST_CONFIG") {
        Ok(path) => TestConfig::load(&path)?,
        Err(_) => TestConfig::load("config/test-cards.toml")?, // fallback
    };

    let cards = config.into_cardapps();

    for card in cards {
        println!("** Run tests on card '{}' **", card.get_name());

        let mut c: Card<Open> = card.get_card()?;
        println!(" -> Card opened");
        let mut tx = c.transaction()?;
        println!("    started transaction");

        println!("Reset");
        let _ = run_test(&mut tx, test_reset, &[])?;

        print!("Set user data");
        let userdata_out = run_test(&mut tx, test_set_user_data, &[])?;
        println!(" {userdata_out:x?}");

        print!("Set login data");
        let login_data_out = run_test(&mut tx, test_set_login_data, &[])?;
        println!(" {login_data_out:x?}");

        let key_files = {
            let config = card.get_config();
            if let Some(import) = &config.import {
                import.clone()
            } else {
                vec![]
            }
        };

        for key_file in &key_files {
            // upload keys
            print!("Upload key '{key_file}'");
            let upload_res = run_test(&mut tx, test_upload_keys, &[key_file]);

            if let Err(TestError::KeyUploadError(_file, err)) = &upload_res {
                // The card doesn't support this key type, so skip to the
                // next key - don't try to decrypt/sign for this key.

                println!(" => Upload failed ({err:?}), skip tests");

                continue;
            }

            let upload_out = upload_res?;
            println!(" {upload_out:x?}");

            #[allow(clippy::expect_used)]
            let key = std::fs::read_to_string(key_file).expect("Unable to read ciphertext");

            // decrypt
            print!("  Decrypt");

            let (ssk, _) = SignedSecretKey::from_string(&key)?;
            let spk: SignedPublicKey = ssk.into();
            let ciphertext = util::encrypt_to("Hello world!\n", &spk)?;

            let dec_out = run_test(&mut tx, test_decrypt, &[&key, &ciphertext])?;
            println!(" {dec_out:x?}");

            // sign
            print!("  Sign");

            let sign_out = run_test(&mut tx, test_sign, &[&key])?;
            println!(" {sign_out:x?}");
        }

        // FIXME: import key with password

        println!();
    }

    Ok(())
}
