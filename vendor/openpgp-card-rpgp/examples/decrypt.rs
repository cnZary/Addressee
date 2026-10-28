// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::BufReader;

use card_backend_pcsc::PcscBackend;
use openpgp_card::{Card, ocard::KeyType, state::Open};
use openpgp_card_rpgp::CardSlot;
use pgp::composed::Message;

/// This program decrypts an OpenPGP message that it reads from stdin.
///
/// It uses an OpenPGP card to decrypt the message, and takes two arguments:
/// - a "card ident" which identifies an OpenPGP card device,
/// - a file that contains the User PIN for that card (e.g. the file could contain the string
///   "123456")
///
/// When decryption is successful, the decrypted payload is printed to stdout.
///
/// This example program can be run like:
///
/// `$ cat encrypted_message | cargo run --example decrypt -- 0000:12345678 pinfile`
fn main() -> testresult::TestResult {
    // Get encrypted message from stdin
    let stdin = std::io::stdin();
    let (encrypted, _headers) = Message::from_reader(BufReader::new(stdin))?;

    // Handle command line arguments
    let args = std::env::args().collect::<Vec<_>>();

    if args.len() != 3 {
        eprintln!("Usage: decrypt card-ident pin-file");
        return Ok(());
    }

    let card_ident = &args[1];
    let pin_file = &args[2];

    // Load User PIN from the pin file
    let pin = std::fs::read(pin_file)?;
    let pin = pin.trim_ascii(); // drop newline or spaces, if any

    // Now let's find the card that the user wants, starting with all cards that PCSC knows about
    let cards = PcscBackend::card_backends(None)?;

    // Select the OpenPGP application on the card with the right "ident"
    let mut card = Card::<Open>::open_by_ident(cards, card_ident)?;

    // Start a PCSC transaction on the card
    let mut tx = card.transaction()?;

    // Present User PIN to the card
    tx.card().verify_pw1_user(pin.to_vec().into())?;

    // Initialize a `CardSlot` for decryption that can perform private key operations for rPGP
    let cs = CardSlot::init_from_card(&mut tx, KeyType::Decryption, &|| {
        eprintln!("Touch confirmation needed for decryption")
    })?;

    // Decrypt the message
    let mut decrypted = cs.decrypt_message(encrypted)?;

    // Copy the plaintext data from "decrypted" to stdout
    std::io::copy(&mut decrypted, &mut std::io::stdout())?;

    Ok(())
}
