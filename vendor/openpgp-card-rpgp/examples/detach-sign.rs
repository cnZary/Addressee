// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use card_backend_pcsc::PcscBackend;
use openpgp_card::{Card, ocard::KeyType, state::Open};
use openpgp_card_rpgp::{CardSlot, Error};
use pgp::{
    composed::{ArmorOptions, DetachedSignature},
    packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData},
    types::{KeyDetails, Password, SigningKey, Timestamp},
};

/// This program produces a detached OpenPGP signature for the data that it reads from stdin.
///
/// It uses an OpenPGP card to sign the message, and takes two arguments:
/// - a "card ident" which identifies an OpenPGP card device,
/// - a file that contains the User PIN for that card (e.g. the file could contain the string
///   "123456")
///
/// When signing is successful, the detached signature is printed to stdout.
///
/// This example program can be run like:
///
/// `$ echo "hello world" | cargo run --example detach-sign -- 0000:12345678 pinfile`
///
///
/// A generated signature can be verified with any SOP implementation, e.g.
///
/// `$ echo "hello world" | rsop verify <sig> <cert>`
fn main() -> testresult::TestResult {
    // Handle command line arguments
    let args = std::env::args().collect::<Vec<_>>();

    if args.len() != 3 {
        eprintln!("Usage: detach-sign card-ident pin-file");
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

    // Present User PIN to the card, for signing
    tx.card().verify_pw1_sign(pin.to_vec().into())?;

    // Initialize a `CardSlot` for signing that can perform private key operations for rPGP
    let cs = CardSlot::init_from_card(&mut tx, KeyType::Signing, &|| {
        eprintln!("touch confirmation needed")
    })?;

    // Set up signature config
    let config = signature_config(&cs)?;

    // Read all data from stdin and produce a signature for it
    let signature = config.sign(&cs, &Password::empty(), std::io::stdin())?;

    let signature = DetachedSignature { signature };

    // Write the signature to stdout (in armored form)
    signature.to_armored_writer(&mut std::io::stdout(), ArmorOptions::default())?;

    Ok(())
}

/// Set up a basic signature configuration for a binary data signature
fn signature_config(cs: &CardSlot) -> Result<SignatureConfig, Error> {
    let mut config = SignatureConfig::v4(
        SignatureType::Binary,
        cs.public_key().algorithm(),
        cs.hash_alg(),
    );
    config
        .hashed_subpackets
        .push(Subpacket::regular(SubpacketData::SignatureCreationTime(
            Timestamp::now(),
        ))?);
    config
        .hashed_subpackets
        .push(Subpacket::regular(SubpacketData::IssuerKeyId(
            cs.legacy_key_id(),
        ))?);
    config
        .hashed_subpackets
        .push(Subpacket::regular(SubpacketData::IssuerFingerprint(
            cs.fingerprint(),
        ))?);

    Ok(config)
}
