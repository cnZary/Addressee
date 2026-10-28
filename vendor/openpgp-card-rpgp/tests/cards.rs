// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wrapping of cards for tests. Open a list of cards, based on a
//! TestConfig configuration file

use std::collections::BTreeMap;

use anyhow::Result;
use card_backend_pcsc::PcscBackend;
use card_backend_scdc::ScdBackend;
use openpgp_card::{Error, state::Open};
use serde::Deserialize;

// const SHARE_MODE: Option<ShareMode> = Some(ShareMode::Shared);

#[derive(Debug, Deserialize)]
pub struct TestConfig {
    card: BTreeMap<String, Card>,
}

#[derive(Debug, Deserialize)]
pub struct Card {
    backend: BTreeMap<String, String>,
    config: Config,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub keygen: Option<Vec<String>>,
    pub import: Option<Vec<String>>,
}

/// An "opened" card, via one particular backend, with test-metadata
#[derive(Debug)]
pub struct TestCardData {
    name: String,
    tc: TestCard,
    config: Config,
}

impl TestCardData {
    pub fn get_card(&self) -> Result<openpgp_card::Card<Open>> {
        self.tc.open()
    }

    pub fn get_config(&self) -> &Config {
        &self.config
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }
}

impl TestConfig {
    pub fn load(file: &str) -> Result<Self> {
        let config_file = std::fs::read_to_string(file)?;

        let config: Self = toml::from_str(&config_file)?;
        Ok(config)
    }

    pub fn into_cardapps(self) -> Vec<TestCardData> {
        let mut cards = vec![];

        for (name, card) in self.card {
            for (backend, id) in &card.backend {
                let tc: TestCard = match backend.as_str() {
                    "pcsc" => TestCard::Pcsc(id.to_string()),
                    "scdc" => TestCard::Scdc(id.to_string()),
                    #[allow(clippy::unimplemented)]
                    _ => unimplemented!("unexpected backend {}", backend),
                };

                cards.push(TestCardData {
                    name: name.clone(),
                    tc,
                    config: card.config.clone(),
                })
            }
        }

        cards
    }
}

#[derive(Debug)]
pub enum TestCard {
    Pcsc(String),
    Scdc(String),
}

impl TestCard {
    pub fn open(&self) -> Result<openpgp_card::Card<Open>> {
        match self {
            Self::Pcsc(ident) => {
                // Attempt to shutdown SCD, if it is running.
                // Ignore any errors that occur during that shutdown attempt.
                let res = ScdBackend::shutdown_scd(None);
                log::trace!(" Attempt to shutdown scd: {res:?}");

                // Make three attempts to open the card before failing
                // (this can be useful in ShareMode::Exclusive)
                let mut i = 1;
                let card: Result<openpgp_card::Card<Open>, Error> = loop {
                    i += 1;

                    let cards = PcscBackend::card_backends(None)?;
                    let res = openpgp_card::Card::<Open>::open_by_ident(cards, ident);

                    println!("Got result for card: {ident}");

                    if let Err(e) = &res {
                        println!("Result is an error: {e:x?}");
                    } else {
                        println!("Result is a happy card");
                    }

                    if let Ok(res) = res {
                        break Ok(res);
                    }

                    if i > 3 {
                        break Err(Error::NotFound(format!("Couldn't open card {ident}")));
                    }

                    // sleep for 100ms
                    println!("Will sleep for 100ms");
                    std::thread::sleep(std::time::Duration::from_millis(100));
                };

                Ok(card?)
            }
            Self::Scdc(serial) => {
                let backend = ScdBackend::open_by_serial(None, serial)?;
                Ok(openpgp_card::Card::<Open>::new(backend)?)
            }
        }
    }
}
