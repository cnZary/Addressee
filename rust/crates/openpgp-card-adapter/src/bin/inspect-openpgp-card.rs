use std::process::ExitCode;

use openpgp_card_adapter::{
    ExpectedSerial,
    inspection::{IdentityRequirement, InspectionError, inspect_reader},
};
use thiserror::Error;

const HELP: &str = "Usage: inspect-openpgp-card --reader <exact-name> [--serial <expected-openpgp-serial-hex>]\n\
\n\
Inspect only the exact PC/SC reader supplied. No card is selected by enumeration\n\
order. When supplied, the serial must be exactly eight hexadecimal digits without\n\
a 0x prefix. Read-only discovery accepts any standards-compliant OpenPGP card.\n\
\n\
This inspector has no PIN or card-management options. It never authorizes a\n\
state-changing operation and does not use vendor-specific runtime SDKs.";

#[derive(Debug)]
struct Options {
    reader: String,
    serial: Option<ExpectedSerial>,
}

enum Action {
    Help,
    Inspect(Options),
}

#[derive(Debug, Error)]
enum CliError {
    #[error(
        "invalid command line: {0}\nUsage: inspect-openpgp-card --reader <exact-name> [--serial <expected-openpgp-serial-hex>]"
    )]
    Usage(&'static str),

    #[error("invalid expected OpenPGP serial: {0}")]
    Identity(#[from] openpgp_card_adapter::IdentityError),

    #[error("card inspection failed: {0}")]
    Inspection(#[from] InspectionError),
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("inspect-openpgp-card: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), CliError> {
    match parse_args(std::env::args().skip(1))? {
        Action::Help => {
            println!("{HELP}");
            Ok(())
        }
        Action::Inspect(options) => {
            let requirement = options
                .serial
                .map_or(IdentityRequirement::Discover, IdentityRequirement::Serial);
            println!("{}", inspect_reader(&options.reader, requirement)?);
            Ok(())
        }
    }
}

fn parse_args<I, S>(args: I) -> Result<Action, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into);
    let mut reader = None;
    let mut serial = None;

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "-h" | "--help" => return Ok(Action::Help),
            "--reader" => {
                if reader.is_some() {
                    return Err(CliError::Usage("--reader was supplied more than once"));
                }
                let value = args
                    .next()
                    .ok_or(CliError::Usage("--reader requires an exact reader name"))?;
                if value.is_empty() {
                    return Err(CliError::Usage("--reader requires a non-empty name"));
                }
                reader = Some(value);
            }
            "--serial" => {
                if serial.is_some() {
                    return Err(CliError::Usage("--serial was supplied more than once"));
                }
                let value = args.next().ok_or(CliError::Usage(
                    "--serial requires exactly eight hexadecimal digits",
                ))?;
                serial = Some(value.parse::<ExpectedSerial>()?);
            }
            _ => {
                return Err(CliError::Usage(
                    "unrecognized argument; only --reader, --serial, and --help are supported",
                ));
            }
        }
    }

    let reader = reader.ok_or(CliError::Usage("--reader is required"))?;
    Ok(Action::Inspect(Options { reader, serial }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_discovery_requires_only_an_exact_reader() {
        let action = parse_args(["--reader", "Any OpenPGP Reader"]).expect("valid arguments");
        let Action::Inspect(options) = action else {
            panic!("expected inspection arguments");
        };
        assert_eq!(options.reader, "Any OpenPGP Reader");
        assert_eq!(options.serial, None);
    }

    #[test]
    fn optional_serial_must_use_the_canonical_form() {
        let action =
            parse_args(["--reader", "Reader", "--serial", "0123abcd"]).expect("valid arguments");
        let Action::Inspect(options) = action else {
            panic!("expected inspection arguments");
        };
        assert_eq!(options.serial.map(|serial| serial.get()), Some(0x0123ABCD));
        assert!(parse_args(["--reader", "Reader", "--serial", "ABCD"]).is_err());
    }

    #[test]
    fn unknown_and_duplicate_options_are_rejected() {
        assert!(matches!(
            parse_args(["--pin", "not-a-real-pin"]),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(
            parse_args(["--reader", "One", "--reader", "Two"]),
            Err(CliError::Usage(_))
        ));
    }
}
