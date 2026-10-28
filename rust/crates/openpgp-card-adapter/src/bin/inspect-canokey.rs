use std::process::ExitCode;

use openpgp_card_adapter::{
    ExpectedSerial,
    inspection::{IdentityRequirement, InspectionError, inspect_reader},
};
use thiserror::Error;

const HELP: &str = "Usage: inspect-canokey --reader <exact-name> --serial <expected-openpgp-serial-hex>\n\
\n\
Inspect only the exact PC/SC reader and exact 32-bit OpenPGP serial supplied.\n\
The serial must be exactly eight hexadecimal digits, without a 0x prefix.\n\
\n\
This inspector is read-only and has no PIN or card-management options. The caller\n\
must verify USB VID/PID before invocation. AID matching alone is not\n\
destructive-test authorization.";

#[derive(Debug)]
struct Options {
    reader: String,
    serial: ExpectedSerial,
}

enum Action {
    Help,
    Inspect(Options),
}

#[derive(Debug, Error)]
enum CliError {
    #[error(
        "invalid command line: {0}\nUsage: inspect-canokey --reader <exact-name> --serial <expected-openpgp-serial-hex>"
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
            eprintln!("inspect-canokey: {error}");
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
            println!(
                "{}",
                inspect_reader(
                    &options.reader,
                    IdentityRequirement::AuthorizedCanokey(options.serial),
                )?
            );
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
    let serial = serial.ok_or(CliError::Usage("--serial is required"))?;
    Ok(Action::Inspect(Options { reader, serial }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_required_exact_reader_and_serial() {
        let action = parse_args(["--reader", "Exact Reader Name", "--serial", "0123ABCD"])
            .expect("valid arguments");
        let Action::Inspect(options) = action else {
            panic!("expected inspection arguments");
        };
        assert_eq!(options.reader, "Exact Reader Name");
        assert_eq!(options.serial.get(), 0x0123ABCD);
    }

    #[test]
    fn help_is_available_without_reader_or_serial() {
        assert!(matches!(parse_args(["--help"]), Ok(Action::Help)));
    }

    #[test]
    fn missing_required_options_are_rejected() {
        assert!(matches!(
            parse_args(Vec::<String>::new()),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(
            parse_args(["--reader", "Reader"]),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(
            parse_args(["--serial", "0123ABCD"]),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn unknown_and_duplicate_options_are_rejected() {
        assert!(matches!(
            parse_args(["--pin", "not-a-real-pin"]),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(
            parse_args(["--reader", "One", "--reader", "Two", "--serial", "0123ABCD"]),
            Err(CliError::Usage(_))
        ));
    }
}
