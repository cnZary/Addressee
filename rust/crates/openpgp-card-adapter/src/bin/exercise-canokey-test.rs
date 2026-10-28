use std::{
    error::Error, ffi::OsString, fs::OpenOptions, io::Write as _, path::PathBuf, process::ExitCode,
    sync::Arc,
};

use openpgp_card::ocard::KeyType;
use openpgp_card_adapter::{
    CardIdentity, ExpectedSerial,
    hardware_test::{CanokeyCryptoAuthorization, validate_usb_identity},
    interaction::{CardInteractionError, PinProvider, PinPurpose, StderrTouchPrompt},
    pinentry::PinEntry,
    remote_key::CardSession,
    resolver::CardKeyResolver,
    workflow_gpg::{exercise_gpg_interop, parse_public_certificate, read_public_certificate},
    workflow_test::{exercise_v4_workflows, v4_component_fingerprints},
};
use openpgp_core::RemotePrivateKeyResolver as _;
use zeroize::Zeroizing;

struct DiagnosticPinEntry(PinEntry);

impl PinProvider for DiagnosticPinEntry {
    fn request_pin(
        &self,
        purpose: PinPurpose,
        identity: &CardIdentity,
    ) -> Result<Zeroizing<String>, CardInteractionError> {
        eprintln!(
            "Requesting {purpose:?} PIN for card {:04X}:{:08X}.",
            identity.manufacturer(),
            identity.serial()
        );
        let result = self.0.request_pin(purpose, identity);
        match &result {
            Ok(_) => eprintln!("PIN entry completed for {purpose:?}."),
            Err(error) => eprintln!(
                "PIN entry failed for {purpose:?}: {}.",
                interaction_error_category(error)
            ),
        }
        result
    }
}

fn interaction_error_category(error: &CardInteractionError) -> &'static str {
    match error {
        CardInteractionError::Cancelled => "cancelled",
        CardInteractionError::Unavailable(_) => "unavailable",
        CardInteractionError::Protocol(_) => "protocol error",
        CardInteractionError::Rejected(_) => "rejected",
        CardInteractionError::InvalidEncoding => "invalid encoding",
        CardInteractionError::InvalidLength { .. } => "invalid length",
        CardInteractionError::EmptyPin => "empty PIN",
        CardInteractionError::TouchFailed(_) => "touch failed",
    }
}

const USAGE: &str = "Usage: exercise-canokey-test --reader <exact-name> --serial <8-hex> --usb-serial <8-hex> --public-cert <existing-public-file> --artifacts <new-directory> --pinentry <executable> [--gpg <executable>] --authorize-crypto-test <scope>\n\nUses an already uploaded disposable v4 P-256 certificate without changing card state.\nRequires live USB and OpenPGP identity matching. PINs are read only by pinentry.\nNo reset, PIN change, key import, key generation, or automatic retry is available.";

struct Options {
    reader: String,
    serial: ExpectedSerial,
    usb_serial: ExpectedSerial,
    public_certificate: PathBuf,
    artifacts: PathBuf,
    pinentry: PathBuf,
    gpg: PathBuf,
    authorization: CanokeyCryptoAuthorization,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Disposable CanoKey cryptographic test stopped: {error}");
            let mut source = error.source();
            while let Some(cause) = source {
                eprintln!("Caused by: {cause}");
                source = cause.source();
            }
            eprintln!(
                "No operation was retried automatically. Inspect the exact card before any retry; this tool never resets or reconfigures a card."
            );
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let Some(options) = parse(std::env::args_os().skip(1))? else {
        println!("{USAGE}");
        return Ok(());
    };
    if options.artifacts.exists() {
        return Err("the artifact directory must not already exist".into());
    }
    validate_usb_identity(&options.reader, options.serial, options.usb_serial)?;
    let public = read_public_certificate(&options.public_certificate)?;
    let certificate = parse_public_certificate(&public)?;
    certificate.verify_bindings()?;
    let (certificate_fingerprint, signing_fingerprint, decryption_fingerprint) =
        v4_component_fingerprints(&certificate)?;
    let pins = Arc::new(DiagnosticPinEntry(PinEntry::new(&options.pinentry)));
    let session = CardSession::connect(
        &options.reader,
        options.serial,
        pins,
        Arc::new(StderrTouchPrompt),
    )?;
    options
        .authorization
        .validate_identity(session.identity())?;
    let mut resolver = CardKeyResolver::new(session);
    resolver.register(&certificate, KeyType::Signing, &signing_fingerprint)?;
    resolver.register(&certificate, KeyType::Decryption, &decryption_fingerprint)?;
    if resolver
        .signing_key(&certificate_fingerprint, &decryption_fingerprint)?
        .is_some()
        || resolver
            .decryption_key(&certificate_fingerprint, &signing_fingerprint)?
            .is_some()
    {
        return Err("the resolver returned a component for the wrong operation".into());
    }

    println!(
        "Beginning card-backed message checks. PINs are requested individually; no retry is automatic."
    );
    let artifacts = exercise_v4_workflows(&certificate, &resolver).inspect_err(|_| {
        eprintln!(
            "Card-backed message workflow stopped; remote failure category: {:?}.",
            resolver.session().failure_kind()
        );
    })?;
    artifacts.write_to(&options.artifacts)?;
    let mut public_output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(options.artifacts.join("public.asc"))?;
    public_output.write_all(&public)?;
    public_output.sync_all()?;
    println!(
        "Card-backed detached, attached, cleartext, encryption, and combined checks passed. Artifacts: {}",
        options.artifacts.display()
    );
    exercise_gpg_interop(
        &certificate,
        &public,
        &resolver,
        None,
        &options.artifacts,
        &options.gpg,
    )?;
    println!(
        "GnuPG verified card-backed signatures. GnuPG-only and signed-plus-encrypted messages were decrypted by the application through the authorized card; GnuPG card-private-key integration is not claimed."
    );
    println!("GnuPG diagnostics: {}", options.artifacts.display());
    Ok(())
}

fn parse(arguments: impl Iterator<Item = OsString>) -> Result<Option<Options>, Box<dyn Error>> {
    let mut reader = None;
    let mut serial = None;
    let mut usb_serial = None;
    let mut public_certificate = None;
    let mut artifacts = None;
    let mut pinentry = None;
    let mut gpg = None;
    let mut authorization = None;
    let arguments = arguments.collect::<Vec<_>>();
    if arguments.first().is_some_and(|value| value == "--help") {
        if arguments.len() == 1 {
            return Ok(None);
        }
        return Err("--help cannot be combined with a card operation".into());
    }
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let argument = argument
            .into_string()
            .map_err(|_| "arguments must be valid UTF-8")?;
        let name = argument.as_str();
        let value = arguments
            .next()
            .ok_or("every option requires a value")?
            .into_string()
            .map_err(|_| "option values must be valid UTF-8")?;
        match name {
            "--reader" => set(&mut reader, value)?,
            "--serial" => set(&mut serial, value.parse()?)?,
            "--usb-serial" => set(&mut usb_serial, value.parse()?)?,
            "--public-cert" => set(&mut public_certificate, PathBuf::from(value))?,
            "--artifacts" => set(&mut artifacts, PathBuf::from(value))?,
            "--pinentry" => set(&mut pinentry, PathBuf::from(value))?,
            "--gpg" => set(&mut gpg, PathBuf::from(value))?,
            "--authorize-crypto-test" => set(&mut authorization, value)?,
            _ => return Err("unknown option; no card operation was attempted".into()),
        }
    }
    let serial = serial.ok_or("--serial is required")?;
    let authorization = CanokeyCryptoAuthorization::new(
        serial,
        authorization
            .as_deref()
            .ok_or("explicit cryptographic-test authorization is required")?,
    )?;
    Ok(Some(Options {
        reader: reader.ok_or("--reader is required")?,
        serial,
        usb_serial: usb_serial.ok_or("--usb-serial is required")?,
        public_certificate: public_certificate.ok_or("--public-cert is required")?,
        artifacts: artifacts.ok_or("--artifacts is required")?,
        pinentry: pinentry.ok_or("--pinentry is required")?,
        gpg: gpg.unwrap_or_else(|| PathBuf::from("gpg")),
        authorization,
    }))
}

fn set<T>(destination: &mut Option<T>, value: T) -> Result<(), Box<dyn Error>> {
    if destination.replace(value).is_some() {
        return Err("duplicate options are not allowed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> impl Iterator<Item = OsString> {
        values.iter().map(OsString::from)
    }

    #[test]
    fn help_does_not_access_a_card() {
        assert!(parse(arguments(&["--help"])).expect("help").is_none());
        assert!(parse(arguments(&["--help", "--reader", "any"])).is_err());
    }

    #[test]
    fn cryptographic_operations_require_identity_and_explicit_scope() {
        assert!(parse(arguments(&["--reader", "synthetic-reader"])).is_err());
        assert!(
            parse(arguments(&[
                "--reader",
                "synthetic-reader",
                "--serial",
                "1234ABCD",
                "--usb-serial",
                "1234ABCD",
                "--public-cert",
                "public.asc",
                "--artifacts",
                "unused-artifacts",
                "--pinentry",
                "/bin/false",
                "--authorize-crypto-test",
                "unrelated-operation",
            ]))
            .is_err()
        );
    }

    #[test]
    fn duplicate_options_are_rejected_before_connecting() {
        assert!(parse(arguments(&["--reader", "first", "--reader", "second",])).is_err());
    }
}
