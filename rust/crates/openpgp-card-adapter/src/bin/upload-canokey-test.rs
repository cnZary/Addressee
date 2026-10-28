use std::{
    error::Error,
    ffi::OsString,
    fs::OpenOptions,
    io::{self, Write as _},
    path::PathBuf,
    process::ExitCode,
};

#[cfg(test)]
use openpgp_card_adapter::hardware_upload::DISPOSABLE_UPLOAD_AUTHORIZATION;
use openpgp_card_adapter::{
    DisposableCertificate, DisposableSlot, ExpectedSerial,
    hardware_test::validate_usb_identity,
    hardware_upload::{
        DisposableUploadAuthorization, upload_disposable_p256, upload_disposable_p256_pair,
    },
    pinentry::PinEntry,
};
use openpgp_policy::GenerationProfile;

const USAGE: &str = "Usage: upload-canokey-test --reader <exact-name> --serial <8-hex> --usb-serial <8-hex> --slot <signing|decryption|both> --pinentry <executable> --public-out <new-file> --authorize-disposable-test <scope>\n\nRequires live USB validation and empty slots. PINs are read only by pinentry.\nThe pair profile uses one certificate for both slots in one card transaction.\nNo reset, PIN change, key generation on card, or arbitrary overwrite is available.";

struct Options {
    reader: String,
    serial: ExpectedSerial,
    usb_serial: ExpectedSerial,
    slots: Vec<DisposableSlot>,
    pinentry: PathBuf,
    public_output: PathBuf,
    authorization: DisposableUploadAuthorization,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Disposable CanoKey test stopped: {error}");
            eprintln!(
                "Inspect the exact card before any retry; no operation was retried automatically."
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
    if options.public_output.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the public-certificate output must be a new file",
        )
        .into());
    }
    validate_usb_identity(&options.reader, options.serial, options.usb_serial)?;
    let certificate = DisposableCertificate::generate(&GenerationProfile::nist_p256_v4())?;
    let mut public_output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&options.public_output)?;
    public_output.write_all(&certificate.public_armor()?)?;
    public_output.sync_all()?;
    let pins = PinEntry::new(&options.pinentry);
    let components = match options.slots.as_slice() {
        [slot] => vec![upload_disposable_p256(
            &options.authorization,
            &options.reader,
            &certificate,
            *slot,
            &pins,
        )?],
        [DisposableSlot::Signing, DisposableSlot::Decryption] => upload_disposable_p256_pair(
            &options.authorization,
            &options.reader,
            &certificate,
            &pins,
        )?
        .to_vec(),
        _ => return Err("the pair profile must select signing and decryption".into()),
    };
    println!("Disposable certificate: {}", certificate.fingerprint());
    for (slot, component) in options.slots.iter().zip(components) {
        println!("Uploaded {slot:?} subkey: {component}");
    }
    println!("Public certificate: {}", options.public_output.display());
    Ok(())
}

fn parse(arguments: impl Iterator<Item = OsString>) -> Result<Option<Options>, Box<dyn Error>> {
    let mut reader = None;
    let mut serial = None;
    let mut usb_serial = None;
    let mut slot = None;
    let mut pinentry = None;
    let mut public_output = None;
    let mut authorization = None;
    let arguments = arguments.collect::<Vec<_>>();
    if arguments.first().is_some_and(|value| value == "--help") {
        if arguments.len() == 1 {
            return Ok(None);
        }
        return Err("--help cannot be combined with a state-changing command".into());
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
            "--slot" => set(
                &mut slot,
                match value.as_str() {
                    "signing" => vec![DisposableSlot::Signing],
                    "decryption" => vec![DisposableSlot::Decryption],
                    "both" => vec![DisposableSlot::Signing, DisposableSlot::Decryption],
                    _ => return Err("the slot must be signing, decryption, or both".into()),
                },
            )?,
            "--pinentry" => set(&mut pinentry, PathBuf::from(value))?,
            "--public-out" => set(&mut public_output, PathBuf::from(value))?,
            "--authorize-disposable-test" => set(&mut authorization, value)?,
            _ => return Err("unknown option; no card operation was attempted".into()),
        }
    }
    let serial = serial.ok_or("--serial is required")?;
    let authorization = DisposableUploadAuthorization::new(
        serial,
        authorization
            .as_deref()
            .ok_or("explicit disposable-test authorization is required")?,
    )?;
    Ok(Some(Options {
        reader: reader.ok_or("--reader is required")?,
        serial,
        usb_serial: usb_serial.ok_or("--usb-serial is required")?,
        slots: slot.ok_or("--slot is required")?,
        pinentry: pinentry.ok_or("--pinentry is required")?,
        public_output: public_output.ok_or("--public-out is required")?,
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
    fn help_does_not_require_device_arguments() {
        assert!(parse(arguments(&["--help"])).expect("help").is_none());
        assert!(parse(arguments(&["--help", "--reader", "any"])).is_err());
    }

    #[test]
    fn destructive_options_require_all_identity_and_authorization_fields() {
        assert!(parse(arguments(&["--reader", "any"])).is_err());
        assert!(
            parse(arguments(&[
                "--reader",
                "any",
                "--serial",
                "1234ABCD",
                "--usb-serial",
                "1234ABCD",
                "--slot",
                "signing",
                "--pinentry",
                "/bin/false",
                "--public-out",
                "unused",
                "--authorize-disposable-test",
                "not-authorized",
            ]))
            .is_err()
        );
    }

    #[test]
    fn duplicate_options_are_rejected_before_connecting() {
        let error = parse(arguments(&["--reader", "first", "--reader", "second"]));
        assert!(error.is_err());
    }

    #[test]
    fn pair_profile_requires_two_slots_and_explicit_authorization() {
        let options = parse(arguments(&[
            "--reader",
            "synthetic-reader",
            "--serial",
            "1234ABCD",
            "--usb-serial",
            "1234ABCD",
            "--slot",
            "both",
            "--pinentry",
            "/bin/false",
            "--public-out",
            "unused-public-output",
            "--authorize-disposable-test",
            DISPOSABLE_UPLOAD_AUTHORIZATION,
        ]))
        .expect("valid pair arguments")
        .expect("pair profile");
        assert_eq!(
            options.slots,
            [DisposableSlot::Signing, DisposableSlot::Decryption]
        );
    }
}
