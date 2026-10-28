use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::Duration,
};

use zeroize::Zeroizing;

use crate::{
    CardIdentity,
    interaction::{CardInteractionError, PinProvider, PinPurpose},
};

const MAX_RESPONSE_LINE_BYTES: usize = 4096;
const MAX_PIN_BYTES: usize = 1024;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

pub struct PinEntry {
    program: PathBuf,
    response_timeout: Duration,
}

impl PinEntry {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            response_timeout: RESPONSE_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_timeout(program: impl Into<PathBuf>, response_timeout: Duration) -> Self {
        Self {
            program: program.into(),
            response_timeout,
        }
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    fn request(
        &self,
        purpose: PinPurpose,
        identity: &CardIdentity,
    ) -> Result<Zeroizing<String>, CardInteractionError> {
        let mut process = PinEntryProcess::spawn(&self.program, self.response_timeout)?;
        process.expect_ok()?;
        process.command("SETTITLE Addressee OpenPGP Card")?;
        process.command(&format!(
            "SETDESC OpenPGP card {:04X}:{:08X}, application {}.{}",
            identity.manufacturer(),
            identity.serial(),
            identity.version() >> 8,
            identity.version() & 0xFF
        ))?;
        let prompt = match purpose {
            PinPurpose::Signing => "SETPROMPT User PIN for signing:",
            PinPurpose::User => "SETPROMPT User PIN:",
            PinPurpose::Admin => "SETPROMPT Admin PIN:",
        };
        process.command(prompt)?;
        process.write_command("GETPIN")?;
        let pin = process.read_secret_data()?;
        process.finish()?;
        decode_secret(pin)
    }
}

impl PinProvider for PinEntry {
    fn request_pin(
        &self,
        purpose: PinPurpose,
        identity: &CardIdentity,
    ) -> Result<Zeroizing<String>, CardInteractionError> {
        self.request(purpose, identity)
    }
}

struct PinEntryProcess {
    child: Option<Child>,
    input: ChildStdin,
    output: Receiver<std::io::Result<String>>,
    reader: Option<JoinHandle<()>>,
    response_timeout: Duration,
}

impl PinEntryProcess {
    fn spawn(program: &Path, response_timeout: Duration) -> Result<Self, CardInteractionError> {
        let mut child = Command::new(program)
            .arg("--timeout")
            .arg("60")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                CardInteractionError::Unavailable(format!(
                    "cannot start {}: {error}",
                    program.display()
                ))
            })?;
        let Some(input) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CardInteractionError::Protocol(
                "pinentry stdin is unavailable",
            ));
        };
        let Some(output) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CardInteractionError::Protocol(
                "pinentry stdout is unavailable",
            ));
        };
        let (sender, receiver) = mpsc::sync_channel(32);
        let reader = match thread::Builder::new()
            .name("addressee-pinentry-reader".to_owned())
            .spawn(move || {
                let mut output = BufReader::new(output);
                loop {
                    let mut line = String::new();
                    match output.read_line(&mut line) {
                        Ok(0) => {
                            let _ = sender.send(Ok(String::new()));
                            break;
                        }
                        Ok(_) => {
                            if line.ends_with('\n') {
                                line.pop();
                                if line.ends_with('\r') {
                                    line.pop();
                                }
                            }
                            if sender.send(Ok(line)).is_err() {
                                break;
                            }
                        }
                        Err(error) => {
                            let _ = sender.send(Err(error));
                            break;
                        }
                    }
                }
            }) {
            Ok(reader) => reader,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CardInteractionError::Unavailable(format!(
                    "cannot start the pinentry reader: {error}"
                )));
            }
        };
        Ok(Self {
            child: Some(child),
            input,
            output: receiver,
            reader: Some(reader),
            response_timeout,
        })
    }

    fn read_line(&mut self) -> Result<String, CardInteractionError> {
        let line = match self.output.recv_timeout(self.response_timeout) {
            Ok(Ok(line)) => line,
            Ok(Err(error)) => {
                return Err(CardInteractionError::Unavailable(format!(
                    "cannot read pinentry output: {error}"
                )));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(CardInteractionError::Unavailable(
                    "pinentry response timed out".to_owned(),
                ));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(CardInteractionError::Unavailable(
                    "the pinentry reader stopped unexpectedly".to_owned(),
                ));
            }
        };
        if line.is_empty() {
            return Err(CardInteractionError::Protocol(
                "pinentry closed output unexpectedly",
            ));
        }
        if line.len() > MAX_RESPONSE_LINE_BYTES {
            return Err(CardInteractionError::Protocol(
                "pinentry response line exceeds its limit",
            ));
        }
        Ok(line)
    }

    fn expect_ok(&mut self) -> Result<(), CardInteractionError> {
        for _ in 0..32 {
            let line = self.read_line()?;
            if line.starts_with('S') {
                continue;
            }
            if line == "OK" || line.starts_with("OK ") {
                return Ok(());
            }
            if line.starts_with("ERR") {
                return Err(pinentry_error(&line));
            }
            return Err(CardInteractionError::Protocol(
                "expected an OK response from pinentry",
            ));
        }
        Err(CardInteractionError::Protocol(
            "pinentry returned too many status lines",
        ))
    }

    fn write_command(&mut self, command: &str) -> Result<(), CardInteractionError> {
        if command.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return Err(CardInteractionError::Protocol(
                "pinentry command contains a line break",
            ));
        }
        self.input.write_all(command.as_bytes()).map_err(|error| {
            CardInteractionError::Unavailable(format!("cannot write to pinentry: {error}"))
        })?;
        self.input.write_all(b"\n").map_err(|error| {
            CardInteractionError::Unavailable(format!("cannot write to pinentry: {error}"))
        })?;
        self.input.flush().map_err(|error| {
            CardInteractionError::Unavailable(format!("cannot flush pinentry input: {error}"))
        })
    }

    fn command(&mut self, command: &str) -> Result<(), CardInteractionError> {
        self.write_command(command)?;
        self.expect_ok()
    }

    fn read_secret_data(&mut self) -> Result<Zeroizing<Vec<u8>>, CardInteractionError> {
        let mut secret = Zeroizing::new(Vec::new());
        for _ in 0..32 {
            let line = self.read_line()?;
            if line == "OK" || line.starts_with("OK ") {
                return Ok(secret);
            }
            if line.starts_with("ERR") {
                return Err(pinentry_error(&line));
            }
            if line.starts_with('S') {
                continue;
            }
            let Some(data) = line.strip_prefix("D ") else {
                return Err(CardInteractionError::Protocol(
                    "expected a pinentry data response",
                ));
            };
            append_percent_decoded(&mut secret, data)?;
            if secret.len() > MAX_PIN_BYTES {
                return Err(CardInteractionError::InvalidLength {
                    actual: secret.len(),
                    maximum: MAX_PIN_BYTES,
                });
            }
        }
        Err(CardInteractionError::Protocol(
            "pinentry returned too many data or status lines",
        ))
    }

    fn finish(mut self) -> Result<(), CardInteractionError> {
        self.command("BYE")?;
        let status = self
            .child
            .take()
            .ok_or(CardInteractionError::Protocol(
                "pinentry process was already closed",
            ))?
            .wait()
            .map_err(|error| {
                CardInteractionError::Unavailable(format!("cannot wait for pinentry: {error}"))
            })?;
        self.cleanup();
        if status.success() {
            Ok(())
        } else {
            Err(CardInteractionError::Protocol(
                "pinentry exited unsuccessfully",
            ))
        }
    }

    fn cleanup(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.output = mpsc::channel().1;
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for PinEntryProcess {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn pinentry_error(line: &str) -> CardInteractionError {
    let mut fields = line
        .strip_prefix("ERR")
        .unwrap_or(line)
        .trim()
        .splitn(2, ' ');
    let code = fields.next().and_then(|value| value.parse::<u32>().ok());
    let description = fields.next().unwrap_or("").to_ascii_lowercase();
    if description.contains("cancel") {
        CardInteractionError::Cancelled
    } else {
        CardInteractionError::Rejected(code)
    }
}

fn append_percent_decoded(output: &mut Vec<u8>, input: &str) -> Result<(), CardInteractionError> {
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            output.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(CardInteractionError::Protocol(
                "pinentry data has an incomplete percent escape",
            ));
        }
        let high = hex_digit(bytes[index + 1])?;
        let low = hex_digit(bytes[index + 2])?;
        output.push(high << 4 | low);
        index += 3;
    }
    Ok(())
}

fn hex_digit(byte: u8) -> Result<u8, CardInteractionError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(CardInteractionError::Protocol(
            "pinentry data has an invalid percent escape",
        )),
    }
}

fn decode_secret(bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, CardInteractionError> {
    let text =
        std::str::from_utf8(bytes.as_slice()).map_err(|_| CardInteractionError::InvalidEncoding)?;
    Ok(Zeroizing::new(text.to_owned()))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    static NEXT_SCRIPT: AtomicUsize = AtomicUsize::new(0);

    struct TestScript(PathBuf);

    impl TestScript {
        fn new(response: &str) -> Self {
            Self::write(&format!(
                "#!/bin/sh\nprintf '%s\\n' 'OK ready'\nwhile IFS= read -r line; do\ncase \"$line\" in\nGETPIN) printf '%s\\n' '{response}' ;;\nBYE) printf '%s\\n' 'OK bye'; exit 0 ;;\n*) printf '%s\\n' 'OK' ;;\nesac\ndone\n"
            ))
        }

        fn hanging() -> Self {
            Self::write(
                "#!/bin/sh\nprintf '%s\\n' 'OK ready'\nwhile IFS= read -r line; do\n:\ndone\n",
            )
        }

        fn write(script: &str) -> Self {
            let id = NEXT_SCRIPT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "addressee-pinentry-test-{}-{id}.sh",
                std::process::id()
            ));
            fs::write(&path, script).expect("write test pinentry");
            let mut permissions = fs::metadata(&path)
                .expect("test script metadata")
                .permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&path, permissions).expect("test script permissions");
            Self(path)
        }
    }

    impl Drop for TestScript {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn identity() -> CardIdentity {
        CardIdentity::new(0xF1D0, 0x00989ADF, 0x0304)
    }

    #[test]
    fn assuan_decoding_preserves_spaces_plus_and_percent() {
        let decoded = decode_secret(Zeroizing::new(append_decoded_for_test(
            " my+secret%25pass%20",
        )))
        .expect("valid UTF-8");
        assert_eq!(decoded.as_str(), " my+secret%pass ");
    }

    #[test]
    fn malformed_percent_escapes_are_rejected() {
        for input in ["%", "%0", "%GG"] {
            let mut bytes = Vec::new();
            assert!(append_percent_decoded(&mut bytes, input).is_err());
        }
    }

    #[test]
    fn pinentry_protocol_never_logs_the_secret() {
        let script = TestScript::new("D test%20value%25+\nOK");
        let provider = PinEntry::new(&script.0);
        let pin = provider
            .request_pin(PinPurpose::User, &identity())
            .expect("pinentry response");
        assert_eq!(pin.as_str(), "test value%+");
    }

    #[test]
    fn pinentry_cancellation_is_distinct() {
        let script = TestScript::new("ERR 83886179 Operation cancelled");
        let provider = PinEntry::new(&script.0);
        assert!(matches!(
            provider.request_pin(PinPurpose::Admin, &identity()),
            Err(CardInteractionError::Cancelled)
        ));
    }

    #[test]
    fn unresponsive_pinentry_times_out_and_is_cleaned_up() {
        let script = TestScript::hanging();
        let provider = PinEntry::with_timeout(&script.0, Duration::from_millis(20));
        assert!(matches!(
            provider.request_pin(PinPurpose::User, &identity()),
            Err(CardInteractionError::Unavailable(message))
                if message == "pinentry response timed out"
        ));
    }

    #[test]
    fn external_pinentry_smoke() {
        let Some(program) = std::env::var_os("ADDRESSEE_TEST_PINENTRY") else {
            return;
        };
        let provider = PinEntry::with_timeout(program, Duration::from_secs(3));
        let pin = provider
            .request_pin(PinPurpose::Admin, &identity())
            .expect("the explicitly configured test pinentry must respond");
        assert!(!pin.is_empty());
    }

    fn append_decoded_for_test(input: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_percent_decoded(&mut bytes, input).expect("valid encoded data");
        bytes
    }
}
