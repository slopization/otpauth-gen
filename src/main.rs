//! Read one TOTP credential and write one one-time code to standard output.

use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::process::{self, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use totp_rfc6238::high_level::TotpBuilder;
use totp_rfc6238::oath_uri::key_from_base32;
use totp_rfc6238::{HashAlgorithm, TotpGenerator};
use zeroize::Zeroizing;

/// Largest credential that the tool will read. A credential is a few lines.
const MAX_INPUT: u64 = 64 * 1024;

/// Shortest key that the tool accepts, in bytes. 80 bits is the legacy floor.
const MIN_KEY_LEN: usize = 10;

/// Keys that the `key=value` form knows.
const KNOWN_KEYS: [&str; 5] = ["secret", "algorithm", "digits", "period", "type"];

/// URI parameters that do not change the code and are safe to ignore.
const IGNORED_URI_KEYS: [&str; 3] = ["issuer", "image", "counter"];

#[derive(Debug, Parser)]
#[command(
    name = "otpauth-gen",
    version,
    about = "Read one TOTP credential and write one one-time code to standard output.",
    after_help = "The credential can be an otpauth:// URI, a key=value block, or one bare
base32 secret. Standard input is the default source."
)]
struct Cli {
    /// Decrypt the input with gpg.
    #[arg(long)]
    gpg: bool,

    /// Decrypt the input with age.
    #[arg(long, conflicts_with = "gpg")]
    age: bool,

    /// Use this identity file with age. Requires --age.
    #[arg(short = 'i', long, value_name = "PATH", requires = "age")]
    identity: Option<String>,

    /// Use this Unix time instead of the system clock. For tests.
    #[arg(long, value_name = "EPOCH")]
    now: Option<u64>,

    /// Read the credential from this file. Use - for standard input.
    #[arg(value_name = "FILE", default_value = "-")]
    file: String,
}

#[derive(Debug)]
struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Error(message.into())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error(error.to_string())
    }
}

type Result<T> = std::result::Result<T, Error>;

fn main() {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => {
            if let Err(error) = write_code(&code) {
                eprintln!("otpauth-gen: {error}");
                process::exit(2);
            }
        }
        Err(error) => {
            eprintln!("otpauth-gen: {error}");
            process::exit(2);
        }
    }
}

fn run(cli: &Cli) -> Result<String> {
    let raw = read_input(cli)?;
    let text = std::str::from_utf8(&raw).map_err(|_| Error::new("input is not valid UTF-8"))?;
    let (builder, key) = parse(text)?;
    let now = match cli.now {
        Some(now) => now,
        None => current_time()?,
    };
    Ok(builder.build().get_code_with(&key, || now))
}

fn read_input(cli: &Cli) -> Result<Zeroizing<Vec<u8>>> {
    if cli.gpg || cli.age {
        read_decrypted(cli)
    } else {
        read_plaintext(&cli.file)
    }
}

fn read_plaintext(file: &str) -> Result<Zeroizing<Vec<u8>>> {
    if file == "-" {
        if io::stdin().is_terminal() {
            return Err(Error::new(
                "standard input is a terminal; give a FILE or pipe a credential",
            ));
        }
        read_all(io::stdin().lock(), "standard input")
    } else {
        eprintln!("otpauth-gen: warning: {}", plaintext_file_warning(file));
        let handle =
            fs::File::open(file).map_err(|e| Error::new(format!("cannot open {file}: {e}")))?;
        read_all(handle, file)
    }
}

fn read_decrypted(cli: &Cli) -> Result<Zeroizing<Vec<u8>>> {
    let (program, mut command) = if cli.gpg {
        let mut command = Command::new("gpg");
        command.arg("--quiet").arg("--decrypt");
        ("gpg", command)
    } else {
        let mut command = Command::new("age");
        command.arg("-d");
        if let Some(identity) = &cli.identity {
            command.arg("-i").arg(identity);
        }
        ("age", command)
    };

    if cli.file == "-" {
        command.stdin(Stdio::inherit());
    } else {
        let handle = fs::File::open(&cli.file)
            .map_err(|e| Error::new(format!("cannot open {}: {e}", cli.file)))?;
        command.stdin(Stdio::from(handle));
    }

    command.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let mut child = command
        .spawn()
        .map_err(|e| Error::new(format!("cannot run {program}: {e}")))?;

    let mut buffer = Zeroizing::new(Vec::new());
    {
        let mut stdout = child.stdout.take().expect("stdout is piped");
        stdout
            .by_ref()
            .take(MAX_INPUT + 1)
            .read_to_end(&mut buffer)
            .map_err(|e| Error::new(format!("cannot read output of {program}: {e}")))?;
    }

    if buffer.len() as u64 > MAX_INPUT {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::new(format!(
            "output of {program} is larger than 64 KiB"
        )));
    }

    let status = child
        .wait()
        .map_err(|e| Error::new(format!("cannot wait for {program}: {e}")))?;
    if !status.success() {
        return Err(Error::new(format!("{program} failed with {status}")));
    }

    Ok(buffer)
}

fn read_all<R: Read>(mut reader: R, what: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut buffer = Zeroizing::new(Vec::new());
    reader
        .by_ref()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut buffer)
        .map_err(|e| Error::new(format!("cannot read {what}: {e}")))?;
    if buffer.len() as u64 > MAX_INPUT {
        return Err(Error::new(format!("{what} is larger than 64 KiB")));
    }
    Ok(buffer)
}

#[cfg(unix)]
fn plaintext_file_warning(file: &str) -> String {
    use std::os::unix::fs::PermissionsExt;

    let mut message = format!("{file}: the secret is stored in plaintext");
    if let Ok(metadata) = fs::metadata(file) {
        if metadata.file_type().is_file() {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                message.push_str(&format!(" and other users can read it (mode {mode:04o})"));
            }
        }
    }
    message.push('.');
    message
}

#[cfg(not(unix))]
fn plaintext_file_warning(file: &str) -> String {
    format!("{file}: the secret is stored in plaintext.")
}

fn parse(text: &str) -> Result<(TotpBuilder, Zeroizing<Vec<u8>>)> {
    let text = text.trim_start_matches('\u{feff}');

    let mut body: Vec<(usize, &str)> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        body.push((index + 1, line));
    }

    let Some(&(_, first)) = body.first() else {
        return Err(Error::new("empty credential"));
    };

    if first.starts_with("otpauth://") {
        if body.len() > 1 {
            return Err(Error::new(format!(
                "line {}: more than one credential in the input",
                body[1].0
            )));
        }
        return parse_uri(first);
    }

    if body.len() == 1 {
        return parse_single_line(body[0]);
    }

    parse_key_value(&body)
}

fn parse_uri(uri: &str) -> Result<(TotpBuilder, Zeroizing<Vec<u8>>)> {
    let rest = uri
        .strip_prefix("otpauth://")
        .ok_or_else(|| Error::new("the URI must start with otpauth://"))?;

    let (path, query) = match rest.split_once('?') {
        Some((path, query)) => (path, query),
        None => (rest, ""),
    };
    let (kind, _label) = match path.split_once('/') {
        Some((kind, label)) => (kind, label),
        None => (path, ""),
    };

    if kind.eq_ignore_ascii_case("hotp") {
        return Err(Error::new(
            "the URI is HOTP; otpauth-gen keeps no counter, so it makes TOTP codes only",
        ));
    }
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(Error::new("the URI type is not totp"));
    }

    let mut fields = Fields::new("the URI");
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        let name = raw_key.trim().to_ascii_lowercase();
        if IGNORED_URI_KEYS.contains(&name.as_str()) {
            continue;
        }
        let value = percent_decode(raw_value)?;
        fields.set("the URI", &name, &value)?;
    }
    fields.finish()
}

fn parse_single_line((number, line): (usize, &str)) -> Result<(TotpBuilder, Zeroizing<Vec<u8>>)> {
    if let Some((raw_key, _)) = line.split_once('=') {
        let name = raw_key.trim().to_ascii_lowercase();
        if KNOWN_KEYS.contains(&name.as_str()) {
            return parse_key_value(&[(number, line)]);
        }
        // A padded base32 secret contains "=" too. Try it before you reject it.
        if let Ok(key) = decode_secret(line) {
            return default_shape(key);
        }
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(Error::new(format!("line {number}: unknown key {name:?}")));
        }
        return Err(Error::new(format!("line {number}: not a TOTP credential")));
    }

    let key = decode_secret(line).map_err(|_| {
        Error::new(format!(
            "line {number}: not a TOTP credential; expected base32, key=value, or otpauth://"
        ))
    })?;
    default_shape(key)
}

fn parse_key_value(lines: &[(usize, &str)]) -> Result<(TotpBuilder, Zeroizing<Vec<u8>>)> {
    let mut fields = Fields::new("the credential");

    for &(number, line) in lines {
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            return Err(Error::new(format!("line {number}: expected key=value")));
        };
        let place = format!("line {number}");
        fields.set(&place, raw_key, raw_value)?;
    }

    fields.finish()
}

/// The keys that a credential can set, collected from any input form.
struct Fields {
    place: String,
    secret: Option<Zeroizing<Vec<u8>>>,
    digits: Option<usize>,
    period: Option<u64>,
    algorithm: Option<HashAlgorithm>,
    seen: Vec<String>,
}

impl Fields {
    fn new(place: impl Into<String>) -> Self {
        Fields {
            place: place.into(),
            secret: None,
            digits: None,
            period: None,
            algorithm: None,
            seen: Vec::new(),
        }
    }

    fn set(&mut self, place: &str, raw_key: &str, raw_value: &str) -> Result<()> {
        let name = raw_key.trim().to_ascii_lowercase();
        let value = raw_value.trim();

        if !KNOWN_KEYS.contains(&name.as_str()) {
            return Err(Error::new(format!("{place}: unknown key {name:?}")));
        }
        if self.seen.contains(&name) {
            return Err(Error::new(format!("{place}: duplicate key {name:?}")));
        }
        self.seen.push(name.clone());

        match name.as_str() {
            "secret" => {
                if value.is_empty() {
                    return Err(Error::new(format!("{place}: the secret is empty")));
                }
                self.secret = Some(decode_secret(value)?);
            }
            "algorithm" => self.algorithm = Some(parse_algorithm(place, value)?),
            "digits" => {
                self.digits = Some(
                    value
                        .parse()
                        .map_err(|_| Error::new(format!("{place}: digits must be 6 or 8")))?,
                );
            }
            "period" => {
                self.period = Some(value.parse().map_err(|_| {
                    Error::new(format!("{place}: period must be a number of seconds"))
                })?);
            }
            "type" => {
                if value.eq_ignore_ascii_case("hotp") {
                    return Err(Error::new(format!(
                        "{place}: HOTP is not supported; otpauth-gen makes TOTP codes only"
                    )));
                }
                if !value.eq_ignore_ascii_case("totp") {
                    return Err(Error::new(format!("{place}: type must be totp")));
                }
            }
            _ => unreachable!("the key is checked above"),
        }
        Ok(())
    }

    fn finish(self) -> Result<(TotpBuilder, Zeroizing<Vec<u8>>)> {
        let place = self.place;
        let key = self
            .secret
            .ok_or_else(|| Error::new(format!("{place}: missing secret")))?;
        check_key(&key)?;
        let digits = self.digits.unwrap_or(6);
        let period = self.period.unwrap_or(30);
        let algorithm = self.algorithm.unwrap_or(HashAlgorithm::SHA1);
        Ok((make_builder(digits, period, algorithm)?, key))
    }
}

fn percent_decode(raw: &str) -> Result<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(Error::new("the URI has a broken percent escape"));
            }
            let high = hex_value(bytes[index + 1])?;
            let low = hex_value(bytes[index + 2])?;
            out.push((high << 4) | low);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).map_err(|_| Error::new("the URI is not valid UTF-8"))
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::new("the URI has a broken percent escape")),
    }
}

fn decode_secret(raw: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut encoded: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    while encoded.ends_with('=') {
        encoded.pop();
    }
    if encoded.is_empty() {
        return Err(Error::new("the secret is empty"));
    }
    if !encoded.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(Error::new("the secret is not base32"));
    }
    let key =
        key_from_base32(encoded).map_err(|e| Error::new(format!("bad base32 secret: {e}")))?;
    Ok(Zeroizing::new(key))
}

fn parse_algorithm(place: &str, value: &str) -> Result<HashAlgorithm> {
    if value.eq_ignore_ascii_case("SHA1") {
        Ok(HashAlgorithm::SHA1)
    } else if value.eq_ignore_ascii_case("SHA256") {
        Ok(HashAlgorithm::SHA256)
    } else if value.eq_ignore_ascii_case("SHA512") {
        Ok(HashAlgorithm::SHA512)
    } else {
        Err(Error::new(format!(
            "{place}: algorithm must be SHA1, SHA256, or SHA512"
        )))
    }
}

fn check_key(key: &[u8]) -> Result<()> {
    if key.len() < MIN_KEY_LEN {
        return Err(Error::new(format!(
            "the secret is {} bytes; 10 or more are required",
            key.len()
        )));
    }
    Ok(())
}

fn check_shape(digits: usize, period: u64) -> Result<()> {
    if digits != 6 && digits != 8 {
        return Err(Error::new("digits must be 6 or 8"));
    }
    if period == 0 {
        return Err(Error::new("period must be one second or more"));
    }
    Ok(())
}

fn make_builder(digits: usize, period: u64, algorithm: HashAlgorithm) -> Result<TotpBuilder> {
    check_shape(digits, period)?;
    let builder = TotpGenerator::new()
        .set_digit(digits)
        .map_err(|_| Error::new("digits must be 6 or 8"))?
        .set_step(period)
        .map_err(|_| Error::new("period must be one second or more"))?;
    Ok(builder.set_hash_algorithm(algorithm))
}

fn default_shape(key: Zeroizing<Vec<u8>>) -> Result<(TotpBuilder, Zeroizing<Vec<u8>>)> {
    check_key(&key)?;
    Ok((make_builder(6, 30, HashAlgorithm::SHA1)?, key))
}

fn current_time() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Error::new("the system clock is before the Unix epoch"))
}

fn write_code(code: &str) -> Result<()> {
    let mut stdout = io::stdout().lock();
    let result = stdout
        .write_all(code.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush());
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(Error::new(format!("cannot write the code: {error}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use totp_rfc6238::oath_uri::key_to_base32_uppercase;

    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    fn b32(key: &[u8]) -> String {
        key_to_base32_uppercase(key.to_vec())
    }

    fn code(text: &str, now: u64) -> Result<String> {
        let (builder, key) = parse(text)?;
        Ok(builder.build().get_code_with(&key, || now))
    }

    fn rejects(text: &str) -> String {
        match parse(text) {
            Ok(_) => panic!("expected an error for {text:?}"),
            Err(error) => error.to_string(),
        }
    }

    fn key_value(seed: &[u8], algorithm: &str) -> String {
        format!("secret={}\nalgorithm={}\ndigits=8\n", b32(seed), algorithm)
    }

    #[test]
    fn rfc6238_vectors() {
        let cases = [
            (&SEED_SHA1, "SHA1", "94287082"),
            (&SEED_SHA256, "SHA256", "46119246"),
            (&SEED_SHA512, "SHA512", "90693936"),
        ];
        for (seed, algorithm, expected) in cases {
            assert_eq!(
                code(&key_value(seed, algorithm), 59).expect("the code"),
                expected,
                "{algorithm} at T=59"
            );
        }

        assert_eq!(
            code(&key_value(SEED_SHA1, "SHA1"), 1_111_111_109).expect("the code"),
            "07081804",
            "the code must keep its leading zero"
        );
        assert_eq!(
            code(&key_value(SEED_SHA1, "SHA1"), 20_000_000_000).expect("the code"),
            "65353130"
        );
    }

    #[test]
    fn uri_without_issuer_works() {
        let uri = format!("otpauth://totp/alice?secret={}", b32(SEED_SHA1));
        assert_eq!(code(&uri, 59).expect("the code"), "287082");
    }

    #[test]
    fn uri_matches_the_key_value_form() {
        let uri = format!(
            "otpauth://totp/Example:alice?secret={}&issuer=Example&algorithm=SHA256&digits=8&period=60",
            b32(SEED_SHA256)
        );
        let file = format!(
            "secret={}\nalgorithm=SHA256\ndigits=8\nperiod=60\n",
            b32(SEED_SHA256)
        );
        assert_eq!(
            code(&uri, 1_111_111_109).expect("the code"),
            code(&file, 1_111_111_109).expect("the code")
        );
    }

    #[test]
    fn uri_ignores_label_and_extra_parameters() {
        let plain = format!("otpauth://totp/x?secret={}", b32(SEED_SHA1));
        let decorated = format!(
            "otpauth://totp/Example%20Inc:alice?secret={}&issuer=Example&image=https%3A%2F%2Fx&counter=0",
            b32(SEED_SHA1)
        );
        assert_eq!(
            code(&plain, 59).expect("the code"),
            code(&decorated, 59).expect("the code")
        );
    }

    #[test]
    fn bare_secret_accepts_spaces_case_and_padding() {
        let plain = format!("secret={}", b32(SEED_SHA1));
        let padded = format!("{}====", b32(SEED_SHA1).to_lowercase());
        for form in [
            padded,
            "gezd gnbv gy3t qojq gezd gnbv gy3t qojq".to_string(),
        ] {
            let got = code(&form, 59).expect("the code");
            let want = code(&plain, 59).expect("the code");
            assert_eq!(got, want, "form {form:?}");
        }
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let text = format!(
            "# my account\n\nsecret={}\n\n# trailing note\n",
            b32(SEED_SHA1)
        );
        assert_eq!(code(&text, 59).expect("the code"), "287082");
    }

    #[test]
    fn rejects_bad_input() {
        let secret = b32(SEED_SHA1);

        assert!(rejects(&format!("otpauth://hotp/x?secret={secret}&counter=0")).contains("HOTP"));
        assert!(rejects(&format!("secret={secret}\ntype=hotp")).contains("not supported"));
        assert!(rejects(&format!("secret={secret}\ndigit=8")).contains("unknown key"));
        assert!(rejects(&format!("secret={secret}\nsecret={secret}")).contains("duplicate"));
        assert!(rejects(&format!("secret={secret}\ndigits=7")).contains("6 or 8"));
        assert!(rejects(&format!("secret={secret}\nperiod=0")).contains("period"));
        assert!(rejects(&format!("otpauth://totp/x?secret={secret}&foo=1")).contains("unknown key"));
        assert!(rejects("").contains("empty"));
        assert!(rejects(&format!("= {secret}")).contains("not a TOTP credential"));
        assert!(rejects("GEZDGNBV").contains("10 or more"));
        assert!(rejects(&format!(
            "otpauth://totp/x?secret={secret}\notpauth://totp/y?secret={secret}"
        ))
        .contains("more than one"));

        let stray = rejects(&format!("secret={secret}\nJBSWY3DPEHPK3PXP"));
        assert!(
            !stray.contains("JBSWY3DPEHPK3PXP"),
            "the error echoed the input"
        );
    }

    #[test]
    fn percent_encoded_secret_is_decoded() {
        let encoded = b32(SEED_SHA1);
        let uri = format!("otpauth://totp/x?secret={encoded}%3D");
        let plain = format!("secret={encoded}");
        assert_eq!(
            code(&uri, 59).expect("the code"),
            code(&plain, 59).expect("the code")
        );
    }
}
