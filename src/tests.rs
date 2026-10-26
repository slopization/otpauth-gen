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
        (SEED_SHA1, "SHA1", "94287082"),
        (SEED_SHA256, "SHA256", "46119246"),
        (SEED_SHA512, "SHA512", "90693936"),
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
