use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_otpauth-gen");
const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn run_with(command: &mut Command, input: &str) -> (i32, String, String) {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn otpauth-gen");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(input.as_bytes())
        .expect("write standard input");
    let output = child.wait_with_output().expect("wait for otpauth-gen");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn run(args: &[&str], input: &str) -> (i32, String, String) {
    let mut command = Command::new(BIN);
    command.args(args);
    run_with(&mut command, input)
}

fn run_with_path(args: &[&str], input: &str, dir: &Path) -> (i32, String, String) {
    let mut path = dir.as_os_str().to_os_string();
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    let mut command = Command::new(BIN);
    command.args(args).env("PATH", path);
    run_with(&mut command, input)
}

fn credential(digits: usize) -> String {
    format!("secret={SECRET}\ndigits={digits}\n")
}

#[test]
fn writes_one_code_to_stdout() {
    let (status, stdout, stderr) = run(&["--now", "59"], &credential(8));
    assert_eq!(status, 0, "stderr: {stderr}");
    assert_eq!(stdout, "94287082\n");
    assert_eq!(stderr, "");
}

#[test]
fn uri_input_matches_file_input() {
    let uri = format!("otpauth://totp/x?secret={SECRET}&digits=8");
    let (status, stdout, stderr) = run(&["--now", "59"], &uri);
    assert_eq!(status, 0, "stderr: {stderr}");
    assert_eq!(stdout, "94287082\n");
}

#[test]
fn bad_input_exits_two_with_empty_stdout() {
    let (status, stdout, stderr) = run(&["--now", "59"], "digit=8\n");
    assert_eq!(status, 2);
    assert_eq!(stdout, "");
    assert!(stderr.contains("unknown key"), "stderr: {stderr}");
}

#[test]
fn writes_only_the_code_for_a_long_stream() {
    let text = format!("# comment\n\n{}\n", credential(8));
    let (status, stdout, _) = run(&["--now", "59"], &text);
    assert_eq!(status, 0);
    assert_eq!(stdout.len(), 9, "the code and one newline");
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn temp_file(name: &str, body: &str, mode: u32) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("otpauth-gen-{}-{name}", std::process::id()));
        fs::write(&path, body).expect("write the temporary file");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("set the mode");
        path
    }

    fn temp_dir(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("otpauth-gen-{}-{name}-dir", std::process::id()));
        path
    }

    fn fake_gpg(dir: &Path, body: &str) {
        fs::create_dir_all(dir).expect("create the temporary directory");
        let path = dir.join("gpg");
        fs::write(&path, body).expect("write the fake gpg");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("set the mode");
    }

    #[test]
    fn warns_about_a_plaintext_file_that_others_can_read() {
        let path = temp_file("loose", &credential(8), 0o644);
        let (status, stdout, stderr) = run(&["--now", "59", path.to_str().unwrap()], "");
        let _ = fs::remove_file(&path);
        assert_eq!(status, 0);
        assert_eq!(stdout, "94287082\n");
        assert!(stderr.contains("plaintext"), "stderr: {stderr}");
        assert!(stderr.contains("0644"), "stderr: {stderr}");
        assert!(!stderr.contains("chmod"), "stderr: {stderr}");
    }

    #[test]
    fn reads_a_private_file_by_path() {
        let path = temp_file("tight", &credential(8), 0o600);
        let (status, stdout, stderr) = run(&["--now", "59", path.to_str().unwrap()], "");
        let _ = fs::remove_file(&path);
        assert_eq!(status, 0, "stderr: {stderr}");
        assert_eq!(stdout, "94287082\n");
        assert!(stderr.contains("plaintext"), "stderr: {stderr}");
        assert!(!stderr.contains("0644"), "stderr: {stderr}");
    }

    #[test]
    fn decryptor_receives_the_ciphertext_on_stdin() {
        let dir = temp_dir("good");
        fake_gpg(&dir, "#!/bin/sh\ncat\n");
        let (status, stdout, stderr) =
            run_with_path(&["--gpg", "--now", "59"], &credential(8), &dir);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(status, 0, "stderr: {stderr}");
        assert_eq!(stdout, "94287082\n");
    }

    #[test]
    fn a_failed_decryptor_writes_no_code() {
        let dir = temp_dir("bad");
        fake_gpg(&dir, "#!/bin/sh\nexit 3\n");
        let (status, stdout, stderr) =
            run_with_path(&["--gpg", "--now", "59"], &credential(8), &dir);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(status, 2);
        assert_eq!(stdout, "");
        assert!(stderr.contains("gpg failed"), "stderr: {stderr}");
    }

    #[test]
    fn encrypted_input_skips_the_mode_check() {
        let dir = temp_dir("perm");
        fake_gpg(&dir, "#!/bin/sh\ncat\n");
        let path = temp_file("cipher", &credential(8), 0o644);
        let (status, stdout, stderr) =
            run_with_path(&["--gpg", "--now", "59", path.to_str().unwrap()], "", &dir);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(status, 0, "stderr: {stderr}");
        assert_eq!(stdout, "94287082\n");
    }
}
