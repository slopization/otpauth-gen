# otpauth-gen

otpauth-gen reads one TOTP credential and writes one one-time code to standard output.

## Build

Run `cargo build --release`. The binary is at `target/release/otpauth-gen`. Copy the binary to a directory in `PATH`. The program uses `clap` for the command line and `totp_rfc6238` for the code.

## Use

Send the credential to the tool on standard input.

```sh
printf 'secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' | otpauth-gen
```

The tool writes the code and one newline to standard output. It writes errors to standard error. It writes nothing to standard output after an error. For a plain credential, the tool stops with an error if standard input is a terminal.

## The credential file

Put one credential in one file. The name of the file is the name of the account. Keep the directory private, with mode 700.

```sh
mkdir -m 700 ~/.otp
printf 'secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n' > ~/.otp/github
chmod 600 ~/.otp/github
otpauth-gen ~/.otp/github
```

A credential has one required key, `secret`. It has four optional keys: `algorithm`, `digits`, `period`, and `type`. The value of `secret` is a base32 string. The tool ignores spaces, letter case, and `=` padding in the secret.

```
# a comment
secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
algorithm=SHA256
digits=8
period=60
```

If you omit `algorithm`, the tool uses SHA1. If you omit `digits`, the tool uses 6 digits. If you omit `period`, the tool uses 30 seconds. The value of `digits` must be 6 or 8. The value of `algorithm` must be SHA1, SHA256, or SHA512. The value of `type` must be `totp`. An unknown key or a duplicate key is an error.

## Other input forms

The tool also accepts an `otpauth://` URI. Put the URI in the file or in the pipe. The tool ignores the label and the `issuer` parameter, because the file name is the name of the account.

```sh
printf 'otpauth://totp/GitHub:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' | otpauth-gen
```

The tool also accepts one bare base32 string. This form uses SHA1, 6 digits, and 30 seconds.

## Decryption

The tool has no encryption code. It starts `gpg` or `age` and reads the plaintext from that program. Use `--gpg` for gpg and `--age` for age.

```sh
otpauth-gen --gpg ~/.otp/github.gpg
otpauth-gen --age -i ~/.age/identity.txt ~/.otp/github.age
age -d ~/.otp/github.age | otpauth-gen
```

The decryptor gets the encrypted bytes on its standard input. The decryptor gets the terminal for its password prompt. A failed decryptor stops the tool before any code is written.

For another tool, use a pipe.

```sh
openssl enc -d -in github.enc | otpauth-gen
```

## Security

A plain file is readable by every process that runs as you. A backup program and a search command also read it. Encrypt the file at rest with `gpg` or `age`.

The tool refuses a plain file that other users can read. Run `chmod 600` on the file after the message. The tool does not test the mode of an encrypted file.

The secret never goes on the command line. The tool has no flag for a password or a key. The code is the only output on standard output.

## Exit status

The tool exits with 0 after it writes a code. It exits with 2 after an error. A failure writes nothing to standard output.

## Tests

`--now EPOCH` replaces the system clock. The tests use this flag to get known codes. Run `cargo test` to run the tests. Do not use this flag to log in.

## Limits

The tool makes TOTP codes only. It rejects HOTP input because HOTP needs a counter. The tool keeps no state and writes no file. The input must be 64 KiB or smaller. A secret must have 10 bytes or more.
