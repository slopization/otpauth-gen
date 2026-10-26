# otpauth-gen

otpauth-gen reads one TOTP credential and writes one one-time code to standard output.

## Build

Run `cargo build --release`. The binary is at `target/release/otpauth-gen`. Copy the binary to a directory in `PATH`. The program uses `clap` for the command line and `totp_rfc6238` for the code.

## Use

A credential is usually a full `otpauth://` URI. The tool reads it from standard input. Read the URI with no echo, and send it to the tool.

```console
$ read -rsp 'otpauth URI: ' uri; echo; printf '%s\n' "$uri" | otpauth-gen
otpauth URI: 
287082
```

Paste the URI after the prompt, and it does not appear on the screen. `-s` turns off the echo. `-p` sets the prompt, and it needs bash. `read` sets a variable and writes nothing to standard output, so the `printf` line sends the value.

`read` runs before the pipe. A pipeline runs in a subshell in bash, so a variable that `read` sets inside a pipe is lost.

The tool writes the code and one newline to standard output. It writes errors to standard error. It writes nothing to standard output after an error. For a plain credential, the tool stops with an error if standard input is a terminal.

## The credential file

Put one credential in one file. The name of the file is the name of the account. Keep the directory private, with mode 700. The file can hold the full URI. The tool ignores the label and the `issuer` parameter, because the file name is the name of the account. The compact form below is also accepted.

```sh
mkdir -m 700 ~/.otp
printf 'secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n' > ~/.otp/github
chmod 600 ~/.otp/github
otpauth-gen ~/.otp/github
```

The secret in this example is the public test secret from RFC 6238. Do not use it for a real account.

A credential has one required key, `secret`. It has four optional keys: `algorithm`, `digits`, `period`, and `type`. The value of `secret` is a base32 string. The tool ignores spaces, letter case, and `=` padding in the secret.

```
# a comment
secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
algorithm=SHA256
digits=8
period=60
```

If you omit `algorithm`, the tool uses SHA1. If you omit `digits`, the tool uses 6 digits. If you omit `period`, the tool uses 30 seconds. The value of `digits` must be 6 or 8. The value of `algorithm` must be SHA1, SHA256, or SHA512. The value of `type` must be `totp`. An unknown key or a duplicate key is an error.

## Store the secret

The example above stores the test secret in plaintext. For a real store, keep the encrypted form in the same directory.

Do not type the credential as a command argument. The shell writes the command line to its history file, and `ps` can show the line to other users.

```sh
read -rsp 'otpauth URI: ' uri; echo; printf '%s\n' "$uri" | age -p > ~/.otp/github.age
```

`age -p` asks for a passphrase and needs no key file. `age -e -r` uses a public key from `age-keygen`, and `gpg -e -r RECIPIENT` uses a gpg key. Keep the identity file and the gpg secret key outside `~/.otp`.

Read the passphrase file with `otpauth-gen --age ~/.otp/github.age`. Read the gpg file with `otpauth-gen --gpg ~/.otp/github.gpg`. An identity file needs `-i PATH`.

An editor that writes its buffer to a program is another way to enter the URI. Vim and Neovim do this with `:w !otpauth-gen`. Start Vim with `-n -i NONE` so it keeps no swap file and no viminfo file. Type the URI, run `:w !otpauth-gen`, and quit with `:q!`. The code appears in the message area of the editor. Nano cannot write its buffer to a program.

Do not put a plain file in a git repository. An encrypted file does not expose the secret. Keep the identity file out of the repository.

## Bare secrets

The tool also accepts one bare base32 secret. This form uses SHA1, 6 digits, and 30 seconds. If you have the URI, use it instead.

## Decryption

The tool has no encryption code. It starts `gpg` or `age` and reads the plaintext from that program. Use `--gpg` for gpg and `--age` for age.

```sh
otpauth-gen --gpg ~/.otp/github.gpg
otpauth-gen --age -i ~/.age/key.txt ~/.otp/github.age
age -d ~/.otp/github.age | otpauth-gen
```

The decryptor gets the encrypted bytes on its standard input. The decryptor gets the terminal for its password prompt. A failed decryptor stops the tool before any code is written.

For another tool, use a pipe.

```sh
openssl enc -d -in github.enc | otpauth-gen
```

## Security

A plain file keeps the secret without encryption. A backup program, a search command, and every process that runs as you can read it. Encrypt the file at rest with `gpg` or `age`.

The tool warns when it reads a plain file. The warning gives the path and the risk. The tool does not refuse the file and does not change it. The tool does not test the mode of an encrypted file.

The secret never goes on the command line. The tool has no flag for a password or a key. The code is the only output on standard output.

## Exit status

The tool exits with 0 after it writes a code. It exits with 2 after an error. A failure writes nothing to standard output.

## Tests

`--now EPOCH` replaces the system clock. The tests use this flag to get known codes. Run `cargo test` to run the tests. Do not use this flag to log in.

## Limits

The tool makes TOTP codes only. It rejects HOTP input because HOTP needs a counter. The tool keeps no state and writes no file. The input must be 64 KiB or smaller. A secret must have 10 bytes or more.
