# oat

Local, encrypted one-time passwords in your terminal.

`oat` stores your TOTP secrets in a single file sealed with XChaCha20-Poly1305.
The encryption key lives in your OS keychain and is recoverable with a master
password. Nothing leaves the machine. If anything other than `oat` changes the
vault file, `oat` tells you the next time you open it.

## Install

```
go install github.com/AbhinavMir/oat@latest
```

Or build from source:

```
go build -o oat .
```

## Use

```
oat                 open the vault browser
oat add google.com  add an account (asks for username + secret)
oat add d u secret  add without prompts
oat ls              list accounts
oat get github      print and copy the current code for a match
oat rm github       remove an account
```

The secret can be a raw base32 string (`JBSWY3DPEHPK3PXP`) or a full
`otpauth://totp/...` URI.

In the browser: `/` search, `c` copy, `a` add, `x` delete, `q` quit.

## Where things live

- `~/.config/oat/vault.enc` — the sealed vault
- `~/.config/oat/meta.json` — the authenticated integrity record

Set `OAT_DIR` to move them. Set `OAT_PASSWORD` to run non-interactively.

## How it protects your secrets

- Secrets are encrypted at rest with XChaCha20-Poly1305.
- The data key is wrapped by an Argon2id key derived from your master password,
  and cached in the OS keychain so you only type the password when the keychain
  can't answer.
- Every write records an HMAC of the file keyed by the data key. On open, `oat`
  recomputes it; a mismatch means the file was changed by something else, and it
  says so.
