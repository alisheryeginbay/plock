# plock

Lock yourself out of an account for a while.

`plock` generates a random password, time-lock encrypts it with
[tlock](https://github.com/thibmeu/tlock-rs) against the
[drand quicknet](https://drand.love) beacon, and shows it to you once so you can
set it on the account. Until the unlock time, nobody can decrypt it, including you.

## Install

```sh
cargo install --path .
```

## Usage

```sh
plock new instagram                      # locked for 7 days (default)
plock new instagram --for 2w             # or 36h, 1d 12h, 10s, ...
plock new instagram --until "2026-12-01 09:00"   # local time; a bare date means midnight
plock new                                # name defaults to the current time, e.g. 2026-10-11-195312

plock list                               # every entry, its unlock time and time left
plock open instagram                     # decrypts once the unlock time has passed
```

Password options for `new`: `--length N` (default 32) and `--no-symbols`.

### What `new` does

1. Computes the first drand round at or after the unlock time.
2. Generates the password from lowercase, uppercase, digits and symbols. Look-alike
   characters (`l`, `I`, `O`, `0`, `1`) are left out, and every character class is
   guaranteed to appear.
3. Encrypts it and writes `<name>.age` to disk (fsynced) before showing you anything.
4. Shows the password on the terminal's alternate screen, so it never lands in
   scrollback. It also copies it to the clipboard, marked so that macOS clipboard
   managers don't record it.
5. Asks whether you set it on the account, then asks you to retype (paste) it. If the
   retype fails 3 times, it shows the password again.

Answering **n** deletes the entry. **Ctrl-C** clears the clipboard but keeps the
entry, in case you already changed the password; it prints the `rm` command if you
didn't. The clipboard is cleared once you confirm.

`open` shows the decrypted password the same way and clears the clipboard when you
dismiss it.

## Storage

Entries are standard armored age files in `$PLOCK_DIR`, otherwise
`$XDG_DATA_HOME/plock`, otherwise `~/.local/share/plock`.

There is no backup. **If you lose the file, you lose the password.** The files can
be synced or stored anywhere, because nobody can open them before the unlock time.
After that, anyone with the file can.

Other tlock clients pointed at quicknet (chain hash
`52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`) can decrypt them
too, e.g. [`dee`](https://github.com/thibmeu/drand-rs) or
[`tle`](https://github.com/drand/tlock).

## How it works

drand publishes a BLS signature for each round, every 3 seconds. tlock encrypts to
a *future* round's identity, and that round's signature is the decryption key, so
the ciphertext can't be opened until drand publishes it.

- Encryption is offline. Quicknet's chain info (public key, genesis time, period)
  is built into the binary, so an endpoint can't substitute a different key.
- Decryption fetches the round's beacon from `api.drand.sh`, `drand.cloudflare.com`,
  `api2.drand.sh` or `api3.drand.sh`, and verifies it against the built-in public key.

You're trusting that the drand league of entities doesn't collude to publish
signatures early. Neither tlock-rs nor this tool has been audited.

## Development

```sh
cargo test                    # offline tests
cargo test -- --ignored       # encrypt/decrypt round-trip against live drand
```
