use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, execute};
use drand_core::HttpClient;
use drand_core::chain::{ChainInfo, ChainOptions, ChainVerification};
use jiff::tz::TimeZone;
use jiff::{SpanRound, Timestamp, Unit, Zoned};
use zeroize::Zeroizing;

/// drand quicknet: unchained, 3s period. Pinned so encryption works offline and
/// a malicious endpoint can't hand us a different public key.
const QUICKNET_INFO: &str = r#"{
    "public_key": "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
    "period": 3,
    "genesis_time": 1692803367,
    "hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    "groupHash": "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e",
    "schemeID": "bls-unchained-g1-rfc9380",
    "metadata": { "beaconID": "quicknet" }
}"#;

const DRAND_ENDPOINTS: &[&str] = &[
    "https://api.drand.sh",
    "https://drand.cloudflare.com",
    "https://api2.drand.sh",
    "https://api3.drand.sh",
];

const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &[u8] = b"23456789";
const SYMBOLS: &[u8] = b"!@#$%^&*-_=+?";

const RETYPE_ATTEMPTS: usize = 3;

#[derive(Parser)]
#[command(about = "Generate passwords that stay time-locked (via drand tlock) until a chosen moment")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new password and time-lock it
    New {
        /// Name for this entry, e.g. "instagram"
        name: String,
        /// Lock duration, e.g. 7d, 2w, 36h
        #[arg(long = "for", default_value = "7d", conflicts_with = "until")]
        duration: String,
        /// Lock until a local date/time, e.g. "2026-10-20 09:00" or 2026-10-20
        #[arg(long)]
        until: Option<String>,
        /// Password length
        #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u16).range(8..=256))]
        length: u16,
        /// Only letters and digits
        #[arg(long)]
        no_symbols: bool,
    },
    /// List entries and when they unlock
    List,
    /// Decrypt an entry if its time has come
    Open { name: String },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::New { name, duration, until, length, no_symbols } => {
            cmd_new(&name, &duration, until.as_deref(), length.into(), no_symbols)
        }
        Cmd::List => cmd_list(),
        Cmd::Open { name } => cmd_open(&name),
    }
}

// ---------------------------------------------------------------- commands

fn cmd_new(name: &str, duration: &str, until: Option<&str>, length: usize, no_symbols: bool) -> Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        bail!("`new` needs an interactive terminal");
    }
    let path = entry_path(name)?;
    if path.exists() {
        bail!("{} already exists", path.display());
    }

    let unlock_at = match until {
        Some(s) => parse_until(s)?,
        None => parse_duration(duration)?,
    };
    if unlock_at <= Zoned::now() {
        bail!("unlock time must be in the future");
    }

    let info = quicknet();
    let round = round_at(&info, unlock_at.timestamp());
    let unlock_at = round_time(&info, round).to_zoned(TimeZone::system());

    let password = generate_password(length, !no_symbols)?;

    let mut armored = tlock_age::armor::ArmoredWriter::wrap_output(vec![])?;
    tlock_age::encrypt(&mut armored, password.as_bytes(), &info.hash(), &info.public_key(), round)?;
    let ciphertext = armored.finish()?;

    // Sanity check: the header we just wrote must point at the round we chose.
    let header = tlock_age::decrypt_header(ciphertext.as_slice())?;
    if header.round() != round || header.hash() != info.hash() {
        bail!("internal error: encrypted header does not match the requested round");
    }

    write_durably(&path, &ciphertext)?;

    println!("Saved {}", path.display());
    println!("Locked until {} (drand round {round})", fmt_time(&unlock_at));
    println!();
    println!("Next: the password is shown full-screen and copied to the clipboard.");
    println!("Set it on the account, come back and press Enter.");
    println!();
    wait_key("Press Enter to reveal...")?.or_abort(|| abort_new(&path, None))?;

    let mut clip = Clip::new();
    loop {
        clip.set(&password);
        let shown = reveal(&password, &format!(
            "Set this as the new password for \"{name}\"{}.\n\nPress Enter when done, Ctrl-C to abort.",
            if clip.ok { " (it's on your clipboard)" } else { "" }
        ))?;
        if shown == Key::Abort {
            return abort_new(&path, Some(&mut clip));
        }

        match confirm("Did you set it on the account? [y/n] ")? {
            Some(true) => {}
            Some(false) => {
                clip.clear();
                fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
                println!("Deleted {}. Nothing is locked.", path.display());
                return Ok(());
            }
            None => return abort_new(&path, Some(&mut clip)),
        }

        // The clipboard stays populated here: nobody can retype 32 random chars
        // from memory. Pasting still catches a clipboard that changed under you
        // (i.e. what went into the site may not be this password).
        let mut matched = false;
        for attempt in 1..=RETYPE_ATTEMPTS {
            let typed = match read_hidden(&format!("Retype it to confirm ({attempt}/{RETYPE_ATTEMPTS}): "))? {
                Some(t) => t,
                None => return abort_new(&path, Some(&mut clip)),
            };
            if typed.as_str() == password.as_str() {
                matched = true;
                break;
            }
            println!("Doesn't match.");
        }
        if matched {
            break;
        }
        println!("Showing it again.");
    }

    clip.clear();
    println!();
    println!("Locked. \"{name}\" opens {} ({} from now).", fmt_time(&unlock_at), fmt_remaining(&unlock_at)?);
    Ok(())
}

fn abort_new(path: &Path, clip: Option<&mut Clip>) -> Result<()> {
    if let Some(clip) = clip {
        clip.clear();
    }
    println!();
    println!("Aborted. The encrypted entry was KEPT at {}", path.display());
    println!("(in case you already set the password). If you didn't, delete it:");
    println!("  rm {}", shell_quote(path));
    std::process::exit(130);
}

fn cmd_list() -> Result<()> {
    let dir = data_dir()?;
    let mut rows = vec![];
    if dir.exists() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().is_none_or(|e| e != "age") {
                continue;
            }
            let name = path.file_stem().unwrap().to_string_lossy().into_owned();
            let unlock = read_unlock_time(&path).ok();
            rows.push((name, unlock));
        }
    }
    if rows.is_empty() {
        println!("No entries in {}", dir.display());
        return Ok(());
    }
    rows.sort_by(|a, b| a.1.cmp(&b.1));

    let width = rows.iter().map(|r| r.0.len()).max().unwrap_or(0);
    let now = Zoned::now();
    for (name, unlock) in rows {
        let status = match unlock {
            None => "unreadable".to_string(),
            Some(t) if t <= now => format!("{}  unlocked", fmt_time(&t)),
            Some(t) => format!("{}  {} left", fmt_time(&t), fmt_remaining(&t)?),
        };
        println!("{name:<width$}  {status}");
    }
    Ok(())
}

fn cmd_open(name: &str) -> Result<()> {
    let path = entry_path(name)?;
    if !path.exists() {
        bail!("no entry named {name:?} (see `plock list`)");
    }
    let ciphertext = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;

    let info = quicknet();
    let header = tlock_age::decrypt_header(ciphertext.as_slice())?;
    if header.hash() != info.hash() {
        bail!("{} was not encrypted to drand quicknet", path.display());
    }
    let unlock_at = round_time(&info, header.round()).to_zoned(TimeZone::system());
    if unlock_at > Zoned::now() {
        println!("Still locked: {} left (opens {}).", fmt_remaining(&unlock_at)?, fmt_time(&unlock_at));
        std::process::exit(1);
    }

    let signature = fetch_signature(&info, header.round())?;
    let mut plain = Zeroizing::new(vec![]);
    tlock_age::decrypt(&mut *plain, ciphertext.as_slice(), &info.hash(), &signature)?;
    let password = Zeroizing::new(String::from_utf8(plain.to_vec()).context("decrypted data is not UTF-8")?);

    let mut clip = Clip::new();
    clip.set(&password);
    reveal(&password, &format!(
        "Password for \"{name}\"{}.\n\nPress Enter to dismiss.",
        if clip.ok { " (copied to clipboard)" } else { "" }
    ))?;
    clip.clear();
    if clip.ok {
        println!("Clipboard cleared.");
    }
    Ok(())
}

// ---------------------------------------------------------------- drand

fn quicknet() -> ChainInfo {
    serde_json::from_str(QUICKNET_INFO).expect("embedded chain info is valid")
}

/// First round whose time is >= `t`. Round r is emitted at genesis + (r-1)*period.
fn round_at(info: &ChainInfo, t: Timestamp) -> u64 {
    let elapsed = (t.as_second() as u64).saturating_sub(info.genesis_time());
    elapsed.div_ceil(info.period()) + 1
}

fn round_time(info: &ChainInfo, round: u64) -> Timestamp {
    Timestamp::from_second((info.genesis_time() + (round - 1) * info.period()) as i64).unwrap()
}

fn fetch_signature(info: &ChainInfo, round: u64) -> Result<Vec<u8>> {
    let options = ChainOptions::new(true, false, Some(ChainVerification::from(info.clone())));
    let mut last_err = None;
    for base in DRAND_ENDPOINTS {
        let url = format!("{base}/{}", hex::encode(info.hash()));
        let result = HttpClient::new(&url, Some(options.clone())).and_then(|c| c.get(round));
        match result {
            Ok(beacon) => return Ok(beacon.signature()),
            Err(e) => last_err = Some(format!("{base}: {e}")),
        }
    }
    bail!(
        "could not fetch drand round {round} from any endpoint (last error: {}). \
         If the unlock time just passed, wait a few seconds and retry.",
        last_err.unwrap_or_default()
    )
}

fn read_unlock_time(path: &Path) -> Result<Zoned> {
    let header = tlock_age::decrypt_header(File::open(path)?)?;
    Ok(round_time(&quicknet(), header.round()).to_zoned(TimeZone::system()))
}

// ---------------------------------------------------------------- storage

fn data_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("PLOCK_DIR") {
        return Ok(dir.into());
    }
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        return Ok(PathBuf::from(dir).join("plock"));
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local/share/plock"))
}

fn entry_path(name: &str) -> Result<PathBuf> {
    let valid = !name.is_empty()
        && !name.starts_with('.')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c));
    if !valid {
        bail!("invalid name {name:?}: use letters, digits, '.', '_', '-', '@'");
    }
    Ok(data_dir()?.join(format!("{name}.age")))
}

/// Write to a temp file, fsync, rename into place, fsync the directory, so the
/// ciphertext is on disk before the password is ever shown.
fn write_durably(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap();
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = path.with_extension("age.tmp");
    let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

// ---------------------------------------------------------------- password

fn generate_password(length: usize, symbols: bool) -> Result<Zeroizing<String>> {
    let mut classes: Vec<&[u8]> = vec![LOWER, UPPER, DIGITS];
    if symbols {
        classes.push(SYMBOLS);
    }
    let alphabet: Vec<u8> = classes.concat();
    // Regenerate until every class is present, to satisfy typical site rules.
    loop {
        let mut pw = Zeroizing::new(String::with_capacity(length));
        for _ in 0..length {
            pw.push(alphabet[random_below(alphabet.len())?] as char);
        }
        if classes.iter().all(|c| pw.bytes().any(|b| c.contains(&b))) {
            return Ok(pw);
        }
    }
}

/// Uniform index in 0..n via rejection sampling.
fn random_below(n: usize) -> Result<usize> {
    let limit = 256 - (256 % n);
    loop {
        let mut b = [0u8; 1];
        getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
        if (b[0] as usize) < limit {
            return Ok(b[0] as usize % n);
        }
    }
}

// ---------------------------------------------------------------- time

fn parse_duration(s: &str) -> Result<Zoned> {
    let span: jiff::Span = s.parse().with_context(|| format!("invalid duration {s:?} (try 7d, 2w, 36h)"))?;
    Ok(Zoned::now().checked_add(span)?)
}

fn parse_until(s: &str) -> Result<Zoned> {
    if let Ok(ts) = s.parse::<Timestamp>() {
        return Ok(ts.to_zoned(TimeZone::system()));
    }
    let normalized = s.trim().replacen(' ', "T", 1);
    if let Ok(dt) = normalized.parse::<jiff::civil::DateTime>() {
        return Ok(dt.to_zoned(TimeZone::system())?);
    }
    if let Ok(d) = normalized.parse::<jiff::civil::Date>() {
        return Ok(d.to_zoned(TimeZone::system())?);
    }
    bail!("invalid time {s:?} (try \"2026-10-20 09:00\" or 2026-10-20)")
}

fn fmt_time(t: &Zoned) -> String {
    t.strftime("%a %Y-%m-%d %H:%M:%S %Z").to_string()
}

fn fmt_remaining(t: &Zoned) -> Result<String> {
    let now = Zoned::now();
    // Minutes are plenty for long waits; seconds matter in the last hour.
    let smallest = if t.timestamp().as_second() - now.timestamp().as_second() < 3600 {
        Unit::Second
    } else {
        Unit::Minute
    };
    let span = now.until(t)?.round(
        SpanRound::new()
            .largest(Unit::Day)
            .smallest(smallest)
            .mode(jiff::RoundMode::Ceil)
            .relative(&now),
    )?;
    Ok(format!("{span:#}"))
}

// ---------------------------------------------------------------- terminal

#[derive(PartialEq)]
enum Key {
    Enter,
    Abort,
    Char(char),
    Backspace,
}

impl Key {
    fn or_abort(self, on_abort: impl FnOnce() -> Result<()>) -> Result<()> {
        if self == Key::Abort { on_abort() } else { Ok(()) }
    }
}

/// Raw mode for the guard's lifetime, so Ctrl-C reaches us as a key instead of
/// killing the process with the alternate screen or clipboard still showing.
struct RawMode;

impl RawMode {
    fn on() -> Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(RawMode)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

struct AltScreen;

impl AltScreen {
    fn on() -> Result<Self> {
        execute!(io::stdout(), EnterAlternateScreen, cursor::MoveTo(0, 0))?;
        Ok(AltScreen)
    }
}

impl Drop for AltScreen {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

fn next_key() -> Result<Key> {
    loop {
        if let Event::Key(KeyEvent { code, modifiers, kind: KeyEventKind::Press, .. }) = event::read()? {
            let ctrl = modifiers.contains(KeyModifiers::CONTROL);
            return Ok(match code {
                KeyCode::Char('c' | 'd') if ctrl => Key::Abort,
                KeyCode::Esc => Key::Abort,
                KeyCode::Enter => Key::Enter,
                KeyCode::Backspace => Key::Backspace,
                KeyCode::Char(c) if !ctrl => Key::Char(c),
                _ => continue,
            });
        }
    }
}

fn wait_key(prompt: &str) -> Result<Key> {
    print!("{prompt}");
    io::stdout().flush()?;
    let _raw = RawMode::on()?;
    loop {
        if let k @ (Key::Enter | Key::Abort) = next_key()? {
            print!("\r\n");
            return Ok(k);
        }
    }
}

/// Show the password on the alternate screen so it never lands in scrollback.
fn reveal(password: &str, message: &str) -> Result<Key> {
    let _alt = AltScreen::on()?;
    let mut out = io::stdout();
    write!(out, "\r\n    {password}\r\n\r\n")?;
    for line in message.lines() {
        write!(out, "{line}\r\n")?;
    }
    out.flush()?;
    wait_key("")
}

fn confirm(prompt: &str) -> Result<Option<bool>> {
    print!("{prompt}");
    io::stdout().flush()?;
    let _raw = RawMode::on()?;
    loop {
        let answer = match next_key()? {
            Key::Abort => None,
            Key::Char('y' | 'Y') => Some(true),
            Key::Char('n' | 'N') => Some(false),
            _ => continue,
        };
        print!("{}\r\n", match answer { Some(true) => "y", Some(false) => "n", None => "" });
        return Ok(answer);
    }
}

fn read_hidden(prompt: &str) -> Result<Option<Zeroizing<String>>> {
    print!("{prompt}");
    io::stdout().flush()?;
    let _raw = RawMode::on()?;
    let mut buf = Zeroizing::new(String::new());
    loop {
        match next_key()? {
            Key::Enter => break,
            Key::Abort => {
                print!("\r\n");
                return Ok(None);
            }
            Key::Backspace => {
                buf.pop();
            }
            Key::Char(c) => buf.push(c),
        }
    }
    print!("\r\n");
    Ok(Some(buf))
}

fn shell_quote(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', r"'\''"))
}

// ---------------------------------------------------------------- clipboard

struct Clip {
    inner: Option<arboard::Clipboard>,
    ours: Option<Zeroizing<String>>,
    ok: bool,
}

impl Clip {
    fn new() -> Self {
        Clip { inner: arboard::Clipboard::new().ok(), ours: None, ok: false }
    }

    fn set(&mut self, text: &str) {
        let Some(cb) = self.inner.as_mut() else { return };
        let set = cb.set();
        // Mark as concealed so clipboard managers (Raycast, Maccy, ...) skip it.
        #[cfg(target_os = "macos")]
        let set = {
            use arboard::SetExtApple;
            set.exclude_from_history()
        };
        self.ok = set.text(text).is_ok();
        if self.ok {
            self.ours = Some(Zeroizing::new(text.to_string()));
        }
    }

    /// Clear only if the clipboard still holds what we put there.
    fn clear(&mut self) {
        let (Some(cb), Some(ours)) = (self.inner.as_mut(), self.ours.take()) else { return };
        if cb.get_text().is_ok_and(|t| Zeroizing::new(t).as_str() == ours.as_str()) {
            let _ = cb.clear();
        }
    }
}

impl Drop for Clip {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_math_lands_on_or_after_target() {
        let info = quicknet();
        let t = Timestamp::from_second(1_800_000_001).unwrap();
        let r = round_at(&info, t);
        assert!(round_time(&info, r) >= t);
        assert!(round_time(&info, r - 1) < t);
    }

    #[test]
    fn password_has_every_class() {
        for _ in 0..200 {
            let pw = generate_password(12, true).unwrap();
            assert_eq!(pw.len(), 12);
            for class in [LOWER, UPPER, DIGITS, SYMBOLS] {
                assert!(pw.bytes().any(|b| class.contains(&b)));
            }
        }
        assert!(generate_password(16, false).unwrap().bytes().all(|b| !SYMBOLS.contains(&b)));
    }

    #[test]
    fn parses_durations_and_dates() {
        for d in ["7d", "2w", "36h", "1d 12h"] {
            assert!(parse_duration(d).unwrap() > Zoned::now(), "{d}");
        }
        assert!(parse_duration("soon").is_err());
        for t in ["2030-10-20", "2030-10-20 09:00", "2030-10-20T09:00", "2030-10-20T09:00:00Z"] {
            assert_eq!(parse_until(t).unwrap().year(), 2030, "{t}");
        }
        assert!(parse_until("next friday").is_err());
    }

    /// Hits the network: encrypt to a past round and decrypt with the real beacon.
    #[test]
    #[ignore]
    fn roundtrip_against_drand() {
        let info = quicknet();
        let round = round_at(&info, Timestamp::now()) - 100;
        let mut armored = tlock_age::armor::ArmoredWriter::wrap_output(vec![]).unwrap();
        tlock_age::encrypt(&mut armored, &b"hunter2"[..], &info.hash(), &info.public_key(), round).unwrap();
        let ct = armored.finish().unwrap();

        let sig = fetch_signature(&info, round).unwrap();
        let mut out = vec![];
        tlock_age::decrypt(&mut out, ct.as_slice(), &info.hash(), &sig).unwrap();
        assert_eq!(out, b"hunter2");

        // The wrong round's signature must not decrypt it.
        let wrong = fetch_signature(&info, round - 1).unwrap();
        // tlock 0.0.10 panics (assert in ibe.rs) rather than erroring here.
        let r = std::panic::catch_unwind(|| tlock_age::decrypt(vec![], ct.as_slice(), &info.hash(), &wrong));
        assert!(r.is_err() || r.unwrap().is_err());
    }
}
