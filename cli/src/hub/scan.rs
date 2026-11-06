//! A folder as the Hub sees it: which files are collected (skip list, `.yougoriignore`, limits,
//! portable paths, links never followed), which files are refused because they carry credentials,
//! and the version digest. The website applies the same rules with the same reading of every file
//! (`server/hub/rules.mjs` and `scan.mjs`), so a check here and an upload there never disagree.
use super::unicode;
use sha2::{Digest, Sha256};
use std::{
    borrow::Cow,
    collections::BTreeMap,
    io::Read,
    path::Path,
};

/// The same `.yougoriignore` rules as copies into environments use.
#[path = "../../../src-tauri/src/ignore_rules.rs"]
pub mod ignore_rules;

/// A version's files by relative `/`-separated path.
pub type Files = BTreeMap<String, Vec<u8>>;

/// Folders and files never collected.
pub const SKIPPED: &[&str] = &[".git", "node_modules", ".venv", "venv", "__pycache__", "target", "dist", ".DS_Store", "Thumbs.db"];

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub files: usize,
    pub file_bytes: u64,
    pub total_bytes: u64,
}

pub const LIMITS: Limits = Limits { files: 1000, file_bytes: 5 * 1024 * 1024, total_bytes: 25 * 1024 * 1024 };

/// The longest path, and the longest folder or file name in it, in UTF-16 units as the website
/// counts them.
pub const PATH_MAX: usize = 512;
pub const PART_MAX: usize = 255;

/// What a collection found, and what it left out on purpose.
#[derive(Debug, Default)]
pub struct Collected {
    pub files: Files,
    /// Skipped folders and files, and links, as relative paths.
    pub skipped: Vec<String>,
}

impl Collected {
    pub fn bytes(&self) -> u64 {
        self.files.values().map(|bytes| bytes.len() as u64).sum()
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of the lines `SHA256  PATH\n` for every file, sorted by path as bytes.
pub fn digest<'a>(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut lines: Vec<(&str, &str)> = files.into_iter().collect();
    lines.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let text: String = lines.iter().map(|(path, sha)| format!("{sha}  {path}\n")).collect();
    sha256_hex(text.as_bytes())
}

/// The digest of collected files.
pub fn digest_of(files: &Files) -> String {
    let hashes: Vec<(String, String)> = files.iter().map(|(path, bytes)| (path.clone(), sha256_hex(bytes))).collect();
    digest(hashes.iter().map(|(path, sha)| (path.as_str(), sha.as_str())))
}

/// Windows device names, which no folder can hold whatever their extension: CON, PRN, AUX, NUL,
/// CONIN$, CONOUT$, COM0-COM9, LPT0-LPT9 and COM/LPT with a superscript 1, 2 or 3, in any case.
fn reserved_windows_name(part: &str) -> bool {
    let lower = part.to_ascii_lowercase();
    let device = |stem: &str| {
        if matches!(stem, "con" | "prn" | "aux" | "nul" | "conin$" | "conout$") {
            return true;
        }
        let mut chars = stem.chars();
        let prefix: String = chars.by_ref().take(3).collect();
        (prefix == "com" || prefix == "lpt") && matches!((chars.next(), chars.next()), (Some('0'..='9' | '¹' | '²' | '³'), None))
    };
    match lower.split_once('.') {
        None => device(&lower),
        // An extension does not help, as the website reads it (`(?:\..*)?$`).
        Some((stem, extension)) => device(stem) && !extension.contains(['\n', '\r', '\u{2028}', '\u{2029}']),
    }
}

/// Characters no Windows file name may hold.
pub const FORBIDDEN: &[char] = &['\\', ':', '*', '?', '"', '<', '>', '|'];

/// The rule every published path follows, as people read it (docs/hub.md section 6.4).
pub const PATH_RULE: &str = "relative, with / between folders, at most 512 characters and 255 per name, no empty, . or .. part, no name ending in a dot or space, none of \\ : * ? \" < > |, control or invisible characters, and no Windows device name such as CON, NUL, COM1 or LPT1";

/// A relative, portable file path: `/` separators, no `..`, nothing Windows cannot store and
/// nothing invisible. The website's `checkPath`.
pub fn check_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("A file has an empty name. Rename it.".into());
    }
    if unicode::utf16_len(path) > PATH_MAX {
        return Err(format!("{} is longer than {PATH_MAX} characters. Use a shorter path.", shown(path)));
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(format!("{} is not a relative file path. Use a path inside the folder, such as app/server.js.", shown(path)));
    }
    if path.chars().any(|c| FORBIDDEN.contains(&c) || matches!(c, '\0'..='\u{1F}' | '\u{7F}') || unicode::invisible(c)) {
        return Err(format!("{} has a character some computers cannot store or show (\\ : * ? \" < > | or an invisible one). Rename it.", shown(path)));
    }
    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(format!("{} has an empty, \".\" or \"..\" part. Use a plain relative path.", shown(path)));
        }
        if unicode::utf16_len(part) > PART_MAX {
            return Err(format!("{} has a name longer than {PART_MAX} characters. Use a shorter name.", shown(path)));
        }
        if part.ends_with(['.', ' ']) || reserved_windows_name(part) {
            return Err(format!("{} cannot be stored on Windows. Rename it.", shown(path)));
        }
    }
    Ok(())
}

/// Names one computer would store as a single file: the same path once accents are composed and
/// letter case is ignored (NFC, then lowercase), or a file with the name of a folder. The website
/// refuses both.
pub fn clashes<'a>(paths: impl IntoIterator<Item = &'a str>) -> Result<(), String> {
    match clash(paths) {
        None => Ok(()),
        Some(Clash::Same(first, second)) => Err(format!("{} and {} are the same file on Windows and macOS (their names differ only in letter case or accent encoding). Rename one of them.", shown(&first), shown(&second))),
        Some(Clash::Folder(path, file)) => Err(format!("{} is inside a folder that has the same name as the file {}. Rename one of them.", shown(&path), shown(&file))),
    }
}

/// The first path that clashes with another, as [`clashes`] finds it.
pub fn clashing<'a>(paths: impl IntoIterator<Item = &'a str>) -> Option<String> {
    match clash(paths)? {
        Clash::Same(_, path) | Clash::Folder(path, _) => Some(path),
    }
}

enum Clash {
    /// Two paths with the same key.
    Same(String, String),
    /// A path inside a folder named like a file.
    Folder(String, String),
}

fn clash<'a>(paths: impl IntoIterator<Item = &'a str>) -> Option<Clash> {
    let paths: Vec<&str> = paths.into_iter().collect();
    let mut seen: BTreeMap<String, &str> = BTreeMap::new();
    for path in &paths {
        if let Some(other) = seen.insert(unicode::path_key(path), path) {
            return Some(Clash::Same(other.to_owned(), path.to_string()));
        }
    }
    for path in &paths {
        let key = unicode::path_key(path);
        let parts: Vec<&str> = key.split('/').collect();
        for depth in 1..parts.len() {
            if let Some(file) = seen.get(&parts[..depth].join("/")) {
                return Some(Clash::Folder(path.to_string(), file.to_string()));
            }
        }
    }
    None
}

/// A path or name for a message, without anything that could control the terminal or reorder the
/// text: control characters become `?`, invisible ones are written as `\uXXXX`.
pub fn shown(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars().take(300) {
        if c.is_control() {
            out.push('?');
        } else if unicode::format_char(c) || unicode::hidden(c) {
            let code = c as u32;
            out.push_str(&if code > 0xFFFF { format!("\\u{{{code:x}}}") } else { format!("\\u{code:04x}") });
        } else {
            out.push(c);
        }
    }
    out
}

/// Collects `root` for the Hub with the standard limits.
pub fn collect(root: &Path) -> Result<Collected, String> {
    collect_with(root, LIMITS)
}

/// Collects `root`: the skip list and `.yougoriignore` are left out, links are never followed,
/// and every limit is a plain refusal that names what to leave out.
pub fn collect_with(root: &Path, limits: Limits) -> Result<Collected, String> {
    let metadata = std::fs::metadata(root).map_err(|e| format!("Cannot open the folder {}: {e}. Check the path.", root.display()))?;
    if !metadata.is_dir() {
        return Err(format!("{} is not a folder. Give the template or tool folder.", root.display()));
    }
    let rules = match std::fs::read_to_string(root.join(ignore_rules::FILE_NAME)) {
        Ok(text) => Some(ignore_rules::Rules::parse(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("Cannot read .yougoriignore: {e}")),
    };
    let mut collected = Collected::default();
    let mut total = 0u64;
    let mut pending = vec![(String::new(), root.to_path_buf())];
    while let Some((relative, folder)) = pending.pop() {
        let mut entries = std::fs::read_dir(&folder)
            .map_err(|e| format!("Cannot read the folder {}: {e}", folder.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Cannot read the folder {}: {e}", folder.display()))?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| format!("A file name in {} is not valid text. Rename it.", folder.display()))?;
            let path = if relative.is_empty() { name.to_owned() } else { format!("{relative}/{name}") };
            let kind = entry.file_type().map_err(|e| format!("Cannot read {}: {e}", shown(&path)))?;
            if kind.is_symlink() {
                collected.skipped.push(format!("{} (a link; links are not followed)", shown(&path)));
                continue;
            }
            if SKIPPED.contains(&name) {
                collected.skipped.push(shown(&path));
                continue;
            }
            if rules.as_ref().is_some_and(|rules| rules.ignored(&path, kind.is_dir())) {
                collected.skipped.push(format!("{} (.yougoriignore)", shown(&path)));
                continue;
            }
            if kind.is_dir() {
                pending.push((path, entry.path()));
                continue;
            }
            if !kind.is_file() {
                collected.skipped.push(format!("{} (not a regular file)", shown(&path)));
                continue;
            }
            check_path(&path)?;
            if collected.files.len() >= limits.files {
                return Err(format!("The folder has more than {} files. Leave dependencies and build output out with .yougoriignore.", limits.files));
            }
            let mut bytes = Vec::new();
            std::fs::File::open(entry.path())
                .and_then(|file| file.take(limits.file_bytes + 1).read_to_end(&mut bytes))
                .map_err(|e| format!("Cannot read {}: {e}", shown(&path)))?;
            if bytes.len() as u64 > limits.file_bytes {
                return Err(format!("{} is larger than {}. Leave it out with .yougoriignore or make it smaller.", shown(&path), size(limits.file_bytes)));
            }
            total += bytes.len() as u64;
            if total > limits.total_bytes {
                return Err(format!("The folder is larger than {}. Leave large files and build output out with .yougoriignore.", size(limits.total_bytes)));
            }
            collected.files.insert(path, bytes);
        }
    }
    clashes(collected.files.keys().map(String::as_str))?;
    collected.skipped.sort();
    Ok(collected)
}

/// A size as people read it: 512 B, 34 KB, 5 MiB.
pub fn size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    if bytes >= KIB * KIB && bytes.is_multiple_of(KIB * KIB) {
        format!("{} MiB", bytes / (KIB * KIB))
    } else if bytes >= KIB * KIB {
        format!("{:.1} MB", bytes as f64 / (KIB * KIB) as f64)
    } else if bytes >= KIB {
        format!("{} KB", bytes.div_ceil(KIB))
    } else {
        format!("{bytes} B")
    }
}

/// Text when the bytes are UTF-8 without NUL characters, as the website decides.
pub fn text(bytes: &[u8]) -> Option<&str> {
    if bytes.contains(&0) {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

/// What the credential scan reads in a file.
pub enum Searchable<'a> {
    Text(Cow<'a, str>),
    /// Any other file, read byte by byte: the keys searched for are plain ASCII.
    Binary(&'a [u8]),
}

fn utf16(bytes: &[u8], little: bool) -> String {
    let units = bytes.chunks_exact(2).map(|pair| if little { u16::from_le_bytes([pair[0], pair[1]]) } else { u16::from_be_bytes([pair[0], pair[1]]) });
    let mut text: String = char::decode_utf16(units).map(|unit| unit.unwrap_or('\u{FFFD}')).collect();
    if !bytes.len().is_multiple_of(2) {
        text.push('\u{FFFD}');
    }
    // A decoder drops the byte-order mark at the start.
    if text.starts_with('\u{feff}') {
        text.remove(0);
    }
    text
}

/// UTF-8 text; UTF-16 text with a byte-order mark, or detected by its zero bytes over the first
/// 4 KiB (mostly zero odd bytes: little-endian; mostly zero even bytes: big-endian), as PowerShell
/// writes it; every other file byte by byte. The website's `searchable`.
pub fn searchable(bytes: &[u8]) -> Searchable<'_> {
    if let Some(text) = text(bytes) {
        return Searchable::Text(Cow::Borrowed(text.strip_prefix('\u{feff}').unwrap_or(text)));
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return Searchable::Text(Cow::Owned(utf16(rest, true)));
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return Searchable::Text(Cow::Owned(utf16(rest, false)));
    }
    let sample = bytes.len().min(4096);
    let (mut even, mut odd) = (0usize, 0usize);
    for (index, byte) in bytes[..sample].iter().enumerate() {
        if *byte == 0 {
            if index.is_multiple_of(2) { even += 1 } else { odd += 1 }
        }
    }
    if sample >= 2 && odd * 4 > sample && even * 50 < sample {
        return Searchable::Text(Cow::Owned(utf16(bytes, true)));
    }
    if sample >= 2 && even * 4 > sample && odd * 50 < sample {
        return Searchable::Text(Cow::Owned(utf16(bytes, false)));
    }
    Searchable::Binary(bytes)
}

/// What the credential scan found: refusals, each naming the file (and line), and the files
/// with a wallet address, which are allowed but noted on the review.
#[derive(Debug, Default)]
pub struct Findings {
    pub refused: Vec<String>,
    pub wallets: Vec<String>,
}

impl Findings {
    /// The review's note about wallet addresses, worded as the Hub page words it.
    pub fn wallet_notice(&self) -> Option<String> {
        if self.wallets.is_empty() {
            return None;
        }
        let shown: Vec<&str> = self.wallets.iter().take(3).map(String::as_str).collect();
        Some(format!(
            "The files contain a wallet address ({}{}). Hub templates are free and never pay their creator.",
            shown.join(", "),
            if self.wallets.len() > 3 { ", …" } else { "" }
        ))
    }
}

/// Why a path can never be published, whatever it holds.
pub fn forbidden_name(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    let name = parts.last().copied().unwrap_or_default().to_lowercase();
    let folders: Vec<String> = parts[..parts.len().saturating_sub(1)].iter().map(|part| part.to_lowercase()).collect();
    if let Some(folder) = folders.iter().find(|folder| matches!(folder.as_str(), ".git" | "node_modules" | ".venv" | "venv" | "__pycache__" | ".ssh")) {
        return Some(format!("{} is inside {folder}/, which is never part of a template. Leave that folder out", shown(path)));
    }
    let key_file = name.strip_prefix("id_").is_some_and(|kind| matches!(kind, "rsa" | "dsa" | "ecdsa" | "ed25519"));
    if key_file || [".p12", ".pfx", ".kdbx"].iter().any(|extension| name.ends_with(extension)) {
        return Some(format!("{} looks like a private key file", shown(path)));
    }
    if matches!(name.as_str(), ".credentials.json" | ".git-credentials" | ".netrc" | "_netrc" | ".pypirc") {
        return Some(format!("{} is a credentials file", shown(path)));
    }
    if name == "auth.json" && folders.iter().any(|folder| matches!(folder.as_str(), ".codex" | ".opencode" | "opencode" | "kilo" | ".kilo")) {
        return Some(format!("{} is a tool's sign-in file", shown(path)));
    }
    None
}

/// A word character as a regular expression reads `\b`: ASCII letters, digits and `_` only.
fn word(byte: Option<&u8>) -> bool {
    byte.is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

#[derive(Clone, Copy)]
enum Class {
    /// `[A-Za-z0-9_-]`
    KeyChars,
    /// `[A-Za-z0-9]`
    Alphanumeric,
    /// `[0-9A-Z]`
    UpperDigits,
    /// `[A-Za-z0-9_]`
    Words,
    /// `[A-Za-z0-9-]`
    Slack,
    /// `[0-9a-fA-F]`
    Hex,
}

impl Class {
    fn has(self, byte: u8) -> bool {
        match self {
            Class::KeyChars => byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-',
            Class::Alphanumeric => byte.is_ascii_alphanumeric(),
            Class::UpperDigits => byte.is_ascii_uppercase() || byte.is_ascii_digit(),
            Class::Words => byte.is_ascii_alphanumeric() || byte == b'_',
            Class::Slack => byte.is_ascii_alphanumeric() || byte == b'-',
            Class::Hex => byte.is_ascii_hexdigit(),
        }
    }
}

/// One kind of key or token: `\b`, a prefix, then `min` (exactly, or at least) body characters,
/// optionally ending at a word boundary. Each mirrors one of the website's patterns.
struct Token {
    prefixes: &'static [&'static str],
    class: Class,
    min: usize,
    /// `{min}` rather than `{min,}`.
    exact: bool,
    /// A `\b` after the body.
    bounded: bool,
    what: &'static str,
}

const TOKENS: &[Token] = &[
    // \bsk-(?:proj-|ant-(?:api|admin)\d{2}-)?[A-Za-z0-9_-]{20,}: the optional part is made of body
    // characters, so the run after `sk-` decides.
    Token { prefixes: &["sk-"], class: Class::KeyChars, min: 20, exact: false, bounded: false, what: "an OpenAI or Anthropic API key" },
    Token { prefixes: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"], class: Class::Alphanumeric, min: 36, exact: true, bounded: true, what: "a GitHub token" },
    Token { prefixes: &["github_pat_"], class: Class::Words, min: 50, exact: false, bounded: false, what: "a GitHub token" },
    Token { prefixes: &["AKIA", "ASIA"], class: Class::UpperDigits, min: 16, exact: true, bounded: true, what: "an AWS access key" },
    Token { prefixes: &["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"], class: Class::Slack, min: 10, exact: false, bounded: false, what: "a Slack token" },
    Token { prefixes: &["AIza"], class: Class::KeyChars, min: 35, exact: true, bounded: true, what: "a Google API key" },
    Token { prefixes: &["hf_"], class: Class::Alphanumeric, min: 30, exact: false, bounded: true, what: "a Hugging Face token" },
    Token { prefixes: &["sk_live_", "rk_live_"], class: Class::Alphanumeric, min: 20, exact: false, bounded: false, what: "a Stripe secret key" },
    Token { prefixes: &["ygs_", "ygw_"], class: Class::KeyChars, min: 30, exact: false, bounded: false, what: "a Yougori sign-in token" },
    Token { prefixes: &["ygrid_"], class: Class::Hex, min: 64, exact: true, bounded: true, what: "a Closed Neo Grid API key" },
];

impl Token {
    /// Where a match that starts at `at` with `prefix` ends, as the website's pattern matches it.
    fn end(&self, bytes: &[u8], at: usize, prefix: &str) -> Option<usize> {
        let body = at + prefix.len();
        let boundary = |end: usize| word(bytes.get(end - 1)) != word(bytes.get(end));
        if self.exact {
            let end = body + self.min;
            let whole = bytes.get(body..end).is_some_and(|run| run.iter().all(|b| self.class.has(*b)));
            return (whole && (!self.bounded || boundary(end))).then_some(end);
        }
        let run = bytes[body..].iter().take_while(|b| self.class.has(**b)).count();
        if run < self.min {
            return None;
        }
        if !self.bounded {
            return Some(body + run);
        }
        (self.min..=run).rev().map(|length| body + length).find(|end| boundary(*end))
    }
}

/// Obvious placeholders such as sk-xxxxxxxxxxxxxxxxxxxxxxxx or sk-your-key-goes-here-1234 are not
/// keys: `(?:x{6,}|\*{6,}|0{12,}|your|example|placeholder|replace|redacted|dummy|change-?me|<|\$\{)`.
pub fn placeholder(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["xxxxxx", "******", "000000000000", "your", "example", "placeholder", "replace", "redacted", "dummy", "changeme", "change-me", "<", "${"].iter().any(|word| lower.contains(word))
}

/// Whitespace as `\s` reads it at `at`, and its length in bytes.
fn space_at(bytes: &[u8], at: usize, binary: bool) -> Option<usize> {
    let byte = *bytes.get(at)?;
    if binary {
        return matches!(byte, b'\t'..=b'\r' | b' ' | 0xA0).then_some(1);
    }
    let length = match byte {
        0..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    };
    let c = std::str::from_utf8(bytes.get(at..at + length)?).ok()?.chars().next()?;
    unicode::js_space(c).then_some(length)
}

/// `-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----\s*(?:[A-Za-z0-9+/=]{40}|Proc-Type:)`:
/// a header alone (in code that reads keys, or documentation) is not a key; the key after it is.
fn private_key_end(bytes: &[u8], at: usize, binary: bool) -> Option<usize> {
    const HEAD: &[u8] = b"-----BEGIN ";
    if !bytes[at..].starts_with(HEAD) {
        return None;
    }
    let mut starts = vec![at + HEAD.len()];
    loop {
        let from = *starts.last().unwrap_or(&0);
        let length = bytes[from..].iter().take_while(|b| b.is_ascii_uppercase() || b.is_ascii_digit()).count();
        if length == 0 || bytes.get(from + length) != Some(&b' ') {
            break;
        }
        starts.push(from + length + 1);
    }
    starts.iter().rev().find_map(|&from| {
        let rest = bytes.get(from..)?.strip_prefix(b"PRIVATE KEY")?;
        let rest = rest.strip_prefix(b" BLOCK").unwrap_or(rest);
        let rest = rest.strip_prefix(b"-----")?;
        let mut end = bytes.len() - rest.len();
        while let Some(length) = space_at(bytes, end, binary) {
            end += length;
        }
        if bytes.get(end..end + 40).is_some_and(|run| run.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))) {
            Some(end + 40)
        } else if bytes[end..].starts_with(b"Proc-Type:") {
            Some(end + 10)
        } else {
            None
        }
    })
}

/// Every key or token in `bytes`, as (where it starts, what it is). Each pattern finds its matches
/// left to right without overlapping itself, and a match that is a placeholder is passed over.
fn tokens(bytes: &[u8], binary: bool) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    // Where each pattern may match next: TOKENS, then the private key.
    let mut next = vec![0usize; TOKENS.len() + 1];
    for at in 0..bytes.len() {
        let first = bytes[at];
        if first == b'-' && at >= next[TOKENS.len()] {
            if let Some(end) = private_key_end(bytes, at, binary) {
                next[TOKENS.len()] = end;
                if !placeholder(&String::from_utf8_lossy(&bytes[at..end])) {
                    found.push((at, "a private key"));
                }
            }
            continue;
        }
        if !matches!(first, b's' | b'g' | b'A' | b'x' | b'h' | b'r' | b'y') || (at > 0 && word(bytes.get(at - 1))) {
            continue;
        }
        for (index, token) in TOKENS.iter().enumerate() {
            if at < next[index] {
                continue;
            }
            let Some(prefix) = token.prefixes.iter().find(|prefix| bytes[at..].starts_with(prefix.as_bytes())) else { continue };
            if let Some(end) = token.end(bytes, at, prefix) {
                next[index] = end;
                if !placeholder(&String::from_utf8_lossy(&bytes[at..end])) {
                    found.push((at, token.what));
                }
            }
        }
    }
    found
}

/// `\b0x[0-9a-fA-F]{40}\b`
fn wallet(bytes: &[u8]) -> bool {
    bytes.windows(2).enumerate().any(|(at, pair)| {
        pair == b"0x"
            && (at == 0 || !word(bytes.get(at - 1)))
            && bytes.get(at + 2..at + 42).is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            && !word(bytes.get(at + 42))
    })
}

/// `_authToken[ \t]*=[ \t]*(?!["']?\$\{)[^\s#;]`: a token written into an `.npmrc`, unless it
/// is read from a variable.
fn npm_tokens(text: &str) -> Vec<usize> {
    text.match_indices("_authToken").filter_map(|(at, key)| {
        let rest = text[at + key.len()..].trim_start_matches([' ', '\t']);
        let value = rest.strip_prefix('=')?.trim_start_matches([' ', '\t']);
        let variable = value.starts_with("${") || value.starts_with("\"${") || value.starts_with("'${");
        let first = value.chars().next()?;
        (!variable && !unicode::js_space(first) && first != '#' && first != ';').then_some(at)
    }).collect()
}

/// Whether a variable holds a secret: a part of its name (split on `_` and `-`) such as KEY or
/// PASSWORD, or PASSWORD, SECRET, TOKEN or APIKEY anywhere in it. The website's `secretName`.
pub fn secret_name(name: &str) -> bool {
    const PARTS: &[&str] = &["KEY", "KEYS", "TOKEN", "TOKENS", "SECRET", "SECRETS", "PASSWORD", "PASSWORDS", "PASSWD", "PASS", "PWD", "CREDENTIAL", "CREDENTIALS", "PRIVATE"];
    let upper = name.to_uppercase();
    upper.split(['_', '-']).any(|part| PARTS.contains(&part)) || ["PASSWORD", "SECRET", "TOKEN", "APIKEY"].iter().any(|word| upper.contains(word))
}

/// In an example environment file, the first secret-like variable with a real value, as (line,
/// name). A value is read up to ` #`, trimmed and unquoted; a placeholder is fine.
fn example_problem(text: &str) -> Option<(usize, String)> {
    for (index, line) in text.split('\n').enumerate() {
        let line = unicode::js_trim(line.strip_suffix('\r').unwrap_or(line));
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let assignment = |line: &str| -> Option<(String, String)> {
            let name_length = line.bytes().take_while(|b| b.is_ascii_alphanumeric() || *b == b'_').count();
            if name_length == 0 || line.as_bytes()[0].is_ascii_digit() {
                return None;
            }
            let value = line[name_length..].trim_start_matches(unicode::js_space).strip_prefix('=')?;
            // `.` never matches a line break, so such a line is no assignment.
            if value.contains(['\r', '\u{2028}', '\u{2029}']) {
                return None;
            }
            Some((line[..name_length].to_owned(), value.to_owned()))
        };
        let exported = line.strip_prefix("export").filter(|rest| rest.starts_with(unicode::js_space)).map(|rest| rest.trim_start_matches(unicode::js_space)).and_then(assignment);
        let Some((name, value)) = exported.or_else(|| assignment(line)) else { continue };
        if !secret_name(&name) {
            continue;
        }
        let cut = value.char_indices().find(|(at, c)| unicode::js_space(*c) && value[at + c.len_utf8()..].starts_with('#')).map_or(value.as_str(), |(at, _)| &value[..at]);
        let mut value = unicode::js_trim(cut);
        let quoted = value.chars().count() >= 2 && (value.starts_with('"') && value.ends_with('"') || value.starts_with('\'') && value.ends_with('\''));
        if quoted {
            value = unicode::js_trim(&value[1..value.len() - 1]);
        }
        if !value.is_empty() && !placeholder(value) {
            return Some((index + 1, name));
        }
    }
    None
}

fn line_of(bytes: &[u8], at: usize) -> usize {
    bytes[..at].iter().filter(|b| **b == b'\n').count() + 1
}

/// Every refusal in a version's files, and the files with wallet addresses. The website's
/// `scanFiles`, reading each file the same way.
pub fn scan(files: &Files) -> Findings {
    let mut findings = Findings::default();
    for (path, bytes) in files {
        if let Some(reason) = forbidden_name(path) {
            findings.refused.push(format!("{reason}."));
            continue;
        }
        let name = path.rsplit('/').next().unwrap_or(path).to_lowercase();
        let searchable = searchable(bytes);
        let (scanned, binary): (&[u8], bool) = match &searchable {
            Searchable::Text(text) => (text.as_bytes(), false),
            Searchable::Binary(bytes) => (bytes, true),
        };
        if name == ".env" || name.starts_with(".env.") {
            let example = matches!(name.as_str(), ".env.example" | ".env.sample" | ".env.template" | ".env.defaults");
            match &searchable {
                Searchable::Text(text) if example => {
                    if let Some((line, variable)) = example_problem(text) {
                        findings.refused.push(format!("Leave {variable} empty in {} (line {line}), or write a placeholder such as your-key-here. Keys belong in secret inputs, never in files.", shown(path)));
                    }
                }
                _ => {
                    findings.refused.push(format!("{}: environment files with values are never published. Remove it and keep a .env.example with empty values instead.", shown(path)));
                    continue;
                }
            }
        }
        let mut lines: Vec<(usize, &str)> = Vec::new();
        if let (Searchable::Text(text), ".npmrc") = (&searchable, name.as_str()) {
            lines.extend(npm_tokens(text).into_iter().map(|at| (at, "an npm token")));
        }
        lines.extend(tokens(scanned, binary));
        lines.sort();
        let mut said = Vec::new();
        for (at, what) in lines {
            let message = if binary {
                format!("{} (a binary file): looks like {what}. Remove it; keys belong in secret inputs, never in files.", shown(path))
            } else {
                format!("{} line {}: looks like {what}. Remove it; keys belong in secret inputs, never in files.", shown(path), line_of(scanned, at))
            };
            if !said.contains(&message) {
                said.push(message);
            }
            if said.len() >= 10 {
                break;
            }
        }
        findings.refused.extend(said);
        if !binary && wallet(scanned) {
            findings.wallets.push(path.clone());
        }
    }
    findings
}

// ---- Live values in descriptions -----------------------------------------------------------
// A description, README or changelog is shown to everyone. It must not hold what a running setup
// hands out: an invite names a company's hub and its certificate, and a quick link opens the
// publisher's own running setup. Placeholders such as desk-invite:… or
// https://your-app.trycloudflare.com are fine. The website's `scanDescriptions` and
// `checkDescription`, with the same patterns.

const INVITES: &[(&str, &str)] = &[("grid", "Closed Neo Grid invite"), ("desk", "Sandbox Grid invite"), ("access", "Access Grid invite"), ("bounty", "closed bounty invite")];

/// What a live value is, and what to write instead.
struct Live {
    at: usize,
    what: String,
    instead: String,
}

/// Base64url as Node's `Buffer.from(text, 'base64url')` reads it: six bits a character, whole
/// bytes only, a leftover part dropped.
fn base64url(text: &str) -> Vec<u8> {
    let (mut bytes, mut bits, mut count) = (Vec::new(), 0u32, 0u32);
    for c in text.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => continue,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            bytes.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    bytes
}

/// An invite only when its body is the JSON a real invite carries: an address and a fingerprint.
fn real_invite(body: &str) -> bool {
    let json: Option<serde_json::Value> = serde_json::from_str(&String::from_utf8_lossy(&base64url(body))).ok();
    json.is_some_and(|wire| wire.get("a").is_some_and(serde_json::Value::is_string) && wire.get("f").is_some_and(serde_json::Value::is_string))
}

/// `\b(grid|desk|access|bounty)-invite:(eyJ[A-Za-z0-9_-]{20,2048})`, left to right: the first
/// whose body is a real invite.
fn live_invite(text: &str) -> Option<Live> {
    let bytes = text.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        let start = at;
        at += 1;
        if !matches!(bytes[start], b'g' | b'd' | b'a' | b'b') || (start > 0 && word(bytes.get(start - 1))) {
            continue;
        }
        let rest = &bytes[start..];
        let Some((kind, what)) = INVITES.iter().find(|(kind, _)| rest.starts_with(kind.as_bytes()) && rest[kind.len()..].starts_with(b"-invite:eyJ")) else { continue };
        let body = start + kind.len() + "-invite:".len();
        let run = bytes[body + 3..].iter().take_while(|b| b.is_ascii_alphanumeric() || **b == b'_' || **b == b'-').count().min(2048);
        if run < 20 {
            continue;
        }
        let end = body + 3 + run;
        if real_invite(&text[body..end]) {
            return Some(Live { at: start, what: format!("a live {what}"), instead: format!("share invites privately, and write a placeholder such as {kind}-invite:… instead") });
        }
        at = end;
    }
    None
}

/// `\bhttps?:\/\/[a-z0-9]+(?:-[a-z0-9]+){2,}\.trycloudflare\.com\b(?!\.[a-z0-9])` in any letter
/// case, left to right: the first that is not a placeholder. The host must end at .com, so
/// `….trycloudflare.com.example.org` is another site, while a full stop ending a sentence is not.
fn live_quick_link(text: &str) -> Option<Live> {
    const HOST: &[u8] = b".trycloudflare.com";
    let bytes = text.as_bytes();
    // Bytes, not text: a start may fall inside a character, and only ASCII is compared.
    let lower = text.to_ascii_lowercase().into_bytes();
    let mut at = 0;
    while at < bytes.len() {
        let start = at;
        at += 1;
        if (start > 0 && word(bytes.get(start - 1))) || !lower[start..].starts_with(b"http") {
            continue;
        }
        let scheme = if lower[start..].starts_with(b"https://") { 8 } else if lower[start..].starts_with(b"http://") { 7 } else { continue };
        let name = start + scheme;
        let length = bytes[name..].iter().take_while(|b| b.is_ascii_alphanumeric() || **b == b'-').count();
        let labels: Vec<&[u8]> = bytes[name..name + length].split(|b| *b == b'-').collect();
        let end = name + length + HOST.len();
        let longer = bytes.get(end) == Some(&b'.') && bytes.get(end + 1).is_some_and(u8::is_ascii_alphanumeric);
        if labels.len() < 3 || labels.iter().any(|label| label.is_empty()) || !lower[name + length..].starts_with(HOST) || word(bytes.get(end)) || longer {
            continue;
        }
        if !placeholder(&text[start..end]) {
            return Some(Live { at: start, what: "a quick link to a running setup".into(), instead: "it opens your own setup; write a placeholder such as https://your-link.trycloudflare.com instead".into() });
        }
        at = end;
    }
    None
}

/// The first live value in a text: invites first, then quick links, as the website looks.
fn live_value(text: &str) -> Option<Live> {
    live_invite(text).or_else(|| live_quick_link(text))
}

/// Whether a text holds a live invite, read as descriptions are (the website's `inviteIn`).
pub fn invite_in(text: &str) -> bool {
    live_invite(text).is_some()
}

/// Whether a text holds a quick link to a running setup, read as descriptions are (the website's
/// `quickLinkIn`).
pub fn quick_link_in(text: &str) -> bool {
    live_quick_link(text).is_some()
}

/// `^(?:readme|changelog)(?:\.[a-z]+)?$` in any letter case: files whose text describes the item.
fn describing(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let rest = lower.strip_prefix("readme").or_else(|| lower.strip_prefix("changelog"));
    rest.is_some_and(|rest| rest.is_empty() || rest.strip_prefix('.').is_some_and(|extension| !extension.is_empty() && extension.bytes().all(|b| b.is_ascii_lowercase())))
}

/// The README, changelog and marker file (`marker`) problems: each file's first live value, with
/// its line. Files that are not UTF-8 text are not read, as on the website.
pub fn descriptions(files: &Files, marker: &str) -> Vec<String> {
    files.iter().filter(|(path, _)| path.as_str() == marker || describing(path.rsplit('/').next().unwrap_or(path))).filter_map(|(path, bytes)| {
        let text = text(bytes)?;
        let live = live_value(text)?;
        Some(format!("{} line {}: holds {}. Hub pages are public: {}.", shown(path), line_of(text.as_bytes(), live.at), live.what, live.instead))
    }).collect()
}

/// Everything the website refuses in an upload's files and description fields: `scan`, then live
/// values in the README, changelog and marker file and in the title, summary, changelog and
/// subtitle (`fields`, by name).
pub fn scan_upload(files: &Files, marker: &str, fields: &[(&str, Option<&str>)]) -> Findings {
    let mut findings = scan(files);
    findings.refused.extend(descriptions(files, marker));
    findings.refused.extend(live_fields(fields));
    findings
}

/// The title, summary, changelog and subtitle problems, by field name ("summary").
pub fn live_fields(fields: &[(&str, Option<&str>)]) -> Vec<String> {
    fields.iter().filter_map(|(field, text)| {
        let live = live_value((*text)?)?;
        Some(format!("The {field} holds {}. Hub pages are public: {}.", live.what, live.instead))
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(entries: &[(&str, &str)]) -> Files {
        entries.iter().map(|(path, text)| (path.to_string(), text.as_bytes().to_vec())).collect()
    }

    const KEY_MATERIAL: &str = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW";

    #[test]
    fn each_key_pattern_is_refused_with_its_file_and_line() {
        let cases = [
            ("sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z".to_owned(), "an OpenAI or Anthropic API key"),
            ("sk-ant-api03-Ab3dEf6hIj9kLm2nOp5qRs8tUv".to_owned(), "an OpenAI or Anthropic API key"),
            (format!("ghp_{}", "a1B2c3D4e5".repeat(3) + "f6G7h8"), "a GitHub token"),
            (format!("github_pat_{}", "A1b2C3d4E5".repeat(5)), "a GitHub token"),
            ("AKIAIOSFODNN7ABCDEFG".to_owned(), "an AWS access key"),
            ("xoxb-1234567890-abcdefghij".to_owned(), "a Slack token"),
            (format!("AIza{}", "Sy0123456789abcdefghijklmnopqrstu-_"), "a Google API key"),
            (format!("AIza{}-v2", "Sy0123456789abcdefghijklmnopqrstuvw"), "a Google API key"),
            (format!("hf_{}", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0dF"), "a Hugging Face token"),
            (format!("sk_live_{}", "4eC39HqLyjWDarjtT1zdp7dc"), "a Stripe secret key"),
            (format!("ygs_{}", "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MDEyMzQ1"), "a Yougori sign-in token"),
            (format!("ygrid_{}", "0123456789abcdef".repeat(4)), "a Closed Neo Grid API key"),
            (format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{KEY_MATERIAL}"), "a private key"),
            (format!("-----BEGIN PRIVATE KEY-----{KEY_MATERIAL}"), "a private key"),
            ("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED".to_owned(), "a private key"),
            (format!("-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n\r\n{KEY_MATERIAL}"), "a private key"),
        ];
        for (secret, what) in cases {
            let found = scan(&files(&[("app/config.js", &format!("// settings\nconst key = \"{secret}\";\n"))]));
            assert_eq!(found.refused.len(), 1, "{secret}: {:?}", found.refused);
            let said = &found.refused[0];
            assert!(said.starts_with("app/config.js line 2: looks like "), "{said}");
            assert!(said.contains(what), "{secret}: {said}");
            assert!(!said.contains(&secret), "the message never repeats the secret");
        }
    }

    /// A real invite of `kind`, as the hub writes one: base64url JSON with an address and a fingerprint.
    fn invite(kind: &str) -> String {
        use base64::Engine;
        let wire = serde_json::json!({"v": 1, "c": "Acme", "a": "10.0.0.5:7463", "f": "AB".repeat(32)});
        format!("{kind}-invite:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wire.to_string()))
    }

    const LINK: &str = "https://seasonal-deck-organisms-sf.trycloudflare.com";

    #[test]
    fn live_invites_and_quick_links_in_descriptions_are_refused_with_the_file_and_line() {
        let marker = "yougori-template.yaml";
        let cases = [
            ("README.md", format!("# my-api\n\nJoin with {}\n", invite("desk")), "README.md line 3: holds a live Sandbox Grid invite. Hub pages are public: share invites privately, and write a placeholder such as desk-invite:… instead."),
            ("docs/README.md", format!("Hub: {}", invite("grid")), "docs/README.md line 1: holds a live Closed Neo Grid invite."),
            ("CHANGELOG.md", format!("## 1.0.0\n\n{}\n", invite("access")), "CHANGELOG.md line 3: holds a live Access Grid invite."),
            (marker, format!("name: my-api\nversion: 1.0.0\nlicense: MIT\nsummary: An API.\ndescription: Join {}\n", invite("bounty")), "yougori-template.yaml line 5: holds a live closed bounty invite."),
            ("README.md", format!("Open {LINK} to try it.\n"), "README.md line 1: holds a quick link to a running setup. Hub pages are public: it opens your own setup; write a placeholder such as https://your-link.trycloudflare.com instead."),
            ("readme", format!("Café — ouvrez {}.\n", LINK.to_uppercase()), "readme line 1: holds a quick link to a running setup."),
        ];
        for (path, text, said) in cases {
            let found = descriptions(&files(&[(path, &text)]), marker);
            assert_eq!(found.len(), 1, "{path}: {found:?}");
            assert!(found[0].starts_with(said), "{}", found[0]);
        }
        // An invite comes before a quick link, wherever each is, as the website looks for them.
        let both = descriptions(&files(&[("README.md", &format!("{LINK}\n\n{}\n", invite("desk")))]), marker);
        assert!(both[0].starts_with("README.md line 3: holds a live Sandbox Grid invite"), "{both:?}");
        // The title, summary, changelog and subtitle, by name.
        let fields = live_fields(&[("title", Some("My API")), ("summary", Some(&format!("Try it at {LINK}"))), ("changelog", Some(&format!("First version.\n{}", invite("desk")))), ("subtitle", None)]);
        assert_eq!(fields, [
            "The summary holds a quick link to a running setup. Hub pages are public: it opens your own setup; write a placeholder such as https://your-link.trycloudflare.com instead.",
            "The changelog holds a live Sandbox Grid invite. Hub pages are public: share invites privately, and write a placeholder such as desk-invite:… instead.",
        ]);
        let upload = scan_upload(&files(&[("README.md", &invite("grid")), ("app/a.js", &format!("const key = 'ygrid_{}'\n", "0123456789abcdef".repeat(4)))]), marker, &[("summary", Some(LINK))]);
        assert_eq!(upload.refused.len(), 3, "{:?}", upload.refused);
    }

    #[test]
    fn placeholders_examples_and_invites_outside_descriptions_are_fine() {
        let marker = "yougori-template.yaml";
        let allowed = [
            ("README.md", "# my-api\n\nJoin with desk-invite:… or grid-invite:..., e.g. desk-invite:abc.\nOpen https://your-app-name.trycloudflare.com or https://x.trycloudflare.com.\nAn access-invite:eyJub3QgYW4gaW52aXRlIGF0IGFsbCB9 is not one.\n".to_owned()),
            // Code that reads invites, and another tool's marker, are not descriptions.
            ("app/fixture.js", format!("export const sample = '{}'\n", invite("desk"))),
            ("yougori-tool.yaml", format!("summary: {}\n", invite("desk"))),
            ("README.en.md", invite("desk")),
            ("README.md5", invite("desk")),
            // Not a word boundary before it, not a whole host, or not trycloudflare.com.
            ("README.md", format!("x{}", invite("desk"))),
            ("README.md", format!("x{LINK} {}", LINK.replace(".com", ".community"))),
            ("README.md", "https://a--b-c.trycloudflare.com https://a-b.trycloudflare.com https://a-b-c.trycloudflare.com.evil.example/".into()),
            ("README.md", "desk-invite:eyJ2IjoxfQ is too short, and desk-invite:eyJhYmMiOiJkZWYiLCJnaGkiOiJqa2wifQ has no address.".into()),
        ];
        for (path, text) in allowed {
            assert_eq!(descriptions(&files(&[(path, &text)]), marker), Vec::<String>::new(), "{path}: {text}");
        }
        // The host ends at .com: a path, or a full stop ending the sentence, still leaves it a quick link.
        for text in ["https://a-b-c.trycloudflare.com/x", "Open https://a-b-c.trycloudflare.com.", "(https://a-b-c.trycloudflare.com.)"] {
            assert_eq!(descriptions(&files(&[("README.md", text)]), marker).len(), 1, "{text}");
        }
        // A README that is not UTF-8 text is not read, as on the website.
        let mut binary = invite("desk").into_bytes();
        binary.push(0);
        assert!(descriptions(&[("README.md".to_owned(), binary)].into(), marker).is_empty());
        assert_eq!(base64url("eyJ2IjoxfQ"), b"{\"v\":1}", "a leftover part is dropped, as Node does");
    }

    #[test]
    fn placeholders_words_headers_and_partial_matches_are_not_keys() {
        for text in [
            "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_owned(),
            "sk-your-key-goes-here-1234567890".to_owned(),
            "sk-change-me-1234567890123456789".to_owned(),
            "OPENAI_API_KEY=sk-...".to_owned(),
            "task-management-and-scheduling-system".to_owned(),
            "the risk-assessment-for-every-new-feature".to_owned(),
            "AKIAIOSFODNN7ABCDEFGH".to_owned(),
            format!("ghp_{}", "a".repeat(40)),
            format!("hf_{}_x", "a".repeat(40)),
            format!("AIza{}--", "a".repeat(34)),
            "hf_short".to_owned(),
            "0x52908400098527886E0F7030069857D2E4169EE7".to_owned(),
            "if line.starts_with(\"-----BEGIN RSA PRIVATE KEY-----\") {".to_owned(),
            "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----".to_owned(),
        ] {
            assert!(scan(&files(&[("notes.md", &text)])).refused.is_empty(), "{text}");
        }
    }

    #[test]
    fn utf16_and_binary_files_are_read_as_the_website_reads_them() {
        let key = format!("hf_{}", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0dF");
        let le: Vec<u8> = format!("line one\nKEY={key}\n").encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut with_mark = vec![0xFF, 0xFE];
        with_mark.extend(&le);
        let be: Vec<u8> = format!("x\n\n{key}").encode_utf16().flat_map(u16::to_be_bytes).collect();
        let mut binary = vec![0u8, 1, 2, 0x89, b'P', b'N', b'G', b' '];
        binary.extend(key.as_bytes());
        for (bytes, said) in [
            (le, "a.ps1 line 2: looks like a Hugging Face token"),
            (with_mark, "a.ps1 line 2: looks like a Hugging Face token"),
            (be, "a.ps1 line 3: looks like a Hugging Face token"),
            (binary, "a.ps1 (a binary file): looks like a Hugging Face token"),
        ] {
            let found = scan(&Files::from([("a.ps1".to_owned(), bytes)]));
            assert!(found.refused.len() == 1 && found.refused[0].starts_with(said), "{said}: {:?}", found.refused);
        }
        assert!(matches!(searchable(b"\xef\xbb\xbfplain"), Searchable::Text(text) if text == "plain"), "the byte-order mark is dropped");
    }

    #[test]
    fn a_long_one_line_file_is_scanned_without_a_copy_per_character() {
        let mut text = "a".repeat(5 * 1024 * 1024 - 64);
        text.push_str(" sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z");
        let started = std::time::Instant::now();
        let found = scan(&files(&[("big.txt", &text)]));
        assert_eq!(found.refused.len(), 1);
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "{:?}", started.elapsed());
    }

    #[test]
    fn environment_and_credential_files_are_refused_but_examples_may_hold_plain_values() {
        let ok = scan(&files(&[(".env.example", "\u{feff}# Fill these in\nOPENAI_API_KEY=\nexport\tPORT=3000\nNAME='' # comment\nDB_PASSWORD=change-me\nAPI_TOKEN=\"<your token>\"\nAUTH_URL=https://example.com/auth\nSECRET_KEY= # set me\n")]));
        assert!(ok.refused.is_empty(), "{:?}", ok.refused);
        for (line, text, variable) in [
            (2, "PORT=3000\nDB_PASSWORD=hunter2\n", "DB_PASSWORD"),
            (1, "export   GITHUB_TOKEN='abc123'  # mine\n", "GITHUB_TOKEN"),
            (1, "MYAPIKEY=abc\n", "MYAPIKEY"),
            (2, "private-key=x\nPRIVATE_KEY=abc\n", "PRIVATE_KEY"),
        ] {
            let found = scan(&files(&[("conf/.env.sample", text)]));
            assert_eq!(found.refused, [format!("Leave {variable} empty in conf/.env.sample (line {line}), or write a placeholder such as your-key-here. Keys belong in secret inputs, never in files.")], "{text}");
        }
        let env = scan(&files(&[("api/.env", "SECRET=hunter2\n")]));
        assert_eq!(env.refused, ["api/.env: environment files with values are never published. Remove it and keep a .env.example with empty values instead."]);
        assert!(!scan(&files(&[(".env.local", "")])).refused.is_empty(), "only examples may exist, even empty");
        let tokens = scan(&files(&[(".env.example", &format!("HELP=see {}\n", "sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z"))]));
        assert!(tokens.refused[0].contains(".env.example line 1: looks like an OpenAI"), "the key patterns still run on examples: {:?}", tokens.refused);
        for path in [".credentials.json", "home/.codex/auth.json", ".git-credentials", ".netrc", "_netrc", ".pypirc", "keys/id_rsa", "id_ed25519", "cert.p12", "secrets/.ssh/config", "x/node_modules/a.js"] {
            assert_eq!(scan(&files(&[(path, "{}")])).refused.len(), 1, "{path}");
        }
        assert!(scan(&files(&[("auth.json", "{}")])).refused.is_empty(), "an auth.json outside a tool folder is ordinary");
        let npm = scan(&files(&[(".npmrc", "registry=https://registry.npmjs.org\n//registry.npmjs.org/:_authToken=npm_abc123\n")]));
        assert!(npm.refused[0].contains(".npmrc line 2: looks like an npm token"), "{:?}", npm.refused);
        for fine in ["//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n", "_authToken = \"${NPM_TOKEN}\"\n", "_authToken=\n", "_authToken= # later\n"] {
            assert!(scan(&files(&[(".npmrc", fine)])).refused.is_empty(), "{fine}");
        }
        assert!(secret_name("db_password") && secret_name("AWS_SECRET_ACCESS_KEY") && secret_name("PASS") && !secret_name("AUTH_URL") && !secret_name("KEYBOARD_LAYOUT") && !secret_name("PASSAGE"));
    }

    #[test]
    fn wallet_addresses_are_allowed_and_noted() {
        let found = scan(&files(&[("app/wallet.js", "const payTo = \"0x52908400098527886E0F7030069857D2E4169EE7\";\n"), ("b.txt", "0x1234")]));
        assert!(found.refused.is_empty());
        assert_eq!(found.wallets, ["app/wallet.js"]);
        assert_eq!(found.wallet_notice().unwrap(), "The files contain a wallet address (app/wallet.js). Hub templates are free and never pay their creator.");
        assert!(scan(&files(&[("a.txt", "0x52908400098527886E0F7030069857D2E4169EE7aa")])).wallets.is_empty(), "a longer hex run is not an address");
    }

    #[test]
    fn digest_is_sha256sum_lines_sorted_by_path_bytes() {
        let sorted = format!("{}  B.txt\n{}  a.txt\n{}  a/b.txt\n", sha256_hex(b"B"), sha256_hex(b"a"), sha256_hex(b"ab"));
        let hashes = [("a/b.txt", sha256_hex(b"ab")), ("a.txt", sha256_hex(b"a")), ("B.txt", sha256_hex(b"B"))];
        let expected = sha256_hex(sorted.as_bytes());
        assert_eq!(digest(hashes.iter().map(|(path, sha)| (*path, sha.as_str()))), expected);
        let files: Files = [("a/b.txt", "ab"), ("a.txt", "a"), ("B.txt", "B")].iter().map(|(p, t)| (p.to_string(), t.as_bytes().to_vec())).collect();
        assert_eq!(digest_of(&files), expected);
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn paths_follow_the_hub_rules() {
        for good in ["yougori.yaml", "app/server.js", ".env.example", "a/.b/c", "naïve/日本.txt", "con .txt", "a b/c d.txt"] {
            assert!(check_path(good).is_ok(), "{good}");
        }
        for bad in ["", "/abs", "a/", "a//b", "./a", "a/../b", "..", "a\\b", "c:x", "tab\there", "esc\u{1b}x", "del\u{7f}", "dot./x", "space /x", "con", "aux.txt", "dir/LPT1.log", "Com0", "lpt9.x", "COM¹.txt", "conin$", "CONOUT$.log", &"a".repeat(513), &format!("{}/b", "a".repeat(256))] {
            assert!(check_path(bad).is_err(), "{bad:?}");
        }
        // The soft hyphen, U+180E and the tag characters show as nothing too; the website refuses them as well.
        for character in ['*', '?', '"', '<', '>', '|', '\u{202e}', '\u{200b}', '\u{feff}', '\u{2066}', '\u{61c}', '\u{ad}', '\u{180e}', '\u{e0041}'] {
            let refused = check_path(&format!("site/a{character}b.txt")).unwrap_err();
            assert!(refused.contains("has a character some computers cannot store or show"), "{character:?}: {refused}");
        }
        assert!(check_path("evil\u{202e}txt.exe").unwrap_err().starts_with("evil\\u202etxt.exe"), "a hidden character is shown, never applied");
        for allowed in ["COM10", "console.log", "auxiliary/x", "nul-file", "lpt", "com", "x/conin"] {
            assert!(check_path(allowed).is_ok(), "{allowed}");
        }
        assert_eq!(unicode::utf16_len(&"😀".repeat(256)), 512);
        assert!(check_path(&format!("{}/x", "😀".repeat(128))).is_err(), "names are counted in UTF-16 units, as the website counts them");
    }

    #[test]
    fn names_one_computer_stores_as_one_file_are_refused() {
        assert!(clashes(["app/server.js", "App/Readme.md", "café.txt"]).is_ok());
        let accents = clashes(["caf\u{e9}.txt", "cafe\u{301}.txt"]).unwrap_err();
        assert!(accents.contains("are the same file on Windows and macOS"), "{accents}");
        assert!(clashes(["README.md", "readme.md"]).is_err());
        let folder = clashes(["app", "App/server.js"]).unwrap_err();
        assert!(folder.contains("App/server.js is inside a folder that has the same name as the file app"), "{folder}");
    }

    #[test]
    fn collection_skips_folders_honours_yougoriignore_and_never_follows_links() {
        let root = tempfile::tempdir().unwrap();
        let write = |path: &str, text: &str| {
            let path = root.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write("yougori-template.yaml", "name: x\n");
        write("app/server.js", "ok");
        write("node_modules/left/index.js", "x");
        write(".git/HEAD", "x");
        write("app/__pycache__/m.pyc", "x");
        write("dist/bundle.js", "x");
        write("target/debug/app", "x");
        write("Thumbs.db", "x");
        write("logs/run.log", "x");
        write("keep/notes.log", "x");
        write(".yougoriignore", "*.log\n!keep/*.log\n");
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), "outside").unwrap();
        let linked = {
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(outside.path(), root.path().join("linked")).is_ok()
            }
            #[cfg(windows)]
            {
                std::os::windows::fs::symlink_dir(outside.path(), root.path().join("linked")).is_ok()
                    || std::process::Command::new("cmd")
                        .args(["/C", "mklink", "/J"])
                        .arg(root.path().join("linked"))
                        .arg(outside.path())
                        .output()
                        .is_ok_and(|output| output.status.success())
            }
        };
        let collected = collect(root.path()).unwrap();
        let paths: Vec<&str> = collected.files.keys().map(String::as_str).collect();
        assert_eq!(paths, [".yougoriignore", "app/server.js", "keep/notes.log", "yougori-template.yaml"]);
        for skipped in ["node_modules", ".git", "app/__pycache__", "dist", "target", "Thumbs.db", "logs/run.log (.yougoriignore)"] {
            assert!(collected.skipped.iter().any(|s| s == skipped), "{skipped}: {:?}", collected.skipped);
        }
        if linked {
            assert!(collected.skipped.iter().any(|s| s.starts_with("linked (a link")), "{:?}", collected.skipped);
            assert!(!paths.iter().any(|p| p.contains("secret")));
        }
        assert_eq!(collected.bytes(), 18 + 2 + 1 + 8);
    }

    #[test]
    fn collection_limits_are_plain_refusals() {
        let root = tempfile::tempdir().unwrap();
        for index in 0..3 {
            std::fs::write(root.path().join(format!("f{index}.txt")), "12345").unwrap();
        }
        let limits = |files, file_bytes, total_bytes| Limits { files, file_bytes, total_bytes };
        assert!(collect_with(root.path(), limits(2, 100, 100)).unwrap_err().contains("more than 2 files"));
        assert!(collect_with(root.path(), limits(10, 4, 100)).unwrap_err().contains("f0.txt is larger than 4 B"));
        assert!(collect_with(root.path(), limits(10, 100, 12)).unwrap_err().contains("The folder is larger than 12 B"));
        assert_eq!(collect_with(root.path(), limits(3, 5, 15)).unwrap().files.len(), 3);
        assert!(collect(&root.path().join("missing")).unwrap_err().contains("Cannot open the folder"));
        assert_eq!(size(5 * 1024 * 1024), "5 MiB");
        assert_eq!(size(34_567), "34 KB");
    }
}
