//! The fake `ssh-keygen` of the key generation tests (tests only, Windows): this test
//! executable, started by [`ProcessKeygenPort`](super::ProcessKeygenPort) exactly as the
//! real program would be. Nothing here runs `ssh-keygen` or generates a key.
//!
//! Like the fake client (`fake_client`), it starts from a CRT initializer of its own
//! (`.CRT$XCU`), which runs before `main` and before libtest reads its arguments. It
//! becomes the fake only when the first three arguments are `-q -t ed25519` (the rendered
//! shape; the fake client needs `-F none`), `PATH` is absent (the port clears it; every
//! cargo run has it) and the working directory holds [`KEYGEN_SCRIPT_FILE`]. It then reads
//! stdin to its end, writes a [`Record`] of what it was given to [`KEYGEN_RECORD_FILE`] in
//! that directory, acts out the [`KeygenScript`] on the `-f` path and exits. Any other
//! start of the executable only reads the command line and the environment, returns at
//! once and runs the tests as usual.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::fake_client::Record;
use super::fakes::ed25519_blob;
use super::wire::base64_encode;

/// The script file the fake looks for in its working directory.
pub const KEYGEN_SCRIPT_FILE: &str = "fake-ssh-keygen-script.json";
/// The record the fake writes to its working directory before acting.
pub const KEYGEN_RECORD_FILE: &str = "fake-ssh-keygen-record.json";
/// What the fake writes as the private key file: fixed test bytes, not a key.
pub const FAKE_PRIVATE_KEY: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----\n\
fake test key, not a key\n\
-----END OPENSSH PRIVATE KEY-----\n";

/// The argv shape that starts the fake.
const KEYGEN_SHAPE: [&str; 3] = ["-q", "-t", "ed25519"];

/// Exit codes of a fake that could not do its part.
const BAD_SCRIPT: i32 = 81;
const STDIN_FAILED: i32 = 82;
const RECORD_FAILED: i32 = 83;
const NO_TARGET: i32 = 84;
const WRITE_FAILED: i32 = 85;

/// What the fake does after recording.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "act", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum KeygenScript {
    /// Writes [`FAKE_PRIVATE_KEY`] to the `-f` path and `ssh-ed25519 <key> <comment>` and
    /// LF to `<path>.pub`, where the key is the test Ed25519 blob of `seed` and the comment
    /// the `-C` argument, and exits with 0.
    Generate { seed: u8 },
    /// Writes [`FAKE_PRIVATE_KEY`] to the `-f` path and `public` exactly to `<path>.pub`,
    /// and exits with 0.
    WritePublic { public: String },
    /// Exits with 0 without writing any file.
    ExitWithoutFiles,
    /// Writes no file, prints `stderr` and exits with `code`.
    Fail { stderr: String, code: i32 },
}

crate::foundation::strict_serde::strict_tag!(KeygenScript, "act");

/// The `.pub` line the fake writes for `seed` and `comment`.
pub fn public_line(seed: u8, comment: &str) -> String {
    format!(
        "ssh-ed25519 {} {comment}\n",
        base64_encode(&ed25519_blob(seed))
    )
}

#[used]
#[link_section = ".CRT$XCU"]
static FAKE_KEYGEN_ENTRY: extern "C" fn() = fake_keygen_entry;

/// Runs before `main`; becomes the fake only when started as the port starts the program.
extern "C" fn fake_keygen_entry() {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    let started_as_keygen = KEYGEN_SHAPE
        .iter()
        .enumerate()
        .all(|(index, word)| arguments.get(index + 1).is_some_and(|given| given == word))
        && std::env::var_os("PATH").is_none();
    if !started_as_keygen {
        return;
    }
    let Ok(directory) = std::env::current_dir() else {
        return;
    };
    let Ok(script) = std::fs::read(directory.join(KEYGEN_SCRIPT_FILE)) else {
        return;
    };
    std::process::exit(act(&arguments, &directory, &script));
}

/// The word after `flag` in `words`.
fn value_after<'a>(words: &'a [String], flag: &str) -> Option<&'a str> {
    let position = words.iter().position(|word| word == flag)?;
    words.get(position + 1).map(String::as_str)
}

/// Writes `bytes` to a new file at `path`; false if anything is there already, as
/// `ssh-keygen` would ask before overwriting.
fn write_new(path: &Path, bytes: &[u8]) -> bool {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .is_ok()
}

fn act(arguments: &[OsString], directory: &Path, script: &[u8]) -> i32 {
    let Ok(script) = serde_json::from_slice::<KeygenScript>(script) else {
        return BAD_SCRIPT;
    };
    let mut stdin = Vec::new();
    if std::io::stdin().lock().read_to_end(&mut stdin).is_err() {
        return STDIN_FAILED;
    }
    let mut words = arguments
        .iter()
        .map(|word| word.to_string_lossy().into_owned());
    let record = Record {
        program: words.next().unwrap_or_default(),
        arguments: words.collect(),
        environment: std::env::vars_os()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect(),
        working_directory: directory.to_path_buf(),
        stdin,
    };
    let written = serde_json::to_vec(&record)
        .ok()
        .is_some_and(|json| std::fs::write(directory.join(KEYGEN_RECORD_FILE), json).is_ok());
    if !written {
        return RECORD_FAILED;
    }
    let Some(target) = value_after(&record.arguments, "-f") else {
        return NO_TARGET;
    };
    let comment = value_after(&record.arguments, "-C").unwrap_or_default();
    let public = match script {
        KeygenScript::Generate { seed } => public_line(seed, comment),
        KeygenScript::WritePublic { public } => public,
        KeygenScript::ExitWithoutFiles => return 0,
        KeygenScript::Fail { stderr, code } => {
            let _ = std::io::stderr().lock().write_all(stderr.as_bytes());
            return code;
        }
    };
    let both = write_new(Path::new(target), FAKE_PRIVATE_KEY)
        && write_new(Path::new(&format!("{target}.pub")), public.as_bytes());
    if both {
        0
    } else {
        WRITE_FAILED
    }
}
