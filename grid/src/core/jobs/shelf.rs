//! Where an artifact's bytes are kept: one file per checksum, in a folder beside the realm's
//! database, with a staging folder inside it where bytes wait while they arrive.
//!
//! The database holds what an artifact is called, which attempt sent it, how large it is and what
//! it hashed to. The bytes are not in it, for the same reason a workspace's data is not: a realm is
//! a record of what happened, not a store for what anybody made. Each kept file is named by its
//! checksum and by nothing else, so no name a job chose ever becomes part of a path on this
//! computer, and two attempts that made the same bytes share one file.
//!
//! Bytes arrive in two steps, so that a large upload never needs the realm. They are first written
//! into the staging folder, counted and hashed as they come, and compared with what the computer
//! declared; a copy that stops short, runs long or hashes to something else is removed there and
//! then. Only bytes that matched are later put in place under their checksum, by the door that also
//! records them. Reading a copy back, or carrying it into a copy of the realm, hashes it again, so a
//! file damaged on this disk is reported as damaged rather than handed on as if it were whole.
use sha2::{Digest, Sha256};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Why bytes were not kept, or could not be read back.
#[derive(Debug)]
pub(super) enum Refusal {
    /// The bytes hash to something other than what was declared.
    Mismatch,
    /// Fewer bytes arrived than were declared; the number is how many did.
    Short(u64),
    /// More bytes arrived than were declared.
    Long,
    /// A kept copy no longer hashes to what was recorded, or is no longer the size it was.
    Damaged,
    /// A kept or staged copy is not on this computer any more.
    Missing,
    /// The disk or the folder would not do what was asked; the sentence says what.
    Trouble(String),
}

/// The folder an artifact's bytes are kept in.
#[derive(Clone, Debug)]
pub(super) struct Shelf {
    folder: PathBuf,
}

const CHUNK: usize = 64 * 1024;

/// The folder inside the shelf where bytes wait while they arrive.
const STAGING: &str = "staging";

/// What a file in the staging folder ends with.
const PARTIAL: &str = "partial";

/// The folder beside a realm's database: `realm.db` keeps its job artifacts in `realm.job-artifacts`.
pub(super) fn folder_beside(realm: &Path) -> PathBuf {
    realm.with_extension("job-artifacts")
}

impl Shelf {
    pub(super) fn beside(realm: &Path) -> Shelf {
        Shelf { folder: folder_beside(realm) }
    }

    pub(super) fn at(folder: PathBuf) -> Shelf {
        Shelf { folder }
    }

    pub(super) fn folder(&self) -> &Path {
        &self.folder
    }

    fn staging(&self) -> PathBuf {
        self.folder.join(STAGING)
    }

    /// The one file a checksum names. Only ever 64 lowercase hexadecimal characters, so nothing
    /// else can become part of the path.
    fn place(&self, sha256: &str) -> Result<PathBuf, Refusal> {
        if sha256.len() != 64 || !sha256.bytes().all(|letter| matches!(letter, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(Refusal::Trouble("An artifact is kept under its checksum, which is 64 lowercase hexadecimal characters".into()));
        }
        Ok(self.folder.join(sha256))
    }

    /// Streams exactly `size` bytes from `data` into a new file in the staging folder, if they hash
    /// to `sha256`, and answers where it is. Nothing is kept under the checksum yet. Reads at most
    /// one byte more than was declared, which is how a copy that runs long is noticed without
    /// reading on.
    pub(super) fn stage(&self, size: u64, sha256: &str, data: &mut dyn Read) -> Result<PathBuf, Refusal> {
        self.place(sha256)?;
        let staging = self.staging();
        std::fs::create_dir_all(&staging).map_err(|error| Refusal::Trouble(format!("Cannot prepare the folder this grid stages job artifacts in: {error}")))?;
        let partial = staging.join(format!("{sha256}.{}.{PARTIAL}", &crate::token()[..8]));
        if let Err(refusal) = write_checked(&partial, size, sha256, data) {
            let _ = std::fs::remove_file(&partial);
            return Err(refusal);
        }
        Ok(partial)
    }

    /// Puts staged bytes in place under their checksum, and answers whether this made the kept
    /// copy. When a copy is already kept, the same checksum is the same bytes, and the staged file
    /// is simply removed.
    pub(super) fn keep_staged(&self, staged: &Path, sha256: &str) -> Result<bool, Refusal> {
        let target = self.place(sha256)?;
        if target.exists() {
            let _ = std::fs::remove_file(staged);
            return Ok(false);
        }
        match std::fs::rename(staged, &target) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Err(Refusal::Missing),
            Err(error) => {
                let _ = std::fs::remove_file(staged);
                Err(Refusal::Trouble(format!("Cannot keep this artifact: {error}")))
            }
        }
    }

    /// Writes a kept copy into `into`, hashing it on the way, and says so when it no longer
    /// matches what was recorded. Whoever reads must discard what was written if this refuses.
    pub(super) fn send(&self, size: u64, sha256: &str, into: &mut dyn Write) -> Result<u64, Refusal> {
        let place = self.place(sha256)?;
        let mut file = open(&place)?;
        let (sent, digest) = hash_through(&mut file, size, Some(into))?;
        if sent != size || digest != sha256 {
            return Err(Refusal::Damaged);
        }
        Ok(sent)
    }

    /// Removes the kept copy of one checksum. A copy that is already gone is not an error.
    pub(super) fn remove(&self, sha256: &str) -> Result<(), Refusal> {
        let place = self.place(sha256)?;
        match std::fs::remove_file(&place) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Refusal::Trouble(format!("Cannot remove a job artifact's bytes: {error}"))),
        }
    }

    /// Removes staged files that nothing has been written to since `before`, and answers how many
    /// went. An upload that is still arriving keeps its file fresh, so it is never taken from under
    /// the computer sending it; a file that cannot be removed now is left for the next sweep.
    pub(super) fn sweep_staging(&self, before: SystemTime) -> usize {
        let Ok(entries) = std::fs::read_dir(self.staging()) else { return 0 };
        let mut removed = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != PARTIAL) {
                continue;
            }
            let Ok(modified) = entry.metadata().and_then(|about| about.modified()) else { continue };
            if modified < before && std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        removed
    }

    /// Copies one kept file onto another shelf: hashed as it is read, hashed again where it landed,
    /// and only then kept there. A source that does not match its checksum is damaged, and nothing
    /// of it is kept on the other side.
    pub(super) fn carry(&self, to: &Shelf, size: u64, sha256: &str) -> Result<(), Refusal> {
        let source = self.place(sha256)?;
        let mut file = open(&source)?;
        let staged = match to.stage(size, sha256, &mut file) {
            Ok(staged) => staged,
            Err(Refusal::Mismatch | Refusal::Short(_) | Refusal::Long) => return Err(Refusal::Damaged),
            Err(other) => return Err(other),
        };
        let landed = open(&staged).and_then(|mut copy| hash_through(&mut copy, size, None));
        match landed {
            Ok((bytes, digest)) if bytes == size && digest == sha256 => {}
            _ => {
                let _ = std::fs::remove_file(&staged);
                return Err(Refusal::Trouble("A job artifact did not read back as it was written while the realm was being copied".into()));
            }
        }
        to.keep_staged(&staged, sha256).map(|_| ())
    }
}

fn open(path: &Path) -> Result<std::fs::File, Refusal> {
    match std::fs::File::open(path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == ErrorKind::NotFound => Err(Refusal::Missing),
        Err(error) => Err(Refusal::Trouble(format!("Cannot read this artifact: {error}"))),
    }
}

/// Reads a file to its end, at most one byte past `size`, hashing as it goes and passing the bytes
/// on to `into` when there is one. Answers how many bytes there were and what they hashed to.
fn hash_through(file: &mut std::fs::File, size: u64, mut into: Option<&mut dyn Write>) -> Result<(u64, String), Refusal> {
    let mut hasher = Sha256::new();
    let mut seen: u64 = 0;
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let read = match file.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(Refusal::Trouble(format!("Cannot read this artifact: {error}"))),
        };
        if read == 0 {
            break;
        }
        seen += read as u64;
        if seen > size {
            return Err(Refusal::Damaged);
        }
        hasher.update(&buffer[..read]);
        if let Some(into) = into.as_mut() {
            into.write_all(&buffer[..read]).map_err(|error| Refusal::Trouble(format!("Cannot pass this artifact on: {error}")))?;
        }
    }
    Ok((seen, hex::encode(hasher.finalize())))
}

/// Copies `data` into a new file at `path`, counting and hashing as it goes, and flushes it to the
/// disk only once it is known to be exactly what was declared.
fn write_checked(path: &Path, size: u64, sha256: &str, data: &mut dyn Read) -> Result<(), Refusal> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| Refusal::Trouble(format!("Cannot start keeping this artifact: {error}")))?;
    let mut hasher = Sha256::new();
    let mut seen: u64 = 0;
    let mut buffer = vec![0u8; CHUNK];
    let mut limited = data.take(size.saturating_add(1));
    loop {
        let read = match limited.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(Refusal::Trouble(format!("Cannot read this artifact as it arrived: {error}"))),
        };
        if read == 0 {
            break;
        }
        seen += read as u64;
        if seen > size {
            return Err(Refusal::Long);
        }
        hasher.update(&buffer[..read]);
        file.write_all(&buffer[..read]).map_err(|error| Refusal::Trouble(format!("Cannot keep this artifact: {error}")))?;
    }
    if seen < size {
        return Err(Refusal::Short(seen));
    }
    if hex::encode(hasher.finalize()) != sha256 {
        return Err(Refusal::Mismatch);
    }
    file.sync_all().map_err(|error| Refusal::Trouble(format!("Cannot keep this artifact: {error}")))
}
