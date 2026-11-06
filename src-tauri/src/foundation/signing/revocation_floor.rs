//! The trust-root service's revocation floor: every key material an accepted trust-root
//! file revoked, kept on disk so that a revocation survives a restart (S08 in
//! docs/combined-plan-leftover-tasks.md, the remainder "persisting the revocation floor
//! across restarts"; docs/combined-gpu-memory-and-vm-sandbox-plan.md S2 CORE-08, line 217;
//! VM-W45, line 2668: "rollback resistance ... emergency revocation"; VM-W48, line 2671;
//! VM-P48, line 2823: emergency revocation has "documented secure recovery paths").
//!
//! A [`RevocationFloor`] is one file, [`REVOCATION_FLOOR_FILE`], in a directory the caller
//! names (the engine's own data folder). The trust-root service takes it at open
//! (`TrustRootService::open_with_floor`) and refuses, across restarts, every trust-root
//! file that lists, unrevoked, key material the floor holds.
//!
//! - **Key material, not names.** An entry is the key's publisher identity (the
//!   fingerprint of its public key), the id it was revoked as, the reason given and when
//!   the service first saw the revocation ([`FloorRevocation`]). Nothing ties it to the
//!   trust-root file's location or to the ids it uses: a file read from another place, or
//!   listing the key under another id, is judged the same.
//! - **Persist first, then use.** The service records a new revocation here
//!   ([`RevocationFloor::record`]) before the file that carries it is put in force. A
//!   failed write keeps the roots that were in force and is reported. Writes go through
//!   the durable streams' atomic write (`events::owner`), so after a crash the file holds
//!   its old or its new content.
//! - **Read strictly, at open.** The file has the shape of the authority store's files
//!   (coordination/store.rs): a header line, a JSON object naming the file, its format
//!   and the digest of the body, then the body, JSON read strictly. A torn or edited file,
//!   another file under this one's name, another format, a body that breaks the floor's
//!   rules (a bad key id, the same key material twice, too many entries), a file larger
//!   than [`MAX_REVOCATION_FLOOR_BYTES`] or one that cannot be read leaves the floor
//!   unusable ([`FloorState::Unusable`]): a service opened with it trusts nothing, and its
//!   status names the file and the remedy. The file is left as it is, never replaced or
//!   ignored. A missing file is a first run; nothing is written until the first
//!   revocation.
//! - **Lifting a revocation** is the owner's deliberate act, never a reload's or a
//!   restart's: with the engine stopped, the owner removes the floor file, which lifts
//!   every revocation it held, makes sure the trust-root file still revokes every key that
//!   must stay revoked, and starts the engine. The next accepted file seeds the floor
//!   again.
//!
//! Limits: one writer per directory, the service that opened it (the engine holds a
//! single-instance lock on its data folder). The digest guards against tearing and
//! accidental edits, not against someone who rewrites the file with a matching digest.
//! Whoever controls the disk can still remove the floor, or roll it back together with the
//! trust-root file to an older pair; as for the authority store, only a monotonic counter
//! outside the host's storage would catch that, an owner decision recorded under S04.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::roots::RootKeyId;
use crate::foundation::catalog::PublisherId;
use crate::foundation::events::write_atomic;
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::foundation::report::Label;

/// The floor's file in its directory.
pub const REVOCATION_FLOOR_FILE: &str = "revocation-floor.json";

/// The floor file format this build reads and writes; the header carries it. Another
/// format is refused, never reinterpreted.
pub const REVOCATION_FLOOR_FORMAT: u32 = 1;

/// Most revoked key materials one floor holds. A trust-root file lists at most
/// [`super::MAX_TRUST_ROOT_KEYS`]; this leaves room for many files' revocations.
pub const MAX_FLOOR_REVOCATIONS: usize = 4096;

/// Largest floor file read.
pub const MAX_REVOCATION_FLOOR_BYTES: u64 = 4 << 20;

/// What the header's `file` names.
const FILE_TAG: &str = "revocation_floor";

/// Domain of the body's digest, which binds the file's kind and format too.
const BODY_DOMAIN: &str = "yougori/signing/revocation-floor/v1";

/// One revoked key material the floor holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FloorRevocation {
    /// The key material, by its publisher identity: the fingerprint of its public key.
    pub publisher: PublisherId,
    /// The id the key was revoked as in the first accepted file that revoked it.
    pub revoked_as: RootKeyId,
    /// The reason that file gave.
    pub reason: Label,
    /// When the service first saw the revocation, on its calendar.
    pub first_seen: DateTime<Utc>,
}

/// Why a floor file cannot be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FloorProblem {
    /// The file is larger than [`MAX_REVOCATION_FLOOR_BYTES`].
    TooLarge { max_bytes: u64 },
    /// The header line is missing or does not read as one: the file is torn or is no
    /// floor file.
    Header { message: String },
    /// The header names another file: some other store's file is under this one's name.
    OtherFile,
    /// A format this build does not read.
    Format { found: u32 },
    /// The body does not match the header's digest: the file is torn or was edited.
    Digest,
    /// The body matches its digest but does not read as a floor.
    Body { message: String },
    /// The entry at `index` (from zero) has a key id that breaks the identifier rule.
    InvalidKeyId { index: usize },
    /// The same key material is listed twice.
    DuplicateKey { publisher: PublisherId },
    /// More than [`MAX_FLOOR_REVOCATIONS`] entries.
    TooManyRevocations { max: usize },
}

impl fmt::Display for FloorProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { max_bytes } => write!(f, "it is larger than {max_bytes} bytes"),
            Self::Header { message } => write!(f, "its header cannot be read ({message})"),
            Self::OtherFile => f.write_str("its header names another file"),
            Self::Format { found } => write!(
                f,
                "it has format {found}; this build reads format {REVOCATION_FLOOR_FORMAT}"
            ),
            Self::Digest => f.write_str("its body does not match its digest: torn or edited"),
            Self::Body { message } => write!(f, "its body cannot be read ({message})"),
            Self::InvalidKeyId { index } => {
                write!(f, "its entry {index} has an invalid key id")
            }
            Self::DuplicateKey { publisher } => {
                write!(f, "it lists the key of publisher {publisher} twice")
            }
            Self::TooManyRevocations { max } => {
                write!(f, "it lists more than {max} revocations")
            }
        }
    }
}

/// Why the floor cannot be used, or why a revocation was not recorded in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FloorError {
    /// The caller could not name the floor's directory.
    NoDirectory { reason: String },
    /// The floor file, or its directory, could not be read, created or written.
    Io {
        action: &'static str,
        path: PathBuf,
        kind: io::ErrorKind,
        message: String,
    },
    /// The floor file cannot be used. It is left as it is, never replaced.
    Unusable {
        path: PathBuf,
        problem: FloorProblem,
    },
    /// The floor could not be encoded; nothing was written.
    Encoding { message: String },
    /// Recording would take the floor past [`MAX_FLOOR_REVOCATIONS`]; nothing was written.
    Full { max: usize },
}

impl FloorError {
    fn io(action: &'static str, path: &Path, error: &io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

impl fmt::Display for FloorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDirectory { reason } => {
                write!(f, "the revocation floor has no directory: {reason}")
            }
            Self::Io {
                action,
                path,
                message,
                ..
            } => write!(
                f,
                "could not {action} the revocation floor, {}: {message}",
                path.display()
            ),
            Self::Unusable { path, problem } => write!(
                f,
                "the revocation floor, {}, cannot be used: {problem}; it is left as it is",
                path.display()
            ),
            Self::Encoding { message } => {
                write!(f, "the revocation floor could not be encoded: {message}")
            }
            Self::Full { max } => write!(
                f,
                "the revocation floor would hold more than {max} revocations; nothing was \
                 written"
            ),
        }
    }
}

impl std::error::Error for FloorError {}

/// The state of the floor, in the trust-root status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum FloorState {
    /// The service keeps no floor (`TrustRootService::open`): its revocations hold for
    /// its own life only.
    NotKept,
    /// No floor file exists yet: a first run. The first revocation writes it.
    FirstRun,
    /// The floor file was read or written and is in use.
    Kept,
    /// The floor cannot be used, so nothing is trusted until the remedy is done.
    Unusable { problem: String, remedy: String },
}

/// The floor in the trust-root status: where it is, how many revocations it holds and
/// its state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FloorStatus {
    /// The floor file, when its directory is known.
    pub location: Option<String>,
    /// The revoked key materials it holds.
    pub revocations: usize,
    #[serde(flatten)]
    pub state: FloorState,
}

/// The header line of the floor file.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FloorHeader {
    file: String,
    format: u32,
    digest: Digest,
}

/// The body of the floor file.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FloorBody {
    /// In publisher order.
    revocations: Vec<RevocationWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationWire {
    publisher: PublisherId,
    revoked_as: String,
    reason: Label,
    first_seen: DateTime<Utc>,
}

impl From<&FloorRevocation> for RevocationWire {
    fn from(revocation: &FloorRevocation) -> Self {
        Self {
            publisher: revocation.publisher,
            revoked_as: revocation.revoked_as.as_str().to_owned(),
            reason: revocation.reason.clone(),
            first_seen: revocation.first_seen,
        }
    }
}

/// The durable floor of revoked key material. See the module documentation.
#[derive(Debug)]
pub struct RevocationFloor {
    /// The floor file, when its directory is known.
    path: Option<PathBuf>,
    /// Why the floor cannot be used, if it cannot. Fixed at open.
    failure: Option<FloorError>,
    /// Whether the file exists: read at open or written since.
    stored: bool,
    revocations: BTreeMap<PublisherId, FloorRevocation>,
}

impl RevocationFloor {
    /// The floor kept in `directory`, read strictly now. A missing file is a first run;
    /// a file that cannot be used leaves the floor unusable, and the file as it is.
    /// Nothing is created before the first revocation is recorded.
    pub fn open(directory: &Path) -> Self {
        let path = directory.join(REVOCATION_FLOOR_FILE);
        let (failure, stored, revocations) = match read(&path) {
            Ok(None) => (None, false, BTreeMap::new()),
            Ok(Some(revocations)) => (None, true, revocations),
            Err(error) => (Some(error), false, BTreeMap::new()),
        };
        Self {
            path: Some(path),
            failure,
            stored,
            revocations,
        }
    }

    /// A floor whose directory the caller could not name, for `reason`. It is unusable, so
    /// a service opened with it trusts nothing.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            path: None,
            failure: Some(FloorError::NoDirectory {
                reason: reason.into(),
            }),
            stored: false,
            revocations: BTreeMap::new(),
        }
    }

    /// The floor file, when its directory is known.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Why the floor cannot be used, if it cannot.
    pub fn problem(&self) -> Option<&FloorError> {
        self.failure.as_ref()
    }

    /// Every revoked key material the floor holds, in publisher order.
    pub fn revocations(&self) -> impl Iterator<Item = &FloorRevocation> {
        self.revocations.values()
    }

    /// The floor's revocation of `publisher`'s key, if it holds one.
    pub fn revocation(&self, publisher: &PublisherId) -> Option<&FloorRevocation> {
        self.revocations.get(publisher)
    }

    /// How many revoked key materials the floor holds.
    pub fn len(&self) -> usize {
        self.revocations.len()
    }

    /// Whether the floor holds no revocation.
    pub fn is_empty(&self) -> bool {
        self.revocations.is_empty()
    }

    /// Where the floor is, how many revocations it holds and its state.
    pub fn status(&self) -> FloorStatus {
        let state = match &self.failure {
            Some(error) => FloorState::Unusable {
                problem: error.to_string(),
                remedy: self.remedy(),
            },
            None if self.stored => FloorState::Kept,
            None => FloorState::FirstRun,
        };
        FloorStatus {
            location: self.path.as_ref().map(|path| path.display().to_string()),
            revocations: self.revocations.len(),
            state,
        }
    }

    /// What the owner can do about an unusable floor.
    pub(super) fn remedy(&self) -> String {
        match (&self.failure, &self.path) {
            (Some(FloorError::NoDirectory { .. }), _) | (_, None) => {
                "The engine named no folder for the revocation floor, so nothing is trusted: \
                 without it a restart could withdraw a revocation. Start the engine again \
                 once its data folder is available."
                    .to_owned()
            }
            (_, Some(path)) => format!(
                "The revocation floor {} cannot be used, so nothing is trusted; it is left \
                 as it is. Restore it from a backup of the engine's data folder. To lift \
                 every revocation it holds instead, remove it while the engine is stopped, \
                 make sure the trust-root file revokes every key that must stay revoked, and \
                 start the engine.",
                path.display()
            ),
        }
    }

    /// Adds every revocation of `found` whose key material the floor lacks, and writes the
    /// floor, creating its directory if needed, before the caller puts in force the file
    /// that carries them. Returns how many were added; with none, nothing is written. On
    /// an error nothing is added, and the file holds its old content or, if the write
    /// failed only after the new content was in place, the new one: a superset, which the
    /// next record writes again.
    pub(super) fn record(&mut self, found: Vec<FloorRevocation>) -> Result<usize, FloorError> {
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        let Some(path) = self.path.clone() else {
            return Err(FloorError::NoDirectory {
                reason: "the floor was opened without one".to_owned(),
            });
        };
        let mut next = self.revocations.clone();
        for revocation in found {
            next.entry(revocation.publisher).or_insert(revocation);
        }
        let added = next.len().saturating_sub(self.revocations.len());
        if added == 0 {
            return Ok(0);
        }
        if next.len() > MAX_FLOOR_REVOCATIONS {
            return Err(FloorError::Full {
                max: MAX_FLOOR_REVOCATIONS,
            });
        }
        let bytes = encode(&next)?;
        if let Some(directory) = path.parent() {
            fs::create_dir_all(directory)
                .map_err(|error| FloorError::io("create the folder of", &path, &error))?;
        }
        write_atomic(&path, &bytes).map_err(|error| FloorError::io("write", &path, &error))?;
        self.revocations = next;
        self.stored = true;
        Ok(added)
    }
}

/// The floor at `path`, if the file exists.
fn read(path: &Path) -> Result<Option<BTreeMap<PublisherId, FloorRevocation>>, FloorError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(FloorError::io("read", path, &error)),
    };
    let mut bytes = Vec::new();
    file.take(MAX_REVOCATION_FLOOR_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| FloorError::io("read", path, &error))?;
    let unusable = |problem| FloorError::Unusable {
        path: path.to_path_buf(),
        problem,
    };
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_REVOCATION_FLOOR_BYTES {
        return Err(unusable(FloorProblem::TooLarge {
            max_bytes: MAX_REVOCATION_FLOOR_BYTES,
        }));
    }
    decode(&bytes).map(Some).map_err(unusable)
}

/// The digest of `body` in the current format.
fn body_digest(body: &[u8]) -> Digest {
    DigestBuilder::new(BODY_DOMAIN)
        .str(FILE_TAG)
        .u64(u64::from(REVOCATION_FLOOR_FORMAT))
        .bytes(body)
        .finish()
}

/// The floor's bytes: the header line, then the body.
fn encode(revocations: &BTreeMap<PublisherId, FloorRevocation>) -> Result<Vec<u8>, FloorError> {
    let encoding = |error: serde_json::Error| FloorError::Encoding {
        message: error.to_string(),
    };
    let body = FloorBody {
        revocations: revocations.values().map(RevocationWire::from).collect(),
    };
    let body = serde_json::to_vec_pretty(&body).map_err(encoding)?;
    let header = FloorHeader {
        file: FILE_TAG.to_owned(),
        format: REVOCATION_FLOOR_FORMAT,
        digest: body_digest(&body),
    };
    let mut bytes = serde_json::to_vec(&header).map_err(encoding)?;
    bytes.push(b'\n');
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

/// The floor's revocations from its bytes, checked against the header and the floor's
/// rules.
fn decode(bytes: &[u8]) -> Result<BTreeMap<PublisherId, FloorRevocation>, FloorProblem> {
    let mut parts = bytes.splitn(2, |byte| *byte == b'\n');
    let (Some(header), Some(body)) = (parts.next(), parts.next()) else {
        return Err(FloorProblem::Header {
            message: "the file has no header line".to_owned(),
        });
    };
    let header: FloorHeader =
        serde_json::from_slice(header).map_err(|error| FloorProblem::Header {
            message: error.to_string(),
        })?;
    if header.file != FILE_TAG {
        return Err(FloorProblem::OtherFile);
    }
    if header.format != REVOCATION_FLOOR_FORMAT {
        return Err(FloorProblem::Format {
            found: header.format,
        });
    }
    if body_digest(body) != header.digest {
        return Err(FloorProblem::Digest);
    }
    let body: FloorBody = serde_json::from_slice(body).map_err(|error| FloorProblem::Body {
        message: error.to_string(),
    })?;
    if body.revocations.len() > MAX_FLOOR_REVOCATIONS {
        return Err(FloorProblem::TooManyRevocations {
            max: MAX_FLOOR_REVOCATIONS,
        });
    }
    let mut revocations = BTreeMap::new();
    for (index, wire) in body.revocations.into_iter().enumerate() {
        let revoked_as =
            RootKeyId::new(wire.revoked_as).map_err(|_| FloorProblem::InvalidKeyId { index })?;
        let publisher = wire.publisher;
        let revocation = FloorRevocation {
            publisher,
            revoked_as,
            reason: wire.reason,
            first_seen: wire.first_seen,
        };
        if revocations.insert(publisher, revocation).is_some() {
            return Err(FloorProblem::DuplicateKey { publisher });
        }
    }
    Ok(revocations)
}
