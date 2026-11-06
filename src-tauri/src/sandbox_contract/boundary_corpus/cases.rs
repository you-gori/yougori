//! The VM-CP-15 corpus as data (VM part §17 VM-CP-15, line 3154: "the file broker's case
//! corpus: symlink, hard link, junction, reparse point, alternate data stream, UNC and device
//! path, case alias, Unicode normalization, long path, and a rename race during an open
//! cannot escape the granted root", positive control "an in-root relative path resolves";
//! §5.1 line 2213: "Test symlinks, hard links, mount changes, Windows junctions/reparse
//! points, alternate data streams, UNC/device paths, case folding, reserved names, Unicode
//! normalization and path length limits"; VM-P15, line 2779).
//!
//! One [`BoundaryCase`] per item: the entries to build on a real directory, then the
//! actions, each request naming its attack input, the layer expected to stop it and the
//! exact refusal it must give. Nothing here touches a file; [`super::run_case`] does.

use std::fmt;
use std::path::{Component, Path, Prefix};

use serde::{Deserialize, Serialize};

use crate::sandbox_contract::files::{
    FileOperation, GuestName, LinkKind, NameRefusal, ResolveIntent, ResolveRefusal, Resolved,
    MAX_COMPONENT_BYTES, MAX_NAME_BYTES, MAX_NAME_COMPONENTS,
};

/// The link kind a directory link made by the runner is: a junction (`mklink /J`, which
/// needs no privilege) on Windows, a symlink elsewhere.
#[cfg(windows)]
pub const DIR_LINK: LinkKind = LinkKind::Junction;
/// The link kind a directory link made by the runner is: a junction (`mklink /J`, which
/// needs no privilege) on Windows, a symlink elsewhere.
#[cfg(not(windows))]
pub const DIR_LINK: LinkKind = LinkKind::Symlink;

/// The link kind a planted mount is refused as. A Windows volume mount carries the
/// mount-point reparse tag a junction carries, so it is refused as a junction. On Linux,
/// where this process may mount (root), the runner makes a real mount, a directory on a
/// device of its own that the resolver refuses by comparing volumes
/// ([`LinkKind::MountCrossing`]); elsewhere a symlink to `/` stands in and is refused as one.
pub fn mount_link() -> LinkKind {
    if cfg!(windows) {
        LinkKind::Junction
    } else if super::host::can_mount() {
        LinkKind::MountCrossing
    } else {
        LinkKind::Symlink
    }
}

/// The marker every file outside the granted root holds; bytes containing it were read
/// outside the root.
pub const OUTSIDE_CANARY: &[u8] = b"yougori boundary corpus: outside the granted root";

/// The marker every file name in the outside tree carries and no in-root name does, so a
/// listing or a refusal naming such an entry proves a step looked outside the root even
/// when no outside byte is read.
pub const OUTSIDE_SUFFIX: &str = "outside";

/// The name the mount-change case tries to create through the mount; the runner checks it
/// never appears at the mount's target.
pub const MOUNT_PROBE: &str = "yougori-boundary-probe.txt";

/// A third-party reparse tag (no Microsoft bit, no name-surrogate bit) the reparse-point
/// case sets on a file; no file-system filter handles it.
pub const FILE_REPARSE_TAG: u32 = 0x0000_7967;

/// A third-party name-surrogate reparse tag the reparse-point case sets on an empty
/// directory, as a link-like product of another vendor would.
pub const DIRECTORY_REPARSE_TAG: u32 = 0x2000_7967;

/// Swap cycles in the rename race. The known path-based-listing bug showed about once in
/// 18,000 swaps, so a run of this size has a real chance of catching it while staying a
/// few seconds; the swapping thread, not the count, sets the wall time.
pub const RACE_CYCLES: u32 = 4_000;

/// What every file the corpus plants inside the root holds unless a case says otherwise.
const NOTES: &[u8] = b"in-root notes";
/// What a refused write or create would have written.
const PLANTED: &[u8] = b"planted by the boundary corpus";

/// The items of the VM-CP-15 row, the reserved names and mount changes of the §5.1 line,
/// VM-P15's traversal, and the positive control.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseId {
    /// The positive control: an in-root relative path resolves and is served.
    InRootControl,
    Symlink,
    HardLink,
    Junction,
    /// A reparse point of another kind than symlink and junction.
    ReparsePoint,
    AlternateDataStream,
    UncAndDevicePath,
    CaseAlias,
    UnicodeNormalization,
    LongPath,
    RenameRace,
    /// From the §5.1 line.
    ReservedName,
    /// From the §5.1 line.
    MountChange,
    /// From VM-P15.
    Traversal,
}

impl CaseId {
    pub const ALL: [Self; 14] = [
        Self::InRootControl,
        Self::Symlink,
        Self::HardLink,
        Self::Junction,
        Self::ReparsePoint,
        Self::AlternateDataStream,
        Self::UncAndDevicePath,
        Self::CaseAlias,
        Self::UnicodeNormalization,
        Self::LongPath,
        Self::RenameRace,
        Self::ReservedName,
        Self::MountChange,
        Self::Traversal,
    ];

    /// The stable name, also the case's directory name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InRootControl => "in_root_control",
            Self::Symlink => "symlink",
            Self::HardLink => "hard_link",
            Self::Junction => "junction",
            Self::ReparsePoint => "reparse_point",
            Self::AlternateDataStream => "alternate_data_stream",
            Self::UncAndDevicePath => "unc_and_device_path",
            Self::CaseAlias => "case_alias",
            Self::UnicodeNormalization => "unicode_normalization",
            Self::LongPath => "long_path",
            Self::RenameRace => "rename_race",
            Self::ReservedName => "reserved_name",
            Self::MountChange => "mount_change",
            Self::Traversal => "traversal",
        }
    }

    /// Where the plan names the item, in its words.
    pub const fn source(self) -> &'static str {
        match self {
            Self::InRootControl => "VM-CP-15 positive control: an in-root relative path resolves",
            Self::Symlink => "VM-CP-15: symlink",
            Self::HardLink => "VM-CP-15: hard link",
            Self::Junction => "VM-CP-15: junction",
            Self::ReparsePoint => "VM-CP-15: reparse point",
            Self::AlternateDataStream => "VM-CP-15: alternate data stream",
            Self::UncAndDevicePath => "VM-CP-15: UNC and device path",
            Self::CaseAlias => "VM-CP-15: case alias",
            Self::UnicodeNormalization => "VM-CP-15: Unicode normalization",
            Self::LongPath => "VM-CP-15: long path",
            Self::RenameRace => "VM-CP-15: a rename race during an open",
            Self::ReservedName => "VM §5.1: reserved names",
            Self::MountChange => "VM §5.1: mount changes",
            Self::Traversal => "VM-P15: traversal",
        }
    }
}

impl fmt::Display for CaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The layer a probe expects to stop an attack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    /// [`GuestName::parse`], the first filter. The resolver and the file service take only
    /// a [`GuestName`], so a refused text reaches neither.
    NameFilter,
    /// [`GrantedRoot::resolve`](crate::sandbox_contract::files::GrantedRoot::resolve); the
    /// file service runs the operation too and must give the same refusal.
    Resolver,
    /// The file service's reads during a concurrent rename: each is the in-root content or
    /// one of the expected refusals.
    Service,
}

/// Where a setup entry is made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// Beneath the granted root.
    Root,
    /// Beneath the case's directory outside the root, which holds [`OUTSIDE_CANARY`] files.
    Outside,
}

/// What a link points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A name beneath the outside directory; empty for the directory itself.
    Outside(String),
    /// A name beneath the granted root.
    Root(String),
}

/// One entry the runner makes on the real directory. Names are `/`-separated and relative
/// to the root unless a [`Place`] says otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    File {
        place: Place,
        name: String,
        bytes: Vec<u8>,
    },
    Directory {
        place: Place,
        name: String,
    },
    /// A directory link: a junction made with `cmd /D /C mklink /J` on Windows, a symlink
    /// elsewhere ([`DIR_LINK`]).
    DirectoryLink {
        name: String,
        target: Target,
    },
    /// A file symlink; where Windows refuses it for want of the privilege the case is
    /// skipped, never passed.
    FileSymlink {
        name: String,
        target: Target,
    },
    /// A directory symlink, skipped like [`Step::FileSymlink`].
    DirectorySymlink {
        name: String,
        target: Target,
    },
    HardLink {
        name: String,
        target: Target,
    },
    /// An NTFS alternate data stream `name:stream`; nothing is made elsewhere, where the
    /// colon is an ordinary character.
    Stream {
        name: String,
        stream: String,
        bytes: Vec<u8>,
    },
    /// A new empty file, or empty directory, carrying a reparse point with `tag`
    /// (Windows only; the case is skipped elsewhere).
    TaggedReparsePoint {
        name: String,
        directory: bool,
        tag: u32,
    },
    /// A mount at `name`: on Windows a mount-point reparse point (`mklink /J`) to another
    /// volume's system directory, or to the outside directory when there is no other
    /// volume; on Linux as root a real mount (a small tmpfs); elsewhere a symlink to `/`
    /// ([`mount_link`]).
    MountPoint {
        name: String,
    },
    Rename {
        from: String,
        to: String,
    },
}

impl Step {
    /// The step in words, without host paths.
    pub fn describe(&self) -> String {
        let place = |place: &Place| match place {
            Place::Root => "",
            Place::Outside => "outside ",
        };
        let target = |target: &Target| match target {
            Target::Outside(name) if name.is_empty() => "<outside>".to_owned(),
            Target::Outside(name) => format!("<outside>/{name}"),
            Target::Root(name) => name.clone(),
        };
        match self {
            Self::File {
                place: at, name, ..
            } => format!("{}file {name}", place(at)),
            Self::Directory { place: at, name } => format!("{}directory {name}", place(at)),
            Self::DirectoryLink { name, target: to } => {
                format!("directory link {name} -> {}", target(to))
            }
            Self::FileSymlink { name, target: to } => {
                format!("file symlink {name} -> {}", target(to))
            }
            Self::DirectorySymlink { name, target: to } => {
                format!("directory symlink {name} -> {}", target(to))
            }
            Self::HardLink { name, target: to } => format!("hard link {name} -> {}", target(to)),
            Self::Stream { name, stream, .. } => format!("alternate data stream {name}:{stream}"),
            Self::TaggedReparsePoint {
                name,
                directory,
                tag,
            } => format!(
                "reparse point {tag:#010x} on the {} {name}",
                if *directory { "directory" } else { "file" }
            ),
            Self::MountPoint { name } => format!("mount at {name}"),
            Self::Rename { from, to } => format!("rename {from} -> {to}"),
        }
    }
}

/// A host path spelling, applied to a file in the case's outside directory as a guest
/// name: the attack a guest makes by naming a host path instead of a relative name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostSpelling {
    /// `D:\dir\file`.
    Drive,
    /// `D:/dir/file`.
    DriveForward,
    /// `\dir\file`, rooted on the current drive.
    Rooted,
    /// `\\?\D:\dir\file`.
    Verbatim,
    /// `//?/D:/dir/file`.
    VerbatimForward,
    /// `\\.\D:\dir\file`.
    DeviceNamespace,
    /// `\??\D:\dir\file`, the NT object namespace.
    NtNamespace,
    /// `\\?\UNC\localhost\D$\dir\file`.
    VerbatimUnc,
    /// `\\localhost\D$\dir\file`, the administrative share.
    AdministrativeShare,
}

impl HostSpelling {
    pub const ALL: [Self; 9] = [
        Self::Drive,
        Self::DriveForward,
        Self::Rooted,
        Self::Verbatim,
        Self::VerbatimForward,
        Self::DeviceNamespace,
        Self::NtNamespace,
        Self::VerbatimUnc,
        Self::AdministrativeShare,
    ];

    /// The refusal the name filter gives this spelling of any path.
    pub fn expected(self) -> NameRefusal {
        match self {
            Self::Drive | Self::DriveForward => NameRefusal::DrivePath,
            Self::Rooted => NameRefusal::AbsolutePath,
            Self::Verbatim
            | Self::VerbatimForward
            | Self::DeviceNamespace
            | Self::NtNamespace
            | Self::VerbatimUnc => NameRefusal::DevicePath,
            Self::AdministrativeShare => NameRefusal::UncPath,
        }
    }

    fn spell(self, drive: char, parts: &[String]) -> String {
        let back = parts.join("\\");
        let forward = parts.join("/");
        match self {
            Self::Drive => format!("{drive}:\\{back}"),
            Self::DriveForward => format!("{drive}:/{forward}"),
            Self::Rooted => format!("\\{back}"),
            Self::Verbatim => format!("\\\\?\\{drive}:\\{back}"),
            Self::VerbatimForward => format!("//?/{drive}:/{forward}"),
            Self::DeviceNamespace => format!("\\\\.\\{drive}:\\{back}"),
            Self::NtNamespace => format!("\\??\\{drive}:\\{back}"),
            Self::VerbatimUnc => format!("\\\\?\\UNC\\localhost\\{drive}$\\{back}"),
            Self::AdministrativeShare => format!("\\\\localhost\\{drive}$\\{back}"),
        }
    }
}

/// What a guest sends as a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestInput {
    /// The text as given.
    Text(String),
    /// The file `outside` beneath the case's outside directory, spelled as a host path;
    /// the runner fills in the real path.
    HostPath {
        spelling: HostSpelling,
        outside: String,
    },
}

impl GuestInput {
    /// The text sent for a case whose outside directory is `outside_directory`.
    pub fn render(&self, outside_directory: &Path) -> String {
        match self {
            Self::Text(text) => text.clone(),
            Self::HostPath { spelling, outside } => {
                let (drive, mut parts) = decompose(outside_directory);
                parts.extend(outside.split('/').map(str::to_owned));
                spelling.spell(drive, &parts)
            }
        }
    }

    /// The input for a report: characters other than printable ASCII written as `\u{..}`,
    /// and `X:\<outside>` for the host path of the outside directory.
    pub fn describe(&self) -> String {
        let text = match self {
            Self::Text(text) => text.clone(),
            Self::HostPath { spelling, outside } => {
                let mut parts = vec!["<outside>".to_owned()];
                parts.extend(outside.split('/').map(str::to_owned));
                spelling.spell('X', &parts)
            }
        };
        text.chars()
            .map(|character| {
                if character.is_ascii_graphic() || character == ' ' {
                    character.to_string()
                } else {
                    character.escape_unicode().to_string()
                }
            })
            .collect()
    }
}

/// The drive letter (`C` where the path has none) and the components after the root.
fn decompose(path: &Path) -> (char, Vec<String>) {
    let mut drive = 'C';
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                if let Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) = prefix.kind() {
                    drive = char::from(letter);
                }
            }
            Component::RootDir => {}
            other => parts.push(other.as_os_str().to_string_lossy().into_owned()),
        }
    }
    (drive, parts)
}

/// The file-service operation a request makes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeOperation {
    Read,
    List,
    Create {
        bytes: Vec<u8>,
    },
    Write {
        bytes: Vec<u8>,
    },
    Delete,
    /// Renames the probed name to `to`.
    RenameFrom {
        to: GuestName,
    },
    /// Renames the in-root `from` to the probed name.
    RenameInto {
        from: GuestName,
    },
}

impl ProbeOperation {
    /// How the resolver is asked about the probed name: a create's or a rename target's
    /// last component may be absent.
    pub fn intent(&self) -> ResolveIntent {
        match self {
            Self::Create { .. } | Self::RenameInto { .. } => ResolveIntent::Create,
            _ => ResolveIntent::Open,
        }
    }

    pub fn file_operation(&self) -> FileOperation {
        match self {
            Self::Read => FileOperation::Read,
            Self::List => FileOperation::List,
            Self::Create { .. } => FileOperation::Create,
            Self::Write { .. } => FileOperation::Write,
            Self::Delete => FileOperation::Delete,
            Self::RenameFrom { .. } | Self::RenameInto { .. } => FileOperation::Rename,
        }
    }
}

/// What the file service must have done for a request that is served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// The read returned exactly these bytes.
    Read(Vec<u8>),
    /// The create left exactly these bytes at the name beneath the root.
    Created(Vec<u8>),
    /// The listing named exactly these entries.
    Listed(Vec<String>),
}

/// The exact result a request must give.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expected {
    /// The name filter refuses the text with exactly this; nothing below it runs.
    NameRefused(NameRefusal),
    /// The resolver refuses with exactly this, and the file service refuses the operation
    /// with `ServiceRefusal::Resolve` of the same refusal, changing nothing in the root.
    Refused(ResolveRefusal),
    /// The positive outcome: the resolver gives `resolved` and the service performs the
    /// operation inside the root.
    Served { resolved: Resolved, effect: Effect },
}

impl Expected {
    /// The layer expected to stop the request; `None` for a served one.
    pub fn layer(&self) -> Option<Layer> {
        match self {
            Self::NameRefused(_) => Some(Layer::NameFilter),
            Self::Refused(_) => Some(Layer::Resolver),
            Self::Served { .. } => None,
        }
    }
}

/// One guest request with its expected result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub input: GuestInput,
    pub operation: ProbeOperation,
    pub expected: Expected,
}

/// A rename race during opens: while the directory `directory` is swapped `cycles` times
/// with the directory link `link` by renames on another thread, `name` is read, resolved
/// and listed through the service over and over.
///
/// The race is strict. Each round must give exactly one of:
/// - the in-root outcome: `inside` for a read, a file of its length for a resolution, the
///   root's own entries ([`Race::listed`]) for a listing;
/// - one of the `allowed` refusals, whose every named guest name must be one of
///   [`Race::in_root_names`].
///
/// Anything else fails the case: other bytes, an I/O failure, or a refusal naming an entry
/// that exists only outside the root. The last is the point of the outside tree being
/// spelled unlike the root's: a refusal that names `b-outside.txt` proves a step looked
/// outside the granted root, even though no outside byte was read.
///
/// This catches the known path-based-listing bug. On Windows the case-alias check lists
/// each opened directory by its current path, not by its handle (cap-std's `Dir::entries`
/// asks the handle for its path and lists that path), so renames between the two make the
/// listing miss (an I/O "not found") or land on the link's target outside the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Race {
    pub directory: GuestName,
    /// Where the directory waits while the link holds its name.
    pub moved: String,
    pub link: String,
    pub name: GuestName,
    pub inside: Vec<u8>,
    pub cycles: u32,
    pub allowed: Vec<ResolveRefusal>,
    /// The entries a listing of [`Race::directory`] gives when it lands on the real
    /// directory.
    pub listed: Vec<String>,
    /// Every guest name a refusal of this race may name. A refusal naming anything else
    /// has looked outside the granted root.
    pub in_root_names: Vec<GuestName>,
}

/// One step of a case after the root and service are opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// A change to the tree behind the open root, as a guest or another process makes it.
    Change(Step),
    Request(Request),
    Race(Race),
}

/// One corpus case: what to build, then what to do and expect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundaryCase {
    pub id: CaseId,
    /// Made before the root is opened.
    pub setup: Vec<Step>,
    pub actions: Vec<Action>,
    /// Unit tests of the files module that check the same refusals in more detail; the
    /// corpus does not repeat them.
    pub also_covered_by: &'static [&'static str],
}

/// The corpus could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CorpusError {
    /// A name the corpus itself uses does not pass the name filter: a corpus bug.
    CorpusName { text: String, refusal: NameRefusal },
}

impl fmt::Display for CorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CorpusName { text, refusal } => write!(
                f,
                "the corpus name {} is refused: {refusal}",
                text.escape_debug()
            ),
        }
    }
}

impl std::error::Error for CorpusError {}

fn guest(text: &str) -> Result<GuestName, CorpusError> {
    GuestName::parse(text).map_err(|refusal| CorpusError::CorpusName {
        text: text.to_owned(),
        refusal,
    })
}

fn root_file(name: &str, bytes: &[u8]) -> Step {
    Step::File {
        place: Place::Root,
        name: name.to_owned(),
        bytes: bytes.to_vec(),
    }
}

fn root_directory(name: &str) -> Step {
    Step::Directory {
        place: Place::Root,
        name: name.to_owned(),
    }
}

fn outside(name: &str) -> Target {
    Target::Outside(name.to_owned())
}

fn rename(from: &str, to: &str) -> Action {
    Action::Change(Step::Rename {
        from: from.to_owned(),
        to: to.to_owned(),
    })
}

fn request(text: &str, operation: ProbeOperation, expected: Expected) -> Action {
    Action::Request(Request {
        input: GuestInput::Text(text.to_owned()),
        operation,
        expected,
    })
}

fn create(bytes: &[u8]) -> ProbeOperation {
    ProbeOperation::Create {
        bytes: bytes.to_vec(),
    }
}

fn write(bytes: &[u8]) -> ProbeOperation {
    ProbeOperation::Write {
        bytes: bytes.to_vec(),
    }
}

fn link_refused(at: &str, link: LinkKind) -> Result<Expected, CorpusError> {
    Ok(Expected::Refused(ResolveRefusal::LinkRefused {
        at: guest(at)?,
        link,
    }))
}

fn case_alias(requested: &str, stored: &str) -> Result<Expected, CorpusError> {
    Ok(Expected::Refused(ResolveRefusal::CaseAlias {
        requested: guest(requested)?,
        stored: guest(stored)?,
    }))
}

fn byte_count(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

fn served_read(bytes: &[u8]) -> Expected {
    Expected::Served {
        resolved: Resolved::File {
            size_bytes: byte_count(bytes),
            executable: false,
        },
        effect: Effect::Read(bytes.to_vec()),
    }
}

fn served_create(bytes: &[u8]) -> Expected {
    Expected::Served {
        resolved: Resolved::Absent,
        effect: Effect::Created(bytes.to_vec()),
    }
}

/// The whole corpus, one case per [`CaseId`], in [`CaseId::ALL`] order.
pub fn corpus() -> Result<Vec<BoundaryCase>, CorpusError> {
    Ok(vec![
        in_root_control()?,
        symlink()?,
        hard_link()?,
        junction()?,
        reparse_point()?,
        alternate_data_stream()?,
        unc_and_device_path(),
        case_alias_case()?,
        unicode_normalization(),
        long_path()?,
        rename_race()?,
        reserved_name(),
        mount_change()?,
        traversal(),
    ])
}

fn in_root_control() -> Result<BoundaryCase, CorpusError> {
    let main = b"fn main() {}\n";
    let created = b"created inside the root";
    Ok(BoundaryCase {
        id: CaseId::InRootControl,
        setup: vec![
            root_file("src/main.rs", main),
            root_file("notes.txt", NOTES),
        ],
        actions: vec![
            request("src/main.rs", ProbeOperation::Read, served_read(main)),
            request("notes.txt", ProbeOperation::Read, served_read(NOTES)),
            request("src/new.txt", create(created), served_create(created)),
            request(
                "src",
                ProbeOperation::List,
                Expected::Served {
                    resolved: Resolved::Directory,
                    effect: Effect::Listed(vec!["main.rs".to_owned(), "new.txt".to_owned()]),
                },
            ),
        ],
        also_covered_by: &[
            "files::root_tests::the_resolver_matches_the_model_on_a_real_tree",
            "files::service_tests::reads_return_exact_bytes_within_the_read_limit",
        ],
    })
}

fn symlink() -> Result<BoundaryCase, CorpusError> {
    let symlink = LinkKind::Symlink;
    Ok(BoundaryCase {
        id: CaseId::Symlink,
        setup: vec![
            root_file("notes.txt", NOTES),
            Step::FileSymlink {
                name: "file-out".to_owned(),
                target: outside("secret-outside.txt"),
            },
            Step::DirectorySymlink {
                name: "dir-out".to_owned(),
                target: outside(""),
            },
            Step::FileSymlink {
                name: "file-in".to_owned(),
                target: Target::Root("notes.txt".to_owned()),
            },
        ],
        actions: vec![
            request(
                "file-out",
                ProbeOperation::Read,
                link_refused("file-out", symlink)?,
            ),
            request(
                "file-out",
                write(PLANTED),
                link_refused("file-out", symlink)?,
            ),
            request(
                "file-out",
                ProbeOperation::Delete,
                link_refused("file-out", symlink)?,
            ),
            request(
                "dir-out/secret-outside.txt",
                ProbeOperation::Read,
                link_refused("dir-out", symlink)?,
            ),
            request(
                "dir-out/planted.txt",
                create(PLANTED),
                link_refused("dir-out", symlink)?,
            ),
            request(
                "file-in",
                ProbeOperation::Read,
                link_refused("file-in", symlink)?,
            ),
        ],
        also_covered_by: &[
            "files::root_tests::symlinks_to_files_and_directories_are_refused_where_they_can_be_made",
        ],
    })
}

fn hard_link() -> Result<BoundaryCase, CorpusError> {
    let hard = LinkKind::HardLink;
    Ok(BoundaryCase {
        id: CaseId::HardLink,
        setup: vec![
            root_file("notes.txt", NOTES),
            Step::HardLink {
                name: "shadow.txt".to_owned(),
                target: outside("secret-outside.txt"),
            },
        ],
        actions: vec![
            request(
                "shadow.txt",
                ProbeOperation::Read,
                link_refused("shadow.txt", hard)?,
            ),
            request(
                "shadow.txt",
                write(PLANTED),
                link_refused("shadow.txt", hard)?,
            ),
            request(
                "shadow.txt",
                ProbeOperation::Delete,
                link_refused("shadow.txt", hard)?,
            ),
            request(
                "shadow.txt/x",
                create(PLANTED),
                link_refused("shadow.txt", hard)?,
            ),
            request(
                "shadow.txt",
                ProbeOperation::RenameFrom {
                    to: guest("moved.txt")?,
                },
                link_refused("shadow.txt", hard)?,
            ),
        ],
        also_covered_by: &[
            "files::root_tests::a_hard_linked_file_is_refused_for_resolve_open_and_as_an_ancestor",
            "files::service_tests::every_operation_through_or_of_a_link_is_refused",
        ],
    })
}

fn junction() -> Result<BoundaryCase, CorpusError> {
    let escape = || link_refused("escape", DIR_LINK);
    Ok(BoundaryCase {
        id: CaseId::Junction,
        setup: vec![
            root_file("notes.txt", NOTES),
            root_directory("a/b"),
            Step::DirectoryLink {
                name: "escape".to_owned(),
                target: outside(""),
            },
            Step::DirectoryLink {
                name: "a/b/deep".to_owned(),
                target: outside("sub-outside"),
            },
        ],
        actions: vec![
            request("escape/secret-outside.txt", ProbeOperation::Read, escape()?),
            request("escape/sub-outside/deeper-outside.txt", ProbeOperation::Read, escape()?),
            request("escape", ProbeOperation::List, escape()?),
            request("escape/planted.txt", create(PLANTED), escape()?),
            request("escape/secret-outside.txt", write(PLANTED), escape()?),
            request("escape/secret-outside.txt", ProbeOperation::Delete, escape()?),
            request("escape", ProbeOperation::Delete, escape()?),
            request(
                "escape/secret-outside.txt",
                ProbeOperation::RenameFrom {
                    to: guest("stolen.txt")?,
                },
                escape()?,
            ),
            request(
                "escape/notes.txt",
                ProbeOperation::RenameInto {
                    from: guest("notes.txt")?,
                },
                escape()?,
            ),
            request(
                "a/b/deep/deeper-outside.txt",
                ProbeOperation::Read,
                link_refused("a/b/deep", DIR_LINK)?,
            ),
        ],
        also_covered_by: &[
            "files::root_tests::a_directory_link_to_outside_the_root_is_refused_at_every_component_and_never_followed",
            "files::root_tests::a_directory_link_inside_the_root_is_refused_too",
            "files::service_tests::every_operation_through_or_of_a_link_is_refused",
        ],
    })
}

fn reparse_point() -> Result<BoundaryCase, CorpusError> {
    let reparse = LinkKind::ReparsePoint;
    Ok(BoundaryCase {
        id: CaseId::ReparsePoint,
        setup: vec![
            Step::TaggedReparsePoint {
                name: "tagged.dat".to_owned(),
                directory: false,
                tag: FILE_REPARSE_TAG,
            },
            Step::TaggedReparsePoint {
                name: "tagged-dir".to_owned(),
                directory: true,
                tag: DIRECTORY_REPARSE_TAG,
            },
        ],
        actions: vec![
            request(
                "tagged.dat",
                ProbeOperation::Read,
                link_refused("tagged.dat", reparse)?,
            ),
            request(
                "tagged.dat",
                write(PLANTED),
                link_refused("tagged.dat", reparse)?,
            ),
            request(
                "tagged.dat",
                ProbeOperation::Delete,
                link_refused("tagged.dat", reparse)?,
            ),
            request(
                "tagged-dir/x",
                ProbeOperation::Read,
                link_refused("tagged-dir", reparse)?,
            ),
            request(
                "tagged-dir/new.txt",
                create(PLANTED),
                link_refused("tagged-dir", reparse)?,
            ),
            request(
                "tagged-dir",
                ProbeOperation::List,
                link_refused("tagged-dir", reparse)?,
            ),
        ],
        // The model's ReparsePoint entry only; no real reparse point of another kind is made
        // by the files tests.
        also_covered_by: &[
            "files::resolve::tests::every_link_kind_is_refused_as_the_target_and_on_the_way",
        ],
    })
}

fn alternate_data_stream() -> Result<BoundaryCase, CorpusError> {
    let visible = b"the visible content";
    let hidden = b"the hidden stream";
    let stream =
        |byte_offset| Expected::NameRefused(NameRefusal::AlternateDataStream { byte_offset });
    Ok(BoundaryCase {
        id: CaseId::AlternateDataStream,
        setup: vec![
            root_file("notes.txt", visible),
            Step::Stream {
                name: "notes.txt".to_owned(),
                stream: "hidden".to_owned(),
                bytes: hidden.to_vec(),
            },
            root_directory("dir"),
            Step::Stream {
                name: "dir".to_owned(),
                stream: "dstream".to_owned(),
                bytes: hidden.to_vec(),
            },
        ],
        actions: vec![
            request("notes.txt:hidden", ProbeOperation::Read, stream(9)),
            request("notes.txt::$DATA", ProbeOperation::Read, stream(9)),
            request("notes.txt:hidden:$DATA", ProbeOperation::Read, stream(9)),
            request("dir:dstream", ProbeOperation::Read, stream(3)),
            request("notes.txt:hidden", write(PLANTED), stream(9)),
            request("new.txt:stream", create(PLANTED), stream(7)),
            // The stream is not reachable through the main name either.
            request("notes.txt", ProbeOperation::Read, served_read(visible)),
        ],
        also_covered_by: &[
            "files::names::tests::backslashes_streams_and_forbidden_characters_are_refused",
        ],
    })
}

fn unc_and_device_path() -> BoundaryCase {
    let mut actions: Vec<Action> = HostSpelling::ALL
        .into_iter()
        .map(|spelling| {
            Action::Request(Request {
                input: GuestInput::HostPath {
                    spelling,
                    outside: "secret-outside.txt".to_owned(),
                },
                operation: ProbeOperation::Read,
                expected: Expected::NameRefused(spelling.expected()),
            })
        })
        .collect();
    actions.push(Action::Request(Request {
        input: GuestInput::HostPath {
            spelling: HostSpelling::Verbatim,
            outside: "planted-outside.txt".to_owned(),
        },
        operation: create(PLANTED),
        expected: Expected::NameRefused(NameRefusal::DevicePath),
    }));
    for (text, refusal) in [
        (
            "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\secret.txt",
            NameRefusal::DevicePath,
        ),
        ("\\\\.\\PhysicalDrive0", NameRefusal::DevicePath),
        ("\\\\.\\pipe\\yougori", NameRefusal::DevicePath),
        ("//?/UNC/server/share/secret.txt", NameRefusal::DevicePath),
        ("\\\\server\\share\\secret.txt", NameRefusal::UncPath),
        ("//server/share/secret.txt", NameRefusal::UncPath),
    ] {
        actions.push(request(
            text,
            ProbeOperation::Read,
            Expected::NameRefused(refusal),
        ));
    }
    BoundaryCase {
        id: CaseId::UncAndDevicePath,
        setup: Vec::new(),
        actions,
        also_covered_by: &["files::names::tests::absolute_drive_unc_and_device_paths_are_refused"],
    }
}

fn case_alias_case() -> Result<BoundaryCase, CorpusError> {
    let inner = b"inner";
    let alias_name = |index| Expected::NameRefused(NameRefusal::ShortNameAlias { index });
    let trailing = |index| Expected::NameRefused(NameRefusal::TrailingDotOrSpace { index });
    Ok(BoundaryCase {
        id: CaseId::CaseAlias,
        setup: vec![
            root_file("Notes.txt", NOTES),
            root_file("Data/inner.txt", inner),
            root_file("LongDirectoryName/inner.txt", inner),
            Step::DirectoryLink {
                name: "Escape".to_owned(),
                target: outside(""),
            },
        ],
        actions: vec![
            request(
                "notes.txt",
                ProbeOperation::Read,
                case_alias("notes.txt", "Notes.txt")?,
            ),
            request(
                "NOTES.TXT",
                create(PLANTED),
                case_alias("NOTES.TXT", "Notes.txt")?,
            ),
            request(
                "DATA/inner.txt",
                ProbeOperation::Read,
                case_alias("DATA", "Data")?,
            ),
            request(
                "data/inner.txt",
                write(PLANTED),
                case_alias("data", "Data")?,
            ),
            request(
                "escape/secret-outside.txt",
                ProbeOperation::Read,
                case_alias("escape", "Escape")?,
            ),
            request("LONGDI~1/inner.txt", ProbeOperation::Read, alias_name(0)),
            request("Notes.txt.", ProbeOperation::Read, trailing(0)),
            request("Notes.txt ", ProbeOperation::Read, trailing(0)),
            request("Notes.txt", ProbeOperation::Read, served_read(NOTES)),
        ],
        also_covered_by: &[
            "files::root_tests::a_case_alias_is_refused_with_the_stored_spelling",
            "files::service_tests::create_refuses_an_existing_name_and_needs_a_real_parent",
            "files::names::tests::short_name_aliases_are_refused",
            "files::names::tests::trailing_dots_and_spaces_are_refused",
        ],
    })
}

fn unicode_normalization() -> BoundaryCase {
    let non_ascii = |byte_offset| Expected::NameRefused(NameRefusal::NonAscii { byte_offset });
    BoundaryCase {
        id: CaseId::UnicodeNormalization,
        setup: vec![
            // Stored composed (NFC); the decomposed spelling would alias it on a volume that
            // normalizes names.
            root_file("caf\u{e9}.txt", NOTES),
            root_file("notes.txt", NOTES),
        ],
        actions: vec![
            request("caf\u{e9}.txt", ProbeOperation::Read, non_ascii(3)),
            request("cafe\u{301}.txt", ProbeOperation::Read, non_ascii(4)),
            // Full-width full stops and solidus: traversal after a best-fit conversion.
            request(
                "\u{ff0e}\u{ff0e}/outside/secret.txt",
                ProbeOperation::Read,
                non_ascii(0),
            ),
            request("..\u{ff0f}secret.txt", ProbeOperation::Read, non_ascii(2)),
            // A full-width reverse solidus becomes '\' under the ANSI best-fit mapping.
            request("..\u{ff3c}secret.txt", ProbeOperation::Read, non_ascii(2)),
            request("\u{2025}/secret.txt", ProbeOperation::Read, non_ascii(0)),
            request("notes\u{200b}.txt", ProbeOperation::Read, non_ascii(5)),
            // The Kelvin sign folds to 'k' under Unicode case folding.
            request("\u{212a}elvin.txt", create(PLANTED), non_ascii(0)),
        ],
        also_covered_by: &["files::names::tests::control_and_non_ascii_characters_are_refused"],
    }
}

fn long_path() -> Result<BoundaryCase, CorpusError> {
    let first = "a".repeat(200);
    let second = "b".repeat(200);
    let third = "c".repeat(200);
    let deep = format!("{first}/{second}/{third}/d");
    let inside = b"deep inside the root";
    let created = b"created deep inside the root";
    let component = "x".repeat(MAX_COMPONENT_BYTES + 1);
    let too_long = vec!["y".repeat(250); 5].join("/");
    let too_deep = vec!["d"; MAX_NAME_COMPONENTS + 1].join("/");
    Ok(BoundaryCase {
        id: CaseId::LongPath,
        // Made with short names, so `mklink` never sees a long path, then renamed until the
        // host path is far beyond MAX_PATH (260 characters).
        setup: vec![
            root_file("a/b/c/d/in.txt", inside),
            Step::DirectoryLink {
                name: "a/b/c/d/escape".to_owned(),
                target: outside(""),
            },
            Step::Rename {
                from: "a/b/c".to_owned(),
                to: format!("a/b/{third}"),
            },
            Step::Rename {
                from: "a/b".to_owned(),
                to: format!("a/{second}"),
            },
            Step::Rename {
                from: "a".to_owned(),
                to: first.clone(),
            },
        ],
        actions: vec![
            request(
                &format!("{deep}/in.txt"),
                ProbeOperation::Read,
                served_read(inside),
            ),
            request(
                &format!("{deep}/new.txt"),
                create(created),
                served_create(created),
            ),
            request(
                &format!("{deep}/escape/secret-outside.txt"),
                ProbeOperation::Read,
                link_refused(&format!("{deep}/escape"), DIR_LINK)?,
            ),
            request(
                &format!("{deep}/escape/planted.txt"),
                create(PLANTED),
                link_refused(&format!("{deep}/escape"), DIR_LINK)?,
            ),
            request(
                &component,
                ProbeOperation::Read,
                Expected::NameRefused(NameRefusal::ComponentTooLong {
                    index: 0,
                    bytes: component.len(),
                    limit: MAX_COMPONENT_BYTES,
                }),
            ),
            request(
                &too_long,
                ProbeOperation::Read,
                Expected::NameRefused(NameRefusal::NameTooLong {
                    bytes: too_long.len(),
                    limit: MAX_NAME_BYTES,
                }),
            ),
            request(
                &too_deep,
                ProbeOperation::Read,
                Expected::NameRefused(NameRefusal::TooManyComponents {
                    components: MAX_NAME_COMPONENTS + 1,
                    limit: MAX_NAME_COMPONENTS,
                }),
            ),
        ],
        also_covered_by: &["files::names::tests::overlong_components_and_names_are_refused"],
    })
}

fn rename_race() -> Result<BoundaryCase, CorpusError> {
    let inside = b"inside the root";
    let swapped = || link_refused("a", DIR_LINK);
    Ok(BoundaryCase {
        id: CaseId::RenameRace,
        setup: vec![
            root_file("a/b.txt", inside),
            Step::DirectoryLink {
                name: "j".to_owned(),
                target: outside(""),
            },
        ],
        actions: vec![
            request("a/b.txt", ProbeOperation::Read, served_read(inside)),
            // Swapped between two opens: the next open meets the link as itself.
            rename("a", "a-moved"),
            rename("j", "a"),
            request("a/b.txt", ProbeOperation::Read, swapped()?),
            request("a/planted.txt", create(PLANTED), swapped()?),
            rename("a", "j"),
            rename("a-moved", "a"),
            // Swapped during the opens, over and over.
            Action::Race(Race {
                directory: guest("a")?,
                moved: "a-moved".to_owned(),
                link: "j".to_owned(),
                name: guest("a/b.txt")?,
                inside: inside.to_vec(),
                cycles: RACE_CYCLES,
                allowed: vec![
                    ResolveRefusal::LinkRefused {
                        at: guest("a")?,
                        link: DIR_LINK,
                    },
                    ResolveRefusal::NotFound { at: guest("a")? },
                    ResolveRefusal::NotFound {
                        at: guest("a/b.txt")?,
                    },
                ],
                listed: vec!["b.txt".to_owned()],
                in_root_names: vec![guest("a")?, guest("a/b.txt")?],
            }),
            request("a/b.txt", ProbeOperation::Read, served_read(inside)),
        ],
        also_covered_by: &[
            "files::root_tests::a_directory_swapped_for_a_link_mid_walk_never_yields_the_outside_file",
            "files::root_tests::a_file_swapped_after_it_was_opened_is_still_the_opened_file",
            "files::root_tests::a_hard_link_planted_after_the_parent_was_opened_is_met_as_itself",
        ],
    })
}

fn reserved_name() -> BoundaryCase {
    let reserved = |index| Expected::NameRefused(NameRefusal::ReservedName { index });
    BoundaryCase {
        id: CaseId::ReservedName,
        setup: vec![root_directory("dir")],
        actions: vec![
            request("CON", ProbeOperation::Read, reserved(0)),
            request("nul.txt", create(PLANTED), reserved(0)),
            request("dir/COM1.log", write(PLANTED), reserved(1)),
            request("LPT9", ProbeOperation::Read, reserved(0)),
            request("CONIN$", ProbeOperation::Read, reserved(0)),
            request("CLOCK$", ProbeOperation::Read, reserved(0)),
            request("dir/aux.tar.gz", ProbeOperation::Read, reserved(1)),
            request("NUL .txt", ProbeOperation::Read, reserved(0)),
            // A superscript digit makes COM¹ a device on Windows; it is not ASCII.
            request(
                "COM\u{b9}",
                ProbeOperation::Read,
                Expected::NameRefused(NameRefusal::NonAscii { byte_offset: 3 }),
            ),
        ],
        also_covered_by: &[
            "files::names::tests::reserved_names_are_refused_with_any_extension_and_case",
        ],
    }
}

/// A mount change: a directory replaced by a mount after the root was opened.
///
/// Which branch of the resolver this reaches depends on the platform. On Windows a volume
/// mount point is a reparse point carrying the mount-point tag, so the walk stops at the
/// link check and the refusal is a junction's; the resolver's separate `MountCrossing`
/// branch, which compares volume serials of an entry that is *not* a reparse point, is
/// unreachable there. On Linux as root the runner mounts a tmpfs at the name, an entry on
/// another device with no link at all, so that branch is what refuses it (first run on 31
/// October 2026); without root a symlink stands in and only the link branch is exercised.
/// The runner measures and records which it was, so the note says what this run
/// exercised.
fn mount_change() -> Result<BoundaryCase, CorpusError> {
    let inside = b"inside the root";
    let mounted = || link_refused("data", mount_link());
    Ok(BoundaryCase {
        id: CaseId::MountChange,
        setup: vec![root_file("data/inside.txt", inside)],
        actions: vec![
            request("data/inside.txt", ProbeOperation::Read, served_read(inside)),
            // The directory is replaced by a mount after the root and service were opened.
            rename("data", "data-before-mount"),
            Action::Change(Step::MountPoint {
                name: "data".to_owned(),
            }),
            request("data/inside.txt", ProbeOperation::Read, mounted()?),
            request(&format!("data/{MOUNT_PROBE}"), create(PLANTED), mounted()?),
            request("data", ProbeOperation::List, mounted()?),
            request("data", ProbeOperation::Delete, mounted()?),
            request(
                "data-before-mount/inside.txt",
                ProbeOperation::Read,
                served_read(inside),
            ),
        ],
        // The model's MountCrossing entry; the files tests make no real mount.
        also_covered_by: &[
            "files::resolve::tests::every_link_kind_is_refused_as_the_target_and_on_the_way",
        ],
    })
}

fn traversal() -> BoundaryCase {
    let traversal = |index| Expected::NameRefused(NameRefusal::Traversal { index });
    BoundaryCase {
        id: CaseId::Traversal,
        setup: vec![root_file("notes.txt", NOTES)],
        actions: vec![
            request("..", ProbeOperation::List, traversal(0)),
            request("../outside/secret.txt", ProbeOperation::Read, traversal(0)),
            request(
                "notes/../../outside/secret.txt",
                ProbeOperation::Read,
                traversal(1),
            ),
            request("../outside/planted.txt", create(PLANTED), traversal(0)),
            request(
                "./notes.txt",
                ProbeOperation::Read,
                Expected::NameRefused(NameRefusal::DotComponent { index: 0 }),
            ),
        ],
        also_covered_by: &["files::names::tests::traversal_and_dot_components_are_refused"],
    }
}
