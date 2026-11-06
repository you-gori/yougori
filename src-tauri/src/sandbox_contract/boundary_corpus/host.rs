//! Building a case on a real directory and observing it without following anything
//! (VM-CP-15 "host-observed").
//!
//! Every case gets its own directory beneath the caller's scratch directory: `root`, the
//! granted root, and `outside`, which holds files marked with [`OUTSIDE_CANARY`] for links
//! to point at. Junctions are made with `cmd /D /C mklink /J` (no privilege needed); symlinks
//! with the standard library, and a refusal for want of the privilege is reported as such,
//! so the case is skipped rather than passed. Reparse points of another kind get a
//! third-party tag through `FSCTL_SET_REPARSE_POINT`, which needs no privilege. Snapshots
//! record every entry beneath a directory without following a link or reparse point.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::cases::{CaseId, Place, Step, Target, OUTSIDE_CANARY};
use super::report::SkipReason;
use crate::foundation::ids::{digest, Digest};

/// Domain of the digests a [`Snapshot`] keeps of file contents.
const SNAPSHOT_DOMAIN: &str = "yougori/sandbox/boundary-corpus/snapshot/v1";

/// Why a step was not made.
#[derive(Debug)]
pub(super) enum StepProblem {
    /// The step cannot be made here, for the reason given; the case is skipped.
    Skip(SkipReason),
    /// `cmd /D /C mklink /J` exited unsuccessfully.
    Command {
        code: Option<i32>,
    },
    Io(io::ErrorKind),
}

impl From<io::Error> for StepProblem {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

impl std::fmt::Display for StepProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Skip(reason) => write!(f, "skipped: {reason}"),
            Self::Command { code: Some(code) } => write!(f, "mklink exited with code {code}"),
            Self::Command { code: None } => f.write_str("mklink was stopped"),
            Self::Io(kind) => write!(f, "{kind:?}"),
        }
    }
}

/// What a step left that the runner checks after the case.
pub(super) enum Applied {
    Done,
    /// A stream that must still hold `bytes` when the case ends.
    Stream {
        path: PathBuf,
        bytes: Vec<u8>,
    },
    /// A mount at `link` to `target`; nothing may appear at `target` through it.
    /// `other_volume` is the measured answer to whether the target sits on another
    /// volume than the root, or `None` when neither volume could be read. `real` is a real
    /// mount (Linux, as root), taken down before the case directory is removed.
    Mounted {
        link: PathBuf,
        target: PathBuf,
        other_volume: Option<bool>,
        real: bool,
    },
}

/// Whether a planted mount is a real one here: on Linux, when this process may mount.
pub(super) fn can_mount() -> bool {
    platform::can_mount()
}

/// Takes down a real mount the runner made.
pub(super) fn unmount(link: &Path) -> io::Result<()> {
    platform::unmount(link)
}

/// One case's directory: the granted root and the outside tree beside it.
pub(super) struct CaseTree {
    pub base: PathBuf,
    pub root: PathBuf,
    pub outside: PathBuf,
}

impl CaseTree {
    /// Makes `scratch/<case>` (which must not exist), the empty root and the outside tree,
    /// each file holding [`OUTSIDE_CANARY`] and a suffix of its own.
    ///
    /// Every outside name is spelled unlike every in-root name ([`OUTSIDE_SUFFIX`]), so a
    /// listing or a refusal that lands outside the root names an entry no in-root step
    /// could have produced, and is visible even when no outside byte is read. The race's
    /// target directory has a second entry for the same reason.
    pub fn create(scratch: &Path, case: CaseId) -> io::Result<Self> {
        let base = scratch.join(case.as_str());
        fs::create_dir(&base)?;
        let tree = Self {
            root: base.join("root"),
            outside: base.join("outside"),
            base,
        };
        fs::create_dir(&tree.root)?;
        fs::create_dir_all(tree.outside.join("sub-outside"))?;
        for (name, suffix) in [
            ("secret-outside.txt", &b" (secret)"[..]),
            ("sub-outside/deeper-outside.txt", &b" (deeper)"[..]),
            ("b-outside.txt", &b" (race target)"[..]),
            ("also-outside.txt", &b" (race sibling)"[..]),
        ] {
            fs::write(
                tree.host(Place::Outside, name),
                [OUTSIDE_CANARY, suffix].concat(),
            )?;
        }
        Ok(tree)
    }

    /// The host path of the `/`-separated `name` beneath `place`.
    pub fn host(&self, place: Place, name: &str) -> PathBuf {
        let base = match place {
            Place::Root => &self.root,
            Place::Outside => &self.outside,
        };
        name.split('/')
            .filter(|part| !part.is_empty())
            .fold(base.clone(), |path, part| path.join(part))
    }

    fn target(&self, target: &Target) -> PathBuf {
        match target {
            Target::Outside(name) => self.host(Place::Outside, name),
            Target::Root(name) => self.host(Place::Root, name),
        }
    }

    /// Makes `step`.
    pub fn apply(&self, step: &Step) -> Result<Applied, StepProblem> {
        match step {
            Step::File { place, name, bytes } => {
                let path = self.host(*place, name);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(path, bytes)?;
            }
            Step::Directory { place, name } => fs::create_dir_all(self.host(*place, name))?,
            Step::DirectoryLink { name, target } => {
                platform::directory_link(&self.host(Place::Root, name), &self.target(target))?;
            }
            Step::FileSymlink { name, target } => {
                platform::file_symlink(&self.host(Place::Root, name), &self.target(target))?;
            }
            Step::DirectorySymlink { name, target } => {
                platform::directory_symlink(&self.host(Place::Root, name), &self.target(target))?;
            }
            Step::HardLink { name, target } => {
                fs::hard_link(self.target(target), self.host(Place::Root, name))?;
            }
            Step::Stream {
                name,
                stream,
                bytes,
            } => {
                return Ok(
                    platform::stream(&self.host(Place::Root, name), stream, bytes)?.map_or(
                        Applied::Done,
                        |path| Applied::Stream {
                            path,
                            bytes: bytes.clone(),
                        },
                    ),
                );
            }
            Step::TaggedReparsePoint {
                name,
                directory,
                tag,
            } => platform::tagged_reparse_point(&self.host(Place::Root, name), *directory, *tag)?,
            Step::MountPoint { name } => {
                let link = self.host(Place::Root, name);
                let (target, real) = platform::mount_point(&link, &self.root, &self.outside)?;
                // Measured, not assumed: the volume the target really sits on, compared
                // with the root's, so the case can insist it crossed one.
                let other_volume = match (
                    platform::volume_serial(&self.root),
                    platform::volume_serial(&target),
                ) {
                    (Some(root), Some(target)) => Some(root != target),
                    _ => None,
                };
                return Ok(Applied::Mounted {
                    link,
                    target,
                    other_volume,
                    real,
                });
            }
            Step::Rename { from, to } => {
                fs::rename(self.host(Place::Root, from), self.host(Place::Root, to))?;
            }
        }
        Ok(Applied::Done)
    }

    /// Removes the case directory. Links are removed as links: the standard library's
    /// recursive removal never descends into a symlink, junction or mount point.
    pub fn remove(self) -> io::Result<()> {
        fs::remove_dir_all(&self.base)
    }
}

/// What one entry is, read without following it. Every field a change could hide in is
/// recorded, so a case fails on a retargeted link, a rewritten or touched file, a new hard
/// link or a new alternate data stream, not only on a changed name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Observed {
    Directory,
    /// A symlink, junction, mount point or other reparse point, never entered or read:
    /// its reparse tag and the target it names, read without following it.
    Link {
        tag: u32,
        target: String,
    },
    File {
        content: Digest,
        size_bytes: u64,
        /// The write time, so a rewrite with the same bytes is still a change.
        modified_nanos: u128,
        /// Names this file has; a new hard link to it changes this.
        links: u64,
        /// Alternate data streams by name and length (Windows); empty elsewhere.
        streams: Vec<(String, u64)>,
    },
}

/// Every entry beneath a directory by `/`-separated name.
pub(super) type Snapshot = BTreeMap<String, Observed>;

/// Records every entry beneath `base` without following links or reparse points.
pub(super) fn snapshot(base: &Path) -> io::Result<Snapshot> {
    let mut found = Snapshot::new();
    let mut pending = vec![(base.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            let observed = if platform::is_link(&metadata) {
                Observed::Link {
                    tag: platform::reparse_tag(&path).unwrap_or_default(),
                    // A target that is not valid Unicode is recorded lossily; it is only
                    // ever compared with itself.
                    target: fs::read_link(&path)
                        .map(|target| target.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                }
            } else if metadata.is_dir() {
                pending.push((path, format!("{name}/")));
                Observed::Directory
            } else {
                let bytes = fs::read(&path)?;
                Observed::File {
                    content: digest(SNAPSHOT_DOMAIN, &[bytes.as_slice()]),
                    size_bytes: metadata.len(),
                    modified_nanos: metadata
                        .modified()
                        .ok()
                        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|since| since.as_nanos())
                        .unwrap_or_default(),
                    links: platform::link_count(&path),
                    streams: platform::streams(&path),
                }
            };
            found.insert(name, observed);
        }
    }
    Ok(found)
}

/// Whether `bytes` hold the marker of the files outside the root.
pub(super) fn holds_canary(bytes: &[u8]) -> bool {
    bytes
        .windows(OUTSIDE_CANARY.len())
        .any(|window| window == OUTSIDE_CANARY)
}

#[cfg(windows)]
mod platform {
    use std::ffi::OsString;
    use std::fs::{self, Metadata};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use std::path::{Component, Path, PathBuf, Prefix};
    use std::process::{Command, Stdio};

    use windows_sys::Win32::Storage::FileSystem::{
        FileAttributeTagInfo, FileStreamInfo, GetDriveTypeW, GetFileInformationByHandle,
        GetFileInformationByHandleEx, GetLogicalDrives, BY_HANDLE_FILE_INFORMATION,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    use super::{SkipReason, StepProblem};

    /// ERROR_PRIVILEGE_NOT_HELD: no SeCreateSymbolicLinkPrivilege and no Developer Mode.
    const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;
    /// The control code that sets a reparse point on an open handle.
    const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
    /// The GUID a third-party reparse point carries; any GUID will do.
    const REPARSE_GUID: u128 = 0x7967_626f_756e_6461_7279_636f_7270_7573;
    /// The private data of the corpus's reparse points.
    const REPARSE_DATA: &[u8] = b"yougori boundary corpus";
    /// `GetDriveTypeW`'s answer for a fixed disk (`DRIVE_FIXED`, in the
    /// `Win32_System_WindowsProgramming` feature this crate does not enable).
    const DRIVE_FIXED: u32 = 3;

    /// No real mount is made on Windows: a junction to another volume stands in.
    pub fn can_mount() -> bool {
        false
    }

    /// The mount stand-in: a junction to [`mount_target`]; never a real mount.
    pub fn mount_point(
        link: &Path,
        root: &Path,
        outside: &Path,
    ) -> Result<(PathBuf, bool), StepProblem> {
        let (target, _) = mount_target(root, outside);
        directory_link(link, &target)?;
        Ok((target, false))
    }

    pub fn unmount(_link: &Path) -> io::Result<()> {
        Ok(())
    }

    /// A junction made by `cmd /D /C mklink /J`, which needs no privilege.
    pub fn directory_link(link: &Path, target: &Path) -> Result<(), StepProblem> {
        let status = Command::new("cmd")
            .arg("/D")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(StepProblem::Command {
                code: status.code(),
            })
        }
    }

    fn symlink_made(made: io::Result<()>) -> Result<(), StepProblem> {
        match made {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD) => {
                Err(StepProblem::Skip(SkipReason::SymlinkPrivilege))
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn file_symlink(link: &Path, target: &Path) -> Result<(), StepProblem> {
        symlink_made(std::os::windows::fs::symlink_file(target, link))
    }

    pub fn directory_symlink(link: &Path, target: &Path) -> Result<(), StepProblem> {
        symlink_made(std::os::windows::fs::symlink_dir(target, link))
    }

    /// Writes the stream `path:stream`; returns its path.
    pub fn stream(path: &Path, stream: &str, bytes: &[u8]) -> io::Result<Option<PathBuf>> {
        let mut name = OsString::from(path.as_os_str());
        name.push(":");
        name.push(stream);
        let path = PathBuf::from(name);
        fs::write(&path, bytes)?;
        Ok(Some(path))
    }

    /// A new empty file or directory at `path` carrying a reparse point with the
    /// third-party `tag`, in the REPARSE_GUID_DATA_BUFFER layout such tags require.
    pub fn tagged_reparse_point(path: &Path, directory: bool, tag: u32) -> Result<(), StepProblem> {
        if directory {
            fs::create_dir(path)?;
        } else {
            fs::write(path, b"")?;
        }
        let file = fs::OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let data_length = u16::try_from(REPARSE_DATA.len())
            .map_err(|_| StepProblem::Io(io::ErrorKind::InvalidInput))?;
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&tag.to_le_bytes());
        buffer.extend_from_slice(&data_length.to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes());
        buffer.extend_from_slice(&uuid::Uuid::from_u128(REPARSE_GUID).to_bytes_le());
        buffer.extend_from_slice(REPARSE_DATA);
        let length = u32::try_from(buffer.len())
            .map_err(|_| StepProblem::Io(io::ErrorKind::InvalidInput))?;
        let mut returned = 0u32;
        // SAFETY: `file` is an open handle with write access for the whole call; the input
        // pointer and `length` describe `buffer`, which outlives the call; no output buffer
        // is passed, `returned` is a writable u32 and the call is synchronous.
        let done = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_SET_REPARSE_POINT,
                buffer.as_ptr().cast(),
                length,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if done == 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn drive(path: &Path) -> Option<u8> {
        match path.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                    Some(letter.to_ascii_uppercase())
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// An existing directory on another volume than the root, for the mount case to cross
    /// to: the Windows directory when it is on another volume (nobody but the system may
    /// change it), else the root of another fixed volume ([`other_fixed_volume`]; the case
    /// never writes through the mount, and checks that nothing appeared at the target),
    /// else the outside directory on the root's own volume; and whether another volume was
    /// found. Before 30 October 2026 only the Windows directory was tried, so the corpus
    /// could cross a volume only when its scratch directory was off the system drive, and
    /// the whole-corpus test failed wherever TMP stayed on it.
    pub fn mount_target(root: &Path, outside: &Path) -> (PathBuf, bool) {
        let system = std::env::var_os("SystemRoot").map(PathBuf::from);
        if let Some(system) = system.filter(|system| {
            system.is_dir() && drive(system).is_some() && drive(system) != drive(root)
        }) {
            return (system, true);
        }
        match other_fixed_volume(root) {
            Some(volume) => (volume, true),
            None => (outside.to_path_buf(), false),
        }
    }

    /// The root directory of the first fixed volume that is not the root's (A to Z, from
    /// `GetLogicalDrives`): never a removable, optical, network or RAM drive, whose
    /// presence and speed are not this computer's to rely on.
    fn other_fixed_volume(root: &Path) -> Option<PathBuf> {
        // SAFETY: `GetLogicalDrives` takes no arguments and returns a bitmask.
        let drives = unsafe { GetLogicalDrives() };
        (b'A'..=b'Z')
            .filter(|letter| drives & (1u32 << (letter - b'A')) != 0)
            .filter(|letter| Some(*letter) != drive(root))
            .find_map(|letter| {
                let path = PathBuf::from(format!("{}:\\", char::from(letter)));
                let wide: Vec<u16> = path
                    .as_os_str()
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();
                // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives the call.
                let kind = unsafe { GetDriveTypeW(wide.as_ptr()) };
                (kind == DRIVE_FIXED && path.is_dir()).then_some(path)
            })
    }

    /// The volume serial number the directory at `path` sits on.
    pub fn volume_serial(path: &Path) -> Option<u32> {
        let file = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .ok()?;
        // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is a valid value of this plain C
        // struct of integers.
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the handle is open for the whole call and `information` is writable.
        let read = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) };
        (read != 0).then_some(information.dwVolumeSerialNumber)
    }

    /// Any reparse point: symlinks, junctions, mount points and other tags.
    pub fn is_link(metadata: &Metadata) -> bool {
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    /// The reparse tag of the entry at `path`, read without following it, so a link
    /// retargeted to another kind is a change.
    pub fn reparse_tag(path: &Path) -> Option<u32> {
        fs::symlink_metadata(path)
            .ok()
            .map(|metadata| metadata.file_attributes())
            .and_then(|_| {
                let file = fs::OpenOptions::new()
                    .access_mode(FILE_READ_ATTRIBUTES)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(path)
                    .ok()?;
                let mut tag = FILE_ATTRIBUTE_TAG_INFO {
                    FileAttributes: 0,
                    ReparseTag: 0,
                };
                let size = u32::try_from(std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>()).ok()?;
                // SAFETY: the handle is open for the whole call and `tag` is a writable
                // FILE_ATTRIBUTE_TAG_INFO of exactly `size` bytes.
                let read = unsafe {
                    GetFileInformationByHandleEx(
                        file.as_raw_handle(),
                        FileAttributeTagInfo,
                        (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                        size,
                    )
                };
                (read != 0).then_some(tag.ReparseTag)
            })
    }

    /// How many names the file at `path` has. The standard library's accessor is
    /// unstable, so the count comes from the handle, as `files::fsutil` reads it.
    pub fn link_count(path: &Path) -> u64 {
        let Ok(file) = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
        else {
            return 0;
        };
        // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is a valid value of this plain C
        // struct of integers.
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the handle is open for the whole call and `information` is writable.
        let read = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) };
        if read == 0 {
            return 0;
        }
        u64::from(information.nNumberOfLinks)
    }

    /// The alternate data streams of the file at `path`, by name and length, so one added
    /// or changed behind the corpus's back is a change. The unnamed `::$DATA` stream is
    /// the file's own content and is left out.
    pub fn streams(path: &Path) -> Vec<(String, u64)> {
        let Ok(file) = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
        else {
            return Vec::new();
        };
        // FILE_STREAM_INFO is a variable-length chain; 64 KiB holds far more streams than
        // any corpus file has.
        let mut buffer = vec![0u8; 64 * 1024];
        let Ok(size) = u32::try_from(buffer.len()) else {
            return Vec::new();
        };
        // SAFETY: the handle is open for the whole call and `buffer` is writable for
        // exactly `size` bytes; nothing is read from it unless the call succeeds.
        let read = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileStreamInfo,
                buffer.as_mut_ptr().cast(),
                size,
            )
        };
        if read == 0 {
            return Vec::new();
        }
        let mut streams = Vec::new();
        let mut offset = 0usize;
        loop {
            let Some(record) = buffer.get(offset..) else {
                break;
            };
            if record.len() < 24 {
                break;
            }
            let next = u32::from_le_bytes([record[0], record[1], record[2], record[3]]);
            let name_bytes = usize::try_from(u32::from_le_bytes([
                record[4], record[5], record[6], record[7],
            ]))
            .unwrap_or(0);
            let size_bytes = u64::from_le_bytes([
                record[8], record[9], record[10], record[11], record[12], record[13], record[14],
                record[15],
            ]);
            if let Some(name) = record.get(24..24usize.saturating_add(name_bytes)) {
                let wide: Vec<u16> = name
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect();
                let text = String::from_utf16_lossy(&wide);
                if text != "::$DATA" {
                    streams.push((text, size_bytes));
                }
            }
            match usize::try_from(next) {
                Ok(0) => break,
                Ok(step) => offset = offset.saturating_add(step),
                Err(_) => break,
            }
        }
        streams.sort();
        streams
    }
}

#[cfg(not(windows))]
mod platform {
    use std::fs::{self, Metadata};
    use std::io;
    use std::path::{Path, PathBuf};

    use super::{SkipReason, StepProblem};

    pub fn directory_link(link: &Path, target: &Path) -> Result<(), StepProblem> {
        Ok(std::os::unix::fs::symlink(target, link)?)
    }

    pub fn file_symlink(link: &Path, target: &Path) -> Result<(), StepProblem> {
        Ok(std::os::unix::fs::symlink(target, link)?)
    }

    pub fn directory_symlink(link: &Path, target: &Path) -> Result<(), StepProblem> {
        Ok(std::os::unix::fs::symlink(target, link)?)
    }

    /// No alternate data streams: the colon is an ordinary character here.
    pub fn stream(_path: &Path, _stream: &str, _bytes: &[u8]) -> io::Result<Option<PathBuf>> {
        Ok(None)
    }

    pub fn tagged_reparse_point(
        _path: &Path,
        _directory: bool,
        _tag: u32,
    ) -> Result<(), StepProblem> {
        Err(StepProblem::Skip(SkipReason::NotOnThisPlatform))
    }

    /// Whether this process may mount: on Linux, as root, where mounting a small tmpfs on a
    /// scratch directory and taking it down again succeeded (asked once).
    #[cfg(target_os = "linux")]
    pub fn can_mount() -> bool {
        static CAN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *CAN.get_or_init(|| {
            // SAFETY: geteuid has no preconditions.
            if unsafe { libc::geteuid() } != 0 {
                return false;
            }
            let probe = std::env::temp_dir().join(format!("yg-corpus-mount-{}", std::process::id()));
            if fs::create_dir(&probe).is_err() {
                return false;
            }
            let mounted = mount_tmpfs(&probe).is_ok() && unmount(&probe).is_ok();
            let _ = fs::remove_dir(&probe);
            mounted
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn can_mount() -> bool {
        false
    }

    /// A small tmpfs at the directory `at`: no devices, no set-user-ID, no execution.
    #[cfg(target_os = "linux")]
    fn mount_tmpfs(at: &Path) -> io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(at.as_os_str().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: every pointer is a NUL-terminated string that outlives the call.
        let made = unsafe {
            libc::mount(
                c"yougori-corpus".as_ptr(),
                path.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                c"size=1m,mode=0755".as_ptr().cast(),
            )
        };
        if made != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// A mount at `link`: where this process may mount, a real one (a tmpfs, a device of
    /// its own, met by the resolver as a directory on another volume); otherwise a symlink
    /// to `/` stands in. The target is where a write through it would land.
    pub fn mount_point(
        link: &Path,
        _root: &Path,
        _outside: &Path,
    ) -> Result<(PathBuf, bool), StepProblem> {
        #[cfg(target_os = "linux")]
        if can_mount() {
            fs::create_dir(link)?;
            if let Err(error) = mount_tmpfs(link) {
                let _ = fs::remove_dir(link);
                return Err(error.into());
            }
            return Ok((link.to_path_buf(), true));
        }
        let target = PathBuf::from("/");
        std::os::unix::fs::symlink(&target, link)?;
        Ok((target, false))
    }

    /// Takes a real mount down, detached, so nothing that still holds it open keeps it.
    #[cfg(target_os = "linux")]
    pub fn unmount(link: &Path) -> io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(link.as_os_str().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: a NUL-terminated path that outlives the call.
        if unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn unmount(_link: &Path) -> io::Result<()> {
        Ok(())
    }

    pub fn is_link(metadata: &Metadata) -> bool {
        metadata.file_type().is_symlink()
    }

    /// The device the path sits on.
    pub fn volume_serial(path: &Path) -> Option<u32> {
        fs::symlink_metadata(path)
            .ok()
            .map(|metadata| std::os::unix::fs::MetadataExt::dev(&metadata))
            .and_then(|device| u32::try_from(device).ok())
    }

    /// Unix has no reparse tags; a symlink is the only link kind here.
    pub fn reparse_tag(_path: &Path) -> Option<u32> {
        None
    }

    pub fn link_count(path: &Path) -> u64 {
        fs::symlink_metadata(path)
            .map(|metadata| std::os::unix::fs::MetadataExt::nlink(&metadata))
            .unwrap_or_default()
    }

    /// No alternate data streams outside NTFS.
    pub fn streams(_path: &Path) -> Vec<(String, u64)> {
        Vec::new()
    }
}
