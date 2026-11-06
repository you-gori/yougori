//! The raw file identity of a sandbox root, and opening the root again by it alone (VM part
//! §6.1: "Recovery reconciles actual VM objects and resources rather than trusting old PID
//! numbers"; §6.4: "Cleanup uses host-created object handles and verified managed roots,
//! resists reparse/symlink races"; VM-W24, VM-W29; M13).
//!
//! A [`RootIdentity`] is a digest: it recognises an object but cannot find one. When the
//! sandbox root's name no longer holds the directory created, recovery
//! ([`recover_teardown`](super::recover_teardown)) finds that directory again by what the
//! digest is made from, which the launch journals beside it ([`RawFileIdentity`]): the
//! 64-bit volume serial number and the 128-bit file ID that `FileIdInfo` reads from the
//! root's handle, with the creation time the digest also binds. They are read from the
//! handle the new root was confirmed through, and recorded only when they give exactly the
//! identity read from the handle that created it ([`recorded_identity`]): the digest's volume
//! is the serial number's low 32 bits, which `GetFileInformationByHandle` reports, and its
//! index the file ID's low 64 bits, NTFS's file reference. A volume that keeps no file IDs,
//! or whose IDs do not give the digest so (a ReFS volume with IDs beyond 64 bits), has
//! nothing recorded, and recovery refuses there. The high halves are bound by no digest:
//! recovery accepts only an object whose handle gives the whole raw identity again.
//!
//! [`open_by_id`] opens by `OpenFileById` through a handle on the volume (the managed
//! parent's), never by a path and without following a reparse point, and accepts only the
//! real directory whose handle gives both the whole raw identity and the expected digest.
//! NTFS refuses to delete or rename through a handle opened by file ID (it does not know
//! which of the object's names to remove), so [`delete_by_id`] reads, from such a handle,
//! each name the directory has and the file ID of the directory holding it
//! (`FileHardLinkInformation`, whose 64-bit IDs are the 128-bit ones' low halves on NTFS;
//! NTFS does not serve the full-ID class), opens that directory by its file ID in turn, and
//! removes the name relative to its handle only while the name still names the object
//! opened ([`fsutil::remove_host_owned`]). Unix has no open by file ID: nothing is recorded
//! there, every step here fails as unsupported, and recovery refuses before reaching one
//! ([`OPENS_BY_ID`]).

use std::fmt;
use std::io;

use cap_std::fs::{Dir, File};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::fsutil::{self, HandleInfo, HandleKind};
use super::review::RootIdentity;
use super::root::identity_of;

/// Whether this platform opens a file by its ID: Windows only.
pub(super) const OPENS_BY_ID: bool = cfg!(windows);

/// A 128-bit file ID as `FileIdInfo` gives it, written as 32 hexadecimal digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId128([u8; 16]);

impl FileId128 {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The low 64 bits, little-endian as the volume stores them: NTFS's file reference, and
    /// the index `GetFileInformationByHandle` reports there.
    pub const fn low_u64(&self) -> u64 {
        let [a, b, c, d, e, f, g, h, ..] = self.0;
        u64::from_le_bytes([a, b, c, d, e, f, g, h])
    }
}

impl fmt::Debug for FileId128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileId128({})", hex::encode(self.0))
    }
}

impl fmt::Display for FileId128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl Serialize for FileId128 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for FileId128 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let mut bytes = [0u8; 16];
        hex::decode_to_slice(&text, &mut bytes)
            .map_err(|_| serde::de::Error::custom("a file ID is 32 hexadecimal digits"))?;
        Ok(Self(bytes))
    }
}

/// The raw identity of a directory, read from its handle: what its [`RootIdentity`] is a
/// digest of, kept so the directory can be opened again by its file ID when no name of it
/// is known (Windows).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawFileIdentity {
    /// The volume serial number, all 64 bits (`FILE_ID_INFO.VolumeSerialNumber`).
    pub volume_serial: u64,
    /// The file ID on that volume (`FILE_ID_INFO.FileId`).
    pub file_id: FileId128,
    /// The creation time, which the identity digest also binds.
    pub created: u64,
}

impl RawFileIdentity {
    /// The identity digest of the object with this raw identity: the root's own digest over
    /// the serial number's low 32 bits, the file ID's low 64 bits and the creation time.
    pub fn identity(&self) -> RootIdentity {
        // The digest reads the volume, the index and the creation time only.
        identity_of(&HandleInfo {
            kind: HandleKind::Directory,
            volume: self.volume_serial & u64::from(u32::MAX),
            index: self.file_id.low_u64(),
            links: 0,
            size: 0,
            executable: false,
            created: self.created,
        })
    }
}

/// The raw identity of the directory `dir` is opened on, read from that handle, when it
/// gives exactly `expected`; `None` where the platform opens nothing by file ID, the volume
/// keeps no file IDs, or its IDs do not give `expected`.
pub(super) fn recorded_identity(dir: &Dir, expected: RootIdentity) -> Option<RawFileIdentity> {
    let info = fsutil::dir_info(dir).ok()?;
    let (volume_serial, file_id) = platform::dir_file_id(dir).ok()?;
    let raw = RawFileIdentity {
        volume_serial,
        file_id,
        created: info.created,
    };
    (raw.identity() == expected).then_some(raw)
}

/// The 64-bit serial number of the volume `dir` is on.
pub(super) fn volume_serial(dir: &Dir) -> io::Result<u64> {
    platform::dir_file_id(dir).map(|(volume_serial, _)| volume_serial)
}

/// What an open by file ID found.
pub(super) enum ById {
    /// The real directory with the whole raw identity and the expected digest, opened as
    /// itself to list it and open its entries relative to it.
    Found(File),
    /// Nothing on the volume has the file ID.
    Gone,
    /// The file ID names another object: no real directory, or not the one expected.
    Other,
}

/// Opens the object with `raw`'s file ID through `volume`, a handle on the volume `raw` names,
/// never by a path and without following a reparse point. Found only when its handle gives
/// both the whole of `raw` and the digest `expected`.
pub(super) fn open_by_id(
    volume: &Dir,
    raw: &RawFileIdentity,
    expected: RootIdentity,
) -> io::Result<ById> {
    let Some(file) = platform::open_by_id(volume, &raw.file_id)? else {
        return Ok(ById::Gone);
    };
    let info = fsutil::file_info(&file)?;
    let (volume_serial, file_id) = platform::file_file_id(&file)?;
    let opened = RawFileIdentity {
        volume_serial,
        file_id,
        created: info.created,
    };
    let found =
        info.kind == HandleKind::Directory && identity_of(&info) == expected && opened == *raw;
    Ok(if found {
        ById::Found(file)
    } else {
        ById::Other
    })
}

/// What deleting a directory by its file ID did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Deletion {
    Deleted,
    /// Deleted, but still there: on a volume without POSIX delete semantics while another
    /// process holds it open; a later run finishes it.
    Pending,
    /// No name of it could be removed: each named something else by the time it was opened,
    /// or its directory was gone; nothing was changed, and a later run tries again.
    Changed,
    /// Its only names are ones the platform's string form cannot carry; nothing was changed.
    Unrepresentable,
    /// Nothing on the volume has the file ID.
    Gone,
    /// The file ID names another object; nothing was changed.
    Other,
}

/// Deletes the empty directory with `raw`'s file ID and the digest `expected`. A handle
/// opened by that ID ([`open_by_id`]) gives each name the directory has and the file ID of
/// the directory holding it; each holder is opened by its ID in turn, and the name removed
/// relative to its handle only while it still names the directory opened (a read-only
/// attribute does not keep it: the host made it). The directory is then opened by its ID
/// again, and one still there is pending.
pub(super) fn delete_by_id(
    volume: &Dir,
    raw: &RawFileIdentity,
    expected: RootIdentity,
) -> io::Result<Deletion> {
    let file = match open_by_id(volume, raw, expected)? {
        ById::Found(file) => file,
        ById::Gone => return Ok(Deletion::Gone),
        ById::Other => return Ok(Deletion::Other),
    };
    let info = fsutil::file_info(&file)?;
    let links = platform::links(&file)?;
    // Every handle to the directory is closed before it is removed.
    drop(file);
    let mut outcome = if links.is_empty() {
        Deletion::Changed
    } else {
        Deletion::Unrepresentable
    };
    for (holder_id, name) in links {
        let Some(name) = name.to_str() else {
            continue;
        };
        outcome = Deletion::Changed;
        let Some(holder) = platform::open_by_id(volume, &holder_id)? else {
            continue;
        };
        if fsutil::file_info(&holder)?.kind != HandleKind::Directory {
            continue;
        }
        match fsutil::remove_host_owned(&fsutil::into_dir(holder), name, &info) {
            Ok(true) => {
                outcome = Deletion::Deleted;
                break;
            }
            Ok(false) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    if outcome != Deletion::Deleted {
        return Ok(outcome);
    }
    Ok(match open_by_id(volume, raw, expected) {
        Ok(ById::Gone | ById::Other) => Deletion::Deleted,
        // A delete-pending directory cannot be opened at all.
        Ok(ById::Found(_)) | Err(_) => Deletion::Pending,
    })
}

#[cfg(windows)]
mod platform {
    use std::ffi::OsString;
    use std::io;
    use std::os::windows::ffi::OsStringExt as _;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

    use cap_std::fs::{Dir, File};
    use windows_sys::Wdk::Storage::FileSystem::{
        FileHardLinkInformation, NtQueryInformationFile, FILE_LINKS_INFORMATION,
        FILE_LINK_ENTRY_INFORMATION,
    };
    use windows_sys::Win32::Foundation::{
        RtlNtStatusToDosError, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, ERROR_PATH_NOT_FOUND,
        INVALID_HANDLE_VALUE, NTSTATUS,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        ExtendedFileIdType, FileIdInfo, GetFileInformationByHandleEx, OpenFileById,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_ID_128,
        FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FILE_ID_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    use super::FileId128;

    fn invalid_input() -> io::Error {
        io::Error::from(io::ErrorKind::InvalidInput)
    }

    fn malformed() -> io::Error {
        io::Error::from(io::ErrorKind::InvalidData)
    }

    fn size_of_u32<T>() -> io::Result<u32> {
        u32::try_from(std::mem::size_of::<T>()).map_err(|_| invalid_input())
    }

    /// An NT status as a result, failures carrying their Win32 error code.
    fn nt_result(status: NTSTATUS) -> io::Result<()> {
        if status >= 0 {
            return Ok(());
        }
        // SAFETY: RtlNtStatusToDosError only maps one status code to an error code.
        let code = unsafe { RtlNtStatusToDosError(status) };
        Err(io::Error::from_raw_os_error(
            i32::try_from(code).unwrap_or(i32::MAX),
        ))
    }

    /// The volume serial number and file ID `handle`'s object has (`FileIdInfo`).
    fn file_id_info(handle: RawHandle) -> io::Result<(u64, FileId128)> {
        let mut info = FILE_ID_INFO::default();
        let size = size_of_u32::<FILE_ID_INFO>()?;
        // SAFETY: `handle` is an open handle owned by the caller for the whole call, and
        // `info` is a writable FILE_ID_INFO of exactly `size` bytes.
        let read = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                std::ptr::addr_of_mut!(info).cast(),
                size,
            )
        };
        if read == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            info.VolumeSerialNumber,
            FileId128::from_bytes(info.FileId.Identifier),
        ))
    }

    pub fn dir_file_id(dir: &Dir) -> io::Result<(u64, FileId128)> {
        file_id_info(dir.as_raw_handle())
    }

    pub fn file_file_id(file: &File) -> io::Result<(u64, FileId128)> {
        file_id_info(file.as_raw_handle())
    }

    /// No object has the file ID: NTFS answers a file reference no record holds, or one
    /// whose sequence number moved on, with an invalid parameter, and one beyond its records
    /// with not found.
    fn gone(error: &io::Error) -> bool {
        matches!(
            error
                .raw_os_error()
                .and_then(|code| u32::try_from(code).ok()),
            Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_INVALID_PARAMETER)
        )
    }

    /// `OpenFileById` of `file_id` on `volume`'s volume, for listing and for opens relative
    /// to it, the object itself and never what a reparse point names; `None` when nothing
    /// has the ID.
    pub fn open_by_id(volume: &Dir, file_id: &FileId128) -> io::Result<Option<File>> {
        let descriptor = FILE_ID_DESCRIPTOR {
            dwSize: size_of_u32::<FILE_ID_DESCRIPTOR>()?,
            Type: ExtendedFileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 {
                ExtendedFileId: FILE_ID_128 {
                    Identifier: *file_id.as_bytes(),
                },
            },
        };
        // SAFETY: `volume`'s handle is open for the whole call, `descriptor` is a live
        // FILE_ID_DESCRIPTOR whose size field says its size, and no security attributes are
        // passed.
        let handle = unsafe {
            OpenFileById(
                volume.as_raw_handle(),
                &descriptor,
                FILE_GENERIC_READ | FILE_TRAVERSE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            let error = io::Error::last_os_error();
            return if gone(&error) { Ok(None) } else { Err(error) };
        }
        // SAFETY: OpenFileById succeeded, so `handle` is a new open handle owned here alone.
        let owned = unsafe { OwnedHandle::from_raw_handle(handle) };
        Ok(Some(File::from_std(std::fs::File::from(owned))))
    }

    /// The most bytes one query of an object's names fills: a directory has one name, or
    /// two with a short name, of at most 255 UTF-16 units.
    const LINKS_BUFFER_BYTES: usize = 4 * 1024;

    // Where the fields of the names' records lie.
    const RETURNED: usize = std::mem::offset_of!(FILE_LINKS_INFORMATION, EntriesReturned);
    const FIRST: usize = std::mem::offset_of!(FILE_LINKS_INFORMATION, Entry);
    const NEXT: usize = std::mem::offset_of!(FILE_LINK_ENTRY_INFORMATION, NextEntryOffset);
    const PARENT: usize = std::mem::offset_of!(FILE_LINK_ENTRY_INFORMATION, ParentFileId);
    const NAME_UNITS: usize = std::mem::offset_of!(FILE_LINK_ENTRY_INFORMATION, FileNameLength);
    const NAME: usize = std::mem::offset_of!(FILE_LINK_ENTRY_INFORMATION, FileName);

    /// The `N` bytes of `record` at `at`, when all of them lie inside it.
    fn field<const N: usize>(record: &[u8], at: usize) -> io::Result<[u8; N]> {
        at.checked_add(N)
            .and_then(|end| record.get(at..end))
            .and_then(|bytes| <[u8; N]>::try_from(bytes).ok())
            .ok_or_else(malformed)
    }

    fn field_u32(record: &[u8], at: usize) -> io::Result<u32> {
        field(record, at).map(u32::from_ne_bytes)
    }

    fn field_usize(record: &[u8], at: usize) -> io::Result<usize> {
        usize::try_from(field_u32(record, at)?).map_err(|_| malformed())
    }

    /// Each name in `batch`, as `FileHardLinkInformation` filled it, with the file ID of the
    /// directory holding it, the 64-bit ID as the low half of a 128-bit one. Every field is
    /// read from inside the batch, and a name's length counts UTF-16 units; a name that is
    /// empty or holds a separator or NUL is malformed.
    fn parse_links(batch: &[u8]) -> io::Result<Vec<(FileId128, OsString)>> {
        let returned = field_u32(batch, RETURNED)?;
        let mut links = Vec::new();
        let mut offset = FIRST;
        for _ in 0..returned {
            let record = batch.get(offset..).ok_or_else(malformed)?;
            let units = field_usize(record, NAME_UNITS)?;
            let name = units
                .checked_mul(2)
                .and_then(|bytes| NAME.checked_add(bytes))
                .and_then(|end| record.get(NAME..end))
                .ok_or_else(malformed)?;
            let wide: Vec<u16> = name
                .chunks_exact(2)
                .filter_map(|pair| <[u8; 2]>::try_from(pair).ok())
                .map(u16::from_ne_bytes)
                .collect();
            if wide.is_empty()
                || wide
                    .iter()
                    .any(|&unit| unit == 0 || unit == u16::from(b'\\') || unit == u16::from(b'/'))
            {
                return Err(malformed());
            }
            let [a, b, c, d, e, f, g, h] = field::<8>(record, PARENT)?;
            let parent = [a, b, c, d, e, f, g, h, 0, 0, 0, 0, 0, 0, 0, 0];
            links.push((FileId128::from_bytes(parent), OsString::from_wide(&wide)));
            match field_usize(record, NEXT)? {
                0 => break,
                next => offset = offset.checked_add(next).ok_or_else(malformed)?,
            }
        }
        Ok(links)
    }

    /// Each name the object `file` is opened on has, with the file ID of the directory
    /// holding it, read from the handle (`FileHardLinkInformation`).
    pub fn links(file: &File) -> io::Result<Vec<(FileId128, OsString)>> {
        // Room for an 8-byte aligned window, which the records' fields assume.
        let mut buffer = vec![0u8; LINKS_BUFFER_BYTES + 7];
        let window = buffer.as_ptr().align_offset(8);
        let end = window
            .checked_add(LINKS_BUFFER_BYTES)
            .ok_or_else(invalid_input)?;
        let length = u32::try_from(LINKS_BUFFER_BYTES).map_err(|_| invalid_input())?;
        let target = buffer.get_mut(window..end).ok_or_else(invalid_input)?;
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: `file`'s handle is open for the whole call; `target` is a live, writable,
        // 8-byte aligned slice of exactly `length` bytes and `status_block` a writable local.
        // The call is synchronous and keeps no pointer.
        let status = unsafe {
            NtQueryInformationFile(
                file.as_raw_handle(),
                &mut status_block,
                target.as_mut_ptr().cast(),
                length,
                FileHardLinkInformation,
            )
        };
        nt_result(status)?;
        let filled = status_block.Information.min(LINKS_BUFFER_BYTES);
        let batch = target.get(..filled).ok_or_else(malformed)?;
        parse_links(batch)
    }
}

#[cfg(unix)]
mod platform {
    use std::ffi::OsString;
    use std::io;

    use cap_std::fs::{Dir, File};

    use super::FileId128;

    fn unsupported() -> io::Error {
        io::Error::from(io::ErrorKind::Unsupported)
    }

    pub fn dir_file_id(_dir: &Dir) -> io::Result<(u64, FileId128)> {
        Err(unsupported())
    }

    pub fn file_file_id(_file: &File) -> io::Result<(u64, FileId128)> {
        Err(unsupported())
    }

    pub fn open_by_id(_volume: &Dir, _file_id: &FileId128) -> io::Result<Option<File>> {
        Err(unsupported())
    }

    pub fn links(_file: &File) -> io::Result<Vec<(FileId128, OsString)>> {
        Err(unsupported())
    }
}
