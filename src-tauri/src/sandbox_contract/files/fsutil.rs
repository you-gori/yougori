//! Platform steps for handle-relative resolution beneath an opened root (VM part §5.1:
//! "Resolve them beneath the opened root using platform-safe handle-relative operations.
//! A prior string canonicalization check is not enough against rename, symlink or
//! reparse-point races"; M12).
//!
//! Every open names one component relative to an already opened directory handle, through
//! `cap-std`, which never resolves a name outside its directory. On top of that:
//!
//! - Windows: the open passes `FILE_FLAG_OPEN_REPARSE_POINT`, so cap-primitives' relative
//!   `NtCreateFile` opens a symlink, junction or other reparse point as itself instead of
//!   resolving it, and the handle's own attributes and reparse tag say what it is. Changes
//!   go through handles too, because cap-std's own create-directory, rename and remove on
//!   Windows rebuild the directory's full path from its handle and resolve that path again:
//!   a directory is created by a relative `NtCreateFile`, an entry is renamed by
//!   `NtSetInformationFile` naming the target directory's handle (a replacing rename with
//!   POSIX semantics where the volume has them), and removed by setting delete disposition,
//!   with POSIX semantics where the volume has them, on a handle opened as the entry
//!   itself. Each opens the entry again as itself and checks it is still the
//!   object the walk checked.
//! - Unix: cap-std can still resolve a symlink within its directory on some platforms, so
//!   after the open the name is read again without following (`fstatat` with
//!   `AT_SYMLINK_NOFOLLOW`) and must be no link and name exactly the opened object
//!   (device and inode). A name that no longer names the opened object is refused. Changes
//!   use cap-std's `mkdirat`, `renameat`, `linkat` and `unlinkat`, relative to the
//!   directory's descriptor, after the same confirmation.
//!
//! A directory is listed through its own handle too ([`read_directory`]). On Windows,
//! cap-std's listing rebuilds the directory's current path from its handle and lists
//! whatever that path names when it opens it: another directory after a rename racing it,
//! or, deterministically, after the Win32 path layer drops a trailing dot. So the listing
//! reads the records of a handle opened again as the directory itself, relative to its
//! handle with an empty name. On Unix, cap-std's listing already reads a descriptor opened
//! from the directory's own (`openat` of `.`, then `fdopendir`) and is kept.
//!
//! What an entry is (directory, regular file, link kind, device), its volume, index, link
//! count, size and execute bit are always read from a handle opened as the entry itself, or
//! on Unix from a non-following stat, never by resolving a path.

use std::ffi::OsString;
use std::io::{self, Read};
use std::path::Path;

use cap_std::fs::{Dir, File, OpenOptions};

use super::resolve::LinkKind;
use crate::foundation::ids::{ContentHasher, ContentKey};

/// What a handle refers to, read from the handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HandleKind {
    Directory,
    File,
    Link(LinkKind),
    /// A device, FIFO or socket.
    Device,
}

/// What the host reads from one open handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct HandleInfo {
    pub kind: HandleKind,
    /// The volume serial number (Windows) or device (Unix).
    pub volume: u64,
    /// The file index (Windows) or inode (Unix).
    pub index: u64,
    pub links: u64,
    pub size: u64,
    /// Any execute bit; Windows has none.
    pub executable: bool,
    /// The creation time on Windows; 0 on Unix, where the device and inode identify.
    pub created: u64,
}

impl HandleInfo {
    /// The same object as `other`.
    pub fn same_object(&self, other: &HandleInfo) -> bool {
        self.volume == other.volume && self.index == other.index
    }

    /// The same object as `expected`, still of its kind.
    pub fn is(&self, expected: &HandleInfo) -> bool {
        self.same_object(expected) && self.kind == expected.kind
    }
}

/// One entry of a directory as the listing read through the directory's own handle gives it
/// ([`read_directory`]): its name and what the listing record says of it, with no query of
/// its own. The record is the directory's view when it was read. A caller that acts on an
/// entry still opens it relative to the directory's handle and checks what it opened, which
/// also reads what no record holds: the volume, the link count and a current size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DirectoryEntry {
    /// The entry's name exactly as stored; never `.` or `..`.
    pub name: OsString,
    /// What the record says the entry is, without following it: on Windows from its
    /// attributes and reparse tag, mapped as a handle's are; on Unix from its `d_type`.
    /// `None` where the record does not say (`DT_UNKNOWN`).
    pub kind: Option<HandleKind>,
    /// The record's `FILE_ATTRIBUTE_*` bits (Windows).
    #[cfg(windows)]
    pub attributes: u32,
    /// A reparse point's tag, which the record carries in place of its EA size (Windows).
    #[cfg(windows)]
    pub reparse_tag: Option<u32>,
    /// The file id; on NTFS, the index a handle opened as the entry reports (Windows).
    #[cfg(windows)]
    pub file_id: u64,
}

#[cfg(windows)]
mod platform {
    use std::ffi::OsString;
    use std::io;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::path::Path;

    use cap_std::fs::{Dir, File, OpenOptions, OpenOptionsExt};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FileIdBothDirectoryInformation, FileRenameInformation, FileRenameInformationEx,
        NtCreateFile, NtQueryDirectoryFile, NtSetInformationFile, FILE_CREATE,
        FILE_DIRECTORY_FILE, FILE_INFORMATION_CLASS, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
        FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS,
        FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows_sys::Win32::Foundation::{
        RtlNtStatusToDosError, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, HANDLE, NTSTATUS,
        OBJ_CASE_INSENSITIVE, STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FileAttributeTagInfo, FileBasicInfo, FileDispositionInfo, FileDispositionInfoEx,
        GetFileInformationByHandle, GetFileInformationByHandleEx, SetFileInformationByHandle,
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_DISPOSITION_FLAG_DELETE,
        FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_BOTH_DIR_INFO, FILE_INFO_BY_HANDLE_CLASS,
        FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    use super::{DirectoryEntry, HandleInfo, HandleKind, LinkKind};

    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
    const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

    /// Options that open the entry itself, directory or not, and never what a reparse
    /// point names.
    pub fn no_follow(options: &mut OpenOptions) {
        options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }

    fn combine(high: u32, low: u32) -> u64 {
        (u64::from(high) << 32) | u64::from(low)
    }

    fn invalid_input() -> io::Error {
        io::Error::from(io::ErrorKind::InvalidInput)
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

    fn wide(component: &Path) -> Vec<u16> {
        component.as_os_str().encode_wide().collect()
    }

    fn reparse_tag(handle: RawHandle) -> io::Result<u32> {
        let mut tag = FILE_ATTRIBUTE_TAG_INFO {
            FileAttributes: 0,
            ReparseTag: 0,
        };
        let size = size_of_u32::<FILE_ATTRIBUTE_TAG_INFO>()?;
        // SAFETY: `handle` is an open handle owned by the caller for the whole call, and
        // `tag` is a writable FILE_ATTRIBUTE_TAG_INFO of exactly `size` bytes.
        let read = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfo,
                (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size,
            )
        };
        if read == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(tag.ReparseTag)
    }

    /// What an object with `attributes` is; `reparse_tag` tells a reparse point's kind.
    fn kind_of(attributes: u32, reparse_tag: u32) -> HandleKind {
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            HandleKind::Link(match reparse_tag {
                IO_REPARSE_TAG_SYMLINK => LinkKind::Symlink,
                IO_REPARSE_TAG_MOUNT_POINT => LinkKind::Junction,
                _ => LinkKind::ReparsePoint,
            })
        } else if attributes & FILE_ATTRIBUTE_DEVICE != 0 {
            HandleKind::Device
        } else if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            HandleKind::Directory
        } else {
            HandleKind::File
        }
    }

    fn handle_info(handle: RawHandle) -> io::Result<HandleInfo> {
        // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is a valid value of this plain
        // C struct of integers.
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `handle` is an open handle owned by the caller for the whole call, and
        // `information` is a writable BY_HANDLE_FILE_INFORMATION.
        if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let attributes = information.dwFileAttributes;
        let tag = if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            reparse_tag(handle)?
        } else {
            0
        };
        Ok(HandleInfo {
            kind: kind_of(attributes, tag),
            volume: u64::from(information.dwVolumeSerialNumber),
            index: combine(information.nFileIndexHigh, information.nFileIndexLow),
            links: u64::from(information.nNumberOfLinks),
            size: combine(information.nFileSizeHigh, information.nFileSizeLow),
            executable: false,
            created: combine(
                information.ftCreationTime.dwHighDateTime,
                information.ftCreationTime.dwLowDateTime,
            ),
        })
    }

    pub fn file_info(file: &File) -> io::Result<HandleInfo> {
        handle_info(file.as_raw_handle())
    }

    pub fn dir_info(dir: &Dir) -> io::Result<HandleInfo> {
        handle_info(dir.as_raw_handle())
    }

    /// The entry itself, opened for its attributes only, which a file another process
    /// locked against reading still allows.
    pub fn entry_info(parent: &Dir, component: &Path) -> io::Result<HandleInfo> {
        let mut options = OpenOptions::new();
        options.access_mode(FILE_READ_ATTRIBUTES);
        no_follow(&mut options);
        file_info(&parent.open_with(component, &options)?)
    }

    /// The open itself did not follow anything, so there is nothing to confirm.
    pub fn confirm(_parent: &Dir, _component: &Path, _opened: &HandleInfo) -> io::Result<bool> {
        Ok(true)
    }

    /// Windows has no execute bit; executable types are flagged by name at review.
    pub fn set_executable(_file: &File, _executable: bool) -> io::Result<()> {
        Ok(())
    }

    /// The directory at `path` itself, never what a reparse point there names.
    pub fn open_root(path: &Path) -> io::Result<Dir> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        Ok(Dir::from_std_file(file))
    }

    /// Creates the directory `component` in `parent` by a create relative to the parent's
    /// handle, and returns what the created handle says of it. Names fold case as Windows
    /// names do, so a name taken in another case fails with `AlreadyExists` too.
    pub fn create_directory(parent: &Dir, component: &Path) -> io::Result<HandleInfo> {
        let name = wide(component);
        let length = u16::try_from(name.len().saturating_mul(2)).map_err(|_| invalid_input())?;
        let object_name = UNICODE_STRING {
            Length: length,
            MaximumLength: length,
            Buffer: name.as_ptr().cast_mut(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of_u32::<OBJECT_ATTRIBUTES>()?,
            RootDirectory: parent.as_raw_handle(),
            ObjectName: &object_name,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut status_block = IO_STATUS_BLOCK::default();
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: every pointer refers to a live local for the whole call: `handle` receives
        // the new handle, `attributes` names `object_name`, whose buffer `name` outlives the
        // call, and `parent`'s directory handle is open; `status_block` is writable, and no
        // allocation size or extended attributes are passed.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                &attributes,
                &mut status_block,
                std::ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_CREATE,
                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
                std::ptr::null(),
                0,
            )
        };
        nt_result(status)?;
        // SAFETY: NtCreateFile succeeded, so `handle` is a new open handle owned here alone.
        let created = unsafe { OwnedHandle::from_raw_handle(handle) };
        handle_info(created.as_raw_handle())
    }

    /// The entry itself, opened with `access` (which holds the right to rename or delete
    /// it), if it is still the object `expected` describes.
    fn open_expected(
        parent: &Dir,
        component: &Path,
        expected: &HandleInfo,
        access: u32,
    ) -> io::Result<Option<File>> {
        let mut options = OpenOptions::new();
        options.access_mode(access);
        no_follow(&mut options);
        let file = parent.open_with(component, &options)?;
        Ok(file_info(&file)?.is(expected).then_some(file))
    }

    /// Renames the entry through its own handle into `target_parent`'s handle, replacing an
    /// existing `target` only when `replace` is set; `false` when the name no longer names
    /// `expected`, in which case nothing changed. A replacing rename takes POSIX semantics
    /// where the volume has them, so it lands even while another process holds the target
    /// open with delete sharing (as the file service's own reads do), whose handle then reads
    /// on the replaced file; a volume without them (FAT) gets the legacy rename, which fails
    /// on a target open at all.
    pub fn rename(
        parent: &Dir,
        component: &Path,
        expected: &HandleInfo,
        target_parent: &Dir,
        target: &Path,
        replace: bool,
    ) -> io::Result<bool> {
        let Some(file) = open_expected(
            parent,
            component,
            expected,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        )?
        else {
            return Ok(false);
        };
        if replace {
            match set_rename_ex(&file, target_parent, target) {
                Err(error) if unsupported(&error) => {}
                set => return set.map(|()| true),
            }
        }
        set_rename(&file, target_parent, target, FileRenameInformation, u32::from(replace))?;
        Ok(true)
    }

    #[cfg(test)]
    thread_local! {
        /// Set by tests to take the legacy rename, as every replacing rename on a volume
        /// without the extended class (FAT) does.
        pub static LEGACY_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// The extended, replacing rename: POSIX semantics.
    fn set_rename_ex(file: &File, target_parent: &Dir, target: &Path) -> io::Result<()> {
        #[cfg(test)]
        if LEGACY_RENAME.with(std::cell::Cell::get) {
            return Err(io::Error::from_raw_os_error(
                i32::try_from(ERROR_NOT_SUPPORTED).unwrap_or(i32::MAX),
            ));
        }
        set_rename(
            file,
            target_parent,
            target,
            FileRenameInformationEx,
            FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
        )
    }

    /// One rename of `file` to `target` in `target_parent`, in information `class`: the
    /// legacy class reads the union's first byte as `ReplaceIfExists` (so `flags` is 0 or
    /// 1), the extended one reads it whole as its flags.
    fn set_rename(
        file: &File,
        target_parent: &Dir,
        target: &Path,
        class: FILE_INFORMATION_CLASS,
        flags: u32,
    ) -> io::Result<()> {
        let name = wide(target);
        let name_bytes = name.len().saturating_mul(2);
        let total = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName)
            .saturating_add(name_bytes)
            .max(std::mem::size_of::<FILE_RENAME_INFORMATION>());
        let name_length = u32::try_from(name_bytes).map_err(|_| invalid_input())?;
        let length = u32::try_from(total).map_err(|_| invalid_input())?;
        // Whole u64 words keep the buffer aligned for the structure's handle field.
        let mut buffer = vec![0u64; total.div_ceil(8)];
        let information = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: `buffer` is zeroed, 8-byte aligned and at least `total` bytes, which hold
        // the structure up to its name followed by the whole name, so every write stays
        // inside it and no reference to it is formed. `file` is open with DELETE access and
        // `target_parent`'s directory handle is open for the whole call.
        let status = unsafe {
            std::ptr::addr_of_mut!((*information).Anonymous.Flags).write(flags);
            std::ptr::addr_of_mut!((*information).RootDirectory)
                .write(target_parent.as_raw_handle());
            std::ptr::addr_of_mut!((*information).FileNameLength).write(name_length);
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                std::ptr::addr_of_mut!((*information).FileName).cast::<u16>(),
                name.len(),
            );
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut status_block,
                information.cast_const().cast(),
                length,
                class,
            )
        };
        nt_result(status)
    }

    #[cfg(test)]
    thread_local! {
        /// Set by tests to take the legacy disposition, as every removal on a volume
        /// without the extended class (FAT) does.
        pub static LEGACY_DISPOSITION: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
    }

    /// Sets the information `class` of `handle` to `value`, which must be that class's
    /// structure.
    fn set_information<T>(
        handle: RawHandle,
        class: FILE_INFO_BY_HANDLE_CLASS,
        value: &T,
    ) -> io::Result<()> {
        let size = size_of_u32::<T>()?;
        // SAFETY: `handle` is an open handle owned by the caller for the whole call, and
        // `value` is a live structure of `class` of exactly `size` bytes.
        let set =
            unsafe { SetFileInformationByHandle(handle, class, (value as *const T).cast(), size) };
        if set == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The extended disposition: POSIX semantics, so the name goes when this handle closes
    /// even while another process holds the entry open with delete sharing.
    fn set_disposition_ex(handle: RawHandle, host_owned: bool) -> io::Result<()> {
        #[cfg(test)]
        if LEGACY_DISPOSITION.with(std::cell::Cell::get) {
            return Err(io::Error::from_raw_os_error(
                i32::try_from(ERROR_NOT_SUPPORTED).unwrap_or(i32::MAX),
            ));
        }
        let mut flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
        if host_owned {
            flags |= FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
        }
        set_information(
            handle,
            FileDispositionInfoEx,
            &FILE_DISPOSITION_INFO_EX { Flags: flags },
        )
    }

    /// The legacy disposition, which leaves the name until the last handle to the entry
    /// closes. A host-owned entry's read-only attribute is cleared first through the same
    /// handle, and set again if the disposition fails.
    fn set_disposition_legacy(handle: RawHandle, host_owned: bool) -> io::Result<()> {
        let restore = if host_owned {
            clear_read_only(handle)?
        } else {
            None
        };
        let set = set_information(
            handle,
            FileDispositionInfo,
            &FILE_DISPOSITION_INFO { DeleteFile: true },
        );
        if let (Err(_), Some(original)) = (&set, restore) {
            let _ = set_information(handle, FileBasicInfo, &original);
        }
        set
    }

    /// Clears the read-only attribute of `handle`'s entry; the basic information that sets
    /// it again when it was set. Zero times leave the times as they are.
    fn clear_read_only(handle: RawHandle) -> io::Result<Option<FILE_BASIC_INFO>> {
        let mut basic = FILE_BASIC_INFO::default();
        let size = size_of_u32::<FILE_BASIC_INFO>()?;
        // SAFETY: `handle` is an open handle owned by the caller for the whole call, and
        // `basic` is a writable FILE_BASIC_INFO of exactly `size` bytes.
        let read = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileBasicInfo,
                (&mut basic as *mut FILE_BASIC_INFO).cast(),
                size,
            )
        };
        if read == 0 {
            return Err(io::Error::last_os_error());
        }
        if basic.FileAttributes & FILE_ATTRIBUTE_READONLY == 0 {
            return Ok(None);
        }
        let original = FILE_BASIC_INFO {
            FileAttributes: basic.FileAttributes,
            ..FILE_BASIC_INFO::default()
        };
        // Zero attributes would mean "unchanged".
        let cleared = basic.FileAttributes & !FILE_ATTRIBUTE_READONLY;
        let changed = FILE_BASIC_INFO {
            FileAttributes: if cleared == 0 {
                FILE_ATTRIBUTE_NORMAL
            } else {
                cleared
            },
            ..FILE_BASIC_INFO::default()
        };
        set_information(handle, FileBasicInfo, &changed)?;
        Ok(Some(original))
    }

    /// The extended disposition is not available on this volume.
    fn unsupported(error: &io::Error) -> bool {
        matches!(
            error
                .raw_os_error()
                .and_then(|code| u32::try_from(code).ok()),
            Some(ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED)
        )
    }

    /// Removes the entry by setting delete disposition on its own handle, with POSIX
    /// semantics, so the name goes at once even while another process holds the entry open
    /// with delete sharing; `false` when the name no longer names `expected`, in which case
    /// nothing changed. A directory must be empty. `host_owned` also ignores a read-only
    /// attribute. A volume without the extended disposition (FAT) gets the legacy one.
    pub fn remove(
        parent: &Dir,
        component: &Path,
        expected: &HandleInfo,
        host_owned: bool,
    ) -> io::Result<bool> {
        let mut access = DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        if host_owned {
            access |= FILE_WRITE_ATTRIBUTES;
        }
        let Some(file) = open_expected(parent, component, expected, access)? else {
            return Ok(false);
        };
        let handle = file.as_raw_handle();
        match set_disposition_ex(handle, host_owned) {
            Err(error) if unsupported(&error) => set_disposition_legacy(handle, host_owned)?,
            set => set?,
        }
        Ok(true)
    }

    // Listing. `NtQueryDirectoryFile` with the `FileIdBothDirectoryInformation` class, the
    // class `GetFileInformationByHandleEx(FileIdBothDirectoryInfo)` wraps: every file system
    // that lists serves it, FAT and exFAT included, which the extended-id class is not; its
    // record carries the attributes, the file id and, in place of the EA size, a reparse
    // point's tag, as `FindFirstFile` reads it. The native call is taken over the wrapper
    // because it reports how many bytes it wrote, so the records are parsed within exactly
    // those, and because its first query restarts the scan by a flag.

    /// The most bytes one listing query fills: thirteen records of the longest names (255
    /// UTF-16 units, 614 bytes with the record) or some sixty typical ones. A teardown holds
    /// one listing per level of depth, so it stays small.
    pub const LISTING_BUFFER_BYTES: usize = 8 * 1024;

    // Where the fields of a FILE_ID_BOTH_DIR_INFO record lie.
    const NEXT_ENTRY: usize = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, NextEntryOffset);
    const ATTRIBUTES: usize = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileAttributes);
    const NAME_LENGTH: usize = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileNameLength);
    const EA_SIZE: usize = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, EaSize);
    const FILE_ID: usize = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileId);
    const NAME: usize = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);

    fn malformed() -> io::Error {
        io::Error::from(io::ErrorKind::InvalidData)
    }

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

    /// The record at `offset` of the `batch` one query filled, and where the next record
    /// starts. Every field and the name are read from inside the record, which must lie
    /// inside the batch and end where the next one starts; a record that does not, or whose
    /// name is empty, of odd length or holds a separator or NUL, is malformed. `.` and `..`
    /// yield no entry.
    pub fn parse_record(
        batch: &[u8],
        offset: usize,
    ) -> io::Result<(Option<DirectoryEntry>, Option<usize>)> {
        let rest = batch.get(offset..).ok_or_else(malformed)?;
        let (record, next) = match field_u32(rest, NEXT_ENTRY)? {
            0 => (rest, None),
            length => {
                let length = usize::try_from(length).map_err(|_| malformed())?;
                let record = rest.get(..length).ok_or_else(malformed)?;
                (
                    record,
                    Some(offset.checked_add(length).ok_or_else(malformed)?),
                )
            }
        };
        let attributes = field_u32(record, ATTRIBUTES)?;
        let name_bytes =
            usize::try_from(field_u32(record, NAME_LENGTH)?).map_err(|_| malformed())?;
        let ea_size = field_u32(record, EA_SIZE)?;
        let file_id = field(record, FILE_ID).map(u64::from_ne_bytes)?;
        let name = NAME
            .checked_add(name_bytes)
            .and_then(|end| record.get(NAME..end))
            .ok_or_else(malformed)?;
        let units = name.chunks_exact(2);
        if name.is_empty() || !units.remainder().is_empty() {
            return Err(malformed());
        }
        let wide: Vec<u16> = units
            .filter_map(|pair| <[u8; 2]>::try_from(pair).ok())
            .map(u16::from_ne_bytes)
            .collect();
        if wide
            .iter()
            .any(|&unit| unit == 0 || unit == u16::from(b'\\') || unit == u16::from(b'/'))
        {
            return Err(malformed());
        }
        let dot = u16::from(b'.');
        if wide == [dot] || wide == [dot, dot] {
            return Ok((None, next));
        }
        let reparse_tag = (attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0).then_some(ea_size);
        let entry = DirectoryEntry {
            name: OsString::from_wide(&wide),
            kind: Some(kind_of(attributes, reparse_tag.unwrap_or(0))),
            attributes,
            reparse_tag,
            file_id,
        };
        Ok((Some(entry), next))
    }

    /// The scan behind one listing (see [`super::read_directory`]).
    pub struct Scan {
        /// The directory opened again for listing, so the scan position is this listing's.
        handle: OwnedHandle,
        /// Room for an 8-byte aligned window of [`LISTING_BUFFER_BYTES`], which the
        /// records' 64-bit fields need; the window is parsed as plain bytes.
        buffer: Vec<u8>,
        /// Where the window starts in `buffer`.
        window: usize,
        /// How many bytes of the window the last query filled.
        filled: usize,
        /// Where the next record of the window starts; `None` once the batch is used up.
        next: Option<usize>,
        /// Whether a query has run; the first one restarts the scan.
        started: bool,
        /// The scan ended or failed: nothing more comes.
        finished: bool,
    }

    /// Opens `dir` again for listing only, by a create relative to its own handle with an
    /// empty name, which names the directory itself and no path. A scan position belongs
    /// to the open file object, which a cloned handle shares (every walk starts from a clone
    /// of the root's handle), so each listing has a file object of its own.
    pub fn read_directory(dir: &Dir) -> io::Result<Scan> {
        let object_name = UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: std::ptr::null_mut(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of_u32::<OBJECT_ATTRIBUTES>()?,
            RootDirectory: dir.as_raw_handle(),
            ObjectName: &object_name,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut status_block = IO_STATUS_BLOCK::default();
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: every pointer refers to a live local for the whole call: `handle` receives
        // the new handle, `attributes` names the empty `object_name`, whose buffer is never
        // read, and `dir`'s handle is open; `status_block` is writable, and no allocation
        // size or extended attributes are passed.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                FILE_LIST_DIRECTORY | SYNCHRONIZE,
                &attributes,
                &mut status_block,
                std::ptr::null(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
                std::ptr::null(),
                0,
            )
        };
        nt_result(status)?;
        // SAFETY: NtCreateFile succeeded, so `handle` is a new open handle owned here alone.
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        let buffer = vec![0u8; LISTING_BUFFER_BYTES + 7];
        let window = buffer.as_ptr().align_offset(8);
        if window > 7 {
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
        Ok(Scan {
            handle,
            buffer,
            window,
            filled: 0,
            next: None,
            started: false,
            finished: false,
        })
    }

    impl Scan {
        /// Fills the window with the next batch of records, or marks the scan finished.
        fn query(&mut self) -> io::Result<()> {
            let restart = !self.started;
            self.started = true;
            let length = u32::try_from(LISTING_BUFFER_BYTES).map_err(|_| invalid_input())?;
            let end = self
                .window
                .checked_add(LISTING_BUFFER_BYTES)
                .ok_or_else(invalid_input)?;
            let window = self
                .buffer
                .get_mut(self.window..end)
                .ok_or_else(invalid_input)?;
            let mut status_block = IO_STATUS_BLOCK::default();
            // SAFETY: `self.handle` is the listing handle owned here, open for listing and
            // for synchronous I/O; `window` is a live, writable, 8-byte aligned slice of
            // exactly `length` bytes and `status_block` a writable local. No event, APC
            // routine or name filter is passed, and on a synchronous handle the call
            // completes before it returns, so no pointer is kept.
            let status = unsafe {
                NtQueryDirectoryFile(
                    self.handle.as_raw_handle(),
                    std::ptr::null_mut(),
                    None,
                    std::ptr::null(),
                    &mut status_block,
                    window.as_mut_ptr().cast(),
                    length,
                    FileIdBothDirectoryInformation,
                    false,
                    std::ptr::null(),
                    restart,
                )
            };
            // The scan's end; a first query that finds nothing at all, as in a volume's
            // root, which has no `.`, says "no such file".
            if status == STATUS_NO_MORE_FILES || (restart && status == STATUS_NO_SUCH_FILE) {
                self.finished = true;
                return Ok(());
            }
            nt_result(status)?;
            self.filled = status_block.Information.min(LISTING_BUFFER_BYTES);
            // A success that wrote nothing would never end the scan.
            if self.filled == 0 {
                return Err(malformed());
            }
            self.next = Some(0);
            Ok(())
        }

        /// The record at `offset` of the last batch, moving on to the one after it.
        fn take(&mut self, offset: usize) -> io::Result<Option<DirectoryEntry>> {
            let end = self.window.checked_add(self.filled).ok_or_else(malformed)?;
            let batch = self.buffer.get(self.window..end).ok_or_else(malformed)?;
            let (entry, next) = parse_record(batch, offset)?;
            self.next = next;
            Ok(entry)
        }

        /// The next entry, querying for the next batch when this one is used up.
        pub fn next_entry(&mut self) -> Option<io::Result<DirectoryEntry>> {
            while !self.finished {
                let step = match self.next {
                    Some(offset) => self.take(offset),
                    None => self.query().map(|()| None),
                };
                match step {
                    Ok(Some(entry)) => return Some(Ok(entry)),
                    Ok(None) => {}
                    Err(error) => {
                        self.finished = true;
                        return Some(Err(error));
                    }
                }
            }
            None
        }
    }
}

#[cfg(unix)]
mod platform {
    use std::io;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::path::Path;

    use cap_std::fs::{
        Dir, File, FileType, FileTypeExt, Metadata, MetadataExt, OpenOptions, OpenOptionsExt,
        Permissions, PermissionsExt, ReadDir,
    };

    use super::{DirectoryEntry, HandleInfo, HandleKind, LinkKind};

    /// Options that refuse a symlink as the last component where the platform can, and
    /// never block on a FIFO swapped in by a concurrent writer.
    pub fn no_follow(options: &mut OpenOptions) {
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }

    /// What `file_type` says an object is; `None` for an unknown type, which only a
    /// directory entry can have.
    fn kind_of(file_type: FileType) -> Option<HandleKind> {
        if file_type.is_symlink() {
            Some(HandleKind::Link(LinkKind::Symlink))
        } else if file_type.is_dir() {
            Some(HandleKind::Directory)
        } else if file_type.is_file() {
            Some(HandleKind::File)
        } else if file_type.is_block_device()
            || file_type.is_char_device()
            || file_type.is_fifo()
            || file_type.is_socket()
        {
            Some(HandleKind::Device)
        } else {
            None
        }
    }

    fn metadata_info(metadata: &Metadata) -> HandleInfo {
        // A stat always knows the type; anything else would be some device.
        let kind = kind_of(metadata.file_type()).unwrap_or(HandleKind::Device);
        HandleInfo {
            kind,
            volume: metadata.dev(),
            index: metadata.ino(),
            links: metadata.nlink(),
            size: metadata.len(),
            executable: metadata.mode() & 0o111 != 0,
            created: 0,
        }
    }

    pub fn file_info(file: &File) -> io::Result<HandleInfo> {
        Ok(metadata_info(&file.metadata()?))
    }

    pub fn dir_info(dir: &Dir) -> io::Result<HandleInfo> {
        Ok(metadata_info(&dir.dir_metadata()?))
    }

    /// The entry from a stat that does not follow it.
    pub fn entry_info(parent: &Dir, component: &Path) -> io::Result<HandleInfo> {
        Ok(metadata_info(&parent.symlink_metadata(component)?))
    }

    /// The name, read again without following, is no symlink and names the opened object.
    pub fn confirm(parent: &Dir, component: &Path, opened: &HandleInfo) -> io::Result<bool> {
        let current = entry_info(parent, component)?;
        Ok(!matches!(current.kind, HandleKind::Link(_)) && current.same_object(opened))
    }

    pub fn set_executable(file: &File, executable: bool) -> io::Result<()> {
        file.set_permissions(Permissions::from_mode(if executable {
            0o755
        } else {
            0o644
        }))
    }

    /// The directory at `path` itself; a symlink there fails the open.
    pub fn open_root(path: &Path) -> io::Result<Dir> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(path)?;
        Ok(Dir::from_std_file(file))
    }

    /// `mkdirat`, which fails with `AlreadyExists` on any existing entry. It yields no
    /// handle, so what was created is read by a non-following stat right after it.
    pub fn create_directory(parent: &Dir, component: &Path) -> io::Result<HandleInfo> {
        parent.create_dir(component)?;
        entry_info(parent, component)
    }

    /// Renames the confirmed entry. `renameat` replaces an existing file, so without
    /// `replace` a regular file moves by a new link, which fails if the target name is
    /// taken, and then the old name's removal. A directory is renamed by `renameat`, which
    /// never replaces a file or a non-empty directory.
    pub fn rename(
        parent: &Dir,
        component: &Path,
        expected: &HandleInfo,
        target_parent: &Dir,
        target: &Path,
        replace: bool,
    ) -> io::Result<bool> {
        if !confirm(parent, component, expected)? {
            return Ok(false);
        }
        if replace || expected.kind != HandleKind::File {
            parent.rename(component, target_parent, target)?;
            return Ok(true);
        }
        parent.hard_link(component, target_parent, target)?;
        if let Err(error) = parent.remove_file(component) {
            let _ = target_parent.remove_file(target);
            return Err(error);
        }
        Ok(true)
    }

    /// `unlinkat` of the confirmed entry, which ignores the file mode, so `_host_owned`
    /// changes nothing. A directory must be empty.
    pub fn remove(
        parent: &Dir,
        component: &Path,
        expected: &HandleInfo,
        _host_owned: bool,
    ) -> io::Result<bool> {
        if !confirm(parent, component, expected)? {
            return Ok(false);
        }
        if expected.kind == HandleKind::Directory {
            parent.remove_dir(component)?;
        } else {
            parent.remove_file(component)?;
        }
        Ok(true)
    }

    /// The scan behind one listing (see [`super::read_directory`]): cap-std's, which reads
    /// a descriptor of its own, opened from the directory's (`openat` of `.`, then
    /// `fdopendir`), so it follows the directory, never a path, and keeps its own position.
    pub struct Scan {
        entries: ReadDir,
        /// A read failed: nothing more comes.
        finished: bool,
    }

    pub fn read_directory(dir: &Dir) -> io::Result<Scan> {
        Ok(Scan {
            entries: dir.entries()?,
            finished: false,
        })
    }

    impl Scan {
        /// The next entry other than `.` and `..`.
        pub fn next_entry(&mut self) -> Option<io::Result<DirectoryEntry>> {
            while !self.finished {
                let entry = match self.entries.next()? {
                    Ok(entry) => entry,
                    Err(error) => {
                        self.finished = true;
                        return Some(Err(error));
                    }
                };
                let name = entry.file_name();
                if name == "." || name == ".." {
                    continue;
                }
                // The record's `d_type`. Where it has none, cap-std answers unknown (Linux)
                // or reads the name by a stat relative to the descriptor, never following.
                let kind = entry.file_type().ok().and_then(kind_of);
                return Some(Ok(DirectoryEntry { name, kind }));
            }
            None
        }
    }
}

/// Opens `component` of `parent` for reading without following it.
pub(super) fn open_entry<P: AsRef<Path>>(parent: &Dir, component: P) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    platform::no_follow(&mut options);
    parent.open_with(component, &options)
}

/// What `component` of `parent` is, without following it and without the right to read it,
/// so an entry another process locked against reading still has its kind and size. Nothing
/// is read through it.
pub(super) fn entry_info<P: AsRef<Path>>(parent: &Dir, component: P) -> io::Result<HandleInfo> {
    platform::entry_info(parent, component.as_ref())
}

/// Creates `component` in `parent` exclusively: an existing entry of any kind, a link
/// included, makes this fail with `AlreadyExists`.
pub(super) fn create_new(parent: &Dir, component: &str) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    parent.open_with(component, &options).map_err(|error| {
        // Windows refuses a create over a directory or a directory link as access denied.
        if error.kind() != io::ErrorKind::AlreadyExists && entry_info(parent, component).is_ok() {
            io::Error::from(io::ErrorKind::AlreadyExists)
        } else {
            error
        }
    })
}

/// [`create_new`], opened for reading as well, such as for an upload that is read back.
pub(super) fn create_new_read_write(parent: &Dir, component: &str) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    parent.open_with(component, &options).map_err(|error| {
        if error.kind() != io::ErrorKind::AlreadyExists && entry_info(parent, component).is_ok() {
            io::Error::from(io::ErrorKind::AlreadyExists)
        } else {
            error
        }
    })
}

pub(super) fn file_info(file: &File) -> io::Result<HandleInfo> {
    platform::file_info(file)
}

pub(super) fn dir_info(dir: &Dir) -> io::Result<HandleInfo> {
    platform::dir_info(dir)
}

/// Whether `component` of `parent` still names exactly the opened object and is no link
/// (Unix); always true on Windows, whose open never followed.
pub(super) fn confirm<P: AsRef<Path>>(
    parent: &Dir,
    component: P,
    opened: &HandleInfo,
) -> io::Result<bool> {
    platform::confirm(parent, component.as_ref(), opened)
}

pub(super) fn set_executable(file: &File, executable: bool) -> io::Result<()> {
    platform::set_executable(file, executable)
}

/// Opens the host directory at `path` itself, never what a link or reparse point as its
/// last component names. Only the host's own selection of a root reaches this.
pub(super) fn open_root(path: &Path) -> io::Result<Dir> {
    platform::open_root(path)
}

/// Creates the directory `component` in `parent`, relative to the parent's handle, and
/// returns what was created: on Windows read from the creating handle, on Unix from a
/// non-following stat right after `mkdirat`. An existing entry of any kind fails with
/// `AlreadyExists`.
pub(super) fn create_directory(parent: &Dir, component: &str) -> io::Result<HandleInfo> {
    platform::create_directory(parent, Path::new(component))
}

/// Renames `component` of `parent`, which must still be the object `expected` describes,
/// to `target` in `target_parent`. Without `replace` an existing `target` fails with
/// `AlreadyExists` and is never replaced (on Unix a directory may still replace an empty
/// directory). `false` when the name no longer names `expected`; nothing changed then. A
/// replacing rename is atomic and, as on Unix, lands over a target another handle holds
/// open (on Windows one opened with delete sharing, except on a volume without POSIX
/// rename semantics), which reads on the replaced file.
pub(super) fn rename(
    parent: &Dir,
    component: &str,
    expected: &HandleInfo,
    target_parent: &Dir,
    target: &str,
    replace: bool,
) -> io::Result<bool> {
    platform::rename(
        parent,
        Path::new(component),
        expected,
        target_parent,
        Path::new(target),
        replace,
    )
}

/// Removes `component` of `parent`, which must still be the object `expected` describes;
/// a directory must be empty. `false` when the name no longer names `expected`; nothing
/// changed then. On Windows the name goes at once (POSIX delete semantics), even while
/// another process holds the entry open with delete sharing, except on a volume without
/// them (FAT), where it lingers until the last handle closes.
pub(super) fn remove(parent: &Dir, component: &str, expected: &HandleInfo) -> io::Result<bool> {
    platform::remove(parent, Path::new(component), expected, false)
}

/// [`remove`] for an object the host created and owns, such as a managed tree being torn
/// down: a read-only attribute does not keep it (Windows; a Unix `unlink` ignores the
/// file mode anyway).
pub(super) fn remove_host_owned(
    parent: &Dir,
    component: &str,
    expected: &HandleInfo,
) -> io::Result<bool> {
    platform::remove(parent, Path::new(component), expected, true)
}

/// Makes this thread's removals take the legacy disposition, as on a volume without the
/// extended one (tests only).
#[cfg(all(test, windows))]
pub(super) fn force_legacy_disposition(legacy: bool) {
    platform::LEGACY_DISPOSITION.with(|forced| forced.set(legacy));
}

/// Makes this thread's replacing renames take the legacy class, as on a volume without the
/// extended one (tests only).
#[cfg(all(test, windows))]
pub(super) fn force_legacy_rename(legacy: bool) {
    platform::LEGACY_RENAME.with(|forced| forced.set(legacy));
}

/// The opened directory as a directory handle for the next component.
pub(super) fn into_dir(file: File) -> Dir {
    Dir::from_std_file(file.into_std())
}

/// A listing of one directory, read through its own handle ([`read_directory`]).
pub(super) struct DirectoryEntries(platform::Scan);

impl Iterator for DirectoryEntries {
    type Item = io::Result<DirectoryEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next_entry()
    }
}

/// Lists the directory `dir` through its own handle, never by a path rebuilt from it, so a
/// rename or swap of it or of a directory above it cannot make the listing read another
/// directory. The listing has its own scan position, so listings of one directory, through
/// cloned handles included, never disturb each other. Entries come in the file system's
/// order, a batch at a time, so a caller that stops early reads no further; `.` and `..`
/// never come. An entry the record finds malformed (Windows) fails with `InvalidData`, and
/// after any error the listing ends.
pub(super) fn read_directory(dir: &Dir) -> io::Result<DirectoryEntries> {
    platform::read_directory(dir).map(DirectoryEntries)
}

/// How `parent` spells `component`: `Exact` when an entry has exactly this name, `Alias`
/// with the stored spelling when only an ASCII case-insensitive match exists (a
/// case-insensitive volume would open it), `Absent` otherwise.
pub(super) enum Spelling {
    Exact,
    Alias(String),
    Absent,
}

pub(super) fn spelling(parent: &Dir, component: &str) -> io::Result<Spelling> {
    let mut alias = None;
    for entry in read_directory(parent)? {
        let name = entry?.name;
        if name == component {
            return Ok(Spelling::Exact);
        }
        if alias.is_none() {
            if let Some(text) = name.to_str() {
                if text.eq_ignore_ascii_case(component) {
                    alias = Some(text.to_owned());
                }
            }
        }
    }
    Ok(alias.map_or(Spelling::Absent, Spelling::Alias))
}

/// Why a file could not be read whole.
pub(super) enum ReadProblem {
    TooLarge {
        size_bytes: u64,
    },
    /// The open file is no longer the regular file of the length observed.
    Changed,
    Io(io::Error),
}

impl From<io::Error> for ReadProblem {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Reads the whole of the open regular file `file` whose observed length is
/// `expected_bytes`, refusing more than `max_bytes` and a length change while reading.
pub(super) fn read_open(
    file: &mut File,
    expected_bytes: u64,
    max_bytes: u64,
) -> Result<Vec<u8>, ReadProblem> {
    if expected_bytes > max_bytes {
        return Err(ReadProblem::TooLarge {
            size_bytes: expected_bytes,
        });
    }
    let mut bytes = Vec::with_capacity(usize::try_from(expected_bytes).unwrap_or(0));
    file.take(expected_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).ok() != Some(expected_bytes) {
        return Err(ReadProblem::Changed);
    }
    let after = file_info(file)?;
    if after.kind != HandleKind::File || after.size != expected_bytes {
        return Err(ReadProblem::Changed);
    }
    Ok(bytes)
}

/// The content key of the open regular file `file` of `size_bytes`, read in chunks, or
/// `None` when it does not hold exactly that many bytes.
pub(super) fn hash_open(file: &mut File, size_bytes: u64) -> io::Result<Option<ContentKey>> {
    let mut hasher = ContentHasher::new(size_bytes);
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let Some(chunk) = buffer.get(..read) else {
            return Ok(None);
        };
        if hasher.update(chunk).is_err() {
            return Ok(None);
        }
    }
    Ok(hasher.finish().ok())
}

#[cfg(test)]
#[path = "listing_tests.rs"]
mod listing_tests;
