//! One catalog at a time owns a root directory.
//!
//! [`Catalog::open`](super::Catalog::open) takes an exclusive lock on the root's [`LOCK_FILE`]
//! before it reads, creates or removes anything else under the root, and the catalog holds the
//! lock for as long as it lives. The lock is the operating system's own file lock: `flock` on
//! Linux and macOS, the call the engine's single-instance lock makes there, and `LockFileEx` on
//! Windows. The system releases it when the holding process ends, however it ends, so a crash
//! leaves no stale lock and nothing to clean up. The handle is not inherited, so a process the
//! holder started (a VM it runs, say) never keeps the lock after the holder is gone.
//!
//! A second open of a held root, by another engine or by another catalog in the same process,
//! waits [`RELEASE_GRACE`] for a holder that is just ending and is then refused
//! ([`OpenFailure::InUse`]): it reads, creates and removes nothing there, so it can never remove
//! the temporary files of the holder's writes in progress.
//!
//! The lock file stays on disk, empty, and never needs cleaning up. Removing it when a catalog
//! closes would let one opener lock a file that another is about to replace, and both would
//! think they own the root; for the same reason it must not be deleted while an engine runs.
//! On Windows the holder locks a byte far past the file's end, so programs that copy or read
//! the root (a backup, an archive tool) still read the file, as they always can on Linux and
//! macOS, where the lock binds only those who take it.

use std::fs::{File, OpenOptions};
use std::io;
use std::thread;
use std::time::{Duration, Instant};

use super::provenance::StorageOperation;
use super::state::OpenFailure;
use super::store::Layout;

/// The file in a catalog root whose exclusive lock the root's owner holds.
pub const LOCK_FILE: &str = "catalog.lock";

/// How long an open waits for a held lock before it refuses the root: time for the system to
/// finish releasing the lock of a holder that just ended, which Windows documents may take a
/// moment after the process is gone.
pub(super) const RELEASE_GRACE: Duration = Duration::from_secs(2);

/// How often a held lock is tried again within [`RELEASE_GRACE`].
const RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// The exclusive hold on one catalog root. Dropping it, or the end of the process that holds
/// it, releases the root.
#[derive(Debug)]
pub(super) struct RootLock {
    file: File,
}

impl RootLock {
    /// Takes the lock of `layout`'s root, creating the root and its lock file when missing. A
    /// lock another holder keeps past [`RELEASE_GRACE`] is refused, with nothing else under the
    /// root read, created or removed.
    pub(super) fn acquire(layout: &Layout) -> Result<Self, OpenFailure> {
        let root = layout.root_path();
        layout.create_dir(root)?;
        let path = root.join(LOCK_FILE);
        let file =
            open(&path).map_err(|error| layout.failure(StorageOperation::Open, &path, error))?;
        let deadline = Instant::now() + RELEASE_GRACE;
        loop {
            match try_lock(&file) {
                Ok(true) => return Ok(Self { file }),
                Ok(false) if Instant::now() < deadline => thread::sleep(RETRY_INTERVAL),
                Ok(false) => {
                    return Err(OpenFailure::InUse {
                        root: root.to_path_buf(),
                    })
                }
                Err(error) => {
                    return Err(layout.failure(StorageOperation::Lock, &path, error).into())
                }
            }
        }
    }
}

impl Drop for RootLock {
    /// Releases the lock at once; closing the file would release it too.
    fn drop(&mut self) {
        unlock(&self.file);
    }
}

/// Opens the lock file, creating it empty when missing and never changing its contents. For
/// writing too, as the engine's single-instance lock does: on NFS, Linux takes `flock` as a
/// POSIX lock, and an exclusive one needs a writable descriptor.
#[cfg(not(windows))]
fn open(path: &std::path::Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

/// Takes the exclusive lock without waiting: `Ok(false)` when another holder has it.
#[cfg(not(windows))]
fn try_lock(file: &File) -> io::Result<bool> {
    match file.try_lock() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}

#[cfg(not(windows))]
fn unlock(file: &File) {
    let _closing_releases_it_anyway = file.unlock();
}

/// The byte the lock covers, far past the end of the empty file, so the lock never stands in
/// the way of reading it.
#[cfg(windows)]
const LOCKED_BYTE: u64 = 1 << 62;

/// Opens the lock file, creating it empty when missing and never changing its contents. The
/// handle the lock is taken on only reads, so any program may open the file beside it.
#[cfg(windows)]
fn open(path: &std::path::Path) -> io::Result<File> {
    let held = || OpenOptions::new().read(true).open(path);
    match held() {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // Creating the file needs write access; the held handle does not. Two openers
            // creating it at once both succeed, and the lock then decides between them.
            drop(
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(path)?,
            );
            held()
        }
        opened => opened,
    }
}

#[cfg(windows)]
fn overlapped() -> windows_sys::Win32::System::IO::OVERLAPPED {
    let mut overlapped = windows_sys::Win32::System::IO::OVERLAPPED::default();
    overlapped.Anonymous.Anonymous.Offset = LOCKED_BYTE as u32;
    overlapped.Anonymous.Anonymous.OffsetHigh = (LOCKED_BYTE >> 32) as u32;
    overlapped
}

/// Takes the exclusive lock of [`LOCKED_BYTE`] without waiting: `Ok(false)` when another
/// holder has it.
#[cfg(windows)]
fn try_lock(file: &File) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, ERROR_LOCK_VIOLATION};
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    let mut overlapped = overlapped();
    // SAFETY: the handle is open for reading for the whole call, and `overlapped` is a valid,
    // initialized structure that outlives it; the handle is synchronous, so the call completes
    // before it returns.
    let locked = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    if locked != 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(code) if code == ERROR_LOCK_VIOLATION as i32 || code == ERROR_IO_PENDING as i32 => {
            Ok(false)
        }
        _ => Err(error),
    }
}

#[cfg(windows)]
fn unlock(file: &File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    let mut overlapped = overlapped();
    // SAFETY: as for `LockFileEx`; unlocking a byte this handle locked. A failure leaves the
    // release to the handle's close, which follows at once.
    let _closing_releases_it_anyway =
        unsafe { UnlockFileEx(file.as_raw_handle(), 0, 1, 0, &mut overlapped) };
}
