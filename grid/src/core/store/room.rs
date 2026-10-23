//! How much room is left where a realm lives.
//!
//! A realm is one SQLite database in write-ahead logging with every commit flushed, which means
//! three files in one folder and a journal that grows between check-points. A disk with no room
//! left is the most common real failure for that shape, and it is not a tidy one: the realm stops
//! being able to record what happened, and refusing to record what happened means refusing
//! whatever caused it, so the first an operator hears of it is the grid refusing work.
//!
//! So this is asked in three places and nowhere else. Starting a realm asks, because an operator
//! who is told now can pick another disk and has lost nothing. Taking a copy asks, because a copy
//! is the largest single write a realm ever makes and a half-written copy is worse than no copy,
//! particularly in `upgrade_with_a_copy` where the copy is the only way back. And `Core::ready`
//! asks, because that is the check an operator runs first and it is where a warning belongs. The
//! ordinary write path does not ask: a check per transaction would be a syscall per audited action
//! for a condition that changes over hours, and SQLite already refuses a write it cannot make.
//!
//! **What is measured, and where it is not.** On Windows this asks the operating system for the
//! free space on the volume the realm is on, and that is the platform this ships on. Everywhere
//! else it answers that it does not know, and every caller treats not knowing as permission to
//! carry on rather than as a refusal. That is the same rule `identity.rs` and `hardware.rs`
//! already follow: a fact that was not measured is reported as not measured and never as no. The
//! reason it is not measured elsewhere is worth writing down rather than leaving as an oversight.
//! There is no free-space call in the standard library, none in any crate this one already
//! depends on, and the POSIX one needs a `statvfs` whose layout differs between Linux, macOS and
//! the BSDs; declaring it by hand would be guessing at a C structure on platforms nobody here
//! builds for, and a wrong guess there is not a wrong number, it is undefined behaviour. A host
//! that can measure it on another platform should refuse before it opens the realm.
use std::path::Path;

/// The least room a realm will be started or copied into.
///
/// Two hundred and fifty-six megabytes. It is a floor rather than an estimate of what a realm
/// needs: a realm at the published sizes is much larger than this, and what this number is for is
/// the case where there is so little room that the first check-point fails. An operator with less
/// than this free has a disk problem to solve before they have a grid problem.
pub const FLOOR: u64 = 256 * 1024 * 1024;

/// Below this, `Core::ready` says so. One gigabyte, which is enough warning to act on for a file
/// that grows by an event at a time.
pub const LOW: u64 = 1024 * 1024 * 1024;

/// How many bytes are free where this path is, or nothing when this build cannot measure it.
///
/// The path does not have to exist: what is asked about is the folder it would be in, so this
/// answers for a realm that is about to be created as well as one that is already there.
pub fn free(path: &Path) -> Option<u64> {
    let folder = if path.is_dir() { path } else { path.parent().filter(|folder| !folder.as_os_str().is_empty())? };
    free_on(folder)
}

#[cfg(windows)]
fn free_on(folder: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    // `GetDiskFreeSpaceExW` wants a directory, and the first of its three numbers is the one that
    // matters: how much the calling user may use, which is what a quota makes different from the
    // volume's own free space.
    let wide: Vec<u16> = folder.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut available: u64 = 0;
    // SAFETY: `wide` is a null-terminated UTF-16 path that outlives the call, and the two pointers
    // are to a local that outlives it too. The two numbers this does not use are passed as null,
    // which the documented signature allows.
    let answered = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut available, std::ptr::null_mut(), std::ptr::null_mut()) };
    (answered != 0).then_some(available)
}

#[cfg(not(windows))]
fn free_on(_folder: &Path) -> Option<u64> {
    None
}

/// Refuses when there is measurably not enough room, and says what to do about it.
///
/// `wanted` is what is about to be written, and `FLOOR` is on top of it, because a realm needs
/// room to keep working after whatever this is has been written. A build that cannot measure the
/// disk allows it: this must never be the thing that stops a grid being started on a platform
/// where the number is simply unknown.
pub fn enough_for(path: &Path, wanted: u64, what: &str) -> Result<(), String> {
    let Some(free) = free(path) else { return Ok(()) };
    let needed = wanted.saturating_add(FLOOR);
    if free >= needed {
        return Ok(());
    }
    Err(format!(
        "There is not enough room on this disk {what}: {} free, and this needs {}. Free some space on the disk this grid is kept on, or keep the grid somewhere with more room, and try again. Nothing was written.",
        in_words(free),
        in_words(needed)
    ))
}

/// A size as a person would say it. Whole units, because a tenth of a gigabyte is not a thing
/// anybody acts on and the number is going into a sentence.
pub fn in_words(bytes: u64) -> String {
    const GB: u64 = 1024 * 1024 * 1024;
    const MB: u64 = 1024 * 1024;
    if bytes >= GB {
        format!("{} GB", bytes / GB)
    } else if bytes >= MB {
        format!("{} MB", bytes / MB)
    } else {
        format!("{bytes} bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PROVES that the sentence a short disk is refused with names both numbers and tells an
    /// operator what to do, that a disk with room refuses nothing, and that a build which cannot
    /// measure the disk allows everything rather than refusing everything.
    ///
    /// DOES NOT PROVE anything about a disk that is actually full. Filling the disk of whoever
    /// runs these tests is not something a test suite may do, so what is exercised is the
    /// arithmetic and the wording against a number this test supplies.
    #[test]
    fn a_disk_with_no_room_is_refused_in_words_and_one_with_room_is_not() {
        let folder = tempfile::tempdir().unwrap();
        let realm = folder.path().join("acme.db");

        // Whatever this computer has, asking for everything it has plus a floor is refused and
        // asking for nothing is not. On a build that cannot measure, both are allowed, and the
        // test says which of the two it is rather than passing vacuously.
        match free(&realm) {
            Some(free) => {
                assert!(enough_for(&realm, 0, "for this grid").is_ok(), "a disk with {free} bytes free takes an empty realm");
                let refused = enough_for(&realm, free, "for this grid").unwrap_err();
                assert!(refused.contains("not enough room") && refused.contains("Free some space") && refused.contains("Nothing was written"), "{refused}");
                assert!(refused.contains(&in_words(free)), "the refusal says how much there is: {refused}");
            }
            None => assert!(enough_for(&realm, u64::MAX / 2, "for this grid").is_ok(), "a build that cannot measure the disk refuses nothing"),
        }

        // A folder that is not there at all is answered for by its parent, so a realm that is
        // about to be created can be asked about before anything exists.
        assert_eq!(free(&folder.path().join("not-made-yet.db")).is_some(), free(folder.path()).is_some());

        assert_eq!(in_words(5 * 1024 * 1024 * 1024), "5 GB");
        assert_eq!(in_words(700 * 1024 * 1024), "700 MB");
        assert_eq!(in_words(12), "12 bytes");
    }
}
