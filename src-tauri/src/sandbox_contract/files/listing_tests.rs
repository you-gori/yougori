//! Listing a directory by its handle (VM part §5.1: "Resolve them beneath the opened root
//! using platform-safe handle-relative operations. A prior string canonicalization check is
//! not enough against rename, symlink or reparse-point races"; M12, follow-up M12L from the
//! VM-CP-15 boundary corpus).
//!
//! [`read_directory`] lists the directory a handle holds, whatever its old path names now,
//! and the case-alias check built on it never names another directory's entry. On Windows a
//! directory named with a trailing dot shows the difference deterministically: the Win32
//! path layer drops the dot, so a listing by the rebuilt path reads its namesake.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use cap_std::fs::Dir;

use super::super::fakes::{at, session};
use super::super::root::{Stop, Walk};
use super::super::root_tests::{dir_link, name, names_in, tree, write, DIR_LINK};
use super::super::{
    FileGrant, FileOperation, FileQuota, FileService, GrantMode, GrantedRoot, QuotaUsage,
    RequestContext, MAX_LISTED_ENTRIES,
};
use super::{open_root, read_directory, spelling, HandleKind, Spelling};
use crate::foundation::ids::{ExecutionCategory, TrustScope};

/// The names `dir`'s own listing gives, sorted, after checking none came twice.
fn listed(dir: &Dir) -> Vec<String> {
    let mut names: Vec<String> = read_directory(dir)
        .unwrap()
        .map(|entry| entry.unwrap().name.into_string().unwrap())
        .collect();
    let count = names.len();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), count, "an entry was listed twice");
    names
}

/// What the case-alias check says of `component` in `dir`.
fn spelled(dir: &Dir, component: &str) -> String {
    match spelling(dir, component).unwrap() {
        Spelling::Exact => "exact".to_owned(),
        Spelling::Alias(stored) => format!("alias:{stored}"),
        Spelling::Absent => "absent".to_owned(),
    }
}

/// Whether `name` is no longer than one name component may be: 255 UTF-16 units on
/// Windows, 255 bytes on Unix.
fn fits(name: &str) -> bool {
    #[cfg(windows)]
    let length = name.encode_utf16().count();
    #[cfg(unix)]
    let length = name.len();
    length <= 255
}

/// The longest name made of `unit` repeated.
fn longest(unit: &str) -> String {
    let mut name = String::new();
    while fits(&format!("{name}{unit}")) {
        name.push_str(unit);
    }
    name
}

/// Creates `count` empty files in `dir`, named after their index and padded to `width`
/// characters; their names.
fn populate(dir: &Path, count: usize, width: usize) -> Vec<String> {
    fs::create_dir_all(dir).unwrap();
    let mut names: Vec<String> = (0..count)
        .map(|index| format!("entry-{index:05}-{}", "x".repeat(width)))
        .collect();
    for entry in &names {
        fs::write(dir.join(entry), b"").unwrap();
    }
    names.sort();
    names
}

#[test]
fn the_listing_follows_the_handle_when_its_directory_is_renamed_and_replaced() {
    let temp = tempfile::tempdir().unwrap();
    let held = temp.path().join("held");
    write(&held, "first.txt", b"1");
    write(&held, "second.txt", b"2");
    let dir = open_root(&held).unwrap();
    fs::rename(&held, temp.path().join("moved")).unwrap();
    write(&held, "replacement.txt", b"r");
    assert_eq!(names_in(&held), ["replacement.txt"]);
    assert_eq!(listed(&dir), ["first.txt", "second.txt"]);
    // The directory above renamed and replaced, the held one inside it. NTFS refuses to
    // rename a directory while one beneath it is open, so only Unix can do this.
    #[cfg(unix)]
    {
        let parent = temp.path().join("parent");
        write(&parent, "inner/deep.txt", b"d");
        let inner = open_root(&parent.join("inner")).unwrap();
        fs::rename(&parent, temp.path().join("parent-moved")).unwrap();
        write(&parent, "inner/impostor.txt", b"i");
        assert_eq!(listed(&inner), ["deep.txt"]);
    }
}

#[test]
fn the_case_alias_check_under_that_swap_names_nothing_from_the_other_directory() {
    let temp = tempfile::tempdir().unwrap();
    let held = temp.path().join("held");
    write(&held, "Data.txt", b"held");
    let dir = open_root(&held).unwrap();
    fs::rename(&held, temp.path().join("moved")).unwrap();
    write(&held, "DATA.TXT", b"other");
    write(&held, "Secret.txt", b"other");
    assert_eq!(spelled(&dir, "Data.txt"), "exact");
    assert_eq!(spelled(&dir, "data.txt"), "alias:Data.txt");
    assert_eq!(spelled(&dir, "Secret.txt"), "absent");
    assert_eq!(spelled(&dir, "secret.txt"), "absent");
}

#[test]
fn a_walk_whose_directory_is_swapped_names_nothing_from_outside_the_root() {
    for asked in ["d/data.txt", "d/secret.txt"] {
        let tree = tree();
        write(&tree.root, "d/Data.txt", b"inside");
        write(&tree.outside, "other/DATA.TXT", b"outside");
        write(&tree.outside, "other/SECRET.txt", b"outside");
        let root = GrantedRoot::open(&tree.root).unwrap();
        let d = tree.root.join("d");
        let mut swapped = false;
        // Once `d` is open, it moves away and a directory from outside takes its name.
        let walked = root
            .walk_with(&name(asked), &mut |index| {
                if index == 0 {
                    fs::rename(&d, tree.root.join("d-moved")).unwrap();
                    fs::rename(tree.outside.join("other"), &d).unwrap();
                    swapped = true;
                }
            })
            .unwrap();
        assert!(swapped, "the swap is what this test exercises");
        match (asked, walked) {
            (
                "d/data.txt",
                Walk::Blocked {
                    component: 1,
                    stop: Stop::CaseAlias { stored },
                },
            ) => assert_eq!(stored, "Data.txt"),
            ("d/secret.txt", Walk::Missing { missing: 1 }) => {}
            (asked, Walk::Blocked { component, stop }) => {
                panic!("{asked}: blocked at {component}: {stop:?}")
            }
            (asked, Walk::Missing { missing }) => panic!("{asked}: {missing} missing"),
            (asked, Walk::Found(_)) => panic!("{asked}: found"),
        }
    }
}

/// A directory named `x.` beside one named `x`: the Win32 path layer drops the trailing
/// dot, so the path rebuilt from the handle of `x.` names `x`. The listing reads `x.`.
#[cfg(windows)]
#[test]
fn a_directory_whose_path_the_win32_layer_rewrites_is_listed_as_itself() {
    use super::{create_directory, create_new, into_dir, open_entry};

    let temp = tempfile::tempdir().unwrap();
    write(&temp.path().join("x"), "KEPT.TXT", b"namesake");
    write(&temp.path().join("x"), "SECRET.txt", b"namesake");
    let parent = open_root(temp.path()).unwrap();
    create_directory(&parent, "x.").unwrap();
    let dotted = into_dir(open_entry(&parent, "x.").unwrap());
    drop(create_new(&dotted, "kept.txt").unwrap());
    // A listing by the path reads the namesake.
    assert_eq!(
        names_in(&temp.path().join("x.")),
        ["KEPT.TXT", "SECRET.txt"]
    );
    assert_eq!(listed(&dotted), ["kept.txt"]);
    assert_eq!(spelled(&dotted, "kept.txt"), "exact");
    assert_eq!(spelled(&dotted, "Kept.txt"), "alias:kept.txt");
    assert_eq!(spelled(&dotted, "secret.txt"), "absent");
    assert_eq!(spelled(&dotted, "SECRET.txt"), "absent");
}

#[test]
fn names_up_to_the_component_limit_and_non_ascii_names_are_listed_exactly() {
    let temp = tempfile::tempdir().unwrap();
    let held = temp.path().join("names");
    fs::create_dir(&held).unwrap();
    let pairs = longest("\u{1F600}");
    let files = [
        longest("a"),
        longest("\u{fc}"),
        format!("{pairs}x"),
        "\u{65e5}\u{672c}\u{8a9e}\u{306e}\u{30d5}\u{30a1}\u{30a4}\u{30eb}.txt".to_owned(),
        "\u{395}\u{3bb}\u{3bb}\u{3b7}\u{3bd}\u{3b9}\u{3ba}\u{3ac}".to_owned(),
        "mixed-\u{1D11E}-\u{fc}-\u{65e5}.txt".to_owned(),
    ];
    let directory = longest("d");
    for file in &files {
        fs::write(held.join(file), b"x").unwrap();
    }
    fs::create_dir(held.join(&directory)).unwrap();
    #[cfg(windows)]
    {
        assert_eq!(files[0].encode_utf16().count(), 255);
        assert_eq!(files[1].encode_utf16().count(), 255);
        assert_eq!(files[2].encode_utf16().count(), 255);
    }
    #[cfg(unix)]
    assert_eq!(files[0].len(), 255);
    let dir = open_root(&held).unwrap();
    let mut expected: Vec<String> = files.to_vec();
    expected.push(directory.clone());
    expected.sort();
    assert_eq!(listed(&dir), expected);
    for entry in read_directory(&dir).unwrap() {
        let entry = entry.unwrap();
        let kind = if entry.name == directory.as_str() {
            HandleKind::Directory
        } else {
            HandleKind::File
        };
        assert!(
            entry.kind == Some(kind) || (cfg!(unix) && entry.kind.is_none()),
            "{:?}: {:?}",
            entry.name,
            entry.kind
        );
    }
    assert_eq!(
        spelled(&dir, &files[0].to_uppercase()),
        format!("alias:{}", files[0])
    );
    assert_eq!(spelled(&dir, &files[2]), "exact");
}

/// A name that is no Unicode at all, a lone surrogate, comes back unit for unit.
#[cfg(windows)]
#[test]
fn a_name_with_a_lone_surrogate_comes_back_unchanged() {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    let temp = tempfile::tempdir().unwrap();
    let lone = OsString::from_wide(&[0x61, 0xD800, 0x62]);
    fs::write(temp.path().join(&lone), b"x").unwrap();
    let dir = open_root(temp.path()).unwrap();
    let entries: Vec<_> = read_directory(&dir).unwrap().map(Result::unwrap).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, lone);
    assert_eq!(
        entries[0].name.encode_wide().collect::<Vec<_>>(),
        [0x61, 0xD800, 0x62]
    );
    assert!(entries[0].name.to_str().is_none());
}

#[test]
fn a_listing_of_many_batches_returns_every_entry_once() {
    let temp = tempfile::tempdir().unwrap();
    let held = temp.path().join("many");
    let names = populate(&held, 400, 120);
    #[cfg(windows)]
    {
        // Each record is its fixed part and the name, 8-byte aligned.
        let header = std::mem::offset_of!(
            windows_sys::Win32::Storage::FileSystem::FILE_ID_BOTH_DIR_INFO,
            FileName
        );
        let bytes: usize = names
            .iter()
            .map(|entry| (header + 2 * entry.encode_utf16().count()).div_ceil(8) * 8)
            .sum();
        assert!(
            bytes > 10 * super::platform::LISTING_BUFFER_BYTES,
            "{bytes}"
        );
    }
    let dir = open_root(&held).unwrap();
    assert_eq!(listed(&dir), names);
    // A caller that stops early, as the case-alias check on an exact match does.
    assert_eq!(read_directory(&dir).unwrap().take(3).count(), 3);
    assert_eq!(spelled(&dir, &names[399]), "exact");
    assert_eq!(
        spelled(&dir, &names[0].to_uppercase()),
        format!("alias:{}", names[0])
    );
}

#[test]
fn listings_through_cloned_handles_keep_their_own_positions() {
    let temp = tempfile::tempdir().unwrap();
    let held = temp.path().join("shared");
    let names = populate(&held, 200, 60);
    let dir = open_root(&held).unwrap();
    // A clone shares the open directory, and so would a scan position kept in it.
    let clone = dir.try_clone().unwrap();
    let mut first = read_directory(&dir).unwrap();
    let mut second = read_directory(&clone).unwrap();
    let (mut seen_first, mut seen_second) = (Vec::new(), Vec::new());
    loop {
        let (a, b) = (first.next(), second.next());
        if a.is_none() && b.is_none() {
            break;
        }
        if let Some(entry) = a {
            seen_first.push(entry.unwrap().name.into_string().unwrap());
        }
        if let Some(entry) = b {
            seen_second.push(entry.unwrap().name.into_string().unwrap());
        }
        if seen_first.len() == 50 {
            // A whole listing in between, through either handle.
            assert_eq!(listed(&clone), names);
            assert_eq!(listed(&dir), names);
        }
    }
    seen_first.sort();
    seen_second.sort();
    assert_eq!(seen_first, names);
    assert_eq!(seen_second, names);
}

#[test]
fn an_empty_directory_lists_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let held = temp.path().join("empty");
    fs::create_dir(&held).unwrap();
    let dir = open_root(&held).unwrap();
    assert!(listed(&dir).is_empty());
    assert_eq!(spelled(&dir, "anything"), "absent");
    // Emptied again after holding an entry.
    fs::write(held.join("gone.txt"), b"x").unwrap();
    assert_eq!(listed(&dir), ["gone.txt"]);
    fs::remove_file(held.join("gone.txt")).unwrap();
    assert!(listed(&dir).is_empty());
    // A listing that ended stays ended.
    let mut listing = read_directory(&dir).unwrap();
    assert!(listing.next().is_none());
    assert!(listing.next().is_none());
}

#[test]
fn the_record_says_what_each_entry_is() {
    let tree = tree();
    write(&tree.root, "file.txt", b"abc");
    write(&tree.root, "sub/inner.txt", b"x");
    dir_link(&tree.root.join("link"), &tree.outside);
    let dir = open_root(&tree.root).unwrap();
    let mut seen = BTreeSet::new();
    for entry in read_directory(&dir).unwrap() {
        let entry = entry.unwrap();
        let text = entry.name.to_str().unwrap().to_owned();
        let expected = match text.as_str() {
            "file.txt" => HandleKind::File,
            "sub" => HandleKind::Directory,
            "link" => HandleKind::Link(DIR_LINK),
            other => panic!("unexpected entry {other}"),
        };
        assert!(
            entry.kind == Some(expected) || (cfg!(unix) && entry.kind.is_none()),
            "{text}: {:?}",
            entry.kind
        );
        #[cfg(windows)]
        {
            use super::entry_info;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            };
            // IO_REPARSE_TAG_MOUNT_POINT: a junction.
            let tag = (text == "link").then_some(0xA000_0003);
            assert_eq!(entry.reparse_tag, tag, "{text}");
            assert_eq!(
                entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
                text == "link"
            );
            assert_eq!(
                entry.attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
                text != "file.txt"
            );
            // The id a handle opened as the entry reports, on NTFS.
            assert_eq!(entry.file_id, entry_info(&dir, &entry.name).unwrap().index);
        }
        seen.insert(text);
    }
    assert_eq!(seen.len(), 3);
    // The record shows a read-only attribute too, without a query of its own.
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY;
        let file = tree.root.join("file.txt");
        let original = fs::metadata(&file).unwrap().permissions();
        let mut read_only = original.clone();
        read_only.set_readonly(true);
        fs::set_permissions(&file, read_only).unwrap();
        let attributes = read_directory(&dir)
            .unwrap()
            .map(Result::unwrap)
            .find(|entry| entry.name == "file.txt")
            .unwrap()
            .attributes;
        // Writable again, so the temporary directory can go.
        fs::set_permissions(&file, original).unwrap();
        assert_ne!(attributes & FILE_ATTRIBUTE_READONLY, 0);
    }
}

#[cfg(windows)]
#[test]
fn malformed_records_fail_without_reading_past_the_batch() {
    use std::io::ErrorKind;
    use std::mem::offset_of;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ID_BOTH_DIR_INFO,
    };

    use super::platform::parse_record;

    type Info = FILE_ID_BOTH_DIR_INFO;
    const HEADER: usize = offset_of!(Info, FileName);

    /// One record: `next` 0 for the last, the name's length as `length`, or the name's.
    fn record(next: u32, attributes: u32, ea: u32, name: &str, length: Option<u32>) -> Vec<u8> {
        let wide: Vec<u16> = name.encode_utf16().collect();
        let name_bytes = 2 * wide.len();
        let mut bytes = vec![0u8; (HEADER + name_bytes).div_ceil(8) * 8];
        let mut put = |at: usize, value: &[u8]| bytes[at..at + value.len()].copy_from_slice(value);
        put(offset_of!(Info, NextEntryOffset), &next.to_ne_bytes());
        put(offset_of!(Info, FileAttributes), &attributes.to_ne_bytes());
        let length = length.unwrap_or(u32::try_from(name_bytes).unwrap());
        put(offset_of!(Info, FileNameLength), &length.to_ne_bytes());
        put(offset_of!(Info, EaSize), &ea.to_ne_bytes());
        put(
            offset_of!(Info, FileId),
            &0x1234_5678_9abc_u64.to_ne_bytes(),
        );
        for (index, unit) in wide.iter().enumerate() {
            put(HEADER + 2 * index, &unit.to_ne_bytes());
        }
        bytes
    }

    fn refused(batch: &[u8], offset: usize) {
        match parse_record(batch, offset) {
            Err(error) => assert_eq!(error.kind(), ErrorKind::InvalidData),
            Ok(parsed) => panic!("parsed {parsed:?}"),
        }
    }

    // Well formed: a file, then a reparse point, chained.
    let first = record(0, 0x20, 7, "a.txt", None);
    let first_length = u32::try_from(first.len()).unwrap();
    let mut batch = record(first_length, 0x20, 7, "a.txt", None);
    batch.extend(record(
        0,
        FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
        0xA000_0003,
        "j",
        None,
    ));
    let (entry, next) = parse_record(&batch, 0).unwrap();
    let entry = entry.unwrap();
    assert_eq!(entry.name, "a.txt");
    assert_eq!(entry.kind, Some(HandleKind::File));
    assert_eq!(entry.reparse_tag, None);
    assert_eq!(entry.file_id, 0x1234_5678_9abc);
    assert_eq!(next, Some(first.len()));
    let (entry, next) = parse_record(&batch, first.len()).unwrap();
    let entry = entry.unwrap();
    assert_eq!(
        entry.kind,
        Some(HandleKind::Link(super::LinkKind::Junction))
    );
    assert_eq!(entry.reparse_tag, Some(0xA000_0003));
    assert_eq!(next, None);
    // `.` and `..` yield no entry.
    for dots in [".", ".."] {
        let (entry, next) =
            parse_record(&record(0, FILE_ATTRIBUTE_DIRECTORY, 0, dots, None), 0).unwrap();
        assert!(entry.is_none() && next.is_none());
    }

    let plain = record(0, 0x20, 0, "abc", None);
    // An offset past the batch, and a batch shorter than a record's fixed part.
    refused(&plain, plain.len() + 1);
    refused(&plain[..HEADER - 1], 0);
    // A name longer than what is left of the batch, or reaching past the next record.
    refused(&record(0, 0x20, 0, "abc", Some(4096)), 0);
    refused(&record(0, 0x20, 0, "abc", Some(u32::MAX)), 0);
    let mut overlapping = record(8, 0x20, 0, "abc", None);
    overlapping.extend(record(0, 0x20, 0, "b", None));
    refused(&overlapping, 0);
    // A next record past the batch's end, or exactly at it.
    refused(&record(u32::MAX, 0x20, 0, "abc", None), 0);
    let at_end = record(u32::try_from(plain.len()).unwrap(), 0x20, 0, "abc", None);
    assert_eq!(parse_record(&at_end, 0).unwrap().1, Some(at_end.len()));
    refused(&at_end, at_end.len());
    // An odd or empty name, and one holding a separator or NUL.
    refused(&record(0, 0x20, 0, "abc", Some(5)), 0);
    refused(&record(0, 0x20, 0, "", None), 0);
    for bad in ["a\\b", "a/b", "a\0b"] {
        refused(&record(0, 0x20, 0, bad, None), 0);
    }
}

#[test]
fn the_service_listing_keeps_its_bound_and_the_count_covers_every_batch() {
    let tree = tree();
    let total = MAX_LISTED_ENTRIES + 3;
    let names: BTreeSet<String> = populate(&tree.root, total, 0).into_iter().collect();
    fs::write(tree.root.join("sized.txt"), b"abcde").unwrap();
    let entries = u64::try_from(total + 1).unwrap();
    let scope = TrustScope::named(ExecutionCategory::VmSandbox, "sandbox-a");
    let serve = |max_entries: u64| {
        let root = GrantedRoot::open(&tree.root).unwrap();
        let grant = FileGrant::new(
            root.handle(),
            GrantMode::QuarantineOutput,
            BTreeSet::from([FileOperation::List]),
            scope,
            session(1),
            at(100),
            FileQuota {
                max_total_bytes: 1_000_000,
                max_entries,
                max_file_bytes: 1_000,
            },
        )
        .unwrap();
        FileService::new(grant, root).unwrap()
    };
    let service = serve(entries);
    assert_eq!(
        service.usage(),
        Some(QuotaUsage {
            total_bytes: 5,
            entries
        })
    );
    // One entry more than the quota allows cannot be counted within it.
    assert_eq!(serve(entries - 1).usage(), None);
    let context = RequestContext {
        scope,
        now: at(1),
        session: session(1),
    };
    let listing = service.list(&context, None).unwrap();
    assert!(listing.truncated);
    assert_eq!(listing.unaddressable, 0);
    assert_eq!(listing.entries.len(), MAX_LISTED_ENTRIES);
    let shown: BTreeSet<&str> = listing
        .entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    assert_eq!(shown.len(), MAX_LISTED_ENTRIES);
    assert!(shown
        .iter()
        .all(|entry| names.contains(*entry) || *entry == "sized.txt"));
}
