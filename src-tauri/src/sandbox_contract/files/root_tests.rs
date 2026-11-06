//! The granted root and its race-resistant resolution on real temporary trees (VM part §5.1:
//! "Resolve them beneath the opened root using platform-safe handle-relative operations";
//! "Test symlinks, hard links, mount changes, Windows junctions/reparse points ... case
//! folding"; VM-P15; M12).
//!
//! Directory links are junctions on Windows (`mklink /J`, which needs no privilege) and
//! symlinks on Unix. Windows symlinks need a privilege or Developer Mode; where creating one
//! fails for that reason the assertion is skipped with a note on stderr.

use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::fsutil::HandleKind;
use super::root::{EntryProblem, Opened, Stop, Walk};
use super::*;

/// What `outside/secret.txt` holds.
pub(super) const SECRET: &[u8] = b"outside secret";

/// The link kind a directory link made by [`dir_link`] is.
#[cfg(windows)]
pub(super) const DIR_LINK: LinkKind = LinkKind::Junction;
#[cfg(unix)]
pub(super) const DIR_LINK: LinkKind = LinkKind::Symlink;

/// A temporary directory holding the granted `root` and an `outside` tree that links may
/// point at: `outside/secret.txt` and `outside/sub/deeper.txt`, both holding [`SECRET`].
pub(super) struct Tree {
    pub dir: TempDir,
    pub root: PathBuf,
    pub outside: PathBuf,
}

pub(super) fn tree() -> Tree {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    let outside = dir.path().join("outside");
    fs::create_dir(&root).unwrap();
    write(&outside, "secret.txt", SECRET);
    write(&outside, "sub/deeper.txt", SECRET);
    Tree { dir, root, outside }
}

pub(super) fn name(text: &str) -> GuestName {
    GuestName::parse(text).unwrap()
}

/// The host path of the `/`-separated `text` beneath `base`.
pub(super) fn host(base: &Path, text: &str) -> PathBuf {
    text.split('/')
        .fold(base.to_path_buf(), |path, part| path.join(part))
}

pub(super) fn write(base: &Path, text: &str, bytes: &[u8]) {
    let path = host(base, text);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

pub(super) fn bytes_len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap()
}

/// Makes `link` a directory link to `target`: a junction on Windows, a symlink on Unix.
pub(super) fn dir_link(link: &Path, target: &Path) {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "mklink /J {} {} failed: {} {}",
            link.display(),
            target.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
}

/// Whether a symlink could be made; false, with a note, where Windows refuses it for want
/// of the privilege.
fn privileged(made: std::io::Result<()>, link: &Path) -> bool {
    match made {
        Ok(()) => true,
        // ERROR_PRIVILEGE_NOT_HELD: no SeCreateSymbolicLinkPrivilege and no Developer Mode.
        Err(error) if cfg!(windows) && error.raw_os_error() == Some(1314) => {
            eprintln!(
                "skipped: creating the symlink {} needs a privilege or Developer Mode",
                link.display()
            );
            false
        }
        Err(error) => panic!("symlink {}: {error}", link.display()),
    }
}

/// Makes `link` a symlink to the file `target`, or returns false where the platform refuses
/// for want of the privilege.
pub(super) fn file_symlink(link: &Path, target: &Path) -> bool {
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(target, link);
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(target, link);
    privileged(made, link)
}

/// Makes `link` a symlink to the directory `target`, or returns false where the platform
/// refuses for want of the privilege.
pub(super) fn dir_symlink(link: &Path, target: &Path) -> bool {
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_dir(target, link);
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(target, link);
    privileged(made, link)
}

/// Every entry beneath `base`, by `/`-separated name, read without following any link:
/// `dir`, `link` or `file:<content>`.
pub(super) fn snapshot(base: &Path) -> BTreeMap<String, String> {
    fn collect(base: &Path, path: &Path, found: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(path).unwrap() {
            let full = entry.unwrap().path();
            let key = full
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let metadata = fs::symlink_metadata(&full).unwrap();
            if metadata.file_type().is_symlink() {
                found.insert(key, "link".to_owned());
            } else if metadata.is_dir() {
                found.insert(key, "dir".to_owned());
                collect(base, &full, found);
            } else {
                let content = String::from_utf8_lossy(&fs::read(&full).unwrap()).into_owned();
                found.insert(key, format!("file:{content}"));
            }
        }
    }
    let mut found = BTreeMap::new();
    collect(base, base, &mut found);
    found
}

/// The names in the host directory `path`.
pub(super) fn names_in(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Whether `path` names anything, a dangling link included.
pub(super) fn present(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn open(path: &Path) -> GrantedRoot {
    GrantedRoot::open(path).unwrap()
}

fn content(mut opened: Opened) -> Vec<u8> {
    let mut bytes = Vec::new();
    opened.file.read_to_end(&mut bytes).unwrap();
    bytes
}

fn refused<T>(result: Result<T, EntryProblem>) -> ResolveRefusal {
    match result {
        Err(EntryProblem::Refused(refusal)) => refusal,
        Err(other) => panic!("expected a refusal, got {other:?}"),
        Ok(_) => panic!("expected a refusal, got success"),
    }
}

fn io_kind<T>(result: Result<T, EntryProblem>) -> ErrorKind {
    match result {
        Err(EntryProblem::Io(error)) => error.kind(),
        Err(other) => panic!("expected an I/O error, got {other:?}"),
        Ok(_) => panic!("expected an I/O error, got success"),
    }
}

fn link_refused(at: &str, link: LinkKind) -> ResolveRefusal {
    ResolveRefusal::LinkRefused { at: name(at), link }
}

fn not_found(at: &str) -> ResolveRefusal {
    ResolveRefusal::NotFound { at: name(at) }
}

fn file(size_bytes: u64) -> Resolved {
    Resolved::File {
        size_bytes,
        executable: false,
    }
}

const INTENTS: [ResolveIntent; 2] = [ResolveIntent::Open, ResolveIntent::Create];

fn dir_link_entry(target: &Path) -> EntryKind {
    let target = target.display().to_string();
    if cfg!(windows) {
        EntryKind::Junction { target }
    } else {
        EntryKind::Symlink { target }
    }
}

#[test]
fn the_resolver_matches_the_model_on_a_real_tree() {
    let tree = tree();
    // The resolver refuses a case variant on every volume, as the model specifies with
    // case folding on, so the alias names are compared on every platform.
    let case_insensitive = true;
    let mut model = RootModel::new(case_insensitive);
    let files: [(&str, &[u8]); 4] = [
        ("src/main.rs", b"fn main() {}\n"),
        ("src/lib/mod.rs", b"pub mod x;\n"),
        ("docs/README.md", b"# Readme\n"),
        ("notes.txt", b"notes"),
    ];
    for (text, bytes) in files {
        write(&tree.root, text, bytes);
        model.insert(
            name(text),
            EntryKind::File {
                size_bytes: bytes_len(bytes),
                executable: false,
            },
        );
    }
    fs::create_dir(tree.root.join("empty")).unwrap();
    model.insert(name("empty"), EntryKind::Directory);
    fs::hard_link(
        tree.outside.join("secret.txt"),
        tree.root.join("shadow.txt"),
    )
    .unwrap();
    model.insert(name("shadow.txt"), EntryKind::HardLink { link_count: 2 });
    dir_link(&tree.root.join("escape"), &tree.outside);
    model.insert(name("escape"), dir_link_entry(&tree.outside));
    dir_link(&tree.root.join("inside"), &tree.root.join("src"));
    model.insert(name("inside"), dir_link_entry(&tree.root.join("src")));

    let mut names = vec![
        "src",
        "src/main.rs",
        "src/lib",
        "src/lib/mod.rs",
        "src/lib/mod.rs/x",
        "src/missing.rs",
        "src/missing/x.rs",
        "missing",
        "missing/deeper/x",
        "notes.txt",
        "notes.txt/x",
        "shadow.txt",
        "shadow.txt/x",
        "escape",
        "escape/secret.txt",
        "escape/sub/deeper.txt",
        "escape/missing",
        "inside",
        "inside/main.rs",
        "empty",
        "empty/new",
        "empty/new/deeper",
        "docs",
        "docs/README.md",
    ];
    if case_insensitive {
        names.extend([
            "docs/readme.md",
            "DOCS/README.md",
            "Docs/x/y",
            "SRC",
            "src/MAIN.RS",
            "NOTES.TXT",
            "Shadow.txt",
            "ESCAPE/secret.txt",
            "Inside",
            "EMPTY/new",
        ]);
    }

    let root = open(&tree.root);
    for text in names {
        for intent in INTENTS {
            assert_eq!(
                root.resolve(&name(text), intent),
                model.resolve(&name(text), intent),
                "{text} {intent:?}"
            );
        }
    }
    // The comparison is not vacuous: the model gives each kind of result.
    let open_intent = ResolveIntent::Open;
    assert_eq!(
        root.resolve(&name("src/main.rs"), open_intent),
        Ok(file(13))
    );
    assert_eq!(
        root.resolve(&name("empty/new"), ResolveIntent::Create),
        Ok(Resolved::Absent)
    );
    assert_eq!(
        root.resolve(&name("escape/secret.txt"), open_intent),
        Err(link_refused("escape", DIR_LINK))
    );
    assert_eq!(
        root.resolve(&name("shadow.txt"), open_intent),
        Err(link_refused("shadow.txt", LinkKind::HardLink))
    );
    if case_insensitive {
        assert_eq!(
            root.resolve(&name("docs/readme.md"), open_intent),
            Err(ResolveRefusal::CaseAlias {
                requested: name("docs/readme.md"),
                stored: name("docs/README.md"),
            })
        );
    }
}

#[test]
fn a_directory_link_to_outside_the_root_is_refused_at_every_component_and_never_followed() {
    let tree = tree();
    write(&tree.root, "a/b/keep.txt", b"keep");
    dir_link(&tree.root.join("escape"), &tree.outside);
    dir_link(&host(&tree.root, "a/b/deep"), &tree.outside);
    let outside_before = snapshot(&tree.outside);
    let root = open(&tree.root);
    for (text, at) in [
        ("escape", "escape"),
        ("escape/secret.txt", "escape"),
        ("escape/sub/deeper.txt", "escape"),
        ("escape/missing.txt", "escape"),
        ("a/b/deep", "a/b/deep"),
        ("a/b/deep/secret.txt", "a/b/deep"),
        ("a/b/deep/sub/deeper.txt", "a/b/deep"),
    ] {
        for intent in INTENTS {
            assert_eq!(
                root.resolve(&name(text), intent),
                Err(link_refused(at, DIR_LINK)),
                "{text} {intent:?}"
            );
        }
    }
    // The walk stops at the link: nothing behind it is ever opened.
    assert!(matches!(
        root.walk(&name("escape/secret.txt")).unwrap(),
        Walk::Blocked { component: 0, stop: Stop::Link(link) } if link == DIR_LINK
    ));
    assert!(matches!(
        root.walk(&name("a/b/deep/sub/deeper.txt")).unwrap(),
        Walk::Blocked { component: 2, stop: Stop::Link(link) } if link == DIR_LINK
    ));
    let escape = link_refused("escape", DIR_LINK);
    assert_eq!(refused(root.open_file(&name("escape/secret.txt"))), escape);
    assert_eq!(refused(root.directory(Some(&name("escape")))), escape);
    assert_eq!(
        refused(root.create_file(&name("escape/new.txt"), b"planted", false)),
        escape
    );
    assert_eq!(refused(root.create_directory(&name("escape/new"))), escape);
    assert_eq!(
        refused(root.remove_file(&name("escape/secret.txt"))),
        escape
    );
    assert_eq!(refused(root.remove_directory(&name("escape/sub"))), escape);
    assert_eq!(
        refused(root.replace_file(&name("escape/secret.txt"), b"x", false, "stage.tmp")),
        escape
    );
    assert_eq!(
        refused(root.open_file(&name("a/b/deep/secret.txt"))),
        link_refused("a/b/deep", DIR_LINK)
    );
    assert_eq!(snapshot(&tree.outside), outside_before);
}

#[test]
fn a_directory_link_inside_the_root_is_refused_too() {
    let tree = tree();
    write(&tree.root, "src/main.rs", b"fn main() {}\n");
    dir_link(&tree.root.join("inside"), &tree.root.join("src"));
    let root = open(&tree.root);
    for text in ["inside", "inside/main.rs", "inside/new.rs"] {
        for intent in INTENTS {
            assert_eq!(
                root.resolve(&name(text), intent),
                Err(link_refused("inside", DIR_LINK)),
                "{text} {intent:?}"
            );
        }
    }
    assert_eq!(
        refused(root.open_file(&name("inside/main.rs"))),
        link_refused("inside", DIR_LINK)
    );
    assert_eq!(
        refused(root.create_file(&name("inside/new.rs"), b"x", false)),
        link_refused("inside", DIR_LINK)
    );
    assert!(!tree.root.join("src").join("new.rs").exists());
    // The real directory resolves as itself.
    assert_eq!(
        root.resolve(&name("src/main.rs"), ResolveIntent::Open),
        Ok(file(13))
    );
}

#[test]
fn symlinks_to_files_and_directories_are_refused_where_they_can_be_made() {
    let tree = tree();
    write(&tree.root, "a.txt", b"inside");
    let made = [
        (
            "file-out",
            file_symlink(
                &tree.root.join("file-out"),
                &tree.outside.join("secret.txt"),
            ),
        ),
        (
            "file-in",
            file_symlink(&tree.root.join("file-in"), &tree.root.join("a.txt")),
        ),
        (
            "dir-out",
            dir_symlink(&tree.root.join("dir-out"), &tree.outside),
        ),
    ];
    let root = open(&tree.root);
    for (text, made) in made {
        if !made {
            continue;
        }
        for intent in INTENTS {
            assert_eq!(
                root.resolve(&name(text), intent),
                Err(link_refused(text, LinkKind::Symlink)),
                "{text} {intent:?}"
            );
            assert_eq!(
                root.resolve(&name(&format!("{text}/x")), intent),
                Err(link_refused(text, LinkKind::Symlink)),
                "{text}/x {intent:?}"
            );
        }
        assert_eq!(
            refused(root.open_file(&name(text))),
            link_refused(text, LinkKind::Symlink)
        );
        assert_eq!(
            refused(root.remove_file(&name(text))),
            link_refused(text, LinkKind::Symlink)
        );
        assert!(present(&tree.root.join(text)));
    }
    assert_eq!(fs::read(tree.outside.join("secret.txt")).unwrap(), SECRET);
    assert_eq!(fs::read(tree.root.join("a.txt")).unwrap(), b"inside");
}

#[test]
fn a_hard_linked_file_is_refused_for_resolve_open_and_as_an_ancestor() {
    let tree = tree();
    fs::hard_link(
        tree.outside.join("secret.txt"),
        tree.root.join("shadow.txt"),
    )
    .unwrap();
    write(&tree.root, "a/real.txt", b"real");
    fs::hard_link(
        host(&tree.root, "a/real.txt"),
        host(&tree.root, "a/twin.txt"),
    )
    .unwrap();
    let root = open(&tree.root);
    for (text, at) in [
        ("shadow.txt", "shadow.txt"),
        ("shadow.txt/x", "shadow.txt"),
        ("a/real.txt", "a/real.txt"),
        ("a/twin.txt", "a/twin.txt"),
        ("a/twin.txt/deeper/x", "a/twin.txt"),
    ] {
        for intent in INTENTS {
            assert_eq!(
                root.resolve(&name(text), intent),
                Err(link_refused(at, LinkKind::HardLink)),
                "{text} {intent:?}"
            );
        }
    }
    assert!(matches!(
        root.walk(&name("shadow.txt/x")).unwrap(),
        Walk::Blocked {
            component: 0,
            stop: Stop::Link(LinkKind::HardLink)
        }
    ));
    let shadow = link_refused("shadow.txt", LinkKind::HardLink);
    assert_eq!(refused(root.open_file(&name("shadow.txt"))), shadow);
    assert_eq!(refused(root.directory(Some(&name("shadow.txt")))), shadow);
    assert_eq!(
        refused(root.create_file(&name("shadow.txt/x"), b"x", false)),
        shadow
    );
    assert_eq!(
        refused(root.replace_file(&name("shadow.txt"), b"x", false, "stage.tmp")),
        shadow
    );
    assert_eq!(refused(root.remove_file(&name("shadow.txt"))), shadow);
    assert!(present(&tree.root.join("shadow.txt")));
    assert!(!present(&tree.root.join("stage.tmp")));
    assert_eq!(fs::read(tree.outside.join("secret.txt")).unwrap(), SECRET);
    // With its other name gone the file has one name and resolves again.
    fs::remove_file(host(&tree.root, "a/twin.txt")).unwrap();
    assert_eq!(
        root.resolve(&name("a/real.txt"), ResolveIntent::Open),
        Ok(file(4))
    );
    assert_eq!(
        content(root.open_file(&name("a/real.txt")).unwrap()),
        b"real"
    );
}

#[cfg(windows)]
#[test]
fn a_case_alias_is_refused_with_the_stored_spelling() {
    let tree = tree();
    write(&tree.root, "README.md", b"readme");
    write(&tree.root, "Src/Main.rs", b"main");
    let root = open(&tree.root);
    // (the name asked for, the component that aliases, the stored spelling of it)
    for (text, requested, stored) in [
        ("readme.md", "readme.md", "README.md"),
        ("src/Main.rs", "src", "Src"),
        ("Src/main.rs", "Src/main.rs", "Src/Main.rs"),
        ("SRC/MAIN.RS", "SRC", "Src"),
    ] {
        for intent in INTENTS {
            assert_eq!(
                root.resolve(&name(text), intent),
                Err(ResolveRefusal::CaseAlias {
                    requested: name(requested),
                    stored: name(stored),
                }),
                "{text} {intent:?}"
            );
        }
    }
    assert!(matches!(
        root.walk(&name("readme.md")).unwrap(),
        Walk::Blocked { component: 0, stop: Stop::CaseAlias { stored } } if stored == "README.md"
    ));
    assert_eq!(
        refused(root.open_file(&name("readme.md"))),
        ResolveRefusal::CaseAlias {
            requested: name("readme.md"),
            stored: name("README.md"),
        }
    );
    // Exclusive creation meets the stored entry on a case-insensitive volume.
    assert_eq!(
        io_kind(root.create_file(&name("readme.md"), b"other", false)),
        ErrorKind::AlreadyExists
    );
    assert_eq!(names_in(&tree.root), ["README.md", "Src"]);
    assert_eq!(fs::read(tree.root.join("README.md")).unwrap(), b"readme");
    assert_eq!(
        root.resolve(&name("README.md"), ResolveIntent::Open),
        Ok(file(6))
    );
}

#[test]
fn a_directory_swapped_for_a_link_mid_walk_never_yields_the_outside_file() {
    let tree = tree();
    write(&tree.root, "a/b.txt", b"original");
    write(&tree.outside, "b.txt", b"outside");
    let root = open(&tree.root);
    let a = tree.root.join("a");
    let moved = tree.root.join("a-moved");
    let mut swapped = false;
    let walked = root
        .walk_with(&name("a/b.txt"), &mut |index| {
            if index == 0 {
                match fs::rename(&a, &moved) {
                    Ok(()) => {
                        dir_link(&a, &tree.outside);
                        swapped = true;
                    }
                    Err(error) => eprintln!("the open directory could not be renamed: {error}"),
                }
            }
        })
        .unwrap();
    match walked {
        Walk::Found(opened) => assert_eq!(content(opened), b"original"),
        Walk::Blocked { component, stop } => {
            eprintln!("the walk refused at {component}: {stop:?}");
        }
        Walk::Missing { missing } => panic!("the original file went missing ({missing})"),
    }
    assert!(swapped, "the swap is what this test exercises");
    assert_eq!(
        root.resolve(&name("a/b.txt"), ResolveIntent::Open),
        Err(link_refused("a", DIR_LINK))
    );
    assert_eq!(fs::read(tree.outside.join("b.txt")).unwrap(), b"outside");
    assert_eq!(fs::read(moved.join("b.txt")).unwrap(), b"original");
}

#[test]
fn a_file_swapped_after_it_was_opened_is_still_the_opened_file() {
    let tree = tree();
    write(&tree.root, "a/b.txt", b"original");
    let root = open(&tree.root);
    let b = host(&tree.root, "a/b.txt");
    let old = host(&tree.root, "a/b-old.txt");
    let secret = tree.outside.join("secret.txt");
    let mut swapped = false;
    let walked = root
        .walk_with(&name("a/b.txt"), &mut |index| {
            if index == 1 {
                match fs::rename(&b, &old) {
                    Ok(()) => {
                        fs::hard_link(&secret, &b).unwrap();
                        swapped = true;
                    }
                    Err(error) => eprintln!("the open file could not be renamed: {error}"),
                }
            }
        })
        .unwrap();
    let Walk::Found(opened) = walked else {
        panic!("the walk did not end on the opened file");
    };
    assert!(opened.is_single_file());
    assert_eq!(content(opened), b"original");
    assert!(swapped, "the swap is what this test exercises");
    // The name now holds a hard link to the outside file, which a new open refuses.
    assert_eq!(
        refused(root.open_file(&name("a/b.txt"))),
        link_refused("a/b.txt", LinkKind::HardLink)
    );
}

#[test]
fn a_hard_link_planted_after_the_parent_was_opened_is_met_as_itself() {
    let tree = tree();
    write(&tree.root, "a/b.txt", b"original");
    let root = open(&tree.root);
    let b = host(&tree.root, "a/b.txt");
    let secret = tree.outside.join("secret.txt");
    let walked = root
        .walk_with(&name("a/b.txt"), &mut |index| {
            if index == 0 {
                fs::remove_file(&b).unwrap();
                fs::hard_link(&secret, &b).unwrap();
            }
        })
        .unwrap();
    let Walk::Found(opened) = walked else {
        panic!("the walk did not open the planted name");
    };
    // The caller judges the opened object: two names, so every open refuses it.
    assert_eq!(opened.info.kind, HandleKind::File);
    assert_eq!(opened.info.links, 2);
    assert!(!opened.is_single_file());
    drop(opened);
    assert_eq!(
        refused(root.open_file(&name("a/b.txt"))),
        link_refused("a/b.txt", LinkKind::HardLink)
    );
}

#[test]
fn the_opened_root_keeps_its_files_after_its_path_is_replaced() {
    let tree = tree();
    write(&tree.root, "a.txt", b"original");
    write(&tree.root, "dir/b.txt", b"b");
    let root = open(&tree.root);
    let identity = root.identity();
    let moved = tree.dir.path().join("root-moved");
    match fs::rename(&tree.root, &moved) {
        Ok(()) => {
            write(&tree.root, "a.txt", b"impostor");
            write(&tree.root, "dir/b.txt", b"impostor b");
            assert_eq!(
                content(root.open_file(&name("a.txt")).unwrap()),
                b"original"
            );
            assert_eq!(
                root.resolve(&name("dir/b.txt"), ResolveIntent::Open),
                Ok(file(1))
            );
            // A new file lands in the opened root, never at its old path.
            root.create_file(&name("new.txt"), b"new", false).unwrap();
            assert_eq!(fs::read(moved.join("new.txt")).unwrap(), b"new");
            assert!(!present(&tree.root.join("new.txt")));
            assert_eq!(root.identity(), identity);
            assert_ne!(open(&tree.root).identity(), identity);
        }
        Err(error) => {
            eprintln!("the open root could not be renamed: {error}");
            assert_eq!(
                content(root.open_file(&name("a.txt")).unwrap()),
                b"original"
            );
            assert_eq!(fs::read(tree.root.join("a.txt")).unwrap(), b"original");
        }
    }
}

#[test]
fn two_opens_of_one_directory_share_an_identity_and_another_directory_differs() {
    let tree = tree();
    fs::create_dir(tree.root.join("sub")).unwrap();
    let first = open(&tree.root);
    let second = open(&tree.root);
    assert_eq!(first.identity(), second.identity());
    assert_eq!(first.handle(), second.handle());
    assert_eq!(first.handle().digest(), first.identity().digest());
    // Another spelling of the same directory is the same object.
    let respelled = open(&tree.root.join("sub").join(".."));
    assert_eq!(respelled.identity(), first.identity());
    let other = open(&tree.outside);
    assert_ne!(other.identity(), first.identity());
    assert_ne!(other.handle(), first.handle());
    assert_ne!(open(&tree.root.join("sub")).identity(), first.identity());
    assert_eq!(first.origin(), fs::canonicalize(&tree.root).unwrap());
}

#[test]
fn the_same_path_replaced_by_another_directory_has_another_identity() {
    let tree = tree();
    let original = open(&tree.root).identity();
    let moved = tree.dir.path().join("root-moved");
    fs::rename(&tree.root, &moved).unwrap();
    fs::create_dir(&tree.root).unwrap();
    assert_ne!(open(&tree.root).identity(), original);
    // The identity follows the object, not the path.
    assert_eq!(open(&moved).identity(), original);
}

#[test]
fn a_file_or_a_link_cannot_be_opened_as_a_root() {
    let tree = tree();
    write(&tree.root, "a.txt", b"a");
    dir_link(&tree.dir.path().join("linked"), &tree.root);
    assert!(matches!(
        GrantedRoot::open(&tree.root.join("a.txt")),
        Err(RootOpenError::NotARealDirectory)
    ));
    assert!(matches!(
        GrantedRoot::open(&tree.dir.path().join("linked")),
        Err(RootOpenError::NotARealDirectory)
    ));
    assert!(matches!(
        GrantedRoot::open(&tree.dir.path().join("missing")),
        Err(RootOpenError::Io(error)) if error.kind() == ErrorKind::NotFound
    ));
    let symlinked = tree.dir.path().join("symlinked");
    if dir_symlink(&symlinked, &tree.root) {
        assert!(matches!(
            GrantedRoot::open(&symlinked),
            Err(RootOpenError::NotARealDirectory)
        ));
    }
}

#[test]
fn create_file_is_exclusive_even_over_a_link() {
    let tree = tree();
    write(&tree.root, "a.txt", b"keep");
    fs::create_dir(tree.root.join("dir")).unwrap();
    dir_link(&tree.root.join("link"), &tree.outside);
    let outside_before = snapshot(&tree.outside);
    let root = open(&tree.root);
    root.create_file(&name("new.txt"), b"fresh", false).unwrap();
    assert_eq!(fs::read(tree.root.join("new.txt")).unwrap(), b"fresh");
    root.create_file(&name("dir/inner.txt"), b"inner", false)
        .unwrap();
    assert_eq!(
        fs::read(host(&tree.root, "dir/inner.txt")).unwrap(),
        b"inner"
    );
    for taken in ["a.txt", "new.txt"] {
        assert_eq!(
            io_kind(root.create_file(&name(taken), b"clobber", false)),
            ErrorKind::AlreadyExists,
            "{taken}"
        );
    }
    // An existing directory or directory link is never replaced or followed (the error
    // kind is checked in the next test).
    for taken in ["dir", "link"] {
        assert!(
            root.create_file(&name(taken), b"clobber", false).is_err(),
            "{taken}"
        );
    }
    assert!(tree.root.join("dir").is_dir());
    assert_eq!(fs::read(tree.root.join("a.txt")).unwrap(), b"keep");
    assert_eq!(fs::read(tree.root.join("new.txt")).unwrap(), b"fresh");
    assert!(fs::symlink_metadata(tree.root.join("link"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        refused(root.create_file(&name("missing/x.txt"), b"x", false)),
        not_found("missing")
    );
    assert_eq!(
        refused(root.create_file(&name("a.txt/x"), b"x", false)),
        ResolveRefusal::NotADirectory { at: name("a.txt") }
    );
    assert_eq!(snapshot(&tree.outside), outside_before);
}

#[test]
fn create_file_over_a_directory_or_a_directory_link_fails_with_already_exists() {
    let tree = tree();
    fs::create_dir(tree.root.join("dir")).unwrap();
    dir_link(&tree.root.join("link"), &tree.outside);
    let outside_before = snapshot(&tree.outside);
    let root = open(&tree.root);
    // fsutil::create_new: "an existing entry of any kind, a link included, makes this fail
    // with `AlreadyExists`".
    for taken in ["dir", "link"] {
        assert_eq!(
            io_kind(root.create_file(&name(taken), b"clobber", false)),
            ErrorKind::AlreadyExists,
            "{taken}"
        );
    }
    assert!(tree.root.join("dir").is_dir());
    assert_eq!(snapshot(&tree.outside), outside_before);
}

#[test]
fn replace_file_swaps_the_content_and_leaves_no_staging_file() {
    let tree = tree();
    write(&tree.root, "dir/f.txt", b"old content");
    let root = open(&tree.root);
    root.replace_file(&name("dir/f.txt"), b"new", false, ".stage.tmp")
        .unwrap();
    assert_eq!(fs::read(host(&tree.root, "dir/f.txt")).unwrap(), b"new");
    assert_eq!(names_in(&tree.root.join("dir")), ["f.txt"]);
    assert_eq!(
        root.resolve(&name("dir/f.txt"), ResolveIntent::Open),
        Ok(file(3))
    );
    root.replace_file(&name("dir/f.txt"), b"", false, ".stage.tmp")
        .unwrap();
    assert_eq!(fs::read(host(&tree.root, "dir/f.txt")).unwrap(), b"");
    assert_eq!(names_in(&tree.root.join("dir")), ["f.txt"]);
}

#[test]
fn replace_file_refuses_a_taken_staging_name_and_keeps_both_files() {
    let tree = tree();
    write(&tree.root, "dir/f.txt", b"old content");
    write(&tree.root, "dir/.stage.tmp", b"someone else's");
    let root = open(&tree.root);
    assert_eq!(
        io_kind(root.replace_file(&name("dir/f.txt"), b"new", false, ".stage.tmp")),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        fs::read(host(&tree.root, "dir/f.txt")).unwrap(),
        b"old content"
    );
    assert_eq!(
        fs::read(host(&tree.root, "dir/.stage.tmp")).unwrap(),
        b"someone else's"
    );
}

#[test]
fn replace_file_refuses_links_directories_and_missing_targets() {
    let tree = tree();
    fs::create_dir(tree.root.join("dir")).unwrap();
    dir_link(&tree.root.join("link"), &tree.outside);
    fs::hard_link(
        tree.outside.join("secret.txt"),
        tree.root.join("shadow.txt"),
    )
    .unwrap();
    let before = snapshot(&tree.root);
    let outside_before = snapshot(&tree.outside);
    let root = open(&tree.root);
    let replace = |text: &str| root.replace_file(&name(text), b"x", false, ".stage.tmp");
    assert_eq!(refused(replace("link")), link_refused("link", DIR_LINK));
    assert_eq!(
        refused(replace("link/secret.txt")),
        link_refused("link", DIR_LINK)
    );
    assert_eq!(
        refused(replace("shadow.txt")),
        link_refused("shadow.txt", LinkKind::HardLink)
    );
    assert_eq!(refused(replace("missing.txt")), not_found("missing.txt"));
    assert!(matches!(replace("dir"), Err(EntryProblem::NotAFile)));
    assert_eq!(snapshot(&tree.root), before);
    assert_eq!(snapshot(&tree.outside), outside_before);
}

#[test]
fn remove_file_refuses_links_and_directories() {
    let tree = tree();
    write(&tree.root, "a.txt", b"a");
    write(&tree.root, "dir/keep.txt", b"keep");
    dir_link(&tree.root.join("link"), &tree.outside);
    fs::hard_link(
        tree.outside.join("secret.txt"),
        tree.root.join("shadow.txt"),
    )
    .unwrap();
    let outside_before = snapshot(&tree.outside);
    let root = open(&tree.root);
    root.remove_file(&name("a.txt")).unwrap();
    assert!(!present(&tree.root.join("a.txt")));
    assert_eq!(
        refused(root.remove_file(&name("link"))),
        link_refused("link", DIR_LINK)
    );
    assert!(present(&tree.root.join("link")));
    assert!(matches!(
        root.remove_file(&name("dir")),
        Err(EntryProblem::NotAFile)
    ));
    assert!(tree.root.join("dir").is_dir());
    assert_eq!(
        refused(root.remove_file(&name("shadow.txt"))),
        link_refused("shadow.txt", LinkKind::HardLink)
    );
    assert!(present(&tree.root.join("shadow.txt")));
    assert_eq!(
        refused(root.remove_file(&name("a.txt"))),
        not_found("a.txt")
    );
    assert_eq!(snapshot(&tree.outside), outside_before);
}

#[test]
fn directories_are_created_and_removed_beneath_the_root_only() {
    let tree = tree();
    write(&tree.root, "a.txt", b"a");
    dir_link(&tree.root.join("link"), &tree.outside);
    let outside_before = snapshot(&tree.outside);
    let root = open(&tree.root);
    root.create_directory(&name("d")).unwrap();
    root.create_directory(&name("d/e")).unwrap();
    assert!(host(&tree.root, "d/e").is_dir());
    for taken in ["d", "a.txt", "link"] {
        assert_eq!(
            io_kind(root.create_directory(&name(taken))),
            ErrorKind::AlreadyExists,
            "{taken}"
        );
    }
    assert_eq!(
        refused(root.create_directory(&name("missing/x"))),
        not_found("missing")
    );
    assert_eq!(
        refused(root.create_directory(&name("link/x"))),
        link_refused("link", DIR_LINK)
    );
    assert_eq!(
        io_kind(root.remove_directory(&name("d"))),
        ErrorKind::DirectoryNotEmpty
    );
    root.remove_directory(&name("d/e")).unwrap();
    root.remove_directory(&name("d")).unwrap();
    assert!(!present(&tree.root.join("d")));
    assert!(matches!(
        root.remove_directory(&name("a.txt")),
        Err(EntryProblem::Refused(_))
    ));
    assert!(present(&tree.root.join("a.txt")));
    assert_eq!(
        refused(root.remove_directory(&name("link"))),
        link_refused("link", DIR_LINK)
    );
    assert!(present(&tree.root.join("link")));
    assert_eq!(
        refused(root.remove_directory(&name("missing"))),
        not_found("missing")
    );
    assert_eq!(snapshot(&tree.outside), outside_before);
}

#[test]
fn directory_hands_out_the_root_or_a_real_directory_only() {
    let tree = tree();
    write(&tree.root, "a.txt", b"a");
    write(&tree.root, "d/inner.txt", b"inner");
    dir_link(&tree.root.join("link"), &tree.outside);
    let root = open(&tree.root);
    let listed = |dir: cap_std::fs::Dir| {
        let mut names: Vec<String> = dir
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    assert_eq!(
        listed(root.directory(None).unwrap()),
        ["a.txt", "d", "link"]
    );
    assert_eq!(
        listed(root.directory(Some(&name("d"))).unwrap()),
        ["inner.txt"]
    );
    assert_eq!(
        refused(root.directory(Some(&name("a.txt")))),
        ResolveRefusal::NotADirectory { at: name("a.txt") }
    );
    assert_eq!(
        refused(root.directory(Some(&name("link")))),
        link_refused("link", DIR_LINK)
    );
    assert_eq!(
        refused(root.directory(Some(&name("missing")))),
        not_found("missing")
    );
}

#[test]
fn copies_and_top_level_opens_refuse_links() {
    let tree = tree();
    write(&tree.root, "src/main.rs", b"fn main() {}\n");
    fs::hard_link(
        tree.outside.join("secret.txt"),
        tree.root.join("shadow.txt"),
    )
    .unwrap();
    let backups = tree.dir.path().join("backups");
    write(&backups, "keep/old.txt", b"old");
    fs::hard_link(
        host(&backups, "keep/old.txt"),
        host(&backups, "keep/twin.txt"),
    )
    .unwrap();
    dir_link(&backups.join("linked"), &tree.outside);
    write(&backups, "plain.txt", b"plain");
    let outside_before = snapshot(&tree.outside);
    let root = open(&tree.root);
    let target = open(&backups);
    assert_eq!(
        root.copy_file_to(&name("src/main.rs"), &target, "keep", "main.rs.bak")
            .unwrap(),
        13
    );
    assert_eq!(
        fs::read(host(&backups, "keep/main.rs.bak")).unwrap(),
        b"fn main() {}\n"
    );
    assert_eq!(
        io_kind(root.copy_file_to(&name("src/main.rs"), &target, "keep", "main.rs.bak")),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        refused(root.copy_file_to(&name("shadow.txt"), &target, "keep", "shadow.bak")),
        link_refused("shadow.txt", LinkKind::HardLink)
    );
    assert!(root
        .copy_file_to(&name("src/main.rs"), &target, "linked", "main.rs.bak")
        .is_err());
    assert!(!present(&tree.outside.join("main.rs.bak")));

    let opened = target.open_top_file("keep", "main.rs.bak").unwrap();
    assert_eq!(content(opened), b"fn main() {}\n");
    assert!(matches!(
        target.open_top_file("keep", "old.txt"),
        Err(EntryProblem::Changed)
    ));
    assert!(target.open_top_file("linked", "secret.txt").is_err());
    assert!(target.open_top_file("plain.txt", "x").is_err());
    target.create_top_directory("fresh").unwrap();
    assert!(backups.join("fresh").is_dir());
    assert_eq!(
        target.create_top_directory("fresh").unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(snapshot(&tree.outside), outside_before);
}

#[test]
fn a_rename_never_replaces_an_existing_name() {
    let tree = tree();
    write(&tree.root, "a.txt", b"a");
    write(&tree.root, "b.txt", b"b");
    write(&tree.root, "d/c.txt", b"c");
    let root = open(&tree.root);
    let before = snapshot(&tree.root);
    let mut taken = vec![("a.txt", "b.txt"), ("a.txt", "d"), ("a.txt", "d/c.txt")];
    if cfg!(windows) {
        // Unix renames a directory with renameat, which refuses a file target as not a
        // directory rather than as taken.
        taken.push(("d", "b.txt"));
    }
    for (from, to) in taken {
        assert_eq!(
            io_kind(root.rename_entry(&name(from), &name(to))),
            ErrorKind::AlreadyExists,
            "{from} -> {to}"
        );
    }
    assert_eq!(snapshot(&tree.root), before);
    root.rename_entry(&name("a.txt"), &name("d/a.txt")).unwrap();
    root.rename_entry(&name("d"), &name("e")).unwrap();
    assert_eq!(names_in(&tree.root), ["b.txt", "e"]);
    assert_eq!(names_in(&tree.root.join("e")), ["a.txt", "c.txt"]);
    assert_eq!(fs::read(host(&tree.root, "e/a.txt")).unwrap(), b"a");
}

#[test]
fn a_rename_refuses_links_and_hard_linked_files_as_sources() {
    let tree = tree();
    write(&tree.root, "d/keep.txt", b"keep");
    dir_link(&tree.root.join("link"), &tree.outside);
    fs::hard_link(
        tree.outside.join("secret.txt"),
        tree.root.join("shadow.txt"),
    )
    .unwrap();
    let outside_before = snapshot(&tree.outside);
    let root = open(&tree.root);
    assert_eq!(
        refused(root.rename_entry(&name("link"), &name("moved"))),
        link_refused("link", DIR_LINK)
    );
    assert_eq!(
        refused(root.rename_entry(&name("link/secret.txt"), &name("stolen.txt"))),
        link_refused("link", DIR_LINK)
    );
    assert_eq!(
        refused(root.rename_entry(&name("shadow.txt"), &name("moved.txt"))),
        link_refused("shadow.txt", LinkKind::HardLink)
    );
    assert_eq!(
        refused(root.rename_entry(&name("d/keep.txt"), &name("link/keep.txt"))),
        link_refused("link", DIR_LINK)
    );
    assert_eq!(names_in(&tree.root), ["d", "link", "shadow.txt"]);
    assert_eq!(snapshot(&tree.outside), outside_before);
}

#[test]
fn a_change_to_an_entry_replaced_since_its_check_changes_nothing() {
    let tree = tree();
    write(&tree.root, "a.txt", b"checked");
    fs::create_dir(tree.root.join("d")).unwrap();
    let root = open(&tree.root);
    let Opened {
        parent,
        component,
        file,
        info,
    } = root.open_file(&name("a.txt")).unwrap();
    drop(file);
    // The checked file moves aside, so the replacement cannot reuse its index.
    fs::rename(tree.root.join("a.txt"), tree.root.join("kept.txt")).unwrap();
    fs::write(tree.root.join("a.txt"), b"replacement").unwrap();
    let target = root.directory(Some(&name("d"))).unwrap();
    assert!(!fsutil::remove(&parent, &component, &info).unwrap());
    assert!(!fsutil::rename(&parent, &component, &info, &target, "moved.txt", false).unwrap());
    assert!(!fsutil::rename(&parent, &component, &info, &parent, "kept.txt", true).unwrap());
    assert_eq!(fs::read(tree.root.join("a.txt")).unwrap(), b"replacement");
    assert_eq!(fs::read(tree.root.join("kept.txt")).unwrap(), b"checked");
    assert!(names_in(&tree.root.join("d")).is_empty());
}

#[test]
fn removing_a_file_or_an_empty_directory_takes_exactly_that_entry() {
    let tree = tree();
    write(&tree.root, "d/a.txt", b"a");
    write(&tree.root, "d/b.txt", b"b");
    fs::create_dir(tree.root.join("d/empty")).unwrap();
    let root = open(&tree.root);
    root.remove_file(&name("d/a.txt")).unwrap();
    root.remove_directory(&name("d/empty")).unwrap();
    assert_eq!(names_in(&tree.root.join("d")), ["b.txt"]);
    // The removed names are free again at once.
    root.create_file(&name("d/a.txt"), b"again", false).unwrap();
    root.create_directory(&name("d/empty")).unwrap();
    assert_eq!(names_in(&tree.root.join("d")), ["a.txt", "b.txt", "empty"]);
    assert_eq!(fs::read(host(&tree.root, "d/a.txt")).unwrap(), b"again");
}

#[test]
fn a_created_directory_is_exclusive_and_case_aliases_collide_where_names_fold() {
    let tree = tree();
    fs::create_dir(tree.root.join("Out")).unwrap();
    write(&tree.root, "a.txt", b"a");
    let root = open(&tree.root);
    assert_eq!(
        io_kind(root.create_directory(&name("Out"))),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        io_kind(root.create_directory(&name("a.txt"))),
        ErrorKind::AlreadyExists
    );
    if cfg!(windows) {
        assert_eq!(
            io_kind(root.create_directory(&name("out"))),
            ErrorKind::AlreadyExists
        );
    }
    root.create_top_directory("top").unwrap();
    assert_eq!(
        root.create_top_directory("top").unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(names_in(&tree.root), ["Out", "a.txt", "top"]);
}

#[test]
fn an_opened_root_records_the_canonical_path_of_the_directory_it_opened() {
    let tree = tree();
    write(&tree.root, "d/x.txt", b"x");
    let root = open(&tree.root.join("d").join("..").join("d"));
    assert_eq!(
        root.origin(),
        fs::canonicalize(tree.root.join("d")).unwrap()
    );
    assert_eq!(root.identity(), open(&tree.root.join("d")).identity());
}

/// PROVES a streaming create lands under its name only whole and as expected: a source
/// shorter or longer than declared, or of other content than expected, leaves neither the
/// name nor the staging file, and a taken name is never replaced.
#[test]
fn a_streaming_create_lands_whole_or_not_at_all() {
    let tree = tree();
    let root = GrantedRoot::open(&tree.root).unwrap();
    let bytes = vec![5u8; 300 * 1024];
    let wanted = crate::foundation::ids::ContentKey::of(&bytes);
    // Shorter and longer than declared.
    for (declared, source) in [(bytes.len() as u64 + 1, &bytes[..]), (bytes.len() as u64 - 1, &bytes[..])] {
        let mut reader = source;
        let made = root.create_file_from(&name("streamed.bin"), &mut reader, declared, false, ".staging-a", None);
        assert!(matches!(made, Err(EntryProblem::Changed)), "{declared}: {made:?}");
        assert!(!tree.root.join("streamed.bin").exists() && !tree.root.join(".staging-a").exists());
    }
    // Other content than expected.
    let mut reader = &bytes[..];
    let other = crate::foundation::ids::ContentKey::of(b"other");
    assert!(matches!(root.create_file_from(&name("streamed.bin"), &mut reader, bytes.len() as u64, false, ".staging-b", Some(other)), Err(EntryProblem::Changed)));
    assert!(!tree.root.join("streamed.bin").exists() && !tree.root.join(".staging-b").exists());
    // Whole and as expected.
    let mut reader = &bytes[..];
    assert_eq!(root.create_file_from(&name("streamed.bin"), &mut reader, bytes.len() as u64, false, ".staging-c", Some(wanted)).unwrap(), wanted);
    assert_eq!(fs::read(tree.root.join("streamed.bin")).unwrap(), bytes);
    // A taken name is never replaced.
    let mut reader: &[u8] = b"new";
    assert!(matches!(root.create_file_from(&name("streamed.bin"), &mut reader, 3, false, ".staging-d", None), Err(EntryProblem::Io(error)) if error.kind() == ErrorKind::AlreadyExists));
    assert_eq!(fs::read(tree.root.join("streamed.bin")).unwrap(), bytes);
    assert!(!tree.root.join(".staging-d").exists());
}
