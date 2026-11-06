//! Untrusted guest names (VM part §5.1 lines 2047–2049; VM-P15).
//!
//! A guest path is an untrusted relative name, never a host path. [`GuestName::parse`] is
//! a first filter: it refuses traversal, absolute, drive, UNC and device paths, alternate
//! data streams, Windows reserved names, trailing dots and spaces, control and forbidden
//! characters, short-name aliases and overlong names. It is not protection against rename,
//! symlink or reparse-point races (line 2047): a name that passes can still meet a link
//! planted after the check. The real control is handle-relative resolution beneath the
//! opened root, refusing links and mount crossings at every component:
//! [`GrantedRoot`](super::GrantedRoot), with the results [`RootModel`](super::RootModel)
//! specifies. A name filter is not the protection for secrets either; the granted root and
//! operation set are (line 2049).
//!
//! Portable [`GuestName`] values remain ASCII and case-folded. [`ImageName`] is a
//! distinct type for Linux VM image contents: byte-exact UTF-8, case-sensitive,
//! with ordinary POSIX punctuation. It cannot be passed to a host file-service
//! method expecting GuestName. Both profiles reject traversal, controls and
//! backslashes and enforce the same component, depth and total byte bounds.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Portable host-file name; the file service accepts only this type.
pub type GuestName = RelativeName<false>;
/// Linux image-only name. It must never be materialized on the host filesystem.
pub type ImageName = RelativeName<true>;
pub type CollisionRefusal = NameCollision<false>;
pub type NameSet = RelativeNameSet<false>;

/// Longest accepted component, in bytes: NAME_MAX on Linux and the NTFS component limit.
pub const MAX_COMPONENT_BYTES: usize = 255;
/// Longest accepted name, in bytes, separators included.
pub const MAX_NAME_BYTES: usize = 1024;
/// Most components in one name.
pub const MAX_NAME_COMPONENTS: usize = 64;

/// Device names Windows resolves in every directory, with any extension. COM0, LPT0 and
/// CLOCK$ are included as the strict superset.
const RESERVED_STEMS: [&str; 27] = [
    "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$", "COM0", "COM1", "COM2", "COM3",
    "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
    "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Characters Windows refuses in names, including the wildcards.
const FORBIDDEN_CHARACTERS: [char; 6] = ['<', '>', '"', '|', '?', '*'];

/// Why a guest name was refused (VM part §5.1 line 2049).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum NameRefusal {
    Empty,
    NameTooLong {
        bytes: usize,
        limit: usize,
    },
    TooManyComponents {
        components: usize,
        limit: usize,
    },
    /// `\\?\`, `\\.\`, `\??\` and their forward-slash spellings.
    DevicePath,
    /// `\\server\share` or `//server/share`.
    UncPath,
    /// Starts with a separator.
    AbsolutePath,
    /// `C:`, `C:\` or the drive-relative `C:name`.
    DrivePath,
    NonAscii {
        byte_offset: usize,
    },
    ControlCharacter {
        byte_offset: usize,
        code: u32,
    },
    /// A backslash: guest names separate components with `/` only.
    Backslash {
        byte_offset: usize,
    },
    /// A colon after the first component's start: an NTFS alternate data stream.
    AlternateDataStream {
        byte_offset: usize,
    },
    ForbiddenCharacter {
        character: char,
    },
    /// `a//b` or a trailing `/`.
    EmptyComponent {
        index: usize,
    },
    /// `.` as a component.
    DotComponent {
        index: usize,
    },
    /// `..` as a component.
    Traversal {
        index: usize,
    },
    ComponentTooLong {
        index: usize,
        bytes: usize,
        limit: usize,
    },
    /// Windows strips a trailing dot or space, so the name would alias another.
    TrailingDotOrSpace {
        index: usize,
    },
    /// CON, NUL, COM1, LPT1 and the rest, with any extension.
    ReservedName {
        index: usize,
    },
    /// `~` followed by a digit, the 8.3 short-name form that can alias a long name.
    ShortNameAlias {
        index: usize,
    },
}

impl fmt::Display for NameRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the name is empty"),
            Self::NameTooLong { bytes, limit } => {
                write!(
                    f,
                    "the name has {bytes} bytes; at most {limit} are accepted"
                )
            }
            Self::TooManyComponents { components, limit } => write!(
                f,
                "the name has {components} components; at most {limit} are accepted"
            ),
            Self::DevicePath => f.write_str("device paths are refused"),
            Self::UncPath => f.write_str("network (UNC) paths are refused"),
            Self::AbsolutePath => f.write_str("absolute paths are refused; names are relative"),
            Self::DrivePath => f.write_str("drive paths are refused"),
            Self::NonAscii { byte_offset } => write!(
                f,
                "non-ASCII character at byte {byte_offset}; normalization cannot be checked"
            ),
            Self::ControlCharacter { byte_offset, code } => {
                write!(f, "control character {code:#04x} at byte {byte_offset}")
            }
            Self::Backslash { byte_offset } => {
                write!(
                    f,
                    "backslash at byte {byte_offset}; use '/' between components"
                )
            }
            Self::AlternateDataStream { byte_offset } => {
                write!(
                    f,
                    "colon at byte {byte_offset} names an alternate data stream"
                )
            }
            Self::ForbiddenCharacter { character } => {
                write!(f, "the character '{character}' is not allowed in names")
            }
            Self::EmptyComponent { index } => write!(f, "component {index} is empty"),
            Self::DotComponent { index } => write!(f, "component {index} is '.'"),
            Self::Traversal { index } => write!(f, "component {index} is '..'"),
            Self::ComponentTooLong {
                index,
                bytes,
                limit,
            } => write!(
                f,
                "component {index} has {bytes} bytes; at most {limit} are accepted"
            ),
            Self::TrailingDotOrSpace { index } => {
                write!(f, "component {index} ends with a dot or a space")
            }
            Self::ReservedName { index } => {
                write!(f, "component {index} is a reserved device name")
            }
            Self::ShortNameAlias { index } => {
                write!(f, "component {index} has the short-name form '~digit'")
            }
        }
    }
}

impl std::error::Error for NameRefusal {}

/// A bounded relative name. IMAGE selects the Linux-image namespace; the public
/// aliases keep that namespace distinct from portable host-file grants. A valid
/// name proves only lexical safety, never safe filesystem resolution.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelativeName<const IMAGE: bool> {
    text: String,
}

impl<const IMAGE: bool> RelativeName<IMAGE> {
    /// Checks `text` against every rule in this module.
    pub fn parse(text: &str) -> Result<Self, NameRefusal> {
        if text.is_empty() {
            return Err(NameRefusal::Empty);
        }
        if text.len() > MAX_NAME_BYTES {
            return Err(NameRefusal::NameTooLong {
                bytes: text.len(),
                limit: MAX_NAME_BYTES,
            });
        }
        if IMAGE {
            if text.starts_with('/') {
                return Err(NameRefusal::AbsolutePath);
            }
        } else {
            check_prefix(text)?;
        }
        for (byte_offset, character) in text.char_indices() {
            if !IMAGE && !character.is_ascii() {
                return Err(NameRefusal::NonAscii { byte_offset });
            }
            if character.is_control() {
                return Err(NameRefusal::ControlCharacter {
                    byte_offset,
                    code: u32::from(character),
                });
            }
            if character == '\\' {
                return Err(NameRefusal::Backslash { byte_offset });
            }
            if !IMAGE && character == ':' {
                return Err(NameRefusal::AlternateDataStream { byte_offset });
            }
            if !IMAGE && FORBIDDEN_CHARACTERS.contains(&character) {
                return Err(NameRefusal::ForbiddenCharacter { character });
            }
        }
        let components = text.split('/').count();
        if components > MAX_NAME_COMPONENTS {
            return Err(NameRefusal::TooManyComponents {
                components,
                limit: MAX_NAME_COMPONENTS,
            });
        }
        for (index, component) in text.split('/').enumerate() {
            check_component(index, component, IMAGE)?;
        }
        Ok(Self {
            text: text.to_owned(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The components, first to last.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.text.split('/')
    }

    pub fn component_count(&self) -> usize {
        self.components().count()
    }

    /// The last component.
    pub fn file_name(&self) -> &str {
        self.text.rsplit('/').next().unwrap_or(&self.text)
    }

    /// The name without its last component; `None` for a single component.
    pub fn parent(&self) -> Option<RelativeName<IMAGE>> {
        let split = self.text.rfind('/')?;
        self.text.get(..split).map(|text| Self {
            text: text.to_owned(),
        })
    }

    /// Every proper prefix, shortest first: `a`, `a/b` for `a/b/c`.
    pub fn ancestors(&self) -> Vec<RelativeName<IMAGE>> {
        self.text
            .match_indices('/')
            .filter_map(|(split, _)| self.text.get(..split))
            .map(|text| Self {
                text: text.to_owned(),
            })
            .collect()
    }

    /// Portable names use ASCII case folding; image names retain their exact bytes.
    pub fn folded(&self) -> String {
        if IMAGE {
            self.text.clone()
        } else {
            self.text.to_ascii_lowercase()
        }
    }

    /// Whether `prefix` is this name or one of its ancestors, comparing exact case.
    pub fn starts_with(&self, prefix: &RelativeName<IMAGE>) -> bool {
        self.text == prefix.text
            || (self.text.len() > prefix.text.len()
                && self.text.starts_with(prefix.text.as_str())
                && self.text.as_bytes().get(prefix.text.len()) == Some(&b'/'))
    }

    /// `self/child`, checked again as a whole.
    pub fn join(&self, child: &RelativeName<IMAGE>) -> Result<RelativeName<IMAGE>, NameRefusal> {
        Self::parse(&format!("{}/{}", self.text, child.text))
    }
}

impl<const IMAGE: bool> fmt::Debug for RelativeName<IMAGE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelativeName<IMAGE>({})", self.text)
    }
}

impl<const IMAGE: bool> fmt::Display for RelativeName<IMAGE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl<const IMAGE: bool> Serialize for RelativeName<IMAGE> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.text)
    }
}

impl<'de, const IMAGE: bool> Deserialize<'de> for RelativeName<IMAGE> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

fn check_prefix(text: &str) -> Result<(), NameRefusal> {
    let head: String = text
        .chars()
        .take(4)
        .map(|character| if character == '\\' { '/' } else { character })
        .collect();
    if head.starts_with("//?/") || head.starts_with("//./") || head.starts_with("/??/") {
        return Err(NameRefusal::DevicePath);
    }
    if head.starts_with("//") {
        return Err(NameRefusal::UncPath);
    }
    if head.starts_with('/') {
        return Err(NameRefusal::AbsolutePath);
    }
    let bytes = text.as_bytes();
    if matches!((bytes.first(), bytes.get(1)), (Some(letter), Some(b':')) if letter.is_ascii_alphabetic())
    {
        return Err(NameRefusal::DrivePath);
    }
    Ok(())
}

fn check_component(index: usize, component: &str, image: bool) -> Result<(), NameRefusal> {
    if component.is_empty() {
        return Err(NameRefusal::EmptyComponent { index });
    }
    if component == "." {
        return Err(NameRefusal::DotComponent { index });
    }
    if component == ".." {
        return Err(NameRefusal::Traversal { index });
    }
    if component.len() > MAX_COMPONENT_BYTES {
        return Err(NameRefusal::ComponentTooLong {
            index,
            bytes: component.len(),
            limit: MAX_COMPONENT_BYTES,
        });
    }
    if image {
        return Ok(());
    }
    if component.ends_with('.') || component.ends_with(' ') {
        return Err(NameRefusal::TrailingDotOrSpace { index });
    }
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    if RESERVED_STEMS.contains(&stem.as_str()) {
        return Err(NameRefusal::ReservedName { index });
    }
    let bytes = component.as_bytes();
    if bytes
        .windows(2)
        .any(|pair| pair[0] == b'~' && pair[1].is_ascii_digit())
    {
        return Err(NameRefusal::ShortNameAlias { index });
    }
    Ok(())
}

/// What a name in a [`RelativeNameSet<IMAGE>`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryRole {
    File,
    Directory,
}

/// Why a name cannot join a [`RelativeNameSet<IMAGE>`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum NameCollision<const IMAGE: bool> {
    /// The same name twice.
    Duplicate { name: RelativeName<IMAGE> },
    /// Two names that differ only in case within one directory (line 2049).
    CaseFold {
        existing: RelativeName<IMAGE>,
        name: RelativeName<IMAGE>,
    },
    /// A file is used as a directory by another name.
    ParentIsFile {
        parent: RelativeName<IMAGE>,
        name: RelativeName<IMAGE>,
    },
}

impl<const IMAGE: bool> fmt::Display for NameCollision<IMAGE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate { name } => write!(f, "{name} appears twice"),
            Self::CaseFold { existing, name } => {
                write!(f, "{name} differs from {existing} only in case")
            }
            Self::ParentIsFile { parent, name } => {
                write!(
                    f,
                    "{name} needs {parent} to be a directory, but it is a file"
                )
            }
        }
    }
}

impl<const IMAGE: bool> std::error::Error for NameCollision<IMAGE> {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recorded {
    File,
    Directory,
    /// A directory only implied by a longer name; an explicit directory entry may follow.
    Implied,
}

/// Names that will share one tree, checked so that no two collide under case folding,
/// none appears twice and no file is used as a directory (VM part §5.1 line 2049).
#[derive(Clone, Debug, Default)]
pub struct RelativeNameSet<const IMAGE: bool> {
    by_fold: BTreeMap<String, (RelativeName<IMAGE>, Recorded)>,
}

impl<const IMAGE: bool> RelativeNameSet<IMAGE> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `name` as `role`, or refuses it and changes nothing.
    pub fn insert(
        &mut self,
        name: &RelativeName<IMAGE>,
        role: EntryRole,
    ) -> Result<(), NameCollision<IMAGE>> {
        let ancestors = name.ancestors();
        for ancestor in &ancestors {
            if let Some((existing, recorded)) = self.by_fold.get(&ancestor.folded()) {
                if existing != ancestor {
                    return Err(NameCollision::<IMAGE>::CaseFold {
                        existing: existing.clone(),
                        name: ancestor.clone(),
                    });
                }
                if *recorded == Recorded::File {
                    return Err(NameCollision::<IMAGE>::ParentIsFile {
                        parent: ancestor.clone(),
                        name: name.clone(),
                    });
                }
            }
        }
        let upgraded = match self.by_fold.get(&name.folded()) {
            None => false,
            Some((existing, _)) if existing != name => {
                return Err(NameCollision::<IMAGE>::CaseFold {
                    existing: existing.clone(),
                    name: name.clone(),
                })
            }
            Some((_, Recorded::Implied)) if role == EntryRole::Directory => true,
            Some((_, Recorded::Implied)) => {
                return Err(NameCollision::<IMAGE>::ParentIsFile {
                    parent: name.clone(),
                    name: name.clone(),
                })
            }
            Some(_) => return Err(NameCollision::<IMAGE>::Duplicate { name: name.clone() }),
        };
        for ancestor in ancestors {
            self.by_fold
                .entry(ancestor.folded())
                .or_insert((ancestor, Recorded::Implied));
        }
        let recorded = match role {
            EntryRole::File => Recorded::File,
            EntryRole::Directory => Recorded::Directory,
        };
        if upgraded || !self.by_fold.contains_key(&name.folded()) {
            self.by_fold.insert(name.folded(), (name.clone(), recorded));
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.by_fold.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_fold.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> GuestName {
        GuestName::parse(text).unwrap()
    }

    fn refused(text: &str) -> NameRefusal {
        GuestName::parse(text).unwrap_err()
    }

    #[test]
    fn ordinary_relative_names_pass() {
        for text in [
            "a",
            "src/main.rs",
            "deep/er/still/file.tar.gz",
            ".gitignore",
            "con-tents/null.ok",
            "CONSOLE",
            "nul_file",
            "COM10",
            "Foo$Bar.class",
        ] {
            assert_eq!(name(text).as_str(), text);
        }
    }

    #[test]
    fn traversal_and_dot_components_are_refused() {
        assert_eq!(refused(".."), NameRefusal::Traversal { index: 0 });
        assert_eq!(refused("a/../b"), NameRefusal::Traversal { index: 1 });
        assert_eq!(refused("a/.."), NameRefusal::Traversal { index: 1 });
        assert_eq!(refused("."), NameRefusal::DotComponent { index: 0 });
        assert_eq!(refused("a/./b"), NameRefusal::DotComponent { index: 1 });
        assert_eq!(refused("a//b"), NameRefusal::EmptyComponent { index: 1 });
        assert_eq!(refused("a/"), NameRefusal::EmptyComponent { index: 1 });
        assert_eq!(refused(""), NameRefusal::Empty);
    }

    #[test]
    fn absolute_drive_unc_and_device_paths_are_refused() {
        assert_eq!(refused("/etc/passwd"), NameRefusal::AbsolutePath);
        assert_eq!(refused("\\Windows"), NameRefusal::AbsolutePath);
        assert_eq!(refused("C:"), NameRefusal::DrivePath);
        assert_eq!(refused("C:\\Users"), NameRefusal::DrivePath);
        assert_eq!(refused("c:/Users"), NameRefusal::DrivePath);
        assert_eq!(refused("D:relative"), NameRefusal::DrivePath);
        assert_eq!(refused("\\\\server\\share"), NameRefusal::UncPath);
        assert_eq!(refused("//server/share"), NameRefusal::UncPath);
        assert_eq!(refused("\\\\?\\C:\\x"), NameRefusal::DevicePath);
        assert_eq!(refused("\\\\.\\PhysicalDrive0"), NameRefusal::DevicePath);
        assert_eq!(refused("//?/C:/x"), NameRefusal::DevicePath);
        assert_eq!(refused("//./pipe/x"), NameRefusal::DevicePath);
        assert_eq!(refused("\\??\\C:\\x"), NameRefusal::DevicePath);
    }

    #[test]
    fn backslashes_streams_and_forbidden_characters_are_refused() {
        assert_eq!(refused("a\\b"), NameRefusal::Backslash { byte_offset: 1 });
        assert_eq!(
            refused("file.txt:secret"),
            NameRefusal::AlternateDataStream { byte_offset: 8 }
        );
        assert_eq!(
            refused("file::$DATA"),
            NameRefusal::AlternateDataStream { byte_offset: 4 }
        );
        assert_eq!(
            refused("dir/x:y"),
            NameRefusal::AlternateDataStream { byte_offset: 5 }
        );
        for character in FORBIDDEN_CHARACTERS {
            assert_eq!(
                refused(&format!("a{character}b")),
                NameRefusal::ForbiddenCharacter { character }
            );
        }
    }

    #[test]
    fn reserved_names_are_refused_with_any_extension_and_case() {
        for stem in RESERVED_STEMS {
            assert_eq!(refused(stem), NameRefusal::ReservedName { index: 0 });
            assert_eq!(
                refused(&format!("dir/{}.txt", stem.to_ascii_lowercase())),
                NameRefusal::ReservedName { index: 1 }
            );
            assert_eq!(
                refused(&format!("{stem}.tar.gz")),
                NameRefusal::ReservedName { index: 0 }
            );
        }
        assert_eq!(refused("NUL .txt"), NameRefusal::ReservedName { index: 0 });
        assert_eq!(refused("cOm1.log"), NameRefusal::ReservedName { index: 0 });
        assert_eq!(refused("lpt9"), NameRefusal::ReservedName { index: 0 });
    }

    #[test]
    fn trailing_dots_and_spaces_are_refused() {
        assert_eq!(
            refused("file."),
            NameRefusal::TrailingDotOrSpace { index: 0 }
        );
        assert_eq!(
            refused("file "),
            NameRefusal::TrailingDotOrSpace { index: 0 }
        );
        assert_eq!(
            refused("dir./x"),
            NameRefusal::TrailingDotOrSpace { index: 0 }
        );
        assert_eq!(
            refused("a/..."),
            NameRefusal::TrailingDotOrSpace { index: 1 }
        );
        assert_eq!(
            refused("nul."),
            NameRefusal::TrailingDotOrSpace { index: 0 }
        );
    }

    #[test]
    fn control_and_non_ascii_characters_are_refused() {
        assert_eq!(
            refused("a\u{0}b"),
            NameRefusal::ControlCharacter {
                byte_offset: 1,
                code: 0
            }
        );
        assert_eq!(
            refused("a\nb"),
            NameRefusal::ControlCharacter {
                byte_offset: 1,
                code: 10
            }
        );
        assert_eq!(
            refused("a\u{7f}"),
            NameRefusal::ControlCharacter {
                byte_offset: 1,
                code: 0x7f
            }
        );
        // Composed and decomposed spellings of one name; neither passes.
        assert_eq!(
            refused("caf\u{e9}"),
            NameRefusal::NonAscii { byte_offset: 3 }
        );
        assert_eq!(
            refused("cafe\u{301}"),
            NameRefusal::NonAscii { byte_offset: 4 }
        );
        // A superscript digit makes COM¹ a device name on Windows.
        assert_eq!(
            refused("COM\u{b9}"),
            NameRefusal::NonAscii { byte_offset: 3 }
        );
        // A full-width solidus is not a separator here, and is refused.
        assert_eq!(
            refused("a\u{ff0f}b"),
            NameRefusal::NonAscii { byte_offset: 1 }
        );
    }

    #[test]
    fn short_name_aliases_are_refused() {
        assert_eq!(
            refused("PROGRA~1"),
            NameRefusal::ShortNameAlias { index: 0 }
        );
        assert_eq!(
            refused("dir/BUILD~12.SH"),
            NameRefusal::ShortNameAlias { index: 1 }
        );
        assert_eq!(name("backup~").as_str(), "backup~");
    }

    #[test]
    fn overlong_components_and_names_are_refused() {
        let longest = "a".repeat(MAX_COMPONENT_BYTES);
        assert!(GuestName::parse(&longest).is_ok());
        assert_eq!(
            refused(&"a".repeat(MAX_COMPONENT_BYTES + 1)),
            NameRefusal::ComponentTooLong {
                index: 0,
                bytes: 256,
                limit: 255
            }
        );
        let long_name = vec!["b".repeat(200); 6].join("/");
        assert_eq!(long_name.len(), 1205);
        assert_eq!(
            refused(&long_name),
            NameRefusal::NameTooLong {
                bytes: 1205,
                limit: 1024
            }
        );
        let deep = vec!["d"; MAX_NAME_COMPONENTS + 1].join("/");
        assert_eq!(
            refused(&deep),
            NameRefusal::TooManyComponents {
                components: 65,
                limit: 64
            }
        );
        assert!(GuestName::parse(&vec!["d"; MAX_NAME_COMPONENTS].join("/")).is_ok());
    }

    #[test]
    fn prefixes_parents_and_ancestors_follow_components() {
        let deep = name("a/b/c.txt");
        assert_eq!(deep.file_name(), "c.txt");
        assert_eq!(deep.parent(), Some(name("a/b")));
        assert_eq!(deep.ancestors(), vec![name("a"), name("a/b")]);
        assert!(deep.starts_with(&name("a")));
        assert!(deep.starts_with(&name("a/b/c.txt")));
        assert!(!name("ab/c").starts_with(&name("a")));
        assert!(!deep.starts_with(&name("A")));
        assert_eq!(name("a").parent(), None);
        assert_eq!(deep.join(&name("d")).unwrap(), name("a/b/c.txt/d"));
        let wide = name(&"w".repeat(255));
        assert!(matches!(
            wide.join(&wide)
                .and_then(|twice| twice.join(&twice))
                .and_then(|four| four.join(&wide)),
            Err(NameRefusal::NameTooLong { .. })
        ));
    }

    #[test]
    fn names_deserialize_only_through_the_filter() {
        let parsed: GuestName = serde_json::from_str("\"src/lib.rs\"").unwrap();
        assert_eq!(parsed, name("src/lib.rs"));
        assert!(serde_json::from_str::<GuestName>("\"../etc\"").is_err());
        assert!(serde_json::from_str::<GuestName>("\"C:\\\\x\"").is_err());
        assert_eq!(serde_json::to_string(&parsed).unwrap(), "\"src/lib.rs\"");
    }

    #[test]
    fn case_fold_collisions_within_a_directory_are_refused() {
        let mut set = NameSet::new();
        set.insert(&name("src/Main.rs"), EntryRole::File).unwrap();
        assert_eq!(
            set.insert(&name("src/main.rs"), EntryRole::File),
            Err(CollisionRefusal::CaseFold {
                existing: name("src/Main.rs"),
                name: name("src/main.rs")
            })
        );
        assert_eq!(
            set.insert(&name("SRC/other.rs"), EntryRole::File),
            Err(CollisionRefusal::CaseFold {
                existing: name("src"),
                name: name("SRC")
            })
        );
        // The same file name in another directory is no collision.
        set.insert(&name("lib/main.rs"), EntryRole::File).unwrap();
        assert_eq!(
            set.insert(&name("lib/main.rs"), EntryRole::File),
            Err(CollisionRefusal::Duplicate {
                name: name("lib/main.rs")
            })
        );
    }

    #[test]
    fn a_file_cannot_also_be_a_directory() {
        let mut set = NameSet::new();
        set.insert(&name("a"), EntryRole::File).unwrap();
        assert_eq!(
            set.insert(&name("a/b"), EntryRole::File),
            Err(CollisionRefusal::ParentIsFile {
                parent: name("a"),
                name: name("a/b")
            })
        );
        let mut later = NameSet::new();
        later.insert(&name("x/y"), EntryRole::File).unwrap();
        assert_eq!(
            later.insert(&name("x"), EntryRole::File),
            Err(CollisionRefusal::ParentIsFile {
                parent: name("x"),
                name: name("x")
            })
        );
        // An explicit directory entry after its children is fine, but only once.
        later.insert(&name("x"), EntryRole::Directory).unwrap();
        assert_eq!(
            later.insert(&name("x"), EntryRole::Directory),
            Err(CollisionRefusal::Duplicate { name: name("x") })
        );
        // A refused insert changes nothing.
        let before = later.len();
        assert!(later.insert(&name("X/z"), EntryRole::File).is_err());
        assert_eq!(later.len(), before);
    }
}
