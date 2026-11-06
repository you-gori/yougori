//! Archive-entry checks for imports (VM part §5.2 line 2073; VM-P37).
//!
//! The input is a typed entry list as a constrained parser would report it, never archive
//! bytes: the host parses nothing here. The checks refuse unsafe names, links whose
//! target escapes the root, links reached through or pointing at another link, device
//! entries, duplicate and case-fold-colliding entries, and decompression past its bounds:
//! entry count, per-entry and total uncompressed size, and the expansion ratio of each
//! entry, which bounds the whole archive's ratio as well. Declared sizes are claims, so [`ExtractionMeter`] holds the
//! extraction to them as bytes are produced. The host never mounts a guest-produced
//! filesystem image to inspect it, and complex parsing runs in a constrained helper or a
//! separate VM ([`check_inspection`]).

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

#[cfg(test)]
use super::names::{CollisionRefusal, GuestName};
use super::names::{EntryRole, NameCollision, NameRefusal, RelativeName, RelativeNameSet};
pub type ArchiveRefusal = ArchiveCheckRefusal<false>;
pub type ImageArchiveRefusal = ArchiveCheckRefusal<true>;
pub type CheckedArchive = CheckedArchiveFor<false>;

/// One archive entry's type and declared sizes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArchiveEntryKind {
    File {
        uncompressed_bytes: u64,
        compressed_bytes: u64,
    },
    Directory,
    Symlink {
        target: String,
    },
    HardLink {
        target: String,
    },
    CharacterDevice,
    BlockDevice,
    Fifo,
    Socket,
}

/// One entry as the parser reports it; `name` is untrusted text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ArchiveEntry {
    pub name: String,
    pub kind: ArchiveEntryKind,
}

/// Decompression bounds (VM-P37: archive bombs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ArchiveLimits {
    pub max_entries: usize,
    pub max_entry_uncompressed_bytes: u64,
    pub max_total_uncompressed_bytes: u64,
    /// Largest accepted uncompressed-to-compressed ratio of each entry, which bounds the
    /// whole archive's ratio too.
    pub max_ratio: u64,
}

/// Why an archive was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum ArchiveCheckRefusal<const IMAGE: bool> {
    TooManyEntries {
        entries: usize,
        limit: usize,
    },
    UnsafeName {
        index: usize,
        refusal: NameRefusal,
    },
    Collision {
        index: usize,
        refusal: NameCollision<IMAGE>,
    },
    /// The link target is absolute, a drive, UNC or device path, or climbs above the
    /// root.
    EscapingLink {
        index: usize,
        name: RelativeName<IMAGE>,
    },
    UnsafeLinkTarget {
        index: usize,
        name: RelativeName<IMAGE>,
        refusal: NameRefusal,
    },
    /// An entry lies beneath a link, or a link's target passes through or names another
    /// link.
    ThroughLink {
        index: usize,
        name: RelativeName<IMAGE>,
    },
    /// A hard link must name an earlier regular file entry.
    HardLinkTarget {
        index: usize,
        name: RelativeName<IMAGE>,
    },
    DeviceEntry {
        index: usize,
        name: RelativeName<IMAGE>,
    },
    EntryTooLarge {
        index: usize,
        uncompressed_bytes: u64,
        limit: u64,
    },
    TotalTooLarge {
        total_uncompressed_bytes: u64,
        limit: u64,
    },
    RatioExceeded {
        index: usize,
        uncompressed_bytes: u64,
        compressed_bytes: u64,
        max_ratio: u64,
    },
    /// Extraction produced more bytes than the entry declared.
    ExtractionExceededDeclared {
        index: usize,
        declared_bytes: u64,
        produced_bytes: u64,
    },
    /// Extraction ended an entry short of its declared size.
    ExtractionShortOfDeclared {
        index: usize,
        declared_bytes: u64,
        produced_bytes: u64,
    },
    /// Bytes for an entry that is not a regular file of the checked list.
    ExtractionUnknownEntry {
        index: usize,
    },
}

impl<const IMAGE: bool> fmt::Display for ArchiveCheckRefusal<IMAGE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyEntries { entries, limit } => {
                write!(f, "{entries} entries; at most {limit}")
            }
            Self::UnsafeName { index, refusal } => write!(f, "entry {index}: {refusal}"),
            Self::Collision { index, refusal } => write!(f, "entry {index}: {refusal}"),
            Self::EscapingLink { index, name } => {
                write!(f, "entry {index} ({name}) links outside the root")
            }
            Self::UnsafeLinkTarget {
                index,
                name,
                refusal,
            } => write!(
                f,
                "entry {index} ({name}) links to an unsafe name: {refusal}"
            ),
            Self::ThroughLink { index, name } => {
                write!(f, "entry {index} ({name}) passes through another link")
            }
            Self::HardLinkTarget { index, name } => write!(
                f,
                "entry {index} ({name}) hard-links to something other than an earlier file"
            ),
            Self::DeviceEntry { index, name } => write!(f, "entry {index} ({name}) is a device"),
            Self::EntryTooLarge {
                index,
                uncompressed_bytes,
                limit,
            } => write!(
                f,
                "entry {index} expands to {uncompressed_bytes} bytes; at most {limit}"
            ),
            Self::TotalTooLarge {
                total_uncompressed_bytes,
                limit,
            } => write!(
                f,
                "the archive expands to {total_uncompressed_bytes} bytes; at most {limit}"
            ),
            Self::RatioExceeded {
                index,
                uncompressed_bytes,
                compressed_bytes,
                max_ratio,
            } => write!(
                f,
                "entry {index} expands {compressed_bytes} bytes to {uncompressed_bytes}, \
                 beyond {max_ratio}x"
            ),
            Self::ExtractionExceededDeclared {
                index,
                declared_bytes,
                produced_bytes,
            } => write!(
                f,
                "entry {index} produced {produced_bytes} bytes but declared {declared_bytes}"
            ),
            Self::ExtractionShortOfDeclared {
                index,
                declared_bytes,
                produced_bytes,
            } => write!(
                f,
                "entry {index} ended at {produced_bytes} bytes but declared {declared_bytes}"
            ),
            Self::ExtractionUnknownEntry { index } => {
                write!(f, "entry {index} is not a checked regular file")
            }
        }
    }
}

impl<const IMAGE: bool> std::error::Error for ArchiveCheckRefusal<IMAGE> {}

/// An entry list that passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedArchiveFor<const IMAGE: bool> {
    names: Vec<RelativeName<IMAGE>>,
    declared_bytes: Vec<Option<u64>>,
    total_uncompressed_bytes: u64,
    total_compressed_bytes: u64,
}

impl<const IMAGE: bool> CheckedArchiveFor<IMAGE> {
    /// The validated names, in entry order.
    pub fn names(&self) -> &[RelativeName<IMAGE>] {
        &self.names
    }

    pub fn total_uncompressed_bytes(&self) -> u64 {
        self.total_uncompressed_bytes
    }

    pub fn total_compressed_bytes(&self) -> u64 {
        self.total_compressed_bytes
    }
}

/// Whether `uncompressed` exceeds `max_ratio` times `compressed`; any expansion of zero
/// compressed bytes does.
fn ratio_exceeded(uncompressed: u64, compressed: u64, max_ratio: u64) -> bool {
    uncompressed > 0 && u128::from(uncompressed) > u128::from(compressed) * u128::from(max_ratio)
}

fn is_link_target_absolute<const IMAGE: bool>(target: &str) -> bool {
    let bytes = target.as_bytes();
    target.starts_with('/')
        || target.contains('\\')
        || (!IMAGE
            && matches!((bytes.first(), bytes.get(1)), (Some(letter), Some(b':')) if letter.is_ascii_alphabetic()))
}

/// The components a link's target names, resolved lexically from the link's directory, or
/// `None` when it climbs above the root. `.` components are skipped.
fn link_walk<const IMAGE: bool>(link: &RelativeName<IMAGE>, target: &str) -> Option<Vec<String>> {
    let mut stack: Vec<String> = link
        .parent()
        .map(|parent| parent.components().map(str::to_owned).collect())
        .unwrap_or_default();
    for component in target.split('/') {
        match component {
            "." => {}
            ".." => {
                stack.pop()?;
            }
            other => stack.push(other.to_owned()),
        }
    }
    Some(stack)
}

/// Portable host-file archive checks; image validation cannot create this type.
pub fn check_archive(
    entries: &[ArchiveEntry],
    limits: &ArchiveLimits,
) -> Result<CheckedArchive, ArchiveRefusal> {
    check_archive_for::<false>(entries, limits)
}

/// Checks entries in the selected namespace; no filesystem effects.

pub(crate) fn check_archive_for<const IMAGE: bool>(
    entries: &[ArchiveEntry],
    limits: &ArchiveLimits,
) -> Result<CheckedArchiveFor<IMAGE>, ArchiveCheckRefusal<IMAGE>> {
    if entries.len() > limits.max_entries {
        return Err(ArchiveCheckRefusal::<IMAGE>::TooManyEntries {
            entries: entries.len(),
            limit: limits.max_entries,
        });
    }
    let mut set = RelativeNameSet::<IMAGE>::new();
    let mut names = Vec::with_capacity(entries.len());
    let mut declared_bytes = Vec::with_capacity(entries.len());
    let mut symlinks = BTreeSet::new();
    let mut regular_files = BTreeSet::new();
    let mut total_uncompressed_bytes = 0u64;
    let mut total_compressed_bytes = 0u64;
    for (index, entry) in entries.iter().enumerate() {
        let raw = match entry.kind {
            ArchiveEntryKind::Directory => entry.name.strip_suffix('/').unwrap_or(&entry.name),
            _ => entry.name.as_str(),
        };
        let name =
            RelativeName::<IMAGE>::parse(raw)
                .map_err(|refusal| ArchiveCheckRefusal::<IMAGE>::UnsafeName { index, refusal })?;
        let role = match entry.kind {
            ArchiveEntryKind::Directory => EntryRole::Directory,
            _ => EntryRole::File,
        };
        set.insert(&name, role)
            .map_err(|refusal| ArchiveCheckRefusal::<IMAGE>::Collision { index, refusal })?;
        let mut declared = None;
        match &entry.kind {
            ArchiveEntryKind::CharacterDevice
            | ArchiveEntryKind::BlockDevice
            | ArchiveEntryKind::Fifo
            | ArchiveEntryKind::Socket => {
                return Err(ArchiveCheckRefusal::<IMAGE>::DeviceEntry { index, name })
            }
            ArchiveEntryKind::File {
                uncompressed_bytes,
                compressed_bytes,
            } => {
                if *uncompressed_bytes > limits.max_entry_uncompressed_bytes {
                    return Err(ArchiveCheckRefusal::<IMAGE>::EntryTooLarge {
                        index,
                        uncompressed_bytes: *uncompressed_bytes,
                        limit: limits.max_entry_uncompressed_bytes,
                    });
                }
                if ratio_exceeded(*uncompressed_bytes, *compressed_bytes, limits.max_ratio) {
                    return Err(ArchiveCheckRefusal::<IMAGE>::RatioExceeded {
                        index,
                        uncompressed_bytes: *uncompressed_bytes,
                        compressed_bytes: *compressed_bytes,
                        max_ratio: limits.max_ratio,
                    });
                }
                total_uncompressed_bytes =
                    total_uncompressed_bytes.saturating_add(*uncompressed_bytes);
                total_compressed_bytes = total_compressed_bytes.saturating_add(*compressed_bytes);
                if total_uncompressed_bytes > limits.max_total_uncompressed_bytes {
                    return Err(ArchiveCheckRefusal::<IMAGE>::TotalTooLarge {
                        total_uncompressed_bytes,
                        limit: limits.max_total_uncompressed_bytes,
                    });
                }
                regular_files.insert(name.folded());
                declared = Some(*uncompressed_bytes);
            }
            ArchiveEntryKind::Symlink { target } => {
                if is_link_target_absolute::<IMAGE>(target) {
                    return Err(ArchiveCheckRefusal::<IMAGE>::EscapingLink { index, name });
                }
                let Some(resolved) = link_walk(&name, target) else {
                    return Err(ArchiveCheckRefusal::<IMAGE>::EscapingLink { index, name });
                };
                if let Err(refusal) = RelativeName::<IMAGE>::parse(&resolved.join("/")) {
                    return Err(ArchiveCheckRefusal::<IMAGE>::UnsafeLinkTarget {
                        index,
                        name,
                        refusal,
                    });
                }
                symlinks.insert(name.folded());
            }
            ArchiveEntryKind::HardLink { target } => {
                let earlier_file = RelativeName::<IMAGE>::parse(target)
                    .map(|target| regular_files.contains(&target.folded()))
                    .unwrap_or(false);
                if !earlier_file {
                    return Err(ArchiveCheckRefusal::<IMAGE>::HardLinkTarget { index, name });
                }
            }
            ArchiveEntryKind::Directory => {}
        }
        names.push(name);
        declared_bytes.push(declared);
    }
    for (index, (entry, name)) in entries.iter().zip(&names).enumerate() {
        if name
            .ancestors()
            .iter()
            .any(|ancestor| symlinks.contains(&ancestor.folded()))
        {
            return Err(ArchiveCheckRefusal::<IMAGE>::ThroughLink {
                index,
                name: name.clone(),
            });
        }
        if let ArchiveEntryKind::Symlink { target } = &entry.kind {
            let mut walked = name
                .parent()
                .map(|parent| parent.components().map(str::to_owned).collect::<Vec<_>>())
                .unwrap_or_default();
            for component in target.split('/') {
                match component {
                    "." => continue,
                    ".." => {
                        walked.pop();
                        continue;
                    }
                    other => walked.push(other.to_owned()),
                }
                if symlinks.contains(
                    &RelativeName::<IMAGE>::parse(&walked.join("/"))
                        .map(|n| n.folded())
                        .unwrap_or_default(),
                ) {
                    return Err(ArchiveCheckRefusal::<IMAGE>::ThroughLink {
                        index,
                        name: name.clone(),
                    });
                }
            }
        }
    }
    Ok(CheckedArchiveFor {
        names,
        declared_bytes,
        total_uncompressed_bytes,
        total_compressed_bytes,
    })
}

/// Holds an extraction to the checked declarations as bytes are produced: no entry past
/// its declared size or short of it, and no total past the limit.
#[derive(Clone, Debug)]
pub struct ExtractionMeter {
    declared_bytes: Vec<Option<u64>>,
    produced_bytes: Vec<u64>,
    total_produced_bytes: u64,
    max_total_uncompressed_bytes: u64,
}

impl ExtractionMeter {
    pub fn new(checked: &CheckedArchive, limits: &ArchiveLimits) -> Self {
        Self {
            declared_bytes: checked.declared_bytes.clone(),
            produced_bytes: vec![0; checked.declared_bytes.len()],
            total_produced_bytes: 0,
            max_total_uncompressed_bytes: limits.max_total_uncompressed_bytes,
        }
    }

    /// `bytes` more were produced for entry `index`.
    pub fn produced(&mut self, index: usize, bytes: u64) -> Result<(), ArchiveRefusal> {
        let (Some(Some(declared)), Some(produced)) = (
            self.declared_bytes.get(index).copied(),
            self.produced_bytes.get_mut(index),
        ) else {
            return Err(ArchiveRefusal::ExtractionUnknownEntry { index });
        };
        let next = produced.saturating_add(bytes);
        if next > declared {
            return Err(ArchiveRefusal::ExtractionExceededDeclared {
                index,
                declared_bytes: declared,
                produced_bytes: next,
            });
        }
        let total = self.total_produced_bytes.saturating_add(bytes);
        if total > self.max_total_uncompressed_bytes {
            return Err(ArchiveRefusal::TotalTooLarge {
                total_uncompressed_bytes: total,
                limit: self.max_total_uncompressed_bytes,
            });
        }
        *produced = next;
        self.total_produced_bytes = total;
        Ok(())
    }

    /// Entry `index` ended; it must have produced exactly its declared size.
    pub fn finish_entry(&self, index: usize) -> Result<(), ArchiveRefusal> {
        let (Some(Some(declared)), Some(produced)) = (
            self.declared_bytes.get(index).copied(),
            self.produced_bytes.get(index).copied(),
        ) else {
            return Err(ArchiveRefusal::ExtractionUnknownEntry { index });
        };
        if produced != declared {
            return Err(ArchiveRefusal::ExtractionShortOfDeclared {
                index,
                declared_bytes: declared,
                produced_bytes: produced,
            });
        }
        Ok(())
    }
}

/// Who produced an artifact being imported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactOrigin {
    GuestProduced,
    /// The writable importer of §5.3, separate from consumers.
    TrustedImporter,
}

/// How an import's contents would be inspected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionMethod {
    /// Mounting the image on the host.
    HostMount,
    /// Parsing archive or image bytes inside a host process.
    HostProcessParser,
    ConstrainedHelper,
    SeparateVm,
}

/// What is being imported and how its contents would be inspected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ImportInspection {
    pub origin: ArtifactOrigin,
    pub filesystem_image: bool,
    pub method: InspectionMethod,
}

/// Why an inspection plan was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum InspectionRefusal {
    /// The host does not mount a filesystem image to inspect it (line 2073).
    HostMount { origin: ArtifactOrigin },
    /// Complex parsing runs in a constrained helper or VM, not the host (line 2073).
    HostParsing { origin: ArtifactOrigin },
}

impl fmt::Display for InspectionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostMount { .. } => f.write_str("the host never mounts an image to inspect it"),
            Self::HostParsing { .. } => {
                f.write_str("archive and image parsing runs in a constrained helper or VM")
            }
        }
    }
}

impl std::error::Error for InspectionRefusal {}

/// Accepts only a constrained helper or a separate VM for inspecting an import (§5.2
/// line 2073). Host mounting is refused for every image, the strict reading of "the host
/// should not mount a guest-produced filesystem image"; parsing in a host process is
/// refused for every origin.
pub fn check_inspection(inspection: &ImportInspection) -> Result<(), InspectionRefusal> {
    match inspection.method {
        InspectionMethod::HostMount => Err(InspectionRefusal::HostMount {
            origin: inspection.origin,
        }),
        InspectionMethod::HostProcessParser => Err(InspectionRefusal::HostParsing {
            origin: inspection.origin,
        }),
        InspectionMethod::ConstrainedHelper | InspectionMethod::SeparateVm => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    fn limits() -> ArchiveLimits {
        ArchiveLimits {
            max_entries: 8,
            max_entry_uncompressed_bytes: 64 * MIB,
            max_total_uncompressed_bytes: 100 * MIB,
            max_ratio: 100,
        }
    }

    fn file(name: &str, uncompressed_bytes: u64, compressed_bytes: u64) -> ArchiveEntry {
        ArchiveEntry {
            name: name.into(),
            kind: ArchiveEntryKind::File {
                uncompressed_bytes,
                compressed_bytes,
            },
        }
    }

    fn entry(name: &str, kind: ArchiveEntryKind) -> ArchiveEntry {
        ArchiveEntry {
            name: name.into(),
            kind,
        }
    }

    fn symlink(name: &str, target: &str) -> ArchiveEntry {
        entry(
            name,
            ArchiveEntryKind::Symlink {
                target: target.into(),
            },
        )
    }

    fn guest(text: &str) -> GuestName {
        GuestName::parse(text).unwrap()
    }

    #[test]
    fn an_ordinary_archive_passes() {
        let checked = check_archive(
            &[
                entry("src/", ArchiveEntryKind::Directory),
                file("src/main.rs", 4_000, 1_000),
                file("README.md", 2_000, 900),
                symlink("src/current", "main.rs"),
                entry(
                    "copy.md",
                    ArchiveEntryKind::HardLink {
                        target: "README.md".into(),
                    },
                ),
            ],
            &limits(),
        )
        .unwrap();
        assert_eq!(checked.names().len(), 5);
        assert_eq!(checked.total_uncompressed_bytes(), 6_000);
        assert_eq!(checked.total_compressed_bytes(), 1_900);
    }

    #[test]
    fn unsafe_entry_names_are_refused() {
        for (text, refusal) in [
            ("../evil", NameRefusal::Traversal { index: 0 }),
            ("/etc/passwd", NameRefusal::AbsolutePath),
            ("C:\\Windows\\x.dll", NameRefusal::DrivePath),
            ("a/nul.txt", NameRefusal::ReservedName { index: 1 }),
            (
                "a/b:stream",
                NameRefusal::AlternateDataStream { byte_offset: 3 },
            ),
        ] {
            assert_eq!(
                check_archive(&[file(text, 1, 1)], &limits()),
                Err(ArchiveRefusal::UnsafeName { index: 0, refusal })
            );
        }
    }

    #[test]
    fn duplicate_and_case_folded_entries_are_refused() {
        assert_eq!(
            check_archive(&[file("a.txt", 1, 1), file("a.txt", 1, 1)], &limits()),
            Err(ArchiveRefusal::Collision {
                index: 1,
                refusal: CollisionRefusal::Duplicate {
                    name: guest("a.txt")
                }
            })
        );
        assert_eq!(
            check_archive(
                &[file("Doc/a.txt", 1, 1), file("doc/b.txt", 1, 1)],
                &limits()
            ),
            Err(ArchiveRefusal::Collision {
                index: 1,
                refusal: CollisionRefusal::CaseFold {
                    existing: guest("Doc"),
                    name: guest("doc")
                }
            })
        );
        assert_eq!(
            check_archive(
                &[
                    entry("d/", ArchiveEntryKind::Directory),
                    entry("d/", ArchiveEntryKind::Directory)
                ],
                &limits()
            ),
            Err(ArchiveRefusal::Collision {
                index: 1,
                refusal: CollisionRefusal::Duplicate { name: guest("d") }
            })
        );
    }

    #[test]
    fn links_escaping_the_root_are_refused() {
        for target in [
            "../outside",
            "a/../../outside",
            "/etc/passwd",
            "C:/Windows",
            "..\\x",
            "\\\\server\\share",
        ] {
            assert_eq!(
                check_archive(&[symlink("link", target)], &limits()),
                Err(ArchiveRefusal::EscapingLink {
                    index: 0,
                    name: guest("link")
                }),
                "{target}"
            );
        }
        // Climbing within the root is lexical only and stays inside.
        assert!(check_archive(&[symlink("a/b/link", "../c")], &limits()).is_ok());
        assert_eq!(
            check_archive(&[symlink("a/link", "../..")], &limits()),
            Err(ArchiveRefusal::EscapingLink {
                index: 0,
                name: guest("a/link")
            })
        );
        assert_eq!(
            check_archive(&[symlink("a/link", "..")], &limits()),
            Err(ArchiveRefusal::UnsafeLinkTarget {
                index: 0,
                name: guest("a/link"),
                refusal: NameRefusal::Empty
            })
        );
        assert_eq!(
            check_archive(&[symlink("link", "CON")], &limits()),
            Err(ArchiveRefusal::UnsafeLinkTarget {
                index: 0,
                name: guest("link"),
                refusal: NameRefusal::ReservedName { index: 0 }
            })
        );
    }

    #[test]
    fn entries_beneath_links_and_link_chains_are_refused() {
        // The classic escape: a link to the parent, then a file written through it.
        assert_eq!(
            check_archive(&[symlink("up", "x"), file("up/passwd", 1, 1)], &limits()),
            Err(ArchiveRefusal::Collision {
                index: 1,
                refusal: CollisionRefusal::ParentIsFile {
                    parent: guest("up"),
                    name: guest("up/passwd")
                }
            })
        );
        assert_eq!(
            check_archive(&[symlink("a", "b"), symlink("b", "c")], &limits()),
            Err(ArchiveRefusal::ThroughLink {
                index: 0,
                name: guest("a")
            })
        );
        assert_eq!(
            check_archive(
                &[symlink("s", "deep/dir"), symlink("t", "s/../ok")],
                &limits()
            ),
            Err(ArchiveRefusal::ThroughLink {
                index: 1,
                name: guest("t")
            })
        );
    }

    #[test]
    fn hard_links_must_name_an_earlier_regular_file() {
        let hard = |target: &str| {
            entry(
                "h",
                ArchiveEntryKind::HardLink {
                    target: target.into(),
                },
            )
        };
        for target in ["../../etc/shadow", "/etc/shadow", "later.txt", "dir"] {
            assert_eq!(
                check_archive(
                    &[
                        entry("dir/", ArchiveEntryKind::Directory),
                        hard(target),
                        file("later.txt", 1, 1)
                    ],
                    &limits()
                ),
                Err(ArchiveRefusal::HardLinkTarget {
                    index: 1,
                    name: guest("h")
                }),
                "{target}"
            );
        }
    }

    #[test]
    fn device_entries_are_refused() {
        for kind in [
            ArchiveEntryKind::CharacterDevice,
            ArchiveEntryKind::BlockDevice,
            ArchiveEntryKind::Fifo,
            ArchiveEntryKind::Socket,
        ] {
            assert_eq!(
                check_archive(&[entry("dev/sda", kind)], &limits()),
                Err(ArchiveRefusal::DeviceEntry {
                    index: 0,
                    name: guest("dev/sda")
                })
            );
        }
    }

    #[test]
    fn archive_bombs_are_refused_by_count_size_and_ratio() {
        let many: Vec<ArchiveEntry> = (0..9).map(|i| file(&format!("f{i}"), 1, 1)).collect();
        assert_eq!(
            check_archive(&many, &limits()),
            Err(ArchiveRefusal::TooManyEntries {
                entries: 9,
                limit: 8
            })
        );
        assert_eq!(
            check_archive(&[file("big", 64 * MIB + 1, 64 * MIB)], &limits()),
            Err(ArchiveRefusal::EntryTooLarge {
                index: 0,
                uncompressed_bytes: 64 * MIB + 1,
                limit: 64 * MIB
            })
        );
        // 50 MiB + 50 MiB is the limit exactly; one more byte is refused.
        assert!(check_archive(
            &[file("a", 50 * MIB, MIB), file("b", 50 * MIB, MIB)],
            &limits()
        )
        .is_ok());
        assert_eq!(
            check_archive(
                &[file("a", 50 * MIB, MIB), file("b", 50 * MIB + 1, MIB)],
                &limits()
            ),
            Err(ArchiveRefusal::TotalTooLarge {
                total_uncompressed_bytes: 100 * MIB + 1,
                limit: 100 * MIB
            })
        );
        // A 42 KB zip of 4.5 PB is the classic bomb; here 10 KiB expanding to 1,000 KiB is
        // exactly 100x and passes, and one more byte is refused.
        assert!(check_archive(&[file("r", 1_024_000, 10_240)], &limits()).is_ok());
        assert_eq!(
            check_archive(&[file("r", 1_024_001, 10_240)], &limits()),
            Err(ArchiveRefusal::RatioExceeded {
                index: 0,
                uncompressed_bytes: 1_024_001,
                compressed_bytes: 10_240,
                max_ratio: 100
            })
        );
        assert!(matches!(
            check_archive(&[file("zero", 1, 0)], &limits()),
            Err(ArchiveRefusal::RatioExceeded { .. })
        ));
        assert!(check_archive(&[file("empty", 0, 0)], &limits()).is_ok());
    }

    #[test]
    fn per_entry_ratios_bound_the_whole_archive() {
        let tight = ArchiveLimits {
            max_ratio: 10,
            ..limits()
        };
        // 1,000 / 100 is exactly 10x and passes; 1,000 / 90 is refused.
        assert_eq!(
            check_archive(&[file("a", 1_000, 100), file("b", 1_000, 90)], &tight),
            Err(ArchiveRefusal::RatioExceeded {
                index: 1,
                uncompressed_bytes: 1_000,
                compressed_bytes: 90,
                max_ratio: 10
            })
        );
        let checked = check_archive(
            &[file("a", 1_000, 100), file("b", 500, 50), file("c", 0, 7)],
            &tight,
        )
        .unwrap();
        assert!(
            u128::from(checked.total_uncompressed_bytes())
                <= u128::from(checked.total_compressed_bytes()) * 10
        );
    }

    #[test]
    fn extraction_is_held_to_the_declared_sizes() {
        let checked = check_archive(
            &[
                file("a", 100, 10),
                entry("d/", ArchiveEntryKind::Directory),
                file("b", 50, 5),
            ],
            &limits(),
        )
        .unwrap();
        let mut meter = ExtractionMeter::new(&checked, &limits());
        meter.produced(0, 60).unwrap();
        meter.produced(0, 40).unwrap();
        meter.finish_entry(0).unwrap();
        // The header said 50 bytes; the stream keeps going.
        meter.produced(2, 50).unwrap();
        assert_eq!(
            meter.produced(2, 1),
            Err(ArchiveRefusal::ExtractionExceededDeclared {
                index: 2,
                declared_bytes: 50,
                produced_bytes: 51
            })
        );
        assert_eq!(
            meter.produced(1, 1),
            Err(ArchiveRefusal::ExtractionUnknownEntry { index: 1 })
        );
        assert_eq!(
            meter.produced(7, 1),
            Err(ArchiveRefusal::ExtractionUnknownEntry { index: 7 })
        );
        let mut short = ExtractionMeter::new(&checked, &limits());
        short.produced(0, 99).unwrap();
        assert_eq!(
            short.finish_entry(0),
            Err(ArchiveRefusal::ExtractionShortOfDeclared {
                index: 0,
                declared_bytes: 100,
                produced_bytes: 99
            })
        );
    }

    #[test]
    fn the_host_never_mounts_or_parses_an_import_itself() {
        for origin in [
            ArtifactOrigin::GuestProduced,
            ArtifactOrigin::TrustedImporter,
        ] {
            assert_eq!(
                check_inspection(&ImportInspection {
                    origin,
                    filesystem_image: true,
                    method: InspectionMethod::HostMount
                }),
                Err(InspectionRefusal::HostMount { origin })
            );
            assert_eq!(
                check_inspection(&ImportInspection {
                    origin,
                    filesystem_image: false,
                    method: InspectionMethod::HostProcessParser
                }),
                Err(InspectionRefusal::HostParsing { origin })
            );
            for method in [
                InspectionMethod::ConstrainedHelper,
                InspectionMethod::SeparateVm,
            ] {
                assert_eq!(
                    check_inspection(&ImportInspection {
                        origin,
                        filesystem_image: true,
                        method
                    }),
                    Ok(())
                );
            }
        }
    }
}
