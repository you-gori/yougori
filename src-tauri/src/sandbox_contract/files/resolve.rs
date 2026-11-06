//! Typed model of resolution beneath a granted root (VM part §5.1 lines 2047–2049;
//! VM-P15).
//!
//! [`RootModel`] holds directory entries as typed values, link kinds included, so the
//! resolution rules are specified and tested without creating a symlink, junction or
//! mount. Resolution walks one component at a time and refuses to follow any link kind:
//! symlinks, hard-linked files, junctions, other reparse points and mount crossings.
//! Following a link that stays inside the root would need a second resolution of its
//! target, which is the race the plan warns about, so the strict reading refuses them
//! all. On a case-insensitive root a request whose spelling differs from the stored entry
//! is refused as a case alias.
//!
//! This is a model, not the control. The control is [`GrantedRoot::resolve`]: handle-relative
//! opens beneath the opened root that never follow a link (M12; [`super::fsutil`]), giving
//! on a real directory the results of a model with case folding on, whatever the volume.
//! A model check made before such an open is not race-proof (line 2047).
//!
//! [`GrantedRoot::resolve`]: super::GrantedRoot::resolve

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use super::names::GuestName;
use crate::foundation::ids::Digest;

/// One directory entry as the host observes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntryKind {
    File {
        size_bytes: u64,
        executable: bool,
    },
    Directory,
    Symlink {
        target: String,
    },
    /// A regular file with more than one name; another name may lie outside the root.
    HardLink {
        link_count: u32,
    },
    Junction {
        target: String,
    },
    /// Any other reparse point, by its tag.
    ReparsePoint {
        tag: u32,
    },
    /// A directory on another volume or mount.
    MountCrossing {
        volume: Digest,
    },
    /// A device, FIFO or socket.
    Device,
}

impl EntryKind {
    /// The link kind of this entry, if it is one.
    pub fn link_kind(&self) -> Option<LinkKind> {
        match self {
            Self::Symlink { .. } => Some(LinkKind::Symlink),
            Self::HardLink { .. } => Some(LinkKind::HardLink),
            Self::Junction { .. } => Some(LinkKind::Junction),
            Self::ReparsePoint { .. } => Some(LinkKind::ReparsePoint),
            Self::MountCrossing { .. } => Some(LinkKind::MountCrossing),
            Self::File { .. } | Self::Directory | Self::Device => None,
        }
    }
}

/// The link kinds resolution never follows (VM-P15).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    Symlink,
    HardLink,
    Junction,
    ReparsePoint,
    MountCrossing,
}

/// Whether the caller opens an existing entry or may create the last component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveIntent {
    Open,
    Create,
}

/// What a name resolved to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "resolved", rename_all = "snake_case")]
pub enum Resolved {
    File {
        size_bytes: u64,
        executable: bool,
    },
    Directory,
    /// The last component does not exist and its parent is a directory (create only).
    Absent,
}

/// Why resolution stopped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ResolveRefusal {
    /// A link kind at `at`; it is never followed.
    LinkRefused {
        at: GuestName,
        link: LinkKind,
    },
    /// A device, FIFO or socket at `at`.
    DeviceRefused {
        at: GuestName,
    },
    /// The stored entry is spelled differently on a case-insensitive root.
    CaseAlias {
        requested: GuestName,
        stored: GuestName,
    },
    NotFound {
        at: GuestName,
    },
    NotADirectory {
        at: GuestName,
    },
    /// The runtime resolver could not read `at`; the model never returns this.
    Io {
        at: GuestName,
        detail: String,
    },
}

impl fmt::Display for ResolveRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LinkRefused { at, link } => write!(f, "{at} is a {link:?}; it is not followed"),
            Self::DeviceRefused { at } => write!(f, "{at} is a device"),
            Self::CaseAlias { requested, stored } => {
                write!(f, "{requested} would alias {stored}")
            }
            Self::NotFound { at } => write!(f, "{at} does not exist"),
            Self::NotADirectory { at } => write!(f, "{at} is not a directory"),
            Self::Io { at, detail } => write!(f, "{at} could not be read: {detail}"),
        }
    }
}

impl std::error::Error for ResolveRefusal {}

/// A granted root as typed entries, for specifying and testing resolution.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RootModel {
    case_insensitive: bool,
    entries: BTreeMap<GuestName, EntryKind>,
    by_fold: BTreeMap<String, GuestName>,
}

impl RootModel {
    /// An empty root; `case_insensitive` for NTFS and default APFS volumes.
    pub fn new(case_insensitive: bool) -> Self {
        Self {
            case_insensitive,
            ..Self::default()
        }
    }

    /// Records `name` as `kind`, and its missing ancestors as directories. On a
    /// case-insensitive root a second spelling of a stored name replaces nothing and is
    /// recorded under the first spelling's fold, as the volume would.
    pub fn insert(&mut self, name: GuestName, kind: EntryKind) {
        for ancestor in name.ancestors() {
            if self.lookup(&ancestor).is_none() {
                self.record(ancestor, EntryKind::Directory);
            }
        }
        self.record(name, kind);
    }

    fn record(&mut self, name: GuestName, kind: EntryKind) {
        if self.case_insensitive {
            if let Some(stored) = self.by_fold.get(&name.folded()) {
                let stored = stored.clone();
                self.entries.insert(stored, kind);
                return;
            }
            self.by_fold.insert(name.folded(), name.clone());
        }
        self.entries.insert(name, kind);
    }

    fn lookup(&self, name: &GuestName) -> Option<(&GuestName, &EntryKind)> {
        if self.case_insensitive {
            let stored = self.by_fold.get(&name.folded())?;
            self.entries.get_key_value(stored)
        } else {
            self.entries.get_key_value(name)
        }
    }

    /// Resolves `name` one component at a time, refusing every link kind, device and case
    /// alias on the way (VM-P15).
    pub fn resolve(
        &self,
        name: &GuestName,
        intent: ResolveIntent,
    ) -> Result<Resolved, ResolveRefusal> {
        let mut prefixes = name.ancestors();
        prefixes.push(name.clone());
        let last = prefixes.len().saturating_sub(1);
        for (index, prefix) in prefixes.into_iter().enumerate() {
            let is_last = index == last;
            let Some((stored, kind)) = self.lookup(&prefix) else {
                return if is_last && intent == ResolveIntent::Create {
                    Ok(Resolved::Absent)
                } else {
                    Err(ResolveRefusal::NotFound { at: prefix })
                };
            };
            if stored != &prefix {
                return Err(ResolveRefusal::CaseAlias {
                    requested: prefix,
                    stored: stored.clone(),
                });
            }
            if let Some(link) = kind.link_kind() {
                return Err(ResolveRefusal::LinkRefused { at: prefix, link });
            }
            match kind {
                EntryKind::Device => return Err(ResolveRefusal::DeviceRefused { at: prefix }),
                EntryKind::Directory if is_last => return Ok(Resolved::Directory),
                EntryKind::Directory => {}
                EntryKind::File {
                    size_bytes,
                    executable,
                } if is_last => {
                    return Ok(Resolved::File {
                        size_bytes: *size_bytes,
                        executable: *executable,
                    })
                }
                _ => return Err(ResolveRefusal::NotADirectory { at: prefix }),
            }
        }
        Err(ResolveRefusal::NotFound { at: name.clone() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    fn name(text: &str) -> GuestName {
        GuestName::parse(text).unwrap()
    }

    fn file(size_bytes: u64) -> EntryKind {
        EntryKind::File {
            size_bytes,
            executable: false,
        }
    }

    fn tree(case_insensitive: bool) -> RootModel {
        let mut model = RootModel::new(case_insensitive);
        model.insert(name("src/main.rs"), file(10));
        model.insert(
            name("escape"),
            EntryKind::Symlink {
                target: "../../etc".into(),
            },
        );
        model.insert(
            name("inside-link"),
            EntryKind::Symlink {
                target: "src".into(),
            },
        );
        model.insert(name("shadow"), EntryKind::HardLink { link_count: 2 });
        model.insert(
            name("junction"),
            EntryKind::Junction {
                target: "C:\\Users".into(),
            },
        );
        model.insert(name("cloud"), EntryKind::ReparsePoint { tag: 0x9000_001a });
        model.insert(
            name("mnt"),
            EntryKind::MountCrossing {
                volume: digest("yougori/test/volume/v1", &[b"usb"]),
            },
        );
        model.insert(name("fifo"), EntryKind::Device);
        model
    }

    #[test]
    fn plain_files_and_directories_resolve() {
        let model = tree(false);
        assert_eq!(
            model.resolve(&name("src/main.rs"), ResolveIntent::Open),
            Ok(Resolved::File {
                size_bytes: 10,
                executable: false
            })
        );
        assert_eq!(
            model.resolve(&name("src"), ResolveIntent::Open),
            Ok(Resolved::Directory)
        );
        assert_eq!(
            model.resolve(&name("src/new.rs"), ResolveIntent::Create),
            Ok(Resolved::Absent)
        );
        assert_eq!(
            model.resolve(&name("src/new.rs"), ResolveIntent::Open),
            Err(ResolveRefusal::NotFound {
                at: name("src/new.rs")
            })
        );
        assert_eq!(
            model.resolve(&name("missing/new.rs"), ResolveIntent::Create),
            Err(ResolveRefusal::NotFound {
                at: name("missing")
            })
        );
        assert_eq!(
            model.resolve(&name("src/main.rs/x"), ResolveIntent::Create),
            Err(ResolveRefusal::NotADirectory {
                at: name("src/main.rs")
            })
        );
    }

    #[test]
    fn every_link_kind_is_refused_as_the_target_and_on_the_way() {
        let model = tree(false);
        for (at, link) in [
            ("escape", LinkKind::Symlink),
            ("inside-link", LinkKind::Symlink),
            ("shadow", LinkKind::HardLink),
            ("junction", LinkKind::Junction),
            ("cloud", LinkKind::ReparsePoint),
            ("mnt", LinkKind::MountCrossing),
        ] {
            for intent in [ResolveIntent::Open, ResolveIntent::Create] {
                assert_eq!(
                    model.resolve(&name(at), intent),
                    Err(ResolveRefusal::LinkRefused { at: name(at), link })
                );
                assert_eq!(
                    model.resolve(&name(&format!("{at}/passwd")), intent),
                    Err(ResolveRefusal::LinkRefused { at: name(at), link })
                );
            }
        }
        assert_eq!(
            model.resolve(&name("fifo"), ResolveIntent::Open),
            Err(ResolveRefusal::DeviceRefused { at: name("fifo") })
        );
    }

    #[test]
    fn case_aliases_are_refused_on_a_case_insensitive_root() {
        let model = tree(true);
        assert_eq!(
            model.resolve(&name("SRC/main.rs"), ResolveIntent::Open),
            Err(ResolveRefusal::CaseAlias {
                requested: name("SRC"),
                stored: name("src")
            })
        );
        assert_eq!(
            model.resolve(&name("src/MAIN.rs"), ResolveIntent::Create),
            Err(ResolveRefusal::CaseAlias {
                requested: name("src/MAIN.rs"),
                stored: name("src/main.rs")
            })
        );
        assert_eq!(
            model.resolve(&name("ESCAPE/x"), ResolveIntent::Open),
            Err(ResolveRefusal::CaseAlias {
                requested: name("ESCAPE"),
                stored: name("escape")
            })
        );
        // A case-sensitive root holds them as different names.
        let sensitive = tree(false);
        assert_eq!(
            sensitive.resolve(&name("SRC/main.rs"), ResolveIntent::Open),
            Err(ResolveRefusal::NotFound { at: name("SRC") })
        );
    }

    #[test]
    fn a_link_planted_later_is_refused_when_resolution_reaches_it() {
        let mut model = tree(false);
        assert!(model
            .resolve(&name("src/main.rs"), ResolveIntent::Open)
            .is_ok());
        // The guest swaps the directory for a link after the name check passed. The name
        // is still valid; only resolution at use refuses it.
        model.insert(name("src"), EntryKind::Symlink { target: "/".into() });
        assert_eq!(
            model.resolve(&name("src/main.rs"), ResolveIntent::Open),
            Err(ResolveRefusal::LinkRefused {
                at: name("src"),
                link: LinkKind::Symlink
            })
        );
    }
}
