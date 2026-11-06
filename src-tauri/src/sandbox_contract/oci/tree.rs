//! OCI whiteouts applied across the layer stack into one read-only tree index (VM-W33;
//! §5.3 "verify image identity, provenance and layout").
//!
//! Layers apply in order. Within a layer, its opaque markers (`.wh..wh..opq`) and
//! whiteouts (`.wh.<name>`) apply first and only to what lower layers left, then its own
//! entries apply in archive order. A whiteout or an entry that would pass through a
//! symbolic link or a file of the tree is refused. Names and whiteouts use the Linux
//! image namespace, preserving case and UTF-8 spelling exactly. The finished
//! tree is checked again as a whole by V05's [`check_archive`], so a link planted by one
//! layer and used by another is refused like one inside a single layer.
//!
//! The tree is an index for the guest, never a directory on the host: each file names the
//! layer, the offset of its data in that layer's expanded stream, its size and its sha256,
//! so the guest can check every file as it materializes it inside the VM.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::archive::check_image_archive as check_archive;
use super::digest::OciDigest;
use super::layer::{LayerEntry, LayerEntryKind, LayerReport};
use super::limits::{detail, ImportLimits};
use crate::sandbox_contract::files::{
    ArchiveEntry, ArchiveEntryKind, ImageArchiveRefusal as ArchiveRefusal, ImageName,
};

/// Where a file's bytes are: a layer of the image, an offset into that layer's expanded
/// tar stream, a size and a sha256 digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileContent {
    pub layer: u32,
    pub data_offset_bytes: u64,
    pub size_bytes: u64,
    pub sha256: OciDigest,
}

strict_oci_enum! {
    /// One node of the resulting read-only tree. Extended attribute values are hex.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum TreeNode tag "kind" {
        Directory {
            mode: u32,
            uid: u64,
            gid: u64,
            xattrs: BTreeMap<String, String>,
            /// Created only because a longer name needed it.
            implied: bool,
        },
        File {
            mode: u32,
            uid: u64,
            gid: u64,
            xattrs: BTreeMap<String, String>,
            content: FileContent,
            /// The regular file this one is a hard link to, while both still share content.
            hard_link_to: Option<ImageName>,
        },
        Symlink {
            target: String,
            uid: u64,
            gid: u64,
        },
    }
}

/// One named node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeEntry {
    pub name: ImageName,
    pub node: TreeNode,
}

/// Counts over a tree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TreeSummary {
    pub directories: usize,
    pub files: usize,
    pub hard_links: usize,
    pub symlinks: usize,
    pub file_bytes: u64,
}

/// The read-only tree of an image: entries sorted by name, every ancestor present as a
/// directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TreeIndex {
    pub entries: Vec<TreeEntry>,
    pub summary: TreeSummary,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TreeBody {
    entries: Vec<TreeEntry>,
}

/// Why the layer stack does not make a safe tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum TreeRefusal {
    TooManyLayers,
    TooManyNodes {
        nodes: usize,
        limit: usize,
    },
    /// The name passes through a symbolic link of the tree.
    ThroughLink {
        layer: u32,
        index: usize,
        name: ImageName,
        link: ImageName,
    },
    /// The name needs a file of the tree to be a directory.
    ParentNotDirectory {
        layer: u32,
        index: usize,
        name: ImageName,
        parent: ImageName,
    },
    /// An opaque marker inside something that is not a directory.
    OpaqueOnNonDirectory {
        layer: u32,
        index: usize,
        directory: ImageName,
    },
    /// A hard link whose target is not a regular file of the tree.
    HardLinkTarget {
        layer: u32,
        index: usize,
        name: ImageName,
    },
    /// V05's check of the whole tree.
    Archive {
        refusal: ArchiveRefusal,
    },
    /// A tree index that does not parse.
    Malformed {
        detail: String,
    },
    Unsorted {
        name: ImageName,
    },
    LayerOutOfRange {
        name: ImageName,
        layer: u32,
    },
    MissingParent {
        name: ImageName,
    },
    FileTooLarge {
        name: ImageName,
        size_bytes: u64,
    },
    BrokenHardLink {
        name: ImageName,
    },
}

impl fmt::Display for TreeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyLayers => f.write_str("too many layers to number"),
            Self::TooManyNodes { nodes, limit } => {
                write!(f, "the tree has more than {limit} nodes ({nodes})")
            }
            Self::ThroughLink {
                layer,
                index,
                name,
                link,
            } => write!(
                f,
                "layer {layer} entry {index}: {name} passes through link {link}"
            ),
            Self::ParentNotDirectory {
                layer,
                index,
                name,
                parent,
            } => write!(
                f,
                "layer {layer} entry {index}: {name} needs file {parent} as a directory"
            ),
            Self::OpaqueOnNonDirectory {
                layer,
                index,
                directory,
            } => write!(
                f,
                "layer {layer} entry {index}: {directory} is not a directory"
            ),
            Self::HardLinkTarget { layer, index, name } => {
                write!(
                    f,
                    "layer {layer} entry {index}: {name} links to no regular file"
                )
            }
            Self::Archive { refusal } => write!(f, "the merged tree: {refusal}"),
            Self::Malformed { detail } => write!(f, "malformed tree index: {detail}"),
            Self::Unsorted { name } => write!(f, "{name} is out of order or repeated"),
            Self::LayerOutOfRange { name, layer } => {
                write!(
                    f,
                    "{name} names layer {layer}, which the image does not have"
                )
            }
            Self::MissingParent { name } => write!(f, "{name} has no parent directory"),
            Self::FileTooLarge { name, size_bytes } => {
                write!(f, "{name} declares {size_bytes} bytes")
            }
            Self::BrokenHardLink { name } => write!(f, "{name} is a broken hard link"),
        }
    }
}

impl std::error::Error for TreeRefusal {}

fn hex_xattrs(xattrs: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, String> {
    xattrs
        .iter()
        .map(|(name, value)| (name.clone(), hex::encode(value)))
        .collect()
}

/// Applies layers in order into one tree (VM-W33).
#[derive(Clone, Debug)]
pub struct TreeBuilder {
    nodes: BTreeMap<String, TreeNode>,
    layers: u32,
    limits: ImportLimits,
}

impl TreeBuilder {
    /// An empty tree held to `limits`.
    pub fn new(limits: &ImportLimits) -> Self {
        Self {
            nodes: BTreeMap::new(),
            layers: 0,
            limits: *limits,
        }
    }

    fn remove_node(&mut self, name: &str) {
        self.nodes.remove(name);
    }

    fn remove_descendants(&mut self, name: &str) {
        let prefix = format!("{name}/");
        let doomed: Vec<String> = self
            .nodes
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .map(|(key, _)| key.clone())
            .collect();
        for key in doomed {
            self.remove_node(&key);
        }
    }

    fn insert_node(&mut self, name: &ImageName, node: TreeNode) -> Result<(), TreeRefusal> {
        self.nodes.insert(name.as_str().to_owned(), node);
        if self.nodes.len() > self.limits.max_image_entries {
            return Err(TreeRefusal::TooManyNodes {
                nodes: self.nodes.len(),
                limit: self.limits.max_image_entries,
            });
        }
        Ok(())
    }

    /// Refuses a name below a link or a file of the tree; returns the missing ancestors.
    fn walk_ancestors(
        &self,
        layer: u32,
        index: usize,
        name: &ImageName,
    ) -> Result<Vec<ImageName>, TreeRefusal> {
        let mut missing = Vec::new();
        for ancestor in name.ancestors() {
            match self.nodes.get(ancestor.as_str()) {
                Some(TreeNode::Directory { .. }) => {}
                Some(TreeNode::Symlink { .. }) => {
                    return Err(TreeRefusal::ThroughLink {
                        layer,
                        index,
                        name: name.clone(),
                        link: ancestor,
                    })
                }
                Some(TreeNode::File { .. }) => {
                    return Err(TreeRefusal::ParentNotDirectory {
                        layer,
                        index,
                        name: name.clone(),
                        parent: ancestor,
                    })
                }
                None => {
                    missing.push(ancestor);
                }
            }
        }
        Ok(missing)
    }

    /// Applies the next layer of the stack.
    pub fn apply(&mut self, report: &LayerReport) -> Result<(), TreeRefusal> {
        let layer = self.layers;
        self.layers = self
            .layers
            .checked_add(1)
            .ok_or(TreeRefusal::TooManyLayers)?;
        for entry in &report.entries {
            if let LayerEntryKind::OpaqueWhiteout { directory } = &entry.kind {
                self.apply_opaque(layer, entry.index, directory.as_ref())?;
            }
        }
        for entry in &report.entries {
            if let LayerEntryKind::Whiteout { target } = &entry.kind {
                self.apply_whiteout(layer, entry.index, target)?;
            }
        }
        for entry in &report.entries {
            self.apply_entry(layer, entry)?;
        }
        Ok(())
    }

    fn apply_opaque(
        &mut self,
        layer: u32,
        index: usize,
        directory: Option<&ImageName>,
    ) -> Result<(), TreeRefusal> {
        let Some(directory) = directory else {
            self.nodes.clear();
            return Ok(());
        };
        self.walk_ancestors(layer, index, directory)?;
        match self.nodes.get(directory.as_str()) {
            Some(TreeNode::Directory { .. }) => {
                self.remove_descendants(directory.as_str());
                Ok(())
            }
            Some(_) => Err(TreeRefusal::OpaqueOnNonDirectory {
                layer,
                index,
                directory: directory.clone(),
            }),
            None => Ok(()),
        }
    }

    fn apply_whiteout(
        &mut self,
        layer: u32,
        index: usize,
        target: &ImageName,
    ) -> Result<(), TreeRefusal> {
        self.walk_ancestors(layer, index, target)?;
        if self.nodes.contains_key(target.as_str()) {
            self.remove_node(target.as_str());
            self.remove_descendants(target.as_str());
            return Ok(());
        }
        Ok(())
    }

    fn apply_entry(&mut self, layer: u32, entry: &LayerEntry) -> Result<(), TreeRefusal> {
        let index = entry.index;
        let node = match &entry.kind {
            LayerEntryKind::Whiteout { .. } | LayerEntryKind::OpaqueWhiteout { .. } => {
                return Ok(())
            }
            LayerEntryKind::Directory => TreeNode::Directory {
                mode: entry.mode,
                uid: entry.uid,
                gid: entry.gid,
                xattrs: hex_xattrs(&entry.xattrs),
                implied: false,
            },
            LayerEntryKind::File {
                size_bytes,
                sha256,
                data_offset_bytes,
            } => TreeNode::File {
                mode: entry.mode,
                uid: entry.uid,
                gid: entry.gid,
                xattrs: hex_xattrs(&entry.xattrs),
                content: FileContent {
                    layer,
                    data_offset_bytes: *data_offset_bytes,
                    size_bytes: *size_bytes,
                    sha256: *sha256,
                },
                hard_link_to: None,
            },
            LayerEntryKind::Symlink { target } => TreeNode::Symlink {
                target: target.clone(),
                uid: entry.uid,
                gid: entry.gid,
            },
            LayerEntryKind::HardLink { target } => {
                let content = match self.nodes.get(target.as_str()) {
                    Some(TreeNode::File { content, .. }) if content.layer == layer => *content,
                    _ => {
                        return Err(TreeRefusal::HardLinkTarget {
                            layer,
                            index,
                            name: entry.name.clone(),
                        })
                    }
                };
                TreeNode::File {
                    mode: entry.mode,
                    uid: entry.uid,
                    gid: entry.gid,
                    xattrs: hex_xattrs(&entry.xattrs),
                    content,
                    hard_link_to: Some(target.clone()),
                }
            }
        };
        let name = &entry.name;
        for missing in self.walk_ancestors(layer, index, name)? {
            self.insert_node(
                &missing,
                TreeNode::Directory {
                    mode: 0o755,
                    uid: 0,
                    gid: 0,
                    xattrs: BTreeMap::new(),
                    implied: true,
                },
            )?;
        }
        let existing_is_directory = matches!(
            self.nodes.get(name.as_str()),
            Some(TreeNode::Directory { .. })
        );
        if !(existing_is_directory && matches!(node, TreeNode::Directory { .. })) {
            self.remove_descendants(name.as_str());
        }
        self.insert_node(name, node)
    }

    /// Finishes the tree: hard links whose target was later removed or replaced become
    /// plain files with the content they had, and V05 checks the whole tree.
    pub fn finish(mut self) -> Result<TreeIndex, TreeRefusal> {
        let stale: Vec<String> = self
            .nodes
            .iter()
            .filter_map(|(name, node)| match node {
                TreeNode::File {
                    content,
                    hard_link_to: Some(target),
                    ..
                } => {
                    let shared = matches!(
                        self.nodes.get(target.as_str()),
                        Some(TreeNode::File { content: other, hard_link_to: None, .. }) if other == content
                    );
                    (!shared).then(|| name.clone())
                }
                _ => None,
            })
            .collect();
        for name in stale {
            if let Some(TreeNode::File { hard_link_to, .. }) = self.nodes.get_mut(&name) {
                *hard_link_to = None;
            }
        }
        let entries = self
            .nodes
            .into_iter()
            .map(|(name, node)| {
                ImageName::parse(&name)
                    .map(|name| TreeEntry { name, node })
                    .map_err(|refusal| TreeRefusal::Archive {
                        refusal: ArchiveRefusal::UnsafeName { index: 0, refusal },
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        TreeIndex::checked(entries, self.layers, &self.limits)
    }
}

impl TreeIndex {
    /// Checks a sorted entry list as a closed, safe tree for an image of `layers` layers:
    /// strictly sorted names, every ancestor a directory, files within bounds and in
    /// range, hard links to a regular file with the same content, and V05's checks.
    fn checked(
        entries: Vec<TreeEntry>,
        layers: u32,
        limits: &ImportLimits,
    ) -> Result<Self, TreeRefusal> {
        if entries.len() > limits.max_image_entries {
            return Err(TreeRefusal::TooManyNodes {
                nodes: entries.len(),
                limit: limits.max_image_entries,
            });
        }
        let mut by_name: BTreeMap<&str, &TreeNode> = BTreeMap::new();
        let mut previous: Option<&ImageName> = None;
        for entry in &entries {
            if previous.is_some_and(|previous| previous >= &entry.name) {
                return Err(TreeRefusal::Unsorted {
                    name: entry.name.clone(),
                });
            }
            previous = Some(&entry.name);
            by_name.insert(entry.name.as_str(), &entry.node);
        }
        let mut summary = TreeSummary::default();
        let mut files = Vec::new();
        let mut links = Vec::new();
        for entry in &entries {
            let name = &entry.name;
            let parent_ok = name.parent().is_none_or(|parent| {
                matches!(
                    by_name.get(parent.as_str()),
                    Some(TreeNode::Directory { .. })
                )
            });
            if !parent_ok {
                return Err(TreeRefusal::MissingParent { name: name.clone() });
            }
            match &entry.node {
                TreeNode::Directory { .. } => {
                    summary.directories = summary.directories.saturating_add(1);
                    files.push(ArchiveEntry {
                        name: name.as_str().to_owned(),
                        kind: ArchiveEntryKind::Directory,
                    });
                }
                TreeNode::File {
                    content,
                    hard_link_to,
                    ..
                } => {
                    if content.layer >= layers {
                        return Err(TreeRefusal::LayerOutOfRange {
                            name: name.clone(),
                            layer: content.layer,
                        });
                    }
                    if content.size_bytes > limits.max_file_bytes {
                        return Err(TreeRefusal::FileTooLarge {
                            name: name.clone(),
                            size_bytes: content.size_bytes,
                        });
                    }
                    match hard_link_to {
                        None => {
                            summary.files = summary.files.saturating_add(1);
                            summary.file_bytes =
                                summary.file_bytes.saturating_add(content.size_bytes);
                            files.push(ArchiveEntry {
                                name: name.as_str().to_owned(),
                                kind: ArchiveEntryKind::File {
                                    uncompressed_bytes: content.size_bytes,
                                    compressed_bytes: content.size_bytes,
                                },
                            });
                        }
                        Some(target) => {
                            let shared = matches!(
                                by_name.get(target.as_str()),
                                Some(TreeNode::File { content: other, hard_link_to: None, .. }) if other == content
                            );
                            if !shared {
                                return Err(TreeRefusal::BrokenHardLink { name: name.clone() });
                            }
                            summary.hard_links = summary.hard_links.saturating_add(1);
                            links.push(ArchiveEntry {
                                name: name.as_str().to_owned(),
                                kind: ArchiveEntryKind::HardLink {
                                    target: target.as_str().to_owned(),
                                },
                            });
                        }
                    }
                }
                TreeNode::Symlink { target, .. } => {
                    summary.symlinks = summary.symlinks.saturating_add(1);
                    files.push(ArchiveEntry {
                        name: name.as_str().to_owned(),
                        kind: ArchiveEntryKind::Symlink {
                            target: target.clone(),
                        },
                    });
                }
            }
        }
        files.extend(links);
        check_archive(&files, &limits.tree_archive_limits())
            .map_err(|refusal| TreeRefusal::Archive { refusal })?;
        Ok(Self { entries, summary })
    }

    /// The canonical JSON body published in the tree envelope.
    pub(crate) fn body_bytes(&self) -> Result<Vec<u8>, TreeRefusal> {
        serde_json::to_vec(&TreeBody {
            entries: self.entries.clone(),
        })
        .map_err(|error| TreeRefusal::Malformed {
            detail: detail(error),
        })
    }

    /// Parses and re-checks a published tree body for an image of `layers` layers.
    pub(crate) fn from_body(
        bytes: &[u8],
        layers: u32,
        limits: &ImportLimits,
    ) -> Result<Self, TreeRefusal> {
        let body: TreeBody =
            serde_json::from_slice(bytes).map_err(|error| TreeRefusal::Malformed {
                detail: detail(error),
            })?;
        Self::checked(body.entries, layers, limits)
    }

    /// The node at `name`, if any.
    pub fn get(&self, name: &str) -> Option<&TreeNode> {
        self.entries
            .binary_search_by(|entry| entry.name.as_str().cmp(name))
            .ok()
            .and_then(|position| self.entries.get(position))
            .map(|entry| &entry.node)
    }
}
