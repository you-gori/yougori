//! Absolute guest paths, and the guest layout protected paths resolve against (VM-W07;
//! VM-CP-05 "a write to `~/.bashrc` or `.git/hooks/` fails").
//!
//! V15 names a protected path relative to the workload user's home (`~/`) or to the
//! workspace root ([`ProtectedPath`]); a read-only mount and a Landlock rule need the
//! absolute path in the guest. A [`GuestLayout`] says where the home and the workspace
//! are and, for a Landlock ruleset only, where the workload may write and which device
//! nodes the inner container is given (V15 has no field for either). An
//! [`AbsoluteGuestPath`] is already normal: absolute, no empty, `.` or `..` component, no
//! trailing `/`, no backslash and no character `foundation::text` judges hazardous, so
//! one path has one spelling. Whether a component is a symbolic link is the installer's
//! to check when it mounts or opens the path.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::lsm::{SHARED_MEMORY_DIRECTORY, STANDARD_DEVICES};
use crate::foundation::text::is_hazardous;
use crate::sandbox_contract::confinement::{PathRoot, ProtectedPath};

/// Longest accepted guest path, in bytes.
pub const MAX_GUEST_PATH_BYTES: usize = 1024;
/// Most components one guest path may have.
pub const MAX_GUEST_PATH_COMPONENTS: usize = 48;
/// Most writable roots one layout may list.
pub const MAX_WRITABLE_ROOTS: usize = 16;
/// Most device nodes one layout may list.
pub const MAX_DEVICE_NODES: usize = 32;

/// Why a guest path was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestPathRefusal {
    Empty,
    TooLong {
        bytes: usize,
        max: usize,
    },
    /// A hazardous character (`foundation::text`).
    Hazardous {
        character: char,
    },
    /// Backslashes are not separators in a guest path and hide intent.
    Backslash,
    /// Not starting with `/`.
    Relative,
    /// `/` alone: no component.
    NoComponent,
    /// A trailing `/`; the normal form has none.
    TrailingSlash,
    /// An empty component (`/a//b`).
    EmptyComponent,
    /// A `.` or `..` component.
    DotComponent,
    TooManyComponents {
        count: usize,
        max: usize,
    },
}

impl fmt::Display for GuestPathRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the guest path is empty"),
            Self::TooLong { bytes, max } => {
                write!(f, "the guest path has {bytes} bytes; at most {max}")
            }
            Self::Hazardous { character } => write!(
                f,
                "the guest path contains the hazardous character U+{:04X}",
                u32::from(*character)
            ),
            Self::Backslash => f.write_str("the guest path contains a backslash"),
            Self::Relative => f.write_str("a guest path starts with `/`"),
            Self::NoComponent => f.write_str("the guest path names only the root"),
            Self::TrailingSlash => f.write_str("the guest path ends with `/`"),
            Self::EmptyComponent => f.write_str("the guest path has an empty component"),
            Self::DotComponent => f.write_str("the guest path has a `.` or `..` component"),
            Self::TooManyComponents { count, max } => {
                write!(f, "the guest path has {count} components; at most {max}")
            }
        }
    }
}

impl std::error::Error for GuestPathRefusal {}

/// A normal absolute path inside the guest, such as `/home/agent/.bashrc`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AbsoluteGuestPath {
    components: Vec<String>,
}

impl AbsoluteGuestPath {
    /// Accepts only a normal absolute path; see [`GuestPathRefusal`].
    pub fn parse(text: &str) -> Result<Self, GuestPathRefusal> {
        if text.is_empty() {
            return Err(GuestPathRefusal::Empty);
        }
        if text.len() > MAX_GUEST_PATH_BYTES {
            return Err(GuestPathRefusal::TooLong {
                bytes: text.len(),
                max: MAX_GUEST_PATH_BYTES,
            });
        }
        if let Some(character) = text.chars().find(|character| is_hazardous(*character)) {
            return Err(GuestPathRefusal::Hazardous { character });
        }
        if text.contains('\\') {
            return Err(GuestPathRefusal::Backslash);
        }
        let Some(rest) = text.strip_prefix('/') else {
            return Err(GuestPathRefusal::Relative);
        };
        if rest.is_empty() {
            return Err(GuestPathRefusal::NoComponent);
        }
        if rest.ends_with('/') {
            return Err(GuestPathRefusal::TrailingSlash);
        }
        let mut components = Vec::new();
        for component in rest.split('/') {
            if component.is_empty() {
                return Err(GuestPathRefusal::EmptyComponent);
            }
            if component == "." || component == ".." {
                return Err(GuestPathRefusal::DotComponent);
            }
            components.push(component.to_owned());
        }
        if components.len() > MAX_GUEST_PATH_COMPONENTS {
            return Err(GuestPathRefusal::TooManyComponents {
                count: components.len(),
                max: MAX_GUEST_PATH_COMPONENTS,
            });
        }
        Ok(Self { components })
    }

    /// The components, root first.
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// The canonical text form.
    pub fn to_text(&self) -> String {
        format!("/{}", self.components.join("/"))
    }

    /// Whether this path is `other` or lies beneath it, component by component.
    pub fn is_within(&self, other: &Self) -> bool {
        self.components.starts_with(&other.components)
    }

    /// `/dev/<name>` for a fixed device name of this module's callers: one component with
    /// no `/`, no backslash, no hazardous character and neither `.` nor `..`, so it is
    /// already normal (a test parses each one).
    pub(super) fn device(name: &'static str) -> Self {
        Self {
            components: vec!["dev".to_owned(), name.to_owned()],
        }
    }

    /// This path with `relative`'s components appended, checked again as a whole.
    fn joined(&self, relative: &[String]) -> Result<Self, GuestPathRefusal> {
        let mut text = self.to_text();
        for component in relative {
            text.push('/');
            text.push_str(component);
        }
        Self::parse(&text)
    }
}

impl TryFrom<String> for AbsoluteGuestPath {
    type Error = GuestPathRefusal;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<AbsoluteGuestPath> for String {
    fn from(path: AbsoluteGuestPath) -> Self {
        path.to_text()
    }
}

impl fmt::Display for AbsoluteGuestPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

/// Why a layout was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LayoutRefusal {
    TooManyWritableRoots {
        count: usize,
        max: usize,
    },
    /// One writable root listed twice.
    DuplicateWritableRoot {
        path: AbsoluteGuestPath,
    },
    TooManyDeviceNodes {
        count: usize,
        max: usize,
    },
    /// One device node listed twice.
    DuplicateDeviceNode {
        path: AbsoluteGuestPath,
    },
    /// A device node not beneath `/dev`.
    DeviceNodeOutsideDev {
        path: AbsoluteGuestPath,
    },
    /// A device node a Landlock ruleset always grants, or one beneath such a directory
    /// (`lsm::STANDARD_DEVICES` and `lsm::SHARED_MEMORY_DIRECTORY`).
    StandardDevice {
        path: AbsoluteGuestPath,
    },
}

impl fmt::Display for LayoutRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyWritableRoots { count, max } => {
                write!(f, "the layout lists {count} writable roots; at most {max}")
            }
            Self::DuplicateWritableRoot { path } => {
                write!(f, "the layout lists the writable root {path} twice")
            }
            Self::TooManyDeviceNodes { count, max } => {
                write!(f, "the layout lists {count} device nodes; at most {max}")
            }
            Self::DuplicateDeviceNode { path } => {
                write!(f, "the layout lists the device node {path} twice")
            }
            Self::DeviceNodeOutsideDev { path } => {
                write!(f, "the device node {path} is not beneath /dev")
            }
            Self::StandardDevice { path } => write!(
                f,
                "the device node {path} is always granted and is not declared"
            ),
        }
    }
}

impl std::error::Error for LayoutRefusal {}

/// The serialized form of a [`GuestLayout`]. Every field is required.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutDocument {
    /// The workload user's home directory, which `~/` names.
    pub home: AbsoluteGuestPath,
    /// The workspace root, which a relative protected path names.
    pub workspace: AbsoluteGuestPath,
    /// Where the workload may write when a Landlock ruleset is compiled; read only then.
    pub writable_roots: Vec<AbsoluteGuestPath>,
    /// The device nodes the inner container is given beyond the standard ones, such as a
    /// GPU's `/dev/nvidia0`; a Landlock ruleset grants writes to each. Read only then.
    pub device_nodes: Vec<AbsoluteGuestPath>,
}

/// Where V15's roots are in the guest, and where the workload may write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "LayoutDocument", into = "LayoutDocument")]
pub struct GuestLayout {
    home: AbsoluteGuestPath,
    workspace: AbsoluteGuestPath,
    writable_roots: Vec<AbsoluteGuestPath>,
    device_nodes: Vec<AbsoluteGuestPath>,
}

impl GuestLayout {
    /// Sorts the writable roots and the device nodes, and refuses a duplicate, too many,
    /// a device node outside `/dev` or one a Landlock ruleset always grants.
    pub fn new(document: LayoutDocument) -> Result<Self, LayoutRefusal> {
        let LayoutDocument {
            home,
            workspace,
            mut writable_roots,
            mut device_nodes,
        } = document;
        if writable_roots.len() > MAX_WRITABLE_ROOTS {
            return Err(LayoutRefusal::TooManyWritableRoots {
                count: writable_roots.len(),
                max: MAX_WRITABLE_ROOTS,
            });
        }
        if device_nodes.len() > MAX_DEVICE_NODES {
            return Err(LayoutRefusal::TooManyDeviceNodes {
                count: device_nodes.len(),
                max: MAX_DEVICE_NODES,
            });
        }
        writable_roots.sort();
        if let Some(path) = first_repeat(&writable_roots) {
            return Err(LayoutRefusal::DuplicateWritableRoot { path });
        }
        device_nodes.sort();
        if let Some(path) = first_repeat(&device_nodes) {
            return Err(LayoutRefusal::DuplicateDeviceNode { path });
        }
        let dev = [String::from("dev")];
        let standard = standard_device_grants();
        for path in &device_nodes {
            if path.components.len() < 2 || !path.components.starts_with(&dev) {
                return Err(LayoutRefusal::DeviceNodeOutsideDev { path: path.clone() });
            }
            if standard.iter().any(|granted| path.is_within(granted)) {
                return Err(LayoutRefusal::StandardDevice { path: path.clone() });
            }
        }
        Ok(Self {
            home,
            workspace,
            writable_roots,
            device_nodes,
        })
    }

    pub fn home(&self) -> &AbsoluteGuestPath {
        &self.home
    }

    pub fn workspace(&self) -> &AbsoluteGuestPath {
        &self.workspace
    }

    /// The writable roots, sorted.
    pub fn writable_roots(&self) -> &[AbsoluteGuestPath] {
        &self.writable_roots
    }

    /// The declared device nodes, sorted.
    pub fn device_nodes(&self) -> &[AbsoluteGuestPath] {
        &self.device_nodes
    }

    /// `path` resolved against its root: `~/x` under the home, `x` under the workspace.
    pub fn resolve(&self, path: &ProtectedPath) -> Result<AbsoluteGuestPath, GuestPathRefusal> {
        let text = path.to_text();
        let (root, body) = match path.root() {
            PathRoot::Home => (&self.home, text.strip_prefix("~/").unwrap_or(&text)),
            PathRoot::Workspace => (&self.workspace, text.as_str()),
        };
        let body = body.strip_suffix('/').unwrap_or(body);
        let relative: Vec<String> = body.split('/').map(str::to_owned).collect();
        root.joined(&relative)
    }
}

impl TryFrom<LayoutDocument> for GuestLayout {
    type Error = LayoutRefusal;

    fn try_from(document: LayoutDocument) -> Result<Self, Self::Error> {
        Self::new(document)
    }
}

impl From<GuestLayout> for LayoutDocument {
    fn from(layout: GuestLayout) -> Self {
        Self {
            home: layout.home,
            workspace: layout.workspace,
            writable_roots: layout.writable_roots,
            device_nodes: layout.device_nodes,
        }
    }
}

/// The first path that appears twice in sorted `paths`.
fn first_repeat(paths: &[AbsoluteGuestPath]) -> Option<AbsoluteGuestPath> {
    paths.windows(2).find_map(|pair| match pair {
        [first, second] if first == second => Some(first.clone()),
        _ => None,
    })
}

/// The device paths every Landlock ruleset grants, in path order.
pub(super) fn standard_device_grants() -> Vec<AbsoluteGuestPath> {
    let mut grants: Vec<AbsoluteGuestPath> = STANDARD_DEVICES
        .iter()
        .chain(std::iter::once(&SHARED_MEMORY_DIRECTORY))
        .map(|name| AbsoluteGuestPath::device(name))
        .collect();
    grants.sort();
    grants
}
