//! Observing the destination and reviewing the exact diff (VM part §5.2 steps 3 and 5,
//! lines 2065 and 2067; VM-P16, VM-P34).
//!
//! The destination's expected base state is observed per target without following links:
//! absent (with how many components are missing), a regular file with its content key, or
//! something that cannot be replaced. The review pairs each frozen entry with that state,
//! names the change exactly (add, modify from one content key to another, unchanged) and
//! flags executable, configuration and hook changes, such as `.git/hooks`,
//! `.github/workflows`, shell initialization files, build scripts, package lifecycle
//! manifests and execute bits. Flags compare case-folded names, so a differently cased
//! spelling on a case-insensitive volume is flagged too.
//!
//! Review reads bytes and metadata only. Nothing on the host runs tests, hooks, filters or
//! build scripts during review (line 2071), and a reviewed change is not a proof that the
//! code is harmless.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::fsutil::{self, HandleKind};
use super::manifest::{FileKind, FrozenManifest, IoStep, PromotionRefusal};
use super::names::GuestName;
use super::root::{GrantedRoot, RootOpenError, Walk};
use crate::foundation::ids::{ContentKey, Digest, DigestBuilder};

const SNAPSHOT_DOMAIN: &str = "yougori/sandbox/files/destination-snapshot/v1";
const REVIEW_DOMAIN: &str = "yougori/sandbox/files/promotion-review/v1";

/// Why a component of a name stops the walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathBlock {
    /// An ancestor is a regular file.
    File,
    /// A symlink, junction or other reparse point.
    Link,
    Other,
    /// The volume found an entry spelled differently: a case alias (line 2049).
    CaseAlias,
}

impl PathBlock {
    const fn tag(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Link => "link",
            Self::Other => "other",
            Self::CaseAlias => "case_alias",
        }
    }
}

strict_tagged_enum! {
    /// One target's state in the destination (§5.2 step 4: the expected base state).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum DestinationState (tag = "state", wire = DestinationStateWire, wire_name = "DestinationStateWire") {
        /// The last `missing_components` components do not exist; 1 means the parent
        /// directory exists.
        Absent { missing_components: u64 },
        File { size_bytes: u64, content: ContentKey, kind: FileKind },
        Directory,
        /// A symlink, junction or other reparse point.
        Link,
        /// A regular file with more than one name.
        HardLinked,
        /// A device, FIFO or socket.
        Other,
        /// Component `component` (0 for the first) is not a real directory, or is a case
        /// alias.
        Blocked { component: u64, block: PathBlock },
    }
}

impl DestinationState {
    fn encode(&self, builder: DigestBuilder) -> DigestBuilder {
        match self {
            Self::Absent { missing_components } => builder.str("absent").u64(*missing_components),
            Self::File {
                size_bytes,
                content,
                kind,
            } => builder
                .str("file")
                .u64(*size_bytes)
                .digest(content.digest())
                .str(match kind {
                    FileKind::Regular => "regular",
                    FileKind::Executable => "executable",
                }),
            Self::Directory => builder.str("directory"),
            Self::Link => builder.str("link"),
            Self::HardLinked => builder.str("hard_linked"),
            Self::Other => builder.str("other"),
            Self::Blocked { component, block } => {
                builder.str("blocked").u64(*component).str(block.tag())
            }
        }
    }
}

/// The identity of a root directory: a digest of the opened object's volume and index (and,
/// on Windows, creation time), read from its handle ([`GrantedRoot::identity`]). A root
/// renamed or replaced after it was opened has another identity.
///
/// [`GrantedRoot::identity`]: super::GrantedRoot::identity
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RootIdentity(Digest);

impl RootIdentity {
    pub(super) const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }
}

/// Opens the host-selected destination root at `path`.
pub(super) fn open_destination(path: &Path) -> Result<GrantedRoot, PromotionRefusal> {
    GrantedRoot::open(path).map_err(|error| match error {
        RootOpenError::NotARealDirectory | RootOpenError::Changed => {
            PromotionRefusal::DestinationRootInvalid
        }
        RootOpenError::Io(error) => PromotionRefusal::io(IoStep::InspectRoot, None, &error),
    })
}

/// The destination's state for every entry of one manifest, bound by a digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SnapshotWire")]
pub struct DestinationSnapshot {
    root: RootIdentity,
    entries: BTreeMap<GuestName, DestinationState>,
    digest: Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotWire {
    root: RootIdentity,
    entries: BTreeMap<GuestName, DestinationState>,
    digest: Digest,
}

impl TryFrom<SnapshotWire> for DestinationSnapshot {
    type Error = PromotionRefusal;

    fn try_from(wire: SnapshotWire) -> Result<Self, Self::Error> {
        let snapshot = Self::new(wire.root, wire.entries);
        if snapshot.digest != wire.digest {
            return Err(PromotionRefusal::SnapshotDigestMismatch);
        }
        Ok(snapshot)
    }
}

impl DestinationSnapshot {
    fn new(root: RootIdentity, entries: BTreeMap<GuestName, DestinationState>) -> Self {
        let mut builder = DigestBuilder::new(SNAPSHOT_DOMAIN)
            .digest(&root.0)
            .u64(entries.len() as u64);
        for (name, state) in &entries {
            builder = state.encode(builder.str(name.as_str()));
        }
        let digest = builder.finish();
        Self {
            root,
            entries,
            digest,
        }
    }

    pub fn root(&self) -> RootIdentity {
        self.root
    }

    pub fn entries(&self) -> &BTreeMap<GuestName, DestinationState> {
        &self.entries
    }

    pub fn state(&self, name: &GuestName) -> Option<&DestinationState> {
        self.entries.get(name)
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Observes `name` beneath the opened `root` without following links.
pub(super) fn observe_entry(
    root: &GrantedRoot,
    name: &GuestName,
) -> Result<DestinationState, PromotionRefusal> {
    let io = |error: &std::io::Error| {
        PromotionRefusal::io(IoStep::ObserveDestination, Some(name), error)
    };
    let mut opened = match root.walk(name).map_err(|error| io(&error))? {
        Walk::Missing { missing, .. } => {
            return Ok(DestinationState::Absent {
                missing_components: count(missing),
            })
        }
        Walk::Blocked { component, stop } => {
            return Ok(DestinationState::Blocked {
                component: count(component),
                block: stop.block(),
            })
        }
        Walk::Found(opened) => opened,
    };
    match opened.info.kind {
        HandleKind::Link(_) => return Ok(DestinationState::Link),
        HandleKind::Directory => return Ok(DestinationState::Directory),
        HandleKind::Device => return Ok(DestinationState::Other),
        HandleKind::File => {}
    }
    if opened.info.links > 1 {
        return Ok(DestinationState::HardLinked);
    }
    let size_bytes = opened.info.size;
    let content = fsutil::hash_open(&mut opened.file, size_bytes)
        .map_err(|error| io(&error))?
        .ok_or_else(|| PromotionRefusal::DestinationChanged { name: name.clone() })?;
    let kind = if opened.info.executable {
        FileKind::Executable
    } else {
        FileKind::Regular
    };
    Ok(DestinationState::File {
        size_bytes,
        content,
        kind,
    })
}

/// Observes the destination's expected base state for every entry of `manifest`
/// (§5.2 step 4), opening the host-selected root at `destination_root` first.
pub fn observe_destination(
    destination_root: &Path,
    manifest: &FrozenManifest,
) -> Result<DestinationSnapshot, PromotionRefusal> {
    observe_destination_in(&open_destination(destination_root)?, manifest)
}

/// Observes the destination's expected base state for every entry of `manifest` beneath
/// the already opened `destination` (§5.2 step 4).
pub fn observe_destination_in(
    destination: &GrantedRoot,
    manifest: &FrozenManifest,
) -> Result<DestinationSnapshot, PromotionRefusal> {
    let mut entries = BTreeMap::new();
    for entry in manifest.entries() {
        entries.insert(entry.name.clone(), observe_entry(destination, &entry.name)?);
    }
    Ok(DestinationSnapshot::new(destination.identity(), entries))
}

/// A change the reviewer must see called out (§5.2 step 3; VM-P34).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewFlag {
    /// An execute bit is new or added.
    ExecutableBit,
    /// A type the host runs directly or by association, such as `.exe`, `.bat`, `.ps1`,
    /// `.sh` or `.lnk`.
    ExecutableType,
    /// Git hooks or a hook manager's configuration.
    GitHook,
    /// Git configuration and attributes, which can name filters, credential helpers and
    /// hook paths, and anything else under `.git`.
    GitConfiguration,
    CiWorkflow,
    ShellInit,
    BuildScript,
    /// Package manifests, lockfiles and package-manager configuration, which can carry
    /// lifecycle scripts.
    PackageLifecycle,
    /// Editor, container and toolchain configuration that can start programs.
    ToolConfiguration,
}

impl ReviewFlag {
    const fn tag(self) -> &'static str {
        match self {
            Self::ExecutableBit => "executable_bit",
            Self::ExecutableType => "executable_type",
            Self::GitHook => "git_hook",
            Self::GitConfiguration => "git_configuration",
            Self::CiWorkflow => "ci_workflow",
            Self::ShellInit => "shell_init",
            Self::BuildScript => "build_script",
            Self::PackageLifecycle => "package_lifecycle",
            Self::ToolConfiguration => "tool_configuration",
        }
    }
}

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "com", "scr", "cpl", "msi", "msp", "msc", "bat", "cmd", "ps1", "psm1",
    "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "url", "reg", "jar", "pyw",
    "so", "dylib", "sh", "bash", "zsh", "fish", "command", "appimage", "desktop", "app",
];

const HOOK_FILES: &[&str] = &[
    ".pre-commit-config.yaml",
    ".pre-commit-hooks.yaml",
    "lefthook.yml",
    "lefthook.yaml",
    ".lefthook.yml",
];

const GIT_CONFIGURATION_FILES: &[&str] = &[".gitattributes", ".gitmodules", ".gitconfig"];

const CI_FILES: &[&str] = &[
    ".gitlab-ci.yml",
    ".travis.yml",
    "azure-pipelines.yml",
    "jenkinsfile",
    "bitbucket-pipelines.yml",
    "appveyor.yml",
    ".drone.yml",
];

const SHELL_INIT_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".cshrc",
    ".tcshrc",
    ".kshrc",
    ".mkshrc",
    ".envrc",
    "profile.ps1",
    "microsoft.powershell_profile.ps1",
    "microsoft.vscode_profile.ps1",
];

const BUILD_FILES: &[&str] = &[
    "build.rs",
    "makefile",
    "gnumakefile",
    "cmakelists.txt",
    "configure",
    "configure.ac",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "gradlew",
    "gradlew.bat",
    "gradle-wrapper.properties",
    "pom.xml",
    "mvnw",
    "mvnw.cmd",
    "build.xml",
    "meson.build",
    "build",
    "build.bazel",
    "workspace",
    "workspace.bazel",
    "module.bazel",
    "rakefile",
    "justfile",
    ".justfile",
    "taskfile.yml",
    "taskfile.yaml",
    "setup.py",
    "conftest.py",
    "noxfile.py",
    "tox.ini",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "build.sbt",
    "flake.nix",
    "default.nix",
    "shell.nix",
];

const PACKAGE_FILES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
    "bunfig.toml",
    "pyproject.toml",
    "setup.cfg",
    "requirements.txt",
    "pipfile",
    "pipfile.lock",
    "poetry.lock",
    "cargo.toml",
    "gemfile",
    "gemfile.lock",
    "composer.json",
    "composer.lock",
    "go.mod",
    "deno.json",
    "deno.jsonc",
];

const TOOL_DIRECTORIES: &[&str] = &[".vscode", ".idea", ".devcontainer", ".fleet", ".zed"];

const TOOL_FILES: &[&str] = &[
    "rust-toolchain",
    "rust-toolchain.toml",
    ".tool-versions",
    ".nvmrc",
    ".node-version",
    ".python-version",
    ".ruby-version",
    ".sdkmanrc",
    "global.json",
    "mise.toml",
    ".mise.toml",
];

/// The flags for a file named `name` arriving as `kind`, replacing a file of
/// `previous` kind if any.
pub(super) fn flags_for(
    name: &GuestName,
    kind: FileKind,
    previous: Option<FileKind>,
) -> BTreeSet<ReviewFlag> {
    let folded: Vec<String> = name
        .components()
        .map(|component| component.to_ascii_lowercase())
        .collect();
    let file = folded.last().map(String::as_str).unwrap_or("");
    let first = folded.first().map(String::as_str).unwrap_or("");
    let second = folded.get(1).map(String::as_str);
    let extension = file
        .rsplit_once('.')
        .filter(|(stem, _)| !stem.is_empty())
        .map(|(_, extension)| extension);
    let mut flags = BTreeSet::new();
    if kind == FileKind::Executable && previous != Some(FileKind::Executable) {
        flags.insert(ReviewFlag::ExecutableBit);
    }
    if extension.is_some_and(|extension| EXECUTABLE_EXTENSIONS.contains(&extension)) {
        flags.insert(ReviewFlag::ExecutableType);
    }
    for (index, component) in folded.iter().enumerate() {
        if component == ".git" {
            if folded.get(index + 1).map(String::as_str) == Some("hooks") {
                flags.insert(ReviewFlag::GitHook);
            } else {
                flags.insert(ReviewFlag::GitConfiguration);
            }
        }
        if component == ".config" && folded.get(index + 1).map(String::as_str) == Some("fish") {
            flags.insert(ReviewFlag::ShellInit);
        }
    }
    if matches!(first, ".husky" | ".githooks") || HOOK_FILES.contains(&file) {
        flags.insert(ReviewFlag::GitHook);
    }
    if GIT_CONFIGURATION_FILES.contains(&file) {
        flags.insert(ReviewFlag::GitConfiguration);
    }
    if (first == ".github" && matches!(second, Some("workflows" | "actions")))
        || matches!(first, ".circleci" | ".buildkite")
        || CI_FILES.contains(&file)
    {
        flags.insert(ReviewFlag::CiWorkflow);
    }
    if SHELL_INIT_FILES.contains(&file) {
        flags.insert(ReviewFlag::ShellInit);
    }
    if BUILD_FILES.contains(&file) || extension == Some("cmake") || first == ".cargo" {
        flags.insert(ReviewFlag::BuildScript);
    }
    if PACKAGE_FILES.contains(&file) || extension == Some("gemspec") {
        flags.insert(ReviewFlag::PackageLifecycle);
    }
    if TOOL_DIRECTORIES.contains(&first) || TOOL_FILES.contains(&file) {
        flags.insert(ReviewFlag::ToolConfiguration);
    }
    flags
}

strict_tagged_enum! {
    /// What applying one entry changes.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ChangeKind (tag = "change", wire = ChangeKindWire, wire_name = "ChangeKindWire") {
        Add,
        Modify { from: ContentKey, from_size_bytes: u64, from_kind: FileKind },
        /// Same bytes and kind already in place; applying leaves it alone.
        Unchanged,
    }
}

/// One reviewed entry: the exact change and its flags.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedChange {
    pub name: GuestName,
    pub change: ChangeKind,
    pub size_bytes: u64,
    pub content: ContentKey,
    pub kind: FileKind,
    pub flags: BTreeSet<ReviewFlag>,
}

/// The exact diff of one manifest against one destination snapshot (§5.2 step 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ReviewWire")]
pub struct Review {
    manifest: Digest,
    destination: Digest,
    changes: Vec<ReviewedChange>,
    digest: Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewWire {
    manifest: Digest,
    destination: Digest,
    changes: Vec<ReviewedChange>,
    digest: Digest,
}

impl TryFrom<ReviewWire> for Review {
    type Error = PromotionRefusal;

    fn try_from(wire: ReviewWire) -> Result<Self, Self::Error> {
        let review = Self::new(wire.manifest, wire.destination, wire.changes);
        if review.digest != wire.digest {
            return Err(PromotionRefusal::ReviewDigestMismatch);
        }
        Ok(review)
    }
}

impl Review {
    fn new(manifest: Digest, destination: Digest, changes: Vec<ReviewedChange>) -> Self {
        let digest = review_digest(manifest, destination, &changes);
        Self {
            manifest,
            destination,
            changes,
            digest,
        }
    }

    pub fn manifest(&self) -> Digest {
        self.manifest
    }

    pub fn destination(&self) -> Digest {
        self.destination
    }

    pub fn changes(&self) -> &[ReviewedChange] {
        &self.changes
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// Every entry with at least one flag, and its flags.
    pub fn flagged(&self) -> BTreeMap<GuestName, BTreeSet<ReviewFlag>> {
        self.changes
            .iter()
            .filter(|change| !change.flags.is_empty())
            .map(|change| (change.name.clone(), change.flags.clone()))
            .collect()
    }

    pub(super) fn recomputed_digest(&self) -> Digest {
        review_digest(self.manifest, self.destination, &self.changes)
    }
}

fn review_digest(manifest: Digest, destination: Digest, changes: &[ReviewedChange]) -> Digest {
    let mut builder = DigestBuilder::new(REVIEW_DOMAIN)
        .digest(&manifest)
        .digest(&destination)
        .u64(changes.len() as u64);
    for change in changes {
        builder = builder.str(change.name.as_str());
        builder = match &change.change {
            ChangeKind::Add => builder.str("add"),
            ChangeKind::Modify {
                from,
                from_size_bytes,
                from_kind,
            } => builder
                .str("modify")
                .digest(from.digest())
                .u64(*from_size_bytes)
                .str(match from_kind {
                    FileKind::Regular => "regular",
                    FileKind::Executable => "executable",
                }),
            ChangeKind::Unchanged => builder.str("unchanged"),
        };
        builder = builder
            .u64(change.size_bytes)
            .digest(change.content.digest())
            .str(match change.kind {
                FileKind::Regular => "regular",
                FileKind::Executable => "executable",
            })
            .u64(change.flags.len() as u64);
        for flag in &change.flags {
            builder = builder.str(flag.tag());
        }
    }
    builder.finish()
}

/// Reviews `manifest` against `snapshot` (§5.2 step 3). A target that is not absent and
/// not a replaceable regular file is refused.
pub fn review(
    manifest: &FrozenManifest,
    snapshot: &DestinationSnapshot,
) -> Result<Review, PromotionRefusal> {
    let names: BTreeSet<&GuestName> = manifest.entries().iter().map(|entry| &entry.name).collect();
    if names.len() != snapshot.entries.len()
        || !snapshot.entries.keys().all(|name| names.contains(name))
    {
        return Err(PromotionRefusal::SnapshotDoesNotMatchManifest);
    }
    let mut changes = Vec::with_capacity(manifest.entries().len());
    for entry in manifest.entries() {
        let state = snapshot
            .entries
            .get(&entry.name)
            .ok_or(PromotionRefusal::SnapshotDoesNotMatchManifest)?;
        let (change, previous) = match state {
            DestinationState::Absent { .. } => (ChangeKind::Add, None),
            DestinationState::File {
                size_bytes,
                content,
                kind,
            } => {
                if *content == entry.content && *kind == entry.kind {
                    (ChangeKind::Unchanged, Some(*kind))
                } else {
                    (
                        ChangeKind::Modify {
                            from: *content,
                            from_size_bytes: *size_bytes,
                            from_kind: *kind,
                        },
                        Some(*kind),
                    )
                }
            }
            other => {
                return Err(PromotionRefusal::TargetNotAFile {
                    name: entry.name.clone(),
                    state: other.clone(),
                })
            }
        };
        let flags = if change == ChangeKind::Unchanged {
            BTreeSet::new()
        } else {
            flags_for(&entry.name, entry.kind, previous)
        };
        changes.push(ReviewedChange {
            name: entry.name.clone(),
            change,
            size_bytes: entry.size_bytes,
            content: entry.content,
            kind: entry.kind,
            flags,
        });
    }
    Ok(Review::new(manifest.digest(), snapshot.digest, changes))
}
