//! Workload profiles and their confinement profiles (VM-W07 "Inner confinement and guest
//! hardening per workload profile"; VM-R65 "Adapt developer, service and device
//! profiles"; VM-CP-05 "strict profile"; VM-R66; §3.4).
//!
//! A [`ConfinementProfile`] is the whole inner confinement of one workload profile: a
//! non-root uid policy, the exact capability set, no_new_privs, the forbidden interfaces
//! with their mechanisms, the protected read-only paths, the tools that must keep
//! working, the recorded exceptions and the kernel settings it requires. It is strict,
//! bounded input: reading sorts every list, refuses duplicates and unknown fields, and
//! validates every rule below. Its digest, under its own domain, covers every field, so
//! adding an exception produces a new identity.
//!
//! Each [`WorkloadProfile`] names a baseline of interfaces that must be refused. Every
//! baseline interface is either forbidden with a mechanism or covered by a recorded
//! exception (reason and owner) for a named tool that needs it; an interface that is
//! simply left out is refused. Nothing is disabled and then silently re-enabled (§3.4).
//!
//! Exceptions. The strict tool profile admits exceptions only for `perf_event_open` and
//! `ptrace`, and a ptrace exception still needs the "only this user's processes" rule
//! enforced by credentials or the LSM (§3.4). It admits none for io_uring, bpf,
//! userfaultfd, kexec, module loading, AF_VSOCK or protected-path writes, nor any
//! capability: VM-CP-05 checks io_uring, AF_VSOCK, the protected paths and the exact
//! capability set, and bpf, userfaultfd, kexec and module loading are the VM-R57 and §3.4
//! defaults with no strict-profile use.
//! No profile admits an exception for kexec, module loading, AF_VSOCK or ptrace of other
//! users' processes: the workload never loads kernel code (drivers are compiled in or
//! loaded by the guest agent under a signed-module profile, §3.4), the workload's AF_VSOCK
//! restriction stays (VM-R56), and the own-user rule is the floor §3.4 sets.
//!
//! Ptrace and process memory (M07B). Another process's memory is reachable through
//! ptrace(2), process_vm_readv(2), process_vm_writev(2), pidfd_getfd(2) and by opening
//! `/proc/<pid>/mem`. The kernel gates all of them with one ptrace access check in attach
//! mode (`ptrace_may_access`; `mm_access` for the procfs file). Seccomp sees only system
//! call numbers, so it refuses the first four and never the procfs open, whose path it
//! cannot read (§3.4). So a profile that forbids `ptrace` declares the LSM for it, as
//! primary or backup ([`ProfileRefusal::PtraceMemoryNeedsLsm`]): Yama's admin-only scope
//! acts in that access check and refuses every attach-mode access without
//! `CAP_SYS_PTRACE`, the procfs file included (`open` fails with `EACCES`), while a
//! process's own `/proc/self/mem` stays open. `ptrace_other_users` needs no such rule:
//! every mechanism V15 accepts for it (credentials, capability absence, the LSM) acts in
//! the same check, and seccomp is refused for it already.
//!
//! Repository protection (M07B; VM-CP-05 `.git/hooks/`; §4.6 "guest-controlled hooks,
//! filters, helpers, remote configuration"). A read-only `.git/hooks/` alone is sidestepped
//! by renaming the workload-owned `.git` (the mount moves with it) or by pointing
//! `core.hooksPath`, `core.fsmonitor` or an include elsewhere from a git configuration
//! file the workload can write. So a profile that protects any path in the workspace
//! repository protects [`REPOSITORY_PROTECTION`] with it: the whole `.git/` directory
//! (a mount point cannot be renamed or replaced, and its configuration is no longer
//! writable) and the user-level configuration files the same uid's later git reads
//! (`~/.gitconfig`, `~/.config/git/`). It may hold no capability that defeats root
//! ownership, because the guest's system git configuration, which the compiled policy
//! also writes, is protected by root ownership alone. The compiler turns this into the
//! repository section of the guest policy (`guest_policy::repository`).

use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU32;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::capability::LinuxCapability;
use super::interfaces::{Interface, Mechanism};
use super::kernel::{KernelOption, KernelSetting};
use super::responsibility::{
    check_assignment, AssignmentContext, ForbiddenInterface, ResponsibilityMap,
    ResponsibilityRefusal,
};
use super::text::{OwnerName, RecordedReason, TextRefusal, ToolName};
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::foundation::text::is_hazardous;

/// The profile version this build reads.
pub const CONFINEMENT_PROFILE_VERSION: u32 = 1;
/// Most required tools one profile may list.
pub const MAX_REQUIRED_TOOLS: usize = 64;
/// Most protected paths one profile may list.
pub const MAX_PROTECTED_PATHS: usize = 32;
/// Most recorded exceptions one profile may hold.
pub const MAX_EXCEPTIONS: usize = 16;
/// Longest protected path, in bytes.
pub const MAX_PROTECTED_PATH_BYTES: usize = 256;
/// Most components one protected path may have.
pub const MAX_PATH_COMPONENTS: usize = 16;

/// The protected paths a profile lists together once it protects any path in the
/// workspace repository (see the module notes), in [`ProtectedPath`] order.
pub const REPOSITORY_PROTECTION: [&str; 3] = ["~/.config/git/", "~/.gitconfig", ".git/"];

/// The digest domain of [`ConfinementProfile::digest`]; a new field layout needs a new
/// domain.
const PROFILE_DIGEST_DOMAIN: &str = "yougori/sandbox/confinement/profile/v1";

/// The uid the strict tool profile runs as.
const STRICT_UID: NonZeroU32 = NonZeroU32::MIN.saturating_add(999);

/// The capabilities the current inner container keeps
/// (`appliance/agent/container_security.go`, `containerCapabilities`): the developer
/// ceiling.
const DEVELOPER_CAPABILITIES: [LinuxCapability; 11] = [
    LinuxCapability::Chown,
    LinuxCapability::DacOverride,
    LinuxCapability::Fowner,
    LinuxCapability::Fsetid,
    LinuxCapability::Kill,
    LinuxCapability::NetBindService,
    LinuxCapability::Setgid,
    LinuxCapability::Setuid,
    LinuxCapability::Setfcap,
    LinuxCapability::SysChroot,
    LinuxCapability::AuditWrite,
];

/// The baseline every profile but the strict one shares, before its ptrace rule.
const COMMON_BASELINE: [Interface; 7] = [
    Interface::IoUring,
    Interface::Bpf,
    Interface::Userfaultfd,
    Interface::PerfEventOpen,
    Interface::Kexec,
    Interface::ModuleLoading,
    Interface::VsockSocket,
];

/// A workload profile (VM-R65 "developer, service and device profiles"; VM-CP-05 "strict
/// profile").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadProfile {
    /// AI and tool execution under VM-CP-05's strict profile: no capabilities, a fixed
    /// non-root uid, io_uring absent from the kernel, protected shell and hook paths, and
    /// host corroboration required.
    StrictTool,
    /// Interactive development: the current inner container's capabilities, debuggers
    /// on the workload's own processes.
    Developer,
    /// A long-running service: binds low ports, nothing else.
    Service,
    /// A device workload such as a GPU runtime: no capabilities by default.
    Device,
}

impl WorkloadProfile {
    /// Every workload profile.
    pub const ALL: [Self; 4] = [
        Self::StrictTool,
        Self::Developer,
        Self::Service,
        Self::Device,
    ];

    /// The snake_case label used in records and digests.
    pub const fn label(self) -> &'static str {
        match self {
            Self::StrictTool => "strict_tool",
            Self::Developer => "developer",
            Self::Service => "service",
            Self::Device => "device",
        }
    }

    /// The interfaces this profile must refuse unless a recorded exception covers them
    /// (VM-R55, VM-R57, VM-CP-05).
    pub fn baseline_forbidden(self) -> BTreeSet<Interface> {
        let mut baseline: BTreeSet<Interface> = COMMON_BASELINE.into_iter().collect();
        match self {
            Self::StrictTool => {
                baseline.insert(Interface::Ptrace);
                baseline.insert(Interface::ProtectedPathWrite);
            }
            // Debuggers trace the developer's own processes; other users' stay refused.
            Self::Developer => {
                baseline.insert(Interface::PtraceOtherUsers);
            }
            Self::Service | Self::Device => {
                baseline.insert(Interface::Ptrace);
            }
        }
        baseline
    }

    /// The capabilities a profile may hold without an exception (VM-R66).
    pub const fn capability_ceiling(self) -> &'static [LinuxCapability] {
        match self {
            Self::StrictTool => &[],
            Self::Developer => &DEVELOPER_CAPABILITIES,
            Self::Service => &[LinuxCapability::NetBindService],
            // Pinned host buffers for device DMA.
            Self::Device => &[LinuxCapability::IpcLock],
        }
    }

    /// Whether a recorded exception for `target` is admissible at all in this profile;
    /// see the module notes for the decisions.
    pub fn admits_exception(self, target: ExceptionTarget) -> bool {
        match target {
            ExceptionTarget::Interface { interface } => match interface {
                Interface::Kexec
                | Interface::ModuleLoading
                | Interface::VsockSocket
                | Interface::PtraceOtherUsers => false,
                Interface::IoUring
                | Interface::Bpf
                | Interface::Userfaultfd
                | Interface::ProtectedPathWrite => self != Self::StrictTool,
                Interface::PerfEventOpen | Interface::Ptrace => true,
            },
            ExceptionTarget::Capability { capability } => {
                self != Self::StrictTool && !capability.never_granted()
            }
        }
    }

    /// The protected paths this profile must list (VM-CP-05: "a write to `~/.bashrc` or
    /// `.git/hooks/` fails").
    pub const fn minimum_protected_paths(self) -> &'static [&'static str] {
        match self {
            Self::StrictTool => &["~/.bashrc", ".git/hooks/"],
            Self::Developer | Self::Service | Self::Device => &[],
        }
    }

    /// Whether host corroboration is always required (VM-CP-05 "Must for: strict
    /// profile"). A profile can require it for other reasons; see
    /// [`ConfinementProfile::requires_host_corroboration`].
    pub const fn requires_host_corroboration(self) -> bool {
        matches!(self, Self::StrictTool)
    }
}

impl fmt::Display for WorkloadProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

strict_confinement_enum! {
    /// Which uid the workload runs as (VM-R66 "Non-root workloads"). Uid 0 cannot be
    /// expressed: a fixed uid and gid are non-zero by type.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum UidPolicy tag "policy" {
        /// Exactly this non-root uid and gid.
        Fixed {
            uid: NonZeroU32,
            gid: NonZeroU32,
        },
        /// Whatever non-root uid the image names; uid 0 is refused at launch.
        AnyNonRoot,
    }
}

impl UidPolicy {
    /// Whether a process running as `uid` satisfies the policy.
    pub fn admits(&self, uid: u32) -> bool {
        match self {
            Self::Fixed { uid: fixed, .. } => fixed.get() == uid,
            Self::AnyNonRoot => uid != 0,
        }
    }
}

/// What a protected path is relative to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathRoot {
    /// The workload user's home directory, written `~/`.
    Home,
    /// The workspace (repository) root, written as a relative path.
    Workspace,
}

/// Why a protected path was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathRefusal {
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
    /// An absolute guest path; protected paths are relative to the home or workspace.
    Absolute,
    /// `~user/` or a bare `~`; only `~/` is accepted.
    TildeForm,
    /// Nothing after the root.
    NoComponent,
    /// An empty component (`a//b`).
    EmptyComponent,
    /// A `.` or `..` component.
    DotComponent,
    TooManyComponents {
        count: usize,
        max: usize,
    },
}

impl fmt::Display for PathRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the protected path is empty"),
            Self::TooLong { bytes, max } => {
                write!(f, "the protected path has {bytes} bytes; at most {max}")
            }
            Self::Hazardous { character } => write!(
                f,
                "the protected path contains the hazardous character U+{:04X}",
                u32::from(*character)
            ),
            Self::Backslash => f.write_str("the protected path contains a backslash"),
            Self::Absolute => {
                f.write_str("a protected path is relative to `~/` or the workspace root")
            }
            Self::TildeForm => f.write_str("only `~/` names the home directory"),
            Self::NoComponent => f.write_str("the protected path names only its root"),
            Self::EmptyComponent => f.write_str("the protected path has an empty component"),
            Self::DotComponent => f.write_str("the protected path has a `.` or `..` component"),
            Self::TooManyComponents { count, max } => {
                write!(
                    f,
                    "the protected path has {count} components; at most {max}"
                )
            }
        }
    }
}

impl std::error::Error for PathRefusal {}

/// A path the workload must not write (VM-CP-05: `~/.bashrc`, `.git/hooks/`). A trailing
/// `/` names a directory and everything under it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProtectedPath {
    root: PathRoot,
    components: Vec<String>,
    directory: bool,
}

impl ProtectedPath {
    /// Parses `~/relative`, or `relative` to the workspace root, with an optional
    /// trailing `/` for a directory.
    pub fn parse(text: &str) -> Result<Self, PathRefusal> {
        if text.is_empty() {
            return Err(PathRefusal::Empty);
        }
        if text.len() > MAX_PROTECTED_PATH_BYTES {
            return Err(PathRefusal::TooLong {
                bytes: text.len(),
                max: MAX_PROTECTED_PATH_BYTES,
            });
        }
        if let Some(character) = text.chars().find(|character| is_hazardous(*character)) {
            return Err(PathRefusal::Hazardous { character });
        }
        if text.contains('\\') {
            return Err(PathRefusal::Backslash);
        }
        let (root, rest) = if let Some(rest) = text.strip_prefix("~/") {
            (PathRoot::Home, rest)
        } else if text.starts_with('~') {
            return Err(PathRefusal::TildeForm);
        } else if text.starts_with('/') {
            return Err(PathRefusal::Absolute);
        } else {
            (PathRoot::Workspace, text)
        };
        let (body, directory) = match rest.strip_suffix('/') {
            Some(body) => (body, true),
            None => (rest, false),
        };
        if body.is_empty() {
            return Err(PathRefusal::NoComponent);
        }
        let mut components = Vec::new();
        for component in body.split('/') {
            if component.is_empty() {
                return Err(PathRefusal::EmptyComponent);
            }
            if component == "." || component == ".." {
                return Err(PathRefusal::DotComponent);
            }
            components.push(component.to_owned());
        }
        if components.len() > MAX_PATH_COMPONENTS {
            return Err(PathRefusal::TooManyComponents {
                count: components.len(),
                max: MAX_PATH_COMPONENTS,
            });
        }
        Ok(Self {
            root,
            components,
            directory,
        })
    }

    /// What the path is relative to.
    pub const fn root(&self) -> PathRoot {
        self.root
    }

    /// Whether it names a directory and everything under it.
    pub const fn is_directory(&self) -> bool {
        self.directory
    }

    /// Whether it lies in the workspace repository: `.git` itself or anything beneath it.
    pub fn in_repository(&self) -> bool {
        self.root == PathRoot::Workspace
            && self
                .components
                .first()
                .is_some_and(|component| component == ".git")
    }

    /// The canonical text form, such as `~/.bashrc` or `.git/hooks/`.
    pub fn to_text(&self) -> String {
        let prefix = match self.root {
            PathRoot::Home => "~/",
            PathRoot::Workspace => "",
        };
        let suffix = if self.directory { "/" } else { "" };
        format!("{prefix}{}{suffix}", self.components.join("/"))
    }
}

impl TryFrom<String> for ProtectedPath {
    type Error = PathRefusal;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<ProtectedPath> for String {
    fn from(path: ProtectedPath) -> Self {
        path.to_text()
    }
}

impl fmt::Display for ProtectedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

/// A tool the profile must keep working, and what it needs (VM-W07 "Required tools
/// work"; VM-R65).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredTool {
    pub name: ToolName,
    /// Interfaces the tool uses.
    pub interfaces: Vec<Interface>,
    /// Capabilities the tool needs.
    pub capabilities: Vec<LinuxCapability>,
}

impl RequiredTool {
    /// A tool needing nothing restricted.
    pub fn plain(name: ToolName) -> Self {
        Self {
            name,
            interfaces: Vec::new(),
            capabilities: Vec::new(),
        }
    }

    /// Whether the tool needs what `target` names.
    pub fn needs(&self, target: ExceptionTarget) -> bool {
        match target {
            ExceptionTarget::Interface { interface } => self.interfaces.contains(&interface),
            ExceptionTarget::Capability { capability } => self.capabilities.contains(&capability),
        }
    }
}

strict_confinement_enum! {
    /// What a recorded exception relaxes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum ExceptionTarget tag "kind" {
        /// A baseline interface the profile does not forbid.
        Interface { interface: Interface },
        /// A capability above the profile's ceiling.
        Capability { capability: LinuxCapability },
    }
}

impl ExceptionTarget {
    fn kind(self) -> &'static str {
        match self {
            Self::Interface { .. } => "interface",
            Self::Capability { .. } => "capability",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Interface { interface } => interface.label(),
            Self::Capability { capability } => capability.kernel_name(),
        }
    }
}

impl fmt::Display for ExceptionTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.kind(), self.name())
    }
}

/// An explicit, recorded exception for one tool (VM-R57 "explicit supported exceptions";
/// §3.4 "documented compatibility handling"). It is part of the profile's identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfinementException {
    pub target: ExceptionTarget,
    /// The required tool that needs the target.
    pub tool: ToolName,
    pub reason: RecordedReason,
    pub owner: OwnerName,
}

/// A profile list, named in refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileList {
    Capabilities,
    Forbidden,
    ProtectedPaths,
    RequiredTools,
    ToolInterfaces,
    ToolCapabilities,
    Exceptions,
    KernelSettings,
}

impl fmt::Display for ProfileList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Capabilities => "capabilities",
            Self::Forbidden => "forbidden interfaces",
            Self::ProtectedPaths => "protected paths",
            Self::RequiredTools => "required tools",
            Self::ToolInterfaces => "a tool's interfaces",
            Self::ToolCapabilities => "a tool's capabilities",
            Self::Exceptions => "exceptions",
            Self::KernelSettings => "kernel settings",
        })
    }
}

/// Why a confinement profile was refused (VM-W07; §3.4; VM-R66).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileRefusal {
    UnsupportedVersion {
        found: u32,
    },
    TooMany {
        list: ProfileList,
        count: usize,
        max: usize,
    },
    /// One entry twice; for forbidden interfaces, tools and exceptions, one key twice.
    Duplicate {
        list: ProfileList,
    },
    /// The strict profile always sets no_new_privs.
    NoNewPrivsRequired {
        workload: WorkloadProfile,
    },
    CapabilityNeverGranted {
        capability: LinuxCapability,
    },
    /// A capability above the profile's ceiling with no exception.
    CapabilityAboveCeiling {
        workload: WorkloadProfile,
        capability: LinuxCapability,
    },
    /// The profile holds a capability that grants an interface it forbids.
    CapabilityContradictsForbiddenInterface {
        capability: LinuxCapability,
        interface: Interface,
    },
    /// An assignment its mechanism cannot enforce.
    Responsibility(ResponsibilityRefusal),
    /// A baseline interface neither forbidden nor covered by an exception: it would be
    /// re-enabled silently (§3.4).
    BaselineInterfaceUnaccounted {
        workload: WorkloadProfile,
        interface: Interface,
    },
    ForbiddenAndExcepted {
        interface: Interface,
    },
    /// An exception for something the profile would allow anyway.
    ExceptionNotNeeded {
        target: ExceptionTarget,
    },
    ExceptionNotAdmitted {
        workload: WorkloadProfile,
        target: ExceptionTarget,
    },
    /// A capability exception for a capability the profile does not hold.
    ExceptionCapabilityNotHeld {
        capability: LinuxCapability,
    },
    ExceptionForUnknownTool {
        tool: ToolName,
    },
    ExceptionToolDoesNotNeedTarget {
        tool: ToolName,
        target: ExceptionTarget,
    },
    /// A ptrace exception without "ptrace only this user's processes" forbidden (§3.4).
    PtraceExceptionNeedsOwnUserRule,
    /// Ptrace forbidden without the LSM: seccomp alone leaves another process's
    /// `/proc/<pid>/mem` open (see the module notes).
    PtraceMemoryNeedsLsm,
    /// A path in the workspace repository is protected but this one of
    /// [`REPOSITORY_PROTECTION`] is not.
    RepositoryProtectionIncomplete {
        path: ProtectedPath,
    },
    /// The repository is protected while the profile holds a capability that defeats the
    /// root ownership protecting the guest's system git configuration.
    RepositoryProtectionDefeatedByCapability {
        capability: LinuxCapability,
    },
    /// A required tool needs a forbidden interface; it would not work (VM-W07).
    ToolNeedsForbiddenInterface {
        tool: ToolName,
        interface: Interface,
    },
    /// A tool relies on an exception recorded for another tool.
    ToolLacksException {
        tool: ToolName,
        target: ExceptionTarget,
    },
    ToolNeedsMissingCapability {
        tool: ToolName,
        capability: LinuxCapability,
    },
    /// Protected paths listed but protected-path writes not forbidden.
    ProtectedPathsWithoutMechanism,
    /// Protected-path writes forbidden but no path listed.
    ProtectedPathMechanismWithoutPaths,
    MissingProtectedPath {
        path: ProtectedPath,
    },
    /// A required kernel setting no host-side build fact can establish.
    SettingHasNoHostEvidence {
        setting: KernelSetting,
    },
    InvalidText {
        refusal: TextRefusal,
    },
    InvalidPath {
        refusal: PathRefusal,
    },
}

impl fmt::Display for ProfileRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { found } => write!(
                f,
                "confinement profile version {found} is not supported; this build reads \
                 version {CONFINEMENT_PROFILE_VERSION}"
            ),
            Self::TooMany { list, count, max } => {
                write!(f, "{count} {list} exceed the bound of {max}")
            }
            Self::Duplicate { list } => write!(f, "{list} contain a duplicate"),
            Self::NoNewPrivsRequired { workload } => {
                write!(f, "the {workload} profile requires no_new_privs")
            }
            Self::CapabilityNeverGranted { capability } => {
                write!(f, "no workload profile may hold {capability}")
            }
            Self::CapabilityAboveCeiling {
                workload,
                capability,
            } => write!(
                f,
                "{capability} is above the {workload} ceiling and has no recorded exception"
            ),
            Self::CapabilityContradictsForbiddenInterface {
                capability,
                interface,
            } => write!(
                f,
                "{capability} grants {interface}, which the profile forbids"
            ),
            Self::Responsibility(refusal) => write!(f, "{refusal}"),
            Self::BaselineInterfaceUnaccounted {
                workload,
                interface,
            } => write!(
                f,
                "the {workload} profile must forbid {interface} or record an exception for it"
            ),
            Self::ForbiddenAndExcepted { interface } => {
                write!(f, "{interface} is both forbidden and excepted")
            }
            Self::ExceptionNotNeeded { target } => {
                write!(f, "the exception for {target} relaxes nothing")
            }
            Self::ExceptionNotAdmitted { workload, target } => {
                write!(f, "the {workload} profile admits no exception for {target}")
            }
            Self::ExceptionCapabilityNotHeld { capability } => {
                write!(
                    f,
                    "the exception for {capability} names a capability not held"
                )
            }
            Self::ExceptionForUnknownTool { tool } => {
                write!(
                    f,
                    "the exception names {tool}, which is not a required tool"
                )
            }
            Self::ExceptionToolDoesNotNeedTarget { tool, target } => {
                write!(f, "{tool} does not need {target}")
            }
            Self::PtraceExceptionNeedsOwnUserRule => f.write_str(
                "a ptrace exception needs ptrace of other users' processes forbidden by \
                 credentials or the LSM",
            ),
            Self::PtraceMemoryNeedsLsm => f.write_str(
                "ptrace is forbidden without the LSM: seccomp cannot refuse opening another \
                 process's /proc/<pid>/mem",
            ),
            Self::RepositoryProtectionIncomplete { path } => write!(
                f,
                "a path in the workspace repository is protected but {path} is not, so the \
                 hooks could be moved or pointed elsewhere"
            ),
            Self::RepositoryProtectionDefeatedByCapability { capability } => write!(
                f,
                "{capability} defeats the root ownership that protects the guest's system git \
                 configuration"
            ),
            Self::ToolNeedsForbiddenInterface { tool, interface } => {
                write!(f, "{tool} needs {interface}, which the profile forbids")
            }
            Self::ToolLacksException { tool, target } => {
                write!(f, "{tool} uses {target} without its own recorded exception")
            }
            Self::ToolNeedsMissingCapability { tool, capability } => {
                write!(
                    f,
                    "{tool} needs {capability}, which the profile does not hold"
                )
            }
            Self::ProtectedPathsWithoutMechanism => {
                f.write_str("protected paths are listed but writes to them are not forbidden")
            }
            Self::ProtectedPathMechanismWithoutPaths => {
                f.write_str("protected-path writes are forbidden but no path is listed")
            }
            Self::MissingProtectedPath { path } => {
                write!(f, "the profile must protect {path}")
            }
            Self::SettingHasNoHostEvidence { setting } => write!(
                f,
                "{setting} cannot be required: no host-side build fact establishes it"
            ),
            Self::InvalidText { refusal } => write!(f, "{refusal}"),
            Self::InvalidPath { refusal } => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for ProfileRefusal {}

impl From<ResponsibilityRefusal> for ProfileRefusal {
    fn from(refusal: ResponsibilityRefusal) -> Self {
        Self::Responsibility(refusal)
    }
}

impl From<TextRefusal> for ProfileRefusal {
    fn from(refusal: TextRefusal) -> Self {
        Self::InvalidText { refusal }
    }
}

impl From<PathRefusal> for ProfileRefusal {
    fn from(refusal: PathRefusal) -> Self {
        Self::InvalidPath { refusal }
    }
}

/// The serialized form of a [`ConfinementProfile`]. Every field is required.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDocument {
    pub version: u32,
    pub workload: WorkloadProfile,
    pub uid: UidPolicy,
    /// The exact capability set (VM-CP-05 "the capability set equals the profile").
    pub capabilities: Vec<LinuxCapability>,
    pub no_new_privs: bool,
    pub forbidden: Vec<ForbiddenInterface>,
    pub protected_paths: Vec<ProtectedPath>,
    pub required_tools: Vec<RequiredTool>,
    pub exceptions: Vec<ConfinementException>,
    /// Kernel settings that must be forced by the guest kernel's build (VM-R71).
    pub kernel_settings: Vec<KernelSetting>,
}

/// A validated inner confinement profile with its identity (VM-W07; VM-P05).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfinementProfile {
    document: ProfileDocument,
    digest: Digest,
}

impl ConfinementProfile {
    /// Normalizes and validates `document`: sorted lists, no duplicates, bounds, and every
    /// rule in the module notes.
    pub fn new(mut document: ProfileDocument) -> Result<Self, ProfileRefusal> {
        if document.version != CONFINEMENT_PROFILE_VERSION {
            return Err(ProfileRefusal::UnsupportedVersion {
                found: document.version,
            });
        }
        bounded(
            document.required_tools.len(),
            MAX_REQUIRED_TOOLS,
            ProfileList::RequiredTools,
        )?;
        bounded(
            document.protected_paths.len(),
            MAX_PROTECTED_PATHS,
            ProfileList::ProtectedPaths,
        )?;
        bounded(
            document.exceptions.len(),
            MAX_EXCEPTIONS,
            ProfileList::Exceptions,
        )?;
        sort_unique(
            &mut document.capabilities,
            |c| *c,
            ProfileList::Capabilities,
        )?;
        sort_unique(
            &mut document.forbidden,
            |entry| entry.interface,
            ProfileList::Forbidden,
        )?;
        sort_unique(
            &mut document.protected_paths,
            Clone::clone,
            ProfileList::ProtectedPaths,
        )?;
        sort_unique(
            &mut document.required_tools,
            |tool| tool.name.clone(),
            ProfileList::RequiredTools,
        )?;
        for tool in &mut document.required_tools {
            sort_unique(&mut tool.interfaces, |i| *i, ProfileList::ToolInterfaces)?;
            sort_unique(
                &mut tool.capabilities,
                |c| *c,
                ProfileList::ToolCapabilities,
            )?;
        }
        sort_unique(
            &mut document.exceptions,
            |exception| (exception.target, exception.tool.clone()),
            ProfileList::Exceptions,
        )?;
        sort_unique(
            &mut document.kernel_settings,
            |s| *s,
            ProfileList::KernelSettings,
        )?;
        validate(&document)?;
        let digest = compute_digest(&document);
        Ok(Self { document, digest })
    }

    /// The built-in profile for `workload`. Each one validates; the result is a `Result`
    /// only so that nothing here can panic.
    pub fn builtin(workload: WorkloadProfile) -> Result<Self, ProfileRefusal> {
        Self::new(builtin_document(workload)?)
    }

    /// The profile's identity: a digest under its own domain over every field.
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    /// The normalized document.
    pub const fn document(&self) -> &ProfileDocument {
        &self.document
    }

    pub const fn workload(&self) -> WorkloadProfile {
        self.document.workload
    }

    pub const fn uid(&self) -> UidPolicy {
        self.document.uid
    }

    /// The exact capability set.
    pub fn capabilities(&self) -> BTreeSet<LinuxCapability> {
        self.document.capabilities.iter().copied().collect()
    }

    pub const fn no_new_privs(&self) -> bool {
        self.document.no_new_privs
    }

    /// The forbidden interfaces, in interface order.
    pub fn forbidden(&self) -> &[ForbiddenInterface] {
        &self.document.forbidden
    }

    /// How `interface` is refused; `None` when the profile does not forbid it.
    pub fn assignment(&self, interface: Interface) -> Option<&ForbiddenInterface> {
        self.document
            .forbidden
            .iter()
            .find(|entry| entry.interface == interface)
    }

    pub fn protected_paths(&self) -> &[ProtectedPath] {
        &self.document.protected_paths
    }

    pub fn required_tools(&self) -> &[RequiredTool] {
        &self.document.required_tools
    }

    pub fn exceptions(&self) -> &[ConfinementException] {
        &self.document.exceptions
    }

    pub fn kernel_settings(&self) -> &[KernelSetting] {
        &self.document.kernel_settings
    }

    /// Every mechanism the profile relies on, as primary or backup.
    pub fn mechanisms(&self) -> BTreeSet<Mechanism> {
        self.document
            .forbidden
            .iter()
            .flat_map(ForbiddenInterface::mechanisms)
            .collect()
    }

    /// The build options the profile relies on being absent: those of every interface
    /// refused by [`Mechanism::KernelOptionAbsent`].
    pub fn required_absent_options(&self) -> BTreeSet<KernelOption> {
        self.document
            .forbidden
            .iter()
            .filter(|entry| entry.uses(Mechanism::KernelOptionAbsent))
            .flat_map(|entry| entry.interface.kernel_options().iter().copied())
            .collect()
    }

    /// Whether the evaluator requires host corroboration: always for the strict profile
    /// (VM-CP-05), and whenever the profile relies on an absent kernel option or a
    /// kernel setting, which only the host's build record can show (§3.4, §8.1).
    pub fn requires_host_corroboration(&self) -> bool {
        self.document.workload.requires_host_corroboration()
            || !self.required_absent_options().is_empty()
            || !self.document.kernel_settings.is_empty()
    }

    /// The separated per-mechanism responsibilities (VM-W07).
    pub fn responsibilities(&self) -> ResponsibilityMap {
        ResponsibilityMap::of(&self.document.forbidden)
    }
}

impl Serialize for ConfinementProfile {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.document.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ConfinementProfile {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(ProfileDocument::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

fn bounded(count: usize, max: usize, list: ProfileList) -> Result<(), ProfileRefusal> {
    if count > max {
        return Err(ProfileRefusal::TooMany { list, count, max });
    }
    Ok(())
}

/// Sorts `items` by `key` and refuses two items with one key.
fn sort_unique<T, K: Ord>(
    items: &mut [T],
    key: impl Fn(&T) -> K,
    list: ProfileList,
) -> Result<(), ProfileRefusal> {
    items.sort_by_key(|item| key(item));
    let repeated = items.windows(2).any(|pair| match pair {
        [first, second] => key(first) == key(second),
        _ => false,
    });
    if repeated {
        return Err(ProfileRefusal::Duplicate { list });
    }
    Ok(())
}

fn validate(document: &ProfileDocument) -> Result<(), ProfileRefusal> {
    let workload = document.workload;
    let capabilities: BTreeSet<LinuxCapability> = document.capabilities.iter().copied().collect();
    let forbids = |interface: Interface| {
        document
            .forbidden
            .iter()
            .any(|entry| entry.interface == interface)
    };
    let excepted = |target: ExceptionTarget| {
        document
            .exceptions
            .iter()
            .any(|exception| exception.target == target)
    };

    if workload == WorkloadProfile::StrictTool && !document.no_new_privs {
        return Err(ProfileRefusal::NoNewPrivsRequired { workload });
    }

    let ceiling = workload.capability_ceiling();
    for capability in &capabilities {
        if capability.never_granted() {
            return Err(ProfileRefusal::CapabilityNeverGranted {
                capability: *capability,
            });
        }
        let target = ExceptionTarget::Capability {
            capability: *capability,
        };
        if !ceiling.contains(capability) && !excepted(target) {
            return Err(ProfileRefusal::CapabilityAboveCeiling {
                workload,
                capability: *capability,
            });
        }
    }

    let context = AssignmentContext {
        capabilities: &capabilities,
        no_new_privs: document.no_new_privs,
    };
    for entry in &document.forbidden {
        check_assignment(entry, &context)?;
        if let Some(capability) = entry
            .interface
            .granting_capabilities()
            .iter()
            .find(|capability| capabilities.contains(capability))
        {
            return Err(ProfileRefusal::CapabilityContradictsForbiddenInterface {
                capability: *capability,
                interface: entry.interface,
            });
        }
        if excepted(ExceptionTarget::Interface {
            interface: entry.interface,
        }) {
            return Err(ProfileRefusal::ForbiddenAndExcepted {
                interface: entry.interface,
            });
        }
    }

    let baseline = workload.baseline_forbidden();
    for interface in &baseline {
        if !forbids(*interface)
            && !excepted(ExceptionTarget::Interface {
                interface: *interface,
            })
        {
            return Err(ProfileRefusal::BaselineInterfaceUnaccounted {
                workload,
                interface: *interface,
            });
        }
    }

    for exception in &document.exceptions {
        let target = exception.target;
        let needed = match target {
            ExceptionTarget::Interface { interface } => baseline.contains(&interface),
            ExceptionTarget::Capability { capability } => !ceiling.contains(&capability),
        };
        if !needed {
            return Err(ProfileRefusal::ExceptionNotNeeded { target });
        }
        if !workload.admits_exception(target) {
            return Err(ProfileRefusal::ExceptionNotAdmitted { workload, target });
        }
        if let ExceptionTarget::Capability { capability } = target {
            if !capabilities.contains(&capability) {
                return Err(ProfileRefusal::ExceptionCapabilityNotHeld { capability });
            }
        }
        let tool = document
            .required_tools
            .iter()
            .find(|tool| tool.name == exception.tool)
            .ok_or_else(|| ProfileRefusal::ExceptionForUnknownTool {
                tool: exception.tool.clone(),
            })?;
        if !tool.needs(target) {
            return Err(ProfileRefusal::ExceptionToolDoesNotNeedTarget {
                tool: exception.tool.clone(),
                target,
            });
        }
    }

    if excepted(ExceptionTarget::Interface {
        interface: Interface::Ptrace,
    }) && !forbids(Interface::PtraceOtherUsers)
    {
        return Err(ProfileRefusal::PtraceExceptionNeedsOwnUserRule);
    }
    if document
        .forbidden
        .iter()
        .any(|entry| entry.interface == Interface::Ptrace && !entry.uses(Mechanism::Lsm))
    {
        return Err(ProfileRefusal::PtraceMemoryNeedsLsm);
    }

    for tool in &document.required_tools {
        let has_own_exception = |target: ExceptionTarget| {
            document
                .exceptions
                .iter()
                .any(|exception| exception.target == target && exception.tool == tool.name)
        };
        for interface in &tool.interfaces {
            if forbids(*interface) {
                return Err(ProfileRefusal::ToolNeedsForbiddenInterface {
                    tool: tool.name.clone(),
                    interface: *interface,
                });
            }
            let target = ExceptionTarget::Interface {
                interface: *interface,
            };
            if baseline.contains(interface) && !has_own_exception(target) {
                return Err(ProfileRefusal::ToolLacksException {
                    tool: tool.name.clone(),
                    target,
                });
            }
        }
        for capability in &tool.capabilities {
            if !capabilities.contains(capability) {
                return Err(ProfileRefusal::ToolNeedsMissingCapability {
                    tool: tool.name.clone(),
                    capability: *capability,
                });
            }
            let target = ExceptionTarget::Capability {
                capability: *capability,
            };
            if !ceiling.contains(capability) && !has_own_exception(target) {
                return Err(ProfileRefusal::ToolLacksException {
                    tool: tool.name.clone(),
                    target,
                });
            }
        }
    }

    let path_rule = forbids(Interface::ProtectedPathWrite);
    if !document.protected_paths.is_empty() && !path_rule {
        return Err(ProfileRefusal::ProtectedPathsWithoutMechanism);
    }
    if document.protected_paths.is_empty() && path_rule {
        return Err(ProfileRefusal::ProtectedPathMechanismWithoutPaths);
    }
    for text in workload.minimum_protected_paths() {
        let path = ProtectedPath::parse(text)?;
        if !document.protected_paths.contains(&path) {
            return Err(ProfileRefusal::MissingProtectedPath { path });
        }
    }
    if document
        .protected_paths
        .iter()
        .any(ProtectedPath::in_repository)
    {
        for text in REPOSITORY_PROTECTION {
            let path = ProtectedPath::parse(text)?;
            if !document.protected_paths.contains(&path) {
                return Err(ProfileRefusal::RepositoryProtectionIncomplete { path });
            }
        }
        if let Some(capability) = Mechanism::NamespaceCredentials
            .defeating_capabilities(Interface::ProtectedPathWrite)
            .iter()
            .find(|capability| capabilities.contains(capability))
        {
            return Err(ProfileRefusal::RepositoryProtectionDefeatedByCapability {
                capability: *capability,
            });
        }
    }

    if let Some(setting) = document
        .kernel_settings
        .iter()
        .find(|setting| setting.forced_by().is_empty())
    {
        return Err(ProfileRefusal::SettingHasNoHostEvidence { setting: *setting });
    }
    Ok(())
}

fn count(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}

/// Every field, in a fixed order, each list prefixed by its length.
fn compute_digest(document: &ProfileDocument) -> Digest {
    let mut builder = DigestBuilder::new(PROFILE_DIGEST_DOMAIN)
        .u64(u64::from(document.version))
        .str(document.workload.label());
    builder = match document.uid {
        UidPolicy::Fixed { uid, gid } => builder
            .str("fixed")
            .u64(u64::from(uid.get()))
            .u64(u64::from(gid.get())),
        UidPolicy::AnyNonRoot => builder.str("any_non_root"),
    };
    builder = builder.u64(count(document.capabilities.len()));
    for capability in &document.capabilities {
        builder = builder.str(capability.kernel_name());
    }
    builder = builder.u64(u64::from(document.no_new_privs));
    builder = builder.u64(count(document.forbidden.len()));
    for entry in &document.forbidden {
        builder = builder
            .str(entry.interface.label())
            .str(entry.primary.label())
            .str(entry.backup.map_or("none", Mechanism::label));
    }
    builder = builder.u64(count(document.protected_paths.len()));
    for path in &document.protected_paths {
        builder = builder.str(&path.to_text());
    }
    builder = builder.u64(count(document.required_tools.len()));
    for tool in &document.required_tools {
        builder = builder
            .str(tool.name.as_str())
            .u64(count(tool.interfaces.len()));
        for interface in &tool.interfaces {
            builder = builder.str(interface.label());
        }
        builder = builder.u64(count(tool.capabilities.len()));
        for capability in &tool.capabilities {
            builder = builder.str(capability.kernel_name());
        }
    }
    builder = builder.u64(count(document.exceptions.len()));
    for exception in &document.exceptions {
        builder = builder
            .str(exception.target.kind())
            .str(exception.target.name())
            .str(exception.tool.as_str())
            .str(exception.reason.as_str())
            .str(exception.owner.as_str());
    }
    builder = builder.u64(count(document.kernel_settings.len()));
    for setting in &document.kernel_settings {
        builder = builder.str(setting.label());
    }
    builder.finish()
}

fn tool(
    name: &str,
    interfaces: &[Interface],
    capabilities: &[LinuxCapability],
) -> Result<RequiredTool, ProfileRefusal> {
    Ok(RequiredTool {
        name: ToolName::new(name)?,
        interfaces: interfaces.to_vec(),
        capabilities: capabilities.to_vec(),
    })
}

/// The built-in documents (VM-R65, VM-CP-05). Seccomp is the primary for every
/// syscall-number rule; kexec and module loading also fail on the missing capability; the
/// strict profile removes io_uring from the kernel and protects its paths, VM-CP-05's and
/// the repository protection, with a read-only mount and credential separation. Every
/// profile that forbids ptrace backs seccomp with the LSM (Yama) for `/proc/<pid>/mem`.
fn builtin_document(workload: WorkloadProfile) -> Result<ProfileDocument, ProfileRefusal> {
    use Interface as I;
    use Mechanism as M;
    let seccomp = |interface| ForbiddenInterface::new(interface, M::Seccomp);
    let capability_backup =
        |interface| ForbiddenInterface::with_backup(interface, M::Seccomp, M::CapabilityAbsence);
    let mut forbidden = vec![
        seccomp(I::Bpf),
        seccomp(I::Userfaultfd),
        seccomp(I::PerfEventOpen),
        capability_backup(I::Kexec),
        capability_backup(I::ModuleLoading),
        seccomp(I::VsockSocket),
    ];
    let document =
        |uid, capabilities: &[LinuxCapability], forbidden, paths, tools| ProfileDocument {
            version: CONFINEMENT_PROFILE_VERSION,
            workload,
            uid,
            capabilities: capabilities.to_vec(),
            no_new_privs: true,
            forbidden,
            protected_paths: paths,
            required_tools: tools,
            exceptions: Vec::new(),
            kernel_settings: Vec::new(),
        };
    Ok(match workload {
        WorkloadProfile::StrictTool => {
            forbidden.extend([
                ForbiddenInterface::with_backup(I::IoUring, M::KernelOptionAbsent, M::Seccomp),
                ForbiddenInterface::with_backup(I::Ptrace, M::Seccomp, M::Lsm),
                ForbiddenInterface::with_backup(
                    I::ProtectedPathWrite,
                    M::ReadOnlyMount,
                    M::NamespaceCredentials,
                ),
            ]);
            document(
                UidPolicy::Fixed {
                    uid: STRICT_UID,
                    gid: STRICT_UID,
                },
                &[],
                forbidden,
                vec![
                    ProtectedPath::parse("~/.bashrc")?,
                    ProtectedPath::parse("~/.config/git/")?,
                    ProtectedPath::parse("~/.gitconfig")?,
                    ProtectedPath::parse(".git/")?,
                    ProtectedPath::parse(".git/hooks/")?,
                ],
                vec![
                    tool("git", &[], &[])?,
                    tool("python3", &[], &[])?,
                    tool("sh", &[], &[])?,
                ],
            )
        }
        WorkloadProfile::Developer => {
            forbidden.extend([
                seccomp(I::IoUring),
                // Credentials cannot hold this rule while the profile keeps setuid and
                // setgid, so the LSM (Yama) carries it.
                ForbiddenInterface::new(I::PtraceOtherUsers, M::Lsm),
            ]);
            document(
                UidPolicy::AnyNonRoot,
                &DEVELOPER_CAPABILITIES,
                forbidden,
                Vec::new(),
                vec![
                    tool("gdb", &[I::Ptrace], &[])?,
                    tool("git", &[], &[])?,
                    tool("make", &[], &[])?,
                    tool("sh", &[], &[])?,
                ],
            )
        }
        WorkloadProfile::Service => {
            forbidden.extend([
                seccomp(I::IoUring),
                ForbiddenInterface::with_backup(I::Ptrace, M::Seccomp, M::Lsm),
            ]);
            document(
                UidPolicy::AnyNonRoot,
                &[LinuxCapability::NetBindService],
                forbidden,
                Vec::new(),
                vec![tool("entrypoint", &[], &[LinuxCapability::NetBindService])?],
            )
        }
        WorkloadProfile::Device => {
            forbidden.extend([
                seccomp(I::IoUring),
                ForbiddenInterface::with_backup(I::Ptrace, M::Seccomp, M::Lsm),
            ]);
            document(
                UidPolicy::AnyNonRoot,
                &[],
                forbidden,
                Vec::new(),
                vec![RequiredTool::plain(ToolName::new("gpu-runtime")?)],
            )
        }
    })
}
