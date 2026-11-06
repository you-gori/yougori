//! Supervisor safety (VM part §6.4 lines 2325–2329; VM-P24 line 2797; VM-P49 line
//! 2647; §2.6 line 2013).
//!
//! The supervisor accepts only bounded, typed lifecycle messages over authenticated local
//! IPC: no path, URL or archive can be carried, and an oversized frame is refused before
//! parsing. Cleanup names a managed root the supervisor itself created plus a relative
//! path inside it, opened without following links; a guest-chosen path has no type here.
//! User source data is never cleaned. The fallback when the supervisor itself dies is
//! declared, and watchdogs cannot depend on one another.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::leases::ActivityKind;
use super::pool::VolumeKind;
use super::revocation::{Acknowledgment, GrantRevocationCause, RevocationCause};
use crate::foundation::ids::{
    digest, validate_identifier, Digest, ExecutionId, GrantId, IdError, MonotonicTime,
};

/// The longest relative path a cleanup message may carry, in bytes.
pub const MAX_PATH_BYTES: usize = 1024;
/// The longest component of such a path, in bytes.
const MAX_COMPONENT_BYTES: usize = 255;
/// The largest lifecycle message frame, in bytes (§6.4 "bounded lifecycle messages").
pub const MAX_FRAME_BYTES: usize = 4096;

/// Why a path was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum PathRefusal {
    Empty,
    TooLong {
        bytes: usize,
        max: usize,
    },
    /// A leading separator or a drive letter: an absolute path names a host location.
    Absolute,
    /// A `..` component would leave the root.
    ParentComponent,
    /// An empty or `.` component.
    EmptyComponent,
    ComponentTooLong {
        bytes: usize,
        max: usize,
    },
    /// A backslash, a colon (URL scheme, drive, alternate data stream), a control
    /// character or a tilde.
    ForbiddenCharacter {
        character: char,
    },
}

crate::foundation::strict_serde::strict_tag!(PathRefusal, "refusal");

impl fmt::Display for PathRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the path is empty"),
            Self::TooLong { bytes, max } => {
                write!(f, "the path is {bytes} bytes, longer than {max}")
            }
            Self::Absolute => f.write_str("an absolute path is never accepted"),
            Self::ParentComponent => f.write_str("a '..' component would leave the root"),
            Self::EmptyComponent => f.write_str("an empty or '.' component"),
            Self::ComponentTooLong { bytes, max } => {
                write!(f, "a component is {bytes} bytes, longer than {max}")
            }
            Self::ForbiddenCharacter { character } => {
                write!(f, "the path contains {character:?}")
            }
        }
    }
}

impl std::error::Error for PathRefusal {}

/// A relative path inside a managed root: forward-slash components, none empty, `.` or
/// `..`, no backslash, colon, tilde or control character, bounded in length.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RelativePath(String);

impl RelativePath {
    pub fn new(text: impl Into<String>) -> Result<Self, PathRefusal> {
        let text = text.into();
        if text.is_empty() {
            return Err(PathRefusal::Empty);
        }
        if text.len() > MAX_PATH_BYTES {
            return Err(PathRefusal::TooLong {
                bytes: text.len(),
                max: MAX_PATH_BYTES,
            });
        }
        if let Some(character) = text
            .chars()
            .find(|character| matches!(character, '\\' | ':' | '~') || character.is_control())
        {
            return Err(PathRefusal::ForbiddenCharacter { character });
        }
        if text.starts_with('/') {
            return Err(PathRefusal::Absolute);
        }
        for component in text.split('/') {
            match component {
                "" | "." => return Err(PathRefusal::EmptyComponent),
                ".." => return Err(PathRefusal::ParentComponent),
                _ => {}
            }
            if component.len() > MAX_COMPONENT_BYTES {
                return Err(PathRefusal::ComponentTooLong {
                    bytes: component.len(),
                    max: MAX_COMPONENT_BYTES,
                });
            }
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }
}

impl<'de> Deserialize<'de> for RelativePath {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for RelativePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A managed root, by the identity the supervisor gave it when it created it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ManagedRootId(Digest);

impl ManagedRootId {
    pub const DOMAIN: &'static str = "yougori/lifecycle/managed-root/v1";

    pub const fn digest(self) -> Digest {
        self.0
    }
}

impl fmt::Debug for ManagedRootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ManagedRootId({})", self.0)
    }
}

impl fmt::Display for ManagedRootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A root the supervisor created for one sandbox (§6.4 "verified managed roots").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRoot {
    pub id: ManagedRootId,
    pub sandbox: ExecutionId,
    pub kind: VolumeKind,
    pub created_at: MonotonicTime,
}

/// What a cleanup names: a managed root and a relative path inside it. There is no way to
/// build one from a path a guest chose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupTarget {
    pub root: ManagedRootId,
    pub path: RelativePath,
}

/// How a cleanup opens what it deletes (§6.4 "resists reparse/symlink races").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenMode {
    /// Open relative to the root's handle, never following symlinks or reparse points,
    /// and verify the object's identity after opening.
    RootHandleNoFollowVerified,
}

/// A cleanup the supervisor will perform: the target, the root it was checked against and
/// the one open mode. Only [`ManagedRoots::plan_cleanup`] makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CleanupPlan {
    pub target: CleanupTarget,
    pub root: ManagedRoot,
    pub open_mode: OpenMode,
}

/// Why a cleanup was refused (§2.6 "cleanup cannot follow guest-created paths outside the
/// supervisor's managed roots").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum CleanupRefusal {
    /// No managed root has this identity; a guest cannot name one into existence.
    UnknownRoot { root: ManagedRootId },
    /// The root belongs to another sandbox.
    OtherSandbox {
        root: ManagedRootId,
        owner: ExecutionId,
    },
    /// User source data is preserved (VM-W24).
    UserSourcePreserved { root: ManagedRootId },
}

crate::foundation::strict_serde::strict_tag!(CleanupRefusal, "refusal");

impl fmt::Display for CleanupRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRoot { root } => write!(f, "{root} is not a managed root"),
            Self::OtherSandbox { root, owner } => {
                write!(f, "managed root {root} belongs to sandbox {owner}")
            }
            Self::UserSourcePreserved { root } => {
                write!(
                    f,
                    "managed root {root} holds user source data and is preserved"
                )
            }
        }
    }
}

impl std::error::Error for CleanupRefusal {}

/// The managed roots a supervisor created.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRoots {
    roots: BTreeMap<ManagedRootId, ManagedRoot>,
    next: u64,
}

impl ManagedRoots {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a root for `sandbox`; its identity is the supervisor's, derived from the
    /// sandbox and a counter, never from anything the guest supplied.
    pub fn create(
        &mut self,
        sandbox: &ExecutionId,
        kind: VolumeKind,
        now: MonotonicTime,
    ) -> ManagedRootId {
        self.next = self.next.saturating_add(1);
        let id = ManagedRootId(digest(
            ManagedRootId::DOMAIN,
            &[sandbox.as_str().as_bytes(), &self.next.to_be_bytes()],
        ));
        self.roots.insert(
            id,
            ManagedRoot {
                id,
                sandbox: sandbox.clone(),
                kind,
                created_at: now,
            },
        );
        id
    }

    pub fn get(&self, root: ManagedRootId) -> Option<&ManagedRoot> {
        self.roots.get(&root)
    }

    /// The roots of `sandbox`.
    pub fn of<'a>(
        &'a self,
        sandbox: &'a ExecutionId,
    ) -> impl Iterator<Item = &'a ManagedRoot> + 'a {
        self.roots
            .values()
            .filter(move |root| &root.sandbox == sandbox)
    }

    /// Plans a cleanup of `target` for `sandbox`: the root must exist, belong to the
    /// sandbox and not hold user source data. The path was bounded by its type.
    pub fn plan_cleanup(
        &self,
        sandbox: &ExecutionId,
        target: CleanupTarget,
    ) -> Result<CleanupPlan, CleanupRefusal> {
        let root = self
            .roots
            .get(&target.root)
            .ok_or(CleanupRefusal::UnknownRoot { root: target.root })?;
        if &root.sandbox != sandbox {
            return Err(CleanupRefusal::OtherSandbox {
                root: target.root,
                owner: root.sandbox.clone(),
            });
        }
        if root.kind.is_user_source() {
            return Err(CleanupRefusal::UserSourcePreserved { root: target.root });
        }
        Ok(CleanupPlan {
            target,
            root: root.clone(),
            open_mode: OpenMode::RootHandleNoFollowVerified,
        })
    }

    /// Forgets the roots of `sandbox` once their cleanup finished.
    pub fn release(&mut self, sandbox: &ExecutionId) -> usize {
        let before = self.roots.len();
        self.roots.retain(|_, root| &root.sandbox != sandbox);
        before.saturating_sub(self.roots.len())
    }
}

/// A lifecycle message the supervisor accepts (§6.4 "only bounded lifecycle messages").
/// Every field is typed: identifiers follow the ids.rs grammar, paths are relative paths
/// in managed roots, and nothing can carry a URL, a host path or an archive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "message", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum LifecycleMessage {
    Activity {
        execution: ExecutionId,
        kind: ActivityKind,
    },
    Acknowledge {
        execution: ExecutionId,
        acknowledgment: Acknowledgment,
    },
    Revoke {
        execution: ExecutionId,
        cause: RevocationCause,
    },
    /// Revokes one grant under the sandbox's authority and nothing else (§6.3 step 1).
    RevokeGrant {
        execution: ExecutionId,
        grant: GrantId,
        cause: GrantRevocationCause,
    },
    Stop {
        execution: ExecutionId,
    },
    Cleanup {
        execution: ExecutionId,
        target: CleanupTarget,
    },
}

crate::foundation::strict_serde::strict_tag!(LifecycleMessage, "message");

impl LifecycleMessage {
    pub fn execution(&self) -> &ExecutionId {
        match self {
            Self::Activity { execution, .. }
            | Self::Acknowledge { execution, .. }
            | Self::Revoke { execution, .. }
            | Self::RevokeGrant { execution, .. }
            | Self::Stop { execution }
            | Self::Cleanup { execution, .. } => execution,
        }
    }
}

/// Who sent a frame (§6.4 "authenticated local IPC").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "peer", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum PeerIdentity {
    /// A local principal the IPC layer authenticated.
    Authenticated {
        principal: String,
    },
    Unauthenticated,
}

crate::foundation::strict_serde::strict_tag!(PeerIdentity, "peer");

/// Why a frame was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum FrameRefusal {
    Unauthenticated,
    TooLarge {
        bytes: usize,
        max: usize,
    },
    /// Malformed, an unknown message, an unknown field, or a value outside its type.
    Malformed {
        detail: String,
    },
    /// The principal is not an identifier of the shared grammar.
    BadPrincipal {
        error: String,
    },
}

crate::foundation::strict_serde::strict_tag!(FrameRefusal, "refusal");

impl fmt::Display for FrameRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthenticated => f.write_str("the peer is not authenticated"),
            Self::TooLarge { bytes, max } => {
                write!(f, "the frame is {bytes} bytes, larger than {max}")
            }
            Self::Malformed { detail } => write!(f, "the frame is malformed: {detail}"),
            Self::BadPrincipal { error } => write!(f, "the principal is refused: {error}"),
        }
    }
}

impl std::error::Error for FrameRefusal {}

/// One frame of authenticated local IPC.
pub struct MessageFrame;

impl MessageFrame {
    /// Parses one frame from `peer`: refused unauthenticated, refused above
    /// [`MAX_FRAME_BYTES`] before parsing, and refused on any field the message type does
    /// not name. The detail of a malformed frame is bounded.
    pub fn parse(peer: &PeerIdentity, bytes: &[u8]) -> Result<LifecycleMessage, FrameRefusal> {
        match peer {
            PeerIdentity::Unauthenticated => return Err(FrameRefusal::Unauthenticated),
            PeerIdentity::Authenticated { principal } => {
                validate_identifier(principal).map_err(|error: IdError| {
                    FrameRefusal::BadPrincipal {
                        error: error.to_string(),
                    }
                })?;
            }
        }
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(FrameRefusal::TooLarge {
                bytes: bytes.len(),
                max: MAX_FRAME_BYTES,
            });
        }
        serde_json::from_slice(bytes).map_err(|error| FrameRefusal::Malformed {
            detail: error.to_string().chars().take(200).collect(),
        })
    }
}

/// The declared fallback when the supervisor itself dies (§6.4 "OS-enforced child/job
/// cleanup or a service manager must provide the declared fallback").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "fallback", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum SupervisorDeathFallback {
    /// The OS job or child relationship ends every VM with the supervisor; nothing
    /// survives, so nothing holds authority.
    OsJobCleanup,
    /// A service manager restarts the supervisor within `restart_within`; it recovers,
    /// revives no authority and re-authorizes what it finds alive.
    ServiceManagerRestart { restart_within: Duration },
}

crate::foundation::strict_serde::strict_tag!(SupervisorDeathFallback, "fallback");

/// A watchdog, by name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WatchdogId(String);

impl WatchdogId {
    pub fn new(name: impl Into<String>) -> Result<Self, IdError> {
        let name = name.into();
        validate_identifier(&name)?;
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WatchdogId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a watchdog dependency was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum WatchdogRefusal {
    /// The dependency would close a cycle: a chain of watchdogs all waiting for one
    /// another (§6.4).
    MutualDependency {
        cycle: Vec<WatchdogId>,
    },
    SelfWatch {
        watchdog: WatchdogId,
    },
}

crate::foundation::strict_serde::strict_tag!(WatchdogRefusal, "refusal");

impl fmt::Display for WatchdogRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MutualDependency { cycle } => {
                let names: Vec<&str> = cycle.iter().map(WatchdogId::as_str).collect();
                write!(
                    f,
                    "watchdogs would wait for one another: {}",
                    names.join(" -> ")
                )
            }
            Self::SelfWatch { watchdog } => write!(f, "{watchdog} cannot watch itself"),
        }
    }
}

impl std::error::Error for WatchdogRefusal {}

/// Who watches whom. A dependency that would make watchdogs wait for one another is
/// refused when declared.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchdogGraph {
    watches: BTreeMap<WatchdogId, BTreeSet<WatchdogId>>,
}

impl WatchdogGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `from` reaches `to` through declared watches.
    fn path(&self, from: &WatchdogId, to: &WatchdogId) -> Option<Vec<WatchdogId>> {
        let mut stack = vec![(from.clone(), vec![from.clone()])];
        let mut seen = BTreeSet::new();
        while let Some((current, trail)) = stack.pop() {
            if &current == to {
                return Some(trail);
            }
            if !seen.insert(current.clone()) {
                continue;
            }
            if let Some(next) = self.watches.get(&current) {
                for watched in next {
                    let mut trail = trail.clone();
                    trail.push(watched.clone());
                    stack.push((watched.clone(), trail));
                }
            }
        }
        None
    }

    /// Declares that `watcher` watches `watched`, unless that closes a cycle.
    pub fn declare(
        &mut self,
        watcher: WatchdogId,
        watched: WatchdogId,
    ) -> Result<(), WatchdogRefusal> {
        if watcher == watched {
            return Err(WatchdogRefusal::SelfWatch { watchdog: watcher });
        }
        if let Some(mut cycle) = self.path(&watched, &watcher) {
            cycle.push(watched.clone());
            return Err(WatchdogRefusal::MutualDependency { cycle });
        }
        self.watches.entry(watcher).or_default().insert(watched);
        Ok(())
    }

    pub fn watched_by(&self, watcher: &WatchdogId) -> impl Iterator<Item = &WatchdogId> {
        self.watches.get(watcher).into_iter().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execution(name: &str) -> ExecutionId {
        ExecutionId::new(name).unwrap()
    }

    fn peer() -> PeerIdentity {
        PeerIdentity::Authenticated {
            principal: "engine".to_owned(),
        }
    }

    #[test]
    fn relative_paths_refuse_everything_that_could_leave_a_root() {
        assert!(RelativePath::new("work/out/result.txt").is_ok());
        assert_eq!(RelativePath::new(""), Err(PathRefusal::Empty));
        assert_eq!(RelativePath::new("/etc/passwd"), Err(PathRefusal::Absolute));
        assert_eq!(
            RelativePath::new("D:/data"),
            Err(PathRefusal::ForbiddenCharacter { character: ':' })
        );
        assert_eq!(
            RelativePath::new("a\\b"),
            Err(PathRefusal::ForbiddenCharacter { character: '\\' })
        );
        assert_eq!(
            RelativePath::new("http://example.test/x"),
            Err(PathRefusal::ForbiddenCharacter { character: ':' })
        );
        assert_eq!(
            RelativePath::new("a/../b"),
            Err(PathRefusal::ParentComponent)
        );
        assert_eq!(RelativePath::new(".."), Err(PathRefusal::ParentComponent));
        assert_eq!(RelativePath::new("a//b"), Err(PathRefusal::EmptyComponent));
        assert_eq!(RelativePath::new("./a"), Err(PathRefusal::EmptyComponent));
        assert_eq!(RelativePath::new("a/"), Err(PathRefusal::EmptyComponent));
        assert_eq!(
            RelativePath::new("~/a"),
            Err(PathRefusal::ForbiddenCharacter { character: '~' })
        );
        assert_eq!(
            RelativePath::new("a\0b"),
            Err(PathRefusal::ForbiddenCharacter { character: '\0' })
        );
        assert_eq!(
            RelativePath::new("x".repeat(MAX_PATH_BYTES + 1)),
            Err(PathRefusal::TooLong {
                bytes: MAX_PATH_BYTES + 1,
                max: MAX_PATH_BYTES
            })
        );
        assert_eq!(
            RelativePath::new(format!("a/{}", "x".repeat(256))),
            Err(PathRefusal::ComponentTooLong {
                bytes: 256,
                max: 255
            })
        );
        assert!(serde_json::from_str::<RelativePath>("\"../x\"").is_err());
    }

    #[test]
    fn cleanup_follows_only_supervisor_created_roots_of_the_same_sandbox() {
        let mut roots = ManagedRoots::new();
        let overlay = roots.create(
            &execution("exe-a"),
            VolumeKind::ExecutableEnvironmentCache,
            MonotonicTime::ZERO,
        );
        let source = roots.create(
            &execution("exe-a"),
            VolumeKind::SourceWorkspace,
            MonotonicTime::ZERO,
        );
        let other = roots.create(
            &execution("exe-b"),
            VolumeKind::UnreviewedOutput,
            MonotonicTime::ZERO,
        );
        let path = RelativePath::new("tmp/build").unwrap();
        let plan = roots
            .plan_cleanup(
                &execution("exe-a"),
                CleanupTarget {
                    root: overlay,
                    path: path.clone(),
                },
            )
            .unwrap();
        assert_eq!(plan.open_mode, OpenMode::RootHandleNoFollowVerified);
        let guest_claimed = ManagedRootId(digest("yougori/test/guest-root/v1", &[b"/"]));
        assert_eq!(
            roots.plan_cleanup(
                &execution("exe-a"),
                CleanupTarget {
                    root: guest_claimed,
                    path: path.clone()
                }
            ),
            Err(CleanupRefusal::UnknownRoot {
                root: guest_claimed
            })
        );
        assert_eq!(
            roots.plan_cleanup(
                &execution("exe-a"),
                CleanupTarget {
                    root: other,
                    path: path.clone()
                }
            ),
            Err(CleanupRefusal::OtherSandbox {
                root: other,
                owner: execution("exe-b")
            })
        );
        assert_eq!(
            roots.plan_cleanup(&execution("exe-a"), CleanupTarget { root: source, path }),
            Err(CleanupRefusal::UserSourcePreserved { root: source })
        );
        assert_eq!(roots.release(&execution("exe-a")), 2);
        assert_eq!(roots.of(&execution("exe-b")).count(), 1);
    }

    #[test]
    fn frames_are_bounded_typed_and_authenticated() {
        let activity = serde_json::json!({
            "message": "activity", "execution": "exe-a", "kind": "command"
        });
        let parsed = MessageFrame::parse(&peer(), activity.to_string().as_bytes()).unwrap();
        assert_eq!(
            parsed,
            LifecycleMessage::Activity {
                execution: execution("exe-a"),
                kind: ActivityKind::Command
            }
        );
        assert_eq!(
            MessageFrame::parse(
                &PeerIdentity::Unauthenticated,
                activity.to_string().as_bytes()
            ),
            Err(FrameRefusal::Unauthenticated)
        );
        assert!(matches!(
            MessageFrame::parse(
                &PeerIdentity::Authenticated {
                    principal: "bad principal".to_owned()
                },
                activity.to_string().as_bytes()
            ),
            Err(FrameRefusal::BadPrincipal { .. })
        ));
        let with_path = serde_json::json!({
            "message": "stop", "execution": "exe-a", "cleanup_path": "/var/lib/vm"
        });
        assert!(matches!(
            MessageFrame::parse(&peer(), with_path.to_string().as_bytes()),
            Err(FrameRefusal::Malformed { .. })
        ));
        let with_url = serde_json::json!({
            "message": "cleanup", "execution": "exe-a",
            "target": {"root": "00".repeat(32), "path": "https://example.test/archive.tar"}
        });
        assert!(matches!(
            MessageFrame::parse(&peer(), with_url.to_string().as_bytes()),
            Err(FrameRefusal::Malformed { .. })
        ));
        let unknown = serde_json::json!({"message": "exec", "execution": "exe-a", "argv": ["sh"]});
        assert!(matches!(
            MessageFrame::parse(&peer(), unknown.to_string().as_bytes()),
            Err(FrameRefusal::Malformed { .. })
        ));
        let huge = vec![b' '; MAX_FRAME_BYTES + 1];
        assert_eq!(
            MessageFrame::parse(&peer(), &huge),
            Err(FrameRefusal::TooLarge {
                bytes: MAX_FRAME_BYTES + 1,
                max: MAX_FRAME_BYTES
            })
        );
        let garbage = MessageFrame::parse(&peer(), &vec![b'{'; 300]).unwrap_err();
        if let FrameRefusal::Malformed { detail } = garbage {
            assert!(detail.chars().count() <= 200);
        } else {
            panic!("{garbage:?}");
        }
    }

    #[test]
    fn watchdogs_cannot_wait_for_one_another() {
        let mut graph = WatchdogGraph::new();
        let (a, b, c) = (
            WatchdogId::new("supervisor").unwrap(),
            WatchdogId::new("engine").unwrap(),
            WatchdogId::new("relay").unwrap(),
        );
        graph.declare(a.clone(), b.clone()).unwrap();
        graph.declare(b.clone(), c.clone()).unwrap();
        assert_eq!(
            graph.declare(c.clone(), a.clone()),
            Err(WatchdogRefusal::MutualDependency {
                cycle: vec![a.clone(), b.clone(), c.clone(), a.clone()]
            })
        );
        assert_eq!(
            graph.declare(b.clone(), a.clone()),
            Err(WatchdogRefusal::MutualDependency {
                cycle: vec![a.clone(), b.clone(), a.clone()]
            })
        );
        assert_eq!(
            graph.declare(a.clone(), a.clone()),
            Err(WatchdogRefusal::SelfWatch {
                watchdog: a.clone()
            })
        );
        assert_eq!(graph.watched_by(&a).count(), 1);
        assert_eq!(
            serde_json::to_value(SupervisorDeathFallback::OsJobCleanup).unwrap(),
            serde_json::json!({"fallback": "os_job_cleanup"})
        );
    }
}
