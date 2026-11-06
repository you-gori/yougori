//! VM-D15's narrow privileged launcher (line 3209: "a narrow privileged launcher around
//! the official jailer first"; §7.2 line 2370: prefer a narrow privileged launcher using
//! supported jailer behavior over reimplementing it; VM-P49 line 2824: a stale PID, a
//! reused handle or a malicious path cannot cause unrelated termination or deletion).
//!
//! The launcher may perform, for one launch, only the operations a [`LauncherPlan`]
//! lists, each with exactly the planned parameters:
//!
//! 1. create the launch's network namespace, which holds only `lo` unless the profile
//!    declares a network interface, and then one tap device per declared interface;
//! 2. create the chroot and the image directory, root-owned;
//! 3. stage the pinned kernel and root image into the jail, root-owned and read-only,
//!    from the content-addressed artifact directory;
//! 4. create the private socket directory where Firecracker binds the API and link
//!    sockets, and the host-owned sink directory with the logger and metrics pipes;
//! 5. execute the official jailer once, with the exact argument vector and the pinned
//!    jailer and Firecracker binaries, without a shell.
//!
//! After the jailer runs, it may terminate the jail through the launch's own cgroup
//! (`cgroup.kill`, never a PID) and remove the cgroup, the jail directory and the network
//! namespace, in that order, each only if the launch created it and each once. Setup in
//! any other order, a repeat, setup after cleanup has begun, an operation with other
//! parameters, and any operation outside this closed set are refused. Requests arrive as
//! JSON over the launcher's channel; [`PrivilegedOperation::from_json`] refuses an unknown
//! operation by name before anything else is read, and a tag that is not a string or a key
//! repeated in one object as malformed.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::host::HostOwner;
use super::layout;
use super::names::{HostPath, InterfaceName, JailIdentity, NameError};
use crate::foundation::ids::ContentKey;

/// The longest launcher request accepted, in bytes.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// Mode of the chroot and the image directory.
pub const ROOT_DIRECTORY_MODE: u32 = 0o755;
/// Mode of a staged artifact: readable, writable by nobody.
pub const ARTIFACT_MODE: u32 = 0o444;
/// Mode of the private socket directory: the jail and the host owner's group only.
pub const SOCKET_DIRECTORY_MODE: u32 = 0o770;
/// Mode of the host-owned sink directory: the jail may enter it, not change it.
pub const SINK_DIRECTORY_MODE: u32 = 0o750;
/// Mode of a sink pipe: the host owner and the jail's group may read and write it.
pub const SINK_MODE: u32 = 0o660;

/// Which pinned artifact a staging operation copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    Kernel,
    RootImage,
}

/// Which host-owned sink a pipe serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkKind {
    Logger,
    Metrics,
}

/// The closed set of privileged operations (VM-D15). Any other request is refused. A
/// request reads only with its tag as a string and no key repeated in one object, at the
/// top level or nested in another record (`foundation::strict_serde`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum PrivilegedOperation {
    CreateNetworkNamespace {
        netns: HostPath,
    },
    CreateTapDevice {
        netns: HostPath,
        device: InterfaceName,
        owner: JailIdentity,
    },
    CreateDirectory {
        path: HostPath,
        owner_uid: u32,
        group_gid: u32,
        mode: u32,
    },
    StageArtifact {
        role: ArtifactRole,
        source: HostPath,
        target: HostPath,
        content_key: ContentKey,
        length_bytes: u64,
        mode: u32,
    },
    CreateSink {
        kind: SinkKind,
        path: HostPath,
        owner_uid: u32,
        group_gid: u32,
        mode: u32,
    },
    RunJailer {
        argv: Vec<String>,
        jailer_content_key: ContentKey,
        exec_content_key: ContentKey,
    },
    /// Writes `1` to the launch's own `cgroup.kill`.
    TerminateJail {
        cgroup: HostPath,
    },
    RemoveCgroup {
        cgroup: HostPath,
    },
    RemoveJail {
        jail_dir: HostPath,
    },
    RemoveNetworkNamespace {
        netns: HostPath,
    },
}

crate::foundation::strict_serde::strict_tag!(PrivilegedOperation, "op");

/// The tag of every operation in the closed set.
pub const OPERATION_TAGS: [&str; 10] = [
    "create_network_namespace",
    "create_tap_device",
    "create_directory",
    "stage_artifact",
    "create_sink",
    "run_jailer",
    "terminate_jail",
    "remove_cgroup",
    "remove_jail",
    "remove_network_namespace",
];

impl PrivilegedOperation {
    /// The operation's tag, as it appears in a request.
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::CreateNetworkNamespace { .. } => "create_network_namespace",
            Self::CreateTapDevice { .. } => "create_tap_device",
            Self::CreateDirectory { .. } => "create_directory",
            Self::StageArtifact { .. } => "stage_artifact",
            Self::CreateSink { .. } => "create_sink",
            Self::RunJailer { .. } => "run_jailer",
            Self::TerminateJail { .. } => "terminate_jail",
            Self::RemoveCgroup { .. } => "remove_cgroup",
            Self::RemoveJail { .. } => "remove_jail",
            Self::RemoveNetworkNamespace { .. } => "remove_network_namespace",
        }
    }

    /// Whether the operation ends a launch rather than sets one up.
    pub const fn is_cleanup(&self) -> bool {
        matches!(
            self,
            Self::TerminateJail { .. }
                | Self::RemoveCgroup { .. }
                | Self::RemoveJail { .. }
                | Self::RemoveNetworkNamespace { .. }
        )
    }

    /// Reads one request. An operation outside the closed set is refused by name; a
    /// known operation with a missing, extra or malformed field, a tag that is not a
    /// string, or a key repeated in one object is refused as malformed.
    pub fn from_json(text: &str) -> Result<Self, LauncherRefusal> {
        if text.len() > MAX_REQUEST_BYTES {
            return Err(LauncherRefusal::TooLarge {
                bytes: text.len(),
                max_bytes: MAX_REQUEST_BYTES,
            });
        }
        let value: Value =
            serde_json::from_str(text).map_err(|error| LauncherRefusal::Malformed {
                detail: error.to_string(),
            })?;
        let Some(op) = value.get("op").and_then(Value::as_str) else {
            return Err(LauncherRefusal::Malformed {
                detail: "the request names no operation".to_owned(),
            });
        };
        if !OPERATION_TAGS.contains(&op) {
            return Err(LauncherRefusal::OutsideClosedSet {
                op: op.chars().take(64).collect(),
            });
        }
        // Read from the text again, not from `value`, which kept only the last of a
        // repeated key.
        serde_json::from_str(text).map_err(|error| LauncherRefusal::Malformed {
            detail: error.to_string(),
        })
    }
}

/// Why the launcher refused an operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum LauncherRefusal {
    TooLarge {
        bytes: usize,
        max_bytes: usize,
    },
    Malformed {
        detail: String,
    },
    /// The operation is not one the launcher can ever perform.
    OutsideClosedSet {
        op: String,
    },
    /// The operation is in the closed set, but not with these parameters for this launch.
    NotPlanned {
        op: &'static str,
    },
    /// A planned setup operation ahead of its turn.
    OutOfOrder {
        op: &'static str,
        expected: &'static str,
    },
    AlreadyPerformed {
        op: &'static str,
    },
    /// Cleanup has begun, so nothing is set up again.
    SetupAfterCleanup {
        op: &'static str,
    },
    /// The launch never created what the cleanup operation would remove.
    NothingCreated {
        op: &'static str,
    },
    /// A cleanup operation after a later one.
    CleanupOutOfOrder {
        op: &'static str,
    },
}

impl fmt::Display for LauncherRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes, max_bytes } => {
                write!(f, "the request is {bytes} bytes, more than {max_bytes}")
            }
            Self::Malformed { detail } => write!(f, "the request is malformed: {detail}"),
            Self::OutsideClosedSet { op } => write!(
                f,
                "{op:?} is not an operation of the privileged launcher, which performs only \
                 its closed set"
            ),
            Self::NotPlanned { op } => {
                write!(f, "this {op} operation is not planned for this launch")
            }
            Self::OutOfOrder { op, expected } => {
                write!(
                    f,
                    "{op} is out of order; the next planned operation is {expected}"
                )
            }
            Self::AlreadyPerformed { op } => write!(f, "this {op} operation was already performed"),
            Self::SetupAfterCleanup { op } => {
                write!(f, "cleanup has begun, so {op} is refused")
            }
            Self::NothingCreated { op } => {
                write!(
                    f,
                    "{op} is refused: this launch never created what it removes"
                )
            }
            Self::CleanupOutOfOrder { op } => {
                write!(f, "{op} is refused after a later cleanup step")
            }
        }
    }
}

impl std::error::Error for LauncherRefusal {}

/// One cleanup step and the setup step that creates what it removes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CleanupStep {
    pub operation: PrivilegedOperation,
    /// The index of the setup operation that creates the resource.
    pub created_by: usize,
}

/// A pinned artifact to stage: where the verified copy lies and what it must be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StagedArtifact {
    pub(super) source: HostPath,
    pub(super) content_key: ContentKey,
    pub(super) length_bytes: u64,
}

/// Everything the launcher plan is derived from.
pub(super) struct LauncherInputs {
    pub(super) netns: HostPath,
    pub(super) taps: Vec<InterfaceName>,
    pub(super) identity: JailIdentity,
    pub(super) owner: HostOwner,
    pub(super) jail_dir: HostPath,
    pub(super) chroot_dir: HostPath,
    pub(super) kernel: StagedArtifact,
    pub(super) root_image: StagedArtifact,
    pub(super) argv: Vec<String>,
    pub(super) jailer_content_key: ContentKey,
    pub(super) exec_content_key: ContentKey,
    pub(super) cgroup: HostPath,
}

/// The privileged operations of one launch, in order, and its cleanup steps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LauncherPlan {
    setup: Vec<PrivilegedOperation>,
    cleanup: Vec<CleanupStep>,
}

impl LauncherPlan {
    pub(super) fn new(inputs: LauncherInputs) -> Result<Self, NameError> {
        let in_jail = |fixed: &'static str| inputs.chroot_dir.within(&layout::path(fixed));
        let mut setup = vec![PrivilegedOperation::CreateNetworkNamespace {
            netns: inputs.netns.clone(),
        }];
        for device in &inputs.taps {
            setup.push(PrivilegedOperation::CreateTapDevice {
                netns: inputs.netns.clone(),
                device: device.clone(),
                owner: inputs.identity,
            });
        }
        let jail_created_by = setup.len();
        setup.push(PrivilegedOperation::CreateDirectory {
            path: inputs.chroot_dir.clone(),
            owner_uid: 0,
            group_gid: 0,
            mode: ROOT_DIRECTORY_MODE,
        });
        setup.push(PrivilegedOperation::CreateDirectory {
            path: in_jail(layout::IMAGE_DIRECTORY)?,
            owner_uid: 0,
            group_gid: 0,
            mode: ROOT_DIRECTORY_MODE,
        });
        for (role, artifact, fixed) in [
            (ArtifactRole::Kernel, &inputs.kernel, layout::KERNEL_IMAGE),
            (
                ArtifactRole::RootImage,
                &inputs.root_image,
                layout::ROOT_IMAGE,
            ),
        ] {
            setup.push(PrivilegedOperation::StageArtifact {
                role,
                source: artifact.source.clone(),
                target: in_jail(fixed)?,
                content_key: artifact.content_key,
                length_bytes: artifact.length_bytes,
                mode: ARTIFACT_MODE,
            });
        }
        setup.push(PrivilegedOperation::CreateDirectory {
            path: in_jail(layout::SOCKET_DIRECTORY)?,
            owner_uid: inputs.identity.uid,
            group_gid: inputs.owner.gid,
            mode: SOCKET_DIRECTORY_MODE,
        });
        setup.push(PrivilegedOperation::CreateDirectory {
            path: in_jail(layout::SINK_DIRECTORY)?,
            owner_uid: inputs.owner.uid,
            group_gid: inputs.identity.gid,
            mode: SINK_DIRECTORY_MODE,
        });
        for (kind, fixed) in [
            (SinkKind::Logger, layout::LOG_SINK),
            (SinkKind::Metrics, layout::METRICS_SINK),
        ] {
            setup.push(PrivilegedOperation::CreateSink {
                kind,
                path: in_jail(fixed)?,
                owner_uid: inputs.owner.uid,
                group_gid: inputs.identity.gid,
                mode: SINK_MODE,
            });
        }
        let jailer_created_by = setup.len();
        setup.push(PrivilegedOperation::RunJailer {
            argv: inputs.argv,
            jailer_content_key: inputs.jailer_content_key,
            exec_content_key: inputs.exec_content_key,
        });
        let cleanup = vec![
            CleanupStep {
                operation: PrivilegedOperation::TerminateJail {
                    cgroup: inputs.cgroup.clone(),
                },
                created_by: jailer_created_by,
            },
            CleanupStep {
                operation: PrivilegedOperation::RemoveCgroup {
                    cgroup: inputs.cgroup,
                },
                created_by: jailer_created_by,
            },
            CleanupStep {
                operation: PrivilegedOperation::RemoveJail {
                    jail_dir: inputs.jail_dir,
                },
                created_by: jail_created_by,
            },
            CleanupStep {
                operation: PrivilegedOperation::RemoveNetworkNamespace {
                    netns: inputs.netns,
                },
                created_by: 0,
            },
        ];
        Ok(Self { setup, cleanup })
    }

    /// The setup operations, in the only order the launcher accepts them.
    pub fn setup(&self) -> &[PrivilegedOperation] {
        &self.setup
    }

    /// The cleanup steps, in the only order the launcher accepts them.
    pub fn cleanup(&self) -> &[CleanupStep] {
        &self.cleanup
    }

    /// A session that authorizes this plan's operations one by one.
    pub fn session(&self) -> LauncherSession {
        LauncherSession {
            plan: self.clone(),
            performed_setup: 0,
            cleanup_done: vec![false; self.cleanup.len()],
            last_cleanup: None,
        }
    }
}

/// What the launcher may now do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum Authorized {
    Setup { step: usize },
    Cleanup { step: usize },
}

/// The launcher's state for one launch: which setup operations it performed and which
/// cleanup steps it took.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LauncherSession {
    plan: LauncherPlan,
    performed_setup: usize,
    cleanup_done: Vec<bool>,
    last_cleanup: Option<usize>,
}

impl LauncherSession {
    /// Authorizes one operation, or refuses it.
    pub fn authorize(
        &mut self,
        operation: &PrivilegedOperation,
    ) -> Result<Authorized, LauncherRefusal> {
        if operation.is_cleanup() {
            return self.authorize_cleanup(operation);
        }
        let op = operation.tag();
        if self.last_cleanup.is_some() {
            return Err(LauncherRefusal::SetupAfterCleanup { op });
        }
        let setup = &self.plan.setup;
        match setup.iter().position(|planned| planned == operation) {
            None => Err(LauncherRefusal::NotPlanned { op }),
            Some(index) if index < self.performed_setup => {
                Err(LauncherRefusal::AlreadyPerformed { op })
            }
            Some(index) if index > self.performed_setup => Err(LauncherRefusal::OutOfOrder {
                op,
                expected: setup
                    .get(self.performed_setup)
                    .map_or("nothing", PrivilegedOperation::tag),
            }),
            Some(index) => {
                self.performed_setup += 1;
                Ok(Authorized::Setup { step: index })
            }
        }
    }

    fn authorize_cleanup(
        &mut self,
        operation: &PrivilegedOperation,
    ) -> Result<Authorized, LauncherRefusal> {
        let op = operation.tag();
        let Some((index, step)) = self
            .plan
            .cleanup
            .iter()
            .enumerate()
            .find(|(_, step)| &step.operation == operation)
        else {
            return Err(LauncherRefusal::NotPlanned { op });
        };
        if self.performed_setup <= step.created_by {
            return Err(LauncherRefusal::NothingCreated { op });
        }
        if self.cleanup_done.get(index).copied().unwrap_or(true) {
            return Err(LauncherRefusal::AlreadyPerformed { op });
        }
        if self.last_cleanup.is_some_and(|last| last > index) {
            return Err(LauncherRefusal::CleanupOutOfOrder { op });
        }
        if let Some(done) = self.cleanup_done.get_mut(index) {
            *done = true;
        }
        self.last_cleanup = Some(index);
        Ok(Authorized::Cleanup { step: index })
    }

    /// How many setup operations were authorized.
    pub fn performed_setup(&self) -> usize {
        self.performed_setup
    }

    /// Whether every setup operation, the jailer run included, was authorized.
    pub fn setup_complete(&self) -> bool {
        self.performed_setup == self.plan.setup.len()
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures;
    use super::*;

    /// An operation as serde reads a field of another internally tagged enum: buffered,
    /// where a tag written as a number would read as the variant's index without the
    /// strict tag.
    #[derive(Debug, Deserialize)]
    #[serde(tag = "wrap", rename_all = "snake_case")]
    enum Wrapped {
        Inner { value: PrivilegedOperation },
    }

    /// Reads the request `text` buffered, nested in [`Wrapped`].
    fn read_nested(text: &str) -> Result<PrivilegedOperation, String> {
        serde_json::from_str::<Wrapped>(&format!(r#"{{"wrap":"inner","value":{text}}}"#))
            .map(|Wrapped::Inner { value }| value)
            .map_err(|error| error.to_string())
    }

    fn setup_and_cleanup() -> (Vec<PrivilegedOperation>, Vec<PrivilegedOperation>) {
        let plan = fixtures::plan();
        let launcher = plan.launcher();
        (
            launcher.setup().to_vec(),
            launcher
                .cleanup()
                .iter()
                .map(|step| step.operation.clone())
                .collect(),
        )
    }

    #[test]
    fn the_plan_is_exactly_the_closed_set_for_one_launch() {
        let plan = fixtures::plan();
        let tags: Vec<&str> = plan.launcher().setup().iter().map(|op| op.tag()).collect();
        assert_eq!(
            tags,
            [
                "create_network_namespace",
                "create_directory",
                "create_directory",
                "stage_artifact",
                "stage_artifact",
                "create_directory",
                "create_directory",
                "create_sink",
                "create_sink",
                "run_jailer",
            ]
        );
        let cleanup: Vec<&str> = plan
            .launcher()
            .cleanup()
            .iter()
            .map(|step| step.operation.tag())
            .collect();
        assert_eq!(
            cleanup,
            [
                "terminate_jail",
                "remove_cgroup",
                "remove_jail",
                "remove_network_namespace"
            ]
        );
        let PrivilegedOperation::RunJailer { argv, .. } = &plan.launcher().setup()[9] else {
            panic!("the last setup operation runs the jailer");
        };
        assert_eq!(argv, &plan.jailer().argv());
    }

    #[test]
    fn artifacts_are_root_owned_read_only_and_sinks_are_host_owned() {
        let plan = fixtures::plan();
        let host = fixtures::host();
        let identity = fixtures::identity();
        let chroot = plan.jailer().chroot_dir().unwrap();
        for operation in plan.launcher().setup() {
            match operation {
                PrivilegedOperation::StageArtifact {
                    target,
                    mode,
                    source,
                    content_key,
                    ..
                } => {
                    assert_eq!(*mode, ARTIFACT_MODE);
                    assert!(target.as_str().starts_with(chroot.as_str()));
                    assert_eq!(source.file_name(), content_key.to_string());
                }
                PrivilegedOperation::CreateSink {
                    path,
                    owner_uid,
                    group_gid,
                    mode,
                    ..
                } => {
                    assert_eq!(*owner_uid, host.owner.uid);
                    assert_ne!(*owner_uid, identity.uid);
                    assert_eq!(*group_gid, identity.gid);
                    assert_eq!(*mode, SINK_MODE);
                    assert!(path.as_str().starts_with(chroot.as_str()));
                }
                PrivilegedOperation::CreateDirectory {
                    path,
                    owner_uid,
                    mode,
                    ..
                } => {
                    assert!(path.as_str().starts_with(chroot.as_str()));
                    if *owner_uid == 0 {
                        assert_eq!(*mode, ROOT_DIRECTORY_MODE);
                    } else {
                        assert_eq!(mode & 0o007, 0, "{path} is private");
                    }
                    if path.as_str().ends_with("/sinks") {
                        assert_eq!(*owner_uid, host.owner.uid);
                    }
                    if path.as_str().ends_with("/run") {
                        assert_eq!(*owner_uid, identity.uid);
                        assert_eq!(*mode, SOCKET_DIRECTORY_MODE);
                    }
                }
                _ => {}
            }
        }
    }

    #[test]
    fn the_full_sequence_is_authorized_in_order_and_once() {
        let (setup, cleanup) = setup_and_cleanup();
        let mut session = fixtures::plan().launcher().session();
        for (index, operation) in setup.iter().enumerate() {
            assert_eq!(
                session.authorize(operation),
                Ok(Authorized::Setup { step: index })
            );
        }
        assert!(session.setup_complete());
        assert_eq!(
            session.authorize(&setup[0]),
            Err(LauncherRefusal::AlreadyPerformed {
                op: "create_network_namespace"
            })
        );
        for (index, operation) in cleanup.iter().enumerate() {
            assert_eq!(
                session.authorize(operation),
                Ok(Authorized::Cleanup { step: index })
            );
            assert_eq!(
                session.authorize(operation),
                Err(LauncherRefusal::AlreadyPerformed {
                    op: operation.tag()
                })
            );
        }
    }

    #[test]
    fn setup_out_of_order_or_after_cleanup_is_refused() {
        let (setup, cleanup) = setup_and_cleanup();
        let mut session = fixtures::plan().launcher().session();
        assert_eq!(
            session.authorize(&setup[9]),
            Err(LauncherRefusal::OutOfOrder {
                op: "run_jailer",
                expected: "create_network_namespace"
            })
        );
        assert_eq!(session.performed_setup(), 0);
        session.authorize(&setup[0]).unwrap();
        session.authorize(&setup[1]).unwrap();
        assert_eq!(
            session.authorize(&cleanup[3]),
            Ok(Authorized::Cleanup { step: 3 })
        );
        assert_eq!(
            session.authorize(&setup[2]),
            Err(LauncherRefusal::SetupAfterCleanup {
                op: "create_directory"
            })
        );
        assert!(!session.setup_complete());
    }

    #[test]
    fn cleanup_removes_only_what_the_launch_created_and_never_goes_back() {
        let (setup, cleanup) = setup_and_cleanup();
        let mut fresh = fixtures::plan().launcher().session();
        for operation in &cleanup {
            assert_eq!(
                fresh.authorize(operation),
                Err(LauncherRefusal::NothingCreated {
                    op: operation.tag()
                })
            );
        }

        let mut partial = fixtures::plan().launcher().session();
        partial.authorize(&setup[0]).unwrap();
        for operation in &cleanup[..3] {
            assert_eq!(
                partial.authorize(operation),
                Err(LauncherRefusal::NothingCreated {
                    op: operation.tag()
                })
            );
        }
        assert!(partial.authorize(&cleanup[3]).is_ok());

        let mut full = fixtures::plan().launcher().session();
        for operation in &setup {
            full.authorize(operation).unwrap();
        }
        full.authorize(&cleanup[1]).unwrap();
        assert_eq!(
            full.authorize(&cleanup[0]),
            Err(LauncherRefusal::CleanupOutOfOrder {
                op: "terminate_jail"
            })
        );
        assert!(full.authorize(&cleanup[3]).is_ok());
        assert_eq!(
            full.authorize(&cleanup[2]),
            Err(LauncherRefusal::CleanupOutOfOrder { op: "remove_jail" })
        );
    }

    #[test]
    fn changed_parameters_are_not_planned() {
        let (setup, cleanup) = setup_and_cleanup();
        let mut session = fixtures::plan().launcher().session();
        let PrivilegedOperation::CreateNetworkNamespace { netns } = &setup[0] else {
            panic!("the first operation creates the namespace");
        };
        let tap = PrivilegedOperation::CreateTapDevice {
            netns: netns.clone(),
            device: InterfaceName::new("tap0").unwrap(),
            owner: fixtures::identity(),
        };
        session.authorize(&setup[0]).unwrap();
        assert_eq!(
            session.authorize(&tap),
            Err(LauncherRefusal::NotPlanned {
                op: "create_tap_device"
            })
        );
        for operation in &setup[1..9] {
            session.authorize(operation).unwrap();
        }
        let PrivilegedOperation::RunJailer {
            argv,
            jailer_content_key,
            exec_content_key,
        } = &setup[9]
        else {
            panic!("the last setup operation runs the jailer");
        };
        let mut weakened = argv.clone();
        weakened.push("--no-seccomp".to_owned());
        let mut shell = argv.clone();
        shell[0] = "/bin/sh".to_owned();
        for changed in [
            PrivilegedOperation::RunJailer {
                argv: weakened,
                jailer_content_key: *jailer_content_key,
                exec_content_key: *exec_content_key,
            },
            PrivilegedOperation::RunJailer {
                argv: shell,
                jailer_content_key: *jailer_content_key,
                exec_content_key: *exec_content_key,
            },
            PrivilegedOperation::RunJailer {
                argv: argv.clone(),
                jailer_content_key: *exec_content_key,
                exec_content_key: *exec_content_key,
            },
        ] {
            assert_eq!(
                session.authorize(&changed),
                Err(LauncherRefusal::NotPlanned { op: "run_jailer" })
            );
        }
        session.authorize(&setup[9]).unwrap();
        let PrivilegedOperation::RemoveJail { jail_dir } = &cleanup[2] else {
            panic!("the third cleanup step removes the jail");
        };
        let parent = HostPath::new(
            jail_dir
                .as_str()
                .rsplit_once('/')
                .map(|(parent, _)| parent)
                .unwrap(),
        )
        .unwrap();
        for unrelated in [
            PrivilegedOperation::RemoveJail { jail_dir: parent },
            PrivilegedOperation::RemoveJail {
                jail_dir: HostPath::new("/home").unwrap(),
            },
            PrivilegedOperation::TerminateJail {
                cgroup: HostPath::new("/sys/fs/cgroup").unwrap(),
            },
        ] {
            assert_eq!(
                session.authorize(&unrelated),
                Err(LauncherRefusal::NotPlanned {
                    op: unrelated.tag()
                })
            );
        }
    }

    #[test]
    fn a_tap_device_is_planned_only_for_a_declared_interface() {
        let plan = fixtures::network_plan();
        let taps: Vec<&PrivilegedOperation> = plan
            .launcher()
            .setup()
            .iter()
            .filter(|op| op.tag() == "create_tap_device")
            .collect();
        assert_eq!(taps.len(), 1);
        let PrivilegedOperation::CreateTapDevice { device, owner, .. } = taps[0] else {
            panic!("a tap operation");
        };
        assert_eq!(device.as_str(), "tap0");
        assert_eq!(*owner, fixtures::identity());
        assert_eq!(plan.launcher().setup()[1].tag(), "create_tap_device");
        assert!(fixtures::plan()
            .launcher()
            .setup()
            .iter()
            .all(|op| op.tag() != "create_tap_device"));
    }

    #[test]
    fn requests_outside_the_closed_set_are_refused_by_name() {
        for (text, op) in [
            (
                r#"{"op":"set_sysctl","name":"net.ipv4.ip_forward","value":"1"}"#,
                "set_sysctl",
            ),
            (
                r#"{"op":"run_command","argv":["/bin/sh","-c","id"]}"#,
                "run_command",
            ),
            (
                r#"{"op":"load_kernel_module","name":"vhost_vsock"}"#,
                "load_kernel_module",
            ),
            (
                r#"{"op":"mount","source":"/home","target":"/srv/x"}"#,
                "mount",
            ),
            (r#"{"op":"kill_process","pid":1}"#, "kill_process"),
            (
                r#"{"op":"chown","path":"/etc/shadow","uid":64001}"#,
                "chown",
            ),
        ] {
            assert_eq!(
                PrivilegedOperation::from_json(text),
                Err(LauncherRefusal::OutsideClosedSet { op: op.to_owned() }),
                "{text}"
            );
        }
        let long = format!(r#"{{"op":"{}"}}"#, "x".repeat(200));
        assert!(matches!(
            PrivilegedOperation::from_json(&long),
            Err(LauncherRefusal::OutsideClosedSet { op }) if op.len() == 64
        ));
    }

    #[test]
    fn requests_round_trip_and_refuse_extra_or_malformed_fields() {
        let (setup, cleanup) = setup_and_cleanup();
        for operation in setup.iter().chain(&cleanup) {
            let text = serde_json::to_string(operation).unwrap();
            assert_eq!(
                PrivilegedOperation::from_json(&text).as_ref(),
                Ok(operation),
                "{text}"
            );
            let mut extra = serde_json::to_value(operation).unwrap();
            extra["shell"] = true.into();
            assert!(matches!(
                PrivilegedOperation::from_json(&extra.to_string()),
                Err(LauncherRefusal::Malformed { .. })
            ));
        }
        for text in [
            "not json",
            r#"{"netns":"/run/netns/x"}"#,
            r#"{"op":7}"#,
            r#"{"op":"create_network_namespace","netns":"/run/netns/../x"}"#,
            r#"{"op":"create_network_namespace"}"#,
        ] {
            assert!(
                matches!(
                    PrivilegedOperation::from_json(text),
                    Err(LauncherRefusal::Malformed { .. })
                ),
                "{text}"
            );
        }
        let oversized = format!(
            r#"{{"op":"create_network_namespace","netns":"/{}"}}"#,
            "a".repeat(MAX_REQUEST_BYTES)
        );
        assert!(matches!(
            PrivilegedOperation::from_json(&oversized),
            Err(LauncherRefusal::TooLarge { .. })
        ));
        for tag in OPERATION_TAGS {
            assert!(
                setup.iter().chain(&cleanup).any(|op| op.tag() == tag)
                    || tag == "create_tap_device",
                "{tag}"
            );
        }
        assert!(!LauncherRefusal::OutsideClosedSet { op: "x".to_owned() }
            .to_string()
            .is_empty());
    }

    #[test]
    fn every_operation_reads_only_with_string_tags_and_no_repeated_key() {
        let (setup, cleanup) = setup_and_cleanup();
        let tap = fixtures::network_plan().launcher().setup()[1].clone();
        let samples: Vec<PrivilegedOperation> =
            setup.into_iter().chain(cleanup).chain([tap]).collect();
        for tag in OPERATION_TAGS {
            assert!(samples.iter().any(|op| op.tag() == tag), "{tag}");
        }
        let tags: Vec<Value> = OPERATION_TAGS.iter().map(|tag| (*tag).into()).collect();
        let roles: Vec<Value> = [ArtifactRole::Kernel, ArtifactRole::RootImage]
            .iter()
            .map(|role| serde_json::to_value(role).unwrap())
            .collect();
        let kinds: Vec<Value> = [SinkKind::Logger, SinkKind::Metrics]
            .iter()
            .map(|kind| serde_json::to_value(kind).unwrap())
            .collect();
        let refused = |text: &str| {
            assert!(
                serde_json::from_str::<PrivilegedOperation>(text).is_err(),
                "{text}"
            );
            assert!(read_nested(text).is_err(), "{text} nested");
            assert!(
                matches!(
                    PrivilegedOperation::from_json(text),
                    Err(LauncherRefusal::Malformed { .. })
                ),
                "{text} by the launcher"
            );
        };
        let mut swapped_names = Vec::new();
        for operation in &samples {
            let text = serde_json::to_string(operation).unwrap();
            // The written form reads at the top level, through the launcher and buffered,
            // and writes back unchanged.
            for read in [
                serde_json::from_str::<PrivilegedOperation>(&text).map_err(|e| e.to_string()),
                PrivilegedOperation::from_json(&text).map_err(|e| e.to_string()),
                read_nested(&text),
            ] {
                assert_eq!(read.as_ref(), Ok(operation), "{text}");
                assert_eq!(serde_json::to_string(&read.unwrap()).unwrap(), text);
            }

            // Each string naming a variant, the tag and the names of the plain enums it
            // holds, swapped for that variant's index (declaration order) is refused.
            let value: Value = serde_json::from_str(&text).unwrap();
            for (key, variants) in [("op", &tags), ("role", &roles), ("kind", &kinds)] {
                let Some(name) = value.get(key) else {
                    continue;
                };
                let index = variants.iter().position(|variant| variant == name).unwrap();
                let mut swapped = value.clone();
                swapped[key] = index.into();
                refused(&swapped.to_string());
                swapped_names.push(key);
            }

            // A repeated tag, and a repeated field, are refused.
            let body = text.strip_prefix('{').unwrap();
            refused(&format!(r#"{{"op":"{}",{body}"#, operation.tag()));
            let (field, field_value) = value
                .as_object()
                .unwrap()
                .iter()
                .find(|(key, _)| *key != "op")
                .unwrap();
            let open = text.strip_suffix('}').unwrap();
            refused(&format!(
                "{open},{}:{field_value}}}",
                Value::from(field.as_str())
            ));
        }
        assert_eq!(
            swapped_names.iter().filter(|key| **key == "op").count(),
            samples.len()
        );
        assert!(swapped_names.contains(&"role") && swapped_names.contains(&"kind"));

        // The written form is the one the launcher has always read.
        let text = r#"{"op":"remove_cgroup","cgroup":"/sys/fs/cgroup/yougori/a"}"#;
        let read = PrivilegedOperation::from_json(text).unwrap();
        assert_eq!(serde_json::to_string(&read).unwrap(), text);
    }
}
