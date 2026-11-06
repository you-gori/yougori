//! Cleanup safety (VM part §6.4 lines 2145–2149; §2.6 line 1836; VM-W24; VM-P49).
//!
//! Cleanup acts only on objects the host created and registered, at creation, under a
//! managed root whose identity is observed again and must match before anything is
//! deleted. It never accepts a guest-supplied path and never terminates a process by a
//! stored PID: a process is named by its identity behind a stable handle (a pidfd, a Job
//! or process handle, a framework VM object), and a PID now held by another process is
//! refused as reused. That identity is the one `foundation::process` gives every host
//! process (its PID with its creation time, read through the handle the host holds), and
//! which process holds a PID now is the host's own observation
//! ([`ObservedIdentities::observe_processes`], through
//! [`ProcessIdentity::holder_of`]), never a guest's report or a stored number. A VM's host
//! process is registered from the [`HostProcess`] the host started it as, with the role it
//! was bound to then. A handle from an earlier registration of the same object is stale.
//! User source data is never a cleanup target, and an object already gone is reported as
//! such rather than searched for elsewhere. This validates a request; deleting through
//! handles while resisting reparse and symlink races is the runtime's part (line 2149).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::Digest;
use crate::foundation::process::{HostProcess, ProcessError, ProcessIdentity, ProcessRole};

/// A root directory the supervisor created and manages, by its host-assigned identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ManagedRootId(Digest);

impl ManagedRootId {
    pub const fn from_host(identity: Digest) -> Self {
        Self(identity)
    }
}

/// A host-created object: its identity and the registration generation it was handed
/// out under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectHandle {
    pub object: Digest,
    pub generation: u64,
}

/// What a managed object is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedObjectKind {
    Overlay,
    ScratchDirectory,
    Socket,
    Perimeter,
    Snapshot,
    VmProcess,
    /// The user's own source data; preserved, never cleaned up (line 2149).
    UserSourceData,
    /// A volume the renewal plan carries past the boot (retained into the next sandbox, or
    /// quarantined); kept, never cleaned up.
    RetainedVolume,
}

/// The stable handle a process identity is held by (line 2147).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessHandleKind {
    LinuxPidFd,
    WindowsJobObject,
    MacFrameworkVm,
}

impl ProcessHandleKind {
    /// The handle a [`HostProcess`] is held by on this platform.
    #[cfg(windows)]
    pub const HOST: Self = Self::WindowsJobObject;
    /// The handle a [`HostProcess`] is held by on this platform.
    #[cfg(target_os = "linux")]
    pub const HOST: Self = Self::LinuxPidFd;
    /// The handle a [`HostProcess`] is held by on this platform.
    #[cfg(not(any(windows, target_os = "linux")))]
    pub const HOST: Self = Self::MacFrameworkVm;
}

/// A host process the supervisor started and manages: the host's identity of it (the PID
/// alone is never enough), what it was bound to run for when it started, the kind of
/// stable handle it is held by and its image.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedProcess {
    pub identity: ProcessIdentity,
    pub role: ProcessRole,
    pub handle: ProcessHandleKind,
    pub image: Digest,
}

impl ManagedProcess {
    /// `process` as the host holds it, running `image`: its identity and role are read from
    /// the handle, never supplied.
    pub fn of(process: &HostProcess, image: Digest) -> Self {
        Self {
            identity: process.identity(),
            role: process.role().clone(),
            handle: ProcessHandleKind::HOST,
            image,
        }
    }
}

/// What a cleanup request names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "target", rename_all = "snake_case")]
pub enum CleanupTarget {
    Object {
        handle: ObjectHandle,
    },
    Process {
        identity: ProcessIdentity,
    },
    /// A path from the guest; always refused.
    GuestPath {
        path: String,
    },
    /// A PID read back from storage, with no identity; always refused.
    StoredPid {
        pid: u32,
    },
}

/// What the host observes now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservedIdentities {
    /// Each managed root's identity as observed now.
    pub roots: BTreeMap<ManagedRootId, Digest>,
    /// Objects still present.
    pub objects_present: BTreeSet<Digest>,
    /// The process now holding each PID, as the host observes it.
    pub processes: BTreeMap<u32, ProcessIdentity>,
}

impl ObservedIdentities {
    /// Records which process holds the PID of every process `registry` manages, as the host
    /// observes it now ([`ProcessIdentity::holder_of`]); a PID no process holds is left out,
    /// so its process counts as gone. Fails, recording nothing further, when the host cannot
    /// observe a PID (a platform the process module does not support refuses with a typed
    /// error).
    pub fn observe_processes(&mut self, registry: &ManagedObjects) -> Result<(), ProcessError> {
        self.observe_processes_with(registry, ProcessIdentity::holder_of)
    }

    fn observe_processes_with(
        &mut self,
        registry: &ManagedObjects,
        mut holder_of: impl FnMut(u32) -> Result<Option<ProcessIdentity>, ProcessError>,
    ) -> Result<(), ProcessError> {
        for process in registry.processes() {
            let pid = process.identity.pid;
            match holder_of(pid)? {
                Some(holder) => {
                    self.processes.insert(pid, holder);
                }
                None => {
                    self.processes.remove(&pid);
                }
            }
        }
        Ok(())
    }
}

/// A validated cleanup step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "plan", rename_all = "snake_case")]
pub enum CleanupPlan {
    Delete {
        root: ManagedRootId,
        object: Digest,
        kind: ManagedObjectKind,
    },
    Terminate {
        identity: ProcessIdentity,
    },
    /// Already gone: nothing to do, and nothing is looked for elsewhere.
    AlreadyGone {
        object: Digest,
    },
}

/// Why a cleanup request was refused (VM-P49).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum CleanupRefusal {
    /// The supervisor never accepts a cleanup path from the guest.
    GuestPathNeverAccepted,
    /// A stored PID without a verified identity behind a stable handle.
    UnverifiedPid {
        pid: u32,
    },
    UnknownRoot {
        root: ManagedRootId,
    },
    /// Not an object the host created and registered.
    UnknownObject {
        object: Digest,
    },
    /// The handle is from an earlier registration of the object.
    StaleHandle {
        presented_generation: u64,
        registered_generation: u64,
    },
    /// User source data is preserved.
    PreservesUserData {
        object: Digest,
    },
    /// The renewal plan keeps this volume past the boot.
    RetainedByRenewal {
        object: Digest,
    },
    /// The managed root no longer has the identity it was registered with.
    RootIdentityChanged {
        root: ManagedRootId,
    },
    /// Not a process the host started.
    UnknownProcess {
        pid: u32,
    },
    /// The PID now belongs to another process.
    PidReused {
        pid: u32,
    },
    /// Only a VM's host process is registered as a VM process; a model runner belongs to the
    /// model activations (S3.1).
    NotAVmHostProcess {
        pid: u32,
    },
}

impl fmt::Display for CleanupRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GuestPathNeverAccepted => f.write_str("cleanup never takes a path from the guest"),
            Self::UnverifiedPid { pid } => {
                write!(f, "PID {pid} has no verified identity; it is not terminated")
            }
            Self::UnknownRoot { root } => write!(f, "{root:?} is not a managed root"),
            Self::UnknownObject { object } => write!(f, "{object} is not a managed object"),
            Self::StaleHandle {
                presented_generation,
                registered_generation,
            } => write!(
                f,
                "the handle is from registration {presented_generation}, now {registered_generation}"
            ),
            Self::PreservesUserData { object } => write!(f, "{object} is user data and is kept"),
            Self::RetainedByRenewal { object } => {
                write!(f, "{object} is a volume the renewal plan keeps")
            }
            Self::RootIdentityChanged { root } => write!(f, "{root:?} changed identity"),
            Self::UnknownProcess { pid } => write!(f, "PID {pid} is not a managed process"),
            Self::PidReused { pid } => write!(f, "PID {pid} now belongs to another process"),
            Self::NotAVmHostProcess { pid } => {
                write!(f, "PID {pid} is not the host process of a VM")
            }
        }
    }
}

impl std::error::Error for CleanupRefusal {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObjectRecord {
    root: ManagedRootId,
    kind: ManagedObjectKind,
    generation: u64,
    process: Option<ManagedProcess>,
}

/// The supervisor's registry of managed roots and host-created objects.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManagedObjects {
    roots: BTreeMap<ManagedRootId, Digest>,
    objects: BTreeMap<Digest, ObjectRecord>,
}

impl ManagedObjects {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a root the supervisor created, with its identity at creation.
    pub fn register_root(&mut self, root: ManagedRootId, identity: Digest) {
        self.roots.insert(root, identity);
    }

    /// Records an object the host just created under `root`. Registering the same object
    /// again hands out a new generation, so the earlier handle is stale.
    pub fn register_object(
        &mut self,
        root: ManagedRootId,
        kind: ManagedObjectKind,
        object: Digest,
        process: Option<ManagedProcess>,
    ) -> Result<ObjectHandle, CleanupRefusal> {
        if !self.roots.contains_key(&root) {
            return Err(CleanupRefusal::UnknownRoot { root });
        }
        let generation = self
            .objects
            .get(&object)
            .map_or(1, |record| record.generation.saturating_add(1));
        self.objects.insert(
            object,
            ObjectRecord {
                root,
                kind,
                generation,
                process,
            },
        );
        Ok(ObjectHandle { object, generation })
    }

    /// Records the host process of a VM the host just started, under `root`, named by the
    /// digest of its identity. Only a VM's host process is registered here.
    pub fn register_vm_process(
        &mut self,
        root: ManagedRootId,
        process: ManagedProcess,
    ) -> Result<ObjectHandle, CleanupRefusal> {
        if !matches!(process.role, ProcessRole::VmHost { .. }) {
            return Err(CleanupRefusal::NotAVmHostProcess {
                pid: process.identity.pid,
            });
        }
        let object = process.identity.digest();
        self.register_object(root, ManagedObjectKind::VmProcess, object, Some(process))
    }

    /// The processes registered, in object order.
    fn processes(&self) -> impl Iterator<Item = &ManagedProcess> {
        self.objects
            .values()
            .filter_map(|record| record.process.as_ref())
    }

    /// Validates one cleanup request against the registry and what the host observes
    /// now (VM-P49).
    pub fn validate_cleanup(
        &self,
        target: &CleanupTarget,
        observed: &ObservedIdentities,
    ) -> Result<CleanupPlan, CleanupRefusal> {
        match target {
            CleanupTarget::GuestPath { .. } => Err(CleanupRefusal::GuestPathNeverAccepted),
            CleanupTarget::StoredPid { pid } => Err(CleanupRefusal::UnverifiedPid { pid: *pid }),
            CleanupTarget::Object { handle } => self.validate_object(*handle, observed),
            CleanupTarget::Process { identity } => self.validate_process(*identity, observed),
        }
    }

    fn validate_object(
        &self,
        handle: ObjectHandle,
        observed: &ObservedIdentities,
    ) -> Result<CleanupPlan, CleanupRefusal> {
        let record = self
            .objects
            .get(&handle.object)
            .ok_or(CleanupRefusal::UnknownObject {
                object: handle.object,
            })?;
        if record.generation != handle.generation {
            return Err(CleanupRefusal::StaleHandle {
                presented_generation: handle.generation,
                registered_generation: record.generation,
            });
        }
        if record.kind == ManagedObjectKind::UserSourceData {
            return Err(CleanupRefusal::PreservesUserData {
                object: handle.object,
            });
        }
        if record.kind == ManagedObjectKind::RetainedVolume {
            return Err(CleanupRefusal::RetainedByRenewal {
                object: handle.object,
            });
        }
        self.verify_root(record.root, observed)?;
        if let Some(process) = &record.process {
            return verify_process(process.identity, observed).map(|plan| {
                plan.unwrap_or(CleanupPlan::AlreadyGone {
                    object: handle.object,
                })
            });
        }
        if !observed.objects_present.contains(&handle.object) {
            return Ok(CleanupPlan::AlreadyGone {
                object: handle.object,
            });
        }
        Ok(CleanupPlan::Delete {
            root: record.root,
            object: handle.object,
            kind: record.kind,
        })
    }

    fn validate_process(
        &self,
        identity: ProcessIdentity,
        observed: &ObservedIdentities,
    ) -> Result<CleanupPlan, CleanupRefusal> {
        let (object, record) = self
            .objects
            .iter()
            .find(|(_, record)| {
                record
                    .process
                    .as_ref()
                    .is_some_and(|process| process.identity == identity)
            })
            .ok_or(CleanupRefusal::UnknownProcess { pid: identity.pid })?;
        self.verify_root(record.root, observed)?;
        Ok(verify_process(identity, observed)?
            .unwrap_or(CleanupPlan::AlreadyGone { object: *object }))
    }

    fn verify_root(
        &self,
        root: ManagedRootId,
        observed: &ObservedIdentities,
    ) -> Result<(), CleanupRefusal> {
        let registered = self
            .roots
            .get(&root)
            .ok_or(CleanupRefusal::UnknownRoot { root })?;
        if observed.roots.get(&root) != Some(registered) {
            return Err(CleanupRefusal::RootIdentityChanged { root });
        }
        Ok(())
    }
}

/// `Some(Terminate)` when the PID still holds exactly this process, `None` when nothing
/// holds it, and a refusal when another process does.
fn verify_process(
    identity: ProcessIdentity,
    observed: &ObservedIdentities,
) -> Result<Option<CleanupPlan>, CleanupRefusal> {
    match observed.processes.get(&identity.pid) {
        None => Ok(None),
        Some(current) if *current == identity => Ok(Some(CleanupPlan::Terminate { identity })),
        Some(_) => Err(CleanupRefusal::PidReused { pid: identity.pid }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    fn id(name: &str) -> Digest {
        digest("yougori/test/cleanup/v1", &[name.as_bytes()])
    }

    fn root() -> ManagedRootId {
        ManagedRootId::from_host(id("root"))
    }

    fn vm_process(pid: u32, start_time_ticks: u64) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            start_time_ticks,
        }
    }

    fn vm_role() -> ProcessRole {
        let execution = crate::foundation::ids::ExecutionId::new("sandbox-a").unwrap();
        ProcessRole::VmHost {
            execution,
            vm: crate::foundation::coordination::VmInstanceId::new(id("vm-instance")),
            boot: crate::foundation::ids::SandboxBootGeneration::new(1),
        }
    }

    fn managed(identity: ProcessIdentity) -> ManagedProcess {
        ManagedProcess {
            identity,
            role: vm_role(),
            handle: ProcessHandleKind::WindowsJobObject,
            image: id("qemu"),
        }
    }

    fn registry() -> (ManagedObjects, ObjectHandle, ObjectHandle, ObjectHandle) {
        let mut objects = ManagedObjects::new();
        objects.register_root(root(), id("root-identity"));
        let overlay = objects
            .register_object(root(), ManagedObjectKind::Overlay, id("overlay"), None)
            .unwrap();
        let vm = objects
            .register_object(
                root(),
                ManagedObjectKind::VmProcess,
                id("vm"),
                Some(managed(vm_process(4242, 1_000))),
            )
            .unwrap();
        let source = objects
            .register_object(
                root(),
                ManagedObjectKind::UserSourceData,
                id("project"),
                None,
            )
            .unwrap();
        (objects, overlay, vm, source)
    }

    fn observed() -> ObservedIdentities {
        ObservedIdentities {
            roots: BTreeMap::from([(root(), id("root-identity"))]),
            objects_present: BTreeSet::from([id("overlay"), id("vm"), id("project")]),
            processes: BTreeMap::from([(4242, vm_process(4242, 1_000))]),
        }
    }

    #[test]
    fn the_host_observes_which_process_holds_each_registered_pid() {
        let (objects, _, _, _) = registry();
        let mut seen = ObservedIdentities::default();
        seen.observe_processes_with(&objects, |pid| {
            assert_eq!(pid, 4242);
            Ok(Some(vm_process(4242, 1_000)))
        })
        .unwrap();
        assert_eq!(seen.processes, observed().processes);
        // A PID another process holds now is recorded as that process; one no process
        // holds is left out.
        seen.observe_processes_with(&objects, |_| Ok(Some(vm_process(4242, 9_999))))
            .unwrap();
        assert_eq!(seen.processes[&4242], vm_process(4242, 9_999));
        seen.observe_processes_with(&objects, |_| Ok(None)).unwrap();
        assert!(seen.processes.is_empty());
        let unsupported = ProcessError::Unsupported {
            platform: "test".to_owned(),
        };
        assert_eq!(
            seen.observe_processes_with(&objects, |_| Err(unsupported.clone())),
            Err(unsupported)
        );
    }

    #[test]
    fn only_a_vm_host_process_registers_as_a_vm_process() {
        let mut objects = ManagedObjects::new();
        objects.register_root(root(), id("root-identity"));
        let runner = ManagedProcess {
            role: ProcessRole::ModelRunner {
                execution: crate::foundation::ids::ExecutionId::new("sandbox-a").unwrap(),
                model: crate::foundation::coordination::ModelId::new(id("model")),
                generations: crate::foundation::coordination::ModelGenerations {
                    activation: crate::foundation::ids::ModelActivationGeneration::new(1),
                    gpu_allocation: crate::foundation::ids::GpuAllocationGeneration::new(1),
                },
            },
            ..managed(vm_process(7, 1))
        };
        assert_eq!(
            objects.register_vm_process(root(), runner),
            Err(CleanupRefusal::NotAVmHostProcess { pid: 7 })
        );
        let handle = objects
            .register_vm_process(root(), managed(vm_process(7, 1)))
            .unwrap();
        assert_eq!(handle.object, vm_process(7, 1).digest());
    }

    #[test]
    fn host_created_objects_under_a_verified_root_are_cleaned_up() {
        let (objects, overlay, vm, _) = registry();
        assert_eq!(
            objects.validate_cleanup(&CleanupTarget::Object { handle: overlay }, &observed()),
            Ok(CleanupPlan::Delete {
                root: root(),
                object: id("overlay"),
                kind: ManagedObjectKind::Overlay
            })
        );
        assert_eq!(
            objects.validate_cleanup(&CleanupTarget::Object { handle: vm }, &observed()),
            Ok(CleanupPlan::Terminate {
                identity: vm_process(4242, 1_000)
            })
        );
        assert_eq!(
            objects.validate_cleanup(
                &CleanupTarget::Process {
                    identity: vm_process(4242, 1_000)
                },
                &observed()
            ),
            Ok(CleanupPlan::Terminate {
                identity: vm_process(4242, 1_000)
            })
        );
    }

    #[test]
    fn a_guest_supplied_path_is_never_accepted() {
        let (objects, ..) = registry();
        for path in [
            "../../Users/me",
            "C:\\Users\\me\\project",
            "/home/me",
            "scratch/tmp",
        ] {
            assert_eq!(
                objects
                    .validate_cleanup(&CleanupTarget::GuestPath { path: path.into() }, &observed()),
                Err(CleanupRefusal::GuestPathNeverAccepted)
            );
        }
    }

    #[test]
    fn a_stored_pid_without_identity_is_never_terminated() {
        let (objects, ..) = registry();
        assert_eq!(
            objects.validate_cleanup(&CleanupTarget::StoredPid { pid: 4242 }, &observed()),
            Err(CleanupRefusal::UnverifiedPid { pid: 4242 })
        );
    }

    #[test]
    fn a_reused_pid_is_refused_and_an_exited_process_is_already_gone() {
        let (objects, _, vm, _) = registry();
        let mut reused = observed();
        reused.processes.insert(4242, vm_process(4242, 9_999));
        assert_eq!(
            objects.validate_cleanup(&CleanupTarget::Object { handle: vm }, &reused),
            Err(CleanupRefusal::PidReused { pid: 4242 })
        );
        assert_eq!(
            objects.validate_cleanup(
                &CleanupTarget::Process {
                    identity: vm_process(4242, 1_000)
                },
                &reused
            ),
            Err(CleanupRefusal::PidReused { pid: 4242 })
        );
        let mut exited = observed();
        exited.processes.clear();
        assert_eq!(
            objects.validate_cleanup(&CleanupTarget::Object { handle: vm }, &exited),
            Ok(CleanupPlan::AlreadyGone { object: id("vm") })
        );
        assert_eq!(
            objects.validate_cleanup(
                &CleanupTarget::Process {
                    identity: vm_process(77, 5)
                },
                &observed()
            ),
            Err(CleanupRefusal::UnknownProcess { pid: 77 })
        );
    }

    #[test]
    fn stale_handles_unknown_objects_and_user_data_are_refused() {
        let (mut objects, overlay, _, source) = registry();
        let again = objects
            .register_object(root(), ManagedObjectKind::Overlay, id("overlay"), None)
            .unwrap();
        assert_eq!(again.generation, 2);
        assert_eq!(
            objects.validate_cleanup(&CleanupTarget::Object { handle: overlay }, &observed()),
            Err(CleanupRefusal::StaleHandle {
                presented_generation: 1,
                registered_generation: 2
            })
        );
        let forged = ObjectHandle {
            object: id("C:/Users/me"),
            generation: 1,
        };
        assert_eq!(
            objects.validate_cleanup(&CleanupTarget::Object { handle: forged }, &observed()),
            Err(CleanupRefusal::UnknownObject {
                object: id("C:/Users/me")
            })
        );
        assert_eq!(
            objects.validate_cleanup(&CleanupTarget::Object { handle: source }, &observed()),
            Err(CleanupRefusal::PreservesUserData {
                object: id("project")
            })
        );
        let retained = objects
            .register_object(
                root(),
                ManagedObjectKind::RetainedVolume,
                id("unreviewed-output"),
                None,
            )
            .unwrap();
        assert_eq!(
            objects.validate_cleanup(&CleanupTarget::Object { handle: retained }, &observed()),
            Err(CleanupRefusal::RetainedByRenewal {
                object: id("unreviewed-output")
            })
        );
    }

    #[test]
    fn a_root_that_changed_identity_stops_cleanup() {
        let (objects, overlay, ..) = registry();
        let mut swapped = observed();
        swapped
            .roots
            .insert(root(), id("a-junction-to-the-users-folder"));
        assert_eq!(
            objects.validate_cleanup(&CleanupTarget::Object { handle: overlay }, &swapped),
            Err(CleanupRefusal::RootIdentityChanged { root: root() })
        );
        let mut missing = observed();
        missing.roots.clear();
        assert_eq!(
            objects.validate_cleanup(&CleanupTarget::Object { handle: overlay }, &missing),
            Err(CleanupRefusal::RootIdentityChanged { root: root() })
        );
        let mut unmanaged = ManagedObjects::new();
        assert_eq!(
            unmanaged.register_object(root(), ManagedObjectKind::Overlay, id("x"), None),
            Err(CleanupRefusal::UnknownRoot { root: root() })
        );
    }

    #[test]
    fn a_partly_deleted_resource_is_reported_gone_and_nothing_else_is_touched() {
        let (objects, overlay, ..) = registry();
        let mut partial = observed();
        partial.objects_present.remove(&id("overlay"));
        assert_eq!(
            objects.validate_cleanup(&CleanupTarget::Object { handle: overlay }, &partial),
            Ok(CleanupPlan::AlreadyGone {
                object: id("overlay")
            })
        );
    }
}
