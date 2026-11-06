//! The Firecracker backend behind the VM backend contract (VM-W17 row, line 2616; VM-W16
//! line 2615; VM-W22 line 2621; VM-D15 line 3209; §7.2 lines 2366–2375; §6.4 lines
//! 2320–2324; VM-CP-01 to VM-CP-04, lines 3151–3154; leftover entry M03).
//!
//! [`FirecrackerBackend::launch_jailed`] runs, in order, and refuses at the first failure:
//!
//! 1. the contract's [`precheck`] (the request pinned to this build, the features it needs,
//!    fresh host-probe hypervisor evidence and any perimeter evidence), then the jail's
//!    names, the CORE-03 reservation, a free jail identity from the host's range, the
//!    [`LaunchPlan`] and the plan's configuration against the approved golden file, all
//!    before any privileged operation;
//! 2. the launcher's setup operations, each authorized by the launch's session before the
//!    launcher sees it, with each staged artifact's verified content key and the jailer's
//!    exit checked;
//! 3. the one process the jailer left in the launch's cgroup, bound by its
//!    `foundation::process` identity, and the API sequence, one call at a time, stopping
//!    at the first refusal;
//! 4. the host's observations: Firecracker's own description, the configuration it runs
//!    against the golden file (VM-CP-02), the process's status, namespaces, cgroup and
//!    descriptors against the expected state (VM-CP-04), its chroot, and a KVM VM among its
//!    descriptors (VM-CP-01);
//! 5. the contract's [`admit_with_configuration`], which seals the launch record with the
//!    configuration facts of step 4: VM-CP-02's comparison, the digests of the golden file
//!    and of the running configuration with the device flags from the golden check's
//!    forbidden items, and VM-CP-03's listing of the API socket in the jail's socket
//!    directory (line 3153).
//!
//! Any refusal after the first privileged operation runs the launcher's own cleanup:
//! kill through the launch's cgroup, observe the end, then remove only what this launch
//! created. A jail whose cleanup is incomplete keeps its names and jail identity, so no
//! later launch reuses them; the contract hears it as
//! [`LaunchRefusal::CleanupIncomplete`] with what may remain, the VM stays listed by
//! [`VmBackend::running`] while the host has not observed its end, and a stop of it runs
//! the withheld cleanup again. There is no emulation path: Firecracker runs on KVM or not
//! at all, and the backend offers no [`DeveloperEmulation`](crate::sandbox::backend::DeveloperEmulation).
//!
//! [`VmBackend::reobserve`] runs step 4 again on a running VM through the same ports:
//! Firecracker's description against the golden file with the calls sent at launch, the
//! host's state, the process's identity, status, namespaces, cgroup, descriptors and
//! chroot, and KVM; a VM that no longer passes refuses as a launch would. The guest image
//! counts only while the host sees the process hold the staged root image; the launcher's
//! closed set has no operation that verifies the staged copy's content again. The
//! configuration facts it observes again are passed on with the §1.3 facts, and the
//! contract judges them as admission did.
//!
//! A VM's handle is the contract's [`vm_handle`] of its sandbox and boot generation,
//! bound to its jail and its process identity. [`VmBackend::stop`] kills through the
//! launch's own cgroup, never a PID, and stops only on the host's proof of the end;
//! stopping again is "already gone". [`VmBackend::running`] lists every VM whose end the
//! host has not observed. Snapshots and restores are refused by name.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::api::ApiCall;
use super::golden::{GoldenCheck, GoldenFile};
use super::host::{HostError, JailHost};
use super::jail::{CleanupReport, Jail, JailEnd, StepError};
use super::launcher::{ArtifactRole, PrivilegedOperation};
use super::layout;
use super::linux_state::compare as compare_linux_state;
use super::names::{HostPath, JailId, JailIdentity};
use super::observe::{
    configuration_facts, holds_kvm_vm, launch_facts, linux_state, running_configuration,
    JailObservation,
};
use super::plan::{pinned_backend, LaunchPlan, PlanInputs, PlanRefusal};
use super::ports::{
    ApiPort, HostObservationPort, LauncherPort, LauncherReport, ObservationFailure, ReservationBook,
};
use super::profile::{FirecrackerProfile, ProfileError};
use super::proof::JailTermination;
use super::refusal::{FirecrackerRefusal, LaunchFailure};
use crate::foundation::coordination::{SnapshotManifest, SnapshotOrigin, VmInstanceId};
use crate::foundation::evidence::Satisfied;
use crate::foundation::ids::{Digest, ExecutionId, SandboxBootGeneration};
use crate::foundation::process::{Ending, IdentityCheck, ProcessIdentity, ProcessRole};
use crate::sandbox::backend::{
    admit_with_configuration, precheck, reobserved_with_configuration, vm_handle, Accelerator,
    BackendFeatures, BackendIdentity, BackendKind, BackendOperation, BackendRefusal,
    ConfigurationFacts, ConfinementControl, Feature, HostEvidence, HostObserved, LaunchFacts,
    LaunchRefusal, LaunchRequest, Launched, ObservedProperties, Reobservation,
    ReobservationRefusal, Restored, StopOutcome, VmBackend,
};
use crate::sandbox::trust::{ComponentKind, ComponentVersion, PinnedConfiguration};

/// What the backend is set up with: host configuration, never a launch request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirecrackerSettings {
    /// The approved profile every launch follows.
    pub profile: FirecrackerProfile,
    /// The pinned Firecracker row (VM-W46): Firecracker and its jailer from one release.
    pub configuration: PinnedConfiguration,
    pub host: JailHost,
    /// The profile's approved golden file, versioned with the backend (VM-CP-02).
    pub golden: GoldenFile,
    /// How long the backend's host observations stay fresh.
    pub fresh_for: Duration,
}

/// Why the backend could not be set up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum SettingsError {
    Profile {
        error: ProfileError,
    },
    Host {
        error: HostError,
    },
    Configuration {
        refusal: PlanRefusal,
    },
    /// The golden file is of another Firecracker version than the pinned row.
    GoldenVersion {
        golden: ComponentVersion,
        pinned: ComponentVersion,
    },
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile { error } => write!(f, "the Firecracker profile is refused: {error}"),
            Self::Host { error } => write!(f, "the host's jail settings are refused: {error}"),
            Self::Configuration { refusal } => write!(f, "{refusal}"),
            Self::GoldenVersion { golden, pinned } => write!(
                f,
                "the golden file is of Firecracker {golden}, but the pinned row is {pinned}"
            ),
        }
    }
}

impl std::error::Error for SettingsError {}

/// What a VM's handle is bound to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JailBinding {
    pub vm: VmInstanceId,
    pub jail: JailId,
    /// The unprivileged identity the jailer dropped to.
    pub identity: JailIdentity,
    /// What the process runs for, bound at launch.
    pub role: ProcessRole,
    /// The jail's Firecracker process.
    pub process: ProcessIdentity,
}

/// The outcome of [`FirecrackerBackend::stop_jail`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "stop", rename_all = "snake_case")]
pub enum JailStop {
    /// No VM of this backend runs with the handle: never launched, or already stopped.
    AlreadyGone,
    /// The host observed the jail's end; the report says whether everything the launch
    /// created is removed.
    Stopped { cleanup: CleanupReport },
    /// The host has not observed the jail's end; nothing was removed and the VM stays
    /// listed.
    NotStopped { cleanup: CleanupReport },
}

#[derive(Clone, Debug)]
struct RunningVm {
    launched: Launched,
    jail: Jail,
    configured: Configured,
}

/// What a running VM was launched with, which a re-observation checks it against.
#[derive(Clone, Debug)]
struct Configured {
    request: LaunchRequest,
    plan: LaunchPlan,
    paths: JailPaths,
    process: ProcessIdentity,
    /// The API calls as the port wrote them.
    sent: Vec<ApiCall>,
    /// The root image as the launcher verified the staged copy.
    guest_image: Digest,
}

/// What step 4 observed of a running jail, for admission.
struct JailFacts {
    /// The §1.3 facts.
    launch: LaunchFacts,
    /// VM-CP-02's comparison and VM-CP-03's listing.
    configuration: ConfigurationFacts,
}

/// The VM a jail's process runs for, by the role bound at launch.
fn vm_of(jail: &Jail) -> Option<VmInstanceId> {
    match jail.role() {
        ProcessRole::VmHost { vm, .. } => Some(*vm),
        ProcessRole::ModelRunner { .. }
        | ProcessRole::GuestRelay { .. }
        | ProcessRole::SandboxExecutor { .. }
        | ProcessRole::SandboxSupervisor { .. } => None,
    }
}

/// The Firecracker backend over a privileged launcher (`L`), Firecracker's API (`A`), the
/// host's own observations (`H`) and the CORE-03 ledger's records (`R`).
#[derive(Debug)]
pub struct FirecrackerBackend<L, A, H, R> {
    identity: BackendIdentity,
    features: BackendFeatures,
    settings: FirecrackerSettings,
    launcher: L,
    api: A,
    host: H,
    reservations: R,
    running: BTreeMap<VmInstanceId, RunningVm>,
    ended: BTreeMap<VmInstanceId, JailTermination>,
    uncleaned: BTreeMap<JailId, Jail>,
    used_boots: BTreeSet<(ExecutionId, SandboxBootGeneration)>,
}

impl<L, A, H, R> FirecrackerBackend<L, A, H, R>
where
    L: LauncherPort,
    A: ApiPort,
    H: HostObservationPort,
    R: ReservationBook,
{
    /// A backend for `settings` over the given ports. The profile, the host's jail
    /// settings and the pinned row are checked now, and the golden file must be of the
    /// row's Firecracker version. It offers launch and stop only.
    pub fn new(
        settings: FirecrackerSettings,
        launcher: L,
        api: A,
        host: H,
        reservations: R,
    ) -> Result<Self, SettingsError> {
        settings
            .profile
            .validate()
            .map_err(|error| SettingsError::Profile { error })?;
        settings
            .host
            .validate()
            .map_err(|error| SettingsError::Host { error })?;
        let identity = pinned_backend(&settings.configuration)
            .map_err(|refusal| SettingsError::Configuration { refusal })?;
        if let Some(runtime) = settings.configuration.component(ComponentKind::Runtime) {
            if settings.golden.firecracker_version() != &runtime.version {
                return Err(SettingsError::GoldenVersion {
                    golden: settings.golden.firecracker_version().clone(),
                    pinned: runtime.version.clone(),
                });
            }
        }
        Ok(Self {
            identity,
            features: BackendFeatures::none(),
            settings,
            launcher,
            api,
            host,
            reservations,
            running: BTreeMap::new(),
            ended: BTreeMap::new(),
            uncleaned: BTreeMap::new(),
            used_boots: BTreeSet::new(),
        })
    }

    pub fn settings(&self) -> &FirecrackerSettings {
        &self.settings
    }

    pub fn launcher(&self) -> &L {
        &self.launcher
    }

    pub fn launcher_mut(&mut self) -> &mut L {
        &mut self.launcher
    }

    pub fn api(&self) -> &A {
        &self.api
    }

    pub fn api_mut(&mut self) -> &mut A {
        &mut self.api
    }

    pub fn host(&self) -> &H {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    pub fn reservations_mut(&mut self) -> &mut R {
        &mut self.reservations
    }

    /// What `vm`'s handle is bound to, while it runs.
    pub fn bound(&self, vm: &VmInstanceId) -> Option<JailBinding> {
        let running = self.running.get(vm)?;
        Some(JailBinding {
            vm: *vm,
            jail: running.jail.id().clone(),
            identity: running.jail.identity(),
            role: running.jail.role().clone(),
            process: running.jail.process()?,
        })
    }

    /// The host's proof that `vm`'s jail ended, once a stop or reconciliation observed it.
    pub fn termination_proof(&self, vm: &VmInstanceId) -> Option<&JailTermination> {
        self.ended.get(vm)
    }

    /// The jails whose cleanup is incomplete, from refused launches and stopped VMs. Their
    /// names and jail identities stay taken.
    pub fn uncleaned(&self) -> Vec<JailId> {
        self.uncleaned.keys().cloned().collect()
    }

    /// The first jail identity of the host's range that no running or uncleaned jail
    /// holds; user and group id are the same number.
    fn free_identity(&self) -> Option<JailIdentity> {
        let held: BTreeSet<u32> = self
            .running
            .values()
            .map(|running| &running.jail)
            .chain(self.uncleaned.values())
            .map(|jail| jail.identity().uid)
            .collect();
        let range = self.settings.host.jail_ids;
        (0..range.count)
            .filter_map(|offset| range.first.checked_add(offset))
            .find(|id| !held.contains(id))
            .map(|id| JailIdentity { uid: id, gid: id })
    }

    /// Launches one boot, or refuses with the typed refusal and the state of the
    /// launcher's own cleanup. A launch of a boot that runs returns that VM again.
    pub fn launch_jailed(
        &mut self,
        request: &LaunchRequest,
        host: &dyn HostEvidence,
    ) -> Result<Launched, LaunchFailure> {
        let boot = request.generations.boot;
        let vm = vm_handle(BackendKind::Firecracker, &request.execution, boot);
        if let Some(running) = self.running.get(&vm) {
            return Ok(running.launched.clone());
        }
        let refuse = |refusal| LaunchFailure::before_creation(vm, refusal);
        if self.used_boots.contains(&(request.execution.clone(), boot)) {
            return Err(refuse(FirecrackerRefusal::Admission {
                refusal: LaunchRefusal::BootGenerationUsed {
                    execution: request.execution.clone(),
                    boot,
                },
            }));
        }
        let evidence = precheck(request, &self.identity, &self.features, host)
            .map_err(|refusal| refuse(FirecrackerRefusal::Admission { refusal }))?;
        let jail = JailId::derive(
            &request.execution,
            &request.tenant,
            &request.machine,
            &request.generations,
        );
        if self.uncleaned.contains_key(&jail) {
            return Err(refuse(FirecrackerRefusal::JailNotCleanedUp { jail }));
        }
        let reservation = self
            .reservations
            .reservation(request.reservation)
            .ok_or_else(|| {
                refuse(FirecrackerRefusal::ReservationUnknown {
                    reservation: request.reservation,
                })
            })?;
        let identity = self.free_identity().ok_or_else(|| {
            refuse(FirecrackerRefusal::NoJailIdentity {
                range: self.settings.host.jail_ids,
            })
        })?;
        let plan = LaunchPlan::build(&PlanInputs {
            request,
            profile: &self.settings.profile,
            configuration: &self.settings.configuration,
            host: &self.settings.host,
            identity,
            reservation: &reservation,
        })
        .map_err(|refusal| refuse(FirecrackerRefusal::Plan { refusal }))?;
        let planned = GoldenCheck::run(
            &self.settings.golden,
            &GoldenFile::from_plan(&plan),
            &self.settings.profile,
        );
        if !planned.passed() {
            return Err(refuse(FirecrackerRefusal::PlanNotGolden { check: planned }));
        }
        let paths = self.paths(&plan).map_err(refuse)?;
        let role = ProcessRole::VmHost {
            execution: request.execution.clone(),
            vm,
            boot,
        };
        let mut jail = Jail::new(&plan, identity, role, paths.cgroup.clone());
        match self.run(&plan, &paths, &mut jail, request, host, evidence) {
            Ok((launched, configured)) => {
                self.used_boots.insert((request.execution.clone(), boot));
                self.running.insert(
                    vm,
                    RunningVm {
                        launched: launched.clone(),
                        jail,
                        configured,
                    },
                );
                Ok(launched)
            }
            Err(refusal) => {
                let cleanup = jail.clean_up(&mut self.launcher, &self.host, true);
                if !jail.cleaned_up() {
                    self.uncleaned.insert(jail.id().clone(), jail);
                }
                Err(LaunchFailure {
                    vm,
                    refusal,
                    cleanup: Some(cleanup),
                })
            }
        }
    }

    /// The host paths of a plan's jail.
    fn paths(&self, plan: &LaunchPlan) -> Result<JailPaths, FirecrackerRefusal> {
        let name = |error| FirecrackerRefusal::Plan {
            refusal: PlanRefusal::Name { error },
        };
        let chroot = plan.jailer().chroot_dir().map_err(name)?;
        Ok(JailPaths {
            socket: chroot
                .within(&layout::path(layout::API_SOCKET))
                .map_err(name)?,
            cgroup: self
                .settings
                .host
                .cgroup_root
                .join_relative(&plan.expected_state().cgroup)
                .map_err(name)?,
            chroot,
        })
    }

    /// Steps 2 to 5 of a launch, from the first privileged operation to the sealed
    /// record, with what a re-observation checks the running VM against.
    fn run(
        &mut self,
        plan: &LaunchPlan,
        paths: &JailPaths,
        jail: &mut Jail,
        request: &LaunchRequest,
        host: &dyn HostEvidence,
        evidence: Satisfied,
    ) -> Result<(Launched, Configured), FirecrackerRefusal> {
        let vm = vm_handle(
            BackendKind::Firecracker,
            &request.execution,
            request.generations.boot,
        );
        let guest_image = self.set_up(plan, jail)?;
        let found = self
            .host
            .cgroup_processes(&paths.cgroup)
            .map_err(observation_failed)?;
        let [process] = found.as_slice() else {
            return Err(FirecrackerRefusal::JailProcesses { found });
        };
        let process = *process;
        jail.bind_process(process);

        let mut sent = Vec::new();
        for call in plan.api().calls() {
            let reply = self.api.send(&paths.socket, &call).map_err(|failure| {
                FirecrackerRefusal::ApiUnreachable {
                    path: call.path.clone(),
                    detail: failure.detail,
                }
            })?;
            if !reply.accepted() {
                return Err(FirecrackerRefusal::ApiRefused {
                    path: call.path,
                    status: reply.status,
                    fault_message: reply.fault_message,
                });
            }
            sent.push(reply.sent);
        }
        let configured = Configured {
            request: request.clone(),
            plan: plan.clone(),
            paths: paths.clone(),
            process,
            sent,
            guest_image,
        };
        let JailFacts {
            launch,
            configuration,
        } = self.observe_jail(&configured, false, host)?;
        let record = admit_with_configuration(
            request,
            &self.identity,
            host,
            evidence,
            launch,
            configuration,
            vm,
            None,
        )
        .map_err(|refusal| FirecrackerRefusal::Admission { refusal })?;
        Ok((Launched { vm, record }, configured))
    }

    /// Step 4, at launch and again later: Firecracker's own description and the
    /// configuration it runs against the golden file (VM-CP-02), the host's state, the
    /// process's status, namespaces, cgroup and descriptors against the expected state
    /// (VM-CP-04), its identity and chroot, and a KVM VM among its descriptors (VM-CP-01);
    /// the facts are stamped now, the configuration facts of the passing golden check
    /// with them. The guest image is the root image as the launcher verified the staged
    /// copy; observing `again`, it counts only while the host sees the process hold the
    /// staged root image, and is not observed otherwise.
    fn observe_jail(
        &mut self,
        configured: &Configured,
        again: bool,
        host: &dyn HostEvidence,
    ) -> Result<JailFacts, FirecrackerRefusal> {
        let Configured {
            plan,
            paths,
            process,
            sent,
            guest_image,
            ..
        } = configured;
        let process = *process;
        let info = self.api.describe(&paths.socket).map_err(|failure| {
            FirecrackerRefusal::ApiUnreachable {
                path: "/".to_owned(),
                detail: failure.detail,
            }
        })?;
        let Some(running) = running_configuration(
            plan.jail_id().as_str(),
            &info,
            sent,
            &plan.jailer().firecracker_args(),
        ) else {
            return Err(FirecrackerRefusal::InstanceMismatch {
                expected_id: plan.jail_id().clone(),
                info,
            });
        };
        let golden = GoldenCheck::run(&self.settings.golden, &running, &self.settings.profile);
        if !golden.passed() {
            return Err(FirecrackerRefusal::ConfigurationNotGolden { check: golden });
        }

        let state = self.host.host().map_err(observation_failed)?;
        // A process the host cannot read because it is gone or replaced is refused as such.
        let observation = match self.host.observe(&process, &paths.cgroup) {
            Ok(observation) => observation,
            Err(failure) => {
                return Err(match self.host.check(&process) {
                    Ok(found @ (IdentityCheck::Gone | IdentityCheck::Reused)) => {
                        FirecrackerRefusal::ProcessNotHeld { process, found }
                    }
                    Ok(IdentityCheck::Same) | Err(_) => observation_failed(failure),
                });
            }
        };
        match self.host.check(&process).map_err(observation_failed)? {
            IdentityCheck::Same => {}
            found => return Err(FirecrackerRefusal::ProcessNotHeld { process, found }),
        }
        let observed = linux_state(&observation, &process)?;
        let report = compare_linux_state(plan.expected_state(), &observed);
        if !report.passed() {
            return Err(FirecrackerRefusal::StateDiffers { report });
        }
        if observation.root != paths.chroot.as_str() {
            return Err(FirecrackerRefusal::NotChrooted {
                expected: paths.chroot.clone(),
                observed: observation.root,
            });
        }
        let mut controls = report.observed_controls();
        controls.insert(ConfinementControl::FilesystemLimits);
        let attached = !again
            || observation
                .descriptors
                .iter()
                .any(|target| target == layout::ROOT_IMAGE);
        let now = host.now();
        let fresh_for = self.settings.fresh_for;
        Ok(JailFacts {
            launch: launch_facts(
                &JailObservation {
                    host: &state,
                    kvm: holds_kvm_vm(&observation.descriptors),
                    controls,
                    guest_image: attached.then_some(*guest_image),
                    declares_network: self.settings.profile.declares_network(),
                },
                now,
                fresh_for,
            ),
            configuration: configuration_facts(
                &self.settings.golden,
                &running,
                &golden,
                &state,
                now,
                fresh_for,
            ),
        })
    }

    /// Performs every setup operation of the plan through the launch's session, checking
    /// each report; returns the root image as the launcher verified its staged copy.
    fn set_up(&mut self, plan: &LaunchPlan, jail: &mut Jail) -> Result<Digest, FirecrackerRefusal> {
        let mut guest_image = None;
        for operation in plan.launcher().setup() {
            let op = operation.tag();
            let report = jail
                .perform(&mut self.launcher, operation)
                .map_err(|error| step_refusal(op, error))?;
            match (operation, report) {
                (
                    PrivilegedOperation::StageArtifact {
                        role,
                        content_key,
                        length_bytes,
                        ..
                    },
                    LauncherReport::Staged {
                        content_key: staged,
                        length_bytes: staged_length,
                    },
                ) => {
                    if staged != *content_key || staged_length != *length_bytes {
                        return Err(FirecrackerRefusal::StagedArtifactDiffers {
                            role: *role,
                            pinned: *content_key,
                            pinned_length: *length_bytes,
                            staged,
                            staged_length,
                        });
                    }
                    if *role == ArtifactRole::RootImage {
                        guest_image = Some(*staged.digest());
                    }
                }
                (PrivilegedOperation::RunJailer { .. }, LauncherReport::JailerExited { code }) => {
                    if code != 0 {
                        return Err(FirecrackerRefusal::JailerFailed { code });
                    }
                }
                (
                    PrivilegedOperation::StageArtifact { .. }
                    | PrivilegedOperation::RunJailer { .. },
                    report,
                )
                | (
                    _,
                    report @ (LauncherReport::Staged { .. } | LauncherReport::JailerExited { .. }),
                ) => {
                    return Err(FirecrackerRefusal::UnexpectedReport { op, report });
                }
                (_, LauncherReport::Done) => {}
            }
        }
        guest_image.ok_or(FirecrackerRefusal::UnexpectedReport {
            op: "stage_artifact",
            report: LauncherReport::Done,
        })
    }

    /// Stops `vm`: kills its jail through the launch's own cgroup, once, and removes what
    /// the launch created once the host observes the end. Without that observation the VM
    /// stays listed and a later stop observes again; the kill is never sent twice. A
    /// refused launch's jail whose end the host has not observed is stopped the same way.
    pub fn stop_jail(&mut self, vm: &VmInstanceId) -> JailStop {
        let Some(running) = self.running.get_mut(vm) else {
            return self.stop_uncleaned(vm);
        };
        let cleanup = running.jail.clean_up(&mut self.launcher, &self.host, true);
        let Some(proof) = cleanup.proof().cloned() else {
            return JailStop::NotStopped { cleanup };
        };
        self.end(vm, proof);
        JailStop::Stopped { cleanup }
    }

    /// Stops the jail a refused launch of `vm` left without an observed end: another round
    /// of its cleanup, the kill not sent again. A VM whose end was observed is gone.
    fn stop_uncleaned(&mut self, vm: &VmInstanceId) -> JailStop {
        if self.ended.contains_key(vm) {
            return JailStop::AlreadyGone;
        }
        let Some(jail) = self
            .uncleaned
            .values_mut()
            .find(|jail| vm_of(jail) == Some(*vm))
        else {
            return JailStop::AlreadyGone;
        };
        let cleanup = jail.clean_up(&mut self.launcher, &self.host, true);
        let Some(proof) = cleanup.proof().cloned() else {
            return JailStop::NotStopped { cleanup };
        };
        self.ended.insert(*vm, proof);
        self.uncleaned.retain(|_, jail| !jail.cleaned_up());
        JailStop::Stopped { cleanup }
    }

    /// Moves a VM whose end the host observed to the ended, keeping its jail while its
    /// cleanup is incomplete.
    fn end(&mut self, vm: &VmInstanceId, proof: JailTermination) {
        if let Some(running) = self.running.remove(vm) {
            if !running.jail.cleaned_up() {
                self.uncleaned
                    .insert(running.jail.id().clone(), running.jail);
            }
        }
        self.ended.insert(*vm, proof);
    }

    /// Reconciles with the host: every running VM whose jail the host observes ended on
    /// its own is moved to the ended, with its proof, and its launch's removals are
    /// performed; every uncleaned jail whose end the host now observes gets its withheld
    /// removals. Returns the VMs found ended.
    pub fn reconcile(&mut self) -> Vec<VmInstanceId> {
        let ended: Vec<VmInstanceId> = self
            .running
            .iter()
            .filter(|(_, running)| running.jail.observe_end(&self.host, Ending::Exited).is_ok())
            .map(|(vm, _)| *vm)
            .collect();
        for vm in &ended {
            let proof = self.running.get_mut(vm).and_then(|running| {
                running
                    .jail
                    .clean_up(&mut self.launcher, &self.host, false)
                    .proof()
                    .cloned()
            });
            if let Some(proof) = proof {
                self.end(vm, proof);
            }
        }
        for jail in self.uncleaned.values_mut() {
            jail.clean_up(&mut self.launcher, &self.host, false);
        }
        self.uncleaned.retain(|_, jail| !jail.cleaned_up());
        ended
    }
}

/// The host paths of one jail.
#[derive(Clone, Debug)]
struct JailPaths {
    chroot: HostPath,
    /// The API socket Firecracker binds in the host-created socket directory.
    socket: HostPath,
    /// The launch's own cgroup.
    cgroup: HostPath,
}

/// A setup operation that was not performed, as a refusal.
fn step_refusal(op: &'static str, error: StepError) -> FirecrackerRefusal {
    match error {
        StepError::Refused(refusal) => FirecrackerRefusal::Launcher { refusal },
        StepError::Failed(failure) => FirecrackerRefusal::LauncherFailed {
            op,
            detail: failure.detail,
        },
    }
}

fn observation_failed(failure: ObservationFailure) -> FirecrackerRefusal {
    FirecrackerRefusal::ObservationFailed {
        detail: failure.detail,
    }
}

impl<L, A, H, R> VmBackend for FirecrackerBackend<L, A, H, R>
where
    L: LauncherPort,
    A: ApiPort,
    H: HostObservationPort,
    R: ReservationBook,
{
    fn identity(&self) -> &BackendIdentity {
        &self.identity
    }

    fn features(&self) -> &BackendFeatures {
        &self.features
    }

    fn launch(
        &mut self,
        request: &LaunchRequest,
        host: &dyn HostEvidence,
    ) -> Result<Launched, LaunchRefusal> {
        self.launch_jailed(request, host)
            .map_err(|failure| failure.to_launch_refusal())
    }

    fn stop(&mut self, vm: &VmInstanceId) -> Result<StopOutcome, BackendRefusal> {
        match self.stop_jail(vm) {
            JailStop::AlreadyGone => Ok(StopOutcome::AlreadyGone),
            JailStop::Stopped { .. } => Ok(StopOutcome::Stopped),
            JailStop::NotStopped { cleanup } => Err(BackendRefusal::Failed {
                operation: BackendOperation::Stop,
                detail: match &cleanup.end {
                    JailEnd::NotProven { reason } => reason.to_string(),
                    _ => "the host has not observed the jail's end".to_owned(),
                },
            }),
        }
    }

    fn snapshot(
        &mut self,
        _vm: &VmInstanceId,
        _origin: SnapshotOrigin,
    ) -> Result<SnapshotManifest, BackendRefusal> {
        Err(BackendRefusal::Unsupported {
            feature: Feature::Snapshot,
        })
    }

    fn restore(
        &mut self,
        _request: &LaunchRequest,
        _snapshot: &SnapshotManifest,
        _host: &dyn HostEvidence,
    ) -> Result<Restored, LaunchRefusal> {
        Err(LaunchRefusal::Unsupported {
            feature: Feature::Restore,
        })
    }

    fn actual_accelerator(
        &self,
        vm: &VmInstanceId,
    ) -> Result<HostObserved<Accelerator>, BackendRefusal> {
        self.running
            .get(vm)
            .map(|running| running.launched.record.accelerator().clone())
            .ok_or(BackendRefusal::NoSuchVm { vm: *vm })
    }

    fn confinement_evidence(
        &self,
        vm: &VmInstanceId,
    ) -> Result<ObservedProperties, BackendRefusal> {
        self.running
            .get(vm)
            .map(|running| running.launched.record.host_observed().clone())
            .ok_or(BackendRefusal::NoSuchVm { vm: *vm })
    }

    /// Every VM whose end the host has not observed, refused launches' jails included:
    /// one it cannot observe is listed, so that nothing it holds is released while it may
    /// run.
    fn running(&self) -> Vec<VmInstanceId> {
        let launched = self
            .running
            .iter()
            .filter(|(_, running)| {
                running
                    .jail
                    .observe_end(&self.host, Ending::Exited)
                    .is_err()
            })
            .map(|(vm, _)| *vm);
        let left = self
            .uncleaned
            .values()
            .filter(|jail| jail.observe_end(&self.host, Ending::Exited).is_err())
            .filter_map(vm_of);
        launched
            .chain(left)
            .collect::<BTreeSet<VmInstanceId>>()
            .into_iter()
            .collect()
    }

    /// Observes a running VM again through the same ports as step 4 of its launch, stamped
    /// now, with the launch's CORE-01 requirements evaluated again. Nothing is changed or
    /// ended; a VM that no longer passes is refused as its launch would be.
    fn reobserve(
        &mut self,
        vm: &VmInstanceId,
        host: &dyn HostEvidence,
    ) -> Result<Reobservation, ReobservationRefusal> {
        let Some(running) = self.running.get(vm) else {
            return Err(
                if self.uncleaned.values().any(|jail| vm_of(jail) == Some(*vm)) {
                    ReobservationRefusal::NotAdmitted { vm: *vm }
                } else {
                    ReobservationRefusal::NoSuchVm { vm: *vm }
                },
            );
        };
        let configured = running.configured.clone();
        let record = running.launched.record.clone();
        let observed = self
            .observe_jail(&configured, true, host)
            .map_err(|refusal| ReobservationRefusal::Refused {
                refusal: Box::new(refusal.launch_refusal()),
            })?;
        reobserved_with_configuration(
            &configured.request,
            &record,
            &self.identity,
            host,
            observed.launch,
            observed.configuration,
        )
    }
}
