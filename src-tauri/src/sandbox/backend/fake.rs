//! The fake backend of VM-W16 (line 2615), driven by a script of what the host observes,
//! so lifecycle and scenario tests upstream can launch, stop, snapshot, restore, observe
//! again and fail deterministically, a refused launch whose cleanup is incomplete
//! included. The script may also state the hypervisor configuration the host observes
//! (VM-CP-02, VM-CP-03), and a test may hand the fake GPU checks the host made before
//! assignment (VM-CP-31), which it orders before the assignment it stamps at launch; it
//! makes the same configuration facts again when it observes a running VM again. It
//! touches nothing on the host and certifies nothing (S2 line 206); its kind is always
//! [`BackendKind::Fake`], which the evidence matrix refuses to call supported.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::accelerator::{Accelerator, Emulator, HardwareFailure};
use super::admission::{admit_with_configuration, precheck, vm_handle, LaunchFacts};
use super::configuration::{
    ConfigurationComparison, ConfigurationFacts, GpuAssignmentOrder, HostInterfaceListing,
};
use super::contract::{
    BackendFeatures, BackendIdentity, BackendKind, BackendOperation, BackendRefusal,
    DeveloperEmulation, EmulatedVm, Feature, HostEvidence, LaunchRefusal, Launched, LeftBehind,
    ReobservationRefusal, Restored, StopOutcome, VmBackend,
};
use super::facets::{
    ConfinementControl, CredentialExposure, DeviceInventory, IsolationObservation,
    NetworkAuthority, ObservedGpu, OperatorConfidentiality, Persistence, PhysicalHost,
};
use super::observation::{
    GuestAsserted, GuestAssertions, HostBuild, HostFact, HostObserved, ObservedProperties,
};
use super::reobservation::{reobserved_with_configuration, Reobservation};
use super::request::{EmulationRequest, LaunchRequest};
use crate::foundation::coordination::{
    validate_vm_snapshot, verify_restored_vm, RestoreAction, RestoreExpectation, RestoredVmReport,
    SnapshotContent, SnapshotId, SnapshotManifest, SnapshotOrigin, VmInstanceId,
};
use crate::foundation::evidence::{
    BackendVersion, ClockReading, ConfigurationFingerprint, HypervisorKind, SourceClass,
    UnknownReason,
};
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionId, SandboxBootGeneration};

/// The digest domain of the fake's snapshot identities.
const SNAPSHOT_DOMAIN: &str = "yougori/sandbox/fake/snapshot/v1";
/// The digest domain of the fake's guest identities.
const GUEST_IDENTITY_DOMAIN: &str = "yougori/sandbox/fake/guest-identity/v1";
/// The digest domain of the fake's emulated VM handles.
const EMULATED_DOMAIN: &str = "yougori/sandbox/fake/emulated/v1";
/// The first PID the fake hands out.
const FIRST_PID: u32 = 1000;

/// What the script says the host observes about one fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Scripted<T> {
    HostObserved(T),
    /// Host-observed and corroborated by the controlled check `control` names.
    Verified {
        value: T,
        control: Digest,
    },
    /// The host observes nothing.
    Unavailable {
        reason: UnknownReason,
    },
}

impl<T: Clone> Scripted<T> {
    fn stamp(
        &self,
        now: ClockReading,
        fresh_for: Duration,
        configuration: ConfigurationFingerprint,
    ) -> HostFact<T> {
        match self {
            Self::HostObserved(value) => HostFact::observed(HostObserved::stamp(
                value.clone(),
                now,
                fresh_for,
                configuration,
            )),
            Self::Verified { value, control } => HostFact::observed(HostObserved::verified(
                value.clone(),
                now,
                fresh_for,
                configuration,
                *control,
            )),
            Self::Unavailable { reason } => HostFact::unavailable(*reason),
        }
    }
}

/// What the guest asserts about itself, per facet; `None` means it says nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestScript {
    pub accelerator: Option<Accelerator>,
    pub isolation: Option<IsolationObservation>,
    pub confinement: Option<BTreeSet<ConfinementControl>>,
    pub network: Option<NetworkAuthority>,
    pub credentials: Option<CredentialExposure>,
    pub persistence: Option<Persistence>,
    pub devices: Option<DeviceInventory>,
    pub confidentiality: Option<OperatorConfidentiality>,
}

impl GuestScript {
    fn received(&self, now: ClockReading) -> GuestAssertions {
        GuestAssertions {
            accelerator: self
                .accelerator
                .map(|value| GuestAsserted::received(value, now)),
            isolation: self
                .isolation
                .map(|value| GuestAsserted::received(value, now)),
            confinement: self
                .confinement
                .clone()
                .map(|value| GuestAsserted::received(value, now)),
            network: self
                .network
                .clone()
                .map(|value| GuestAsserted::received(value, now)),
            credentials: self
                .credentials
                .clone()
                .map(|value| GuestAsserted::received(value, now)),
            persistence: self
                .persistence
                .clone()
                .map(|value| GuestAsserted::received(value, now)),
            devices: self
                .devices
                .clone()
                .map(|value| GuestAsserted::received(value, now)),
            confidentiality: self
                .confidentiality
                .map(|value| GuestAsserted::received(value, now)),
        }
    }
}

/// What the host observes when the fake launches, and how the fake behaves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostScript {
    /// The configuration the host's observations are made under.
    pub configuration: ConfigurationFingerprint,
    /// How long each observation stays fresh.
    pub fresh_for: Duration,
    pub host: Scripted<HostBuild>,
    /// The guest image the host observes booted.
    pub guest_image: Scripted<Digest>,
    pub accelerator: Scripted<Accelerator>,
    /// A hardware virtualization failure met while creating; nothing is created.
    pub hardware_failure: Option<HardwareFailure>,
    /// A creation failure of the backend itself; nothing is created.
    pub create_failure: Option<String>,
    pub isolation: Scripted<IsolationObservation>,
    pub confinement: Scripted<BTreeSet<ConfinementControl>>,
    pub network: Scripted<NetworkAuthority>,
    pub credentials: Scripted<CredentialExposure>,
    pub persistence: Scripted<Persistence>,
    pub devices: Scripted<DeviceInventory>,
    pub confidentiality: Scripted<OperatorConfidentiality>,
    pub guest: GuestScript,
    /// Forbidden contents a snapshot is found to contain.
    pub snapshot_contents: BTreeSet<SnapshotContent>,
    /// What a restore performs on the restored VM.
    pub restore_actions: BTreeSet<RestoreAction>,
    /// A broken restore that brings back the snapshot's VM handle and guest identity.
    pub restore_reuses_identity: bool,
    /// A failure to end a created VM: a launch refused after creation leaves it running
    /// and listed, and a stop fails, while this is set. Scripts written before it read as
    /// none.
    #[serde(default)]
    pub teardown_failure: Option<String>,
    /// A failure to observe a running VM again. Scripts written before it read as none.
    #[serde(default)]
    pub reobserve_failure: Option<String>,
    /// The golden comparison the host makes of the running configuration (VM-CP-02),
    /// stamped at launch; none passes no comparison. Scripts written before it read as
    /// none.
    #[serde(default)]
    pub configuration_comparison: Option<ConfigurationComparison>,
    /// The listing check the host makes of the running hypervisor (VM-CP-03), stamped at
    /// launch; none passes no listing. Scripts written before it read as none.
    #[serde(default)]
    pub interface_listing: Option<HostInterfaceListing>,
}

impl HostScript {
    /// A clean hardware VM: every fact host-observed, an own guest kernel on a shared
    /// host, every confinement control, offline, no credentials, an ephemeral task, CPU
    /// only, no confidentiality claim, every required restore action, and observations
    /// fresh for ten minutes.
    pub fn hardware_vm(
        hypervisor: HypervisorKind,
        host: HostBuild,
        guest_image: Digest,
        configuration: ConfigurationFingerprint,
    ) -> Self {
        Self {
            configuration,
            fresh_for: Duration::from_secs(600),
            host: Scripted::HostObserved(host),
            guest_image: Scripted::HostObserved(guest_image),
            accelerator: Scripted::HostObserved(Accelerator::Hardware { hypervisor }),
            hardware_failure: None,
            create_failure: None,
            isolation: Scripted::HostObserved(IsolationObservation {
                own_guest_kernel: true,
                physical_host: PhysicalHost::Shared,
            }),
            confinement: Scripted::HostObserved(ConfinementControl::all()),
            network: Scripted::HostObserved(NetworkAuthority::offline()),
            credentials: Scripted::HostObserved(CredentialExposure::none()),
            persistence: Scripted::HostObserved(Persistence::EphemeralTask),
            devices: Scripted::HostObserved(DeviceInventory::cpu_only()),
            confidentiality: Scripted::HostObserved(OperatorConfidentiality::None),
            guest: GuestScript::default(),
            snapshot_contents: BTreeSet::new(),
            restore_actions: RestoreAction::REQUIRED.into_iter().collect(),
            restore_reuses_identity: false,
            teardown_failure: None,
            reobserve_failure: None,
            configuration_comparison: None,
            interface_listing: None,
        }
    }

    /// The configuration facts the host observes now: the scripted comparison and
    /// listing stamped now, and no GPU order.
    pub fn configuration_facts(&self, now: ClockReading) -> ConfigurationFacts {
        ConfigurationFacts {
            comparison: self.configuration_comparison.map(|comparison| {
                HostObserved::stamp(comparison, now, self.fresh_for, self.configuration)
            }),
            listing: self.interface_listing.map(|listing| {
                HostObserved::stamp(listing, now, self.fresh_for, self.configuration)
            }),
            gpu_assignments: Vec::new(),
        }
    }

    /// The facts the host observes now, stamped on the evidence clock, as the fake hands
    /// them to admission.
    pub fn facts(&self, now: ClockReading) -> LaunchFacts {
        LaunchFacts {
            accelerator: self
                .accelerator
                .stamp(now, self.fresh_for, self.configuration),
            observed: ObservedProperties {
                host: self.host.stamp(now, self.fresh_for, self.configuration),
                guest_image: self
                    .guest_image
                    .stamp(now, self.fresh_for, self.configuration),
                isolation: self
                    .isolation
                    .stamp(now, self.fresh_for, self.configuration),
                confinement: self
                    .confinement
                    .stamp(now, self.fresh_for, self.configuration),
                network: self.network.stamp(now, self.fresh_for, self.configuration),
                credentials: self
                    .credentials
                    .stamp(now, self.fresh_for, self.configuration),
                persistence: self
                    .persistence
                    .stamp(now, self.fresh_for, self.configuration),
                devices: self.devices.stamp(now, self.fresh_for, self.configuration),
                confidentiality: self.confidentiality.stamp(
                    now,
                    self.fresh_for,
                    self.configuration,
                ),
            },
            guest: self.guest.received(now),
        }
    }
}

/// A call the fake made, in order, for tests that check what happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FakeCall {
    Precheck {
        execution: ExecutionId,
    },
    Create {
        vm: VmInstanceId,
        pid: u32,
    },
    Teardown {
        vm: VmInstanceId,
    },
    Stop {
        vm: VmInstanceId,
    },
    Snapshot {
        vm: VmInstanceId,
    },
    Restore {
        vm: VmInstanceId,
        pid: u32,
    },
    Emulate {
        vm: VmInstanceId,
    },
    /// A refused launch's VM that the script kept from ending.
    TeardownFailed {
        vm: VmInstanceId,
    },
    Reobserve {
        vm: VmInstanceId,
    },
}

#[derive(Clone, Debug)]
struct FakeVm {
    pid: u32,
    guest_identity: Digest,
    request: LaunchRequest,
    launched: Launched,
}

/// The scripted fake backend (VM-W16).
///
/// Handles are digests of the sandbox and boot generation, never PIDs. PIDs come from a
/// small pool that reuses a stopped VM's number first, so a test can show that a stale
/// handle never reaches the process that inherited its PID (VM part §6.4).
#[derive(Debug)]
pub struct FakeBackend {
    identity: BackendIdentity,
    features: BackendFeatures,
    script: HostScript,
    vms: BTreeMap<VmInstanceId, FakeVm>,
    /// Refused launches' VMs that did not end, with their PIDs.
    stuck: BTreeMap<VmInstanceId, u32>,
    emulated: BTreeMap<VmInstanceId, u32>,
    used_boots: BTreeSet<(ExecutionId, SandboxBootGeneration)>,
    free_pids: BTreeSet<u32>,
    next_pid: u32,
    pids_reused: u64,
    snapshots_taken: u64,
    emulation_launches: u64,
    calls: Vec<FakeCall>,
    /// GPU checks the host made before assignment, as a test handed them over.
    checked_gpus: Vec<HostObserved<ObservedGpu>>,
}

impl FakeBackend {
    /// A fake that launches with `hypervisor`, identified as `version` and `artifact`,
    /// offering launch and stop only.
    pub fn new(
        hypervisor: HypervisorKind,
        version: BackendVersion,
        artifact: Digest,
        script: HostScript,
    ) -> Self {
        Self {
            identity: BackendIdentity {
                kind: BackendKind::Fake,
                version,
                artifact,
                hypervisor,
            },
            features: BackendFeatures::none(),
            script,
            vms: BTreeMap::new(),
            stuck: BTreeMap::new(),
            emulated: BTreeMap::new(),
            used_boots: BTreeSet::new(),
            free_pids: BTreeSet::new(),
            next_pid: FIRST_PID,
            pids_reused: 0,
            snapshots_taken: 0,
            emulation_launches: 0,
            calls: Vec::new(),
            checked_gpus: Vec::new(),
        }
    }

    /// From the next launch on, the host's checks of GPUs before assignment (VM-CP-31):
    /// each launch and restore orders every one before an assignment of its device that
    /// it stamps then, and passes the orders to admission. A test stamps the checks before
    /// the launch, on the registry's clock; an empty list passes no order.
    pub fn check_gpus_before_assignment(&mut self, checked: Vec<HostObserved<ObservedGpu>>) {
        self.checked_gpus = checked;
    }

    /// The configuration facts of a launch at `now`: the script's, and an order for every
    /// GPU checked before assignment.
    fn configuration_facts(&self, now: ClockReading) -> ConfigurationFacts {
        let mut facts = self.script.configuration_facts(now);
        facts.gpu_assignments = self
            .checked_gpus
            .iter()
            .map(|checked| GpuAssignmentOrder {
                checked: checked.clone(),
                assigned: HostObserved::stamp(
                    checked.value().device,
                    now,
                    self.script.fresh_for,
                    self.script.configuration,
                ),
            })
            .collect();
        facts
    }

    /// Offers `features` as well.
    pub fn with_features(mut self, features: BackendFeatures) -> Self {
        self.features = features;
        self
    }

    pub fn script(&self) -> &HostScript {
        &self.script
    }

    /// Changes what the host observes from the next launch on.
    pub fn script_mut(&mut self) -> &mut HostScript {
        &mut self.script
    }

    /// The PID the fake's process for `vm` has, while it runs.
    pub fn pid_of(&self, vm: &VmInstanceId) -> Option<u32> {
        self.vms
            .get(vm)
            .map(|fake| fake.pid)
            .or_else(|| self.stuck.get(vm).copied())
            .or_else(|| self.emulated.get(vm).copied())
    }

    /// How many launches took over a stopped VM's PID.
    pub fn pids_reused(&self) -> u64 {
        self.pids_reused
    }

    /// How many emulated VMs were started; a production launch never adds to it.
    pub fn emulation_launches(&self) -> u64 {
        self.emulation_launches
    }

    /// The handles of the emulated, non-sandbox VMs.
    pub fn emulated(&self) -> Vec<VmInstanceId> {
        self.emulated.keys().copied().collect()
    }

    pub fn calls(&self) -> &[FakeCall] {
        &self.calls
    }

    fn allocate_pid(&mut self) -> u32 {
        if let Some(pid) = self.free_pids.iter().next().copied() {
            self.free_pids.remove(&pid);
            self.pids_reused += 1;
            return pid;
        }
        let pid = self.next_pid;
        self.next_pid = self.next_pid.saturating_add(1);
        pid
    }

    fn release_pid(&mut self, pid: u32) {
        self.free_pids.insert(pid);
    }

    fn running_boot(&self, request: &LaunchRequest) -> Option<&FakeVm> {
        let handle = vm_handle(
            BackendKind::Fake,
            &request.execution,
            request.generations.boot,
        );
        self.vms.get(&handle)
    }

    fn boot_unused(&self, request: &LaunchRequest) -> Result<(), LaunchRefusal> {
        let key = (request.execution.clone(), request.generations.boot);
        if self.used_boots.contains(&key) {
            return Err(LaunchRefusal::BootGenerationUsed {
                execution: request.execution.clone(),
                boot: request.generations.boot,
            });
        }
        Ok(())
    }

    /// Creates the fake process for `vm`, or refuses as the script says.
    fn create(&mut self, vm: VmInstanceId, restore: bool) -> Result<u32, LaunchRefusal> {
        if let Some(failure) = &self.script.hardware_failure {
            return Err(LaunchRefusal::HardwareVirtualizationFailed {
                failure: failure.clone(),
            });
        }
        if let Some(detail) = &self.script.create_failure {
            return Err(LaunchRefusal::CreateFailed {
                detail: detail.clone(),
            });
        }
        let pid = self.allocate_pid();
        self.calls.push(if restore {
            FakeCall::Restore { vm, pid }
        } else {
            FakeCall::Create { vm, pid }
        });
        Ok(pid)
    }

    fn teardown(&mut self, vm: VmInstanceId, pid: u32) {
        self.release_pid(pid);
        self.calls.push(FakeCall::Teardown { vm });
    }

    /// Ends a created VM whose launch was refused and returns the refusal; when the script
    /// keeps the VM from ending, it stays running and listed, its boot generation counts
    /// as used, and the refusal says what is left.
    fn refuse_created(
        &mut self,
        request: &LaunchRequest,
        vm: VmInstanceId,
        pid: u32,
        refusal: LaunchRefusal,
    ) -> LaunchRefusal {
        let Some(detail) = self.script.teardown_failure.clone() else {
            self.teardown(vm, pid);
            return refusal;
        };
        self.stuck.insert(vm, pid);
        self.used_boots
            .insert((request.execution.clone(), request.generations.boot));
        self.calls.push(FakeCall::TeardownFailed { vm });
        LaunchRefusal::CleanupIncomplete {
            vm,
            refusal: Box::new(refusal),
            left: vec![LeftBehind::Process { detail }],
        }
    }

    fn guest_identity(vm: VmInstanceId, boot: SandboxBootGeneration) -> Digest {
        DigestBuilder::new(GUEST_IDENTITY_DOMAIN)
            .digest(&vm.digest())
            .u64(boot.get())
            .finish()
    }

    fn keep(
        &mut self,
        request: &LaunchRequest,
        pid: u32,
        guest_identity: Digest,
        launched: Launched,
    ) {
        self.used_boots
            .insert((request.execution.clone(), request.generations.boot));
        self.vms.insert(
            launched.vm,
            FakeVm {
                pid,
                guest_identity,
                request: request.clone(),
                launched,
            },
        );
    }
}

impl VmBackend for FakeBackend {
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
        if let Some(running) = self.running_boot(request) {
            return Ok(running.launched.clone());
        }
        self.boot_unused(request)?;
        self.calls.push(FakeCall::Precheck {
            execution: request.execution.clone(),
        });
        let evidence = precheck(request, &self.identity, &self.features, host)?;
        let vm = vm_handle(
            BackendKind::Fake,
            &request.execution,
            request.generations.boot,
        );
        let pid = self.create(vm, false)?;
        let now = host.now();
        let facts = self.script.facts(now);
        let configuration = self.configuration_facts(now);
        match admit_with_configuration(
            request,
            &self.identity,
            host,
            evidence,
            facts,
            configuration,
            vm,
            None,
        ) {
            Ok(record) => {
                let launched = Launched { vm, record };
                let guest_identity = Self::guest_identity(vm, request.generations.boot);
                self.keep(request, pid, guest_identity, launched.clone());
                Ok(launched)
            }
            Err(refusal) => Err(self.refuse_created(request, vm, pid, refusal)),
        }
    }

    /// Stops the VM; while the script keeps VMs from ending, a stop of a running or left
    /// VM fails and the VM stays listed.
    fn stop(&mut self, vm: &VmInstanceId) -> Result<StopOutcome, BackendRefusal> {
        self.calls.push(FakeCall::Stop { vm: *vm });
        if let Some(detail) = &self.script.teardown_failure {
            if self.vms.contains_key(vm) || self.stuck.contains_key(vm) {
                return Err(BackendRefusal::Failed {
                    operation: BackendOperation::Stop,
                    detail: detail.clone(),
                });
            }
        }
        if let Some(fake) = self.vms.remove(vm) {
            self.release_pid(fake.pid);
            return Ok(StopOutcome::Stopped);
        }
        if let Some(pid) = self.stuck.remove(vm) {
            self.release_pid(pid);
            return Ok(StopOutcome::Stopped);
        }
        if let Some(pid) = self.emulated.remove(vm) {
            self.release_pid(pid);
            return Ok(StopOutcome::Stopped);
        }
        Ok(StopOutcome::AlreadyGone)
    }

    fn snapshot(
        &mut self,
        vm: &VmInstanceId,
        origin: SnapshotOrigin,
    ) -> Result<SnapshotManifest, BackendRefusal> {
        if !self.features.supports(Feature::Snapshot) {
            return Err(BackendRefusal::Unsupported {
                feature: Feature::Snapshot,
            });
        }
        let fake = self
            .vms
            .get(vm)
            .ok_or(BackendRefusal::NoSuchVm { vm: *vm })?;
        self.snapshots_taken += 1;
        let snapshot = SnapshotId::new(
            DigestBuilder::new(SNAPSHOT_DOMAIN)
                .digest(&vm.digest())
                .u64(self.snapshots_taken)
                .finish(),
        );
        let manifest = SnapshotManifest {
            snapshot,
            origin,
            image_profile: fake.launched.record.pinned().guest_image,
            contents: self.script.snapshot_contents.clone(),
            source_vm: *vm,
            guest_identity: fake.guest_identity,
        };
        self.calls.push(FakeCall::Snapshot { vm: *vm });
        Ok(manifest)
    }

    fn restore(
        &mut self,
        request: &LaunchRequest,
        snapshot: &SnapshotManifest,
        host: &dyn HostEvidence,
    ) -> Result<Restored, LaunchRefusal> {
        self.features.require(Feature::Restore)?;
        validate_vm_snapshot(snapshot, request.pinned.guest_image)
            .map_err(|defects| LaunchRefusal::SnapshotNotRestorable { defects })?;
        self.boot_unused(request)?;
        self.calls.push(FakeCall::Precheck {
            execution: request.execution.clone(),
        });
        let evidence = precheck(request, &self.identity, &self.features, host)?;
        let boot = request.generations.boot;
        let fresh = vm_handle(BackendKind::Fake, &request.execution, boot);
        let (vm, guest_identity) = if self.script.restore_reuses_identity {
            (snapshot.source_vm, snapshot.guest_identity)
        } else {
            (fresh, Self::guest_identity(fresh, boot))
        };
        let pid = self.create(vm, true)?;
        let report = RestoredVmReport {
            vm,
            boot,
            snapshot: snapshot.snapshot,
            guest_identity,
            actions: self.script.restore_actions.clone(),
            attached_volumes: request.required.persistence.volumes(),
            policy: request.generations.policy,
            image_profile: snapshot.image_profile,
            presented_epochs: BTreeSet::new(),
            source: SourceClass::HostProbe,
        };
        let expectation = RestoreExpectation {
            boot,
            snapshot: snapshot.clone(),
            authorized_volumes: request.required.persistence.volumes(),
            policy: request.generations.policy,
        };
        let verified = match verify_restored_vm(&report, &expectation) {
            Ok(verified) => verified,
            Err(refusal) => {
                return Err(self.refuse_created(
                    request,
                    vm,
                    pid,
                    LaunchRefusal::RestoreRefused { refusal },
                ));
            }
        };
        let now = host.now();
        let facts = self.script.facts(now);
        let configuration = self.configuration_facts(now);
        match admit_with_configuration(
            request,
            &self.identity,
            host,
            evidence,
            facts,
            configuration,
            vm,
            Some(snapshot.snapshot),
        ) {
            Ok(record) => {
                let launched = Launched { vm, record };
                self.keep(request, pid, guest_identity, launched.clone());
                Ok(Restored {
                    launched,
                    report,
                    verified,
                })
            }
            Err(refusal) => Err(self.refuse_created(request, vm, pid, refusal)),
        }
    }

    fn actual_accelerator(
        &self,
        vm: &VmInstanceId,
    ) -> Result<HostObserved<Accelerator>, BackendRefusal> {
        self.vms
            .get(vm)
            .map(|fake| fake.launched.record.accelerator().clone())
            .ok_or(BackendRefusal::NoSuchVm { vm: *vm })
    }

    fn confinement_evidence(
        &self,
        vm: &VmInstanceId,
    ) -> Result<ObservedProperties, BackendRefusal> {
        self.vms
            .get(vm)
            .map(|fake| fake.launched.record.host_observed().clone())
            .ok_or(BackendRefusal::NoSuchVm { vm: *vm })
    }

    /// Every admitted VM and every refused launch's VM that did not end.
    fn running(&self) -> Vec<VmInstanceId> {
        self.vms
            .keys()
            .chain(self.stuck.keys())
            .copied()
            .collect::<BTreeSet<VmInstanceId>>()
            .into_iter()
            .collect()
    }

    /// Observes the running VM again: the script's facts as they are now, stamped now,
    /// with the configuration facts a launch passes now (the script's comparison and
    /// listing, and an order for every GPU checked before assignment) and the launch's
    /// CORE-01 requirements evaluated again; refused as the script says.
    fn reobserve(
        &mut self,
        vm: &VmInstanceId,
        host: &dyn HostEvidence,
    ) -> Result<Reobservation, ReobservationRefusal> {
        self.calls.push(FakeCall::Reobserve { vm: *vm });
        let Some(fake) = self.vms.get(vm) else {
            return Err(if self.stuck.contains_key(vm) {
                ReobservationRefusal::NotAdmitted { vm: *vm }
            } else {
                ReobservationRefusal::NoSuchVm { vm: *vm }
            });
        };
        if let Some(detail) = &self.script.reobserve_failure {
            return Err(ReobservationRefusal::refused(
                LaunchRefusal::BackendSpecific {
                    backend: BackendKind::Fake,
                    detail: detail.clone(),
                },
            ));
        }
        let now = host.now();
        let facts = self.script.facts(now);
        let configuration = self.configuration_facts(now);
        reobserved_with_configuration(
            &fake.request,
            &fake.launched.record,
            &self.identity,
            host,
            facts,
            configuration,
        )
    }
}

impl DeveloperEmulation for FakeBackend {
    fn launch_emulated(
        &mut self,
        request: &EmulationRequest,
        host: &dyn HostEvidence,
    ) -> Result<EmulatedVm, BackendRefusal> {
        if !self.features.supports(Feature::DeveloperEmulation) {
            return Err(BackendRefusal::Unsupported {
                feature: Feature::DeveloperEmulation,
            });
        }
        self.emulation_launches += 1;
        let vm = VmInstanceId::new(
            DigestBuilder::new(EMULATED_DOMAIN)
                .str(request.execution.as_str())
                .digest(&request.guest_image)
                .u64(self.emulation_launches)
                .u64(host.now().at().as_nanos())
                .finish(),
        );
        let pid = self.allocate_pid();
        self.emulated.insert(vm, pid);
        self.calls.push(FakeCall::Emulate { vm });
        Ok(EmulatedVm {
            vm,
            execution: request.execution.clone(),
            emulator: Emulator::Tcg,
        })
    }
}
