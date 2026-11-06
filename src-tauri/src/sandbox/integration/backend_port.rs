//! The backend contract as the lifecycle's backend port (VM part §6.1 launch
//! transaction, §6.4 handles that are never a PID, §6.6 restore; VM-W16 line 2613; VM-W22
//! line 2620; §8.1 launch records; VM-P01 line 2776, VM-P21 line 2796, VM-P42 line 2817,
//! VM-P49 line 2824; the VB1 and VL1 integration notes of the rollout plan).
//!
//! The lifecycle supervisor drives the CORE-04 launch transaction through its own small
//! `VmBackend` port; the backend contract of VB1 is wider and typed differently. The
//! [`BackendPort`] bridges them for the duration of one supervisor call, over a
//! [`LaunchTable`] that outlives the call: the launch profiles per execution, every
//! sealed launch record, the restored-VM reports, the perimeters prepared, and every
//! refused launch with its typed refusal.
//!
//! - A boot request becomes a backend launch request with the reservation key mapped to
//!   the ledger reservation id, the contract digest and the rest from the profile.
//! - Readiness is the backend's host-observed state: the VM runs, its confinement
//!   evidence is readable, and the record's facts are current on the host clock. Once the
//!   launch-time facts are stale, the latest re-observation counts while it is current;
//!   otherwise the port asks the backend to observe the VM again
//!   (`VmBackend::reobserve`) and the record judges what the host found by the rules of
//!   admission (`LaunchRecord::assert_current_with`). Readiness stays unavailable until
//!   that fresh evidence exists (§8.1 line 2439; leftover entries H01, S01, M02, M08).
//! - A handle is the backend's stable VM identity plus the launch record's identity as
//!   its token. A check consults the backend's running set and the record: a stale handle
//!   whose VM is gone stops nothing, and a token that does not match its record is never
//!   acted on (§6.4; VM-P49).
//! - A refused launch or restore is the lifecycle's typed `BackendFailure`, and nothing
//!   was kept: no record, no handle, no authority (VM-P01, VM-P42). When the backend says
//!   its cleanup is incomplete (`LaunchRefusal::CleanupIncomplete`), the boot's perimeter
//!   is held for the VM left behind: removing it first stops that VM through the backend,
//!   and refuses while the backend cannot, so the lifecycle's rollback stalls and nothing
//!   the VM may still use is released.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use super::profile::{LaunchProfile, ReservationResolver, ReservationUnresolved};
use crate::foundation::coordination::{
    BootRequest, PerimeterId, Readiness, ReadinessReport, RestoredVmReport, SnapshotId,
    SnapshotManifest, SnapshotOrigin, VmInstanceId,
};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{
    Digest, DigestBuilder, ExecutionId, MonotonicTime, PolicyEpoch, SandboxBootGeneration,
};
use crate::sandbox::backend::{
    BackendRefusal, Feature, HostEvidence, LaunchRecord, LaunchRefusal, LaunchRequest, Launched,
    Reobservation, Restored, StopOutcome as ContractStop, VmBackend as ContractBackend,
};
use crate::sandbox::lifecycle::{
    BackendCapabilities, BackendFailure, BackendOperation, HandleIdentity, StateReset, StopOutcome,
    VmBackend as LifecycleBackend, VmHandle,
};

/// The digest domain of the perimeter identities this port prepares.
pub const PERIMETER_DOMAIN: &str = "yougori/sandbox/integration/perimeter/v1";

/// What the port is configured with: the host machine the launches bind to, and whether
/// the backend's restore resets a clone's application state (§6.6: "choose cold boot
/// when the application state cannot be safely reset"). The backend contract has no
/// state-reset feature, so the declaration is explicit here and never assumed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PortConfig {
    /// The host machine, by the identity digest its host adapter derives (CORE-01).
    pub machine: Digest,
    pub state_reset: StateReset,
}

/// Which operation a refused launch attempted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchAttempt {
    Launch,
    Restore,
}

/// Why the port could not launch or restore. Every variant is typed; the lifecycle sees
/// its `Display` as the backend failure's detail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum LaunchProblem {
    /// No launch profile was set for the execution; nothing was launched.
    NoProfile { execution: ExecutionId },
    /// The boot's reservation key names no ledger reservation the backend may bind.
    Reservation { refusal: ReservationUnresolved },
    /// The perimeter handed to the launch is not the one prepared for this boot.
    PerimeterNotPrepared { perimeter: PerimeterId },
    /// The backend refused, with its typed refusal (VB1).
    Backend { refusal: LaunchRefusal },
}

impl fmt::Display for LaunchProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProfile { execution } => {
                write!(f, "no launch profile is set for execution {execution}")
            }
            Self::Reservation { refusal } => write!(f, "{refusal}"),
            Self::PerimeterNotPrepared { perimeter } => {
                write!(f, "perimeter {perimeter} was not prepared for this boot")
            }
            Self::Backend { refusal } => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for LaunchProblem {}

/// A launch or restore the port refused, kept with its typed problem so the audit sink
/// can record the refusal as such. Serialize only, like the refusal it carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RefusedLaunch {
    pub execution: ExecutionId,
    pub boot: SandboxBootGeneration,
    pub attempt: LaunchAttempt,
    pub problem: LaunchProblem,
    /// When the port refused, on the host evidence clock.
    pub at: MonotonicTime,
}

/// What the port keeps across supervisor calls.
#[derive(Debug)]
pub struct LaunchTable {
    config: PortConfig,
    profiles: BTreeMap<ExecutionId, LaunchProfile>,
    records: BTreeMap<VmInstanceId, LaunchRecord>,
    restored: BTreeMap<VmInstanceId, RestoredVmReport>,
    perimeters: BTreeSet<PerimeterId>,
    refused: Vec<RefusedLaunch>,
    unrecorded: BTreeSet<VmInstanceId>,
    /// The latest re-observation of each VM, by its handle.
    reobservations: BTreeMap<VmInstanceId, Reobservation>,
    /// The VM a refused launch left behind, by the perimeter of its boot.
    left_behind: BTreeMap<PerimeterId, VmInstanceId>,
}

impl LaunchTable {
    pub fn new(config: PortConfig) -> Self {
        Self {
            config,
            profiles: BTreeMap::new(),
            records: BTreeMap::new(),
            restored: BTreeMap::new(),
            perimeters: BTreeSet::new(),
            refused: Vec::new(),
            unrecorded: BTreeSet::new(),
            reobservations: BTreeMap::new(),
            left_behind: BTreeMap::new(),
        }
    }

    pub fn config(&self) -> &PortConfig {
        &self.config
    }

    /// Sets the profile every boot of `execution` launches under; replaces an earlier one.
    pub fn set_profile(&mut self, execution: ExecutionId, profile: LaunchProfile) {
        self.profiles.insert(execution, profile);
    }

    pub fn profile(&self, execution: &ExecutionId) -> Option<&LaunchProfile> {
        self.profiles.get(execution)
    }

    /// The sealed record of a VM this port launched or restored, kept after it stopped.
    pub fn record(&self, vm: &VmInstanceId) -> Option<&LaunchRecord> {
        self.records.get(vm)
    }

    pub fn records(&self) -> impl Iterator<Item = &LaunchRecord> {
        self.records.values()
    }

    /// The latest record of `execution`, by boot generation.
    pub fn latest_record(&self, execution: &ExecutionId) -> Option<&LaunchRecord> {
        self.records
            .values()
            .filter(|record| &record.sandbox().execution == execution)
            .max_by_key(|record| record.sandbox().generations.boot)
    }

    /// What the host found in a restored VM, as the backend reported it.
    pub fn restored(&self, vm: &VmInstanceId) -> Option<&RestoredVmReport> {
        self.restored.get(vm)
    }

    pub fn perimeters(&self) -> &BTreeSet<PerimeterId> {
        &self.perimeters
    }

    /// Every refused launch, in order.
    pub fn refused(&self) -> &[RefusedLaunch] {
        &self.refused
    }

    /// Takes the refused launches recorded so far, for the audit sink.
    pub fn take_refused(&mut self) -> Vec<RefusedLaunch> {
        std::mem::take(&mut self.refused)
    }

    /// VMs the backend listed that this port never launched; they get no handle.
    pub fn unrecorded(&self) -> &BTreeSet<VmInstanceId> {
        &self.unrecorded
    }

    /// The latest re-observation the backend made of `vm` for readiness.
    pub fn reobservation(&self, vm: &VmInstanceId) -> Option<&Reobservation> {
        self.reobservations.get(vm)
    }

    /// The VMs refused launches left behind, by the perimeter held for each.
    pub fn left_behind(&self) -> &BTreeMap<PerimeterId, VmInstanceId> {
        &self.left_behind
    }

    /// The perimeter identity of one boot.
    pub fn perimeter_of(execution: &ExecutionId, boot: SandboxBootGeneration) -> PerimeterId {
        PerimeterId::new(
            DigestBuilder::new(PERIMETER_DOMAIN)
                .str(execution.as_str())
                .u64(boot.get())
                .finish(),
        )
    }

    /// The port over `backend` and the host's evidence, for one supervisor call.
    pub fn port<'a, B, H, R>(
        &'a mut self,
        backend: &'a mut B,
        host: &'a H,
        reservations: &'a R,
    ) -> BackendPort<'a, B, H, R>
    where
        B: ContractBackend + ?Sized,
        H: HostEvidence,
        R: ReservationResolver + ?Sized,
    {
        BackendPort {
            table: self,
            backend,
            host,
            reservations,
        }
    }

    fn handle_of(&self, record: &LaunchRecord) -> VmHandle {
        VmHandle {
            vm: record.vm(),
            execution: record.sandbox().execution.clone(),
            boot: record.sandbox().generations.boot,
            token: record.identity(),
        }
    }
}

/// The lifecycle's backend port over the backend contract, for one supervisor call.
pub struct BackendPort<'a, B: ?Sized, H: ?Sized, R: ?Sized> {
    table: &'a mut LaunchTable,
    backend: &'a mut B,
    host: &'a H,
    reservations: &'a R,
}

impl<'a, B, H, R> BackendPort<'a, B, H, R>
where
    B: ContractBackend + ?Sized,
    H: HostEvidence,
    R: ReservationResolver + ?Sized,
{
    pub fn table(&self) -> &LaunchTable {
        self.table
    }

    fn failure(operation: BackendOperation, problem: &LaunchProblem) -> BackendFailure {
        BackendFailure {
            operation,
            detail: problem.to_string(),
        }
    }

    fn refuse(
        &mut self,
        request: &BootRequest,
        attempt: LaunchAttempt,
        problem: LaunchProblem,
    ) -> BackendFailure {
        let operation = match attempt {
            LaunchAttempt::Launch => BackendOperation::Launch,
            LaunchAttempt::Restore => BackendOperation::Restore,
        };
        let failure = Self::failure(operation, &problem);
        if let LaunchProblem::Backend { refusal } = &problem {
            if let Some((vm, _)) = refusal.left_behind() {
                let perimeter =
                    LaunchTable::perimeter_of(&request.execution, request.generations.boot);
                self.table.left_behind.insert(perimeter, vm);
            }
        }
        self.table.refused.push(RefusedLaunch {
            execution: request.execution.clone(),
            boot: request.generations.boot,
            attempt,
            problem,
            at: self.host.now().at(),
        });
        failure
    }

    /// The backend launch request of `request`, or the typed problem.
    fn launch_request(
        &self,
        request: &BootRequest,
        perimeter: &PerimeterId,
    ) -> Result<LaunchRequest, LaunchProblem> {
        let profile = self.table.profiles.get(&request.execution).ok_or_else(|| {
            LaunchProblem::NoProfile {
                execution: request.execution.clone(),
            }
        })?;
        if !self.table.perimeters.contains(perimeter)
            || *perimeter != LaunchTable::perimeter_of(&request.execution, request.generations.boot)
        {
            return Err(LaunchProblem::PerimeterNotPrepared {
                perimeter: *perimeter,
            });
        }
        let reservation = self
            .reservations
            .resolve(&request.execution, &request.reservation)
            .map_err(|refusal| LaunchProblem::Reservation { refusal })?;
        Ok(LaunchRequest {
            execution: request.execution.clone(),
            tenant: request.tenant.clone(),
            generations: request.generations,
            machine: self.table.config.machine,
            configuration: profile.configuration,
            contract: profile.contract,
            pinned: profile.pinned,
            device_profile: profile.device_profile.clone(),
            required: profile.required.clone(),
            reservation,
        })
    }

    fn keep(&mut self, launched: &Launched) -> VmHandle {
        let handle = self.table.handle_of(&launched.record);
        self.table
            .records
            .insert(launched.vm, launched.record.clone());
        handle
    }

    fn stop_failure(refusal: BackendRefusal) -> BackendFailure {
        BackendFailure {
            operation: BackendOperation::Stop,
            detail: refusal.to_string(),
        }
    }

    /// Whether `record`'s launch may be presented as current now: on its launch-time
    /// facts while they are current, then on the latest re-observation while it is, and
    /// otherwise on a re-observation the backend makes now, judged by the record.
    fn current(&mut self, record: &LaunchRecord) -> Readiness {
        let vm = record.vm();
        let Err(stale) = record.assert_current(self.host.now()) else {
            return Readiness::Ready;
        };
        if let Some(latest) = self.table.reobservations.get(&vm) {
            if record.assert_current_with(self.host.now(), latest).is_ok() {
                return Readiness::Ready;
            }
        }
        let reobservation = match self.backend.reobserve(&vm, self.host) {
            Ok(reobservation) => reobservation,
            Err(refusal) => {
                self.table.reobservations.remove(&vm);
                return Readiness::NotReady {
                    detail: format!("{stale}; {refusal}"),
                };
            }
        };
        let verdict = record.assert_current_with(self.host.now(), &reobservation);
        self.table.reobservations.insert(vm, reobservation);
        match verdict {
            Ok(()) => Readiness::Ready,
            Err(refusal) => Readiness::NotReady {
                detail: format!("{stale}; {refusal}"),
            },
        }
    }
}

impl<'a, B, H, R> LifecycleBackend for BackendPort<'a, B, H, R>
where
    B: ContractBackend + ?Sized,
    H: HostEvidence,
    R: ReservationResolver + ?Sized,
{
    fn capabilities(&self) -> BackendCapabilities {
        let features = self.backend.features();
        BackendCapabilities {
            snapshot_restore: features.supports(Feature::Snapshot)
                && features.supports(Feature::Restore),
            state_reset: self.table.config.state_reset.clone(),
        }
    }

    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, BackendFailure> {
        let perimeter = LaunchTable::perimeter_of(&request.execution, request.generations.boot);
        self.table.perimeters.insert(perimeter);
        Ok(perimeter)
    }

    fn launch(
        &mut self,
        request: &BootRequest,
        perimeter: &PerimeterId,
    ) -> Result<VmHandle, BackendFailure> {
        let launch = match self.launch_request(request, perimeter) {
            Ok(launch) => launch,
            Err(problem) => return Err(self.refuse(request, LaunchAttempt::Launch, problem)),
        };
        match self.backend.launch(&launch, self.host) {
            Ok(launched) => Ok(self.keep(&launched)),
            Err(refusal) => Err(self.refuse(
                request,
                LaunchAttempt::Launch,
                LaunchProblem::Backend { refusal },
            )),
        }
    }

    fn restore(
        &mut self,
        request: &BootRequest,
        perimeter: &PerimeterId,
        snapshot: &SnapshotManifest,
    ) -> Result<VmHandle, BackendFailure> {
        let launch = match self.launch_request(request, perimeter) {
            Ok(launch) => launch,
            Err(problem) => return Err(self.refuse(request, LaunchAttempt::Restore, problem)),
        };
        match self.backend.restore(&launch, snapshot, self.host) {
            Ok(Restored {
                launched, report, ..
            }) => {
                let handle = self.keep(&launched);
                self.table.restored.insert(launched.vm, report);
                Ok(handle)
            }
            Err(refusal) => Err(self.refuse(
                request,
                LaunchAttempt::Restore,
                LaunchProblem::Backend { refusal },
            )),
        }
    }

    /// Host-observed readiness (§6.1 boot_evidence_checked): the VM runs on the backend,
    /// the handle is the record's, the confinement evidence is readable, and the launch
    /// is current now: on the record's facts, or once they are stale on a current
    /// re-observation, asking the backend to observe again when the latest one is not.
    fn observe_readiness(&mut self, handle: &VmHandle) -> ReadinessReport {
        let readiness = match self.table.records.get(&handle.vm).cloned() {
            None => Readiness::NotReady {
                detail: format!("VM {} has no launch record", handle.vm),
            },
            Some(record) if record.identity() != handle.token => Readiness::NotReady {
                detail: format!("the handle of VM {} is not its record's", handle.vm),
            },
            Some(record) => {
                if !self.backend.running().contains(&handle.vm) {
                    Readiness::NotReady {
                        detail: format!("VM {} is not running", handle.vm),
                    }
                } else {
                    match self.backend.confinement_evidence(&handle.vm) {
                        Err(refusal) => Readiness::NotReady {
                            detail: refusal.to_string(),
                        },
                        Ok(_) => self.current(&record),
                    }
                }
            }
        };
        ReadinessReport {
            source: SourceClass::HostProbe,
            readiness,
        }
    }

    /// The backend's own report of the restored VM. A VM this port did not restore
    /// yields a report from no host observation, which verification refuses.
    fn inspect_restored(&mut self, handle: &VmHandle) -> RestoredVmReport {
        match self.table.restored.get(&handle.vm) {
            Some(report)
                if self
                    .table
                    .records
                    .get(&handle.vm)
                    .map(LaunchRecord::identity)
                    == Some(handle.token) =>
            {
                report.clone()
            }
            _ => RestoredVmReport {
                vm: handle.vm,
                boot: handle.boot,
                snapshot: SnapshotId::new(Digest::from_bytes([0; 32])),
                guest_identity: Digest::from_bytes([0; 32]),
                actions: BTreeSet::new(),
                attached_volumes: BTreeSet::new(),
                policy: PolicyEpoch::FIRST,
                image_profile: Digest::from_bytes([0; 32]),
                presented_epochs: BTreeSet::new(),
                source: SourceClass::Fixture,
            },
        }
    }

    /// The object behind the handle is the VM the handle was created for only while the
    /// backend runs that VM and the token is its record's identity (§6.4; VM-P49).
    fn check_handle(&mut self, handle: &VmHandle) -> HandleIdentity {
        match self.table.records.get(&handle.vm) {
            None => HandleIdentity::Gone,
            Some(record) if record.identity() != handle.token => HandleIdentity::Reused {
                holder: Some(record.sandbox().execution.clone()),
            },
            Some(_) => {
                if self.backend.running().contains(&handle.vm) {
                    HandleIdentity::Matches
                } else {
                    HandleIdentity::Gone
                }
            }
        }
    }

    fn stop(&mut self, handle: &VmHandle) -> Result<StopOutcome, BackendFailure> {
        match self.check_handle(handle) {
            HandleIdentity::Reused { .. } => {
                return Err(BackendFailure {
                    operation: BackendOperation::Stop,
                    detail: format!(
                        "the handle of VM {} is not its record's; nothing was stopped",
                        handle.vm
                    ),
                });
            }
            HandleIdentity::Gone if !self.table.records.contains_key(&handle.vm) => {
                return Ok(StopOutcome::AlreadyGone);
            }
            HandleIdentity::Gone | HandleIdentity::Matches => {}
        }
        match self.backend.stop(&handle.vm) {
            Ok(ContractStop::Stopped) => Ok(StopOutcome::Stopped),
            Ok(ContractStop::AlreadyGone) => Ok(StopOutcome::AlreadyGone),
            Err(refusal) => Err(Self::stop_failure(refusal)),
        }
    }

    fn snapshot(
        &mut self,
        handle: &VmHandle,
        origin: SnapshotOrigin,
    ) -> Result<SnapshotManifest, BackendFailure> {
        if self.check_handle(handle) != HandleIdentity::Matches {
            return Err(BackendFailure {
                operation: BackendOperation::Snapshot,
                detail: format!("VM {} is not running under this handle", handle.vm),
            });
        }
        self.backend
            .snapshot(&handle.vm, origin)
            .map_err(|refusal| BackendFailure {
                operation: BackendOperation::Snapshot,
                detail: refusal.to_string(),
            })
    }

    /// Removes the perimeter. A perimeter held for a VM a refused launch left behind is
    /// removed only once the backend stops that VM; while it cannot, the removal is
    /// refused and the perimeter stays.
    fn teardown_perimeter(&mut self, perimeter: &PerimeterId) -> Result<(), BackendFailure> {
        if let Some(vm) = self.table.left_behind.get(perimeter).copied() {
            self.backend.stop(&vm).map_err(|refusal| BackendFailure {
                operation: BackendOperation::TeardownPerimeter,
                detail: format!(
                    "VM {vm}, left behind by a refused launch, is not shown stopped: {refusal}"
                ),
            })?;
            self.table.left_behind.remove(perimeter);
        }
        self.table.perimeters.remove(perimeter);
        Ok(())
    }

    /// Every VM the backend runs that this port launched, by its handle; a VM without a
    /// record gets no handle and is counted as unrecorded.
    fn list(&mut self) -> Result<Vec<VmHandle>, BackendFailure> {
        let mut handles = Vec::new();
        for vm in self.backend.running() {
            match self.table.records.get(&vm) {
                Some(record) => handles.push(self.table.handle_of(record)),
                None => {
                    self.table.unrecorded.insert(vm);
                }
            }
        }
        Ok(handles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::coordination::{ReservationKey, ReservationPurpose, SandboxGenerations};
    use crate::foundation::evidence::fakes::FakeProbe;
    use crate::foundation::evidence::{
        BackendVersion, Capability, ConfigurationFingerprint, HypervisorKind, HypervisorSubject,
        Observation, OsKind, ProbeRegistry, Subject, SupportDetail,
    };
    use crate::foundation::ids::{digest, Clock, ManualClock, TenantId};
    use crate::foundation::ledger::ReservationId;
    use crate::sandbox::backend::{
        Architecture, BackendFeatures, BuildId, DeviceExposure, DeviceProfile, FakeBackend,
        FakeCall, HostBuild, HostScript, PinnedArtifacts, RequiredProperties,
    };
    use std::sync::Arc;
    use std::time::Duration;

    const MINUTE: Duration = Duration::from_secs(60);

    struct Table(BTreeMap<ReservationKey, ReservationId>);

    impl ReservationResolver for Table {
        fn resolve(
            &self,
            _execution: &ExecutionId,
            key: &ReservationKey,
        ) -> Result<ReservationId, ReservationUnresolved> {
            self.0
                .get(key)
                .copied()
                .ok_or(ReservationUnresolved::NotOpen { key: *key })
        }
    }

    fn reservation(number: u64) -> ReservationId {
        serde_json::from_value(number.into()).unwrap()
    }

    fn machine() -> Digest {
        digest("yougori/test/machine/v1", &[b"m"])
    }

    fn config(name: &str) -> ConfigurationFingerprint {
        ConfigurationFingerprint::from_settings([("host", name)]).unwrap()
    }

    fn image() -> Digest {
        digest("yougori/test/image/v1", &[b"alpine"])
    }

    fn artifact() -> Digest {
        digest("yougori/test/backend/v1", &[b"fake"])
    }

    fn execution(name: &str) -> ExecutionId {
        ExecutionId::new(name).unwrap()
    }

    struct Host {
        clock: Arc<ManualClock>,
        registry: ProbeRegistry<Arc<ManualClock>>,
        probe: Arc<FakeProbe>,
    }

    impl Host {
        /// The hypervisor probe observes KVM available under configuration "a" now.
        fn observe(&mut self) {
            let subject = Subject::Hypervisor(HypervisorSubject {
                machine: machine(),
                hypervisor: HypervisorKind::Kvm,
            });
            self.probe.respond(
                &subject,
                Observation::supported(
                    config("a"),
                    Duration::from_secs(600),
                    SupportDetail::Hypervisor {
                        hypervisor: HypervisorKind::Kvm,
                    },
                ),
            );
            self.registry
                .refresh(Capability::HypervisorAvailable, &subject)
                .unwrap();
        }
    }

    fn host() -> Host {
        let clock = Arc::new(ManualClock::default());
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let probe = Arc::new(FakeProbe::hypervisor_availability());
        registry.register(Box::new(Arc::clone(&probe))).unwrap();
        let mut host = Host {
            clock,
            registry,
            probe,
        };
        host.observe();
        host
    }

    fn backend() -> FakeBackend {
        let script = HostScript::hardware_vm(
            HypervisorKind::Kvm,
            HostBuild {
                os: OsKind::Linux,
                build: BuildId::new("6.6.0").unwrap(),
                architecture: Architecture::X86_64,
            },
            image(),
            config("a"),
        );
        FakeBackend::new(
            HypervisorKind::Kvm,
            BackendVersion::new("0.1.0").unwrap(),
            artifact(),
            script,
        )
        .with_features(BackendFeatures::of([Feature::Snapshot, Feature::Restore]))
    }

    fn profile() -> LaunchProfile {
        LaunchProfile {
            configuration: config("a"),
            contract: digest("yougori/test/contract/v1", &[b"c"]),
            pinned: PinnedArtifacts {
                guest_image: image(),
                backend: artifact(),
            },
            device_profile: DeviceProfile {
                identity: digest("yougori/test/profile/v1", &[b"minimal"]),
                devices: DeviceExposure::cpu_only(),
            },
            required: RequiredProperties::strictest(MINUTE),
        }
    }

    fn table() -> LaunchTable {
        let mut table = LaunchTable::new(PortConfig {
            machine: machine(),
            state_reset: StateReset::Supported,
        });
        table.set_profile(execution("exe-1"), profile());
        table
    }

    fn boot(name: &str, boot: u64) -> (BootRequest, ReservationKey) {
        let generations = SandboxGenerations {
            boot: SandboxBootGeneration::new(boot),
            ..SandboxGenerations::FIRST
        };
        let key = ReservationKey::derive(
            &execution(name),
            &ReservationPurpose::Sandbox {
                boot: generations.boot,
            },
        );
        (
            BootRequest {
                execution: execution(name),
                tenant: TenantId::new("tenant-1").unwrap(),
                generations,
                reservation: key,
            },
            key,
        )
    }

    #[test]
    fn a_boot_request_becomes_a_launch_request_bound_to_its_reservation_and_profile() {
        let host = host();
        let mut backend = backend();
        let mut table = table();
        let (request, key) = boot("exe-1", 1);
        let reservations = Table(BTreeMap::from([(key, reservation(7))]));
        let mut port = table.port(&mut backend, &host.registry, &reservations);
        let perimeter = port.prepare_perimeter(&request).unwrap();
        assert_eq!(
            perimeter,
            LaunchTable::perimeter_of(&execution("exe-1"), SandboxBootGeneration::FIRST)
        );
        let handle = port.launch(&request, &perimeter).unwrap();
        assert_eq!(handle.execution, execution("exe-1"));
        assert_eq!(handle.boot, SandboxBootGeneration::FIRST);
        let record = port.table().record(&handle.vm).unwrap().clone();
        assert_eq!(handle.token, record.identity());
        assert_eq!(record.reservation(), reservation(7));
        assert_eq!(
            record.contract(),
            digest("yougori/test/contract/v1", &[b"c"])
        );
        assert_eq!(record.sandbox().generations, request.generations);
        assert!(record.accelerator().value().is_hardware_virtualized());
        let readiness = port.observe_readiness(&handle);
        assert_eq!(readiness.source, SourceClass::HostProbe);
        assert_eq!(readiness.readiness, Readiness::Ready);
        assert_eq!(port.check_handle(&handle), HandleIdentity::Matches);
        assert_eq!(port.list().unwrap(), vec![handle.clone()]);
        assert_eq!(
            port.capabilities(),
            BackendCapabilities {
                snapshot_restore: true,
                state_reset: StateReset::Supported
            }
        );
        // Launching the same boot again is the same object (§6.1 idempotent transitions).
        assert_eq!(port.launch(&request, &perimeter).unwrap(), handle);
        assert_eq!(port.stop(&handle).unwrap(), StopOutcome::Stopped);
        assert_eq!(port.check_handle(&handle), HandleIdentity::Gone);
        assert_eq!(port.stop(&handle).unwrap(), StopOutcome::AlreadyGone);
        assert!(
            port.table().record(&handle.vm).is_some(),
            "the record outlives the VM"
        );
        port.teardown_perimeter(&perimeter).unwrap();
        assert!(port.table().perimeters().is_empty());
        assert!(port.table().refused().is_empty());
    }

    #[test]
    fn missing_profile_reservation_or_perimeter_refuses_before_anything_is_created() {
        let host = host();
        let mut backend = backend();
        let mut table = table();
        let (request, key) = boot("exe-2", 1);
        let reservations = Table(BTreeMap::from([(key, reservation(1))]));
        let mut port = table.port(&mut backend, &host.registry, &reservations);
        let perimeter = port.prepare_perimeter(&request).unwrap();
        let failure = port.launch(&request, &perimeter).unwrap_err();
        assert_eq!(failure.operation, BackendOperation::Launch);
        assert!(failure.detail.contains("no launch profile"));
        let (request, _) = boot("exe-1", 1);
        let foreign = PerimeterId::new(digest("yougori/test/perimeter/v1", &[b"x"]));
        let failure = port.launch(&request, &foreign).unwrap_err();
        assert!(failure.detail.contains("was not prepared"));
        let perimeter = port.prepare_perimeter(&request).unwrap();
        let (unreserved, _) = boot("exe-1", 2);
        let perimeter_2 = port.prepare_perimeter(&unreserved).unwrap();
        let failure = port.launch(&unreserved, &perimeter_2).unwrap_err();
        assert!(failure.detail.contains("no open coordination reservation"));
        assert!(port.list().unwrap().is_empty());
        let refused = port.table().refused();
        assert_eq!(refused.len(), 3);
        assert!(matches!(
            refused[0].problem,
            LaunchProblem::NoProfile { .. }
        ));
        assert!(matches!(
            refused[1].problem,
            LaunchProblem::PerimeterNotPrepared { .. }
        ));
        assert!(matches!(
            refused[2].problem,
            LaunchProblem::Reservation {
                refusal: ReservationUnresolved::NotOpen { .. }
            }
        ));
        assert!(backend
            .calls()
            .iter()
            .all(|call| !matches!(call, FakeCall::Create { .. })));
        let _ = perimeter;
    }

    #[test]
    fn a_backend_refusal_is_the_lifecycles_typed_failure_with_nothing_kept() {
        let host = host();
        let mut backend = backend();
        backend.script_mut().hardware_failure = Some(crate::sandbox::backend::HardwareFailure {
            hypervisor: HypervisorKind::Kvm,
            detail: "KVM_CREATE_VM: EPERM".to_owned(),
        });
        let mut table = table();
        let (request, key) = boot("exe-1", 1);
        let reservations = Table(BTreeMap::from([(key, reservation(3))]));
        let mut port = table.port(&mut backend, &host.registry, &reservations);
        let perimeter = port.prepare_perimeter(&request).unwrap();
        let failure = port.launch(&request, &perimeter).unwrap_err();
        assert_eq!(failure.operation, BackendOperation::Launch);
        assert!(failure.detail.contains("nothing is retried in emulation"));
        assert!(port.table().records().next().is_none());
        assert!(port.list().unwrap().is_empty());
        let refused = port.table().refused();
        assert!(matches!(
            &refused[0].problem,
            LaunchProblem::Backend {
                refusal: LaunchRefusal::HardwareVirtualizationFailed { .. }
            }
        ));
        assert_eq!(refused[0].attempt, LaunchAttempt::Launch);
        assert_eq!(refused[0].at, host.clock.now());
        assert_eq!(backend.emulation_launches(), 0);
        let json = serde_json::to_value(&table.refused()[0]).unwrap();
        assert_eq!(json["problem"]["problem"], "backend");
        assert_eq!(
            json["problem"]["refusal"]["kind"],
            "hardware_virtualization_failed"
        );
    }

    #[test]
    fn readiness_is_host_observed_and_goes_stale_with_the_record() {
        let host = host();
        let mut backend = backend();
        let mut table = table();
        let (request, key) = boot("exe-1", 1);
        let reservations = Table(BTreeMap::from([(key, reservation(1))]));
        let mut port = table.port(&mut backend, &host.registry, &reservations);
        let perimeter = port.prepare_perimeter(&request).unwrap();
        let handle = port.launch(&request, &perimeter).unwrap();
        assert_eq!(port.observe_readiness(&handle).readiness, Readiness::Ready);
        host.clock.advance(MINUTE + Duration::from_secs(1));
        assert!(matches!(
            port.observe_readiness(&handle).readiness,
            Readiness::NotReady { detail } if detail.contains("not current")
        ));
        let forged = VmHandle {
            token: digest("yougori/test/token/v1", &[b"forged"]),
            ..handle.clone()
        };
        assert!(matches!(
            port.observe_readiness(&forged).readiness,
            Readiness::NotReady { detail } if detail.contains("not its record's")
        ));
        assert!(matches!(
            port.check_handle(&forged),
            HandleIdentity::Reused { holder: Some(holder) } if holder == execution("exe-1")
        ));
        assert!(
            port.stop(&forged).is_err(),
            "a mismatched token stops nothing"
        );
        assert_eq!(
            port.check_handle(&handle),
            HandleIdentity::Matches,
            "the VM still runs"
        );
        let unknown = VmHandle {
            vm: VmInstanceId::new(digest("yougori/test/vm/v1", &[b"other"])),
            ..handle.clone()
        };
        assert_eq!(port.check_handle(&unknown), HandleIdentity::Gone);
        assert_eq!(port.stop(&unknown).unwrap(), StopOutcome::AlreadyGone);
        assert!(matches!(
            port.observe_readiness(&unknown).readiness,
            Readiness::NotReady { .. }
        ));
    }

    #[test]
    fn a_restore_keeps_the_backends_report_and_an_unrestored_vm_has_none() {
        let host = host();
        let mut backend = backend();
        let mut table = table();
        let (request, key) = boot("exe-1", 1);
        let (second, key_2) = boot("exe-1", 2);
        let reservations = Table(BTreeMap::from([
            (key, reservation(1)),
            (key_2, reservation(2)),
        ]));
        let mut port = table.port(&mut backend, &host.registry, &reservations);
        let perimeter = port.prepare_perimeter(&request).unwrap();
        let handle = port.launch(&request, &perimeter).unwrap();
        assert_eq!(port.inspect_restored(&handle).source, SourceClass::Fixture);
        let manifest = port
            .snapshot(&handle, SnapshotOrigin::PreTenantGolden)
            .unwrap();
        port.stop(&handle).unwrap();
        assert!(port
            .snapshot(&handle, SnapshotOrigin::PreTenantGolden)
            .is_err());
        let perimeter_2 = port.prepare_perimeter(&second).unwrap();
        let restored = port.restore(&second, &perimeter_2, &manifest).unwrap();
        assert_ne!(restored.vm, handle.vm);
        assert_eq!(restored.boot, SandboxBootGeneration::new(2));
        let report = port.inspect_restored(&restored);
        assert_eq!(report.source, SourceClass::HostProbe);
        assert_eq!(report.snapshot, manifest.snapshot);
        assert_eq!(
            port.table().record(&restored.vm).unwrap().restored_from(),
            Some(manifest.snapshot)
        );
        assert_eq!(
            port.table()
                .latest_record(&execution("exe-1"))
                .unwrap()
                .vm(),
            restored.vm
        );
        // A restore of a dirty snapshot is refused by name and nothing is kept.
        let (third, key_3) = boot("exe-1", 3);
        let reservations = Table(BTreeMap::from([(key_3, reservation(3))]));
        let mut port = table.port(&mut backend, &host.registry, &reservations);
        let perimeter_3 = port.prepare_perimeter(&third).unwrap();
        let dirty = SnapshotManifest {
            origin: SnapshotOrigin::TenantWorkload,
            ..manifest
        };
        let failure = port.restore(&third, &perimeter_3, &dirty).unwrap_err();
        assert_eq!(failure.operation, BackendOperation::Restore);
        assert!(matches!(
            &port.table().refused().last().unwrap().problem,
            LaunchProblem::Backend {
                refusal: LaunchRefusal::SnapshotNotRestorable { .. }
            }
        ));
        assert_eq!(port.list().unwrap().len(), 1);
    }

    #[test]
    fn a_vm_the_port_never_launched_gets_no_handle() {
        let host = host();
        let mut backend = backend();
        let mut table = table();
        let direct = LaunchRequest {
            execution: execution("exe-direct"),
            tenant: TenantId::new("tenant-1").unwrap(),
            generations: SandboxGenerations::FIRST,
            machine: machine(),
            configuration: config("a"),
            contract: digest("yougori/test/contract/v1", &[b"c"]),
            pinned: PinnedArtifacts {
                guest_image: image(),
                backend: artifact(),
            },
            device_profile: DeviceProfile {
                identity: digest("yougori/test/profile/v1", &[b"minimal"]),
                devices: DeviceExposure::cpu_only(),
            },
            required: RequiredProperties::strictest(MINUTE),
            reservation: reservation(9),
        };
        let launched = backend.launch(&direct, &host.registry).unwrap();
        let reservations = Table(BTreeMap::new());
        let mut port = table.port(&mut backend, &host.registry, &reservations);
        assert!(port.list().unwrap().is_empty());
        assert_eq!(port.table().unrecorded(), &BTreeSet::from([launched.vm]));
    }

    #[test]
    fn stale_readiness_is_renewed_only_by_a_fresh_reobservation() {
        let mut host = host();
        let mut backend = backend();
        let mut table = table();
        let (request, key) = boot("exe-1", 1);
        let reservations = Table(BTreeMap::from([(key, reservation(1))]));
        let mut port = table.port(&mut backend, &host.registry, &reservations);
        let perimeter = port.prepare_perimeter(&request).unwrap();
        let handle = port.launch(&request, &perimeter).unwrap();
        // While the launch-time facts are current, nothing is observed again.
        assert_eq!(port.observe_readiness(&handle).readiness, Readiness::Ready);
        assert!(port.table().reobservation(&handle.vm).is_none());

        // Stale, and the host probe has not observed again: readiness stays unavailable.
        host.clock.advance(MINUTE + Duration::from_secs(1));
        let mut port = table.port(&mut backend, &host.registry, &reservations);
        assert!(matches!(
            port.observe_readiness(&handle).readiness,
            Readiness::NotReady { detail }
                if detail.contains("not current") && detail.contains("observed again")
        ));
        assert!(port.table().reobservation(&handle.vm).is_none());

        // Fresh CORE-01 evidence and a fresh re-observation of the VM: ready again, on the
        // re-observation, while the record itself stays stale.
        host.observe();
        let mut port = table.port(&mut backend, &host.registry, &reservations);
        assert_eq!(port.observe_readiness(&handle).readiness, Readiness::Ready);
        let record = port.table().record(&handle.vm).unwrap().clone();
        assert!(record.assert_current(host.registry.now()).is_err());
        let reobservation = port.table().reobservation(&handle.vm).unwrap().clone();
        assert_eq!(reobservation.record(), record.identity());
        assert_eq!(reobservation.observed_at(), host.clock.now());
        // A current re-observation is used again without asking the backend.
        assert_eq!(port.observe_readiness(&handle).readiness, Readiness::Ready);
        assert_eq!(
            backend
                .calls()
                .iter()
                .filter(|call| matches!(call, FakeCall::Reobserve { .. }))
                .count(),
            2
        );

        // The host now observes weaker confinement: not ready, whatever the evidence.
        backend.script_mut().confinement =
            crate::sandbox::backend::Scripted::HostObserved(BTreeSet::from([
                crate::sandbox::backend::ConfinementControl::AccountIdentity,
            ]));
        host.clock.advance(MINUTE + Duration::from_secs(1));
        host.observe();
        let mut port = table.port(&mut backend, &host.registry, &reservations);
        assert!(matches!(
            port.observe_readiness(&handle).readiness,
            Readiness::NotReady { detail } if detail.contains("required property is not satisfied")
        ));
        // And a backend that cannot observe again keeps it unavailable.
        drop(port);
        backend.script_mut().confinement = crate::sandbox::backend::Scripted::HostObserved(
            crate::sandbox::backend::ConfinementControl::all(),
        );
        backend.script_mut().reobserve_failure = Some("the VM's handle is lost".to_owned());
        let mut port = table.port(&mut backend, &host.registry, &reservations);
        assert!(matches!(
            port.observe_readiness(&handle).readiness,
            Readiness::NotReady { detail } if detail.contains("the VM's handle is lost")
        ));
        assert!(port.table().reobservation(&handle.vm).is_none());
        drop(port);
        backend.script_mut().reobserve_failure = None;
        let mut port = table.port(&mut backend, &host.registry, &reservations);
        assert_eq!(port.observe_readiness(&handle).readiness, Readiness::Ready);
    }

    #[test]
    fn a_refused_launch_that_left_its_vm_holds_the_perimeter_until_the_vm_stops() {
        let host = host();
        let mut backend = backend();
        backend.script_mut().devices = crate::sandbox::backend::Scripted::Unavailable {
            reason: crate::foundation::evidence::UnknownReason::NotTested,
        };
        backend.script_mut().teardown_failure = Some("the VM did not exit".to_owned());
        let mut table = table();
        let (request, key) = boot("exe-1", 1);
        let reservations = Table(BTreeMap::from([(key, reservation(1))]));
        let mut port = table.port(&mut backend, &host.registry, &reservations);
        let perimeter = port.prepare_perimeter(&request).unwrap();
        let failure = port.launch(&request, &perimeter).unwrap_err();
        assert_eq!(failure.operation, BackendOperation::Launch);
        assert!(failure.detail.contains("may remain"), "{}", failure.detail);
        let refused = &port.table().refused()[0];
        let LaunchProblem::Backend { refusal } = &refused.problem else {
            panic!("{refused:?}");
        };
        let (vm, _) = refusal.left_behind().unwrap();
        assert_eq!(port.table().left_behind().get(&perimeter), Some(&vm));
        // The VM gets no handle, and the perimeter is not removed while it may run.
        assert!(port.list().unwrap().is_empty());
        assert!(port.table().unrecorded().contains(&vm));
        let held = port.teardown_perimeter(&perimeter).unwrap_err();
        assert_eq!(held.operation, BackendOperation::TeardownPerimeter);
        assert!(held.detail.contains("left behind by a refused launch"));
        assert!(port.table().perimeters().contains(&perimeter));

        // Once the backend can stop it, removing the perimeter stops the VM first.
        drop(port);
        backend.script_mut().teardown_failure = None;
        let mut port = table.port(&mut backend, &host.registry, &reservations);
        port.teardown_perimeter(&perimeter).unwrap();
        assert!(port.table().left_behind().is_empty());
        assert!(port.table().perimeters().is_empty());
        drop(port);
        assert!(backend.running().is_empty());
        assert!(backend.calls().contains(&FakeCall::Stop { vm }));
    }
}
