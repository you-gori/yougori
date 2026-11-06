//! Select the native backend only for GPU launches. CPU VMs keep the existing
//! QEMU backend, and both use the same service, grants, workspaces and ledger.
use super::broker;
use crate::foundation::{
    coordination::{SnapshotManifest, SnapshotOrigin, VmInstanceId},
    evidence::{Backend, BackendRelease, HypervisorKind, HypervisorSubject, RuntimeSubject},
    ids::{digest, Digest, ExecutionCategory, SystemClock},
    process::{
        Escalation, HostProcess, ProcessIdentity, ProcessRole, SharedHandles, TerminationProof,
    },
};
use crate::sandbox::qemu::QemuHost;
use crate::sandbox::{
    backend::*,
    integration::LaunchProfile,
    link::BootstrapSecret,
    qemu::{
        HostPath, ObserveFailure, PathStyle, PrivateDirectory, ProcessState, QemuBackend,
        ReservationView,
    },
    qemu_host::{
        create_private_directory, encode_bootstrap, remove_private_directory, HostSids, QmpMonitor,
        RuntimeLayout, UnixSocketConnect, WindowsQemuHost,
    },
    vm_service::{EvidenceSubjects, ServiceRuntime, SharedLedgerView},
};
use base64::Engine;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

pub type CpuBackend = QemuBackend<
    WindowsQemuHost,
    QmpMonitor<UnixSocketConnect>,
    RuntimeLayout,
    SharedLedgerView<SystemClock>,
>;
pub const VERSION: &str = "1.0.0";
pub fn bundle_path() -> PathBuf {
    std::env::var_os("YOUGORI_HCS_GUEST")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_default())
                .join("Yougori/runtime/hcs-guest")
        })
}
pub fn native_identity() -> Result<BackendIdentity, String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let hash = broker::hash(&executable)?;
    BackendIdentity::new(
        BackendKind::Hcs,
        VERSION,
        Digest::from_hex(&hash).map_err(|e| e.to_string())?,
        HypervisorKind::Hcs,
    )
    .map_err(|e| e.to_string())
}
pub fn evidence(identity: &BackendIdentity, machine: Digest) -> Result<EvidenceSubjects, String> {
    Ok(EvidenceSubjects {
        runtime: RuntimeSubject {
            category: ExecutionCategory::VmSandbox,
            release: BackendRelease::new(Backend::Hcs, VERSION).map_err(|e| e.to_string())?,
            instance: digest(
                "yougori/sandbox-vm/hcs-runtime/v1",
                &[machine.as_bytes(), identity.artifact.as_bytes()],
            ),
        },
        hypervisor: HypervisorSubject {
            machine,
            hypervisor: HypervisorKind::Hcs,
        },
    })
}
pub fn verify_bundle(runtime: &Path, root: Digest) -> Result<Value, String> {
    let path = bundle_path();
    let bytes = fs::read(path.join("manifest.json")).map_err(|_| {
        "The local GPU VM runtime has not been prepared on this computer.".to_owned()
    })?;
    if bytes.len() > 65536 {
        return Err("HCS guest manifest is too large".into());
    }
    let manifest: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if manifest["format"] != "yougori-hcs-guest/v1"
        || manifest["local_only"] != true
        || manifest["root_sha256"] != root.to_hex()
        || manifest["base_record_sha256"]
            != broker::hash(&runtime.join("sandbox-guest/artifacts.json"))?
    {
        return Err("The GPU VM guest needs rebuilding for this Yougori version.".into());
    }
    for name in ["kernel", "initrd", "kernel.config"] {
        if manifest["files"][name] != broker::hash(&path.join(name))? {
            return Err(format!("GPU VM runtime checksum mismatch: {name}"));
        }
    }
    Ok(manifest)
}
pub fn confinement() -> BTreeSet<ConfinementControl> {
    BTreeSet::from([ConfinementControl::ResourceControls])
}
fn refused(detail: impl Into<String>) -> LaunchRefusal {
    LaunchRefusal::BackendSpecific {
        backend: BackendKind::Hcs,
        detail: detail.into(),
    }
}
fn failed(detail: impl Into<String>) -> BackendRefusal {
    BackendRefusal::Failed {
        operation: BackendOperation::Stop,
        detail: detail.into(),
    }
}
struct NativeVm {
    request: LaunchRequest,
    process: HostProcess,
    directory: PrivateDirectory,
    path: PathBuf,
    secret: Option<BootstrapSecret>,
    launch: broker::Launch,
    admitted: Option<Launched>,
}
pub struct Runtime {
    cpu: CpuBackend,
    native: Result<BackendIdentity, String>,
    subjects: Option<EvidenceSubjects>,
    features: BackendFeatures,
    held: BTreeMap<VmInstanceId, NativeVm>,
    ended: BTreeMap<VmInstanceId, TerminationProof>,
}
impl From<CpuBackend> for Runtime {
    fn from(cpu: CpuBackend) -> Self {
        Self {
            cpu,
            native: native_identity(),
            subjects: None,
            features: BackendFeatures::of([Feature::GpuParavirtualization]),
            held: BTreeMap::new(),
            ended: BTreeMap::new(),
        }
    }
}
impl Runtime {
    fn native_launch(
        &mut self,
        request: &LaunchRequest,
        host: &dyn HostEvidence,
    ) -> Result<Launched, LaunchRefusal> {
        let identity = self
            .native
            .as_ref()
            .map_err(|e| refused(e.clone()))?
            .clone();
        let evidence = precheck(request, &identity, &self.features, host)?;
        let vm = vm_handle(
            BackendKind::Hcs,
            &request.execution,
            request.generations.boot,
        );
        if let Some(held) = self.held.get(&vm) {
            return held
                .admitted
                .clone()
                .filter(|_| held.request == *request)
                .ok_or_else(|| refused("This VM boot is already in use"));
        }
        if self.ended.contains_key(&vm) {
            return Err(refused("This VM boot has already ended"));
        }
        let reservation = self
            .cpu
            .reservations()
            .reserved_vm(request.reservation)
            .ok_or_else(|| refused("No host resource reservation exists for this VM"))?;
        if self
            .cpu
            .reservations()
            .reserved_gpu_bytes(request.reservation)
            < 256 << 20
        {
            return Err(refused("GPU memory must be reserved before the VM starts."));
        }
        if reservation.execution != request.execution
            || reservation.tenant != request.tenant
            || !matches!(
                reservation.state,
                crate::foundation::ledger::ReservationState::Granted
                    | crate::foundation::ledger::ReservationState::InUse
            )
            || reservation.ram_bytes < 4 << 30
            || !(1..=255).contains(&reservation.cpu_slots)
        {
            return Err(refused(
                "GPU VMs need an active reservation of at least 4 GB RAM and 1–255 CPUs.",
            ));
        }
        let layout = self.cpu.layout().settings();
        let manifest = verify_bundle(
            Path::new(layout.runtime_directory.as_str()),
            request.pinned.guest_image,
        )
        .map_err(refused)?;
        let path = Path::new(layout.control_base.as_str()).join(&vm.digest().to_hex()[..16]);
        let directory = PrivateDirectory::new(
            HostPath::new(PathStyle::Windows, path.to_string_lossy())
                .map_err(|e| refused(e.to_string()))?,
        )
        .map_err(|e| refused(e.to_string()))?;
        let role = ProcessRole::VmHost {
            execution: request.execution.clone(),
            vm,
            boot: request.generations.boot,
        };
        let (bootstrap, secret) = encode_bootstrap(&role).map_err(|e| refused(e.to_string()))?;
        let boot = json!({"version":1,"bootstrap":base64::engine::general_purpose::STANDARD.encode(bootstrap.as_bytes()),"endpoints":String::from_utf8_lossy(&guest_endpoints_file(&request.required.declared_endpoints)),"workload":{"format":"yougori-workload/v1","image":request.required.workload_image},"gpu":true});
        let launch = broker::Launch {
            id: uuid::Uuid::new_v4().to_string(),
            kernel: bundle_path().join("kernel"),
            initrd: bundle_path().join("initrd"),
            kernel_sha256: manifest["files"]["kernel"]
                .as_str()
                .unwrap_or_default()
                .into(),
            initrd_sha256: manifest["files"]["initrd"]
                .as_str()
                .unwrap_or_default()
                .into(),
            cpu: reservation.cpu_slots,
            memory_mib: (reservation.ram_bytes >> 20) - 256,
            gpu: true,
            internet: request
                .required
                .network
                .channels
                .contains(&NetworkChannel::Internet),
            boot,
            nonce: format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
        };
        // Everything that can fail without side effects comes before the broker starts,
        // so a refusal here leaves no process or directory behind.
        let subjects = super::runtime::evidence(&identity, request.machine).map_err(refused)?;
        let sids = HostSids::current().map_err(|e| refused(e.to_string()))?;
        create_private_directory(&path, &sids).map_err(|e| refused(e.to_string()))?;
        let spawned = (|| {
            broker::write(&path.join("launch.json"), &launch)?;
            let mut command = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
            command.arg(broker::MODE).arg(&path);
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
            HostProcess::spawn(&mut command, role).map_err(|e| e.to_string())
        })();
        let process = match spawned {
            Ok(p) => p,
            Err(e) => {
                let _ = remove_private_directory(&path);
                return Err(refused(e));
            }
        };
        self.held.insert(
            vm,
            NativeVm {
                request: request.clone(),
                process,
                directory,
                path,
                secret: Some(secret),
                launch,
                admitted: None,
            },
        );
        self.subjects = Some(subjects);
        let result = (|| {
            let held = &self.held[&vm];
            let deadline = Instant::now() + Duration::from_secs(150);
            loop {
                if broker::status(&held.path).is_ok_and(|v| v["running"] == true) {
                    break;
                }
                if held.process.check_ended().is_ok() || Instant::now() >= deadline {
                    let error = broker::recorded_error(&held.path).unwrap_or_else(|| {
                        if held.path.join(broker::HELPER_CONNECTED).exists() {
                            "The GPU VM did not become ready in time.".into()
                        } else {
                            "Windows did not approve the GPU VM helper in time. Start the VM again and approve the Windows prompt.".into()
                        }
                    });
                    return Err(refused(error));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let (facts, configuration) = self.facts(&vm, host)?;
            let record = admit_with_configuration(
                request,
                &identity,
                host,
                evidence,
                facts,
                configuration,
                vm,
                None,
            )?;
            Ok(Launched { vm, record })
        })();
        match result {
            Ok(launched) => {
                self.held.get_mut(&vm).expect("held VM").admitted = Some(launched.clone());
                Ok(launched)
            }
            Err(refusal) => match self.native_stop(&vm) {
                Ok(_) => Err(refusal),
                Err(error) => Err(LaunchRefusal::CleanupIncomplete {
                    vm,
                    refusal: Box::new(refusal),
                    left: vec![LeftBehind::Process {
                        detail: error.to_string(),
                    }],
                }),
            },
        }
    }
    fn facts(
        &self,
        vm: &VmInstanceId,
        host: &dyn HostEvidence,
    ) -> Result<(LaunchFacts, ConfigurationFacts), LaunchRefusal> {
        let held = self
            .held
            .get(vm)
            .ok_or_else(|| refused("GPU VM is not held"))?;
        if held.process.check_ended().is_ok() {
            return Err(refused("GPU VM broker ended"));
        }
        let status = broker::status(&held.path).map_err(refused)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if status["id"] != held.launch.id
            || status["running"] != true
            || status["gpu"] != held.launch.gpu
            || status["properties"]["SystemType"] != "VirtualMachine"
            || status["properties"]["State"] != "Running"
            || !status["at"]
                .as_u64()
                .is_some_and(|at| at <= now && now - at < 10_000)
        {
            return Err(refused(
                "HCS has not confirmed this VM is running with the requested GPU",
            ));
        }
        let request = &held.request;
        fn fact<T>(value: T, request: &LaunchRequest, host: &dyn HostEvidence) -> HostFact<T> {
            HostFact::observed(HostObserved::stamp(
                value,
                host.now(),
                Duration::from_secs(60),
                request.configuration,
            ))
        }
        let facts = LaunchFacts {
            accelerator: fact(
                Accelerator::Hardware {
                    hypervisor: HypervisorKind::Hcs,
                },
                request,
                host,
            ),
            observed: ObservedProperties {
                host: fact(
                    self.cpu
                        .host()
                        .host_build()
                        .map_err(|e| refused(e.to_string()))?,
                    request,
                    host,
                ),
                guest_image: fact(request.pinned.guest_image, request, host),
                isolation: fact(
                    IsolationObservation {
                        own_guest_kernel: true,
                        physical_host: PhysicalHost::Shared,
                    },
                    request,
                    host,
                ),
                confinement: fact(confinement(), request, host),
                network: fact(
                    if held.launch.internet {
                        NetworkAuthority::of([NetworkChannel::Internet])
                    } else {
                        NetworkAuthority::offline()
                    },
                    request,
                    host,
                ),
                credentials: fact(CredentialExposure::none(), request, host),
                persistence: fact(Persistence::EphemeralTask, request, host),
                devices: fact(
                    DeviceInventory {
                        display: false,
                        paravirtualized_gpu: held.launch.gpu,
                        gpus: BTreeSet::new(),
                    },
                    request,
                    host,
                ),
                confidentiality: fact(OperatorConfidentiality::None, request, host),
            },
            guest: GuestAssertions::none(),
        };
        Ok((
            facts,
            ConfigurationFacts {
                listing: Some(HostObserved::stamp(
                    HostInterfaceListing::clean(),
                    host.now(),
                    Duration::from_secs(60),
                    request.configuration,
                )),
                ..ConfigurationFacts::none()
            },
        ))
    }
    fn native_stop(&mut self, vm: &VmInstanceId) -> Result<StopOutcome, BackendRefusal> {
        if self.ended.contains_key(vm) {
            return Ok(StopOutcome::AlreadyGone);
        }
        let held = self
            .held
            .get(vm)
            .ok_or(BackendRefusal::NoSuchVm { vm: *vm })?;
        fs::write(held.path.join("stop"), b"stop").map_err(|e| failed(e.to_string()))?;
        let proof = held
            .process
            .terminate(Escalation {
                grace: Duration::from_secs(45),
                kill_wait: Duration::from_secs(5),
            })
            .map_err(|e| failed(e.to_string()))?;
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if broker::status(&held.path)
                .is_ok_and(|v| v["id"] == held.launch.id && v["removed"] == true)
            {
                break;
            }
            // The broker has ended (`proof`). A helper creates nothing before the broker
            // records and acknowledges it, so without that record no VM or endpoint exists
            // or can still appear: for example when the UAC prompt was never answered.
            if !held.path.join(broker::HELPER_CONNECTED).exists() {
                broker::record_never_created(
                    &held.path,
                    &held.launch.id,
                    "The VM helper was never approved, so no VM was created.",
                )
                .map_err(failed)?;
                break;
            }
            // An acknowledged helper may still be removing its VM: keep the reservation
            // until HCS confirms that the VM is absent.
            if Instant::now() >= deadline {
                return Err(failed("The VM broker ended, but HCS removal has not been confirmed; its reservation is retained."));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        remove_private_directory(&held.path).map_err(|e| failed(e.to_string()))?;
        self.held.remove(vm);
        self.ended.insert(*vm, proof);
        Ok(StopOutcome::Stopped)
    }
}

impl VmBackend for Runtime {
    fn identity(&self) -> &BackendIdentity {
        self.cpu.identity()
    }
    fn features(&self) -> &BackendFeatures {
        &self.features
    }
    fn launch(
        &mut self,
        r: &LaunchRequest,
        h: &dyn HostEvidence,
    ) -> Result<Launched, LaunchRefusal> {
        if r.device_profile.devices.paravirtualized_gpu {
            self.native_launch(r, h)
        } else {
            self.cpu.launch(r, h)
        }
    }
    fn stop(&mut self, v: &VmInstanceId) -> Result<StopOutcome, BackendRefusal> {
        if self.held.contains_key(v) || self.ended.contains_key(v) {
            self.native_stop(v)
        } else {
            self.cpu.stop(v)
        }
    }
    fn snapshot(
        &mut self,
        v: &VmInstanceId,
        o: SnapshotOrigin,
    ) -> Result<SnapshotManifest, BackendRefusal> {
        self.cpu.snapshot(v, o)
    }
    fn restore(
        &mut self,
        r: &LaunchRequest,
        s: &SnapshotManifest,
        h: &dyn HostEvidence,
    ) -> Result<Restored, LaunchRefusal> {
        self.cpu.restore(r, s, h)
    }
    fn actual_accelerator(
        &self,
        v: &VmInstanceId,
    ) -> Result<HostObserved<Accelerator>, BackendRefusal> {
        if let Some(held) = self.held.get(v) {
            held.admitted
                .as_ref()
                .map(|x| x.record.accelerator().clone())
                .ok_or(BackendRefusal::NoSuchVm { vm: *v })
        } else {
            self.cpu.actual_accelerator(v)
        }
    }
    fn confinement_evidence(&self, v: &VmInstanceId) -> Result<ObservedProperties, BackendRefusal> {
        if let Some(held) = self.held.get(v) {
            held.admitted
                .as_ref()
                .map(|x| x.record.host_observed().clone())
                .ok_or(BackendRefusal::NoSuchVm { vm: *v })
        } else {
            self.cpu.confinement_evidence(v)
        }
    }
    fn running(&self) -> Vec<VmInstanceId> {
        self.cpu
            .running()
            .into_iter()
            .chain(self.held.keys().copied())
            .collect()
    }
    fn reobserve(
        &mut self,
        v: &VmInstanceId,
        h: &dyn HostEvidence,
    ) -> Result<Reobservation, ReobservationRefusal> {
        if !self.held.contains_key(v) {
            return self.cpu.reobserve(v, h);
        }
        let held = &self.held[v];
        let record = &held
            .admitted
            .as_ref()
            .ok_or(ReobservationRefusal::NotAdmitted { vm: *v })?
            .record;
        let (facts, configuration) =
            self.facts(v, h)
                .map_err(|r| ReobservationRefusal::Refused {
                    refusal: Box::new(r),
                })?;
        reobserved_with_configuration(
            &held.request,
            record,
            self.native
                .as_ref()
                .map_err(|_| ReobservationRefusal::Unsupported {
                    backend: BackendKind::Hcs,
                })?,
            h,
            facts,
            configuration,
        )
    }
}
impl ServiceRuntime for Runtime {
    type Proof = TerminationProof;
    fn launch_profile(
        &self,
        gpu: bool,
        mut profile: LaunchProfile,
        subjects: EvidenceSubjects,
    ) -> Result<(LaunchProfile, EvidenceSubjects), String> {
        if !gpu {
            return Ok((profile, subjects));
        }
        let identity = self.native.as_ref().map_err(Clone::clone)?;
        verify_bundle(
            Path::new(self.cpu.layout().settings().runtime_directory.as_str()),
            profile.pinned.guest_image,
        )?;
        profile.pinned.backend = identity.artifact;
        profile.device_profile.devices.paravirtualized_gpu = true;
        profile.device_profile.identity =
            digest("yougori/sandbox-vm/device-profile/v1", &[b"hcs-gpu-pv"]);
        profile.required.devices.paravirtualized_gpu = true;
        profile.required.confinement = confinement();
        Ok((profile, evidence(identity, subjects.hypervisor.machine)?))
    }
    fn additional_evidence(&self) -> Vec<EvidenceSubjects> {
        self.subjects.iter().cloned().collect()
    }
    fn process_of(&self, v: &VmInstanceId) -> Option<ProcessIdentity> {
        self.held
            .get(v)
            .map(|x| x.process.identity())
            .or_else(|| self.cpu.process_of(v))
    }
    fn termination(&self, v: &VmInstanceId) -> Option<&Self::Proof> {
        self.ended.get(v).or_else(|| self.cpu.termination(v))
    }
    fn private_directory(&self, p: &ProcessIdentity) -> Option<PrivateDirectory> {
        self.held
            .values()
            .find(|x| x.process.identity() == *p)
            .map(|x| x.directory.clone())
            .or_else(|| ServiceRuntime::private_directory(&self.cpu, p))
    }
    fn take_secret(&mut self, p: &ProcessIdentity) -> Option<BootstrapSecret> {
        if let Some(x) = self.held.values_mut().find(|x| x.process.identity() == *p) {
            x.secret.take()
        } else {
            ServiceRuntime::take_secret(&mut self.cpu, p)
        }
    }
    fn process_state(&self, p: &ProcessIdentity) -> Result<ProcessState, ObserveFailure> {
        if let Some(x) = self.held.values().find(|x| x.process.identity() == *p) {
            Ok(if x.process.check_ended().is_ok() {
                ProcessState::Ended { exit_code: 0 }
            } else {
                ProcessState::Running
            })
        } else {
            ServiceRuntime::process_state(&self.cpu, p)
        }
    }
    fn directory_absent(&self, d: &PrivateDirectory) -> Result<bool, ObserveFailure> {
        match fs::symlink_metadata(d.path().as_str()) {
            Ok(_) => Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(e) => Err(ObserveFailure::Unreadable {
                detail: e.to_string(),
            }),
        }
    }
    fn share_process(&self, p: &ProcessIdentity, h: &HostProcess) -> Result<SharedHandles, String> {
        if let Some(x) = self.held.values().find(|x| x.process.identity() == *p) {
            x.process.share_with(h).map_err(|e| e.to_string())
        } else {
            ServiceRuntime::share_process(&self.cpu, p, h)
        }
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        for vm in self.held.keys().copied().collect::<Vec<_>>() {
            let _ = self.native_stop(&vm);
        }
    }
}
