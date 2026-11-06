//! The local runner binds the vLLM and Transformers runtimes it starts to the engine's host
//! evidence and unbinds them when they stop (G03, the carry-forward from S01;
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md: the S2 CORE-01 row and GPU-W02 "add
//! GPU/backend-specific observations ... to CORE-01; keep inference-runner identity
//! distinct from VmBackend identity").
//!
//! Every scheduler pass, [`desired`] reads what the pass saw of each model and returns the
//! binding of every vLLM or Transformers runtime known to run in this computer's CUDA
//! runtime, or why it cannot be bound. A runtime is known to run once its runner reports the model loaded
//! (resident, with no release in doubt) under the GPU grant host admission recorded for
//! it. That is the first point where the engine holds both the runtime's start (the grant
//! names the runner instance and the revision it was granted at, and that runner is the
//! one answering) and its GPU (the device of the host ledger reservation made for the
//! grant, digested as host admission digests it). The runner's report only decides when;
//! what the evidence says is observed on the host.
//!
//! [`Binder`] turns successive passes into binds and unbinds, each once: a runtime that
//! stopped, was paused, unloaded or released, was replaced by a new grant, or is no longer
//! seen is unbound, so `host_evidence` drops its evidence.
//!
//! - The release is the one the engine pins for the runner: for vLLM the audited launch
//!   record (`model_memory::profiles::audit::TODAY`, [`pinned_release`]), checked against
//!   the model server this engine ships, whose loader refuses any other vLLM; for the
//!   Transformers runner the release that server installs and checks
//!   (`MODEL_DEPENDENCIES`, [`pinned_transformers_release`]). It is bound only for a
//!   runtime on the image the engine pairs with that runner, running that model server;
//!   for any other the release is not known, nothing is guessed, and the runtime is
//!   reported unbound with the reason.
//! - The instance is a digest, in a domain of its own, of the environment and its start;
//!   no raw identifier leaves the engine.
//! - Only the shared-kernel GPU runtime (the WSL 2 CUDA runtime, VM-D4) is bound. Remote
//!   hosts, provider containers, VM sandboxes, WSL guest assertions and the native macOS
//!   runner are left to their own tasks (`host_evidence::UNCOVERED`), so a runner's
//!   identity never names a VM backend.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde_json::Value;

use super::control::{self, Observation};
use crate::foundation::evidence::{Backend, BackendRelease, RuntimeSubject};
use crate::foundation::ids::{Clock, Digest, DigestBuilder, ExecutionCategory};
use crate::foundation::ledger::{Ledger, Requester, ResourceKey};
use crate::host_evidence::RuntimeBinding;
use crate::model_memory::profiles::audit::{AuditItem, TODAY};

/// The digest domain of a local model runtime's instance: its environment and its start.
pub(super) const INSTANCE_DOMAIN: &str = "yougori/local-model-runtime/v1";

/// The model server this engine ships to every model runtime it starts, with the engine
/// backends it executes before a vLLM or GGUF load (the vLLM launch and its pin live there).
const MODEL_SERVER: &str = concat!(
    include_str!("../../model_server.py"),
    "\n",
    include_str!("../engine_backends.py")
);

/// The longest grant record read back, as the capacity path reads it.
const MAX_GRANT: usize = 2048;

const OTHER_IMAGE: &str = "Its runtime image is not the one the engine pairs with its runner, \
    so its release is not known. Recreate the model to bind its runtime.";
const OTHER_SERVER: &str = "It runs a model server from another engine build, so its release \
    is not known. Restart the model to bind its runtime.";
const NOT_ADMITTED: &str = "Host admission did not admit it on one GPU (only single-GPU vLLM \
    and Transformers models are admitted), so its GPUs are not known.";
const NO_GRANT: &str = "Its GPU grant is not recorded, so its start is not known.";
const OTHER_START: &str =
    "Its recorded GPU grant cannot be read or names another start of its runner.";
const NO_DEVICE: &str = "Host admission holds no GPU for it in this engine session (as after \
    an engine restart); its runtime is bound at its next grant.";

/// The vLLM release the engine pins, or why it is not known.
static PINNED: LazyLock<Result<BackendRelease, String>> = LazyLock::new(|| {
    let drift: Vec<String> = TODAY
        .drift(MODEL_SERVER)
        .into_iter()
        .filter(|drift| {
            matches!(
                drift.item,
                AuditItem::VllmVersion | AuditItem::ExactVersionCheck
            )
        })
        .map(|drift| drift.to_string())
        .collect();
    if !drift.is_empty() {
        return Err(format!(
            "The model server this engine ships does not pin one exact vLLM release: {}",
            drift.join("; ")
        ));
    }
    TODAY
        .vllm_release()
        .map_err(|error| format!("The engine's pinned vLLM release is invalid: {error}"))
});

/// The model server's Transformers pin: the `MODEL_DEPENDENCIES` line naming the release
/// its `install` puts in place and checks before the runner loads.
const TRANSFORMERS_PIN: &str = "MODEL_DEPENDENCIES = {\"transformers\": \"";

/// The Transformers release the engine pins, or why it is not known.
static PINNED_TRANSFORMERS: LazyLock<Result<BackendRelease, String>> = LazyLock::new(|| {
    let mut pins = MODEL_SERVER
        .lines()
        .filter_map(|line| line.strip_prefix(TRANSFORMERS_PIN)?.split('"').next());
    let (Some(version), None) = (pins.next(), pins.next()) else {
        return Err(
            "The model server this engine ships does not pin one exact Transformers release"
                .to_owned(),
        );
    };
    BackendRelease::new(Backend::Transformers, version)
        .map_err(|error| format!("The engine's pinned Transformers release is invalid: {error}"))
});

/// This engine's model server, as the launch options carry it.
static SERVER: LazyLock<String> = LazyLock::new(super::super::server_payload);

/// This engine's engine backends, as a vLLM model's launch options carry them.
static BACKENDS: LazyLock<String> = LazyLock::new(super::super::backends_source);

/// The exact vLLM release the engine runs: the audited launch record's, once the model
/// server this engine ships is seen to pin the same version and to refuse any other.
pub(in crate::model_runner) fn pinned_release() -> Result<&'static BackendRelease, &'static str> {
    PINNED.as_ref().map_err(String::as_str)
}

/// The exact Transformers release the engine runs: the one the model server this engine
/// ships installs and checks (`MODEL_DEPENDENCIES`).
pub(in crate::model_runner) fn pinned_transformers_release() -> Result<&'static BackendRelease, &'static str> {
    PINNED_TRANSFORMERS.as_ref().map_err(String::as_str)
}

/// The exact releases the engine runs, one per runner it binds, or why one is not known.
#[derive(Clone, Copy, Debug)]
pub(super) struct Releases<'a> {
    pub(super) vllm: Result<&'a BackendRelease, &'a str>,
    pub(super) transformers: Result<&'a BackendRelease, &'a str>,
}

/// The releases this engine pins.
pub(super) fn pinned_releases() -> Releases<'static> {
    Releases {
        vllm: pinned_release(),
        transformers: pinned_transformers_release(),
    }
}

/// What a model's saved launch options say about the runtime they start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Launch {
    /// It serves with vLLM.
    vllm: bool,
    /// It serves with the Transformers chat runner: safetensors on the GPU, not a decision
    /// runner, not GGUF, not the CPU runtime.
    transformers: bool,
    /// Host admission admits it on one GPU (the single-GPU vLLM or Transformers profile).
    admitted: bool,
    /// It runs the model server this engine ships (and, for vLLM, the engine backends that
    /// hold its launch and pin).
    current_server: bool,
}

impl Launch {
    /// It serves with vLLM.
    pub(super) fn is_vllm(&self) -> bool {
        self.vllm
    }

    /// Reads the launch options' environment.
    pub(super) fn of(environment: &BTreeMap<String, String>) -> Self {
        let format = environment.get("YOUGORI_MODEL_FORMAT").map(String::as_str);
        let vllm = format == Some("vllm");
        let transformers = matches!(format, None | Some("safetensors"))
            && environment
                .get("YOUGORI_MODEL_CPU")
                .is_none_or(|cpu| cpu != "1")
            && environment.get("YOUGORI_MODEL").is_none_or(|model| {
                !matches!(
                    model.as_str(),
                    "Cloudflare/clef" | "superagent-ai/security-one-27b"
                )
            });
        Self {
            vllm,
            transformers,
            admitted: environment.contains_key(super::capacity::POLICY),
            current_server: (vllm || transformers)
                && environment
                    .get("YOUGORI_MODEL_SERVER_SOURCE")
                    .is_some_and(|source| *source == *SERVER)
                && (!vllm
                    || environment
                        .get("YOUGORI_BACKENDS_SOURCE")
                        .is_some_and(|source| *source == *BACKENDS)),
        }
    }
}

/// What one scheduler pass saw of one model.
pub(super) struct Runner<'a> {
    pub(super) id: &'a str,
    /// Its environment runs: it is not paused, stopping or stopped.
    pub(super) running: bool,
    /// Its provider runs it in this computer's CUDA runtime.
    pub(super) local_cuda: bool,
    /// Its runtime image.
    pub(super) image: &'a str,
    /// Its saved launch options, when they could be read.
    pub(super) launch: Option<Launch>,
    /// The GPU grant host admission recorded for it.
    pub(super) grant: Option<&'a str>,
    /// Its validated health; `None` when paused, silent or invalid.
    pub(super) health: Option<&'a Value>,
}

/// The runner reports its model loaded on the GPU, with no release in doubt.
fn runs(health: &Value) -> bool {
    let optimizer = &health["optimizer"];
    optimizer["resident"] == true
        && optimizer["releaseUncertain"] == false
        && health["status"] != "error"
}

/// The runner instance and the revision its grant was made at, when the grant names the
/// runner that answers now.
fn start(grant: &str, health: &Value) -> Option<(String, u64)> {
    if grant.len() > MAX_GRANT {
        return None;
    }
    let granted: Value = serde_json::from_str(grant).ok()?;
    let Ok(Observation::V1 {
        instance_id,
        sequence,
    }) = control::observation(&granted)
    else {
        return None;
    };
    let Ok(Observation::V1 {
        instance_id: current,
        ..
    }) = control::observation(health)
    else {
        return None;
    };
    (current == instance_id).then_some((instance_id, sequence))
}

/// The GPUs host admission holds for this model: the devices of this machine whose VRAM
/// the open host-level reservation under its execution ([`super::capacity::owner`]) holds.
pub(super) fn admitted_devices<C: Clock>(ledger: &Ledger<C>, environment_id: &str) -> Vec<Digest> {
    let Some(owner) = super::capacity::owner(environment_id) else {
        return Vec::new();
    };
    let machine = ledger.host().machine;
    let mut devices = Vec::new();
    for reservation in ledger.open_reservations() {
        let provenance = reservation.provenance();
        if reservation.parent().is_some()
            || provenance.requester != Requester::Coordination
            || provenance.execution != owner
        {
            continue;
        }
        for resource in reservation.current().resources() {
            if let ResourceKey::Vram(device) = resource {
                if device.machine() == machine && !devices.contains(&device.device()) {
                    devices.push(device.device());
                }
            }
        }
    }
    devices
}

/// The binding of one running local vLLM or Transformers runtime, or why it cannot be bound.
fn binding<C: Clock>(
    runner: &Runner<'_>,
    launch: Launch,
    health: &Value,
    releases: Releases<'_>,
    ledger: Option<&Ledger<C>>,
) -> Result<RuntimeBinding, String> {
    let (release, image) = if launch.vllm {
        (releases.vllm, super::super::vllm::IMAGE)
    } else {
        (releases.transformers, super::super::TRANSFORMERS_IMAGE)
    };
    let release = release.map_err(str::to_owned)?;
    if runner.image != image {
        return Err(OTHER_IMAGE.into());
    }
    if !launch.current_server {
        return Err(OTHER_SERVER.into());
    }
    if !launch.admitted {
        return Err(NOT_ADMITTED.into());
    }
    let grant = runner.grant.ok_or(NO_GRANT)?;
    let (instance_id, sequence) = start(grant, health).ok_or(OTHER_START)?;
    let devices = ledger
        .map(|ledger| admitted_devices(ledger, runner.id))
        .unwrap_or_default();
    if devices.is_empty() {
        return Err(NO_DEVICE.into());
    }
    let instance = DigestBuilder::new(INSTANCE_DOMAIN)
        .str(runner.id)
        .str(&instance_id)
        .u64(sequence)
        .finish();
    RuntimeBinding::new(
        RuntimeSubject {
            category: ExecutionCategory::SharedKernelGpuRuntime,
            release: release.clone(),
            instance,
        },
        devices,
    )
    .map_err(|error| error.to_string())
}

/// The binding of every vLLM or Transformers runtime the pass saw running in this
/// computer's CUDA runtime, or why it cannot be bound, by environment. A runtime that is
/// not running, not local or neither runner's has no entry.
pub(super) fn desired<C: Clock>(
    runners: &[Runner<'_>],
    releases: Releases<'_>,
    ledger: Option<&Ledger<C>>,
) -> BTreeMap<String, Result<RuntimeBinding, String>> {
    runners
        .iter()
        .filter_map(|runner| {
            let launch = runner.launch.filter(|launch| {
                (launch.vllm || launch.transformers) && runner.local_cuda && runner.running
            })?;
            let health = runner.health.filter(|health| runs(health))?;
            Some((
                runner.id.to_owned(),
                binding(runner, launch, health, releases, ledger),
            ))
        })
        .collect()
}

/// One change for the engine's host evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Change {
    Bind(RuntimeBinding),
    Unbind(RuntimeSubject),
}

/// The runtimes one scheduler bound, so that across its passes each is bound once and
/// unbound once, and the ones it could not bind with why.
#[derive(Debug, Default)]
pub(super) struct Binder {
    bound: BTreeMap<String, RuntimeBinding>,
    unbound: BTreeMap<String, String>,
}

impl Binder {
    /// The changes that take the bound runtimes to `desired`: unbinds first, then binds.
    /// A runtime bound unchanged gives none.
    pub(super) fn reconcile(
        &mut self,
        desired: BTreeMap<String, Result<RuntimeBinding, String>>,
    ) -> Vec<Change> {
        let mut bound = BTreeMap::new();
        let mut unbound = BTreeMap::new();
        for (id, outcome) in desired {
            match outcome {
                Ok(binding) => {
                    bound.insert(id, binding);
                }
                Err(reason) => {
                    unbound.insert(id, reason);
                }
            }
        }
        let mut changes: Vec<Change> = self
            .bound
            .iter()
            .filter(|(id, old)| {
                bound
                    .get(*id)
                    .is_none_or(|new: &RuntimeBinding| new.runtime() != old.runtime())
            })
            .map(|(_, old)| Change::Unbind(old.runtime().clone()))
            .collect();
        changes.extend(
            bound
                .iter()
                .filter(|(id, new)| self.bound.get(*id) != Some(*new))
                .map(|(_, new)| Change::Bind(new.clone())),
        );
        self.bound = bound;
        self.unbound = unbound;
        changes
    }

    /// The runtimes bound now, by environment.
    pub(super) fn bindings(&self) -> &BTreeMap<String, RuntimeBinding> {
        &self.bound
    }

    /// Unbinds everything, as when the scheduler stops observing.
    pub(super) fn clear(&mut self) -> Vec<Change> {
        self.reconcile(BTreeMap::new())
    }

    /// The running local vLLM and Transformers runtimes the last pass could not bind, by
    /// environment.
    pub(super) fn unbound(&self) -> &BTreeMap<String, String> {
        &self.unbound
    }
}

/// One pass against what host admission holds now.
pub(super) fn pass(binder: &mut Binder, runners: &[Runner<'_>]) -> Vec<Change> {
    let ledger = super::shared_host_ledger();
    let held = ledger.as_ref().and_then(|ledger| ledger.lock().ok());
    binder.reconcile(desired(runners, pinned_releases(), held.as_deref()))
}

/// Hands `changes` to the engine's host evidence and records the runtimes left unbound.
pub(super) async fn apply(changes: Vec<Change>, unbound: &BTreeMap<String, String>) {
    for change in changes {
        // The evidence service is available for the engine's whole life or never; when it
        // is not, its status says so and there is nothing to bind into.
        let _ = match change {
            Change::Bind(binding) => crate::host_evidence::bind_runtime(binding).await,
            Change::Unbind(runtime) => crate::host_evidence::unbind_runtime(&runtime).await,
        };
    }
    crate::host_evidence::record_unbound(unbound.clone());
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::foundation::evidence::{
        Capability, ComputePlatform, HostSubject, ObservationResult, OsKind, SourceClass, Subject,
        SupportDetail,
    };
    use crate::foundation::ids::{
        digest, GpuDeviceKey, ManualClock, MonotonicTime, OperationId, SystemClock, TenantId,
    };
    use crate::foundation::ledger::{
        Admission, Amounts, CapacityDeclaration, CostPurpose, LedgerConfig, Priority, Provenance,
        QueueLimits, ReservationId, ReservationRequest,
    };
    use crate::host_evidence::{
        device_digest, machine_digest, parse_gpus, CudaRuntimeFacts, EvidenceService, GpuInventory,
        HostInventory, MachineIdentity, OsFacts,
    };

    const GUID: &str = "4C4C4544-0042-3510-8051-B4C04F4B3933";
    const UUID: &str = "GPU-12345678-1234-1234-1234-123456789ABC";
    const OTHER_UUID: &str = "GPU-abcdefab-cdef-abcd-efab-cdefabcdefab";
    const GIB: u64 = 1 << 30;

    /// A versioned runner health, as `gpu_optimizer.py` reports it.
    fn health(instance: char, sequence: u64, resident: bool) -> Value {
        json!({"status": if resident { "ready" } else { "idle" }, "optimizer": {
            "controlProtocol": 1, "instanceId": instance.to_string().repeat(32),
            "sequence": sequence, "enabled": true, "pinned": false, "resident": resident,
            "loading": false, "releaseUncertain": false, "active": 0, "pending": 0}})
    }

    /// The grant record host admission persists, of the target as it was granted.
    fn grant(instance: char, sequence: u64) -> String {
        super::super::configuration::record(&health(instance, sequence, false)).unwrap()
    }

    /// The launch options of a single-GPU vLLM model this engine created.
    fn options() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("YOUGORI_MODEL_FORMAT".to_owned(), "vllm".to_owned()),
            (
                super::super::capacity::POLICY.to_owned(),
                "local-single-vllm-v1".to_owned(),
            ),
            ("YOUGORI_MODEL_SERVER_SOURCE".to_owned(), SERVER.clone()),
            ("YOUGORI_BACKENDS_SOURCE".to_owned(), BACKENDS.clone()),
        ])
    }

    fn release() -> BackendRelease {
        BackendRelease::new(Backend::Vllm, "0.29.0").unwrap()
    }

    fn transformers_release() -> BackendRelease {
        BackendRelease::new(Backend::Transformers, "5.18.0").unwrap()
    }

    /// The engine's releases with only vLLM's known, as the vLLM cases need.
    fn vllm_only<'a>(vllm: Result<&'a BackendRelease, &'a str>) -> Releases<'a> {
        Releases {
            vllm,
            transformers: Err("not pinned in this case"),
        }
    }

    /// The launch options of a single-GPU Transformers model this engine created.
    fn transformers_options() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "YOUGORI_MODEL".to_owned(),
                "Qwen/Qwen2.5-0.5B-Instruct".to_owned(),
            ),
            (
                super::super::capacity::POLICY.to_owned(),
                "local-single-transformers-v1".to_owned(),
            ),
            ("YOUGORI_MODEL_SERVER_SOURCE".to_owned(), SERVER.clone()),
        ])
    }

    /// A running local vLLM model, granted at `grant` and answering with `health`.
    fn runner<'a>(id: &'a str, grant: &'a str, health: &'a Value) -> Runner<'a> {
        Runner {
            id,
            running: true,
            local_cuda: true,
            image: super::super::super::vllm::IMAGE,
            launch: Some(Launch::of(&options())),
            grant: Some(grant),
            health: Some(health),
        }
    }

    fn gpu(uuid: &str) -> GpuDeviceKey {
        GpuDeviceKey {
            machine: machine_digest(GUID).unwrap(),
            device: device_digest(uuid).unwrap(),
        }
    }

    fn tenant() -> TenantId {
        TenantId::new("local-models").unwrap()
    }

    /// This machine's host ledger with both GPUs declared, as host admission declares them.
    fn ledger() -> Ledger<SystemClock> {
        let config = LedgerConfig {
            queue: QueueLimits {
                max_entries: 64,
                max_entries_per_tenant: 64,
                max_wait: Duration::from_secs(60),
            },
            grant_ttl: Duration::from_secs(30),
            unmanaged_usage_max_age: Duration::from_secs(5),
        };
        let machine = machine_digest(GUID).unwrap();
        let mut ledger = Ledger::new(SystemClock::new(), HostSubject { machine }, config);
        for uuid in [UUID, OTHER_UUID] {
            let resource = ResourceKey::vram(gpu(uuid));
            let declaration = CapacityDeclaration {
                total: 16 * GIB,
                supervisor_reserve: 256 << 20,
                unmanaged_in_use: 0,
                source: SourceClass::HostProbe,
            };
            ledger.declare_capacity(resource, declaration).unwrap();
            ledger
                .set_tenant_budget(tenant(), resource, 16 * GIB)
                .unwrap();
        }
        ledger
    }

    /// Admits `id` on `uuid` as host admission does: a host-level reservation under the
    /// model's execution with a model-placement child, both in use.
    fn admit(ledger: &mut Ledger<SystemClock>, id: &str, uuid: &str) -> ReservationId {
        let provenance = Provenance {
            requester: Requester::Coordination,
            execution: super::super::capacity::owner(id).unwrap(),
            operation: OperationId::generate(),
            tenant: tenant(),
            purpose: CostPurpose::Compute,
            retry_number: 0,
        };
        let amounts = Amounts::new().with(ResourceKey::vram(gpu(uuid)), GIB);
        let request =
            ReservationRequest::new(provenance.clone(), Priority::Foreground, amounts.clone());
        let Admission::Granted(parent) = ledger.reserve(request).unwrap() else {
            panic!("the reservation was queued");
        };
        let mut model = provenance;
        model.requester = Requester::ModelPlacement;
        model.operation = OperationId::generate();
        let child = ReservationRequest::new(model, Priority::Foreground, amounts).within(parent);
        let Admission::Granted(child) = ledger.reserve(child).unwrap() else {
            panic!("the child reservation was queued");
        };
        ledger.begin_create(parent).unwrap();
        ledger.begin_create(child).unwrap();
        parent
    }

    /// The evidence service with an inventory of this machine and its one capable GPU.
    fn service() -> EvidenceService<ManualClock> {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(100_000_000_000)));
        let mut service = EvidenceService::new(clock).unwrap();
        let started_at = service.now();
        let csv = format!("{UUID}, 592.01, 8.9, WDDM, Disabled, 16376, 0, 16376");
        service.install(HostInventory {
            machine: MachineIdentity::from_result(machine_digest(GUID)),
            os: Some(OsFacts {
                kind: OsKind::Windows,
                architecture: "x86_64".into(),
                build: Some("26200".into()),
            }),
            gpus: GpuInventory::Devices {
                devices: parse_gpus(&csv).unwrap(),
            },
            cuda_runtime: Some(CudaRuntimeFacts {
                supported: true,
                installed: true,
                running: true,
                update_available: false,
            }),
            started_at,
        });
        service
    }

    /// Applies `changes` as [`apply`] hands them to the engine's service.
    fn apply_to(service: &mut EvidenceService<ManualClock>, changes: Vec<Change>) {
        for change in changes {
            match change {
                Change::Bind(binding) => {
                    let report = service.bind_runtime(binding);
                    assert!(report.refused.is_empty(), "{:?}", report.refused);
                }
                Change::Unbind(runtime) => {
                    service.unbind_runtime(&runtime);
                }
            }
        }
    }

    fn bound(changes: &[Change]) -> Vec<RuntimeBinding> {
        changes
            .iter()
            .filter_map(|change| match change {
                Change::Bind(binding) => Some(binding.clone()),
                Change::Unbind(_) => None,
            })
            .collect()
    }

    fn evidence(
        service: &EvidenceService<ManualClock>,
        capability: Capability,
        runtime: &RuntimeSubject,
    ) -> Option<ObservationResult> {
        service
            .registry()
            .latest(capability, &Subject::Runtime(runtime.clone()))
            .map(|envelope| envelope.result().clone())
    }

    #[test]
    fn the_pinned_release_is_the_one_the_engine_ships_with_its_image() {
        assert_eq!(pinned_release(), Ok(&release()));
        // The image the engine pairs with vLLM names the same release.
        let selected =
            super::super::super::vllm::inspect(&json!({"architectures": ["LlamaForCausalLM"]}))
                .unwrap();
        assert_eq!(selected["runtimeImage"], super::super::super::vllm::IMAGE);
        assert_eq!(
            selected["dependencies"]["vllm"],
            release().version.to_string()
        );
    }

    #[test]
    fn launch_options_name_a_vllm_runtime_admitted_on_one_gpu_with_this_engines_server() {
        assert_eq!(
            Launch::of(&options()),
            Launch {
                vllm: true,
                transformers: false,
                admitted: true,
                current_server: true
            }
        );
        let mut older = options();
        older.insert("YOUGORI_MODEL_SERVER_SOURCE".into(), "older".into());
        assert!(!Launch::of(&older).current_server);
        let mut gguf = options();
        gguf.insert("YOUGORI_MODEL_FORMAT".into(), "gguf".into());
        assert!(!Launch::of(&gguf).vllm);
        assert!(!Launch::of(&gguf).transformers);
    }

    #[test]
    fn launch_options_name_a_transformers_runtime_admitted_on_one_gpu_with_this_engines_server() {
        assert_eq!(
            Launch::of(&transformers_options()),
            Launch {
                vllm: false,
                transformers: true,
                admitted: true,
                current_server: true
            }
        );
        let mut explicit = transformers_options();
        explicit.insert("YOUGORI_MODEL_FORMAT".into(), "safetensors".into());
        assert!(Launch::of(&explicit).transformers);
        // The legacy scheduler's models, the CPU runtime, GGUF, a source publication and the
        // decision runners are not the Transformers chat runtime under a grant.
        let mut legacy = transformers_options();
        legacy.remove(super::super::capacity::POLICY);
        assert!(Launch::of(&legacy).transformers && !Launch::of(&legacy).admitted);
        for (name, value) in [
            ("YOUGORI_MODEL_CPU", "1"),
            ("YOUGORI_MODEL_FORMAT", "gguf"),
            ("YOUGORI_MODEL_FORMAT", "source"),
            ("YOUGORI_MODEL", "Cloudflare/clef"),
            ("YOUGORI_MODEL", "superagent-ai/security-one-27b"),
        ] {
            let mut other = transformers_options();
            other.insert(name.into(), value.into());
            let launch = Launch::of(&other);
            assert!(
                !launch.transformers && !launch.current_server,
                "{name}={value}"
            );
        }
        let mut older = transformers_options();
        older.insert("YOUGORI_MODEL_SERVER_SOURCE".into(), "older".into());
        assert!(Launch::of(&older).transformers && !Launch::of(&older).current_server);
    }

    #[test]
    fn the_pinned_transformers_release_is_the_one_the_model_server_installs() {
        assert_eq!(pinned_transformers_release(), Ok(&transformers_release()));
        // The preflight promises the same release to a supported checkpoint.
        let selected = super::super::super::preflight::inspect(
            "example/chat",
            &json!({"sha": "a".repeat(40), "pipeline_tag": "text-generation", "siblings": [{"rfilename": "model.safetensors", "size": 1}]}),
            &json!({"model_type": "llama"}),
        );
        assert_eq!(selected["runner"], "yougori-transformers-chat");
        assert_eq!(
            selected["dependencies"]["transformers"],
            transformers_release().version.to_string()
        );
        assert_eq!(pinned_releases().vllm, Ok(&release()));
        assert_eq!(pinned_releases().transformers, Ok(&transformers_release()));
    }

    #[test]
    fn a_started_local_transformers_runtime_is_bound_to_its_release_start_and_admitted_gpu() {
        let mut ledger = ledger();
        admit(&mut ledger, "model-t", UUID);
        let granted = grant('c', 2);
        let running = health('c', 5, true);
        let pinned = transformers_release();
        let pinned_vllm = release();
        let releases = Releases {
            vllm: Err("not pinned in this case"),
            transformers: Ok(&pinned),
        };
        let started = Runner {
            image: super::super::super::TRANSFORMERS_IMAGE,
            launch: Some(Launch::of(&transformers_options())),
            ..runner("model-t", &granted, &running)
        };
        let mut binder = Binder::default();
        let changes = binder.reconcile(desired(&[started], releases, Some(&ledger)));
        let [Change::Bind(binding)] = changes.as_slice() else {
            panic!("expected one bind, got {changes:?}");
        };
        let binding = binding.clone();
        let runtime = binding.runtime();
        assert_eq!(runtime.category, ExecutionCategory::SharedKernelGpuRuntime);
        assert_eq!(runtime.release, transformers_release());
        assert_eq!(binding.devices(), &[device_digest(UUID).unwrap()]);
        assert_eq!(
            runtime.instance,
            DigestBuilder::new(INSTANCE_DOMAIN)
                .str("model-t")
                .str(&"c".repeat(32))
                .u64(2)
                .finish()
        );
        assert!(binder.unbound().is_empty());
        let mut service = service();
        apply_to(&mut service, changes);
        assert_eq!(
            evidence(&service, Capability::ComputePlatform, runtime),
            Some(ObservationResult::Supported {
                detail: SupportDetail::ComputePlatform {
                    platform: ComputePlatform::Cuda
                }
            })
        );
        // On the vLLM image, with an unknown Transformers release, or admitted on the legacy
        // scheduler, the runtime is reported unbound with the reason.
        let mut legacy = transformers_options();
        legacy.remove(super::super::capacity::POLICY);
        let cases: Vec<(Runner<'_>, Releases<'_>, &str)> = vec![
            (
                Runner {
                    image: super::super::super::vllm::IMAGE,
                    launch: Some(Launch::of(&transformers_options())),
                    ..runner("model-t", &granted, &running)
                },
                releases,
                OTHER_IMAGE,
            ),
            (
                Runner {
                    image: super::super::super::TRANSFORMERS_IMAGE,
                    launch: Some(Launch::of(&transformers_options())),
                    ..runner("model-t", &granted, &running)
                },
                vllm_only(Ok(&pinned_vllm)),
                "not pinned in this case",
            ),
            (
                Runner {
                    image: super::super::super::TRANSFORMERS_IMAGE,
                    launch: Some(Launch::of(&legacy)),
                    ..runner("model-t", &granted, &running)
                },
                releases,
                NOT_ADMITTED,
            ),
        ];
        for (runner, releases, reason) in cases {
            let mut binder = Binder::default();
            let changes = binder.reconcile(desired(&[runner], releases, Some(&ledger)));
            assert!(changes.is_empty(), "{changes:?}");
            assert_eq!(binder.unbound()["model-t"], reason);
        }
    }

    #[test]
    fn a_started_local_vllm_runtime_is_bound_to_its_release_start_and_admitted_gpu() {
        let mut ledger = ledger();
        admit(&mut ledger, "model-a", UUID);
        admit(&mut ledger, "model-b", OTHER_UUID);
        let granted = grant('a', 4);
        let running = health('a', 7, true);
        let mut binder = Binder::default();
        let changes = binder.reconcile(desired(
            &[runner("model-a", &granted, &running)],
            vllm_only(Ok(&release())),
            Some(&ledger),
        ));
        let [Change::Bind(binding)] = changes.as_slice() else {
            panic!("expected one bind, got {changes:?}");
        };
        let binding = binding.clone();
        let runtime = binding.runtime();
        assert_eq!(runtime.category, ExecutionCategory::SharedKernelGpuRuntime);
        assert_eq!(runtime.release, release());
        // The GPU host admission holds for this model, not the other model's.
        assert_eq!(binding.devices(), &[device_digest(UUID).unwrap()]);
        // A digest of the environment and its start, in its own domain: no raw identifier.
        let instance = DigestBuilder::new(INSTANCE_DOMAIN)
            .str("model-a")
            .str(&"a".repeat(32))
            .u64(4)
            .finish();
        assert_eq!(runtime.instance, instance);
        assert_ne!(
            runtime.instance,
            digest(INSTANCE_DOMAIN, &[b"model-a".as_slice()])
        );
        assert!(binder.unbound().is_empty());

        // Bound into the evidence service, its platform, category and topology are observed.
        let mut service = service();
        apply_to(&mut service, changes);
        assert_eq!(
            evidence(&service, Capability::ComputePlatform, runtime),
            Some(ObservationResult::Supported {
                detail: SupportDetail::ComputePlatform {
                    platform: ComputePlatform::Cuda
                }
            })
        );
        assert_eq!(
            evidence(&service, Capability::RuntimeCategory, runtime),
            Some(ObservationResult::Supported {
                detail: SupportDetail::RuntimeCategory {
                    category: ExecutionCategory::SharedKernelGpuRuntime
                }
            })
        );
        assert!(evidence(&service, Capability::PeerTopology, runtime).is_some());
    }

    #[test]
    fn repeated_observations_of_the_same_runtime_bind_it_once() {
        let mut ledger = ledger();
        admit(&mut ledger, "model-a", UUID);
        let granted = grant('a', 4);
        let mut binder = Binder::default();
        let mut service = service();
        let mut first = None;
        for sequence in [5, 6, 9] {
            // The runner's revision moves on with its use; its start stays the grant's.
            let running = health('a', sequence, true);
            let changes = binder.reconcile(desired(
                &[runner("model-a", &granted, &running)],
                vllm_only(Ok(&release())),
                Some(&ledger),
            ));
            if first.is_none() {
                first = bound(&changes).pop();
                assert!(first.is_some());
                apply_to(&mut service, changes);
            } else {
                assert!(changes.is_empty(), "{changes:?}");
            }
        }
        let runtime = first.unwrap().runtime().clone();
        assert_eq!(
            service
                .status()
                .entries
                .iter()
                .filter(|entry| entry.subject == Subject::Runtime(runtime.clone()))
                .count(),
            3
        );
    }

    #[test]
    fn a_runtime_that_stops_is_released_or_disappears_is_unbound_and_its_evidence_dropped() {
        let granted = grant('a', 4);
        let running = health('a', 7, true);
        let unloaded = health('a', 8, false);
        let mut uncertain = health('a', 8, true);
        uncertain["optimizer"]["releaseUncertain"] = json!(true);
        // Each case is what a later pass sees of the same model.
        for case in [
            "paused or stopped",
            "unloaded",
            "release in doubt",
            "silent",
            "gone",
            "released",
        ] {
            let mut ledger = ledger();
            let reservation = admit(&mut ledger, "model-a", UUID);
            let mut binder = Binder::default();
            let mut service = service();
            let changes = binder.reconcile(desired(
                &[runner("model-a", &granted, &running)],
                vllm_only(Ok(&release())),
                Some(&ledger),
            ));
            let runtime = bound(&changes).pop().unwrap().runtime().clone();
            apply_to(&mut service, changes);
            assert!(evidence(&service, Capability::ComputePlatform, &runtime).is_some());

            let mut runners = vec![runner("model-a", &granted, &running)];
            match case {
                "paused or stopped" => runners[0].running = false,
                "unloaded" => runners[0].health = Some(&unloaded),
                "release in doubt" => runners[0].health = Some(&uncertain),
                "silent" => runners[0].health = None,
                "gone" => runners.clear(),
                _ => {
                    ledger
                        .confirm_release(reservation, SourceClass::HostProbe)
                        .unwrap();
                    runners[0].health = Some(&unloaded);
                }
            }
            let changes =
                binder.reconcile(desired(&runners, vllm_only(Ok(&release())), Some(&ledger)));
            assert_eq!(changes, vec![Change::Unbind(runtime.clone())], "{case}");
            apply_to(&mut service, changes);
            for capability in [
                Capability::ComputePlatform,
                Capability::RuntimeCategory,
                Capability::PeerTopology,
            ] {
                assert!(evidence(&service, capability, &runtime).is_none(), "{case}");
            }
            assert!(
                service
                    .status()
                    .entries
                    .iter()
                    .all(|entry| entry.subject != Subject::Runtime(runtime.clone())),
                "{case}"
            );
            // Nothing is left to unbind, and observing it gone again changes nothing.
            assert!(binder
                .reconcile(desired(&runners, vllm_only(Ok(&release())), Some(&ledger)))
                .is_empty());
        }
    }

    #[test]
    fn a_released_grant_that_still_reports_resident_is_unbound_with_the_reason() {
        let mut ledger = ledger();
        let reservation = admit(&mut ledger, "model-a", UUID);
        let granted = grant('a', 4);
        let running = health('a', 7, true);
        let mut binder = Binder::default();
        let first = binder.reconcile(desired(
            &[runner("model-a", &granted, &running)],
            vllm_only(Ok(&release())),
            Some(&ledger),
        ));
        let runtime = bound(&first).pop().unwrap().runtime().clone();
        ledger
            .confirm_release(reservation, SourceClass::HostProbe)
            .unwrap();
        let changes = binder.reconcile(desired(
            &[runner("model-a", &granted, &running)],
            vllm_only(Ok(&release())),
            Some(&ledger),
        ));
        assert_eq!(changes, vec![Change::Unbind(runtime)]);
        assert_eq!(binder.unbound()["model-a"], NO_DEVICE);
    }

    #[test]
    fn a_new_grant_unbinds_the_old_runtime_and_binds_the_new_one() {
        let mut ledger = ledger();
        admit(&mut ledger, "model-a", UUID);
        let mut binder = Binder::default();
        let (old_grant, old_health) = (grant('a', 4), health('a', 7, true));
        let old = binder.reconcile(desired(
            &[runner("model-a", &old_grant, &old_health)],
            vllm_only(Ok(&release())),
            Some(&ledger),
        ));
        let old = bound(&old).pop().unwrap().runtime().clone();
        // The runner restarted and was granted again.
        let (new_grant, new_health) = (grant('b', 1), health('b', 3, true));
        let changes = binder.reconcile(desired(
            &[runner("model-a", &new_grant, &new_health)],
            vllm_only(Ok(&release())),
            Some(&ledger),
        ));
        let [Change::Unbind(unbound), Change::Bind(binding)] = changes.as_slice() else {
            panic!("expected an unbind then a bind, got {changes:?}");
        };
        assert_eq!(*unbound, old);
        assert_ne!(binding.runtime().instance, old.instance);
        // A grant that names an earlier start of the runner binds nothing.
        let changes = binder.reconcile(desired(
            &[runner("model-a", &old_grant, &new_health)],
            vllm_only(Ok(&release())),
            Some(&ledger),
        ));
        assert_eq!(changes, vec![Change::Unbind(binding.runtime().clone())]);
        assert_eq!(binder.unbound()["model-a"], OTHER_START);
    }

    #[test]
    fn nothing_is_bound_for_an_unknown_release() {
        let mut ledger = ledger();
        admit(&mut ledger, "model-a", UUID);
        let granted = grant('a', 4);
        let running = health('a', 7, true);
        let mut older = options();
        older.insert("YOUGORI_MODEL_SERVER_SOURCE".into(), "older".into());
        let pinned = release();
        let cases: Vec<(Runner<'_>, Result<&BackendRelease, &str>, &str)> = vec![
            (
                runner("model-a", &granted, &running),
                Err("no exact release"),
                "no exact release",
            ),
            (
                Runner {
                    image: "docker.io/vllm/vllm-openai:latest",
                    ..runner("model-a", &granted, &running)
                },
                Ok(&pinned),
                OTHER_IMAGE,
            ),
            (
                Runner {
                    launch: Some(Launch::of(&older)),
                    ..runner("model-a", &granted, &running)
                },
                Ok(&pinned),
                OTHER_SERVER,
            ),
        ];
        for (runner, release, reason) in cases {
            let mut binder = Binder::default();
            let changes = binder.reconcile(desired(&[runner], vllm_only(release), Some(&ledger)));
            assert!(changes.is_empty(), "{changes:?}");
            assert_eq!(binder.unbound()["model-a"], reason);
        }
    }

    #[test]
    fn a_runtime_without_an_admitted_gpu_or_grant_is_not_bound() {
        let ledger = ledger();
        let granted = grant('a', 4);
        let running = health('a', 7, true);
        let mut multi_gpu = options();
        multi_gpu.remove(super::super::capacity::POLICY);
        let cases: Vec<(Runner<'_>, &str)> = vec![
            // Not admitted in this engine session.
            (runner("model-a", &granted, &running), NO_DEVICE),
            (
                Runner {
                    grant: None,
                    ..runner("model-a", &granted, &running)
                },
                NO_GRANT,
            ),
            (
                Runner {
                    launch: Some(Launch::of(&multi_gpu)),
                    ..runner("model-a", &granted, &running)
                },
                NOT_ADMITTED,
            ),
        ];
        for (runner, reason) in cases {
            let mut binder = Binder::default();
            assert!(binder
                .reconcile(desired(&[runner], vllm_only(Ok(&release())), Some(&ledger)))
                .is_empty());
            assert_eq!(binder.unbound()["model-a"], reason);
        }
        // Without a host ledger at all, nothing is bound either.
        let mut binder = Binder::default();
        assert!(binder
            .reconcile(desired::<SystemClock>(
                &[runner("model-a", &granted, &running)],
                vllm_only(Ok(&release())),
                None,
            ))
            .is_empty());
    }

    #[test]
    fn non_local_or_non_vllm_runtimes_are_neither_bound_nor_reported() {
        let mut ledger = ledger();
        admit(&mut ledger, "model-a", UUID);
        let granted = grant('a', 4);
        let running = health('a', 7, true);
        let mut gguf = options();
        gguf.insert("YOUGORI_MODEL_FORMAT".into(), "gguf".into());
        let runners = [
            // A remote host, a provider container, a VM sandbox or the CPU runtime.
            Runner {
                local_cuda: false,
                ..runner("model-a", &granted, &running)
            },
            // llama.cpp runtimes are not this binding's.
            Runner {
                launch: Some(Launch::of(&gguf)),
                ..runner("model-a", &granted, &running)
            },
            // Options that cannot be read say nothing about the runtime.
            Runner {
                launch: None,
                ..runner("model-a", &granted, &running)
            },
        ];
        for runner in runners {
            let mut binder = Binder::default();
            assert!(binder
                .reconcile(desired(&[runner], vllm_only(Ok(&release())), Some(&ledger)))
                .is_empty());
            assert!(binder.unbound().is_empty());
        }
        // The binding itself refuses every category but the local shared-kernel runtime,
        // so a runner never binds as a VM sandbox or a provider container.
        for category in [
            ExecutionCategory::VmSandbox,
            ExecutionCategory::ProviderContainerRuntime,
            ExecutionCategory::HostProcessModelRuntime,
        ] {
            let runtime = RuntimeSubject {
                category,
                release: release(),
                instance: digest(INSTANCE_DOMAIN, &[b"model-a".as_slice()]),
            };
            assert!(RuntimeBinding::new(runtime, vec![device_digest(UUID).unwrap()]).is_err());
        }
    }

    #[test]
    fn clearing_the_binder_unbinds_every_runtime_it_bound() {
        let mut ledger = ledger();
        admit(&mut ledger, "model-a", UUID);
        let granted = grant('a', 4);
        let running = health('a', 7, true);
        let mut binder = Binder::default();
        let changes = binder.reconcile(desired(
            &[runner("model-a", &granted, &running)],
            vllm_only(Ok(&release())),
            Some(&ledger),
        ));
        let runtime = bound(&changes).pop().unwrap().runtime().clone();
        assert_eq!(binder.clear(), vec![Change::Unbind(runtime)]);
        assert!(binder.clear().is_empty());
    }
}
