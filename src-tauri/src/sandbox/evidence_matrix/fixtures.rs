//! Test fixtures: a Linux host whose registry found KVM available, QEMU launch records
//! sealed by the backend contract's own admission from the fake backend's host script, a
//! guest image release signed with a test key from a fixed seed (never a release key),
//! a stamped V15 verdict and the doctor's examination. Digests of upstream files are of
//! placeholder bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use ring::signature::{Ed25519KeyPair, KeyPair};

use super::{assemble, MatrixRow, Reading, RowSources};
use crate::foundation::coordination::{SandboxGenerations, SnapshotId};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, HypervisorKind, HypervisorSubject, Observation, OsKind,
    PerimeterRuleSubject, ProbeRegistry, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, ContentKey, Digest, ExecutionId, ManualClock, MonotonicTime, SandboxBootGeneration,
    TenantId,
};
use crate::foundation::ledger::ReservationId;
use crate::foundation::report::CommitHash;
use crate::foundation::signing::{Ed25519PublicKey, TrustRoots};
use crate::sandbox::backend::{
    admit, precheck, vm_handle, Architecture, BackendFeatures, BackendIdentity, BackendKind,
    BuildId, DeviceExposure, DeviceProfile, HostBuild, HostScript, LaunchRecord, LaunchRequest,
    PerimeterRequirement, PinnedArtifacts, RequiredProperties,
};
use crate::sandbox::doctor::{CheckInputs, Doctor, DoctorReport, DoctorRequest};
use crate::sandbox::guest_image::{
    parse_kernel_config, signing_statement, verify_release, AgentFeatures, ArtifactRole,
    BuildInputSet, BuildRecord, BuildStep, FeatureManifest, FileInput, ImageName, InputName,
    InputVersion, ManifestDocument, ManifestSignature, ProducedArtifact, RecordDocument,
    ReleaseNumber, SourceInput, ToolInput, VerifiedImage, WorkloadFeature, GUEST_IMAGE_FORMAT,
};
use crate::sandbox::link::PROTOCOL_VERSION;
use crate::sandbox::probes::{
    catalog, CheckId, CheckInput, ControlledCheck, Expect, HostKind, JudgeContext, Observations,
    Observed, Part, ProbeOutcome, RunProfile, RunResult, Side, Vm05Evaluation,
};
use crate::sandbox::trust::{
    Architecture as ImageArchitecture, BootMethod, ComponentVersion, DeviceModel, HexBytes,
    UnixSeconds,
};
use crate::sandbox_contract::confinement::{
    ConfinementProfile, ConfinementVerdict, VerdictMeaning, VerdictOutcome, WorkloadProfile,
};

/// How long the host's observations stay fresh (the fake's host script).
pub const FRESH: Duration = Duration::from_secs(600);
/// The oldest evidence the reader accepts.
pub const MAX_AGE: Duration = Duration::from_secs(300);
pub const CONFIG: &str = "host-a";
pub const LINUX_BUILD: &str = "6.8.0-45";

/// The calendar time of the reading: inside the test key's window and the manifest's.
pub const NOW: u64 = 1_790_000_000;
pub const ISSUED_AT: u64 = 1_785_000_000;
pub const EXPIRES_AT: u64 = 1_795_000_000;

pub const ROOT_IMAGE: &[u8] = b"appliance-base root image, release 3";
pub const OTHER_ROOT_IMAGE: &[u8] = b"appliance-base root image, release 3, one byte changed!";
const KERNEL: &[u8] = b"vmlinuz-virt 6.12.47-0-virt";
const AGENT: &[u8] = b"yougori-agent static executable";
const KERNEL_CONFIG: &str = "#\n\
# Linux/x86 6.12.47 Kernel Configuration\n\
#\n\
CONFIG_MODULES=y\n\
# CONFIG_IO_URING is not set\n\
# CONFIG_BPF_SYSCALL is not set\n\
# CONFIG_USERFAULTFD is not set\n\
CONFIG_VSOCKETS=y\n";

pub fn configuration(name: &str) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("host", name)]).unwrap()
}

pub fn host(build: &str) -> HostBuild {
    HostBuild {
        os: OsKind::Linux,
        build: BuildId::new(build).unwrap(),
        architecture: Architecture::X86_64,
    }
}

pub fn linux_host() -> HostBuild {
    host(LINUX_BUILD)
}

pub fn machine() -> Digest {
    digest("yougori/test/evidence-matrix/machine/v1", &[b"m"])
}

pub fn root_image() -> Digest {
    *ContentKey::of(ROOT_IMAGE).digest()
}

pub fn other_root_image() -> Digest {
    *ContentKey::of(OTHER_ROOT_IMAGE).digest()
}

/// The QEMU build `version`, launching with KVM.
pub fn qemu_build(version: &str) -> BackendIdentity {
    BackendIdentity::new(
        BackendKind::Qemu,
        version,
        digest(
            "yougori/test/evidence-matrix/backend/v1",
            &[b"qemu", version.as_bytes()],
        ),
        HypervisorKind::Kvm,
    )
    .unwrap()
}

pub fn qemu() -> BackendIdentity {
    qemu_build("9.2.0")
}

pub fn firecracker() -> BackendIdentity {
    BackendIdentity::new(
        BackendKind::Firecracker,
        "1.13.1",
        digest("yougori/test/evidence-matrix/backend/v1", &[b"firecracker"]),
        HypervisorKind::Kvm,
    )
    .unwrap()
}

pub fn strict_profile() -> Digest {
    ConfinementProfile::builtin(WorkloadProfile::StrictTool)
        .unwrap()
        .digest()
}

pub fn developer_profile() -> Digest {
    ConfinementProfile::builtin(WorkloadProfile::Developer)
        .unwrap()
        .digest()
}

pub fn minimal_devices() -> DeviceProfile {
    device_profile(b"minimal")
}

pub fn device_profile(name: &[u8]) -> DeviceProfile {
    DeviceProfile {
        identity: digest("yougori/test/evidence-matrix/profile/v1", &[name]),
        devices: DeviceExposure::cpu_only(),
    }
}

fn perimeter_id() -> Digest {
    digest("yougori/test/evidence-matrix/perimeter/v1", &[b"host"])
}

fn broker() -> Digest {
    digest("yougori/test/evidence-matrix/principal/v1", &[b"broker"])
}

pub fn block_rule(name: &[u8]) -> Digest {
    digest("yougori/test/evidence-matrix/rule/v1", &[name])
}

/// The independent perimeter restricting the broker with `rules`.
pub fn independent(rules: &[Digest]) -> PerimeterRequirement {
    PerimeterRequirement::Independent {
        perimeter: perimeter_id(),
        principal: broker(),
        rules: rules.iter().copied().collect(),
    }
}

/// A registry on a manual clock whose hypervisor probe found KVM available under
/// `config`, and whose perimeter probe found each of `rules` enforced for the broker.
pub fn kvm_host(
    config: &str,
    rules: &[Digest],
) -> (ProbeRegistry<Arc<ManualClock>>, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000)));
    let mut registry = ProbeRegistry::new(Arc::clone(&clock));
    let hypervisor = FakeProbe::hypervisor_availability();
    let subject = Subject::Hypervisor(HypervisorSubject {
        machine: machine(),
        hypervisor: HypervisorKind::Kvm,
    });
    hypervisor.respond(
        &subject,
        Observation::supported(
            configuration(config),
            FRESH,
            SupportDetail::Hypervisor {
                hypervisor: HypervisorKind::Kvm,
            },
        ),
    );
    registry.register(Box::new(hypervisor)).unwrap();
    registry
        .refresh(Capability::HypervisorAvailable, &subject)
        .unwrap();
    if !rules.is_empty() {
        let perimeter = Arc::new(FakeProbe::new(
            Capability::PerimeterRuleEnforced,
            SourceClass::HostProbe,
        ));
        registry.register(Box::new(Arc::clone(&perimeter))).unwrap();
        for rule in rules {
            let subject = Subject::PerimeterRule(PerimeterRuleSubject {
                machine: machine(),
                perimeter: perimeter_id(),
                rule: *rule,
                principal: broker(),
            });
            perimeter.respond(
                &subject,
                Observation::supported(
                    configuration(config),
                    FRESH,
                    SupportDetail::PerimeterRuleEnforced,
                ),
            );
            registry
                .refresh(Capability::PerimeterRuleEnforced, &subject)
                .unwrap();
        }
    }
    (registry, clock)
}

/// One boot of `execution` on `backend`, pinned to `image`, built with `devices`.
pub fn launch_request(
    backend: &BackendIdentity,
    execution: &str,
    boot: u64,
    image: Digest,
    devices: DeviceProfile,
) -> LaunchRequest {
    LaunchRequest {
        execution: ExecutionId::new(execution).unwrap(),
        tenant: TenantId::new("tenant-1").unwrap(),
        generations: SandboxGenerations {
            boot: SandboxBootGeneration::new(boot),
            ..SandboxGenerations::FIRST
        },
        machine: machine(),
        configuration: configuration(CONFIG),
        contract: digest("yougori/test/evidence-matrix/contract/v1", &[b"c1"]),
        pinned: PinnedArtifacts {
            guest_image: image,
            backend: backend.artifact,
        },
        device_profile: devices,
        required: RequiredProperties::strictest(Duration::from_secs(60)),
        reservation: serde_json::from_value::<ReservationId>(1.into()).unwrap(),
    }
}

/// The record the backend contract's admission seals for `backend` when the host
/// observes `script`.
pub fn admitted(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    request: &LaunchRequest,
    backend: &BackendIdentity,
    script: &HostScript,
    restored_from: Option<SnapshotId>,
) -> LaunchRecord {
    let evidence = precheck(request, backend, &BackendFeatures::none(), registry).unwrap();
    admit(
        request,
        backend,
        registry,
        evidence,
        script.facts(registry.now()),
        vm_handle(backend.kind, &request.execution, request.generations.boot),
        restored_from,
    )
    .unwrap()
}

/// The fake's clean hardware VM on `host`, booted from `image`.
pub fn script(host: HostBuild, image: Digest) -> HostScript {
    HostScript::hardware_vm(HypervisorKind::Kvm, host, image, configuration(CONFIG))
}

/// What a set of records is made of.
#[derive(Clone)]
pub struct Launches {
    pub backend: BackendIdentity,
    pub host: HostBuild,
    pub devices: DeviceProfile,
    pub perimeter: PerimeterRequirement,
    /// Restores of one golden snapshot after the cold boot.
    pub restores: u64,
}

impl Launches {
    pub fn qemu() -> Self {
        Self {
            backend: qemu(),
            host: linux_host(),
            devices: minimal_devices(),
            perimeter: PerimeterRequirement::NotRequired,
            restores: 2,
        }
    }

    /// A cold boot and the restores, oldest first.
    pub fn seal(&self, registry: &ProbeRegistry<Arc<ManualClock>>) -> Vec<LaunchRecord> {
        let golden = SnapshotId::new(digest(
            "yougori/test/evidence-matrix/snapshot/v1",
            &[b"golden"],
        ));
        let script = script(self.host.clone(), root_image());
        (1..=1 + self.restores)
            .map(|boot| {
                let mut request = launch_request(
                    &self.backend,
                    "exe-1",
                    boot,
                    root_image(),
                    self.devices.clone(),
                );
                request.required.perimeter = self.perimeter.clone();
                let restored_from = (boot > 1).then_some(golden);
                admitted(registry, &request, &self.backend, &script, restored_from)
            })
            .collect()
    }
}

// ------------------------------------------------------------------ the doctor's results

fn meeting(expect: Expect) -> Observed {
    let reference = digest("yougori/test/evidence-matrix/reference/v1", &[b"reference"]);
    match expect {
        Expect::Refused => Observed::Attempt { refused: true },
        Expect::Succeeds => Observed::Attempt { refused: false },
        Expect::Absent => Observed::Presence { present: false },
        Expect::Present => Observed::Presence { present: true },
        Expect::Happens => Observed::Event { happened: true },
        Expect::NeverHappens => Observed::Event { happened: false },
        Expect::OneOf(allowed) => Observed::Value {
            value: allowed[0].to_owned(),
        },
        Expect::WithinLimit => Observed::Bounded { value: 1, limit: 2 },
        Expect::Matches => Observed::Comparison {
            observed: reference,
            reference,
        },
        Expect::AllDistinct => Observed::Identities {
            values: vec![
                digest("yougori/test/evidence-matrix/identity/v1", &[b"a"]),
                digest("yougori/test/evidence-matrix/identity/v1", &[b"b"]),
            ],
        },
    }
}

fn violating(expect: Expect) -> Observed {
    match expect {
        Expect::Refused => Observed::Attempt { refused: false },
        Expect::Succeeds => Observed::Attempt { refused: true },
        Expect::Absent => Observed::Presence { present: true },
        Expect::Present => Observed::Presence { present: false },
        Expect::Happens => Observed::Event { happened: false },
        Expect::NeverHappens => Observed::Event { happened: true },
        Expect::OneOf(_) => Observed::Value {
            value: "tcg".to_owned(),
        },
        Expect::WithinLimit => Observed::Bounded { value: 3, limit: 2 },
        Expect::Matches => Observed::Comparison {
            observed: digest("yougori/test/evidence-matrix/observed/v1", &[b"other"]),
            reference: digest("yougori/test/evidence-matrix/reference/v1", &[b"reference"]),
        },
        Expect::AllDistinct => {
            let same = digest("yougori/test/evidence-matrix/identity/v1", &[b"same"]);
            Observed::Identities {
                values: vec![same, same],
            }
        }
    }
}

pub fn observations(row: &ControlledCheck, part: Part, meet: bool) -> Observations {
    row.expectations()
        .filter(|entry| entry.part == part && entry.scope.applies(OsKind::Linux))
        .map(|entry| {
            let observed = if meet {
                meeting(entry.expect)
            } else {
                violating(entry.expect)
            };
            (entry.id, observed)
        })
        .collect()
}

/// Results that pass every check on this Linux host, except `failing`, whose
/// observations all fail, with VM-CP-05 from `verdict`.
pub fn results(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    verdict: &Vm05Evaluation,
    failing: Option<CheckId>,
) -> CheckInputs {
    catalog()
        .iter()
        .map(|row| {
            let input = if row.id.number() == 5 {
                CheckInput::Vm05(verdict.clone())
            } else {
                let kind = match row.side {
                    Side::ControlledExternal => HostKind::ControlledExternal,
                    _ => HostKind::Host,
                };
                let meet = failing != Some(row.id);
                CheckInput::Outcomes(
                    row.parts()
                        .into_iter()
                        .map(|part| {
                            ProbeOutcome::host(
                                row.id,
                                part,
                                kind,
                                registry.now(),
                                FRESH,
                                configuration(CONFIG),
                                RunResult::Observed {
                                    observations: observations(row, part, meet),
                                },
                            )
                            .unwrap()
                        })
                        .collect(),
                )
            };
            (row.id, input)
        })
        .collect()
}

/// A passing V15 verdict for `profile` of `workload`, stamped now.
pub fn evaluation(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    workload: WorkloadProfile,
    profile: Digest,
) -> Vm05Evaluation {
    evaluation_with(registry, workload, profile, VerdictOutcome::Passed)
}

/// A V15 verdict with `outcome` for `profile` of `workload`, stamped now.
pub fn evaluation_with(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    workload: WorkloadProfile,
    profile: Digest,
    outcome: VerdictOutcome,
) -> Vm05Evaluation {
    Vm05Evaluation::evaluated(
        ConfinementVerdict {
            profile,
            workload,
            meaning: VerdictMeaning::InnerControlsDefenseInDepth,
            host_corroboration_required: true,
            checks: Vec::new(),
            outcome,
        },
        registry.now(),
        FRESH,
        configuration(CONFIG),
    )
}

pub fn context(registry: &ProbeRegistry<Arc<ManualClock>>) -> JudgeContext {
    JudgeContext {
        now: registry.now(),
        configuration: configuration(CONFIG),
        max_age: MAX_AGE,
        os: OsKind::Linux,
    }
}

pub fn request(host: HostBuild, profiles: &[RunProfile]) -> DoctorRequest {
    DoctorRequest {
        host,
        configuration: configuration(CONFIG),
        profiles: profiles.iter().copied().collect(),
    }
}

/// The doctor's examination of `host` for the strict profile, with `results`.
pub fn examine(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    host: HostBuild,
    results: BTreeMap<BackendKind, CheckInputs>,
) -> DoctorReport {
    Doctor::new()
        .examine(
            &request(host, &[RunProfile::Strict]),
            &context(registry),
            results,
        )
        .unwrap()
}

// ------------------------------------------------------------------ the guest image

fn produced(version: &str, bytes: &[u8]) -> ProducedArtifact {
    ProducedArtifact {
        version: ComponentVersion::new(version).unwrap(),
        content_key: ContentKey::of(bytes),
        length_bytes: bytes.len() as u64,
    }
}

fn build_record(architecture: ImageArchitecture, root: &[u8]) -> BuildRecord {
    let tool = b"mkfs.ext4 1.47.2-r1 executable";
    let source = b"alpine-minirootfs bytes";
    BuildRecord::new(RecordDocument {
        format: GUEST_IMAGE_FORMAT,
        image: ImageName::new("yougori-guest-strict").unwrap(),
        architecture,
        inputs: BuildInputSet {
            repository: CommitHash::new("3f1c9a7e5b2d4086a1e7c3b9f0d2e4a6c8b0d1e2").unwrap(),
            source_date_epoch: UnixSeconds::new(1_780_000_000),
            sources: vec![SourceInput {
                name: InputName::new("alpine-minirootfs.tar.gz").unwrap(),
                content_key: ContentKey::of(source),
                length_bytes: source.len() as u64,
            }],
            toolchain: vec![ToolInput {
                name: InputName::new("mkfs.ext4").unwrap(),
                version: InputVersion::new("1.47.2-r1").unwrap(),
                content_key: ContentKey::of(tool),
                length_bytes: tool.len() as u64,
            }],
            kernel_configuration: FileInput {
                content_key: ContentKey::of(KERNEL_CONFIG.as_bytes()),
                length_bytes: KERNEL_CONFIG.len() as u64,
            },
            packages: Vec::new(),
        },
        steps: vec![BuildStep {
            name: InputName::new("make-root-image").unwrap(),
            program: InputName::new("mkfs.ext4").unwrap(),
            arguments: Vec::new(),
            environment: BTreeMap::new(),
        }],
        artifacts: BTreeMap::from([
            (
                ArtifactRole::RootImage,
                produced("appliance-2026.10.3", root),
            ),
            (ArtifactRole::Kernel, produced("6.12.47-0-virt", KERNEL)),
        ]),
    })
    .unwrap()
}

fn manifest_document(record: &BuildRecord) -> ManifestDocument {
    let kernel = record.artifact(ArtifactRole::Kernel).unwrap();
    ManifestDocument {
        format: GUEST_IMAGE_FORMAT,
        image: record.image().clone(),
        release: ReleaseNumber::new(3).unwrap(),
        issued_at: UnixSeconds::new(ISSUED_AT),
        expires_at: UnixSeconds::new(EXPIRES_AT),
        build_record: record.content_key(),
        architecture: record.architecture(),
        boot: BootMethod::DirectKernel,
        artifacts: record.artifacts().clone(),
        agent: AgentFeatures {
            version: ComponentVersion::new("agent-1.4.0").unwrap(),
            build: *ContentKey::of(AGENT).digest(),
            link_protocol: PROTOCOL_VERSION,
        },
        kernel: parse_kernel_config(*kernel.content_key.digest(), KERNEL_CONFIG.as_bytes())
            .unwrap(),
        workloads: vec![WorkloadFeature {
            workload: WorkloadProfile::StrictTool,
            confinement_profile: strict_profile(),
            guest_policy: digest("yougori/test/evidence-matrix/guest-policy/v1", &[b"strict"]),
        }],
        devices: BTreeSet::from([DeviceModel::VirtioBlk, DeviceModel::VirtioVsock]),
    }
}

/// The test release key, from a fixed seed. It is never a release key.
fn key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
}

fn trust_roots() -> TrustRoots {
    let public = Ed25519PublicKey::from_bytes(key_pair().public_key().as_ref()).unwrap();
    TrustRoots::from_json(&format!(
        "{{\"format\":1,\"keys\":[{{\"id\":\"guest-release-test\",\"algorithm\":\"ed25519\",\
         \"public_key\":\"{}\",\"classes\":[\"guest_image\"],\
         \"valid_from\":\"2026-01-01T00:00:00Z\",\"valid_until\":\"2027-01-01T00:00:00Z\"}}]}}",
        public.to_hex()
    ))
    .unwrap()
}

/// The release of `root` for `architecture`, with `edit` applied to its manifest before
/// it is signed, verified under the test trust roots.
pub fn release_with(
    architecture: ImageArchitecture,
    root: &[u8],
    edit: impl FnOnce(&mut ManifestDocument),
) -> VerifiedImage {
    let record = build_record(architecture, root);
    let mut document = manifest_document(&record);
    edit(&mut document);
    let manifest = FeatureManifest::new(document).unwrap();
    let pair = key_pair();
    let publisher = Ed25519PublicKey::from_bytes(pair.public_key().as_ref())
        .unwrap()
        .publisher_id();
    let statement = signing_statement(&publisher, manifest.canonical_bytes());
    let signature = ManifestSignature {
        publisher,
        signature: HexBytes::new(pair.sign(statement.as_bytes()).as_ref().to_vec()),
    };
    verify_release(
        manifest.canonical_bytes(),
        record.canonical_bytes(),
        &signature,
        &trust_roots(),
        UnixSeconds::new(NOW),
    )
    .unwrap()
}

pub fn release() -> VerifiedImage {
    release_with(ImageArchitecture::X86_64, ROOT_IMAGE, |_| {})
}

// ------------------------------------------------------------------ one host's evidence

/// One Linux host's evidence: QEMU's records, the release they booted, the verdict, and
/// the doctor's examination with every check passing for QEMU.
pub struct World {
    pub clock: Arc<ManualClock>,
    pub registry: ProbeRegistry<Arc<ManualClock>>,
    pub records: Vec<LaunchRecord>,
    pub image: VerifiedImage,
    pub evaluation: Vm05Evaluation,
    pub doctor: DoctorReport,
}

impl World {
    pub fn new() -> Self {
        Self::of(Launches::qemu(), &[])
    }

    /// The world whose records are `launches`, on a host whose perimeter enforces
    /// `rules`.
    pub fn of(launches: Launches, rules: &[Digest]) -> Self {
        let (registry, clock) = kvm_host(CONFIG, rules);
        let records = launches.seal(&registry);
        let evaluation = evaluation(&registry, WorkloadProfile::StrictTool, strict_profile());
        let doctor = examine(
            &registry,
            launches.host.clone(),
            BTreeMap::from([(launches.backend.kind, results(&registry, &evaluation, None))]),
        );
        Self {
            clock,
            registry,
            records,
            image: release(),
            evaluation,
            doctor,
        }
    }

    /// Everything, for QEMU.
    pub fn sources(&self) -> RowSources<'_> {
        RowSources {
            doctor: &self.doctor,
            backend: BackendKind::Qemu,
            records: &self.records,
            image: Some(&self.image),
            confinement: Some(&self.evaluation),
        }
    }

    pub fn reading(&self) -> Reading {
        Reading {
            context: context(&self.registry),
            calendar: UnixSeconds::new(NOW),
        }
    }

    pub fn row(&self) -> MatrixRow {
        assemble(&self.sources(), &self.reading()).unwrap()
    }
}
