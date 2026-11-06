//! Fakes for the partition and fetch tests: names, policies, workflow fixtures, a seeded
//! generator, a fake registry, a fake class verifier and an in-memory import source.
//! Nothing touches a network; catalogs live in temporary directories.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, Catalog, CatalogConfig, ContentDescriptor, ImportManifest,
    ImportSource, ObjectBytes, PublisherId, Scope, SourceError, SourceIdentity, TrustPolicy,
    VerifierRegistry, VerifierRejection,
};
use crate::foundation::ids::{
    digest, Clock, ContentKey, Digest, ManualClock, MonotonicTime, TenantId,
};
use crate::foundation::report::{RunRecord, RunSubstrate, RUN_RECORD_SAMPLE_JSON};
use crate::foundation::transfer::Endpoint;

pub const MIB: u64 = 1 << 20;
pub const KIB: u64 = 1 << 10;

pub fn tag(text: &str) -> LabelTag {
    LabelTag::new(text).unwrap()
}

pub fn step(text: &str) -> StepId {
    StepId::new(text).unwrap()
}

pub fn data(text: &str) -> DataId {
    DataId::new(text).unwrap()
}

pub fn contract_id(text: &str) -> ContractId {
    ContractId::new(text).unwrap()
}

pub fn volume(text: &str) -> VolumeId {
    VolumeId::new(text).unwrap()
}

pub fn read(source: &str) -> Authority {
    Authority::ReadPrivate {
        source: tag(source),
    }
}

pub fn credential(name: &str) -> Authority {
    Authority::UseCredential {
        credential: tag(name),
    }
}

pub fn exact(contract: &str) -> Authority {
    Authority::ExactRelease {
        contract: contract_id(contract),
    }
}

pub fn ops(list: &[Authority]) -> BTreeSet<Authority> {
    list.iter().cloned().collect()
}

pub fn operator() -> Approval {
    Approval::Operator {
        reviewer: tag("alice"),
    }
}

pub fn preauthorized(rule: &str) -> Approval {
    Approval::PolicyPreauthorized { rule: tag(rule) }
}

/// Weights with round numbers for the worked cost example: 2 s boot, 1 MiB/ms crossings.
pub fn weights() -> CostWeights {
    CostWeights {
        vm_startup_ms: 2_000,
        startup_units_per_vm: 100,
        retention_units_per_vm_second: 1,
        transfer_bytes_per_ms: MIB,
        transfer_units_per_mib: 1,
        delay_units_per_second: 2,
        approval_units: 50,
    }
}

pub fn policy() -> PartitionPolicy {
    PartitionPolicy::new(
        weights(),
        Budgets::with_vm_d12_lifetimes(8, 8, 64 * 1024, 512),
    )
}

pub fn private_source(id: &str, source: &str, size_bytes: u64) -> SourceData {
    SourceData {
        id: data(id),
        label: Label::private(tag(source), Integrity::Trusted),
        origin: LabelOrigin::TrustedPolicy {
            rule: tag("project-root-grant"),
        },
        size_bytes,
    }
}

pub fn public_source(id: &str, source: &str, size_bytes: u64) -> SourceData {
    SourceData {
        id: data(id),
        label: Label::public(tag(source), Integrity::Trusted),
        origin: LabelOrigin::ExplicitProvenance {
            source: tag(source),
        },
        size_bytes,
    }
}

pub fn output(id: &str, size_bytes: u64, immutable: bool) -> StepOutput {
    StepOutput {
        id: data(id),
        size_bytes,
        immutable,
        declared_label: None,
    }
}

pub fn make_step(
    id: &str,
    inputs: &[&str],
    operations: &[Authority],
    outputs: Vec<StepOutput>,
    duration_ms: u64,
    memory_mib: u64,
) -> Step {
    Step {
        id: step(id),
        inputs: inputs.iter().map(|input| data(input)).collect(),
        operations: ops(operations),
        outputs,
        cost: StepCost {
            duration_ms,
            memory_mib,
        },
        volumes: BTreeSet::new(),
    }
}

pub fn handoff(
    id: &str,
    item: &str,
    to: &str,
    approval: Approval,
    max_bytes: u64,
) -> ReleaseContract {
    ReleaseContract {
        id: contract_id(id),
        item: data(item),
        destination: ContractDestination::Step { step: step(to) },
        approval,
        max_bytes,
    }
}

pub fn external(id: &str, item: &str, target: &str, max_bytes: u64) -> ReleaseContract {
    ReleaseContract {
        id: contract_id(id),
        item: data(item),
        destination: ContractDestination::External {
            target: tag(target),
        },
        approval: operator(),
        max_bytes,
    }
}

/// The five-step example of lines 2324–2328: a fetch VM, an analysis/build VM without
/// internet, an immutable patch, an exact release and a narrow executor.
pub fn five_step() -> WorkflowSpec {
    WorkflowSpec {
        sources: vec![
            private_source("project", "private-repo", 50 * MIB),
            public_source("lockfile", "public-lockfile", 64 * KIB),
        ],
        steps: vec![
            make_step(
                "fetch",
                &["lockfile"],
                &[Authority::RegistryFetch],
                vec![output("deps", 200 * MIB, true)],
                30_000,
                1_024,
            ),
            make_step(
                "build",
                &["project", "deps"],
                &[read("private-repo"), Authority::RunUntrustedCode],
                vec![output("patch", 64 * KIB, true)],
                120_000,
                4_096,
            ),
            make_step(
                "apply",
                &["patch"],
                &[credential("repo-token"), exact("release-patch")],
                Vec::new(),
                5_000,
                256,
            ),
        ],
        contracts: vec![
            handoff(
                "deps-to-build",
                "deps",
                "build",
                preauthorized("verified-dependencies"),
                256 * MIB,
            ),
            handoff(
                "patch-to-executor",
                "patch",
                "apply",
                preauthorized("narrow-executor"),
                MIB,
            ),
            external(
                "release-patch",
                "patch",
                "repo:acme-app:branch:fix-123",
                MIB,
            ),
        ],
    }
}

/// A research workflow: gather public documents, analyze them with private notes, publish
/// one summary under an exact release.
pub fn research() -> WorkflowSpec {
    WorkflowSpec {
        sources: vec![
            private_source("notes", "private-notes", 5 * MIB),
            public_source("queries", "public-queries", 4 * KIB),
        ],
        steps: vec![
            make_step(
                "gather",
                &["queries"],
                &[Authority::ArbitraryNetwork],
                vec![output("documents", 30 * MIB, true)],
                60_000,
                1_024,
            ),
            make_step(
                "analyze",
                &["notes", "documents"],
                &[read("private-notes"), Authority::RunUntrustedCode],
                vec![output("summary", 32 * KIB, true)],
                90_000,
                2_048,
            ),
            make_step(
                "publish",
                &["summary"],
                &[credential("blog-token"), exact("publish-summary")],
                Vec::new(),
                2_000,
                256,
            ),
        ],
        contracts: vec![
            handoff(
                "documents-to-analyze",
                "documents",
                "analyze",
                preauthorized("public-docs"),
                64 * MIB,
            ),
            handoff(
                "summary-to-publish",
                "summary",
                "publish",
                preauthorized("narrow-executor"),
                MIB,
            ),
            external("publish-summary", "summary", "site:acme-blog", MIB),
        ],
    }
}

/// A build that requests approved objects lazily while it reads private data, then a test
/// stage on its artifact.
pub fn lazy_build() -> WorkflowSpec {
    WorkflowSpec {
        sources: vec![private_source("project", "private-repo", 20 * MIB)],
        steps: vec![
            make_step(
                "build",
                &["project"],
                &[
                    read("private-repo"),
                    Authority::RunUntrustedCode,
                    Authority::ApprovedContent,
                ],
                vec![output("artifact", 8 * MIB, true)],
                60_000,
                2_048,
            ),
            make_step(
                "test",
                &["artifact"],
                &[Authority::RunUntrustedCode],
                vec![output("test-report", 64 * KIB, false)],
                30_000,
                1_024,
            ),
        ],
        contracts: vec![handoff(
            "artifact-to-test",
            "artifact",
            "test",
            preauthorized("ci"),
            16 * MIB,
        )],
    }
}

/// SplitMix64: the only randomness in these tests, from an explicit seed.
pub struct SeededRng(u64);

impl SeededRng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}

/// A random small workflow over one private and one public source.
pub fn random_workflow(rng: &mut SeededRng, steps: usize) -> WorkflowSpec {
    let menu: [&[Authority]; 7] = [
        &[],
        &[Authority::RunUntrustedCode],
        &[Authority::RegistryFetch],
        &[Authority::ApprovedContent, Authority::RunUntrustedCode],
        &[Authority::ArbitraryNetwork],
        &[read("repo")],
        &[read("repo"), Authority::RunUntrustedCode],
    ];
    let mut spec = WorkflowSpec {
        sources: vec![
            private_source("secret", "repo", (1 + rng.below(32)) * MIB),
            public_source("open", "public", (1 + rng.below(32)) * MIB),
        ],
        steps: Vec::new(),
        contracts: Vec::new(),
    };
    for index in 0..steps {
        let id = format!("s{index}");
        let mut inputs: Vec<String> = Vec::new();
        let mut operations: BTreeSet<Authority> = menu[rng.below(menu.len() as u64) as usize]
            .iter()
            .cloned()
            .collect();
        let release = index + 1 == steps && index > 0 && rng.below(4) == 0;
        if release {
            let item = format!("o{}", rng.below(index as u64));
            let name = format!("release-{index}");
            operations = ops(&[credential("token"), exact(&name)]);
            spec.contracts
                .push(external(&name, &item, "repo:target", 64 * MIB));
            inputs.push(item);
        } else {
            if rng.below(3) == 0 {
                inputs.push("secret".to_string());
                operations.insert(read("repo"));
            }
            if rng.below(3) == 0 {
                inputs.push("open".to_string());
            }
            for producer in 0..index {
                if rng.below(2) == 0 {
                    inputs.push(format!("o{producer}"));
                }
            }
        }
        for input in inputs.iter().filter(|input| input.starts_with('o')) {
            if rng.below(4) != 0 {
                spec.contracts.push(handoff(
                    &format!("c-{input}-{id}"),
                    input,
                    &id,
                    preauthorized("handoff"),
                    64 * MIB,
                ));
            }
        }
        let input_names: Vec<&str> = inputs.iter().map(String::as_str).collect();
        let operations: Vec<Authority> = operations.into_iter().collect();
        spec.steps.push(make_step(
            &id,
            &input_names,
            &operations,
            vec![output(
                &format!("o{index}"),
                (1 + rng.below(64)) * MIB,
                true,
            )],
            (1 + rng.below(60)) * 1_000,
            256 * (1 + rng.below(8)),
        ));
    }
    spec
}

/// CORE-08's golden run record on the fake substrate.
pub fn fake_run() -> RunRecord {
    let mut record: RunRecord = serde_json::from_str(RUN_RECORD_SAMPLE_JSON).unwrap();
    record.substrate = RunSubstrate::FakeTimeControlled;
    record
}

/// CORE-08's golden run record as an authorized disposable run.
pub fn measured_run() -> RunRecord {
    let mut record: RunRecord = serde_json::from_str(RUN_RECORD_SAMPLE_JSON).unwrap();
    record.substrate = RunSubstrate::AuthorizedDisposable {
        authorization: crate::foundation::report::Label::new("disposable-test-host").unwrap(),
    };
    record
}

// ---- VM-N4 fakes -------------------------------------------------------------------

pub fn scope(tenant: &str) -> Scope {
    Scope::tenant(TenantId::new(tenant).unwrap())
}

pub fn publisher(name: &str) -> PublisherId {
    PublisherId::from_key_fingerprint(digest("yougori/test/publisher/v1", &[name.as_bytes()]))
}

pub fn route(name: &str) -> Digest {
    digest("yougori/test/route/v1", &[name.as_bytes()])
}

/// The attestation the fake verifier accepts.
pub fn attest(publisher: &PublisherId, class: ArtifactClass, content: ContentKey) -> Vec<u8> {
    digest(
        "yougori/test/attest/v1",
        &[
            publisher.digest().as_bytes(),
            class.tag().as_bytes(),
            content.digest().as_bytes(),
        ],
    )
    .as_bytes()
    .to_vec()
}

/// A class verifier that accepts [`attest`] attestations and any structure.
pub struct FakeVerifier(pub ArtifactClass);

impl ArtifactVerifier for FakeVerifier {
    fn class(&self) -> ArtifactClass {
        self.0
    }

    fn authenticate(
        &self,
        content: &ContentDescriptor,
        publisher: &PublisherId,
        attestation: &[u8],
    ) -> Result<(), VerifierRejection> {
        if attestation == attest(publisher, content.class, content.content_key).as_slice() {
            Ok(())
        } else {
            Err(VerifierRejection::AttestationInvalid)
        }
    }

    fn validate(
        &self,
        _content: &ContentDescriptor,
        _bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        Ok(())
    }
}

pub const EXTENT_BYTES: u64 = 4 * KIB;

#[derive(Clone, Debug)]
pub struct FakeArtifact {
    pub bytes: Vec<u8>,
    pub class: ArtifactClass,
    pub publisher: PublisherId,
    pub redirect: Option<String>,
    pub corrupt: bool,
    pub resolve_to: Option<ContentKey>,
}

/// An in-memory registry that counts every call, so tests can show no network activity.
#[derive(Debug, Default)]
pub struct FakeRegistry {
    names: BTreeMap<(Digest, String, String), Digest>,
    pub artifacts: BTreeMap<Digest, FakeArtifact>,
    pub resolves: u32,
    pub declarations: u32,
    pub reads: u32,
}

impl FakeRegistry {
    /// Publishes `bytes` as `name` `version` on `registry` and returns its lock entry.
    pub fn publish(
        &mut self,
        registry: &str,
        name: &str,
        version: &str,
        class: ArtifactClass,
        bytes: &[u8],
        by: PublisherId,
    ) -> LockEntry {
        let coordinates = digest(
            "yougori/test/coordinates/v1",
            &[registry.as_bytes(), name.as_bytes(), version.as_bytes()],
        );
        self.names.insert(
            (route(registry), name.to_string(), version.to_string()),
            coordinates,
        );
        self.artifacts.insert(
            coordinates,
            FakeArtifact {
                bytes: bytes.to_vec(),
                class,
                publisher: by,
                redirect: None,
                corrupt: false,
                resolve_to: None,
            },
        );
        LockEntry {
            name: PackageName::new(name).unwrap(),
            version: version.to_string(),
            class,
            content_key: ContentKey::of(bytes),
            length_bytes: bytes.len() as u64,
            route: route(registry),
        }
    }

    pub fn artifact_mut(&mut self, registry: &str, name: &str, version: &str) -> &mut FakeArtifact {
        let coordinates = self.names[&(route(registry), name.to_string(), version.to_string())];
        self.artifacts.get_mut(&coordinates).unwrap()
    }

    pub fn network_calls(&self) -> u32 {
        self.resolves + self.declarations + self.reads
    }

    fn artifact(&self, pin: &PinnedSource) -> Result<&FakeArtifact, RegistryError> {
        self.artifacts
            .get(&pin.coordinates)
            .ok_or(RegistryError::NotFound)
    }
}

impl RegistryPort for FakeRegistry {
    fn resolve(
        &mut self,
        route: &Endpoint,
        name: &PackageName,
        version: &str,
    ) -> Result<ResolvedArtifact, RegistryError> {
        self.resolves += 1;
        let Endpoint::NamedRoute { route } = route else {
            return Err(RegistryError::NotFound);
        };
        let coordinates = *self
            .names
            .get(&(*route, name.as_str().to_string(), version.to_string()))
            .ok_or(RegistryError::NotFound)?;
        let artifact = &self.artifacts[&coordinates];
        Ok(ResolvedArtifact {
            coordinates,
            content_key: artifact
                .resolve_to
                .unwrap_or_else(|| ContentKey::of(&artifact.bytes)),
            length_bytes: artifact.bytes.len() as u64,
            publisher: artifact.publisher,
        })
    }

    fn declaration(&mut self, pin: &PinnedSource) -> Result<RegistryReply, RegistryError> {
        self.declarations += 1;
        let artifact = self.artifact(pin)?;
        if let Some(location) = &artifact.redirect {
            return Ok(RegistryReply::Redirect {
                location: location.clone(),
            });
        }
        let manifest =
            ImportManifest::describe(&artifact.bytes, NonZeroU64::new(EXTENT_BYTES).unwrap());
        Ok(RegistryReply::Artifact(PinnedArtifact {
            attestation: attest(&artifact.publisher, artifact.class, manifest.content_key),
            manifest,
            publisher: artifact.publisher,
        }))
    }

    fn length_bytes(&mut self, pin: &PinnedSource) -> Result<u64, RegistryError> {
        self.reads += 1;
        Ok(self.artifact(pin)?.bytes.len() as u64)
    }

    fn read_at(
        &mut self,
        pin: &PinnedSource,
        offset_bytes: u64,
        buffer: &mut [u8],
    ) -> Result<usize, RegistryError> {
        self.reads += 1;
        let artifact = self.artifact(pin)?;
        let start = (offset_bytes as usize).min(artifact.bytes.len());
        let count = buffer.len().min(artifact.bytes.len() - start);
        buffer[..count].copy_from_slice(&artifact.bytes[start..start + count]);
        if artifact.corrupt && count > 0 {
            buffer[0] ^= 0xff;
        }
        Ok(count)
    }
}

/// An in-memory import source for a user-selected private original.
pub struct MemorySource {
    pub identity: SourceIdentity,
    pub bytes: Vec<u8>,
}

impl ImportSource for MemorySource {
    fn identity(&self) -> SourceIdentity {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        Ok(self.bytes.len() as u64)
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        let start = (offset_bytes as usize).min(self.bytes.len());
        let count = buffer.len().min(self.bytes.len() - start);
        buffer[..count].copy_from_slice(&self.bytes[start..start + count]);
        Ok(count)
    }
}

pub fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000)))
}

/// A catalog with quotas for `scopes`, publisher trust for `trusted` on the package and
/// document classes, and user-selected originals accepted for documents.
pub fn open_catalog(
    root: &Path,
    clock: Arc<ManualClock>,
    scopes: &[Scope],
    trusted: &[PublisherId],
) -> Catalog {
    let mut config = CatalogConfig::new(Duration::from_secs(60));
    for scope in scopes {
        config = config.with_quota(scope.clone(), 1 << 30);
    }
    let mut trust = TrustPolicy::new();
    for publisher in trusted {
        trust = trust.trust_publisher(*publisher);
    }
    config = config
        .with_trust(ArtifactClass::DependencyPackage, trust.clone())
        .with_trust(
            ArtifactClass::DocumentManifest,
            trust.accept_user_selected(),
        );
    let mut verifiers = VerifierRegistry::new();
    verifiers
        .register(Box::new(FakeVerifier(ArtifactClass::DependencyPackage)))
        .unwrap();
    verifiers
        .register(Box::new(FakeVerifier(ArtifactClass::DocumentManifest)))
        .unwrap();
    let clock: Arc<dyn Clock> = clock;
    Catalog::open(root, config, verifiers, clock).unwrap().0
}

/// Deterministic package bytes.
pub fn package_bytes(seed: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}
