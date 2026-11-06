//! Tests for V09 (VM-W10): one or more per acceptance item, rule and refusal of the plan
//! lines in `mod.rs`. Everything runs on fakes; nothing here touches the host.

use std::collections::{BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use super::*;
use crate::foundation::coordination::{SnapshotId, VmInstanceId};
use crate::foundation::events::{
    AuditConfig, AuditDraft, AuditEntry, AuditFailurePolicy, AuditJournal, AuditRecord, AuditSpool,
    AuditStore, Durability, EmissionLimit, HostFact, JournalId, ProducerId, RedactedValue,
    RedactionPolicy, StoreRefusal,
};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{
    digest, Clock, ExecutionId, ManualClock, MonotonicTime, OperationId, SandboxBootGeneration,
};
use crate::foundation::transfer::CredentialRef;
use crate::sandbox_contract::destinations::{
    AddressClass, EmbeddedIpv4Form, HostAddressGeneration, HostAddressState, IpPrefix,
    METADATA_IPV6,
};
use crate::sandbox_contract::effects::{
    CredentialHandle, CredentialRefusal, ExposureProfile, ExternalCredential, GuestExposure,
    IssuerId, SandboxRef, SecretClass,
};
use crate::sandbox_contract::provider::{KnownSecrets, LeakSource, ScanEncoding};

// ---------------------------------------------------------------------------------------
// Fixtures

fn seed(byte: u8) -> CanarySeed {
    CanarySeed::from_bytes([byte; 32])
}

fn sandbox(name: &str) -> SandboxRef {
    SandboxRef {
        issuer: IssuerId::new(digest("yougori/test/issuer/v1", &[b"host-1"])),
        execution: ExecutionId::new(name).unwrap(),
    }
}

fn instance(name: &str) -> VmInstanceId {
    VmInstanceId::new(digest("yougori/test/instance/v1", &[name.as_bytes()]))
}

fn binding(sandbox_name: &str, instance_name: &str, boot: u64) -> SandboxBinding {
    SandboxBinding {
        sandbox: sandbox(sandbox_name),
        instance: instance(instance_name),
        boot: SandboxBootGeneration::new(boot),
    }
}

fn snapshot(name: &str) -> SnapshotId {
    SnapshotId::new(digest("yougori/test/snapshot/v1", &[name.as_bytes()]))
}

/// The host's own addresses: an interface address inside RFC 1918 space.
fn host_state() -> HostAddressState {
    HostAddressState::new(
        HostAddressGeneration::new(1),
        [IpPrefix::host(IpAddr::V4(Ipv4Addr::new(10, 200, 0, 1)))],
    )
}

fn pool() -> HoneyportPool {
    HoneyportPool::new(
        vec![
            IpAddr::V4(Ipv4Addr::new(10, 200, 0, 7)),
            IpAddr::V6("fd12:3456:789a::7".parse().unwrap()),
        ],
        &host_state(),
    )
    .unwrap()
}

fn registry(byte: u8) -> CanaryRegistry {
    CanaryRegistry::new(&seed(byte), pool())
}

fn placement(kind: CanaryKind, location: PlacementLocation) -> PlacementRequest {
    PlacementRequest { kind, location }
}

const CREDENTIAL_PATH: &str = ".config/legacy-deploy/token";
const DOCUMENT_PATH: &str = "docs/finance/q3-payroll.txt";
const DNS_VARIABLE: &str = "INTERNAL_METRICS_HOST";
const HONEYPORT_PATH: &str = "config/replica.yaml";

/// One canary of each kind, at allowed locations.
fn full_placements() -> Vec<PlacementRequest> {
    vec![
        placement(
            CanaryKind::FakeCredential,
            PlacementLocation::home(CREDENTIAL_PATH).unwrap(),
        ),
        placement(
            CanaryKind::DocumentMarker,
            PlacementLocation::workspace(DOCUMENT_PATH).unwrap(),
        ),
        placement(
            CanaryKind::DnsName,
            PlacementLocation::env(DNS_VARIABLE).unwrap(),
        ),
        placement(
            CanaryKind::HoneyportEndpoint,
            PlacementLocation::workspace(HONEYPORT_PATH).unwrap(),
        ),
    ]
}

fn fresh(binding: &SandboxBinding) -> PlantingRequest {
    PlantingRequest {
        binding: binding.clone(),
        origin: PlantOrigin::FreshBoot,
        placements: full_placements(),
    }
}

fn restored(
    binding: &SandboxBinding,
    snapshot: SnapshotId,
    source: &SandboxBinding,
) -> PlantingRequest {
    PlantingRequest {
        binding: binding.clone(),
        origin: PlantOrigin::RestoredFrom {
            snapshot,
            source: source.clone(),
        },
        placements: full_placements(),
    }
}

fn clock() -> ManualClock {
    ManualClock::new(MonotonicTime::from_nanos(5_000_000_000))
}

fn instruction(plan: &PlantingPlan, kind: CanaryKind) -> &PlantingInstruction {
    plan.instructions()
        .iter()
        .find(|instruction| instruction.kind() == kind)
        .unwrap()
}

fn value(plan: &PlantingPlan, kind: CanaryKind) -> String {
    instruction(plan, kind)
        .value()
        .expose_for_planting()
        .to_owned()
}

fn endpoint(registry: &CanaryRegistry, plan: &PlantingPlan) -> SocketAddr {
    let id = instruction(plan, CanaryKind::HoneyportEndpoint).canary();
    registry.canary(id).unwrap().endpoint().unwrap()
}

fn host_bytes(origin: &SandboxBinding, bytes: &[u8]) -> Observation {
    Observation::host_observed(
        origin.clone(),
        MonotonicTime::from_nanos(4_000_000_000),
        ObservedContent::OutboundBytes(bytes.to_vec()),
    )
    .unwrap()
}

fn guest_bytes(origin: &SandboxBinding, bytes: &[u8]) -> Observation {
    Observation::guest_reported(
        origin.clone(),
        ObservedContent::OutboundBytes(bytes.to_vec()),
    )
    .unwrap()
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let group = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(group[0]) << 16) | (u32::from(group[1]) << 8) | u32::from(group[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[derive(Default)]
struct MemoryStore {
    records: Vec<AuditRecord>,
}

impl AuditStore for MemoryStore {
    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        if !self.records.contains(record) {
            self.records.push(record.clone());
        }
        Ok(())
    }
}

#[derive(Default)]
struct MemorySpool {
    records: VecDeque<AuditRecord>,
}

impl AuditSpool for MemorySpool {
    fn push(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        self.records.push_back(record.clone());
        Ok(())
    }

    fn front(&self) -> Result<Option<AuditRecord>, StoreRefusal> {
        Ok(self.records.front().cloned())
    }

    fn pop_front(&mut self) -> Result<(), StoreRefusal> {
        self.records.pop_front();
        Ok(())
    }

    fn len(&self) -> usize {
        self.records.len()
    }

    fn records(&self) -> Result<Vec<AuditRecord>, StoreRefusal> {
        Ok(self.records.iter().cloned().collect())
    }
}

fn audit_config(redaction: RedactionPolicy) -> AuditConfig {
    AuditConfig {
        spool_records: 8,
        revocation_reserve_records: 1,
        failure_policy: AuditFailurePolicy::DenyHighImpact,
        guest_observations: EmissionLimit::new(10, Duration::from_secs(1)).unwrap(),
        redaction,
    }
}

/// Every object key and whether any number in `value` is not an integer.
fn walk_json(value: &serde_json::Value, keys: &mut Vec<String>, has_float: &mut bool) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                keys.push(key.clone());
                walk_json(inner, keys, has_float);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                walk_json(item, keys, has_float);
            }
        }
        serde_json::Value::Number(number) => {
            if !(number.is_u64() || number.is_i64()) {
                *has_float = true;
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------------------
// Registry: seeded generation, binding and formats

#[test]
fn seeded_generation_is_deterministic() {
    let a = binding("sbx-a", "vm-a", 1);
    let mut first = registry(1);
    let mut second = registry(1);
    let one = first.plan(fresh(&a)).unwrap();
    let two = second.plan(fresh(&a)).unwrap();
    assert_eq!(one.summary(), two.summary());
    for kind in CanaryKind::ALL {
        assert_eq!(value(&one, kind), value(&two, kind));
    }
    let mut other = registry(2);
    let three = other.plan(fresh(&a)).unwrap();
    for kind in [
        CanaryKind::FakeCredential,
        CanaryKind::DocumentMarker,
        CanaryKind::DnsName,
    ] {
        assert_ne!(value(&one, kind), value(&three, kind));
    }
    assert_ne!(one.summary(), three.summary());
}

#[test]
fn each_canary_is_bound_to_one_sandbox_instance_and_generation() {
    let a = binding("sbx-a", "vm-a", 3);
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&a)).unwrap();
    assert_eq!(plan.binding(), &a);
    let ids: BTreeSet<CanaryId> = plan.instructions().iter().map(|i| i.canary()).collect();
    assert_eq!(ids.len(), 4);
    for instruction in plan.instructions() {
        let canary = registry.canary(instruction.canary()).unwrap();
        assert_eq!(canary.binding(), &a);
        assert_eq!(canary.kind(), instruction.kind());
        assert_eq!(canary.location(), instruction.location());
        assert_eq!(canary.state(), CanaryState::Active);
        assert_eq!(canary.secret_class(), SecretClass::FakeCanary);
        assert_eq!(canary.value_digest(), instruction.value().digest());
    }
    assert_eq!(registry.len(), 4);
}

#[test]
fn value_formats_are_internal_and_mimic_no_credential_format() {
    let mut registry = registry(9);
    let zone_suffix = format!(".{CANARY_DNS_ZONE}");
    assert!(CANARY_DNS_ZONE.ends_with(".internal"));
    for n in 0..40 {
        let plan = registry
            .plan(fresh(&binding("sbx", &format!("vm-{n}"), 1)))
            .unwrap();
        let credential = value(&plan, CanaryKind::FakeCredential);
        let marker_hex = credential.strip_prefix(FAKE_CREDENTIAL_PREFIX).unwrap();
        assert_eq!(marker_hex.len(), 64);
        assert!(marker_hex.bytes().all(|b| b.is_ascii_hexdigit()));
        let document = value(&plan, CanaryKind::DocumentMarker);
        assert!(document.starts_with(DOCUMENT_MARKER_PREFIX));
        assert_eq!(document.len(), DOCUMENT_MARKER_PREFIX.len() + 64);
        let dns = value(&plan, CanaryKind::DnsName);
        let label = dns.strip_suffix(&zone_suffix).unwrap();
        assert!(!label.contains('.') && label.len() <= 63 && label.len() == 33);
        for text in [&credential, &document, &dns] {
            let folded = text.to_ascii_lowercase();
            for prefix in THIRD_PARTY_CREDENTIAL_PREFIXES {
                assert!(!folded.starts_with(prefix), "{prefix} mimicked");
            }
        }
        let socket = endpoint(&registry, &plan);
        assert!(pool().addresses().contains(&socket.ip()));
        assert!((HONEYPORT_FIRST_PORT..=HONEYPORT_LAST_PORT).contains(&socket.port()));
    }
}

#[test]
fn canary_tokens_exist_only_for_kinds_that_carry_the_whole_marker() {
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&binding("sbx", "vm", 1))).unwrap();
    for instruction in plan.instructions() {
        let canary = registry.canary(instruction.canary()).unwrap();
        match canary.kind() {
            CanaryKind::FakeCredential | CanaryKind::DocumentMarker => {
                let token = canary.token().unwrap();
                assert!(token.appears_in(instruction.value().expose_for_planting().as_bytes()));
                assert_eq!(token.class(), SecretClass::FakeCanary);
            }
            CanaryKind::DnsName | CanaryKind::HoneyportEndpoint => {
                assert!(canary.token().is_none())
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// VM-CP-21: clones, re-planting and attribution

#[test]
fn clones_restored_from_one_snapshot_get_distinct_values() {
    let a = binding("sbx-a", "vm-a", 1);
    let b = binding("sbx-b", "vm-b", 2);
    let c = binding("sbx-c", "vm-c", 2);
    let golden = snapshot("golden");
    let mut registry = registry(1);
    let plans = [
        registry.plan(fresh(&a)).unwrap(),
        registry.plan(restored(&b, golden, &a)).unwrap(),
        registry.plan(restored(&c, golden, &a)).unwrap(),
    ];
    let mut texts = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for plan in &plans {
        for instruction in plan.instructions() {
            assert!(texts.insert(instruction.value().expose_for_planting().to_owned()));
            assert!(digests.insert(instruction.value().digest()));
        }
    }
    assert_eq!(texts.len(), 12);

    // Two hosts given the same seed still differ, because each value includes its binding.
    let mut host_one = self::registry(7);
    let mut host_two = self::registry(7);
    let on_one = host_one.plan(restored(&b, golden, &a)).unwrap();
    let on_two = host_two.plan(restored(&c, golden, &a)).unwrap();
    for kind in [
        CanaryKind::FakeCredential,
        CanaryKind::DocumentMarker,
        CanaryKind::DnsName,
    ] {
        assert_ne!(value(&on_one, kind), value(&on_two, kind));
    }
}

#[test]
fn an_old_value_seen_after_restore_is_attributed_to_the_old_instance() {
    let a = binding("sbx-a", "vm-a", 1);
    let b = binding("sbx-b", "vm-b", 2);
    let unrelated = binding("sbx-d", "vm-d", 1);
    let golden = snapshot("golden");
    let mut registry = registry(1);
    let plan_a = registry.plan(fresh(&a)).unwrap();
    let plan_b = registry.plan(restored(&b, golden, &a)).unwrap();
    let clock = clock();

    let old = value(&plan_a, CanaryKind::FakeCredential);
    let report = registry.match_observation(&host_bytes(&b, old.as_bytes()), &clock);
    assert_eq!(report.hits.len(), 1);
    let hit = &report.hits[0];
    assert_eq!(
        hit.canary(),
        instruction(&plan_a, CanaryKind::FakeCredential).canary()
    );
    assert_eq!(hit.planted_in(), &a);
    assert_ne!(hit.planted_in(), &b);
    assert_eq!(hit.observed_in(), &b);
    assert_eq!(
        hit.attribution(),
        Attribution::CarriedBySnapshot { snapshot: golden }
    );

    let new = value(&plan_b, CanaryKind::FakeCredential);
    let report = registry.match_observation(&host_bytes(&b, new.as_bytes()), &clock);
    assert_eq!(report.hits[0].planted_in(), &b);
    assert_eq!(report.hits[0].attribution(), Attribution::PlantedHere);

    let report = registry.match_observation(&host_bytes(&unrelated, old.as_bytes()), &clock);
    assert_eq!(report.hits[0].planted_in(), &a);
    assert_eq!(report.hits[0].attribution(), Attribution::PlantedElsewhere);

    // The snapshot-carried file is attributed to the old instance until the clone
    // re-plants that path.
    let mut lazy = self::registry(2);
    let lazy_a = lazy.plan(fresh(&a)).unwrap();
    let mut other_paths = full_placements();
    other_paths.retain(|p| p.kind != CanaryKind::DocumentMarker);
    lazy.plan(PlantingRequest {
        binding: b.clone(),
        origin: PlantOrigin::RestoredFrom {
            snapshot: golden,
            source: a.clone(),
        },
        placements: other_paths,
    })
    .unwrap();
    let read = Observation::guest_reported(
        b.clone(),
        ObservedContent::FileRead(FileLocation::new(
            FileRoot::Workspace,
            GuestPath::new(DOCUMENT_PATH).unwrap(),
        )),
    )
    .unwrap();
    let report = lazy.match_observation(&read, &clock);
    assert_eq!(report.hits.len(), 1);
    assert_eq!(
        report.hits[0].canary(),
        instruction(&lazy_a, CanaryKind::DocumentMarker).canary()
    );
    assert_eq!(report.hits[0].planted_in(), &a);
    assert_eq!(
        report.hits[0].attribution(),
        Attribution::CarriedBySnapshot { snapshot: golden }
    );
}

#[test]
fn replanting_needs_a_new_generation_and_retires_the_old_one() {
    let first = binding("sbx-a", "vm-a", 1);
    let second = binding("sbx-a", "vm-a", 2);
    let mut registry = registry(1);
    let plan_one = registry.plan(fresh(&first)).unwrap();
    assert_eq!(
        registry.plan(fresh(&first)),
        Err(PlanRefusal::AlreadyPlanted)
    );
    let plan_two = registry.plan(fresh(&second)).unwrap();
    assert_eq!(
        registry.plan(fresh(&binding("sbx-a", "vm-a", 1))),
        Err(PlanRefusal::AlreadyPlanted)
    );
    let mut renamed = fresh(&binding("sbx-a", "vm-a", 2));
    renamed.placements.truncate(1);
    assert_eq!(registry.plan(renamed), Err(PlanRefusal::AlreadyPlanted));
    let mut gap = self::registry(3);
    gap.plan(fresh(&binding("sbx-a", "vm-a", 5))).unwrap();
    assert_eq!(
        gap.plan(fresh(&binding("sbx-a", "vm-a", 4))),
        Err(PlanRefusal::StaleGeneration {
            latest: SandboxBootGeneration::new(5)
        })
    );

    for kind in CanaryKind::ALL {
        assert_ne!(value(&plan_one, kind), value(&plan_two, kind));
    }
    for instruction in plan_one.instructions() {
        assert_eq!(
            registry.canary(instruction.canary()).unwrap().state(),
            CanaryState::Retired
        );
    }
    let old = value(&plan_one, CanaryKind::DocumentMarker);
    let report = registry.match_observation(&host_bytes(&second, old.as_bytes()), &clock());
    let hit = &report.hits[0];
    assert_eq!(hit.planted_in(), &first);
    assert_eq!(hit.canary_state(), CanaryState::Retired);
    assert_eq!(hit.attribution(), Attribution::OtherGeneration);
}

#[test]
fn retiring_keeps_matching_and_attribution() {
    let a = binding("sbx-a", "vm-a", 1);
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&a)).unwrap();
    assert_eq!(registry.retire(&a), 4);
    assert_eq!(registry.retire(&a), 0);
    assert_eq!(registry.retire(&binding("sbx-x", "vm-x", 1)), 0);
    let dns = value(&plan, CanaryKind::DnsName);
    let query = Observation::host_observed(
        binding("sbx-z", "vm-z", 1),
        MonotonicTime::from_nanos(1),
        ObservedContent::DnsQuery(dns),
    )
    .unwrap();
    let report = registry.match_observation(&query, &clock());
    assert_eq!(report.hits[0].canary_state(), CanaryState::Retired);
    assert_eq!(report.hits[0].planted_in(), &a);
}

#[test]
fn a_restore_cannot_come_from_itself_or_a_newer_generation() {
    let target = binding("sbx-a", "vm-a", 2);
    let mut registry = registry(1);
    assert_eq!(
        registry.plan(restored(&target, snapshot("s"), &target)),
        Err(PlanRefusal::RestoreSourceIsSelf)
    );
    assert_eq!(
        registry.plan(restored(
            &target,
            snapshot("s"),
            &binding("sbx-a", "vm-a", 3)
        )),
        Err(PlanRefusal::RestoreSourceNotOlder)
    );
    assert!(registry.is_empty());
    registry
        .plan(restored(
            &target,
            snapshot("s"),
            &binding("sbx-a", "vm-a", 1),
        ))
        .unwrap();
}

// ---------------------------------------------------------------------------------------
// §8.2 placement rules

fn covered_location(rule: DiscoveryRule) -> Vec<PlacementLocation> {
    match rule {
        DiscoveryRule::HomePath(path) => {
            let first = path.split('/').next().unwrap();
            vec![
                PlacementLocation::home(path).unwrap(),
                PlacementLocation::home(&format!("{path}/canary.txt")).unwrap(),
                PlacementLocation::home(&path.to_ascii_uppercase()).unwrap(),
                PlacementLocation::home(first).unwrap(),
                PlacementLocation::workspace(&format!("{path}/canary.txt")).unwrap(),
            ]
        }
        DiscoveryRule::NameAnywhere(name) => vec![
            PlacementLocation::home(name).unwrap(),
            PlacementLocation::workspace(&format!("src/deep/{name}")).unwrap(),
            PlacementLocation::workspace(&format!("{}/x", name.to_ascii_uppercase())).unwrap(),
        ],
        DiscoveryRule::NamePrefixAnywhere(prefix) => vec![
            PlacementLocation::workspace(&format!("{prefix}local")).unwrap(),
            PlacementLocation::home(&format!("app/{prefix}production")).unwrap(),
        ],
        DiscoveryRule::EnvName(name) => vec![
            PlacementLocation::env(name).unwrap(),
            PlacementLocation::env(&name.to_ascii_lowercase()).unwrap(),
        ],
        DiscoveryRule::EnvPrefix(prefix) => vec![
            PlacementLocation::env(&format!("{prefix}CANARY")).unwrap(),
            PlacementLocation::env(&format!("{}canary", prefix.to_ascii_lowercase())).unwrap(),
        ],
    }
}

#[test]
fn every_sdk_discovery_location_refuses_planting() {
    let mut registry = registry(1);
    for entry in SDK_DISCOVERY_LOCATIONS {
        for location in covered_location(entry.rule) {
            assert!(
                entry.covers(&location),
                "{location} not covered by {entry:?}"
            );
            for kind in [CanaryKind::FakeCredential, CanaryKind::DnsName] {
                match check_placement(kind, &location) {
                    Err(PlacementRefusal::SdkDiscovery {
                        tool,
                        location: refused,
                    }) => {
                        assert_eq!(refused, location);
                        assert!(SDK_DISCOVERY_LOCATIONS
                            .iter()
                            .any(|e| e.tool == tool && e.covers(&location)));
                    }
                    other => panic!("{location}: {other:?}"),
                }
            }
            let mut request = fresh(&binding("sbx", "vm", 1));
            request.placements = vec![placement(CanaryKind::FakeCredential, location.clone())];
            assert!(matches!(
                registry.plan(request),
                Err(PlanRefusal::Placement {
                    placement: PlacementRefusal::SdkDiscovery { .. }
                })
            ));
        }
    }
    assert!(registry.is_empty());
}

#[test]
fn named_sdk_cases_are_refused_and_ordinary_locations_allowed() {
    let refused = [
        PlacementLocation::home(".aws/credentials").unwrap(),
        PlacementLocation::workspace(".aws/credentials").unwrap(),
        PlacementLocation::home(".config").unwrap(),
        PlacementLocation::workspace("services/api/.env").unwrap(),
        PlacementLocation::workspace(".env.production").unwrap(),
        PlacementLocation::home(".cache/huggingface/token").unwrap(),
        PlacementLocation::home(".ssh/id_ed25519").unwrap(),
        PlacementLocation::workspace("frontend/.npmrc").unwrap(),
        PlacementLocation::env("aws_access_key_id").unwrap(),
        PlacementLocation::env("GOOGLE_APPLICATION_CREDENTIALS").unwrap(),
        PlacementLocation::env("TF_TOKEN_app_terraform_io").unwrap(),
        PlacementLocation::env("OPENAI_API_KEY").unwrap(),
        PlacementLocation::env("https_proxy").unwrap(),
        PlacementLocation::env("KUBECONFIG").unwrap(),
    ];
    for location in &refused {
        assert!(
            matches!(
                check_placement(CanaryKind::FakeCredential, location),
                Err(PlacementRefusal::SdkDiscovery { .. })
            ),
            "{location} was allowed"
        );
    }
    let aws = check_placement(
        CanaryKind::FakeCredential,
        &PlacementLocation::home(".aws/credentials").unwrap(),
    );
    assert!(
        matches!(aws, Err(PlacementRefusal::SdkDiscovery { tool, .. }) if tool == "AWS CLI and SDKs")
    );
    let allowed = [
        PlacementLocation::home(CREDENTIAL_PATH).unwrap(),
        PlacementLocation::workspace(DOCUMENT_PATH).unwrap(),
        PlacementLocation::workspace("ops/notes/environment.md").unwrap(),
        PlacementLocation::env("LEGACY_DEPLOY_TOKEN").unwrap(),
        PlacementLocation::env(DNS_VARIABLE).unwrap(),
    ];
    for location in &allowed {
        check_placement(CanaryKind::FakeCredential, location).unwrap();
    }
}

#[test]
fn locations_must_be_normal_relative_paths_and_valid_names() {
    let cases = [
        ("", LocationError::Empty),
        ("/etc/passwd", LocationError::EmptyComponent),
        ("a//b", LocationError::EmptyComponent),
        ("a/", LocationError::EmptyComponent),
        ("../x", LocationError::DotComponent),
        ("a/./b", LocationError::DotComponent),
        ("a\\b", LocationError::InvalidPathCharacter),
        ("caf\u{e9}", LocationError::InvalidPathCharacter),
        ("a b", LocationError::InvalidPathCharacter),
        ("a\0b", LocationError::InvalidPathCharacter),
    ];
    for (text, error) in cases {
        assert_eq!(GuestPath::new(text), Err(error), "{text:?}");
    }
    assert_eq!(
        GuestPath::new("a".repeat(256)),
        Err(LocationError::TooLong { max_bytes: 255 })
    );
    assert_eq!(
        GuestPath::new(vec!["d"; 17].join("/")),
        Err(LocationError::TooManyComponents { max: 16 })
    );
    GuestPath::new(vec!["d"; 16].join("/")).unwrap();
    GuestPath::new("a".repeat(255)).unwrap();
    for name in ["1A", "A-B", "A B", "\u{c4}"] {
        assert_eq!(
            EnvName::new(name),
            Err(LocationError::InvalidEnvName),
            "{name:?}"
        );
    }
    assert_eq!(EnvName::new(""), Err(LocationError::Empty));
    assert_eq!(
        EnvName::new("A".repeat(129)),
        Err(LocationError::TooLong { max_bytes: 128 })
    );
    EnvName::new("_PRIVATE_1").unwrap();
    assert!(serde_json::from_str::<GuestPath>("\"../x\"").is_err());
    assert!(serde_json::from_str::<EnvName>("\"A-B\"").is_err());
    let location: PlacementLocation =
        serde_json::from_str(r#"{"location":"file","root":"home","path":"notes/a.txt"}"#).unwrap();
    assert_eq!(location, PlacementLocation::home("notes/a.txt").unwrap());
}

#[test]
fn plan_shape_rules_refuse_and_register_nothing() {
    let target = binding("sbx", "vm", 1);
    let mut registry = registry(1);
    let mut empty = fresh(&target);
    empty.placements.clear();
    assert_eq!(registry.plan(empty), Err(PlanRefusal::Empty));

    let mut many = fresh(&target);
    many.placements = (0..17)
        .map(|n| {
            placement(
                CanaryKind::FakeCredential,
                PlacementLocation::workspace(&format!("notes/n{n}.txt")).unwrap(),
            )
        })
        .collect();
    assert_eq!(registry.plan(many), Err(PlanRefusal::TooMany { max: 16 }));

    let mut in_env = fresh(&target);
    in_env.placements = vec![placement(
        CanaryKind::DocumentMarker,
        PlacementLocation::env("REPORT_MARKER").unwrap(),
    )];
    assert!(matches!(
        registry.plan(in_env),
        Err(PlanRefusal::Placement {
            placement: PlacementRefusal::KindNeedsFile {
                kind: CanaryKind::DocumentMarker,
                ..
            }
        })
    ));

    let mut duplicate = fresh(&target);
    duplicate.placements = vec![
        placement(
            CanaryKind::FakeCredential,
            PlacementLocation::workspace("notes/a.txt").unwrap(),
        ),
        placement(
            CanaryKind::DocumentMarker,
            PlacementLocation::workspace("NOTES/A.TXT").unwrap(),
        ),
    ];
    assert!(matches!(
        registry.plan(duplicate),
        Err(PlanRefusal::Placement {
            placement: PlacementRefusal::DuplicateLocation { .. }
        })
    ));
    let mut env_duplicate = fresh(&target);
    env_duplicate.placements = vec![
        placement(
            CanaryKind::FakeCredential,
            PlacementLocation::env("LEGACY_KEY").unwrap(),
        ),
        placement(
            CanaryKind::DnsName,
            PlacementLocation::env("legacy_key").unwrap(),
        ),
    ];
    assert!(matches!(
        registry.plan(env_duplicate),
        Err(PlanRefusal::Placement {
            placement: PlacementRefusal::DuplicateLocation { .. }
        })
    ));

    let mut no_pool = CanaryRegistry::new(&seed(1), HoneyportPool::none());
    assert_eq!(
        no_pool.plan(fresh(&target)),
        Err(PlanRefusal::NoHoneyportPool)
    );
    assert!(registry.is_empty() && no_pool.is_empty());
    registry.plan(fresh(&target)).unwrap();
}

#[test]
fn honeyport_pools_classify_through_v02() {
    let host = host_state();
    let refused: [(IpAddr, AddressClass); 13] = [
        (
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            AddressClass::Metadata,
        ),
        (IpAddr::V6(METADATA_IPV6[0]), AddressClass::Metadata),
        (
            IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200)),
            AddressClass::Metadata,
        ),
        (
            IpAddr::V6("::ffff:169.254.169.254".parse().unwrap()),
            AddressClass::EmbeddedIpv4(EmbeddedIpv4Form::Mapped),
        ),
        (
            IpAddr::V4(Ipv4Addr::new(10, 200, 0, 1)),
            AddressClass::HostOwned,
        ),
        (
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            AddressClass::Loopback,
        ),
        (IpAddr::V6(Ipv6Addr::LOCALHOST), AddressClass::Loopback),
        (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), AddressClass::Public),
        (
            IpAddr::V6("2001:4860:4860::8888".parse().unwrap()),
            AddressClass::Public,
        ),
        (
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            AddressClass::Multicast,
        ),
        (
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            AddressClass::LinkLocal,
        ),
        (
            IpAddr::V4(Ipv4Addr::new(169, 254, 20, 10)),
            AddressClass::LinkLocal,
        ),
        (
            IpAddr::V6("fe80::1".parse().unwrap()),
            AddressClass::LinkLocal,
        ),
    ];
    for (address, class) in refused {
        assert_eq!(
            HoneyportPool::new(vec![address], &host),
            Err(HoneyportRefusal::AddressClassRefused { address, class }),
            "{address}"
        );
        // One refused address refuses the whole pool.
        assert!(
            HoneyportPool::new(vec![IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), address], &host)
                .is_err()
        );
    }
    let accepted: [IpAddr; 5] = [
        IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 9)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 7, 7)),
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
        IpAddr::V6("fd00::1".parse().unwrap()),
    ];
    let pool = HoneyportPool::new(accepted.to_vec(), &host).unwrap();
    assert_eq!(pool.addresses(), accepted.as_slice());
    let twice = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(
        HoneyportPool::new(vec![twice, twice], &host),
        Err(HoneyportRefusal::Duplicate { address: twice })
    );
    let too_many: Vec<IpAddr> = (0..=256u32)
        .map(|n| IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n)))
        .collect();
    assert_eq!(
        HoneyportPool::new(too_many, &host),
        Err(HoneyportRefusal::TooMany { max: 256 })
    );
}

// ---------------------------------------------------------------------------------------
// §4.5: a canary is never a credential; no production secret becomes a trap

#[test]
fn a_canary_can_never_act_as_a_credential() {
    assert!(!SecretClass::FakeCanary.is_genuine());
    assert!(!SecretClass::FakeCanary.is_external_credential());
    for profile in [ExposureProfile::Strict, ExposureProfile::Standard] {
        assert_eq!(
            SecretClass::FakeCanary.guest_exposure(profile),
            GuestExposure::Allowed
        );
    }
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&binding("sbx", "vm", 1))).unwrap();
    let reference = CredentialRef::from_digest(digest("yougori/test/vault/v1", &[b"ref"]));
    for instruction in plan.instructions() {
        let canary = registry.canary(instruction.canary()).unwrap();
        assert_eq!(
            CredentialHandle::for_class(
                reference,
                canary.secret_class(),
                ExternalCredential::LongLivedProvider
            ),
            Err(CredentialRefusal::NotAnExternalCredential {
                class: SecretClass::FakeCanary
            })
        );
        let text = instruction.value().expose_for_planting();
        let expected = Err(CredentialUseRefusal::CanaryValue {
            canary: canary.id(),
            kind: canary.kind(),
        });
        assert_eq!(registry.refuse_credential_use(text.as_bytes()), expected);
        let header = format!("Authorization: Bearer {text}");
        assert_eq!(registry.refuse_credential_use(header.as_bytes()), expected);
        assert_eq!(
            registry.refuse_credential_use(base64(header.as_bytes()).as_bytes()),
            expected
        );
    }
    registry
        .refuse_credential_use(b"ghp_unrelatedGenuineLookingValue0123456789")
        .unwrap();
}

// ---------------------------------------------------------------------------------------
// Matcher

#[test]
fn canary_values_are_recognized_by_the_provider_scan() {
    let a = binding("sbx", "vm", 1);
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&a)).unwrap();
    let credential = registry
        .canary(instruction(&plan, CanaryKind::FakeCredential).canary())
        .unwrap();
    let text = value(&plan, CanaryKind::FakeCredential);
    let scanner = KnownSecrets::new().with_canary(credential.token().unwrap());
    let body = format!("{{\"echo\":\"{}\"}}", base64(text.as_bytes()));
    assert_eq!(
        scanner.find(body.as_bytes()),
        Some((LeakSource::Canary, ScanEncoding::Base64Standard))
    );

    let clock = clock();
    let cases = [
        (text.clone().into_bytes(), ScanEncoding::Verbatim),
        (
            text.to_ascii_uppercase().into_bytes(),
            ScanEncoding::AsciiCaseInsensitive,
        ),
        (
            hex::encode_upper(text.as_bytes()).into_bytes(),
            ScanEncoding::Hexadecimal,
        ),
        (
            format!("POST /upload\r\n\r\nd={}", base64(text.as_bytes())).into_bytes(),
            ScanEncoding::Base64Standard,
        ),
    ];
    for (bytes, encoding) in cases {
        let report = registry.match_observation(&host_bytes(&a, &bytes), &clock);
        assert_eq!(report.hits.len(), 1);
        assert_eq!(
            report.hits[0].observation(),
            ObservationLabel::OutboundBytes {
                encoding,
                length: bytes.len() as u64
            }
        );
    }
}

#[test]
fn each_observation_kind_matches_its_canaries() {
    let a = binding("sbx", "vm", 1);
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&a)).unwrap();
    let clock = clock();
    let dns = value(&plan, CanaryKind::DnsName);
    let dns_id = instruction(&plan, CanaryKind::DnsName).canary();

    let exact = Observation::host_observed(
        a.clone(),
        MonotonicTime::from_nanos(77),
        ObservedContent::DnsQuery(format!("{}.", dns.to_ascii_uppercase())),
    )
    .unwrap();
    let report = registry.match_observation(&exact, &clock);
    assert_eq!(report.hits.len(), 1);
    assert_eq!(report.hits[0].canary(), dns_id);
    assert_eq!(
        report.hits[0].observation(),
        ObservationLabel::DnsQuery {
            matched: DnsMatch::Exact
        }
    );
    assert_eq!(
        report.hits[0].source(),
        ObservationSource::HostObserved {
            observed_at: MonotonicTime::from_nanos(77)
        }
    );
    assert_eq!(report.hits[0].matched_at(), clock.now());

    let sub = Observation::guest_reported(
        a.clone(),
        ObservedContent::DnsQuery(format!("data-1f.x.{dns}")),
    )
    .unwrap();
    let report = registry.match_observation(&sub, &clock);
    assert_eq!(
        report.hits[0].observation(),
        ObservationLabel::DnsQuery {
            matched: DnsMatch::Subdomain
        }
    );
    let glued =
        Observation::guest_reported(a.clone(), ObservedContent::DnsQuery(format!("evil{dns}")))
            .unwrap();
    assert!(registry.match_observation(&glued, &clock).hits.is_empty());
    let zone_only = Observation::guest_reported(
        a.clone(),
        ObservedContent::DnsQuery(CANARY_DNS_ZONE.to_owned()),
    )
    .unwrap();
    assert!(registry
        .match_observation(&zone_only, &clock)
        .hits
        .is_empty());

    let honeyport = endpoint(&registry, &plan);
    let attempt = Observation::host_observed(
        a.clone(),
        MonotonicTime::from_nanos(1),
        ObservedContent::ConnectionAttempt(honeyport),
    )
    .unwrap();
    let report = registry.match_observation(&attempt, &clock);
    assert_eq!(report.hits.len(), 1);
    assert_eq!(report.hits[0].kind(), CanaryKind::HoneyportEndpoint);
    assert_eq!(
        report.hits[0].observation(),
        ObservationLabel::ConnectionAttempt
    );
    let other_port = SocketAddr::new(
        honeyport.ip(),
        if honeyport.port() == HONEYPORT_LAST_PORT {
            HONEYPORT_FIRST_PORT
        } else {
            honeyport.port() + 1
        },
    );
    let miss = Observation::host_observed(
        a.clone(),
        MonotonicTime::from_nanos(1),
        ObservedContent::ConnectionAttempt(other_port),
    )
    .unwrap();
    assert!(registry.match_observation(&miss, &clock).hits.is_empty());
    let as_text = host_bytes(&a, honeyport.to_string().as_bytes());
    assert!(registry.match_observation(&as_text, &clock).hits.is_empty());

    let read = Observation::guest_reported(
        a.clone(),
        ObservedContent::FileRead(FileLocation::new(
            FileRoot::Workspace,
            GuestPath::new(DOCUMENT_PATH).unwrap(),
        )),
    )
    .unwrap();
    let report = registry.match_observation(&read, &clock);
    assert_eq!(report.hits.len(), 1);
    assert_eq!(report.hits[0].kind(), CanaryKind::DocumentMarker);
    assert_eq!(report.hits[0].observation(), ObservationLabel::FileRead);
    let other_file = Observation::guest_reported(
        a.clone(),
        ObservedContent::FileRead(FileLocation::new(
            FileRoot::Home,
            GuestPath::new(DOCUMENT_PATH).unwrap(),
        )),
    )
    .unwrap();
    assert!(registry
        .match_observation(&other_file, &clock)
        .hits
        .is_empty());

    let benign = host_bytes(
        &a,
        b"GET /simple/requests/ HTTP/1.1\r\nHost: pypi.org\r\n\r\n",
    );
    assert!(registry.match_observation(&benign, &clock).hits.is_empty());
}

#[test]
fn guest_reports_stay_guest_reports() {
    let a = binding("sbx", "vm", 1);
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&a)).unwrap();
    let text = value(&plan, CanaryKind::FakeCredential);
    let observation = guest_bytes(&a, text.as_bytes());
    assert_eq!(observation.source(), ObservationSource::GuestReported);
    let report = registry.match_observation(&observation, &clock());
    let hit = &report.hits[0];
    assert_eq!(hit.source(), ObservationSource::GuestReported);
    assert_eq!(hit.source_class(), SourceClass::GuestReport);
    assert!(matches!(
        hit.audit_draft(),
        AuditDraft::GuestObservation { .. }
    ));
    let json = serde_json::to_value(hit).unwrap();
    assert_eq!(
        json["source"],
        serde_json::json!({ "source": "guest_reported" })
    );

    assert_eq!(
        Observation::host_observed(
            a.clone(),
            MonotonicTime::from_nanos(1),
            ObservedContent::FileRead(FileLocation::new(
                FileRoot::Workspace,
                GuestPath::new(DOCUMENT_PATH).unwrap()
            )),
        ),
        Err(ObservationRefusal::HostCannotObserveGuestFileRead)
    );
    // A guest cannot smuggle a host label or a time into a stored source label.
    assert!(serde_json::from_str::<ObservationSource>(
        r#"{"source":"guest_reported","observed_at":5}"#
    )
    .is_err());
}

#[test]
fn canary_use_produces_the_intended_audit_event() {
    let a = binding("sbx", "vm", 4);
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&a)).unwrap();
    let text = value(&plan, CanaryKind::FakeCredential);
    let clock = clock();
    let hit = registry
        .match_observation(&guest_bytes(&a, text.as_bytes()), &clock)
        .hits
        .remove(0);
    let policy = RedactionPolicy::metadata_only().keeping_untrusted_text();
    let (mut journal, mut authority) = AuditJournal::open(
        JournalId::new("warden").unwrap(),
        ProducerId::new("relay").unwrap(),
        MemoryStore::default(),
        MemorySpool::default(),
        &clock,
        audit_config(policy),
    )
    .unwrap();
    let context = hit.event_context(OperationId::new("canary-watch").unwrap());
    let receipt = journal
        .append(&mut authority, context, hit.audit_draft())
        .unwrap();
    assert_eq!(receipt.durability, Durability::Durable);
    let records = &journal.store().records;
    assert_eq!(records.len(), 1);
    let event = records[0].event();
    assert_eq!(event.provenance().source(), SourceClass::GuestReport);
    assert_eq!(
        event.generations().sandbox_boot,
        Some(SandboxBootGeneration::new(4))
    );
    let AuditEntry::GuestObservation { fields } = event.payload() else {
        panic!("not a guest observation: {:?}", event.payload());
    };
    assert_eq!(fields.omitted_fields(), 0);
    assert!(matches!(
        fields.get("event"),
        Some(RedactedValue::Text { text, .. }) if text == "canary_hit"
    ));
    assert!(matches!(
        fields.get("meaning"),
        Some(RedactedValue::Text { text, .. }) if text == "signal_not_proof"
    ));
    let stored = serde_json::to_string(&records[0]).unwrap();
    assert!(!stored.contains(&text));
}

#[test]
fn host_observed_hits_are_filed_as_detection_signals() {
    let a = binding("sbx", "vm", 1);
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&a)).unwrap();
    let text = value(&plan, CanaryKind::DocumentMarker);
    let clock = clock();
    let hit = registry
        .match_observation(&host_bytes(&a, text.as_bytes()), &clock)
        .hits
        .remove(0);
    assert_eq!(hit.source_class(), SourceClass::HostProbe);
    assert!(matches!(
        hit.audit_draft(),
        AuditDraft::HostFact {
            fact: HostFact::DetectionSignal,
            ..
        }
    ));
    let (mut journal, mut authority) = AuditJournal::open(
        JournalId::new("warden").unwrap(),
        ProducerId::new("relay").unwrap(),
        MemoryStore::default(),
        MemorySpool::default(),
        &clock,
        audit_config(RedactionPolicy::metadata_only()),
    )
    .unwrap();
    let context = hit.event_context(OperationId::new("canary-watch").unwrap());
    let receipt = journal
        .append(&mut authority, context, hit.audit_draft())
        .unwrap();
    assert_eq!(receipt.durability, Durability::Durable);
    let records = &journal.store().records;
    assert_eq!(records.len(), 1);
    let event = records[0].event();
    assert_eq!(event.provenance().source(), SourceClass::HostProbe);
    let AuditEntry::HostFact { fact, fields } = event.payload() else {
        panic!("not a host fact: {:?}", event.payload());
    };
    assert_eq!(*fact, HostFact::DetectionSignal);
    assert!(matches!(
        fields.get("meaning"),
        Some(RedactedValue::Text { text, .. }) if text == "signal_not_proof"
    ));
    let stored = serde_json::to_string(&records[0]).unwrap();
    assert!(!stored.contains(&text));
    let fields = RedactionPolicy::metadata_only()
        .redact(hit.audit_fields())
        .unwrap();
    assert_eq!(fields.omitted_fields(), 0);
    assert_eq!(
        fields.get("value_digest"),
        Some(&RedactedValue::Digest {
            digest: hit.value_digest()
        })
    );
    assert_eq!(
        fields.get("observed_at_ns"),
        Some(&RedactedValue::Unsigned {
            value: 4_000_000_000
        })
    );
}

#[test]
fn hits_carry_no_value_and_no_guest_content() {
    let a = binding("sbx", "vm", 1);
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&a)).unwrap();
    let clock = clock();
    for kind in [
        CanaryKind::FakeCredential,
        CanaryKind::DocumentMarker,
        CanaryKind::DnsName,
    ] {
        let text = value(&plan, kind);
        let payload = format!("PRIVATE-GUEST-PROSE {text} MORE-PRIVATE-PROSE");
        let observation = guest_bytes(&a, payload.as_bytes());
        let report = registry.match_observation(&observation, &clock);
        assert_eq!(report.hits.len(), 1);
        let json = serde_json::to_string(&report.hits[0]).unwrap();
        let debug = format!(
            "{report:?} {observation:?} {registry:?} {plan:?} {:?}",
            report.hits[0].audit_fields()
        );
        let marker = text.rsplit(['_', '-']).next().unwrap().to_owned();
        let label = text.split('.').next().unwrap().to_owned();
        for shown in [&json, &debug] {
            assert!(!shown.contains(&text), "{kind}: value in clear");
            assert!(
                !shown.contains(&marker) && !shown.contains(&label),
                "{kind}: marker"
            );
            assert!(
                !shown.contains("PRIVATE-GUEST-PROSE"),
                "{kind}: guest content"
            );
        }
    }
    let summary = serde_json::to_string(&plan.summary()).unwrap();
    for instruction in plan.instructions() {
        assert!(!summary.contains(instruction.value().expose_for_planting()));
    }
}

#[test]
fn hit_events_are_bounded() {
    let long = |prefix: &str| format!("{prefix}{}", "x".repeat(128 - prefix.len()));
    let planted = SandboxBinding {
        sandbox: SandboxRef {
            issuer: IssuerId::new(digest("yougori/test/issuer/v1", &[b"h"])),
            execution: ExecutionId::new(long("p")).unwrap(),
        },
        instance: instance("planted"),
        boot: SandboxBootGeneration::new(u64::MAX - 1),
    };
    let observed = SandboxBinding {
        sandbox: SandboxRef {
            issuer: IssuerId::new(digest("yougori/test/issuer/v1", &[b"h"])),
            execution: ExecutionId::new(long("o")).unwrap(),
        },
        instance: instance("observed"),
        boot: SandboxBootGeneration::new(u64::MAX),
    };
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&planted)).unwrap();
    registry
        .plan(restored(&observed, snapshot("s"), &planted))
        .unwrap();
    let corpus = calibration_corpus(&registry, &plan, &planted);
    let record = calibrate(&registry, &planted, &corpus, &clock()).unwrap();
    registry.attach_calibration(&planted, &record).unwrap();
    let text = value(&plan, CanaryKind::FakeCredential);
    let observation = Observation::host_observed(
        observed.clone(),
        MonotonicTime::from_nanos(u64::MAX),
        ObservedContent::OutboundBytes(base64(text.as_bytes()).into_bytes()),
    )
    .unwrap();
    let late = ManualClock::new(MonotonicTime::from_nanos(u64::MAX));
    let hit = registry
        .match_observation(&observation, &late)
        .hits
        .remove(0);
    assert!(matches!(
        hit.attribution(),
        Attribution::CarriedBySnapshot { .. }
    ));
    assert!(hit.calibration().is_some());
    let json = serde_json::to_vec(&hit).unwrap();
    assert!(
        json.len() <= MAX_CANARY_HIT_JSON_BYTES,
        "{} bytes",
        json.len()
    );
    let fields = hit.audit_fields();
    assert!(fields.len() <= RedactionPolicy::DEFAULT_MAX_FIELDS);
    assert_eq!(
        RedactionPolicy::default()
            .redact(fields)
            .unwrap()
            .omitted_fields(),
        0
    );
}

#[test]
fn hits_per_observation_and_observation_sizes_are_bounded() {
    let mut registry = registry(1);
    let mut buffer = Vec::new();
    for n in 0..3 {
        let mut request = fresh(&binding("sbx", &format!("vm-{n}"), 1));
        request.placements = (0..16)
            .map(|i| {
                placement(
                    CanaryKind::FakeCredential,
                    PlacementLocation::workspace(&format!("keys/k{i}.txt")).unwrap(),
                )
            })
            .collect();
        let plan = registry.plan(request).unwrap();
        for instruction in plan.instructions() {
            buffer.extend_from_slice(instruction.value().expose_for_planting().as_bytes());
            buffer.push(b' ');
        }
    }
    let report =
        registry.match_observation(&host_bytes(&binding("sbx", "vm-0", 1), &buffer), &clock());
    assert_eq!(report.hits.len(), MAX_HITS_PER_OBSERVATION);
    assert_eq!(report.omitted_hits, 16);
    assert_eq!(report.total_hits(), 48);

    let origin = binding("sbx", "vm-0", 1);
    assert_eq!(
        Observation::guest_reported(
            origin.clone(),
            ObservedContent::OutboundBytes(vec![b'a'; MAX_OBSERVATION_BYTES + 1])
        ),
        Err(ObservationRefusal::TooLarge {
            bytes: (MAX_OBSERVATION_BYTES + 1) as u64,
            max: MAX_OBSERVATION_BYTES as u64
        })
    );
    Observation::guest_reported(
        origin.clone(),
        ObservedContent::OutboundBytes(vec![b'a'; MAX_OBSERVATION_BYTES]),
    )
    .unwrap();
    let long_label = format!("{}.internal", "a".repeat(64));
    let long_name = vec!["abcdefg"; 32].join(".");
    for name in [
        "",
        ".",
        "a..b",
        "caf\u{e9}.internal",
        "a b.internal",
        &long_label,
        &long_name,
    ] {
        assert_eq!(
            Observation::guest_reported(origin.clone(), ObservedContent::DnsQuery(name.to_owned())),
            Err(ObservationRefusal::MalformedDnsName),
            "{name:?}"
        );
    }
}

#[test]
fn a_hit_is_a_signal_and_carries_no_verdict() {
    let a = binding("sbx", "vm", 1);
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&a)).unwrap();
    let text = value(&plan, CanaryKind::FakeCredential);
    let hit = registry
        .match_observation(&host_bytes(&a, text.as_bytes()), &clock())
        .hits
        .remove(0);
    assert_eq!(hit.meaning(), HitMeaning::SignalNotProof);
    let json = serde_json::to_value(&hit).unwrap();
    assert_eq!(json["meaning"], "signal_not_proof");
    let mut keys = Vec::new();
    let mut has_float = false;
    walk_json(&json, &mut keys, &mut has_float);
    assert!(!has_float);
    for key in &keys {
        for word in [
            "verdict",
            "malicious",
            "score",
            "severity",
            "probability",
            "confidence",
        ] {
            assert!(!key.contains(word), "{key}");
        }
    }
    let back: CanaryHit = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(back, hit);
    let mut with_verdict = json.clone();
    with_verdict["verdict"] = serde_json::json!("malicious");
    assert!(serde_json::from_value::<CanaryHit>(with_verdict).is_err());
    let mut as_proof = json;
    as_proof["meaning"] = serde_json::json!("proof");
    assert!(serde_json::from_value::<CanaryHit>(as_proof).is_err());
}

#[test]
fn a_stored_hit_cannot_claim_what_the_matcher_never_reports() {
    let a = binding("sbx", "vm", 1);
    let mut registry = registry(1);
    registry.plan(fresh(&a)).unwrap();
    let read = Observation::guest_reported(
        a.clone(),
        ObservedContent::FileRead(FileLocation::new(
            FileRoot::Workspace,
            GuestPath::new(DOCUMENT_PATH).unwrap(),
        )),
    )
    .unwrap();
    let hit = registry.match_observation(&read, &clock()).hits.remove(0);
    let json = serde_json::to_value(&hit).unwrap();
    assert_eq!(
        serde_json::from_value::<CanaryHit>(json.clone()).unwrap(),
        hit
    );
    let mut upgraded = json.clone();
    upgraded["source"] = serde_json::json!({"source": "host_observed", "observed_at": 1});
    assert!(serde_json::from_value::<CanaryHit>(upgraded).is_err());
    let mut elsewhere = json.clone();
    elsewhere["attribution"] = serde_json::json!({"attribution": "planted_elsewhere"});
    assert!(serde_json::from_value::<CanaryHit>(elsewhere).is_err());
    let mut moved = json.clone();
    moved["observed_in"] = serde_json::to_value(binding("sbx", "vm-other", 1)).unwrap();
    assert!(serde_json::from_value::<CanaryHit>(moved).is_err());
    let mut wrong_kind = json.clone();
    wrong_kind["observation"] = serde_json::json!({"observation": "connection_attempt"});
    assert!(serde_json::from_value::<CanaryHit>(wrong_kind).is_err());
    let mut dns_on_document = json;
    dns_on_document["observation"] =
        serde_json::json!({"observation": "dns_query", "matched": "exact"});
    assert!(serde_json::from_value::<CanaryHit>(dns_on_document).is_err());
}

#[test]
fn strict_enums_refuse_unknown_fields() {
    for (text, ok) in [
        (r#"{"attribution":"planted_here"}"#, true),
        (r#"{"attribution":"planted_here","extra":1}"#, false),
    ] {
        assert_eq!(
            serde_json::from_str::<Attribution>(text).is_ok(),
            ok,
            "{text}"
        );
    }
    assert!(serde_json::from_str::<PlantOrigin>(r#"{"origin":"fresh_boot"}"#).is_ok());
    assert!(serde_json::from_str::<PlantOrigin>(r#"{"origin":"fresh_boot","x":1}"#).is_err());
    assert!(serde_json::from_str::<ObservationLabel>(
        r#"{"observation":"connection_attempt","port":5}"#
    )
    .is_err());
    assert!(serde_json::from_str::<PlacementLocation>(
        r#"{"location":"environment_variable","name":"A","extra":1}"#
    )
    .is_err());
    assert!(serde_json::from_str::<PlanRefusal>(r#"{"refusal":"empty","x":1}"#).is_err());
}

#[test]
fn without_a_plan_nothing_matches() {
    let registry = registry(1);
    assert!(registry.is_empty());
    let report = registry.match_observation(
        &host_bytes(
            &binding("sbx", "vm", 1),
            b"ygcf1_0000000000000000000000000000000000000000000000000000000000000000",
        ),
        &clock(),
    );
    assert_eq!(report, MatchReport::default());
}

// ---------------------------------------------------------------------------------------
// Calibration

fn calibration_corpus(
    registry: &CanaryRegistry,
    plan: &PlantingPlan,
    target: &SandboxBinding,
) -> Vec<CalibrationSample> {
    let tool = |name: &str| SampleLabel::BenignTooling {
        tool: SampleName::new(name).unwrap(),
    };
    let fixture = |name: &str| SampleLabel::AdversarialFixture {
        fixture: SampleName::new(name).unwrap(),
    };
    let at = MonotonicTime::from_nanos(10);
    let host = |content| Observation::host_observed(target.clone(), at, content).unwrap();
    let guest = |content| Observation::guest_reported(target.clone(), content).unwrap();
    let credential = value(plan, CanaryKind::FakeCredential);
    let document = value(plan, CanaryKind::DocumentMarker);
    let dns = value(plan, CanaryKind::DnsName);
    vec![
        CalibrationSample {
            label: tool("ide-indexer"),
            observations: vec![
                guest(ObservedContent::FileRead(FileLocation::new(
                    FileRoot::Workspace,
                    GuestPath::new(DOCUMENT_PATH).unwrap(),
                ))),
                guest(ObservedContent::FileRead(FileLocation::new(
                    FileRoot::Workspace,
                    GuestPath::new("src/main.rs").unwrap(),
                ))),
            ],
        },
        CalibrationSample {
            label: tool("aws-cli-discovery"),
            observations: vec![host(ObservedContent::OutboundBytes(
                b"GET / HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n".to_vec(),
            ))],
        },
        CalibrationSample {
            label: tool("pip-install"),
            observations: vec![host(ObservedContent::DnsQuery("pypi.org".to_owned()))],
        },
        CalibrationSample {
            label: tool("git-fetch"),
            observations: vec![host(ObservedContent::ConnectionAttempt(
                "140.82.112.3:443".parse().unwrap(),
            ))],
        },
        CalibrationSample {
            label: fixture("exfil-base64-post"),
            observations: vec![host(ObservedContent::OutboundBytes(
                format!("POST /c HTTP/1.1\r\n\r\n{}", base64(credential.as_bytes())).into_bytes(),
            ))],
        },
        CalibrationSample {
            label: fixture("dns-beacon"),
            observations: vec![host(ObservedContent::DnsQuery(format!("chunk1.{dns}")))],
        },
        CalibrationSample {
            label: fixture("honeyport-probe"),
            observations: vec![host(ObservedContent::ConnectionAttempt(endpoint(
                registry, plan,
            )))],
        },
        CalibrationSample {
            label: fixture("document-exfil"),
            observations: vec![host(ObservedContent::OutboundBytes(
                hex::encode_upper(document.as_bytes()).into_bytes(),
            ))],
        },
    ]
}

#[test]
fn calibration_counts_benign_false_positives_and_adversarial_detections() {
    let target = binding("calibration", "vm-cal", 1);
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&target)).unwrap();
    let corpus = calibration_corpus(&registry, &plan, &target);
    let record = calibrate(&registry, &target, &corpus, &clock()).unwrap();
    assert_eq!(record.meaning, CalibrationMeaning::CountsOnThisCorpusOnly);
    assert_eq!(record.profile, plan.profile());
    assert_eq!(
        record.benign_tooling,
        SampleCounts {
            samples: 4,
            samples_with_hits: 1,
            hits: 1
        }
    );
    assert_eq!(
        record.adversarial_fixtures,
        SampleCounts {
            samples: 4,
            samples_with_hits: 4,
            hits: 4
        }
    );
    assert_eq!(
        record.false_positives(),
        Counted {
            count: 1,
            sample_size: 4
        }
    );
    assert_eq!(
        record.detections(),
        Counted {
            count: 4,
            sample_size: 4
        }
    );
    let expected = [
        (CanaryKind::FakeCredential, 0, 1),
        (CanaryKind::DocumentMarker, 1, 1),
        (CanaryKind::DnsName, 0, 1),
        (CanaryKind::HoneyportEndpoint, 0, 1),
    ];
    assert_eq!(record.by_kind.len(), 4);
    for (entry, (kind, benign, adversarial)) in record.by_kind.iter().zip(expected) {
        assert_eq!(
            (entry.kind, entry.benign_hits, entry.adversarial_hits),
            (kind, benign, adversarial)
        );
    }
    assert_eq!(
        record.benign_tools_with_hits,
        vec![SampleName::new("ide-indexer").unwrap()]
    );
    assert_eq!(record.benign_tools_omitted, 0);
    let summary = record.summary();
    assert!(summary.contains("benign tooling: 1 of 4 samples"));
    assert!(summary.contains("adversarial fixtures: 4 of 4 samples"));
    assert!(summary.contains("not a detection probability, a score or a guarantee"));

    // Same corpus, same record and identity; a changed corpus changes both.
    let again = calibrate(&registry, &target, &corpus, &clock()).unwrap();
    assert_eq!(again.id(), record.id());
    let shorter = &corpus[1..];
    let other = calibrate(&registry, &target, shorter, &clock()).unwrap();
    assert_ne!(other.corpus, record.corpus);
    assert_ne!(other.id(), record.id());
}

#[test]
fn calibration_exposes_no_probability_score_or_guarantee() {
    let target = binding("calibration", "vm-cal", 1);
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&target)).unwrap();
    let corpus = calibration_corpus(&registry, &plan, &target);
    let record = calibrate(&registry, &target, &corpus, &clock()).unwrap();
    let json = serde_json::to_value(&record).unwrap();
    let mut keys = Vec::new();
    let mut has_float = false;
    walk_json(&json, &mut keys, &mut has_float);
    assert!(!has_float, "a non-integer number in {json}");
    for key in &keys {
        for word in [
            "prob",
            "score",
            "rate",
            "guarantee",
            "confidence",
            "likelihood",
            "precision",
            "recall",
        ] {
            assert!(!key.contains(word), "{key}");
        }
    }
    let back: CalibrationRecord = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(back, record);
    let mut claimed = json.clone();
    claimed["detection_probability"] = serde_json::json!(0.99);
    assert!(serde_json::from_value::<CalibrationRecord>(claimed).is_err());
    let mut guaranteed = json.clone();
    guaranteed["meaning"] = serde_json::json!("guaranteed_detector");
    assert!(serde_json::from_value::<CalibrationRecord>(guaranteed).is_err());
    let mut rated = json.clone();
    rated["benign_tooling"]["rate"] = serde_json::json!(0.25);
    assert!(serde_json::from_value::<CalibrationRecord>(rated).is_err());
    let mut doubled = json.clone();
    doubled["by_kind"][1]["kind"] = serde_json::json!("fake_credential");
    assert!(serde_json::from_value::<CalibrationRecord>(doubled).is_err());
    let mut inflated = json.clone();
    inflated["adversarial_fixtures"]["hits"] = serde_json::json!(40);
    assert!(serde_json::from_value::<CalibrationRecord>(inflated).is_err());
    let mut extra_tool = json.clone();
    extra_tool["benign_tools_omitted"] = serde_json::json!(1);
    assert!(serde_json::from_value::<CalibrationRecord>(extra_tool).is_err());
    for counts in [
        serde_json::json!({"samples": 2, "samples_with_hits": 3, "hits": 3}),
        serde_json::json!({"samples": 2, "samples_with_hits": 2, "hits": 1}),
        serde_json::json!({"samples": 2, "samples_with_hits": 0, "hits": 1}),
    ] {
        assert!(serde_json::from_value::<SampleCounts>(counts).is_err());
    }
}

#[test]
fn calibration_refuses_unmeasured_or_foreign_corpora() {
    let target = binding("calibration", "vm-cal", 1);
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&target)).unwrap();
    let corpus = calibration_corpus(&registry, &plan, &target);
    let clock = clock();
    assert_eq!(
        calibrate(&registry, &binding("nobody", "vm", 1), &corpus, &clock),
        Err(CalibrationRefusal::NoPlan)
    );
    assert_eq!(
        calibrate(&registry, &target, &corpus[..4], &clock),
        Err(CalibrationRefusal::NoAdversarialSamples)
    );
    assert_eq!(
        calibrate(&registry, &target, &corpus[4..], &clock),
        Err(CalibrationRefusal::NoBenignSamples)
    );
    assert_eq!(
        calibrate(&registry, &target, &[], &clock),
        Err(CalibrationRefusal::NoBenignSamples)
    );
    let mut empty = corpus.clone();
    empty[0].observations.clear();
    assert_eq!(
        calibrate(&registry, &target, &empty, &clock),
        Err(CalibrationRefusal::EmptySample)
    );
    let mut foreign = corpus.clone();
    foreign[1].observations = vec![host_bytes(&binding("other", "vm", 1), b"benign")];
    assert_eq!(
        calibrate(&registry, &target, &foreign, &clock),
        Err(CalibrationRefusal::ForeignObservation)
    );
    let elsewhere = registry.plan(fresh(&binding("other", "vm", 1))).unwrap();
    let mut outside = corpus.clone();
    outside[1].observations = vec![host_bytes(
        &target,
        value(&elsewhere, CanaryKind::FakeCredential).as_bytes(),
    )];
    assert_eq!(
        calibrate(&registry, &target, &outside, &clock),
        Err(CalibrationRefusal::HitOutsidePlan)
    );
    let too_many: Vec<CalibrationSample> = corpus
        .iter()
        .cycle()
        .take(MAX_CALIBRATION_SAMPLES + 1)
        .cloned()
        .collect();
    assert_eq!(
        calibrate(&registry, &target, &too_many, &clock),
        Err(CalibrationRefusal::TooManySamples { max: 4_096 })
    );
}

#[test]
fn calibrated_response_marks_hits_with_their_calibration() {
    let calibration_binding = binding("calibration", "vm-cal", 1);
    let production = binding("prod", "vm-prod", 1);
    let differing = binding("prod-2", "vm-prod-2", 1);
    let mut registry = registry(1);
    let calibration_plan = registry.plan(fresh(&calibration_binding)).unwrap();
    let mut reordered = fresh(&production);
    reordered.placements.reverse();
    let production_plan = registry.plan(reordered).unwrap();
    let mut smaller = fresh(&differing);
    smaller.placements.truncate(2);
    registry.plan(smaller).unwrap();
    assert_eq!(calibration_plan.profile(), production_plan.profile());
    let corpus = calibration_corpus(&registry, &calibration_plan, &calibration_binding);
    let record = calibrate(&registry, &calibration_binding, &corpus, &clock()).unwrap();

    let text = value(&production_plan, CanaryKind::FakeCredential);
    let before = registry.match_observation(&host_bytes(&production, text.as_bytes()), &clock());
    assert_eq!(before.hits[0].calibration(), None);
    registry.attach_calibration(&production, &record).unwrap();
    let after = registry.match_observation(&host_bytes(&production, text.as_bytes()), &clock());
    assert_eq!(after.hits[0].calibration(), Some(record.id()));
    assert_eq!(
        registry.attach_calibration(&differing, &record),
        Err(CalibrationMismatch::ProfileDiffers)
    );
    assert_eq!(
        registry.attach_calibration(&binding("none", "vm", 1), &record),
        Err(CalibrationMismatch::NoPlan)
    );
}

// ---------------------------------------------------------------------------------------
// Bounds, summaries and the absence of external paths

#[test]
fn registry_capacity_and_value_space_are_bounded() {
    let mut small = registry(1).with_capacity(6);
    small.plan(fresh(&binding("sbx", "vm-1", 1))).unwrap();
    assert_eq!(
        small.plan(fresh(&binding("sbx", "vm-2", 1))),
        Err(PlanRefusal::RegistryFull { max: 6 })
    );
    assert_eq!(small.len(), 4);
    let clamped = registry(1).with_capacity(usize::MAX);
    assert!(format!("{clamped:?}").contains("canaries: 0"));

    let one_address =
        HoneyportPool::new(vec![IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9))], &host_state()).unwrap();
    let mut registry = CanaryRegistry::new(&seed(3), one_address);
    let mut endpoints = BTreeSet::new();
    let mut refusal = None;
    for n in 0..2_000 {
        let mut request = fresh(&binding("sbx", &format!("vm-{n}"), 1));
        request.placements = (0..16)
            .map(|i| {
                placement(
                    CanaryKind::HoneyportEndpoint,
                    PlacementLocation::workspace(&format!("cfg/h{i}.yaml")).unwrap(),
                )
            })
            .collect();
        match registry.plan(request) {
            Ok(plan) => {
                for instruction in plan.instructions() {
                    let socket = registry
                        .canary(instruction.canary())
                        .unwrap()
                        .endpoint()
                        .unwrap();
                    assert!(endpoints.insert(socket), "endpoint issued twice");
                }
            }
            Err(error) => {
                refusal = Some(error);
                break;
            }
        }
    }
    assert_eq!(
        refusal,
        Some(PlanRefusal::ValueSpaceExhausted {
            kind: CanaryKind::HoneyportEndpoint
        })
    );
    assert!(endpoints.len() <= usize::from(HONEYPORT_LAST_PORT - HONEYPORT_FIRST_PORT) + 1);
    assert_eq!(registry.len(), endpoints.len());
}

#[test]
fn plan_summaries_hold_digests_not_values() {
    let a = binding("sbx", "vm", 1);
    let mut registry = registry(1);
    let plan = registry.plan(fresh(&a)).unwrap();
    let summary = plan.summary();
    assert_eq!(registry.plan_summary(&a), Some(summary.clone()));
    assert_eq!(registry.plan_summary(&binding("x", "y", 1)), None);
    for (entry, instruction) in summary.entries.iter().zip(plan.instructions()) {
        assert_eq!(entry.value_digest, instruction.value().digest());
        assert_eq!(&entry.location, instruction.location());
    }
    let json = serde_json::to_string(&summary).unwrap();
    let back: PlanSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, summary);
    assert_eq!(back.digest(), summary.digest());
    let mut changed = summary.clone();
    changed.entries[0].kind = CanaryKind::DnsName;
    assert_ne!(changed.digest(), summary.digest());
    let mut moved = summary.clone();
    moved.origin = PlantOrigin::RestoredFrom {
        snapshot: snapshot("s"),
        source: binding("sbx", "vm", 0),
    };
    assert_ne!(moved.digest(), summary.digest());
    assert!(serde_json::from_str::<PlanSummary>(
        &json.replace("\"entries\"", "\"values\":[],\"entries\"")
    )
    .is_err());
    assert_eq!(ProfileDigest::of(&full_placements()), plan.profile());
}

#[test]
fn no_external_notification_path_exists_in_the_module() {
    let sources = [
        include_str!("mod.rs"),
        include_str!("calibration.rs"),
        include_str!("canary.rs"),
        include_str!("generator.rs"),
        include_str!("hit.rs"),
        include_str!("observe.rs"),
        include_str!("placement.rs"),
        include_str!("registry.rs"),
        include_str!("tests.rs"),
    ];
    let forbidden: Vec<String> = [
        ["Tcp", "Stream"],
        ["Tcp", "Listener"],
        ["Udp", "Socket"],
        ["http", "://"],
        ["https", "://"],
        ["web", "hook"],
        ["std::", "process"],
        ["std::", "fs"],
        ["to_socket", "_addrs"],
        ["lookup", "_host"],
        ["Command", "::new"],
        ["smtp", "."],
        ["mailto", ":"],
        ["notify", "("],
        ["reqw", "est"],
    ]
    .iter()
    .map(|parts| parts.concat())
    .collect();
    for source in sources {
        for token in &forbidden {
            assert!(!source.contains(token.as_str()), "found {token}");
        }
    }
    // The only outputs are values for planting, events and calibration records.
    assert!(CANARY_DNS_ZONE.ends_with(".internal"));
}
