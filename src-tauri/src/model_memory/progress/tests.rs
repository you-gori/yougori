//! Tests of the §3.10 rules (docs/combined-gpu-memory-and-vm-sandbox-plan.md lines
//! 646–655), at least one per rule of the P08 brief (rollout plan §15). They run on the
//! committed CORE-06 event hub and reconciler, CORE-04 coordinator, CORE-03 ledger and
//! CORE-02 catalog, with fakes only for the VM backend, the loader and a scripted
//! catalog.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use super::fakes::{
    idle_host, lease_terms, model, owner, session, FakeCatalog, FakeLoader, SandboxHost, SeededRng,
};
use super::*;
use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, Catalog, CatalogConfig, Checkpoint, ContentDescriptor,
    ExtentDigest, ExtentEntry, ImportManifest, ImportProgress, ImportRequest, ImportSource,
    ImportStage, ImportStart, ImportStatus, IntegrityFailure, ObjectBytes, ObjectId,
    ObjectMetadata, ObjectRole, ObjectStatus, PublisherId, Scope, SourceError, SourceIdentity,
    TrustClaim, TrustPolicy, Uninterrupted, VerifierRegistry, VerifierRejection,
};
use crate::foundation::coordination::{
    GpuAllocationHandle, LeaseKind, LeaseRefusal, RecoveryReport as CoordinatorRecovery,
};
use crate::foundation::events::{
    Arrival, CancellationBoundary, DataSource, EventEnvelope, EventHub, EventSequence, Generations,
    HubConfig, LossReason, MetricsConfig, MetricsTotals, Phase, Polling, ProducerId,
    ProducerIncarnation, ProgressBatch, ProgressConfig, ProgressError, ProgressSnapshot,
    ProgressUpdate, QueueReason, ReconcileConfig, Reconciler, Resolution, ResourceKind,
    RevocationConfig, StreamKind, TrackedResourceId,
};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{
    digest, Clock, ContentKey, ExecutionId, Incarnation, ManualClock, MonotonicTime, OperationId,
    TenantId,
};
use crate::foundation::report::{ClockId, EventName, IntervalKind, Label, NotMeasuredReason};

const MB: u64 = 1_000_000;
const GB: u64 = 1_000_000_000;

type Hub = EventHub<Arc<ManualClock>>;
type Publisher = ProgressPublisher<Arc<ManualClock>>;
type Event = EventEnvelope<ProgressUpdate>;

fn op(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

fn new_clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(MonotonicTime::ZERO))
}

fn clock_id() -> ClockId {
    ClockId::new(Label::new("host-monotonic").unwrap())
}

fn weights(name: &str) -> TrackedResourceId {
    TrackedResourceId::new(digest("yougori/test/weights/v1", &[name.as_bytes()]))
}

/// The engine's event plane after a start under `first_incarnation`, with room for
/// `max_tracked` progress states.
fn hub_with(clock: &Arc<ManualClock>, first_incarnation: u64, max_tracked: usize) -> Hub {
    EventHub::new(
        clock.clone(),
        HubConfig {
            metrics: MetricsConfig {
                capacity_events: 16,
                sample_above_events: 16,
                keep_one_in: NonZeroU32::MIN,
                retention: Duration::from_secs(60),
                max_series: 4,
            },
            progress: ProgressConfig {
                max_tracked,
                terminal_retention: Duration::from_secs(3_600),
            },
            revocation: RevocationConfig {
                max_pending_executions: 4,
            },
            first_incarnation: ProducerIncarnation::new(first_incarnation).unwrap(),
        },
    )
    .unwrap()
}

fn producer_id() -> ProducerId {
    ProducerId::new("model-memory").unwrap()
}

/// This module's progress producer, registered on `hub` for the start under
/// `incarnation`.
fn publisher_on(hub: &mut Hub, clock: &Arc<ManualClock>, incarnation: u64) -> Publisher {
    let producer = hub
        .register_progress(producer_id(), SourceClass::HostProbe, None)
        .unwrap();
    ProgressPublisher::new(
        producer,
        Incarnation::new(incarnation),
        clock.clone(),
        clock_id(),
        PublishPolicy::default(),
    )
    .unwrap()
}

/// A daemon's first start: its hub and publisher under incarnation 1.
fn daemon(clock: &Arc<ManualClock>) -> (Hub, Publisher) {
    let mut hub = hub_with(clock, 1, 512);
    let publisher = publisher_on(&mut hub, clock, 1);
    (hub, publisher)
}

fn queued_for_gpu(needed_bytes: u64) -> Stage {
    Stage::queued(QueueReason::GpuMemory { needed_bytes })
}

fn from_local_storage() -> Stage {
    Stage::from_source(Phase::Restoring, DataSource::LocalStorage)
}

fn request(resource: TrackedResourceId, total_bytes: u64, stage: Stage) -> TrackRequest {
    TrackRequest {
        resource,
        kind: ResourceKind::Weights,
        total_bytes,
        stage,
    }
}

fn generations_of(handle: &GpuAllocationHandle) -> Generations {
    Generations::NONE
        .with_model_activation(handle.generations.activation)
        .with_gpu_allocation(handle.generations.gpu_allocation)
}

fn position(event: &Event) -> (ProducerIncarnation, EventSequence) {
    (event.provenance().incarnation(), event.sequence())
}

/// A client of the progress stream over a link that numbers its deliveries and can lose,
/// repeat or reorder them. CORE-06's reconciler drops repeats and finds gaps, and the
/// latest state of each operation wins. A delivery's resolved marks are applied only
/// while every earlier delivery arrived: after a loss they could also cover states the
/// link lost, so those gaps stay open until a snapshot answers a poll.
struct Receiver {
    reconciler: Reconciler,
    states: BTreeMap<OperationId, Event>,
    /// The number of the next delivery whose resolved marks may be applied.
    next_delivery: usize,
}

impl Receiver {
    fn new() -> Self {
        Self {
            reconciler: Reconciler::new(ReconcileConfig {
                max_streams: 4,
                window_sequences: 1_000_000,
                max_polls: 3,
                poll_interval: Duration::from_secs(2),
            })
            .unwrap(),
            states: BTreeMap::new(),
            next_delivery: 0,
        }
    }

    fn receive(&mut self, event: &Event) -> Arrival {
        let arrival = self.reconciler.observe_event(event).unwrap().arrival;
        if arrival.is_new() {
            self.keep(event);
        }
        arrival
    }

    fn keep(&mut self, event: &Event) {
        let newer = self
            .position(event.operation())
            .map_or(true, |stored| position(event) > stored);
        if newer {
            self.states.insert(event.operation().clone(), event.clone());
        }
    }

    /// Delivery `number` of the link.
    fn deliver(&mut self, number: usize, batch: &ProgressBatch) -> Vec<Arrival> {
        let arrivals = batch
            .updates
            .iter()
            .map(|update| self.receive(update))
            .collect();
        if number == self.next_delivery {
            for resolved in &batch.resolved {
                self.reconciler
                    .resolve_through(resolved, Resolution::Superseded)
                    .unwrap();
            }
            self.next_delivery += 1;
        }
        arrivals
    }

    /// A snapshot taken after the link sent `deliveries` deliveries.
    fn apply_snapshot(&mut self, snapshot: &ProgressSnapshot, deliveries: usize) {
        for state in &snapshot.states {
            self.reconciler.observe_event(state).unwrap();
            self.keep(state);
        }
        for resolved in &snapshot.resolved {
            self.reconciler
                .resolve_through(resolved, Resolution::Superseded)
                .unwrap();
        }
        self.next_delivery = self.next_delivery.max(deliveries);
    }

    fn position(&self, operation: &OperationId) -> Option<(ProducerIncarnation, EventSequence)> {
        self.states.get(operation).map(position)
    }

    fn state(&self, operation: &OperationId) -> Option<(Phase, ProgressUpdate)> {
        self.states
            .get(operation)
            .map(|event| (event.phase(), *event.payload()))
    }

    fn public(&self, operation: &OperationId) -> Option<PublicProgress> {
        self.states.get(operation).map(PublicProgress::from_event)
    }
}

/// A link that numbers the hub's deliveries.
#[derive(Default)]
struct Link {
    sent: usize,
}

impl Link {
    fn drain(&mut self, hub: &mut Hub) -> (usize, ProgressBatch) {
        let number = self.sent;
        self.sent += 1;
        (number, hub.drain(0).progress)
    }
}

fn intent(name: &str, kind: JobKind, total_bytes: u64) -> JobIntent {
    JobIntent {
        operation: op(name),
        execution: ExecutionId::new("exe-1").unwrap(),
        tenant: TenantId::new("tenant-1").unwrap(),
        kind,
        class: ArtifactClass::ModelWeights,
        content: ContentKey::of(name.as_bytes()),
        total_bytes,
    }
}

fn extent(index: u32, offset_bytes: u64, length_bytes: u64) -> VerifiedExtent {
    VerifiedExtent {
        extent: index,
        entry: ExtentEntry {
            offset_bytes,
            length_bytes,
            digest: ExtentDigest::of(&index.to_be_bytes()),
        },
    }
}

fn commit_of(intent: &JobIntent) -> ArtifactCommit {
    ArtifactCommit {
        object: intent.object(),
        total_bytes: intent.total_bytes,
    }
}

/// Every object key in `value`, at any depth.
fn keys(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                found.push(key.clone());
                keys(inner, found);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| keys(item, found)),
        _ => {}
    }
}

/// Every string value in `value`, at any depth.
fn texts(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::String(text) => found.push(text.clone()),
        Value::Object(map) => map.values().for_each(|inner| texts(inner, found)),
        Value::Array(items) => items.iter().for_each(|item| texts(item, found)),
        _ => {}
    }
}

fn is_tag(text: &str) -> bool {
    !text.is_empty() && text.chars().all(|c| c.is_ascii_lowercase() || c == '_')
}

fn is_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn journal_path(dir: &Path) -> std::path::PathBuf {
    dir.join(JOURNAL_FILE_NAME)
}

/// Appends a well-formed line, checksum included, as a writer outside this module might.
fn append_line(dir: &Path, line: &Value) {
    let json = serde_json::to_string(line).unwrap();
    let check = digest(
        "yougori/model-memory/progress/journal-line/v1",
        &[json.as_bytes()],
    );
    let mut file = OpenOptions::new()
        .append(true)
        .open(journal_path(dir))
        .unwrap();
    writeln!(file, "{} {json}", check.to_hex()).unwrap();
}

fn line_count(dir: &Path) -> u64 {
    std::fs::read_to_string(journal_path(dir))
        .unwrap()
        .lines()
        .count() as u64
}

/// A start under `incarnation` on a host whose coordinator restarted with nothing to
/// recover, so it runs on a clock session of its own.
fn try_start<K: CatalogObjects>(
    dir: &Path,
    incarnation: u64,
    catalog: &K,
    loader: &mut FakeLoader,
) -> Result<(JobControl, RecoveryReport), RecoveryError> {
    let host = idle_host(&new_clock(), session(1_000 + u128::from(incarnation)));
    JobControl::start(
        dir,
        Incarnation::new(incarnation),
        catalog,
        &host,
        &CoordinatorRecovery::default(),
        loader,
    )
}

fn start<K: CatalogObjects>(
    dir: &Path,
    incarnation: u64,
    catalog: &K,
    loader: &mut FakeLoader,
) -> (JobControl, RecoveryReport) {
    try_start(dir, incarnation, catalog, loader).unwrap()
}

// Rule 1: the event fields of line 648.

#[test]
fn every_line_648_field_is_on_a_published_event() {
    let clock = new_clock();
    let mut sandbox = SandboxHost::launch(&clock);
    let handle = sandbox.activate(model("chat"));
    let (mut hub, mut publisher) = daemon(&clock);
    let operation = op("op-load-1");
    publisher
        .track(
            &mut hub,
            &operation,
            request(weights("m"), 1000 * MB, queued_for_gpu(4 * GB)),
        )
        .unwrap();
    let first = hub.drain(0).progress.updates;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].phase(), Phase::Queued);
    assert_eq!(
        first[0].payload().queue_reason(),
        Some(QueueReason::GpuMemory {
            needed_bytes: 4 * GB
        })
    );
    assert_eq!(
        first[0].payload().cancellation(),
        CancellationBoundary::Anytime
    );
    assert_eq!(first[0].payload().eta(), None);

    publisher
        .set_allocation(&mut hub, &sandbox.host, &operation, &handle)
        .unwrap();
    publisher
        .set_stage(&mut hub, &operation, from_local_storage())
        .unwrap();
    for index in 0..4 {
        clock.advance(Duration::from_secs(1));
        publisher
            .extent_arrived(&mut hub, &operation, index, 100 * MB)
            .unwrap();
        publisher
            .extent_committed(&mut hub, &operation, index)
            .unwrap();
    }
    clock.advance(Duration::from_millis(100));
    assert_eq!(
        publisher
            .extent_started(&mut hub, &operation, 4, 100 * MB)
            .unwrap(),
        PublishOutcome::Coalesced
    );
    clock.advance(Duration::from_millis(200));
    assert_eq!(publisher.flush_due(&mut hub).unwrap(), 1);

    let delivery = hub.drain(0).progress;
    // One coalesced state per operation and resource.
    assert_eq!(delivery.updates.len(), 1);
    let last = &delivery.updates[0];
    // Operation ID, monotonic sequence and typed generations: the envelope's.
    assert_eq!(last.operation(), &operation);
    assert_eq!(last.stream(), StreamKind::Progress);
    assert_eq!(last.sequence().get(), publisher.stats().published);
    assert_eq!(delivery.resolved[0].through, last.sequence());
    assert_eq!(last.generations(), &generations_of(&handle));
    // Phase and the GPU fields: the payload's.
    assert_eq!(last.phase(), Phase::Restoring);
    let update = last.payload();
    assert_eq!(update.resource(), weights("m"));
    assert_eq!(update.kind(), ResourceKind::Weights);
    assert_eq!(update.source(), Some(DataSource::LocalStorage));
    assert_eq!(
        (
            update.completed_bytes(),
            update.total_bytes(),
            update.committed_usable_bytes()
        ),
        (400 * MB, Some(1000 * MB), 400 * MB)
    );
    // 400 MB usable after three steady 100 MB/s segments: 600 MB take 6 s, at a
    // confidence of (3 - 1) / (3 + 1).
    let eta = update.eta().unwrap();
    assert_eq!(
        (
            eta.remaining_low_seconds(),
            eta.remaining_high_seconds(),
            eta.confidence_percent()
        ),
        (6, 6, 50)
    );
    assert_eq!(update.queue_reason(), None);
    // The copy in flight arrives before a cancellation takes effect.
    assert_eq!(
        update.cancellation(),
        CancellationBoundary::AtCompletedBytes {
            completed_bytes: 500 * MB
        }
    );
    let json = serde_json::to_value(update).unwrap();
    let mut fields: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "cancellation",
            "committed_usable_bytes",
            "completed_bytes",
            "eta",
            "from",
            "kind",
            "resource",
            "total_bytes"
        ]
    );
}

#[test]
fn credentials_prompts_and_private_paths_are_unrepresentable() {
    let clock = new_clock();
    let (mut hub, mut publisher) = daemon(&clock);
    let operation = op("op-load-1");
    publisher
        .track(
            &mut hub,
            &operation,
            request(weights("m"), 10 * GB, queued_for_gpu(4 * GB)),
        )
        .unwrap();
    let event = hub.drain(0).progress.updates.remove(0);
    let json = serde_json::to_value(event.payload()).unwrap();
    // No payload field holds free text: every string is a tag name or a digest.
    let mut found = Vec::new();
    texts(&json, &mut found);
    assert!(!found.is_empty());
    for text in &found {
        assert!(is_tag(text) || is_digest(text), "free text {text:?}");
    }
    // Reading refuses every field the schema does not name, at every level, including
    // next to the tag of a unit variant.
    let attempts: [(&str, &str, Value); 5] = [
        ("", "prompt", json!("summarize my tax return")),
        ("", "api_key", json!("sk-live-0123456789")),
        ("", "path", json!("C:/Users/me/models/private.gguf")),
        ("queue_reason", "path", json!("/home/me/secret")),
        ("cancellation", "token", json!("ghp_0123456789")),
    ];
    for (at, field, value) in attempts {
        let mut copy = json.clone();
        let target = if at.is_empty() {
            &mut copy
        } else {
            &mut copy[at]
        };
        target[field] = value;
        assert!(
            serde_json::from_value::<ProgressUpdate>(copy).is_err(),
            "{at}.{field} was accepted"
        );
    }
    let mut unit_reason = json.clone();
    unit_reason["queue_reason"] = json!({"reason": "transfer_slot"});
    assert!(serde_json::from_value::<ProgressUpdate>(unit_reason.clone()).is_ok());
    unit_reason["queue_reason"]["path"] = json!("/srv/private");
    assert!(serde_json::from_value::<ProgressUpdate>(unit_reason).is_err());
    // A resource is a digest, never a model name or a path.
    let mut named = json.clone();
    named["resource"] = json!("C:/Users/me/models/private.gguf");
    assert!(serde_json::from_value::<ProgressUpdate>(named).is_err());
    // Nothing rides beside the payload: the envelope and its generations refuse extras.
    let mut envelope = serde_json::to_value(&event).unwrap();
    envelope["generations"]["device_pointer"] = json!(140_737_488_355_328_u64);
    assert!(serde_json::from_value::<Event>(envelope.clone()).is_err());
    let mut envelope = serde_json::to_value(&event).unwrap();
    envelope["prompt"] = json!("hello");
    assert!(serde_json::from_value::<Event>(envelope).is_err());
    assert_eq!(
        serde_json::from_value::<ProgressUpdate>(json).unwrap(),
        *event.payload()
    );
}

// Rule 2: event-driven progress with a reconnect snapshot and bounded polling.

#[test]
fn a_reconnect_snapshot_restores_the_latest_state() {
    let clock = new_clock();
    let (mut hub, mut publisher) = daemon(&clock);
    let operations = [op("op-a"), op("op-b"), op("op-c")];
    for (index, operation) in operations.iter().enumerate() {
        publisher
            .track(
                &mut hub,
                operation,
                request(weights(&format!("m{index}")), 300 * MB, queued_for_gpu(GB)),
            )
            .unwrap();
        publisher
            .set_stage(&mut hub, operation, from_local_storage())
            .unwrap();
        clock.advance(Duration::from_secs(1));
        publisher
            .extent_arrived(&mut hub, operation, 0, 100 * MB)
            .unwrap();
    }
    // The receiver connected late: it starts from the snapshot, never a replay.
    let mut link = Link::default();
    let mut receiver = Receiver::new();
    receiver.apply_snapshot(&publisher.snapshot(&mut hub).unwrap(), link.sent);
    for operation in &operations {
        assert_eq!(
            receiver.state(operation),
            Some(publisher.progress(operation).unwrap())
        );
    }
    // Every earlier sequence is closed as superseded; nothing is left to poll for.
    assert!(receiver.reconciler.gaps().is_empty());
    assert!(receiver.reconciler.totals().superseded > 0);
    assert_eq!(receiver.reconciler.poll(clock.now()), Polling::default());

    // The connection drops while progress goes on, and deliveries are lost.
    let _lost = link.drain(&mut hub);
    clock.advance(Duration::from_millis(100));
    publisher
        .extent_committed(&mut hub, &operations[0], 0)
        .unwrap();
    publisher
        .set_stage(
            &mut hub,
            &operations[1],
            Stage::queued(QueueReason::EarlierRequests { requests_ahead: 2 }),
        )
        .unwrap();
    assert_eq!(
        publisher
            .extent_arrived(&mut hub, &operations[2], 1, 100 * MB)
            .unwrap(),
        PublishOutcome::Coalesced
    );
    let _lost = link.drain(&mut hub);
    // On reconnect, the snapshot holds the held (coalesced) state too.
    receiver.apply_snapshot(&publisher.snapshot(&mut hub).unwrap(), link.sent);
    for operation in &operations {
        assert_eq!(
            receiver.state(operation),
            Some(publisher.progress(operation).unwrap())
        );
    }
    assert_eq!(
        receiver.state(&operations[2]).unwrap().1.completed_bytes(),
        200 * MB
    );
    assert_eq!(
        receiver.public(&operations[1]).unwrap().message(),
        "waiting for 2 earlier requests"
    );
    assert!(receiver.reconciler.gaps().is_empty());
    // Deliveries resume where the snapshot left off. The held state the snapshot already
    // brought arrives again, as a duplicate that changes nothing.
    publisher
        .set_stage(&mut hub, &operations[1], from_local_storage())
        .unwrap();
    let (number, batch) = link.drain(&mut hub);
    let arrivals = receiver.deliver(number, &batch);
    assert_eq!(arrivals.len(), 2);
    assert!(arrivals.contains(&Arrival::Duplicate));
    assert!(arrivals.contains(&Arrival::Fresh));
    for operation in &operations {
        assert_eq!(
            receiver.state(operation),
            Some(publisher.progress(operation).unwrap())
        );
    }
    assert!(receiver.reconciler.gaps().is_empty());
}

#[test]
fn reconciliation_polling_is_bounded_and_only_reconciles() {
    let clock = new_clock();
    let (mut hub, mut publisher) = daemon(&clock);
    let mut link = Link::default();
    let mut receiver = Receiver::new();
    let operation = op("op-1");
    publisher
        .track(
            &mut hub,
            &operation,
            request(weights("m"), 600 * MB, queued_for_gpu(GB)),
        )
        .unwrap();
    publisher
        .set_stage(&mut hub, &operation, from_local_storage())
        .unwrap();
    // While every delivery arrives the receiver never polls, though the hub coalesced
    // most updates away.
    for index in 0..60 {
        clock.advance(Duration::from_secs(1));
        publisher
            .extent_arrived(&mut hub, &operation, index, 10 * MB)
            .unwrap();
        publisher
            .extent_committed(&mut hub, &operation, index)
            .unwrap();
        let (number, batch) = link.drain(&mut hub);
        receiver.deliver(number, &batch);
        assert_eq!(receiver.reconciler.poll(clock.now()), Polling::default());
    }
    assert!(receiver.reconciler.totals().superseded > 0);

    // A lost delivery leaves a gap that the next one reveals.
    publisher
        .set_stage(&mut hub, &operation, Stage::at(Phase::Activating))
        .unwrap();
    let _lost = link.drain(&mut hub);
    publisher
        .set_stage(&mut hub, &operation, Stage::at(Phase::Completed))
        .unwrap();
    let (number, batch) = link.drain(&mut hub);
    assert!(matches!(
        receiver.deliver(number, &batch)[..],
        [Arrival::FreshAfterGap { .. }]
    ));
    // One poll for the gap, none again within the interval, and the snapshot that
    // answers it closes the gap.
    let polling = receiver.reconciler.poll(clock.now());
    assert_eq!(polling.requests.len(), 1);
    assert_eq!(polling.requests[0].attempt, 1);
    assert_eq!(
        receiver
            .reconciler
            .poll(clock.now().saturating_add(Duration::from_secs(1))),
        Polling::default()
    );
    receiver.apply_snapshot(&publisher.snapshot(&mut hub).unwrap(), link.sent);
    assert!(receiver.reconciler.gaps().is_empty());
    assert_eq!(
        receiver.state(&operation),
        Some(publisher.progress(&operation).unwrap())
    );
    clock.advance(Duration::from_secs(3_600));
    assert_eq!(receiver.reconciler.poll(clock.now()), Polling::default());

    // Polls that are never answered are bounded: three, at least 2 s apart, after which
    // the gap is marked lost, explicitly and with its reason.
    let other = op("op-2");
    publisher
        .track(
            &mut hub,
            &other,
            request(weights("n"), 100 * MB, queued_for_gpu(4 * GB)),
        )
        .unwrap();
    let _lost = link.drain(&mut hub);
    publisher
        .set_stage(&mut hub, &other, from_local_storage())
        .unwrap();
    let (number, batch) = link.drain(&mut hub);
    assert!(matches!(
        receiver.deliver(number, &batch)[..],
        [Arrival::FreshAfterGap { .. }]
    ));
    let mut attempts = Vec::new();
    let mut lost = Vec::new();
    for _ in 0..20 {
        clock.advance(Duration::from_secs(1));
        let polling = receiver.reconciler.poll(clock.now());
        attempts.extend(
            polling
                .requests
                .iter()
                .map(|request| (request.attempt, clock.now())),
        );
        lost.extend(polling.lost);
    }
    assert_eq!(
        attempts
            .iter()
            .map(|(attempt, _)| *attempt)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert!(attempts
        .windows(2)
        .all(|pair| pair[1].1.saturating_duration_since(pair[0].1) >= Duration::from_secs(2)));
    assert_eq!(lost.len(), 1);
    assert_eq!(lost[0].reason, LossReason::RecoveryExhausted);
    assert!(receiver.reconciler.gaps().is_empty());
    // A later snapshot still brings the latest state.
    receiver.apply_snapshot(&publisher.snapshot(&mut hub).unwrap(), link.sent);
    assert_eq!(
        receiver.state(&other),
        Some(publisher.progress(&other).unwrap())
    );
}

#[test]
fn lost_duplicated_and_reordered_events_converge() {
    for seed in 0..20 {
        let clock = new_clock();
        let (mut hub, mut publisher) = daemon(&clock);
        let mut link = Link::default();
        let mut receiver = Receiver::new();
        let mut rng = SeededRng::new(seed);
        let operations: Vec<OperationId> = (0..4).map(|index| op(&format!("op-{index}"))).collect();
        receiver.apply_snapshot(&publisher.snapshot(&mut hub).unwrap(), link.sent);
        for (index, operation) in operations.iter().enumerate() {
            publisher
                .track(
                    &mut hub,
                    operation,
                    request(weights(&format!("m{index}")), 20 * MB, queued_for_gpu(GB)),
                )
                .unwrap();
        }
        let mut next_extent = vec![0_u64; operations.len()];
        let mut sent = Vec::new();
        for _ in 0..300 {
            clock.advance(Duration::from_millis(100 + rng.below(400)));
            let which = rng.below(operations.len() as u64) as usize;
            let operation = &operations[which];
            match publisher.progress(operation).unwrap().0 {
                Phase::Queued => {
                    publisher
                        .set_stage(&mut hub, operation, from_local_storage())
                        .unwrap();
                }
                Phase::Restoring if next_extent[which] < 20 => {
                    let index = next_extent[which];
                    publisher
                        .extent_arrived(&mut hub, operation, index, MB)
                        .unwrap();
                    if rng.below(5) == 0 {
                        // A hash mismatch: discarded and fetched again later.
                        publisher
                            .extent_discarded(&mut hub, operation, index)
                            .unwrap();
                    } else {
                        publisher
                            .extent_committed(&mut hub, operation, index)
                            .unwrap();
                        next_extent[which] += 1;
                    }
                }
                Phase::Restoring => {
                    publisher
                        .set_stage(&mut hub, operation, Stage::at(Phase::Activating))
                        .unwrap();
                }
                Phase::Activating => {
                    publisher
                        .set_stage(&mut hub, operation, Stage::at(Phase::Completed))
                        .unwrap();
                }
                _ => {}
            }
            publisher.flush_due(&mut hub).unwrap();
            sent.push(link.drain(&mut hub));
        }
        // Lose a fifth, repeat a third, and swap neighbours.
        let mut arriving = Vec::new();
        for delivery in sent {
            if rng.below(5) == 0 {
                continue;
            }
            if rng.below(3) == 0 {
                arriving.push(delivery.clone());
            }
            arriving.push(delivery);
        }
        for index in 1..arriving.len() {
            if rng.below(3) == 0 {
                arriving.swap(index - 1, index);
            }
        }
        for (number, batch) in &arriving {
            let before: Vec<_> = batch
                .updates
                .iter()
                .map(|update| receiver.position(update.operation()))
                .collect();
            let arrivals = receiver.deliver(*number, batch);
            for ((update, arrival), before) in batch.updates.iter().zip(&arrivals).zip(before) {
                let after = receiver.position(update.operation());
                assert!(after >= before, "seed {seed}: the receiver moved back");
                if !arrival.is_new() {
                    assert_eq!(after, before, "seed {seed}: a repeat changed the view");
                }
            }
        }
        // Every poll the reconciler asks for is answered with a snapshot.
        for _ in 0..10 {
            clock.advance(Duration::from_secs(61));
            if receiver.reconciler.poll(clock.now()).requests.is_empty() {
                break;
            }
            receiver.apply_snapshot(&publisher.snapshot(&mut hub).unwrap(), link.sent);
        }
        // A lost tail reveals no gap; the reconnect snapshot closes it.
        receiver.apply_snapshot(&publisher.snapshot(&mut hub).unwrap(), link.sent);
        for operation in &operations {
            assert_eq!(
                receiver.state(operation),
                Some(publisher.progress(operation).unwrap()),
                "seed {seed}"
            );
        }
        assert!(receiver.reconciler.gaps().is_empty(), "seed {seed}");
        assert!(receiver.reconciler.totals().duplicates > 0, "seed {seed}");
    }
}

#[test]
fn repeated_commands_and_updates_are_idempotent() {
    let clock = new_clock();
    let (mut hub, mut publisher) = daemon(&clock);
    let operation = op("op-1");
    let track = request(weights("m"), 200 * MB, queued_for_gpu(GB));
    assert_eq!(
        publisher.track(&mut hub, &operation, track).unwrap(),
        PublishOutcome::Published
    );
    assert_eq!(
        publisher.track(&mut hub, &operation, track).unwrap(),
        PublishOutcome::Unchanged
    );
    assert_eq!(
        publisher.track(
            &mut hub,
            &operation,
            TrackRequest {
                total_bytes: 1,
                ..track
            }
        ),
        Err(PublishError::TrackConflict)
    );
    publisher
        .set_stage(&mut hub, &operation, from_local_storage())
        .unwrap();
    assert_eq!(
        publisher
            .set_stage(&mut hub, &operation, from_local_storage())
            .unwrap(),
        PublishOutcome::Unchanged
    );
    clock.advance(Duration::from_secs(1));
    publisher
        .extent_started(&mut hub, &operation, 0, 100 * MB)
        .unwrap();
    assert_eq!(
        publisher
            .extent_started(&mut hub, &operation, 0, 100 * MB)
            .unwrap(),
        PublishOutcome::Unchanged
    );
    publisher
        .extent_arrived(&mut hub, &operation, 0, 100 * MB)
        .unwrap();
    assert_eq!(
        publisher
            .extent_arrived(&mut hub, &operation, 0, 100 * MB)
            .unwrap(),
        PublishOutcome::Unchanged
    );
    assert_eq!(
        publisher.extent_arrived(&mut hub, &operation, 0, 50 * MB),
        Err(PublishError::ExtentConflict { index: 0 })
    );
    publisher.extent_committed(&mut hub, &operation, 0).unwrap();
    assert_eq!(
        publisher.extent_committed(&mut hub, &operation, 0).unwrap(),
        PublishOutcome::Unchanged
    );
    assert_eq!(
        publisher.extent_discarded(&mut hub, &operation, 7).unwrap(),
        PublishOutcome::Unchanged
    );
    let (_, update) = publisher.progress(&operation).unwrap();
    assert_eq!(
        (update.completed_bytes(), update.committed_usable_bytes()),
        (100 * MB, 100 * MB)
    );
    // A state that arrives twice, by delivery and again in a snapshot, applies once.
    let snapshot = publisher.snapshot(&mut hub).unwrap();
    let mut link = Link::default();
    let mut receiver = Receiver::new();
    let (number, batch) = link.drain(&mut hub);
    receiver.deliver(number, &batch);
    let view = receiver.state(&operation);
    assert_eq!(receiver.receive(&snapshot.states[0]), Arrival::Duplicate);
    receiver.apply_snapshot(&snapshot, link.sent);
    assert_eq!(receiver.state(&operation), view);

    // The same for job commands, across a restart too.
    let dir = tempfile::tempdir().unwrap();
    let catalog = FakeCatalog::default();
    let mut loader = FakeLoader::default();
    let (mut control, _) = start(dir.path(), 1, &catalog, &mut loader);
    let load = intent("op-load", JobKind::Load, 300);
    assert_eq!(
        control.submit(load.clone(), &mut loader).unwrap(),
        Submission::Submitted
    );
    assert_eq!(
        control.submit(load.clone(), &mut loader).unwrap(),
        Submission::AlreadySubmitted
    );
    assert_eq!(loader.submitted.len(), 1);
    assert_eq!(
        control.submit(
            JobIntent {
                total_bytes: 301,
                ..load.clone()
            },
            &mut loader
        ),
        Err(JobError::Journal(JournalError::Refused(
            RecordRefusal::IntentConflict
        )))
    );
    let first = extent(0, 0, 100);
    assert_eq!(
        control
            .record_verified_extent(&load.operation, first)
            .unwrap(),
        Recorded::Written
    );
    assert_eq!(
        control
            .record_verified_extent(&load.operation, first)
            .unwrap(),
        Recorded::AlreadyPresent
    );
    let lines = line_count(dir.path());
    drop(control);
    let (mut control, report) = start(dir.path(), 2, &catalog, &mut loader);
    assert_eq!(report.resubmitted, [load.operation.clone()]);
    assert_eq!(
        control.submit(load.clone(), &mut loader).unwrap(),
        Submission::AlreadySubmitted
    );
    assert_eq!(loader.submitted.len(), 2);
    // Only the restart added a line: its incarnation.
    assert_eq!(line_count(dir.path()), lines + 1);

    // Cancelling twice cancels once; an undelivered cancellation is delivered on repeat.
    loader.refuse_cancellations = true;
    assert!(control.cancel(&load.operation, &mut loader).is_err());
    loader.refuse_cancellations = false;
    assert_eq!(
        control.cancel(&load.operation, &mut loader).unwrap(),
        Cancellation::Cancelled
    );
    assert_eq!(
        control.cancel(&load.operation, &mut loader).unwrap(),
        Cancellation::AlreadyFinished(JobOutcome::Cancelled)
    );
    assert_eq!(loader.cancelled, [load.operation.clone()]);
    assert_eq!(
        control
            .finish(&load.operation, JobOutcome::Cancelled)
            .unwrap(),
        Recorded::AlreadyPresent
    );
    assert_eq!(
        control.finish(&load.operation, JobOutcome::Failed),
        Err(JobError::Journal(JournalError::Refused(
            RecordRefusal::OutcomeConflict {
                recorded: JobOutcome::Cancelled
            }
        )))
    );
}

#[test]
fn progress_never_goes_on_the_audit_or_metrics_stream() {
    let clock = new_clock();
    // Room for one progress state.
    let mut hub = hub_with(&clock, 1, 1);
    let mut publisher = publisher_on(&mut hub, &clock, 1);
    // A progress producer emits on the progress stream and nowhere else.
    assert_eq!(publisher.producer().key().stream, StreamKind::Progress);
    let first = op("op-1");
    let second = op("op-2");
    assert_eq!(
        publisher
            .track(
                &mut hub,
                &first,
                request(weights("a"), 10 * MB, from_local_storage())
            )
            .unwrap(),
        PublishOutcome::Published
    );
    // The stream is full of a live state: the second operation's latest state waits.
    // Nothing blocks, nothing is dropped, and nothing spills into another stream.
    assert_eq!(
        publisher
            .track(
                &mut hub,
                &second,
                request(weights("b"), 10 * MB, queued_for_gpu(GB))
            )
            .unwrap(),
        PublishOutcome::Deferred
    );
    assert_eq!(
        publisher
            .set_stage(&mut hub, &second, from_local_storage())
            .unwrap(),
        PublishOutcome::Deferred
    );
    for index in 0..10 {
        clock.advance(Duration::from_secs(1));
        publisher
            .extent_arrived(&mut hub, &first, index, MB)
            .unwrap();
        publisher.extent_committed(&mut hub, &first, index).unwrap();
    }
    publisher
        .set_stage(&mut hub, &first, Stage::at(Phase::Completed))
        .unwrap();
    let delivered = hub.drain(0);
    assert_eq!(delivered.progress.updates.len(), 1);
    assert_eq!(delivered.progress.updates[0].phase(), Phase::Completed);
    // Once its final state is delivered, the ended operation makes room, and the second
    // operation's latest state goes out.
    assert_eq!(publisher.flush_due(&mut hub).unwrap(), 1);
    let delivered = hub.drain(0);
    assert_eq!(delivered.progress.updates.len(), 1);
    assert_eq!(delivered.progress.updates[0].operation(), &second);
    assert_eq!(delivered.progress.updates[0].phase(), Phase::Restoring);
    assert!(publisher.stats().deferred >= 2);
    // Nothing reached the metrics stream or the revocation lane, and the hub holds no
    // audit journal to reach.
    assert_eq!(hub.metrics().totals(), MetricsTotals::default());
    assert!(delivered.metrics.events.is_empty());
    assert!(delivered.revocations.notices.is_empty());
}

#[test]
fn progress_is_one_record_per_operation_never_one_stream_per_tensor() {
    let clock = new_clock();
    let (mut hub, mut publisher) = daemon(&clock);
    let operation = op("op-model");
    const TENSORS: u64 = 10_000;
    publisher
        .track(
            &mut hub,
            &operation,
            request(weights("m"), TENSORS * 100_000, queued_for_gpu(GB)),
        )
        .unwrap();
    publisher
        .set_stage(&mut hub, &operation, from_local_storage())
        .unwrap();
    for index in 0..TENSORS {
        clock.advance(Duration::from_millis(10));
        publisher
            .extent_arrived(&mut hub, &operation, index, 100_000)
            .unwrap();
        publisher
            .extent_committed(&mut hub, &operation, index)
            .unwrap();
    }
    // 100 s at one byte update per 250 ms, plus the first state, the stage change and
    // the update that made every byte usable.
    let applied = hub.progress().totals().applied;
    assert!(applied <= 100_000 / 250 + 3, "{applied} events");
    assert_eq!(hub.progress().tracked(), 1);
    let delivery = hub.drain(0).progress;
    assert_eq!(delivery.updates.len(), 1);
    assert_eq!(delivery.updates[0].operation(), &operation);
    assert_eq!(
        delivery.updates[0].payload().committed_usable_bytes(),
        TENSORS * 100_000
    );
    // Tracking every tensor as its own operation is refused at the bound.
    let mut refused = None;
    for index in 0..TENSORS {
        if let Err(error) = publisher.track(
            &mut hub,
            &op(&format!("tensor-{index}")),
            request(weights(&format!("t{index}")), 100_000, queued_for_gpu(GB)),
        ) {
            refused = Some((index, error));
            break;
        }
    }
    assert_eq!(
        refused,
        Some((255, PublishError::TooManyOperations { max: 256 }))
    );
    // No resource kind names a tensor.
    assert!(serde_json::from_value::<ResourceKind>(json!("tensor")).is_err());
}

// Rule 3: the journal.

#[test]
fn the_journal_persists_intent_artifact_commits_and_verified_extents() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = FakeCatalog::default();
    let mut loader = FakeLoader::default();
    let (mut control, report) = start(dir.path(), 1, &catalog, &mut loader);
    assert_eq!(report.incarnation, Incarnation::FIRST);
    assert_eq!(
        report.journal,
        JournalOpened {
            records: 1,
            discarded_tail_bytes: 0
        }
    );
    let prepare = intent("op-prepare", JobKind::Prepare, 300);
    let load = intent("op-load", JobKind::Load, 300);
    control.submit(prepare.clone(), &mut loader).unwrap();
    control.submit(load.clone(), &mut loader).unwrap();
    control
        .record_artifact_commit(&prepare.operation, commit_of(&prepare))
        .unwrap();
    for index in 0..3 {
        control
            .record_verified_extent(&load.operation, extent(index, u64::from(index) * 100, 100))
            .unwrap();
    }
    // The import's resumable state, as the catalog reports it (T05).
    let paused = ImportState {
        reached: Checkpoint::Stage {
            stage: ImportStage::TemporaryRepresentation,
        },
        progress: ImportProgress {
            verified_extents: 3,
            fetched_extents: 3,
            fetched_bytes: 300,
            ..ImportProgress::default()
        },
    };
    assert_eq!(
        control
            .record_import_state(&load.operation, paused)
            .unwrap(),
        Recorded::Written
    );
    assert_eq!(
        control
            .record_import_state(&load.operation, paused)
            .unwrap(),
        Recorded::AlreadyPresent
    );
    // Nothing about the import follows a committed artifact.
    assert_eq!(
        control.record_import_state(&prepare.operation, paused),
        Err(JobError::Journal(JournalError::Refused(
            RecordRefusal::ArtifactAlreadyCommitted
        )))
    );
    let before = control.state().clone();
    drop(control);

    let (control, report) = start(dir.path(), 2, &catalog, &mut loader);
    assert_eq!(report.incarnation, Incarnation::new(2));
    assert_eq!(control.state().incarnation(), Some(Incarnation::new(2)));
    for operation in [&prepare.operation, &load.operation] {
        assert_eq!(control.state().job(operation), before.job(operation));
    }
    let job = control.state().job(&load.operation).unwrap();
    assert_eq!(job.intent(), &load);
    assert_eq!(job.intent().object(), commit_of(&load).object);
    assert_eq!(job.import_state(), Some(&paused));
    let extents: Vec<VerifiedExtent> = job.verified_extents().copied().collect();
    assert_eq!(
        extents,
        (0..3)
            .map(|index| extent(index, u64::from(index) * 100, 100))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        control.state().job(&prepare.operation).unwrap().artifact(),
        Some(&commit_of(&prepare))
    );
    // Each line is its checksum, a space and the JSON; the first is the format header.
    let text = std::fs::read_to_string(journal_path(dir.path())).unwrap();
    let (check, header) = text.lines().next().unwrap().split_once(' ').unwrap();
    assert_eq!(
        check,
        digest(
            "yougori/model-memory/progress/journal-line/v1",
            &[header.as_bytes()]
        )
        .to_hex()
    );
    assert_eq!(
        serde_json::from_str::<Value>(header).unwrap(),
        json!({"sequence": 1, "record": {"type": "header", "format": JOURNAL_FORMAT_VERSION}})
    );
}

#[test]
fn the_journal_never_stores_device_pointers_leases_or_generations() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = FakeCatalog::default();
    let mut loader = FakeLoader::default();
    let (mut control, _) = start(dir.path(), 1, &catalog, &mut loader);
    let load = intent("op-load", JobKind::Load, 200);
    control.submit(load.clone(), &mut loader).unwrap();
    control
        .record_verified_extent(&load.operation, extent(0, 0, 100))
        .unwrap();
    control
        .record_artifact_commit(&load.operation, commit_of(&load))
        .unwrap();
    control
        .finish(&load.operation, JobOutcome::Completed)
        .unwrap();
    drop(control);
    let text = std::fs::read_to_string(journal_path(dir.path())).unwrap();
    for line in text.lines() {
        let (_, record) = line.split_once(' ').unwrap();
        let mut names = Vec::new();
        keys(&serde_json::from_str(record).unwrap(), &mut names);
        for name in names {
            for word in [
                "pointer",
                "handle",
                "lease",
                "address",
                "prompt",
                "path",
                "token",
                "generation",
                "allocation",
            ] {
                assert!(!name.contains(word), "the journal stores {name}");
            }
        }
    }
    // A record that tries to carry a device pointer is refused when read, even as the
    // last, fully written line.
    let mut smuggled = serde_json::to_value(intent("op-other", JobKind::Load, 10)).unwrap();
    smuggled["device_pointer"] = json!(140_737_488_355_328_u64);
    let sequence = line_count(dir.path()) + 1;
    append_line(
        dir.path(),
        &json!({"sequence": sequence, "record": {"type": "intent", "intent": smuggled}}),
    );
    assert_eq!(
        try_start(dir.path(), 2, &catalog, &mut loader).err(),
        Some(RecoveryError::Journal(JournalError::Corrupt {
            line: sequence,
            reason: CorruptReason::Unparseable
        }))
    );
    // There is no lease or generation record at all, and no record or line takes an
    // extra field, next to a record's tag, beside it, or inside a catalog type that would
    // itself ignore it.
    let mut progress = serde_json::to_value(ImportProgress::default()).unwrap();
    let checkpoint = serde_json::to_value(Checkpoint::Extent { extent: 3 }).unwrap();
    let mut smuggled_checkpoint = checkpoint.clone();
    smuggled_checkpoint["device_pointer"] = json!(4096);
    let clean_progress = progress.clone();
    progress["gpu_lease"] = json!(41);
    for smuggled in [
        json!({"type": "gpu_lease", "lease": 41}),
        json!({"type": "generations_issued", "floors": {"model_activation": 1, "gpu_allocation": 1}}),
        json!({"type": "incarnation", "incarnation": 2, "session": session(7), "gpu_lease": 41}),
        json!({"type": "import_reached", "operation": "op-load", "state": {"reached": smuggled_checkpoint, "progress": clean_progress}}),
        json!({"type": "import_reached", "operation": "op-load", "state": {"reached": checkpoint, "progress": progress}}),
    ] {
        let dir = tempfile::tempdir().unwrap();
        drop(start(dir.path(), 1, &catalog, &mut loader));
        let sequence = line_count(dir.path()) + 1;
        append_line(
            dir.path(),
            &json!({"sequence": sequence, "record": smuggled}),
        );
        assert_eq!(
            try_start(dir.path(), 2, &catalog, &mut loader).err(),
            Some(RecoveryError::Journal(JournalError::Corrupt {
                line: sequence,
                reason: CorruptReason::Unparseable
            })),
            "{smuggled}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    drop(start(dir.path(), 1, &catalog, &mut loader));
    let sequence = line_count(dir.path()) + 1;
    append_line(
        dir.path(),
        &json!({"sequence": sequence, "record": {"type": "incarnation", "incarnation": 2, "session": session(7)}, "device_pointer": 4096}),
    );
    assert!(matches!(
        try_start(dir.path(), 3, &catalog, &mut loader).err(),
        Some(RecoveryError::Journal(JournalError::Corrupt {
            reason: CorruptReason::Unparseable,
            ..
        }))
    ));
    // The same line without the extra field is accepted, so the refusal is the field's.
    let dir = tempfile::tempdir().unwrap();
    drop(start(dir.path(), 1, &catalog, &mut loader));
    let sequence = line_count(dir.path()) + 1;
    append_line(
        dir.path(),
        &json!({"sequence": sequence, "record": {"type": "incarnation", "incarnation": 2, "session": session(7)}}),
    );
    let (control, _) = start(dir.path(), 3, &catalog, &mut loader);
    assert_eq!(control.incarnation(), Incarnation::new(3));
}

#[test]
fn a_torn_tail_is_cut_off_and_corruption_refuses_to_open() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = FakeCatalog::default();
    let mut loader = FakeLoader::default();
    let (mut control, _) = start(dir.path(), 1, &catalog, &mut loader);
    let load = intent("op-load", JobKind::Load, 300);
    control.submit(load.clone(), &mut loader).unwrap();
    let state = control.state().clone();
    drop(control);
    // A write that never completed: no newline.
    let mut file = OpenOptions::new()
        .append(true)
        .open(journal_path(dir.path()))
        .unwrap();
    file.write_all(b"0123abc {\"sequ").unwrap();
    drop(file);
    let (mut control, report) = start(dir.path(), 2, &catalog, &mut loader);
    assert_eq!(report.journal.discarded_tail_bytes, 14);
    assert_eq!(
        control.state().job(&load.operation),
        state.job(&load.operation)
    );
    control
        .record_verified_extent(&load.operation, extent(0, 0, 100))
        .unwrap();
    drop(control);
    // A complete final line whose checksum does not match was torn too.
    let mut file = OpenOptions::new()
        .append(true)
        .open(journal_path(dir.path()))
        .unwrap();
    file.write_all(format!("{} {{}}\n", "0".repeat(64)).as_bytes())
        .unwrap();
    drop(file);
    let (control, report) = start(dir.path(), 3, &catalog, &mut loader);
    assert_eq!(report.journal.discarded_tail_bytes, 68);
    assert_eq!(
        control
            .state()
            .job(&load.operation)
            .unwrap()
            .verified_extents()
            .count(),
        1
    );
    drop(control);
    // Damage before the end refuses to open: the journal is never read past it.
    let path = journal_path(dir.path());
    let text = std::fs::read_to_string(&path).unwrap();
    let damaged = text.replacen("op-load", "op-lOad", 1);
    std::fs::write(&path, damaged).unwrap();
    let damaged_line = text
        .lines()
        .position(|line| line.contains("op-load"))
        .unwrap() as u64
        + 1;
    assert_eq!(
        try_start(dir.path(), 4, &catalog, &mut loader).err(),
        Some(RecoveryError::Journal(JournalError::Corrupt {
            line: damaged_line,
            reason: CorruptReason::BadCheck
        }))
    );
    // Another format, such as format 1, which recorded no clock session with a start,
    // is refused, not reinterpreted.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(journal_path(dir.path()), "").unwrap();
    append_line(
        dir.path(),
        &json!({"sequence": 1, "record": {"type": "header", "format": 1}}),
    );
    append_line(
        dir.path(),
        &json!({"sequence": 2, "record": {"type": "incarnation", "incarnation": 1}}),
    );
    assert_eq!(
        try_start(dir.path(), 2, &catalog, &mut loader).err(),
        Some(RecoveryError::Journal(JournalError::UnsupportedFormat {
            found: 1
        }))
    );
}

#[test]
fn the_journal_refuses_inconsistent_records() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = FakeCatalog::default();
    let mut loader = FakeLoader::default();
    let (mut control, _) = start(dir.path(), 1, &catalog, &mut loader);
    let load = intent("op-load", JobKind::Load, 300);
    fn refused<T>(refusal: RecordRefusal) -> Result<T, JobError> {
        Err(JobError::Journal(JournalError::Refused(refusal)))
    }
    assert_eq!(
        control.submit(intent("op-empty", JobKind::Load, 0), &mut loader),
        refused(RecordRefusal::ZeroTotalBytes)
    );
    assert_eq!(
        control.record_verified_extent(&load.operation, extent(0, 0, 100)),
        refused(RecordRefusal::UnknownOperation)
    );
    control.submit(load.clone(), &mut loader).unwrap();
    control
        .record_verified_extent(&load.operation, extent(0, 0, 100))
        .unwrap();
    assert_eq!(
        control.record_verified_extent(&load.operation, extent(1, 50, 100)),
        refused(RecordRefusal::ExtentOverlap { extent: 1 })
    );
    assert_eq!(
        control.record_verified_extent(&load.operation, extent(1, 250, 100)),
        refused(RecordRefusal::ExtentOutOfRange)
    );
    assert_eq!(
        control.record_verified_extent(&load.operation, extent(1, 100, 0)),
        refused(RecordRefusal::EmptyExtent)
    );
    assert_eq!(
        control.record_verified_extent(&load.operation, extent(0, 100, 100)),
        refused(RecordRefusal::ExtentConflict { extent: 0 })
    );
    assert_eq!(
        control.finish(&load.operation, JobOutcome::Completed),
        refused(RecordRefusal::CompletedWithoutArtifact)
    );
    assert_eq!(
        control.record_artifact_commit(
            &load.operation,
            ArtifactCommit {
                object: ObjectId::new(
                    &load.scope(),
                    ArtifactClass::ModelWeights,
                    ContentKey::of(b"another")
                ),
                total_bytes: 300
            }
        ),
        refused(RecordRefusal::ArtifactMismatch)
    );
    control
        .record_artifact_commit(&load.operation, commit_of(&load))
        .unwrap();
    assert_eq!(
        control.record_verified_extent(&load.operation, extent(1, 100, 100)),
        refused(RecordRefusal::ArtifactAlreadyCommitted)
    );
    drop(control);
    // An incarnation is used once and only rises; the first is at least 1.
    let not_after = |last, found| {
        Some(RecoveryError::Journal(JournalError::Refused(
            RecordRefusal::IncarnationNotAfter { last, found },
        )))
    };
    assert_eq!(
        try_start(dir.path(), 1, &catalog, &mut loader).err(),
        not_after(Some(Incarnation::FIRST), Incarnation::FIRST)
    );
    let fresh = tempfile::tempdir().unwrap();
    assert_eq!(
        try_start(fresh.path(), 0, &catalog, &mut loader).err(),
        not_after(None, Incarnation::new(0))
    );
    // A later incarnation may skip some, as a start that crashed before journaling would.
    let (control, _) = start(dir.path(), 5, &catalog, &mut loader);
    assert_eq!(control.incarnation(), Incarnation::new(5));
}

// Rule 4: restart reconciliation.

#[test]
fn a_restart_never_assumes_gpu_leases_survive() {
    let clock = new_clock();
    let dir = tempfile::tempdir().unwrap();
    let catalog = FakeCatalog::default();
    let mut loader = FakeLoader::default();
    let sandbox = SandboxHost::launch(&clock);
    let (mut control, _) = JobControl::start(
        dir.path(),
        Incarnation::FIRST,
        &catalog,
        &sandbox.host,
        &CoordinatorRecovery::default(),
        &mut loader,
    )
    .unwrap();
    let load = intent("op-load", JobKind::Load, 300);
    control.submit(load.clone(), &mut loader).unwrap();
    let mut sandbox = sandbox;
    let lease = sandbox
        .host
        .start_child_work(
            &owner(),
            op("op-transfer"),
            LeaseKind::Transfer,
            lease_terms(),
        )
        .unwrap()
        .id();
    assert!(sandbox.host.check_lease(lease).is_ok());
    drop(control);

    // A start on a coordinator that still honours the lease is refused, before it
    // touches the journal.
    let claimed = CoordinatorRecovery {
        leases_not_revived: vec![lease],
        ..CoordinatorRecovery::default()
    };
    let lines = line_count(dir.path());
    assert_eq!(
        JobControl::start(
            dir.path(),
            Incarnation::new(2),
            &catalog,
            &sandbox.host,
            &claimed,
            &mut loader
        )
        .err(),
        Some(RecoveryError::LeaseSurvived { lease })
    );
    assert_eq!(line_count(dir.path()), lines);

    // The daemon restarts: the coordinator recovers and revives no lease.
    let (sandbox, recovered) = sandbox.restart(&clock);
    assert_eq!(recovered.leases_not_revived, [lease]);
    let mut loader = FakeLoader::default();
    let (_, report) = JobControl::start(
        dir.path(),
        Incarnation::new(2),
        &catalog,
        &sandbox.host,
        &recovered,
        &mut loader,
    )
    .unwrap();
    assert_eq!(report.leases_not_revived, [lease]);
    assert_eq!(
        sandbox.host.check_lease(lease).err(),
        Some(LeaseRefusal::NotRevived)
    );
    // The job is resubmitted with no lease, generation or GPU state to resume from.
    assert_eq!(
        loader.submitted,
        [LoadRequest {
            intent: load,
            resume: ResumePoint::fresh(),
            incarnation: Incarnation::new(2),
        }]
    );
}

#[test]
fn a_restart_invalidates_stale_generations() {
    let clock = new_clock();
    let dir = tempfile::tempdir().unwrap();
    let catalog = FakeCatalog::default();
    let mut loader = FakeLoader::default();
    let mut sandbox = SandboxHost::launch(&clock);
    let (mut control, report) = JobControl::start(
        dir.path(),
        Incarnation::FIRST,
        &catalog,
        &sandbox.host,
        &CoordinatorRecovery::default(),
        &mut loader,
    )
    .unwrap();
    assert!(report.stale_allocations.is_empty());
    let load = intent("op-load", JobKind::Load, 300);
    control.submit(load.clone(), &mut loader).unwrap();
    let old = sandbox.activate(model("chat"));
    let (mut hub, mut publisher) = daemon(&clock);
    publisher
        .track(
            &mut hub,
            &load.operation,
            request(weights("chat"), 300, from_local_storage()),
        )
        .unwrap();
    publisher
        .set_allocation(&mut hub, &sandbox.host, &load.operation, &old)
        .unwrap();
    drop(control);

    // A start on a coordinator that still honours the allocation is refused.
    let claimed = CoordinatorRecovery {
        retired_activations: vec![old.clone()],
        ..CoordinatorRecovery::default()
    };
    assert_eq!(
        JobControl::start(
            dir.path(),
            Incarnation::new(2),
            &catalog,
            &sandbox.host,
            &claimed,
            &mut loader
        )
        .err(),
        Some(RecoveryError::AllocationSurvived {
            handle: old.clone()
        })
    );

    // The daemon restarts: the coordinator retires every activation and reuses no
    // generation.
    let (mut sandbox, recovered) = sandbox.restart(&clock);
    assert_eq!(recovered.retired_activations, [old.clone()]);
    let mut loader = FakeLoader::default();
    let (_, report) = JobControl::start(
        dir.path(),
        Incarnation::new(2),
        &catalog,
        &sandbox.host,
        &recovered,
        &mut loader,
    )
    .unwrap();
    assert_eq!(report.stale_allocations, [old.clone()]);
    assert_eq!(report.resubmitted, [load.operation.clone()]);

    // Progress under the stale generation is refused at the source.
    let mut hub = hub_with(&clock, report.incarnation.get(), 512);
    let mut publisher = publisher_on(&mut hub, &clock, report.incarnation.get());
    publisher
        .track(
            &mut hub,
            &load.operation,
            request(
                weights("chat"),
                300,
                Stage::queued(QueueReason::Authorization),
            ),
        )
        .unwrap();
    assert_eq!(
        publisher.set_allocation(&mut hub, &sandbox.host, &load.operation, &old),
        Err(PublishError::StaleAllocation {
            refusal: LeaseRefusal::StaleGpuAllocation {
                bound: old.generations.gpu_allocation,
                current: None
            }
        })
    );
    // Fresh authority, then a fresh allocation above every generation from before.
    sandbox.authorize();
    let fresh = sandbox.activate(model("chat"));
    assert!(fresh.generations.activation > old.generations.activation);
    assert!(fresh.generations.gpu_allocation > old.generations.gpu_allocation);
    publisher
        .set_stage(&mut hub, &load.operation, from_local_storage())
        .unwrap();
    assert_eq!(
        publisher
            .set_allocation(&mut hub, &sandbox.host, &load.operation, &fresh)
            .unwrap(),
        PublishOutcome::Published
    );
    assert_eq!(
        hub.drain(0).progress.updates[0].generations(),
        &generations_of(&fresh)
    );
    assert_eq!(
        publisher.set_allocation(&mut hub, &sandbox.host, &load.operation, &old),
        Err(PublishError::StaleAllocation {
            refusal: LeaseRefusal::StaleGpuAllocation {
                bound: old.generations.gpu_allocation,
                current: Some(fresh.generations.gpu_allocation)
            }
        })
    );
}

#[test]
fn a_later_start_checks_the_coordinator_whatever_the_report_says() {
    let clock = new_clock();
    let dir = tempfile::tempdir().unwrap();
    let catalog = FakeCatalog::default();
    let mut loader = FakeLoader::default();
    let empty = CoordinatorRecovery::default();
    let mut sandbox = SandboxHost::launch(&clock);
    let (control, _) = JobControl::start(
        dir.path(),
        Incarnation::FIRST,
        &catalog,
        &sandbox.host,
        &empty,
        &mut loader,
    )
    .unwrap();
    assert_eq!(
        control.state().started_on(sandbox.host.session()),
        Some(Incarnation::FIRST)
    );
    drop(control);
    let lease = sandbox
        .host
        .start_child_work(
            &owner(),
            op("op-transfer"),
            LeaseKind::Transfer,
            lease_terms(),
        )
        .unwrap()
        .id();
    let lines = line_count(dir.path());

    // A later start passes the empty report of a first start, but the coordinator never
    // restarted: the first start ran on its clock session, so its lease is from before
    // this start, and it is still honoured.
    assert_eq!(
        JobControl::start(
            dir.path(),
            Incarnation::new(2),
            &catalog,
            &sandbox.host,
            &empty,
            &mut loader
        )
        .err(),
        Some(RecoveryError::LeaseSurvived { lease })
    );
    // A lease that may still be in use counts as surviving too, although a cancellation
    // means the coordinator no longer honours it.
    sandbox.host.release_lease(lease).unwrap();
    let cancelling = sandbox
        .host
        .start_child_work(
            &owner(),
            op("op-transfer-2"),
            LeaseKind::Transfer,
            lease_terms(),
        )
        .unwrap()
        .id();
    sandbox.host.raise_policy_epoch(&owner()).unwrap();
    assert!(sandbox.host.check_lease(cancelling).is_err());
    assert_eq!(
        JobControl::start(
            dir.path(),
            Incarnation::new(2),
            &catalog,
            &sandbox.host,
            &empty,
            &mut loader
        )
        .err(),
        Some(RecoveryError::LeaseSurvived { lease: cancelling })
    );
    sandbox.host.acknowledge_cancellation(cancelling).unwrap();
    // An allocation from before the start is refused the same way.
    let handle = sandbox.activate(model("chat"));
    assert_eq!(
        JobControl::start(
            dir.path(),
            Incarnation::new(2),
            &catalog,
            &sandbox.host,
            &empty,
            &mut loader
        )
        .err(),
        Some(RecoveryError::AllocationSurvived {
            handle: handle.clone()
        })
    );
    // No refused start journaled anything.
    assert_eq!(line_count(dir.path()), lines);

    // After a real restart the coordinator itself shows that its recovery revived no
    // lease and retired every activation, so the same empty report is enough, and the
    // report lists what was found from before the restart.
    let survivor = sandbox
        .host
        .start_child_work(
            &owner(),
            op("op-transfer-3"),
            LeaseKind::Transfer,
            lease_terms(),
        )
        .unwrap()
        .id();
    let (sandbox, recovered) = sandbox.restart(&clock);
    assert_eq!(recovered.leases_not_revived, [survivor]);
    assert_eq!(recovered.retired_activations, [handle.clone()]);
    let (control, report) = JobControl::start(
        dir.path(),
        Incarnation::new(2),
        &catalog,
        &sandbox.host,
        &empty,
        &mut loader,
    )
    .unwrap();
    assert_eq!(report.leases_not_revived, [survivor]);
    assert_eq!(report.stale_allocations, [handle]);
    assert_eq!(
        sandbox.host.check_lease(survivor).err(),
        Some(LeaseRefusal::NotRevived)
    );
    assert_eq!(
        control.state().started_on(sandbox.host.session()),
        Some(Incarnation::new(2))
    );
}

#[test]
fn a_restart_recovers_through_the_normal_loader() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = FakeCatalog::default();
    let mut loader = FakeLoader::default();
    let (mut control, _) = start(dir.path(), 1, &catalog, &mut loader);
    let committed = intent("op-a-committed", JobKind::Prepare, 300);
    let partial = intent("op-b-partial", JobKind::Load, 300);
    let vanished = intent("op-c-vanished", JobKind::Load, 300);
    let done = intent("op-d-done", JobKind::Load, 300);
    let cancelled = intent("op-e-cancelled", JobKind::Prepare, 300);
    let found = intent("op-f-found", JobKind::Load, 300);
    let quarantined = intent("op-g-quarantined", JobKind::Prepare, 300);
    for job in [
        &committed,
        &partial,
        &vanished,
        &done,
        &cancelled,
        &found,
        &quarantined,
    ] {
        control.submit(job.clone(), &mut loader).unwrap();
    }
    for job in [&committed, &vanished, &done, &quarantined] {
        control
            .record_artifact_commit(&job.operation, commit_of(job))
            .unwrap();
    }
    for index in 0..3 {
        control
            .record_verified_extent(
                &partial.operation,
                extent(index, u64::from(index) * 100, 100),
            )
            .unwrap();
    }
    let paused = ImportState {
        reached: Checkpoint::Extent { extent: 3 },
        progress: ImportProgress {
            verified_extents: 3,
            fetched_extents: 3,
            fetched_bytes: 300,
            ..ImportProgress::default()
        },
    };
    control
        .record_import_state(&partial.operation, paused)
        .unwrap();
    control
        .finish(&done.operation, JobOutcome::Completed)
        .unwrap();
    control.cancel(&cancelled.operation, &mut loader).unwrap();
    drop(control);

    // Actual state after the restart, as the catalog reports it: one journaled commit
    // is still published, one is gone and one is quarantined; one object the journal
    // never saw committed is published.
    for job in [&committed, &found] {
        catalog.set_status(job.scope(), job.object(), ObjectStatus::Published);
    }
    catalog.set_status(
        quarantined.scope(),
        quarantined.object(),
        ObjectStatus::Quarantined {
            reason: IntegrityFailure::ExtentCorrupt { extent: 1 },
        },
    );
    let mut loader = FakeLoader::default();
    let (mut control, report) = start(dir.path(), 2, &catalog, &mut loader);
    let incarnation = Incarnation::new(2);
    let committed_resume = ResumePoint {
        artifact_committed: true,
        ..ResumePoint::fresh()
    };
    assert_eq!(
        loader.submitted,
        [
            LoadRequest {
                intent: committed.clone(),
                resume: committed_resume.clone(),
                incarnation,
            },
            // Journaled extents travel as claims; the catalog's resumed import
            // re-verifies each before reuse.
            LoadRequest {
                intent: partial.clone(),
                resume: ResumePoint {
                    artifact_committed: false,
                    journaled_extents: (0..3)
                        .map(|index| extent(index, u64::from(index) * 100, 100))
                        .collect(),
                    import: Some(paused),
                },
                incarnation,
            },
            LoadRequest {
                intent: vanished.clone(),
                resume: ResumePoint::fresh(),
                incarnation,
            },
            LoadRequest {
                intent: found.clone(),
                resume: committed_resume,
                incarnation,
            },
            LoadRequest {
                intent: quarantined.clone(),
                resume: ResumePoint::fresh(),
                incarnation,
            },
        ]
    );
    assert_eq!(
        report.reimport,
        [vanished.operation.clone(), quarantined.operation.clone()]
    );
    assert_eq!(report.found_committed, [found.operation.clone()]);
    assert_eq!(
        control.state().job(&found.operation).unwrap().artifact(),
        Some(&commit_of(&found))
    );
    // A fresh job enters through the same loader call.
    let fresh = intent("op-h-fresh", JobKind::Load, 300);
    control.submit(fresh.clone(), &mut loader).unwrap();
    assert_eq!(
        loader.submitted.last(),
        Some(&LoadRequest {
            intent: fresh,
            resume: ResumePoint::fresh(),
            incarnation,
        })
    );
    drop(control);

    // Without the catalog nothing is assumed: the start fails, and a later one recovers.
    catalog.unavailable = true;
    assert!(matches!(
        try_start(dir.path(), 3, &catalog, &mut loader).err(),
        Some(RecoveryError::Port(PortError {
            port: PortName::Catalog,
            ..
        }))
    ));
    catalog.unavailable = false;
    let mut loader = FakeLoader::default();
    let (_, report) = start(dir.path(), 4, &catalog, &mut loader);
    assert_eq!(report.resubmitted.len(), 6);
}

/// Accepts every structure and no publisher: only user-selected originals get in.
struct AnyStructure;

impl ArtifactVerifier for AnyStructure {
    fn class(&self) -> ArtifactClass {
        ArtifactClass::ModelWeights
    }

    fn authenticate(
        &self,
        _content: &ContentDescriptor,
        _publisher: &PublisherId,
        _attestation: &[u8],
    ) -> Result<(), VerifierRejection> {
        Err(VerifierRejection::AttestationInvalid)
    }

    fn validate(
        &self,
        _content: &ContentDescriptor,
        _bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        Ok(())
    }
}

struct MemorySource {
    identity: SourceIdentity,
    bytes: Vec<u8>,
}

impl ImportSource for MemorySource {
    fn identity(&self) -> SourceIdentity {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        Ok(self.bytes.len() as u64)
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        let start = usize::try_from(offset_bytes).unwrap().min(self.bytes.len());
        let end = (start + buffer.len()).min(self.bytes.len());
        buffer[..end - start].copy_from_slice(&self.bytes[start..end]);
        Ok(end - start)
    }
}

#[test]
fn a_restart_reads_actual_state_from_the_real_catalog() {
    let clock = new_clock();
    let scope = Scope::tenant(TenantId::new("tenant-1").unwrap());
    let mut verifiers = VerifierRegistry::new();
    verifiers.register(Box::new(AnyStructure)).unwrap();
    let config = CatalogConfig::new(Duration::from_secs(60))
        .with_quota(scope.clone(), 1 << 20)
        .with_trust(
            ArtifactClass::ModelWeights,
            TrustPolicy::new().accept_user_selected(),
        );
    let root = tempfile::tempdir().unwrap();
    let (mut catalog, _) = Catalog::open(root.path(), config, verifiers, clock.clone()).unwrap();
    // The catalog published one job's weights before the daemon could journal it.
    let bytes = b"weights of the published model".to_vec();
    let published = JobIntent {
        content: ContentKey::of(&bytes),
        total_bytes: bytes.len() as u64,
        ..intent("op-published", JobKind::Prepare, 1)
    };
    let mut source = MemorySource {
        identity: SourceIdentity::describe("test", "published-model"),
        bytes: bytes.clone(),
    };
    let request = ImportRequest {
        operation: published.operation.clone(),
        execution: published.execution.clone(),
        scope: scope.clone(),
        class: ArtifactClass::ModelWeights,
        role: ObjectRole::Original,
        manifest: ImportManifest::describe(&bytes, NonZeroU64::new(8).unwrap()),
        trust: TrustClaim::UserSelected,
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    };
    let ImportStart::Started(ticket) = catalog.begin_import(request, source.identity).unwrap()
    else {
        panic!("the import did not start");
    };
    assert!(matches!(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
        ImportStatus::Published { object, .. } if object == published.object()
    ));

    let dir = tempfile::tempdir().unwrap();
    let mut loader = FakeLoader::default();
    let (mut control, _) = start(dir.path(), 1, &catalog, &mut loader);
    let missing = intent("op-missing", JobKind::Load, 300);
    control.submit(published.clone(), &mut loader).unwrap();
    control.submit(missing.clone(), &mut loader).unwrap();
    control
        .record_verified_extent(&missing.operation, extent(0, 0, 100))
        .unwrap();
    drop(control);

    let mut loader = FakeLoader::default();
    let (control, report) = start(dir.path(), 2, &catalog, &mut loader);
    assert_eq!(report.found_committed, [published.operation.clone()]);
    assert_eq!(
        control
            .state()
            .job(&published.operation)
            .unwrap()
            .artifact(),
        Some(&commit_of(&published))
    );
    let resumes: Vec<(&OperationId, bool, usize)> = loader
        .submitted
        .iter()
        .map(|request| {
            (
                &request.intent.operation,
                request.resume.artifact_committed,
                request.resume.journaled_extents.len(),
            )
        })
        .collect();
    assert_eq!(
        resumes,
        [
            (&missing.operation, false, 1),
            (&published.operation, true, 0)
        ]
    );
    // The same content in another tenant's scope is another object, absent there.
    let other = JobIntent {
        tenant: TenantId::new("tenant-2").unwrap(),
        ..published.clone()
    };
    assert_eq!(
        catalog
            .object_status(&other.scope(), other.object())
            .unwrap(),
        ObjectStatus::Absent
    );
}

#[test]
fn progress_from_before_a_restart_is_stale() {
    let clock = new_clock();
    let dir = tempfile::tempdir().unwrap();
    let catalog = FakeCatalog::default();
    let mut loader = FakeLoader::default();
    let (mut control, first) = start(dir.path(), 1, &catalog, &mut loader);
    let load = intent("op-load", JobKind::Load, 300 * MB);
    control.submit(load.clone(), &mut loader).unwrap();
    let mut before = hub_with(&clock, first.incarnation.get(), 512);
    let mut publisher = publisher_on(&mut before, &clock, first.incarnation.get());
    publisher
        .track(
            &mut before,
            &load.operation,
            request(weights("m"), 300 * MB, queued_for_gpu(GB)),
        )
        .unwrap();
    publisher
        .set_stage(&mut before, &load.operation, from_local_storage())
        .unwrap();
    let mut receiver = Receiver::new();
    receiver.apply_snapshot(&publisher.snapshot(&mut before).unwrap(), 0);
    clock.advance(Duration::from_secs(1));
    publisher
        .extent_arrived(&mut before, &load.operation, 0, 100 * MB)
        .unwrap();
    // Still in flight when the daemon stops.
    let late = before.drain(0).progress;
    let old_snapshot = before.progress_snapshot();
    drop(control);

    // The daemon restarts under incarnation 2, and so does its event plane.
    let (_, report) = start(dir.path(), 2, &catalog, &mut loader);
    assert_eq!(report.resubmitted, [load.operation.clone()]);
    // A progress producer registered under another incarnation is refused.
    let mut unrestarted = hub_with(&clock, 1, 512);
    let producer = unrestarted
        .register_progress(producer_id(), SourceClass::HostProbe, None)
        .unwrap();
    assert_eq!(
        ProgressPublisher::new(
            producer,
            report.incarnation,
            clock.clone(),
            clock_id(),
            PublishPolicy::default()
        )
        .err(),
        Some(PublishError::WrongIncarnation {
            producer: ProducerIncarnation::FIRST,
            daemon: report.incarnation
        })
    );
    let mut after = hub_with(&clock, report.incarnation.get(), 512);
    let mut publisher = publisher_on(&mut after, &clock, report.incarnation.get());
    // The recovered job waits for fresh authority: no lease survived.
    publisher
        .track(
            &mut after,
            &load.operation,
            request(
                weights("m"),
                300 * MB,
                Stage::queued(QueueReason::Authorization),
            ),
        )
        .unwrap();
    for update in &after.drain(0).progress.updates {
        assert_eq!(receiver.receive(update), Arrival::Fresh);
    }
    // Late events and a snapshot from before the restart change nothing.
    for update in &late.updates {
        assert_eq!(receiver.receive(update), Arrival::RetiredIncarnation);
    }
    receiver.apply_snapshot(&old_snapshot, 0);
    assert_eq!(
        receiver
            .position(&load.operation)
            .map(|(incarnation, _)| incarnation),
        ProducerIncarnation::new(2)
    );
    let public = receiver.public(&load.operation).unwrap();
    assert_eq!(public.message(), "waiting for authorization");
    assert_eq!(public.state(), Some(ClientState::Queued));
}

// Rule 5: plain-language public states.

#[test]
fn public_states_speak_plain_language() {
    let clock = new_clock();
    let (mut hub, mut publisher) = daemon(&clock);
    let operation = op("op-load");
    publisher
        .track(
            &mut hub,
            &operation,
            request(weights("m"), 8 * GB, queued_for_gpu(4 * GB)),
        )
        .unwrap();
    let shown = |publisher: &Publisher| {
        let (phase, update) = publisher.progress(&operation).unwrap();
        PublicProgress::new(phase, &update)
    };
    let waiting = shown(&publisher);
    assert_eq!(waiting.message(), "waiting for 4 GB of GPU memory");
    assert_eq!(waiting.state(), Some(ClientState::Queued));
    publisher
        .set_stage(&mut hub, &operation, from_local_storage())
        .unwrap();
    let restoring = shown(&publisher);
    assert_eq!(restoring.message(), "restoring weights from local storage");
    assert_eq!(restoring.state(), Some(ClientState::LoadingModel));
    // A receiver of the event reads the same words.
    let delivered = hub.drain(0).progress.updates;
    assert_eq!(
        PublicProgress::from_event(delivered.last().unwrap()),
        restoring
    );
    for (stage, message, state) in [
        (
            Stage::queued(QueueReason::HostMemory {
                needed_bytes: 8 * GB,
            }),
            "waiting for 8 GB of host memory",
            ClientState::Queued,
        ),
        (
            Stage::queued(QueueReason::EarlierRequests { requests_ahead: 2 }),
            "waiting for 2 earlier requests",
            ClientState::Queued,
        ),
        (
            Stage::at(Phase::Reserving),
            "reserving memory for weights",
            ClientState::FreeingMemory,
        ),
        (
            Stage::from_source(Phase::Transferring, DataSource::RemoteDownload),
            "transferring weights from a download",
            ClientState::LoadingModel,
        ),
        (
            Stage::at(Phase::Activating),
            "activating weights",
            ClientState::LoadingModel,
        ),
    ] {
        publisher.set_stage(&mut hub, &operation, stage).unwrap();
        let public = shown(&publisher);
        assert_eq!((public.message(), public.state()), (message, Some(state)));
    }
}

#[test]
fn todays_client_states_stay_valid_and_new_states_are_additive() {
    // Appendix A.1: the five states the website and clients accept today.
    let today = [
        "queued",
        "freeing_memory",
        "loading_model",
        "generating",
        "retrying",
    ];
    assert_eq!(ClientState::ALL.map(ClientState::as_str), today);
    for phase in Phase::ALL {
        let mut update = ProgressUpdate::new(
            weights("m"),
            ResourceKind::Weights,
            GB,
            Some(GB),
            GB,
            CancellationBoundary::Anytime,
        );
        if phase == Phase::Queued {
            update = update.queued_for(QueueReason::TransferSlot);
        }
        assert_eq!(update.validate(phase), Ok(()), "{phase}");
        let json = serde_json::to_value(PublicProgress::new(phase, &update)).unwrap();
        // `state` is one of today's five, or absent once the operation has ended; the
        // phase travels in a field of its own.
        let state = json.get("state").and_then(Value::as_str);
        assert_eq!(state.is_none(), phase.is_terminal(), "{phase}");
        assert!(
            state.map_or(true, |state| today.contains(&state)),
            "{phase}"
        );
        assert_eq!(json["phase"], phase.name());
        assert!(!json["message"].as_str().unwrap().is_empty(), "{phase}");
    }
    // Clients still read every one of today's values, and nothing new appears in their
    // place.
    for state in today {
        assert!(serde_json::from_value::<ClientState>(json!(state)).is_ok());
    }
    assert!(serde_json::from_value::<ClientState>(json!("recovering")).is_err());
}

#[test]
fn public_progress_never_exposes_handles() {
    let clock = new_clock();
    let mut sandbox = SandboxHost::launch(&clock);
    let handle = sandbox.activate(model("chat"));
    let (mut hub, mut publisher) = daemon(&clock);
    let operation = op("op-load");
    publisher
        .track(
            &mut hub,
            &operation,
            request(weights("m"), 300 * MB, queued_for_gpu(GB)),
        )
        .unwrap();
    publisher
        .set_allocation(&mut hub, &sandbox.host, &operation, &handle)
        .unwrap();
    publisher
        .set_stage(&mut hub, &operation, from_local_storage())
        .unwrap();
    for index in 0..3 {
        clock.advance(Duration::from_secs(1));
        publisher
            .extent_arrived(&mut hub, &operation, index, 50 * MB)
            .unwrap();
        publisher
            .extent_committed(&mut hub, &operation, index)
            .unwrap();
    }
    let snapshot = publisher.snapshot(&mut hub).unwrap();
    let event = &snapshot.states[0];
    // The event carries generations for receivers that reconcile; the public view
    // leaves them out, with every other identity.
    assert_eq!(event.generations(), &generations_of(&handle));
    let json = serde_json::to_value(PublicProgress::from_event(event)).unwrap();
    let mut names = Vec::new();
    keys(&json, &mut names);
    for name in &names {
        for word in [
            "handle",
            "pointer",
            "allocation",
            "generation",
            "lease",
            "resource",
            "identity",
            "operation",
            "producer",
            "sequence",
            "stage",
            "duration",
            "event",
        ] {
            assert!(!name.contains(word), "public output exposes {name}");
        }
    }
    let mut found = Vec::new();
    texts(&json, &mut found);
    assert!(found.iter().all(|text| !is_digest(text)));
    assert_eq!(json["message"], "restoring weights from local storage");
    assert_eq!(json["usable_bytes"], 150 * MB);
}

#[test]
fn stage_timing_appears_only_in_benchmark_or_debug_output() {
    let clock = new_clock();
    let (mut hub, mut publisher) = daemon(&clock);
    let operation = op("op-load");
    publisher
        .track(
            &mut hub,
            &operation,
            request(weights("m"), 200 * MB, queued_for_gpu(GB)),
        )
        .unwrap();
    clock.advance(Duration::from_secs(5));
    publisher
        .set_stage(&mut hub, &operation, Stage::at(Phase::Reserving))
        .unwrap();
    clock.advance(Duration::from_secs(2));
    publisher
        .set_stage(&mut hub, &operation, from_local_storage())
        .unwrap();
    for index in 0..2 {
        clock.advance(Duration::from_secs(5));
        publisher
            .extent_arrived(&mut hub, &operation, index, 100 * MB)
            .unwrap();
        publisher
            .extent_committed(&mut hub, &operation, index)
            .unwrap();
    }
    publisher
        .set_stage(&mut hub, &operation, Stage::at(Phase::Activating))
        .unwrap();
    let running = publisher
        .diagnostics(&operation, DiagnosticLevel::Debug)
        .unwrap();
    let ready_latency = &running.intervals[1];
    assert_eq!(ready_latency.kind, IntervalKind::ReadyLatency);
    assert_eq!(
        ready_latency.measured.reason(),
        Some(NotMeasuredReason::NotRecorded)
    );
    clock.advance(Duration::from_secs(3));
    publisher
        .set_stage(&mut hub, &operation, Stage::at(Phase::Completed))
        .unwrap();

    // Public output has no timing at all.
    let (phase, update) = publisher.progress(&operation).unwrap();
    let mut names = Vec::new();
    keys(
        &serde_json::to_value(PublicProgress::new(phase, &update)).unwrap(),
        &mut names,
    );
    assert!(names.iter().all(
        |name| !["stages", "intervals", "events", "duration_seconds"].contains(&name.as_str())
    ));

    // Debug and benchmark output show each stage, the queue wait separately (S8), and
    // the §2.1 boundaries on the CORE-08 monotonic clock.
    let debug = publisher
        .diagnostics(&operation, DiagnosticLevel::Benchmark)
        .unwrap();
    let seconds = |phase: Phase| {
        debug
            .stages
            .iter()
            .find(|stage| stage.phase == phase)
            .map(|stage| stage.duration_seconds)
    };
    assert_eq!(seconds(Phase::Queued), Some(5.0));
    assert_eq!(seconds(Phase::Reserving), Some(2.0));
    assert_eq!(seconds(Phase::Restoring), Some(10.0));
    assert_eq!(seconds(Phase::Activating), Some(3.0));
    assert_eq!(seconds(Phase::Completed), Some(0.0));
    let interval = |kind: IntervalKind| {
        debug
            .intervals
            .iter()
            .find(|interval| interval.kind == kind)
            .and_then(|interval| interval.measured.value())
            .map(|measured| measured.seconds())
    };
    // Placement requested at 0 s, every weight usable at 17 s; activation 17 s to 20 s.
    assert_eq!(interval(IntervalKind::WeightAvailability), Some(17.0));
    assert_eq!(interval(IntervalKind::ReadyLatency), Some(3.0));
    let names: Vec<EventName> = debug
        .events
        .iter()
        .map(|event| event.event.name())
        .collect();
    assert_eq!(
        names,
        [
            EventName::PlacementRequested,
            EventName::WeightsUsable,
            EventName::ActivationRequested,
            EventName::EngineReadyForShape,
        ]
    );
    assert_eq!(
        debug.events.last().unwrap().at_nanos,
        MonotonicTime::from_nanos(20_000_000_000)
    );
}

// Rules the publisher keeps on its own.

#[test]
fn generations_only_move_forward_and_a_new_allocation_restarts_bytes() {
    let clock = new_clock();
    let mut sandbox = SandboxHost::launch(&clock);
    let first = sandbox.activate(model("chat"));
    let second = sandbox.activate(model("chat"));
    let (mut hub, mut publisher) = daemon(&clock);
    let operation = op("op-load");
    publisher
        .track(
            &mut hub,
            &operation,
            request(weights("m"), 200 * MB, from_local_storage()),
        )
        .unwrap();
    publisher
        .set_allocation(&mut hub, &sandbox.host, &operation, &second)
        .unwrap();
    publisher
        .extent_arrived(&mut hub, &operation, 0, 100 * MB)
        .unwrap();
    publisher.extent_committed(&mut hub, &operation, 0).unwrap();
    assert_eq!(
        publisher.set_allocation(&mut hub, &sandbox.host, &operation, &first),
        Err(PublishError::GenerationWentBack)
    );
    // Another model's allocation is not this operation's.
    let other = sandbox.activate(model("embed"));
    assert_eq!(
        publisher.set_allocation(&mut hub, &sandbox.host, &operation, &other),
        Err(PublishError::AllocationConflict)
    );
    // Clearing the allocation discards the bytes in it; the old value never returns.
    publisher.clear_allocation(&mut hub, &operation).unwrap();
    assert_eq!(
        publisher
            .progress(&operation)
            .unwrap()
            .1
            .committed_usable_bytes(),
        0
    );
    assert_eq!(
        publisher.set_allocation(&mut hub, &sandbox.host, &operation, &second),
        Err(PublishError::GenerationWentBack)
    );
    let third = sandbox.activate(model("chat"));
    publisher
        .set_allocation(&mut hub, &sandbox.host, &operation, &third)
        .unwrap();
    assert_eq!(
        publisher.generations(&operation).unwrap(),
        generations_of(&third)
    );
    // A new allocation restarts byte progress.
    publisher
        .extent_arrived(&mut hub, &operation, 0, 100 * MB)
        .unwrap();
    publisher.extent_committed(&mut hub, &operation, 0).unwrap();
    let fourth = sandbox.activate(model("chat"));
    publisher
        .set_allocation(&mut hub, &sandbox.host, &operation, &fourth)
        .unwrap();
    let (_, update) = publisher.progress(&operation).unwrap();
    assert_eq!(
        (update.completed_bytes(), update.committed_usable_bytes()),
        (0, 0)
    );
    // Usable bytes never fall within one allocation: a committed extent stays.
    publisher
        .extent_arrived(&mut hub, &operation, 0, 100 * MB)
        .unwrap();
    publisher.extent_committed(&mut hub, &operation, 0).unwrap();
    assert_eq!(
        publisher.extent_discarded(&mut hub, &operation, 0),
        Err(PublishError::CommittedExtentDiscarded { index: 0 })
    );
    assert_eq!(
        publisher.extent_committed(&mut hub, &operation, 1),
        Err(PublishError::ExtentNotArrived { index: 1 })
    );
    assert_eq!(
        publisher.extent_arrived(&mut hub, &operation, 1, 101 * MB),
        Err(PublishError::BytesExceedTotal)
    );
    assert_eq!(
        publisher.extent_started(&mut hub, &operation, 1, 101 * MB),
        Err(PublishError::BytesExceedTotal)
    );
    // A model generates only with every byte usable, and CORE-06 completes an
    // operation only then.
    assert_eq!(
        publisher.set_stage(&mut hub, &operation, Stage::at(Phase::Running)),
        Err(PublishError::NotAllUsable {
            phase: Phase::Running
        })
    );
    assert!(matches!(
        publisher.set_stage(&mut hub, &operation, Stage::at(Phase::Completed)),
        Err(PublishError::Invalid(
            ProgressError::CompletedNotWhole { .. }
        ))
    ));
    publisher
        .set_stage(&mut hub, &operation, Stage::at(Phase::Activating))
        .unwrap();
    assert_eq!(
        publisher.extent_arrived(&mut hub, &operation, 1, 100 * MB),
        Err(PublishError::BytesOutsideTransfer {
            phase: Phase::Activating
        })
    );
    publisher
        .set_stage(&mut hub, &operation, Stage::at(Phase::Failed))
        .unwrap();
    assert_eq!(
        publisher.set_stage(&mut hub, &operation, from_local_storage()),
        Err(PublishError::Ended)
    );
    assert_eq!(
        publisher
            .set_stage(&mut hub, &operation, Stage::at(Phase::Failed))
            .unwrap(),
        PublishOutcome::Unchanged
    );
    // An ended operation has no remaining time.
    assert_eq!(publisher.progress(&operation).unwrap().1.eta(), None);
}

#[test]
fn the_cancellation_boundary_follows_the_stage_and_the_copies_in_flight() {
    let clock = new_clock();
    let (mut hub, mut publisher) = daemon(&clock);
    let operation = op("op-load");
    publisher
        .track(
            &mut hub,
            &operation,
            request(weights("m"), 300 * MB, queued_for_gpu(GB)),
        )
        .unwrap();
    let boundary = |publisher: &Publisher| publisher.progress(&operation).unwrap().1.cancellation();
    assert_eq!(boundary(&publisher), CancellationBoundary::Anytime);
    publisher
        .set_stage(&mut hub, &operation, from_local_storage())
        .unwrap();
    publisher
        .extent_started(&mut hub, &operation, 0, 100 * MB)
        .unwrap();
    publisher
        .extent_started(&mut hub, &operation, 1, 100 * MB)
        .unwrap();
    // Two copies in flight: a cancellation takes effect once 200 MB have arrived.
    assert_eq!(
        boundary(&publisher),
        CancellationBoundary::AtCompletedBytes {
            completed_bytes: 200 * MB
        }
    );
    // Bytes may keep moving from another source, but the copies in flight arrive or are
    // discarded before the operation does anything else.
    publisher
        .set_stage(
            &mut hub,
            &operation,
            Stage::from_source(Phase::Transferring, DataSource::RemoteDownload),
        )
        .unwrap();
    assert_eq!(
        boundary(&publisher),
        CancellationBoundary::AtCompletedBytes {
            completed_bytes: 200 * MB
        }
    );
    for stage in [Stage::at(Phase::Activating), queued_for_gpu(GB)] {
        assert_eq!(
            publisher.set_stage(&mut hub, &operation, stage),
            Err(PublishError::CopiesInFlight {
                in_flight_bytes: 200 * MB
            })
        );
    }
    publisher
        .extent_arrived(&mut hub, &operation, 0, 100 * MB)
        .unwrap();
    publisher.extent_discarded(&mut hub, &operation, 1).unwrap();
    // Arrived bytes still being verified do not hold a cancellation back: unverified
    // bytes are discarded, never used.
    assert_eq!(boundary(&publisher), CancellationBoundary::Anytime);
    publisher.extent_committed(&mut hub, &operation, 0).unwrap();
    // Activation is atomic: it completes or rolls back first (§3.6 step 5).
    publisher
        .set_stage(&mut hub, &operation, Stage::at(Phase::Activating))
        .unwrap();
    assert_eq!(boundary(&publisher), CancellationBoundary::EndOfPhase);
    publisher
        .set_stage(&mut hub, &operation, Stage::at(Phase::Cancelled))
        .unwrap();
    assert_eq!(boundary(&publisher), CancellationBoundary::Anytime);
}

#[test]
fn a_publisher_needs_a_policy_that_can_estimate() {
    let clock = new_clock();
    let mut hub = hub_with(&clock, 1, 8);
    for policy in [
        PublishPolicy {
            min_publish_interval: Duration::ZERO,
            ..PublishPolicy::default()
        },
        PublishPolicy {
            max_operations: 0,
            ..PublishPolicy::default()
        },
        PublishPolicy {
            eta_window_samples: MIN_SEGMENTS_FOR_ESTIMATE,
            ..PublishPolicy::default()
        },
    ] {
        let producer = hub
            .register_progress(producer_id(), SourceClass::HostProbe, None)
            .unwrap();
        // Each registration is a new incarnation of the producer.
        let incarnation = Incarnation::new(producer.key().incarnation.get());
        assert_eq!(
            ProgressPublisher::new(producer, incarnation, clock.clone(), clock_id(), policy).err(),
            Some(PublishError::InvalidPolicy)
        );
    }
}
