//! The resource adapters: the V02 release account, the connections gate's outgoing
//! connections and the file service's usage counts as V14 resource readings, each fed
//! through V14's sustained windows and responder (VM part §2.5, §4.7, §5.1, §8.2; VM-W43;
//! M17B).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::Duration;

use super::fixtures::*;
use super::*;
use crate::foundation::evidence::NetworkGrant;
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, ExecutionId, GrantId, ManualClock, MonotonicTime,
    PolicyEpoch,
};
use crate::foundation::transfer::GeneralReleaseBudget;
use crate::sandbox_contract::connections::{
    ConnectionAuthority, ConnectionBudget, ConnectionGate, ConnectionId, ConnectionRequest,
    SandboxRegistration, SessionStream, StreamError, StreamRead,
};
use crate::sandbox_contract::destinations::{
    ChannelPolicy, ConnectionGrant, DestinationPort, InFlightAllowance, NetworkMode,
    ReleaseAccount, ReleaseChannel, ReleaseTrustClass, SandboxEndpoint, ServiceIdentity,
};
use crate::sandbox_contract::files::{
    FileGrant, FileOperation, FileQuota, FileService, GrantMode, GrantedRoot, QuotaUsage,
    RootHandle, SandboxClass,
};
use crate::sandbox_contract::response::{
    DecisionReason, HostObserver, MonitoredResource, Reading, ResourceMonitor, ResourceObservation,
    ResponseAction, SeriesKey, SignalAssessment, SignalClass, SignalSource, SustainedWindow,
};

// ---------------------------------------------------------------------------------------
// Shared

/// A monitor on the host session judging `resource` over `window`.
fn monitor(resource: MonitoredResource, window: SustainedWindow) -> ResourceMonitor {
    ResourceMonitor::new(
        host_session(),
        &uncertain(),
        BTreeMap::from([(resource, window)]),
        16,
    )
    .unwrap()
}

/// Feeds a reading's draft into `monitor` at the clock's time.
fn feed(
    monitor: &mut ResourceMonitor,
    reading: ResourceReading,
    now: &ManualClock,
) -> ResourceObservation {
    monitor
        .observe(&signal(reading.into_draft().unwrap()), now)
        .unwrap()
}

fn triggered(observation: ResourceObservation) -> SignalAssessment {
    match observation {
        ResourceObservation::Triggered { assessment, .. } => assessment,
        other => panic!("expected a trigger, got {other:?}"),
    }
}

fn held(observation: &ResourceObservation) -> bool {
    matches!(observation, ResourceObservation::Held { .. })
}

/// The V14 response to a resource assessment about task sandbox `exe-a`.
fn respond(
    assessment: &SignalAssessment,
    now: &ManualClock,
) -> crate::sandbox_contract::response::ResponseRecord {
    let mut responder = responder_with(now, &[("exe-a", SandboxClass::Task, &[])]);
    responded(responder.respond_to(assessment).unwrap())
}

/// Checks the parts every reading shares: the sandbox, the class, the host observer, V14's
/// series subject, the host clock's time and session, no grant, and V14's acceptance.
fn assert_reading(
    reading: &ResourceReading,
    resource: MonitoredResource,
    observer: HostObserver,
    now: &ManualClock,
) {
    let draft = reading.draft().unwrap();
    assert_eq!(draft.sandbox, execution("exe-a"));
    assert_eq!(draft.class, SignalClass::Resource { resource });
    assert_eq!(draft.source, SignalSource::HostObserved { observer });
    assert_eq!(draft.subject, SeriesKey::subject(resource));
    assert_eq!(draft.observed_at, now.now());
    assert_eq!(draft.session, host_session());
    assert_eq!(draft.violated_grant, None);
    assert!(matches!(draft.reading, Reading::Amount { .. }));
    signal(draft.clone());
}

#[test]
fn every_v14_resource_is_either_measured_by_a_committed_source_or_listed_open() {
    let measured: BTreeSet<MonitoredResource> = MEASURED_RESOURCES
        .iter()
        .map(|(resource, _)| *resource)
        .collect();
    let open: BTreeSet<MonitoredResource> = OPEN_RESOURCES.into_iter().collect();
    assert_eq!(measured.len(), MEASURED_RESOURCES.len());
    assert_eq!(open.len(), OPEN_RESOURCES.len());
    assert!(measured.is_disjoint(&open));
    assert_eq!(
        measured.union(&open).copied().collect::<BTreeSet<_>>(),
        MonitoredResource::ALL.into_iter().collect::<BTreeSet<_>>()
    );
    // Each measured resource names an observer V14 accepts for it.
    for (resource, observer) in MEASURED_RESOURCES {
        assert!(
            resource.host_observers().contains(&observer),
            "{resource:?}"
        );
    }
    assert_eq!(
        MEASURED_RESOURCES,
        [
            (
                MonitoredResource::ReleaseBudgetSpentBytes,
                HostObserver::Broker
            ),
            (
                MonitoredResource::ConnectionsPerSecond,
                HostObserver::Perimeter
            ),
            (MonitoredResource::DiskBytes, HostObserver::Supervisor),
            (
                MonitoredResource::CpuMillicores,
                HostObserver::HypervisorCounters
            ),
            (
                MonitoredResource::MemoryBytes,
                HostObserver::HypervisorCounters
            ),
            (MonitoredResource::ProcessCount, HostObserver::Supervisor),
        ]
    );
}

// ---------------------------------------------------------------------------------------
// The V02 release account

fn account() -> ReleaseAccount {
    ReleaseAccount::new(
        BTreeMap::from([(
            ReleaseChannel::ProviderRequest,
            ChannelPolicy {
                budget_bytes: 10_000,
                trust_class: ReleaseTrustClass::External,
            },
        )]),
        GeneralReleaseBudget::with_limit(100_000),
        InFlightAllowance {
            bytes: 5,
            documented_reason: "TLS framing is sized when sent".into(),
        },
    )
    .unwrap()
}

#[test]
fn a_release_reading_is_the_accounts_counted_bytes_by_the_broker() {
    let now = clock();
    let mut release = account();
    let reading = release_spent_reading(&release, &observed("exe-a", &now));
    assert_eq!(reading.amount(), Some(0));
    assert_reading(
        &reading,
        MonitoredResource::ReleaseBudgetSpentBytes,
        HostObserver::Broker,
        &now,
    );
    release
        .charge(ReleaseChannel::ProviderRequest, 300)
        .unwrap();
    // Bytes past a reservation within the allowance count too.
    let reservation = release
        .reserve(ReleaseChannel::ProviderRequest, 100)
        .unwrap();
    release.commit(reservation, 104).unwrap();
    now.advance(SECOND);
    let reading = release_spent_reading(&release, &observed("exe-a", &now));
    assert_eq!(reading.amount(), Some(404));
    assert_eq!(reading.ordinary(), None);
    // An overrun closes the account; its bytes are counted and the reading keeps them.
    let reservation = release
        .reserve(ReleaseChannel::ProviderRequest, 10)
        .unwrap();
    assert!(release.commit(reservation, 30).is_err());
    assert!(release.is_closed());
    now.advance(SECOND);
    let reading = release_spent_reading(&release, &observed("exe-a", &now));
    assert_eq!(reading.amount(), Some(release.counted_bytes_out()));
    assert_eq!(reading.amount(), Some(434));
}

#[test]
fn a_release_budget_spent_for_the_sustain_window_notifies_and_denies_new_high_impact() {
    let now = clock();
    let resource = MonitoredResource::ReleaseBudgetSpentBytes;
    let mut monitor = monitor(
        resource,
        SustainedWindow {
            high_mark: 1_000,
            low_mark: 500,
            sustain_seconds: 30,
            clear_seconds: 30,
            max_sample_gap_seconds: 10,
        },
    );
    let mut release = account();
    // Under the high mark nothing rises.
    release
        .charge(ReleaseChannel::ProviderRequest, 999)
        .unwrap();
    let observation = feed(
        &mut monitor,
        release_spent_reading(&release, &observed("exe-a", &now)),
        &now,
    );
    assert!(held(&observation), "{observation:?}");
    release
        .charge(ReleaseChannel::ProviderRequest, 201)
        .unwrap();
    for _ in 0..3 {
        now.advance(10 * SECOND);
        let observation = feed(
            &mut monitor,
            release_spent_reading(&release, &observed("exe-a", &now)),
            &now,
        );
        assert!(held(&observation), "{observation:?}");
    }
    now.advance(10 * SECOND);
    let assessment = triggered(feed(
        &mut monitor,
        release_spent_reading(&release, &observed("exe-a", &now)),
        &now,
    ));
    assert!(assessment.freshness().is_fresh());
    let record = respond(&assessment, &now);
    assert_eq!(
        record.decision.actions,
        BTreeSet::from([
            ResponseAction::NotifyUser,
            ResponseAction::DenyNewHighImpact
        ])
    );
    assert_eq!(
        record.decision.reason,
        DecisionReason::SustainedResource {
            resource,
            observer: HostObserver::Broker
        }
    );
}

// ---------------------------------------------------------------------------------------
// The connections gate

/// CORE-04 as the gate reads it: every sandbox holds the first epochs and every network
/// grant, on the test clock.
struct HeldAuthority<'a> {
    clock: &'a ManualClock,
}

impl ConnectionAuthority for HeldAuthority<'_> {
    fn now(&self) -> MonotonicTime {
        self.clock.now()
    }

    fn current_epoch(&self, _sandbox: &ExecutionId) -> Option<AuthorizationEpoch> {
        Some(AuthorizationEpoch::FIRST)
    }

    fn current_policy(&self, _sandbox: &ExecutionId) -> Option<PolicyEpoch> {
        Some(PolicyEpoch::FIRST)
    }

    fn holds_network_grant(&self, _sandbox: &ExecutionId, _grant: &NetworkGrant) -> bool {
        true
    }

    fn grant_revoked(&self, _sandbox: &ExecutionId, _grant: GrantId) -> bool {
        false
    }
}

/// A stream end with nothing to read that accepts every write.
struct QuietStream;

impl SessionStream for QuietStream {
    fn read(&mut self, _buffer: &mut [u8]) -> Result<StreamRead, StreamError> {
        Ok(StreamRead::Idle)
    }

    fn write(&mut self, _bytes: &[u8]) -> Result<(), StreamError> {
        Ok(())
    }

    fn finish(&mut self) {}

    fn close(&mut self) {}
}

fn service() -> ServiceIdentity {
    ServiceIdentity::new("api").unwrap()
}

fn port() -> DestinationPort {
    DestinationPort::new(8000).unwrap()
}

fn endpoint(sandbox: &str) -> SandboxEndpoint {
    SandboxEndpoint {
        execution: execution(sandbox),
        scope: scope_of(sandbox),
    }
}

/// A gate with `sandboxes` attached, each offering the API, and both grants recorded for
/// every ordered pair of them.
fn gate_with(authority: &HeldAuthority<'_>, sandboxes: &[&str]) -> ConnectionGate {
    let mut gate = ConnectionGate::new();
    for sandbox in sandboxes {
        gate.attach(
            authority,
            SandboxRegistration {
                endpoint: endpoint(sandbox),
                mode: NetworkMode::DeclaredTransport,
                max_publication_lifetime: Duration::from_secs(3_600),
                published_services: BTreeSet::from([service()]),
            },
        )
        .unwrap();
    }
    for caller in sandboxes {
        for callee in sandboxes.iter().filter(|callee| *callee != caller) {
            let allowed = ConnectionGrant {
                caller: endpoint(caller),
                callee: endpoint(callee),
                service: service(),
                port: port(),
                expires_at: at(START_SECONDS + 86_400),
            };
            gate.grant_outbound(authority, allowed.clone()).unwrap();
            gate.grant_inbound(authority, allowed).unwrap();
        }
    }
    gate
}

/// Opens one connection from `caller` to `callee`.
fn connect(
    gate: &mut ConnectionGate,
    authority: &HeldAuthority<'_>,
    caller: &str,
    callee: &str,
) -> ConnectionId {
    gate.connect(
        authority,
        ConnectionRequest {
            caller: execution(caller),
            callee: execution(callee),
            service: service(),
            port: port(),
            budget: ConnectionBudget {
                caller_to_callee_bytes: 100,
                callee_to_caller_bytes: 100,
            },
        },
        Box::new(QuietStream),
        Box::new(QuietStream),
    )
    .unwrap()
    .id()
}

fn count(gate: &ConnectionGate, sandbox: &str, now: &ManualClock) -> ConnectionCount {
    ConnectionCount::of_gate(gate, observed(sandbox, now))
}

#[test]
fn a_connection_rate_counts_only_the_connections_the_guest_opened_by_the_perimeter() {
    let now = clock();
    let authority = HeldAuthority { clock: &now };
    let mut gate = gate_with(&authority, &["exe-a", "exe-b", "exe-c"]);
    // Open before the earlier count: not opened in the interval.
    let before = [
        connect(&mut gate, &authority, "exe-a", "exe-b"),
        connect(&mut gate, &authority, "exe-a", "exe-c"),
    ];
    let earlier = count(&gate, "exe-a", &now);
    assert_eq!(earlier.outgoing().collect::<Vec<_>>(), before.to_vec());
    // In the interval: three opened by exe-a and kept open, one opened and closed again,
    // and three opened toward exe-a by other sandboxes.
    for callee in ["exe-b", "exe-c", "exe-b"] {
        connect(&mut gate, &authority, "exe-a", callee);
    }
    let brief = connect(&mut gate, &authority, "exe-a", "exe-b");
    gate.close_connection(brief).unwrap();
    for caller in ["exe-b", "exe-c", "exe-b"] {
        connect(&mut gate, &authority, caller, "exe-a");
    }
    now.advance(SECOND);
    let later = count(&gate, "exe-a", &now);
    assert_eq!(later.outgoing().count(), 5);
    let reading = connection_rate_reading(&earlier, &later);
    // The brief connection is not seen: the reading is a lower bound.
    assert_eq!(reading.amount(), Some(3));
    assert_reading(
        &reading,
        MonitoredResource::ConnectionsPerSecond,
        HostObserver::Perimeter,
        &now,
    );
    // The callee's own count holds none of the connections opened toward it.
    assert_eq!(count(&gate, "exe-c", &now).outgoing().count(), 1);
    // The gate's session count is not this one's either: no ingress session is counted.
    assert_eq!(gate.open_sessions(), 0);
}

#[test]
fn a_connection_rate_rounds_down_and_counts_that_do_not_fit_make_no_reading() {
    let now = clock();
    let authority = HeldAuthority { clock: &now };
    let mut gate = gate_with(&authority, &["exe-a", "exe-b"]);
    let earlier = count(&gate, "exe-a", &now);
    connect(&mut gate, &authority, "exe-a", "exe-b");
    now.advance(2 * SECOND);
    let later = count(&gate, "exe-a", &now);
    // One connection in two seconds is half a connection per second: zero, rounded down.
    assert_eq!(connection_rate_reading(&earlier, &later).amount(), Some(0));
    // Three in half a second are six per second.
    let earlier = later;
    for _ in 0..3 {
        connect(&mut gate, &authority, "exe-a", "exe-b");
    }
    now.advance(Duration::from_millis(500));
    let later = count(&gate, "exe-a", &now);
    assert_eq!(connection_rate_reading(&earlier, &later).amount(), Some(6));
    // Not in time order, or no interval at all: the host called inconsistently.
    for (first, second) in [(&later, &earlier), (&later, &later)] {
        assert_eq!(
            connection_rate_reading(first, second).ordinary(),
            Some(Ordinary::HostConfiguration)
        );
    }
    // Another sandbox's count.
    let other = count(&gate, "exe-b", &now);
    assert_eq!(
        connection_rate_reading(&earlier, &other).ordinary(),
        Some(Ordinary::HostConfiguration)
    );
    // Another clock session: the interval cannot be known.
    now.advance(SECOND);
    let restarted =
        ConnectionCount::of_gate(&gate, Observed::read(execution("exe-a"), &now, session(2)));
    let reading = connection_rate_reading(&later, &restarted);
    assert_eq!(reading.ordinary(), Some(Ordinary::NotCurrent));
    assert_eq!(reading.draft(), None);
}

#[test]
fn a_sustained_connection_rate_notifies_and_isolates_and_never_revokes() {
    let now = clock();
    let authority = HeldAuthority { clock: &now };
    let mut gate = gate_with(&authority, &["exe-a", "exe-b"]);
    let resource = MonitoredResource::ConnectionsPerSecond;
    let mut monitor = monitor(
        resource,
        SustainedWindow {
            high_mark: 5,
            low_mark: 1,
            sustain_seconds: 3,
            clear_seconds: 3,
            max_sample_gap_seconds: 1,
        },
    );
    let mut earlier = count(&gate, "exe-a", &now);
    let mut outcome = None;
    // Six new connections every second: over the high mark from the first reading.
    for second in 1..=4 {
        for _ in 0..6 {
            connect(&mut gate, &authority, "exe-a", "exe-b");
        }
        now.advance(SECOND);
        let later = count(&gate, "exe-a", &now);
        let reading = connection_rate_reading(&earlier, &later);
        assert_eq!(reading.amount(), Some(6));
        let observation = feed(&mut monitor, reading, &now);
        if second < 4 {
            assert!(held(&observation), "{second}: {observation:?}");
        } else {
            outcome = Some(observation);
        }
        earlier = later;
    }
    let assessment = triggered(outcome.unwrap());
    let record = respond(&assessment, &now);
    assert_eq!(
        record.decision.actions,
        BTreeSet::from([ResponseAction::NotifyUser, ResponseAction::Isolate])
    );
    assert_eq!(
        record.decision.reason,
        DecisionReason::SustainedResource {
            resource,
            observer: HostObserver::Perimeter
        }
    );
}

// ---------------------------------------------------------------------------------------
// The file service's usage counts

fn root(name: &str) -> RootHandle {
    RootHandle::from_host(digest("yougori/test/root/v1", &[name.as_bytes()]))
}

fn usage(name: &str, guest_can_change: bool, total_bytes: Option<u64>) -> RootUsage {
    RootUsage {
        root: root(name),
        scope: scope_of("exe-a"),
        guest_can_change,
        usage: total_bytes.map(|total_bytes| QuotaUsage {
            total_bytes,
            entries: 1,
        }),
    }
}

/// A service for sandbox `exe-a` over `path` under `mode`, permitting `operations`, with
/// room for `max_entries` entries.
fn serve(
    path: &Path,
    mode: GrantMode,
    operations: &[FileOperation],
    max_entries: u64,
) -> FileService {
    let opened = GrantedRoot::open(path).unwrap();
    let file_grant = FileGrant::new(
        opened.handle(),
        mode,
        operations.iter().copied().collect(),
        scope_of("exe-a"),
        host_session(),
        at(START_SECONDS + 3_600),
        FileQuota {
            max_total_bytes: 1_000_000,
            max_entries,
            max_file_bytes: 100_000,
        },
    )
    .unwrap();
    FileService::new(file_grant, opened).unwrap()
}

#[test]
fn a_disk_reading_sums_the_roots_the_guest_can_change_by_the_supervisor() {
    let now = clock();
    let roots = [
        usage("output", true, Some(1_000)),
        usage("workspace", true, Some(500)),
        // A read-only snapshot holds the host's input: left out, counted or not.
        usage("snapshot", false, Some(9_999)),
        usage("snapshot-uncounted", false, None),
    ];
    let reading = disk_reading(&roots, scope_of("exe-a"), &observed("exe-a", &now));
    assert_eq!(reading.amount(), Some(1_500));
    assert_reading(
        &reading,
        MonitoredResource::DiskBytes,
        HostObserver::Supervisor,
        &now,
    );
}

#[test]
fn a_disk_reading_needs_every_changeable_root_counted_and_a_consistent_call() {
    let now = clock();
    let seen = observed("exe-a", &now);
    let scope = scope_of("exe-a");
    // A root that could not be counted would make the sum read low.
    assert_eq!(
        disk_reading(
            &[
                usage("output", true, Some(10)),
                usage("workspace", true, None)
            ],
            scope,
            &seen
        )
        .ordinary(),
        Some(Ordinary::HostFault)
    );
    // Another sandbox's root, or one root twice: the host called inconsistently.
    let mut foreign = usage("other", true, Some(10));
    foreign.scope = scope_of("exe-b");
    for roots in [
        vec![usage("output", true, Some(10)), foreign],
        vec![
            usage("output", true, Some(10)),
            usage("output", true, Some(10)),
        ],
    ] {
        assert_eq!(
            disk_reading(&roots, scope, &seen).ordinary(),
            Some(Ordinary::HostConfiguration)
        );
    }
    // No root the guest can change: nothing of the guest's to count.
    for roots in [vec![], vec![usage("snapshot", false, Some(10))]] {
        let reading = disk_reading(&roots, scope, &seen);
        assert_eq!(reading.ordinary(), Some(Ordinary::NothingObserved));
        assert_eq!(reading.into_draft(), None);
    }
}

#[test]
fn root_usage_reads_what_a_real_file_service_counted() {
    let now = clock();
    let tree = tempfile::tempdir().unwrap();
    let output = tree.path().join("output");
    let snapshot = tree.path().join("snapshot");
    let crowded = tree.path().join("crowded");
    for path in [&output, &snapshot, &crowded] {
        fs::create_dir(path).unwrap();
    }
    fs::write(output.join("result.bin"), [0u8; 100]).unwrap();
    fs::create_dir(output.join("logs")).unwrap();
    fs::write(
        output.join("logs").join("run.txt"),
        b"twenty-three bytes long",
    )
    .unwrap();
    fs::write(snapshot.join("input.bin"), [0u8; 4_000]).unwrap();
    for name in ["a", "b", "c"] {
        fs::write(crowded.join(name), b"x").unwrap();
    }
    let writes = [
        FileOperation::Read,
        FileOperation::Create,
        FileOperation::Write,
    ];
    let output = serve(&output, GrantMode::QuarantineOutput, &writes, 100);
    let snapshot = serve(
        &snapshot,
        GrantMode::ReadOnlySnapshot {
            snapshot: digest("yougori/test/snapshot/v1", &[b"v1"]),
        },
        &[FileOperation::Read, FileOperation::List],
        100,
    );
    let counted = RootUsage::of(&output);
    assert_eq!(counted.root, output.grant().root());
    assert_eq!(counted.scope, scope_of("exe-a"));
    assert!(counted.guest_can_change);
    assert_eq!(
        counted.usage,
        Some(QuotaUsage {
            total_bytes: 123,
            entries: 3
        })
    );
    assert!(!RootUsage::of(&snapshot).guest_can_change);
    let roots = [RootUsage::of(&output), RootUsage::of(&snapshot)];
    let reading = disk_reading(&roots, scope_of("exe-a"), &observed("exe-a", &now));
    assert_eq!(reading.amount(), Some(123));
    // More entries than the quota allows: the service cannot count the root.
    let crowded = serve(&crowded, GrantMode::QuarantineOutput, &writes, 2);
    assert_eq!(RootUsage::of(&crowded).usage, None);
    let roots = [RootUsage::of(&output), RootUsage::of(&crowded)];
    assert_eq!(
        disk_reading(&roots, scope_of("exe-a"), &observed("exe-a", &now)).ordinary(),
        Some(Ordinary::HostFault)
    );
}

#[test]
fn sustained_disk_use_only_notifies_and_clears_after_the_clear_window() {
    let now = clock();
    let resource = MonitoredResource::DiskBytes;
    let mut monitor = monitor(
        resource,
        SustainedWindow {
            high_mark: 1_000,
            low_mark: 400,
            sustain_seconds: 20,
            clear_seconds: 20,
            max_sample_gap_seconds: 10,
        },
    );
    let read = |bytes: u64, now: &ManualClock| {
        disk_reading(
            &[usage("output", true, Some(bytes))],
            scope_of("exe-a"),
            &observed("exe-a", now),
        )
    };
    for _ in 0..2 {
        let observation = feed(&mut monitor, read(1_200, &now), &now);
        assert!(held(&observation), "{observation:?}");
        now.advance(10 * SECOND);
    }
    let assessment = triggered(feed(&mut monitor, read(1_200, &now), &now));
    let record = respond(&assessment, &now);
    assert_eq!(
        record.decision.actions,
        BTreeSet::from([ResponseAction::NotifyUser])
    );
    assert_eq!(
        record.decision.reason,
        DecisionReason::SustainedResource {
            resource,
            observer: HostObserver::Supervisor
        }
    );
    // Under the low mark for the whole clear window: the incident may close.
    for _ in 0..2 {
        now.advance(10 * SECOND);
        let observation = feed(&mut monitor, read(300, &now), &now);
        assert!(held(&observation), "{observation:?}");
    }
    now.advance(10 * SECOND);
    assert!(matches!(
        feed(&mut monitor, read(300, &now), &now),
        ResourceObservation::Cleared { .. }
    ));
}
