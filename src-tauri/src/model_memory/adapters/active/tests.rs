//! Adapters on an active model (G06, GPU-W10): attach and switch within the backend's
//! limits as CORE-03 children of the activation's reservation, merged variants that need
//! a grant on every input, KV keyed by the route that produced it, and revocation of an
//! adapter's grant through the coordinator, with the drain and the release through the
//! ledger. Grants are checked through a real CORE-02 catalog, reservations through a real
//! CORE-03 ledger, and the last test runs against a real CORE-04 coordinator.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::foundation::coordination::{LeaseCancellation, LeaseKind};
use crate::foundation::evidence::HostSubject;
use crate::foundation::ids::{
    AuthorizationEpoch, GpuAllocationGeneration, ManualClock, ModelActivationGeneration,
};
use crate::foundation::ledger::{
    CapacityDeclaration, LedgerConfig, Priority, QueueLimits, ReservationState, ResourceKey,
};
use crate::model_memory::adapters::adapter::{AdapterRefusal, LayerShape};
use crate::model_memory::adapters::fakes::{
    adapter_identity, adapter_reference, execution, execution_identity, id, kv_spec, layers,
    logical, logical_identity, request, tenant, trust, verified, versioned, LIMITS, NOW,
};
use crate::model_memory::adapters::kv::{KvReuseSpec, KvSharing};
use crate::model_memory::boundaries::LimitKind;
use crate::model_memory::identity::fakes::GrantCatalog;
use crate::model_memory::identity::{
    GrantTerms, KvReuseRefusal as ScopeRefusal, KvScopeComponent, LoraRefusal, MergeScale,
    MergedAdapter, RevokedAuthorities,
};

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;
const DRAIN: Duration = Duration::from_secs(5);

fn gpu() -> GpuDeviceKey {
    GpuDeviceKey {
        machine: id("machine"),
        device: id("gpu-0"),
    }
}

fn vram() -> ResourceKey {
    ResourceKey::vram(gpu())
}

/// The runtime execution the activation serves under.
fn runtime() -> ExecutionId {
    ExecutionId::new("exe-runtime").unwrap()
}

fn operation(name: &str) -> OperationId {
    OperationId::new(format!("op-{name}")).unwrap()
}

fn artifact(name: &str) -> ArtifactIdentity {
    ArtifactIdentity::from_manifest_digest(&id(name))
}

fn at_seconds(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * 1_000_000_000)
}

/// Two adapters of 512 MiB together at most.
const TWO_SLOTS: BackendAdapterLimits = BackendAdapterLimits {
    rank: LIMITS,
    max_resident: 2,
    max_bytes: 512 * MIB,
};

/// The host: a CORE-03 ledger with one 32 GiB GPU, and the coordination authority's
/// grant tombstones.
struct FakeHost {
    ledger: Ledger<Arc<ManualClock>>,
    revoked: BTreeSet<(ExecutionId, GrantId)>,
}

impl GrantRevocations for FakeHost {
    fn is_revoked(&self, execution: &ExecutionId, grant: GrantId) -> bool {
        self.revoked.contains(&(execution.clone(), grant))
    }

    /// The fake authority is never revoked as a whole; tests of that revoke a real
    /// coordinator or apply its notice.
    fn authority_revoked(&self, _execution: &ExecutionId, _epoch: AuthorizationEpoch) -> bool {
        false
    }
}

impl AdapterHost for FakeHost {
    type Clock = Arc<ManualClock>;

    fn write_ledger<R>(&mut self, write: impl FnOnce(&mut Ledger<Arc<ManualClock>>) -> R) -> R {
        write(&mut self.ledger)
    }
}

/// One activation of base-8b holding `activation_bytes` of its own GPU memory, with
/// adapters attached under `limits`, and a catalog where the base's owner and the
/// adapter lab publish and grant their artifacts.
struct World {
    host: FakeHost,
    parent: ReservationId,
    adapters: ActiveAdapters,
    catalog: GrantCatalog,
}

impl World {
    fn new(limits: BackendAdapterLimits, activation_bytes: u64) -> Self {
        let clock = Arc::new(ManualClock::new(NOW));
        let mut ledger = Ledger::new(
            Arc::clone(&clock),
            HostSubject {
                machine: id("machine"),
            },
            LedgerConfig {
                queue: QueueLimits {
                    max_entries: 8,
                    max_entries_per_tenant: 4,
                    max_wait: Duration::from_secs(60),
                },
                grant_ttl: Duration::from_secs(60),
                unmanaged_usage_max_age: Duration::from_secs(24 * 3_600),
            },
        );
        ledger
            .declare_capacity(
                vram(),
                CapacityDeclaration {
                    total: 32 * GIB,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        ledger
            .set_tenant_budget(tenant("acme"), vram(), 32 * GIB)
            .unwrap();
        let provenance = Provenance {
            requester: Requester::ModelPlacement,
            execution: runtime(),
            operation: operation("activation"),
            tenant: tenant("acme"),
            purpose: CostPurpose::Compute,
            retry_number: 0,
        };
        let request = ReservationRequest::new(
            provenance,
            Priority::Foreground,
            Amounts::new().vram_bytes(gpu(), activation_bytes),
        );
        let Ok(Admission::Granted(parent)) = ledger.reserve(request) else {
            panic!("the activation was not reserved");
        };
        ledger.begin_create(parent).unwrap();
        let catalog = GrantCatalog::open(clock, &[tenant("lab"), tenant("models")]);
        Self {
            host: FakeHost {
                ledger,
                revoked: BTreeSet::new(),
            },
            parent,
            adapters: ActiveAdapters::new(active_base(parent), limits, DRAIN),
            catalog,
        }
    }

    /// `grantee`'s grant from `owner` to serve `artifact` in the fixtures' trust scope.
    fn grant(&self, owner: &str, grantee: &str, artifact: ArtifactIdentity) -> ScopedGrant {
        self.catalog.scoped_grant(
            &ExecutionId::new(format!("exe-{grantee}")).unwrap(),
            GrantTerms {
                grantor: tenant(owner),
                grantee: tenant(grantee),
                artifact,
                scope: trust(),
                uses: BTreeSet::from([GrantedUse::Serve]),
                expires_at: MonotonicTime::from_nanos(u64::MAX),
            },
        )
    }

    /// `grantee`'s grants to serve each adapter named, from the lab.
    fn adapter_grants(&self, grantee: &str, adapters: &[&str]) -> Vec<ScopedGrant> {
        adapters
            .iter()
            .map(|name| self.grant("lab", grantee, artifact(name)))
            .collect()
    }

    fn attach(
        &mut self,
        name: &str,
        bytes: u64,
        grants: &[ScopedGrant],
    ) -> Result<AttachReceipt, AttachRefusal> {
        let caller = Caller {
            tenant: &tenant("acme"),
            grants,
        };
        self.adapters.attach(
            &mut self.host,
            attachment(name, bytes),
            &caller,
            &operation(name),
            NOW,
        )
    }

    fn admit(
        &mut self,
        lease: u64,
        route: Route,
        grantee: &str,
        grants: &[ScopedGrant],
    ) -> Result<AdapterUse, RouteRefusal> {
        let caller = Caller {
            tenant: &tenant(grantee),
            grants,
        };
        self.adapters
            .admit(LeaseId::new(lease), route, &caller, &self.host, NOW)
    }

    /// The coordinator revokes `adapter`'s grant under the runtime at `at`, cancelling
    /// `cancelled` leases with the bound each names.
    fn revoke(
        &mut self,
        adapter: &str,
        at: MonotonicTime,
        cancelled: &[(u64, MonotonicTime)],
    ) -> RevokedGrant {
        let grant = adapter_grant_id(&adapter_identity(adapter));
        self.host.revoked.insert((runtime(), grant));
        RevokedGrant {
            execution: runtime(),
            grant,
            epoch: AuthorizationEpoch::new(1),
            at,
            network: None,
            cancellations: cancelled
                .iter()
                .map(|(lease, bound_at)| LeaseCancellation {
                    lease: LeaseId::new(*lease),
                    kind: LeaseKind::ModelRequest,
                    requested_at: at,
                    bound_at: *bound_at,
                    expires_at: at_seconds(600),
                })
                .collect(),
            activations: Vec::new(),
        }
    }

    /// The ledger's record of an open reservation.
    fn record(
        &self,
        reservation: ReservationId,
    ) -> Option<&crate::foundation::ledger::ReservationRecord> {
        self.host.ledger.reservation(reservation)
    }

    /// Room left in the activation's reservation for children.
    fn room(&self) -> u64 {
        self.host.ledger.parent_room(self.parent, vram()).unwrap()
    }
}

fn active_base(reservation: ReservationId) -> ActiveBase {
    ActiveBase {
        logical: logical_identity("base-8b"),
        execution: execution_identity("base-8b"),
        layers: layers(),
        authority: runtime(),
        epoch: AuthorizationEpoch::new(1),
        trust_scope: trust(),
        reservation,
        device: gpu(),
    }
}

/// Adapter `name` for base-8b, owned by the lab, holding `bytes` once loaded.
fn attachment(name: &str, bytes: u64) -> AdapterAttachment {
    AdapterAttachment {
        reference: adapter_reference(name, "base-8b"),
        artifact: OwnedArtifact {
            owner: tenant("lab"),
            artifact: artifact(name),
        },
        bytes,
    }
}

/// base-8b with `adapters` merged in order, its base owned by `models`, its adapters by
/// the lab.
fn variant(adapters: &[&str]) -> MergedVariant {
    let logical = adapters.iter().fold(logical("base-8b"), |spec, name| {
        spec.with_merged(MergedAdapter {
            adapter: adapter_identity(name),
            scale: MergeScale::new(1.0).unwrap(),
            procedure: versioned("linear-merge"),
        })
    });
    MergedVariant {
        execution: execution(&logical),
        logical,
        base: OwnedArtifact {
            owner: tenant("models"),
            artifact: artifact("base-8b"),
        },
        adapters: adapters
            .iter()
            .map(|name| {
                (
                    adapter_identity(name),
                    OwnedArtifact {
                        owner: tenant("lab"),
                        artifact: artifact(name),
                    },
                )
            })
            .collect(),
    }
}

/// KV computed on `route`'s model and adapter by acme over the contract prefix.
fn kv_on(route_model: ExecutionIdentity, adapter: Option<&str>) -> KvReuseSpec {
    kv_spec(
        route_model,
        adapter.map(adapter_identity),
        4_096,
        "contract",
        "acme",
    )
}

fn stored(spec: KvReuseSpec) -> StoredKv {
    StoredKv {
        spec,
        trust_scope: trust(),
        sharing: KvSharing::TenantScoped,
    }
}

/// P07's context: nothing shared or revoked, a verified backend, at `NOW`.
fn reuse(
    world: &World,
    kv: &StoredKv,
    wanted: KvReuseSpec,
    under: &AdapterUse,
) -> Result<KvReuseGrant, AdapterKvRefusal> {
    let revocations = RevokedAuthorities::new();
    let enforcement = verified();
    let sharing = PublicPrefixSharing::none();
    let context = KvReuseContext {
        sharing: &sharing,
        revocations: &revocations,
        enforcement: &enforcement,
        now: NOW,
    };
    world
        .adapters
        .check_kv_reuse(kv, &request(wanted), under, &world.host, &context)
}

#[test]
fn an_adapter_grant_names_exactly_one_adapter() {
    let sql = adapter_grant_id(&adapter_identity("sql"));
    assert_eq!(sql, adapter_grant_id(&adapter_identity("sql")));
    assert_ne!(sql, adapter_grant_id(&adapter_identity("legal")));
}

#[test]
fn an_adapter_is_attached_as_a_child_of_the_activations_reservation() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let grants = world.adapter_grants("acme", &["sql"]);
    let receipt = world.attach("sql", 256 * MIB, &grants).unwrap();
    assert!(receipt.newly_attached);
    assert_eq!(receipt.bytes, 256 * MIB);
    let record = world.record(receipt.reservation).unwrap();
    assert_eq!(record.parent(), Some(world.parent));
    assert_eq!(record.state(), ReservationState::InUse);
    assert_eq!(record.granted().get(vram()), 256 * MIB);
    assert_eq!(record.provenance().execution, runtime());
    assert_eq!(world.room(), 4 * GIB - 256 * MIB);
    assert_eq!(world.adapters.resident_bytes(), 256 * MIB);
    // Attaching it again, for a caller holding its own grant, reserves nothing more.
    let again = world.attach("sql", 256 * MIB, &grants).unwrap();
    assert_eq!(again.reservation, receipt.reservation);
    assert!(!again.newly_attached);
    assert_eq!(world.room(), 4 * GIB - 256 * MIB);
}

#[test]
fn compatibility_and_authorization_are_checked_before_anything_is_reserved() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let grants = world.adapter_grants("acme", &["sql", "other-base", "wide"]);
    // No grant at all, then a grant for another tenant's use.
    assert_eq!(
        world.attach("sql", 256 * MIB, &[]),
        Err(AttachRefusal::Unauthorized(GrantRefusal::Missing))
    );
    let globex = world.adapter_grants("globex", &["sql"]);
    assert_eq!(
        world.attach("sql", 256 * MIB, &globex),
        Err(AttachRefusal::Unauthorized(GrantRefusal::ForAnotherTenant))
    );
    // Made for another base.
    let mut other = attachment("other-base", 256 * MIB);
    other.reference = adapter_reference("other-base", "base-70b");
    let caller = Caller {
        tenant: &tenant("acme"),
        grants: &grants,
    };
    assert!(matches!(
        world
            .adapters
            .attach(&mut world.host, other, &caller, &operation("x"), NOW),
        Err(AttachRefusal::Incompatible(
            AdapterRefusal::BaseMismatch { .. }
        ))
    ));
    // A layer the base does not have.
    let mut wide = attachment("wide", 256 * MIB);
    wide.reference.layers.insert(
        "layers.9.o_proj".to_string(),
        LayerShape {
            input_features: 4096,
            output_features: 4096,
        },
    );
    assert!(matches!(
        world
            .adapters
            .attach(&mut world.host, wide, &caller, &operation("y"), NOW),
        Err(AttachRefusal::Incompatible(
            AdapterRefusal::UnknownLayer { .. }
        ))
    ));
    assert_eq!(world.room(), 4 * GIB);
    assert_eq!(world.adapters.resident_count(), 0);
}

#[test]
fn an_adapter_beyond_the_backends_limits_is_refused() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let grants = world.adapter_grants("acme", &["sql"]);
    assert_eq!(
        world.attach("sql", 513 * MIB, &grants),
        Err(AttachRefusal::ExceedsLimits {
            requested_bytes: 513 * MIB,
            max_bytes: 512 * MIB,
            max_resident: 2,
        })
    );
    assert_eq!(world.attach("sql", 0, &grants), Err(AttachRefusal::NoBytes));
    let mut none = World::new(
        BackendAdapterLimits {
            max_resident: 0,
            ..TWO_SLOTS
        },
        4 * GIB,
    );
    let grants = none.adapter_grants("acme", &["sql"]);
    assert!(matches!(
        none.attach("sql", MIB, &grants),
        Err(AttachRefusal::ExceedsLimits {
            max_resident: 0,
            ..
        })
    ));
    assert_eq!(world.room(), 4 * GIB);
}

#[test]
fn an_adapter_that_fits_once_another_is_released_waits() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let grants = world.adapter_grants("acme", &["sql", "legal", "math"]);
    world.attach("sql", 256 * MIB, &grants).unwrap();
    world.attach("legal", 128 * MIB, &grants).unwrap();
    // No slot is free.
    assert_eq!(
        world.attach("math", 64 * MIB, &grants),
        Err(AttachRefusal::AwaitingRelease {
            requested_bytes: 64 * MIB,
            free_bytes: 128 * MIB,
            free_slots: 0,
        })
    );
    // A slot, but too few bytes.
    let drain = world
        .adapters
        .detach(adapter_identity("legal"), NOW)
        .unwrap();
    assert_eq!(drain.unload, vec![adapter_identity("legal")]);
    world
        .adapters
        .release_unloaded(
            &mut world.host,
            adapter_identity("legal"),
            SourceClass::GuestReport,
        )
        .unwrap();
    assert_eq!(
        world.attach("math", 300 * MIB, &grants),
        Err(AttachRefusal::AwaitingRelease {
            requested_bytes: 300 * MIB,
            free_bytes: 256 * MIB,
            free_slots: 1,
        })
    );
    world.attach("math", 256 * MIB, &grants).unwrap();
    assert_eq!(world.adapters.resident_bytes(), 512 * MIB);
    assert_eq!(world.room(), 4 * GIB - 512 * MIB);
}

#[test]
fn the_ledger_refuses_an_adapter_past_the_activations_reservation() {
    // The backend allows 512 MiB of adapters, but the activation reserved only 384 MiB of
    // its own memory, so the ledger refuses the child and names the parent as the limit.
    let mut world = World::new(TWO_SLOTS, 384 * MIB);
    let grants = world.adapter_grants("acme", &["sql", "legal"]);
    world.attach("sql", 256 * MIB, &grants).unwrap();
    let Err(AttachRefusal::Ledger { refusal }) = world.attach("legal", 256 * MIB, &grants) else {
        panic!("the ledger did not refuse the adapter");
    };
    assert_eq!(refusal.limit, LimitKind::ParentReservation);
    assert_eq!(refusal.requested, 256 * MIB);
    assert_eq!(refusal.available, 128 * MIB);
    assert_eq!(world.adapters.resident_count(), 1);
    assert!(world
        .adapters
        .attachment(&adapter_identity("legal"))
        .is_none());
}

#[test]
fn nothing_is_carved_from_a_reservation_that_is_not_open() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let grants = world.adapter_grants("acme", &["sql"]);
    let parent = world.parent;
    world.host.ledger.cancel(parent).unwrap();
    world
        .host
        .ledger
        .confirm_release(parent, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(
        world.attach("sql", 256 * MIB, &grants),
        Err(AttachRefusal::NoReservation)
    );
    assert_eq!(world.adapters.resident_count(), 0);
}

#[test]
fn a_session_switches_only_onto_an_attached_adapter() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let grants = world.adapter_grants("acme", &["sql", "legal"]);
    world.attach("sql", 256 * MIB, &grants).unwrap();
    let session = AdaptedModel::base(logical("base-8b"));
    let on_sql = world
        .adapters
        .switch_session(&session, Some(adapter_identity("sql")), &world.host)
        .unwrap();
    assert_eq!(on_sql.unmerged, Some(adapter_identity("sql")));
    assert_eq!(on_sql.logical, logical("base-8b"));
    assert_eq!(
        world
            .adapters
            .switch_session(&on_sql, Some(adapter_identity("legal")), &world.host),
        Err(SwitchRefusal::Route(RouteRefusal::NotAttached {
            adapter: adapter_identity("legal"),
        }))
    );
    world.attach("legal", 128 * MIB, &grants).unwrap();
    let on_legal = world
        .adapters
        .switch_session(&on_sql, Some(adapter_identity("legal")), &world.host)
        .unwrap();
    assert_eq!(on_legal.unmerged, Some(adapter_identity("legal")));
    let plain = world
        .adapters
        .switch_session(&on_legal, None, &world.host)
        .unwrap();
    assert_eq!(plain, session);
    // A session on a merged variant runs another model than this base.
    let merged = AdaptedModel::base(variant(&["sql"]).logical);
    assert_eq!(
        world
            .adapters
            .switch_session(&merged, Some(adapter_identity("sql")), &world.host),
        Err(SwitchRefusal::OtherBase)
    );
    // A detached adapter takes no session.
    world
        .adapters
        .detach(adapter_identity("legal"), NOW)
        .unwrap();
    assert_eq!(
        world
            .adapters
            .switch_session(&on_sql, Some(adapter_identity("legal")), &world.host),
        Err(SwitchRefusal::Route(RouteRefusal::Detaching {
            adapter: adapter_identity("legal"),
        }))
    );
    // T07 still refuses subtracting a merged adapter; switching never does it.
    assert!(matches!(
        AdaptedModel::base(variant(&["sql"]).logical)
            .apply(&AdapterChange::SubtractMerged(adapter_identity("sql"))),
        Err(LoraRefusal::SubtractionIsNotExactUndo { .. })
    ));
}

#[test]
fn switching_on_a_single_slot_backend_drains_the_old_adapter_first() {
    let one_slot = BackendAdapterLimits {
        max_resident: 1,
        ..TWO_SLOTS
    };
    let mut world = World::new(one_slot, 4 * GIB);
    let grants = world.adapter_grants("acme", &["sql", "legal"]);
    let sql = world.attach("sql", 256 * MIB, &grants).unwrap();
    let request = world
        .admit(1, Route::Adapter(adapter_identity("sql")), "acme", &grants)
        .unwrap();
    let base = execution_identity("base-8b");
    let sql_kv = stored(kv_on(base, Some("sql")));
    world
        .adapters
        .record_kv(&sql_kv, &request, &world.host, NOW)
        .unwrap();
    // The slot is taken, so legal waits.
    assert!(matches!(
        world.attach("legal", 256 * MIB, &grants),
        Err(AttachRefusal::AwaitingRelease { free_slots: 0, .. })
    ));
    // Detaching sql drains its request within the bound; its memory stays reserved.
    let drain = world.adapters.detach(adapter_identity("sql"), NOW).unwrap();
    assert_eq!(
        drain.draining,
        vec![DrainingRequest {
            lease: LeaseId::new(1),
            route: Route::Adapter(adapter_identity("sql")),
            bound_at: NOW.saturating_add(DRAIN),
            revoked: None,
        }]
    );
    assert!(drain.unload.is_empty());
    assert_eq!(
        world.admit(2, Route::Adapter(adapter_identity("sql")), "acme", &grants),
        Err(RouteRefusal::Detaching {
            adapter: adapter_identity("sql"),
        })
    );
    assert_eq!(
        world.adapters.release_unloaded(
            &mut world.host,
            adapter_identity("sql"),
            SourceClass::GuestReport
        ),
        Err(ReleaseRefusal::StillInUse {
            adapter: adapter_identity("sql"),
            leases: vec![LeaseId::new(1)],
        })
    );
    assert_eq!(world.room(), 4 * GIB - 256 * MIB);
    // The request ends; sql is unloaded and released through the ledger.
    assert_eq!(
        world.adapters.finish(LeaseId::new(1)),
        Some(adapter_identity("sql"))
    );
    let released = world
        .adapters
        .release_unloaded(
            &mut world.host,
            adapter_identity("sql"),
            SourceClass::GuestReport,
        )
        .unwrap();
    assert!(matches!(released, ReleaseOutcome::Released { .. }));
    assert!(world.record(sql.reservation).is_none());
    assert_eq!(world.room(), 4 * GIB);
    // Now legal takes the slot, and the session switches onto it.
    world.attach("legal", 256 * MIB, &grants).unwrap();
    let session = AdaptedModel {
        logical: logical("base-8b"),
        unmerged: Some(adapter_identity("sql")),
    };
    let switched = world
        .adapters
        .switch_session(&session, Some(adapter_identity("legal")), &world.host)
        .unwrap();
    assert_eq!(switched.unmerged, Some(adapter_identity("legal")));
    // The KV sql produced is never served under legal, even for the same prefix.
    let on_legal = world
        .admit(
            3,
            Route::Adapter(adapter_identity("legal")),
            "acme",
            &grants,
        )
        .unwrap();
    assert_eq!(
        reuse(&world, &sql_kv, kv_on(base, Some("legal")), &on_legal),
        Err(AdapterKvRefusal::ProducedUnderAnother {
            produced: Route::Adapter(adapter_identity("sql")),
            serving: Route::Adapter(adapter_identity("legal")),
        })
    );
}

#[test]
fn a_release_needs_an_observation_with_authority_and_keeps_the_memory_counted_until_then() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let grants = world.adapter_grants("acme", &["sql"]);
    let receipt = world.attach("sql", 256 * MIB, &grants).unwrap();
    assert_eq!(
        world.adapters.release_unloaded(
            &mut world.host,
            adapter_identity("sql"),
            SourceClass::GuestReport
        ),
        Err(ReleaseRefusal::StillAttached {
            adapter: adapter_identity("sql"),
        })
    );
    world.adapters.detach(adapter_identity("sql"), NOW).unwrap();
    let refused = world.adapters.release_unloaded(
        &mut world.host,
        adapter_identity("sql"),
        SourceClass::Fixture,
    );
    assert!(matches!(
        refused,
        Err(ReleaseRefusal::Ledger(
            LedgerError::SourceNotAuthoritative { .. }
        ))
    ));
    assert_eq!(
        world
            .record(receipt.reservation)
            .map(|record| record.state()),
        Some(ReservationState::Releasing)
    );
    assert_eq!(world.adapters.resident_bytes(), 256 * MIB);
    assert_eq!(world.room(), 4 * GIB - 256 * MIB);
    world
        .adapters
        .release_unloaded(
            &mut world.host,
            adapter_identity("sql"),
            SourceClass::GuestReport,
        )
        .unwrap();
    assert_eq!(world.room(), 4 * GIB);
    assert_eq!(world.adapters.resident_count(), 0);
}

#[test]
fn an_adapter_request_needs_the_callers_own_grant() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let grants = world.adapter_grants("acme", &["sql"]);
    world.attach("sql", 256 * MIB, &grants).unwrap();
    let used = world
        .admit(1, Route::Adapter(adapter_identity("sql")), "acme", &grants)
        .unwrap();
    assert_eq!(used.model(), execution_identity("base-8b"));
    assert_eq!(used.adapter(), Some(adapter_identity("sql")));
    // globex presents acme's grant, then none.
    assert_eq!(
        world.admit(
            2,
            Route::Adapter(adapter_identity("sql")),
            "globex",
            &grants
        ),
        Err(RouteRefusal::Unauthorized {
            input: Input::Adapter(adapter_identity("sql")),
            refusal: GrantRefusal::ForAnotherTenant,
        })
    );
    assert_eq!(
        world.admit(3, Route::Adapter(adapter_identity("sql")), "globex", &[]),
        Err(RouteRefusal::Unauthorized {
            input: Input::Adapter(adapter_identity("sql")),
            refusal: GrantRefusal::Missing,
        })
    );
    // The owner revokes initech's catalog grant: its next request is refused.
    let object = world
        .catalog
        .publish_artifact(&tenant("lab"), &artifact("sql"));
    let initech = ExecutionId::new("exe-initech").unwrap();
    let catalog_grant = world.catalog.grant(
        &tenant("lab"),
        object,
        &tenant("initech"),
        &initech,
        MonotonicTime::from_nanos(u64::MAX),
    );
    let terms = GrantTerms {
        grantor: tenant("lab"),
        grantee: tenant("initech"),
        artifact: artifact("sql"),
        scope: trust(),
        uses: BTreeSet::from([GrantedUse::Serve]),
        expires_at: MonotonicTime::from_nanos(u64::MAX),
    };
    let initech_grants =
        [ScopedGrant::from_catalog(world.catalog.catalog(), object, initech, terms).unwrap()];
    let sql = Route::Adapter(adapter_identity("sql"));
    world.admit(4, sql, "initech", &initech_grants).unwrap();
    world.catalog.revoke(&tenant("lab"), catalog_grant);
    assert!(matches!(
        world.admit(5, sql, "initech", &initech_grants),
        Err(RouteRefusal::Unauthorized {
            refusal: GrantRefusal::CatalogRefused(_),
            ..
        })
    ));
    assert_eq!(
        world.admit(1, Route::Base, "acme", &[]),
        Err(RouteRefusal::LeaseInUse {
            lease: LeaseId::new(1),
        })
    );
}

#[test]
fn a_merged_variant_serves_only_callers_with_a_grant_on_every_input() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let merged = variant(&["sql", "legal"]);
    let identity = world
        .adapters
        .record_variant(merged.clone(), &world.host)
        .unwrap();
    // A distinct identity from the base and from a variant of either adapter alone.
    assert_eq!(identity, merged.execution.identity().unwrap());
    assert_ne!(identity, execution_identity("base-8b"));
    assert_ne!(identity, variant(&["sql"]).execution.identity().unwrap());
    let base_grant = world.grant("models", "acme", artifact("base-8b"));
    let mut all = world.adapter_grants("acme", &["sql", "legal"]);
    all.push(base_grant.clone());
    let used = world
        .admit(1, Route::Merged(identity), "acme", &all)
        .unwrap();
    assert_eq!(used.model(), identity);
    assert_eq!(used.adapter(), None);
    // Missing one adapter's grant, or the base's, refuses the variant.
    let mut no_legal = world.adapter_grants("acme", &["sql"]);
    no_legal.push(base_grant);
    assert_eq!(
        world.admit(2, Route::Merged(identity), "acme", &no_legal),
        Err(RouteRefusal::Unauthorized {
            input: Input::Adapter(adapter_identity("legal")),
            refusal: GrantRefusal::Missing,
        })
    );
    let no_base = world.adapter_grants("acme", &["sql", "legal"]);
    assert_eq!(
        world.admit(3, Route::Merged(identity), "acme", &no_base),
        Err(RouteRefusal::Unauthorized {
            input: Input::Base,
            refusal: GrantRefusal::Missing,
        })
    );
    // Another tenant holding acme's grants is refused too.
    assert!(matches!(
        world.admit(4, Route::Merged(identity), "globex", &all),
        Err(RouteRefusal::Unauthorized {
            refusal: GrantRefusal::ForAnotherTenant,
            ..
        })
    ));
    assert_eq!(
        world.admit(
            5,
            Route::Merged(variant(&["math"]).execution.identity().unwrap()),
            "acme",
            &all
        ),
        Err(RouteRefusal::UnknownVariant {
            variant: variant(&["math"]).execution.identity().unwrap(),
        })
    );
}

#[test]
fn a_merged_variant_names_every_input_of_this_base() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let host = &world.host;
    let adapters = &mut world.adapters;
    let mut missing = variant(&["sql", "legal"]);
    missing.adapters.remove(&adapter_identity("legal"));
    assert_eq!(
        adapters.record_variant(missing, host),
        Err(VariantRefusal::MissingInput {
            adapter: adapter_identity("legal"),
        })
    );
    let mut extra = variant(&["sql"]);
    extra.adapters.insert(
        adapter_identity("legal"),
        OwnedArtifact {
            owner: tenant("lab"),
            artifact: artifact("legal"),
        },
    );
    assert_eq!(
        adapters.record_variant(extra, host),
        Err(VariantRefusal::UnknownInput {
            adapter: adapter_identity("legal"),
        })
    );
    let mut unmerged = variant(&["sql"]);
    unmerged.logical = logical("base-8b");
    assert_eq!(
        adapters.record_variant(unmerged, host),
        Err(VariantRefusal::NotMerged)
    );
    let mut other_base = variant(&["sql"]);
    other_base.logical = logical("base-70b").with_merged(MergedAdapter {
        adapter: adapter_identity("sql"),
        scale: MergeScale::new(1.0).unwrap(),
        procedure: versioned("linear-merge"),
    });
    other_base.execution = execution(&other_base.logical);
    assert_eq!(
        adapters.record_variant(other_base, host),
        Err(VariantRefusal::OtherBase {
            base: logical_identity("base-70b"),
        })
    );
    let mut runs_the_base = variant(&["sql"]);
    runs_the_base.execution = execution(&logical("base-8b"));
    assert_eq!(
        adapters.record_variant(runs_the_base, host),
        Err(VariantRefusal::ExecutesAnotherModel)
    );
}

#[test]
fn kv_produced_under_one_adapter_or_variant_is_never_served_under_another() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let mut grants = world.adapter_grants("acme", &["sql", "legal"]);
    grants.push(world.grant("models", "acme", artifact("base-8b")));
    world.attach("sql", 256 * MIB, &grants).unwrap();
    world.attach("legal", 128 * MIB, &grants).unwrap();
    let merged = world
        .adapters
        .record_variant(variant(&["sql"]), &world.host)
        .unwrap();
    let base = execution_identity("base-8b");
    let on_base = world.admit(1, Route::Base, "acme", &[]).unwrap();
    let on_sql = world
        .admit(2, Route::Adapter(adapter_identity("sql")), "acme", &grants)
        .unwrap();
    let on_legal = world
        .admit(
            3,
            Route::Adapter(adapter_identity("legal")),
            "acme",
            &grants,
        )
        .unwrap();
    let on_merged = world
        .admit(4, Route::Merged(merged), "acme", &grants)
        .unwrap();
    let base_kv = stored(kv_on(base, None));
    let sql_kv = stored(kv_on(base, Some("sql")));
    let merged_kv = stored(kv_on(merged, None));
    let host = &world.host;
    // Each state is recorded only on the route that produced it.
    assert_eq!(
        world.adapters.record_kv(&sql_kv, &on_legal, host, NOW),
        Err(KvRecordRefusal::NotProducedOnRoute)
    );
    assert_eq!(
        world.adapters.record_kv(&base_kv, &on_sql, host, NOW),
        Err(KvRecordRefusal::NotProducedOnRoute)
    );
    let base_key = world
        .adapters
        .record_kv(&base_kv, &on_base, host, NOW)
        .unwrap();
    let sql_key = world
        .adapters
        .record_kv(&sql_kv, &on_sql, host, NOW)
        .unwrap();
    let merged_key = world
        .adapters
        .record_kv(&merged_kv, &on_merged, host, NOW)
        .unwrap();
    assert_eq!(world.adapters.kv_route(&base_key), Some(Route::Base));
    assert_eq!(
        world.adapters.kv_route(&sql_key),
        Some(Route::Adapter(adapter_identity("sql")))
    );
    assert_eq!(
        world.adapters.kv_route(&merged_key),
        Some(Route::Merged(merged))
    );
    // On its own route, P07's check grants the reuse.
    assert_eq!(
        reuse(&world, &sql_kv, sql_kv.spec.clone(), &on_sql)
            .unwrap()
            .key(),
        sql_key
    );
    reuse(&world, &merged_kv, merged_kv.spec.clone(), &on_merged).unwrap();
    reuse(&world, &base_kv, base_kv.spec.clone(), &on_base).unwrap();
    // Under any other route it is refused, whatever the KV request claims.
    let cases = [
        (
            &sql_kv,
            kv_on(base, Some("legal")),
            &on_legal,
            Route::Adapter(adapter_identity("sql")),
        ),
        (
            &sql_kv,
            kv_on(base, None),
            &on_base,
            Route::Adapter(adapter_identity("sql")),
        ),
        (
            &sql_kv,
            kv_on(merged, None),
            &on_merged,
            Route::Adapter(adapter_identity("sql")),
        ),
        (&base_kv, kv_on(base, Some("sql")), &on_sql, Route::Base),
        (
            &merged_kv,
            kv_on(base, Some("sql")),
            &on_sql,
            Route::Merged(merged),
        ),
        (
            &merged_kv,
            kv_on(base, None),
            &on_base,
            Route::Merged(merged),
        ),
    ];
    for (kv, wanted, under, produced) in cases {
        assert_eq!(
            reuse(&world, kv, wanted, under),
            Err(AdapterKvRefusal::ProducedUnderAnother {
                produced,
                serving: under.route(),
            })
        );
    }
    // A KV request claiming the producing adapter while served under another is refused.
    assert_eq!(
        reuse(&world, &sql_kv, sql_kv.spec.clone(), &on_legal),
        Err(AdapterKvRefusal::RequestNotOnItsRoute)
    );
    // Another tenant on the same adapter: P07 keeps the KV tenant-scoped.
    let globex_grants = world.adapter_grants("globex", &["sql"]);
    let globex = world
        .admit(
            5,
            Route::Adapter(adapter_identity("sql")),
            "globex",
            &globex_grants,
        )
        .unwrap();
    let mut wanted = sql_kv.spec.clone();
    wanted.scope.authority = crate::model_memory::adapters::fakes::authority("globex", 1);
    assert_eq!(
        reuse(&world, &sql_kv, wanted, &globex),
        Err(AdapterKvRefusal::Reuse(kv::KvReuseRefusal::Scope(
            ScopeRefusal::ScopeMismatch {
                components: vec![KvScopeComponent::Tenant, KvScopeComponent::SessionAuthority],
            }
        )))
    );
    // KV never recorded is never reused.
    let unrecorded = stored(kv_spec(
        base,
        Some(adapter_identity("sql")),
        8,
        "other",
        "acme",
    ));
    assert_eq!(
        reuse(&world, &unrecorded, unrecorded.spec.clone(), &on_sql),
        Err(AdapterKvRefusal::NotRecorded)
    );
    assert_eq!(world.adapters.drop_kv(&base_key), Some(Route::Base));
    assert_eq!(
        reuse(&world, &base_kv, base_kv.spec.clone(), &on_base),
        Err(AdapterKvRefusal::NotRecorded)
    );
}

#[test]
fn revoking_an_adapters_grant_denies_new_requests_from_the_tombstone_on() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let mut grants = world.adapter_grants("acme", &["sql"]);
    grants.push(world.grant("models", "acme", artifact("base-8b")));
    world.attach("sql", 256 * MIB, &grants).unwrap();
    let merged = world
        .adapters
        .record_variant(variant(&["sql"]), &world.host)
        .unwrap();
    // The coordinator revokes; its record has not reached the registry yet.
    let revoked = world.revoke("sql", NOW, &[]);
    let grant = revoked.grant;
    assert_eq!(
        world.admit(1, Route::Adapter(adapter_identity("sql")), "acme", &grants),
        Err(RouteRefusal::Revoked { grant })
    );
    assert_eq!(
        world.admit(2, Route::Merged(merged), "acme", &grants),
        Err(RouteRefusal::VariantInvalidated {
            variant: merged,
            grant,
        })
    );
    assert_eq!(
        world.attach("sql", 256 * MIB, &grants),
        Err(AttachRefusal::Revoked { grant })
    );
    assert_eq!(
        world
            .adapters
            .record_variant(variant(&["sql", "legal"]), &world.host),
        Err(VariantRefusal::InputRevoked {
            adapter: adapter_identity("sql"),
            grant,
        })
    );
    assert_eq!(
        world.adapters.switch_session(
            &AdaptedModel::base(logical("base-8b")),
            Some(adapter_identity("sql")),
            &world.host
        ),
        Err(SwitchRefusal::Route(RouteRefusal::Revoked { grant }))
    );
    // The base still serves.
    world.admit(3, Route::Base, "acme", &[]).unwrap();
}

#[test]
fn a_revocation_detaches_invalidates_drains_and_releases_through_the_ledger() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let mut grants = world.adapter_grants("acme", &["sql", "legal"]);
    grants.push(world.grant("models", "acme", artifact("base-8b")));
    let sql = world.attach("sql", 256 * MIB, &grants).unwrap();
    world.attach("legal", 128 * MIB, &grants).unwrap();
    let with_sql = world
        .adapters
        .record_variant(variant(&["sql"]), &world.host)
        .unwrap();
    let with_legal = world
        .adapters
        .record_variant(variant(&["legal"]), &world.host)
        .unwrap();
    let base = execution_identity("base-8b");
    let on_sql = world
        .admit(1, Route::Adapter(adapter_identity("sql")), "acme", &grants)
        .unwrap();
    let on_with_sql = world
        .admit(2, Route::Merged(with_sql), "acme", &grants)
        .unwrap();
    let on_legal = world
        .admit(
            3,
            Route::Adapter(adapter_identity("legal")),
            "acme",
            &grants,
        )
        .unwrap();
    let host = &world.host;
    let sql_key = world
        .adapters
        .record_kv(&stored(kv_on(base, Some("sql"))), &on_sql, host, NOW)
        .unwrap();
    let with_sql_key = world
        .adapters
        .record_kv(&stored(kv_on(with_sql, None)), &on_with_sql, host, NOW)
        .unwrap();
    let legal_kv = stored(kv_on(base, Some("legal")));
    let legal_key = world
        .adapters
        .record_kv(&legal_kv, &on_legal, host, NOW)
        .unwrap();
    // The coordinator cancelled lease 1 with a bound 2 s on; lease 2 gets the drain bound.
    let at = at_seconds(10);
    let revoked = world.revoke("sql", at, &[(1, at_seconds(12))]);
    let effects = world.adapters.apply_revocation(&revoked);
    assert_eq!(effects.grant, revoked.grant);
    assert_eq!(effects.detached, vec![adapter_identity("sql")]);
    assert_eq!(effects.variants, vec![with_sql]);
    assert_eq!(
        effects.kv.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([sql_key, with_sql_key])
    );
    assert_eq!(
        effects.drain.draining,
        vec![
            DrainingRequest {
                lease: LeaseId::new(1),
                route: Route::Adapter(adapter_identity("sql")),
                bound_at: at_seconds(12),
                revoked: Some(revoked.grant),
            },
            DrainingRequest {
                lease: LeaseId::new(2),
                route: Route::Merged(with_sql),
                bound_at: at.saturating_add(DRAIN),
                revoked: Some(revoked.grant),
            },
        ]
    );
    assert!(effects.drain.unload.is_empty());
    assert_eq!(
        world.adapters.attachment(&adapter_identity("sql")),
        Some(AttachmentView {
            bytes: 256 * MIB,
            reservation: sql.reservation,
            detached: Some(DetachCause::Revoked {
                grant: revoked.grant
            }),
            in_flight: 1,
        })
    );
    assert_eq!(
        world.adapters.variant_invalidated_by(&with_sql),
        Some(Some(revoked.grant))
    );
    assert_eq!(
        world.adapters.variant_invalidated_by(&with_legal),
        Some(None)
    );
    // In flight: each request runs until its bound, then must have stopped.
    assert_eq!(
        world
            .adapters
            .check_request(LeaseId::new(1), at_seconds(11)),
        Ok(RequestStanding::Draining {
            bound_at: at_seconds(12),
            revoked: Some(revoked.grant),
        })
    );
    assert_eq!(
        world
            .adapters
            .check_request(LeaseId::new(1), at_seconds(12)),
        Err(RequestRefusal::DrainBoundPassed {
            lease: LeaseId::new(1),
            bound_at: at_seconds(12),
        })
    );
    assert_eq!(
        world
            .adapters
            .check_request(LeaseId::new(3), at_seconds(30)),
        Ok(RequestStanding::Serving)
    );
    // A draining request records no KV under the revoked adapter.
    assert_eq!(
        world.adapters.record_kv(
            &stored(kv_on(base, Some("sql"))),
            &on_sql,
            &world.host,
            at_seconds(11)
        ),
        Err(KvRecordRefusal::Route(RouteRefusal::Revoked {
            grant: revoked.grant
        }))
    );
    // Legal and its KV are untouched.
    assert_eq!(
        world.adapters.kv_route(&legal_key),
        Some(Route::Adapter(adapter_identity("legal")))
    );
    reuse(&world, &legal_kv, legal_kv.spec.clone(), &on_legal).unwrap();
    // The reservation stays counted while a request may use the adapter.
    assert!(matches!(
        world.adapters.release_unloaded(
            &mut world.host,
            adapter_identity("sql"),
            SourceClass::GuestReport
        ),
        Err(ReleaseRefusal::StillInUse { .. })
    ));
    let overdue = world.adapters.end_overdue(at_seconds(12));
    assert_eq!(overdue.ended.len(), 1);
    assert_eq!(overdue.ended[0].lease, LeaseId::new(1));
    assert_eq!(overdue.unload, vec![adapter_identity("sql")]);
    let overdue = world.adapters.end_overdue(at.saturating_add(DRAIN));
    assert_eq!(overdue.ended[0].lease, LeaseId::new(2));
    assert!(overdue.unload.is_empty());
    assert_eq!(world.room(), 4 * GIB - 384 * MIB);
    world
        .adapters
        .release_unloaded(
            &mut world.host,
            adapter_identity("sql"),
            SourceClass::GuestReport,
        )
        .unwrap();
    assert!(world.record(sql.reservation).is_none());
    assert_eq!(world.room(), 4 * GIB - 128 * MIB);
    assert!(world
        .adapters
        .attachment(&adapter_identity("sql"))
        .is_none());
    // Applying the record again changes nothing, and the grant is never honoured again.
    let again = world.adapters.apply_revocation(&revoked);
    assert!(again.detached.is_empty() && again.variants.is_empty() && again.kv.is_empty());
    world.host.revoked.clear();
    assert_eq!(
        world.attach("sql", 256 * MIB, &grants),
        Err(AttachRefusal::Revoked {
            grant: revoked.grant
        })
    );
}

#[test]
fn a_revocation_of_an_idle_adapter_lists_it_to_unload_at_once() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let grants = world.adapter_grants("acme", &["sql"]);
    world.attach("sql", 256 * MIB, &grants).unwrap();
    // A detach in progress is overtaken by the revocation, and the earlier bound stays.
    world
        .admit(1, Route::Adapter(adapter_identity("sql")), "acme", &grants)
        .unwrap();
    world.adapters.detach(adapter_identity("sql"), NOW).unwrap();
    let revoked = world.revoke("sql", at_seconds(3), &[]);
    let effects = world.adapters.apply_revocation(&revoked);
    assert_eq!(effects.detached, vec![adapter_identity("sql")]);
    assert_eq!(
        effects.drain.draining[0].bound_at,
        NOW.saturating_add(DRAIN)
    );
    assert_eq!(effects.drain.draining[0].revoked, Some(revoked.grant));
    assert_eq!(
        world.adapters.check_request(LeaseId::new(1), at_seconds(2)),
        Ok(RequestStanding::Draining {
            bound_at: NOW.saturating_add(DRAIN),
            revoked: Some(revoked.grant),
        })
    );
    assert_eq!(
        world.adapters.finish(LeaseId::new(1)),
        Some(adapter_identity("sql"))
    );
    let mut idle = World::new(TWO_SLOTS, 4 * GIB);
    let grants = idle.adapter_grants("acme", &["sql"]);
    idle.attach("sql", 256 * MIB, &grants).unwrap();
    let revoked = idle.revoke("sql", NOW, &[]);
    let effects = idle.adapters.apply_revocation(&revoked);
    assert_eq!(effects.drain.unload, vec![adapter_identity("sql")]);
}

#[test]
fn a_revocation_under_another_authority_changes_nothing() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let grants = world.adapter_grants("acme", &["sql"]);
    world.attach("sql", 256 * MIB, &grants).unwrap();
    let mut revoked = world.revoke("sql", NOW, &[]);
    world.host.revoked.clear();
    revoked.execution = ExecutionId::new("exe-elsewhere").unwrap();
    let effects = world.adapters.apply_revocation(&revoked);
    assert!(effects.detached.is_empty());
    assert_eq!(effects.drain, Drain::default());
    world
        .admit(1, Route::Adapter(adapter_identity("sql")), "acme", &grants)
        .unwrap();
}

/// End to end on the committed coordinator and ledger: a VM sandbox's model activation,
/// an adapter carved from its GPU reservation, the coordinator's per-grant revocation and
/// the release of the adapter's memory.
#[test]
fn the_coordinators_grant_revocation_returns_the_adapters_memory_through_the_ledger() {
    use crate::model_memory::progress::fakes as host;

    let clock = Arc::new(ManualClock::new(NOW));
    let mut sandbox = host::SandboxHost::launch(&clock);
    let model = host::model("base");
    let handle = sandbox.activate(model);
    sandbox
        .host
        .complete_activation(&host::owner(), model, handle.generations.activation)
        .unwrap();
    let parent = activation_reservation(
        &sandbox.host,
        model,
        handle.generations.activation,
        handle.generations.gpu_allocation,
    );
    let mut adapters = ActiveAdapters::new(
        ActiveBase {
            authority: host::owner(),
            epoch: current_epoch(&sandbox.host),
            device: host::gpu(),
            ..active_base(parent)
        },
        TWO_SLOTS,
        DRAIN,
    );
    let catalog = GrantCatalog::open(clock.clone(), &[tenant("lab")]);
    let grant = catalog.scoped_grant(
        &host::owner(),
        GrantTerms {
            grantor: tenant("lab"),
            grantee: host::tenant(),
            artifact: artifact("sql"),
            scope: trust(),
            uses: BTreeSet::from([GrantedUse::Serve]),
            expires_at: MonotonicTime::from_nanos(u64::MAX),
        },
    );
    let grants = [grant];
    let caller = Caller {
        tenant: &host::tenant(),
        grants: &grants,
    };
    let now = sandbox.host.now();
    let receipt = adapters
        .attach(
            &mut sandbox.host,
            attachment("sql", 256 * MIB),
            &caller,
            &operation("attach-sql"),
            now,
        )
        .unwrap();
    let record = sandbox
        .host
        .capacity()
        .ledger()
        .reservation(receipt.reservation)
        .unwrap();
    assert_eq!(record.parent(), Some(parent));
    assert_eq!(record.provenance().execution, host::owner());
    let lease = sandbox
        .host
        .admit_request(
            &host::owner(),
            model,
            operation("request"),
            host::lease_terms(),
        )
        .unwrap();
    let sql = adapter_identity("sql");
    adapters
        .admit(lease.id(), Route::Adapter(sql), &caller, &sandbox.host, now)
        .unwrap();
    let revoked = sandbox
        .host
        .revoke_grant(&host::owner(), adapter_grant_id(&sql))
        .unwrap();
    // The tombstone denies new requests before the record is applied.
    assert_eq!(
        adapters.admit(
            LeaseId::new(u64::MAX),
            Route::Adapter(sql),
            &caller,
            &sandbox.host,
            now
        ),
        Err(RouteRefusal::Revoked {
            grant: revoked.grant
        })
    );
    // Model request leases carry no adapter grant, so the coordinator cancelled none:
    // the request drains by the registry's bound.
    assert!(revoked.cancellations.is_empty());
    let effects = adapters.apply_revocation(&revoked);
    assert_eq!(effects.detached, vec![sql]);
    assert_eq!(
        effects.drain.draining,
        vec![DrainingRequest {
            lease: lease.id(),
            route: Route::Adapter(sql),
            bound_at: revoked.at.saturating_add(DRAIN),
            revoked: Some(revoked.grant),
        }]
    );
    sandbox.host.finish_request(lease.id()).unwrap();
    assert_eq!(adapters.finish(lease.id()), Some(sql));
    let room_before = sandbox
        .host
        .capacity()
        .ledger()
        .parent_room(parent, ResourceKey::vram(host::gpu()))
        .unwrap();
    let released = adapters
        .release_unloaded(&mut sandbox.host, sql, SourceClass::GuestReport)
        .unwrap();
    assert!(matches!(released, ReleaseOutcome::Released { .. }));
    let ledger = sandbox.host.capacity().ledger();
    assert!(ledger.reservation(receipt.reservation).is_none());
    assert_eq!(
        ledger
            .parent_room(parent, ResourceKey::vram(host::gpu()))
            .unwrap(),
        room_before + 256 * MIB
    );
    assert!(sandbox
        .host
        .grant_revoked(&host::owner(), adapter_grant_id(&sql)));
}

/// The ledger reservation of the activation's own GPU memory: its GPU holding's.
fn activation_reservation(
    host: &crate::model_memory::progress::fakes::Host,
    model: crate::foundation::coordination::ModelId,
    activation: ModelActivationGeneration,
    allocation: GpuAllocationGeneration,
) -> ReservationId {
    use crate::foundation::coordination::HoldingId;
    let owner = crate::model_memory::progress::fakes::owner();
    let activations = host.model_activations(&owner, model).unwrap();
    assert!(activations.activation(activation).is_some());
    let holding = activations.holding(HoldingId::Gpu { allocation }).unwrap();
    let key = holding.reservations()[0];
    host.capacity().record(&key).unwrap().id()
}

/// The authorization epoch of the test sandbox's authority now.
fn current_epoch(host: &crate::model_memory::progress::fakes::Host) -> AuthorizationEpoch {
    let owner = crate::model_memory::progress::fakes::owner();
    host.sandbox(&owner).unwrap().generations().authorization
}

mod epoch;
mod lease_binding;
mod limits_and_waits;
mod variant_memory;
