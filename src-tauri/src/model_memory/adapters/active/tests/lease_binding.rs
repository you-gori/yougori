//! Model request leases bound to the grants of what they are served with (G06: "model
//! request leases carry no adapter grant yet, so `revoke_grant` cancels none and the drain
//! bound always applies"; CORE-04 per-grant revocation; VM part §6.3 steps 1–2), end to
//! end on the committed coordinator and ledger.

use super::*;
use crate::foundation::coordination::{CancelCause, Lease, LeaseRefusal};
use crate::model_memory::progress::fakes as host;

/// A drain bound far from the leases' own five seconds, so the two are told apart.
const LONG_DRAIN: Duration = Duration::from_secs(30);

/// A VM sandbox's serving activation with adapters `names` attached, each granted to the
/// sandbox's tenant by the lab.
struct Served {
    sandbox: host::SandboxHost,
    model: crate::foundation::coordination::ModelId,
    adapters: ActiveAdapters,
    grants: Vec<ScopedGrant>,
}

impl Served {
    fn new(names: &[&str]) -> Self {
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
        let adapters = ActiveAdapters::new(
            ActiveBase {
                authority: host::owner(),
                epoch: current_epoch(&sandbox.host),
                device: host::gpu(),
                ..active_base(parent)
            },
            TWO_SLOTS,
            LONG_DRAIN,
        );
        let catalog = GrantCatalog::open(clock.clone(), &[tenant("lab")]);
        let grants = names
            .iter()
            .map(|name| {
                catalog.scoped_grant(
                    &host::owner(),
                    GrantTerms {
                        grantor: tenant("lab"),
                        grantee: host::tenant(),
                        artifact: artifact(name),
                        scope: trust(),
                        uses: BTreeSet::from([GrantedUse::Serve]),
                        expires_at: MonotonicTime::from_nanos(u64::MAX),
                    },
                )
            })
            .collect();
        let mut served = Self {
            sandbox,
            model,
            adapters,
            grants,
        };
        for name in names {
            let caller = Caller {
                tenant: &host::tenant(),
                grants: &served.grants,
            };
            let now = served.sandbox.host.now();
            served
                .adapters
                .attach(
                    &mut served.sandbox.host,
                    attachment(name, 128 * MIB),
                    &caller,
                    &operation(name),
                    now,
                )
                .unwrap();
        }
        served
    }

    /// A model request lease from the coordinator.
    fn lease(&mut self, name: &str) -> Lease {
        self.sandbox
            .host
            .admit_request(
                &host::owner(),
                self.model,
                operation(name),
                host::lease_terms(),
            )
            .unwrap()
    }

    fn admit_bound(&mut self, lease: LeaseId, route: Route) -> Result<AdapterUse, RouteRefusal> {
        let caller = Caller {
            tenant: &host::tenant(),
            grants: &self.grants,
        };
        let now = self.sandbox.host.now();
        self.adapters
            .admit_bound(&mut self.sandbox.host, lease, route, &caller, now)
    }

    fn grants_of(&self, lease: LeaseId) -> BTreeSet<GrantId> {
        self.sandbox
            .host
            .lease_record(lease)
            .unwrap()
            .lease()
            .grants()
            .clone()
    }
}

#[test]
fn a_bound_request_is_cancelled_by_its_adapters_revocation_with_its_own_bound() {
    let mut served = Served::new(&["sql", "legal"]);
    let (sql, legal) = (adapter_identity("sql"), adapter_identity("legal"));
    let on_sql = served.lease("on-sql");
    let on_legal = served.lease("on-legal");
    let on_base = served.lease("on-base");
    served
        .admit_bound(on_sql.id(), Route::Adapter(sql))
        .unwrap();
    served
        .admit_bound(on_legal.id(), Route::Adapter(legal))
        .unwrap();
    served.admit_bound(on_base.id(), Route::Base).unwrap();
    // The coordinator records each lease bound to the grant of what it is served with.
    assert_eq!(
        served.grants_of(on_sql.id()),
        BTreeSet::from([adapter_grant_id(&sql)])
    );
    assert_eq!(
        served.grants_of(on_legal.id()),
        BTreeSet::from([adapter_grant_id(&legal)])
    );
    assert!(served.grants_of(on_base.id()).is_empty());

    let revoked = served
        .sandbox
        .host
        .revoke_grant(&host::owner(), adapter_grant_id(&sql))
        .unwrap();
    // The revocation cancels exactly the lease bound to the grant, with its own bound.
    assert_eq!(revoked.cancellations.len(), 1);
    let cancellation = revoked.cancellations[0];
    assert_eq!(cancellation.lease, on_sql.id());
    assert_eq!(
        cancellation.bound_at,
        revoked.at.saturating_add(host::lease_terms().cancel_within)
    );
    assert_eq!(
        served.sandbox.host.check_lease(on_sql.id()),
        Err(LeaseRefusal::Cancelled {
            cause: CancelCause::GrantRevoked
        })
    );
    assert_eq!(
        served.sandbox.host.check_result_publication(on_sql.id()),
        Err(LeaseRefusal::Cancelled {
            cause: CancelCause::GrantRevoked
        })
    );
    assert!(served.sandbox.host.check_lease(on_legal.id()).is_ok());
    assert!(served.sandbox.host.check_lease(on_base.id()).is_ok());

    // The registry stops it by that bound, not by its own drain bound.
    let effects = served.adapters.apply_revocation(&revoked);
    assert_eq!(
        effects.drain.draining,
        vec![DrainingRequest {
            lease: on_sql.id(),
            route: Route::Adapter(sql),
            bound_at: cancellation.bound_at,
            revoked: Some(revoked.grant),
        }]
    );
    assert_ne!(cancellation.bound_at, revoked.at.saturating_add(LONG_DRAIN));
    assert_eq!(
        served
            .adapters
            .check_request(on_legal.id(), revoked.at.saturating_add(LONG_DRAIN)),
        Ok(RequestStanding::Serving)
    );
}

#[test]
fn a_binding_the_coordinator_refuses_admits_nothing() {
    let mut served = Served::new(&["sql"]);
    let sql = adapter_identity("sql");
    let sql_grant = adapter_grant_id(&sql);
    // A lease the coordinator no longer honours cannot be bound.
    let gone = served.lease("gone");
    served.sandbox.host.finish_request(gone.id()).unwrap();
    assert_eq!(
        served.admit_bound(gone.id(), Route::Adapter(sql)),
        Err(RouteRefusal::LeaseNotBound {
            refusal: LeaseRefusal::Released
        })
    );
    assert_eq!(
        served
            .adapters
            .check_request(gone.id(), served.sandbox.host.now()),
        Err(RequestRefusal::UnknownRequest { lease: gone.id() })
    );
    assert_eq!(served.adapters.attachment(&sql).unwrap().in_flight, 0);

    // A grant revoked already is never bound, and nothing else is bound with it.
    let live = served.lease("live");
    let legal_grant = adapter_grant_id(&adapter_identity("legal"));
    served
        .sandbox
        .host
        .revoke_grant(&host::owner(), legal_grant)
        .unwrap();
    assert_eq!(
        served
            .sandbox
            .host
            .bind_grants(live.id(), &BTreeSet::from([sql_grant, legal_grant])),
        Err(LeaseRefusal::GrantRevoked { grant: legal_grant })
    );
    assert!(served.grants_of(live.id()).is_empty());
    // Binding again changes nothing, and the lease keeps its terms and expiry.
    let bound = served
        .sandbox
        .host
        .bind_grants(live.id(), &BTreeSet::from([sql_grant]))
        .unwrap();
    let again = served
        .sandbox
        .host
        .bind_grants(live.id(), &BTreeSet::from([sql_grant]))
        .unwrap();
    assert_eq!(bound, again);
    assert_eq!(again.grants(), &BTreeSet::from([sql_grant]));
    assert_eq!(again.expires_at(), live.expires_at());
    assert_eq!(again.terms(), live.terms());
}

#[test]
fn a_route_depends_on_the_grant_of_every_adapter_it_serves_with() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let merged = world
        .adapters
        .record_variant(variant(&["sql", "legal"]), &world.host)
        .unwrap();
    let (sql, legal) = (adapter_identity("sql"), adapter_identity("legal"));
    assert!(world.adapters.route_grants(Route::Base).is_empty());
    assert_eq!(
        world.adapters.route_grants(Route::Adapter(sql)),
        BTreeSet::from([adapter_grant_id(&sql)])
    );
    assert_eq!(
        world.adapters.route_grants(Route::Merged(merged)),
        BTreeSet::from([adapter_grant_id(&sql), adapter_grant_id(&legal)])
    );
}
