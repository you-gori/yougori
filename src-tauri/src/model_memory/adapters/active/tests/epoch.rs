//! Revoking the activation's whole authority (G06: "whole-authority (epoch) revocation";
//! CORE-04, INT-02): every route, variant, KV state and waiting attachment ends, requests
//! drain by their declared bounds, and nothing new is honoured, from the coordinator's
//! own state before its notice is applied.

use super::*;
use crate::foundation::coordination::RevocationNotice;

fn epoch(value: u64) -> AuthorizationEpoch {
    AuthorizationEpoch::new(value)
}

/// The coordinator's notice that the runtime's epoch 1 was revoked at `at`.
fn notice(at: MonotonicTime) -> RevocationNotice {
    RevocationNotice {
        execution: runtime(),
        revoked: epoch(1),
        current: epoch(2),
        at,
    }
}

fn cancelled(lease: u64, at: MonotonicTime, bound_at: MonotonicTime) -> LeaseCancellation {
    LeaseCancellation {
        lease: LeaseId::new(lease),
        kind: LeaseKind::ModelRequest,
        requested_at: at,
        bound_at,
        expires_at: at_seconds(600),
    }
}

#[test]
fn revoking_the_whole_authority_ends_every_route_kv_and_waiting_attachment() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let mut grants = world.adapter_grants("acme", &["sql", "legal", "math"]);
    grants.push(world.grant("models", "acme", artifact("base-8b")));
    let sql = world.attach("sql", 256 * MIB, &grants).unwrap();
    world.attach("legal", 128 * MIB, &grants).unwrap();
    // No slot is free, so math waits for one.
    assert!(matches!(
        world.attach("math", 64 * MIB, &grants),
        Err(AttachRefusal::AwaitingRelease { .. })
    ));
    let merged = world
        .adapters
        .record_variant(variant(&["sql"]), &world.host)
        .unwrap();
    let base = execution_identity("base-8b");
    let on_base = world.admit(1, Route::Base, "acme", &grants).unwrap();
    let on_sql = world
        .admit(2, Route::Adapter(adapter_identity("sql")), "acme", &grants)
        .unwrap();
    world
        .admit(3, Route::Merged(merged), "acme", &grants)
        .unwrap();
    let host = &world.host;
    let base_key = world
        .adapters
        .record_kv(&stored(kv_on(base, None)), &on_base, host, NOW)
        .unwrap();
    let sql_key = world
        .adapters
        .record_kv(&stored(kv_on(base, Some("sql"))), &on_sql, host, NOW)
        .unwrap();

    // The coordinator cancelled lease 2 with a bound 1 s on; the others get the drain bound.
    let at = at_seconds(10);
    let cancellations = [cancelled(2, at, at_seconds(11))];
    let effects = world
        .adapters
        .apply_authority_revocation(&notice(at), &cancellations);
    assert_eq!(effects.epoch, Some(epoch(1)));
    assert_eq!(world.adapters.authority_revoked(), Some(epoch(1)));
    assert_eq!(
        effects.detached.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([adapter_identity("sql"), adapter_identity("legal")])
    );
    assert_eq!(effects.variants, vec![merged]);
    assert_eq!(
        effects.kv.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([base_key, sql_key])
    );
    assert_eq!(effects.withdrawn, vec![adapter_identity("math")]);
    assert_eq!(
        effects.drain.draining,
        vec![
            DrainingRequest {
                lease: LeaseId::new(1),
                route: Route::Base,
                bound_at: at.saturating_add(DRAIN),
                revoked: None,
            },
            DrainingRequest {
                lease: LeaseId::new(2),
                route: Route::Adapter(adapter_identity("sql")),
                bound_at: at_seconds(11),
                revoked: None,
            },
            DrainingRequest {
                lease: LeaseId::new(3),
                route: Route::Merged(merged),
                bound_at: at.saturating_add(DRAIN),
                revoked: None,
            },
        ]
    );
    // Legal serves nothing, so it unloads at once; sql waits for its request.
    assert_eq!(effects.drain.unload, vec![adapter_identity("legal")]);
    assert!(effects.drain.unload_variants.is_empty());
    assert_eq!(
        world
            .adapters
            .attachment(&adapter_identity("legal"))
            .unwrap()
            .detached,
        Some(DetachCause::AuthorityRevoked { epoch: epoch(1) })
    );

    // Each request stops at its next cancellation boundary, by its bound at the latest.
    assert_eq!(
        world
            .adapters
            .check_request(LeaseId::new(1), at_seconds(11)),
        Ok(RequestStanding::AuthorityRevoked {
            bound_at: at.saturating_add(DRAIN),
            epoch: epoch(1),
        })
    );
    assert_eq!(
        world
            .adapters
            .check_request(LeaseId::new(2), at_seconds(11)),
        Err(RequestRefusal::DrainBoundPassed {
            lease: LeaseId::new(2),
            bound_at: at_seconds(11),
        })
    );

    // Nothing new is attached, admitted, switched, recorded or reused.
    let revoked = epoch(1);
    assert_eq!(
        world.attach("math", 64 * MIB, &grants),
        Err(AttachRefusal::AuthorityRevoked { epoch: revoked })
    );
    assert_eq!(
        world.admit(4, Route::Base, "acme", &grants),
        Err(RouteRefusal::AuthorityRevoked { epoch: revoked })
    );
    assert_eq!(
        world
            .adapters
            .record_variant(variant(&["legal"]), &world.host),
        Err(VariantRefusal::AuthorityRevoked { epoch: revoked })
    );
    assert_eq!(
        world
            .adapters
            .switch_session(&AdaptedModel::base(logical("base-8b")), None, &world.host),
        Err(SwitchRefusal::Route(RouteRefusal::AuthorityRevoked {
            epoch: revoked
        }))
    );
    assert_eq!(
        world.adapters.record_kv(
            &stored(kv_on(base, None)),
            &on_base,
            &world.host,
            at_seconds(11)
        ),
        Err(KvRecordRefusal::Route(RouteRefusal::AuthorityRevoked {
            epoch: revoked
        }))
    );
    assert!(world.adapters.kv_route(&base_key).is_none());

    // Applying the notice again changes nothing.
    assert_eq!(
        world
            .adapters
            .apply_authority_revocation(&notice(at), &cancellations),
        AuthorityRevocationEffects::default()
    );

    // Memory returns through the ledger once nothing uses it.
    world
        .adapters
        .release_unloaded(
            &mut world.host,
            adapter_identity("legal"),
            SourceClass::GuestReport,
        )
        .unwrap();
    assert!(matches!(
        world.adapters.release_unloaded(
            &mut world.host,
            adapter_identity("sql"),
            SourceClass::GuestReport
        ),
        Err(ReleaseRefusal::StillInUse { .. })
    ));
    let overdue = world.adapters.end_overdue(at.saturating_add(DRAIN));
    assert_eq!(overdue.ended.len(), 3);
    assert_eq!(overdue.unload, vec![adapter_identity("sql")]);
    world
        .adapters
        .release_unloaded(
            &mut world.host,
            adapter_identity("sql"),
            SourceClass::GuestReport,
        )
        .unwrap();
    assert!(world.record(sql.reservation).is_none());
    assert_eq!(world.room(), 4 * GIB);
    assert_eq!(world.adapters.resident_count(), 0);
}

#[test]
fn a_notice_for_another_authority_or_an_earlier_epoch_changes_nothing() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    world.adapters = ActiveAdapters::new(
        ActiveBase {
            epoch: epoch(3),
            ..active_base(world.parent)
        },
        TWO_SLOTS,
        DRAIN,
    );
    let grants = world.adapter_grants("acme", &["sql"]);
    world.attach("sql", 256 * MIB, &grants).unwrap();
    let elsewhere = RevocationNotice {
        execution: ExecutionId::new("exe-elsewhere").unwrap(),
        ..notice(NOW)
    };
    assert_eq!(
        world.adapters.apply_authority_revocation(&elsewhere, &[]),
        AuthorityRevocationEffects::default()
    );
    // Epoch 1 was revoked before this activation was published under epoch 3.
    assert_eq!(
        world.adapters.apply_authority_revocation(&notice(NOW), &[]),
        AuthorityRevocationEffects::default()
    );
    world
        .admit(1, Route::Adapter(adapter_identity("sql")), "acme", &grants)
        .unwrap();
    // A revocation of a later epoch ends this one too.
    let later = RevocationNotice {
        revoked: epoch(4),
        current: epoch(5),
        ..notice(NOW)
    };
    let effects = world.adapters.apply_authority_revocation(&later, &[]);
    assert_eq!(effects.epoch, Some(epoch(3)));
    assert_eq!(effects.detached, vec![adapter_identity("sql")]);
}

/// End to end on the committed coordinator: its revocation of the sandbox's authority
/// denies new work here at once, from its own epoch, and its record of the cancelled
/// leases gives each request its bound.
#[test]
fn the_coordinators_revocation_denies_new_work_before_its_notice_arrives() {
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
    let published = current_epoch(&sandbox.host);
    let mut adapters = ActiveAdapters::new(
        ActiveBase {
            authority: host::owner(),
            epoch: published,
            device: host::gpu(),
            ..active_base(parent)
        },
        TWO_SLOTS,
        DRAIN,
    );
    let catalog = GrantCatalog::open(clock.clone(), &[tenant("lab")]);
    let grants = [catalog.scoped_grant(
        &host::owner(),
        GrantTerms {
            grantor: tenant("lab"),
            grantee: host::tenant(),
            artifact: artifact("sql"),
            scope: trust(),
            uses: BTreeSet::from([GrantedUse::Serve]),
            expires_at: MonotonicTime::from_nanos(u64::MAX),
        },
    )];
    let caller = Caller {
        tenant: &host::tenant(),
        grants: &grants,
    };
    let now = sandbox.host.now();
    let sql = adapter_identity("sql");
    adapters
        .attach(
            &mut sandbox.host,
            attachment("sql", 256 * MIB),
            &caller,
            &operation("attach-sql"),
            now,
        )
        .unwrap();
    let lease = sandbox
        .host
        .admit_request(
            &host::owner(),
            model,
            operation("request"),
            host::lease_terms(),
        )
        .unwrap();
    adapters
        .admit(lease.id(), Route::Adapter(sql), &caller, &sandbox.host, now)
        .unwrap();

    let notice = sandbox.host.revoke(&host::owner()).unwrap();
    assert_eq!(notice.revoked, published);
    // The coordinator's epoch moved on: nothing new before the notice is applied.
    assert_eq!(
        adapters.admit(
            LeaseId::new(u64::MAX),
            Route::Base,
            &caller,
            &sandbox.host,
            now
        ),
        Err(RouteRefusal::AuthorityRevoked { epoch: published })
    );
    assert_eq!(
        adapters.attach(
            &mut sandbox.host,
            attachment("legal", 128 * MIB),
            &caller,
            &operation("attach-legal"),
            now,
        ),
        Err(AttachRefusal::AuthorityRevoked { epoch: published })
    );
    let cancellations = sandbox
        .host
        .revocation(&host::owner())
        .unwrap()
        .cancellations()
        .to_vec();
    let bound_at = cancellations
        .iter()
        .find(|cancellation| cancellation.lease == lease.id())
        .unwrap()
        .bound_at;
    let effects = adapters.apply_authority_revocation(&notice, &cancellations);
    assert_eq!(effects.detached, vec![sql]);
    assert_eq!(
        effects.drain.draining,
        vec![DrainingRequest {
            lease: lease.id(),
            route: Route::Adapter(sql),
            bound_at,
            revoked: None,
        }]
    );
    // The request stops; the adapter's memory is released through the ledger.
    sandbox.host.acknowledge_cancellation(lease.id()).unwrap();
    assert_eq!(adapters.finish(lease.id()), Some(sql));
    assert!(adapters
        .release_unloaded(&mut sandbox.host, sql, SourceClass::GuestReport)
        .is_ok());
    assert_eq!(adapters.resident_count(), 0);
}
