//! Adapter limits from CORE-01 evidence and waiting attachments first in, first out (G06:
//! "a CORE-01 capability for adapter limits" and "a FIFO for waiting attaches"; GPU-W10
//! lines 1305 and 1307).

use std::num::{NonZeroU32, NonZeroU64};

use super::*;
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, CapabilityDomain, ConfigurationFingerprint,
    EvidencePolicy, EvidenceRefusal, Observation, ProbeRegistry, Remedy, RuntimeSubject, Subject,
    SubjectKind, SupportDetail, UnknownReason, UnsupportedReason,
};
use crate::foundation::ids::{digest, ExecutionCategory};
use crate::model_memory::boundaries::WaitLimits;

const HOUR: Duration = Duration::from_secs(3_600);

const POLICY: EvidencePolicy = EvidencePolicy {
    minimum_source: SourceClass::GuestReport,
    max_age: HOUR,
};

fn release(version: &str) -> BackendRelease {
    BackendRelease::new(Backend::Vllm, version).unwrap()
}

fn runtime_subject() -> RuntimeSubject {
    RuntimeSubject {
        category: ExecutionCategory::VmSandbox,
        release: release("0.31.0"),
        instance: digest("yougori/test/instance/v1", &[b"vm-host"]),
    }
}

fn configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(digest("yougori/test/configuration/v1", &[b"vm"]))
}

/// The limits a backend reports: rank 64, `resident` adapters in `bytes`.
fn reported(release: BackendRelease, resident: u32, bytes: u64) -> SupportDetail {
    SupportDetail::AdapterLimits {
        release,
        max_rank: NonZeroU32::new(LIMITS.max_rank).unwrap(),
        max_resident: NonZeroU32::new(resident).unwrap(),
        max_bytes: NonZeroU64::new(bytes).unwrap(),
    }
}

/// A registry on its own clock with a live-report probe of adapter limits.
struct Evidence {
    clock: Arc<ManualClock>,
    registry: ProbeRegistry<Arc<ManualClock>>,
    probe: Arc<FakeProbe>,
}

impl Evidence {
    fn new() -> Self {
        let clock = Arc::new(ManualClock::new(NOW));
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let probe = Arc::new(FakeProbe::guest_report(Capability::AdapterLimits));
        registry.register(Box::new(Arc::clone(&probe))).unwrap();
        Self {
            clock,
            registry,
            probe,
        }
    }

    fn observe(&mut self, observation: Observation) {
        let subject = Subject::Runtime(runtime_subject());
        self.probe.respond(&subject, observation);
        self.registry
            .refresh(Capability::AdapterLimits, &subject)
            .unwrap();
    }

    fn limits(&self) -> Result<EvidencedAdapterLimits, AdapterLimitsRefusal> {
        evidenced_adapter_limits(&self.registry, &runtime_subject(), configuration(), POLICY)
    }
}

#[test]
fn adapter_limits_are_a_backend_capability_of_one_runtime() {
    let capability = Capability::AdapterLimits;
    assert_eq!(capability.domain(), CapabilityDomain::Backend);
    assert_eq!(capability.subject_kind(), SubjectKind::Runtime);
    assert_eq!(capability.weakest_source(), SourceClass::GuestReport);
    assert_eq!(serde_json::to_value(capability).unwrap(), "adapter_limits");
    let subject = Subject::Runtime(runtime_subject());
    assert!(reported(release("0.31.0"), 2, GIB).fits(capability, &subject));
    assert!(!reported(release("0.29.0"), 2, GIB).fits(capability, &subject));
    assert!(!reported(release("0.31.0"), 2, GIB).fits(Capability::KvGrowth, &subject));
    let json = serde_json::to_value(reported(release("0.31.0"), 2, GIB)).unwrap();
    assert_eq!(json["kind"], "adapter_limits");
    let mut none = json.clone();
    none["max_resident"] = 0.into();
    assert!(serde_json::from_value::<SupportDetail>(none).is_err());
    let mut extra = json;
    extra["per_tenant"] = 1.into();
    assert!(serde_json::from_value::<SupportDetail>(extra).is_err());
}

#[test]
fn adapter_limits_come_only_from_fresh_evidence_for_the_exact_runtime() {
    let mut evidence = Evidence::new();
    // Nothing observed: no limits, so no unmerged adapter is attached.
    let missing = evidence.limits().unwrap_err();
    assert_eq!(
        missing,
        AdapterLimitsRefusal::Evidence(EvidenceRefusal::Missing {
            capability: Capability::AdapterLimits
        })
    );
    assert_eq!(missing.remedy(), Remedy::RunCheck);
    assert!(missing.to_string().contains("not evidenced"));

    evidence.observe(Observation::supported(
        configuration(),
        HOUR,
        reported(release("0.31.0"), 2, 512 * MIB),
    ));
    let limits = evidence.limits().unwrap();
    assert_eq!(limits.limits(), TWO_SLOTS);
    assert_eq!(limits.fresh_until(), NOW.saturating_add(HOUR));
    assert_eq!(limits.source(), SourceClass::GuestReport);

    // The backend serves no unmerged adapters, or reported another release's limits.
    evidence.observe(Observation::unsupported(
        configuration(),
        HOUR,
        UnsupportedReason::FeatureAbsent,
    ));
    assert!(matches!(
        evidence.limits(),
        Err(AdapterLimitsRefusal::Evidence(
            EvidenceRefusal::Unsupported { .. }
        ))
    ));
    evidence.observe(Observation::supported(
        configuration(),
        HOUR,
        reported(release("0.29.0"), 2, 512 * MIB),
    ));
    assert_eq!(
        evidence.limits(),
        Err(AdapterLimitsRefusal::Evidence(EvidenceRefusal::Unknown {
            capability: Capability::AdapterLimits,
            reason: UnknownReason::InconsistentReport,
        }))
    );
}

#[test]
fn evidenced_limits_serve_new_attachments_only_while_fresh() {
    let mut evidence = Evidence::new();
    evidence.observe(Observation::supported(
        configuration(),
        HOUR,
        reported(release("0.31.0"), 2, 512 * MIB),
    ));
    let limits = evidence.limits().unwrap();
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    world.adapters =
        ActiveAdapters::with_evidenced_limits(active_base(world.parent), limits, DRAIN);
    assert_eq!(world.adapters.limits(), TWO_SLOTS);
    assert_eq!(
        world.adapters.limits_fresh_until(),
        Some(limits.fresh_until())
    );
    let grants = world.adapter_grants("acme", &["sql", "legal", "math"]);
    world.attach("sql", 256 * MIB, &grants).unwrap();

    // Past the evidence's freshness nothing more is attached; what is attached serves.
    let caller = Caller {
        tenant: &tenant("acme"),
        grants: &grants,
    };
    let late = limits.fresh_until().saturating_add(Duration::from_nanos(1));
    assert_eq!(
        world.adapters.attach(
            &mut world.host,
            attachment("legal", 128 * MIB),
            &caller,
            &operation("legal"),
            late,
        ),
        Err(AttachRefusal::LimitsNotCurrent {
            fresh_until: limits.fresh_until()
        })
    );
    world
        .admit(1, Route::Adapter(adapter_identity("sql")), "acme", &grants)
        .unwrap();

    // Fresh evidence of smaller limits: one adapter at a time, so the next one waits.
    evidence.clock.advance(HOUR);
    evidence.observe(Observation::supported(
        configuration(),
        HOUR,
        reported(release("0.31.0"), 1, 512 * MIB),
    ));
    let renewed = evidence.limits().unwrap();
    world.adapters.renew_limits(renewed);
    assert_eq!(world.adapters.limits().max_resident, 1);
    assert_eq!(
        world.adapters.attach(
            &mut world.host,
            attachment("legal", 128 * MIB),
            &caller,
            &operation("legal"),
            late,
        ),
        Err(AttachRefusal::AwaitingRelease {
            requested_bytes: 128 * MIB,
            free_bytes: 256 * MIB,
            free_slots: 0,
        })
    );
}

#[test]
fn waiting_attachments_are_served_first_in_first_out() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let grants = world.adapter_grants("acme", &["sql", "legal", "math", "code", "docs"]);
    world.attach("sql", 256 * MIB, &grants).unwrap();
    world.attach("legal", 128 * MIB, &grants).unwrap();
    // No slot is free: math waits, then code behind it.
    assert_eq!(
        world.attach("math", 64 * MIB, &grants),
        Err(AttachRefusal::AwaitingRelease {
            requested_bytes: 64 * MIB,
            free_bytes: 128 * MIB,
            free_slots: 0,
        })
    );
    assert!(matches!(
        world.attach("code", 32 * MIB, &grants),
        Err(AttachRefusal::AwaitingRelease { .. })
    ));
    let waiting = |world: &mut World| -> Vec<AdapterIdentity> {
        world
            .adapters
            .attach_waiters(NOW)
            .into_iter()
            .map(|waiter| waiter.key)
            .collect()
    };
    assert_eq!(
        waiting(&mut world),
        vec![adapter_identity("math"), adapter_identity("code")]
    );

    // One slot frees: the later attachment fits it, but the earlier one claims it.
    world
        .adapters
        .detach(adapter_identity("legal"), NOW)
        .unwrap();
    world
        .adapters
        .release_unloaded(
            &mut world.host,
            adapter_identity("legal"),
            SourceClass::GuestReport,
        )
        .unwrap();
    assert_eq!(
        world.attach("code", 32 * MIB, &grants),
        Err(AttachRefusal::QueuedBehind {
            requested_bytes: 32 * MIB,
            free_bytes: 256 * MIB,
            free_slots: 1,
            ahead: 1,
        })
    );
    let math = world.attach("math", 64 * MIB, &grants).unwrap();
    assert!(math.newly_attached);
    assert_eq!(
        world.attach("code", 32 * MIB, &grants),
        Err(AttachRefusal::AwaitingRelease {
            requested_bytes: 32 * MIB,
            free_bytes: 192 * MIB,
            free_slots: 0,
        })
    );
    assert_eq!(waiting(&mut world), vec![adapter_identity("code")]);

    // An attachment that gives up leaves its place.
    assert!(world.adapters.withdraw_attach(&adapter_identity("code")));
    assert!(!world.adapters.withdraw_attach(&adapter_identity("code")));
    assert!(waiting(&mut world).is_empty());

    // The queue is bounded in length and in time.
    world.adapters.set_attach_wait_limits(WaitLimits {
        max_waiters: 1,
        max_wait: Duration::from_secs(10),
    });
    assert!(matches!(
        world.attach("code", 32 * MIB, &grants),
        Err(AttachRefusal::AwaitingRelease { .. })
    ));
    assert_eq!(
        world.attach("docs", 32 * MIB, &grants),
        Err(AttachRefusal::WaitQueueFull { waiting: 1 })
    );
    assert!(world
        .adapters
        .attach_waiters(NOW.saturating_add(Duration::from_secs(10)))
        .is_empty());
    // An adapter past the limits never waits.
    assert!(matches!(
        world.attach("docs", GIB, &grants),
        Err(AttachRefusal::ExceedsLimits { .. })
    ));
    assert!(waiting(&mut world).is_empty());
}
