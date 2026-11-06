//! KV growth from CORE-01 evidence (G06: "a CORE-01 KV-growth capability (the runner
//! declares it today)"; GPU-W10 line 1305). Increments come only from fresh `KvGrowth`
//! evidence for the exact runtime's backend release; without it the pool is held whole,
//! whatever the runner declares.

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use super::governor::{activation_request, authority, residency_of, DECLARED};
use super::support::*;
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, CapabilityDomain, ConfigurationFingerprint,
    EvidencePolicy, EvidenceRefusal, Observation, ProbeRegistry, RuntimeSubject, SourceClass,
    Staleness, Subject, SubjectKind, SupportDetail, UnknownReason, UnsupportedReason,
};
use crate::foundation::ids::{digest, ExecutionCategory, ManualClock, MonotonicTime};
use crate::model_memory::boundaries::*;

const KIB: u64 = 1 << 10;

fn release(version: &str) -> BackendRelease {
    BackendRelease::new(Backend::Vllm, version).unwrap()
}

fn runtime() -> RuntimeSubject {
    RuntimeSubject {
        category: ExecutionCategory::VmSandbox,
        release: release("0.31.0"),
        instance: digest("yougori/test/instance/v1", &[b"vm-host"]),
    }
}

fn configuration(name: &str) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(digest(
        "yougori/test/configuration/v1",
        &[name.as_bytes()],
    ))
}

const POLICY: EvidencePolicy = EvidencePolicy {
    minimum_source: SourceClass::GuestReport,
    max_age: HOUR,
};

/// What the runner declares: 128 KiB per token, and growth it claims for itself.
const DECLARED_LAYOUT: KvLayout = KvLayout {
    bytes_per_token: 128 * KIB,
    growth: KvGrowth::Increments {
        increment_bytes: MIB,
    },
};

fn grows_by(release: BackendRelease, bytes: u64) -> SupportDetail {
    SupportDetail::KvGrowth {
        release,
        increment_bytes: NonZeroU64::new(bytes).unwrap(),
    }
}

/// A registry with a live-report probe of KV growth.
fn registry(clock: &Arc<ManualClock>) -> (ProbeRegistry<Arc<ManualClock>>, Arc<FakeProbe>) {
    let mut registry = ProbeRegistry::new(Arc::clone(clock));
    let probe = Arc::new(FakeProbe::guest_report(Capability::KvGrowth));
    registry.register(Box::new(Arc::clone(&probe))).unwrap();
    (registry, probe)
}

fn observe(
    registry: &mut ProbeRegistry<Arc<ManualClock>>,
    probe: &FakeProbe,
    observation: Observation,
) {
    let subject = Subject::Runtime(runtime());
    probe.respond(&subject, observation);
    registry.refresh(Capability::KvGrowth, &subject).unwrap();
}

#[test]
fn kv_growth_is_a_backend_capability_of_one_runtime() {
    let capability = Capability::KvGrowth;
    assert_eq!(capability.domain(), CapabilityDomain::Backend);
    assert_eq!(capability.subject_kind(), SubjectKind::Runtime);
    assert_eq!(capability.weakest_source(), SourceClass::GuestReport);
    assert_eq!(serde_json::to_value(capability).unwrap(), "kv_growth");
    let subject = Subject::Runtime(runtime());
    assert!(grows_by(release("0.31.0"), MIB).fits(capability, &subject));
    // Another release, another capability or a plain detail never fits.
    assert!(!grows_by(release("0.29.0"), MIB).fits(capability, &subject));
    assert!(!grows_by(release("0.31.0"), MIB).fits(Capability::AdapterLimits, &subject));
    assert!(!SupportDetail::Plain.fits(capability, &subject));
    // The detail reads back strictly: no zero increment, no unknown field.
    let json = serde_json::to_value(grows_by(release("0.31.0"), MIB)).unwrap();
    assert_eq!(json["kind"], "kv_growth");
    assert!(serde_json::from_value::<SupportDetail>(json.clone()).is_ok());
    let mut zero = json.clone();
    zero["increment_bytes"] = 0.into();
    assert!(serde_json::from_value::<SupportDetail>(zero).is_err());
    let mut extra = json;
    extra["trusted"] = true.into();
    assert!(serde_json::from_value::<SupportDetail>(extra).is_err());
}

#[test]
fn increments_come_only_from_fresh_evidence_for_the_exact_runtime() {
    let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
    let (mut registry, probe) = registry(&clock);
    let current = configuration("vm");

    // Nothing observed: the pool is held whole, whatever the runner declares.
    let missing = evidenced_kv_growth(&registry, &runtime(), current, POLICY);
    assert_eq!(missing.growth(), KvGrowth::Fixed);
    assert_eq!(
        missing.held_whole_because(),
        Some(&EvidenceRefusal::Missing {
            capability: Capability::KvGrowth
        })
    );
    assert_eq!(missing.layout(DECLARED_LAYOUT).growth, KvGrowth::Fixed);

    // A live report of growth: the evidenced increment, not the declared one.
    observe(
        &mut registry,
        &probe,
        Observation::supported(current, HOUR, grows_by(release("0.31.0"), 256 * MIB)),
    );
    let grows = evidenced_kv_growth(&registry, &runtime(), current, POLICY);
    let increments = KvGrowth::Increments {
        increment_bytes: 256 * MIB,
    };
    assert_eq!(grows.growth(), increments);
    assert_eq!(grows.held_whole_because(), None);
    assert_eq!(
        grows.fresh_until(),
        Some(MonotonicTime::ZERO.saturating_add(HOUR))
    );
    assert_eq!(
        grows.layout(DECLARED_LAYOUT),
        KvLayout {
            bytes_per_token: 128 * KIB,
            growth: increments,
        }
    );
    assert_eq!(
        grows.spec(DECLARED_LAYOUT, 2 * GIB),
        KvSpec {
            bytes_per_token: 128 * KIB,
            pool_bytes: 2 * GIB,
            growth: increments,
        }
    );

    // Another configuration in force: the observation no longer applies.
    let other = evidenced_kv_growth(&registry, &runtime(), configuration("changed"), POLICY);
    assert_eq!(other.growth(), KvGrowth::Fixed);
    assert!(matches!(
        other.held_whole_because(),
        Some(EvidenceRefusal::FingerprintChanged { .. })
    ));

    // Past its freshness, the pool is held whole again.
    clock.advance(HOUR + Duration::from_secs(1));
    let stale = evidenced_kv_growth(&registry, &runtime(), current, POLICY);
    assert_eq!(stale.growth(), KvGrowth::Fixed);
    assert!(matches!(
        stale.held_whole_because(),
        Some(EvidenceRefusal::Stale {
            staleness: Staleness::TooOld { .. },
            ..
        })
    ));

    // The backend says it cannot grow, or reports growth for another release.
    observe(
        &mut registry,
        &probe,
        Observation::unsupported(current, HOUR, UnsupportedReason::FeatureAbsent),
    );
    let unsupported = evidenced_kv_growth(&registry, &runtime(), current, POLICY);
    assert_eq!(unsupported.growth(), KvGrowth::Fixed);
    assert!(matches!(
        unsupported.held_whole_because(),
        Some(EvidenceRefusal::Unsupported { .. })
    ));
    observe(
        &mut registry,
        &probe,
        Observation::supported(current, HOUR, grows_by(release("0.29.0"), 256 * MIB)),
    );
    let inconsistent = evidenced_kv_growth(&registry, &runtime(), current, POLICY);
    assert_eq!(inconsistent.growth(), KvGrowth::Fixed);
    assert_eq!(
        inconsistent.held_whole_because(),
        Some(&EvidenceRefusal::Unknown {
            capability: Capability::KvGrowth,
            reason: UnknownReason::InconsistentReport,
        })
    );

    // A fixture never shows that a real backend grows its KV.
    let mut fixtures = ProbeRegistry::new(Arc::clone(&clock));
    let fixture = Arc::new(FakeProbe::new(Capability::KvGrowth, SourceClass::Fixture));
    fixtures.register(Box::new(Arc::clone(&fixture))).unwrap();
    observe(
        &mut fixtures,
        &fixture,
        Observation::supported(current, HOUR, grows_by(release("0.31.0"), 256 * MIB)),
    );
    let weak = evidenced_kv_growth(&fixtures, &runtime(), current, POLICY);
    assert_eq!(weak.growth(), KvGrowth::Fixed);
    assert!(matches!(
        weak.held_whole_because(),
        Some(EvidenceRefusal::SourceTooWeak { .. })
    ));
}

/// The governor commits the pool in the evidenced increments, or holds it whole.
#[test]
fn an_activation_commits_its_kv_as_the_evidence_shows() {
    let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
    let (mut registry, probe) = registry(&clock);
    let current = configuration("vm");
    let whole = evidenced_kv_growth(&registry, &runtime(), current, POLICY);
    observe(
        &mut registry,
        &probe,
        Observation::supported(current, HOUR, grows_by(release("0.31.0"), 512 * MIB)),
    );
    let grows = evidenced_kv_growth(&registry, &runtime(), current, POLICY);

    for (evidence, committed) in [(&grows, 512 * MIB), (&whole, 2 * GIB)] {
        let mut world = World::new();
        let mut request = activation_request(&world, "activation");
        if let Some(spec) = request.spec.as_mut() {
            spec.kv = evidence.spec(DECLARED_LAYOUT, 2 * GIB);
            spec.declared = DECLARED;
        }
        let pending = world.governor.admit(&request).unwrap().activation.unwrap();
        let residency = residency_of(&world);
        let generation = world
            .governor
            .publish_activation(pending, residency)
            .unwrap();
        let placement = world.placement(world.scenario.model_a);
        let authority = authority(&world, "request");
        let held = world
            .governor
            .lease_execution(&authority, &placement, generation, shape(1_024))
            .unwrap();
        assert_eq!(held.kv_bytes(), 128 * MIB);
        assert_eq!(
            world
                .governor
                .kv_usage(&placement, world.epoch(), generation),
            Some((committed, 128 * MIB))
        );
        world.governor.release_execution_lease(held).unwrap();
    }
}
