//! Evidence states: one state per value, taken from the CORE-01 source, never an assertion
//! shown as verified, and never stale evidence shown as current.

use std::sync::Arc;

use serde_json::json;

use super::*;
use crate::foundation::evidence::{Remedy as EvidenceRemedy, Satisfied};
use crate::foundation::product::{
    Asserter, Evidence, EvidenceCode, Fact, FactError, Observer, RefusalCode, Remedy, ShownAt,
    VerifiedBy,
};

/// io_uring evidence reported by `source`, which a requirement accepting guest reports
/// takes.
fn io_uring(source: SourceClass) -> (Satisfied, ClockReading) {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)));
    let mut registry = ProbeRegistry::new(Arc::clone(&clock));
    let probe = Arc::new(FakeProbe::new(Capability::IoUring, source));
    registry.register(Box::new(Arc::clone(&probe))).unwrap();
    let subject = Subject::Runtime(runtime(ExecutionCategory::VmSandbox));
    probe.respond(
        &subject,
        Observation::supported(config(), HOUR, SupportDetail::Plain),
    );
    registry.refresh(Capability::IoUring, &subject).unwrap();
    let requirement = Requirement::new(
        Capability::IoUring,
        subject,
        SourceClass::Fixture,
        HOUR,
        config(),
    );
    (registry.evaluate(&requirement).unwrap(), registry.now())
}

#[test]
fn core01_evidence_takes_its_state_from_its_source() {
    let mut host = Probes::new(SourceClass::HostProbe);
    let satisfied = host.satisfied(ExecutionCategory::VmSandbox);
    let verified = Evidence::from_satisfied(&satisfied, host.now());
    assert_eq!(
        verified,
        Evidence::Verified {
            by: VerifiedBy::HostProbe {
                capability: Capability::RuntimeCategory
            },
            observed_at: satisfied.observed_at(),
            fresh_until: satisfied.fresh_until(),
        }
    );

    let mut provider = Probes::new(SourceClass::ProviderApi);
    let satisfied = provider.satisfied(ExecutionCategory::ProviderContainerRuntime);
    let observed = Evidence::from_satisfied(&satisfied, provider.now());
    assert!(matches!(
        observed,
        Evidence::Observed {
            by: Observer::ProviderApi,
            ..
        }
    ));
    assert!(!observed.is_verified());
    assert_eq!(observed.source(), Some(SourceClass::ProviderApi));

    // CORE-01 never satisfies a requirement with a recorded declaration or a fixture, so
    // a guest report is the weakest source a satisfied requirement can have.
    let (satisfied, now) = io_uring(SourceClass::GuestReport);
    let asserted = Evidence::from_satisfied(&satisfied, now);
    assert_eq!(
        asserted,
        Evidence::Asserted {
            by: Asserter::Guest,
            received_at: Some(satisfied.observed_at()),
        }
    );
    assert!(!asserted.is_verified() && !asserted.is_observed());
    assert_eq!(asserted.source(), Some(SourceClass::GuestReport));
    for by in [
        Asserter::Declaration,
        Asserter::Fixture,
        Asserter::LegacyRecord,
    ] {
        assert!(by.source() < SourceClass::GuestReport);
    }
}

#[test]
fn stale_core01_evidence_is_unavailable_and_drops_the_value() {
    let mut host = Probes::new(SourceClass::HostProbe);
    let satisfied = host.satisfied(ExecutionCategory::VmSandbox);
    let current = Fact::from_satisfied("kvm", &satisfied, host.now());
    assert_eq!(current.value(), Some(&"kvm"));
    host.advance(HOUR + Duration::from_secs(1));
    let stale = Fact::from_satisfied("kvm", &satisfied, host.now());
    assert_eq!(stale.value(), None);
    let refusal = stale.evidence().refusal().unwrap();
    assert_eq!(
        refusal.code,
        RefusalCode::Evidence {
            code: EvidenceCode::Stale
        }
    );
    assert_eq!(
        refusal.remedy(),
        &Remedy::Evidence {
            step: EvidenceRemedy::RunCheckAgain
        }
    );
}

#[test]
fn a_shown_document_rechecked_later_never_presents_stale_evidence_as_current() {
    let mut host = Probes::new(SourceClass::HostProbe);
    let satisfied = host.satisfied(ExecutionCategory::VmSandbox);
    let shown = ShownAt::of(host.now(), config());
    let fact = Fact::from_satisfied(1u8, &satisfied, host.now());
    assert!(fact.evidence().is_verified());

    host.advance(Duration::from_secs(60));
    let still = fact.as_of(&shown, host.now(), config());
    assert_eq!(still, fact);

    let moved = fact.as_of(&shown, host.now(), other_config());
    assert_eq!(moved.value(), None);
    assert_eq!(
        moved.evidence().refusal().unwrap().code,
        RefusalCode::Evidence {
            code: EvidenceCode::ConfigurationChanged
        }
    );

    let restarted = ProbeRegistry::new(Arc::clone(&host.clock));
    let other_clock = fact.as_of(&shown, restarted.now(), config());
    assert_eq!(
        other_clock.evidence().refusal().unwrap().code,
        RefusalCode::Evidence {
            code: EvidenceCode::Stale
        }
    );

    host.advance(HOUR);
    let old = fact.as_of(&shown, host.now(), config());
    assert_eq!(old.value(), None);
    assert!(old
        .evidence()
        .refusal()
        .unwrap()
        .reason
        .as_str()
        .contains("was current until"));

    let asserted = Fact::new(
        2u8,
        Evidence::Asserted {
            by: Asserter::Guest,
            received_at: None,
        },
    )
    .unwrap();
    assert_eq!(asserted.as_of(&shown, host.now(), other_config()), asserted);
}

#[test]
fn only_the_host_verifies_and_only_the_host_or_a_provider_observes() {
    let verified_by_guest = refused::<Evidence>(json!({
        "state": "verified", "by": {"kind": "guest"}, "observed_at": 1, "fresh_until": 2
    }));
    assert!(
        verified_by_guest.contains("unknown variant"),
        "{verified_by_guest}"
    );
    let observed_by_guest = refused::<Evidence>(json!({
        "state": "observed", "by": "guest", "observed_at": 1, "fresh_until": 2
    }));
    assert!(
        observed_by_guest.contains("unknown variant"),
        "{observed_by_guest}"
    );
    let asserted_with_time = refused::<Evidence>(json!({
        "state": "asserted", "by": "guest", "observed_at": 1
    }));
    assert!(
        asserted_with_time.contains("unknown field"),
        "{asserted_with_time}"
    );
    let unit_with_extra = refused::<Evidence>(json!({
        "state": "verified", "by": {"kind": "controlled_check", "trusted": true},
        "observed_at": 1, "fresh_until": 2
    }));
    assert!(
        unit_with_extra.contains("unknown field"),
        "{unit_with_extra}"
    );
    let backwards = refused::<Evidence>(json!({
        "state": "observed", "by": "host", "observed_at": 5, "fresh_until": 2
    }));
    assert!(backwards.contains("freshness bound"), "{backwards}");
    let fine = json!({
        "state": "verified", "by": {"kind": "controlled_check"}, "observed_at": 1, "fresh_until": 2
    });
    assert!(serde_json::from_value::<Evidence>(fine)
        .unwrap()
        .is_verified());
}

#[test]
fn a_fact_holds_a_value_exactly_when_it_is_available() {
    let refusal = json!({
        "code": {"domain": "evidence", "code": "evidence_missing"},
        "reason": "there is no evidence",
        "remedy": {"remedy": "evidence", "step": {"action": "run_check"}},
        "remedy_text": "run the check"
    });
    let with_value = refused::<Fact<u8>>(json!({
        "value": 3, "evidence": {"state": "unavailable", "refusal": refusal}
    }));
    assert!(with_value.contains("holds no value"), "{with_value}");
    let without_value = refused::<Fact<u8>>(json!({
        "evidence": {"state": "asserted", "by": "request"}
    }));
    assert!(without_value.contains("needs its value"), "{without_value}");
    let unknown = refused::<Fact<u8>>(json!({
        "value": 3, "evidence": {"state": "asserted", "by": "request"}, "trust": 1
    }));
    assert!(unknown.contains("unknown field"), "{unknown}");

    let unavailable: Fact<u8> = serde_json::from_value(json!({
        "evidence": {"state": "unavailable", "refusal": refusal}
    }))
    .unwrap();
    assert_eq!(unavailable.value(), None);
    assert_eq!(round_trip(&unavailable), unavailable);
    assert_eq!(
        Fact::new(1u8, unavailable.evidence().clone()),
        Err(FactError::UnavailableWithValue)
    );
}
