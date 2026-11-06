//! Labels computed from stored bases: observed, asserted, verified and unavailable, with
//! freshness, configuration and clock judged at viewing time on a fake clock.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::foundation::evidence::{
    Capability as ProbeCapability, EvidenceRefusal, ProbeRegistry, Remedy, SourceClass, Staleness,
    UnknownReason,
};
use crate::foundation::ids::{digest, ManualClock, MonotonicTime};
use crate::sandbox::backend::{FactName, HostObserved, ObservationProblem};
use crate::sandbox_contract::declarations::{RefusalCode, RemovalEffect};
use crate::sandbox_contract::policy::PolicyLayer;

fn registry() -> (Arc<ManualClock>, ProbeRegistry<Arc<ManualClock>>) {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(5_000)));
    let registry = ProbeRegistry::new(Arc::clone(&clock));
    (clock, registry)
}

fn stamp_now(registry: &ProbeRegistry<Arc<ManualClock>>, fresh_for: Duration) -> ObservationStamp {
    ObservationStamp {
        clock: registry.session(),
        observed_at: registry.now().at(),
        fresh_for,
        configuration: config("a"),
    }
}

fn evidence_now(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    source: SourceClass,
    fresh_for: Duration,
) -> EvidenceStamp {
    let at = registry.now().at();
    EvidenceStamp {
        capability: ProbeCapability::HypervisorAvailable,
        subject: digest("yougori/test/views/subject/v1", &[b"kvm"]),
        source,
        configuration: config("a"),
        clock: registry.session(),
        observed_at: at,
        fresh_until: at.saturating_add(fresh_for),
    }
}

fn evidence_remedy(label: &FactLabel) -> Option<Remedy> {
    match label {
        FactLabel::Unavailable {
            remedy: WhatToDo::Evidence { remedy },
            ..
        } => Some(*remedy),
        _ => None,
    }
}

#[test]
fn a_current_host_observation_is_observed_until_its_shorter_bound() {
    let (clock, registry) = registry();
    let stamp = stamp_now(&registry, Duration::from_secs(600));
    let basis = FactBasis::HostObserved { stamp };
    let start = stamp.observed_at;
    let expected = FactLabel::Observed {
        source: SourceClass::HostProbe,
        observed_at: start,
        fresh_until: start.saturating_add(MINUTE),
    };
    assert_eq!(
        basis.label_at(registry.now(), config("a"), MINUTE),
        expected
    );
    clock.advance(MINUTE);
    assert_eq!(
        basis.label_at(registry.now(), config("a"), MINUTE),
        expected
    );
    // The observation's own bound caps a reader's looser one.
    let short = FactBasis::HostObserved {
        stamp: ObservationStamp {
            fresh_for: Duration::from_secs(90),
            ..stamp
        },
    };
    assert!(matches!(
        short.label_at(registry.now(), config("a"), HOUR),
        FactLabel::Observed { fresh_until, .. }
            if fresh_until == start.saturating_add(Duration::from_secs(90))
    ));
}

#[test]
fn a_stale_host_observation_is_unavailable_with_its_last_time_and_remedy() {
    let (clock, registry) = registry();
    let stamp = stamp_now(&registry, Duration::from_secs(600));
    let basis = FactBasis::HostObserved { stamp };
    clock.advance(MINUTE + Duration::from_secs(1));
    let label = basis.label_at(registry.now(), config("a"), MINUTE);
    assert_eq!(
        label,
        FactLabel::Unavailable {
            why: Unavailability::NotCurrent {
                problem: ObservationProblem::Stale {
                    staleness: Staleness::TooOld {
                        age: Duration::from_secs(61),
                        limit: MINUTE,
                    },
                },
                last_observed_at: stamp.observed_at,
            },
            remedy: WhatToDo::Evidence {
                remedy: Remedy::RunCheckAgain
            },
        }
    );
    let text = label.to_string();
    assert!(text.starts_with("unavailable: the observation is 61s old, beyond its 60s limit"));
    assert!(text.contains("last observed at 5000 ns"));
    assert!(text.ends_with("what you can do: run the check again"));
    // A reader's tighter bound makes it stale sooner.
    let tight = FactBasis::HostObserved { stamp };
    assert!(tight
        .label_at(registry.now(), config("a"), Duration::from_secs(10))
        .is_unavailable());
}

#[test]
fn configuration_is_judged_first_and_asks_for_a_recheck() {
    let (clock, registry) = registry();
    let stamp = stamp_now(&registry, Duration::from_secs(600));
    // Stale and from another configuration: the configuration is named.
    clock.advance(HOUR);
    for basis in [
        FactBasis::HostObserved { stamp },
        FactBasis::HostVerified { stamp },
    ] {
        let label = basis.label_at(registry.now(), config("b"), MINUTE);
        assert_eq!(
            label,
            FactLabel::Unavailable {
                why: Unavailability::NotCurrent {
                    problem: ObservationProblem::OtherConfiguration {
                        observed_under: config("a"),
                        current: config("b"),
                    },
                    last_observed_at: stamp.observed_at,
                },
                remedy: WhatToDo::Evidence {
                    remedy: Remedy::RecheckCurrentConfiguration
                },
            }
        );
        assert!(label.to_string().contains("another host configuration"));
    }
}

#[test]
fn another_clock_or_a_future_time_is_never_current() {
    let (clock, registry) = registry();
    let stamp = stamp_now(&registry, Duration::MAX);
    let restarted = ProbeRegistry::new(Arc::clone(&clock));
    for basis in [
        FactBasis::HostObserved { stamp },
        FactBasis::HostVerified { stamp },
    ] {
        assert!(matches!(
            basis.label_at(restarted.now(), config("a"), Duration::MAX),
            FactLabel::Unavailable {
                why: Unavailability::NotCurrent {
                    problem: ObservationProblem::Stale {
                        staleness: Staleness::OtherClock
                    },
                    ..
                },
                ..
            }
        ));
    }
    let future = FactBasis::HostVerified {
        stamp: ObservationStamp {
            observed_at: MonotonicTime::from_nanos(u64::MAX),
            ..stamp
        },
    };
    assert!(matches!(
        future.label_at(registry.now(), config("a"), Duration::MAX),
        FactLabel::Unavailable {
            why: Unavailability::NotCurrent {
                problem: ObservationProblem::Stale {
                    staleness: Staleness::ObservedAfterNow
                },
                ..
            },
            ..
        }
    ));
}

#[test]
fn stamps_judge_exactly_as_the_backend_does() {
    let (clock, registry) = registry();
    let observation =
        HostObserved::stamp(7u8, registry.now(), Duration::from_secs(90), config("a"));
    let stamp = ObservationStamp::of(&observation);
    assert_eq!(stamp.observed_at, observation.observed_at());
    assert_eq!(stamp.clock, registry.session());
    let restarted = ProbeRegistry::new(Arc::clone(&clock));
    for step in 0..8u64 {
        for max_age in [Duration::from_secs(10), MINUTE, HOUR] {
            for configuration in [config("a"), config("b")] {
                for now in [registry.now(), restarted.now()] {
                    assert_eq!(
                        stamp.current_at(now, max_age, configuration).map(|_| ()),
                        observation.current_at(now, max_age, configuration),
                        "step {step}, max age {max_age:?}"
                    );
                }
            }
        }
        clock.advance(Duration::from_secs(15));
    }
}

#[test]
fn a_corroborated_observation_is_verified_only_while_current() {
    let (clock, registry) = registry();
    let stamp = stamp_now(&registry, Duration::from_secs(600));
    let basis = FactBasis::HostVerified { stamp };
    assert_eq!(
        basis.label_at(registry.now(), config("a"), MINUTE),
        FactLabel::Verified {
            by: VerifiedBy::ControlledCheck,
            observed_at: stamp.observed_at,
            fresh_until: stamp.observed_at.saturating_add(MINUTE),
        }
    );
    clock.advance(MINUTE + Duration::from_nanos(1));
    let stale = basis.label_at(registry.now(), config("a"), MINUTE);
    assert!(stale.is_unavailable() && !stale.is_verified());
    assert_eq!(evidence_remedy(&stale), Some(Remedy::RunCheckAgain));
}

#[test]
fn core01_evidence_is_verified_only_while_fresh_under_the_configuration_in_force() {
    let (clock, registry) = registry();
    let stamp = evidence_now(&registry, SourceClass::HostProbe, MINUTE);
    let basis = FactBasis::Core01Evidence { stamp };
    let verified = basis.label_at(registry.now(), config("a"), HOUR);
    assert_eq!(
        verified,
        FactLabel::Verified {
            by: VerifiedBy::Evidence {
                capability: ProbeCapability::HypervisorAvailable,
                source: SourceClass::HostProbe,
            },
            observed_at: stamp.observed_at,
            fresh_until: stamp.fresh_until,
        }
    );
    assert!(verified
        .to_string()
        .starts_with("verified by hypervisor availability evidence from a host probe"));
    // A reader's tighter bound applies.
    assert!(matches!(
        basis.label_at(registry.now(), config("a"), Duration::from_secs(5)),
        FactLabel::Verified { fresh_until, .. }
            if fresh_until == stamp.observed_at.saturating_add(Duration::from_secs(5))
    ));
    // Another configuration: CORE-01's own refusal and remedy.
    let other = basis.label_at(registry.now(), config("b"), HOUR);
    assert_eq!(
        other,
        FactLabel::Unavailable {
            why: Unavailability::EvidenceRefused {
                refusal: EvidenceRefusal::FingerprintChanged {
                    capability: ProbeCapability::HypervisorAvailable,
                    observed_under: config("a"),
                    current: config("b"),
                },
                last_observed_at: stamp.observed_at,
            },
            remedy: WhatToDo::Evidence {
                remedy: Remedy::RecheckCurrentConfiguration
            },
        }
    );
    // Past its freshness.
    clock.advance(MINUTE + Duration::from_secs(1));
    let stale = basis.label_at(registry.now(), config("a"), HOUR);
    assert!(matches!(
        &stale,
        FactLabel::Unavailable {
            why: Unavailability::EvidenceRefused {
                refusal: EvidenceRefusal::Stale {
                    staleness: Staleness::TooOld { .. },
                    ..
                },
                ..
            },
            remedy: WhatToDo::Evidence {
                remedy: Remedy::RunCheckAgain
            },
        }
    ));
    // CORE-01's text already names the remedy, so it is not repeated.
    let text = stale.to_string();
    assert_eq!(text.matches("run the check again").count(), 1, "{text}");
    // Another clock session.
    let restarted = ProbeRegistry::new(Arc::clone(&clock));
    assert!(matches!(
        basis.label_at(restarted.now(), config("a"), HOUR),
        FactLabel::Unavailable {
            why: Unavailability::EvidenceRefused {
                refusal: EvidenceRefusal::Stale {
                    staleness: Staleness::OtherClock,
                    ..
                },
                ..
            },
            ..
        }
    ));
}

#[test]
fn core01_evidence_from_a_guest_report_is_never_verified() {
    let (_clock, registry) = registry();
    for source in [
        SourceClass::Fixture,
        SourceClass::RecordedDeclaration,
        SourceClass::GuestReport,
        SourceClass::ProviderApi,
    ] {
        let basis = FactBasis::Core01Evidence {
            stamp: evidence_now(&registry, source, HOUR),
        };
        let label = basis.label_at(registry.now(), config("a"), HOUR);
        assert_eq!(
            label,
            FactLabel::Unavailable {
                why: Unavailability::EvidenceRefused {
                    refusal: EvidenceRefusal::SourceTooWeak {
                        capability: ProbeCapability::HypervisorAvailable,
                        observed: source,
                        required: SourceClass::HostProbe,
                    },
                    last_observed_at: registry.now().at(),
                },
                remedy: WhatToDo::Evidence {
                    remedy: Remedy::ObtainStrongerEvidence {
                        required: SourceClass::HostProbe
                    }
                },
            },
            "{source:?}"
        );
    }
}

#[test]
fn assertions_stay_assertions_at_every_time_and_configuration() {
    let (clock, registry) = registry();
    let restarted = ProbeRegistry::new(Arc::clone(&clock));
    let received = Some(MonotonicTime::from_nanos(5_000));
    let guest = FactBasis::Asserted {
        by: AssertedBy::Guest,
        received_at: received,
    };
    for _ in 0..3 {
        for now in [registry.now(), restarted.now()] {
            for configuration in [config("a"), config("b")] {
                assert_eq!(
                    guest.label_at(now, configuration, Duration::ZERO),
                    FactLabel::Asserted {
                        by: AssertedBy::Guest,
                        received_at: received,
                    }
                );
                for by in [
                    AssertedBy::LaunchRequest,
                    AssertedBy::Declaration,
                    AssertedBy::Contract,
                ] {
                    let label = FactBasis::Asserted {
                        by,
                        received_at: None,
                    }
                    .label_at(now, configuration, Duration::ZERO);
                    assert!(label.is_asserted() && !label.is_verified() && !label.is_observed());
                }
            }
        }
        clock.advance(HOUR);
    }
    let text = guest
        .label_at(registry.now(), config("a"), MINUTE)
        .to_string();
    assert_eq!(
        text,
        "asserted by the guest at 5000 ns; a guest assertion never satisfies a host requirement"
    );
    assert!(AssertedBy::Guest.from_launch_record());
    assert!(AssertedBy::LaunchRequest.from_launch_record());
    assert!(!AssertedBy::Declaration.from_launch_record());
    assert!(!AssertedBy::Contract.from_launch_record());
}

#[test]
fn a_missing_host_observation_names_its_reason_and_a_guest_only_fact_asks_for_host_evidence() {
    let (_clock, registry) = registry();
    for (reason, remedy) in [
        (UnknownReason::NotTested, Remedy::RunCheck),
        (UnknownReason::Inconclusive, Remedy::RunCheckAgain),
        (UnknownReason::Unreachable, Remedy::RunCheckAgain),
    ] {
        let missing = FactBasis::NotObserved {
            reason,
            guest_asserted: false,
        };
        assert_eq!(
            missing.label_at(registry.now(), config("a"), MINUTE),
            FactLabel::Unavailable {
                why: Unavailability::NotObserved { reason },
                remedy: WhatToDo::Evidence { remedy },
            }
        );
        let guest_only = FactBasis::NotObserved {
            reason,
            guest_asserted: true,
        };
        let label = guest_only.label_at(registry.now(), config("a"), MINUTE);
        assert_eq!(
            label,
            FactLabel::Unavailable {
                why: Unavailability::OnlyGuestAsserted { reason },
                remedy: WhatToDo::Evidence {
                    remedy: Remedy::ObtainStrongerEvidence {
                        required: SourceClass::HostProbe
                    }
                },
            }
        );
        assert!(label
            .to_string()
            .contains("never satisfies a host requirement"));
    }
}

#[test]
fn contract_removals_and_planning_refusals_say_why_and_what_to_do() {
    let (_clock, registry) = registry();
    let removed = FactBasis::NotPermitted {
        excluded_by: BTreeSet::from([PolicyLayer::ProductCeiling, PolicyLayer::Delegation]),
        effect: RemovalEffect::Dropped,
    };
    let label = removed.label_at(registry.now(), config("a"), MINUTE);
    assert_eq!(
        label,
        FactLabel::Unavailable {
            why: Unavailability::NotPermitted {
                excluded_by: BTreeSet::from([PolicyLayer::ProductCeiling, PolicyLayer::Delegation]),
                effect: RemovalEffect::Dropped,
            },
            remedy: WhatToDo::Refusal {
                code: RefusalCode::RequiredAuthorityRemoved
            },
        }
    );
    assert_eq!(
        label.to_string(),
        format!(
            "unavailable: not permitted by the product ceiling or the delegation; it was \
             optional and is dropped; what you can do: {}",
            RefusalCode::RequiredAuthorityRemoved.help()
        )
    );
    let refused = FactBasis::Refused {
        code: RefusalCode::RequirementUnmet,
        remedy: WhatToDo::Evidence {
            remedy: Remedy::RecheckCurrentConfiguration,
        },
    };
    let label = refused.label_at(registry.now(), config("a"), MINUTE);
    assert!(label
        .to_string()
        .starts_with("unavailable: planning refused it [requirement_unmet]"));
    assert_eq!(
        evidence_remedy(&label),
        Some(Remedy::RecheckCurrentConfiguration)
    );
}

#[test]
fn bases_round_trip_and_refuse_unknown_fields_and_tags() {
    let (_clock, registry) = registry();
    let bases = [
        FactBasis::HostObserved {
            stamp: stamp_now(&registry, MINUTE),
        },
        FactBasis::HostVerified {
            stamp: stamp_now(&registry, MINUTE),
        },
        FactBasis::Core01Evidence {
            stamp: evidence_now(&registry, SourceClass::HostProbe, MINUTE),
        },
        FactBasis::Asserted {
            by: AssertedBy::Guest,
            received_at: Some(MonotonicTime::from_nanos(9)),
        },
        FactBasis::Asserted {
            by: AssertedBy::Contract,
            received_at: None,
        },
        FactBasis::NotObserved {
            reason: UnknownReason::NotTested,
            guest_asserted: true,
        },
        FactBasis::NotPermitted {
            excluded_by: BTreeSet::from([PolicyLayer::Delegation]),
            effect: RemovalEffect::LaunchRefused,
        },
        FactBasis::Refused {
            code: RefusalCode::NoHostEvidence,
            remedy: WhatToDo::Refusal {
                code: RefusalCode::NoHostEvidence,
            },
        },
    ];
    for basis in bases {
        let value = serde_json::to_value(&basis).unwrap();
        assert_eq!(
            serde_json::from_value::<FactBasis>(value.clone()).unwrap(),
            basis
        );
        let mut extra = value.clone();
        extra["verified"] = json!(true);
        assert!(
            serde_json::from_value::<FactBasis>(extra).is_err(),
            "{value}"
        );
    }
    let mut inner = serde_json::to_value(FactBasis::HostObserved {
        stamp: stamp_now(&registry, MINUTE),
    })
    .unwrap();
    inner["stamp"]["trusted"] = json!(true);
    assert!(serde_json::from_value::<FactBasis>(inner).is_err());
    assert!(serde_json::from_value::<FactBasis>(json!({"basis": "certified"})).is_err());
    assert!(serde_json::from_value::<FactBasis>(json!({
        "basis": "asserted", "by": "operator_score"
    }))
    .is_err());
    let what = WhatToDo::Evidence {
        remedy: Remedy::RunCheck,
    };
    let mut loose = serde_json::to_value(what).unwrap();
    assert_eq!(
        serde_json::from_value::<WhatToDo>(loose.clone()).unwrap(),
        what
    );
    loose["note"] = json!("x");
    assert!(serde_json::from_value::<WhatToDo>(loose).is_err());
}

#[test]
fn fits_pairs_each_value_with_its_bases_only() {
    let (_clock, registry) = registry();
    let host = FactBasis::HostObserved {
        stamp: stamp_now(&registry, MINUTE),
    };
    let guest = FactBasis::Asserted {
        by: AssertedBy::Guest,
        received_at: Some(MonotonicTime::ZERO),
    };
    let guest_without_time = FactBasis::Asserted {
        by: AssertedBy::Guest,
        received_at: None,
    };
    let contract = FactBasis::Asserted {
        by: AssertedBy::Contract,
        received_at: None,
    };
    let core01 = FactBasis::Core01Evidence {
        stamp: evidence_now(&registry, SourceClass::HostProbe, MINUTE),
    };
    let accelerator = FactValue::Accelerator { accelerator: kvm() };
    assert!(accelerator.fits(&host) && accelerator.fits(&guest));
    assert!(!accelerator.fits(&contract) && !accelerator.fits(&core01));
    assert!(!accelerator.fits(&guest_without_time));
    let image = FactValue::GuestImage { image: image() };
    assert!(image.fits(&host) && !image.fits(&guest));
    let hypervisor = FactValue::HypervisorAvailable {
        hypervisor: crate::foundation::evidence::HypervisorKind::Kvm,
    };
    assert!(hypervisor.fits(&core01) && !hypervisor.fits(&host) && !hypervisor.fits(&guest));
    let offline = FactValue::ContractNetwork { offline: true };
    assert!(offline.fits(&contract) && !offline.fits(&host) && !offline.fits(&guest));
    let unobserved = FactValue::Unobserved {
        fact: FactName::Network,
    };
    assert!(unobserved.fits(&FactBasis::NotObserved {
        reason: UnknownReason::NotTested,
        guest_asserted: false
    }));
    assert!(!unobserved.fits(&host));
    assert_eq!(unobserved.section(), Section::Releases);
    assert_eq!(
        FactValue::Unobserved {
            fact: FactName::Persistence
        }
        .section(),
        Section::ReadsAndKeeps
    );
}
