//! The view as shown at a moment: host facts observed or verified only while current,
//! stale and other-configuration evidence never presented as current, a lying guest only
//! ever asserted, and no score anywhere.

use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::Value;

use super::*;
use crate::foundation::evidence::{EvidenceRefusal, Remedy, SourceClass, Staleness, UnknownReason};
use crate::foundation::ids::digest;
use crate::sandbox::backend::{
    ConfinementControl, CredentialExposure, IsolationObservation, NetworkAuthority,
    ObservationProblem, OperatorConfidentiality, Persistence, PhysicalHost, Scripted,
};
use crate::sandbox_contract::declarations::RefusalCode;

/// Whether the fact is one the host observed or CORE-01 verified.
fn is_host_value(fact: &FactValue) -> bool {
    matches!(
        fact,
        FactValue::Accelerator { .. }
            | FactValue::HostBuild { .. }
            | FactValue::GuestImage { .. }
            | FactValue::Isolation { .. }
            | FactValue::Confinement { .. }
            | FactValue::Network { .. }
            | FactValue::Credentials { .. }
            | FactValue::Persistence { .. }
            | FactValue::Devices { .. }
            | FactValue::Confidentiality { .. }
            | FactValue::HypervisorAvailable { .. }
    )
}

/// The labels of the host's own facts (not the guest's) at the viewing time.
fn host_labels(view: &SandboxView, shown: &ShownView) -> Vec<FactLabel> {
    let hosts = host_bases(view);
    let mut labels = Vec::new();
    for section in Section::ALL {
        let facts: Vec<(usize, &ViewFact)> = view
            .facts()
            .iter()
            .enumerate()
            .filter(|(_, fact)| fact.section() == section)
            .collect();
        for ((index, _), line) in facts.iter().zip(shown.section(section)) {
            if hosts.contains(index) {
                labels.push(line.label.clone());
            }
        }
    }
    labels
}

#[test]
fn at_launch_host_facts_are_observed_and_the_hypervisor_evidence_verified() {
    let fixture = launch();
    let view = fixture.view();
    let shown = fixture.shown(&view);
    let hypervisor = labels_of(&shown, |fact| {
        matches!(fact, FactValue::HypervisorAvailable { .. })
    });
    assert!(matches!(
        hypervisor.as_slice(),
        [FactLabel::Verified {
            by: VerifiedBy::Evidence {
                source: SourceClass::HostProbe,
                ..
            },
            ..
        }]
    ));
    let observed = host_labels(&view, &shown);
    assert_eq!(observed.len(), 11);
    assert_eq!(
        observed.iter().filter(|label| label.is_observed()).count(),
        10
    );
    for label in labels_of(&shown, |fact| {
        matches!(
            fact,
            FactValue::Backend { .. } | FactValue::PinnedArtifacts { .. }
        )
    }) {
        assert_eq!(
            label,
            FactLabel::Asserted {
                by: AssertedBy::LaunchRequest,
                received_at: None
            }
        );
    }
    assert!(
        labels_of(&shown, |fact| matches!(fact, FactValue::Access { .. }))
            .iter()
            .all(|label| matches!(
                label,
                FactLabel::Asserted {
                    by: AssertedBy::Contract,
                    ..
                }
            ))
    );
    assert_eq!(shown.view, view.digest());
    assert_eq!(shown.launch_record, fixture.record.identity());
    assert_eq!(shown.clock, fixture.record.clock());
}

#[test]
fn scripted_corroborated_facts_are_verified_while_current() {
    let fixture = launch_with(Setup::default(), |script| {
        script.accelerator = Scripted::Verified {
            value: kvm(),
            control: control(),
        };
        script.isolation = Scripted::Verified {
            value: IsolationObservation {
                own_guest_kernel: true,
                physical_host: PhysicalHost::Shared,
            },
            control: control(),
        };
    });
    let view = fixture.view();
    for wanted in [
        |fact: &FactValue| matches!(fact, FactValue::Accelerator { .. }),
        |fact: &FactValue| matches!(fact, FactValue::Isolation { .. }),
    ] {
        let labels = labels_of(&fixture.shown(&view), wanted);
        assert!(matches!(
            labels.as_slice(),
            [FactLabel::Verified {
                by: VerifiedBy::ControlledCheck,
                ..
            }]
        ));
    }
    fixture.host.advance(MINUTE + Duration::from_secs(1));
    let later = fixture.shown(&view);
    assert!(
        labels_of(&later, |fact| matches!(fact, FactValue::Accelerator { .. }))
            .iter()
            .all(FactLabel::is_unavailable)
    );
}

#[test]
fn past_its_freshness_no_host_fact_is_presented_as_current() {
    let fixture = launch();
    let view = fixture.view();
    // At the boundary the evidence still holds.
    fixture.host.advance(MINUTE);
    let edge = fixture.shown(&view);
    assert!(host_labels(&view, &edge)
        .iter()
        .all(|label| label.is_observed() || label.is_verified()));
    fixture.host.advance(Duration::from_nanos(1));
    let stale = fixture.shown(&view);
    let labels = host_labels(&view, &stale);
    assert_eq!(labels.len(), 11);
    for label in &labels {
        match label {
            FactLabel::Unavailable {
                why:
                    Unavailability::NotCurrent {
                        problem:
                            ObservationProblem::Stale {
                                staleness: Staleness::TooOld { .. },
                            },
                        ..
                    },
                remedy:
                    WhatToDo::Evidence {
                        remedy: Remedy::RunCheckAgain,
                    },
            } => {}
            FactLabel::Unavailable {
                why:
                    Unavailability::EvidenceRefused {
                        refusal:
                            EvidenceRefusal::Stale {
                                staleness: Staleness::TooOld { .. },
                                ..
                            },
                        ..
                    },
                remedy:
                    WhatToDo::Evidence {
                        remedy: Remedy::RunCheckAgain,
                    },
            } => {}
            other => panic!("stale evidence shown as {other:?}"),
        }
    }
    // Assertions are untouched by time: they never were current evidence.
    assert!(stale
        .lines()
        .filter(|line| !is_host_value(&line.fact) || line.label.is_asserted())
        .all(|line| !line.label.is_observed() && !line.label.is_verified()));
    // The stored view did not change; showing it again under fresh evidence is a new
    // view of a new launch, not a relabelling of this one.
    assert_eq!(SandboxView::from_json(&view.to_json().unwrap()), Ok(view));
}

#[test]
fn under_another_configuration_nothing_is_verified() {
    let fixture = launch();
    let view = fixture.view();
    let shown = view.status_at(fixture.now(), config("b"));
    assert!(shown
        .lines()
        .all(|line| !line.label.is_verified() && !line.label.is_observed()));
    for label in host_labels(&view, &shown) {
        assert!(
            matches!(
                &label,
                FactLabel::Unavailable {
                    why: Unavailability::NotCurrent {
                        problem: ObservationProblem::OtherConfiguration { .. },
                        ..
                    },
                    remedy: WhatToDo::Evidence {
                        remedy: Remedy::RecheckCurrentConfiguration
                    },
                } | FactLabel::Unavailable {
                    why: Unavailability::EvidenceRefused {
                        refusal: EvidenceRefusal::FingerprintChanged { .. },
                        ..
                    },
                    remedy: WhatToDo::Evidence {
                        remedy: Remedy::RecheckCurrentConfiguration
                    },
                }
            ),
            "{label:?}"
        );
    }
    assert_eq!(shown.configuration, config("b"));
}

#[test]
fn after_a_restart_every_host_fact_is_from_another_clock() {
    let fixture = launch();
    let view = fixture.view();
    let restarted = fixture.host.restarted();
    let shown = view.status_at(restarted.now(), config("a"));
    for label in host_labels(&view, &shown) {
        assert!(
            matches!(
                &label,
                FactLabel::Unavailable {
                    why: Unavailability::NotCurrent {
                        problem: ObservationProblem::Stale {
                            staleness: Staleness::OtherClock
                        },
                        ..
                    },
                    ..
                } | FactLabel::Unavailable {
                    why: Unavailability::EvidenceRefused {
                        refusal: EvidenceRefusal::Stale {
                            staleness: Staleness::OtherClock,
                            ..
                        },
                        ..
                    },
                    ..
                }
            ),
            "{label:?}"
        );
    }
    assert_ne!(shown.clock, fixture.record.clock());
}

#[test]
fn a_lying_guest_is_only_ever_asserted() {
    let fixture = launch_with(Setup::default(), |script| {
        script.guest.accelerator = Some(kvm());
        script.guest.isolation = Some(IsolationObservation {
            own_guest_kernel: true,
            physical_host: PhysicalHost::Dedicated,
        });
        script.guest.network = Some(NetworkAuthority::offline());
        script.guest.credentials = Some(CredentialExposure::none());
        script.guest.confinement = Some(ConfinementControl::all());
        script.guest.persistence = Some(Persistence::EphemeralTask);
        script.guest.confidentiality = Some(OperatorConfidentiality::VerifiedConfidentialVm {
            scope: digest("yougori/test/views/scope/v1", &[b"everything"]),
        });
    });
    let view = fixture.view();
    let guest: BTreeSet<usize> = view
        .facts()
        .iter()
        .enumerate()
        .filter(|(_, fact)| is_guest(fact))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(guest.len(), 7);
    let check = |shown: &ShownView| {
        let mut seen = 0;
        for section in Section::ALL {
            let facts: Vec<(usize, &ViewFact)> = view
                .facts()
                .iter()
                .enumerate()
                .filter(|(_, fact)| fact.section() == section)
                .collect();
            for ((index, _), line) in facts.iter().zip(shown.section(section)) {
                if guest.contains(index) {
                    seen += 1;
                    assert!(
                        matches!(
                            line.label,
                            FactLabel::Asserted {
                                by: AssertedBy::Guest,
                                received_at: Some(_)
                            }
                        ),
                        "{line}"
                    );
                    assert!(line
                        .to_string()
                        .contains("a guest assertion never satisfies a host requirement"));
                }
            }
        }
        assert_eq!(seen, guest.len());
    };
    // While the host's facts are current, beside them.
    let now = fixture.shown(&view);
    check(&now);
    // The host's own observation of the network and credentials is what is observed;
    // the guest's claims of offline and no credentials are only asserted.
    let network = labels_of(
        &now,
        |fact| matches!(fact, FactValue::Network { authority } if !authority.is_offline()),
    );
    assert!(matches!(network.as_slice(), [FactLabel::Observed { .. }]));
    let confidential = labels_of(&now, |fact| {
        matches!(
            fact,
            FactValue::Confidentiality {
                confidentiality: OperatorConfidentiality::VerifiedConfidentialVm { .. }
            }
        )
    });
    assert!(matches!(
        confidential.as_slice(),
        [FactLabel::Asserted {
            by: AssertedBy::Guest,
            ..
        }]
    ));
    // When the host's facts go stale, the guest's do not fill in for them.
    fixture.host.advance(HOUR);
    let stale = fixture.shown(&view);
    check(&stale);
    assert!(stale
        .lines()
        .all(|line| !line.label.is_observed() && !line.label.is_verified()));
    // Under another configuration and after a restart, likewise.
    check(&view.status_at(fixture.now(), config("b")));
    check(&view.status_at(fixture.host.restarted().now(), config("a")));
}

#[test]
fn a_guest_agreeing_with_the_host_is_still_only_asserted() {
    let fixture = launch_with(Setup::default(), |script| {
        script.guest.accelerator = Some(kvm());
        script.guest.network = Some(routes_and_operations());
    });
    let view = fixture.view();
    let shown = fixture.shown(&view);
    let accelerators = labels_of(
        &shown,
        |fact| matches!(fact, FactValue::Accelerator { accelerator } if *accelerator == kvm()),
    );
    assert_eq!(accelerators.len(), 2);
    assert!(accelerators[0].is_observed());
    assert!(accelerators[1].is_asserted() && !accelerators[1].is_verified());
    let networks = labels_of(&shown, |fact| matches!(fact, FactValue::Network { .. }));
    assert!(networks[0].is_observed() && networks[1].is_asserted());
}

#[test]
fn every_line_has_exactly_one_label_and_the_json_names_it() {
    let fixture = launch();
    let view = fixture.view();
    for shown in [
        fixture.shown(&view),
        view.status_at(fixture.now(), config("b")),
    ] {
        assert_eq!(shown.lines().count(), view.facts().len());
        let json = serde_json::to_value(&shown).unwrap();
        let sections = json["sections"].as_array().unwrap();
        assert_eq!(sections.len(), Section::ALL.len());
        for (section, expected) in sections.iter().zip(Section::ALL) {
            assert_eq!(section["section"], serde_json::to_value(expected).unwrap());
            assert_eq!(section["title"], expected.title());
            for line in section["lines"].as_array().unwrap() {
                let label = line["label"]["label"].as_str().unwrap();
                assert!(
                    ["observed", "asserted", "verified", "unavailable"].contains(&label),
                    "{line}"
                );
            }
        }
        for line in shown.lines() {
            let flags = [
                line.label.is_observed(),
                line.label.is_asserted(),
                line.label.is_verified(),
                line.label.is_unavailable(),
            ];
            assert_eq!(flags.iter().filter(|flag| **flag).count(), 1);
            assert!(line.to_string().contains(&line.fact.to_string()));
        }
    }
}

#[test]
fn unavailable_lists_stale_facts_and_withheld_capabilities() {
    let fixture = launch();
    let view = fixture.view();
    let now = fixture.shown(&view);
    let withheld: Vec<&ShownLine> = now.unavailable().collect();
    assert_eq!(withheld.len(), 1);
    assert!(matches!(
        &withheld[0].fact,
        FactValue::Requested { tuple, .. } if *tuple == connect_registry()
    ));
    assert!(matches!(
        withheld[0].label,
        FactLabel::Unavailable {
            remedy: WhatToDo::Refusal {
                code: RefusalCode::RequiredAuthorityRemoved
            },
            ..
        }
    ));
    fixture.host.advance(HOUR);
    let later = fixture.shown(&view);
    assert_eq!(later.unavailable().count(), 1 + 11);
}

/// Words that would make a view a score, grade, rating or percentage.
const SCORE_WORDS: [&str; 14] = [
    "score",
    "scores",
    "scored",
    "scoring",
    "grade",
    "grades",
    "graded",
    "grading",
    "rating",
    "ratings",
    "rated",
    "percent",
    "percentage",
    "percentile",
];

/// The first score word or percent sign in `text`, if any.
fn score_word(text: &str) -> Option<String> {
    if text.contains('%') {
        return Some("%".to_owned());
    }
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .map(str::to_ascii_lowercase)
        .find(|word| SCORE_WORDS.contains(&word.as_str()))
}

#[test]
fn no_score_grade_rating_or_percentage_anywhere() {
    let fixture = launch_with(
        Setup {
            granted: vec![write_outputs(), release_results(), create_issue()],
            ..Setup::default()
        },
        |script| {
            script.guest.accelerator = Some(kvm());
            script.guest.confidentiality = Some(OperatorConfidentiality::None);
            script.isolation = Scripted::Verified {
                value: IsolationObservation {
                    own_guest_kernel: true,
                    physical_host: PhysicalHost::Shared,
                },
                control: control(),
            };
        },
    );
    let view = fixture.view();
    let mut texts = vec![view.to_json().unwrap(), ViewNotice::TEXT.to_owned()];
    let mut shown_views = vec![
        fixture.shown(&view),
        view.status_at(fixture.now(), config("b")),
    ];
    fixture.host.advance(HOUR);
    shown_views.push(fixture.shown(&view));
    shown_views.push(view.status_at(fixture.host.restarted().now(), config("a")));
    for shown in &shown_views {
        texts.push(serde_json::to_string(shown).unwrap());
        for line in shown.lines() {
            texts.push(line.to_string());
            texts.push(line.fact.to_string());
            texts.push(line.label.to_string());
        }
    }
    for section in Section::ALL {
        texts.push(section.to_string());
    }
    for by in [
        AssertedBy::Guest,
        AssertedBy::LaunchRequest,
        AssertedBy::Declaration,
        AssertedBy::Contract,
    ] {
        texts.push(by.to_string());
    }
    for code in RefusalCode::ALL {
        texts.push(WhatToDo::Refusal { code: *code }.to_string());
        texts.push(Unavailability::Refused { code: *code }.to_string());
    }
    for reason in [
        UnknownReason::NotTested,
        UnknownReason::Inconclusive,
        UnknownReason::Unreachable,
        UnknownReason::InconsistentReport,
    ] {
        texts.push(Unavailability::NotObserved { reason }.to_string());
        texts.push(Unavailability::OnlyGuestAsserted { reason }.to_string());
        texts.push(
            WhatToDo::Evidence {
                remedy: reason.remedy(),
            }
            .to_string(),
        );
    }
    texts.push(VerifiedBy::ControlledCheck.to_string());
    let other = digest("yougori/test/views/other/v1", &[b"x"]);
    let contract = fixture.evaluation.resolved().identity();
    for error in [
        ViewError::ContractMismatch {
            record: other,
            contract,
        },
        ViewError::PreviewForAnotherContract {
            preview: other,
            contract,
        },
        ViewError::PreviewDoesNotMatchContract,
        ViewError::Unserializable {
            detail: "x".to_owned(),
        },
    ] {
        texts.push(error.to_string());
    }
    for refusal in [
        ViewRefusal::Malformed {
            detail: "x".to_owned(),
        },
        ViewRefusal::DigestMismatch {
            stored: other,
            computed: other,
        },
        ViewRefusal::BasisDoesNotFit { index: 1 },
        ViewRefusal::OtherLaunchRecord {
            view: other,
            record: other,
        },
        ViewRefusal::OtherContract {
            view: other,
            contract,
        },
        ViewRefusal::DiffersFromContract,
    ] {
        texts.push(refusal.to_string());
    }
    for part in [
        RecordPart::Contract,
        RecordPart::Sandbox,
        RecordPart::Vm,
        RecordPart::Configuration,
        RecordPart::Clock,
        RecordPart::MaxAge,
        RecordPart::Facts,
    ] {
        texts.push(ViewRefusal::DiffersFromRecord { part }.to_string());
    }
    for text in &texts {
        assert_eq!(score_word(text), None, "{text}");
    }
    // The checker itself catches what it looks for, as whole words only.
    assert_eq!(
        score_word("a security Score of 7"),
        Some("score".to_owned())
    );
    assert_eq!(score_word("rated 90%"), Some("%".to_owned()));
    assert_eq!(score_word("an operating system upgrade"), None);
    let json: Value = serde_json::from_str(&texts[0]).unwrap();
    assert!(json.get("score").is_none());
}
