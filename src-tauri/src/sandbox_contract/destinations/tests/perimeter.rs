//! VM §4.4, VM-W15, VM-P26: the perimeter as a declared profile, and rule enforcement as
//! CORE-01 evidence only.

use std::sync::Arc;

use super::*;
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, EvidenceRefusal, Observation, PerimeterRuleSubject,
    ProbeRegistry, SourceClass, Subject, SupportDetail, UnknownReason, UnsupportedReason,
};

fn broker_identity() -> Digest {
    test_digest("broker-service-identity")
}

fn block(prefix_text: &str, length: u8) -> PerimeterRule {
    PerimeterRule {
        action: RuleAction::Block,
        prefix: IpPrefix::new(ip(prefix_text), length).unwrap(),
        ports: PortSelector::All,
    }
}

fn windows_profile(rules: Vec<PerimeterRule>) -> Result<PerimeterProfile, PerimeterError> {
    PerimeterProfile::declare(
        PerimeterPlatform::Windows,
        PerimeterOptions::default(),
        PerimeterPlatform::Windows.required_properties(PerimeterOptions::default()),
        None,
        broker_identity(),
        rules,
    )
}

fn probe(
    rule: &PerimeterRule,
    address: &str,
    without_rule: ProbeOutcome,
    with_rule: ProbeOutcome,
) -> MustProbe {
    MustProbe {
        address: ip(address),
        port: port(443),
        controlled_endpoint: true,
        rule: rule.digest(),
        probing_identity: broker_identity(),
        without_rule,
        with_rule,
    }
}

#[test]
fn each_platform_requires_its_own_properties_and_the_common_ones() {
    use PerimeterProperty as P;
    let common = [
        P::TransactionalInstall,
        P::ScopeVerified,
        P::UnrelatedRulesPreserved,
        P::RollbackAvailable,
        P::ElevationOnlyForConcreteOperations,
    ];
    let cases: &[(PerimeterPlatform, &[PerimeterProperty])] = &[
        (
            PerimeterPlatform::Linux,
            &[
                P::DedicatedIdentityOrNetNamespace,
                P::NarrowNftablesRules,
                P::ResourceLimits,
                P::EmptyNamespaceOnlyRequiredIpc,
            ],
        ),
        (
            PerimeterPlatform::Windows,
            &[
                P::ScopedToBrokerIdentity,
                P::EnabledNetworkProfilesValidated,
                P::BlockPrecedenceAccounted,
                P::MachineOutboundDefaultsUnchanged,
            ],
        ),
        (
            PerimeterPlatform::MacOs,
            &[
                P::SupportedEnforcementApiVerified,
                P::ProcessScopedNotUserScoped,
                P::NoDeprecatedOrPrivateInterface,
            ],
        ),
        (PerimeterPlatform::Remote, &[P::PerimeterOutsideGuest]),
    ];
    for (platform, specific) in cases {
        let required = platform.required_properties(PerimeterOptions::default());
        assert_eq!(
            required.len(),
            common.len() + specific.len(),
            "{platform:?}"
        );
        assert!(common
            .iter()
            .chain(specific.iter())
            .all(|property| required.contains(property)));
    }
    let rootless = PerimeterOptions {
        rootless_delegation: true,
        ..PerimeterOptions::default()
    };
    assert!(PerimeterPlatform::Linux
        .required_properties(rootless)
        .contains(&P::RootlessDelegationTested));
    assert!(!PerimeterPlatform::Windows
        .required_properties(rootless)
        .contains(&P::RootlessDelegationTested));
    let operator = PerimeterOptions {
        protects_against_provider_operator: true,
        ..PerimeterOptions::default()
    };
    assert!(PerimeterPlatform::Remote
        .required_properties(operator)
        .contains(&P::IndependentOfProviderOperator));
}

#[test]
fn a_profile_missing_a_required_property_is_refused() {
    let mut declared = PerimeterPlatform::MacOs.required_properties(PerimeterOptions::default());
    declared.remove(&PerimeterProperty::ProcessScopedNotUserScoped);
    assert_eq!(
        PerimeterProfile::declare(
            PerimeterPlatform::MacOs,
            PerimeterOptions::default(),
            declared,
            None,
            broker_identity(),
            vec![]
        ),
        Err(PerimeterError::MissingProperty {
            property: PerimeterProperty::ProcessScopedNotUserScoped
        })
    );
    let rootless = PerimeterOptions {
        rootless_delegation: true,
        ..PerimeterOptions::default()
    };
    assert_eq!(
        PerimeterProfile::declare(
            PerimeterPlatform::Linux,
            rootless,
            PerimeterPlatform::Linux.required_properties(PerimeterOptions::default()),
            None,
            broker_identity(),
            vec![]
        ),
        Err(PerimeterError::MissingProperty {
            property: PerimeterProperty::RootlessDelegationTested
        })
    );
}

#[test]
fn block_all_then_allow_is_refused_as_contradictory() {
    let block_all = block("0.0.0.0", 0);
    let allow = PerimeterRule {
        action: RuleAction::Allow,
        prefix: IpPrefix::host(ip("93.184.216.34")),
        ports: PortSelector::Only(port(443)),
    };
    assert_eq!(
        windows_profile(vec![block_all, allow]),
        Err(PerimeterError::ContradictoryRules {
            block: block_all,
            allow
        })
    );
    // Non-overlapping rules are fine, and ports matter for overlap.
    let block_smtp = PerimeterRule {
        action: RuleAction::Block,
        prefix: IpPrefix::host(ip("93.184.216.34")),
        ports: PortSelector::Only(port(25)),
    };
    assert!(windows_profile(vec![block_smtp, allow]).is_ok());
    assert!(check_rules(&[block("10.0.0.0", 8), allow]).is_ok());
}

#[test]
fn a_remote_perimeter_must_be_outside_the_guest_and_independent_when_the_operator_is_a_threat() {
    let operator = PerimeterOptions {
        protects_against_provider_operator: true,
        ..PerimeterOptions::default()
    };
    let declared = PerimeterPlatform::Remote.required_properties(operator);
    assert_eq!(
        PerimeterProfile::declare(
            PerimeterPlatform::Remote,
            operator,
            declared.clone(),
            Some(RemoteEnforcement::ProviderOperatorFirewall),
            broker_identity(),
            vec![]
        ),
        Err(PerimeterError::OperatorFirewallNotIndependent)
    );
    assert!(PerimeterProfile::declare(
        PerimeterPlatform::Remote,
        operator,
        declared.clone(),
        Some(RemoteEnforcement::IndependentNetworkControl),
        broker_identity(),
        vec![]
    )
    .is_ok());
    assert_eq!(
        PerimeterProfile::declare(
            PerimeterPlatform::Remote,
            operator,
            declared,
            None,
            broker_identity(),
            vec![]
        ),
        Err(PerimeterError::RemoteEnforcementMismatch)
    );
    let plain = PerimeterOptions::default();
    assert!(PerimeterProfile::declare(
        PerimeterPlatform::Remote,
        plain,
        PerimeterPlatform::Remote.required_properties(plain),
        Some(RemoteEnforcement::ProviderOperatorFirewall),
        broker_identity(),
        vec![]
    )
    .is_ok());
    assert_eq!(
        PerimeterProfile::declare(
            PerimeterPlatform::Linux,
            plain,
            PerimeterPlatform::Linux.required_properties(plain),
            Some(RemoteEnforcement::HostOutsideGuest),
            broker_identity(),
            vec![]
        ),
        Err(PerimeterError::RemoteEnforcementMismatch)
    );
}

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);

fn target() -> PerimeterTarget {
    PerimeterTarget {
        machine: test_digest("machine"),
        perimeter: perimeter_id(),
    }
}

fn probe_config() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(test_digest("perimeter-configuration"))
}

/// A host whose registry has one perimeter probe adapter of a fixed source class.
struct Host {
    clock: Arc<ManualClock>,
    registry: ProbeRegistry<Arc<ManualClock>>,
    probe: Arc<FakeProbe>,
}

impl Host {
    fn new(source: SourceClass) -> Self {
        let clock = Arc::new(clock());
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let probe = Arc::new(FakeProbe::new(Capability::PerimeterRuleEnforced, source));
        registry.register(Box::new(Arc::clone(&probe))).unwrap();
        Self {
            clock,
            registry,
            probe,
        }
    }

    /// The adapter reports `observation` for `subject`, and the registry stamps it.
    fn record(&mut self, subject: &PerimeterRuleSubject, observation: Observation) {
        let subject = Subject::PerimeterRule(*subject);
        self.probe.respond(&subject, observation);
        self.registry
            .refresh(Capability::PerimeterRuleEnforced, &subject)
            .unwrap();
    }

    /// Runs `must_probe` against `rule` through the host adapter.
    fn probe_rule(
        &mut self,
        rule: &PerimeterRule,
        subject: &PerimeterRuleSubject,
        must_probe: &MustProbe,
    ) {
        let observation = must_probe.observe_block_rule(rule, subject, probe_config(), HOUR);
        self.record(subject, observation);
    }

    fn assess(&self, profile: &PerimeterProfile) -> PerimeterAssessment {
        profile.assess(&self.registry, target(), MINUTE, probe_config())
    }
}

fn blocked(rule: &PerimeterRule) -> ProbeOutcome {
    ProbeOutcome::BlockedByRule {
        rule: rule.digest(),
    }
}

#[test]
fn a_block_rule_counts_as_enforced_only_through_a_fresh_host_probe_satisfied() {
    let lan = block("10.0.0.0", 8);
    let profile = windows_profile(vec![lan]).unwrap();
    let subjects = profile.block_rule_subjects(target());
    assert_eq!(subjects.len(), 1);
    let (rule, subject) = subjects[0];
    assert_eq!(rule, lan);
    assert_eq!(subject.rule, lan.digest());
    assert_eq!(subject.principal, broker_identity());
    assert_eq!(subject.perimeter, perimeter_id().digest());
    let (_, requirement) = profile.requirements(target(), MINUTE, probe_config())[0].clone();
    assert!(requirement.is_host_only());
    assert_eq!(requirement.capability, Capability::PerimeterRuleEnforced);

    let mut host = Host::new(SourceClass::HostProbe);
    // Nothing observed yet: missing, not assumed.
    let missing = host.assess(&profile);
    assert!(!missing.verified());
    assert_eq!(
        missing.refused,
        vec![(
            lan,
            EvidenceRefusal::Missing {
                capability: Capability::PerimeterRuleEnforced
            }
        )]
    );

    host.probe_rule(
        &lan,
        &subject,
        &probe(&lan, "10.20.0.5", ProbeOutcome::Connected, blocked(&lan)),
    );
    let assessment = host.assess(&profile);
    assert!(assessment.verified());
    let (enforced_rule, enforced) = &assessment.enforced[0];
    assert_eq!(*enforced_rule, lan);
    assert_eq!(enforced.subject(), &subject);
    assert_eq!(enforced.evidence().source(), SourceClass::HostProbe);
    assert_eq!(
        enforced.evidence().detail(),
        &SupportDetail::PerimeterRuleEnforced
    );
    assert_eq!(assessment.fresh_until(), Some(START.saturating_add(MINUTE)));

    // The fact is a view over fresh evidence only: after the maximum age it is refused.
    host.clock.advance(MINUTE + Duration::from_nanos(1));
    let stale = host.assess(&profile);
    assert!(!stale.verified());
    assert!(matches!(stale.refused[0].1, EvidenceRefusal::Stale { .. }));
}

#[test]
fn a_timeout_or_inconclusive_probe_never_passes() {
    let lan = block("10.0.0.0", 8);
    let profile = windows_profile(vec![lan]).unwrap();
    let (_, subject) = profile.block_rule_subjects(target())[0];
    let mut uncontrolled = probe(
        &lan,
        "10.255.255.1",
        ProbeOutcome::TimedOut,
        ProbeOutcome::TimedOut,
    );
    uncontrolled.controlled_endpoint = false;
    let cases = [
        (
            probe(
                &lan,
                "10.20.0.5",
                ProbeOutcome::Connected,
                ProbeOutcome::TimedOut,
            ),
            UnknownReason::Inconclusive,
        ),
        (
            probe(
                &lan,
                "10.20.0.5",
                ProbeOutcome::Connected,
                ProbeOutcome::FailedWithoutEvidence,
            ),
            UnknownReason::Inconclusive,
        ),
        (
            probe(
                &lan,
                "10.20.0.5",
                ProbeOutcome::Connected,
                ProbeOutcome::Unreachable,
            ),
            UnknownReason::Unreachable,
        ),
        (
            probe(&lan, "10.20.0.5", ProbeOutcome::TimedOut, blocked(&lan)),
            UnknownReason::Inconclusive,
        ),
        // A timeout to an unused private address is inconclusive (line 1989).
        (uncontrolled, UnknownReason::Inconclusive),
    ];
    for (must_probe, reason) in cases {
        let mut host = Host::new(SourceClass::HostProbe);
        host.probe_rule(&lan, &subject, &must_probe);
        let assessment = host.assess(&profile);
        assert!(!assessment.verified(), "{must_probe:?}");
        assert_eq!(
            assessment.refused[0].1,
            EvidenceRefusal::Unknown {
                capability: Capability::PerimeterRuleEnforced,
                reason
            },
            "{must_probe:?}"
        );
    }
    // A connection with the rule in place shows the rule is not enforced.
    let mut host = Host::new(SourceClass::HostProbe);
    host.probe_rule(
        &lan,
        &subject,
        &probe(
            &lan,
            "10.20.0.5",
            ProbeOutcome::Connected,
            ProbeOutcome::Connected,
        ),
    );
    assert_eq!(
        host.assess(&profile).refused[0].1,
        EvidenceRefusal::Unsupported {
            capability: Capability::PerimeterRuleEnforced,
            reason: UnsupportedReason::NotEnforced,
        }
    );
}

#[test]
fn evidence_for_another_rule_principal_machine_or_perimeter_does_not_count() {
    let lan = block("10.0.0.0", 8);
    let metadata = PerimeterRule {
        action: RuleAction::Block,
        prefix: IpPrefix::host(ip("169.254.169.254")),
        ports: PortSelector::All,
    };
    let profile = windows_profile(vec![lan]).unwrap();
    let (_, subject) = profile.block_rule_subjects(target())[0];
    let supported =
        || Observation::supported(probe_config(), HOUR, SupportDetail::PerimeterRuleEnforced);
    let others = [
        PerimeterRuleSubject {
            principal: test_digest("test-runner"),
            ..subject
        },
        PerimeterRuleSubject {
            rule: metadata.digest(),
            ..subject
        },
        PerimeterRuleSubject {
            machine: test_digest("other-machine"),
            ..subject
        },
        PerimeterRuleSubject {
            perimeter: test_digest("other-perimeter"),
            ..subject
        },
    ];
    for other in others {
        let mut host = Host::new(SourceClass::HostProbe);
        host.record(&other, supported());
        assert_eq!(
            host.assess(&profile).refused,
            vec![(
                lan,
                EvidenceRefusal::Missing {
                    capability: Capability::PerimeterRuleEnforced
                }
            )]
        );
        assert!(RuleEnforced::evaluate(&host.registry, other, MINUTE, probe_config()).is_ok());
    }

    // The probe record itself must match the subject: another identity, a block recorded
    // for another rule, or an address outside the rule is an inconsistent report.
    let mut other_identity = probe(&lan, "10.20.0.5", ProbeOutcome::Connected, blocked(&lan));
    other_identity.probing_identity = test_digest("test-runner");
    let other_rule = probe(
        &lan,
        "10.20.0.5",
        ProbeOutcome::Connected,
        blocked(&metadata),
    );
    let outside = probe(&lan, "11.0.0.1", ProbeOutcome::Connected, blocked(&lan));
    let mut named_other = probe(&lan, "10.20.0.5", ProbeOutcome::Connected, blocked(&lan));
    named_other.rule = metadata.digest();
    for must_probe in [other_identity, other_rule, outside, named_other] {
        let mut host = Host::new(SourceClass::HostProbe);
        host.probe_rule(&lan, &subject, &must_probe);
        assert_eq!(
            host.assess(&profile).refused[0].1,
            EvidenceRefusal::Unknown {
                capability: Capability::PerimeterRuleEnforced,
                reason: UnknownReason::InconsistentReport,
            },
            "{must_probe:?}"
        );
    }
}

#[test]
fn a_guest_report_or_a_changed_configuration_never_shows_enforcement() {
    let lan = block("10.0.0.0", 8);
    let profile = windows_profile(vec![lan]).unwrap();
    let (_, subject) = profile.block_rule_subjects(target())[0];
    let mut guest = Host::new(SourceClass::GuestReport);
    guest.probe_rule(
        &lan,
        &subject,
        &probe(&lan, "10.20.0.5", ProbeOutcome::Connected, blocked(&lan)),
    );
    assert_eq!(
        guest.assess(&profile).refused[0].1,
        EvidenceRefusal::SourceTooWeak {
            capability: Capability::PerimeterRuleEnforced,
            observed: SourceClass::GuestReport,
            required: SourceClass::HostProbe,
        }
    );
    let mut host = Host::new(SourceClass::HostProbe);
    host.probe_rule(
        &lan,
        &subject,
        &probe(&lan, "10.20.0.5", ProbeOutcome::Connected, blocked(&lan)),
    );
    let changed = ConfigurationFingerprint::from_digest(test_digest("rules-reinstalled"));
    let assessment = profile.assess(&host.registry, target(), MINUTE, changed);
    assert!(matches!(
        assessment.refused[0].1,
        EvidenceRefusal::FingerprintChanged { .. }
    ));
}

#[test]
fn a_profile_is_verified_only_when_every_block_rule_has_its_own_evidence() {
    let lan = block("10.0.0.0", 8);
    let metadata = PerimeterRule {
        action: RuleAction::Block,
        prefix: IpPrefix::host(ip("169.254.169.254")),
        ports: PortSelector::All,
    };
    let allow = PerimeterRule {
        action: RuleAction::Allow,
        prefix: IpPrefix::host(ip("93.184.216.34")),
        ports: PortSelector::Only(port(443)),
    };
    let profile = windows_profile(vec![lan, metadata, allow]).unwrap();
    let subjects = profile.block_rule_subjects(target());
    assert_eq!(
        subjects.iter().map(|(rule, _)| *rule).collect::<Vec<_>>(),
        vec![lan, metadata]
    );
    let mut host = Host::new(SourceClass::HostProbe);
    host.probe_rule(
        &lan,
        &subjects[0].1,
        &probe(&lan, "10.20.0.5", ProbeOutcome::Connected, blocked(&lan)),
    );
    let partial = host.assess(&profile);
    assert!(!partial.verified());
    assert_eq!(partial.enforced.len(), 1);
    assert_eq!(partial.refused[0].0, metadata);
    host.probe_rule(
        &metadata,
        &subjects[1].1,
        &probe(
            &metadata,
            "169.254.169.254",
            ProbeOutcome::Connected,
            blocked(&metadata),
        ),
    );
    assert!(host.assess(&profile).verified());
    // A profile without block rules shows nothing.
    let no_blocks = windows_profile(vec![allow]).unwrap();
    assert!(no_blocks.block_rule_subjects(target()).is_empty());
    assert!(!host.assess(&no_blocks).verified());
}

#[test]
fn an_enforcement_context_is_enforced_only_with_evidence_for_its_default_deny() {
    let endpoint = ip("10.0.5.20");
    let context = EnforcementContext::dedicated(perimeter_id(), endpoint, port(5000));
    let machine = test_digest("machine");
    let subject = context.default_deny_subject(machine, broker_identity());
    assert_eq!(subject.rule, context.default_deny_digest());
    assert!(context.permits(endpoint, port(5000)));
    assert!(!context.permits(ip("10.0.5.21"), port(5000)));
    assert!(!context.permits(endpoint, port(5001)));
    let mut host = Host::new(SourceClass::HostProbe);
    assert_eq!(
        context.enforced(
            &host.registry,
            machine,
            broker_identity(),
            MINUTE,
            probe_config()
        ),
        Err(EvidenceRefusal::Missing {
            capability: Capability::PerimeterRuleEnforced
        })
    );
    let sibling = MustProbe {
        address: ip("10.0.5.21"),
        port: port(5000),
        controlled_endpoint: true,
        rule: context.default_deny_digest(),
        probing_identity: broker_identity(),
        without_rule: ProbeOutcome::Connected,
        with_rule: ProbeOutcome::BlockedByRule {
            rule: context.default_deny_digest(),
        },
    };
    // Probing the permitted endpoint itself proves nothing about the default deny.
    let permitted = MustProbe {
        address: endpoint,
        ..sibling
    };
    host.record(
        &subject,
        permitted.observe_default_deny(&context, &subject, probe_config(), HOUR),
    );
    assert!(matches!(
        context.enforced(
            &host.registry,
            machine,
            broker_identity(),
            MINUTE,
            probe_config()
        ),
        Err(EvidenceRefusal::Unknown {
            reason: UnknownReason::InconsistentReport,
            ..
        })
    ));
    let timed_out = MustProbe {
        with_rule: ProbeOutcome::TimedOut,
        ..sibling
    };
    host.record(
        &subject,
        timed_out.observe_default_deny(&context, &subject, probe_config(), HOUR),
    );
    assert!(matches!(
        context.enforced(
            &host.registry,
            machine,
            broker_identity(),
            MINUTE,
            probe_config()
        ),
        Err(EvidenceRefusal::Unknown {
            reason: UnknownReason::Inconclusive,
            ..
        })
    ));
    host.record(
        &subject,
        sibling.observe_default_deny(&context, &subject, probe_config(), HOUR),
    );
    let enforced = context
        .enforced(
            &host.registry,
            machine,
            broker_identity(),
            MINUTE,
            probe_config(),
        )
        .unwrap();
    assert_eq!(enforced.subject(), &subject);
    // Another principal's context fact is a different subject.
    assert!(context
        .enforced(
            &host.registry,
            machine,
            test_digest("other-broker"),
            MINUTE,
            probe_config()
        )
        .is_err());
    // Another context, even for the same perimeter, names another default deny.
    let other = EnforcementContext::dedicated(perimeter_id(), ip("10.0.5.30"), port(5000));
    assert_ne!(other.default_deny_digest(), context.default_deny_digest());
    assert!(other
        .enforced(
            &host.registry,
            machine,
            broker_identity(),
            MINUTE,
            probe_config()
        )
        .is_err());
}

#[test]
fn profiles_serialize_strictly_and_state_their_limits() {
    let profile = windows_profile(vec![block("10.0.0.0", 8)]).unwrap();
    let json = serde_json::to_string(&profile).unwrap();
    let read: PerimeterProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(read, profile);
    assert_eq!(read.digest(), profile.digest());
    let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
    value["unexpected"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_str::<PerimeterProfile>(&value.to_string()).is_err());
    let mut missing: serde_json::Value = serde_json::from_str(&json).unwrap();
    missing["declared"] = serde_json::json!(["transactional_install"]);
    assert!(serde_json::from_str::<PerimeterProfile>(&missing.to_string()).is_err());
    assert!(PerimeterProfile::LIMITS
        .iter()
        .any(|limit| limit.contains("encrypted traffic")));
    assert!(PerimeterProfile::LIMITS
        .iter()
        .any(|limit| limit.contains("harmless")));
    let other = windows_profile(vec![block("10.0.0.0", 9)]).unwrap();
    assert_ne!(other.digest(), profile.digest());
}
