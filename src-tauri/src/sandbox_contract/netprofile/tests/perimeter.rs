//! The profile compiled into an independent perimeter (VM-W59; VM §4.4): exact allows,
//! the forbidden blocked, V02 `check_rules`, and a claim that fails instead of widening.

use super::*;
use crate::foundation::evidence::ConfigurationFingerprint;
use crate::sandbox_contract::destinations::{
    PerimeterError, PerimeterProperty, PerimeterRule, PerimeterTarget, PortSelector, RuleAction,
    ServiceIdentity, METADATA_IPV4, METADATA_IPV6,
};

fn compile(
    document: NetworkProfileDocument,
    host: &HostAddressState,
) -> Result<CompiledPerimeter, Vec<PerimeterGap>> {
    let profile = NetworkProfile::new(document).unwrap();
    compile_perimeter(
        &profile,
        &new_pool(),
        host,
        perimeter_base(),
        full_capabilities(),
    )
}

fn allow(prefix_text: &str, port_number: u16) -> PerimeterRule {
    PerimeterRule {
        action: RuleAction::Allow,
        prefix: prefix(prefix_text),
        ports: PortSelector::Only(port(port_number)),
    }
}

#[test]
fn a_pinned_profile_compiles_to_exact_port_scoped_allows_and_blocks() {
    let compiled = compile(pinned_document(), &host_state()).unwrap();
    let allows: BTreeSet<PerimeterRule> = compiled
        .rules()
        .iter()
        .filter(|rule| rule.action == RuleAction::Allow)
        .copied()
        .collect();
    assert_eq!(
        allows,
        BTreeSet::from([
            allow("151.101.0.0/24", 443),
            allow("2a04:4e42::/48", 443),
            allow("140.82.112.0/24", 443),
            allow("10.50.0.20/32", 5000),
            allow("93.184.215.14/32", 443),
            allow("9.9.9.9/32", 53),
        ])
    );
    for address in METADATA_IPV4
        .iter()
        .map(|address| IpAddr::V4(*address))
        .chain(METADATA_IPV6.iter().map(|address| IpAddr::V6(*address)))
    {
        assert!(compiled.rules().contains(&PerimeterRule {
            action: RuleAction::Block,
            prefix: IpPrefix::host(address),
            ports: PortSelector::All,
        }));
        assert!(!compiled.permits(address, port(443)));
    }
    for owned in host_state().owned() {
        assert!(!compiled.permits(owned.network(), port(443)));
    }
    for pool_prefix in new_pool().prefixes() {
        assert!(!compiled.permits(pool_prefix.network(), port(443)));
    }
    assert!(crate::sandbox_contract::destinations::check_rules(compiled.rules()).is_ok());
    assert!(compiled.permits(ip(PYPI_V4), port(443)));
    assert!(!compiled.permits(ip(PYPI_V4), port(80)));
    assert!(!compiled.permits(ip("1.1.1.1"), port(443)));
    assert!(!compiled.permits(ip("10.50.0.21"), port(5000)));
    assert_eq!(
        compiled.sources().get(&allow("10.50.0.20/32", 5000)),
        Some(&BTreeSet::from([RuleSource::Endpoint {
            route: route("registry")
        }]))
    );
    assert_eq!(
        compiled.network_profile(),
        NetworkProfile::new(pinned_document()).unwrap().digest()
    );
}

#[test]
fn a_name_grant_without_perimeter_prefixes_fails_the_claim_instead_of_widening() {
    let gaps = compile(sample_document(), &host_state()).unwrap_err();
    assert_eq!(
        gaps,
        vec![PerimeterGap::NameGrantWithoutPerimeterPrefixes {
            route: route("github")
        }]
    );
}

#[test]
fn rules_the_platform_cannot_express_are_gaps_listed_together() {
    let profile = NetworkProfile::new(pinned_document()).unwrap();
    let capabilities = PerimeterCapabilities {
        ipv4_rules: false,
        ipv6_rules: false,
        port_scoped_rules: false,
        max_rules: 3,
    };
    let gaps = compile_perimeter(
        &profile,
        &new_pool(),
        &host_state(),
        perimeter_base(),
        capabilities,
    )
    .unwrap_err();
    assert!(gaps.contains(&PerimeterGap::Ipv4RulesUnsupported));
    assert!(gaps.contains(&PerimeterGap::Ipv6RulesUnsupported));
    assert!(gaps.contains(&PerimeterGap::PortScopingUnsupported));
    assert!(gaps
        .iter()
        .any(|gap| matches!(gap, PerimeterGap::TooManyRules { max: 3, .. })));

    let only_ipv6_missing = PerimeterCapabilities {
        ipv6_rules: false,
        ..full_capabilities()
    };
    assert_eq!(
        compile_perimeter(
            &profile,
            &new_pool(),
            &host_state(),
            perimeter_base(),
            only_ipv6_missing
        ),
        Err(vec![PerimeterGap::Ipv6RulesUnsupported])
    );
}

#[test]
fn an_endpoint_the_host_now_owns_makes_the_rule_set_contradictory() {
    let host = HostAddressState::new(
        HostAddressGeneration::new(2),
        host_state()
            .owned()
            .copied()
            .chain([IpPrefix::host(ip(REGISTRY))]),
    );
    let gaps = compile(pinned_document(), &host).unwrap_err();
    assert!(matches!(
        gaps.as_slice(),
        [PerimeterGap::Contradictory(
            PerimeterError::ContradictoryRules { .. }
        )]
    ));
}

#[test]
fn the_v02_declaration_still_requires_every_platform_property() {
    let profile = NetworkProfile::new(pinned_document()).unwrap();
    let mut base = perimeter_base();
    base.declared
        .remove(&PerimeterProperty::NarrowNftablesRules);
    assert_eq!(
        compile_perimeter(
            &profile,
            &new_pool(),
            &host_state(),
            base,
            full_capabilities()
        ),
        Err(vec![PerimeterGap::Declaration(
            PerimeterError::MissingProperty {
                property: PerimeterProperty::NarrowNftablesRules
            }
        )])
    );
}

#[test]
fn the_launch_perimeter_asks_core01_for_every_block_rule() {
    let compiled = compile(pinned_document(), &host_state()).unwrap();
    let target = PerimeterTarget {
        machine: test_digest("machine"),
        perimeter: perimeter_id(),
    };
    let launch = compiled.launch_perimeter(
        target,
        ConfigurationFingerprint::from_digest(test_digest("perimeter-config")),
    );
    assert_eq!(&launch.profile, compiled.profile());
    let blocks = compiled
        .rules()
        .iter()
        .filter(|rule| rule.action == RuleAction::Block)
        .count();
    assert_eq!(launch.profile.block_rule_subjects(target).len(), blocks);
    assert!(blocks > 0);
}

#[test]
fn links_publications_and_listeners_are_listed_as_host_transport_decisions() {
    let mut document = pinned_document();
    document.ingress.push(PublicationEntry {
        service: ServiceIdentity::new("web").unwrap(),
        port: port(8080),
        audience: PublicationAudience::Public,
        authentication: PublicationAuthentication::None,
        lifetime_seconds: NonZeroU64::new(600).unwrap(),
    });
    document.links.push(LinkEntry {
        direction: LinkDirection::Outbound,
        peer: LinkPeer {
            execution: exec("sbx-b"),
            scope: scope("sbx-b"),
        },
        service: ServiceIdentity::new("model").unwrap(),
        port: port(9000),
        lifetime_seconds: NonZeroU64::new(600).unwrap(),
    });
    let compiled = compile(document, &host_state()).unwrap();
    let decisions = compiled.host_transport_decisions();
    assert!(decisions.contains(&HostTransportDecision::GatewayListeners));
    assert!(decisions.contains(&HostTransportDecision::Publication {
        service: ServiceIdentity::new("web").unwrap(),
        port: port(8080)
    }));
    assert!(decisions
        .iter()
        .any(|decision| matches!(decision, HostTransportDecision::SandboxLink { .. })));
    assert!(!compiled.permits(ip("10.200.0.3"), port(9000)));
}

#[test]
fn compiling_is_deterministic_and_order_independent() {
    let first = compile(pinned_document(), &host_state()).unwrap();
    let mut permuted = pinned_document();
    permuted.egress.reverse();
    let second = compile(permuted, &host_state()).unwrap();
    assert_eq!(first.profile().digest(), second.profile().digest());
    assert_eq!(first.rules(), second.rules());
}
