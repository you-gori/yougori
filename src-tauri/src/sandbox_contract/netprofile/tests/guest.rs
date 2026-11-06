//! Guest compatibility (VM-W08: proxy first, TUN or synthetic names only when justified)
//! and the network-authority facet (VM §1.3: facets, never a score).

use super::*;
use crate::sandbox_contract::destinations::{CollisionSource, ModeClaim, NetworkMode};
use crate::sandbox_contract::policy::{DeploymentFacet, SecurityPredicate};

fn justification() -> Justification {
    Justification {
        reason: text("the legacy updater ignores proxy variables"),
        applications: BTreeSet::from([ApplicationName::new("legacy-updater").unwrap()]),
        implementation: ImplementationName::new("gvisor-netstack").unwrap(),
    }
}

fn environment(plan: &GuestNetworkPlan) -> BTreeMap<String, String> {
    plan.proxy_environment.iter().cloned().collect()
}

#[test]
fn the_guest_is_configured_proxy_first_with_the_host_listener_as_resolver() {
    let profile = sample_profile();
    let plan = guest_plan(&profile, &new_pool(), &host_state()).unwrap();
    assert_eq!(plan.dns_server_ipv4.to_string(), GATEWAY);
    assert_eq!(
        plan.dns_server_ipv6.map(|address| address.to_string()),
        Some(GATEWAY_V6.to_owned())
    );
    let environment = environment(&plan);
    assert_eq!(environment["HTTPS_PROXY"], "http://10.200.0.1:3128");
    assert_eq!(environment["https_proxy"], "http://10.200.0.1:3128");
    assert_eq!(environment["ALL_PROXY"], "socks5h://10.200.0.1:1080");
    assert_eq!(environment["NO_PROXY"], "localhost,127.0.0.1,::1");
    assert_eq!(plan.tun, None);
    assert_eq!(plan.synthetic, None);

    let mut document = sample_document();
    document.guest.proxy.http_connect = false;
    let socks_only = guest_plan(
        &NetworkProfile::new(document).unwrap(),
        &new_pool(),
        &host_state(),
    )
    .unwrap();
    let environment = self::environment(&socks_only);
    assert!(!environment.contains_key("HTTPS_PROXY"));
    assert!(environment.contains_key("ALL_PROXY"));
}

#[test]
fn justified_layers_are_planned_with_collision_handled_synthetic_ranges() {
    let mut document = sample_document();
    document.guest.tun = Some(justification());
    document.guest.synthetic_names = Some(justification());
    let profile = NetworkProfile::new(document).unwrap();
    let plan = guest_plan(&profile, &new_pool(), &host_state()).unwrap();
    let tun = plan.tun.unwrap();
    assert_eq!(tun.implementation.as_str(), "gvisor-netstack");
    assert_eq!(tun.applications.len(), 1);
    let synthetic = plan.synthetic.unwrap();
    // 100.101.0.0/16 holds the host's VPN address, so V02 skips it and records why.
    assert_eq!(synthetic.ipv4_range, prefix("198.18.0.0/24"));
    assert_eq!(synthetic.skipped.len(), 1);
    assert_eq!(synthetic.skipped[0].prefix, prefix("100.101.0.0/16"));
    assert_eq!(synthetic.skipped[0].source, CollisionSource::HostOwned);
    assert_eq!(synthetic.ipv6_range, Some(prefix("fd99::/64")));
    assert_eq!(synthetic.resolver_ipv4.to_string(), "198.18.0.1");

    let mut config = pool_config();
    config.synthetic_ipv4_candidates = vec![prefix("100.101.0.0/16")];
    let pool = SandboxAddressPool::new(config, &host_state()).unwrap();
    assert!(matches!(
        guest_plan(&profile, &pool, &host_state()),
        Err(GuestPlanError::Synthetic(_))
    ));
}

#[test]
fn the_plan_never_claims_to_change_a_host_decision() {
    assert!(GuestNetworkPlan::HOST_INDEPENDENCE.contains("change"));
    assert!(GuestNetworkPlan::HOST_INDEPENDENCE.contains("no host decision"));
}

#[test]
fn the_authority_report_lists_every_grant_and_no_score() {
    let mut document = pinned_document();
    document.guest.tun = Some(justification());
    document.ingress.push(PublicationEntry {
        service: crate::sandbox_contract::destinations::ServiceIdentity::new("web").unwrap(),
        port: port(8080),
        audience: PublicationAudience::Public,
        authentication: PublicationAuthentication::None,
        lifetime_seconds: NonZeroU64::new(600).unwrap(),
    });
    let profile = NetworkProfile::new(document).unwrap();
    let report = NetworkAuthorityReport::of(&profile);
    assert_eq!(report.facet, DeploymentFacet::NetworkAuthority);
    assert_eq!(report.profile, profile.digest());
    assert_eq!(report.mode, NetworkMode::DeclaredTransport);
    assert!(report.broader_authority.is_some());
    assert_eq!(report.claims_held, vec![ModeClaim::ExplicitConnectionsOnly]);
    assert_eq!(
        report
            .claims_refused
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        strict_claims()
    );
    assert_eq!(
        report.unsatisfiable_predicates,
        vec![
            SecurityPredicate::NoDirectGuestNetwork,
            SecurityPredicate::ContractOffline
        ]
    );
    assert!(report.entries.contains(&AuthorityEntry::ExactEndpoint {
        route: route("registry"),
        reference: "10.50.0.20:5000".to_owned(),
        reason: text("the team's private package registry"),
        private_exception: true,
    }));
    assert!(report.entries.iter().any(|entry| matches!(
        entry,
        AuthorityEntry::ExactEndpoint { route: granted, private_exception: false, .. } if *granted == route("mirror")
    )));
    assert!(report.entries.iter().any(|entry| matches!(
        entry,
        AuthorityEntry::NamedTransportRoute { reference, .. } if reference == "pypi.org:443"
    )));
    assert!(report
        .entries
        .iter()
        .any(|entry| matches!(entry, AuthorityEntry::Publication { public: true, .. })));
    assert!(report
        .entries
        .iter()
        .any(|entry| matches!(entry, AuthorityEntry::GuestLayer { .. })));
    assert!(report
        .entries
        .iter()
        .any(|entry| matches!(entry, AuthorityEntry::AllowedResolver { .. })));

    let lines = report.lines();
    assert!(lines
        .iter()
        .any(|line| line.starts_with("private exception registry: 10.50.0.20:5000")));
    for line in &lines {
        let lower = line.to_lowercase();
        for word in ["score", "tier", "level", "rating"] {
            assert!(!lower.contains(word), "{line}");
        }
    }

    let mut owned = pinned_document();
    owned.kind = BroaderNetworkKind::UserOwnedGeneralVm;
    let owned = NetworkAuthorityReport::of(&NetworkProfile::new(owned).unwrap());
    assert!(owned.claims_held.is_empty());

    let mut empty = sample_document();
    empty.egress.clear();
    empty.resolvers.clear();
    let empty = NetworkAuthorityReport::of(&NetworkProfile::new(empty).unwrap());
    assert_eq!(
        empty.unsatisfiable_predicates,
        vec![SecurityPredicate::NoDirectGuestNetwork]
    );
    assert!(owned.lines()[0].contains("not a strict sandbox"));
}
