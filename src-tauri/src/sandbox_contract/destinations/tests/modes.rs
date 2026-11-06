//! VM §4.1: network modes, their claims, and synthetic addressing with explicit
//! collision, IPv6 and protocol handling.

use super::*;

const ALL_CLAIMS: [ModeClaim; 6] = [
    ModeClaim::NoHostFacingNic,
    ModeClaim::TypedOperationsOnly,
    ModeClaim::HostValidatesEveryOperation,
    ModeClaim::BypassFailsWithoutNic,
    ModeClaim::NoNetworkExposure,
    ModeClaim::ExplicitConnectionsOnly,
];

fn user_owned() -> NetworkMode {
    NetworkMode::UserOwnedGeneralVm {
        perimeter_profile: test_digest("user-profile"),
    }
}

fn prefix(text: &str, length: u8) -> IpPrefix {
    IpPrefix::new(ip(text), length).unwrap()
}

#[test]
fn strict_action_mode_has_no_nic_and_carries_only_typed_operations() {
    let strict = NetworkMode::StrictAction;
    assert!(!strict.has_host_facing_nic());
    for claim in [
        ModeClaim::NoHostFacingNic,
        ModeClaim::TypedOperationsOnly,
        ModeClaim::HostValidatesEveryOperation,
        ModeClaim::BypassFailsWithoutNic,
    ] {
        assert!(strict.require_claim(claim).is_ok());
    }
    assert!(strict.permits(RouteClass::Operation).is_ok());
    for class in [
        RouteClass::Transport,
        RouteClass::Publication,
        RouteClass::SandboxConnection,
    ] {
        assert_eq!(
            strict.permits(class),
            Err(ModeRefusal::RouteClassNotPermitted {
                mode: strict,
                class
            })
        );
    }
    assert_eq!(strict.broader_authority(), None);
}

#[test]
fn declared_transport_mode_reports_its_broader_authority() {
    let declared = NetworkMode::DeclaredTransport;
    assert!(declared.has_host_facing_nic());
    assert!(declared.broader_authority().unwrap().contains("conceal"));
    assert!(declared.permits(RouteClass::Transport).is_ok());
    assert!(declared.permits(RouteClass::Publication).is_ok());
    assert!(declared.require_claim(ModeClaim::NoHostFacingNic).is_err());
    assert!(declared
        .require_claim(ModeClaim::TypedOperationsOnly)
        .is_err());
}

#[test]
fn offline_mode_exposes_nothing() {
    let offline = NetworkMode::Offline;
    for class in [
        RouteClass::Operation,
        RouteClass::Transport,
        RouteClass::Publication,
        RouteClass::SandboxConnection,
    ] {
        assert!(offline.permits(class).is_err());
    }
    assert!(offline.require_claim(ModeClaim::NoNetworkExposure).is_ok());
}

#[test]
fn a_user_owned_general_vm_never_receives_any_strict_mode_claim() {
    let mode = user_owned();
    assert!(mode.claims().is_empty());
    for claim in ALL_CLAIMS {
        assert_eq!(
            mode.require_claim(claim),
            Err(ModeRefusal::ClaimNotHeld { mode, claim }),
            "{claim:?}"
        );
    }
    assert!(mode.has_host_facing_nic());
    assert!(mode.broader_authority().is_some());
    assert!(mode.label().contains("not a strict sandbox"));
}

#[test]
fn modes_serialize_strictly() {
    for mode in [
        NetworkMode::StrictAction,
        NetworkMode::DeclaredTransport,
        NetworkMode::Offline,
        user_owned(),
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(serde_json::from_str::<NetworkMode>(&json).unwrap(), mode);
    }
    assert_eq!(
        serde_json::to_string(&NetworkMode::Offline).unwrap(),
        r#"{"mode":"offline"}"#
    );
    assert!(serde_json::from_str::<NetworkMode>(r#"{"mode":"offline","nic":true}"#).is_err());
    assert!(serde_json::from_str::<NetworkMode>(r#"{"mode":"user_owned_general_vm"}"#).is_err());
    assert!(serde_json::from_str::<NetworkMode>(r#"{"mode":"permissive"}"#).is_err());
}

#[test]
fn a_cgnat_candidate_colliding_with_a_host_vpn_address_is_skipped_explicitly() {
    // The host's overlay VPN lives in CGNAT space, so CGNAT is not assumed unrouted.
    let host = HostAddressState::new(
        HostAddressGeneration::FIRST,
        [IpPrefix::host(ip("100.64.1.5"))],
    );
    let plan = SyntheticAddressPlan::choose(
        &[prefix("100.64.0.0", 16), prefix("198.18.0.0", 16)],
        &[],
        &host,
        &[],
    )
    .unwrap();
    assert_eq!(plan.ipv4_range(), prefix("198.18.0.0", 16));
    assert_eq!(
        plan.skipped(),
        &[SkippedCandidate {
            prefix: prefix("100.64.0.0", 16),
            source: CollisionSource::HostOwned,
        }]
    );
}

#[test]
fn synthetic_candidates_colliding_with_reserved_prefixes_or_metadata_are_skipped() {
    let host = HostAddressState::new(HostAddressGeneration::FIRST, []);
    let registry = IpPrefix::host(ip("100.70.0.9"));
    let plan = SyntheticAddressPlan::choose(
        &[
            prefix("100.70.0.0", 16),
            prefix("100.100.100.0", 24),
            prefix("100.80.0.0", 16),
        ],
        &[],
        &host,
        &[registry],
    )
    .unwrap();
    assert_eq!(plan.ipv4_range(), prefix("100.80.0.0", 16));
    assert_eq!(
        plan.skipped()[0].source,
        CollisionSource::Reserved(registry)
    );
    assert_eq!(
        plan.skipped()[1].source,
        CollisionSource::Metadata(ip("100.100.100.200"))
    );
}

#[test]
fn when_every_candidate_collides_nothing_is_chosen() {
    let host = HostAddressState::new(
        HostAddressGeneration::FIRST,
        [IpPrefix::new(ip("100.64.0.0"), 10).unwrap()],
    );
    let error = SyntheticAddressPlan::choose(
        &[prefix("100.64.0.0", 16), prefix("100.96.0.0", 12)],
        &[],
        &host,
        &[],
    )
    .unwrap_err();
    match error {
        SyntheticError::NoUsableCandidate { family, skipped } => {
            assert_eq!(family, AddressFamily::Ipv4);
            assert_eq!(skipped.len(), 2);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn unsuitable_synthetic_candidates_are_refused() {
    let host = HostAddressState::new(HostAddressGeneration::FIRST, []);
    // Public space would shadow real destinations.
    assert_eq!(
        SyntheticAddressPlan::choose(&[prefix("8.8.0.0", 16)], &[], &host, &[]),
        Err(SyntheticError::UnsuitableCandidate {
            prefix: prefix("8.8.0.0", 16)
        })
    );
    assert!(SyntheticAddressPlan::choose(&[prefix("fd00::", 64)], &[], &host, &[]).is_err());
    assert!(SyntheticAddressPlan::choose(&[prefix("10.0.0.0", 31)], &[], &host, &[]).is_err());
    assert_eq!(
        SyntheticAddressPlan::choose(
            &[prefix("198.18.0.0", 16)],
            &[prefix("2001:db8::", 64)],
            &host,
            &[]
        ),
        Err(SyntheticError::UnsuitableCandidate {
            prefix: prefix("2001:db8::", 64)
        })
    );
}

#[test]
fn an_aaaa_query_without_an_ipv6_grant_gets_no_ipv4_answer() {
    let host = HostAddressState::new(HostAddressGeneration::FIRST, []);
    let mut plan =
        SyntheticAddressPlan::choose(&[prefix("198.18.0.0", 16)], &[], &host, &[]).unwrap();
    let assigned = plan.assign(&name("api.example.com"), false).unwrap();
    assert_eq!(
        assigned.ipv4,
        "198.18.0.2".parse::<std::net::Ipv4Addr>().unwrap()
    );
    assert_eq!(assigned.ipv6, None);
    assert_eq!(
        plan.answer("api.example.com", GuestQueryType::A),
        SyntheticAnswer::Ipv4(assigned.ipv4)
    );
    assert_eq!(
        plan.answer("API.example.com", GuestQueryType::Aaaa),
        SyntheticAnswer::NoIpv6Grant
    );
    assert_eq!(
        plan.assign(&name("v6.example.com"), true),
        Err(SyntheticError::NoIpv6Range)
    );
}

#[test]
fn an_ipv6_grant_gets_a_unique_local_synthetic_answer() {
    let host = HostAddressState::new(HostAddressGeneration::FIRST, []);
    let mut plan = SyntheticAddressPlan::choose(
        &[prefix("198.18.0.0", 16)],
        &[prefix("fd7a:1:2:3::", 64)],
        &host,
        &[],
    )
    .unwrap();
    let both = plan.assign(&name("dual.example.com"), true).unwrap();
    let v4_only = plan.assign(&name("v4.example.com"), false).unwrap();
    assert_eq!(both.ipv6, Some("fd7a:1:2:3::2".parse().unwrap()));
    assert_eq!(
        plan.answer("dual.example.com", GuestQueryType::Aaaa),
        SyntheticAnswer::Ipv6("fd7a:1:2:3::2".parse().unwrap())
    );
    assert_eq!(
        plan.answer("v4.example.com", GuestQueryType::Aaaa),
        SyntheticAnswer::NoIpv6Grant
    );
    assert_ne!(both.ipv4, v4_only.ipv4);
    // The same name keeps its addresses; asking for IPv6 later is not a silent upgrade.
    assert_eq!(plan.assign(&name("dual.example.com"), true).unwrap(), both);
    assert_eq!(
        plan.assign(&name("v4.example.com"), true),
        Err(SyntheticError::NoIpv6Range)
    );
}

#[test]
fn unauthorized_malformed_and_unsupported_queries_are_answered_locally_and_explicitly() {
    let host = HostAddressState::new(HostAddressGeneration::FIRST, []);
    let mut plan =
        SyntheticAddressPlan::choose(&[prefix("198.18.0.0", 16)], &[], &host, &[]).unwrap();
    plan.assign(&name("api.example.com"), false).unwrap();
    assert_eq!(
        plan.answer("exfil-data.attacker.example", GuestQueryType::A),
        SyntheticAnswer::NameNotAuthorized
    );
    assert_eq!(
        plan.answer("db", GuestQueryType::A),
        SyntheticAnswer::MalformedName(NameError::SingleLabel)
    );
    for other in [
        GuestQueryType::Https,
        GuestQueryType::Svcb,
        GuestQueryType::Mx,
        GuestQueryType::Txt,
        GuestQueryType::Srv,
        GuestQueryType::Ptr,
        GuestQueryType::Any,
        GuestQueryType::Other(99),
    ] {
        assert_eq!(
            plan.answer("api.example.com", other),
            SyntheticAnswer::Unsupported(other)
        );
    }
}

#[test]
fn guest_packets_outside_mediated_tcp_and_local_dns_are_refused_explicitly() {
    let host = HostAddressState::new(HostAddressGeneration::FIRST, []);
    let mut plan =
        SyntheticAddressPlan::choose(&[prefix("198.18.0.0", 16)], &[], &host, &[]).unwrap();
    let assigned = plan.assign(&name("api.example.com"), false).unwrap();
    let synthetic = IpAddr::V4(assigned.ipv4);
    assert_eq!(
        plan.handle(synthetic, GuestProtocol::Tcp { port: 443 }),
        ProtocolHandling::MediatedByBroker {
            name: name("api.example.com"),
            port: 443
        }
    );
    assert_eq!(
        plan.handle(
            IpAddr::V4(plan.resolver_ipv4()),
            GuestProtocol::Udp { port: 53 }
        ),
        ProtocolHandling::LocalSyntheticDns
    );
    assert_eq!(
        plan.handle(synthetic, GuestProtocol::Udp { port: 443 }),
        ProtocolHandling::Refused(ProtocolRefusal::Quic)
    );
    assert_eq!(
        plan.handle(synthetic, GuestProtocol::Udp { port: 123 }),
        ProtocolHandling::Refused(ProtocolRefusal::UnsupportedProtocol)
    );
    assert_eq!(
        plan.handle(synthetic, GuestProtocol::Icmp),
        ProtocolHandling::Refused(ProtocolRefusal::UnsupportedProtocol)
    );
    assert_eq!(
        plan.handle(synthetic, GuestProtocol::Other(47)),
        ProtocolHandling::Refused(ProtocolRefusal::UnsupportedProtocol)
    );
    assert_eq!(
        plan.handle(ip("198.18.9.9"), GuestProtocol::Tcp { port: 443 }),
        ProtocolHandling::Refused(ProtocolRefusal::UnassignedAddress)
    );
    // Direct IP and alternate DNS have nowhere to go without a host-facing NIC (VM-P09).
    assert_eq!(
        plan.handle(ip("8.8.8.8"), GuestProtocol::Udp { port: 53 }),
        ProtocolHandling::Refused(ProtocolRefusal::NotSynthetic)
    );
    assert_eq!(
        plan.handle(ip("93.184.216.34"), GuestProtocol::Tcp { port: 443 }),
        ProtocolHandling::Refused(ProtocolRefusal::NotSynthetic)
    );
}

#[test]
fn a_real_address_inside_the_synthetic_range_is_a_collision() {
    let host = HostAddressState::new(HostAddressGeneration::FIRST, []);
    let plan = SyntheticAddressPlan::choose(&[prefix("100.64.0.0", 16)], &[], &host, &[]).unwrap();
    assert_eq!(
        plan.check_real_address(ip("100.64.7.7")),
        Err(SyntheticError::Collision {
            address: ip("100.64.7.7"),
            prefix: prefix("100.64.0.0", 16)
        })
    );
    assert!(plan.check_real_address(ip("100.65.0.1")).is_ok());
}

#[test]
fn a_small_synthetic_range_reports_exhaustion() {
    let host = HostAddressState::new(HostAddressGeneration::FIRST, []);
    // A /30 has four addresses: network, resolver, one name, broadcast.
    let mut plan =
        SyntheticAddressPlan::choose(&[prefix("198.18.0.0", 30)], &[], &host, &[]).unwrap();
    plan.assign(&name("one.example.com"), false).unwrap();
    assert_eq!(
        plan.assign(&name("two.example.com"), false),
        Err(SyntheticError::Exhausted {
            family: AddressFamily::Ipv4
        })
    );
}
