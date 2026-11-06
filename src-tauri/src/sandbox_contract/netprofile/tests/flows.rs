//! The host flow model (VM-W59 acceptance): host and cross-sandbox access only as
//! granted; IPv4 and IPv6; NAT; reconnects; private exceptions; quotas and budgets;
//! transports (VM-P08, VM-P36).

use super::*;
use crate::sandbox_contract::destinations::{
    AddressClass, AddressRule, AuthorizationRefusal, BudgetKind, ConnectionRefusal,
    EmbeddedIpv4Form, MissingSide, ReleaseError, ServiceIdentity,
};

fn link(direction: LinkDirection, peer: &str, service: &str, port_number: u16) -> LinkEntry {
    LinkEntry {
        direction,
        peer: LinkPeer {
            execution: exec(peer),
            scope: scope(peer),
        },
        service: ServiceIdentity::new(service).unwrap(),
        port: port(port_number),
        lifetime_seconds: NonZeroU64::new(600).unwrap(),
    }
}

fn refused_class(result: Result<FlowAdmission, FlowRefusal>) -> AddressClass {
    match result {
        Err(FlowRefusal::Address(refused)) => refused.verdict.class,
        other => panic!("expected an address refusal, got {other:?}"),
    }
}

#[test]
fn host_access_is_prohibited_except_the_dns_and_proxy_listeners() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    assert_eq!(world.tcp(&a, GATEWAY, 53).unwrap().kind, FlowKind::LocalDns);
    assert_eq!(
        world.open(&a, Transport::Udp, GATEWAY, 53).unwrap().kind,
        FlowKind::LocalDns
    );
    assert_eq!(
        world.tcp(&a, GATEWAY_V6, 53).unwrap().kind,
        FlowKind::LocalDns
    );
    let proxy = world.tcp(&a, GATEWAY, 3128).unwrap();
    assert_eq!(
        proxy.kind,
        FlowKind::LocalProxy {
            listener: ProxyListener::HttpConnect
        }
    );
    assert_eq!(proxy.nat, None);
    assert_eq!(
        world.tcp(&a, GATEWAY, 1080).unwrap().kind,
        FlowKind::LocalProxy {
            listener: ProxyListener::Socks5
        }
    );
    for port_number in [22, 80, 443, 853, 8080] {
        assert_eq!(
            world.tcp(&a, GATEWAY, port_number),
            Err(FlowRefusal::HostService {
                address: ip(GATEWAY),
                port: port_number
            })
        );
    }
    assert!(matches!(
        world.open(&a, Transport::Udp, GATEWAY, 853),
        Err(FlowRefusal::HostService { .. })
    ));
    assert!(matches!(
        world.open(&a, Transport::Icmp, GATEWAY, 0),
        Err(FlowRefusal::HostService { .. })
    ));
    for host in [HOST_LAN, HOST_VPN, EGRESS_V6] {
        assert_eq!(
            refused_class(world.tcp(&a, host, 443)),
            AddressClass::HostOwned,
            "{host}"
        );
    }
    assert_eq!(
        refused_class(world.tcp(&a, "127.0.0.1", 443)),
        AddressClass::Loopback
    );
    assert_eq!(
        refused_class(world.tcp(&a, "::1", 443)),
        AddressClass::Loopback
    );

    let host_endpoint = world
        .try_add("sbx-b", |document| {
            document.egress.push(endpoint_grant(
                "host-db",
                HOST_LAN,
                5432,
                None,
                "the host's database",
            ))
        })
        .unwrap_err();
    assert_eq!(
        host_endpoint,
        AdmitError::EndpointNotExternal {
            route: route("host-db"),
            address: ip(HOST_LAN)
        }
    );
    let sandbox_endpoint = world
        .try_add("sbx-c", |document| {
            document.egress.push(endpoint_grant(
                "peer",
                "10.200.0.9",
                22,
                None,
                "a neighbour",
            ))
        })
        .unwrap_err();
    assert!(matches!(
        sandbox_endpoint,
        AdmitError::EndpointNotExternal { .. }
    ));
}

#[test]
fn cross_sandbox_access_needs_grants_at_both_ends_and_is_never_transitive() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |document| {
        document
            .links
            .push(link(LinkDirection::Outbound, "sbx-b", "model", 9000));
        document
            .links
            .push(link(LinkDirection::Outbound, "sbx-c", "cache", 9100));
    });
    let b = world.add("sbx-b", |document| {
        document
            .links
            .push(link(LinkDirection::Inbound, "sbx-a", "model", 9000));
        document
            .links
            .push(link(LinkDirection::Outbound, "sbx-c", "store", 9200));
    });
    let c = world.add("sbx-c", |document| {
        document
            .links
            .push(link(LinkDirection::Inbound, "sbx-b", "store", 9200));
        document
            .links
            .push(link(LinkDirection::Outbound, "sbx-a", "hello", 9300));
    });
    let a_address = world.identity(&a).ipv4.to_string();
    let b_address = world.identity(&b).ipv4.to_string();
    let c_address = world.identity(&c).ipv4.to_string();

    let admitted = world.tcp(&a, &b_address, 9000).unwrap();
    assert_eq!(
        admitted.kind,
        FlowKind::SandboxLink {
            callee: world.identity(&b).endpoint(),
            service: ServiceIdentity::new("model").unwrap()
        }
    );
    assert_eq!(admitted.nat, None);
    let missing = |side| {
        Err(FlowRefusal::Connection(ConnectionRefusal::MissingGrant {
            side,
        }))
    };
    assert_eq!(world.tcp(&a, &b_address, 9001), missing(MissingSide::Both));
    assert_eq!(world.tcp(&b, &a_address, 9000), missing(MissingSide::Both));
    assert_eq!(
        world.tcp(&a, &c_address, 9100),
        missing(MissingSide::Callee)
    );
    assert_eq!(
        world.tcp(&c, &a_address, 9300),
        missing(MissingSide::Callee)
    );
    assert!(world.tcp(&b, &c_address, 9200).is_ok());
    // a reaches b and b reaches c, yet a does not reach c's store.
    assert_eq!(world.tcp(&a, &c_address, 9200), missing(MissingSide::Both));
    assert_eq!(
        world.open(&a, Transport::Udp, &b_address, 9000),
        Err(FlowRefusal::TransportNotGranted {
            transport: Transport::Udp
        })
    );
    assert_eq!(
        world.tcp(&a, "10.200.0.200", 22),
        Err(FlowRefusal::UnassignedSandboxAddress {
            address: ip("10.200.0.200")
        })
    );
    assert_eq!(world.tcp(&a, &a_address, 22), Err(FlowRefusal::OwnAddress));
}

#[test]
fn admission_checks_the_assigned_identity_and_admits_once() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let unassigned = sample_profile();
    let admit = |world: &mut World, profile: NetworkProfile| {
        world.net.admit(
            profile,
            perimeter_id(),
            GeneralReleaseBudget::vm_d12_default(),
            Duration::from_secs(3_600),
        )
    };
    assert_eq!(
        admit(&mut world, unassigned.clone()),
        Err(AdmitError::IdentityNotAssigned {
            execution: exec("sbx-a")
        })
    );
    let assigned = world
        .net
        .assign_identity(exec("sbx-a"), scope("sbx-a"))
        .unwrap();
    let mut wrong = sample_document();
    wrong.identity = NetworkIdentity {
        ipv4: "10.200.0.77".parse().unwrap(),
        ..assigned.clone()
    };
    assert_eq!(
        admit(&mut world, NetworkProfile::new(wrong).unwrap()),
        Err(AdmitError::IdentityMismatch)
    );
    let mut long_lived = base_document(assigned.clone());
    long_lived.ingress.push(PublicationEntry {
        service: ServiceIdentity::new("web").unwrap(),
        port: port(8080),
        audience: PublicationAudience::Public,
        authentication: PublicationAuthentication::None,
        lifetime_seconds: NonZeroU64::new(7_200).unwrap(),
    });
    assert!(matches!(
        admit(&mut world, NetworkProfile::new(long_lived).unwrap()),
        Err(AdmitError::Ingress(
            crate::sandbox_contract::destinations::IngressError::ExpiryTooFar { .. }
        ))
    ));
    let profile = NetworkProfile::new(base_document(assigned)).unwrap();
    assert_eq!(admit(&mut world, profile.clone()), Ok(()));
    assert_eq!(
        admit(&mut world, profile),
        Err(AdmitError::AlreadyAdmitted {
            execution: exec("sbx-a")
        })
    );
}

#[test]
fn nothing_is_published_by_default() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    assert!(matches!(
        world.net.admit_inbound(
            &a,
            &ServiceIdentity::new("web").unwrap(),
            port(8080),
            &crate::sandbox_contract::destinations::InboundCaller::Anonymous
        ),
        Err(FlowRefusal::Ingress(
            crate::sandbox_contract::destinations::IngressError::NotPublished { .. }
        ))
    ));
    assert!(world.net.flows(&a).is_empty());
}

#[test]
fn a_linked_client_does_not_inherit_the_callees_routes() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let client = world.add("sbx-a", |document| {
        document
            .links
            .push(link(LinkDirection::Outbound, "sbx-b", "model", 9000));
        document.egress.retain(|grant| grant.id != route("github"));
    });
    let model = world.add("sbx-b", |document| {
        document
            .links
            .push(link(LinkDirection::Inbound, "sbx-a", "model", 9000));
    });
    let model_address = world.identity(&model).ipv4.to_string();
    assert!(world.tcp(&client, &model_address, 9000).is_ok());
    world.dns(&model, "github.com", GuestQueryType::A);
    assert!(world.tcp(&model, GITHUB_V4, 443).is_ok());
    assert_eq!(
        world.dns(&client, "github.com", GuestQueryType::A),
        DnsAnswer::NameNotAuthorized
    );
    assert!(matches!(
        world.tcp(&client, GITHUB_V4, 443),
        Err(FlowRefusal::Authorization(
            AuthorizationRefusal::AddressNeedsEndpointGrant { .. }
        ))
    ));
    assert!(matches!(
        world.proxy(&client, "github.com:443"),
        Err(FlowRefusal::Authorization(
            AuthorizationRefusal::NotGranted { .. }
        ))
    ));
}

#[test]
fn a_sandbox_whose_address_the_host_now_owns_sends_nothing() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let own = world.identity(&a).ipv4;
    let host = HostAddressState::new(
        HostAddressGeneration::new(2),
        host_state()
            .owned()
            .copied()
            .chain([IpPrefix::host(IpAddr::V4(own))]),
    );
    world.net.replace_host_addresses(host).unwrap();
    assert_eq!(
        world.tcp(&a, MIRROR, 443),
        Err(FlowRefusal::IdentityHostOwned {
            address: IpAddr::V4(own)
        })
    );
}

#[test]
fn a_caller_missing_its_own_grant_is_named() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let f = world.add("sbx-f", |document| {
        document
            .links
            .push(link(LinkDirection::Inbound, "sbx-g", "api", 7000));
    });
    let g = world.add("sbx-g", |_| {});
    let f_address = world.identity(&f).ipv4.to_string();
    assert_eq!(
        world.tcp(&g, &f_address, 7000),
        Err(FlowRefusal::Connection(ConnectionRefusal::MissingGrant {
            side: MissingSide::Caller
        }))
    );
}

#[test]
fn an_expired_link_closes_its_flow_at_the_next_packet() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |document| {
        document
            .links
            .push(link(LinkDirection::Outbound, "sbx-b", "model", 9000));
    });
    let b = world.add("sbx-b", |document| {
        document
            .links
            .push(link(LinkDirection::Inbound, "sbx-a", "model", 9000));
    });
    let b_address = world.identity(&b).ipv4.to_string();
    let key = world.key(&a, Transport::Tcp, &b_address, 9000);
    let flow = world.net.open_flow(&a, key).unwrap().flow;
    assert_eq!(world.net.packet(&a, &key), Ok(flow));
    clock.advance(Duration::from_secs(600));
    assert!(matches!(
        world.net.packet(&a, &key),
        Err(FlowRefusal::Connection(_))
    ));
    assert_eq!(world.net.packet(&a, &key), Err(FlowRefusal::NotEstablished));
    assert!(world.net.flow(&a, flow).is_none());
}

#[test]
fn a_guest_cannot_spoof_its_source_or_mix_families() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let b = world.add("sbx-b", |_| {});
    let mut key = world.key(&a, Transport::Tcp, MIRROR, 443);
    key.source = IpAddr::V4(world.identity(&b).ipv4);
    assert_eq!(
        world.net.open_flow(&a, key),
        Err(FlowRefusal::SpoofedSource { source: key.source })
    );
    key.source = ip("10.200.0.77");
    assert!(matches!(
        world.net.open_flow(&a, key),
        Err(FlowRefusal::SpoofedSource { .. })
    ));
    key.source = ip("fd00:200::2");
    assert_eq!(
        world.net.open_flow(&a, key),
        Err(FlowRefusal::FamilyMismatch)
    );
    assert_eq!(
        world.net.open_flow(&exec("sbx-unknown"), key),
        Err(FlowRefusal::UnknownSandbox {
            execution: exec("sbx-unknown")
        })
    );
}

#[test]
fn a_sandbox_without_ipv6_gets_no_aaaa_answer_and_no_ipv6_flow() {
    let clock = new_clock();
    let mut config = pool_config();
    config.ipv6 = None;
    config.nat.egress_ipv6 = None;
    let pool = SandboxAddressPool::new(config, &host_state()).unwrap();
    let mut world = World::with_pool(&clock, pool);
    let a = world.add("sbx-a", |_| {});
    assert_eq!(
        world.dns(&a, "pypi.org", GuestQueryType::Aaaa),
        DnsAnswer::NoData
    );
    assert_eq!(world.external_calls(), 0);
    let key = FlowKey {
        transport: Transport::Tcp,
        source: ip("fd00:200::2"),
        source_port: 1234,
        destination: ip(PYPI_V6),
        destination_port: 443,
    };
    assert_eq!(
        world.net.open_flow(&a, key),
        Err(FlowRefusal::NoIpv6Identity)
    );
}

#[test]
fn ipv4_and_ipv6_of_a_granted_name_decide_identically() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    assert!(matches!(
        world.dns(&a, "pypi.org", GuestQueryType::A),
        DnsAnswer::Addresses { ref addresses, external: true, .. } if *addresses == vec![ip(PYPI_V4), ip(PYPI_V4_B)]
    ));
    assert!(matches!(
        world.dns(&a, "pypi.org", GuestQueryType::Aaaa),
        DnsAnswer::Addresses { ref addresses, .. } if *addresses == vec![ip(PYPI_V6)]
    ));
    let over_ipv4 = world.tcp(&a, PYPI_V4, 443).unwrap();
    let over_ipv6 = world.tcp(&a, PYPI_V6, 443).unwrap();
    assert_eq!(over_ipv4.kind, over_ipv6.kind);
    assert_eq!(
        over_ipv4.kind,
        FlowKind::Named {
            route: route("pypi"),
            name: name("pypi.org")
        }
    );
    assert_eq!(over_ipv4.nat.unwrap().outside.0, ip("192.168.1.10"));
    assert_eq!(over_ipv6.nat.unwrap().outside.0, ip(EGRESS_V6));
    let over_ipv4 = world.tcp(&a, PYPI_V4, 80);
    assert!(matches!(
        over_ipv4,
        Err(FlowRefusal::Authorization(
            AuthorizationRefusal::PortNotGranted { .. }
        ))
    ));
    assert_eq!(over_ipv4, world.tcp(&a, PYPI_V6, 80));
    let calls = world.external_calls();
    assert_eq!(
        world.dns(&a, "github.com", GuestQueryType::Aaaa),
        DnsAnswer::NoData
    );
    assert_eq!(world.external_calls(), calls);
}

#[test]
fn mapped_translated_and_tunnelled_forms_never_stand_in_for_ipv4() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    world.dns(&a, "pypi.org", GuestQueryType::A);
    assert!(world.tcp(&a, PYPI_V4, 443).is_ok());
    assert!(world.tcp(&a, MIRROR, 443).is_ok());
    let cases = [
        ("::ffff:151.101.0.223", EmbeddedIpv4Form::Mapped),
        ("::ffff:93.184.215.14", EmbeddedIpv4Form::Mapped),
        ("64:ff9b::9765:df", EmbeddedIpv4Form::Nat64WellKnown),
        ("2002:9765:df::1", EmbeddedIpv4Form::SixToFour),
        ("::ffff:10.0.0.1", EmbeddedIpv4Form::Mapped),
    ];
    for (address, form) in cases {
        assert_eq!(
            refused_class(world.tcp(&a, address, 443)),
            AddressClass::EmbeddedIpv4(form),
            "{address}"
        );
    }
}

#[test]
fn refused_classes_are_the_same_in_both_families() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let pairs = [
        ("10.0.0.1", "fd12::1", AddressClass::Private),
        ("169.254.169.254", "fd00:ec2::254", AddressClass::Metadata),
        ("169.254.7.7", "fe80::7", AddressClass::LinkLocal),
        ("224.0.0.251", "ff02::fb", AddressClass::Multicast),
        ("127.0.0.53", "::1", AddressClass::Loopback),
        ("0.0.0.0", "::", AddressClass::Unspecified),
        ("192.0.2.9", "2001:db8::9", AddressClass::Documentation),
    ];
    for (ipv4, ipv6, class) in pairs {
        assert_eq!(refused_class(world.tcp(&a, ipv4, 443)), class, "{ipv4}");
        assert_eq!(refused_class(world.tcp(&a, ipv6, 443)), class, "{ipv6}");
    }
    assert_eq!(
        refused_class(world.tcp(&a, "255.255.255.255", 443)),
        AddressClass::Broadcast
    );
}

#[test]
fn nat_is_deterministic_per_sandbox_block_and_matches_only_replies() {
    let run = || {
        let clock = new_clock();
        let mut world = World::new(&clock);
        let a = world.add("sbx-a", |_| {});
        let b = world.add("sbx-b", |_| {});
        world.dns(&a, "pypi.org", GuestQueryType::A);
        let mut admissions = Vec::new();
        for sandbox in [&a, &b, &a] {
            admissions.push(world.tcp(sandbox, MIRROR, 443));
        }
        admissions.push(world.tcp(&a, PYPI_V4, 443));
        admissions
    };
    let first = run();
    assert_eq!(first, run());
    let outside: Vec<u16> = first
        .iter()
        .map(|admission| admission.as_ref().unwrap().nat.unwrap().outside.1)
        .collect();
    assert_eq!(outside, vec![20_000, 20_008, 20_001, 20_002]);
    for admission in &first {
        let mapping = admission.as_ref().unwrap().nat.unwrap();
        assert!(!new_pool().contains(mapping.destination.0));
        assert!(!host_state().owns(mapping.destination.0));
    }

    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let admission = world.tcp(&a, MIRROR, 443).unwrap();
    let mapping = admission.nat.unwrap();
    assert_eq!(mapping.destination, (ip(MIRROR), 443));
    assert_eq!(
        world
            .net
            .inbound_packet(Transport::Tcp, (ip(MIRROR), 443), mapping.outside),
        Ok((a.clone(), admission.flow, mapping.inside))
    );
    for (transport, from, to) in [
        (Transport::Tcp, (ip("1.1.1.1"), 443), mapping.outside),
        (Transport::Udp, (ip(MIRROR), 443), mapping.outside),
        (
            Transport::Tcp,
            (ip(MIRROR), 443),
            (mapping.outside.0, 20_007),
        ),
    ] {
        assert_eq!(
            world.net.inbound_packet(transport, from, to),
            Err(FlowRefusal::UnsolicitedInbound)
        );
    }
    world.net.close_flow(&a, admission.flow).unwrap();
    assert_eq!(
        world
            .net
            .inbound_packet(Transport::Tcp, (ip(MIRROR), 443), mapping.outside),
        Err(FlowRefusal::UnsolicitedInbound)
    );
}

#[test]
fn nat_never_maps_onto_host_or_sandbox_addresses() {
    let pool = new_pool();
    let host = host_state();
    let mut table = NatTable::new();
    let scope_of = |address: IpAddr| {
        if pool.contains(address) {
            NatScope::Sandbox
        } else if host.owns(address) {
            NatScope::Host
        } else {
            NatScope::External
        }
    };
    let key = |destination: &str| FlowKey {
        transport: Transport::Tcp,
        source: ip("10.200.0.2"),
        source_port: 5555,
        destination: ip(destination),
        destination_port: 443,
    };
    let sandbox = exec("sbx-a");
    for destination in [HOST_LAN, GATEWAY, "10.200.0.3"] {
        assert_eq!(
            table.map(
                &sandbox,
                FlowId(1),
                &key(destination),
                Some(ip(HOST_LAN)),
                (20_000, 8),
                scope_of
            ),
            Err(NatError::DestinationNotExternal {
                address: ip(destination)
            })
        );
    }
    assert_eq!(
        table.map(
            &sandbox,
            FlowId(1),
            &key(MIRROR),
            Some(ip("10.200.0.3")),
            (20_000, 8),
            scope_of
        ),
        Err(NatError::EgressIsSandboxAddress {
            address: ip("10.200.0.3")
        })
    );
    assert_eq!(
        table.map(
            &sandbox,
            FlowId(1),
            &key(MIRROR),
            None,
            (20_000, 8),
            scope_of
        ),
        Err(NatError::NoEgressForFamily)
    );
    let mapping = table
        .map(
            &sandbox,
            FlowId(1),
            &key(MIRROR),
            Some(ip(HOST_LAN)),
            (20_000, 1),
            scope_of,
        )
        .unwrap();
    assert_eq!(mapping.destination, (ip(MIRROR), 443));
    assert_eq!(
        table.map(
            &sandbox,
            FlowId(2),
            &key(MIRROR),
            Some(ip(HOST_LAN)),
            (20_000, 1),
            scope_of
        ),
        Err(NatError::Exhausted)
    );
    table.release(&mapping);
    assert!(table.is_empty());
}

#[test]
fn an_exhausted_nat_block_refuses_without_charging_the_route() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let mut flows = Vec::new();
    for _ in 0..8 {
        flows.push(world.tcp(&a, MIRROR, 443).unwrap());
    }
    assert_eq!(
        world.tcp(&a, MIRROR, 443),
        Err(FlowRefusal::Nat(NatError::Exhausted))
    );
    assert_eq!(world.net.usage(&a, &route("mirror")).connections, 8);
    let freed = flows[3].nat.unwrap().outside.1;
    world.net.close_flow(&a, flows[3].flow).unwrap();
    assert_eq!(
        world.tcp(&a, MIRROR, 443).unwrap().nat.unwrap().outside.1,
        freed
    );
    assert_eq!(world.net.nat().len(), 8);
}

#[test]
fn a_reconnect_is_a_new_flow_authorized_again() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    world.dns(&a, "pypi.org", GuestQueryType::A);
    let key = world.key(&a, Transport::Tcp, PYPI_V4, 443);
    let first = world.net.open_flow(&a, key).unwrap().flow;
    assert_eq!(world.net.packet(&a, &key), Ok(first));
    assert_eq!(
        world.net.open_flow(&a, key),
        Err(FlowRefusal::AlreadyEstablished { flow: first })
    );
    let closed = world.net.close_flow(&a, first).unwrap();
    assert_eq!(closed.reason, CloseReason::Closed);
    assert_eq!(world.net.packet(&a, &key), Err(FlowRefusal::NotEstablished));
    assert_eq!(
        world.net.close_flow(&a, first),
        Err(FlowRefusal::NotEstablished)
    );
    let second = world.net.open_flow(&a, key).unwrap().flow;
    assert_ne!(first, second);
    assert_eq!(world.net.usage(&a, &route("pypi")).connections, 2);
}

#[test]
fn an_expired_answer_stops_new_flows_but_not_established_ones() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    world.dns(&a, "github.com", GuestQueryType::A);
    let key = world.key(&a, Transport::Tcp, GITHUB_V4, 443);
    let flow = world.net.open_flow(&a, key).unwrap().flow;
    clock.advance(Duration::from_secs(60));
    assert_eq!(world.net.packet(&a, &key), Ok(flow));
    assert_eq!(
        world.tcp(&a, GITHUB_V4, 443),
        Err(FlowRefusal::BindingExpired {
            address: ip(GITHUB_V4)
        })
    );
    world.dns(&a, "github.com", GuestQueryType::A);
    assert!(world.tcp(&a, GITHUB_V4, 443).is_ok());
}

#[test]
fn private_exceptions_reach_exactly_their_endpoint() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    assert_eq!(
        world.tcp(&a, REGISTRY, 5000).unwrap().kind,
        FlowKind::Endpoint {
            route: route("registry")
        }
    );
    assert_eq!(
        world.tcp(&a, REGISTRY, 22),
        Err(FlowRefusal::Authorization(
            AuthorizationRefusal::PortNotGranted {
                authority: crate::sandbox_contract::destinations::Authority {
                    host: crate::sandbox_contract::destinations::DestinationHost::Address(ip(
                        REGISTRY
                    )),
                    port: port(22)
                }
            }
        ))
    );
    match world.tcp(&a, "10.50.0.21", 5000) {
        Err(FlowRefusal::Address(refused)) => {
            assert_eq!(refused.verdict.class, AddressClass::Private);
            assert_eq!(refused.rule, AddressRule::ResolvedName);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        world.dns(&a, "registry.corp.internal", GuestQueryType::A),
        DnsAnswer::Addresses { ref addresses, external: false, .. } if *addresses == vec![ip(REGISTRY)]
    ));
    assert_eq!(
        world.dns(&a, "registry.corp.internal", GuestQueryType::Aaaa),
        DnsAnswer::NoData
    );
    assert_eq!(world.external_calls(), 0);
}

#[test]
fn concurrent_flows_are_capped_and_a_closed_flow_frees_its_slot() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |document| document.quotas = quotas(3, 100, 1));
    let first = world.tcp(&a, MIRROR, 443).unwrap();
    world.tcp(&a, GATEWAY, 53).unwrap();
    world.tcp(&a, REGISTRY, 5000).unwrap();
    assert_eq!(
        world.tcp(&a, MIRROR, 443),
        Err(FlowRefusal::ConcurrentFlowLimit { limit: 3 })
    );
    world.net.close_flow(&a, first.flow).unwrap();
    assert!(world.tcp(&a, MIRROR, 443).is_ok());
}

#[test]
fn new_flows_per_interval_use_a_sliding_window() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |document| document.quotas = quotas(100, 2, 10));
    let first = world.tcp(&a, MIRROR, 443).unwrap();
    clock.advance(Duration::from_secs(5));
    world.tcp(&a, MIRROR, 443).unwrap();
    let refused = Err(FlowRefusal::NewFlowRate {
        limit: 2,
        interval_seconds: 10,
    });
    assert_eq!(world.tcp(&a, MIRROR, 443), refused);
    world.net.close_flow(&a, first.flow).unwrap();
    assert_eq!(world.tcp(&a, MIRROR, 443), refused);
    clock.advance(Duration::from_secs(5));
    assert!(world.tcp(&a, MIRROR, 443).is_ok());
    assert_eq!(world.tcp(&a, MIRROR, 443), refused);
}

#[test]
fn connection_and_byte_budgets_are_route_budgets() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |document| {
        for grant in &mut document.egress {
            if grant.id == route("mirror") {
                grant.budgets.connections = 2;
                grant.budgets.bytes_out = 1_500;
                grant.budgets.bytes_in = 700;
            }
        }
    });
    let flow = world.tcp(&a, MIRROR, 443).unwrap().flow;
    world.tcp(&a, MIRROR, 443).unwrap();
    assert!(matches!(
        world.tcp(&a, MIRROR, 443),
        Err(FlowRefusal::Budget(exhausted)) if exhausted.kind == Some(BudgetKind::Connections)
    ));
    assert_eq!(world.net.nat().len(), 2);

    world.net.send(&a, flow, 1_000).unwrap();
    assert!(matches!(
        world.net.send(&a, flow, 501),
        Err(FlowRefusal::Budget(exhausted)) if exhausted.kind == Some(BudgetKind::BytesOut)
    ));
    let release = world.net.release_account(&a).unwrap();
    assert_eq!(release.used_bytes(ReleaseChannel::TransportStream), 1_000);
    assert_eq!(world.net.usage(&a, &route("mirror")).bytes_out, 1_000);
    world.net.receive(&a, flow, 700).unwrap();
    assert!(matches!(
        world.net.receive(&a, flow, 1),
        Err(FlowRefusal::Budget(_))
    ));
    assert_eq!(world.net.usage(&a, &route("mirror")).bytes_in, 700);

    let dns_flow = world.tcp(&a, GATEWAY, 53).unwrap().flow;
    assert_eq!(
        world.net.send(&a, dns_flow, 1),
        Err(FlowRefusal::WrongFlowKind)
    );
}

#[test]
fn an_exhausted_release_channel_refuses_and_leaves_the_route_uncharged() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |document| {
        if let Some(policy) = document
            .release
            .channels
            .get_mut(&ReleaseChannel::TransportStream)
        {
            policy.budget_bytes = 500;
        }
    });
    let flow = world.tcp(&a, MIRROR, 443).unwrap().flow;
    assert!(matches!(
        world.net.send(&a, flow, 600),
        Err(FlowRefusal::Release(ReleaseError::Exhausted(_)))
    ));
    assert_eq!(world.net.usage(&a, &route("mirror")).bytes_out, 0);
    world.net.send(&a, flow, 500).unwrap();
    assert_eq!(world.net.usage(&a, &route("mirror")).bytes_out, 500);
}

#[test]
fn only_tcp_and_explicitly_accepted_quic_leave_the_host() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let b = world.add("sbx-b", |document| {
        for grant in &mut document.egress {
            if grant.id == route("pypi") {
                grant.hazards = hazards(HazardHandling::BroaderTransportGrant(DecisionRef::new(
                    test_digest("quic-accepted"),
                )));
            }
        }
    });
    for sandbox in [&a, &b] {
        world.dns(sandbox, "pypi.org", GuestQueryType::A);
    }
    assert_eq!(
        world.open(&a, Transport::Udp, PYPI_V4, 443),
        Err(FlowRefusal::TransportNotGranted {
            transport: Transport::Udp
        })
    );
    assert!(matches!(
        world.open(&b, Transport::Udp, PYPI_V4, 443).unwrap().kind,
        FlowKind::Named { .. }
    ));
    assert_eq!(
        world.open(&a, Transport::Icmp, MIRROR, 0),
        Err(FlowRefusal::TransportNotGranted {
            transport: Transport::Icmp
        })
    );
    assert_eq!(
        world.open(&a, Transport::Other(255), MIRROR, 0),
        Err(FlowRefusal::TransportNotGranted {
            transport: Transport::Other(255)
        })
    );
    assert_eq!(world.tcp(&a, MIRROR, 0), Err(FlowRefusal::InvalidPort));
}

#[test]
fn flows_are_stamped_with_the_epoch_they_were_decided_under() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let flow = world.tcp(&a, MIRROR, 443).unwrap().flow;
    assert_eq!(
        world.net.epoch(&a),
        Some(crate::foundation::ids::PolicyEpoch::FIRST)
    );
    let record = world.net.flow(&a, flow).unwrap();
    assert_eq!(record.epoch, crate::foundation::ids::PolicyEpoch::FIRST);
    assert_eq!(record.opened_at, START);
    assert_eq!(world.net.flows(&a).len(), 1);
}
