//! DNS and the host proxy (VM §4.2; VM-W08 "no external DNS for unauthorized names";
//! VM-W59 DNS), and the VM-CP-08 and VM-CP-09 cases that need no VM.

use super::*;
use crate::sandbox_contract::destinations::{
    AddressClass, AuthorizationRefusal, BudgetKind, DestinationRefusal, IpLiteralForm, ModeClaim,
    NameError,
};

#[test]
fn an_unauthorized_name_causes_no_external_query() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    for unauthorized in [
        "evil.example.com",
        "dns.google",
        "files.pythonhosted.org",
        "www.pypi.org",
    ] {
        for query_type in [GuestQueryType::A, GuestQueryType::Aaaa] {
            assert_eq!(
                world.dns(&a, unauthorized, query_type),
                DnsAnswer::NameNotAuthorized
            );
        }
    }
    assert_eq!(world.external_calls(), 0);
}

#[test]
fn malformed_names_and_unsupported_types_are_answered_locally() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    for malformed in [
        "",
        "localhost",
        "pypi.org.",
        "127.1",
        "2130706433",
        "pypi..org",
        "us\u{e9}r.example.com",
        "user@pypi.org",
    ] {
        assert!(
            matches!(
                world.dns(&a, malformed, GuestQueryType::A),
                DnsAnswer::Malformed(_)
            ),
            "{malformed:?}"
        );
    }
    for query_type in [
        GuestQueryType::Txt,
        GuestQueryType::Mx,
        GuestQueryType::Https,
        GuestQueryType::Svcb,
        GuestQueryType::Any,
        GuestQueryType::Ptr,
        GuestQueryType::Other(65),
    ] {
        assert_eq!(
            world.dns(&a, "pypi.org", query_type),
            DnsAnswer::Unsupported(query_type)
        );
    }
    assert_eq!(
        world.dns(&a, "github.com", GuestQueryType::Aaaa),
        DnsAnswer::NoData
    );
    assert_eq!(world.external_calls(), 0);
}

#[test]
fn a_granted_name_goes_only_to_its_allowed_resolver_exactly_as_named() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let answer = world.dns(&a, "PyPI.org", GuestQueryType::A);
    assert!(
        matches!(answer, DnsAnswer::Addresses { ref route, external: true, .. } if *route == super::route("pypi"))
    );
    assert_eq!(world.dns.queried(), vec!["pypi.org".to_owned()]);
    assert_eq!(world.rogue.calls(), 0);
    assert_eq!(world.net.usage(&a, &route("pypi")).dns_queries, 1);
    // 12-byte header, "pypi.org" in wire form (10 bytes) and 4 bytes of type and class.
    assert_eq!(
        world
            .net
            .release_account(&a)
            .unwrap()
            .used_bytes(ReleaseChannel::DnsQuery),
        26
    );

    let resolvers: [&dyn Resolver; 1] = [&world.rogue];
    let answer = world
        .net
        .guest_dns(&a, "github.com", GuestQueryType::A, &resolvers)
        .unwrap();
    assert_eq!(
        answer,
        DnsAnswer::Refused(FlowRefusal::ResolverUnavailable {
            resolver: ResolverId::new("host-dns").unwrap()
        })
    );
    assert_eq!(world.rogue.calls(), 0);
    assert_eq!(world.dns.calls(), 1);
}

#[test]
fn answers_outside_the_perimeter_prefixes_or_in_private_space_are_refused() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    world.dns = FakeResolver::new("host-dns");
    world
        .dns
        .answer("pypi.org", AddressFamily::Ipv4, &["151.102.0.1"], 60);
    world
        .dns
        .answer("github.com", AddressFamily::Ipv4, &["10.1.1.1"], 60);
    let a = world.add("sbx-a", |_| {});
    assert_eq!(
        world.dns(&a, "pypi.org", GuestQueryType::A),
        DnsAnswer::Refused(FlowRefusal::OutsidePerimeterPrefixes {
            route: route("pypi"),
            address: ip("151.102.0.1")
        })
    );
    assert!(matches!(
        world.tcp(&a, "151.102.0.1", 443),
        Err(FlowRefusal::Authorization(
            AuthorizationRefusal::AddressNeedsEndpointGrant { .. }
        ))
    ));
    match world.dns(&a, "github.com", GuestQueryType::A) {
        DnsAnswer::Refused(FlowRefusal::Destination(DestinationRefusal::Address(refused))) => {
            assert_eq!(refused.verdict.class, AddressClass::Private);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        world.tcp(&a, "10.1.1.1", 443),
        Err(FlowRefusal::Address(_))
    ));
}

#[test]
fn the_name_budget_is_spent_before_each_query_is_sent() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |document| {
        for grant in &mut document.egress {
            grant.budgets.dns_queries = 2;
        }
    });
    world.dns(&a, "pypi.org", GuestQueryType::A);
    world.dns(&a, "pypi.org", GuestQueryType::Aaaa);
    assert!(matches!(
        world.dns(&a, "pypi.org", GuestQueryType::A),
        DnsAnswer::Refused(FlowRefusal::Destination(DestinationRefusal::Budget(exhausted)))
            if exhausted.kind == Some(BudgetKind::DnsQueries)
    ));
    assert_eq!(world.dns.calls(), 2);
    assert_eq!(world.net.usage(&a, &route("pypi")).dns_queries, 2);
}

#[test]
fn a_sensitive_task_resolves_nothing_and_answers_endpoint_names_locally() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |document| {
        document.data_class = DataClass::SensitiveOffline;
        document.egress.retain(|grant| grant.resolver.is_none());
        document.resolvers.clear();
    });
    assert_eq!(
        world.dns(&a, "pypi.org", GuestQueryType::A),
        DnsAnswer::NameNotAuthorized
    );
    assert!(matches!(
        world.dns(&a, "registry.corp.internal", GuestQueryType::A),
        DnsAnswer::Addresses {
            external: false,
            ..
        }
    ));
    assert!(world.tcp(&a, REGISTRY, 5000).is_ok());
    assert_eq!(world.external_calls(), 0);
}

#[test]
fn the_proxy_authorizes_by_the_same_policy_before_any_resolution() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let proxied = world.proxy(&a, "pypi.org:443").unwrap();
    assert!(matches!(
        &proxied.kind,
        FlowKind::Proxied { route: granted, address, .. } if *granted == route("pypi") && *address == ip(PYPI_V4)
    ));
    assert_eq!(proxied.nat, None);
    assert!(world.proxy(&a, "pypi.org").is_ok());
    assert_eq!(world.dns.calls(), 2);
    assert_eq!(world.net.usage(&a, &route("pypi")).connections, 2);

    let calls = world.external_calls();
    assert!(matches!(
        world.proxy(&a, "pypi.org:22"),
        Err(FlowRefusal::Authorization(
            AuthorizationRefusal::PortNotGranted { .. }
        ))
    ));
    assert!(matches!(
        world.proxy(&a, "unlisted.example.com:443"),
        Err(FlowRefusal::Authorization(
            AuthorizationRefusal::NotGranted { .. }
        ))
    ));
    assert_eq!(
        world.proxy(&a, "1.1.1.1:443"),
        Err(FlowRefusal::Authorization(
            AuthorizationRefusal::AddressNeedsEndpointGrant {
                address: ip("1.1.1.1")
            }
        ))
    );
    assert!(matches!(
        world.proxy(&a, MIRROR).unwrap().kind,
        FlowKind::Proxied { address, .. } if address == ip(MIRROR)
    ));
    assert!(matches!(
        world.proxy(&a, "registry.corp.internal:5000").unwrap().kind,
        FlowKind::Proxied { address, .. } if address == ip(REGISTRY)
    ));
    assert_eq!(world.external_calls(), calls);
}

#[test]
fn proxy_answers_outside_the_perimeter_prefixes_are_refused() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    world.dns = FakeResolver::new("host-dns");
    world.dns.answer(
        "pypi.org",
        AddressFamily::Ipv4,
        &[PYPI_V4, "151.102.0.1"],
        60,
    );
    let a = world.add("sbx-a", |_| {});
    assert_eq!(
        world.proxy(&a, "pypi.org:443"),
        Err(FlowRefusal::OutsidePerimeterPrefixes {
            route: route("pypi"),
            address: ip("151.102.0.1")
        })
    );
    assert!(world.net.flows(&a).is_empty());
}

/// VM-W08: a guest with root can rewrite its own configuration, sockets and packets;
/// none of it moves a host decision. Each trick below is refused by the host model,
/// while the granted route keeps working.
#[test]
fn vm_w08_guest_root_cannot_bypass_host_policy() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let b = world.add("sbx-b", |_| {});
    world.dns(&a, "pypi.org", GuestQueryType::A);

    let mut spoofed = world.key(&a, Transport::Tcp, PYPI_V4, 443);
    spoofed.source = IpAddr::V4(world.identity(&b).ipv4);
    assert!(matches!(
        world.net.open_flow(&a, spoofed),
        Err(FlowRefusal::SpoofedSource { .. })
    ));
    for transport in [Transport::Icmp, Transport::Other(47), Transport::Other(41)] {
        assert_eq!(
            world.open(&a, transport, PYPI_V4, 0),
            Err(FlowRefusal::TransportNotGranted { transport })
        );
    }
    assert!(matches!(
        world.open(&a, Transport::Udp, PYPI_V4, 443),
        Err(FlowRefusal::TransportNotGranted { .. })
    ));
    for (address, port_number) in [
        ("224.0.0.251", 5353),
        ("255.255.255.255", 67),
        ("10.200.0.255", 67),
        ("169.254.169.254", 80),
        (HOST_LAN, 22),
        (GATEWAY, 22),
        ("8.8.8.8", 53),
        ("1.1.1.1", 853),
    ] {
        assert!(
            world
                .open(&a, Transport::Udp, address, port_number)
                .is_err()
                && world.tcp(&a, address, port_number).is_err(),
            "{address}:{port_number}"
        );
    }
    let b_address = world.identity(&b).ipv4.to_string();
    assert!(world.tcp(&a, &b_address, 22).is_err());
    assert!(world.tcp(&a, "::ffff:151.101.0.223", 443).is_err());
    assert_eq!(
        world.dns(&a, "evil.example.com", GuestQueryType::A),
        DnsAnswer::NameNotAuthorized
    );
    assert_eq!(world.rogue.calls(), 0);
    assert!(world.tcp(&a, PYPI_V4, 443).is_ok());
}

/// VM-CP-08: the one normalizer refuses every listed form, and the public test address
/// passes it.
#[test]
fn vm_cp_08_the_normalizer_refuses_every_listed_form() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let literal = |form| Err(FlowRefusal::Name(NameError::IpLiteral { form }));
    assert_eq!(
        world.proxy(&a, "127.1:443"),
        literal(IpLiteralForm::ShortIpv4)
    );
    assert_eq!(
        world.proxy(&a, "2130706433:443"),
        literal(IpLiteralForm::DecimalIntegerIpv4)
    );
    assert_eq!(
        world.proxy(&a, "0177.0.0.1:443"),
        literal(IpLiteralForm::OctalIpv4)
    );
    assert_eq!(
        world.proxy(&a, "0x7f.0.0.1:443"),
        literal(IpLiteralForm::HexIpv4)
    );
    assert_eq!(
        world.proxy(&a, "[fe80::1%25eth0]:443"),
        literal(IpLiteralForm::Ipv6ZoneId)
    );
    assert_eq!(
        world.proxy(&a, "user@pypi.org:443"),
        Err(FlowRefusal::Name(NameError::Userinfo))
    );
    assert!(matches!(
        world.proxy(&a, "[::ffff:10.0.0.1]:443"),
        Err(FlowRefusal::Authorization(
            AuthorizationRefusal::AddressNeedsEndpointGrant { .. }
        ))
    ));

    let refused = [
        (
            "::ffff:10.0.0.1",
            AddressClass::EmbeddedIpv4(
                crate::sandbox_contract::destinations::EmbeddedIpv4Form::Mapped,
            ),
        ),
        ("0.0.0.0", AddressClass::Unspecified),
        ("127.0.0.1", AddressClass::Loopback),
        ("169.254.169.254", AddressClass::Metadata),
        ("fe80::", AddressClass::LinkLocal),
        ("fd12:3456::1", AddressClass::Private),
        ("239.255.255.250", AddressClass::Multicast),
        ("ff05::2", AddressClass::Multicast),
        ("255.255.255.255", AddressClass::Broadcast),
    ];
    for (address, class) in refused {
        match world.tcp(&a, address, 443) {
            Err(FlowRefusal::Address(verdict)) => {
                assert_eq!(verdict.verdict.class, class, "{address}")
            }
            other => panic!("{address}: {other:?}"),
        }
    }
    for owned in host_state().owned() {
        let address = owned.network().to_string();
        assert!(
            matches!(
                world.tcp(&a, &address, 443),
                Err(FlowRefusal::Address(_)) | Err(FlowRefusal::HostService { .. })
            ),
            "{address}"
        );
        assert!(world
            .proxy(
                &a,
                &format!(
                    "{}:443",
                    crate::sandbox_contract::destinations::DestinationHost::Address(
                        owned.network()
                    )
                )
            )
            .is_err());
    }
    // The public test address passes the same normalizer, directly and through the proxy.
    assert!(world.tcp(&a, MIRROR, 443).is_ok());
    assert!(world.proxy(&a, &format!("{MIRROR}:443")).is_ok());
}

/// VM-CP-09, the parts that need no VM: with the guest's proxy settings ignored, a
/// direct connection, a raw socket and DNS to another resolver all fail; the approved
/// proxy and the granted route succeed. "No network device exists" is a strict-profile
/// property a broader profile never claims.
#[test]
fn vm_cp_09_bypass_attempts_fail_and_the_approved_paths_succeed() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    assert_eq!(
        world.tcp(&a, "1.1.1.1", 443),
        Err(FlowRefusal::Authorization(
            AuthorizationRefusal::AddressNeedsEndpointGrant {
                address: ip("1.1.1.1")
            }
        ))
    );
    for transport in [Transport::Other(255), Transport::Icmp] {
        assert_eq!(
            world.open(&a, transport, "1.1.1.1", 0),
            Err(FlowRefusal::TransportNotGranted { transport })
        );
    }
    for (transport, port_number) in [
        (Transport::Udp, 53),
        (Transport::Tcp, 53),
        (Transport::Tcp, 853),
        (Transport::Tcp, 443),
    ] {
        assert!(
            world.open(&a, transport, "8.8.8.8", port_number).is_err(),
            "{transport:?} {port_number}"
        );
    }
    assert_eq!(
        world.dns(&a, "dns.google", GuestQueryType::A),
        DnsAnswer::NameNotAuthorized
    );
    assert_eq!(world.external_calls(), 0);
    let profile = world.net.profile(&a).unwrap().clone();
    assert!(profile.claim(ModeClaim::NoHostFacingNic).is_err());
    assert!(profile.claim(ModeClaim::BypassFailsWithoutNic).is_err());

    assert!(world.proxy(&a, "pypi.org:443").is_ok());
    world.dns(&a, "pypi.org", GuestQueryType::A);
    assert!(world.tcp(&a, PYPI_V4, 443).is_ok());
}
