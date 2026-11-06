//! Seeded property tests on the flow model: VM-P08 (address policy consistent across
//! families and forms), VM-P09 (proxy bypass cannot evade the profile; guest settings
//! change no decision), VM-P36 (cross-sandbox isolation) and the perimeter permitting
//! everything the host admits and nothing the profile forbids.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;
use crate::sandbox_contract::destinations::{
    classify, AddressClass, AuthorizationRefusal, ConnectionRefusal, ServiceIdentity,
};

fn expect_policy_refusal(world: &mut World, sandbox: &ExecutionId, address: IpAddr) {
    let host = host_state();
    let verdict = classify(address, &host);
    let result = world.tcp(sandbox, &address.to_string(), 443);
    match verdict.class {
        AddressClass::Public => assert_eq!(
            result,
            Err(FlowRefusal::Authorization(
                AuthorizationRefusal::AddressNeedsEndpointGrant { address }
            )),
            "{address}"
        ),
        class => match result {
            Err(FlowRefusal::Address(refused)) => {
                assert_eq!(refused.verdict.class, class, "{address}")
            }
            Err(FlowRefusal::HostService { .. }) => assert_eq!(class, AddressClass::HostOwned),
            other => panic!("{address}: {other:?}"),
        },
    }
}

/// VM-P08: with no grant, every address outside the pool is refused, by V02's class when
/// it is not public; every IPv6 form that carries IPv4 is refused even when the IPv4
/// address is granted; both families follow one rule.
#[test]
fn vm_p08_addresses_are_decided_by_one_rule_in_every_family_and_form() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let pool = new_pool();
    let mut random = SplitMix64::new(0x5eed_0008);
    let ipv6_bases: [u128; 8] = [
        0x2000_0000_0000_0000_0000_0000_0000_0000,
        0x2a04_4e42_0000_0000_0000_0000_0000_0000,
        0xfc00_0000_0000_0000_0000_0000_0000_0000,
        0xfe80_0000_0000_0000_0000_0000_0000_0000,
        0xff00_0000_0000_0000_0000_0000_0000_0000,
        0x0000_0000_0000_0000_0000_ffff_0000_0000,
        0x2002_0000_0000_0000_0000_0000_0000_0000,
        0x0064_ff9b_0000_0000_0000_0000_0000_0000,
    ];
    let skip = [ip(MIRROR), ip(REGISTRY)];
    for _ in 0..400 {
        let ipv4 = IpAddr::V4(Ipv4Addr::from(
            u32::try_from(random.below(1 << 32)).unwrap(),
        ));
        if !pool.contains(ipv4) && !skip.contains(&ipv4) {
            expect_policy_refusal(&mut world, &a, ipv4);
        }
        let base = ipv6_bases[usize::try_from(random.below(8)).unwrap()];
        let low = u128::from(random.next()) & 0xffff_ffff_ffff;
        let ipv6 = IpAddr::V6(Ipv6Addr::from(base | low));
        if !pool.contains(ipv6) {
            expect_policy_refusal(&mut world, &a, ipv6);
        }
    }

    for seed in 0..24u64 {
        let mut random = SplitMix64::new(seed);
        let address = loop {
            let candidate = Ipv4Addr::from(u32::try_from(random.below(1 << 32)).unwrap());
            if classify(IpAddr::V4(candidate), &host_state()).class == AddressClass::Public {
                break candidate;
            }
        };
        let clock = new_clock();
        let mut world = World::new(&clock);
        let a = world.add("sbx-a", |document| {
            document.egress.push(endpoint_grant(
                "random",
                &address.to_string(),
                443,
                None,
                "property test",
            ));
        });
        assert!(world.tcp(&a, &address.to_string(), 443).is_ok());
        let octets = address.octets();
        let high = u16::from_be_bytes([octets[0], octets[1]]);
        let low = u16::from_be_bytes([octets[2], octets[3]]);
        for form in [
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, high, low),
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, high, low),
            Ipv6Addr::new(0x2002, high, low, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, high, low),
        ] {
            match world.tcp(&a, &form.to_string(), 443) {
                Err(FlowRefusal::Address(refused)) => {
                    assert!(
                        matches!(refused.verdict.class, AddressClass::EmbeddedIpv4(_)),
                        "{form}"
                    )
                }
                other => panic!("{form}: {other:?}"),
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Action {
    Dns(usize, bool),
    Flow(Transport, usize, u16),
    Proxy(usize),
    CloseOldest,
    Advance(u64),
}

const NAMES: [&str; 6] = [
    "pypi.org",
    "github.com",
    "dns.google",
    "evil.example.com",
    "registry.corp.internal",
    "127.1",
];
const ADDRESSES: [&str; 11] = [
    PYPI_V4,
    PYPI_V6,
    GITHUB_V4,
    MIRROR,
    REGISTRY,
    "8.8.8.8",
    "1.1.1.1",
    GATEWAY,
    "169.254.169.254",
    HOST_LAN,
    "10.200.0.3",
];
const PORTS: [u16; 6] = [443, 53, 853, 80, 5000, 3128];

fn actions(seed: u64, count: usize) -> Vec<Action> {
    let mut random = SplitMix64::new(seed);
    let pick = |random: &mut SplitMix64, length: usize| {
        usize::try_from(random.below(length as u64)).unwrap()
    };
    (0..count)
        .map(|_| match random.below(10) {
            0..=1 => Action::Dns(pick(&mut random, NAMES.len()), random.below(2) == 0),
            2..=5 => {
                let transport = match random.below(6) {
                    0..=3 => Transport::Tcp,
                    4 => Transport::Udp,
                    _ => Transport::Other(255),
                };
                Action::Flow(
                    transport,
                    pick(&mut random, ADDRESSES.len()),
                    PORTS[pick(&mut random, PORTS.len())],
                )
            }
            6..=7 => Action::Proxy(pick(&mut random, NAMES.len())),
            8 => Action::CloseOldest,
            _ => Action::Advance(random.below(90)),
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Dns(DnsAnswer),
    Flow(Result<FlowAdmission, FlowRefusal>),
    Closed(Option<FlowId>),
    Advanced,
}

fn run(guest: GuestCompatibility, plan: &[Action]) -> (Vec<Outcome>, Vec<String>) {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |document| document.guest = guest);
    world.add("sbx-b", |_| {});
    let mut outcomes = Vec::new();
    for action in plan {
        outcomes.push(match *action {
            Action::Dns(index, aaaa) => Outcome::Dns(world.dns(
                &a,
                NAMES[index],
                if aaaa {
                    GuestQueryType::Aaaa
                } else {
                    GuestQueryType::A
                },
            )),
            Action::Flow(transport, index, port_number) => {
                Outcome::Flow(world.open(&a, transport, ADDRESSES[index], port_number))
            }
            Action::Proxy(index) => {
                Outcome::Flow(world.proxy(&a, &format!("{}:443", NAMES[index])))
            }
            Action::CloseOldest => {
                let oldest = world.net.flows(&a).first().map(|record| record.id);
                if let Some(flow) = oldest {
                    world.net.close_flow(&a, flow).unwrap();
                }
                Outcome::Closed(oldest)
            }
            Action::Advance(seconds) => {
                clock.advance(Duration::from_secs(seconds));
                Outcome::Advanced
            }
        });
    }
    (outcomes, world.dns.queried())
}

/// VM-P09: the same guest actions get the same host decisions whatever the guest is
/// configured with: proxy variables, a TUN stack or synthetic names. Direct IP, raw
/// sockets and DNS to other resolvers are decided by the grants alone.
#[test]
fn vm_p09_guest_configuration_never_changes_a_host_decision() {
    let justification = Justification {
        reason: text("the updater ignores proxy variables"),
        applications: BTreeSet::from([ApplicationName::new("legacy-updater").unwrap()]),
        implementation: ImplementationName::new("gvisor-netstack").unwrap(),
    };
    let proxy = |http_connect, socks5| ProxyOffer {
        http_connect,
        socks5,
    };
    let variants = [
        GuestCompatibility {
            proxy: proxy(true, true),
            tun: None,
            synthetic_names: None,
        },
        GuestCompatibility {
            proxy: proxy(true, false),
            tun: None,
            synthetic_names: None,
        },
        GuestCompatibility {
            proxy: proxy(false, true),
            tun: None,
            synthetic_names: None,
        },
        GuestCompatibility {
            proxy: proxy(true, true),
            tun: Some(justification.clone()),
            synthetic_names: None,
        },
        GuestCompatibility {
            proxy: proxy(true, true),
            tun: None,
            synthetic_names: Some(justification.clone()),
        },
        GuestCompatibility {
            proxy: proxy(false, true),
            tun: Some(justification.clone()),
            synthetic_names: Some(justification),
        },
    ];
    for seed in 0..12u64 {
        let plan = actions(0x9000 + seed, 60);
        let reference = run(variants[0].clone(), &plan);
        assert!(reference
            .0
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Flow(Ok(_)))));
        assert!(reference
            .0
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Flow(Err(_)))));
        for variant in &variants[1..] {
            assert_eq!(run(variant.clone(), &plan), reference, "seed {seed}");
        }
    }
}

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

/// VM-P36: separate sandboxes talk only where both ends granted that exact service and
/// port, never transitively; one sandbox's DNS answers and budgets are not another's.
#[test]
fn vm_p36_sandboxes_reach_each_other_only_through_two_ended_grants() {
    let labels = ["sbx-0", "sbx-1", "sbx-2"];
    let services = [("alpha", 7000u16), ("beta", 7001u16)];
    for seed in 0..40u64 {
        let mut random = SplitMix64::new(0x3600 + seed);
        let mut outbound = BTreeSet::new();
        let mut inbound = BTreeSet::new();
        for caller in 0..3usize {
            for callee in 0..3usize {
                if caller == callee {
                    continue;
                }
                for service in 0..services.len() {
                    if random.below(2) == 0 {
                        outbound.insert((caller, callee, service));
                    }
                    if random.below(2) == 0 {
                        inbound.insert((caller, callee, service));
                    }
                }
            }
        }
        let clock = new_clock();
        let mut world = World::new(&clock);
        let mut sandboxes = Vec::new();
        for (index, label) in labels.iter().enumerate() {
            let outbound = outbound.clone();
            let inbound = inbound.clone();
            sandboxes.push(world.add(label, move |document| {
                for &(caller, callee, service) in &outbound {
                    if caller == index {
                        let (name, port_number) = services[service];
                        document.links.push(link(
                            LinkDirection::Outbound,
                            labels[callee],
                            name,
                            port_number,
                        ));
                    }
                }
                for &(caller, callee, service) in &inbound {
                    if callee == index {
                        let (name, port_number) = services[service];
                        document.links.push(link(
                            LinkDirection::Inbound,
                            labels[caller],
                            name,
                            port_number,
                        ));
                    }
                }
            }));
        }
        for caller in 0..3usize {
            for callee in 0..3usize {
                if caller == callee {
                    continue;
                }
                let address = world.identity(&sandboxes[callee]).ipv4.to_string();
                for (service, (_, port_number)) in services.iter().enumerate() {
                    let granted = outbound.contains(&(caller, callee, service))
                        && inbound.contains(&(caller, callee, service));
                    let result = world.tcp(&sandboxes[caller], &address, *port_number);
                    assert_eq!(
                        result.is_ok(),
                        granted,
                        "seed {seed}: {caller}->{callee} {service}"
                    );
                    if !granted {
                        assert!(matches!(
                            result,
                            Err(FlowRefusal::Connection(
                                ConnectionRefusal::MissingGrant { .. }
                            ))
                        ));
                    }
                }
                assert!(world.tcp(&sandboxes[caller], &address, 7002).is_err());
            }
        }
    }

    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let b = world.add("sbx-b", |_| {});
    world.dns(&a, "pypi.org", GuestQueryType::A);
    assert!(world.tcp(&a, PYPI_V4, 443).is_ok());
    assert_eq!(
        world.tcp(&b, PYPI_V4, 443),
        Err(FlowRefusal::Authorization(
            AuthorizationRefusal::AddressNeedsEndpointGrant {
                address: ip(PYPI_V4)
            }
        ))
    );
    assert_eq!(
        world.net.usage(&b, &route("pypi")),
        RouteUsageView::default()
    );
    assert_eq!(world.net.usage(&a, &route("pypi")).connections, 1);
}

/// The perimeter permits every external flow the host admits and nothing the profile
/// forbids: metadata, host and pool addresses are blocked whatever the host model says.
#[test]
fn the_compiled_perimeter_permits_everything_the_host_admits() {
    let compiled = compile_perimeter(
        &NetworkProfile::new(pinned_document()).unwrap(),
        &new_pool(),
        &host_state(),
        perimeter_base(),
        full_capabilities(),
    )
    .unwrap();
    for seed in 0..16u64 {
        let mut random = SplitMix64::new(0x7e57 + seed);
        let clock = new_clock();
        let mut world = World::new(&clock);
        world.dns = FakeResolver::new("host-dns");
        let in_pins = |random: &mut SplitMix64, base: &str| {
            let base: Ipv4Addr = base.parse().unwrap();
            Ipv4Addr::from(u32::from(base) + u32::try_from(random.below(256)).unwrap()).to_string()
        };
        let pypi: Vec<String> = (0..3)
            .map(|_| in_pins(&mut random, "151.101.0.0"))
            .collect();
        let github = [in_pins(&mut random, "140.82.112.0")];
        let pypi_refs: Vec<&str> = pypi.iter().map(String::as_str).collect();
        let github_refs: Vec<&str> = github.iter().map(String::as_str).collect();
        world
            .dns
            .answer("pypi.org", AddressFamily::Ipv4, &pypi_refs, 60);
        world
            .dns
            .answer("github.com", AddressFamily::Ipv4, &github_refs, 60);
        let a = world.add("sbx-a", |document| {
            let identity = document.identity.clone();
            *document = pinned_document();
            document.identity = identity;
        });
        world.dns(&a, "pypi.org", GuestQueryType::A);
        world.dns(&a, "github.com", GuestQueryType::A);
        let mut candidates: Vec<String> = pypi.iter().chain(github.iter()).cloned().collect();
        candidates.extend(
            [
                MIRROR,
                REGISTRY,
                "1.1.1.1",
                HOST_LAN,
                "169.254.169.254",
                "10.200.0.3",
            ]
            .map(str::to_owned),
        );
        let mut admitted = 0;
        for step in 0..40 {
            let address =
                &candidates[usize::try_from(random.below(candidates.len() as u64)).unwrap()];
            let port_number = [443u16, 5000, 80][usize::try_from(random.below(3)).unwrap()];
            if let Ok(admission) = world.tcp(&a, address, port_number) {
                if matches!(
                    admission.kind,
                    FlowKind::Named { .. } | FlowKind::Endpoint { .. }
                ) {
                    assert!(
                        compiled.permits(ip(address), port(port_number)),
                        "{address}:{port_number}"
                    );
                    admitted += 1;
                }
                world.net.close_flow(&a, admission.flow).unwrap();
            }
            if step % 4 == 0 {
                if let Ok(admission) = world.proxy(&a, "pypi.org:443") {
                    if let FlowKind::Proxied {
                        address, authority, ..
                    } = &admission.kind
                    {
                        assert!(compiled.permits(*address, authority.port));
                    }
                    world.net.close_flow(&a, admission.flow).unwrap();
                }
            }
        }
        assert!(admitted > 0, "seed {seed}");
    }
    for forbidden in [
        HOST_LAN,
        HOST_VPN,
        GATEWAY,
        "10.200.0.3",
        "169.254.169.254",
        "168.63.129.16",
        "fd00:ec2::254",
        "fd00:200::5",
    ] {
        for port_number in [53u16, 443, 5000] {
            assert!(
                !compiled.permits(ip(forbidden), port(port_number)),
                "{forbidden}"
            );
        }
    }
}
