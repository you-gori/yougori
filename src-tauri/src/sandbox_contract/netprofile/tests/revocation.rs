//! Revocation and change (VM-W59; VM-W13 "revocation closes existing sessions"; VM §4.2
//! step 6): every affected flow is listed and closed, new ones are refused, the rest
//! continue under the new epoch; published and link responses are release charges.

use super::*;
use crate::foundation::ids::PolicyEpoch;
use crate::sandbox_contract::destinations::{
    AddressClass, AuthenticationMode, AuthorizationRefusal, ConnectionRefusal, InboundCaller,
    IngressError, MissingSide, PrincipalId, ReleaseError, ServiceIdentity,
};

fn web(
    audience: PublicationAudience,
    authentication: PublicationAuthentication,
) -> PublicationEntry {
    PublicationEntry {
        service: ServiceIdentity::new("web").unwrap(),
        port: port(8080),
        audience,
        authentication,
        lifetime_seconds: NonZeroU64::new(600).unwrap(),
    }
}

fn service(text: &str) -> ServiceIdentity {
    ServiceIdentity::new(text).unwrap()
}

#[test]
fn revoking_a_route_lists_every_flow_on_it_and_refuses_new_ones() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    world.dns(&a, "pypi.org", GuestQueryType::A);
    world.dns(&a, "pypi.org", GuestQueryType::Aaaa);
    world.dns(&a, "github.com", GuestQueryType::A);
    let pypi_key = world.key(&a, Transport::Tcp, PYPI_V4, 443);
    let pypi_v4 = world.net.open_flow(&a, pypi_key).unwrap().flow;
    let pypi_v6 = world.tcp(&a, PYPI_V6, 443).unwrap().flow;
    let pypi_proxied = world.proxy(&a, "pypi.org:443").unwrap().flow;
    let github = world.tcp(&a, GITHUB_V4, 443).unwrap().flow;
    let mirror = world.tcp(&a, MIRROR, 443).unwrap().flow;
    let dns = world.tcp(&a, GATEWAY, 53).unwrap().flow;
    let held = world.net.nat().len();

    let revocation = world.net.revoke_route(&a, &route("pypi")).unwrap();
    assert_eq!(
        revocation.flow_ids(),
        BTreeSet::from([pypi_v4, pypi_v6, pypi_proxied])
    );
    assert!(revocation.closed.iter().all(|closed| closed.reason
        == CloseReason::GrantRevoked {
            route: route("pypi")
        }));
    assert_eq!(world.net.nat().len(), held - 2);
    assert_eq!(
        world.net.packet(&a, &pypi_key),
        Err(FlowRefusal::NotEstablished)
    );
    assert!(matches!(
        world.net.open_flow(&a, pypi_key),
        Err(FlowRefusal::Authorization(
            AuthorizationRefusal::AddressNeedsEndpointGrant { .. }
        ))
    ));
    let calls = world.external_calls();
    assert_eq!(
        world.dns(&a, "pypi.org", GuestQueryType::A),
        DnsAnswer::NameNotAuthorized
    );
    assert!(matches!(
        world.proxy(&a, "pypi.org:443"),
        Err(FlowRefusal::Authorization(_))
    ));
    assert_eq!(world.external_calls(), calls);

    assert_eq!(world.net.epoch(&a), Some(PolicyEpoch::new(2)));
    for survivor in [github, mirror, dns] {
        assert_eq!(
            world.net.flow(&a, survivor).unwrap().epoch,
            PolicyEpoch::new(2)
        );
    }
    assert!(world.tcp(&a, GITHUB_V4, 443).is_ok());
    assert_eq!(world.net.usage(&a, &route("pypi")).connections, 3);
    assert_eq!(
        world.net.revoke_route(&a, &route("pypi")),
        Err(ReplaceError::UnknownRoute {
            route: route("pypi")
        })
    );
}

#[test]
fn revoking_the_last_grant_on_a_resolver_drops_the_resolver_too() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    world.net.revoke_route(&a, &route("pypi")).unwrap();
    world.net.revoke_route(&a, &route("github")).unwrap();
    let profile = world.net.profile(&a).unwrap();
    assert!(profile.document().resolvers.is_empty());
    assert_eq!(world.net.epoch(&a), Some(PolicyEpoch::new(3)));
}

#[test]
fn a_changed_grant_closes_its_flows_and_drops_its_answers_while_others_continue() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    world.dns(&a, "pypi.org", GuestQueryType::A);
    world.dns(&a, "github.com", GuestQueryType::A);
    let pypi = world.tcp(&a, PYPI_V4, 443).unwrap().flow;
    let github = world.tcp(&a, GITHUB_V4, 443).unwrap().flow;

    let mut document = world.net.profile(&a).unwrap().document().clone();
    for grant in &mut document.egress {
        if grant.id == route("pypi") {
            grant.budgets.bytes_out = 1;
        }
    }
    let changed = NetworkProfile::new(document).unwrap();
    let revocation = world
        .net
        .replace_profile(&a, changed, PolicyEpoch::new(2))
        .unwrap();
    assert_eq!(revocation.flow_ids(), BTreeSet::from([pypi]));
    assert_eq!(
        revocation.closed[0].reason,
        CloseReason::GrantChanged {
            route: route("pypi")
        }
    );
    assert!(world.net.flow(&a, github).is_some());
    assert!(matches!(
        world.tcp(&a, PYPI_V4, 443),
        Err(FlowRefusal::Authorization(_))
    ));
    assert!(world.tcp(&a, GITHUB_V4, 443).is_ok());
    world.dns(&a, "pypi.org", GuestQueryType::A);
    assert!(world.tcp(&a, PYPI_V4, 443).is_ok());
}

#[test]
fn a_shorter_answer_lifetime_applies_to_answers_already_given() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    world.dns(&a, "pypi.org", GuestQueryType::A);
    let mut document = world.net.profile(&a).unwrap().document().clone();
    document.max_answer_ttl_seconds = NonZeroU64::new(30).unwrap();
    let shorter = NetworkProfile::new(document).unwrap();
    let revocation = world
        .net
        .replace_profile(&a, shorter, PolicyEpoch::new(2))
        .unwrap();
    assert!(revocation.closed.is_empty());
    clock.advance(Duration::from_secs(29));
    assert!(world.tcp(&a, PYPI_V4, 443).is_ok());
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        world.tcp(&a, PYPI_V4, 443),
        Err(FlowRefusal::BindingExpired {
            address: ip(PYPI_V4)
        })
    );
}

#[test]
fn a_replacement_must_be_newer_and_may_change_only_egress() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let current = world.net.profile(&a).unwrap().document().clone();
    let same = NetworkProfile::new(current.clone()).unwrap();
    assert_eq!(
        world
            .net
            .replace_profile(&a, same.clone(), PolicyEpoch::FIRST),
        Err(ReplaceError::NotNewer {
            current: PolicyEpoch::FIRST,
            offered: PolicyEpoch::FIRST
        })
    );
    assert!(matches!(
        world
            .net
            .replace_profile(&exec("sbx-z"), same, PolicyEpoch::new(2)),
        Err(ReplaceError::UnknownSandbox { .. })
    ));
    let edits: Vec<(&str, Edit)> = vec![
        (
            "the network identity",
            Box::new(|document| document.identity.ipv4 = "10.200.0.9".parse().unwrap()),
        ),
        (
            "the network kind",
            Box::new(|document| document.kind = BroaderNetworkKind::UserOwnedGeneralVm),
        ),
        (
            "the release budgets",
            Box::new(|document| document.release.in_flight_allowance.bytes = 1),
        ),
        (
            "the publications",
            Box::new(|document| {
                document.ingress.push(web(
                    PublicationAudience::Public,
                    PublicationAuthentication::None,
                ))
            }),
        ),
        (
            "the sandbox links",
            Box::new(|document| {
                document.links.push(LinkEntry {
                    direction: LinkDirection::Outbound,
                    peer: LinkPeer {
                        execution: exec("sbx-b"),
                        scope: scope("sbx-b"),
                    },
                    service: service("model"),
                    port: port(9000),
                    lifetime_seconds: NonZeroU64::new(600).unwrap(),
                })
            }),
        ),
    ];
    for (section, edit) in edits {
        let mut document = current.clone();
        edit(&mut document);
        let profile = NetworkProfile::new(document).unwrap();
        assert_eq!(
            world.net.replace_profile(&a, profile, PolicyEpoch::new(2)),
            Err(ReplaceError::RequiresReadmission { section })
        );
    }
    let mut document = current;
    document.egress.push(endpoint_grant(
        "host-db",
        HOST_LAN,
        5432,
        None,
        "the host's database",
    ));
    let profile = NetworkProfile::new(document).unwrap();
    assert_eq!(
        world.net.replace_profile(&a, profile, PolicyEpoch::new(2)),
        Err(ReplaceError::EndpointNotExternal {
            route: route("host-db"),
            address: ip(HOST_LAN)
        })
    );
    assert_eq!(world.net.epoch(&a), Some(PolicyEpoch::FIRST));
}

#[test]
fn a_host_address_change_closes_flows_to_addresses_the_host_now_owns() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    world.dns(&a, "pypi.org", GuestQueryType::A);
    let doomed = world.tcp(&a, PYPI_V4, 443).unwrap().flow;
    let kept = world.tcp(&a, PYPI_V4_B, 443).unwrap().flow;
    let proxied = world.proxy(&a, "pypi.org:443").unwrap().flow;
    let registry = world.tcp(&a, REGISTRY, 5000).unwrap().flow;

    assert!(matches!(
        world.net.replace_host_addresses(host_state()),
        Err(ReplaceError::HostNotNewer { .. })
    ));
    let host = HostAddressState::new(
        HostAddressGeneration::new(2),
        host_state()
            .owned()
            .copied()
            .chain([IpPrefix::host(ip(PYPI_V4)), IpPrefix::host(ip(REGISTRY))]),
    );
    let revocation = world.net.replace_host_addresses(host).unwrap();
    assert_eq!(
        revocation.flow_ids(),
        BTreeSet::from([doomed, proxied, registry])
    );
    for closed in &revocation.closed {
        assert!(matches!(
            &closed.reason,
            CloseReason::AddressNowRefused(refused) if refused.verdict.class == AddressClass::HostOwned
        ));
    }
    assert!(world.net.flow(&a, kept).is_some());
    match world.tcp(&a, PYPI_V4, 443) {
        Err(FlowRefusal::Address(refused)) => {
            assert_eq!(refused.verdict.class, AddressClass::HostOwned)
        }
        other => panic!("{other:?}"),
    }
    match world.tcp(&a, REGISTRY, 5000) {
        Err(FlowRefusal::Address(refused)) => {
            assert_eq!(refused.verdict.class, AddressClass::HostOwned)
        }
        other => panic!("{other:?}"),
    }
    assert!(world.tcp(&a, PYPI_V4_B, 443).is_ok());
}

#[test]
fn published_responses_are_charged_and_withdrawal_closes_every_session() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |document| {
        document.ingress.push(web(
            PublicationAudience::Public,
            PublicationAuthentication::None,
        ));
    });
    let first = world
        .net
        .admit_inbound(&a, &service("web"), port(8080), &InboundCaller::Anonymous)
        .unwrap();
    let second = world
        .net
        .admit_inbound(&a, &service("web"), port(8080), &InboundCaller::Anonymous)
        .unwrap();
    assert!(matches!(first.kind, FlowKind::Inbound { .. }));
    world.net.respond(&a, first.flow, 6_000).unwrap();
    let release = world.net.release_account(&a).unwrap();
    assert_eq!(
        release.used_bytes(ReleaseChannel::PublishedServiceResponse),
        6_000
    );
    assert_eq!(release.general().released_bytes(), 6_000);
    assert!(matches!(
        world.net.respond(&a, second.flow, 4_001),
        Err(FlowRefusal::Ingress(IngressError::Release(
            ReleaseError::Exhausted(_)
        )))
    ));
    assert_eq!(
        world
            .net
            .admit_inbound(&a, &service("api"), port(8080), &InboundCaller::Anonymous),
        Err(FlowRefusal::Ingress(IngressError::NotPublished {
            service: service("api"),
            port: port(8080)
        }))
    );
    assert!(matches!(
        world
            .net
            .admit_inbound(&a, &service("web"), port(8081), &InboundCaller::Anonymous),
        Err(FlowRefusal::Ingress(IngressError::NotPublished { .. }))
    ));

    let revocation = world
        .net
        .withdraw_publication(&a, &service("web"), port(8080))
        .unwrap();
    assert_eq!(
        revocation.flow_ids(),
        BTreeSet::from([first.flow, second.flow])
    );
    assert!(revocation
        .closed
        .iter()
        .all(|closed| closed.reason == CloseReason::PublicationWithdrawn));
    assert_eq!(
        world.net.respond(&a, first.flow, 1),
        Err(FlowRefusal::NotEstablished)
    );
    assert!(matches!(
        world
            .net
            .admit_inbound(&a, &service("web"), port(8080), &InboundCaller::Anonymous),
        Err(FlowRefusal::Ingress(IngressError::NotPublished { .. }))
    ));
    assert!(matches!(
        world
            .net
            .withdraw_publication(&a, &service("web"), port(8080)),
        Err(FlowRefusal::Ingress(IngressError::NotPublished { .. }))
    ));
}

#[test]
fn private_publications_keep_their_audience_and_expire() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let alice = PrincipalId::new("alice").unwrap();
    let a = world.add("sbx-a", |document| {
        document.ingress.push(web(
            PublicationAudience::Private {
                principals: BTreeSet::from([PrincipalId::new("alice").unwrap()]),
            },
            PublicationAuthentication::BearerToken,
        ));
    });
    let admit = |world: &mut World, caller: &InboundCaller| {
        world
            .net
            .admit_inbound(&a, &service("web"), port(8080), caller)
    };
    assert_eq!(
        admit(&mut world, &InboundCaller::Anonymous),
        Err(FlowRefusal::Ingress(IngressError::NotAuthenticated))
    );
    assert_eq!(
        admit(
            &mut world,
            &InboundCaller::Authenticated {
                mode: AuthenticationMode::BearerToken,
                principal: PrincipalId::new("eve").unwrap()
            }
        ),
        Err(FlowRefusal::Ingress(IngressError::NotInAudience))
    );
    assert!(matches!(
        admit(
            &mut world,
            &InboundCaller::Authenticated {
                mode: AuthenticationMode::PlatformSession,
                principal: alice.clone()
            }
        ),
        Err(FlowRefusal::Ingress(
            IngressError::WrongAuthentication { .. }
        ))
    ));
    let session = admit(
        &mut world,
        &InboundCaller::Authenticated {
            mode: AuthenticationMode::BearerToken,
            principal: alice,
        },
    )
    .unwrap();
    clock.advance(Duration::from_secs(600));
    assert_eq!(
        world.net.respond(&a, session.flow, 1),
        Err(FlowRefusal::Ingress(IngressError::Expired))
    );
    assert_eq!(
        admit(&mut world, &InboundCaller::Anonymous),
        Err(FlowRefusal::Ingress(IngressError::Expired))
    );
}

#[test]
fn link_responses_are_charged_to_the_callee_and_revocation_closes_link_flows() {
    let clock = new_clock();
    let mut world = World::new(&clock);
    let link = |direction, peer: &str| LinkEntry {
        direction,
        peer: LinkPeer {
            execution: exec(peer),
            scope: scope(peer),
        },
        service: service("model"),
        port: port(9000),
        lifetime_seconds: NonZeroU64::new(600).unwrap(),
    };
    let a = world.add("sbx-a", |document| {
        document.links.push(link(LinkDirection::Outbound, "sbx-b"))
    });
    let b = world.add("sbx-b", |document| {
        document.links.push(link(LinkDirection::Inbound, "sbx-a"))
    });
    let b_address = world.identity(&b).ipv4.to_string();
    let flow = world.tcp(&a, &b_address, 9000).unwrap().flow;
    let mirror = world.tcp(&a, MIRROR, 443).unwrap().flow;
    world.net.respond(&a, flow, 2_500).unwrap();
    assert_eq!(
        world
            .net
            .release_account(&b)
            .unwrap()
            .used_bytes(ReleaseChannel::PublishedServiceResponse),
        2_500
    );
    assert_eq!(
        world
            .net
            .release_account(&a)
            .unwrap()
            .used_bytes(ReleaseChannel::PublishedServiceResponse),
        0
    );
    assert_eq!(
        world.net.respond(&a, mirror, 1),
        Err(FlowRefusal::WrongFlowKind)
    );
    assert_eq!(world.net.send(&a, flow, 1), Err(FlowRefusal::WrongFlowKind));

    let caller = world.identity(&a).endpoint();
    let callee = world.identity(&b).endpoint();
    let revocation = world.net.revoke_link(&caller, &callee);
    assert_eq!(revocation.flow_ids(), BTreeSet::from([flow]));
    assert_eq!(revocation.closed[0].reason, CloseReason::LinkRevoked);
    assert!(world.net.flow(&a, mirror).is_some());
    assert_eq!(
        world.tcp(&a, &b_address, 9000),
        Err(FlowRefusal::Connection(ConnectionRefusal::MissingGrant {
            side: MissingSide::Both
        }))
    );
}
