//! VM §4.2 steps 3–7 through the broker: resolution, address checks, revalidation and
//! budgets (VM-P06–VM-P10, VM-P32, VM-P33).

use super::fakes::FakeResolver;
use super::*;

const V4: AddressFamily = AddressFamily::Ipv4;
const V6: AddressFamily = AddressFamily::Ipv6;

fn broker(clock: &ManualClock, grants: Vec<RouteGrant>) -> DestinationBroker<&ManualClock> {
    DestinationBroker::new(
        policy(NetworkMode::StrictAction, grants),
        host_state(),
        release_account(),
        clock,
    )
}

fn resolver() -> FakeResolver {
    FakeResolver::new("host-dns")
}

fn api_with(edit: impl FnOnce(&mut RouteGrant)) -> RouteGrant {
    let mut grant = api_grant(RedirectPolicy::Reauthorize);
    edit(&mut grant);
    grant
}

#[test]
fn an_authorized_name_resolves_through_its_resolver_and_validates_every_address() {
    let clock = clock();
    let mut broker = broker(&clock, vec![api_grant(RedirectPolicy::Disabled)]);
    let dns = resolver();
    dns.answer(
        "api.example.com",
        V4,
        &["93.184.216.34", "93.184.216.35"],
        60,
    );
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    let validated = broker.resolve(&authorized, V4, &dns).unwrap();
    assert_eq!(validated.addresses().len(), 2);
    assert!(validated
        .addresses()
        .iter()
        .all(|verdict| verdict.class == AddressClass::Public));
    assert_eq!(validated.tls_name(), Some(&name("api.example.com")));
    assert_eq!(
        validated.valid_until(),
        START.saturating_add(Duration::from_secs(60))
    );
    // The resolver saw exactly the authorized absolute name, nothing appended.
    assert_eq!(dns.queried()[0].name(), &name("api.example.com"));
    // One query: one name-budget unit and 12 + 17 + 4 = 33 released DNS bytes.
    assert_eq!(
        broker
            .usage(&route_id("provider-api"))
            .used(BudgetKind::DnsQueries),
        1
    );
    assert_eq!(
        broker
            .release_account()
            .used_bytes(ReleaseChannel::DnsQuery),
        33
    );
    let permit = broker
        .open_connection(&validated, ip("93.184.216.35"))
        .unwrap();
    assert_eq!(permit.tls_name(), Some(&name("api.example.com")));
    assert_eq!(
        broker
            .usage(&route_id("provider-api"))
            .used(BudgetKind::Connections),
        1
    );
}

#[test]
fn authorization_happens_before_any_resolution_or_dns_release() {
    let clock = clock();
    let broker = broker(&clock, vec![api_grant(RedirectPolicy::Disabled)]);
    let dns = resolver();
    dns.answer("secret-data.attacker.example", V4, &["93.184.216.34"], 60);
    assert!(matches!(
        broker.authorize(&request("secret-data.attacker.example")),
        Err(DestinationRefusal::Authorization(
            AuthorizationRefusal::NotGranted { .. }
        ))
    ));
    assert_eq!(dns.calls(), 0);
    assert_eq!(
        broker
            .release_account()
            .used_bytes(ReleaseChannel::DnsQuery),
        0
    );
}

#[test]
fn every_refused_address_class_in_an_answer_refuses_the_whole_answer() {
    let refused = [
        "127.0.0.1",
        "10.0.0.5",
        "172.20.1.1",
        "192.168.50.1",
        "100.64.9.9",
        "169.254.1.1",
        "169.254.169.254",
        "168.63.129.16",
        "224.0.0.251",
        "255.255.255.255",
        "0.0.0.0",
        "192.0.2.10",
        "198.18.0.5",
        "240.1.1.1",
        "192.168.1.10",
        "100.101.102.103",
    ];
    for address in refused {
        let clock = clock();
        let mut broker = broker(&clock, vec![api_grant(RedirectPolicy::Disabled)]);
        let dns = resolver();
        // A public address alongside does not rescue the answer.
        dns.answer("api.example.com", V4, &["93.184.216.34", address], 60);
        let authorized = broker.authorize(&request("api.example.com")).unwrap();
        assert!(
            matches!(
                broker.resolve(&authorized, V4, &dns),
                Err(DestinationRefusal::Address(_))
            ),
            "{address}"
        );
    }
}

#[test]
fn mapped_and_translated_ipv6_answers_are_refused() {
    let ipv6_grant = api_with(|grant| grant.ipv6 = true);
    for address in [
        "::ffff:10.0.0.5",
        "::ffff:169.254.169.254",
        "64:ff9b::a9fe:a9fe",
        "::ffff:0:a9fe:a9fe",
        "2002:a00:5::1",
        "::1",
        "fe80::1",
        "fd00:ec2::254",
        "fd12::9",
        "ff02::1",
        "2001:db8::5",
    ] {
        let clock = clock();
        let mut broker = broker(&clock, vec![ipv6_grant.clone()]);
        let dns = resolver();
        dns.answer("api.example.com", V6, &[address], 60);
        let authorized = broker.authorize(&request("api.example.com")).unwrap();
        assert!(
            matches!(
                broker.resolve(&authorized, V6, &dns),
                Err(DestinationRefusal::Address(_))
            ),
            "{address}"
        );
    }
}

#[test]
fn an_aaaa_query_without_an_ipv6_grant_is_refused_before_resolution() {
    let clock = clock();
    let mut broker = broker(&clock, vec![api_grant(RedirectPolicy::Disabled)]);
    let dns = resolver();
    dns.answer("api.example.com", V6, &["2606:2800:220:1::1"], 60);
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    assert_eq!(
        broker.resolve(&authorized, V6, &dns),
        Err(DestinationRefusal::Ipv6NotGranted)
    );
    assert_eq!(dns.calls(), 0);
}

#[test]
fn an_aaaa_answer_carrying_ipv4_addresses_is_refused() {
    let clock = clock();
    let mut broker = broker(&clock, vec![api_with(|grant| grant.ipv6 = true)]);
    let dns = resolver();
    dns.answer("api.example.com", V6, &["93.184.216.34"], 60);
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    assert_eq!(
        broker.resolve(&authorized, V6, &dns),
        Err(DestinationRefusal::WrongFamily {
            asked: V6,
            address: ip("93.184.216.34")
        })
    );
}

#[test]
fn an_answer_for_a_search_suffixed_or_other_name_is_refused() {
    let clock = clock();
    let mut broker = broker(&clock, vec![api_grant(RedirectPolicy::Disabled)]);
    let dns = resolver();
    dns.push(
        "api.example.com",
        V4,
        Ok(ResolverAnswer {
            name: name("api.example.com.corp.internal"),
            aliases: Vec::new(),
            addresses: vec![ip("93.184.216.34")],
            ttl: Duration::from_secs(60),
        }),
    );
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    assert_eq!(
        broker.resolve(&authorized, V4, &dns),
        Err(DestinationRefusal::AnswerForOtherName {
            asked: name("api.example.com"),
            answered: name("api.example.com.corp.internal"),
        })
    );
}

#[test]
fn alias_chains_are_bounded_and_never_become_the_tls_name() {
    let clock = clock();
    let mut broker = broker(&clock, vec![api_grant(RedirectPolicy::Disabled)]);
    let dns = resolver();
    let chain: Vec<CanonicalName> = (0..MAX_ALIAS_CHAIN)
        .map(|index| name(&format!("hop{index}.cdn.example.net")))
        .collect();
    dns.push(
        "api.example.com",
        V4,
        Ok(ResolverAnswer {
            name: name("api.example.com"),
            aliases: chain.clone(),
            addresses: vec![ip("93.184.216.34")],
            ttl: Duration::from_secs(60),
        }),
    );
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    let validated = broker.resolve(&authorized, V4, &dns).unwrap();
    assert_eq!(validated.aliases(), chain.as_slice());
    assert_eq!(validated.tls_name(), Some(&name("api.example.com")));

    let too_long: Vec<CanonicalName> = (0..=MAX_ALIAS_CHAIN)
        .map(|index| name(&format!("hop{index}.cdn.example.net")))
        .collect();
    let dns = resolver();
    dns.push(
        "api.example.com",
        V4,
        Ok(ResolverAnswer {
            name: name("api.example.com"),
            aliases: too_long,
            addresses: vec![ip("93.184.216.34")],
            ttl: Duration::from_secs(60),
        }),
    );
    assert_eq!(
        broker.resolve(&authorized, V4, &dns),
        Err(DestinationRefusal::AliasChainTooLong {
            length: MAX_ALIAS_CHAIN + 1
        })
    );
}

#[test]
fn only_the_grants_allowed_resolver_may_be_used() {
    let clock = clock();
    let mut broker = broker(&clock, vec![api_grant(RedirectPolicy::Disabled)]);
    let guest = FakeResolver::new("guest-resolver");
    guest.answer("api.example.com", V4, &["93.184.216.34"], 60);
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    assert_eq!(
        broker.resolve(&authorized, V4, &guest),
        Err(DestinationRefusal::ResolverNotAllowed {
            resolver: ResolverId::new("guest-resolver").unwrap()
        })
    );
    assert_eq!(guest.calls(), 0);
}

#[test]
fn resolver_failures_still_count_the_query_that_left() {
    let clock = clock();
    let mut broker = broker(&clock, vec![api_grant(RedirectPolicy::Disabled)]);
    let dns = resolver();
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    assert_eq!(
        broker.resolve(&authorized, V4, &dns),
        Err(DestinationRefusal::ResolverFailed(
            ResolverFailure::NameDoesNotExist
        ))
    );
    assert_eq!(
        broker
            .release_account()
            .used_bytes(ReleaseChannel::DnsQuery),
        33
    );
    dns.answer("api.example.com", V4, &[], 60);
    assert_eq!(
        broker.resolve(&authorized, V4, &dns),
        Err(DestinationRefusal::EmptyAnswer)
    );
}

#[test]
fn a_ttl_change_forces_re_resolution_and_a_rebinding_to_a_private_address_is_caught() {
    let clock = clock();
    let mut broker = broker(&clock, vec![api_grant(RedirectPolicy::Disabled)]);
    let dns = resolver();
    dns.answer("api.example.com", V4, &["93.184.216.34"], 5);
    dns.answer("api.example.com", V4, &["10.0.0.5"], 5);
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    let validated = broker.resolve(&authorized, V4, &dns).unwrap();
    assert!(broker
        .open_connection(&validated, ip("93.184.216.34"))
        .is_ok());
    // The guest cannot connect to an address the broker did not validate.
    assert_eq!(
        broker.open_connection(&validated, ip("10.0.0.5")),
        Err(DestinationRefusal::AddressNotValidated {
            address: ip("10.0.0.5")
        })
    );
    clock.advance(Duration::from_secs(5));
    assert_eq!(
        broker.open_connection(&validated, ip("93.184.216.34")),
        Err(DestinationRefusal::Expired)
    );
    assert!(matches!(
        broker.resolve(&authorized, V4, &dns),
        Err(DestinationRefusal::Address(_))
    ));
}

#[test]
fn a_long_ttl_is_capped_by_the_policy() {
    let clock = clock();
    let mut broker = broker(&clock, vec![api_grant(RedirectPolicy::Disabled)]);
    let dns = resolver();
    dns.answer("api.example.com", V4, &["93.184.216.34"], 86_400);
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    let validated = broker.resolve(&authorized, V4, &dns).unwrap();
    assert_eq!(
        validated.valid_until(),
        START.saturating_add(broker.max_answer_lifetime())
    );
}

#[test]
fn redirect_revalidation_catches_a_rebinding_to_a_private_address() {
    let clock = clock();
    let mut broker = broker(&clock, vec![api_grant(RedirectPolicy::Reauthorize)]);
    let dns = resolver();
    dns.answer("api.example.com", V4, &["93.184.216.34"], 60);
    dns.answer("api.example.com", V4, &["192.168.0.20"], 60);
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    let validated = broker.resolve(&authorized, V4, &dns).unwrap();
    let redirect = broker.follow_redirect(&validated, "https://api.example.com/next", V4, &dns);
    assert!(
        matches!(redirect, Err(DestinationRefusal::Address(refused)) if refused.verdict.class == AddressClass::Private)
    );
    assert_eq!(dns.calls(), 2);
}

#[test]
fn redirects_are_disabled_or_fully_reauthorized_on_the_same_route() {
    let clock = clock();
    let partner = exact_grant(
        "partner",
        "partner.example.org",
        RouteKind::Operation(operation_route(RedirectPolicy::Disabled, false)),
    );
    let mut broker = broker(
        &clock,
        vec![api_grant(RedirectPolicy::Reauthorize), partner],
    );
    let dns = resolver();
    dns.answer("api.example.com", V4, &["93.184.216.34"], 60);
    dns.answer("partner.example.org", V4, &["93.184.216.40"], 60);
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    let validated = broker.resolve(&authorized, V4, &dns).unwrap();
    assert!(broker
        .follow_redirect(&validated, "/next", V4, &dns)
        .is_ok());
    assert!(matches!(
        broker.follow_redirect(&validated, "https://evil.example.net/", V4, &dns),
        Err(DestinationRefusal::Authorization(
            AuthorizationRefusal::NotGranted { .. }
        ))
    ));
    assert_eq!(
        broker.follow_redirect(&validated, "https://partner.example.org/", V4, &dns),
        Err(DestinationRefusal::RedirectLeavesRoute {
            from: route_id("provider-api"),
            to: route_id("partner")
        })
    );
    assert_eq!(
        broker.follow_redirect(&validated, "http://api.example.com/next", V4, &dns),
        Err(DestinationRefusal::Redirect(
            RequestRefusal::RedirectSchemeNotHttps
        ))
    );
    let partner_authorized = broker.authorize(&request("partner.example.org")).unwrap();
    let partner_validated = broker.resolve(&partner_authorized, V4, &dns).unwrap();
    assert_eq!(
        broker.follow_redirect(&partner_validated, "/next", V4, &dns),
        Err(DestinationRefusal::RedirectsDisabled)
    );
}

#[test]
fn a_changed_host_address_state_forces_revalidation() {
    let clock = clock();
    let mut broker = broker(&clock, vec![api_grant(RedirectPolicy::Disabled)]);
    let dns = resolver();
    dns.answer("api.example.com", V4, &["93.184.216.34"], 60);
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    let validated = broker.resolve(&authorized, V4, &dns).unwrap();
    let permit = broker
        .open_connection(&validated, ip("93.184.216.34"))
        .unwrap();
    // The host now owns that address (for example a new VPN or interface address).
    broker
        .replace_host_addresses(HostAddressState::new(
            HostAddressGeneration::new(2),
            [IpPrefix::host(ip("93.184.216.34"))],
        ))
        .unwrap();
    assert!(matches!(
        broker.open_connection(&validated, ip("93.184.216.34")),
        Err(DestinationRefusal::Stale { .. })
    ));
    assert!(matches!(
        broker.reserve_send(&permit, 10),
        Err(DestinationRefusal::Stale { .. })
    ));
    assert!(matches!(
        broker.resolve(&authorized, V4, &dns),
        Err(DestinationRefusal::Address(refused)) if refused.verdict.class == AddressClass::HostOwned
    ));
    assert_eq!(
        broker.replace_host_addresses(HostAddressState::new(HostAddressGeneration::new(2), [])),
        Err(DestinationRefusal::NotNewer)
    );
}

#[test]
fn a_changed_policy_forces_reauthorization_but_keeps_usage() {
    let clock = clock();
    let mut broker = broker(&clock, vec![api_grant(RedirectPolicy::Disabled)]);
    let dns = resolver();
    dns.answer("api.example.com", V4, &["93.184.216.34"], 60);
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    let validated = broker.resolve(&authorized, V4, &dns).unwrap();
    let mut next = parts(
        NetworkMode::StrictAction,
        vec![api_grant(RedirectPolicy::Disabled)],
    );
    next.epoch = PolicyEpoch::new(2);
    broker
        .replace_policy(DestinationPolicy::new(next.clone(), START).unwrap())
        .unwrap();
    assert!(matches!(
        broker.open_connection(&validated, ip("93.184.216.34")),
        Err(DestinationRefusal::Stale { .. })
    ));
    assert!(matches!(
        broker.resolve(&authorized, V4, &dns),
        Err(DestinationRefusal::Stale { .. })
    ));
    assert_eq!(
        broker
            .usage(&route_id("provider-api"))
            .used(BudgetKind::DnsQueries),
        1
    );
    let fresh = broker.authorize(&request("api.example.com")).unwrap();
    assert_eq!(fresh.epoch(), PolicyEpoch::new(2));
    assert!(broker.resolve(&fresh, V4, &dns).is_ok());
    assert_eq!(
        broker
            .usage(&route_id("provider-api"))
            .used(BudgetKind::DnsQueries),
        2
    );
    assert_eq!(
        broker.replace_policy(DestinationPolicy::new(next, START).unwrap()),
        Err(DestinationRefusal::NotNewer)
    );
}

#[test]
fn an_endpoint_inside_the_synthetic_range_is_refused_as_a_collision() {
    // Synthetic ranges are never public, so only a private or CGNAT endpoint can collide.
    let clock = clock();
    let cgnat_plan = SyntheticAddressPlan::choose(
        &[IpPrefix::new(ip("100.72.0.0"), 16).unwrap()],
        &[],
        &HostAddressState::new(HostAddressGeneration::FIRST, []),
        &[],
    )
    .unwrap();
    let registry = endpoint_grant("registry", None, "100.72.0.9", 5000);
    let broker = DestinationBroker::new(
        policy(NetworkMode::StrictAction, vec![registry]),
        host_state(),
        release_account(),
        &clock,
    )
    .with_synthetic_plan(cgnat_plan);
    let authorized = broker.authorize(&request("100.72.0.9:5000")).unwrap();
    assert_eq!(
        broker.validate_endpoint(&authorized),
        Err(DestinationRefusal::Synthetic(SyntheticError::Collision {
            address: ip("100.72.0.9"),
            prefix: IpPrefix::new(ip("100.72.0.0"), 16).unwrap(),
        }))
    );
}

#[test]
fn exact_endpoints_are_validated_without_resolution() {
    let clock = clock();
    let registry = endpoint_grant("registry", Some("registry.corp.example"), "10.0.5.20", 5000);
    let mut broker = broker(&clock, vec![registry]);
    let dns = resolver();
    let authorized = broker
        .authorize(&request("registry.corp.example:5000"))
        .unwrap();
    assert_eq!(
        broker.resolve(&authorized, V4, &dns),
        Err(DestinationRefusal::EndpointNotResolved)
    );
    let validated = broker.validate_endpoint(&authorized).unwrap();
    assert_eq!(validated.tls_name(), Some(&name("registry.corp.example")));
    assert!(broker.open_connection(&validated, ip("10.0.5.20")).is_ok());
    assert_eq!(dns.calls(), 0);
    // If the host comes to own that address, the endpoint is refused.
    broker
        .replace_host_addresses(HostAddressState::new(
            HostAddressGeneration::new(2),
            [IpPrefix::host(ip("10.0.5.20"))],
        ))
        .unwrap();
    assert!(matches!(
        broker.validate_endpoint(&authorized),
        Err(DestinationRefusal::Address(_))
    ));
}

#[test]
fn a_sensitive_task_reaches_exact_endpoints_and_never_resolves() {
    let clock = clock();
    let mut sensitive = parts(
        NetworkMode::StrictAction,
        vec![endpoint_grant("registry", None, "10.0.5.20", 5000)],
    );
    sensitive.data_class = TaskDataClass::SensitiveOffline;
    let mut broker = DestinationBroker::new(
        DestinationPolicy::new(sensitive, START).unwrap(),
        host_state(),
        release_account(),
        &clock,
    );
    let authorized = broker.authorize(&request("10.0.5.20:5000")).unwrap();
    assert!(broker.validate_endpoint(&authorized).is_ok());
    let dns = resolver();
    assert_eq!(
        broker.resolve(&authorized, V4, &dns),
        Err(DestinationRefusal::ResolutionForbidden)
    );
    assert_eq!(
        broker
            .release_account()
            .used_bytes(ReleaseChannel::DnsQuery),
        0
    );
}

#[test]
fn an_exhausted_name_budget_refuses_further_queries() {
    let clock = clock();
    let mut broker = broker(
        &clock,
        vec![api_with(|grant| grant.budgets.dns_queries = 1)],
    );
    let dns = resolver();
    dns.answer("api.example.com", V4, &["93.184.216.34"], 60);
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    assert!(broker.resolve(&authorized, V4, &dns).is_ok());
    let refusal = broker.resolve(&authorized, V4, &dns).unwrap_err();
    match refusal {
        DestinationRefusal::Budget(exhausted) => {
            assert_eq!(
                exhausted.scope,
                BudgetScope::Route(route_id("provider-api"))
            );
            assert_eq!(exhausted.kind, Some(BudgetKind::DnsQueries));
            assert_eq!(
                (exhausted.limit, exhausted.used, exhausted.requested),
                (1, 1, 1)
            );
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(dns.calls(), 1);
    assert_eq!(
        broker
            .release_account()
            .used_bytes(ReleaseChannel::DnsQuery),
        33
    );
}

#[test]
fn an_exhausted_dns_release_channel_refuses_before_the_query_leaves() {
    let clock = clock();
    let release = ReleaseAccount::new(
        BTreeMap::from([(
            ReleaseChannel::DnsQuery,
            channel(40, ReleaseTrustClass::Resolver),
        )]),
        GeneralReleaseBudget::vm_d12_default(),
        InFlightAllowance {
            bytes: 0,
            documented_reason: "no allowance in this test".to_owned(),
        },
    )
    .unwrap();
    let mut broker = DestinationBroker::new(
        policy(
            NetworkMode::StrictAction,
            vec![api_grant(RedirectPolicy::Disabled)],
        ),
        host_state(),
        release,
        &clock,
    );
    let dns = resolver();
    dns.answer("api.example.com", V4, &["93.184.216.34"], 60);
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    assert!(broker.resolve(&authorized, V4, &dns).is_ok());
    assert!(matches!(
        broker.resolve(&authorized, V4, &dns),
        Err(DestinationRefusal::Release(ReleaseError::Exhausted(_)))
    ));
    assert_eq!(dns.calls(), 1);
    assert_eq!(
        broker
            .usage(&route_id("provider-api"))
            .used(BudgetKind::DnsQueries),
        1
    );
}

#[test]
fn connection_byte_and_effect_budgets_are_reserved_centrally() {
    let clock = clock();
    let mut broker = broker(
        &clock,
        vec![api_with(|grant| {
            grant.budgets.connections = 1;
            grant.budgets.bytes_out = 1_000;
            grant.budgets.bytes_in = 100;
            grant.budgets.effects = 1;
        })],
    );
    let dns = resolver();
    dns.answer("api.example.com", V4, &["93.184.216.34"], 60);
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    let validated = broker.resolve(&authorized, V4, &dns).unwrap();
    let permit = broker
        .open_connection(&validated, ip("93.184.216.34"))
        .unwrap();
    assert!(matches!(
        broker.open_connection(&validated, ip("93.184.216.34")),
        Err(DestinationRefusal::Budget(_))
    ));

    // Two concurrent sends cannot both spend the same remainder.
    let first = broker.reserve_send(&permit, 600).unwrap();
    assert!(matches!(
        broker.reserve_send(&permit, 600),
        Err(DestinationRefusal::Budget(_))
    ));
    broker.complete_send(first, 450).unwrap();
    assert_eq!(
        broker
            .usage(&route_id("provider-api"))
            .used(BudgetKind::BytesOut),
        450
    );
    assert_eq!(
        broker
            .release_account()
            .used_bytes(ReleaseChannel::ProviderRequest),
        450
    );
    let second = broker.reserve_send(&permit, 550).unwrap();
    assert_eq!(second.bytes(), 550);
    assert!(matches!(
        broker.complete_send(second, 551),
        Err(DestinationRefusal::Settle(
            SettleError::ExceedsReservation { .. }
        ))
    ));

    broker.record_received(&permit, 100).unwrap();
    assert!(matches!(
        broker.record_received(&permit, 1),
        Err(DestinationRefusal::Budget(_))
    ));

    let effect = broker.reserve_effect(&route_id("provider-api")).unwrap();
    assert!(matches!(
        broker.reserve_effect(&route_id("provider-api")),
        Err(DestinationRefusal::Budget(_))
    ));
    broker
        .settle_effect(effect, EffectOutcome::NotPerformed)
        .unwrap();
    let effect = broker.reserve_effect(&route_id("provider-api")).unwrap();
    // A lost response leaves the effect spent; a retry needs budget of its own.
    broker
        .settle_effect(effect, EffectOutcome::Uncertain)
        .unwrap();
    assert!(matches!(
        broker.reserve_effect(&route_id("provider-api")),
        Err(DestinationRefusal::Budget(_))
    ));
    assert_eq!(
        broker
            .usage(&route_id("provider-api"))
            .used(BudgetKind::Effects),
        1
    );
}

/// A broker with one 100-byte inbound budget on `provider-api`, and a permit for it.
fn inbound_broker(clock: &ManualClock) -> (DestinationBroker<&ManualClock>, ConnectionPermit) {
    let mut broker = broker(clock, vec![api_with(|grant| grant.budgets.bytes_in = 100)]);
    let dns = resolver();
    dns.answer("api.example.com", V4, &["93.184.216.34"], 60);
    let authorized = broker.authorize(&request("api.example.com")).unwrap();
    let validated = broker.resolve(&authorized, V4, &dns).unwrap();
    let permit = broker
        .open_connection(&validated, ip("93.184.216.34"))
        .unwrap();
    (broker, permit)
}

/// The route's inbound bytes: used, then reserved.
fn inbound(broker: &DestinationBroker<&ManualClock>) -> (u64, u64) {
    let usage = broker.usage(&route_id("provider-api"));
    (
        usage.used(BudgetKind::BytesIn),
        usage.reserved(BudgetKind::BytesIn),
    )
}

#[test]
fn received_bytes_are_reserved_centrally_and_settled_once() {
    let clock = clock();
    let (mut broker, permit) = inbound_broker(&clock);
    // Two concurrent receives cannot both spend the same remainder.
    let first = broker.reserve_received(&permit, 60).unwrap();
    assert_eq!(first.bytes(), 60);
    assert_eq!(inbound(&broker), (0, 60));
    assert_eq!(
        broker.reserve_received(&permit, 41),
        Err(DestinationRefusal::Budget(BudgetExhausted {
            scope: BudgetScope::Route(route_id("provider-api")),
            kind: Some(BudgetKind::BytesIn),
            limit: 100,
            used: 0,
            reserved: 60,
            requested: 41,
        }))
    );
    // Under the reservation: the rest returns.
    broker.complete_received(first, 25).unwrap();
    assert_eq!(inbound(&broker), (25, 0));
    // At the reservation.
    let exact = broker.reserve_received(&permit, 30).unwrap();
    broker.complete_received(exact, 30).unwrap();
    assert_eq!(inbound(&broker), (55, 0));
    // Cancelled: nothing is charged.
    let cancelled = broker.reserve_received(&permit, 45).unwrap();
    assert_eq!(inbound(&broker), (55, 45));
    broker.cancel_received(cancelled).unwrap();
    assert_eq!(inbound(&broker), (55, 0));
    // Over the reservation: refused, still charged, and nothing left reserved.
    let over = broker.reserve_received(&permit, 10).unwrap();
    assert_eq!(
        broker.complete_received(over, 12),
        Err(DestinationRefusal::Settle(
            SettleError::ExceedsReservation {
                reserved: 10,
                actual: 12
            }
        ))
    );
    assert_eq!(inbound(&broker), (67, 0));
    // The limit holds: exactly the 33 bytes left can be reserved, and no more.
    assert!(matches!(
        broker.reserve_received(&permit, 34),
        Err(DestinationRefusal::Budget(_))
    ));
    let rest = broker.reserve_received(&permit, 33).unwrap();
    assert!(matches!(
        broker.reserve_received(&permit, 1),
        Err(DestinationRefusal::Budget(_))
    ));
    broker.cancel_received(rest).unwrap();
    // `record_received` charges the same book.
    broker.record_received(&permit, 33).unwrap();
    assert_eq!(inbound(&broker), (100, 0));
    assert!(matches!(
        broker.reserve_received(&permit, 1),
        Err(DestinationRefusal::Budget(_))
    ));
    // Received bytes draw on no release channel.
    assert_eq!(
        broker
            .release_account()
            .used_bytes(ReleaseChannel::ProviderRequest),
        0
    );
}

#[test]
fn a_stale_permit_reserves_no_received_bytes() {
    let clock = clock();
    let (mut broker, permit) = inbound_broker(&clock);
    let held = broker.reserve_received(&permit, 40).unwrap();
    let mut next = parts(
        NetworkMode::StrictAction,
        vec![api_with(|grant| grant.budgets.bytes_in = 100)],
    );
    next.epoch = PolicyEpoch::new(2);
    broker
        .replace_policy(DestinationPolicy::new(next, START).unwrap())
        .unwrap();
    assert!(matches!(
        broker.reserve_received(&permit, 1),
        Err(DestinationRefusal::Stale { .. })
    ));
    assert_eq!(inbound(&broker), (0, 40));
    // A reservation made earlier still settles: the bytes already arrived.
    broker.complete_received(held, 40).unwrap();
    assert_eq!(inbound(&broker), (40, 0));
}

#[test]
fn a_transport_route_charges_the_transport_stream_channel() {
    let clock = clock();
    let transport = exact_grant(
        "git",
        "git.example.com",
        RouteKind::Transport(refusing_transport()),
    );
    let mut broker = DestinationBroker::new(
        policy(NetworkMode::DeclaredTransport, vec![transport]),
        host_state(),
        release_account(),
        &clock,
    );
    let dns = resolver();
    dns.answer("git.example.com", V4, &["140.82.112.3"], 60);
    let tls = DestinationRequest::parse(RouteProtocol::Tls, "git.example.com").unwrap();
    let authorized = broker.authorize(&tls).unwrap();
    let validated = broker.resolve(&authorized, V4, &dns).unwrap();
    let permit = broker
        .open_connection(&validated, ip("140.82.112.3"))
        .unwrap();
    let send = broker.reserve_send(&permit, 300).unwrap();
    broker.complete_send(send, 300).unwrap();
    assert_eq!(
        broker
            .release_account()
            .used_bytes(ReleaseChannel::TransportStream),
        300
    );
    assert_eq!(
        broker
            .release_account()
            .used_bytes(ReleaseChannel::ProviderRequest),
        0
    );
}
