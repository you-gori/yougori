//! VM §4.2: grants, authorization before resolution, wildcards, private endpoints and
//! sensitive tasks.

use super::*;

fn ownership(zone: &str, valid_for_seconds: u64) -> ZoneOwnership {
    ZoneOwnership {
        owner: tenant(),
        zone: name(zone),
        evidence: test_digest("txt-challenge"),
        valid_until: START.saturating_add(Duration::from_secs(valid_for_seconds)),
    }
}

fn wildcard_grant(zone: &str, ownership: ZoneOwnership) -> Result<RouteGrant, PolicyError> {
    Ok(RouteGrant {
        id: route_id("previews"),
        protocol: RouteProtocol::Https,
        target: GrantTarget::Wildcard(WildcardGrant::new(
            name(zone),
            ownership,
            GrantPurpose::new("customer-previews").unwrap(),
        )?),
        port: DestinationPort::HTTPS,
        route: RouteKind::Operation(operation_route(RedirectPolicy::Disabled, false)),
        ipv6: false,
        resolver: Some(resolver_id()),
        budgets: budgets(),
    })
}

#[test]
fn an_exact_grant_authorizes_only_its_exact_name_port_and_protocol() {
    let policy = policy(
        NetworkMode::StrictAction,
        vec![api_grant(RedirectPolicy::Disabled)],
    );
    let authorized = policy
        .authorize(&request("API.example.com"), START)
        .unwrap();
    assert_eq!(authorized.route(), &route_id("provider-api"));
    assert_eq!(authorized.epoch(), PolicyEpoch::FIRST);
    assert_eq!(
        authorized.reach(),
        &Reach::Resolve {
            resolver: resolver_id(),
            ipv6: false
        }
    );
    assert_eq!(authorized.tls_name(&policy), Some(&name("api.example.com")));
    // Exact by default: a subdomain or a sibling is not covered.
    for other in [
        "uploads.api.example.com",
        "example.com",
        "api.example.com.evil.net",
    ] {
        assert!(
            matches!(
                policy.authorize(&request(other), START),
                Err(AuthorizationRefusal::NotGranted { .. })
            ),
            "{other}"
        );
    }
    assert!(matches!(
        policy.authorize(&request("api.example.com:8443"), START),
        Err(AuthorizationRefusal::PortNotGranted { .. })
    ));
    let tls = DestinationRequest::parse(RouteProtocol::Tls, "api.example.com").unwrap();
    assert!(matches!(
        policy.authorize(&tls, START),
        Err(AuthorizationRefusal::ProtocolNotGranted { .. })
    ));
}

#[test]
fn an_address_needs_an_exact_endpoint_grant() {
    let policy = policy(
        NetworkMode::StrictAction,
        vec![api_grant(RedirectPolicy::Disabled)],
    );
    assert_eq!(
        policy.authorize(&request("93.184.216.34"), START),
        Err(AuthorizationRefusal::AddressNeedsEndpointGrant {
            address: ip("93.184.216.34")
        })
    );
}

#[test]
fn a_wildcard_without_matching_ownership_is_refused() {
    let mut other_zone = ownership("other.example.com", 3600);
    other_zone.zone = name("other.example.com");
    assert_eq!(
        wildcard_grant("previews.example.com", other_zone).unwrap_err(),
        PolicyError::OwnershipZoneMismatch {
            zone: name("previews.example.com")
        }
    );
    // A zone missing from the shared-suffix list still needs ownership: the list is not
    // treated as complete protection.
    let unlisted = "user-sites.attacker-hosting.net";
    assert!(!SHARED_SUFFIXES.contains(&unlisted));
    assert!(wildcard_grant(unlisted, ownership("attacker-hosting.net", 3600)).is_err());
    let mut foreign = ownership("previews.example.com", 3600);
    foreign.owner = TenantId::new("tenant-b").unwrap();
    let grant = wildcard_grant("previews.example.com", foreign).unwrap();
    assert_eq!(
        DestinationPolicy::new(parts(NetworkMode::StrictAction, vec![grant]), START),
        Err(PolicyError::OwnerNotTenant {
            zone: name("previews.example.com")
        })
    );
    let expired =
        wildcard_grant("previews.example.com", ownership("previews.example.com", 0)).unwrap();
    assert_eq!(
        DestinationPolicy::new(parts(NetworkMode::StrictAction, vec![expired]), START),
        Err(PolicyError::OwnershipExpired {
            zone: name("previews.example.com")
        })
    );
}

#[test]
fn a_wildcard_over_a_shared_or_special_use_suffix_is_refused_even_with_ownership() {
    // A top-level zone cannot even be written as a name.
    assert_eq!(CanonicalName::parse("com"), Err(NameError::SingleLabel));
    for shared in ["github.io", "herokuapp.com", "co.uk", "s3.amazonaws.com"] {
        assert_eq!(
            wildcard_grant(shared, ownership(shared, 3600)).unwrap_err(),
            PolicyError::SharedSuffix { zone: name(shared) },
            "{shared}"
        );
    }
    assert!(matches!(
        wildcard_grant("corp.internal", ownership("corp.internal", 3600)).unwrap_err(),
        PolicyError::SpecialUseName { .. }
    ));
}

#[test]
fn a_wildcard_matches_exactly_one_label_below_its_owned_zone_while_ownership_holds() {
    let grant = wildcard_grant(
        "previews.example.com",
        ownership("previews.example.com", 60),
    )
    .unwrap();
    let policy = policy(NetworkMode::StrictAction, vec![grant]);
    assert!(policy
        .authorize(&request("pr-17.previews.example.com"), START)
        .is_ok());
    assert_eq!(
        policy.authorize(&request("a.b.previews.example.com"), START),
        Err(AuthorizationRefusal::WildcardTooDeep {
            name: name("a.b.previews.example.com"),
            zone: name("previews.example.com"),
        })
    );
    assert!(matches!(
        policy.authorize(&request("previews.example.com"), START),
        Err(AuthorizationRefusal::NotGranted { .. })
    ));
    let later = START.saturating_add(Duration::from_secs(60));
    assert_eq!(
        policy.authorize(&request("pr-17.previews.example.com"), later),
        Err(AuthorizationRefusal::OwnershipExpired {
            zone: name("previews.example.com")
        })
    );
}

#[test]
fn special_use_names_cannot_be_resolution_grants() {
    for special in [
        "db.internal",
        "printer.local",
        "app.localhost",
        "metadata.google.internal",
        "nas.home.arpa",
    ] {
        let grant = exact_grant(
            "special",
            special,
            RouteKind::Operation(operation_route(RedirectPolicy::Disabled, false)),
        );
        assert!(
            matches!(
                DestinationPolicy::new(parts(NetworkMode::StrictAction, vec![grant]), START),
                Err(PolicyError::SpecialUseName { .. })
            ),
            "{special}"
        );
    }
}

#[test]
fn a_private_registry_needs_its_own_endpoint_grant_and_dedicated_context() {
    let registry = endpoint_grant("registry", Some("registry.corp.example"), "10.0.5.20", 5000);
    let policy = policy(
        NetworkMode::StrictAction,
        vec![api_grant(RedirectPolicy::Disabled), registry],
    );
    let by_address = policy.authorize(&request("10.0.5.20:5000"), START).unwrap();
    assert_eq!(
        by_address.reach(),
        &Reach::Endpoint {
            address: ip("10.0.5.20")
        }
    );
    assert_eq!(
        by_address.tls_name(&policy),
        Some(&name("registry.corp.example"))
    );
    let by_name = policy
        .authorize(&request("registry.corp.example:5000"), START)
        .unwrap();
    assert_eq!(
        by_name.reach(),
        &Reach::Endpoint {
            address: ip("10.0.5.20")
        }
    );
    // Any other private address stays refused.
    assert_eq!(
        policy.authorize(&request("10.0.5.21:5000"), START),
        Err(AuthorizationRefusal::AddressNeedsEndpointGrant {
            address: ip("10.0.5.21")
        })
    );
    assert!(policy.authorize(&request("10.0.5.20:5001"), START).is_err());
}

#[test]
fn a_universal_private_block_with_a_contradictory_exception_is_refused() {
    let address = ip("10.0.5.20");
    let block_all_private = EnforcementContext {
        perimeter: perimeter_id(),
        rules: vec![
            PerimeterRule {
                action: RuleAction::Block,
                prefix: IpPrefix::new(ip("10.0.0.0"), 8).unwrap(),
                ports: PortSelector::All,
            },
            PerimeterRule {
                action: RuleAction::Allow,
                prefix: IpPrefix::host(address),
                ports: PortSelector::Only(port(5000)),
            },
        ],
    };
    assert!(matches!(
        EndpointGrant::new(None, address, port(5000), block_all_private),
        Err(PolicyError::Perimeter(
            PerimeterError::ContradictoryRules { .. }
        ))
    ));
    let too_broad = EnforcementContext {
        perimeter: perimeter_id(),
        rules: vec![PerimeterRule {
            action: RuleAction::Allow,
            prefix: IpPrefix::new(ip("10.0.5.0"), 24).unwrap(),
            ports: PortSelector::Only(port(5000)),
        }],
    };
    assert_eq!(
        EndpointGrant::new(None, address, port(5000), too_broad),
        Err(PolicyError::Perimeter(
            PerimeterError::ContextNotDedicated {
                endpoint: (address, port(5000))
            }
        ))
    );
    let extra = EnforcementContext {
        perimeter: perimeter_id(),
        rules: vec![
            PerimeterRule {
                action: RuleAction::Allow,
                prefix: IpPrefix::host(address),
                ports: PortSelector::Only(port(5000)),
            },
            PerimeterRule {
                action: RuleAction::Allow,
                prefix: IpPrefix::host(ip("10.0.5.21")),
                ports: PortSelector::Only(port(5432)),
            },
        ],
    };
    assert!(EndpointGrant::new(None, address, port(5000), extra).is_err());
    // A context dedicated to another port does not cover this grant.
    let mut grant = endpoint_grant("registry", None, "10.0.5.20", 5000);
    grant.port = port(5001);
    assert!(matches!(
        DestinationPolicy::new(parts(NetworkMode::StrictAction, vec![grant]), START),
        Err(PolicyError::Perimeter(
            PerimeterError::ContextNotDedicated { .. }
        ))
    ));
}

#[test]
fn endpoint_grants_refuse_loopback_metadata_and_other_special_addresses() {
    for forbidden in [
        "127.0.0.1",
        "169.254.169.254",
        "fd00:ec2::254",
        "169.254.10.10",
        "::ffff:10.0.0.1",
        "224.0.0.251",
    ] {
        let address = ip(forbidden);
        assert!(
            matches!(
                EndpointGrant::new(
                    None,
                    address,
                    port(443),
                    EnforcementContext::dedicated(perimeter_id(), address, port(443))
                ),
                Err(PolicyError::EndpointAddress(_))
            ),
            "{forbidden}"
        );
    }
}

#[test]
fn a_sensitive_offline_task_never_resolves_names() {
    let mut sensitive = parts(
        NetworkMode::StrictAction,
        vec![api_grant(RedirectPolicy::Disabled)],
    );
    sensitive.data_class = TaskDataClass::SensitiveOffline;
    assert_eq!(
        DestinationPolicy::new(sensitive, START),
        Err(PolicyError::ResolutionInSensitiveTask {
            route: route_id("provider-api")
        })
    );
    let approved = ContentKeyFixture::approved();
    let mut sensitive = parts(
        NetworkMode::StrictAction,
        vec![endpoint_grant(
            "registry",
            Some("registry.corp.example"),
            "10.0.5.20",
            5000,
        )],
    );
    sensitive.data_class = TaskDataClass::SensitiveOffline;
    sensitive.approved_objects = BTreeSet::from([approved]);
    let policy = DestinationPolicy::new(sensitive, START).unwrap();
    assert!(policy
        .authorize(&request("registry.corp.example:5000"), START)
        .is_ok());
    assert!(policy.authorize_object(&approved).is_ok());
    let other = ContentKeyFixture::other();
    assert_eq!(
        policy.authorize_object(&other),
        Err(AuthorizationRefusal::ObjectNotApproved { key: other })
    );
}

struct ContentKeyFixture;

impl ContentKeyFixture {
    fn approved() -> crate::foundation::ids::ContentKey {
        crate::foundation::ids::ContentKey::of(b"approved base image")
    }

    fn other() -> crate::foundation::ids::ContentKey {
        crate::foundation::ids::ContentKey::of(b"something else")
    }
}

#[test]
fn modes_bound_which_routes_a_policy_may_hold() {
    let transport = exact_grant(
        "raw-tls",
        "git.example.com",
        RouteKind::Transport(refusing_transport()),
    );
    assert!(matches!(
        DestinationPolicy::new(
            parts(NetworkMode::StrictAction, vec![transport.clone()]),
            START
        ),
        Err(PolicyError::Mode { .. })
    ));
    assert!(DestinationPolicy::new(
        parts(NetworkMode::DeclaredTransport, vec![transport.clone()]),
        START
    )
    .is_ok());
    assert!(matches!(
        DestinationPolicy::new(
            parts(
                NetworkMode::Offline,
                vec![api_grant(RedirectPolicy::Disabled)]
            ),
            START
        ),
        Err(PolicyError::Mode { .. })
    ));
    let offline = policy(NetworkMode::Offline, vec![]);
    assert_eq!(
        offline.authorize(&request("api.example.com"), START),
        Err(AuthorizationRefusal::Offline)
    );
    let mut tls_operation = api_grant(RedirectPolicy::Disabled);
    tls_operation.protocol = RouteProtocol::Tls;
    assert!(matches!(
        DestinationPolicy::new(parts(NetworkMode::StrictAction, vec![tls_operation]), START),
        Err(PolicyError::OperationRouteNeedsHttps { .. })
    ));
}

#[test]
fn overlapping_or_duplicate_grants_are_refused() {
    let exact = exact_grant(
        "one",
        "pr-1.previews.example.com",
        RouteKind::Operation(operation_route(RedirectPolicy::Disabled, false)),
    );
    let wildcard = wildcard_grant(
        "previews.example.com",
        ownership("previews.example.com", 3600),
    )
    .unwrap();
    assert!(matches!(
        DestinationPolicy::new(
            parts(NetworkMode::StrictAction, vec![exact, wildcard]),
            START
        ),
        Err(PolicyError::OverlappingGrants { .. })
    ));
    let first = api_grant(RedirectPolicy::Disabled);
    let mut second = api_grant(RedirectPolicy::Disabled);
    second.id = route_id("provider-api-2");
    assert!(matches!(
        DestinationPolicy::new(
            parts(NetworkMode::StrictAction, vec![first.clone(), second]),
            START
        ),
        Err(PolicyError::OverlappingGrants { .. })
    ));
    let mut renamed = exact_grant(
        "provider-api",
        "other.example.com",
        RouteKind::Operation(operation_route(RedirectPolicy::Disabled, false)),
    );
    renamed.budgets.effects = 0;
    assert_eq!(
        DestinationPolicy::new(
            parts(NetworkMode::StrictAction, vec![first, renamed]),
            START
        ),
        Err(PolicyError::DuplicateRouteId {
            route: route_id("provider-api")
        })
    );
}

#[test]
fn name_grants_must_use_an_allowed_resolver_and_endpoints_none() {
    let mut missing = api_grant(RedirectPolicy::Disabled);
    missing.resolver = None;
    assert_eq!(
        DestinationPolicy::new(parts(NetworkMode::StrictAction, vec![missing]), START),
        Err(PolicyError::MissingResolver {
            route: route_id("provider-api")
        })
    );
    let mut foreign = api_grant(RedirectPolicy::Disabled);
    foreign.resolver = Some(ResolverId::new("guest-resolver").unwrap());
    assert!(matches!(
        DestinationPolicy::new(parts(NetworkMode::StrictAction, vec![foreign]), START),
        Err(PolicyError::ResolverNotAllowed { .. })
    ));
    let mut endpoint = endpoint_grant("registry", None, "10.0.5.20", 5000);
    endpoint.resolver = Some(resolver_id());
    assert_eq!(
        DestinationPolicy::new(parts(NetworkMode::StrictAction, vec![endpoint]), START),
        Err(PolicyError::EndpointWithResolver {
            route: route_id("registry")
        })
    );
    let mut family = endpoint_grant("registry", None, "10.0.5.20", 5000);
    family.ipv6 = true;
    assert_eq!(
        DestinationPolicy::new(parts(NetworkMode::StrictAction, vec![family]), START),
        Err(PolicyError::EndpointFamilyMismatch {
            route: route_id("registry")
        })
    );
}
