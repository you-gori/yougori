//! The profile document: strict reading, normalization, identity, grants, private
//! exceptions, perimeter prefixes, resolvers, publications, links, release budgets,
//! guest compatibility, mode and claims (VM-W59; VM §4.1, §4.2, §4.7).

use super::*;
use crate::sandbox_contract::destinations::{
    AddressClass, IngressError, ModeClaim, NetworkMode, PolicyError, PrincipalId, ReleaseError,
    RouteError, ServiceIdentity,
};

fn refused(document: NetworkProfileDocument) -> ProfileError {
    NetworkProfile::new(document).unwrap_err()
}

fn json(document: &NetworkProfileDocument) -> serde_json::Value {
    serde_json::to_value(document).unwrap()
}

fn read(value: serde_json::Value) -> Result<NetworkProfile, ProfileReadError> {
    NetworkProfile::from_json(&value.to_string())
}

#[test]
fn a_profile_round_trips_through_json_with_the_same_digest() {
    let profile = sample_profile();
    let text = profile.to_json().unwrap();
    let again = NetworkProfile::from_json(&text).unwrap();
    assert_eq!(again, profile);
    assert_eq!(again.digest(), profile.digest());
    let through_serde: NetworkProfile =
        serde_json::from_str(&serde_json::to_string(&profile).unwrap()).unwrap();
    assert_eq!(through_serde.digest(), profile.digest());
}

#[test]
fn list_order_does_not_change_the_digest_but_every_field_does() {
    let original = sample_profile();
    let mut permuted = sample_document();
    permuted.egress.reverse();
    if let Some(pypi) = permuted
        .egress
        .iter_mut()
        .find(|grant| grant.id == route("pypi"))
    {
        pypi.perimeter_prefixes.reverse();
    }
    assert_eq!(
        NetworkProfile::new(permuted).unwrap().digest(),
        original.digest()
    );

    let mut edits: Vec<Edit> = vec![
        Box::new(|document| document.kind = BroaderNetworkKind::UserOwnedGeneralVm),
        Box::new(|document| document.max_answer_ttl_seconds = NonZeroU64::new(301).unwrap()),
        Box::new(|document| document.quotas = quotas(63, 64, 1)),
        Box::new(|document| document.egress[0].budgets.connections = 21),
        Box::new(|document| document.egress[0].port = port(8443)),
        Box::new(|document| document.guest.proxy.socks5 = false),
        Box::new(|document| document.egress.retain(|grant| grant.id != route("mirror"))),
    ];
    for (index, edit) in edits.drain(..).enumerate() {
        let mut changed = sample_document();
        edit(&mut changed);
        let changed = NetworkProfile::new(changed).unwrap();
        assert_ne!(changed.digest(), original.digest(), "edit {index}");
    }
}

#[test]
fn reading_refuses_other_versions_unknown_fields_and_unknown_kinds() {
    let mut value = json(&sample_document());
    value["version"] = serde_json::json!(2);
    assert!(
        matches!(read(value), Err(ProfileReadError::Syntax(reason)) if reason.contains("version 2"))
    );

    let mut value = json(&sample_document());
    value["grant_everything"] = serde_json::json!(true);
    assert!(matches!(read(value), Err(ProfileReadError::Syntax(_))));

    for kind in ["strict_action", "offline", "wildcard"] {
        let mut value = json(&sample_document());
        value["kind"] = serde_json::json!(kind);
        assert!(
            matches!(read(value), Err(ProfileReadError::Syntax(_))),
            "{kind}"
        );
    }

    let mut value = json(&sample_document());
    value["egress"][0]["target"] = serde_json::json!({"kind": "wildcard", "zone": "example.com"});
    assert!(matches!(read(value), Err(ProfileReadError::Syntax(_))));

    let mut value = json(&sample_document());
    value["egress"][0]["target"]["owner"] = serde_json::json!("someone");
    assert!(matches!(read(value), Err(ProfileReadError::Syntax(_))));
}

#[test]
fn a_unit_variant_with_an_extra_field_is_refused() {
    let mut document = sample_document();
    document.ingress.push(PublicationEntry {
        service: ServiceIdentity::new("web").unwrap(),
        port: port(8080),
        audience: PublicationAudience::Public,
        authentication: PublicationAuthentication::None,
        lifetime_seconds: NonZeroU64::new(600).unwrap(),
    });
    let mut value = json(&document);
    assert!(read(value.clone()).is_ok());
    value["ingress"][0]["audience"] = serde_json::json!({"kind": "public", "principals": ["eve"]});
    assert!(matches!(read(value), Err(ProfileReadError::Syntax(_))));
}

#[test]
fn guest_addresses_must_be_private_and_the_scope_a_vm_sandbox() {
    for address in [
        "151.101.0.1",
        "127.0.0.1",
        "169.254.1.2",
        "100.64.0.9",
        "0.0.0.0",
        "224.0.0.1",
    ] {
        let mut document = sample_document();
        document.identity.ipv4 = address.parse().unwrap();
        assert!(
            matches!(refused(document), ProfileError::GuestAddress { .. }),
            "{address}"
        );
    }
    for address in ["fd00:ec2::254", "fe80::2", "::1", "2a04:4e42::9"] {
        let mut document = sample_document();
        document.identity.ipv6 = Some(address.parse().unwrap());
        assert!(
            matches!(refused(document), ProfileError::GuestAddress { .. }),
            "{address}"
        );
    }
    let mut document = sample_document();
    document.identity.scope = TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "wsl");
    assert_eq!(refused(document), ProfileError::IdentityNotVmSandbox);
}

#[test]
fn every_endpoint_records_a_reason_without_control_or_format_characters() {
    let mut value = json(&sample_document());
    let index = sample_document()
        .egress
        .iter()
        .position(|grant| grant.id == route("registry"))
        .unwrap();
    value["egress"][index]["target"]
        .as_object_mut()
        .unwrap()
        .remove("reason");
    assert!(
        matches!(read(value), Err(ProfileReadError::Syntax(reason)) if reason.contains("reason"))
    );

    assert_eq!(RecordedText::new("   "), Err(TextError::Empty));
    assert_eq!(
        RecordedText::new("ok\u{1b}[2J"),
        Err(TextError::ControlCharacter {
            character: '\u{1b}'
        })
    );
    assert_eq!(
        RecordedText::new("approve\u{202e}lanigiro"),
        Err(TextError::FormatCharacter {
            character: '\u{202e}'
        })
    );
    // The shared classification also refuses private-use and other invisible characters.
    for hidden in ['\u{E000}', '\u{2061}', '\u{FE0F}'] {
        assert_eq!(
            RecordedText::new(format!("reason{hidden}text")),
            Err(TextError::FormatCharacter { character: hidden })
        );
    }
    assert!(RecordedText::new("a plain reason, with spaces").is_ok());
    assert!(matches!(
        RecordedText::new("x".repeat(RecordedText::MAX_BYTES + 1)),
        Err(TextError::TooLong { .. })
    ));
    assert!(RecordedText::new("x".repeat(RecordedText::MAX_BYTES)).is_ok());
    let mut value = json(&sample_document());
    value["egress"][index]["target"]["reason"] = serde_json::json!("line\nbreak");
    assert!(matches!(read(value), Err(ProfileReadError::Syntax(_))));
}

#[test]
fn private_exceptions_are_endpoints_and_v02_refuses_unpermitted_endpoint_classes() {
    let profile = sample_profile();
    let registry = profile.grant(&route("registry")).unwrap();
    assert!(matches!(registry.target, EgressTarget::Endpoint { .. }));

    for address in [
        "127.0.0.1",
        "169.254.169.254",
        "169.254.1.1",
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "192.0.2.1",
        "fe80::1",
        "::1",
        "ff02::1",
    ] {
        let mut document = sample_document();
        document
            .egress
            .push(endpoint_grant("bad", address, 443, None, "test"));
        match refused(document) {
            ProfileError::Policy(PolicyError::EndpointAddress(refused)) => {
                assert_ne!(refused.verdict.class, AddressClass::Public, "{address}");
            }
            other => panic!("{address}: {other:?}"),
        }
    }
    let mut document = sample_document();
    document.egress.push(endpoint_grant(
        "mapped",
        "::ffff:10.0.0.1",
        443,
        None,
        "test",
    ));
    assert!(matches!(
        refused(document),
        ProfileError::Policy(PolicyError::EndpointAddress(refused))
            if matches!(refused.verdict.class, AddressClass::EmbeddedIpv4(_))
    ));

    let mut document = sample_document();
    document
        .egress
        .push(endpoint_grant("self", "10.200.0.2", 22, None, "test"));
    assert_eq!(
        refused(document),
        ProfileError::EndpointIsOwnAddress {
            route: route("self")
        }
    );
}

#[test]
fn one_name_one_grant_and_one_id_one_grant() {
    let mut document = sample_document();
    let mut second = name_grant("pypi-alt", "pypi.org", &[], false);
    second.port = port(8443);
    document.egress.push(second);
    assert_eq!(
        refused(document),
        ProfileError::NameInSeveralGrants {
            name: name("pypi.org")
        }
    );

    let mut document = sample_document();
    document.egress.push(endpoint_grant(
        "registry-ssh",
        "10.50.0.21",
        22,
        Some("registry.corp.internal"),
        "ssh",
    ));
    assert!(matches!(
        refused(document),
        ProfileError::NameInSeveralGrants { .. }
    ));

    let mut document = sample_document();
    document
        .egress
        .push(name_grant("pypi", "files.pythonhosted.org", &[], false));
    assert_eq!(
        refused(document),
        ProfileError::DuplicateRoute {
            route: route("pypi")
        }
    );
}

#[test]
fn perimeter_prefixes_are_narrow_public_and_of_a_granted_family() {
    let cases: Vec<(&[&str], bool, &str)> = vec![
        (&["151.101.0.0/16"], false, "too broad"),
        (
            &["168.63.129.0/24"],
            false,
            "holds the Azure metadata address",
        ),
        (&["10.1.2.0/24"], false, "private"),
        (&["192.0.2.0/24"], false, "documentation"),
        (&["2a04:4e42::/48"], false, "IPv6 without an IPv6 grant"),
        (&["2a04::/32"], true, "IPv6 too broad"),
        (&["2001:db8::/48"], true, "IPv6 documentation"),
        (&["151.101.0.0/24"], true, "IPv6 granted but no IPv6 prefix"),
        (&["151.101.0.0/24", "151.101.0.0/24"], false, "duplicate"),
    ];
    for (prefixes, ipv6, label) in cases {
        let mut document = sample_document();
        document.egress.retain(|grant| grant.id != route("pypi"));
        document
            .egress
            .push(name_grant("pypi", "pypi.org", prefixes, ipv6));
        let error = refused(document);
        assert!(
            matches!(
                error,
                ProfileError::PerimeterPrefixTooBroad { .. }
                    | ProfileError::PerimeterPrefixNotPublic { .. }
                    | ProfileError::PerimeterPrefixFamily { .. }
                    | ProfileError::MissingIpv6PerimeterPrefix { .. }
                    | ProfileError::DuplicatePerimeterPrefix { .. }
            ),
            "{label}: {error:?}"
        );
    }
    let mut document = sample_document();
    document.egress.retain(|grant| grant.id != route("pypi"));
    document
        .egress
        .push(name_grant("pypi", "pypi.org", &["168.63.129.0/24"], false));
    assert!(matches!(
        refused(document),
        ProfileError::PerimeterPrefixNotPublic {
            class: AddressClass::Metadata,
            ..
        }
    ));

    let mut document = sample_document();
    if let Some(registry) = document
        .egress
        .iter_mut()
        .find(|grant| grant.id == route("registry"))
    {
        registry.perimeter_prefixes = vec![prefix("10.50.0.0/24")];
    }
    assert_eq!(
        refused(document),
        ProfileError::EndpointWithPerimeterPrefixes {
            route: route("registry")
        }
    );
}

#[test]
fn resolvers_are_used_public_and_the_only_ones_grants_may_name() {
    let mut document = sample_document();
    document.resolvers.push(resolver("spare-dns", &["1.1.1.1"]));
    assert!(matches!(
        refused(document),
        ProfileError::UnusedResolver { .. }
    ));

    for upstream in ["10.0.0.53", "127.0.0.53", "169.254.169.253"] {
        let mut document = sample_document();
        document.resolvers = vec![resolver("host-dns", &[upstream])];
        assert!(
            matches!(refused(document), ProfileError::UpstreamNotPublic { .. }),
            "{upstream}"
        );
    }
    let mut document = sample_document();
    document.resolvers = vec![resolver("host-dns", &[])];
    assert!(matches!(
        refused(document),
        ProfileError::ResolverWithoutUpstream { .. }
    ));

    let mut document = sample_document();
    document.resolvers = vec![resolver("host-dns", &[UPSTREAM, UPSTREAM])];
    assert!(matches!(
        refused(document),
        ProfileError::DuplicateUpstream { .. }
    ));

    let mut document = sample_document();
    document.resolvers.push(resolver("host-dns", &["1.1.1.1"]));
    assert!(matches!(
        refused(document),
        ProfileError::DuplicateResolver { .. }
    ));

    let mut document = sample_document();
    document.egress[0].resolver = Some(ResolverId::new("rogue-dns").unwrap());
    assert!(matches!(
        refused(document),
        ProfileError::Policy(PolicyError::ResolverNotAllowed { .. })
    ));
}

#[test]
fn v02_grant_rules_still_apply_inside_a_profile() {
    let mut document = sample_document();
    document
        .egress
        .push(name_grant("local", "printer.local", &[], false));
    assert!(matches!(
        refused(document),
        ProfileError::Policy(PolicyError::SpecialUseName { .. })
    ));

    let mut document = sample_document();
    document.data_class = DataClass::SensitiveOffline;
    assert!(matches!(
        refused(document),
        ProfileError::Policy(PolicyError::ResolutionInSensitiveTask { .. })
    ));
    let mut sensitive = sample_document();
    sensitive.data_class = DataClass::SensitiveOffline;
    sensitive.egress.retain(|grant| grant.resolver.is_none());
    sensitive.resolvers.clear();
    assert!(NetworkProfile::new(sensitive).is_ok());

    let mut document = sample_document();
    document.egress[0]
        .hazards
        .remove(&PassThroughHazard::MissingSni);
    assert!(matches!(
        refused(document),
        ProfileError::Route {
            error: RouteError::UndeclaredHazard { .. },
            ..
        }
    ));
    let mut document = sample_document();
    document.egress[0].hazards.insert(
        PassThroughHazard::InTunnelProtocolChange,
        HazardHandling::Refuse,
    );
    assert!(matches!(
        refused(document),
        ProfileError::Route {
            error: RouteError::CannotEnforceThroughPassThrough { .. },
            ..
        }
    ));

    let mut document = sample_document();
    if let Some(mirror) = document
        .egress
        .iter_mut()
        .find(|grant| grant.id == route("mirror"))
    {
        mirror.resolver = Some(ResolverId::new("host-dns").unwrap());
    }
    assert!(matches!(
        refused(document),
        ProfileError::Policy(PolicyError::EndpointWithResolver { .. })
    ));
}

#[test]
fn an_ipv6_grant_needs_an_ipv6_identity() {
    let mut document = base_document(identity("sbx-a", "10.200.0.2", None));
    document
        .egress
        .push(name_grant("v6", "v6.example.com", &[], true));
    assert_eq!(
        refused(document),
        ProfileError::Ipv6WithoutIdentity { route: route("v6") }
    );
}

#[test]
fn publications_and_links_are_checked_by_v02_and_never_duplicated() {
    let entry = |audience: PublicationAudience, authentication| PublicationEntry {
        service: ServiceIdentity::new("web").unwrap(),
        port: port(8080),
        audience,
        authentication,
        lifetime_seconds: NonZeroU64::new(600).unwrap(),
    };
    let mut document = sample_document();
    document.ingress.push(entry(
        PublicationAudience::Private {
            principals: BTreeSet::new(),
        },
        PublicationAuthentication::BearerToken,
    ));
    assert_eq!(
        refused(document),
        ProfileError::Ingress(IngressError::PrivateNeedsPrincipals)
    );

    let mut document = sample_document();
    document.ingress.push(entry(
        PublicationAudience::Private {
            principals: BTreeSet::from([PrincipalId::new("alice").unwrap()]),
        },
        PublicationAuthentication::None,
    ));
    assert_eq!(
        refused(document),
        ProfileError::Ingress(IngressError::PrivateNeedsAuthentication)
    );

    let mut document = sample_document();
    document.ingress.push(entry(
        PublicationAudience::Public,
        PublicationAuthentication::None,
    ));
    document.ingress.push(entry(
        PublicationAudience::Public,
        PublicationAuthentication::BearerToken,
    ));
    assert!(matches!(
        refused(document),
        ProfileError::DuplicatePublication { .. }
    ));

    let link = |execution: &str| LinkEntry {
        direction: LinkDirection::Outbound,
        peer: LinkPeer {
            execution: exec(execution),
            scope: scope(execution),
        },
        service: ServiceIdentity::new("model").unwrap(),
        port: port(9000),
        lifetime_seconds: NonZeroU64::new(600).unwrap(),
    };
    let mut document = sample_document();
    document.links.push(link("sbx-a"));
    assert_eq!(refused(document), ProfileError::LinkToSelf);
    let mut document = sample_document();
    document.links.push(link("sbx-b"));
    document.links.push(link("sbx-b"));
    assert!(matches!(
        refused(document),
        ProfileError::DuplicateLink { .. }
    ));
    let mut document = sample_document();
    document.links.push(link("sbx-b"));
    assert!(NetworkProfile::new(document).is_ok());
}

#[test]
fn release_budgets_are_checked_by_v02() {
    let mut document = sample_document();
    document.release.channels.insert(
        ReleaseChannel::UserApprovedTransfer,
        ChannelPolicy {
            budget_bytes: 1,
            trust_class: ReleaseTrustClass::LocalUser,
        },
    );
    assert!(matches!(
        refused(document),
        ProfileError::Release(ReleaseError::OwnBudgetChannel { .. })
    ));
    let mut document = sample_document();
    document.release.in_flight_allowance.documented_reason = " ".to_owned();
    assert_eq!(
        refused(document),
        ProfileError::Release(ReleaseError::UndocumentedAllowance)
    );
}

#[test]
fn proxy_first_and_layers_only_with_a_justification_naming_applications() {
    let mut document = sample_document();
    document.guest.proxy = ProxyOffer {
        http_connect: false,
        socks5: false,
    };
    assert_eq!(refused(document), ProfileError::ProxyNotOffered);

    let justification = |applications: &[&str]| Justification {
        reason: text("the legacy updater ignores proxy variables"),
        applications: applications
            .iter()
            .map(|application| ApplicationName::new(*application).unwrap())
            .collect(),
        implementation: ImplementationName::new("gvisor-netstack").unwrap(),
    };
    let mut document = sample_document();
    document.guest.tun = Some(justification(&[]));
    assert_eq!(
        refused(document),
        ProfileError::JustificationWithoutApplications
    );
    let mut document = sample_document();
    document.guest.synthetic_names = Some(justification(&[]));
    assert_eq!(
        refused(document),
        ProfileError::JustificationWithoutApplications
    );

    let mut value = json(&sample_document());
    value["guest"]["tun"] = serde_json::json!({"applications": ["legacy-updater"], "implementation": "gvisor-netstack"});
    assert!(matches!(read(value), Err(ProfileReadError::Syntax(_))));

    let mut document = sample_document();
    document.guest.tun = Some(justification(&["legacy-updater"]));
    document.guest.synthetic_names = Some(justification(&["legacy-updater"]));
    assert!(NetworkProfile::new(document).is_ok());
}

#[test]
fn the_mode_names_this_profile_and_nothing_else() {
    let declared = sample_profile();
    assert_eq!(declared.network_mode(), NetworkMode::DeclaredTransport);
    assert!(declared.check_mode(NetworkMode::DeclaredTransport).is_ok());
    for other in [NetworkMode::StrictAction, NetworkMode::Offline] {
        assert!(declared.check_mode(other).is_err());
    }

    let mut document = sample_document();
    document.kind = BroaderNetworkKind::UserOwnedGeneralVm;
    let owned = NetworkProfile::new(document).unwrap();
    assert_eq!(
        owned.network_mode(),
        NetworkMode::UserOwnedGeneralVm {
            perimeter_profile: owned.digest()
        }
    );
    let other = NetworkMode::UserOwnedGeneralVm {
        perimeter_profile: declared.digest(),
    };
    assert_eq!(
        owned.check_mode(other),
        Err(ProfileModeError {
            expected: owned.network_mode(),
            found: other
        })
    );
}

#[test]
fn a_broader_profile_never_holds_the_strict_modes_claims() {
    let declared = sample_profile();
    let mut document = sample_document();
    document.kind = BroaderNetworkKind::UserOwnedGeneralVm;
    let owned = NetworkProfile::new(document).unwrap();
    for claim in strict_claims() {
        assert!(declared.claim(claim).is_err(), "{claim:?}");
        assert!(owned.claim(claim).is_err(), "{claim:?}");
    }
    assert!(declared.claim(ModeClaim::ExplicitConnectionsOnly).is_ok());
    assert!(owned.claim(ModeClaim::ExplicitConnectionsOnly).is_err());
}

#[test]
fn documents_are_bounded() {
    let mut document = sample_document();
    document.egress = (0..=MAX_EGRESS_GRANTS)
        .map(|index| {
            name_grant(
                &format!("r{index}"),
                &format!("h{index}.example.com"),
                &[],
                false,
            )
        })
        .collect();
    assert_eq!(
        refused(document),
        ProfileError::TooMany {
            field: "egress",
            count: MAX_EGRESS_GRANTS + 1,
            max: MAX_EGRESS_GRANTS
        }
    );
    let mut document = sample_document();
    document.egress[0].perimeter_prefixes = (0..=MAX_PERIMETER_PREFIXES)
        .map(|index| prefix(&format!("151.101.{index}.0/24")))
        .collect();
    assert!(matches!(
        refused(document),
        ProfileError::TooMany {
            field: "perimeter_prefixes",
            ..
        }
    ));
}

#[test]
fn v02_route_grants_and_policy_carry_the_profile_exactly() {
    let profile = sample_profile();
    let grants = profile.route_grants(perimeter_id()).unwrap();
    assert_eq!(grants.len(), 4);
    let policy = profile
        .destination_policy(
            perimeter_id(),
            crate::foundation::ids::PolicyEpoch::FIRST,
            START,
        )
        .unwrap();
    assert_eq!(policy.mode(), NetworkMode::DeclaredTransport);
    assert!(policy.resolver_allowed(&ResolverId::new("host-dns").unwrap()));
    assert!(!policy.resolver_allowed(&ResolverId::new("rogue-dns").unwrap()));
    assert_eq!(policy.max_answer_ttl(), Duration::from_secs(300));
    assert!(policy.grants().all(|grant| matches!(
        grant.route,
        crate::sandbox_contract::destinations::RouteKind::Transport(_)
    )));
}
