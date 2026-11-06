//! VM §4.3 and VM-W03: typed routes, TLS modes, and transport routes that never claim
//! L7 enforcement.

use super::*;

const APPLICATION_LAYER: [EnforcementProperty; 8] = [
    EnforcementProperty::TlsVerifiedForAuthorizedName,
    EnforcementProperty::HttpAuthorityBound,
    EnforcementProperty::HttpMethodBound,
    EnforcementProperty::HttpPathBound,
    EnforcementProperty::HttpQueryBound,
    EnforcementProperty::HeaderPolicyEnforced,
    EnforcementProperty::RedirectsControlled,
    EnforcementProperty::CredentialInjectedByExecutor,
];

fn broader(label: &str) -> HazardHandling {
    HazardHandling::BroaderTransportGrant(DecisionRef::new(test_digest(label)))
}

fn hello(sni: Option<&str>) -> ClientHelloFacts {
    ClientHelloFacts {
        transport: HelloTransport::Tcp,
        sni: sni.map(str::to_owned),
        ech_offered: false,
        alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
    }
}

#[test]
fn a_transport_route_cannot_claim_any_application_layer_enforcement() {
    let route = RouteKind::Transport(refusing_transport());
    for property in APPLICATION_LAYER {
        assert_eq!(
            route.claim(property),
            Err(ClaimRefusal::TransportCannotInspect { property }),
            "{property:?}"
        );
    }
    let properties = route.properties();
    assert!(properties
        .iter()
        .all(|property| !property.is_application_layer()));
    assert!(route
        .claim(EnforcementProperty::DestinationAddressValidated)
        .is_ok());
    assert!(route
        .claim(EnforcementProperty::TlsServerNameMatched)
        .is_ok());
}

#[test]
fn an_operation_route_binds_http_semantics_and_a_credentialed_one_injects_credentials() {
    let plain = RouteKind::Operation(operation_route(RedirectPolicy::Disabled, false));
    for property in APPLICATION_LAYER
        .iter()
        .filter(|property| **property != EnforcementProperty::CredentialInjectedByExecutor)
    {
        assert!(plain.claim(*property).is_ok(), "{property:?}");
    }
    assert_eq!(
        plain.claim(EnforcementProperty::CredentialInjectedByExecutor),
        Err(ClaimRefusal::NotProvided {
            property: EnforcementProperty::CredentialInjectedByExecutor
        })
    );
    let credentialed = RouteKind::Operation(operation_route(RedirectPolicy::Disabled, true));
    assert!(credentialed
        .claim(EnforcementProperty::CredentialInjectedByExecutor)
        .is_ok());
}

#[test]
fn every_pass_through_hazard_must_be_declared_and_in_tunnel_changes_cannot_be_refused() {
    let mut handling = BTreeMap::from([
        (
            PassThroughHazard::EncryptedClientHello,
            HazardHandling::Refuse,
        ),
        (PassThroughHazard::MissingSni, HazardHandling::Refuse),
        (PassThroughHazard::InTunnelProtocolChange, broader("tunnel")),
    ]);
    assert_eq!(
        TransportRoute::new(handling.clone()),
        Err(RouteError::UndeclaredHazard {
            hazard: PassThroughHazard::Http3
        })
    );
    handling.insert(PassThroughHazard::Http3, HazardHandling::Refuse);
    assert!(TransportRoute::new(handling.clone()).is_ok());
    handling.insert(
        PassThroughHazard::InTunnelProtocolChange,
        HazardHandling::Refuse,
    );
    assert_eq!(
        TransportRoute::new(handling),
        Err(RouteError::CannotEnforceThroughPassThrough {
            hazard: PassThroughHazard::InTunnelProtocolChange
        })
    );
}

#[test]
fn a_matching_sni_grants_only_transport_properties() {
    let route = refusing_transport();
    let authorized = name("git.example.com");
    let admission = route
        .admit_hello(Some(&authorized), &hello(Some("GIT.example.com")))
        .unwrap();
    assert_eq!(
        admission.properties,
        BTreeSet::from([
            EnforcementProperty::DestinationAddressValidated,
            EnforcementProperty::TlsServerNameMatched
        ])
    );
    assert!(!admission
        .properties
        .contains(&EnforcementProperty::HttpAuthorityBound));
    assert_eq!(admission.broader_grants.len(), 1);
    assert_eq!(
        admission.broader_grants[0].0,
        PassThroughHazard::InTunnelProtocolChange
    );
}

#[test]
fn an_sni_mismatch_or_malformed_sni_is_refused() {
    let route = refusing_transport();
    let authorized = name("git.example.com");
    assert_eq!(
        route.admit_hello(Some(&authorized), &hello(Some("evil.example.net"))),
        Err(TlsRefusal::SniMismatch {
            expected: Some(authorized.clone()),
            presented: name("evil.example.net")
        })
    );
    assert_eq!(
        route.admit_hello(Some(&authorized), &hello(Some("git.example.com."))),
        Err(TlsRefusal::MalformedSni(NameError::TrailingDot))
    );
    assert!(matches!(
        route.admit_hello(None, &hello(Some("git.example.com"))),
        Err(TlsRefusal::SniMismatch { expected: None, .. })
    ));
}

#[test]
fn missing_sni_ech_and_http3_are_refused_unless_a_broader_grant_was_decided() {
    let refusing = refusing_transport();
    let authorized = name("git.example.com");
    assert_eq!(
        refusing.admit_hello(Some(&authorized), &hello(None)),
        Err(TlsRefusal::HazardRefused {
            hazard: PassThroughHazard::MissingSni
        })
    );
    let mut ech = hello(Some("git.example.com"));
    ech.ech_offered = true;
    assert_eq!(
        refusing.admit_hello(Some(&authorized), &ech),
        Err(TlsRefusal::HazardRefused {
            hazard: PassThroughHazard::EncryptedClientHello
        })
    );
    let mut quic = hello(Some("git.example.com"));
    quic.transport = HelloTransport::Quic;
    assert_eq!(
        refusing.admit_hello(Some(&authorized), &quic),
        Err(TlsRefusal::HazardRefused {
            hazard: PassThroughHazard::Http3
        })
    );

    let permissive = transport_route(broader("no-sni"), broader("ech"), broader("quic"));
    // Accepting the hazard removes the name guarantee it defeats.
    let without_sni = permissive
        .admit_hello(Some(&authorized), &hello(None))
        .unwrap();
    assert_eq!(
        without_sni.properties,
        BTreeSet::from([EnforcementProperty::DestinationAddressValidated])
    );
    assert!(without_sni
        .broader_grants
        .iter()
        .any(|(hazard, _)| *hazard == PassThroughHazard::MissingSni));
    let with_ech = permissive.admit_hello(Some(&authorized), &ech).unwrap();
    assert!(!with_ech
        .properties
        .contains(&EnforcementProperty::TlsServerNameMatched));
    let over_quic = permissive.admit_hello(Some(&authorized), &quic).unwrap();
    assert!(over_quic
        .broader_grants
        .iter()
        .any(|(hazard, _)| *hazard == PassThroughHazard::Http3));
    // The route as a whole no longer promises a matched server name.
    assert!(!RouteKind::Transport(permissive)
        .properties()
        .contains(&EnforcementProperty::TlsServerNameMatched));
}

#[test]
fn a_certificate_pinning_client_cannot_have_its_tls_terminated() {
    let operations = vec![spec(
        "list",
        HttpMethod::Get,
        "/v1/models",
        &[],
        EffectClass::ReadOnly,
    )];
    assert_eq!(
        OperationRoute::new(
            OperationTls::TerminatedAtExecutor,
            None,
            operations.clone(),
            RedirectPolicy::Disabled,
            true
        ),
        Err(RouteError::PinnedClientNeedsIntegration)
    );
    assert!(OperationRoute::new(
        OperationTls::ConstructedByExecutor,
        None,
        operations,
        RedirectPolicy::Disabled,
        true
    )
    .is_ok());
}

#[test]
fn operation_routes_refuse_empty_duplicate_and_ambiguous_operations() {
    assert_eq!(
        OperationRoute::new(
            OperationTls::TerminatedAtExecutor,
            None,
            vec![],
            RedirectPolicy::Disabled,
            false
        ),
        Err(RouteError::NoOperations)
    );
    let a = spec(
        "get",
        HttpMethod::Get,
        "/v1/models/{id}",
        &[],
        EffectClass::ReadOnly,
    );
    let duplicate = spec(
        "get",
        HttpMethod::Post,
        "/v1/jobs",
        &[],
        EffectClass::External,
    );
    assert!(matches!(
        OperationRoute::new(
            OperationTls::TerminatedAtExecutor,
            None,
            vec![a.clone(), duplicate],
            RedirectPolicy::Disabled,
            false
        ),
        Err(RouteError::DuplicateOperation { .. })
    ));
    let overlapping = spec(
        "get-latest",
        HttpMethod::Get,
        "/v1/models/latest",
        &[],
        EffectClass::ReadOnly,
    );
    assert!(matches!(
        OperationRoute::new(
            OperationTls::TerminatedAtExecutor,
            None,
            vec![a.clone(), overlapping],
            RedirectPolicy::Disabled,
            false
        ),
        Err(RouteError::AmbiguousOperations { .. })
    ));
    let other_method = spec(
        "delete",
        HttpMethod::Delete,
        "/v1/models/{id}",
        &[],
        EffectClass::External,
    );
    assert!(OperationRoute::new(
        OperationTls::TerminatedAtExecutor,
        None,
        vec![a, other_method],
        RedirectPolicy::Disabled,
        false
    )
    .is_ok());
}

#[test]
fn path_templates_refuse_ambiguous_segments() {
    for bad in [
        "v1/models",
        "/v1//models",
        "/v1/../models",
        "/v1/./models",
        "/v1/mo%64els",
        "/v1/{}",
        "/v1/a;b",
    ] {
        assert!(PathTemplate::parse(bad).is_err(), "{bad}");
    }
    assert_eq!(PathTemplate::parse("/").unwrap().segments(), &[]);
    let template = PathTemplate::parse("/v1/models/{id}").unwrap();
    assert!(template.matches(&["v1".to_owned(), "models".to_owned(), "m-1".to_owned()]));
    assert!(!template.matches(&["v1".to_owned(), "models".to_owned()]));
    assert_eq!(HttpMethod::parse("get"), None);
    assert_eq!(HttpMethod::parse("CONNECT"), None);
    assert_eq!(HttpMethod::parse("PATCH"), Some(HttpMethod::Patch));
}
