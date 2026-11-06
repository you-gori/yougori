//! VM §4.7, VM-W13 and VM-P36: publications and connected sandboxes.

use super::fakes::FakeResolver;
use super::*;

fn service(text: &str) -> ServiceIdentity {
    ServiceIdentity::new(text).unwrap()
}

fn principal(text: &str) -> PrincipalId {
    PrincipalId::new(text).unwrap()
}

fn sandbox() -> crate::foundation::ids::ExecutionId {
    crate::foundation::ids::ExecutionId::new("exe-preview").unwrap()
}

fn table() -> IngressTable {
    IngressTable::new(
        sandbox(),
        NetworkMode::DeclaredTransport,
        Duration::from_secs(7 * 24 * 3600),
    )
}

fn later(seconds: u64) -> MonotonicTime {
    START.saturating_add(Duration::from_secs(seconds))
}

fn private_request(expires_in_seconds: u64) -> PublicationRequest {
    PublicationRequest {
        service: service("web-preview"),
        port: port(3000),
        audience: Audience::Private {
            principals: BTreeSet::from([principal("alice")]),
        },
        authentication: AuthenticationMode::PlatformSession,
        expires_at: later(expires_in_seconds),
    }
}

fn alice() -> InboundCaller {
    InboundCaller::Authenticated {
        mode: AuthenticationMode::PlatformSession,
        principal: principal("alice"),
    }
}

#[test]
fn nothing_is_published_by_default_and_an_unpublished_service_is_unreachable() {
    let mut table = table();
    assert!(table.active(START).is_empty());
    assert_eq!(
        table.admit(
            &service("web-preview"),
            port(3000),
            &InboundCaller::Anonymous,
            START
        ),
        Err(IngressError::NotPublished {
            service: service("web-preview"),
            port: port(3000)
        })
    );
}

#[test]
fn a_publication_names_identity_port_audience_authentication_and_expiry() {
    let mut table = table();
    let id = table.publish(private_request(3600), START).unwrap();
    let publication = table.publication(id).unwrap();
    assert_eq!(publication.sandbox, sandbox());
    assert_eq!(publication.service, service("web-preview"));
    assert_eq!(publication.port, port(3000));
    assert_eq!(
        publication.authentication,
        AuthenticationMode::PlatformSession
    );
    assert_eq!(publication.published_at, START);
    assert_eq!(publication.expires_at, later(3600));
    assert!(matches!(
        table.publish(private_request(60), START),
        Err(IngressError::AlreadyPublished { .. })
    ));
}

#[test]
fn publications_need_a_mode_that_permits_them_and_a_bounded_future_expiry() {
    for mode in [NetworkMode::StrictAction, NetworkMode::Offline] {
        let mut strict = IngressTable::new(sandbox(), mode, Duration::from_secs(3600));
        assert!(matches!(
            strict.publish(private_request(60), START),
            Err(IngressError::Mode(_))
        ));
    }
    let mut table = table();
    assert_eq!(
        table.publish(private_request(0), START),
        Err(IngressError::ExpiryNotInFuture)
    );
    assert!(matches!(
        table.publish(private_request(7 * 24 * 3600 + 1), START),
        Err(IngressError::ExpiryTooFar { .. })
    ));
}

#[test]
fn a_private_publication_needs_authentication_and_principals() {
    let mut table = table();
    let mut unauthenticated = private_request(60);
    unauthenticated.authentication = AuthenticationMode::None;
    assert_eq!(
        table.publish(unauthenticated, START),
        Err(IngressError::PrivateNeedsAuthentication)
    );
    let mut nobody = private_request(60);
    nobody.audience = Audience::Private {
        principals: BTreeSet::new(),
    };
    assert_eq!(
        table.publish(nobody, START),
        Err(IngressError::PrivateNeedsPrincipals)
    );
}

#[test]
fn private_access_needs_the_right_authentication_and_a_listed_principal() {
    let mut table = table();
    table.publish(private_request(3600), START).unwrap();
    let preview = service("web-preview");
    assert!(table.admit(&preview, port(3000), &alice(), START).is_ok());
    assert_eq!(
        table.admit(&preview, port(3000), &InboundCaller::Anonymous, START),
        Err(IngressError::NotAuthenticated)
    );
    let bob = InboundCaller::Authenticated {
        mode: AuthenticationMode::PlatformSession,
        principal: principal("bob"),
    };
    assert_eq!(
        table.admit(&preview, port(3000), &bob, START),
        Err(IngressError::NotInAudience)
    );
    let token = InboundCaller::Authenticated {
        mode: AuthenticationMode::BearerToken,
        principal: principal("alice"),
    };
    assert_eq!(
        table.admit(&preview, port(3000), &token, START),
        Err(IngressError::WrongAuthentication {
            required: AuthenticationMode::PlatformSession
        })
    );
    assert!(matches!(
        table.admit(&preview, port(3001), &alice(), START),
        Err(IngressError::NotPublished { .. })
    ));
}

#[test]
fn an_explicit_public_publication_admits_anyone_and_is_never_relabelled() {
    let mut table = table();
    let public = PublicationRequest {
        service: service("demo-site"),
        port: port(8080),
        audience: Audience::Public,
        authentication: AuthenticationMode::None,
        expires_at: later(600),
    };
    let id = table.publish(public, START).unwrap();
    assert!(table
        .admit(
            &service("demo-site"),
            port(8080),
            &InboundCaller::Anonymous,
            START
        )
        .is_ok());
    let private = Audience::Private {
        principals: BTreeSet::from([principal("alice")]),
    };
    assert_eq!(
        table.change_audience(id, private),
        Err(IngressError::AudienceChangeRefused)
    );
    assert_eq!(table.publication(id).unwrap().audience, Audience::Public);
    let private_id = table.publish(private_request(600), START).unwrap();
    assert_eq!(
        table.change_audience(private_id, Audience::Public),
        Err(IngressError::AudienceChangeRefused)
    );
}

#[test]
fn expiry_and_withdrawal_end_access_and_existing_sessions() {
    let mut table = table();
    let id = table.publish(private_request(60), START).unwrap();
    let mut release = release_account();
    let session = table
        .admit(&service("web-preview"), port(3000), &alice(), START)
        .unwrap();
    assert_eq!(session.publication(), id);
    table
        .respond(&session, 500, &mut release, later(30))
        .unwrap();
    assert_eq!(
        table.respond(&session, 1, &mut release, later(60)),
        Err(IngressError::Expired)
    );
    assert_eq!(
        table.admit(&service("web-preview"), port(3000), &alice(), later(60)),
        Err(IngressError::Expired)
    );
    let renewed = table.publish(private_request(120), later(60)).unwrap();
    let session = table
        .admit(&service("web-preview"), port(3000), &alice(), later(61))
        .unwrap();
    assert_eq!(session.publication(), renewed);
    table.withdraw(renewed).unwrap();
    assert_eq!(
        table.respond(&session, 1, &mut release, later(62)),
        Err(IngressError::SessionClosed)
    );
    assert!(table.active(later(62)).is_empty());
}

#[test]
fn guest_responses_count_toward_the_release_policy() {
    let mut table = table();
    table.publish(private_request(3600), START).unwrap();
    let mut release = release_account();
    let session = table
        .admit(&service("web-preview"), port(3000), &alice(), START)
        .unwrap();
    table.respond(&session, 9_000, &mut release, START).unwrap();
    assert_eq!(
        release.used_bytes(ReleaseChannel::PublishedServiceResponse),
        9_000
    );
    assert!(matches!(
        table.respond(&session, 1_001, &mut release, START),
        Err(IngressError::Release(ReleaseError::Exhausted(_)))
    ));
}

fn endpoint(execution: &str, scope: &str) -> SandboxEndpoint {
    SandboxEndpoint {
        execution: crate::foundation::ids::ExecutionId::new(execution).unwrap(),
        scope: crate::foundation::ids::TrustScope::named(
            crate::foundation::ids::ExecutionCategory::VmSandbox,
            scope,
        ),
    }
}

fn connection(caller: &SandboxEndpoint, callee: &SandboxEndpoint) -> ConnectionGrant {
    ConnectionGrant {
        caller: caller.clone(),
        callee: callee.clone(),
        service: service("model-api"),
        port: port(8000),
        expires_at: later(3600),
    }
}

#[test]
fn a_sandbox_connection_needs_grants_at_both_ends() {
    let client = endpoint("exe-client", "team-a");
    let model = endpoint("exe-model", "team-a");
    let mut connections = SandboxConnections::new();
    let declared = NetworkMode::DeclaredTransport;
    connections
        .grant_outbound(declared, connection(&client, &model), START)
        .unwrap();
    assert_eq!(
        connections.connect(&client, &model, &service("model-api"), port(8000), START),
        Err(ConnectionRefusal::MissingGrant {
            side: MissingSide::Callee
        })
    );
    let mut inbound_only = SandboxConnections::new();
    inbound_only
        .grant_inbound(declared, connection(&client, &model), START)
        .unwrap();
    assert_eq!(
        inbound_only.connect(&client, &model, &service("model-api"), port(8000), START),
        Err(ConnectionRefusal::MissingGrant {
            side: MissingSide::Caller
        })
    );
    connections
        .grant_inbound(declared, connection(&client, &model), START)
        .unwrap();
    let authorized = connections
        .connect(&client, &model, &service("model-api"), port(8000), START)
        .unwrap();
    assert_eq!(authorized.callee, model);
    // The grant is directed: the reverse connection has no grants.
    assert_eq!(
        connections.connect(&model, &client, &service("model-api"), port(8000), START),
        Err(ConnectionRefusal::MissingGrant {
            side: MissingSide::Both
        })
    );
    assert!(connections
        .connect(&client, &model, &service("admin-api"), port(8000), START)
        .is_err());
    assert!(connections
        .connect(&client, &model, &service("model-api"), port(8001), START)
        .is_err());
    assert!(connections
        .connect(
            &client,
            &model,
            &service("model-api"),
            port(8000),
            later(3600)
        )
        .is_err());
    connections.revoke(&client, &model);
    assert!(connections
        .connect(&client, &model, &service("model-api"), port(8000), START)
        .is_err());
}

#[test]
fn transitive_access_is_never_inferred() {
    let client = endpoint("exe-client", "team-a");
    let model = endpoint("exe-model", "team-a");
    let provider_proxy = endpoint("exe-proxy", "team-a");
    let declared = NetworkMode::DeclaredTransport;
    let mut connections = SandboxConnections::new();
    for (caller, callee) in [(&client, &model), (&model, &provider_proxy)] {
        connections
            .grant_outbound(declared, connection(caller, callee), START)
            .unwrap();
        connections
            .grant_inbound(declared, connection(caller, callee), START)
            .unwrap();
    }
    assert!(connections
        .connect(&client, &model, &service("model-api"), port(8000), START)
        .is_ok());
    assert!(connections
        .connect(
            &model,
            &provider_proxy,
            &service("model-api"),
            port(8000),
            START
        )
        .is_ok());
    assert_eq!(
        connections.connect(
            &client,
            &provider_proxy,
            &service("model-api"),
            port(8000),
            START
        ),
        Err(ConnectionRefusal::MissingGrant {
            side: MissingSide::Both
        })
    );

    // A client allowed to call the model does not inherit the model's provider routes.
    let clock = clock();
    let model_broker = DestinationBroker::new(
        policy(
            NetworkMode::DeclaredTransport,
            vec![api_grant(RedirectPolicy::Disabled)],
        ),
        host_state(),
        release_account(),
        &clock,
    );
    let client_broker = DestinationBroker::new(
        policy(NetworkMode::DeclaredTransport, vec![]),
        host_state(),
        release_account(),
        &clock,
    );
    assert!(model_broker.authorize(&request("api.example.com")).is_ok());
    let dns = FakeResolver::new("host-dns");
    assert!(matches!(
        client_broker.authorize(&request("api.example.com")),
        Err(DestinationRefusal::Authorization(
            AuthorizationRefusal::NotGranted { .. }
        ))
    ));
    assert_eq!(dns.calls(), 0);
}

#[test]
fn a_grant_names_the_peer_trust_scope_exactly() {
    let client = endpoint("exe-client", "team-a");
    let model = endpoint("exe-model", "team-a");
    let declared = NetworkMode::DeclaredTransport;
    let mut connections = SandboxConnections::new();
    connections
        .grant_outbound(declared, connection(&client, &model), START)
        .unwrap();
    connections
        .grant_inbound(declared, connection(&client, &model), START)
        .unwrap();
    let relaunched_elsewhere = endpoint("exe-model", "team-b");
    assert!(connections
        .connect(
            &client,
            &relaunched_elsewhere,
            &service("model-api"),
            port(8000),
            START
        )
        .is_err());
}

#[test]
fn connection_grants_need_a_permitting_mode_and_a_future_expiry() {
    let client = endpoint("exe-client", "team-a");
    let model = endpoint("exe-model", "team-a");
    let mut connections = SandboxConnections::new();
    assert!(matches!(
        connections.grant_outbound(
            NetworkMode::StrictAction,
            connection(&client, &model),
            START
        ),
        Err(ConnectionRefusal::Mode(_))
    ));
    let mut expired = connection(&client, &model);
    expired.expires_at = START;
    assert_eq!(
        connections.grant_inbound(NetworkMode::DeclaredTransport, expired, START),
        Err(ConnectionRefusal::ExpiryNotInFuture)
    );
}

#[test]
fn callee_responses_on_a_connection_count_toward_the_callee_release_policy() {
    let client = endpoint("exe-client", "team-a");
    let model = endpoint("exe-model", "team-a");
    let declared = NetworkMode::DeclaredTransport;
    let mut connections = SandboxConnections::new();
    connections
        .grant_outbound(declared, connection(&client, &model), START)
        .unwrap();
    connections
        .grant_inbound(declared, connection(&client, &model), START)
        .unwrap();
    let authorized = connections
        .connect(&client, &model, &service("model-api"), port(8000), START)
        .unwrap();
    let mut model_release = release_account();
    connections
        .record_response(&authorized, 2_000, &mut model_release, START)
        .unwrap();
    assert_eq!(
        model_release.used_bytes(ReleaseChannel::PublishedServiceResponse),
        2_000
    );
    connections.revoke(&client, &model);
    assert!(connections
        .record_response(&authorized, 1, &mut model_release, START)
        .is_err());
}
