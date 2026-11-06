//! From a sandbox's route declarations to its broker (module docs in `mod.rs`): V02's
//! destination policy with one operation route per declaration, the relay's route table
//! (endpoint name to route id), the credential injector over the executor's vault with one
//! V07 grant per credentialed route, the permits over the declared resolver, the upstream
//! transport (TLS to the authorized name through the host's roots, or plaintext only where
//! declared and never with a credential), and the guest-facing facts: the guest spoke
//! plaintext to a named endpoint, so the name it addressed stands where a TLS server name
//! would (`DeclaredDestinationTls`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Clock, MonotonicTime, PolicyEpoch, TenantId};
use crate::foundation::transfer::{CredentialRef, GeneralReleaseBudget};
use crate::sandbox_contract::destinations::{
    AddressFamily, Authority, CanonicalName, ChannelPolicy, DestinationBroker, DestinationPolicy,
    DestinationPort, EffectClass, GrantTarget, HostAddressGeneration, HostAddressState, HttpMethod,
    InFlightAllowance, IpPrefix, NetworkMode, OperationName, OperationRoute, OperationSpec,
    OperationTls, PathTemplate, PolicyParts, RedirectPolicy, ReleaseAccount, ReleaseChannel,
    ReleaseTrustClass, ResolverId, RouteBudgets, RouteGrant, RouteId, RouteKind, RouteProtocol,
    TaskDataClass, TlsFacts,
};
use crate::sandbox_contract::effects::{
    AccountRef, ExecutorName, OperationKey, OperationName as ContractName, ProviderId, SecretClass,
};
use crate::sandbox_contract::provider::{DestinationBinding, KnownSecrets, VaultGrant};
use crate::sandbox_contract::relay::ReaderLimits;
use crate::sandbox_contract::relay_broker::{
    CredentialAudience, CredentialHeader, CredentialInjector, ExchangeConfig, ExchangeLimits,
    ExchangeObserver,
    GuestTlsSource, HeaderVault, RelayBroker, ResolvingPermits, SharedBroker, TcpConnector,
    UpstreamDeadlines, UpstreamPolicy, UpstreamTls, UpstreamTransport,
};
use crate::sandbox_contract::relay_link::ExchangeId;
use crate::sandbox_contract::relay_process::{GuestEndpoint, RouteEntry, RouteTable};
use crate::sandbox_contract::vault::{SandboxVault, SecretStore};

use super::protocol::{
    account_reference, credential_reference, CredentialHeaderDecl, EffectDecl, ResolverDecl,
    RouteDeclaration,
};
use super::resolver::{FixedResolver, SystemResolver};

/// The executor's name in every grant and scope.
pub const EXECUTOR_NAME: &str = "sandbox-relay-broker";

/// The resolver id the built policy allows.
pub const RESOLVER_ID: &str = "host-resolver";

/// How long a built grant lasts: the sandbox's relay life is bounded by the sandbox; a day
/// bounds it absolutely.
pub const GRANT_LIFETIME: Duration = Duration::from_secs(24 * 3_600);

/// The request and response bounds of every exchange.
pub const REQUEST_HEAD_BYTES: usize = 64 * 1024;
pub const REQUEST_BODY_BYTES: u64 = 8 << 20;
pub const RESPONSE_HEAD_BYTES: usize = 64 * 1024;
pub const RESPONSE_BODY_BYTES: u64 = 64 << 20;

/// Why the declarations could not become a broker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildRefusal {
    pub detail: String,
}

impl fmt::Display for BuildRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the route declarations were refused: {}", self.detail)
    }
}

impl std::error::Error for BuildRefusal {}

fn refuse(detail: impl Into<String>) -> BuildRefusal {
    BuildRefusal {
        detail: detail.into(),
    }
}

/// The guest addressed a named endpoint in plaintext; the route's host name stands where
/// its TLS server name would, for the broker's check.
pub struct DeclaredDestinationTls {
    hosts: BTreeMap<RouteId, String>,
}

impl GuestTlsSource for DeclaredDestinationTls {
    fn facts(&self, _exchange: ExchangeId, route: &RouteId) -> Option<TlsFacts> {
        self.hosts.get(route).map(|host| TlsFacts {
            sni: Some(host.clone()),
        })
    }
}

/// What one sandbox's declarations built.
pub struct BuiltBroker<C: Clock> {
    pub routes: RouteTable,
    pub limits: ReaderLimits,
    pub broker: Arc<RelayBroker<C>>,
    /// The credentials the injector was granted, by route.
    pub credentialed_routes: Vec<RouteId>,
}

impl<C: Clock> fmt::Debug for BuiltBroker<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BuiltBroker")
            .field("routes", &self.routes.len())
            .field("credentialed_routes", &self.credentialed_routes)
            .finish_non_exhaustive()
    }
}

fn method(text: &str) -> Result<HttpMethod, BuildRefusal> {
    Ok(match text.to_ascii_uppercase().as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "PATCH" => HttpMethod::Patch,
        "DELETE" => HttpMethod::Delete,
        other => {
            return Err(refuse(format!(
                "method {other} is not one of GET, POST, PUT, PATCH, DELETE"
            )))
        }
    })
}

/// Builds one sandbox's broker from `declarations` (module notes). `store` holds the
/// credentials; the sandbox gets a vault of its own over it, granted exactly what its
/// routes declare, so no sandbox's grant widens or narrows another's. `session` and `clock`
/// are the executor's; `now` dates the policy and the grants; `host_addresses` are this
/// host's own addresses, which no route may reach; `observer`, when given, is told of every
/// exchange record as it is made (the executor's refusal reports to the engine).
#[allow(clippy::too_many_arguments)]
pub fn build_broker<C: Clock + Clone + Send + Sync + 'static, S: SecretStore + 'static>(
    declarations: &[RouteDeclaration],
    tenant: &TenantId,
    store: S,
    session: ClockSession,
    clock: C,
    shared_clock: Arc<dyn Clock>,
    now: MonotonicTime,
    host_addresses: &[IpAddr],
    observer: Option<ExchangeObserver>,
) -> Result<BuiltBroker<C>, BuildRefusal> {
    if declarations.is_empty() {
        return Err(refuse("no route was declared"));
    }
    let mut vault = SandboxVault::new(store, session);
    let mut audiences = Vec::new();
    let executor = ExecutorName::new(EXECUTOR_NAME).map_err(|error| refuse(error.to_string()))?;
    let resolver_id = ResolverId::new(RESOLVER_ID).map_err(|error| refuse(error.to_string()))?;
    let mut grants = Vec::new();
    let mut entries = Vec::new();
    let mut hosts = BTreeMap::new();
    let mut upstream = UpstreamPolicy::tls_only();
    let mut vault_grants = Vec::new();
    let mut credentialed_routes = Vec::new();
    let mut resolver: Option<ResolverDecl> = None;
    for declaration in declarations {
        let route_id = RouteId::new(&declaration.name)
            .map_err(|error| refuse(format!("route name {:?}: {error}", declaration.name)))?;
        let endpoint = GuestEndpoint::new(&declaration.name)
            .map_err(|error| refuse(format!("endpoint name {:?}: {error}", declaration.name)))?;
        let host = CanonicalName::parse(&declaration.host)
            .map_err(|error| refuse(format!("host {:?}: {error}", declaration.host)))?;
        let port = DestinationPort::new(declaration.port)
            .map_err(|error| refuse(format!("port {}: {error}", declaration.port)))?;
        if declaration.plaintext && declaration.credential.is_some() {
            return Err(refuse(format!(
                "route {}: a credentialed route may not go upstream in plaintext",
                declaration.name
            )));
        }
        if let Some(declared) = &declaration.resolver {
            match &resolver {
                None => resolver = Some(declared.clone()),
                Some(existing) if existing == declared => {}
                Some(_) => return Err(refuse("the routes declare different resolvers")),
            }
        }
        let mut specs = Vec::new();
        for operation in &declaration.operations {
            specs.push(OperationSpec {
                name: OperationName::new(&operation.name)
                    .map_err(|error| refuse(format!("operation {:?}: {error}", operation.name)))?,
                method: method(&operation.method)?,
                path: PathTemplate::parse(&operation.path)
                    .map_err(|error| refuse(format!("path {:?}: {error}", operation.path)))?,
                query_keys: operation.query_keys.clone(),
                effect: match operation.effect {
                    EffectDecl::ReadOnly => EffectClass::ReadOnly,
                    EffectDecl::External => EffectClass::External,
                },
            });
        }
        let credential_ref = declaration
            .credential
            .as_ref()
            .map(|credential| CredentialRef::from_digest(credential_reference(&credential.name)));
        let operation_route = OperationRoute::new(
            OperationTls::TerminatedAtExecutor,
            credential_ref,
            specs,
            RedirectPolicy::Disabled,
            false,
        )
        .map_err(|error| refuse(format!("route {}: {error}", declaration.name)))?;
        grants.push(RouteGrant {
            id: route_id.clone(),
            // The policy knows HTTP over TLS; a plaintext upstream is the transport's
            // exception for the route (`allow_plaintext`), never a credentialed one.
            protocol: RouteProtocol::Https,
            target: GrantTarget::ExactName(host.clone()),
            port,
            route: RouteKind::Operation(operation_route),
            ipv6: false,
            resolver: Some(resolver_id.clone()),
            budgets: RouteBudgets {
                dns_queries: declaration.budgets.dns_queries,
                connections: declaration.budgets.connections,
                bytes_out: declaration.budgets.bytes_out,
                bytes_in: declaration.budgets.bytes_in,
                effects: declaration.budgets.effects,
            },
        });
        entries.push(RouteEntry {
            endpoint,
            route: route_id.clone(),
        });
        hosts.insert(route_id.clone(), declaration.host.clone());
        if declaration.plaintext {
            upstream = upstream.allow_plaintext(route_id.clone());
        }
        if let (Some(credential), Some(reference)) = (&declaration.credential, credential_ref) {
            let provider = ProviderId::new(&credential.provider)
                .map_err(|error| refuse(format!("provider {:?}: {error}", credential.provider)))?;
            let account = AccountRef::new(account_reference(&credential.name));
            let header = match credential.header {
                CredentialHeaderDecl::Authorization => CredentialHeader::Authorization,
                CredentialHeaderDecl::ProxyAuthorization => CredentialHeader::ProxyAuthorization,
                CredentialHeaderDecl::Cookie => CredentialHeader::Cookie,
            };
            audiences.push((
                route_id.clone(),
                CredentialAudience {
                    header,
                    provider: provider.clone(),
                    contract_version: credential.contract_version,
                    account,
                },
            ));
            let operations: BTreeSet<OperationKey> = declaration
                .operations
                .iter()
                .map(|operation| {
                    ContractName::new(&operation.name)
                        .map(|name| OperationKey {
                            provider: provider.clone(),
                            operation: name,
                            contract_version: credential.contract_version,
                        })
                        .map_err(|error| refuse(format!("operation {:?}: {error}", operation.name)))
                })
                .collect::<Result<_, _>>()?;
            let authority = Authority::parse(&declaration.host, port)
                .map_err(|error| refuse(format!("authority {:?}: {error}", declaration.host)))?;
            vault_grants.push(VaultGrant {
                credential: reference,
                class: SecretClass::LongLivedProviderCredential,
                executor: executor.clone(),
                operations,
                routes: BTreeSet::from([DestinationBinding::route_ref_for(&authority)]),
                accounts: BTreeSet::from([account]),
                clock: session,
                expires_at: now.saturating_add(GRANT_LIFETIME),
            });
            credentialed_routes.push(route_id);
        }
    }
    for grant in &vault_grants {
        vault
            .grant(grant.clone())
            .map_err(|error| refuse(format!("the vault grant was refused: {error}")))?;
    }
    let vault: Arc<dyn HeaderVault> = Arc::new(vault);
    let mut injector = CredentialInjector::new(executor.clone(), session, shared_clock, vault);
    for (route, audience) in audiences {
        injector = injector.with_audience(route, audience);
    }
    for grant in vault_grants {
        injector
            .grant(grant)
            .map_err(|error| refuse(format!("the injector's grant was refused: {error}")))?;
    }
    let policy = DestinationPolicy::new(
        PolicyParts {
            tenant: tenant.clone(),
            epoch: PolicyEpoch::FIRST,
            mode: NetworkMode::DeclaredTransport,
            data_class: TaskDataClass::Ordinary,
            grants,
            allowed_resolvers: BTreeSet::from([resolver_id.clone()]),
            approved_objects: BTreeSet::new(),
            max_answer_ttl: Duration::from_secs(300),
        },
        now,
    )
    .map_err(|error| refuse(format!("the policy was refused: {error}")))?;
    let release = ReleaseAccount::new(
        BTreeMap::from([
            (
                ReleaseChannel::DnsQuery,
                ChannelPolicy {
                    budget_bytes: 64 * 1024,
                    trust_class: ReleaseTrustClass::Resolver,
                },
            ),
            (
                ReleaseChannel::ProviderRequest,
                ChannelPolicy {
                    budget_bytes: GeneralReleaseBudget::vm_d12_default().limit_bytes(),
                    trust_class: ReleaseTrustClass::External,
                },
            ),
        ]),
        GeneralReleaseBudget::vm_d12_default(),
        InFlightAllowance {
            bytes: 16 * 1024,
            documented_reason: "TLS record framing is sized only when sent".to_owned(),
        },
    )
    .map_err(|error| refuse(format!("the release account was refused: {error}")))?;
    let owned: Vec<IpPrefix> = host_addresses.iter().copied().map(IpPrefix::host).collect();
    let broker: SharedBroker<C> = Arc::new(Mutex::new(DestinationBroker::new(
        policy,
        HostAddressState::new(HostAddressGeneration::FIRST, owned),
        release,
        clock,
    )));
    let permits: Arc<dyn crate::sandbox_contract::relay_broker::PermitSource<C>> =
        match resolver.unwrap_or(ResolverDecl::System) {
            ResolverDecl::System => Arc::new(ResolvingPermits::new(
                SystemResolver::new(resolver_id),
                AddressFamily::Ipv4,
            )),
            ResolverDecl::Fixed { addresses } => Arc::new(ResolvingPermits::new(
                FixedResolver::new(resolver_id, addresses),
                AddressFamily::Ipv4,
            )),
        };
    let limits = ReaderLimits::new(REQUEST_HEAD_BYTES, REQUEST_BODY_BYTES)
        .map_err(|error| refuse(format!("the request limits were refused: {error}")))?;
    let config = ExchangeConfig {
        limits: ExchangeLimits {
            request: limits,
            response: ReaderLimits::new(RESPONSE_HEAD_BYTES, RESPONSE_BODY_BYTES)
                .map_err(|error| refuse(format!("the response limits were refused: {error}")))?,
        },
        permits,
        credentials: Arc::new(injector),
        upstream,
        known: Arc::new(KnownSecrets::new()),
    };
    let tls = UpstreamTls::platform()
        .map_err(|error| refuse(format!("the host's TLS roots: {error}")))?;
    let transport =
        UpstreamTransport::new(Arc::new(TcpConnector), tls, UpstreamDeadlines::default());
    let routes =
        RouteTable::new(entries).map_err(|error| refuse(format!("the route table: {error:?}")))?;
    Ok(BuiltBroker {
        routes,
        limits,
        broker: Arc::new({
            let relay = RelayBroker::new(
                broker,
                config,
                transport,
                Arc::new(DeclaredDestinationTls { hosts }),
            );
            match observer {
                Some(observer) => relay.with_observer(observer),
                None => relay,
            }
        }),
        credentialed_routes,
    })
}
