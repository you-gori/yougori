//! Tests for M09D: the exchange core over a real V02 broker with a fake resolver and a
//! fake vault; the transport over in-memory streams (`tokio::io::duplex`) to a TLS server
//! whose self-signed certificate rcgen makes in the test, trusted alone by the client;
//! and the link loop over in-memory streams with a real relay-side session. Nothing here
//! opens a socket or resolves a name.

mod exchange;
mod link;
mod transport;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::Semaphore;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{self, HandshakeKind, RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{digest, Digest, ManualClock, MonotonicTime, PolicyEpoch, TenantId};
use crate::foundation::transfer::{CredentialRef, GeneralReleaseBudget};
use crate::sandbox_contract::destinations::{
    AddressFamily, Authority, BudgetKind, CanonicalName, ChannelPolicy, DestinationBroker,
    DestinationPolicy, DestinationPort, EffectClass, GrantTarget, HostAddressGeneration,
    HostAddressState, HttpMethod, InFlightAllowance, IpPrefix, NetworkMode, OperationName,
    OperationRoute, OperationSpec, OperationTls, PathTemplate, PolicyParts, RedirectPolicy,
    ReleaseAccount, ReleaseChannel, ReleaseTrustClass, ResolutionQuery, Resolver, ResolverAnswer,
    ResolverFailure, ResolverId, RouteBudgets, RouteGrant, RouteId, RouteKind, RouteProtocol,
    RouteUsage, TaskDataClass, TlsFacts,
};
use crate::sandbox_contract::effects::{
    AccountRef, CanaryToken, ExecutorName, OperationKey, OperationName as ContractName, ProviderId,
    SecretClass,
};
use crate::sandbox_contract::provider::{
    find_encoded, DestinationBinding, KnownSecrets, ScanEncoding, SecretValue, VaultFacts,
    VaultGrant, VaultRefusal, VaultScope,
};
use crate::sandbox_contract::relay::ReaderLimits;
use crate::sandbox_contract::relay_link::{ExchangeId, WireBytes};

pub(crate) const START: MonotonicTime = MonotonicTime::from_nanos(1_000_000_000_000);

/// The public address every name resolves to.
pub(crate) const UPSTREAM: &str = "93.184.216.34";

/// The credentialed provider API (`provider-api`).
pub(crate) const API: &str = "api.example.com";

/// An API without a credential (`open-api`).
pub(crate) const OPEN: &str = "open.example.com";

/// The raw credential the fake vault holds; the header value is `Bearer ` and this.
pub(crate) const SECRET: &str = "sk-live-fixture-0123456789";

/// A known fixture secret every response is scanned for.
pub(crate) const FIXTURE: &str = "fixture-secret-abcdef";

pub(crate) const SESSION: ClockSession = ClockSession::from_uuid(uuid::Uuid::from_u128(0x5eed));

pub(crate) const OK_BODY: &str = r#"{"data":[]}"#;

pub(crate) fn test_digest(text: &str) -> Digest {
    digest("yougori/test/relay-broker/v1", &[text.as_bytes()])
}

pub(crate) fn route_id(text: &str) -> RouteId {
    RouteId::new(text).unwrap()
}

pub(crate) fn provider() -> RouteId {
    route_id("provider-api")
}

pub(crate) fn open() -> RouteId {
    route_id("open-api")
}

pub(crate) fn credential() -> CredentialRef {
    CredentialRef::from_digest(test_digest("vault-handle"))
}

fn budgets() -> RouteBudgets {
    RouteBudgets {
        dns_queries: 50,
        connections: 50,
        bytes_out: 100_000,
        bytes_in: 1_000_000,
        effects: 20,
    }
}

fn spec(
    op: &str,
    method: HttpMethod,
    path: &str,
    keys: &[&str],
    effect: EffectClass,
) -> OperationSpec {
    OperationSpec {
        name: OperationName::new(op).unwrap(),
        method,
        path: PathTemplate::parse(path).unwrap(),
        query_keys: keys.iter().map(|key| (*key).to_owned()).collect(),
        effect,
    }
}

/// List models (read-only) and create a job (an external effect).
fn operation_route(credentialed: bool) -> OperationRoute {
    OperationRoute::new(
        OperationTls::TerminatedAtExecutor,
        credentialed.then(credential),
        vec![
            spec(
                "list-models",
                HttpMethod::Get,
                "/v1/models",
                &["limit"],
                EffectClass::ReadOnly,
            ),
            spec(
                "create-job",
                HttpMethod::Post,
                "/v1/jobs",
                &[],
                EffectClass::External,
            ),
        ],
        RedirectPolicy::Disabled,
        false,
    )
    .unwrap()
}

fn resolver_id() -> ResolverId {
    ResolverId::new("host-dns").unwrap()
}

fn grant(id: RouteId, host: &str, credentialed: bool) -> RouteGrant {
    RouteGrant {
        id,
        protocol: RouteProtocol::Https,
        target: GrantTarget::ExactName(CanonicalName::parse(host).unwrap()),
        port: DestinationPort::HTTPS,
        route: RouteKind::Operation(operation_route(credentialed)),
        ipv6: false,
        resolver: Some(resolver_id()),
        budgets: budgets(),
    }
}

fn policy() -> DestinationPolicy {
    DestinationPolicy::new(
        PolicyParts {
            tenant: TenantId::new("tenant-a").unwrap(),
            epoch: PolicyEpoch::FIRST,
            mode: NetworkMode::DeclaredTransport,
            data_class: TaskDataClass::Ordinary,
            grants: vec![grant(provider(), API, true), grant(open(), OPEN, false)],
            allowed_resolvers: BTreeSet::from([resolver_id()]),
            approved_objects: BTreeSet::new(),
            max_answer_ttl: Duration::from_secs(300),
        },
        START,
    )
    .unwrap()
}

fn release_account() -> ReleaseAccount {
    ReleaseAccount::new(
        BTreeMap::from([
            (
                ReleaseChannel::DnsQuery,
                ChannelPolicy {
                    budget_bytes: 65_536,
                    trust_class: ReleaseTrustClass::Resolver,
                },
            ),
            (
                ReleaseChannel::ProviderRequest,
                ChannelPolicy {
                    budget_bytes: 1_000_000,
                    trust_class: ReleaseTrustClass::External,
                },
            ),
        ]),
        GeneralReleaseBudget::vm_d12_default(),
        InFlightAllowance {
            bytes: 1_024,
            documented_reason: "TLS record framing is sized only when sent".to_owned(),
        },
    )
    .unwrap()
}

pub(crate) type Broker = DestinationBroker<ManualClock>;

fn broker() -> Broker {
    DestinationBroker::new(
        policy(),
        HostAddressState::new(
            HostAddressGeneration::FIRST,
            [IpPrefix::host("192.168.1.10".parse::<IpAddr>().unwrap())],
        ),
        release_account(),
        ManualClock::new(START),
    )
}

/// Answers every query with [`UPSTREAM`] and performs no lookup.
pub(crate) struct FixedResolver(ResolverId);

impl Resolver for FixedResolver {
    fn id(&self) -> &ResolverId {
        &self.0
    }

    fn resolve(&self, query: &ResolutionQuery) -> Result<ResolverAnswer, ResolverFailure> {
        Ok(ResolverAnswer {
            name: query.name().clone(),
            aliases: Vec::new(),
            addresses: vec![UPSTREAM.parse().unwrap()],
            ttl: Duration::from_secs(60),
        })
    }
}

/// What the fake vault hands out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum VaultMode {
    #[default]
    Honest,
    /// A value with a line break in it.
    LineBreak,
    /// A value longer than its facts said.
    Longer,
}

#[derive(Default)]
pub(crate) struct VaultState {
    secrets: BTreeMap<CredentialRef, Vec<u8>>,
    pub(crate) mode: VaultMode,
    pub(crate) values_given: usize,
}

/// A vault holding [`SECRET`] for [`credential`]; the header value is `Bearer ` + secret.
#[derive(Default)]
pub(crate) struct FakeVault(pub(crate) Mutex<VaultState>);

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FakeVault {
    fn holding_fixture() -> Self {
        let vault = Self::default();
        lock(&vault.0)
            .secrets
            .insert(credential(), SECRET.as_bytes().to_vec());
        vault
    }

    fn secret(&self, scope: &VaultScope) -> Result<Vec<u8>, VaultRefusal> {
        lock(&self.0)
            .secrets
            .get(&scope.credential)
            .cloned()
            .ok_or(VaultRefusal::UnknownCredential)
    }
}

pub(crate) fn bearer(secret: &[u8]) -> Vec<u8> {
    [b"Bearer ".as_slice(), secret].concat()
}

impl HeaderVault for FakeVault {
    fn facts(&self, scope: &VaultScope, _now: MonotonicTime) -> Result<VaultFacts, VaultRefusal> {
        let secret = self.secret(scope)?;
        Ok(VaultFacts {
            class: SecretClass::LongLivedProviderCredential,
            authorization_header_bytes: u64::try_from(bearer(&secret).len()).unwrap(),
        })
    }

    fn header_value(
        &self,
        scope: &VaultScope,
        _now: MonotonicTime,
    ) -> Result<SecretValue, VaultRefusal> {
        let secret = self.secret(scope)?;
        let mut state = lock(&self.0);
        state.values_given += 1;
        let value = match state.mode {
            VaultMode::Honest => bearer(&secret),
            VaultMode::LineBreak => [bearer(&secret), b"\r\nx-extra: 1".to_vec()].concat(),
            VaultMode::Longer => [bearer(&secret), b"-and-more".to_vec()].concat(),
        };
        Ok(SecretValue::new(value))
    }

    fn reflects_secret(&self, scope: &VaultScope, bytes: &[u8]) -> Option<ScanEncoding> {
        let secret = self.secret(scope).ok()?;
        find_encoded(bytes, &secret).or_else(|| find_encoded(bytes, &bearer(&secret)))
    }
}

pub(crate) fn executor() -> ExecutorName {
    ExecutorName::new("relay-broker").unwrap()
}

pub(crate) fn account() -> AccountRef {
    AccountRef::new(test_digest("org-a"))
}

pub(crate) fn operation_key(name: &str) -> OperationKey {
    OperationKey {
        provider: ProviderId::new("forge").unwrap(),
        operation: ContractName::new(name).unwrap(),
        contract_version: 1,
    }
}

pub(crate) fn audience() -> CredentialAudience {
    CredentialAudience {
        header: CredentialHeader::Authorization,
        provider: ProviderId::new("forge").unwrap(),
        contract_version: 1,
        account: account(),
    }
}

pub(crate) fn vault_grant() -> VaultGrant {
    VaultGrant {
        credential: credential(),
        class: SecretClass::LongLivedProviderCredential,
        executor: executor(),
        operations: BTreeSet::from([operation_key("list-models"), operation_key("create-job")]),
        routes: BTreeSet::from([DestinationBinding::route_ref_for(
            &Authority::parse(API, DestinationPort::HTTPS).unwrap(),
        )]),
        accounts: BTreeSet::from([account()]),
        clock: SESSION,
        expires_at: START.saturating_add(Duration::from_secs(3_600)),
    }
}

pub(crate) fn known() -> KnownSecrets {
    KnownSecrets::new()
        .with_fixture(FIXTURE.as_bytes())
        .unwrap()
        .with_canary(canary())
}

pub(crate) fn canary() -> CanaryToken {
    CanaryToken {
        marker: test_digest("canary"),
    }
}

pub(crate) fn limits() -> ExchangeLimits {
    ExchangeLimits {
        request: ReaderLimits::new(8_192, 65_536).unwrap(),
        response: ReaderLimits::new(8_192, 4_096).unwrap(),
    }
}

/// One sandbox's broker, vault, clock and injector.
pub(crate) struct Fixture {
    pub(crate) broker: SharedBroker<ManualClock>,
    pub(crate) vault: Arc<FakeVault>,
    pub(crate) clock: Arc<ManualClock>,
    pub(crate) injector: Arc<CredentialInjector>,
}

pub(crate) fn fixture() -> Fixture {
    let vault = Arc::new(FakeVault::holding_fixture());
    let clock = Arc::new(ManualClock::new(START));
    let injector = CredentialInjector::new(
        executor(),
        SESSION,
        Arc::clone(&clock) as Arc<dyn crate::foundation::ids::Clock>,
        Arc::clone(&vault) as Arc<dyn HeaderVault>,
    )
    .with_audience(provider(), audience());
    injector.grant(vault_grant()).unwrap();
    Fixture {
        broker: Arc::new(Mutex::new(broker())),
        vault,
        clock,
        injector: Arc::new(injector),
    }
}

impl Fixture {
    pub(crate) fn config(&self, upstream: UpstreamPolicy) -> ExchangeConfig<ManualClock> {
        ExchangeConfig {
            limits: limits(),
            permits: Arc::new(ResolvingPermits::new(
                FixedResolver(resolver_id()),
                AddressFamily::Ipv4,
            )),
            credentials: Arc::clone(&self.injector),
            upstream,
            known: Arc::new(known()),
        }
    }

    /// A relay broker over `connector`, with the guest's TLS facts `sni`.
    pub(crate) fn relay(
        &self,
        upstream: UpstreamPolicy,
        connector: Arc<dyn UpstreamConnector>,
        tls: UpstreamTls,
        deadlines: UpstreamDeadlines,
        sni: Option<&str>,
    ) -> RelayBroker<ManualClock> {
        RelayBroker::new(
            Arc::clone(&self.broker),
            self.config(upstream),
            UpstreamTransport::new(connector, tls, deadlines),
            Arc::new(GuestTls(Some(guest_tls(sni)))),
        )
    }

    pub(crate) fn usage(&self, route: &RouteId) -> RouteUsage {
        lock_broker(&self.broker).usage(route)
    }

    pub(crate) fn released(&self) -> u64 {
        lock_broker(&self.broker)
            .release_account()
            .used_bytes(ReleaseChannel::ProviderRequest)
    }

    /// Nothing of any route's budgets is still reserved.
    pub(crate) fn assert_settled(&self) {
        for route in [provider(), open()] {
            let usage = self.usage(&route);
            for kind in BudgetKind::ALL {
                assert_eq!(usage.reserved(kind), 0, "{route}: {kind:?} still reserved");
            }
        }
    }

    /// Nothing of any route was used either: no query, connection, byte or effect.
    pub(crate) fn assert_untouched(&self) {
        for route in [provider(), open()] {
            let usage = self.usage(&route);
            for kind in BudgetKind::ALL {
                assert_eq!(usage.used(kind), 0, "{route}: {kind:?} used");
                assert_eq!(usage.reserved(kind), 0, "{route}: {kind:?} reserved");
            }
        }
        assert_eq!(self.released(), 0);
    }
}

pub(crate) fn guest_tls(sni: Option<&str>) -> TlsFacts {
    TlsFacts {
        sni: sni.map(str::to_owned),
    }
}

/// The guest's TLS facts as the broker's guest-facing side recorded them.
pub(crate) struct GuestTls(pub(crate) Option<TlsFacts>);

impl GuestTlsSource for GuestTls {
    fn facts(&self, _exchange: ExchangeId, _route: &RouteId) -> Option<TlsFacts> {
        self.0.clone()
    }
}

/// A list-models request in the form the broker rebuilds.
pub(crate) fn list_models(host: &str) -> Vec<u8> {
    format!("GET /v1/models?limit=5 HTTP/1.1\r\nhost: {host}\r\naccept: application/json\r\n\r\n")
        .into_bytes()
}

/// A list-models request for `limit` models, in the form the broker rebuilds.
pub(crate) fn list_models_limit(host: &str, limit: u32) -> Vec<u8> {
    format!("GET /v1/models?limit={limit} HTTP/1.1\r\nhost: {host}\r\n\r\n").into_bytes()
}

/// A create-job request in the form the broker rebuilds.
pub(crate) fn create_job(host: &str, body: &str) -> Vec<u8> {
    format!(
        "POST /v1/jobs HTTP/1.1\r\nhost: {host}\r\ncontent-type: application/json\r\n\
content-length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// `request` with the credential header the broker adds, just before the end of the head.
pub(crate) fn with_credential(request: &[u8]) -> Vec<u8> {
    let end = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 2;
    [
        &request[..end],
        b"authorization: ".as_slice(),
        &bearer(SECRET.as_bytes()),
        b"\r\n".as_slice(),
        &request[end..],
    ]
    .concat()
}

/// A 200 response with `body`, in the form the response step rebuilds.
pub(crate) fn ok_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

pub(crate) fn wire(bytes: &[u8]) -> WireBytes {
    WireBytes::new(bytes.to_vec())
}

pub(crate) fn length(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap()
}

pub(crate) fn upstream_target() -> SocketAddr {
    SocketAddr::new(UPSTREAM.parse().unwrap(), 443)
}

/// A certificate rcgen made for `names`, and its key.
pub(crate) struct Certified {
    cert: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

pub(crate) fn certificate(names: &[&str]) -> Certified {
    certificate_from(names, "relay-broker test")
}

/// A self-signed certificate for `names` whose subject and issuer is `issuer`.
pub(crate) fn certificate_from(names: &[&str], issuer: &str) -> Certified {
    let mut params = rcgen::CertificateParams::new(
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, issuer);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    Certified {
        cert: cert.der().clone(),
        key: PrivatePkcs8KeyDer::from(key.serialize_der()),
    }
}

/// A TLS 1.3/1.2 server presenting `cert`, offering `alpn` in that order of preference.
pub(crate) fn server_config(cert: &Certified, alpn: &[&[u8]]) -> Arc<ServerConfig> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.clone()],
                PrivateKeyDer::Pkcs8(cert.key.clone_key()),
            )
            .unwrap();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Arc::new(config)
}

/// The broker's TLS configuration trusting `cert` alone.
pub(crate) fn trusting(cert: &Certified) -> UpstreamTls {
    UpstreamTls::with_roots(roots(cert)).unwrap()
}

pub(crate) fn roots(cert: &Certified) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.clone()).unwrap();
    roots
}

/// What the scripted upstream answers after reading the request.
#[derive(Clone)]
pub(crate) enum Reply {
    /// Writes the bytes, then closes (with `close_notify` under TLS).
    Send(Vec<u8>),
    /// Never answers and keeps the connection open.
    Never,
    /// Answers once a permit is released on the semaphore.
    After(Arc<Semaphore>, Vec<u8>),
    /// Waits for the semaphore only when the request contains the marker.
    GatedOn(&'static str, Arc<Semaphore>, Vec<u8>),
}

/// The scripted upstream on the other end of an in-memory stream.
#[derive(Clone)]
pub(crate) enum Upstream {
    Tls {
        config: Arc<ServerConfig>,
        reply: Reply,
    },
    /// A plaintext HTTP server: it answers whatever it receives.
    Plain(Vec<u8>),
}

/// What the scripted upstream saw.
#[derive(Debug, Default)]
pub(crate) struct Seen {
    pub(crate) targets: Vec<SocketAddr>,
    pub(crate) requests: Vec<Vec<u8>>,
    pub(crate) alpn: Vec<Option<Vec<u8>>>,
    pub(crate) handshakes: Vec<Option<HandshakeKind>>,
    /// The first bytes a plaintext server received.
    pub(crate) first_bytes: Vec<Vec<u8>>,
}

/// Connects to the scripted upstream over `tokio::io::duplex`; records every target.
#[derive(Clone)]
pub(crate) struct ScriptedConnector {
    upstream: Upstream,
    pub(crate) seen: Arc<Mutex<Seen>>,
}

impl ScriptedConnector {
    pub(crate) fn new(upstream: Upstream) -> Self {
        Self {
            upstream,
            seen: Arc::default(),
        }
    }

    pub(crate) fn tls(cert: &Certified, reply: Reply) -> Self {
        Self::new(Upstream::Tls {
            config: server_config(cert, &[HTTP_11_ALPN]),
            reply,
        })
    }

    pub(crate) fn seen(&self) -> MutexGuard<'_, Seen> {
        lock(&self.seen)
    }

    pub(crate) fn shared(&self) -> Arc<dyn UpstreamConnector> {
        Arc::new(self.clone())
    }
}

impl UpstreamConnector for ScriptedConnector {
    fn connect(&self, target: SocketAddr) -> BoxFuture<'_, std::io::Result<Box<dyn UpstreamIo>>> {
        let upstream = self.upstream.clone();
        let seen = Arc::clone(&self.seen);
        Box::pin(async move {
            lock(&seen).targets.push(target);
            let (client, server) = tokio::io::duplex(64 * 1024);
            tokio::spawn(serve(upstream, server, seen));
            Ok(Box::new(client) as Box<dyn UpstreamIo>)
        })
    }
}

async fn serve(upstream: Upstream, mut stream: DuplexStream, seen: Arc<Mutex<Seen>>) {
    match upstream {
        Upstream::Tls { config, reply } => {
            let Ok(mut tls) = TlsAcceptor::from(config).accept(stream).await else {
                return;
            };
            {
                let (_, connection) = tls.get_ref();
                let mut seen = lock(&seen);
                seen.alpn
                    .push(connection.alpn_protocol().map(<[u8]>::to_vec));
                seen.handshakes.push(connection.handshake_kind());
            }
            let request = read_request(&mut tls, Vec::new()).await;
            let reply = match reply {
                Reply::GatedOn(marker, gate, bytes) => {
                    if String::from_utf8_lossy(&request).contains(marker) {
                        Reply::After(gate, bytes)
                    } else {
                        Reply::Send(bytes)
                    }
                }
                other => other,
            };
            lock(&seen).requests.push(request);
            answer(&mut tls, reply).await;
        }
        Upstream::Plain(reply) => {
            let mut first = vec![0_u8; 4_096];
            let count = stream.read(&mut first).await.unwrap_or(0);
            first.truncate(count);
            lock(&seen).first_bytes.push(first.clone());
            if first.first() != Some(&0x16) {
                let request = read_request(&mut stream, first).await;
                lock(&seen).requests.push(request);
            }
            answer(&mut stream, Reply::Send(reply)).await;
        }
    }
}

/// Reads one request: the head, then a `content-length` body.
async fn read_request<S: AsyncRead + Unpin>(stream: &mut S, mut bytes: Vec<u8>) -> Vec<u8> {
    let mut buffer = vec![0_u8; 4_096];
    loop {
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
            let body = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .map_or(0, |value| value.trim().parse::<usize>().unwrap());
            if bytes.len() >= end + 4 + body {
                return bytes;
            }
        }
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return bytes,
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
        }
    }
}

async fn answer<S: AsyncWrite + Unpin>(stream: &mut S, reply: Reply) {
    let bytes = match reply {
        Reply::Send(bytes) => bytes,
        Reply::Never => std::future::pending::<Vec<u8>>().await,
        Reply::After(gate, bytes) | Reply::GatedOn(_, gate, bytes) => {
            let _permit = gate.acquire().await.unwrap();
            bytes
        }
    };
    let _ = stream.write_all(&bytes).await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

/// Deadlines short enough for a test that waits on one.
pub(crate) fn short_deadlines() -> UpstreamDeadlines {
    UpstreamDeadlines {
        connect: Duration::from_secs(5),
        handshake: Duration::from_secs(5),
        send: Duration::from_secs(5),
        receive: Duration::from_millis(300),
    }
}

/// Deadlines that no test reaches.
pub(crate) fn patient_deadlines() -> UpstreamDeadlines {
    UpstreamDeadlines {
        connect: Duration::from_secs(20),
        handshake: Duration::from_secs(20),
        send: Duration::from_secs(20),
        receive: Duration::from_secs(20),
    }
}

/// Opens a fresh book's slot for `exchange`.
pub(crate) fn slot(exchange: u64) -> ExchangeSlot {
    ExchangeBook::new().open(ExchangeId::new(exchange)).unwrap()
}

/// The refusal of a refused answer.
pub(crate) fn refusal_of(answer: &ExchangeAnswer) -> BrokerRefusal {
    match answer.outcome() {
        ExchangeOutcome::Refused(refusal) => refusal.clone(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}
