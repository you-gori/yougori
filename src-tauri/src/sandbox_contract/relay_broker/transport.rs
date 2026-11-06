//! The upstream transport: thin and async over the sans-IO [`BrokerExchange`] (VM part
//! §4.3: strict operation routes terminate TLS at the credential executor; VM §4.2 step
//! 5: TLS is verified for the authorized name, never an alias; VM-W11).
//!
//! [`UpstreamTransport::run`] takes an admitted exchange and its [`UpstreamPlan`] and:
//!
//! - connects through the [`UpstreamConnector`] port to the plan's target, which is the
//!   [`ConnectionPermit`](crate::sandbox_contract::destinations::ConnectionPermit)'s
//!   address and port and nothing resolved from guest input ([`TcpConnector`] for the
//!   host; the tests use in-memory streams);
//! - on a TLS route, runs the handshake with `tokio-rustls` under [`UpstreamTls`]: the
//!   `ring` provider, TLS 1.3 or 1.2, the authorized destination's name as the server
//!   name, ALPN offering `http/1.1` alone (any other negotiated protocol is refused), and
//!   session resumption off, so no TLS session carries over between exchanges, let alone
//!   sandboxes. Roots come from the operating system through `rustls-platform-verifier`
//!   ([`UpstreamTls::platform`]) or from the caller ([`UpstreamTls::with_roots`]);
//! - writes the exact plan bytes, counting what the stream accepted, and settles the send
//!   with that count;
//! - reads the response into the exchange's response step until it is complete or the
//!   upstream closes, then drops the connection: one response, no keep-alive, no
//!   pipelining;
//! - bounds each stage by its [`UpstreamDeadlines`].
//!
//! The exchange always ends in exactly one answer. If the future is dropped first (the
//! link loop stopping), a guard settles every open reservation in the shared broker as a
//! [`BrokerRefusal::Cancelled`] failure.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_util::future::BoxFuture;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use tokio_rustls::rustls::client::Resumption;
use tokio_rustls::rustls::client::WantsClientCert;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{
    self, AlertDescription, CertificateError, ClientConfig, ConfigBuilder, RootCertStore,
};
use tokio_rustls::TlsConnector;

use super::exchange::{
    BrokerExchange, ExchangeAnswer, ExchangeSlot, TlsName, UpstreamPlan, UpstreamSecurity,
};
use super::refusal::{BrokerRefusal, TlsFailure, UpstreamFailure, UpstreamStage};
use crate::foundation::ids::Clock;
use crate::sandbox_contract::destinations::DestinationBroker;
use crate::sandbox_contract::relay::ReadProgress;
use crate::sandbox_contract::relay_link::ExchangeId;

/// The one application protocol offered upstream.
pub const HTTP_11_ALPN: &[u8] = b"http/1.1";

/// The most bytes one read from the upstream takes.
const READ_CHUNK_BYTES: usize = 16 * 1024;

/// A sandbox's destination broker, shared by its concurrent exchanges. It is locked only
/// between awaits, never across one.
pub type SharedBroker<C> = Arc<Mutex<DestinationBroker<C>>>;

/// Locks the shared broker; a poisoned lock is taken over, since every settlement must
/// still happen.
pub fn lock_broker<C: Clock>(broker: &SharedBroker<C>) -> MutexGuard<'_, DestinationBroker<C>> {
    broker.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A byte stream to the upstream.
pub trait UpstreamIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> UpstreamIo for T {}

/// Opens a connection to exactly one address and port. The host perimeter (M10) decides
/// how the host's connector reaches it; the tests use in-memory streams.
pub trait UpstreamConnector: Send + Sync {
    fn connect(&self, target: SocketAddr) -> BoxFuture<'_, io::Result<Box<dyn UpstreamIo>>>;
}

/// The host's direct TCP connector: one connection to the permit's address and port.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpConnector;

impl UpstreamConnector for TcpConnector {
    fn connect(&self, target: SocketAddr) -> BoxFuture<'_, io::Result<Box<dyn UpstreamIo>>> {
        Box::pin(async move {
            let stream = tokio::net::TcpStream::connect(target).await?;
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as Box<dyn UpstreamIo>)
        })
    }
}

/// Why a TLS client configuration could not be built.
#[derive(Clone, Debug, PartialEq)]
pub struct TlsSetupError(rustls::Error);

impl fmt::Display for TlsSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the upstream TLS configuration could not be built: {}",
            self.0
        )
    }
}

impl std::error::Error for TlsSetupError {}

/// The upstream TLS client configuration of one sandbox (see the module notes).
#[derive(Clone)]
pub struct UpstreamTls {
    config: Arc<ClientConfig>,
}

impl fmt::Debug for UpstreamTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamTls")
            .field("alpn", &self.config.alpn_protocols)
            .finish_non_exhaustive()
    }
}

impl UpstreamTls {
    /// Verifies certificates with the operating system's verifier.
    pub fn platform() -> Result<Self, TlsSetupError> {
        let builder = builder()?.with_platform_verifier().map_err(TlsSetupError)?;
        Ok(Self::finish(builder))
    }

    /// Trusts exactly `roots`.
    pub fn with_roots(roots: RootCertStore) -> Result<Self, TlsSetupError> {
        Ok(Self::finish(builder()?.with_root_certificates(roots)))
    }

    fn finish(builder: ConfigBuilder<ClientConfig, WantsClientCert>) -> Self {
        let mut config = builder.with_no_client_auth();
        config.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
        config.resumption = Resumption::disabled();
        config.enable_early_data = false;
        Self {
            config: Arc::new(config),
        }
    }

    /// The configuration, for inspection.
    pub fn client_config(&self) -> &ClientConfig {
        &self.config
    }
}

fn builder() -> Result<ConfigBuilder<ClientConfig, rustls::WantsVerifier>, TlsSetupError> {
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(TlsSetupError)
}

/// The longest each stage of an upstream exchange may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UpstreamDeadlines {
    pub connect: Duration,
    pub handshake: Duration,
    /// Writing the whole request.
    pub send: Duration,
    /// Reading the whole response.
    pub receive: Duration,
}

impl Default for UpstreamDeadlines {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            handshake: Duration::from_secs(10),
            send: Duration::from_secs(30),
            receive: Duration::from_secs(60),
        }
    }
}

/// Connects, talks TLS, sends and receives for admitted exchanges (see the module notes).
pub struct UpstreamTransport {
    connector: Arc<dyn UpstreamConnector>,
    tls: UpstreamTls,
    deadlines: UpstreamDeadlines,
}

impl fmt::Debug for UpstreamTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamTransport")
            .field("tls", &self.tls)
            .field("deadlines", &self.deadlines)
            .finish_non_exhaustive()
    }
}

impl UpstreamTransport {
    pub fn new(
        connector: Arc<dyn UpstreamConnector>,
        tls: UpstreamTls,
        deadlines: UpstreamDeadlines,
    ) -> Self {
        Self {
            connector,
            tls,
            deadlines,
        }
    }

    pub const fn deadlines(&self) -> UpstreamDeadlines {
        self.deadlines
    }

    /// Runs one admitted exchange to its one answer.
    pub async fn run<C: Clock>(
        &self,
        broker: &SharedBroker<C>,
        exchange: BrokerExchange,
        plan: UpstreamPlan,
    ) -> ExchangeAnswer {
        let mut flight = Flight {
            id: exchange.exchange(),
            broker: Arc::clone(broker),
            exchange: Some(exchange),
        };
        let result = self.drive(&mut flight, &plan).await;
        flight.end(result)
    }

    async fn drive<C: Clock>(
        &self,
        flight: &mut Flight<C>,
        plan: &UpstreamPlan,
    ) -> Result<(), BrokerRefusal> {
        let stream = timeout(
            self.deadlines.connect,
            self.connector.connect(plan.target()),
        )
        .await
        .map_err(|_| timed_out(UpstreamStage::Connect))?
        .map_err(|error| io_failure(UpstreamStage::Connect, &error))?;
        match plan.security() {
            UpstreamSecurity::Plaintext => self.exchange_over(flight, stream, plan).await,
            UpstreamSecurity::Tls(name) => {
                let connector = TlsConnector::from(Arc::clone(&self.tls.config));
                let tls = timeout(
                    self.deadlines.handshake,
                    connector.connect(server_name(name)?, stream),
                )
                .await
                .map_err(|_| timed_out(UpstreamStage::Handshake))?
                .map_err(|error| handshake_failure(&error))?;
                match tls.get_ref().1.alpn_protocol() {
                    None | Some(HTTP_11_ALPN) => {}
                    Some(other) => {
                        return Err(UpstreamFailure::NotHttp11 {
                            negotiated: String::from_utf8_lossy(other).into_owned(),
                        }
                        .into())
                    }
                }
                self.exchange_over(flight, tls, plan).await
            }
        }
    }

    /// Sends the request and reads one response over an established stream, then drops
    /// the stream.
    async fn exchange_over<C: Clock, S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        flight: &mut Flight<C>,
        mut stream: S,
        plan: &UpstreamPlan,
    ) -> Result<(), BrokerRefusal> {
        let bytes = plan.request().expose_to_transport();
        let mut written = 0_usize;
        let sent = timeout(
            self.deadlines.send,
            write_counted(&mut stream, bytes, &mut written),
        )
        .await;
        let left = u64::try_from(written).unwrap_or(u64::MAX);
        let settled = flight.step(|exchange, broker| exchange.record_sent(broker, left));
        match sent {
            Err(_) => return Err(timed_out(UpstreamStage::Send)),
            Ok(Err(error)) => return Err(io_failure(UpstreamStage::Send, &error)),
            Ok(Ok(())) => settled?,
        }
        timeout(self.deadlines.receive, read_response(flight, &mut stream))
            .await
            .map_err(|_| timed_out(UpstreamStage::Receive))?
    }
}

/// Writes `bytes`, counting in `written` what the stream accepted, then flushes.
async fn write_counted<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
    written: &mut usize,
) -> io::Result<()> {
    while let Some(rest) = bytes.get(*written..).filter(|rest| !rest.is_empty()) {
        let count = stream.write(rest).await?;
        if count == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        *written = written.saturating_add(count);
    }
    stream.flush().await
}

/// Feeds the upstream's bytes to the exchange until the response is complete or the
/// upstream closes.
async fn read_response<C: Clock, S: AsyncRead + Unpin>(
    flight: &mut Flight<C>,
    stream: &mut S,
) -> Result<(), BrokerRefusal> {
    let mut buffer = vec![0_u8; READ_CHUNK_BYTES];
    loop {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|error| io_failure(UpstreamStage::Receive, &error))?;
        if count == 0 {
            flight.step(|exchange, broker| exchange.end_of_input(broker))?;
            return Ok(());
        }
        let input = buffer.get(..count).unwrap_or_default();
        if flight.step(|exchange, broker| exchange.feed(broker, input))? == ReadProgress::Complete {
            return Ok(());
        }
    }
}

fn timed_out(stage: UpstreamStage) -> BrokerRefusal {
    UpstreamFailure::TimedOut { stage }.into()
}

fn io_failure(stage: UpstreamStage, error: &io::Error) -> BrokerRefusal {
    match error.kind() {
        io::ErrorKind::WriteZero
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::UnexpectedEof => UpstreamFailure::ClosedEarly { stage }.into(),
        kind => UpstreamFailure::Io { stage, kind }.into(),
    }
}

fn server_name(name: &TlsName) -> Result<ServerName<'static>, BrokerRefusal> {
    match name {
        TlsName::Dns(name) => ServerName::try_from(name.to_string())
            .map_err(|_| UpstreamFailure::InvalidServerName.into()),
        TlsName::Address(address) => Ok(ServerName::IpAddress((*address).into())),
    }
}

/// Classifies a failed handshake by the TLS error inside it.
fn handshake_failure(error: &io::Error) -> BrokerRefusal {
    let tls = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    let failure = match tls {
        Some(rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
        )) => TlsFailure::CertificateNameMismatch,
        Some(rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)) => {
            TlsFailure::UntrustedCertificate
        }
        Some(rustls::Error::InvalidCertificate(_)) => TlsFailure::InvalidCertificate,
        Some(
            rustls::Error::NoApplicationProtocol
            | rustls::Error::AlertReceived(AlertDescription::NoApplicationProtocol),
        ) => TlsFailure::NoApplicationProtocol,
        Some(rustls::Error::AlertReceived(_)) => TlsFailure::Alert,
        Some(rustls::Error::PeerIncompatible(_)) => TlsFailure::Incompatible,
        Some(_) => TlsFailure::Other,
        None => return io_failure(UpstreamStage::Handshake, error),
    };
    UpstreamFailure::Tls(failure).into()
}

/// An exchange in flight. Dropped before it ends, it settles every open reservation.
struct Flight<C: Clock> {
    id: ExchangeId,
    broker: SharedBroker<C>,
    exchange: Option<BrokerExchange>,
}

impl<C: Clock> Flight<C> {
    /// Runs one step of the exchange with the broker locked for that step only.
    fn step<R>(
        &mut self,
        step: impl FnOnce(&mut BrokerExchange, &mut DestinationBroker<C>) -> Result<R, BrokerRefusal>,
    ) -> Result<R, BrokerRefusal> {
        let exchange = self.exchange.as_mut().ok_or(BrokerRefusal::Cancelled)?;
        step(exchange, &mut lock_broker(&self.broker))
    }

    /// Ends the exchange with its one answer.
    fn end(mut self, result: Result<(), BrokerRefusal>) -> ExchangeAnswer {
        let Some(exchange) = self.exchange.take() else {
            // Not reachable: only `end` and `drop` take the exchange.
            return ExchangeAnswer::refused(
                ExchangeSlot::closed(self.id),
                BrokerRefusal::Cancelled,
            );
        };
        let mut broker = lock_broker(&self.broker);
        match result {
            Ok(()) => exchange.complete(&mut broker),
            Err(refusal) => exchange.fail(&mut broker, refusal),
        }
    }
}

impl<C: Clock> Drop for Flight<C> {
    fn drop(&mut self) {
        if let Some(exchange) = self.exchange.take() {
            // Nobody waits for the answer; the settlement is what matters.
            let _ = exchange.fail(&mut lock_broker(&self.broker), BrokerRefusal::Cancelled);
        }
    }
}
