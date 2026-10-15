//! The hub's own certificate, pinned by every member, and HTTPS on private addresses only.
use bytes::Bytes;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::{body::Incoming, Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    },
    TlsConnector,
};

pub const DEFAULT_PORT: u16 = 7460;

pub(crate) type Body = UnsyncBoxBody<Bytes, std::io::Error>;

pub(crate) fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into()).map_err(|never| match never {}).boxed_unsync()
}

/// LAN and VPN addresses only, as for LAN sharing.
pub fn private(address: IpAddr) -> bool {
    let v4 = |a: std::net::Ipv4Addr| a.is_private() || a.is_loopback() || a.is_link_local();
    match address {
        IpAddr::V4(a) => v4(a),
        IpAddr::V6(a) => a.is_loopback() || a.is_unique_local() || a.to_ipv4_mapped().is_some_and(v4),
    }
}

/// A DNS name company apps may use for the hub besides its IP address.
pub fn valid_hostname(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
        && name.parse::<IpAddr>().is_err()
}

/// The hub's certificate (PEM) and private key (PKCS#8 DER as hex, one line for the OS vault).
pub struct Identity {
    pub certificate: String,
    pub key: String,
}

pub fn new_identity(address: IpAddr, hostname: Option<&str>) -> Result<Identity, String> {
    let mut names = vec![address.to_string()];
    names.extend(hostname.map(str::to_owned));
    let issued = rcgen::generate_simple_self_signed(names).map_err(|error| format!("Cannot create the grid certificate: {error}"))?;
    Ok(Identity { certificate: issued.cert.pem(), key: hex::encode(issued.signing_key.serialize_der()) })
}

pub fn certificate_der(pem: &str) -> Result<CertificateDer<'static>, String> {
    if pem.len() > 8192 {
        return Err("The grid certificate is too large".into());
    }
    CertificateDer::from_pem_slice(pem.as_bytes()).map_err(|_| "Invalid grid certificate".to_owned())
}

/// SHA-256 of the certificate, for comparing out of band: `AB:CD:…`.
pub fn fingerprint(pem: &str) -> Result<String, String> {
    Ok(fingerprint_der(&certificate_der(pem)?))
}

pub fn fingerprint_der(der: &[u8]) -> String {
    Sha256::digest(der).iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(":")
}

/// Accepts `ab:cd…`, `AB CD …` or plain hex; compares as `AB:CD:…`.
pub fn normalize_fingerprint(text: &str) -> Option<String> {
    let hex: String = text.chars().filter(|c| !matches!(c, ':' | ' ' | '-')).collect::<String>().to_ascii_uppercase();
    (hex.len() == 64 && hex.bytes().all(|c| c.is_ascii_hexdigit())).then(|| hex.as_bytes().chunks(2).map(|pair| String::from_utf8_lossy(pair).into_owned()).collect::<Vec<_>>().join(":"))
}

pub fn certificate_pem(der: &[u8]) -> String {
    use base64::Engine;
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let lines = text.as_bytes().chunks(64).map(|line| format!("{}\n", String::from_utf8_lossy(line))).collect::<String>();
    format!("-----BEGIN CERTIFICATE-----\n{lines}-----END CERTIFICATE-----\n")
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Seen while joining, before the hub has proven that it knows the company password.
pub(crate) type Seen = Arc<std::sync::Mutex<Option<CertificateDer<'static>>>>;

/// Remembers the certificate the hub presents without trusting it yet. The handshake's
/// signature is still checked, so the hub must hold that certificate's private key.
#[derive(Debug)]
struct Capture {
    seen: Seen,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        *self.seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(end_entity.clone().into_owned());
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub(crate) fn capturing_config() -> Result<(Arc<rustls::ClientConfig>, Seen), String> {
    let seen = Seen::default();
    let config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Capture { seen: seen.clone(), provider: provider() }))
        .with_no_client_auth();
    Ok((Arc::new(config), seen))
}

pub(crate) fn server_config(identity: &Identity) -> Result<Arc<rustls::ServerConfig>, String> {
    let key = hex::decode(identity.key.trim()).map_err(|_| "The grid hub's private key is damaged")?;
    let config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der(&identity.certificate)?], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
        .map_err(|_| "The grid hub's certificate does not match its private key".to_owned())?;
    Ok(Arc::new(config))
}

/// Trusts exactly the hub's certificate and nothing else.
pub fn client_config(certificate: &str) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate_der(certificate)?).map_err(|_| "Invalid grid certificate")?;
    let config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// One request on a fresh pinned-TLS connection to the hub. `wait` bounds the time until
/// the response headers arrive; the body is read by the caller.
pub(crate) async fn send<B>(address: SocketAddr, tls: &Arc<rustls::ClientConfig>, mut request: Request<B>, wait: Duration) -> Result<Response<Incoming>, String>
where
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let unreachable = || format!("Cannot reach the grid hub at {address}, or its certificate changed. Check that the hub computer is on and on this network.");
    let socket = tokio::time::timeout(Duration::from_secs(8), tokio::net::TcpStream::connect(address)).await.map_err(|_| unreachable())?.map_err(|_| unreachable())?;
    let name = ServerName::IpAddress(address.ip().into());
    let stream = tokio::time::timeout(Duration::from_secs(8), TlsConnector::from(tls.clone()).connect(name, socket)).await.map_err(|_| unreachable())?.map_err(|_| unreachable())?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|_| unreachable())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    request.headers_mut().insert(hyper::header::HOST, address.to_string().parse().map_err(|_| unreachable())?);
    tokio::time::timeout(wait, sender.send_request(request))
        .await
        .map_err(|_| "The grid hub did not answer in time".to_owned())?
        .map_err(|_| unreachable())
}

/// Reads a bounded JSON body; an empty body is `null`.
pub(crate) async fn json_body(body: Incoming, limit: usize) -> Result<Value, String> {
    let bytes = http_body_util::Limited::new(body, limit)
        .collect()
        .await
        .map_err(|_| format!("The request body exceeds {} KiB or was interrupted", limit / 1024))?
        .to_bytes();
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&bytes).map_err(|_| "The request body must be JSON".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_private_addresses_and_real_hostnames_are_accepted() {
        for address in ["10.0.0.5", "192.168.1.2", "172.16.4.1", "127.0.0.1", "169.254.1.1", "fd00::1", "::1", "::ffff:10.0.0.1"] {
            assert!(private(address.parse().unwrap()), "{address}");
        }
        for address in ["8.8.8.8", "100.64.0.1", "2001:db8::1", "0.0.0.0", "::ffff:8.8.8.8"] {
            assert!(!private(address.parse().unwrap()), "{address}");
        }
        assert!(valid_hostname("grid.acme.internal") && valid_hostname("hub"));
        assert!(!valid_hostname("-bad.example") && !valid_hostname("a..b") && !valid_hostname("10.0.0.5") && !valid_hostname("has space"));
    }
    #[test]
    fn identities_load_into_tls_and_have_stable_fingerprints() {
        let identity = new_identity("10.0.0.5".parse().unwrap(), Some("grid.acme.internal")).unwrap();
        server_config(&identity).unwrap();
        client_config(&identity.certificate).unwrap();
        let print = fingerprint(&identity.certificate).unwrap();
        assert_eq!(print.len(), 32 * 3 - 1);
        assert_eq!(print, fingerprint(&identity.certificate).unwrap());
        let other = new_identity("10.0.0.5".parse().unwrap(), None).unwrap();
        assert!(server_config(&Identity { certificate: identity.certificate, key: other.key }).is_err());
        assert!(certificate_der("not a certificate").is_err());
    }
    #[test]
    fn certificates_round_trip_and_fingerprints_normalize() {
        let identity = new_identity("10.0.0.5".parse().unwrap(), None).unwrap();
        let der = certificate_der(&identity.certificate).unwrap();
        let pem = certificate_pem(&der);
        assert_eq!(certificate_der(&pem).unwrap(), der);
        let print = fingerprint(&identity.certificate).unwrap();
        assert_eq!(fingerprint_der(&der), print);
        assert_eq!(normalize_fingerprint(&print.to_lowercase()).as_deref(), Some(print.as_str()));
        assert_eq!(normalize_fingerprint(&print.replace(':', " ")).as_deref(), Some(print.as_str()));
        assert_eq!(normalize_fingerprint("AB:CD"), None);
    }
}
