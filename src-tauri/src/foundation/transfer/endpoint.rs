//! Directions, typed endpoints and credential handles of a transfer (S2 CORE-05: no
//! generic privileged URL proxy; S3.7: explicit direction and recipient; INT-08:
//! credential boundaries).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::{Digest, ExecutionId, IdError};

/// Which way the bytes move (S3.7: explicit direction).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// From a registered external origin, such as a model repository, into this host.
    Download,
    /// From this host to a registered external recipient, such as a private-weight upload.
    Upload,
    /// Between this host and an enrolled Yougori peer host, in either direction (GPU-W09).
    Peer,
}

impl Direction {
    pub const ALL: [Self; 3] = [Self::Download, Self::Upload, Self::Peer];

    /// The tag written into the envelope's canonical encoding.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Upload => "upload",
            Self::Peer => "peer",
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// A credential held by the host vault, named by handle (INT-08: credential boundaries).
///
/// The envelope carries the handle and never the secret. The host presents the secret
/// only to the envelope's own registered route, on every attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialRef(Digest);

impl CredentialRef {
    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }
}

/// One end of a transfer, as a typed object (S2 CORE-05: no generic privileged URL
/// proxy).
///
/// No variant holds an address. The host resolves a peer by its enrolment and a route by
/// its own registration, so an envelope can only name ends the host already knows, and
/// a URL cannot be expressed at all.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", try_from = "RawEndpoint")]
pub enum Endpoint {
    /// This host's object catalog, within the envelope's tenant scope.
    HostCatalog,
    /// A sandbox or runtime on this host; an envelope may name only its own parent.
    Execution { execution: ExecutionId },
    /// An enrolled Yougori peer host, named by the digest of its enrolled host key.
    PeerHost { host: Digest },
    /// An external origin or recipient the host registered, named by registration digest.
    NamedRoute { route: Digest },
}

/// The serialized form of an [`Endpoint`], read strictly: exactly the fields of its kind
/// and nothing else. (serde's `deny_unknown_fields` does not reach unit variants of a
/// tagged enum, so the check is written here.)
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEndpoint {
    kind: EndpointKind,
    execution: Option<ExecutionId>,
    host: Option<Digest>,
    route: Option<Digest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum EndpointKind {
    HostCatalog,
    Execution,
    PeerHost,
    NamedRoute,
}

impl TryFrom<RawEndpoint> for Endpoint {
    type Error = EndpointError;

    fn try_from(raw: RawEndpoint) -> Result<Self, Self::Error> {
        match (raw.kind, raw.execution, raw.host, raw.route) {
            (EndpointKind::HostCatalog, None, None, None) => Ok(Self::HostCatalog),
            (EndpointKind::Execution, Some(execution), None, None) => {
                Ok(Self::Execution { execution })
            }
            (EndpointKind::PeerHost, None, Some(host), None) => Ok(Self::PeerHost { host }),
            (EndpointKind::NamedRoute, None, None, Some(route)) => Ok(Self::NamedRoute { route }),
            _ => Err(EndpointError::NotTyped),
        }
    }
}

impl Endpoint {
    /// Whether the end is on this host.
    pub const fn is_local(&self) -> bool {
        matches!(self, Self::HostCatalog | Self::Execution { .. })
    }

    /// Reads the text form: `catalog`, `execution:<id>`, `peer:<64 hex>` or
    /// `route:<64 hex>`. Anything else, and in particular any URL, is refused.
    pub fn parse(text: &str) -> Result<Self, EndpointError> {
        if looks_like_url(text) {
            return Err(EndpointError::UrlNotAccepted);
        }
        if text == "catalog" {
            return Ok(Self::HostCatalog);
        }
        let Some((kind, value)) = text.split_once(':') else {
            return Err(EndpointError::NotTyped);
        };
        match kind {
            "execution" => ExecutionId::new(value)
                .map(|execution| Self::Execution { execution })
                .map_err(EndpointError::InvalidExecution),
            "peer" => Digest::from_hex(value)
                .map(|host| Self::PeerHost { host })
                .map_err(|_| EndpointError::InvalidDigest),
            "route" => Digest::from_hex(value)
                .map(|route| Self::NamedRoute { route })
                .map_err(|_| EndpointError::InvalidDigest),
            _ => Err(EndpointError::NotTyped),
        }
    }
}

impl FromStr for Endpoint {
    type Err = EndpointError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostCatalog => f.write_str("catalog"),
            Self::Execution { execution } => write!(f, "execution:{execution}"),
            Self::PeerHost { host } => write!(f, "peer:{host}"),
            Self::NamedRoute { route } => write!(f, "route:{route}"),
        }
    }
}

/// Why endpoint text was refused. The refused text is not echoed, since a URL can carry
/// a secret in its query or user part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointError {
    /// The text is URL-shaped (CORE-05: no generic URL authority).
    UrlNotAccepted,
    /// The text is not one of the typed endpoint forms.
    NotTyped,
    InvalidExecution(IdError),
    /// A peer host or route is named by 64 hexadecimal characters.
    InvalidDigest,
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UrlNotAccepted => f.write_str(
                "a transfer endpoint is a typed object, never a URL; name the host catalog, the \
                 parent execution, an enrolled peer host or a route the host registered",
            ),
            Self::NotTyped => f.write_str(
                "use catalog, execution:<id>, peer:<host key digest> or route:<route digest>",
            ),
            Self::InvalidExecution(error) => write!(f, "invalid execution: {error}"),
            Self::InvalidDigest => {
                f.write_str("a peer host or route digest is 64 hexadecimal characters")
            }
        }
    }
}

impl std::error::Error for EndpointError {}

/// URL-shaped: a `//` authority, a path, query, fragment or user part, or a scheme other
/// than the typed endpoint kinds. Typed forms contain none of these characters, since
/// identifiers and digests cannot.
fn looks_like_url(text: &str) -> bool {
    if text.contains("//")
        || text
            .chars()
            .any(|character| matches!(character, '/' | '\\' | '?' | '#' | '@'))
    {
        return true;
    }
    match text.split_once(':') {
        Some((scheme, _)) => is_scheme(scheme) && !matches!(scheme, "execution" | "peer" | "route"),
        None => false,
    }
}

fn is_scheme(text: &str) -> bool {
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
}

/// What one attempt actually connects, as the transfer executor states it: the
/// authenticated source and recipient and the credential it presents. The session
/// compares it with the envelope at the start of every attempt (INT-08).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    pub source: Endpoint,
    pub recipient: Endpoint,
    pub credential: Option<CredentialRef>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    fn route() -> Endpoint {
        Endpoint::NamedRoute {
            route: digest("yougori/test/route/v1", &[b"model-hub"]),
        }
    }

    #[test]
    fn typed_forms_round_trip_through_text() {
        let peer = Endpoint::PeerHost {
            host: digest("yougori/test/peer/v1", &[b"donor"]),
        };
        let execution = Endpoint::Execution {
            execution: ExecutionId::new("exe-parent").unwrap(),
        };
        for endpoint in [Endpoint::HostCatalog, execution, peer, route()] {
            assert_eq!(Endpoint::parse(&endpoint.to_string()), Ok(endpoint.clone()));
            assert_eq!(endpoint.to_string().parse::<Endpoint>(), Ok(endpoint));
        }
        assert!(Endpoint::HostCatalog.is_local());
        assert!(!route().is_local());
    }

    #[test]
    fn text_that_is_not_a_typed_form_is_refused() {
        assert_eq!(Endpoint::parse(""), Err(EndpointError::NotTyped));
        assert_eq!(Endpoint::parse("host"), Err(EndpointError::NotTyped));
        assert_eq!(Endpoint::parse("Catalog"), Err(EndpointError::NotTyped));
        assert_eq!(
            Endpoint::parse("peer:abc"),
            Err(EndpointError::InvalidDigest)
        );
        assert_eq!(
            Endpoint::parse("execution:-x"),
            Err(EndpointError::InvalidExecution(IdError::InvalidStart))
        );
    }

    #[test]
    fn serde_uses_the_tagged_form_only() {
        let json = serde_json::to_value(route()).unwrap();
        assert_eq!(json["kind"], "named_route");
        assert_eq!(serde_json::from_value::<Endpoint>(json).unwrap(), route());
        assert_eq!(
            serde_json::to_value(Endpoint::HostCatalog).unwrap(),
            serde_json::json!({"kind": "host_catalog"})
        );
        let host = "0".repeat(64);
        for refused in [
            r#"{"kind":"host_catalog","x":1}"#.to_owned(),
            format!(r#"{{"kind":"host_catalog","route":"{host}"}}"#),
            format!(r#"{{"kind":"peer_host","host":"{host}","route":"{host}"}}"#),
            r#"{"kind":"peer_host"}"#.to_owned(),
            r#"{"kind":"execution","execution":"exe-parent","url":"x"}"#.to_owned(),
            r#"{"execution":"exe-parent"}"#.to_owned(),
            r#""catalog""#.to_owned(),
        ] {
            assert!(
                serde_json::from_str::<Endpoint>(&refused).is_err(),
                "{refused}"
            );
        }
        assert_eq!(
            serde_json::from_str::<Endpoint>(&format!(r#"{{"kind":"peer_host","host":"{host}"}}"#))
                .unwrap(),
            Endpoint::PeerHost {
                host: Digest::from_bytes([0; 32])
            }
        );
    }
}
