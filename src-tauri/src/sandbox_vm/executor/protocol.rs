//! The control protocol between the engine and its sandbox executor process (module docs in
//! `mod.rs`): one JSON line per message over the control pipe, strict on both sides, each
//! request answered by exactly one reply in order. No guest byte crosses it. A credential
//! crosses it once, at enrollment, from the engine's transient copy to the executor's
//! store; at use the executor reads its own store and nothing of the value comes back.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::{digest, Digest, ExecutionId};
use crate::foundation::process::ProcessIdentity;
use crate::sandbox_contract::effects::SecretClass;
use crate::sandbox_contract::relay_host::{RelayLifeSummary, RelayStatus, StopReason};
use crate::sandbox_contract::response::{HostObserver, ViolationKind};
use crate::sandbox_contract::vault::ValueForm;

/// The protocol version both ends must speak.
pub const PROTOCOL_VERSION: u32 = 1;

/// The most refused exchanges one poll's reply carries; the rest wait for the next poll.
pub const MAX_REFUSALS_PER_POLL: usize = 256;
/// The longest statement of a refusal carried, in bytes, cut at a character boundary.
pub const MAX_REFUSAL_DETAIL_BYTES: usize = 240;

/// One refused exchange of a running relay, classified by the executor for the engine's
/// response path (`signals::classify_broker_refusal`). It names the sandbox, the route and
/// the exchange; never a request or response byte and never a credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusedExchange {
    pub sandbox: ExecutionId,
    pub route: String,
    pub exchange: u64,
    pub class: RefusalClass,
    /// The broker's statement of the refusal, at most [`MAX_REFUSAL_DETAIL_BYTES`].
    pub detail: String,
}

/// How a refused exchange reads for the response path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case", deny_unknown_fields)]
pub enum RefusalClass {
    /// A guest violation a host observer saw (V14): the engine's responder decides.
    Violation {
        kind: ViolationKind,
        observer: HostObserver,
    },
    /// The confined relay forwarded what the broker's own rebuild or book contradicts.
    RelayProtocol,
    /// An ordinary refusal, by its reason's label (`signals::Ordinary::label`).
    Ordinary { reason: String },
}

/// The longest line either side accepts.
pub const MAX_LINE_BYTES: usize = 256 * 1024;

/// The digest domain a credential's name is turned into its vault reference with.
pub const CREDENTIAL_REFERENCE_DOMAIN: &str = "yougori/sandbox-vm/credential/v1";

/// The digest domain a credential's name is turned into its provider account with.
pub const ACCOUNT_REFERENCE_DOMAIN: &str = "yougori/sandbox-vm/credential-account/v1";

/// The vault reference of the credential called `name`.
pub fn credential_reference(name: &str) -> Digest {
    digest(CREDENTIAL_REFERENCE_DOMAIN, &[name.as_bytes()])
}

/// The provider account the credential called `name` stands for.
pub fn account_reference(name: &str) -> Digest {
    digest(ACCOUNT_REFERENCE_DOMAIN, &[name.as_bytes()])
}

/// How a route's requests carry the credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialHeaderDecl {
    /// `authorization: <value>` (the vault composes the value as the entry says, `Bearer`
    /// and the secret or the secret alone).
    Authorization,
    ProxyAuthorization,
    Cookie,
}

/// One operation of a declared route, in V02's terms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationDecl {
    /// The operation's name in the provider's contract (an identifier).
    pub name: String,
    /// `GET`, `POST`, `PUT`, `PATCH` or `DELETE`.
    pub method: String,
    /// The path template, such as `/v1/messages`.
    pub path: String,
    /// The query keys the operation accepts.
    #[serde(default)]
    pub query_keys: BTreeSet<String>,
    /// `read_only` or `external`.
    pub effect: EffectDecl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectDecl {
    ReadOnly,
    External,
}

/// How names of the route resolve.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "resolver", rename_all = "snake_case")]
pub enum ResolverDecl {
    /// The host's own resolver (`std::net::ToSocketAddrs`).
    System,
    /// Fixed addresses (tests and pinned deployments); the TLS name check still applies.
    Fixed { addresses: Vec<std::net::IpAddr> },
}

/// The credential a route carries, by the name it was enrolled under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialDecl {
    /// The name the credential was enrolled under (`credential enroll`).
    pub name: String,
    #[serde(default = "default_header")]
    pub header: CredentialHeaderDecl,
    /// The provider the operations belong to (an identifier).
    pub provider: String,
    #[serde(default = "default_contract_version")]
    pub contract_version: u32,
}

fn default_header() -> CredentialHeaderDecl {
    CredentialHeaderDecl::Authorization
}

fn default_contract_version() -> u32 {
    1
}

/// The budgets of a route, in V02's terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetsDecl {
    pub dns_queries: u64,
    pub connections: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub effects: u64,
}

impl Default for BudgetsDecl {
    fn default() -> Self {
        Self {
            dns_queries: 64,
            connections: 64,
            bytes_out: 8 << 20,
            bytes_in: 64 << 20,
            effects: 256,
        }
    }
}

/// One declared route: what the guest may reach by name, how, and with which credential
/// (the executor builds V02's policy and the broker from it; the guest never sees it).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteDeclaration {
    /// The route's id and the guest-facing endpoint name (an identifier).
    pub name: String,
    /// The exact destination host name.
    pub host: String,
    /// The destination port, 443 unless declared.
    #[serde(default = "default_port")]
    pub port: u16,
    pub operations: Vec<OperationDecl>,
    #[serde(default)]
    pub credential: Option<CredentialDecl>,
    #[serde(default)]
    pub resolver: Option<ResolverDecl>,
    #[serde(default)]
    pub budgets: BudgetsDecl,
    /// Plaintext HTTP upstream, for tests and local development only; refused with a
    /// credential.
    #[serde(default)]
    pub plaintext: bool,
}

fn default_port() -> u16 {
    443
}

/// A request from the engine to the executor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutorRequest {
    /// The first message: the versions must match.
    Hello {
        version: u32,
        engine_pid: u32,
    },
    /// Starts one sandbox's relay for the declared routes; the relay opens the guest pipe
    /// the reply names, which the engine serves.
    StartRelay {
        sandbox: ExecutionId,
        routes: Vec<RouteDeclaration>,
    },
    StopRelay {
        sandbox: ExecutionId,
        reason: StopReason,
    },
    /// Relays that ended on their own since the last poll.
    Poll,
    Status {
        sandbox: ExecutionId,
    },
    /// Stores or rotates a credential in the executor's vault store. The value crosses the
    /// control pipe here and nowhere else.
    Enroll {
        name: String,
        class: SecretClass,
        form: ValueForm,
        /// The secret, hex.
        secret_hex: String,
    },
    Remove {
        name: String,
    },
    Holds {
        name: String,
    },
    Shutdown,
    /// Acceptance builds only: the next refused exchange on `route` of `sandbox`'s relay is
    /// reported as a perimeter violation (once), so the engine's response path runs from a
    /// refusal the guest really causes.
    #[cfg(feature = "acceptance")]
    MarkNextRefusal {
        sandbox: ExecutionId,
        route: String,
    },
}

/// The executor's reply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutorReply {
    Hello {
        version: u32,
        executor: ProcessIdentity,
    },
    RelayStarted {
        sandbox: ExecutionId,
        relay: ProcessIdentity,
        /// The relay's AppContainer SID, hex, for the guest pipe's DACL.
        container_sid: String,
        /// The guest pipe's name the relay opens.
        guest_pipe: String,
        /// The routes that carry a credential.
        credentialed_routes: Vec<String>,
        /// How many of the host's own addresses the policy refuses as destinations (the
        /// loopback addresses and the interface inventory).
        host_addresses: usize,
        /// Why the interface inventory could not be read, when it could not (the loopback
        /// addresses alone are then refused by the policy).
        host_inventory_error: Option<String>,
    },
    RelayStopped {
        sandbox: ExecutionId,
        life: Option<RelayLifeSummary>,
    },
    Ended {
        lives: Vec<RelayLifeSummary>,
        /// The refused exchanges since the last poll, at most [`MAX_REFUSALS_PER_POLL`].
        #[serde(default)]
        refusals: Vec<RefusedExchange>,
        /// The refusals the executor's bounded queue could not keep since the last poll.
        #[serde(default)]
        refusals_dropped: u64,
    },
    Status {
        sandbox: ExecutionId,
        relay: Option<RelayStatus>,
    },
    Enrolled {
        name: String,
        version: u32,
    },
    Removed {
        name: String,
        existed: bool,
    },
    Holds {
        name: String,
        held: bool,
    },
    Refused {
        detail: String,
    },
    ShuttingDown {
        stopped: usize,
    },
    /// Acceptance builds only: the mark is kept.
    #[cfg(feature = "acceptance")]
    Marked {
        sandbox: ExecutionId,
        route: String,
    },
}

/// Why a line could not be encoded or decoded.
#[derive(Debug)]
pub enum LineError {
    /// The line is longer than [`MAX_LINE_BYTES`].
    TooLong,
    Malformed(String),
}

impl fmt::Display for LineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(f, "a control line is longer than {MAX_LINE_BYTES} bytes"),
            Self::Malformed(detail) => write!(f, "a control line is malformed: {detail}"),
        }
    }
}

impl std::error::Error for LineError {}

/// Encodes one message as a line.
pub fn encode_line<T: Serialize>(message: &T) -> Result<Vec<u8>, LineError> {
    let mut line =
        serde_json::to_vec(message).map_err(|error| LineError::Malformed(error.to_string()))?;
    if line.len() >= MAX_LINE_BYTES {
        return Err(LineError::TooLong);
    }
    line.push(b'\n');
    Ok(line)
}

/// Decodes one line, without its newline.
pub fn decode_line<T: for<'de> Deserialize<'de>>(line: &[u8]) -> Result<T, LineError> {
    if line.len() >= MAX_LINE_BYTES {
        return Err(LineError::TooLong);
    }
    serde_json::from_slice(line).map_err(|error| LineError::Malformed(error.to_string()))
}

/// Overwrites `bytes` with zeros in a way the compiler keeps (a secret that crossed).
pub fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference into the slice.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_replies_round_trip_strictly() {
        let request = ExecutorRequest::StartRelay {
            sandbox: ExecutionId::new("exe-1").unwrap(),
            routes: vec![RouteDeclaration {
                name: "provider".to_owned(),
                host: "api.example.com".to_owned(),
                port: 443,
                operations: vec![OperationDecl {
                    name: "create-message".to_owned(),
                    method: "POST".to_owned(),
                    path: "/v1/messages".to_owned(),
                    query_keys: BTreeSet::new(),
                    effect: EffectDecl::External,
                }],
                credential: Some(CredentialDecl {
                    name: "provider-key".to_owned(),
                    header: CredentialHeaderDecl::Authorization,
                    provider: "provider".to_owned(),
                    contract_version: 1,
                }),
                resolver: Some(ResolverDecl::System),
                budgets: BudgetsDecl::default(),
                plaintext: false,
            }],
        };
        let line = encode_line(&request).unwrap();
        assert!(line.ends_with(b"\n"));
        let decoded: ExecutorRequest = decode_line(&line[..line.len() - 1]).unwrap();
        assert_eq!(decoded, request);
        // Unknown fields of a request are refused.
        assert!(decode_line::<ExecutorRequest>(
            br#"{"request":"status","sandbox":"exe-1","extra":1}"#
        )
        .is_err());
        // Defaults fill a short declaration.
        let short: RouteDeclaration = serde_json::from_str(
            r#"{"name":"p","host":"h.example","operations":[],"credential":{"name":"k","provider":"p"}}"#,
        )
        .unwrap();
        assert_eq!(short.port, 443);
        assert_eq!(
            short.credential.unwrap().header,
            CredentialHeaderDecl::Authorization
        );
        // An over-long line is typed.
        assert!(matches!(
            decode_line::<ExecutorReply>(&vec![b'x'; MAX_LINE_BYTES + 10]),
            Err(LineError::TooLong)
        ));
        let reply = ExecutorReply::Refused {
            detail: "no".to_owned(),
        };
        let line = encode_line(&reply).unwrap();
        let decoded: ExecutorReply = decode_line(&line[..line.len() - 1]).unwrap();
        assert_eq!(decoded, reply);
        // A credential's reference is a function of its name only.
        assert_eq!(credential_reference("k"), credential_reference("k"));
        assert_ne!(credential_reference("k"), account_reference("k"));
    }

    /// PROVES a poll's reply carries the refused exchanges with their classes, strictly,
    /// and an older reply without them still reads (no refusal, none dropped).
    #[test]
    fn a_polls_reply_carries_classified_refusals() {
        let sandbox = ExecutionId::new("exe-1").unwrap();
        let reply = ExecutorReply::Ended {
            lives: Vec::new(),
            refusals: vec![
                RefusedExchange {
                    sandbox: sandbox.clone(),
                    route: "secure".to_owned(),
                    exchange: 3,
                    class: RefusalClass::Violation {
                        kind: ViolationKind::PerimeterRule,
                        observer: HostObserver::Perimeter,
                    },
                    detail: "address not validated".to_owned(),
                },
                RefusedExchange {
                    sandbox,
                    route: "secure".to_owned(),
                    exchange: 4,
                    class: RefusalClass::Ordinary {
                        reason: "not_permitted".to_owned(),
                    },
                    detail: "operation not declared".to_owned(),
                },
            ],
            refusals_dropped: 2,
        };
        let line = encode_line(&reply).unwrap();
        let decoded: ExecutorReply = decode_line(&line[..line.len() - 1]).unwrap();
        assert_eq!(decoded, reply);
        let text = String::from_utf8(line).unwrap();
        assert!(text.contains(r#""class":"violation","kind":"perimeter_rule","observer":"perimeter""#), "{text}");
        let older: ExecutorReply = decode_line(br#"{"reply":"ended","lives":[]}"#).unwrap();
        assert_eq!(
            older,
            ExecutorReply::Ended {
                lives: Vec::new(),
                refusals: Vec::new(),
                refusals_dropped: 0,
            }
        );
        assert!(decode_line::<RefusedExchange>(
            br#"{"sandbox":"exe-1","route":"r","exchange":1,"class":{"class":"relay_protocol"},"detail":"","extra":1}"#
        )
        .is_err());
    }
}
