//! Canary kinds, identities, bindings and values (VM part §4.5 line 2002 "Fake canary";
//! §8.2 line 2274; VM-R43; VM-R86; VM-CP-21).

use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use super::placement::PlacementLocation;
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::{Digest, DigestBuilder, SandboxBootGeneration};
use crate::sandbox_contract::effects::{CanaryToken, SandboxRef, SecretClass};

/// Prefix of every fake credential value: a Yougori-reserved format that no genuine
/// credential uses (Yougori's own are `ygs_`, `ygw_` and `ygrid_`) and that mimics no
/// third-party format, so no third-party secret scanner routes it to a provider (§8.2
/// "without third-party notifications"; VM-R86 "never use production secrets as traps").
pub const FAKE_CREDENTIAL_PREFIX: &str = "ygcf1_";

/// Prefix of every fake document marker (VM-R86 "canary credentials/data").
pub const DOCUMENT_MARKER_PREFIX: &str = "ygcd1-";

/// The zone every DNS canary lives under (VM-R43). `.internal` is the top-level domain
/// ICANN reserved for private use in 2024, so it is never delegated in public DNS and a
/// canary name has no public authoritative server to notify. The relay's resolver must
/// answer these names itself and never forward them (later runtime work, VM-W11).
pub const CANARY_DNS_ZONE: &str = "canary.yougori.internal";

/// First honeyport port: the IANA dynamic and private range starts here (VM-R43).
pub const HONEYPORT_FIRST_PORT: u16 = 49_152;
/// Last honeyport port.
pub const HONEYPORT_LAST_PORT: u16 = 65_535;

/// Credential formats a fake credential must never start with, compared ASCII
/// case-insensitively: well-known third-party prefixes and Yougori's own genuine ones
/// (§8.2; VM-R86). A value in one of these formats could be reported to its issuer by
/// third-party secret scanning, or be mistaken for a genuine credential.
pub const THIRD_PARTY_CREDENTIAL_PREFIXES: &[&str] = &[
    "akia",
    "asia",
    "aiza",
    "ya29.",
    "sk-",
    "sk_",
    "rk_",
    "pk_",
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "hf_",
    "xox",
    "sg.",
    "npm_",
    "pypi-",
    "dop_v1_",
    "shpat_",
    "eyj",
    "ygs_",
    "ygw_",
    "ygrid_",
];

/// A canary kind (VM-R43 honeyports and DNS canaries; VM-R86 canary credentials and data).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryKind {
    /// A fake credential string in a Yougori-reserved format.
    FakeCredential,
    /// A marker inside a fake document.
    DocumentMarker,
    /// A name under [`CANARY_DNS_ZONE`].
    DnsName,
    /// An endpoint on a relay-owned private address where nothing legitimate listens.
    HoneyportEndpoint,
}

impl CanaryKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 4] = [
        Self::FakeCredential,
        Self::DocumentMarker,
        Self::DnsName,
        Self::HoneyportEndpoint,
    ];

    /// The snake_case label used in events.
    pub const fn label(self) -> &'static str {
        match self {
            Self::FakeCredential => "fake_credential",
            Self::DocumentMarker => "document_marker",
            Self::DnsName => "dns_name",
            Self::HoneyportEndpoint => "honeyport_endpoint",
        }
    }

    /// Every canary is a §4.5 fake canary: a detection artifact, never a genuine
    /// credential.
    pub const fn secret_class(self) -> SecretClass {
        SecretClass::FakeCanary
    }

    /// Whether the kind can only be planted as a file (a document marker lives in a fake
    /// document).
    pub const fn needs_file(self) -> bool {
        matches!(self, Self::DocumentMarker)
    }

    pub(super) const fn code(self) -> u64 {
        match self {
            Self::FakeCredential => 1,
            Self::DocumentMarker => 2,
            Self::DnsName => 3,
            Self::HoneyportEndpoint => 4,
        }
    }
}

impl fmt::Display for CanaryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The sandbox, VM instance and boot generation a canary is bound to (VM-W10; VM-CP-21).
/// Every boot or restore raises the boot generation, and clones have distinct instances.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxBinding {
    /// The sandbox, scoped by its issuer.
    pub sandbox: SandboxRef,
    /// The VM instance the host created.
    pub instance: VmInstanceId,
    /// The boot generation; every boot or restore raises it.
    pub boot: SandboxBootGeneration,
}

impl SandboxBinding {
    /// Whether `other` is the same sandbox and VM instance, whatever its boot generation.
    pub fn same_instance(&self, other: &Self) -> bool {
        self.sandbox == other.sandbox && self.instance == other.instance
    }

    pub(super) fn feed(&self, builder: DigestBuilder) -> DigestBuilder {
        builder
            .digest(self.sandbox.issuer.digest())
            .str(self.sandbox.execution.as_str())
            .digest(&self.instance.digest())
            .u64(self.boot.get())
    }
}

/// The identity of one canary: a digest of its binding and the registry's serial, never
/// of its value, so logging it reveals nothing about the value.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CanaryId(Digest);

impl CanaryId {
    pub(super) const DOMAIN: &'static str = "yougori/sandbox/canary/id/v1";

    /// The digest the identity is.
    pub const fn digest(&self) -> &Digest {
        &self.0
    }

    pub(super) const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }
}

impl fmt::Debug for CanaryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CanaryId({})", self.0)
    }
}

impl fmt::Display for CanaryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// One canary value. Only the registry creates one, from its seeded generator; there is no
/// public constructor and no `Deserialize`, so bytes from elsewhere, a production secret
/// included, can never become a canary (VM-R86). It is not `Serialize` either, and its
/// `Debug` output is its digest, so it never reaches a log in clear.
#[derive(Clone, PartialEq, Eq)]
pub struct CanaryValue {
    text: String,
    marker: Digest,
    digest: Digest,
    endpoint: Option<SocketAddr>,
}

impl CanaryValue {
    const DIGEST_DOMAIN: &'static str = "yougori/sandbox/canary/value/v1";

    pub(super) fn fake_credential(marker: Digest) -> Self {
        let text = format!("{FAKE_CREDENTIAL_PREFIX}{}", marker.to_hex());
        Self::build(CanaryKind::FakeCredential, text, marker, None)
    }

    pub(super) fn document_marker(marker: Digest) -> Self {
        let text = format!("{DOCUMENT_MARKER_PREFIX}{}", marker.to_hex());
        Self::build(CanaryKind::DocumentMarker, text, marker, None)
    }

    /// One label of `c` and 32 hexadecimal digits (128 bits of the marker), within the
    /// 63-byte DNS label limit, under [`CANARY_DNS_ZONE`].
    pub(super) fn dns_name(marker: Digest) -> Self {
        let hex = marker.to_hex();
        let label = hex.get(..32).unwrap_or(hex.as_str());
        let text = format!("c{label}.{CANARY_DNS_ZONE}");
        Self::build(CanaryKind::DnsName, text, marker, None)
    }

    pub(super) fn endpoint(marker: Digest, endpoint: SocketAddr) -> Self {
        Self::build(
            CanaryKind::HoneyportEndpoint,
            endpoint.to_string(),
            marker,
            Some(endpoint),
        )
    }

    fn build(kind: CanaryKind, text: String, marker: Digest, endpoint: Option<SocketAddr>) -> Self {
        // Keyed by the secret marker, so even a low-entropy value (a honeyport endpoint)
        // cannot be recovered from its digest by enumeration.
        let digest = DigestBuilder::new(Self::DIGEST_DOMAIN)
            .digest(&marker)
            .u64(kind.code())
            .str(&text)
            .finish();
        Self {
            text,
            marker,
            digest,
            endpoint,
        }
    }

    /// The digest logged in place of the value.
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    /// The value in clear, for the planting instruction handed to the guest agent and for
    /// nothing else; never log it.
    pub fn expose_for_planting(&self) -> &str {
        &self.text
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }

    pub(super) fn socket(&self) -> Option<SocketAddr> {
        self.endpoint
    }

    pub(super) const fn marker(&self) -> Digest {
        self.marker
    }
}

impl fmt::Debug for CanaryValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CanaryValue(digest {})", self.digest)
    }
}

/// Whether a canary still stands in its sandbox or was superseded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryState {
    /// Planted in a running instance.
    Active,
    /// Its instance stopped or was replaced by a newer boot generation. It still matches,
    /// so a value seen later is still attributed to the instance it was planted in.
    Retired,
}

impl CanaryState {
    /// The snake_case label used in events.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }
}

/// One registered canary: what it is, where it was planted and its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Canary {
    pub(super) id: CanaryId,
    pub(super) kind: CanaryKind,
    pub(super) binding: SandboxBinding,
    pub(super) location: PlacementLocation,
    pub(super) value: CanaryValue,
    pub(super) state: CanaryState,
}

impl Canary {
    /// The canary's identity.
    pub const fn id(&self) -> CanaryId {
        self.id
    }

    /// The canary's kind.
    pub const fn kind(&self) -> CanaryKind {
        self.kind
    }

    /// The binding it was planted in, which every hit on it names.
    pub fn binding(&self) -> &SandboxBinding {
        &self.binding
    }

    /// Where it was planted.
    pub fn location(&self) -> &PlacementLocation {
        &self.location
    }

    /// Whether it is active or retired.
    pub const fn state(&self) -> CanaryState {
        self.state
    }

    /// Always [`SecretClass::FakeCanary`] (§4.5 line 2002).
    pub const fn secret_class(&self) -> SecretClass {
        self.kind.secret_class()
    }

    /// The keyed digest logged in place of the value.
    pub const fn value_digest(&self) -> Digest {
        self.value.digest()
    }

    /// The value, for the guest agent's planting step only.
    pub fn value(&self) -> &CanaryValue {
        &self.value
    }

    /// The token the provider response scan (`provider::KnownSecrets::with_canary`) looks
    /// for, for the kinds whose value carries the whole marker in hexadecimal: fake
    /// credentials and document markers. The token holds the marker in clear, so it goes
    /// only into an in-memory scanner and is never logged.
    pub fn token(&self) -> Option<CanaryToken> {
        match self.kind {
            CanaryKind::FakeCredential | CanaryKind::DocumentMarker => Some(CanaryToken {
                marker: self.value.marker(),
            }),
            CanaryKind::DnsName | CanaryKind::HoneyportEndpoint => None,
        }
    }

    /// The honeyport endpoint, for honeyport canaries.
    pub fn endpoint(&self) -> Option<SocketAddr> {
        self.value.socket()
    }
}
