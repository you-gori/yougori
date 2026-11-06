//! Typed observations and the canary matcher (VM-W10 "canary use produces the intended
//! event"; VM-R43; §8.2 line 2274; the relay's matcher, line 2890, is later runtime work).
//!
//! An observation is host-observed or guest-reported, and the label is fixed by the
//! constructor the host calls: nothing converts a guest report into a host observation,
//! and an observation cannot be deserialized. A guest reads files inside the VM where the
//! host cannot see them, so a file read is representable only as a guest report.
//! Outbound bytes are scanned with the provider response scan (`provider::find_encoded`),
//! in the encodings and with the limits `provider::SCAN_COVERAGE` states.

use std::fmt;
use std::net::SocketAddr;

use super::canary::{Canary, CanaryKind, SandboxBinding};
use super::hit::{Attribution, CanaryHit, DnsMatch, ObservationLabel};
use super::placement::FileLocation;
use super::registry::{CanaryRegistry, PlantOrigin};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{Clock, Digest, DigestBuilder, MonotonicTime};
use crate::sandbox_contract::provider::find_encoded;

/// Largest outbound byte observation. A larger one is refused, never cut, since a cut
/// could drop a canary; the relay splits traffic with an overlap of at least the longest
/// encoded canary (later runtime work).
pub const MAX_OBSERVATION_BYTES: usize = 1 << 20;
/// Most hits one observation reports; the rest are counted in [`MatchReport::omitted_hits`].
pub const MAX_HITS_PER_OBSERVATION: usize = 32;
/// Longest DNS name, without the trailing dot.
pub const MAX_DNS_NAME_BYTES: usize = 253;
const MAX_DNS_LABEL_BYTES: usize = 63;

const OBSERVATION_DOMAIN: &str = "yougori/sandbox/canary/observation/v1";

/// What was observed.
#[derive(Clone, PartialEq, Eq)]
pub enum ObservedContent {
    /// Bytes a sandbox sent out (a request, a body, a header block).
    OutboundBytes(Vec<u8>),
    /// A DNS query name.
    DnsQuery(String),
    /// A connection attempt to an endpoint.
    ConnectionAttempt(SocketAddr),
    /// A file the guest reported reading.
    FileRead(FileLocation),
}

impl ObservedContent {
    const fn tag(&self) -> &'static str {
        match self {
            Self::OutboundBytes(_) => "outbound_bytes",
            Self::DnsQuery(_) => "dns_query",
            Self::ConnectionAttempt(_) => "connection_attempt",
            Self::FileRead(_) => "file_read",
        }
    }
}

impl fmt::Debug for ObservedContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Observed content may carry guest data; Debug shows its kind and size only.
        match self {
            Self::OutboundBytes(bytes) => write!(f, "OutboundBytes({} bytes)", bytes.len()),
            Self::DnsQuery(name) => write!(f, "DnsQuery({} bytes)", name.len()),
            Self::ConnectionAttempt(_) => f.write_str("ConnectionAttempt(..)"),
            Self::FileRead(_) => f.write_str("FileRead(..)"),
        }
    }
}

strict_canary_enum! {
    /// Who observed it (CORE-01 source classes: host probe or guest report).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum ObservationSource tag "source" {
        /// The host or the relay saw it itself, at `observed_at` on the host clock.
        HostObserved {
            /// When the host saw it, on the host clock.
            observed_at: MonotonicTime,
        },
        /// The guest reported it; untrusted, and it stays labelled so.
        GuestReported,
    }
}

impl ObservationSource {
    /// The CORE-01 source class.
    pub const fn source_class(self) -> SourceClass {
        match self {
            Self::HostObserved { .. } => SourceClass::HostProbe,
            Self::GuestReported => SourceClass::GuestReport,
        }
    }

    /// The snake_case label used in audit fields.
    pub const fn label(self) -> &'static str {
        match self {
            Self::HostObserved { .. } => "host_observed",
            Self::GuestReported => "guest_reported",
        }
    }
}

/// Why an observation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationRefusal {
    /// More than [`MAX_OBSERVATION_BYTES`] outbound bytes.
    TooLarge {
        /// The bytes given.
        bytes: u64,
        /// The bound.
        max: u64,
    },
    /// Not an ASCII DNS name of labels of 1–63 letters, digits, `-` or `_` within 253
    /// bytes.
    MalformedDnsName,
    /// The host cannot see file reads inside a VM guest; only the guest can report one.
    HostCannotObserveGuestFileRead,
}

impl fmt::Display for ObservationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes, max } => {
                write!(f, "{bytes} observed bytes exceed the bound of {max}")
            }
            Self::MalformedDnsName => f.write_str("the DNS query name is malformed"),
            Self::HostCannotObserveGuestFileRead => f.write_str(
                "a file read inside the guest can only be guest-reported, never host-observed",
            ),
        }
    }
}

impl std::error::Error for ObservationRefusal {}

/// One observation from one sandbox binding: the binding whose channel or traffic it came
/// from, which the host knows itself.
#[derive(Clone, PartialEq, Eq)]
pub struct Observation {
    origin: SandboxBinding,
    source: ObservationSource,
    content: ObservedContent,
    digest: Digest,
}

impl Observation {
    /// Something the host or relay saw itself at `observed_at`.
    pub fn host_observed(
        origin: SandboxBinding,
        observed_at: MonotonicTime,
        content: ObservedContent,
    ) -> Result<Self, ObservationRefusal> {
        if matches!(content, ObservedContent::FileRead(_)) {
            return Err(ObservationRefusal::HostCannotObserveGuestFileRead);
        }
        Self::build(
            origin,
            ObservationSource::HostObserved { observed_at },
            content,
        )
    }

    /// Something the guest reported. No time the guest claims is kept.
    pub fn guest_reported(
        origin: SandboxBinding,
        content: ObservedContent,
    ) -> Result<Self, ObservationRefusal> {
        Self::build(origin, ObservationSource::GuestReported, content)
    }

    fn build(
        origin: SandboxBinding,
        source: ObservationSource,
        content: ObservedContent,
    ) -> Result<Self, ObservationRefusal> {
        let content = match content {
            ObservedContent::OutboundBytes(bytes) if bytes.len() > MAX_OBSERVATION_BYTES => {
                return Err(ObservationRefusal::TooLarge {
                    bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                    max: u64::try_from(MAX_OBSERVATION_BYTES).unwrap_or(u64::MAX),
                });
            }
            ObservedContent::DnsQuery(name) => ObservedContent::DnsQuery(normalize_dns(&name)?),
            other => other,
        };
        let builder = DigestBuilder::new(OBSERVATION_DOMAIN).str(content.tag());
        let digest = match &content {
            ObservedContent::OutboundBytes(bytes) => builder.bytes(bytes),
            ObservedContent::DnsQuery(name) => builder.str(name),
            ObservedContent::ConnectionAttempt(endpoint) => builder.str(&endpoint.to_string()),
            ObservedContent::FileRead(file) => {
                builder.str(file.root.label()).str(file.path.as_str())
            }
        }
        .finish();
        Ok(Self {
            origin,
            source,
            content,
            digest,
        })
    }

    /// The binding the observation came from.
    pub fn origin(&self) -> &SandboxBinding {
        &self.origin
    }

    /// Who observed it.
    pub const fn source(&self) -> ObservationSource {
        self.source
    }

    /// What was observed; never put into an event or a log.
    pub fn content(&self) -> &ObservedContent {
        &self.content
    }

    /// The digest a hit carries in place of the content.
    pub const fn digest(&self) -> Digest {
        self.digest
    }
}

impl fmt::Debug for Observation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Observation")
            .field("origin", &self.origin)
            .field("source", &self.source)
            .field("content", &self.content)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Lowercases, drops one trailing dot and checks the name.
fn normalize_dns(name: &str) -> Result<String, ObservationRefusal> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() || trimmed.len() > MAX_DNS_NAME_BYTES {
        return Err(ObservationRefusal::MalformedDnsName);
    }
    let well_formed = trimmed.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_DNS_LABEL_BYTES
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    });
    if !well_formed {
        return Err(ObservationRefusal::MalformedDnsName);
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// The hits of one observation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MatchReport {
    /// At most [`MAX_HITS_PER_OBSERVATION`], in canary identity order.
    pub hits: Vec<CanaryHit>,
    /// Further hits, counted rather than dropped silently.
    pub omitted_hits: u64,
}

impl MatchReport {
    /// Every hit, the omitted ones included.
    pub fn total_hits(&self) -> u64 {
        u64::try_from(self.hits.len())
            .unwrap_or(u64::MAX)
            .saturating_add(self.omitted_hits)
    }
}

impl CanaryRegistry {
    /// Matches one observation against every canary this registry issued, retired ones
    /// included, and reports each canary found once, stamped with `clock`'s time. A hit is
    /// a signal, not proof (§8.2); it keeps the observation's source label, and it is
    /// attributed to the binding the canary was planted in, whatever binding observed it.
    pub fn match_observation(&self, observation: &Observation, clock: &dyn Clock) -> MatchReport {
        let matched_at = clock.now();
        let mut report = MatchReport::default();
        for (canary, label) in self.candidates(observation) {
            if report.hits.len() < MAX_HITS_PER_OBSERVATION {
                let attribution = self.attribute(&canary.binding, &observation.origin);
                let calibration = self
                    .plans
                    .get(&canary.binding)
                    .and_then(|plan| plan.calibration);
                report.hits.push(CanaryHit::new(
                    canary,
                    observation,
                    label,
                    attribution,
                    matched_at,
                    calibration,
                ));
            } else {
                report.omitted_hits = report.omitted_hits.saturating_add(1);
            }
        }
        report
    }

    fn candidates<'a>(&'a self, observation: &Observation) -> Vec<(&'a Canary, ObservationLabel)> {
        match &observation.content {
            ObservedContent::OutboundBytes(bytes) => {
                let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                self.canaries
                    .values()
                    .filter(|canary| canary.kind != CanaryKind::HoneyportEndpoint)
                    .filter_map(|canary| {
                        find_encoded(bytes, canary.value.as_bytes()).map(|encoding| {
                            (canary, ObservationLabel::OutboundBytes { encoding, length })
                        })
                    })
                    .collect()
            }
            ObservedContent::DnsQuery(name) => self
                .canaries
                .values()
                .filter(|canary| canary.kind == CanaryKind::DnsName)
                .filter_map(|canary| {
                    let canary_name = canary.value.expose_for_planting();
                    let matched = if name == canary_name {
                        Some(DnsMatch::Exact)
                    } else {
                        name.strip_suffix(canary_name)
                            .filter(|head| head.ends_with('.'))
                            .map(|_| DnsMatch::Subdomain)
                    };
                    matched.map(|matched| (canary, ObservationLabel::DnsQuery { matched }))
                })
                .collect(),
            ObservedContent::ConnectionAttempt(endpoint) => self
                .canaries
                .values()
                .filter(|canary| canary.value.socket() == Some(*endpoint))
                .map(|canary| (canary, ObservationLabel::ConnectionAttempt))
                .collect(),
            ObservedContent::FileRead(file) => self.file_candidates(&observation.origin, file),
        }
    }

    /// A path names no value, so a read is matched against the canaries planted at that
    /// path in the reading binding, or, when it planted none there, in the binding its
    /// snapshot was taken of (whose files the snapshot carried).
    fn file_candidates<'a>(
        &'a self,
        origin: &SandboxBinding,
        file: &FileLocation,
    ) -> Vec<(&'a Canary, ObservationLabel)> {
        let planted_at = |binding: &SandboxBinding| -> Vec<(&'a Canary, ObservationLabel)> {
            self.canaries
                .values()
                .filter(|canary| {
                    canary.binding == *binding && canary.location.as_file().as_ref() == Some(file)
                })
                .map(|canary| (canary, ObservationLabel::FileRead))
                .collect()
        };
        let own = planted_at(origin);
        if !own.is_empty() {
            return own;
        }
        match self.plans.get(origin).map(|plan| &plan.origin) {
            Some(PlantOrigin::RestoredFrom { source, .. }) => planted_at(source),
            _ => Vec::new(),
        }
    }

    /// Where a hit on a canary planted in `planted` comes from, seen in `observed`. The
    /// hit always names `planted`; this label only says how the two relate.
    fn attribute(&self, planted: &SandboxBinding, observed: &SandboxBinding) -> Attribution {
        if planted == observed {
            return Attribution::PlantedHere;
        }
        if let Some(PlantOrigin::RestoredFrom { snapshot, source }) =
            self.plans.get(observed).map(|plan| &plan.origin)
        {
            if source == planted {
                return Attribution::CarriedBySnapshot {
                    snapshot: *snapshot,
                };
            }
        }
        if planted.same_instance(observed) {
            return Attribution::OtherGeneration;
        }
        Attribution::PlantedElsewhere
    }
}
