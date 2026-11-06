//! The canary event (VM-W10 "canary use produces the intended event"; §8.2 line 2274
//! "Canary use is a signal, not a proof of malicious intent"; CORE-06 audit).
//!
//! A [`CanaryHit`] carries identifiers, digests and typed labels only: the canary value
//! as its keyed digest, the observation as its digest and length, never guest content.
//! Its meaning is fixed to [`HitMeaning::SignalNotProof`], and it has no verdict, score or
//! severity: deciding a response is VM-W43's (line 2491).

use serde::{Deserialize, Serialize};

use super::calibration::CalibrationId;
use super::canary::{Canary, CanaryId, CanaryKind, CanaryState, SandboxBinding};
use super::observe::{Observation, ObservationSource};
use crate::foundation::coordination::SnapshotId;
use crate::foundation::events::{AuditDraft, EventContext, Field, Generations, HostFact, Phase};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{Digest, MonotonicTime, OperationId};
use crate::sandbox_contract::provider::ScanEncoding;

/// Bound on one hit's JSON encoding, identifiers of the longest accepted length included.
pub const MAX_CANARY_HIT_JSON_BYTES: usize = 2_048;

/// What a hit means: always a signal, never proof (§8.2; VM-R43 "do not invent ...
/// automatic proof from contact").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HitMeaning {
    /// A signal for the response policy, never proof of malicious intent.
    SignalNotProof,
}

strict_canary_enum! {
    /// How the binding a canary was planted in relates to the binding that observed it.
    /// The hit always names the planting binding (VM-CP-21).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Attribution tag "attribution" {
        /// The same sandbox instance and boot generation.
        PlantedHere,
        /// The observing binding was restored from `snapshot`, taken of the planting one.
        CarriedBySnapshot {
            /// The snapshot the observing binding was restored from.
            snapshot: SnapshotId,
        },
        /// The same instance at another boot generation.
        OtherGeneration,
        /// Another sandbox or instance.
        PlantedElsewhere,
    }
}

impl Attribution {
    /// The snake_case label used in audit fields.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::PlantedHere => "planted_here",
            Self::CarriedBySnapshot { .. } => "carried_by_snapshot",
            Self::OtherGeneration => "other_generation",
            Self::PlantedElsewhere => "planted_elsewhere",
        }
    }
}

/// Whether a DNS query named the canary or a name under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMatch {
    /// The query named the canary itself.
    Exact,
    /// The query named a name under the canary.
    Subdomain,
}

impl DnsMatch {
    /// The snake_case label used in audit fields.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Subdomain => "subdomain",
        }
    }
}

strict_canary_enum! {
    /// What kind of observation matched, without its content.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum ObservationLabel tag "observation" {
        /// Outbound bytes of `length` carried the value in `encoding`.
        OutboundBytes {
            /// The encoding the value was found in.
            encoding: ScanEncoding,
            /// The observed bytes' length.
            length: u64,
        },
        /// A DNS query named the canary or a name under it.
        DnsQuery {
            /// Which of the two.
            matched: DnsMatch,
        },
        /// A connection attempt to the honeyport; the endpoint is the value, so it is not
        /// repeated here.
        ConnectionAttempt,
        /// A guest-reported read of the planted file.
        FileRead,
    }
}

impl ObservationLabel {
    /// The snake_case label used in audit fields.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::OutboundBytes { .. } => "outbound_bytes",
            Self::DnsQuery { .. } => "dns_query",
            Self::ConnectionAttempt => "connection_attempt",
            Self::FileRead => "file_read",
        }
    }
}

const fn encoding_label(encoding: ScanEncoding) -> &'static str {
    match encoding {
        ScanEncoding::Verbatim => "verbatim",
        ScanEncoding::AsciiCaseInsensitive => "ascii_case_insensitive",
        ScanEncoding::Hexadecimal => "hexadecimal",
        ScanEncoding::Base64Standard => "base64_standard",
        ScanEncoding::Base64UrlSafe => "base64_url_safe",
        ScanEncoding::PercentEncoded => "percent_encoded",
        ScanEncoding::JsonEscaped => "json_escaped",
    }
}

/// One canary hit: the intended VM-W10 event and a CORE-06 audit-worthy record. It is a
/// signal for the response policy (VM-W43), carrying no verdict. Reading one back refuses
/// a record the matcher could not have produced, such as a host-observed file read or an
/// attribution that contradicts its two bindings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawCanaryHit")]
pub struct CanaryHit {
    meaning: HitMeaning,
    canary: CanaryId,
    kind: CanaryKind,
    value_digest: Digest,
    canary_state: CanaryState,
    planted_in: SandboxBinding,
    observed_in: SandboxBinding,
    attribution: Attribution,
    source: ObservationSource,
    observation: ObservationLabel,
    observation_digest: Digest,
    matched_at: MonotonicTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    calibration: Option<CalibrationId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCanaryHit {
    meaning: HitMeaning,
    canary: CanaryId,
    kind: CanaryKind,
    value_digest: Digest,
    canary_state: CanaryState,
    planted_in: SandboxBinding,
    observed_in: SandboxBinding,
    attribution: Attribution,
    source: ObservationSource,
    observation: ObservationLabel,
    observation_digest: Digest,
    matched_at: MonotonicTime,
    #[serde(default)]
    calibration: Option<CalibrationId>,
}

impl TryFrom<RawCanaryHit> for CanaryHit {
    type Error = &'static str;

    fn try_from(raw: RawCanaryHit) -> Result<Self, Self::Error> {
        let hit = Self {
            meaning: raw.meaning,
            canary: raw.canary,
            kind: raw.kind,
            value_digest: raw.value_digest,
            canary_state: raw.canary_state,
            planted_in: raw.planted_in,
            observed_in: raw.observed_in,
            attribution: raw.attribution,
            source: raw.source,
            observation: raw.observation,
            observation_digest: raw.observation_digest,
            matched_at: raw.matched_at,
            calibration: raw.calibration,
        };
        hit.check()?;
        Ok(hit)
    }
}

impl CanaryHit {
    /// The matcher's invariants, checked on every hit read back.
    fn check(&self) -> Result<(), &'static str> {
        let kind_fits = match self.observation {
            ObservationLabel::OutboundBytes { .. } => self.kind != CanaryKind::HoneyportEndpoint,
            ObservationLabel::DnsQuery { .. } => self.kind == CanaryKind::DnsName,
            ObservationLabel::ConnectionAttempt => self.kind == CanaryKind::HoneyportEndpoint,
            ObservationLabel::FileRead => true,
        };
        if !kind_fits {
            return Err("the observation cannot match a canary of this kind");
        }
        if self.observation == ObservationLabel::FileRead
            && self.source != ObservationSource::GuestReported
        {
            return Err("a file read inside the guest is only ever guest-reported");
        }
        let same = self.planted_in == self.observed_in;
        let same_instance = self.planted_in.same_instance(&self.observed_in);
        let attribution_fits = match self.attribution {
            Attribution::PlantedHere => same,
            Attribution::CarriedBySnapshot { .. } => !same,
            Attribution::OtherGeneration => same_instance && !same,
            Attribution::PlantedElsewhere => !same_instance,
        };
        if !attribution_fits {
            return Err("the attribution contradicts the planting and observing bindings");
        }
        Ok(())
    }

    pub(super) fn new(
        canary: &Canary,
        observation: &Observation,
        label: ObservationLabel,
        attribution: Attribution,
        matched_at: MonotonicTime,
        calibration: Option<CalibrationId>,
    ) -> Self {
        Self {
            meaning: HitMeaning::SignalNotProof,
            canary: canary.id(),
            kind: canary.kind(),
            value_digest: canary.value_digest(),
            canary_state: canary.state(),
            planted_in: canary.binding().clone(),
            observed_in: observation.origin().clone(),
            attribution,
            source: observation.source(),
            observation: label,
            observation_digest: observation.digest(),
            matched_at,
            calibration,
        }
    }

    /// Always [`HitMeaning::SignalNotProof`].
    pub const fn meaning(&self) -> HitMeaning {
        self.meaning
    }

    /// The canary that matched.
    pub const fn canary(&self) -> CanaryId {
        self.canary
    }

    /// The canary's kind.
    pub const fn kind(&self) -> CanaryKind {
        self.kind
    }

    /// The canary value's keyed digest, logged in place of the value.
    pub const fn value_digest(&self) -> Digest {
        self.value_digest
    }

    /// Whether the canary was active or retired when it matched.
    pub const fn canary_state(&self) -> CanaryState {
        self.canary_state
    }

    /// The binding the canary was planted in: the instance the hit is attributed to.
    pub fn planted_in(&self) -> &SandboxBinding {
        &self.planted_in
    }

    /// The binding the observation came from.
    pub fn observed_in(&self) -> &SandboxBinding {
        &self.observed_in
    }

    /// How the planting and observing bindings relate.
    pub const fn attribution(&self) -> Attribution {
        self.attribution
    }

    /// Who observed it; a guest report stays one.
    pub const fn source(&self) -> ObservationSource {
        self.source
    }

    /// The CORE-01 source class of the observation: a guest report stays one.
    pub const fn source_class(&self) -> SourceClass {
        self.source.source_class()
    }

    /// What kind of observation matched, without its content.
    pub const fn observation(&self) -> ObservationLabel {
        self.observation
    }

    /// The digest of the observed content, never the content.
    pub const fn observation_digest(&self) -> Digest {
        self.observation_digest
    }

    /// When the matcher reported it, on the host clock.
    pub const fn matched_at(&self) -> MonotonicTime {
        self.matched_at
    }

    /// The calibration that measured this canary's kinds and locations, if one was
    /// attached (VM-W10 "calibrated response").
    pub const fn calibration(&self) -> Option<CalibrationId> {
        self.calibration
    }

    /// The hit as CORE-06 fields, every one the module's own metadata: identifiers,
    /// digests, counts and fixed labels.
    pub fn audit_fields(&self) -> Vec<Field> {
        let mut fields = vec![
            Field::metadata("event", "canary_hit"),
            Field::metadata("meaning", "signal_not_proof"),
            Field::metadata("canary", *self.canary.digest()),
            Field::metadata("kind", self.kind.label()),
            Field::metadata("value_digest", self.value_digest),
            Field::metadata("canary_state", self.canary_state.label()),
            Field::metadata("planted_issuer", *self.planted_in.sandbox.issuer.digest()),
            Field::metadata(
                "planted_execution",
                self.planted_in.sandbox.execution.as_str(),
            ),
            Field::metadata("planted_instance", self.planted_in.instance.digest()),
            Field::metadata("planted_boot", self.planted_in.boot.get()),
            Field::metadata("observed_issuer", *self.observed_in.sandbox.issuer.digest()),
            Field::metadata(
                "observed_execution",
                self.observed_in.sandbox.execution.as_str(),
            ),
            Field::metadata("observed_instance", self.observed_in.instance.digest()),
            Field::metadata("observed_boot", self.observed_in.boot.get()),
            Field::metadata("attribution", self.attribution.label()),
            Field::metadata("source", self.source.label()),
            Field::metadata("observation", self.observation.label()),
            Field::metadata("observation_digest", self.observation_digest),
            Field::metadata("matched_at_ns", self.matched_at.as_nanos()),
        ];
        if let Attribution::CarriedBySnapshot { snapshot } = self.attribution {
            fields.push(Field::metadata("snapshot", snapshot.digest()));
        }
        if let ObservationSource::HostObserved { observed_at } = self.source {
            fields.push(Field::metadata("observed_at_ns", observed_at.as_nanos()));
        }
        match self.observation {
            ObservationLabel::OutboundBytes { encoding, length } => {
                fields.push(Field::metadata("encoding", encoding_label(encoding)));
                fields.push(Field::metadata("observed_bytes", length));
            }
            ObservationLabel::DnsQuery { matched } => {
                fields.push(Field::metadata("dns_match", matched.label()));
            }
            ObservationLabel::ConnectionAttempt | ObservationLabel::FileRead => {}
        }
        if let Some(calibration) = self.calibration {
            fields.push(Field::metadata("calibration", *calibration.digest()));
        }
        fields
    }

    /// The CORE-06 context of the hit's audit record: the operation, phase `Running`, and
    /// the boot generation of the observing binding.
    pub fn event_context(&self, operation: OperationId) -> EventContext {
        EventContext::new(operation, Phase::Running)
            .with_generations(Generations::NONE.with_sandbox_boot(self.observed_in.boot))
    }

    /// The CORE-06 audit draft. A guest-reported hit is a guest observation, which the
    /// journal labels a guest report and treats as untrusted. A host-observed hit is a host
    /// fact of kind [`HostFact::DetectionSignal`]: a signal, never proof of a compromise
    /// (§8.2 line 2274).
    pub fn audit_draft(&self) -> AuditDraft {
        match self.source {
            ObservationSource::GuestReported => AuditDraft::GuestObservation {
                fields: self.audit_fields(),
            },
            ObservationSource::HostObserved { .. } => AuditDraft::HostFact {
                fact: HostFact::DetectionSignal,
                fields: self.audit_fields(),
            },
        }
    }
}
