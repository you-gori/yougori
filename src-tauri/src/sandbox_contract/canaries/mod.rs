//! V09: optional internal canaries with calibrated response (VM-W10)
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM part §4.5 lines 1991–2004 "Fake
//! canary", §8.2 line 2274, VM-W10 line 2420 and its ownership row line 2890, VM-R43 line
//! 2733, VM-R86 line 2776, VM-P24 line 2624, VM-CP-21 line 2996). Tier 0 only (§12.1):
//! pure, synchronous library code over fakes.
//!
//! Canaries are a detection aid, not a guaranteed detector (§8.2 line 2274: "Canary use is
//! a signal, not a proof of malicious intent or a guaranteed detector"). Tier 0 fakes prove
//! only this contract; they say nothing about a real guest agent, relay, resolver or
//! perimeter.
//!
//! - [`CanaryRegistry`] issues host-generated fixtures from an explicit seeded generator
//!   ([`CanarySeed`]), typed by [`CanaryKind`] and bound to one sandbox, instance and boot
//!   generation ([`SandboxBinding`]). Every value includes its binding, and the registry
//!   never issues one value twice, so clones restored from one snapshot and re-planted get
//!   distinct values (VM-CP-21), and an old value seen after a restore is attributed to the
//!   instance it was planted in, never the new one. A value has no public constructor and
//!   cannot be deserialized, so no production secret can become a trap (VM-R86); every
//!   canary is [`SecretClass::FakeCanary`](crate::sandbox_contract::effects::SecretClass),
//!   which no credential handle accepts, and [`CanaryRegistry::refuse_credential_use`]
//!   refuses any presented credential that carries a canary value.
//! - [`check_placement`] refuses planting at the SDK credential discovery locations in
//!   [`SDK_DISCOVERY_LOCATIONS`] (§8.2 "Avoid planting files that break normal SDK
//!   auto-discovery"). The registry produces and validates a [`PlantingPlan`]; the planting
//!   itself is later guest-agent work (`appliance/agent`, line 2890).
//! - [`CanaryRegistry::match_observation`] matches typed [`Observation`]s (outbound bytes,
//!   DNS queries, connection attempts to honeyports, guest-reported file reads) and reports
//!   [`CanaryHit`]s. A hit is labelled a signal ([`HitMeaning::SignalNotProof`]) and has
//!   no verdict field. A guest-reported observation stays labelled guest-reported. The
//!   matching itself is the relay's later work (line 2890); this is its contract.
//! - [`calibrate`] counts hits on a labelled benign-tooling corpus and on labelled
//!   adversarial fixtures and returns a [`CalibrationRecord`] of counts with their sample
//!   sizes. It has no probability, score, rate or guarantee field, and reading one in is
//!   refused (§8.2 "No geometric detection probability is assumed").
//! - A [`CanaryHit`] is a bounded CORE-06 audit-worthy record of identifiers, digests and
//!   typed labels: the canary value appears only as a keyed digest, and guest content only
//!   as a digest and a length. [`CanaryHit::audit_draft`] files a guest-reported hit as a
//!   CORE-06 guest observation and a host-observed hit as a host fact of kind
//!   `DetectionSignal`, a signal and never proof.
//!
//! Internal only (§8.2 "controlled internal canaries without third-party notifications";
//! VM-W10 "no external tracking"): nothing here sends, resolves or notifies anything.
//! Fake credentials use a Yougori-reserved format that mimics no third-party credential
//! format, DNS canaries live under the special-use `.internal` top-level domain
//! ([`CANARY_DNS_ZONE`]), and honeyports must be relay-owned addresses that V02's
//! classifier (`destinations::classify`) puts in private or shared CGNAT space, never
//! link-local space, a metadata endpoint or a host-owned address ([`HoneyportPool`]).
//! Deciding to isolate, revoke, stop or notify is VM-W43's (line 2491); this module
//! produces events and calibration only.

/// Defines an internally tagged, snake_case enum whose deserialization refuses unknown
/// fields for every variant, unit variants included. serde ignores unknown fields beside
/// the tag of a unit variant even with `deny_unknown_fields`, so reading goes through a
/// twin enum whose unit variants are empty struct variants. Copied from
/// `strict_policy_enum!` in `sandbox_contract/policy/mod.rs`, kept local.
macro_rules! strict_canary_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident tag $tag:literal {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $({
                    $(
                        $(#[$field_meta:meta])*
                        $field:ident : $ty:ty
                    ),* $(,)?
                })?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(serde::Serialize)]
        #[serde(tag = $tag, rename_all = "snake_case")]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant $({ $($(#[$field_meta])* $field : $ty),* })?
            ),*
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(serde::Deserialize)]
                #[serde(tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
                enum Strict {
                    $($variant { $($($field : $ty),*)? }),*
                }
                let record = crate::foundation::strict_serde::read_tagged(deserializer, $tag)?;
                let strict = <Strict as serde::Deserialize>::deserialize(record)
                    .map_err(serde::de::Error::custom)?;
                Ok(match strict {
                    $(Strict::$variant { $($($field),*)? } => Self::$variant $({ $($field),* })?),*
                })
            }
        }
    };
}

mod calibration;
mod canary;
mod generator;
mod hit;
mod observe;
mod placement;
mod registry;

#[cfg(test)]
mod tests;

pub use calibration::{
    calibrate, CalibrationId, CalibrationMeaning, CalibrationRecord, CalibrationRefusal,
    CalibrationSample, Counted, KindCounts, SampleCounts, SampleLabel, SampleName,
    MAX_CALIBRATION_SAMPLES, MAX_LISTED_TOOLS,
};
pub use canary::{
    Canary, CanaryId, CanaryKind, CanaryState, CanaryValue, SandboxBinding, CANARY_DNS_ZONE,
    DOCUMENT_MARKER_PREFIX, FAKE_CREDENTIAL_PREFIX, HONEYPORT_FIRST_PORT, HONEYPORT_LAST_PORT,
    THIRD_PARTY_CREDENTIAL_PREFIXES,
};
pub use generator::CanarySeed;
pub use hit::{
    Attribution, CanaryHit, DnsMatch, HitMeaning, ObservationLabel, MAX_CANARY_HIT_JSON_BYTES,
};
pub use observe::{
    MatchReport, Observation, ObservationRefusal, ObservationSource, ObservedContent,
    MAX_DNS_NAME_BYTES, MAX_HITS_PER_OBSERVATION, MAX_OBSERVATION_BYTES,
};
pub use placement::{
    check_placement, DiscoveryRule, EnvName, FileLocation, FileRoot, GuestPath, LocationError,
    PlacementLocation, PlacementRefusal, SdkDiscoveryLocation, MAX_GUEST_PATH_BYTES,
    MAX_GUEST_PATH_COMPONENTS, SDK_DISCOVERY_LOCATIONS,
};
pub use registry::{
    CalibrationMismatch, CanaryRegistry, CredentialUseRefusal, HoneyportPool, HoneyportRefusal,
    PlacementRequest, PlanEntry, PlanRefusal, PlanSummary, PlantOrigin, PlantingInstruction,
    PlantingPlan, PlantingRequest, ProfileDigest, MAX_CANARIES_PER_PLAN, MAX_HONEYPORT_ADDRESSES,
    MAX_REGISTERED_CANARIES,
};
