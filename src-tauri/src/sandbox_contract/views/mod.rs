//! V17: a typed view model of one launched sandbox's facts, the pure (Tier 0) halves of
//! VM-W04 and VM-W53 (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part: the
//! VM-W04 row "Map VM launch/evidence fields into CORE-01/CORE-06 and the CORE-07
//! setup/CLI views. Distinguish observed, asserted, verified and unavailable facts",
//! acceptance "Tampering detected; stale evidence not presented as current; record does
//! not claim a security score"; the VM-W53 row "Supply sandbox capability,
//! private-data/effect, persistence and evidence fields/views through CORE-07 and PRODUCT
//! ... understandable presets and details", acceptance "A user can understand what will
//! run, what it can read/release and why a capability is unavailable; no new grid/security
//! tab maze"; §8.1 "Evidence records, not security certificates"; S2 CORE-01, CORE-06 and
//! CORE-07).
//!
//! Tier 0 only (§12.1): pure, synchronous library code over fakes. Nothing here renders a
//! screen, prints a command's output, launches anything or reads host state, and nothing
//! here claims that any mechanism enforces anything. Rendering and the `setups/`, `cli/`
//! and `src/` wiring belong to PRODUCT (CORE-07).
//!
//! - [`labels`]: every fact carries exactly one [`FactLabel`]: observed (host-observed,
//!   with its source and observation time), asserted (by the guest, the launch request, a
//!   declaration or the contract, named as such), verified (CORE-01 evidence, or a host
//!   observation corroborated by a controlled check, that is current when viewed under
//!   the configuration in force) or unavailable (why, as a CORE-01 refusal reason or a V08
//!   refusal, and what the user can do, as a CORE-01 remedy or a V08 refusal code's help).
//!   A stored view holds only each fact's [`FactBasis`]: observation times, freshness
//!   bounds, clock sessions and configuration fingerprints. Labels are computed at viewing
//!   time from the shared clock and the current configuration and are never stored, so a
//!   stored view cannot present stale evidence as current (VM-W04 acceptance). A guest
//!   assertion is labelled asserted at every time and under every configuration; it never
//!   becomes observed or verified and never satisfies a host requirement (§8.1; CORE-01;
//!   VM-W09).
//! - [`facts`]: the typed [`FactValue`]s a view shows, each placed in one [`Section`], and
//!   the rule of which basis each kind of value may have.
//! - [`sections`]: the VM-W53 answers, built from the `sandbox::backend` launch record,
//!   the V01 resolved contract and V08's `PolicyPreview` of it (V08 already previews the
//!   contract; its lines are reused here, not rebuilt). Four fixed plain-language sections
//!   a CORE-07 view or the CLI can show in an existing detail surface, with no new tab:
//!   what will run, what it can read, write and keep, what it can release and where, and
//!   what is unavailable and why. Presets are the names the existing types already have:
//!   the V02 network modes (offline, strict action, declared transport, user-owned general
//!   VM), the V08 execution profiles and persistence classes; no new policy is invented.
//! - [`record`]: the stored [`SandboxView`]. It binds the launch record's identity digest
//!   and has its own domain-separated digest ([`VIEW_DOMAIN`]) over everything it shows.
//!   Reading one back is strict (`deny_unknown_fields`, a pinned version, fixed notice
//!   text) and refuses a view whose digest does not match its content or whose fact bases
//!   do not fit their values. [`SandboxView::check_against`] refuses a view that is not
//!   what its launch record yields and [`SandboxView::check_contract`] one whose contract
//!   lines are not the contract's, so a re-sealed forgery is caught too.
//! - [`shown`]: [`SandboxView::status_at`] computes the [`ShownView`]: each section's
//!   facts with their labels at one clock reading under one configuration.
//!
//! No score. No field, variant or text produces a score, grade, rating or percentage;
//! facets are shown one by one (§1.3), and the view's standing notice says it is an
//! evidence record, not a certificate (§8.1).
//!
//! CORE-06. Nothing here emits events: a view is a record read on demand, and its labels
//! exist only when computed. No event family is added; if PRODUCT announces that a view
//! changed, the existing CORE-06 envelope and progress stream carry it.

/// Defines an internally tagged, snake_case enum whose deserialization refuses unknown
/// fields for every variant, unit variants included. serde ignores unknown fields beside
/// the tag of a unit variant even with `deny_unknown_fields`, so reading goes through a
/// twin enum whose unit variants are empty struct variants. Copied from
/// `strict_policy_enum!` in `sandbox_contract/policy/mod.rs`, kept local.
macro_rules! strict_view_enum {
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

pub mod facts;
pub mod labels;
pub mod record;
pub mod sections;
pub mod shown;

#[cfg(test)]
mod tests;

pub use facts::{FactValue, ViewFact};
pub use labels::{
    AssertedBy, EvidenceStamp, FactBasis, FactLabel, ObservationStamp, Unavailability, VerifiedBy,
    WhatToDo,
};
pub use record::{
    RecordPart, SandboxView, ViewBody, ViewError, ViewNotice, ViewRefusal, ViewVersion,
    VIEW_DOMAIN, VIEW_VERSION,
};
pub use sections::{Section, ViewInputs};
pub use shown::{ShownLine, ShownSection, ShownView};
