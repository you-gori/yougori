//! V13: untrusted guest output, preview isolation and content normalization
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §4.7 line 2038, §1.2,
//! §5.2, VM-W58, VM-P03, VM-P33, VM-P35, VM-CP-28 terminal and preview parts, VM-R109
//! and the "sanitized content" residual risk).
//!
//! Tier 0 only (VM §12.1): pure, synchronous filtering and policy code. This is the
//! filtering and policy layer only. It renders nothing, serves nothing, runs no
//! normalizer and starts no VM. It does not prevent prompt injection: a VM does not
//! (§1.2), and semantic prompt injection can survive format conversion (residual-risk
//! row "sanitized content"). Nothing here claims that guest content is safe.
//!
//! - [`TerminalFilter`]: a bounded, stateful ECMA-48/VT parser for guest terminal bytes
//!   fed in arbitrary chunks. It keeps printable text and an allowlist of harmless SGR
//!   styling, and strips or visibly neutralizes everything else with a typed
//!   [`FilterRecord`] (§4.7 "disable dangerous terminal control sequences such as
//!   clipboard writes"; VM-P35; VM-CP-28).
//! - [`GuestText`]: the one display type for guest-controlled strings (filenames, log
//!   lines, titles, HTML text). It writes line breaks, bidirectional controls and
//!   invisible characters as visible escapes, bounds the length and always renders
//!   inside a labelled untrusted frame; [`ApprovalPrompt`] keeps host-built
//!   [`HostText`] apart from it (§4.7 "prevent control characters from spoofing approval
//!   UI").
//! - [`PreviewPolicy`]: the isolated preview origin derived from a V02 publication and
//!   the sandbox boot generation, and the record a later preview server must honour; a
//!   [`check_preview`] refusal for every violation (§4.7 "serve previews on isolated
//!   origins, with no implicit host application session or file access"; VM-CP-28).
//! - [`NormalizationJob`]: the VM-W58 contract. The job runs only in a restricted VM
//!   execution, gets no credentials and no network unless explicitly granted, and its
//!   typed result is validated by the host, which never parses HTML, PDF or archive
//!   bytes itself (§5.2 line 2073). Results are labelled [`NORMALIZATION_LABEL`].
//!
//! Logs keep going through `foundation::events` redaction (CORE-06); this module adds
//! display escaping for the UI, not a second log scrubber.

/// Defines an internally tagged, snake_case enum whose deserialization refuses unknown
/// fields for every variant, unit variants included. serde ignores unknown fields beside
/// the tag of a unit variant even with `deny_unknown_fields`, so reading goes through a
/// twin enum whose unit variants are empty struct variants. Copied from
/// `sandbox_contract/policy/mod.rs`, kept local so this module depends on no other's
/// macros.
macro_rules! strict_untrusted_enum {
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

mod chars;
mod display;
mod normalize;
mod preview;
mod terminal;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests_display;
#[cfg(test)]
mod tests_normalize;
#[cfg(test)]
mod tests_preview;
#[cfg(test)]
mod tests_terminal;

pub use crate::foundation::text::{classify, CharacterClass, CharacterHazard};
pub use chars::MAX_COMBINING_RUN;
pub use display::{
    ApprovalPrompt, DisplayBound, DisplayError, GuestText, GuestTextKind, HostText, HostTextError,
    PromptLine, PromptPart, FRAME_PREFIX,
};
pub use normalize::{
    route_raw, CredentialGrant, DeclaredFormat, JobGrants, JobRefusal, JobViolation, NetworkGrant,
    NormalizationJob, NormalizationOutcome, NormalizationProvenance, NormalizationReport,
    NormalizationRequest, NormalizedArtifact, NormalizerExecution, NormalizerFailure,
    NormalizerIdentity, OutputFormat, RawArtifact, RawDisposition, RawRetention, ReportedOutput,
    ResultRefusal, StoredObject, StoredRole, NORMALIZATION_LABEL,
};
pub use preview::{
    check_preview, derive_preview_origin, site_relation, FileAccess, FrameAncestors, HeaderLine,
    HostApplicationOrigin, HostStateAccess, OriginError, PreviewContext, PreviewDomain,
    PreviewOrigin, PreviewPolicy, PreviewRefusal, PreviewSource, PreviewSubject, PreviewSuffix,
    PreviewViolation, RequestForwarding, SiteRelation, SuffixListing, PERMITTED_SANDBOX_TOKENS,
    PREVIEW_ORIGIN_DOMAIN, REQUIRED_PERMISSIONS_DENIALS,
};
pub use terminal::{
    C1Form, FilterAction, FilterConfig, FilterError, FilterRecord, FilterSummary, FilterTotals,
    FilteredKind, FilteredOutput, KindTag, SequenceEnd, StringTerminator, TerminalFilter,
    TitleTarget, ALLOWED_SGR_PARAMETERS, SGR_RESET,
};
