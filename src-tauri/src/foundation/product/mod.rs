//! CORE-07: the shared setup/API/CLI/UI product contract and migration presentation
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, S2 CORE-07: "execution category,
//! requested capabilities, actual backend, memory/readiness, permissions, evidence,
//! declared agent endpoint capabilities and actionable refusal. Domain packages supply
//! fields and views through one product owner";
//! acceptance "UI and CLI resolve the same state; labelled runtimes never appear as VM
//! sandboxes; migration preserves data and recorded choices"; leftover task S07).
//!
//! One versioned document, [`ProductView`], that the engine API returns and the CLI and
//! desktop both read, so they resolve the same state. This module is the contract and
//! depends on the foundation alone: it converts from CORE-01 evidence and categories and
//! CORE-06 progress itself, and defines its own shape wherever a part comes from a domain
//! package. The engine's `product_views` module converts model-memory, V17/V08/V01 sandbox
//! and setup-crate types into these shapes. Nothing here decides policy, admits a runtime,
//! checks evidence or plans a migration again:
//!
//! - [`version`]: the pinned [`PRODUCT_CONTRACT_VERSION`] and the compatibility rule
//!   ([`read_view`]): a document of the current version is read strictly; one written by a
//!   newer Yougori is refused for anything that acts on it and, for display only, downgraded
//!   explicitly to a notice that interprets nothing in it; an older readable version is
//!   upgraded by its own reader. Every pinned golden fixture of every version stays
//!   readable.
//! - [`evidence`]: the one [`Evidence`] state of a shown value, verified, observed,
//!   asserted or unavailable, and [`Fact`], a value with exactly one such state. The source
//!   of a CORE-01 observation decides its state (a host probe verifies, a provider API
//!   observes, anything weaker asserts), so an assertion is never shown as verified, and a
//!   stored document rechecked later ([`ProductView::as_of`]) never presents stale evidence
//!   as current (VM-W04).
//! - [`refusal`]: an actionable [`Refusal`]: a stable [`RefusalCode`], one plain reason and
//!   a typed [`Remedy`] with its words; CORE-01 and product refusals convert here, and a
//!   V08 policy code is carried as the policy owner's [`PolicyCode`].
//! - [`execution`]: the requested execution category against the actual backend (S1, S3.5,
//!   INT-07, VM-D4–VM-D6). A category is shown only with its own recorded label, and a
//!   document that shows a labelled runtime as a VM sandbox, or admits a category its
//!   request refuses, is refused when read. Requested CORE-01 capabilities carry their
//!   evidence, and weak evidence never fills a strong requirement.
//! - [`model`]: the shapes of model readiness, keep-ready preparation, residency and memory
//!   fit (GPU §2.7, §3.6, §4.1), kept apart from sandbox evidence (INT-11).
//! - [`sandbox_evidence`] and [`permissions`]: the shapes of V17's four sections with each
//!   fact's evidence, and of the permissions a setup asks for or a contract grants, as
//!   shown to the user (VM-W53).
//! - [`endpoint`]: the shape of what a model's agent endpoint declares per dialect (GPU-W11,
//!   S9): every feature with one evidence state, support only on the host's own
//!   conformance run, a runner's declaration only as an assertion, and whether a dialect is
//!   advertised recomputed from its features.
//! - [`grants`]: the CORE-04 grants an execution's authority holds, what each covers, and
//!   whether it is held, lapsed with its authority, revoked in this run or tombstoned
//!   before the last recovery (VM part §6.3; VM-W43), converted here from the coordinator.
//! - [`progress`]: CORE-06 progress, revalidated on read with CORE-06's own check.
//! - [`migration`]: migration state for old setups (VM §1.3, VM-W01, VM-W56, INT-11): every
//!   recorded choice maps by one documented rule, never downward, an ambiguous one waits
//!   for a specific decision, and nothing changes before a backup exists.
//!
//! Golden fixtures in `fixtures/` pin the wire shape for the CLI, the desktop and the API;
//! the `product_views` tests check that they are what the conversions produce.
//! Wiring into setup, the engine API, the CLI and the UI belongs to U01–U05. Nothing here
//! claims enforcement or computes a score.

/// Defines an internally tagged, snake_case enum whose deserialization refuses unknown
/// fields for every variant, unit variants included. serde ignores unknown fields beside
/// the tag of a unit variant even with `deny_unknown_fields`, so reading goes through a
/// twin enum whose unit variants are empty struct variants. The pattern of
/// `strict_view_enum!` in `sandbox_contract/views/mod.rs`, kept local. The record is read
/// through [`read_tagged`](crate::foundation::strict_serde::read_tagged) first, so a tag
/// that is not a string is refused even where serde buffers the record.
macro_rules! strict_product_enum {
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
                let value = crate::foundation::strict_serde::read_tagged(deserializer, $tag)?;
                let strict = <Strict as serde::Deserialize>::deserialize(value)
                    .map_err(serde::de::Error::custom)?;
                Ok(match strict {
                    $(Strict::$variant { $($($field),*)? } => Self::$variant $({ $($field),* })?),*
                })
            }
        }
    };
}

/// Defines a closed set of stable refusal codes: each variant's snake_case string never
/// changes within a contract version, and every string is unique across all code sets
/// (pinned by the tests).
macro_rules! refusal_code_set {
    (
        $(#[$meta:meta])*
        $name:ident {
            $( $(#[$doc:meta])* $variant:ident = $code:literal ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
            serde::Serialize, serde::Deserialize,
        )]
        pub enum $name {
            $( $(#[$doc])* #[serde(rename = $code)] $variant, )*
        }

        impl $name {
            /// Every code of this set.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)*];

            /// The stable snake_case string.
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $code,)* }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

pub mod endpoint;
pub mod evidence;
pub mod execution;
pub mod fixtures;
pub mod grants;
pub mod migration;
pub mod model;
pub mod permissions;
pub mod progress;
pub mod refusal;
pub mod sandbox_evidence;
pub mod text;
pub mod version;
pub mod view;

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

pub use endpoint::{
    AgentEndpoint, CellShown, ConformanceShown, DialectShown, EndpointAspect, EndpointDialect,
    EndpointError, EndpointFeature, EndpointRunner, FeatureLine, FeatureSupport,
    UnsupportedReason,
};
pub use evidence::{Asserter, Evidence, Fact, FactError, Observer, VerifiedBy};
pub use execution::{
    ActualBackend, CapabilityCheck, CapabilityCheckError, CategoryChoice, CategoryShown, Execution,
    ExecutionError, RequestedExecution,
};
pub use fixtures::{GoldenFixture, GOLDEN_FIXTURES};
pub use grants::{
    AuthorityStanding, ExecutionGrants, GrantError, GrantScope, GrantShown, GrantStatus,
};
pub use migration::{
    BackupRef, IsolationTier, LegacyChoice, LegacySandboxType, MigrationError, MigrationItem,
    MigrationOption, MigrationOutcome, MigrationShown, MigrationStatus,
};
pub use model::{
    HostCopyShown, MemoryFit, ModelReadiness, ModelStatus, Preparation, Readiness, ReadyFor,
    Residency,
};
pub use permissions::{PermissionLine, PermissionStatus};
pub use progress::ProgressShown;
pub use refusal::{
    CategoryCode, ContractCode, EvidenceCode, MigrationCode, ModelMemoryCode, PolicyCode,
    PolicyCodeError, Refusal, RefusalCode, Remedy,
};
pub use sandbox_evidence::{
    CapabilityLine, SandboxEvidence, SandboxSection, SectionShown, SANDBOX_NOTICE,
};
pub use text::{ShownText, ShownTextError, MAX_SHOWN_CHARS};
pub use version::{
    read_view, ContractReadError, ContractVersion, Downgraded, Read, ReadPurpose,
    OLDEST_READABLE_VERSION, PRODUCT_CONTRACT_VERSION,
};
pub use view::{ProductView, ShownAt, ViewError, ViewSubject, ViewSubjectKind};
