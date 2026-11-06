//! V08: tool/Hub capability declarations and the shared preview and refusal schema
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §1.3, §2.4, §4.5, §4.6;
//! the pure halves of VM-W37 and VM-W54; scenarios VM-P03, VM-P46 and VM-P47; Tier 0,
//! §12.1).
//!
//! This is the schema and preview layer only. Wiring it into the existing Hub/tool
//! formats, setup planning and CLI commands (`setup/src/{format,plan}.rs`,
//! `src-tauri/src/setups/`, `cli/src/hub/`, `cli/src/{public,parse,security}.rs`) is
//! later work owned by VM-W37, VM-W53 and VM-W54 integration. Nothing here launches,
//! prompts, resolves a name or reads host state.
//!
//! - [`schema`]: a versioned, strictly read declaration in which a template or tool asks
//!   for sandboxes (VM execution profile and persistence class), data access, typed
//!   provider operations, exact destinations, credentials by §4.5 class and extension
//!   executors. Unknown versions, fields, capability kinds and extension runtimes, and
//!   every field that would hand the declaration authority (a ceiling, a delegation, an
//!   approval grant, satisfied evidence, a generation, trust), refuse with typed codes.
//! - [`compile`]: a declaration is a request, never a grant. Compiling yields a V01
//!   [`RequestDocument`](crate::sandbox_contract::policy::RequestDocument) that V01's
//!   [`Validator`](crate::sandbox_contract::policy::Validator) checks and
//!   [`resolve`](crate::sandbox_contract::policy::resolve) intersects with the product
//!   ceiling and the delegation (§2.4). Required capabilities become V01 dependencies, so
//!   removing one refuses planning with V01's reason; optional ones are dropped and shown.
//!   Every sandbox and every extension executor adds the `vm_sandbox` requirement, which
//!   only a VM sandbox satisfies (VM-D4–VM-D6; line 2478).
//! - [`preview`]: one serializable [`PolicyPreview`] built from V01's resolved policy and
//!   launch outcome, with a deterministic text rendering and a JSON form of the same
//!   value (VM-W37 "validate and preview"; VM-W54 "UI and CLI resolve the same policy").
//!   Facets are reported one by one with their verdicts, never as a score (§1.3).
//! - [`refusal`]: a closed, versioned set of stable snake_case codes for every
//!   declaration, validation, launch and non-interactive refusal reachable here, each
//!   with a one-line message and structured detail (VM-W54).
//! - [`noninteractive`]: a non-interactive run refuses with codes on missing
//!   authorization or any required approval; it never prompts and never proceeds.
//! - [`pipeline`]: read → compile → validate → resolve → plan, in one call.
//!
//! Claims. A preview describes the resolved contract and the launch decision. It is not
//! evidence that any mechanism enforces the contract; a contract digest identifies the
//! contract and an issuer identifies who issued it, and neither proves enforcement
//! (§2.4 line 1804). Contract requirements describe what the contract grants; host
//! requirements are met only by CORE-01 host evidence, which a declaration can never
//! supply.

/// Defines an internally tagged, snake_case enum whose deserialization refuses unknown
/// fields for every variant, unit variants included. serde ignores unknown fields beside
/// the tag of a unit variant even with `deny_unknown_fields`, so reading goes through a
/// twin enum whose unit variants are empty struct variants. Copied from
/// `strict_policy_enum!` in `sandbox_contract/policy/mod.rs`, kept local.
macro_rules! strict_declaration_enum {
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

pub mod compile;
pub mod noninteractive;
pub mod pipeline;
pub mod preview;
pub mod refusal;
pub mod schema;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_preview;

pub use compile::{CompiledCapability, CompiledDeclaration, CredentialTerms, DeclaredContext};
pub use noninteractive::{approval_status, decide_non_interactive, NonInteractiveDecision};
pub use pipeline::{evaluate, Evaluation, LaunchOutcome, OutcomeMismatch};
pub use preview::{
    AccessLine, ApprovalLine, ApprovalStatus, ApprovalsView, BudgetLine, ContractLine,
    ContractMeaning, CredentialLine, FacetView, IssuerLine, IssuerMeaning, JudgedBy, PolicyPreview,
    PreviewDecision, PreviewInputs, PreviewNotice, PreviewVersion, RemovalEffect, RemovedLine,
    RunLine, VerdictLine, VerdictStatus, PREVIEW_VERSION,
};
pub use refusal::{
    Refusal, RefusalCode, RefusalDetail, RefusalReport, RefusalSchemaVersion, RefusalStage,
    REFUSAL_SCHEMA_VERSION,
};
pub use schema::{
    read_declaration, Capability, CapabilityDeclaration, CredentialClass, DataClass, Declaration,
    DeclarationVersion, ExecutionProfile, ExtensionDeclaration, ExtensionName, ExtensionRuntime,
    Need, PersistenceClass, SandboxDeclaration, AUTHORITY_FIELDS, DECLARATION_VERSION,
};
