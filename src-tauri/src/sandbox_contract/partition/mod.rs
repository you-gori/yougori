//! VM-N1 workflow compartments and VM-N4 fetch by approved content identity
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §9.1, §9.4, §9.5, §5.3–§5.4,
//! §2.5, §12.2 VM-P45, §12.3 model 6, §10.7 VM-W57 and VM-D12).
//!
//! Tier 0 library code (VM part §12.1): pure, synchronous and deterministic. Nothing here
//! starts a VM, touches a network or reads a host setting; registries are fakes behind
//! [`RegistryPort`], and time comes from [`crate::foundation::ids::Clock`].
//!
//! **VM-N1** (§9.1). A [`Workflow`] is a DAG of [`Step`]s with labelled inputs, required
//! [`Authority`]s, labelled outputs and an execution cost. A [`ConflictRelation`] names
//! authority combinations no compartment may hold together. [`compile`] is the simple
//! rules-based partitioner and [`compile_exhaustive`] the offline oracle for small
//! workflows; both choose compartments and an execution order through one evaluation of
//! the §9.1 objective (VM startup/retention + data transfer + workflow delay + approvals)
//! under its five constraints, and neither claims universal optimality. Every
//! [`CompiledPlan`] and every refusal carries an [`Explanation`]. [`PartitionRun`] keeps
//! labels and history for dynamic steps, revocations and later generations.
//! [`check_model6`] is the exhaustive small-state check of §12.3 model 6.
//!
//! **VM-N4** (§9.4, VM-W57). A [`DependencyManifest`] is compiled before private data
//! enters a compute VM. The compute VM may only ask the [`ContentService`] for approved
//! object IDs; a separate [`FetchService`] resolves them to pinned registry artifacts and
//! imports them through the CORE-02 catalog, which verifies hashes, publisher trust and
//! scope. URLs, package names, queries and redirects from the private VM are refused.
//!
//! **Comparison** (§9.1 experiment). [`compare_arms`] measures one broad VM, manually
//! separated VMs and the compiler on fakes; a [`ComparisonRecord`] carries the
//! fake-substrate provenance of CORE-08 and backs no security or performance claim.

/// Declares an internally tagged enum whose every variant refuses unknown fields when
/// read (copied from `foundation/report/mod.rs`). Serde ignores fields after the tag of a
/// unit variant, so reading goes through a twin enum in which each unit variant is an
/// empty struct variant; the written form is the same.
macro_rules! strict_tagged_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident (tag = $tag:literal, wire = $wire:ident, wire_name = $wire_name:literal) {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $({
                    $(
                        $(#[$field_meta:meta])*
                        $field:ident : $field_type:ty
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
                $variant $({
                    $(
                        $(#[$field_meta])*
                        $field: $field_type
                    ),*
                })?
            ),*
        }

        #[derive(serde::Deserialize)]
        #[serde(tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
        enum $wire {
            $(
                $variant {
                    $($(
                        $field: $field_type
                    ),*)?
                }
            ),*
        }

        impl From<$wire> for $name {
            fn from(wire: $wire) -> Self {
                match wire {
                    $(
                        $wire::$variant { $($($field),*)? } => Self::$variant $({ $($field),* })?,
                    )*
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let record = crate::foundation::strict_serde::read_tagged(deserializer, $tag)?;
                <$wire as serde::Deserialize>::deserialize(record)
                    .map(Self::from)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

mod authority;
mod claims;
mod compare;
mod compile;
mod contract;
mod fetch;
mod label;
mod manifest;
mod model;
mod names;
mod oracle;
mod plan;
mod run;
mod workflow;

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod tests_fetch;
#[cfg(test)]
mod tests_partition;

pub use authority::{Authority, AuthorityKind, Conflict, ConflictReason, ConflictRelation};
pub use claims::{novelty_records, ClaimResult, NoveltyRecord};
pub use compare::{
    compare_arms, Arm, ArmMetrics, AttackPlan, ComparisonError, ComparisonRecord, COMPARISON_DOMAIN,
};
pub use compile::{compile, CompileRefusal};
pub use contract::{Approval, ConfidentialityStatus, ContractDestination, ReleaseContract};
pub use fetch::{
    CacheResult, ChannelClassification, ContentRefusal, ContentRequest, ContentService, FetchMode,
    FetchOutcome, FetchRefusal, FetchService, MetadataLeak, MetadataObservation, PrefetchReport,
    RegistrySource, RequestKind, ServedObject, MAX_REQUEST_BYTES,
};
pub use label::{Integrity, Label, LabelOrigin};
pub use manifest::{
    DependencyManifest, LockEntry, ManifestCompiler, ManifestDraft, ManifestEntry, ManifestOrigin,
    ManifestRefusal, ManifestUpdate, MetadataReleaseAuthorization, PackageName, PinnedArtifact,
    PinnedSource, PrivateExposure, RegistryError, RegistryPort, RegistryReply, ResolvedArtifact,
    UpdateApproval, MANIFEST_DOMAIN, MAX_MANIFEST_ENTRIES,
};
pub use model::{
    check_model6, model_policy, plan_acceptor, Counterexample, ModelBounds, ModelBoundsError,
    ModelReport, MODEL6_MAX_STEPS,
};
pub use names::{ContractId, DataId, LabelTag, StepId, VolumeId};
pub use oracle::{compile_exhaustive, OracleReport, ORACLE_MAX_STEPS};
pub use plan::{
    Budgets, Compartment, CompiledPlan, CostBreakdown, CostWeights, Crossing, CrossingSource,
    Explanation, ExternalRelease, PartitionMethod, PartitionPolicy, PlacementRule, Reason,
    ScheduledStep, Violation, COMPARTMENT_DOMAIN, VM_D12_TASK_ABSOLUTE_MS, VM_D12_TASK_IDLE_MS,
};
pub use run::{
    DynamicOrigin, DynamicPlacement, DynamicStep, PartitionRun, ReleaseRecord, RetainedState,
    RunRefusal,
};
pub use workflow::{
    SourceData, Step, StepCost, StepOutput, Workflow, WorkflowError, WorkflowSpec, MAX_STEPS,
    MAX_STEP_ITEMS, WORKFLOW_DOMAIN,
};
