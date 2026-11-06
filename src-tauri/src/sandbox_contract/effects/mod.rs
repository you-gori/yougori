//! Exact external effects, release budgets and revocation bounds
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM part §2.5, §4.5, §4.6, §6.3,
//! §9.2 VM-N2, §10.5 VM-W31, §12.2 VM-P13, VM-P14, VM-P30–VM-P33, §12.3 models 2 and 4,
//! VM-D12). Tier 0 only (§12.1): pure, synchronous library code over fakes.
//!
//! - [`EffectDescription`] is the immutable description of one external effect (§9.2
//!   line 2344). Its canonical digest is the effect's identity ([`EffectId`]); order that
//!   carries no meaning (named parameters, attachments, preconditions, unordered lists)
//!   does not change it, and every other field does.
//! - [`OperationCapability`] binds the description to one attempt (§4.6 lines
//!   2016–2020): principal, sandbox, generations, policy version, executor, lease,
//!   expiry, nonce and idempotency requirement. [`CapabilityKey`] seals it.
//! - [`EffectRecord`] is the durable state machine of §9.2 lines 2348–2349, and
//!   [`EffectController`] drives it through ports: the CORE-04 coordinator for
//!   generations, leases and revocation ([`AuthorityPort`]), the CORE-06 audit journal
//!   ([`AuditPort`]), a durable store ([`EffectStore`]) and a narrow executor
//!   ([`EffectExecutor`]) that reconstructs the outbound operation itself.
//! - [`StandingDelegation`] and [`IndividualApproval`] are the two authorization bases
//!   (§4.6, VM-W31), with central budget reservations in [`AuthorizationBook`].
//! - [`ReleaseLedger`] accounts every declared release channel (§2.5) under
//!   `counted_bytes_out <= sum(channel_budget) + documented_reserved_in_flight_allowance`.
//!   It bounds bytes, not all information leakage.
//! - [`PostRevocationBounds`], [`RevocationAck`] and [`ReplayGuard`] cover §2.5 lines
//!   1819–1824 and §6.3.
//! - [`check_effect_model`] and [`check_budget_model`] are the exhaustive small-state
//!   checks of §12.3 models 2 and 4, run against this module's own transition and
//!   reservation code.
//!
//! No exactly-once promise is made for a provider without idempotency keys or checkable
//! preconditions (§9.2 line 2361); an uncertain outcome is reported and reconciled
//! before any retry (§4.6 line 2026).

/// Declares an internally tagged enum whose every variant refuses unknown fields when
/// read. Serde ignores fields after the tag of a unit variant even with
/// `deny_unknown_fields`, so reading goes through a twin enum whose unit variants are
/// empty struct variants; the written form is unchanged. The pattern is the one in
/// `foundation/report/mod.rs`, kept local so this module depends on no other's macros.
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

/// Declares a name type checked against the ids.rs identifier grammar.
macro_rules! effect_name {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Accepts the ids.rs identifier grammar: 1–128 letters, digits, '.', '_', ':'
            /// or '-', starting with a letter or digit.
            pub fn new(
                value: impl Into<String>,
            ) -> Result<Self, crate::foundation::ids::IdError> {
                let value = value.into();
                crate::foundation::ids::validate_identifier(&value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                Self::new(<String as serde::Deserialize>::deserialize(deserializer)?)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

/// Declares a digest-backed handle type.
macro_rules! digest_handle {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(
            Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(crate::foundation::ids::Digest);

        impl $name {
            pub const fn new(digest: crate::foundation::ids::Digest) -> Self {
                Self(digest)
            }

            pub const fn digest(&self) -> &crate::foundation::ids::Digest {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

mod budget;
mod canonical;
mod capability;
mod contract;
mod controller;
mod delegation;
mod description;
mod executor;
mod experiment;
mod models;
mod replay;
mod revocation;
mod secrets;
mod state;

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod tests;

pub use budget::{
    AccountingPolicy, ChannelBudget, ChannelDeclaration, ChannelKey, ChannelUsage,
    InFlightAllowance, PolicyError, ReleaseChannelKind, ReleaseCharge, ReleaseLedger,
    ReleasePolicy, ReleaseRefusal, ReleaseRefusalReason, ReleaseReservation, ReservationToken,
    TrustClass, WireMeasure, DEFAULT_GENERAL_RELEASE_BUDGET_BYTES, MAX_RATIONALE_BYTES,
};
pub use canonical::{
    CanonicalError, CanonicalValue, ParamName, Parameters, RawParameters, RawValue, MAX_RAW_DEPTH,
};
pub use capability::{
    AuthorizationBasis, BoundField, CapabilityKey, CapabilityRefusal, ExecutorIdentity,
    ExecutorName, Nonce, OperationCapability, PolicyVersion, SealedCapability, CAPABILITY_DOMAIN,
    MIN_KEY_BYTES,
};
pub use contract::{
    ContractRefusal, ContractRegistry, DeliveryGuarantee, ListOrder, OperationContract, ParamKind,
    ParamSpec, PayloadRule, RouteSpec, ScalarKind,
};
pub use controller::{
    AuditPort, AuthorityPort, AuthorizationRequest, ControllerConfig, CoordinatorEffectAuthority,
    DispatchOutcome, EffectController, EffectError, EffectStore, JournalAudit, LeaseView,
    PersistedEffects, RevocationReport, SandboxStanding, StoreFailure, UncertainReport,
};
pub use delegation::{
    ApprovalId, AuthorizationBook, BudgetHold, BudgetRefusal, DelegationBudget, DelegationId,
    DelegationScope, HoldState, IndividualApproval, MaterialChange, ScopeChange, ScopeViolation,
    StandingDelegation,
};
pub use description::{
    AccountRef, AttachmentName, CostCeiling, Deadline, DescriptionError, Destination,
    EffectDescription, EffectFields, EffectId, Idempotency, IdempotencyKey, IdempotencyRequirement,
    IssuerId, OperationKey, OperationName, OperationNameError, PayloadMismatch, PayloadRef,
    Precondition, ProviderId, ResourceRef, ReviewedArtifact, RouteRef, SandboxRef,
    DESCRIPTION_DOMAIN, HTTP_VERBS,
};
pub use executor::{
    EffectExecutor, ExecutorOutcome, ExecutorRefusal, ExecutorReport, NarrowExecutor,
    OutboundRequest, PayloadStore, PermittedResponse, ProviderLookup, ProviderPort, ProviderReply,
    RequestContent, TypedOperation, IDEMPOTENCY_HEADER_BYTES, PRECONDITION_HEADER_BYTES,
};
pub use experiment::{
    run_mutation_corpus, ApprovalMode, ExperimentError, ModeResult, MutationComparison,
};
pub use models::{
    check_budget_model, check_effect_model, BudgetModelBounds, Counterexample, EffectModelBounds,
    ModelReport,
};
pub use replay::{CompactionReport, NonceRecord, ReplayGuard, ReplayRefusal};
pub use revocation::{
    AckEntry, AckRefusal, BoundNotApplicable, EnforcementPoint, PostRevocationBounds,
    RemoteEnforcementPoint, RemoteLease, RemoteRefusal, RevocationAck, RevocationRecord,
    RevocationRegistry,
};
pub use secrets::{
    CanaryToken, CredentialHandle, CredentialRefusal, ExposureProfile, ExternalCredential,
    GuestExposure, SecretClass, ShortLivedTerms,
};
pub use state::{
    AuditMark, DispatchStep, EffectFailure, EffectPhase, EffectReceipt, EffectRecord, EffectState,
    HeldReservation, Observation, ProviderResult, Reconciliation, ReconciliationSource, SettleStep,
    Settlement, StateRefusal, TransitionEntry, UnknownCause,
};
