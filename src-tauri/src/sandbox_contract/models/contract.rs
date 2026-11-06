//! The vocabulary the small models and the VM-N3 generator share: named invariants
//! (§2.6, §12.3), guards with their enforcement points and the common dependencies of
//! §2.1, adversary injections (VM §1.1, VM-N3), seeded defects (VM-N3 experiment) and the
//! configuration one model runs under.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::explore::{explore, run_steps, Bounds, Exploration, ScriptOutcome, ScriptStep};
use super::{boundary, budget, effect, egress, lifecycle, snapshot, ModelError};

/// The six small models. Effect, lifecycle, budget and snapshot are §12.3 models 2–5;
/// egress and boundary hold the perimeter and host-boundary invariants of §2.6 and the
/// network faults of VM-N3. Models 1 (policy) and 6 (workflow partition) belong to the
/// policy and partition contracts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelKind {
    Effect,
    Lifecycle,
    Budget,
    Snapshot,
    Egress,
    Boundary,
}

impl ModelKind {
    pub const ALL: [Self; 6] = [
        Self::Effect,
        Self::Lifecycle,
        Self::Budget,
        Self::Snapshot,
        Self::Egress,
        Self::Boundary,
    ];

    /// The invariants checked in this model; each invariant belongs to one model.
    pub const fn invariants(self) -> &'static [InvariantId] {
        use InvariantId::*;
        match self {
            Self::Effect => &[
                TicketExactScope,
                FailedAuthorizationDenies,
                AuthorizationAndReservationPrecedeDispatch,
                EffectBindingFixed,
                UncertainOutcomeNotBlindlyRetried,
            ],
            Self::Lifecycle => &[
                EntrypointAfterChecks,
                NoAuthorizationAfterRevocationAck,
                NoAuthorityBeforeEnforcement,
                RevocationMonotonic,
                CleanupNeverRevivesGeneration,
            ],
            Self::Budget => &[ReleaseWithinCeiling, ReservationsWithinBudget],
            Self::Snapshot => &[
                SnapshotCannotRevive,
                RevokedIdentityNotResurrected,
                RestoredCloneUniqueGeneration,
                StaleApprovalsFail,
                OnlyGoldenSnapshotsPooled,
            ],
            Self::Egress => &[NoForbiddenEgress],
            Self::Boundary => &[
                GuestCannotSelectHostTarget,
                ExecutorCannotWiden,
                PromotionAppliesReviewedBytes,
                CleanupWithinManagedRoots,
                NoFallbackWeakening,
            ],
        }
    }

    /// The guards this model gives a meaning to.
    pub fn guards(self) -> Vec<Guard> {
        Guard::ALL
            .into_iter()
            .filter(|guard| guard.model() == self)
            .collect()
    }

    /// The plan clause the model formalizes.
    pub const fn clause(self) -> &'static str {
        match self {
            Self::Effect => "VM §12.3 model 2; §2.6; VM-P13, VM-P30, VM-P31",
            Self::Lifecycle => "VM §12.3 model 3; §6.1, §6.3; §2.6; VM-P14, VM-P19, VM-P24",
            Self::Budget => "VM §12.3 model 4; §2.5; VM-P32, VM-P33",
            Self::Snapshot => "VM §12.3 model 5; §6.6; §2.6; VM-P21, VM-P43",
            Self::Egress => "VM §2.6, VM-N3 network faults; VM-P06, VM-P07, VM-P11, VM-P29",
            Self::Boundary => "VM §2.6; VM-P16, VM-P42, VM-P47, VM-P49",
        }
    }
}

/// A named invariant: a predicate over the states of one model (§2.6, §12.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantId {
    // §2.6, in the order of lines 1828–1837.
    EntrypointAfterChecks,
    GuestCannotSelectHostTarget,
    ExecutorCannotWiden,
    TicketExactScope,
    FailedAuthorizationDenies,
    NoAuthorizationAfterRevocationAck,
    SnapshotCannotRevive,
    PromotionAppliesReviewedBytes,
    CleanupWithinManagedRoots,
    NoFallbackWeakening,
    // §12.3 model 2.
    AuthorizationAndReservationPrecedeDispatch,
    EffectBindingFixed,
    UncertainOutcomeNotBlindlyRetried,
    // §12.3 model 3.
    NoAuthorityBeforeEnforcement,
    RevocationMonotonic,
    CleanupNeverRevivesGeneration,
    // §12.3 model 4.
    ReleaseWithinCeiling,
    ReservationsWithinBudget,
    // §12.3 model 5 and §6.6.
    RevokedIdentityNotResurrected,
    RestoredCloneUniqueGeneration,
    StaleApprovalsFail,
    OnlyGoldenSnapshotsPooled,
    // Perimeter (§2.2 unauthorized effects; VM-P06, VM-P11).
    NoForbiddenEgress,
}

impl InvariantId {
    pub const ALL: [Self; 23] = [
        Self::EntrypointAfterChecks,
        Self::GuestCannotSelectHostTarget,
        Self::ExecutorCannotWiden,
        Self::TicketExactScope,
        Self::FailedAuthorizationDenies,
        Self::NoAuthorizationAfterRevocationAck,
        Self::SnapshotCannotRevive,
        Self::PromotionAppliesReviewedBytes,
        Self::CleanupWithinManagedRoots,
        Self::NoFallbackWeakening,
        Self::AuthorizationAndReservationPrecedeDispatch,
        Self::EffectBindingFixed,
        Self::UncertainOutcomeNotBlindlyRetried,
        Self::NoAuthorityBeforeEnforcement,
        Self::RevocationMonotonic,
        Self::CleanupNeverRevivesGeneration,
        Self::ReleaseWithinCeiling,
        Self::ReservationsWithinBudget,
        Self::RevokedIdentityNotResurrected,
        Self::RestoredCloneUniqueGeneration,
        Self::StaleApprovalsFail,
        Self::OnlyGoldenSnapshotsPooled,
        Self::NoForbiddenEgress,
    ];

    /// The ten invariants of §2.6, in plan order.
    pub const SECTION_2_6: [Self; 10] = [
        Self::EntrypointAfterChecks,
        Self::GuestCannotSelectHostTarget,
        Self::ExecutorCannotWiden,
        Self::TicketExactScope,
        Self::FailedAuthorizationDenies,
        Self::NoAuthorizationAfterRevocationAck,
        Self::SnapshotCannotRevive,
        Self::PromotionAppliesReviewedBytes,
        Self::CleanupWithinManagedRoots,
        Self::NoFallbackWeakening,
    ];

    /// The model whose states the predicate ranges over.
    pub fn model(self) -> ModelKind {
        ModelKind::ALL
            .into_iter()
            .find(|kind| kind.invariants().contains(&self))
            .unwrap_or(ModelKind::Boundary)
    }

    /// The plan clause the invariant comes from.
    pub const fn clause(self) -> &'static str {
        match self {
            Self::EntrypointAfterChecks
            | Self::GuestCannotSelectHostTarget
            | Self::ExecutorCannotWiden
            | Self::TicketExactScope
            | Self::FailedAuthorizationDenies
            | Self::NoAuthorizationAfterRevocationAck
            | Self::SnapshotCannotRevive
            | Self::PromotionAppliesReviewedBytes
            | Self::CleanupWithinManagedRoots
            | Self::NoFallbackWeakening => "VM §2.6",
            Self::AuthorizationAndReservationPrecedeDispatch
            | Self::EffectBindingFixed
            | Self::UncertainOutcomeNotBlindlyRetried => "VM §12.3 model 2",
            Self::NoAuthorityBeforeEnforcement
            | Self::RevocationMonotonic
            | Self::CleanupNeverRevivesGeneration => "VM §12.3 model 3; §6.1, §6.3",
            Self::ReleaseWithinCeiling | Self::ReservationsWithinBudget => "VM §12.3 model 4; §2.5",
            Self::RevokedIdentityNotResurrected
            | Self::RestoredCloneUniqueGeneration
            | Self::StaleApprovalsFail
            | Self::OnlyGoldenSnapshotsPooled => "VM §12.3 model 5; §6.6",
            Self::NoForbiddenEgress => "VM §2.2 unauthorized effects; VM-P06, VM-P11",
        }
    }

    /// The property in words.
    pub const fn statement(self) -> &'static str {
        match self {
            Self::EntrypointAfterChecks => {
                "no workload entrypoint runs before mandatory evidence and policy checks succeed"
            }
            Self::GuestCannotSelectHostTarget => {
                "a guest-controlled message cannot select a host executable, arbitrary host path \
                 or privileged endpoint"
            }
            Self::ExecutorCannotWiden => {
                "no executor API permits widening its fixed operation or reading its underlying \
                 credential"
            }
            Self::TicketExactScope => {
                "one operation ticket authorizes only its exact tenant, generation, resource and \
                 payload, once"
            }
            Self::FailedAuthorizationDenies => {
                "failed or unavailable authorization denies new effects"
            }
            Self::NoAuthorizationAfterRevocationAck => {
                "new authorization cannot succeed after the revocation acknowledgment's \
                 linearization point"
            }
            Self::SnapshotCannotRevive => {
                "old snapshot identities cannot revive authority or spend a budget again"
            }
            Self::PromotionAppliesReviewedBytes => {
                "artifact promotion cannot apply bytes different from those reviewed and \
                 authorized"
            }
            Self::CleanupWithinManagedRoots => {
                "cleanup cannot follow guest-created paths outside the supervisor's managed roots"
            }
            Self::NoFallbackWeakening => {
                "no compatibility fallback changes a required VM boundary or grants additional \
                 authority"
            }
            Self::AuthorizationAndReservationPrecedeDispatch => {
                "authorization and reservation precede every dispatch"
            }
            Self::EffectBindingFixed => {
                "identity, operation digest and epoch do not change between authorization and \
                 dispatch"
            }
            Self::UncertainOutcomeNotBlindlyRetried => {
                "an uncertain external outcome is reconciled before any retry"
            }
            Self::NoAuthorityBeforeEnforcement => {
                "no active authority exists before enforcement is ready"
            }
            Self::RevocationMonotonic => {
                "revocation is monotonic: a revoked boot never regains authority and the \
                 tombstone never moves back"
            }
            Self::CleanupNeverRevivesGeneration => {
                "cleanup retries and redelivered transitions never revive a generation"
            }
            Self::ReleaseWithinCeiling => {
                "counted bytes out stay within the channel budgets plus the documented reserved \
                 in-flight allowance"
            }
            Self::ReservationsWithinBudget => {
                "concurrent reservations never exceed the channel budget"
            }
            Self::RevokedIdentityNotResurrected => {
                "older persisted state cannot resurrect a revoked identity"
            }
            Self::RestoredCloneUniqueGeneration => {
                "a restored clone gets a unique, never reused generation"
            }
            Self::StaleApprovalsFail => "approvals from before a restore or epoch change fail",
            Self::OnlyGoldenSnapshotsPooled => {
                "only golden snapshots created before tenant inputs are pool-eligible"
            }
            Self::NoForbiddenEgress => {
                "no packet from the sandbox reaches a destination outside its own policy"
            }
        }
    }
}

/// Where a guard runs. Guest-located guards are bypassed by guest root, which the threat
/// model grants (VM §1.1, §1.2): they are never counted as a wall against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    Guest,
    Host,
    /// Outside Yougori's trust boundary (a provider); an assumption, not a Yougori guard.
    External,
}

/// The component that enforces a guard (VM-N3 "enforcement points").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementPoint {
    GuestAgent,
    HostPerimeter,
    HostRelay,
    Broker,
    AuthorizationService,
    ReservationLedger,
    Supervisor,
    DurableStore,
    Restorer,
    PromotionApplier,
    CleanupWorker,
    LaunchPlanner,
    Provider,
}

impl EnforcementPoint {
    pub const fn location(self) -> Location {
        match self {
            Self::GuestAgent => Location::Guest,
            Self::Provider => Location::External,
            _ => Location::Host,
        }
    }
}

/// The common dependencies of §2.1 that can defeat several supposed walls at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dependency {
    SharedParser,
    HostKernel,
    SharedPrivilege,
    UpdateKey,
    PolicyError,
}

impl Dependency {
    pub const ALL: [Self; 5] = [
        Self::SharedParser,
        Self::HostKernel,
        Self::SharedPrivilege,
        Self::UpdateKey,
        Self::PolicyError,
    ];

    /// Every guard that fails when this dependency fails.
    pub fn dependents(self) -> Vec<Guard> {
        Guard::ALL
            .into_iter()
            .filter(|guard| guard.dependencies().contains(&self))
            .collect()
    }
}

/// One guard of the security contract: a check at one enforcement point (VM-N3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Guard {
    // Effect model.
    FailClosedAuthorization,
    TicketBinding,
    SingleUseTicket,
    DispatchRequiresReservation,
    NoBlindRetry,
    // Lifecycle model.
    LaunchOrderCheck,
    AuthoritativeEpochCheck,
    AckAfterEnforcerConfirms,
    TransitionGenerationCheck,
    DurableRevocation,
    // Budget model.
    CentralReservation,
    SenderEnforcesReservation,
    RetransmitFromAllowance,
    // Snapshot model.
    DurableEpochOutsideSnapshot,
    TombstoneCheckOnRestore,
    UniqueGeneration,
    InvalidateApprovalsOnRestore,
    ApprovalBoundToGeneration,
    HostBudgetLedger,
    GoldenOnlyPool,
    // Egress model.
    GuestEgressPolicy,
    HostFirewall,
    RelayChannelIdentity,
    RelayAddressCheck,
    // Boundary model.
    ClosedMessageSchema,
    ExecutorFixedOperation,
    CredentialSealed,
    ProviderScopedCredential,
    PromotionDigestRecheck,
    PromotionHostStaging,
    HandleBasedCleanup,
    FallbackKeepsVmBoundary,
}

impl Guard {
    pub const ALL: [Self; 32] = [
        Self::FailClosedAuthorization,
        Self::TicketBinding,
        Self::SingleUseTicket,
        Self::DispatchRequiresReservation,
        Self::NoBlindRetry,
        Self::LaunchOrderCheck,
        Self::AuthoritativeEpochCheck,
        Self::AckAfterEnforcerConfirms,
        Self::TransitionGenerationCheck,
        Self::DurableRevocation,
        Self::CentralReservation,
        Self::SenderEnforcesReservation,
        Self::RetransmitFromAllowance,
        Self::DurableEpochOutsideSnapshot,
        Self::TombstoneCheckOnRestore,
        Self::UniqueGeneration,
        Self::InvalidateApprovalsOnRestore,
        Self::ApprovalBoundToGeneration,
        Self::HostBudgetLedger,
        Self::GoldenOnlyPool,
        Self::GuestEgressPolicy,
        Self::HostFirewall,
        Self::RelayChannelIdentity,
        Self::RelayAddressCheck,
        Self::ClosedMessageSchema,
        Self::ExecutorFixedOperation,
        Self::CredentialSealed,
        Self::ProviderScopedCredential,
        Self::PromotionDigestRecheck,
        Self::PromotionHostStaging,
        Self::HandleBasedCleanup,
        Self::FallbackKeepsVmBoundary,
    ];

    pub const fn model(self) -> ModelKind {
        match self {
            Self::FailClosedAuthorization
            | Self::TicketBinding
            | Self::SingleUseTicket
            | Self::DispatchRequiresReservation
            | Self::NoBlindRetry => ModelKind::Effect,
            Self::LaunchOrderCheck
            | Self::AuthoritativeEpochCheck
            | Self::AckAfterEnforcerConfirms
            | Self::TransitionGenerationCheck
            | Self::DurableRevocation => ModelKind::Lifecycle,
            Self::CentralReservation
            | Self::SenderEnforcesReservation
            | Self::RetransmitFromAllowance => ModelKind::Budget,
            Self::DurableEpochOutsideSnapshot
            | Self::TombstoneCheckOnRestore
            | Self::UniqueGeneration
            | Self::InvalidateApprovalsOnRestore
            | Self::ApprovalBoundToGeneration
            | Self::HostBudgetLedger
            | Self::GoldenOnlyPool => ModelKind::Snapshot,
            Self::GuestEgressPolicy
            | Self::HostFirewall
            | Self::RelayChannelIdentity
            | Self::RelayAddressCheck => ModelKind::Egress,
            Self::ClosedMessageSchema
            | Self::ExecutorFixedOperation
            | Self::CredentialSealed
            | Self::ProviderScopedCredential
            | Self::PromotionDigestRecheck
            | Self::PromotionHostStaging
            | Self::HandleBasedCleanup
            | Self::FallbackKeepsVmBoundary => ModelKind::Boundary,
        }
    }

    pub const fn point(self) -> EnforcementPoint {
        use EnforcementPoint::*;
        match self {
            Self::GuestEgressPolicy => GuestAgent,
            Self::HostFirewall => HostPerimeter,
            Self::RelayChannelIdentity
            | Self::RelayAddressCheck
            | Self::SenderEnforcesReservation
            | Self::RetransmitFromAllowance
            | Self::ClosedMessageSchema => HostRelay,
            Self::TicketBinding
            | Self::SingleUseTicket
            | Self::NoBlindRetry
            | Self::ExecutorFixedOperation
            | Self::CredentialSealed => Broker,
            Self::FailClosedAuthorization
            | Self::AuthoritativeEpochCheck
            | Self::ApprovalBoundToGeneration => AuthorizationService,
            Self::DispatchRequiresReservation
            | Self::CentralReservation
            | Self::HostBudgetLedger => ReservationLedger,
            Self::LaunchOrderCheck
            | Self::AckAfterEnforcerConfirms
            | Self::TransitionGenerationCheck => Supervisor,
            Self::DurableRevocation | Self::DurableEpochOutsideSnapshot => DurableStore,
            Self::TombstoneCheckOnRestore
            | Self::UniqueGeneration
            | Self::InvalidateApprovalsOnRestore
            | Self::GoldenOnlyPool => Restorer,
            Self::ProviderScopedCredential => Provider,
            Self::PromotionDigestRecheck | Self::PromotionHostStaging => PromotionApplier,
            Self::HandleBasedCleanup => CleanupWorker,
            Self::FallbackKeepsVmBoundary => LaunchPlanner,
        }
    }

    pub const fn location(self) -> Location {
        self.point().location()
    }

    /// The common dependencies whose failure also fails this guard. This map is a
    /// modelling assumption to be replaced by the implementation's real dependencies;
    /// every host guard depends on the update key that signs host components.
    pub const fn dependencies(self) -> &'static [Dependency] {
        use Dependency::*;
        match self {
            Self::GuestEgressPolicy => &[PolicyError],
            Self::HostFirewall => &[PolicyError, HostKernel, UpdateKey],
            Self::RelayChannelIdentity => &[HostKernel, UpdateKey],
            Self::RelayAddressCheck => &[PolicyError, SharedParser, UpdateKey],
            Self::TicketBinding => &[SharedParser, SharedPrivilege, UpdateKey],
            Self::SingleUseTicket
            | Self::NoBlindRetry
            | Self::ExecutorFixedOperation
            | Self::CredentialSealed => &[SharedPrivilege, UpdateKey],
            Self::SenderEnforcesReservation
            | Self::ClosedMessageSchema
            | Self::ApprovalBoundToGeneration => &[SharedParser, UpdateKey],
            Self::RetransmitFromAllowance | Self::HandleBasedCleanup => &[HostKernel, UpdateKey],
            Self::FallbackKeepsVmBoundary => &[PolicyError, UpdateKey],
            Self::ProviderScopedCredential => &[],
            Self::FailClosedAuthorization
            | Self::DispatchRequiresReservation
            | Self::LaunchOrderCheck
            | Self::AuthoritativeEpochCheck
            | Self::AckAfterEnforcerConfirms
            | Self::TransitionGenerationCheck
            | Self::DurableRevocation
            | Self::CentralReservation
            | Self::DurableEpochOutsideSnapshot
            | Self::TombstoneCheckOnRestore
            | Self::UniqueGeneration
            | Self::InvalidateApprovalsOnRestore
            | Self::HostBudgetLedger
            | Self::GoldenOnlyPool
            | Self::PromotionDigestRecheck
            | Self::PromotionHostStaging => &[UpdateKey],
        }
    }

    /// The enforcement assumption the guard provides; when a mutation that disables it
    /// breaks an invariant, this is the missing assumption reported (VM-N3).
    pub const fn assumption(self) -> &'static str {
        match self {
            Self::FailClosedAuthorization => {
                "the authorization service denies when it cannot decide (fail closed)"
            }
            Self::TicketBinding => {
                "the broker dispatches only the exact tenant, resource, payload digest, nonce \
                 and current epoch the ticket was issued for"
            }
            Self::SingleUseTicket => "the broker refuses a ticket that was already consumed",
            Self::DispatchRequiresReservation => {
                "the ledger holds a reservation before every dispatch"
            }
            Self::NoBlindRetry => {
                "an uncertain outcome is reconciled with the provider before any retry"
            }
            Self::LaunchOrderCheck => {
                "the supervisor activates authority only after perimeter, boot evidence and \
                 policy checks succeeded for the current generation"
            }
            Self::AuthoritativeEpochCheck => {
                "new authorizations consult the durable revocation record, not a cached view"
            }
            Self::AckAfterEnforcerConfirms => {
                "revocation is acknowledged only after every enforcement point confirms denial"
            }
            Self::TransitionGenerationCheck => {
                "a transition record applies only to the current, unrevoked generation"
            }
            Self::DurableRevocation => {
                "the revocation tombstone and pending revocation survive a crash"
            }
            Self::CentralReservation => {
                "reservations are checked and taken atomically against one central remaining \
                 budget"
            }
            Self::SenderEnforcesReservation => {
                "the relay counts every byte leaving the trust domain against its reservation"
            }
            Self::RetransmitFromAllowance => {
                "unreserved in-flight bytes are charged to the documented allowance, and the \
                 channel resets when it is spent"
            }
            Self::DurableEpochOutsideSnapshot => {
                "the authorization epoch and tombstone live outside every restorable snapshot"
            }
            Self::TombstoneCheckOnRestore => {
                "the restorer checks the identity tombstone before a clone gets authority"
            }
            Self::UniqueGeneration => {
                "every restored clone gets a fresh generation from the host counter"
            }
            Self::InvalidateApprovalsOnRestore => "a restore invalidates every prior approval",
            Self::ApprovalBoundToGeneration => {
                "an approval is honoured only for its own generation and the current epoch"
            }
            Self::HostBudgetLedger => {
                "budget spending is accounted on the host, never in restorable guest state"
            }
            Self::GoldenOnlyPool => {
                "only snapshots taken before tenant inputs, credentials and connections enter a \
                 pool"
            }
            Self::GuestEgressPolicy => "the guest-side egress policy blocks unlisted destinations",
            Self::HostFirewall => {
                "the host perimeter drops all guest traffic except the relay channel"
            }
            Self::RelayChannelIdentity => {
                "the relay takes the sandbox identity from the host-authoritative channel, never \
                 from the message"
            }
            Self::RelayAddressCheck => {
                "the relay checks the address it actually connects to, not a cached name decision"
            }
            Self::ClosedMessageSchema => {
                "guest messages map to a closed set of declared operations; host executables, \
                 paths and endpoints are not representable"
            }
            Self::ExecutorFixedOperation => "the executor performs only its fixed operation",
            Self::CredentialSealed => "no executor API returns or reveals its credential",
            Self::ProviderScopedCredential => {
                "the provider credential itself is scoped to the fixed operation (external)"
            }
            Self::PromotionDigestRecheck => {
                "the applier re-hashes the bytes and applies only the reviewed digest"
            }
            Self::PromotionHostStaging => {
                "reviewed bytes are copied to host-owned staging the guest cannot modify"
            }
            Self::HandleBasedCleanup => {
                "cleanup uses host-created handles inside managed roots and never follows links"
            }
            Self::FallbackKeepsVmBoundary => {
                "a fallback may only pick another VM backend with the same authority, or refuse"
            }
        }
    }
}

/// An adversary capability or environmental condition (VM §1.1 threat model and the
/// VM-N3 named faults). The models are expected to stay safe under all of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Injection {
    /// Guest root: forges messages, bypasses guest-side guards, opens raw sockets.
    HostileGuest,
    /// Unprivileged malicious code inside the guest, which guest policy still binds.
    UnprivilegedGuestCode,
    ApprovalPayloadChanged,
    RelayIdentitySpoofed,
    /// A ticket presented for another resource.
    TicketRetargeted,
    TicketReplayed,
    StaleDnsAnswer,
    SnapshotEpochRestored,
    /// An old transition record redelivered, as a cleanup retry or queued message.
    RedeliveredTransition,
    /// A provider response lost after dispatch: the outcome is uncertain.
    ResponseLost,
    AuthorizationUnavailable,
    EngineCrash,
    Retransmission,
    ConcurrentRequests,
    ArtifactChangedAfterReview,
    GuestCreatedLink,
    BackendUnavailable,
    /// The supervisor's revocation propagation never arrives within the bound.
    SupervisorDelayed,
}

impl Injection {
    pub const ALL: [Self; 18] = [
        Self::HostileGuest,
        Self::UnprivilegedGuestCode,
        Self::ApprovalPayloadChanged,
        Self::RelayIdentitySpoofed,
        Self::TicketRetargeted,
        Self::TicketReplayed,
        Self::StaleDnsAnswer,
        Self::SnapshotEpochRestored,
        Self::RedeliveredTransition,
        Self::ResponseLost,
        Self::AuthorizationUnavailable,
        Self::EngineCrash,
        Self::Retransmission,
        Self::ConcurrentRequests,
        Self::ArtifactChangedAfterReview,
        Self::GuestCreatedLink,
        Self::BackendUnavailable,
        Self::SupervisorDelayed,
    ];

    /// The models the injection acts in.
    pub const fn models(self) -> &'static [ModelKind] {
        use ModelKind::*;
        match self {
            Self::HostileGuest => &[Egress, Boundary],
            Self::UnprivilegedGuestCode | Self::StaleDnsAnswer => &[Egress],
            Self::RelayIdentitySpoofed => &[Effect, Egress],
            Self::ApprovalPayloadChanged
            | Self::TicketRetargeted
            | Self::TicketReplayed
            | Self::ResponseLost
            | Self::AuthorizationUnavailable => &[Effect],
            Self::SnapshotEpochRestored => &[Snapshot],
            Self::RedeliveredTransition | Self::EngineCrash | Self::SupervisorDelayed => {
                &[Lifecycle]
            }
            Self::Retransmission | Self::ConcurrentRequests => &[Budget],
            Self::ArtifactChangedAfterReview
            | Self::GuestCreatedLink
            | Self::BackendUnavailable => &[Boundary],
        }
    }

    /// Every injection of the threat model. `SupervisorDelayed` only removes
    /// interleavings (propagation never arrives), so safety without it implies safety
    /// with it; it is checked on its own as a named fault.
    pub fn threat_model() -> BTreeSet<Self> {
        Self::ALL
            .into_iter()
            .filter(|injection| *injection != Self::SupervisorDelayed)
            .collect()
    }
}

/// Whether a seeded defect is a policy or a lifecycle defect (VM-N3 experiment).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefectClass {
    Policy,
    Lifecycle,
}

/// A known defect seeded into one model's implementation (VM-N3 experiment). Unlike a
/// disabled guard, several are partial or reordered checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Defect {
    RetryIgnoresUncertainty,
    BindingOmitsPayload,
    BindingOmitsTenant,
    FailOpenOnOutage,
    AuthorityBeforeEvidence,
    AckBeforeEnforcerConfirms,
    CleanupRetryRevivesGeneration,
    RevocationNotDurable,
    NonAtomicReservation,
    HeaderNotCounted,
    CloneKeepsGeneration,
    EpochReadFromSnapshot,
    DirtySnapshotPooled,
    RelayTrustsClaimedIdentity,
    AllowDecisionCachedByName,
}

impl Defect {
    pub const ALL: [Self; 15] = [
        Self::RetryIgnoresUncertainty,
        Self::BindingOmitsPayload,
        Self::BindingOmitsTenant,
        Self::FailOpenOnOutage,
        Self::AuthorityBeforeEvidence,
        Self::AckBeforeEnforcerConfirms,
        Self::CleanupRetryRevivesGeneration,
        Self::RevocationNotDurable,
        Self::NonAtomicReservation,
        Self::HeaderNotCounted,
        Self::CloneKeepsGeneration,
        Self::EpochReadFromSnapshot,
        Self::DirtySnapshotPooled,
        Self::RelayTrustsClaimedIdentity,
        Self::AllowDecisionCachedByName,
    ];

    pub const fn model(self) -> ModelKind {
        match self {
            Self::RetryIgnoresUncertainty
            | Self::BindingOmitsPayload
            | Self::BindingOmitsTenant
            | Self::FailOpenOnOutage => ModelKind::Effect,
            Self::AuthorityBeforeEvidence
            | Self::AckBeforeEnforcerConfirms
            | Self::CleanupRetryRevivesGeneration
            | Self::RevocationNotDurable => ModelKind::Lifecycle,
            Self::NonAtomicReservation | Self::HeaderNotCounted => ModelKind::Budget,
            Self::CloneKeepsGeneration
            | Self::EpochReadFromSnapshot
            | Self::DirtySnapshotPooled => ModelKind::Snapshot,
            Self::RelayTrustsClaimedIdentity | Self::AllowDecisionCachedByName => ModelKind::Egress,
        }
    }

    /// The guard whose implementation the defect breaks.
    pub const fn guard(self) -> Guard {
        match self {
            Self::RetryIgnoresUncertainty => Guard::NoBlindRetry,
            Self::BindingOmitsPayload | Self::BindingOmitsTenant => Guard::TicketBinding,
            Self::FailOpenOnOutage => Guard::FailClosedAuthorization,
            Self::AuthorityBeforeEvidence => Guard::LaunchOrderCheck,
            Self::AckBeforeEnforcerConfirms => Guard::AckAfterEnforcerConfirms,
            Self::CleanupRetryRevivesGeneration => Guard::TransitionGenerationCheck,
            Self::RevocationNotDurable => Guard::DurableRevocation,
            Self::NonAtomicReservation => Guard::CentralReservation,
            Self::HeaderNotCounted => Guard::SenderEnforcesReservation,
            Self::CloneKeepsGeneration => Guard::UniqueGeneration,
            Self::EpochReadFromSnapshot => Guard::DurableEpochOutsideSnapshot,
            Self::DirtySnapshotPooled => Guard::GoldenOnlyPool,
            Self::RelayTrustsClaimedIdentity => Guard::RelayChannelIdentity,
            Self::AllowDecisionCachedByName => Guard::RelayAddressCheck,
        }
    }

    pub const fn class(self) -> DefectClass {
        match self.model() {
            ModelKind::Lifecycle | ModelKind::Snapshot => DefectClass::Lifecycle,
            _ => DefectClass::Policy,
        }
    }

    /// The invariant the seeding author expects the defect to break under the threat
    /// model, or `None` for a defect another guard masks (an equivalent mutant). This is
    /// the experiment's ground truth, written before either method ran.
    pub const fn expected_violation(self) -> Option<InvariantId> {
        use InvariantId::*;
        match self {
            Self::RetryIgnoresUncertainty => Some(UncertainOutcomeNotBlindlyRetried),
            Self::BindingOmitsPayload | Self::BindingOmitsTenant => Some(TicketExactScope),
            Self::FailOpenOnOutage => Some(FailedAuthorizationDenies),
            Self::AuthorityBeforeEvidence => Some(NoAuthorityBeforeEnforcement),
            Self::AckBeforeEnforcerConfirms => None,
            Self::CleanupRetryRevivesGeneration => Some(CleanupNeverRevivesGeneration),
            Self::RevocationNotDurable => Some(RevocationMonotonic),
            Self::NonAtomicReservation => Some(ReservationsWithinBudget),
            Self::HeaderNotCounted => Some(ReleaseWithinCeiling),
            Self::CloneKeepsGeneration => Some(RestoredCloneUniqueGeneration),
            Self::EpochReadFromSnapshot => Some(RevokedIdentityNotResurrected),
            Self::DirtySnapshotPooled => Some(OnlyGoldenSnapshotsPooled),
            Self::RelayTrustsClaimedIdentity | Self::AllowDecisionCachedByName => {
                Some(NoForbiddenEgress)
            }
        }
    }
}

/// The configuration a model runs under: guards disabled by a mutation, adversary
/// injections, and seeded defects. The default is the correct model in a benign
/// environment.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize)]
pub struct ModelConfig {
    pub disabled_guards: BTreeSet<Guard>,
    pub injections: BTreeSet<Injection>,
    pub defects: BTreeSet<Defect>,
}

impl ModelConfig {
    /// Every guard on, no injection, no defect.
    pub fn correct() -> Self {
        Self::default()
    }

    /// Every guard on under the whole threat model ([`Injection::threat_model`]).
    pub fn threat_model() -> Self {
        Self {
            injections: Injection::threat_model(),
            ..Self::default()
        }
    }

    pub fn with_injections(mut self, injections: impl IntoIterator<Item = Injection>) -> Self {
        self.injections.extend(injections);
        self
    }

    pub fn without_guards(mut self, guards: impl IntoIterator<Item = Guard>) -> Self {
        self.disabled_guards.extend(guards);
        self
    }

    pub fn with_defects(mut self, defects: impl IntoIterator<Item = Defect>) -> Self {
        self.defects.extend(defects);
        self
    }

    pub fn has(&self, injection: Injection) -> bool {
        self.injections.contains(&injection)
    }

    pub fn defect(&self, defect: Defect) -> bool {
        self.defects.contains(&defect)
    }

    /// Whether `guard` is in force: not disabled, and not a guest-side guard while the
    /// guest is hostile (guest root bypasses it, VM §1.2).
    pub fn enforces(&self, guard: Guard) -> bool {
        !self.disabled_guards.contains(&guard)
            && !(guard.location() == Location::Guest && self.has(Injection::HostileGuest))
    }
}

/// Explores model `kind` under `config` within `bounds`.
pub fn check_model(
    kind: ModelKind,
    config: &ModelConfig,
    bounds: Bounds,
) -> Result<Exploration, ModelError> {
    match kind {
        ModelKind::Effect => explore(&effect::EffectModel::new(config), bounds),
        ModelKind::Lifecycle => explore(&lifecycle::LifecycleModel::new(config), bounds),
        ModelKind::Budget => explore(&budget::BudgetModel::new(config), bounds),
        ModelKind::Snapshot => explore(&snapshot::SnapshotModel::new(config), bounds),
        ModelKind::Egress => explore(&egress::EgressModel::new(config), bounds),
        ModelKind::Boundary => explore(&boundary::BoundaryModel::new(config), bounds),
    }
}

/// Runs a fixed script (a hand-written probe) on model `kind` under `config`.
pub fn run_script(
    kind: ModelKind,
    config: &ModelConfig,
    steps: &[ScriptStep],
) -> Result<ScriptOutcome, ModelError> {
    match kind {
        ModelKind::Effect => run_steps(&effect::EffectModel::new(config), steps),
        ModelKind::Lifecycle => run_steps(&lifecycle::LifecycleModel::new(config), steps),
        ModelKind::Budget => run_steps(&budget::BudgetModel::new(config), steps),
        ModelKind::Snapshot => run_steps(&snapshot::SnapshotModel::new(config), steps),
        ModelKind::Egress => run_steps(&egress::EgressModel::new(config), steps),
        ModelKind::Boundary => run_steps(&boundary::BoundaryModel::new(config), steps),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_invariant_belongs_to_exactly_one_model() {
        for invariant in InvariantId::ALL {
            let owners = ModelKind::ALL
                .into_iter()
                .filter(|kind| kind.invariants().contains(&invariant))
                .count();
            assert_eq!(owners, 1, "{invariant:?}");
            assert!(!invariant.statement().is_empty());
            assert!(invariant.clause().starts_with("VM"));
        }
        // The ten §2.6 invariants are all named and modelled.
        assert_eq!(InvariantId::SECTION_2_6.len(), 10);
        for invariant in InvariantId::SECTION_2_6 {
            assert_eq!(invariant.clause(), "VM §2.6");
        }
    }

    #[test]
    fn guards_have_points_assumptions_and_the_update_key_in_common() {
        for guard in Guard::ALL {
            assert!(!guard.assumption().is_empty(), "{guard:?}");
            assert!(guard.model().guards().contains(&guard));
            if guard.location() == Location::Host {
                assert!(
                    guard.dependencies().contains(&Dependency::UpdateKey),
                    "{guard:?}"
                );
            }
        }
        // Only the provider-side credential scope is outside the update key.
        let outside: Vec<Guard> = Guard::ALL
            .into_iter()
            .filter(|guard| !Dependency::UpdateKey.dependents().contains(guard))
            .collect();
        assert_eq!(
            outside,
            vec![Guard::GuestEgressPolicy, Guard::ProviderScopedCredential]
        );
        assert_eq!(Guard::GuestEgressPolicy.location(), Location::Guest);
        assert_eq!(
            Guard::ProviderScopedCredential.location(),
            Location::External
        );
    }

    #[test]
    fn guest_side_guards_are_not_in_force_against_guest_root() {
        let benign = ModelConfig::correct();
        assert!(benign.enforces(Guard::GuestEgressPolicy));
        let hostile = ModelConfig::correct().with_injections([Injection::HostileGuest]);
        assert!(!hostile.enforces(Guard::GuestEgressPolicy));
        assert!(hostile.enforces(Guard::HostFirewall));
        let disabled = ModelConfig::correct().without_guards([Guard::HostFirewall]);
        assert!(!disabled.enforces(Guard::HostFirewall));
    }

    #[test]
    fn the_threat_model_holds_every_injection_but_the_propagation_delay() {
        let threat = Injection::threat_model();
        assert_eq!(threat.len(), Injection::ALL.len() - 1);
        assert!(!threat.contains(&Injection::SupervisorDelayed));
        for injection in Injection::ALL {
            assert!(!injection.models().is_empty());
        }
    }

    #[test]
    fn seeded_defects_name_their_model_class_and_expectation() {
        let masked: Vec<Defect> = Defect::ALL
            .into_iter()
            .filter(|defect| defect.expected_violation().is_none())
            .collect();
        assert_eq!(masked, vec![Defect::AckBeforeEnforcerConfirms]);
        for defect in Defect::ALL {
            if let Some(invariant) = defect.expected_violation() {
                assert_eq!(invariant.model(), defect.model(), "{defect:?}");
            }
        }
        assert_eq!(
            Defect::EpochReadFromSnapshot.class(),
            DefectClass::Lifecycle
        );
        assert_eq!(Defect::BindingOmitsPayload.class(), DefectClass::Policy);
    }
}
