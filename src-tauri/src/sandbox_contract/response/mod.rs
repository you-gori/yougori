//! V14: violation and resource monitoring policy, the pure half of VM-W43
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM-W43 line 2491; §8.2 lines
//! 2266–2275; §6.3 lines 2129–2144; §6.4 lines 2145–2152; §2.5 lines 1806–1825; §1.3 lines
//! 1718–1735; VM-D7 and VM-D10 lines 3026 and 3029; VM-P14 and VM-P24 lines 2614 and 2624;
//! VM-CP-14 line 2989). Tier 0 only (§12.1 lines 2585–2595): pure, synchronous library
//! code over fakes.
//!
//! This is the policy and decision layer. It monitors no real VM, cuts no channel and stops
//! nothing by itself: its outputs are typed decisions that the runtime applies. The runtime
//! wiring (`src-tauri/src/security/{monitor.rs, containment.rs, network.rs}`, the
//! supervisor in `src-tauri/src/sandbox` and the UI in `src/components/security/`, line
//! 2923) is later work. The one place where a decision is carried out here is
//! [`execute_target`], which drives the committed CORE-04 coordinator and V05's
//! [`respond_to_violation`](crate::sandbox_contract::files::respond_to_violation) on
//! whatever ports it is given; the tests give it fakes.
//!
//! - [`MonitoringSignal`] is one observation with its source and freshness: host-observed
//!   by a named [`HostObserver`] (supervisor, broker, perimeter, hypervisor counters,
//!   executor) or guest-reported, which stays untrusted (§8.2 line 2268). A signal whose
//!   observer cannot see what it claims is refused ([`SignalRefusal::MislabelledSource`]).
//!   A V09 [`CanaryHit`](crate::sandbox_contract::canaries::CanaryHit) becomes one signal
//!   among others and stays a signal, never proof (line 2274).
//! - [`assess_violation`] and [`ResourceMonitor`] turn observations into a
//!   [`SignalAssessment`]. Stale or conflicting host observations are an uncertain result
//!   and never a pass; there is no pass result at all. Resource signals are judged over
//!   [`SustainedWindow`]s with hysteresis, so a reading that hovers near a limit cannot flap
//!   a response on and off.
//! - [`ResponsePolicies`] holds five separate records: [`IsolatePolicy`], [`RevokePolicy`],
//!   [`StopPolicy`], [`NotifyPolicy`] and [`UncertainPolicy`]. [`decide`] is the one
//!   function that maps (class, source, freshness, sandbox class) to a bounded set of
//!   [`ResponseAction`]s with a recorded [`DecisionReason`]. A guest report alone can only
//!   notify or ask for host corroboration. No score exists anywhere (§1.3).
//! - [`Responder`] bounds the responses: one per incident, escalating only along the
//!   explicit [`ESCALATION_LADDER`]; a per-sandbox rate bound on repeats; a response reaches
//!   another sandbox only when it shares the violated grant; no action widens authority.
//! - Every decision lists what it [`Preserved`]: no action deletes volumes, workspaces,
//!   artifacts or snapshots, a stop keeps every V05 volume class, and isolation is
//!   reversible ([`Responder::release_isolation`]) without reviving authority. After a
//!   stop, [`plan_response_cleanup`] passes V05's cleanup safety check and then removes
//!   only the VM's process, perimeter and sockets; overlays, scratch directories and
//!   snapshots stay for recovery.
//! - [`emergency_revoke`] revokes through CORE-04 and the CORE-06 priority lane before it
//!   touches the audit journal. When audit storage is full or failing, the revocation still
//!   takes effect, its record waits in a bounded [`DeferredAudit`] to be written afterward,
//!   and [`HighImpactGate`] denies new high-impact operations.
//! - [`RevocationTimeline`] keeps the five VM-CP-14 times as separate events and carries
//!   the §6.5 stop figure as an [`EngineeringTarget`](TargetLabel::EngineeringTarget), never
//!   as a guarantee.

/// Defines an internally tagged, snake_case enum whose deserialization refuses unknown
/// fields for every variant, unit variants included. serde ignores unknown fields beside
/// the tag of a unit variant even with `deny_unknown_fields`, so reading goes through a
/// twin enum whose unit variants are empty struct variants. Copied from
/// `strict_policy_enum!` in `sandbox_contract/policy/mod.rs`, kept local.
macro_rules! strict_response_enum {
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

mod assess;
mod emergency;
mod emission;
mod policy;
mod responder;
mod signal;
mod timeline;
mod window;

#[cfg(test)]
mod drill_tests;
#[cfg(test)]
mod fakes;
#[cfg(test)]
mod kind_tests;
#[cfg(test)]
mod responder_tests;
#[cfg(test)]
mod tests;

pub use assess::{
    assess_violation, AssessRefusal, Assessment, IncidentKey, SignalAssessment,
    MAX_OBSERVATIONS_PER_ASSESSMENT,
};
pub use emergency::{
    emergency_revoke, execute_target, revoke_shared_grant, Deferral, DeferredAudit, DeferredFlush,
    DeferredProblem, DeferredRecord, EmergencyReceipt, GrantRevocationReceipt, HighImpactDenial,
    HighImpactGate, RevocationAudit, TargetExecution, UnrecordedRetry, UnrecordedRevocation,
};
pub use emission::{record_signal, EmissionGate, SignalAudit};
pub use policy::{
    decide, plan_response_cleanup, response_cleanup_allows, Decision, DecisionInput,
    DecisionReason, EscalationRung, IsolatePolicy, IsolationCut, NotifyPolicy, NotifyRecipient,
    PolicyProblem, Preserved, ResponseAction, ResponseCleanupRefusal, ResponsePolicies,
    RevokePolicy, StopPolicy, UncertainPolicy, ESCALATION_LADDER, RESPONSE_CLEANUP_KINDS,
};
pub use responder::{
    BoundsProblem, DecisionId, IncidentId, IsolationRelease, NotificationOutcome, Responder,
    ResponderRefusal, ResponderTotals, ResponseBounds, ResponseOutcome, ResponseRecord,
    TargetResponse, TargetRole,
};
pub use signal::{
    judge_freshness, Conflict, Freshness, GrantRef, HostObserver, MonitoredResource,
    MonitoringSignal, Reading, SignalClass, SignalDraft, SignalRefusal, SignalSource,
    ViolationKind,
};
pub use timeline::{
    EventSource, RevocationEventKind, RevocationTimeline, TargetLabel, TimelineEntry,
    TimelineRefusal, TimelineStatus, VmStopTarget, VM_STOP_TARGET,
};
pub use window::{
    ResourceMonitor, ResourceObservation, SeriesKey, SustainedWindow, WindowProblem, WindowRefusal,
    WindowState, MAX_MONITORED_SERIES,
};
