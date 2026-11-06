//! The governor's lifecycle decisions on the model lifecycle stream (S06 of
//! docs/combined-plan-leftover-tasks.md: "publish real launch, load ... events through
//! CORE-06 ... correlate operations"; docs/combined-gpu-memory-and-vm-sandbox-plan.md, S2
//! CORE-06 and GPU part §3.6 lines 580–601).
//!
//! Every decision the governor makes in a placement's slot goes through the slot's
//! recording calls ([`PlacementSlot::begin_activation_and_record`] and its siblings in
//! `placement/events.rs`) once a [`PlacementLog`] is configured: step 1, a step that fails
//! the activation, an activation ended without publishing, step 5, and parking, reclaiming
//! and retiring a placement. Each is recorded under its operation: an activation's own for
//! its steps, its publication and its end, and for parking, reclaiming and retiring the
//! operation of the activation that replaced the placement, or else of the activation that
//! made it.
//!
//! The stream is optional, and it never decides anything. Without a log the governor makes
//! exactly the plain calls. With one, the slot decides exactly as the plain call would, and
//! a record the stream refuses is kept in a bounded report ([`RecordingReport`]): it never
//! blocks, delays or reverses the decision.

use std::collections::VecDeque;

use serde::Serialize;

use super::{HostLedger, LedgerPolicyGovernor, PlacementKey};
use crate::foundation::events::RecordError;
use crate::foundation::ids::{AuthorizationEpoch, Clock, OperationId};
use crate::model_memory::placement::{
    AbortReport, ActivationError, ActivationRequest, ActivationStarted,
    PlacementKey as SlotPlacement, PlacementLog, PlacementPorts, PlacementSlot, PublishReport,
    ReclaimReport, Recorded, ReservationPort, SlotError,
};

/// The most refused records a [`RecordingReport`] keeps; refusals past it are counted.
pub const MAX_UNRECORDED: usize = 64;

/// A placement's slot under one authorization epoch, as the governor keys it.
pub(super) type Site = (PlacementKey, AuthorizationEpoch);

/// Which slot call made a decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleDecision {
    /// Step 1 began an activation.
    Prepare,
    /// A step failed the activation.
    Step,
    /// The activation ended without publishing.
    End,
    /// Step 5 published the generation.
    Publish,
    /// A drained placement was parked.
    Park,
    /// Step 7 reclaimed a placement.
    Reclaim,
    /// A placement that held nothing was retired.
    Retire,
}

/// A decision the model lifecycle stream refused to record. The decision stood.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnrecordedDecision {
    pub placement: PlacementKey,
    pub epoch: AuthorizationEpoch,
    pub decision: LifecycleDecision,
    /// The operation the decision was to be recorded under.
    pub operation: OperationId,
    pub error: RecordError,
}

/// What became of the governor's decisions on the model lifecycle stream since the last
/// report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordingReport {
    /// Decisions the stream kept.
    pub recorded: u64,
    /// The latest decisions it refused, oldest first, at most [`MAX_UNRECORDED`].
    pub unrecorded: Vec<UnrecordedDecision>,
    /// Refused decisions beyond the bound, counted only.
    pub unrecorded_beyond_bound: u64,
}

/// The governor's side of the stream: the log, if any, and what it did with each record.
#[derive(Default)]
pub(super) struct Lifecycle {
    log: Option<PlacementLog>,
    recorded: u64,
    unrecorded: VecDeque<UnrecordedDecision>,
    beyond_bound: u64,
}

// The results are the slot's own, passed on unchanged.
#[allow(clippy::result_large_err)]
impl Lifecycle {
    /// The decision `recorded` carries, after noting what the stream did with it.
    fn note<T>(
        &mut self,
        (placement, epoch): Site,
        decision: LifecycleDecision,
        operation: OperationId,
        recorded: Recorded<T>,
    ) -> T {
        match recorded.recorded {
            Some(Ok(_)) => self.recorded = self.recorded.saturating_add(1),
            Some(Err(error)) => {
                if self.unrecorded.len() >= MAX_UNRECORDED {
                    self.unrecorded.pop_front();
                    self.beyond_bound = self.beyond_bound.saturating_add(1);
                }
                self.unrecorded.push_back(UnrecordedDecision {
                    placement,
                    epoch,
                    decision,
                    operation,
                    error,
                });
            }
            None => {}
        }
        recorded.outcome
    }

    /// Step 1, as [`PlacementSlot::begin_activation`].
    pub(super) fn begin<C: Clock>(
        &mut self,
        site: Site,
        slot: &mut PlacementSlot<C>,
        request: &ActivationRequest,
        ports: &mut dyn PlacementPorts,
    ) -> Result<ActivationStarted, ActivationError> {
        let Some(log) = self.log.as_mut() else {
            return slot.begin_activation(request, ports);
        };
        let recorded = slot.begin_activation_and_record(request, ports, log);
        self.note(
            site,
            LifecycleDecision::Prepare,
            request.operation.clone(),
            recorded,
        )
    }

    /// One or more steps of the activation in progress.
    pub(super) fn step<C: Clock, T>(
        &mut self,
        site: Site,
        slot: &mut PlacementSlot<C>,
        step: impl FnOnce(&mut PlacementSlot<C>) -> Result<T, ActivationError>,
    ) -> Result<T, ActivationError> {
        let operation = slot.activation().map(|activation| activation.operation);
        let (Some(log), Some(operation)) = (self.log.as_mut(), operation) else {
            return step(slot);
        };
        let recorded = slot.step_and_record(log, step);
        self.note(site, LifecycleDecision::Step, operation, recorded)
    }

    /// Ends the activation in progress without publishing.
    pub(super) fn end<C: Clock>(
        &mut self,
        site: Site,
        slot: &mut PlacementSlot<C>,
        end: impl FnOnce(&mut PlacementSlot<C>) -> Result<AbortReport, ActivationError>,
    ) -> Result<AbortReport, ActivationError> {
        let operation = slot.activation().map(|activation| activation.operation);
        let (Some(log), Some(operation)) = (self.log.as_mut(), operation) else {
            return end(slot);
        };
        let recorded = slot.end_and_record(log, end);
        self.note(site, LifecycleDecision::End, operation, recorded)
    }

    /// Step 5, as [`PlacementSlot::publish`].
    pub(super) fn publish<C: Clock>(
        &mut self,
        site: Site,
        slot: &mut PlacementSlot<C>,
        ports: &mut dyn PlacementPorts,
    ) -> Result<PublishReport, ActivationError> {
        let operation = slot.activation().map(|activation| activation.operation);
        let (Some(log), Some(operation)) = (self.log.as_mut(), operation) else {
            return slot.publish(ports);
        };
        let recorded = slot.publish_and_record(ports, log);
        self.note(site, LifecycleDecision::Publish, operation, recorded)
    }

    /// Parks a drained placement, as [`PlacementSlot::park`], under `operation`.
    pub(super) fn park<C: Clock>(
        &mut self,
        site: Site,
        slot: &mut PlacementSlot<C>,
        key: SlotPlacement,
        operation: &OperationId,
    ) -> Result<(), SlotError> {
        let Some(log) = self.log.as_mut() else {
            return slot.park(key);
        };
        let recorded = slot.park_and_record(key, operation, log);
        self.note(site, LifecycleDecision::Park, operation.clone(), recorded)
    }

    /// Step 7, as [`PlacementSlot::reclaim`], under `operation`.
    pub(super) fn reclaim<C: Clock>(
        &mut self,
        site: Site,
        slot: &mut PlacementSlot<C>,
        key: SlotPlacement,
        reservations: &mut dyn ReservationPort,
        operation: &OperationId,
    ) -> Result<ReclaimReport, SlotError> {
        let Some(log) = self.log.as_mut() else {
            return slot.reclaim(key, reservations);
        };
        let recorded = slot.reclaim_and_record(key, reservations, operation, log);
        self.note(
            site,
            LifecycleDecision::Reclaim,
            operation.clone(),
            recorded,
        )
    }

    /// Retires a placement that holds nothing, as [`PlacementSlot::retire`], under
    /// `operation`.
    pub(super) fn retire<C: Clock>(
        &mut self,
        site: Site,
        slot: &mut PlacementSlot<C>,
        key: SlotPlacement,
        operation: &OperationId,
    ) -> Result<(), SlotError> {
        let Some(log) = self.log.as_mut() else {
            return slot.retire(key);
        };
        let recorded = slot.retire_and_record(key, operation, log);
        self.note(site, LifecycleDecision::Retire, operation.clone(), recorded)
    }
}

impl<C: Clock + Clone, P: HostLedger<C>> LedgerPolicyGovernor<C, P> {
    /// From now on every lifecycle decision is recorded on `log`, the host's model
    /// lifecycle stream ([`open_placement_log`]); the log recorded on until now, if any,
    /// comes back.
    ///
    /// [`open_placement_log`]: crate::model_memory::placement::open_placement_log
    pub fn record_lifecycle(&mut self, log: PlacementLog) -> Option<PlacementLog> {
        self.lifecycle.log.replace(log)
    }

    /// Stops recording and hands the log back, for instance to close it; decisions are
    /// made exactly as before.
    pub fn stop_recording(&mut self) -> Option<PlacementLog> {
        self.lifecycle.log.take()
    }

    /// The model lifecycle stream decisions are recorded on, for reads.
    pub fn placement_log(&self) -> Option<&PlacementLog> {
        self.lifecycle.log.as_ref()
    }

    /// What the stream did with the decisions since the last report, which starts a new
    /// one.
    pub fn take_recording_report(&mut self) -> RecordingReport {
        let lifecycle = &mut self.lifecycle;
        let report = RecordingReport {
            recorded: lifecycle.recorded,
            unrecorded: lifecycle.unrecorded.drain(..).collect(),
            unrecorded_beyond_bound: lifecycle.beyond_bound,
        };
        lifecycle.recorded = 0;
        lifecycle.beyond_bound = 0;
        report
    }
}
