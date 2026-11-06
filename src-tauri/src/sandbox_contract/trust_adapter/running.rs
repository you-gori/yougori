//! Revocation reaching launches already running (VM-W45, plan line 2668: "emergency
//! revocation"; VM-P23, line 2798; VM-P48, line 2823; VM-W43, line 2666; M18 in
//! docs/combined-plan-leftover-tasks.md, line 217: "a registry of running launches'
//! `LaunchAdmission`s ... a typed report for the lifecycle; it is not a guest violation
//! signal").
//!
//! The update client refuses a revoked release at the execution boundary
//! ([`UpdateClient::admit_launch`]), so once a revocation list is applied no new launch,
//! restart or warm checkout of the release is admitted. A launch admitted before keeps
//! running. [`RunningLaunches`] holds the [`LaunchAdmission`] of each running launch by its
//! execution (one per component for a launch of several, the `launch_set` module): the
//! persisted client registers it when it admits the launch and removes it when the
//! lifecycle ends the launch. When an applied list newly revokes content keys,
//! the persisted client names every running launch whose artifact is among them, with the
//! list's reason, in a [`RevocationReport`]. A launch ended before is not named, and a
//! key revoked before is not newly revoked, so no launch is named twice for one key.
//!
//! What happens to such a launch is the lifecycle's to decide. The plan requires revoked
//! components to fail verification at the actual execution boundary (VM-P23, line 2798;
//! VM-CP-23, line 3173: "refused at the launch boundary") and emergency revocation to have
//! a documented secure recovery path (VM-P48, line 2823). It does not say that a sandbox
//! already running a revoked artifact is stopped, and VM-W43 (line 2666) asks for the
//! isolate, revoke, stop, notify and uncertain-result policies to be defined separately.
//! Which of them a revoked running artifact gets is an owner decision; this module only
//! reports and stops nothing.
//!
//! The report is a host trust event, not a guest violation: the guest did nothing. The
//! response signals (`sandbox_contract::signals`) may revoke or stop a sandbox only for
//! something its guest did, so the report is never turned into a V14 violation signal or a
//! `SignalDraft`, and it names no grant.
//!
//! The registry lives in memory. After an engine restart the lifecycle registers the
//! launches it recovers again (by admitting them); until then a revocation names none of
//! them, though the client refuses their next admission all the same. A reload of the
//! trust roots keeps the registry and names no launch: every release revoked before stays
//! revoked, and a launch admitted under metadata the reload dropped is not reported,
//! though its next admission is refused.
//!
//! [`UpdateClient::admit_launch`]: crate::sandbox::trust::UpdateClient::admit_launch

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use crate::foundation::ids::{ContentKey, ExecutionId};
use crate::sandbox::trust::{LaunchAdmission, RevocationApplied};

/// The execution already has a running launch registered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AlreadyRunning {
    pub execution: ExecutionId,
}

impl fmt::Display for AlreadyRunning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "execution {} already has a running launch",
            self.execution
        )
    }
}

impl std::error::Error for AlreadyRunning {}

/// A running launch whose artifact a revocation list newly revoked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevokedLaunch {
    /// The launch as the client admitted it.
    pub admission: LaunchAdmission,
    /// The revocation list's reason for the artifact's content key.
    pub reason: String,
}

/// What applying one revocation list did, and the running launches it reaches: a host
/// trust event for the lifecycle, not a guest violation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevocationReport {
    /// The client's own account of the list.
    pub applied: RevocationApplied,
    /// Every running launch whose artifact the list newly revoked, by execution.
    pub running: BTreeMap<ExecutionId, RevokedLaunch>,
}

/// The admissions of the launches running now, by execution. A launch of several
/// components (the `launch_set` module) holds one admission per component, never none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunningLaunches {
    launches: BTreeMap<ExecutionId, Vec<LaunchAdmission>>,
}

impl RunningLaunches {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers the launch of `execution` as admitted; an execution has one running launch
    /// at a time.
    pub fn register(
        &mut self,
        execution: ExecutionId,
        admission: LaunchAdmission,
    ) -> Result<(), AlreadyRunning> {
        self.register_all(execution, vec![admission])
    }

    /// Registers the launch of `execution` with the admission of each of its components,
    /// as one launch; an execution has one running launch at a time, and an empty list
    /// registers nothing.
    pub fn register_all(
        &mut self,
        execution: ExecutionId,
        admissions: Vec<LaunchAdmission>,
    ) -> Result<(), AlreadyRunning> {
        if self.launches.contains_key(&execution) {
            return Err(AlreadyRunning { execution });
        }
        if !admissions.is_empty() {
            self.launches.insert(execution, admissions);
        }
        Ok(())
    }

    /// Removes the launch of `execution`, which ended, and returns its admission: the
    /// first, for a launch of several components ([`Self::end_all`] returns them all).
    pub fn end(&mut self, execution: &ExecutionId) -> Option<LaunchAdmission> {
        self.end_all(execution).into_iter().next()
    }

    /// Removes the launch of `execution`, which ended, and returns all its admissions.
    pub fn end_all(&mut self, execution: &ExecutionId) -> Vec<LaunchAdmission> {
        self.launches.remove(execution).unwrap_or_default()
    }

    /// The admission of the launch of `execution`: the first, for a launch of several
    /// components.
    pub fn get(&self, execution: &ExecutionId) -> Option<&LaunchAdmission> {
        self.launches
            .get(execution)
            .and_then(|admissions| admissions.first())
    }

    /// Every admission of the launch of `execution`, empty if none runs.
    pub fn admissions(&self, execution: &ExecutionId) -> &[LaunchAdmission] {
        self.launches.get(execution).map_or(&[], Vec::as_slice)
    }

    pub fn len(&self) -> usize {
        self.launches.len()
    }

    pub fn is_empty(&self) -> bool {
        self.launches.is_empty()
    }

    /// Every admission of every running launch, by execution.
    pub fn iter(&self) -> impl Iterator<Item = (&ExecutionId, &LaunchAdmission)> {
        self.launches.iter().flat_map(|(execution, admissions)| {
            admissions
                .iter()
                .map(move |admission| (execution, admission))
        })
    }

    /// The running launches with an artifact among `newly_revoked`, each with its reason. A
    /// launch of several components is named once, with its first such admission.
    pub fn revoked_by(
        &self,
        newly_revoked: &BTreeMap<ContentKey, String>,
    ) -> BTreeMap<ExecutionId, RevokedLaunch> {
        self.launches
            .iter()
            .filter_map(|(execution, admissions)| {
                admissions.iter().find_map(|admission| {
                    newly_revoked.get(&admission.content_key).map(|reason| {
                        (
                            execution.clone(),
                            RevokedLaunch {
                                admission: admission.clone(),
                                reason: reason.clone(),
                            },
                        )
                    })
                })
            })
            .collect()
    }
}
