//! The doctor's dry run: what each §17 check would observe on this host and whether the
//! run profiles require it, without running anything (VM-W23, line 2622; §17, lines
//! 3145–3188).

use std::collections::BTreeSet;

use serde::Serialize;

use crate::foundation::evidence::OsKind;
use crate::sandbox::probes::{
    catalog, CheckId, ControlledCheck, ExpectationId, Part, PlanNote, PositiveControl, Role,
    RunProfile, ScenarioFamily, Side,
};

/// What every plan states about itself.
pub const PLAN_NOTICE: &str =
    "A plan describes the checks; it runs none of them and changes nothing on the host.";

/// One observation a check would make on this host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PlannedObservation {
    pub id: ExpectationId,
    #[serde(flatten)]
    pub part: Part,
    pub role: Role,
    /// What the plan expects, in its words.
    pub says: &'static str,
}

/// One check as it would run on this host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlannedCheck {
    pub check: CheckId,
    pub families: &'static [ScenarioFamily],
    pub side: Side,
    /// Whether the run profiles refuse to start without it.
    pub required: bool,
    /// Whether it can run on this host's operating system at all.
    pub runs_here: bool,
    /// What its positive control must show, when the plan lists one.
    pub control: Option<&'static str>,
    /// The plan's remark where it lists no positive control.
    pub note: Option<PlanNote>,
    /// The observations that apply on this host, its positive control included.
    pub observes: Vec<PlannedObservation>,
}

/// Every check as it would run on one host for some run profiles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorPlan {
    pub notice: &'static str,
    pub os: OsKind,
    pub profiles: BTreeSet<RunProfile>,
    pub checks: Vec<PlannedCheck>,
}

/// The observations `row` makes on a host of `os`, its positive control included, in
/// table order and in the plan's words.
pub(super) fn observations(row: &ControlledCheck, os: OsKind) -> Vec<PlannedObservation> {
    row.expectations()
        .filter(|entry| entry.scope.applies(os))
        .map(|entry| PlannedObservation {
            id: entry.id,
            part: entry.part,
            role: entry.role,
            says: entry.says,
        })
        .collect()
}

/// The dry run of every §17 check on `os` for `profiles`.
pub fn plan(os: OsKind, profiles: &BTreeSet<RunProfile>) -> DoctorPlan {
    let checks = catalog()
        .iter()
        .map(|row| {
            let (control, note) = match row.positive_control {
                PositiveControl::Expectation { .. } => {
                    (row.control().map(|entry| entry.says), None)
                }
                PositiveControl::NotListed { note } => (None, note),
            };
            PlannedCheck {
                check: row.id,
                families: row.families,
                side: row.side,
                required: row.required_for(profiles),
                runs_here: row.runs_on(os),
                control,
                note,
                observes: observations(row, os),
            }
        })
        .collect();
    DoctorPlan {
        notice: PLAN_NOTICE,
        os,
        profiles: profiles.clone(),
        checks,
    }
}
