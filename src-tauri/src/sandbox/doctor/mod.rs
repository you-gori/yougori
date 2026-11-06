//! The host doctor's VM sandbox half: which backends a host would run sandboxes on, the
//! boundary report of each for the run profiles asked, its §7.1 label, what changed since
//! its previous report (kept across engine restarts), and a dry-run plan of the checks
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM-W23, line 2622, "Host-specific
//! capability/evidence doctor adapters in CORE-01, with freshness and effect on
//! requirements. Report changes without altering host settings silently", acceptance
//! "unsafe/unavailable GPU paths explained"; §7.1, lines 2356–2364, "Until validated,
//! label it experimental or unavailable"; VM-D2, line 3196; M08 of the leftover tracker).
//!
//! Pure library code over [`crate::sandbox::probes`]: nothing here runs a check, starts a
//! VM or changes the host. A check without a result is not tested and never passes, so a
//! host is validated for a backend only when every check its profiles require passed.
//!
//! - [`candidates`]: the backends the plan names for each host operating system.
//! - [`Doctor::examine`]: one [`BoundaryReport`](crate::sandbox::probes::BoundaryReport)
//!   per candidate, its [`Label`], counts of the required checks by status, the blocking
//!   checks, every check that did not pass with its status in the engine's words and what
//!   it expects on this host ([`CheckExplanation`]), the results read from launch records
//!   with their age, and what changed since the previous examination.
//! - [`Doctor::examine_with_records`]: the same, with each backend's results also read
//!   from its sealed launch records and controlled negative launches
//!   ([`RecordResults`](crate::sandbox::probes::RecordResults)), for exactly the check parts
//!   their host-observed facts decide; every other part stays not tested.
//! - [`plan`]: what each check would observe on this host and whether its profiles require
//!   it, without running anything.
//! - `history`: the previous reports a doctor compares with ([`RememberedReport`]), kept
//!   across engine restarts through the [`HistoryStore`] port as one strict, versioned,
//!   digested document; a damaged one is reported in the report's [`History`] and ignored.
//!   [`Doctor::new`] keeps them in memory only, [`Doctor::with_store`] in a store.
//!
//! No tagged enum of this module is read back: [`DoctorChange`] and [`DoctorError`] are
//! written only, and the kept history reads plain records and the string enum
//! [`StatusKind`] straight from JSON, refusing unknown and repeated fields.

mod candidates;
mod examine;
mod history;
mod plan;
mod wording;

#[cfg(test)]
mod tests;

pub use candidates::{candidates, Candidate, CandidateRole};
pub use examine::{
    run_profile, CandidateReport, CheckInputs, Doctor, DoctorChange, DoctorError, DoctorReport,
    DoctorRequest, Label, RecordedResult, StatusCounts, DEFAULT_PROFILES, DOCTOR_NOTICE,
};
pub use history::{
    decode_history, encode_history, BackendChanges, History, HistoryError, HistoryStore,
    MemoryOnly, RememberedCheck, RememberedReport, StatusChange, StoreFailure, HISTORY_FORMAT,
    HISTORY_LIMIT,
};
pub use plan::{plan, DoctorPlan, PlannedCheck, PlannedObservation, PLAN_NOTICE};
pub use wording::{CheckExplanation, StatusKind, StatusText};
