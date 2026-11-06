//! Integration of the VM sandbox runtime layer
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: S4 INTEGRATION row, line 244; S2
//! CORE-01, CORE-03, CORE-04, CORE-06 and CORE-08 rows, lines 210–217; S3 items 1, 4 and 5,
//! lines 223, 226 and 227; S6 INT-02, INT-04 and INT-10, lines 270, 272 and 278; §4.4 lines
//! 1978–1990; §6.3 lines 2304–2323; §12.2 VM-P01, VM-P11, VM-P14, VM-P18, VM-P19,
//! VM-P21, VM-P22, VM-P24, VM-P29, VM-P42, VM-P49 and VM-P50, lines 2776–2825; §17
//! VM-CP-01, VM-CP-11, VM-CP-14, VM-CP-18, VM-CP-19, VM-CP-21, VM-CP-22 and VM-CP-35,
//! lines 3151–3185).
//!
//! The committed backend contract (`sandbox::backend`), lifecycle supervisor
//! (`sandbox::lifecycle`) and audit streams (`sandbox::audit`) each stop at a port. This
//! module closes the seams between them without changing any of them:
//!
//! - [`backend_port`]: [`BackendPort`] presents a `sandbox::backend::VmBackend` as the
//!   lifecycle's own `VmBackend` port. A CORE-04 boot request becomes a backend launch
//!   request: the coordination reservation key is mapped to the CORE-03 reservation id
//!   the backend binds, and the contract digest, pinned artifacts, device profile and
//!   required properties come from a typed [`LaunchProfile`]. Readiness is the backend's
//!   host-observed running and confinement evidence, current on the record's facts or,
//!   once they are stale, on the backend's fresh re-observation of the VM judged by the
//!   record, and unavailable until that exists (§8.1 line 2439); handles are the
//!   backend's stable VM identities bound to the launch record's identity, never a PID; a
//!   refused launch surfaces as the lifecycle's typed failure, is kept with its typed
//!   refusal in the [`LaunchTable`], and leaves no authority; a refused launch whose
//!   cleanup is incomplete holds its boot's perimeter until the backend stops what it
//!   left.
//! - [`audit_sink`]: [`AuditSink`] appends lifecycle receipts (CORE-06 event contexts
//!   with typed generations), revocations, launch records (host facts under the record's
//!   identity digest, with the guest-asserted facts as guest reports and never as host
//!   facts) and refused launches (with their typed refusal, a real backend's included,
//!   with the count of its findings and what an incomplete cleanup may leave, never the
//!   backend's own text) to one audit stream through
//!   the stream directory's single append authority. Acknowledgments carry what
//!   established them (CORE-04's milestone and source where CORE-04 records it), and the
//!   revocation of one grant is written as the stream's typed grant revocation naming the
//!   grant and the epoch left in force, never as a revocation of the sandbox, on the
//!   revocation reserve a revocation of the sandbox uses (CORE-04 per-grant revocation;
//!   §6.3 step 1). [`AuditSink::open_durable`] puts the sink on a CORE-06 durable stream
//!   with one owner across the host's processes (S06), and
//!   [`AuditSink::open_durable_spooled`] adds its bounded spool on file, so records the log
//!   refused survive a restart and drain into it in order, and the revocation reserve left
//!   before the restart is the reserve after it (§8.2 line 2445; VM-W43).
//!   [`AuditSink::release`] releases a durable sink's log and reports the outcome
//!   ([`SinkRelease`]); a seal or owner record that could not be written is a
//!   [`ReleaseFailure`] there, never swallowed, and dropping the sink stays the fallback.
//! - [`assurance`]: launch records and lifecycle measurements become assurance-ledger
//!   claims. VM-P01 "VM-only execution" cites the record's CORE-01 hypervisor evidence,
//!   so a stale or configuration-changed record invalidates the claim through the
//!   ledger's evidence check; a record of the fake backend and a measurement on the fake
//!   substrate back no claim (VM-P50).
//! - `scenarios` (tests): the first VM-P scenarios on the fake backend with a manual
//!   clock and the real coordinator, ledger, audit stream and assurance ledger, including
//!   a grant revocation that leaves the sandbox's other grants alive, a grant revocation
//!   recorded on the reserve while the stream fails closed, a sink on a durable stream
//!   across a restart, and a launch refused without CORE-01 perimeter evidence (§4.4;
//!   VM-CP-11).
//! - `durable_sink_tests` (tests): the sink on the spooled durable stream, whose log
//!   refuses records here as a full disk would: spooled records drained in order after a
//!   restart, ordinary records failed closed while revocations use the reserve, exactly
//!   as before a restart, and a clean and a failed release reported (§8.2 lines 2441–2450;
//!   VM-W42, VM-W43 and VM-W44, lines 2665–2667).
//!
//! Everything is pure and synchronous. No committed module is changed; where a seam
//! needs one, the adapter works around it and the task report names the need.

pub mod assurance;
pub mod audit_sink;
pub mod backend_port;
pub mod profile;

#[cfg(test)]
mod durable_sink_tests;
#[cfg(test)]
mod fakes;
#[cfg(test)]
mod scenarios;

pub use assurance::{
    measurement_citations, revocation_claim, vm_only_execution_claim, ClaimParts, ClaimRefusal,
    MeasurementCitation, MEASUREMENT_RECORD_DOMAIN,
};
pub use audit_sink::{
    AuditSink, LaunchAudit, ReleaseFailure, SinkRefusal, SinkRelease, SinkTotals,
    SUPERVISOR_OPERATION,
};
pub use backend_port::{
    BackendPort, LaunchAttempt, LaunchProblem, LaunchTable, PortConfig, RefusedLaunch,
    PERIMETER_DOMAIN,
};
pub use profile::{LaunchProfile, LedgerReservations, ReservationResolver, ReservationUnresolved};
