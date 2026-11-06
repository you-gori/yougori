//! The §7.1 evidence matrix as data: one evidence row per combination, assembled only
//! from evidence that already exists (docs/combined-gpu-memory-and-vm-sandbox-plan.md:
//! §7.1, lines 2356–2364, "Every supported combination needs an evidence row: host
//! OS/build + architecture + backend/version + guest image + actual hardware accelerator +
//! confinement profile + device set + network enforcement + lifecycle behavior + test
//! result. Until validated, label it experimental or unavailable"; §8.1, lines
//! 2433–2439; VM-W04, line 2589; VM-W23, line 2622; VM-W51, line 2674; E02 of the
//! leftover tracker, which consumes it).
//!
//! Pure library code: nothing here runs a check, starts a VM, reads a file or changes the
//! host. The evidence is what other modules already produce: the doctor's examination of
//! a host ([`DoctorReport`](crate::sandbox::doctor::DoctorReport)), the backend's sealed
//! launch records ([`LaunchRecord`](crate::sandbox::backend::LaunchRecord)), the verified
//! guest image release ([`VerifiedImage`](crate::sandbox::guest_image::VerifiedImage)) and
//! the stamped V15 verdict for VM-CP-05
//! ([`Vm05Evaluation`](crate::sandbox::probes::Vm05Evaluation)); the doctor's report
//! carries the probe results and the results it read from launch records.
//!
//! - [`field`]: one [`Field`] per element of a row: its value with its [`Source`] and
//!   [`Freshness`] at the reading, or [`Unavailable`] with the reason nobody observed it.
//!   A stale value is shown as not current, never as current.
//! - [`row`]: the [`MatrixRow`] of one combination: the host build examined and observed,
//!   the backend examined and its build, the signed manifest with the pinned and booted
//!   root image, the accelerator, the hypervisor's and the guest's confinement, the
//!   device profile and measured inventory, the enforced network channels and the
//!   independent perimeter, the launch paths and lifecycle checks, and the doctor's
//!   examination as the test result. Its identity is the combination (every element but
//!   the test result, the doctor's run profiles included), and its [`Label`] is the
//!   doctor's: unavailable when the doctor's report is not current at the reading, and
//!   experimental, not validated, while any field is unavailable or not current
//!   ([`LabelBasis`]).
//! - [`assemble()`]: the row of one backend from [`RowSources`] at a [`Reading`], after
//!   refusing parts that disagree ([`RowError`]): another host build, another backend or
//!   build, another root image or architecture, records that disagree about a field of
//!   the combination, a doctor result read from a record not given, a verdict for a
//!   profile the image does not install, or a verdict the doctor judged otherwise. The
//!   doctor never examines the fake backend, so its records are refused.
//! - [`matrix`]: the [`EvidenceMatrix`], one row per combination, a combination without a
//!   row unavailable, and [`MatrixChanges`] between two matrices.
//!
//! Every output is Serialize only, for E02's reports; no field computes a score.
//! `sandbox::backend`'s `EvidenceRow` and `ReleaseProfile` remain the release-side form,
//! whose test result names a CORE-08 report; this module does not produce them.
//!
//! [`Label`]: crate::sandbox::doctor::Label

pub mod assemble;
pub mod field;
pub mod matrix;
pub mod row;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;

pub use assemble::{assemble, Reading, RowError, RowSources};
pub use field::{Field, Freshness, RowField, Source, Unavailable};
pub use matrix::{
    EvidenceMatrix, MatrixChanges, MatrixError, RowChange, RowSummary, MATRIX_NOTICE,
};
pub use row::{
    BackendPart, ConfinementPart, DevicePart, GuestConfinement, HostPart, ImagePart, LabelBasis,
    LaunchPath, LifecyclePart, LifecycleResult, MatrixRow, NetworkPart, PerimeterEnforcement,
    SignedImage, COMBINATION_DOMAIN, LIFECYCLE_CHECKS, ROW_NOTICE,
};
