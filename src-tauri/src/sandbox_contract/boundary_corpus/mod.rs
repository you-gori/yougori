//! E01's host-observable part: the VM-CP-15 file-boundary corpus run against the real name
//! filter, resolver and file service (docs/combined-gpu-memory-and-vm-sandbox-plan.md: §17
//! VM-CP-15, line 3154, "the file broker's case corpus: symlink, hard link, junction,
//! reparse point, alternate data stream, UNC and device path, case alias, Unicode
//! normalization, long path, and a rename race during an open cannot escape the granted
//! root", positive control "an in-root relative path resolves"; VM part §5.1, line 2213,
//! "Test symlinks, hard links, mount changes, Windows junctions/reparse points, alternate
//! data streams, UNC/device paths, case folding, reserved names, Unicode normalization and
//! path length limits"; §12.2 VM-P15, line 2779; E01 in docs/combined-plan-leftover-tasks.md,
//! VM-W49 and VM-W50).
//!
//! - [`corpus`]: one [`BoundaryCase`] per item of the row, plus the reserved names and
//!   mount changes of the §5.1 line, VM-P15's traversal and the positive control. Each
//!   request names its attack input, the [`Layer`] expected to stop it (the name filter
//!   [`GuestName`](crate::sandbox_contract::files::GuestName), the resolver
//!   [`GrantedRoot::resolve`](crate::sandbox_contract::files::GrantedRoot::resolve), or
//!   the [`FileService`](crate::sandbox_contract::files::FileService) during a race) and
//!   the exact refusal.
//! - [`run_corpus`] and [`run_case`]: each case built on a real directory beneath a scratch
//!   directory the caller owns (junctions by `cmd /D /C mklink /J`; symlinks only where
//!   permitted, else the case is skipped for privilege and never passed; NTFS alternate
//!   data streams; third-party reparse tags; host paths beyond 260 characters; device and
//!   UNC spellings of a real outside path as guest names), run against the name filter, a
//!   resolver opened through [`OpenResolver`] and a file service, with a check that nothing
//!   outside the root was read or changed. One [`CaseResult`] per case: passed, failed with
//!   what happened, or skipped with why.
//! - [`CorpusReport`]: the run as a record labelled a host-only run on this platform
//!   ([`RunScope::HostOnly`]), never a VM sandbox result. The CORE-08 run record does not
//!   fit a boundary check ([`CorpusReport`] says why); its redacted
//!   [`Label`](crate::foundation::report::Label) is reused.
//!
//! The tests build their scratch directories with `tempfile`, which follows TMP and TEMP:
//! point both off the system drive before running them, or the corpus writes its trees
//! (long paths and all) wherever those point. The mount case crosses to the Windows
//! directory when that is on another volume, else to the root of another fixed volume, so
//! the crossing no longer depends on where TMP points; a computer with one volume cannot
//! cross and the whole-corpus test says so.
//!
//! The corpus does not repeat the files module's unit tests; each case names the tests
//! that check the same refusals in more detail ([`BoundaryCase::also_covered_by`]). Nothing
//! here starts a VM, opens a network connection or resolves a UNC name: device and UNC
//! spellings stop at the name filter, which is the point of those cases.

mod cases;
mod host;
mod report;
mod runner;

#[cfg(test)]
mod tests;

pub use cases::{
    corpus, mount_link, Action, BoundaryCase, CaseId, CorpusError, Effect, Expected, GuestInput, HostSpelling,
    Layer, Place, ProbeOperation, Race, Request, Step, Target, DIRECTORY_REPARSE_TAG, DIR_LINK,
    FILE_REPARSE_TAG, MOUNT_PROBE, OUTSIDE_CANARY, RACE_CYCLES,
};
pub use report::{
    CaseResult, CorpusReport, Finding, ProbeResult, ReportProblem, RunScope, SkipReason, Verdict,
    CORPUS_CHECK, CORPUS_FAMILY, MAX_FINDING_LEN,
};
pub use runner::{
    run_case, run_case_with_reader, run_corpus, OpenGrantedRoot, OpenReader, OpenResolver,
    ReadsFiles, ResolverUnderTest,
};
