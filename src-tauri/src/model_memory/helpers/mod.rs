//! G08, the library half of GPU-W11's helper delivery and loader rollout
//! (docs/combined-plan-leftover-tasks.md G08; docs/combined-gpu-memory-and-vm-sandbox-plan.md
//! GPU-W11 at line 1313: line 1321 "Package model helpers through CORE-08 with
//! authenticated pinned artifact identity and a stable ABI; checksums alone do not
//! establish release trust", line 1327 "Avoid ever-growing source injection", line 1328
//! "Roll out in shadow-observation, opt-in, then backend-specific default stages", lines
//! 1329–1330 on rollback and removing obsolete loops; S2 CORE-08 at line 217; VM-W45 at
//! line 2668 "Do not create a parallel model-helper updater"; Appendix lines 1687 and
//! 1696 on the current source injection).
//!
//! Today the runner injects each helper's compressed source into environment variables
//! that grow with every helper. This module packages helpers as signed, pinned catalog
//! objects and rolls them out per backend while source injection stays the fallback:
//!
//! - [`manifest`] and [`bundle`]: a helper bundle is one object holding a strict,
//!   canonical manifest (helper id, version, [`abi`] version, supported runners and every
//!   file's content key) and the files, each checked against its key.
//! - [`admission`]: bundles are admitted only through the catalog, under their own class
//!   `model_helper`, signed by a key of the configured trust roots, with a compatible ABI;
//!   anything else is refused or, once its key is revoked, quarantined, with a typed
//!   reason. The signature, roots, policy and catalog checks are CORE-08's and CORE-02's
//!   own.
//! - [`identity`]: the [`HelperPin`] runners start from and rollouts move between.
//! - [`rollout`]: shadow, opt-in and backend-default stages per helper and backend,
//!   promotion only on recorded measured passes, automatic rollback to the last good
//!   pinned version on failure evidence, and removal of source injection only as a
//!   recorded decision after its replacement passed.
//! - [`runners`]: a running runner keeps the versions it started with.
//! - [`evidence`] and [`journal`]: every rollout decision and runner start and stop on one
//!   durable stream with one owner, replayed on restart, each decision naming its CORE-08
//!   evidence by identity.
//!
//! The helper ABI is the runner-loader interface, not `boundaries::NativeAbi`; rollout
//! evidence is CORE-08 [`Provenance`](crate::foundation::report::Provenance); backends
//! and exact runner versions are `foundation::evidence`'s
//! [`BackendRelease`](crate::foundation::evidence::BackendRelease). Product
//! controls (opting in, rollout and removal actions, status views) belong to U01/U02.
//!
//! # Production callers
//!
//! The library half ends here; `model_runner` is not changed. A production caller would:
//!
//! 1. At engine start, load the owner's roots (`TrustRoots::load`) into a
//!    `SharedTrustRoots`, register [`helper_verifier`] in the catalog's
//!    `VerifierRegistry`, configure `CatalogConfig::with_trust(HELPER_CLASS,
//!    helper_policy(&roots))` and a host quota, and build one [`HelperAdmission`] with the
//!    loader's [`HostHelperAbi`] and the same roots and calendar. On a reload of the
//!    roots, call `SharedTrustRoots::replace`, then `Catalog::set_trust_policy(
//!    HELPER_CLASS, helper_policy(&roots.current()))`, and restart the runners
//!    [`RunnerPins::running_on_object`] lists for each quarantined object.
//! 2. When a release delivers a bundle and its signature, call [`HelperAdmission::admit`]
//!    and keep the [`AdmittedHelper::pin`].
//! 3. Wire the U01/U02 rollout actions to [`HelperRollouts::propose`],
//!    [`HelperRollouts::promote`] and [`HelperRollouts::remove_source_injection`], each
//!    with [`HelperAdmission::admissibility`] over the catalog.
//! 4. Where `model_runner` now calls `optimizer::environment`, `publisher_source`,
//!    `registry_source` or `clef_source` (`run_model_at_revision`, `run_registry_model`,
//!    `local::run_verified` and `refresh_server`, which starts a new runner process),
//!    call [`HelperRollouts::select`] for each helper with the runner's backend release
//!    and the user's opt-in. For [`ServingHelper::Bundle`] and every shadow pin, call
//!    [`HelperAdmission::open`] and write the returned files into the runner's model
//!    volume instead of the environment; for [`ServingHelper::SourceInjection`], keep
//!    today's injection. Then call [`RunnerPins::start`]; on stop, [`RunnerPins::stop`].
//! 5. Turn each shadow comparison and serving trial into CORE-08 run records, take
//!    `Provenance::of_records`, and call [`HelperRollouts::record`] with a
//!    [`RolloutEvidence`]; a returned [`RecordOutcome::RolledBack`] needs no further
//!    action for new runners, and [`RunnerPins::running_on`] lists the running ones.
//! 6. Keep the rollout and the runner pins in a [`RolloutJournal`], which records each
//!    of these calls durably and restores them on restart; [`journal`] lists its calls.
//!
//! Every test runs on fakes, temporary catalogs and RFC 8032-style test keys generated in
//! the tests. Nothing here loads a helper into a runner or claims a performance result.

pub mod abi;
pub mod admission;
pub mod bundle;
pub mod evidence;
pub mod identity;
pub mod journal;
pub mod manifest;
pub mod rollout;
pub mod runners;

#[cfg(test)]
mod tests;

pub use abi::{HelperAbi, HelperAbiRefusal, HostAbiError, HostHelperAbi};
pub use admission::{
    bundle_statement, helper_policy, helper_verifier, AdmittedHelper, CatalogPins, HelperAdmission,
    HelperBundleStructure, HelperOffer, HelperRefusal, HelperSignature, HELPER_CLASS,
    HELPER_EXTENT_BYTES, HELPER_LABEL, HELPER_SOURCE_KIND, HELPER_VERSION_LABEL,
};
pub use bundle::{BundleError, HelperBundle, BUNDLE_HEADER_BYTES, BUNDLE_MAGIC, MAX_BUNDLE_BYTES};
pub use evidence::{
    check_component, pin_statement, BundleMismatch, EvidenceReference, EvidenceRefusal,
};
pub use identity::{HelperPin, HelperPinId, PinAdmissibility, PinRefusal, HELPER_PIN_DOMAIN};
pub use journal::{
    FellBack, JournalError, JournalRecord, OnQuarantine, ReplayRefusal, ReplayReport,
    RolloutJournal, TrackWithdrawal, Withdrawal,
};
pub use manifest::{
    HelperFile, HelperId, HelperManifest, HelperPath, HelperPathError, HelperVersion,
    HelperVersionError, ManifestError, HELPER_MANIFEST_FORMAT, MAX_HELPER_FILES,
    MAX_HELPER_FILES_BYTES, MAX_HELPER_FILE_BYTES, MAX_HELPER_PATH_BYTES, MAX_HELPER_RUNNERS,
    MAX_MANIFEST_BYTES,
};
pub use rollout::{
    DefaultPath, FallbackReason, HelperRollouts, Promotion, RecordOutcome, RollbackTarget,
    RolloutEvent, RolloutEvidence, RolloutRecord, RolloutRefusal, RolloutStage, RunnerHelpers,
    SelectionRefusal, ServingHelper, SourceInjection, SourceInjectionRemoval, TrackView,
    TrialVerdict,
};
pub use runners::{PinningRefusal, RunnerInstance, RunnerPins, RunnerStart};
