//! V05: capability-rooted files, artifact promotion, persistence classes and leases
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §2.6, §5.1–§5.5, §6.2, §6.4,
//! VM-W14, VM-W24/W25, VM-P15–P18, VM-P34, VM-P37, VM-P49, VM-D7, VM-D10, VM-D12).
//!
//! Tier 0 library code (VM §12.1): name rules, grants, a typed resolution model, archive
//! entry checks, volume classes, lifetime policy and class responses; and, since M12, the
//! host side of file access (VM-W14): a race-resistant resolver beneath an opened root and
//! the file service over it, which promotion also runs on. Their tests use temporary
//! directories. Nothing here starts a VM, touches a perimeter or reads a credential.
//!
//! - [`GuestName`] filters untrusted guest names. It is a first filter only and is not
//!   race-proof (line 2047). [`RootModel`] specifies resolution over typed entries, so
//!   link kinds are refused without creating any link.
//! - [`GrantedRoot`] is the real control: a host-selected directory opened once, beneath
//!   which every name is resolved one handle-relative component at a time, refusing links,
//!   reparse points, hard-linked files, devices, mount crossings and case aliases with the
//!   [`RootModel`] results, and changing entries only through handles (§5.1).
//! - [`FileGrant`] binds a host-selected root handle, operations, trust scope, expiry and
//!   quota (§5.1); [`FileService`] serves one grant beneath its [`GrantedRoot`]. The
//!   guest reaches it only over the host/guest transport (VM-W06), outside this module.
//! - Promotion is a transaction (§5.2): [`freeze`], [`validate_manifest`],
//!   [`observe_destination`], [`review`], [`authorize`] and [`apply`]. Its filesystem
//!   steps work through [`GrantedRoot`] handles ([`freeze_in`],
//!   [`observe_destination_in`], [`apply_in`]), rechecking every precondition at commit.
//! - [`check_archive`] checks a typed archive entry list for imports (§5.2, VM-P37).
//! - [`plan_renewal`] applies the persistent volume classes of §5.5.
//! - [`LifetimePolicy`], [`IdleKeepAlive`], [`ExpiryGuard`] and [`ClockSkewPolicy`]
//!   implement §6.2 and VM-D12 on the coordination leases (CORE-04).
//! - [`engine_death_response`] and [`respond_to_violation`] are VM-D7 and VM-D10.
//! - [`ManagedObjects::validate_cleanup`] is the cleanup safety check of §6.4 (VM-P49).
//!   Processes are named by `foundation::process`'s identity and observed by the host
//!   ([`ObservedIdentities::observe_processes`]); a VM's host process is registered from its
//!   [`HostProcess`](crate::foundation::process::HostProcess) ([`ManagedProcess::of`]).
//! - [`create_fresh_root`], [`RootJournal`] and [`teardown`] are M13's fresh per-boot roots,
//!   their write-ahead journal and teardown through handles; [`RootJournal::record_vm_process`]
//!   journals each VM's host process, and teardown deletes nothing until the host shows every
//!   one ended ([`VmProcessEnds`], [`HostVmEnds`]).

/// Declares an internally tagged enum whose deserializer refuses unknown fields for every
/// variant. serde ignores unknown fields next to the tag of a unit variant even with
/// `deny_unknown_fields`, so reading goes through a twin enum whose unit variants are
/// empty struct variants; the written form is unchanged. The pattern is the one in
/// `foundation/report/mod.rs`, kept local so this module depends on no other's macros.
///
/// The tag must be a string. Inside another tagged enum's fields serde buffers the record
/// and then reads a buffered integer tag as the variant with that index, so a renewal
/// `class` of `1` would read as the second class; reading therefore takes the record as a
/// JSON value first through `foundation::strict_serde::read_tagged`, which refuses a tag that
/// is not a string and a key repeated in one object, before the twin reads it (E01Y's
/// finding).
macro_rules! strict_tagged_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident (tag = $tag:literal, wire = $wire:ident, wire_name = $wire_name:literal) {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $({
                    $(
                        $(#[$field_meta:meta])*
                        $field:ident : $field_type:ty
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
                $variant $({
                    $(
                        $(#[$field_meta])*
                        $field: $field_type
                    ),*
                })?
            ),*
        }

        #[derive(serde::Deserialize)]
        #[serde(tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
        enum $wire {
            $(
                $variant {
                    $($(
                        $field: $field_type
                    ),*)?
                }
            ),*
        }

        impl From<$wire> for $name {
            fn from(wire: $wire) -> Self {
                match wire {
                    $(
                        $wire::$variant { $($($field),*)? } => Self::$variant $({ $($field),* })?,
                    )*
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let record = crate::foundation::strict_serde::read_tagged(deserializer, $tag)?;
                <$wire as serde::Deserialize>::deserialize(record)
                    .map(Self::from)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

mod apply;
mod archive;
mod class;
mod cleanup;
mod file_id;
mod fresh_root;
mod fsutil;
mod grant;
mod lifetimes;
mod manifest;
mod names;
mod recovery;
mod resolve;
mod review;
mod root;
mod root_journal;
mod service;
mod teardown;
mod tree;
mod vm_processes;
mod volumes;

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod fresh_root_tests;
#[cfg(test)]
mod lifetime_tests;
#[cfg(test)]
mod promotion_tests;
#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
mod root_tests;
#[cfg(test)]
mod service_tests;
#[cfg(test)]
mod vm_process_tests;

pub use apply::{
    apply, apply_in, authorize, backup_label, backup_names, execution_reference, undo_interrupted,
    AppliedChange, InterruptedUndo, JournalPromotionAudit, PromotionAudit, PromotionAuthorization,
    PromotionPaths, PromotionReceipt, PromotionRoots, EXECUTION_REFERENCE_DOMAIN,
};
pub use archive::{
    check_archive, check_inspection, ArchiveEntry, ArchiveEntryKind, ArchiveLimits, ArchiveRefusal,
    ArtifactOrigin, CheckedArchive, ExtractionMeter, ImportInspection, InspectionMethod,
    InspectionRefusal,
};
pub use class::{
    engine_death_response, gui_closed_response, respond_to_violation, EngineDeathAction,
    EngineDeathResponse, ExistingOperations, GuiClosedResponse, NewAuthorizations, OneClickStop,
    SandboxClass, ViolationAction, ViolationOutcome,
};
pub use cleanup::{
    CleanupPlan, CleanupRefusal, CleanupTarget, ManagedObjectKind, ManagedObjects, ManagedProcess,
    ManagedRootId, ObjectHandle, ObservedIdentities, ProcessHandleKind,
};
pub use file_id::{FileId128, RawFileIdentity};
pub use fresh_root::{
    compensate_launch, create_fresh_root, CompensatedObject, CompensationError,
    CompensationOutcome, CompensationReport, LaunchCause, LaunchFailure, LaunchRefusal,
    LayoutEntry, LayoutProblem, RootEntry, RootLayout, SandboxBoot, TeardownDisposition,
    FRESH_ROOT_DOMAIN, LAYOUT_VOLUME_DOMAIN, MAX_ROOT_ENTRIES,
};
pub use grant::{
    DisclosureAcknowledgment, FileGrant, FileOperation, FileQuota, FileRequest, GrantMode,
    GrantProblem, GrantRefusal, HostStateClaim, QuotaUsage, RootHandle, LIVE_WORKSPACE_DISCLOSURE,
};
pub use lifetimes::{
    Activity, ClockSkewPolicy, ExpiryGuard, GuardState, IdleKeepAlive, IgnoredActivity,
    KeepAliveDecision, LifetimeLimit, LifetimePolicy, LifetimeProblem, LifetimeRefusal,
    LocalExpiry, RemoteExpiry, RemoteObservation, SkewRefusal, WallClockGuard,
    DEFAULT_IDLE_SECONDS, DEFAULT_SERVICE_RENEWAL_SECONDS, DEFAULT_TASK_ABSOLUTE_SECONDS,
};
pub use manifest::{
    freeze, freeze_in, validate_manifest, ExpectedProvenance, FileKind, FrozenManifest, IoStep,
    ManifestEntry, PromotionPolicy, PromotionRefusal, ProposedFile, Provenance,
};
pub use names::{
    CollisionRefusal, EntryRole, GuestName, NameRefusal, NameSet, MAX_COMPONENT_BYTES,
    MAX_NAME_BYTES, MAX_NAME_COMPONENTS,
};
pub use recovery::{recover_teardown, LeftAtName, RecoveryError, RecoveryRefusal, RecoveryReport};
pub use resolve::{EntryKind, LinkKind, ResolveIntent, ResolveRefusal, Resolved, RootModel};
pub use review::{
    observe_destination, observe_destination_in, review, ChangeKind, DestinationSnapshot,
    DestinationState, PathBlock, Review, ReviewFlag, ReviewedChange, RootIdentity,
};
pub use root::{GrantedRoot, RootOpenError, GRANTED_ROOT_DOMAIN};
pub use root_journal::{
    ObjectState, RegistrationError, RootJournal, RootJournalEntry, RootJournalError,
    RootJournalFailure, RootJournalStore, RootPhase,
};
pub use service::{
    FileService, ListedEntry, ListedKind, Listing, RangeRead, RequestContext, ServiceRefusal,
    MAX_LISTED_ENTRIES, MAX_RANGE_BYTES, MAX_READ_BYTES, MAX_UPLOADS, UPLOAD_IDLE,
};
pub use teardown::{
    teardown, FinishedObject, LeftBehind, TeardownError, TeardownFailure, TeardownOutcome,
    TeardownReport,
};
pub use vm_processes::{
    EndedVmProcess, HostVmEnds, ProcessEndEvidence, VmProcessEnds, VmProcessProblem,
    VmProcessRecordError, VmProcessRefusal,
};
pub use volumes::{
    plan_renewal, CredentialHolder, MountDisposition, MountedStateClaim, PersistenceProfile,
    RenewalBehavior, RenewalPlan, RenewalRefusal, RenewalRequest, RenewalSummary,
    ServiceRenewalContract, ServiceRenewalProblem, StateTrust, VolumeClass, VolumeRenewal,
};

pub(crate) use archive::{check_archive_for, ImageArchiveRefusal};
pub use names::ImageName;
