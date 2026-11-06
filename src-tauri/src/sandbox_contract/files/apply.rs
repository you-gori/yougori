//! Authorizing and applying a promotion (VM part §5.2 steps 4–7, lines 2066–2069; §2.6
//! line 1835; VM-P16).
//!
//! The authorization binds the manifest digest, the review digest and the destination's
//! expected base state, and acknowledges every review flag exactly. Applying rechecks
//! all of it: the review is recomputed from the manifest and snapshot, the destination
//! root and every target are observed again, and every source file is read again and
//! must have its frozen content key. The audit journal must admit the operation before
//! anything in the destination changes. Each target is rechecked once more just before it
//! is written; the bytes written are exactly the buffer whose key matched, so promotion
//! cannot apply bytes other than those reviewed (§2.6).
//!
//! New files are created exclusively and modified files are replaced by an atomic rename
//! after the original is copied to the host's backup root and verified. If any step
//! fails, the completed steps are undone in reverse; a file that changed again after the
//! promotion wrote it is left alone and reported. Originals are never deleted: the copy in
//! the backup root stays after success.
//!
//! Every filesystem step works through the opened roots ([`GrantedRoot`], M12): the
//! source, destination and backup roots are opened once, each name is resolved through
//! handles that never follow a link, and a target is created or replaced relative to the
//! handle of the directory that was checked (line 2047). [`apply_in`] takes roots the host
//! opened at grant time; [`apply`] opens them from paths once.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::fsutil;
use super::manifest::{
    hash_source, open_source, open_source_file, validate_manifest, FileKind, FrozenManifest,
    IoStep, PromotionPolicy, PromotionRefusal,
};
use super::names::GuestName;
use super::review::{
    observe_entry, open_destination, review as review_of, ChangeKind, DestinationSnapshot,
    DestinationState, Review, ReviewFlag, ReviewedChange,
};
use super::root::{EntryProblem, GrantedRoot, RootOpenError};
use crate::foundation::events::{
    AuditAppendAuthority, AuditDraft, AuditJournal, AuditReceipt, AuditRefusal, AuditSpool,
    AuditStore, EventContext, Field, FieldValue, HostFact, Phase,
};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{
    digest, Clock, ContentKey, Digest, DigestBuilder, ExecutionId, MonotonicTime, OperationId,
};

const AUTHORIZATION_DOMAIN: &str = "yougori/sandbox/files/promotion-authorization/v1";

/// The approval of one reviewed promotion (§5.2 step 4), bound to the manifest, the
/// review and the destination's expected base state, with every flag acknowledged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AuthorizationWire")]
pub struct PromotionAuthorization {
    manifest: Digest,
    review: Digest,
    destination: Digest,
    acknowledged: BTreeMap<GuestName, BTreeSet<ReviewFlag>>,
    approval: OperationId,
    clock: ClockSession,
    authorized_at: MonotonicTime,
    expires_at: MonotonicTime,
    digest: Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationWire {
    manifest: Digest,
    review: Digest,
    destination: Digest,
    acknowledged: BTreeMap<GuestName, BTreeSet<ReviewFlag>>,
    approval: OperationId,
    clock: ClockSession,
    authorized_at: MonotonicTime,
    expires_at: MonotonicTime,
    digest: Digest,
}

impl TryFrom<AuthorizationWire> for PromotionAuthorization {
    type Error = PromotionRefusal;

    fn try_from(wire: AuthorizationWire) -> Result<Self, Self::Error> {
        let mut authorization = Self {
            manifest: wire.manifest,
            review: wire.review,
            destination: wire.destination,
            acknowledged: wire.acknowledged,
            approval: wire.approval,
            clock: wire.clock,
            authorized_at: wire.authorized_at,
            expires_at: wire.expires_at,
            digest: wire.digest,
        };
        if authorization.compute_digest() != wire.digest {
            return Err(PromotionRefusal::AuthorizationDigestMismatch);
        }
        authorization.digest = wire.digest;
        Ok(authorization)
    }
}

impl PromotionAuthorization {
    fn compute_digest(&self) -> Digest {
        let mut builder = DigestBuilder::new(AUTHORIZATION_DOMAIN)
            .digest(&self.manifest)
            .digest(&self.review)
            .digest(&self.destination)
            .u64(self.acknowledged.len() as u64);
        for (name, flags) in &self.acknowledged {
            builder = builder.str(name.as_str()).u64(flags.len() as u64);
            for flag in flags {
                builder = builder.str(&format!("{flag:?}"));
            }
        }
        builder
            .str(self.approval.as_str())
            .bytes(self.clock.as_uuid().as_bytes())
            .u64(self.authorized_at.as_nanos())
            .u64(self.expires_at.as_nanos())
            .finish()
    }

    pub fn manifest(&self) -> Digest {
        self.manifest
    }

    pub fn review(&self) -> Digest {
        self.review
    }

    pub fn destination(&self) -> Digest {
        self.destination
    }

    pub fn acknowledged(&self) -> &BTreeMap<GuestName, BTreeSet<ReviewFlag>> {
        &self.acknowledged
    }

    pub fn expires_at(&self) -> MonotonicTime {
        self.expires_at
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }
}

/// Approves `review` (§5.2 step 4). `acknowledged` must name exactly the review's flags,
/// entry by entry: a missing acknowledgment and one for a flag the review lacks are both
/// refused. The approval lasts `valid_for` on `clock`.
pub fn authorize(
    review: &Review,
    acknowledged: BTreeMap<GuestName, BTreeSet<ReviewFlag>>,
    approval: OperationId,
    clock: &dyn Clock,
    session: ClockSession,
    valid_for: Duration,
) -> Result<PromotionAuthorization, PromotionRefusal> {
    if review.recomputed_digest() != review.digest() {
        return Err(PromotionRefusal::ReviewDigestMismatch);
    }
    let flagged = review.flagged();
    for (name, flags) in &flagged {
        let missing: Vec<ReviewFlag> = match acknowledged.get(name) {
            Some(given) => flags.difference(given).copied().collect(),
            None => flags.iter().copied().collect(),
        };
        if !missing.is_empty() {
            return Err(PromotionRefusal::UnacknowledgedFlags {
                name: name.clone(),
                flags: missing,
            });
        }
    }
    for (name, given) in &acknowledged {
        if flagged.get(name) != Some(given) {
            return Err(PromotionRefusal::UnexpectedAcknowledgment { name: name.clone() });
        }
    }
    let authorized_at = clock.now();
    let mut authorization = PromotionAuthorization {
        manifest: review.manifest(),
        review: review.digest(),
        destination: review.destination(),
        acknowledged,
        approval,
        clock: session,
        authorized_at,
        expires_at: authorized_at.saturating_add(valid_for),
        digest: Digest::from_bytes([0; 32]),
    };
    authorization.digest = authorization.compute_digest();
    Ok(authorization)
}

/// The audit port of a promotion (§5.2 step 6: an audit receipt). `admit` records the
/// promotion before anything changes and its receipt is the permission to proceed;
/// `record_outcome` records how it ended.
pub trait PromotionAudit {
    fn admit(&mut self, fields: Vec<Field>) -> Result<AuditReceipt, AuditRefusal>;
    fn record_outcome(
        &mut self,
        applied: bool,
        fields: Vec<Field>,
    ) -> Result<AuditReceipt, AuditRefusal>;
}

/// [`PromotionAudit`] over a CORE-06 audit journal: admission is a high-impact
/// operation, so under the journal's deny policy it needs a durable record.
pub struct JournalPromotionAudit<'a, S, P, C> {
    journal: &'a mut AuditJournal<S, P, C>,
    authority: &'a mut AuditAppendAuthority,
    operation: OperationId,
}

impl<'a, S: AuditStore, P: AuditSpool, C: Clock> JournalPromotionAudit<'a, S, P, C> {
    pub fn new(
        journal: &'a mut AuditJournal<S, P, C>,
        authority: &'a mut AuditAppendAuthority,
        operation: OperationId,
    ) -> Self {
        Self {
            journal,
            authority,
            operation,
        }
    }
}

impl<S: AuditStore, P: AuditSpool, C: Clock> PromotionAudit for JournalPromotionAudit<'_, S, P, C> {
    fn admit(&mut self, fields: Vec<Field>) -> Result<AuditReceipt, AuditRefusal> {
        self.journal.admit_high_impact(
            self.authority,
            EventContext::new(self.operation.clone(), Phase::Requested),
            fields,
        )
    }

    fn record_outcome(
        &mut self,
        applied: bool,
        fields: Vec<Field>,
    ) -> Result<AuditReceipt, AuditRefusal> {
        let phase = if applied {
            Phase::Completed
        } else {
            Phase::Failed
        };
        self.journal.append(
            self.authority,
            EventContext::new(self.operation.clone(), phase),
            AuditDraft::HostFact {
                fact: HostFact::HighImpactOperation,
                fields,
            },
        )
    }
}

/// The three host directories of a promotion, by path: the guest's quarantine output, the
/// user's destination and the host's backup root for originals. [`apply`] opens each once.
#[derive(Clone, Copy, Debug)]
pub struct PromotionPaths<'a> {
    pub source_root: &'a Path,
    pub destination_root: &'a Path,
    pub backup_root: &'a Path,
}

/// The three roots of a promotion, already opened by the host (§5.1; M12): every step of
/// [`apply_in`] works through these handles and never resolves a path again.
#[derive(Clone, Copy, Debug)]
pub struct PromotionRoots<'a> {
    pub source: &'a GrantedRoot,
    pub destination: &'a GrantedRoot,
    pub backup: &'a GrantedRoot,
}

/// What applying did to one entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppliedChange {
    Added {
        name: GuestName,
    },
    /// Replaced; the original's verified copy is at `backup`, beneath the backup root.
    Modified {
        name: GuestName,
        backup: PathBuf,
    },
    Unchanged {
        name: GuestName,
    },
}

/// The record of an applied promotion (§5.2 step 6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromotionReceipt {
    pub manifest: Digest,
    pub authorization: Digest,
    /// The journal's admission, the permission the promotion ran under.
    pub admission: AuditReceipt,
    /// The outcome record; the promotion already happened if it was refused.
    pub outcome: Result<AuditReceipt, AuditRefusal>,
    pub applied: Vec<AppliedChange>,
}

/// The digest domain an execution's id is named under in an audit record.
pub const EXECUTION_REFERENCE_DOMAIN: &str = "yougori/audit/execution/v1";
/// The digest domain a promotion's source operation is named under in an audit record.
const SOURCE_OPERATION_DOMAIN: &str = "yougori/audit/source-operation/v1";

/// How an audit record names `execution`: a digest the stream keeps whole, which anyone
/// holding the id can recompute.
pub fn execution_reference(execution: &ExecutionId) -> Digest {
    digest(EXECUTION_REFERENCE_DOMAIN, &[execution.as_str().as_bytes()])
}

fn audit_fields(manifest: &FrozenManifest, authorization: &PromotionAuthorization) -> Vec<Field> {
    // Who made the files, named in the record itself: a promotion after the sandbox ended,
    // or after a restart of the engine, stays attributed to the sandbox and boot whose
    // files it writes, whatever context the stream still holds for it. Identifiers go in
    // as digests, which the stream keeps (its redaction withholds token-like text).
    let provenance = manifest.provenance();
    vec![
        Field::metadata("action", "artifact_promotion"),
        Field::metadata("execution", FieldValue::Digest(execution_reference(&provenance.execution))),
        Field::metadata("boot", provenance.boot.get()),
        Field::metadata(
            "source_operation",
            FieldValue::Digest(digest(SOURCE_OPERATION_DOMAIN, &[provenance.operation.as_str().as_bytes()])),
        ),
        Field::metadata("scope", FieldValue::Digest(provenance.scope.domain)),
        Field::metadata("manifest", FieldValue::Digest(manifest.digest())),
        Field::metadata("authorization", FieldValue::Digest(authorization.digest())),
        Field::metadata(
            "files",
            u64::try_from(manifest.entries().len()).unwrap_or(u64::MAX),
        ),
        Field::metadata("bytes", manifest.total_bytes()),
    ]
}

/// Applies an authorized promotion (§5.2 steps 5–7), opening the three host-selected roots
/// at `paths` once after the bindings are checked. Refuses, changing nothing in the
/// destination, when any binding, the policy, the destination root, a target or a source
/// byte differs from what was reviewed, or when the audit journal refuses.
#[allow(clippy::too_many_arguments)]
pub fn apply(
    paths: &PromotionPaths<'_>,
    manifest: &FrozenManifest,
    review: &Review,
    snapshot: &DestinationSnapshot,
    authorization: &PromotionAuthorization,
    policy: &PromotionPolicy,
    audit: &mut dyn PromotionAudit,
    clock: &dyn Clock,
    session: ClockSession,
) -> Result<PromotionReceipt, PromotionRefusal> {
    preflight(
        manifest,
        review,
        snapshot,
        authorization,
        policy,
        clock,
        session,
    )?;
    let backup = GrantedRoot::open(paths.backup_root).map_err(|error| match error {
        RootOpenError::NotARealDirectory | RootOpenError::Changed => {
            PromotionRefusal::BackupRootInvalid
        }
        RootOpenError::Io(error) => PromotionRefusal::io(IoStep::InspectRoot, None, &error),
    })?;
    let destination = open_destination(paths.destination_root)?;
    let source = open_source(paths.source_root)?;
    let roots = PromotionRoots {
        source: &source,
        destination: &destination,
        backup: &backup,
    };
    commit(
        &roots,
        manifest,
        review,
        snapshot,
        authorization,
        policy,
        audit,
    )
}

/// Applies an authorized promotion (§5.2 steps 5–7) through roots the host already opened
/// (M12): the same checks as [`apply`], with no path resolved again.
#[allow(clippy::too_many_arguments)]
pub fn apply_in(
    roots: &PromotionRoots<'_>,
    manifest: &FrozenManifest,
    review: &Review,
    snapshot: &DestinationSnapshot,
    authorization: &PromotionAuthorization,
    policy: &PromotionPolicy,
    audit: &mut dyn PromotionAudit,
    clock: &dyn Clock,
    session: ClockSession,
) -> Result<PromotionReceipt, PromotionRefusal> {
    preflight(
        manifest,
        review,
        snapshot,
        authorization,
        policy,
        clock,
        session,
    )?;
    commit(
        roots,
        manifest,
        review,
        snapshot,
        authorization,
        policy,
        audit,
    )
}

/// The checks that need no filesystem: bindings, clock session, expiry and policy.
fn preflight(
    manifest: &FrozenManifest,
    review: &Review,
    snapshot: &DestinationSnapshot,
    authorization: &PromotionAuthorization,
    policy: &PromotionPolicy,
    clock: &dyn Clock,
    session: ClockSession,
) -> Result<(), PromotionRefusal> {
    check_bindings(manifest, review, snapshot, authorization)?;
    if session != authorization.clock {
        return Err(PromotionRefusal::AuthorizationOtherClock);
    }
    if clock.now() >= authorization.expires_at {
        return Err(PromotionRefusal::AuthorizationExpired {
            expired_at: authorization.expires_at,
        });
    }
    validate_manifest(manifest, policy)
}

fn commit(
    roots: &PromotionRoots<'_>,
    manifest: &FrozenManifest,
    review: &Review,
    snapshot: &DestinationSnapshot,
    authorization: &PromotionAuthorization,
    policy: &PromotionPolicy,
    audit: &mut dyn PromotionAudit,
) -> Result<PromotionReceipt, PromotionRefusal> {
    check_backup_root(roots)?;
    if roots.destination.identity() != snapshot.root() {
        return Err(PromotionRefusal::DestinationRootChanged);
    }
    for change in review.changes() {
        recheck_target(roots.destination, snapshot, &change.name)?;
    }
    // Each source is checked by hashing it in bounded chunks; nothing of its content is
    // held. The commit copies it again and refuses a copy whose content key differs.
    let mut staged = Vec::new();
    for change in review.changes() {
        if change.change == ChangeKind::Unchanged {
            continue;
        }
        let (size_bytes, kind, content) = hash_source(roots.source, &change.name, policy.max_file_bytes)
            .map_err(|refusal| match refusal {
                PromotionRefusal::Io { .. } => refusal,
                _ => PromotionRefusal::SourceChanged {
                    name: change.name.clone(),
                },
            })?;
        if content != change.content || kind != change.kind || size_bytes != change.size_bytes {
            return Err(PromotionRefusal::SourceChanged {
                name: change.name.clone(),
            });
        }
        staged.push(change);
    }
    let fields = audit_fields(manifest, authorization);
    let admission =
        audit
            .admit(fields.clone())
            .map_err(|refusal| PromotionRefusal::AuditRefused {
                detail: refusal.to_string(),
            })?;
    let mut commit = Commit::new(roots, manifest, authorization, policy.max_file_bytes);
    match commit.run(snapshot, &staged) {
        Ok(()) => {
            let outcome = audit.record_outcome(true, fields);
            let mut applied = commit.applied;
            for change in review.changes() {
                if change.change == ChangeKind::Unchanged {
                    applied.push(AppliedChange::Unchanged {
                        name: change.name.clone(),
                    });
                }
            }
            Ok(PromotionReceipt {
                manifest: manifest.digest(),
                authorization: authorization.digest(),
                admission,
                outcome,
                applied,
            })
        }
        Err(cause) => {
            let refusal = commit.roll_back(cause);
            let _ = audit.record_outcome(false, fields);
            Err(refusal)
        }
    }
}

fn check_bindings(
    manifest: &FrozenManifest,
    review: &Review,
    snapshot: &DestinationSnapshot,
    authorization: &PromotionAuthorization,
) -> Result<(), PromotionRefusal> {
    if authorization.compute_digest() != authorization.digest {
        return Err(PromotionRefusal::AuthorizationDigestMismatch);
    }
    if authorization.manifest != manifest.digest() {
        return Err(PromotionRefusal::AuthorizationMismatch { bound: "manifest" });
    }
    if authorization.review != review.digest() {
        return Err(PromotionRefusal::AuthorizationMismatch { bound: "review" });
    }
    if authorization.destination != snapshot.digest() {
        return Err(PromotionRefusal::AuthorizationMismatch {
            bound: "destination base state",
        });
    }
    if review_of(manifest, snapshot)? != *review {
        return Err(PromotionRefusal::ReviewDigestMismatch);
    }
    Ok(())
}

/// The backup root is a root of its own: neither the source nor the destination, and not
/// inside either.
fn check_backup_root(roots: &PromotionRoots<'_>) -> Result<(), PromotionRefusal> {
    let backup = roots.backup;
    let inside = |tree: &GrantedRoot| {
        backup.identity() == tree.identity() || backup.origin().starts_with(tree.origin())
    };
    if inside(roots.destination) || inside(roots.source) {
        return Err(PromotionRefusal::BackupRootInsideTree);
    }
    Ok(())
}

/// Observes `name` again and refuses any difference from the reviewed state.
fn recheck_target(
    root: &GrantedRoot,
    snapshot: &DestinationSnapshot,
    name: &GuestName,
) -> Result<(), PromotionRefusal> {
    let expected = snapshot
        .state(name)
        .ok_or(PromotionRefusal::SnapshotDoesNotMatchManifest)?;
    recheck_state(root, expected, name)
}

/// Observes `name` again and refuses any difference from `expected`.
fn recheck_state(
    root: &GrantedRoot,
    expected: &DestinationState,
    name: &GuestName,
) -> Result<(), PromotionRefusal> {
    let current = observe_entry(root, name)?;
    if current == *expected {
        return Ok(());
    }
    Err(match (expected, &current) {
        (DestinationState::Absent { .. }, state)
            if !matches!(state, DestinationState::Absent { .. }) =>
        {
            PromotionRefusal::TargetAppeared { name: name.clone() }
        }
        _ => PromotionRefusal::DestinationChanged { name: name.clone() },
    })
}

/// The refusal for a failed handle step on `name`: an entry that already exists is
/// `exists`, anything that no longer resolves as reviewed is a changed precondition, and
/// other I/O failures are reported under `step`.
fn step_refusal(
    problem: EntryProblem,
    name: &GuestName,
    step: IoStep,
    exists: PromotionRefusal,
) -> PromotionRefusal {
    match problem {
        EntryProblem::Io(error) if error.kind() == std::io::ErrorKind::AlreadyExists => exists,
        EntryProblem::Io(error) => PromotionRefusal::io(step, Some(name), &error),
        EntryProblem::Refused(_) | EntryProblem::NotAFile | EntryProblem::Changed => {
            PromotionRefusal::DestinationChanged { name: name.clone() }
        }
    }
}

/// One completed step, kept so a failure can undo it.
enum Step {
    CreatedDirectory(GuestName),
    Added {
        name: GuestName,
        content: ContentKey,
    },
    Replaced {
        name: GuestName,
        content: ContentKey,
        backup: String,
        original: ContentKey,
        original_kind: FileKind,
    },
}

/// The folder beneath the backup root where a promotion keeps the originals it replaces:
/// one per manifest and authorization.
pub fn backup_label(manifest: &FrozenManifest, authorization: &PromotionAuthorization) -> String {
    let manifest_hex = manifest.digest().to_hex();
    let authorization_hex = authorization.digest().to_hex();
    format!(
        "{}-{}",
        manifest_hex.get(..16).unwrap_or(&manifest_hex),
        authorization_hex.get(..16).unwrap_or(&authorization_hex)
    )
}

/// The name each original a promotion of `review` replaces is kept under in its backup
/// folder, as [`apply_in`] keeps it: the change's place among the changes it applies.
pub fn backup_names(review: &Review) -> BTreeMap<GuestName, String> {
    review
        .changes()
        .iter()
        .filter(|change| change.change != ChangeKind::Unchanged)
        .enumerate()
        .filter(|(_, change)| matches!(change.change, ChangeKind::Modify { .. }))
        .map(|(index, change)| (change.name.clone(), format!("{index}.original")))
        .collect()
}

/// Acceptance builds: holds a promotion after its step `index` when
/// `YOUGORI_ACCEPTANCE_PROMOTION_STEP_PAUSE` names it, writing `paused-promote-step` in the
/// backup root first, so an acceptance run can stop the engine part way through a commit.
#[cfg(feature = "acceptance")]
fn acceptance_step_pause(backup: &GrantedRoot, index: usize) {
    let wanted = std::env::var("YOUGORI_ACCEPTANCE_PROMOTION_STEP_PAUSE")
        .ok()
        .and_then(|text| text.parse::<usize>().ok());
    if wanted != Some(index) {
        return;
    }
    let seconds = std::env::var("YOUGORI_ACCEPTANCE_WORKSPACE_PAUSE_SECONDS")
        .ok()
        .and_then(|text| text.parse::<u64>().ok())
        .unwrap_or(60);
    let _ = std::fs::write(backup.origin().join("paused-promote-step"), b"");
    std::thread::sleep(Duration::from_secs(seconds));
}

#[cfg(not(feature = "acceptance"))]
fn acceptance_step_pause(_: &GrantedRoot, _: usize) {}

/// What undoing a promotion cut short (by an engine stop) did, file by file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct InterruptedUndo {
    /// Replaced by the promotion and put back from the verified original.
    pub restored: Vec<GuestName>,
    /// Added by the promotion and removed again, with the directories it made for them.
    pub removed: Vec<GuestName>,
    /// The promotion had not reached them: the folder holds what the review saw.
    pub not_applied: Vec<GuestName>,
    /// Neither what the promotion wrote nor what the review saw, or written with no
    /// verified original to put back: left exactly as they are.
    pub left: Vec<GuestName>,
}

/// Undoes what a promotion of `review` against `snapshot` that an engine stop cut short
/// wrote into `destination`: each file that still holds exactly what the promotion wrote is
/// put back as the review saw it (the original from `backup`'s folder `label`, verified
/// against its content key, or removed when it was added, with the directories made for
/// it when they are empty). Nothing else is touched.
pub fn undo_interrupted(
    destination: &GrantedRoot,
    backup: &GrantedRoot,
    label: &str,
    review: &Review,
    snapshot: &DestinationSnapshot,
) -> InterruptedUndo {
    let mut undo = InterruptedUndo::default();
    let names = backup_names(review);
    for change in review.changes() {
        if change.change == ChangeKind::Unchanged {
            continue;
        }
        let name = &change.name;
        if !still_holds(destination, name, change.content) {
            let untouched = match (snapshot.state(name), destination.open_file(name)) {
                (Some(DestinationState::Absent { .. }), Err(_)) => true,
                (Some(DestinationState::File { content, size_bytes, .. }), Ok(mut opened)) => {
                    opened.info.size == *size_bytes
                        && fsutil::hash_open(&mut opened.file, *size_bytes).ok().flatten() == Some(*content)
                }
                _ => false,
            };
            if untouched {
                undo.not_applied.push(name.clone());
            } else {
                undo.left.push(name.clone());
            }
            continue;
        }
        match &change.change {
            ChangeKind::Modify { from, from_kind, .. } => {
                let restored = names.get(name).is_some_and(|stored| {
                    backup
                        .open_top_file(label, stored)
                        .ok()
                        .is_some_and(|mut opened| {
                            let size_bytes = opened.info.size;
                            destination
                                .replace_file_from(
                                    name,
                                    &mut opened.file,
                                    size_bytes,
                                    *from_kind == FileKind::Executable,
                                    &format!(".yougori-restore-{}", name.file_name()),
                                    Some(*from),
                                )
                                .is_ok()
                        })
                });
                if restored {
                    undo.restored.push(name.clone());
                } else {
                    undo.left.push(name.clone());
                }
            }
            ChangeKind::Add => {
                if destination.remove_file(name).is_err() {
                    undo.left.push(name.clone());
                    continue;
                }
                // The directories the promotion made for it, deepest first, while empty.
                if let Some(DestinationState::Absent { missing_components }) = snapshot.state(name) {
                    let ancestors = name.ancestors();
                    let made = usize::try_from(missing_components.saturating_sub(1)).unwrap_or(0);
                    for ancestor in ancestors.iter().rev().take(made) {
                        if destination.remove_directory(ancestor).is_err() {
                            break;
                        }
                    }
                }
                undo.removed.push(name.clone());
            }
            ChangeKind::Unchanged => {}
        }
    }
    undo
}

struct Commit<'a> {
    roots: &'a PromotionRoots<'a>,
    label: String,
    /// The policy's largest file, which a source is opened within again.
    max_file_bytes: u64,
    backup_directory: bool,
    steps: Vec<Step>,
    applied: Vec<AppliedChange>,
    /// The directories this commit created for an earlier entry: a later entry beneath
    /// them finds them present, not the absence its snapshot recorded.
    created: BTreeSet<GuestName>,
}

impl<'a> Commit<'a> {
    fn new(
        roots: &'a PromotionRoots<'a>,
        manifest: &FrozenManifest,
        authorization: &PromotionAuthorization,
        max_file_bytes: u64,
    ) -> Self {
        let label = backup_label(manifest, authorization);
        Self {
            roots,
            label,
            max_file_bytes,
            backup_directory: false,
            steps: Vec::new(),
            applied: Vec::new(),
            created: BTreeSet::new(),
        }
    }

    fn run(
        &mut self,
        snapshot: &DestinationSnapshot,
        staged: &[&ReviewedChange],
    ) -> Result<(), PromotionRefusal> {
        for (index, change) in staged.iter().enumerate() {
            let expected = self.expected_state(snapshot, &change.name)?;
            recheck_state(self.roots.destination, &expected, &change.name)?;
            match (&change.change, &expected) {
                (ChangeKind::Add, DestinationState::Absent { missing_components }) => {
                    self.add(index, change, *missing_components)?
                }
                (
                    ChangeKind::Modify {
                        from, from_kind, ..
                    },
                    DestinationState::File { .. },
                ) => self.replace(index, change, *from, *from_kind)?,
                _ => {
                    return Err(PromotionRefusal::DestinationChanged {
                        name: change.name.clone(),
                    })
                }
            }
            acceptance_step_pause(self.roots.backup, index);
        }
        Ok(())
    }

    /// The state `name` must have now: the snapshot's, less the missing ancestors this
    /// commit created for an earlier entry (two new files in one new directory: the first
    /// creates it, the second finds it).
    fn expected_state(
        &self,
        snapshot: &DestinationSnapshot,
        name: &GuestName,
    ) -> Result<DestinationState, PromotionRefusal> {
        let state = snapshot
            .state(name)
            .ok_or(PromotionRefusal::SnapshotDoesNotMatchManifest)?;
        let DestinationState::Absent { missing_components } = state else {
            return Ok(state.clone());
        };
        let ancestors = name.ancestors();
        let first_missing = ancestors.len().saturating_sub(
            usize::try_from(missing_components.saturating_sub(1)).unwrap_or(usize::MAX),
        );
        let created = ancestors
            .iter()
            .skip(first_missing)
            .take_while(|ancestor| self.created.contains(*ancestor))
            .count();
        Ok(DestinationState::Absent {
            missing_components: missing_components
                .saturating_sub(u64::try_from(created).unwrap_or(u64::MAX)),
        })
    }

    /// The approved source of `change`, opened again for its copy: a source that is no
    /// longer the reviewed size or kind refuses before anything of it is written.
    fn source(&self, change: &ReviewedChange) -> Result<super::root::Opened, PromotionRefusal> {
        let changed = || PromotionRefusal::SourceChanged {
            name: change.name.clone(),
        };
        let (opened, kind) = open_source_file(self.roots.source, &change.name, self.max_file_bytes)
            .map_err(|refusal| match refusal {
                PromotionRefusal::Io { .. } => refusal,
                _ => changed(),
            })?;
        if kind != change.kind || opened.info.size != change.size_bytes {
            return Err(changed());
        }
        Ok(opened)
    }

    fn add(
        &mut self,
        index: usize,
        change: &ReviewedChange,
        missing_components: u64,
    ) -> Result<(), PromotionRefusal> {
        let name = &change.name;
        let ancestors = name.ancestors();
        let first_missing = ancestors.len().saturating_sub(
            usize::try_from(missing_components.saturating_sub(1)).unwrap_or(usize::MAX),
        );
        let appeared = || PromotionRefusal::TargetAppeared { name: name.clone() };
        for ancestor in ancestors.iter().skip(first_missing) {
            self.roots
                .destination
                .create_directory(ancestor)
                .map_err(|problem| {
                    step_refusal(problem, name, IoStep::CreateDirectory, appeared())
                })?;
            self.steps.push(Step::CreatedDirectory(ancestor.clone()));
            self.created.insert(ancestor.clone());
        }
        // Copied beside the name and renamed to it once the copy's content key is the
        // reviewed one: the folder never holds a partial or other copy under the name.
        let mut source = self.source(change)?;
        let staging = format!(".yougori-promote-{}-{index}.tmp", self.label);
        self.roots
            .destination
            .create_file_from(
                name,
                &mut source.file,
                change.size_bytes,
                change.kind == FileKind::Executable,
                &staging,
                Some(change.content),
            )
            .map_err(|problem| match problem {
                EntryProblem::Changed => PromotionRefusal::SourceChanged { name: name.clone() },
                problem => step_refusal(problem, name, IoStep::WriteFile, appeared()),
            })?;
        self.steps.push(Step::Added {
            name: name.clone(),
            content: change.content,
        });
        self.applied
            .push(AppliedChange::Added { name: name.clone() });
        Ok(())
    }

    fn ensure_backup_directory(&mut self, name: &GuestName) -> Result<(), PromotionRefusal> {
        if self.backup_directory {
            return Ok(());
        }
        self.roots
            .backup
            .create_top_directory(&self.label)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    PromotionRefusal::StagingConflict { name: name.clone() }
                }
                _ => PromotionRefusal::io(IoStep::WriteBackup, Some(name), &error),
            })?;
        self.backup_directory = true;
        Ok(())
    }

    fn replace(
        &mut self,
        index: usize,
        change: &ReviewedChange,
        original: ContentKey,
        original_kind: FileKind,
    ) -> Result<(), PromotionRefusal> {
        let name = &change.name;
        self.ensure_backup_directory(name)?;
        let backup = format!("{index}.original");
        let conflict = || PromotionRefusal::StagingConflict { name: name.clone() };
        let copied = self
            .roots
            .destination
            .copy_file_to(name, self.roots.backup, &self.label, &backup)
            .map_err(|problem| step_refusal(problem, name, IoStep::WriteBackup, conflict()))?;
        if backup_key(self.roots.backup, &self.label, &backup, copied) != Some(original) {
            return Err(PromotionRefusal::DestinationChanged { name: name.clone() });
        }
        let staging = format!(".yougori-promote-{}-{index}.tmp", self.label);
        let mut source = self.source(change)?;
        self.roots
            .destination
            .replace_file_from(
                name,
                &mut source.file,
                change.size_bytes,
                change.kind == FileKind::Executable,
                &staging,
                Some(change.content),
            )
            .map_err(|problem| match problem {
                EntryProblem::Changed => PromotionRefusal::SourceChanged { name: name.clone() },
                problem => step_refusal(problem, name, IoStep::Replace, conflict()),
            })?;
        self.steps.push(Step::Replaced {
            name: name.clone(),
            content: change.content,
            backup: backup.clone(),
            original,
            original_kind,
        });
        self.applied.push(AppliedChange::Modified {
            name: name.clone(),
            backup: self.roots.backup.origin().join(&self.label).join(backup),
        });
        Ok(())
    }

    /// Undoes every completed step in reverse. A file whose content is no longer what the
    /// promotion wrote is left alone.
    fn roll_back(&mut self, cause: PromotionRefusal) -> PromotionRefusal {
        if self.steps.is_empty() {
            return cause;
        }
        let destination = self.roots.destination;
        let mut restored = Vec::new();
        let mut unrestored = Vec::new();
        while let Some(step) = self.steps.pop() {
            match step {
                Step::CreatedDirectory(name) => {
                    let _ = destination.remove_directory(&name);
                }
                Step::Added { name, content } => {
                    if still_holds(destination, &name, content)
                        && destination.remove_file(&name).is_ok()
                    {
                        restored.push(name);
                    } else {
                        unrestored.push(name);
                    }
                }
                Step::Replaced {
                    name,
                    content,
                    backup,
                    original,
                    original_kind,
                } => {
                    if still_holds(destination, &name, content)
                        && self.put_back(&name, &backup, original, original_kind)
                    {
                        restored.push(name);
                    } else {
                        unrestored.push(name);
                    }
                }
            }
        }
        self.applied.clear();
        PromotionRefusal::RolledBack {
            cause: Box::new(cause),
            restored,
            unrestored,
        }
    }

    /// Restores the verified original from the backup root over `name` with an atomic
    /// rename.
    fn put_back(
        &self,
        name: &GuestName,
        backup: &str,
        original: ContentKey,
        original_kind: FileKind,
    ) -> bool {
        let Ok(mut opened) = self.roots.backup.open_top_file(&self.label, backup) else {
            return false;
        };
        let size_bytes = opened.info.size;
        let staging = format!(".yougori-restore-{}", name.file_name());
        // Copied from the backup and renamed over the name only when the copy is the
        // verified original.
        self.roots
            .destination
            .replace_file_from(
                name,
                &mut opened.file,
                size_bytes,
                original_kind == FileKind::Executable,
                &staging,
                Some(original),
            )
            .is_ok()
    }
}

/// The content key of the backup copy `directory/file` of `size_bytes`.
fn backup_key(
    backup: &GrantedRoot,
    directory: &str,
    file: &str,
    size_bytes: u64,
) -> Option<ContentKey> {
    let mut opened = backup.open_top_file(directory, file).ok()?;
    fsutil::hash_open(&mut opened.file, size_bytes)
        .ok()
        .flatten()
}

/// Whether `name` is still the regular single-name file holding `content`.
fn still_holds(root: &GrantedRoot, name: &GuestName, content: ContentKey) -> bool {
    let Ok(mut opened) = root.open_file(name) else {
        return false;
    };
    let size_bytes = opened.info.size;
    fsutil::hash_open(&mut opened.file, size_bytes)
        .ok()
        .flatten()
        == Some(content)
}
