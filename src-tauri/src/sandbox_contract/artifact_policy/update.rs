//! Runtime updates: an artifact admitted only as a target the update trust client
//! verified through its signed metadata (VM-W48, line 2671; VM-W45, line 2668: "trust
//! roots, key rotation, expiry/version checks ... emergency revocation"; §8.3, line 2453;
//! VM-D13, line 3207; the trust client in `sandbox::trust`).
//!
//! A runtime update carries no publisher signature of its own: the update metadata's
//! roles vouch for it, and the trust client's
//! [`VerifiedTarget`](crate::sandbox::trust::VerifiedTarget) is the only proof that they
//! did. It is an in-memory handle that no data can forge (it is never deserialized), so
//! no attestation bytes can carry it, and a plain signature never stands in for it. The
//! class therefore has its own verifier, [`RuntimeUpdateVerifier`], registered as
//! `OfferedClass::Local`, and the attestation is a ticket: [`UpdateAdmissions::import`]
//! takes an [`OpenedArtifact`] (the trust client's proof that these bytes are the
//! verified target's), verifies the target again with the client at the import's time,
//! records it at the shared [`UpdateAdmissions`] and asks the catalog to admit it with
//! the ticket. The verifier takes the ticket once and admits the object only if the
//! recorded target is of this class, verified through signed metadata (never a
//! developer's unsigned build), and has exactly the object's content key and length,
//! and the claimed publisher is the recorded one and may vouch for `runtime_update` in
//! the trust roots in force now. The ticket is withdrawn after the admission either way.
//!
//! **The ticket is never evidence.** An `AdmissionTicket` names one waiting target by a
//! number local to this process; it carries no signature and no statement. Its field is
//! private and only [`UpdateAdmissions`] builds one, while it records a target the trust
//! client verified; it is neither serialized nor read back as a ticket, and its wire form
//! is the catalog claim's attestation bytes only, which the catalog checks and never
//! records (it records the publisher alone). A CORE-08 `SignedComponent` cannot name it:
//! that is built only by checking a signature over a statement digest.
//!
//! **The publisher is the update root key, as an interim.** The catalog's publisher for
//! the claim is a root key of the client's root metadata in force that the class policy
//! trusts: the trust roots' `runtime_update` keys are the update roots
//! (`trust_adapter::UPDATE_ROOT_CLASS`), the client is started from a root their threshold
//! signed (`trust_adapter::PinnedRoots::bootstrap`), and that root delegates the roles
//! that signed the target. In TUF the targets role signs a target, not root: the root key
//! stands here for the whole verified metadata chain (root, timestamp, snapshot,
//! targets) the client checked. Naming the targets role keys as the publisher stays open
//! under M18. Revoking the root key in the trust roots withdraws the policy's trust in
//! it, so the catalog quarantines what it admitted when the policy is read again after
//! the reload (`CatalogService::apply_trust_roots`). A client whose root has rotated to
//! keys the trust roots do not list admits nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};

use super::publish::{publish, MemorySource, PublishFailure};
use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, Catalog, ContentDescriptor, ImportControl, ImportManifest,
    ImportRequest, ObjectBytes, ObjectId, ObjectMetadata, ObjectRole, PublisherId, Scope,
    SourceIdentity, TrustClaim, VerifierRejection,
};
use crate::foundation::ids::{ContentKey, ExecutionId, OperationId};
use crate::foundation::signing::{KeyRefusal, SharedTrustRoots, TrustCalendar};
use crate::sandbox::trust::{
    OpenedArtifact, PublicKey, ReleaseVersion, Role, TargetName, UnixSeconds, UpdateClient,
    UpdateRefusal, VerificationBasis, VerifiedTarget,
};

/// The artifact class of runtime updates.
pub const UPDATE_CLASS: ArtifactClass = ArtifactClass::RuntimeUpdate;

/// The format tag of an update admission ticket.
pub const UPDATE_TICKET_FORMAT: &str = "yougori.runtime-update.admission-ticket.v1";

/// Largest update ticket read.
pub const MAX_UPDATE_TICKET_BYTES: usize = 256;

/// Most targets waiting for their admission at once. Each import withdraws its own after
/// the catalog's admission, so more waiting means imports racing; the next is refused.
pub const MAX_PENDING_UPDATES: usize = 64;

/// Extent length of runtime update objects in the catalog.
pub const UPDATE_EXTENT_BYTES: NonZeroU64 = match NonZeroU64::new(4 << 20) {
    Some(bytes) => bytes,
    None => NonZeroU64::MIN,
};

/// The catalog source kind of a runtime update; the locator is the target's name and
/// release.
pub const UPDATE_SOURCE_KIND: &str = "runtime-update-target";

/// Private label naming the target.
pub const UPDATE_TARGET_LABEL: &str = "yougori.runtime-update.target";
/// Private label naming the target's release.
pub const UPDATE_RELEASE_LABEL: &str = "yougori.runtime-update.release";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTicket {
    format: String,
    ticket: u64,
}

/// One admission's ticket: the number of a verified target waiting at
/// [`UpdateAdmissions`]. Its field is private and only [`UpdateAdmissions::offer`] builds
/// one, so no code outside this module makes or alters a ticket; it is neither cloned
/// nor serialized, and it is never evidence of a signature (see the module documentation).
#[derive(Debug)]
pub(super) struct AdmissionTicket {
    number: u64,
}

impl AdmissionTicket {
    /// The ticket as the catalog claim's attestation: strict JSON with its format tag.
    pub(super) fn attestation(&self) -> Vec<u8> {
        let wire = WireTicket {
            format: UPDATE_TICKET_FORMAT.to_owned(),
            ticket: self.number,
        };
        // A string and a number: serialization cannot fail, and an empty claim is refused.
        serde_json::to_vec(&wire).unwrap_or_default()
    }
}

/// Why the runtime update verifier did not authenticate a claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum UpdateAttestationRefusal {
    /// The object is of another class; update tickets admit `runtime_update` only.
    WrongClass { class: ArtifactClass },
    /// The attestation is not an update ticket within the bound.
    Malformed { detail: String },
    /// No target waits under this ticket: never issued, already used or withdrawn.
    UnknownTicket,
    /// The claimed publisher is not the one the ticket was issued for.
    OtherPublisher,
    /// The recorded target is of another class, or was not verified through signed
    /// metadata.
    NotAnUpdateTarget,
    /// The object is not the recorded target's bytes.
    TargetDiffers {
        expected: ContentKey,
        expected_bytes: u64,
    },
    /// The publisher's key may not vouch for runtime updates now.
    Key { refusal: KeyRefusal },
}

impl fmt::Display for UpdateAttestationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongClass { class } => write!(f, "an update ticket cannot admit a {class}"),
            Self::Malformed { detail } => write!(f, "the update ticket is malformed: {detail}"),
            Self::UnknownTicket => f.write_str("no verified target waits under this ticket"),
            Self::OtherPublisher => f.write_str("the ticket was issued for another publisher"),
            Self::NotAnUpdateTarget => f.write_str(
                "the recorded target is not a runtime update verified through signed metadata",
            ),
            Self::TargetDiffers {
                expected,
                expected_bytes,
            } => write!(
                f,
                "the object is not the verified target ({expected_bytes} bytes, {expected})"
            ),
            Self::Key { refusal } => refusal.fmt(f),
        }
    }
}

impl std::error::Error for UpdateAttestationRefusal {}

/// One verified target waiting for its admission, and the publisher it is claimed as.
struct Pending {
    target: VerifiedTarget,
    publisher: PublisherId,
}

#[derive(Default)]
struct Desk {
    next: u64,
    pending: BTreeMap<u64, Pending>,
}

/// The targets waiting for their catalog admission, shared by the import path and the
/// class verifier. See the module documentation.
#[derive(Default)]
pub struct UpdateAdmissions {
    desk: Mutex<Desk>,
}

impl fmt::Debug for UpdateAdmissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateAdmissions")
            .field("pending", &self.pending())
            .finish()
    }
}

/// Why a runtime update was not imported. Nothing was published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateImportError {
    /// The opened artifact is a target of another class.
    WrongClass { class: ArtifactClass },
    /// The target was not verified through signed metadata: a developer's unsigned
    /// build is never a release artifact here.
    NotThroughMetadata { name: TargetName },
    /// The trust client no longer verifies the target now: expired metadata, a revoked
    /// release, key or class, an unknown name.
    Client { refusal: UpdateRefusal },
    /// The client's targets name other bytes for this name now.
    Superseded {
        name: TargetName,
        opened: ContentKey,
        current: ContentKey,
    },
    /// No root key of the client's root in force is trusted by the class policy.
    NoTrustedRootKey,
    /// Too many targets wait for their admission.
    TooManyPending,
    /// The catalog did not publish the artifact.
    Catalog { failure: PublishFailure },
}

impl fmt::Display for UpdateImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongClass { class } => {
                write!(f, "the target is a {class}, not a {UPDATE_CLASS}")
            }
            Self::NotThroughMetadata { name } => write!(
                f,
                "target {} was not verified through signed update metadata",
                name.as_str()
            ),
            Self::Client { refusal } => {
                write!(f, "the trust client refuses the target now: {refusal}")
            }
            Self::Superseded {
                name,
                opened,
                current,
            } => write!(
                f,
                "target {} is {current} now, not the opened {opened}",
                name.as_str()
            ),
            Self::NoTrustedRootKey => {
                f.write_str("no root key of the trust client's root is trusted for runtime updates")
            }
            Self::TooManyPending => f.write_str("too many runtime updates await admission"),
            Self::Catalog { failure } => failure.fmt(f),
        }
    }
}

impl std::error::Error for UpdateImportError {}

/// One update import as its caller declares it.
#[derive(Clone, Debug)]
pub struct UpdateImport<'a> {
    pub operation: OperationId,
    /// The importing execution; it binds the catalog's records of the import.
    pub execution: ExecutionId,
    /// The target's bytes as the trust client opened them.
    pub opened: &'a OpenedArtifact,
    /// The time the client verifies the target at.
    pub now: UnixSeconds,
}

/// An imported runtime update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedUpdate {
    pub object: ObjectId,
    /// The host scope held it already; the claim was checked again.
    pub cache_hit: bool,
    pub name: TargetName,
    pub release: ReleaseVersion,
    /// The root key the claim was made as.
    pub publisher: PublisherId,
}

/// The publishers of the root keys of `client`'s root metadata in force.
fn root_publishers(client: &UpdateClient) -> Vec<PublisherId> {
    let root = client.root();
    root.role_keys(Role::Root)
        .map(|keys| {
            keys.key_ids
                .iter()
                .filter_map(|key_id| root.keys.get(key_id))
                .map(PublicKey::publisher_id)
                .collect()
        })
        .unwrap_or_default()
}

impl UpdateAdmissions {
    /// No target waits.
    pub fn new() -> Self {
        Self::default()
    }

    /// The desk changes in complete steps, so a lock poisoned by a panicking holder still
    /// guards a consistent desk and is read through.
    fn desk(&self) -> MutexGuard<'_, Desk> {
        self.desk.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many targets wait for their admission.
    pub fn pending(&self) -> usize {
        self.desk().pending.len()
    }

    /// Records `target` for one admission claimed as `publisher`'s; returns its ticket,
    /// the only way one is made.
    pub(super) fn offer(
        &self,
        target: VerifiedTarget,
        publisher: PublisherId,
    ) -> Result<AdmissionTicket, UpdateImportError> {
        let mut desk = self.desk();
        if desk.pending.len() >= MAX_PENDING_UPDATES {
            return Err(UpdateImportError::TooManyPending);
        }
        desk.next = desk.next.wrapping_add(1);
        let number = desk.next;
        desk.pending.insert(number, Pending { target, publisher });
        Ok(AdmissionTicket { number })
    }

    fn withdraw(&self, ticket: AdmissionTicket) {
        self.desk().pending.remove(&ticket.number);
    }

    fn take(&self, ticket: u64) -> Option<Pending> {
        self.desk().pending.remove(&ticket)
    }

    /// Imports the runtime update `import.opened` into `catalog`'s host scope as a root
    /// key of `client`'s root. See the module documentation.
    pub fn import(
        &self,
        catalog: &mut Catalog,
        client: &UpdateClient,
        import: UpdateImport<'_>,
        control: &mut dyn ImportControl,
    ) -> Result<ImportedUpdate, UpdateImportError> {
        let opened = import.opened;
        let target = opened.target();
        if target.class() != UPDATE_CLASS {
            return Err(UpdateImportError::WrongClass {
                class: target.class(),
            });
        }
        if !matches!(target.basis(), VerificationBasis::Signed { .. }) {
            return Err(UpdateImportError::NotThroughMetadata {
                name: target.name().clone(),
            });
        }
        let current = client
            .verify_target(target.name(), UPDATE_CLASS, import.now)
            .map_err(|refusal| UpdateImportError::Client { refusal })?;
        if current.content_key() != opened.content_key()
            || current.length_bytes() != target.length_bytes()
        {
            return Err(UpdateImportError::Superseded {
                name: target.name().clone(),
                opened: opened.content_key(),
                current: current.content_key(),
            });
        }
        let publisher = catalog
            .config()
            .trust
            .get(&UPDATE_CLASS)
            .and_then(|policy| {
                root_publishers(client)
                    .into_iter()
                    .find(|publisher| policy.trusts(publisher))
            })
            .ok_or(UpdateImportError::NoTrustedRootKey)?;
        let name = current.name().clone();
        let release = current.release().clone();
        let ticket = self.offer(current, publisher)?;
        let request = ImportRequest {
            operation: import.operation.clone(),
            execution: import.execution.clone(),
            scope: Scope::Host,
            class: UPDATE_CLASS,
            role: ObjectRole::Original,
            manifest: ImportManifest::describe(opened.bytes(), UPDATE_EXTENT_BYTES),
            trust: TrustClaim::Publisher {
                publisher,
                attestation: ticket.attestation(),
            },
            depends_on: BTreeSet::new(),
            metadata: ObjectMetadata::new()
                .with_label(UPDATE_TARGET_LABEL, name.as_str())
                .with_label(UPDATE_RELEASE_LABEL, release.as_str()),
        };
        let mut source = MemorySource {
            identity: SourceIdentity::describe(
                UPDATE_SOURCE_KIND,
                &format!("{}@{}", name.as_str(), release.as_str()),
            ),
            bytes: opened.bytes(),
        };
        let published = publish(catalog, request, &mut source, control);
        self.withdraw(ticket);
        let published = published.map_err(|failure| UpdateImportError::Catalog { failure })?;
        Ok(ImportedUpdate {
            object: published.object,
            cache_hit: published.cache_hit,
            name,
            release,
            publisher,
        })
    }
}

/// The catalog verifier of [`ArtifactClass::RuntimeUpdate`]: one waiting verified target
/// per admission. See the module documentation.
#[derive(Clone)]
pub struct RuntimeUpdateVerifier {
    admissions: Arc<UpdateAdmissions>,
    roots: SharedTrustRoots,
    calendar: Arc<dyn TrustCalendar>,
}

impl fmt::Debug for RuntimeUpdateVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeUpdateVerifier")
            .field("admissions", &self.admissions)
            .finish_non_exhaustive()
    }
}

impl RuntimeUpdateVerifier {
    /// A verifier admitting the targets waiting at `admissions`, with publisher keys
    /// judged under the roots in force in `roots` at `calendar`'s time.
    pub fn new(
        admissions: Arc<UpdateAdmissions>,
        roots: SharedTrustRoots,
        calendar: Arc<dyn TrustCalendar>,
    ) -> Self {
        Self {
            admissions,
            roots,
            calendar,
        }
    }

    /// The typed reason behind [`ArtifactVerifier::authenticate`]: takes the ticket
    /// `attestation` names and checks the target waiting under it against `content` and
    /// `publisher`. The ticket is used up either way.
    pub fn check(
        &self,
        content: &ContentDescriptor,
        publisher: &PublisherId,
        attestation: &[u8],
    ) -> Result<(), UpdateAttestationRefusal> {
        if content.class != UPDATE_CLASS {
            return Err(UpdateAttestationRefusal::WrongClass {
                class: content.class,
            });
        }
        if attestation.len() > MAX_UPDATE_TICKET_BYTES {
            return Err(UpdateAttestationRefusal::Malformed {
                detail: format!("{} bytes", attestation.len()),
            });
        }
        let wire: WireTicket = serde_json::from_slice(attestation).map_err(|error| {
            UpdateAttestationRefusal::Malformed {
                detail: error.to_string(),
            }
        })?;
        if wire.format != UPDATE_TICKET_FORMAT {
            return Err(UpdateAttestationRefusal::Malformed {
                detail: "another ticket format".to_owned(),
            });
        }
        let pending = self
            .admissions
            .take(wire.ticket)
            .ok_or(UpdateAttestationRefusal::UnknownTicket)?;
        if pending.publisher != *publisher {
            return Err(UpdateAttestationRefusal::OtherPublisher);
        }
        let target = &pending.target;
        if target.class() != UPDATE_CLASS
            || !matches!(target.basis(), VerificationBasis::Signed { .. })
        {
            return Err(UpdateAttestationRefusal::NotAnUpdateTarget);
        }
        if target.content_key() != content.content_key
            || target.length_bytes() != content.length_bytes
        {
            return Err(UpdateAttestationRefusal::TargetDiffers {
                expected: target.content_key(),
                expected_bytes: target.length_bytes(),
            });
        }
        self.roots
            .current()
            .check_key(publisher, UPDATE_CLASS, self.calendar.now())
            .map(drop)
            .map_err(|refusal| UpdateAttestationRefusal::Key { refusal })
    }
}

impl ArtifactVerifier for RuntimeUpdateVerifier {
    fn class(&self) -> ArtifactClass {
        UPDATE_CLASS
    }

    fn authenticate(
        &self,
        content: &ContentDescriptor,
        publisher: &PublisherId,
        attestation: &[u8],
    ) -> Result<(), VerifierRejection> {
        self.check(content, publisher, attestation)
            .map_err(|_| VerifierRejection::AttestationInvalid)
    }

    /// No structure check of update binaries exists; the object must be of this class
    /// and as long as declared, and the catalog checks its bytes against the content key.
    fn validate(
        &self,
        content: &ContentDescriptor,
        bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        if content.class != UPDATE_CLASS {
            return Err(VerifierRejection::WrongFormat {
                detail: format!("a {} is not a runtime update", content.class),
            });
        }
        if bytes.length_bytes() != content.length_bytes {
            return Err(VerifierRejection::CorruptStructure {
                detail: format!(
                    "{} bytes stored; {} declared",
                    bytes.length_bytes(),
                    content.length_bytes
                ),
            });
        }
        Ok(())
    }
}
