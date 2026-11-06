//! The engine's trust-root service (S08 in docs/combined-plan-leftover-tasks.md:
//! "configure trust roots and real signature verification"; S2 CORE-08, line 217:
//! "Artifact classes retain distinct publisher/trust policies ... An unauthenticated
//! checksum is not a release trust root"; VM-W45, line 2668: "trust roots, key rotation
//! ... emergency revocation"; GPU-W11, line 1321).
//!
//! [`TrustRootService`] owns the owner's trust-root file for the engine. Pure and path
//! based: the caller names the location ([`TrustRootLocation::from_setting`]) and the
//! calendar; this module reads only that one file and no environment.
//!
//! - **No default.** With no location configured the service reports
//!   [`RootsState::NotConfigured`] with a remedy. No key is built in and nothing passes
//!   silently: every class then refuses with [`ClassRefusal::NoTrustRoots`], and every
//!   identification is [`ComponentVerification::NoTrustRoots`].
//! - **One file in force.** A file is checked by [`TrustRoots::load`] and put in force in
//!   one [`SharedTrustRoots`], so every verifier, policy and identification reads the same
//!   roots. A reload swaps the complete roots at once; a refused file, unreadable or
//!   invalid, keeps the roots in force and is reported ([`ReloadOutcome::Refused`],
//!   [`TrustRootStatus::last_refusal`]).
//! - **Revocations are never withdrawn by a reload or a restart.** Once a file with a
//!   revoked key is in force, a later file that lists the same key material unrevoked is
//!   refused ([`LoadRefusal::RevocationWithdrawn`]), under any id and from any location.
//!   A file that drops the key altogether trusts it no longer either way. Opened with a
//!   [`RevocationFloor`] ([`TrustRootService::open_with_floor`], as the engine does), the
//!   service reads the revocations of earlier runs from it at open and writes every new
//!   revocation to it before the file that carries it is put in force; a failed write
//!   refuses the file ([`LoadRefusal::Floor`]) and keeps the roots in force. A floor that
//!   cannot be used, torn, edited or unreadable, fails closed: nothing is trusted, and the
//!   status names the file and the remedy ([`TrustRootStatus::floor`]); a missing floor is
//!   a first run. Lifting a revocation is the owner's deliberate act: removing the floor
//!   file while the engine is stopped (revocation_floor.rs). [`TrustRootService::open`]
//!   keeps no floor, for callers and tests that pass none: its revocations hold for the
//!   service's life only, as before.
//! - **Per class.** A class has keys when the roots in force list a key that may sign it.
//!   For such a class the service gives one [`SignedArtifactVerifier`] and the class's
//!   [`TrustPolicy`] ([`TrustRoots::policy_for`]); a class without keys refuses with
//!   [`ClassRefusal::NoKeys`]. [`TrustRootService::register`] registers them through the
//!   catalog's own registration (`VerifierRegistry::register` and
//!   `CatalogConfig::with_trust`), and [`TrustRootService::apply_policies`] sets the
//!   policies from the roots in force after a reload (`Catalog::set_trust_policy`), so a
//!   revoked key's objects are quarantined. The catalog fixes its verifiers when it opens:
//!   a class that gains its first key in a reload is listed as needing the catalog
//!   reopened ([`ReloadOutcome::Applied`]).
//! - **Status.** [`TrustRootService::status`] lists every class with its keys, their
//!   validity windows and states (valid, not yet valid, expired, revoked with its reason)
//!   and rotations, at the calendar's time, and the revocation floor: its location, how
//!   many revocations it holds and its state.
//!
//! Each verification can be recorded as a CORE-08 [`SignedComponent`]
//! ([`TrustRootService::identify`]).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};

use super::identity::{ComponentVerification, SignedComponent};
use super::revocation_floor::{
    FloorError, FloorRevocation, FloorState, FloorStatus, RevocationFloor,
};
use super::roots::{
    KeyAlgorithm, KeyRefusal, RootKeyId, SharedTrustRoots, TrustRootError, TrustRoots,
    TRUST_ROOTS_FORMAT,
};
use super::verifier::{
    SignedArtifactVerifier, StatementBinding, StructureValidator, TrustCalendar,
};
use crate::foundation::catalog::{
    ArtifactClass, Catalog, CatalogConfig, ContentDescriptor, ObjectId, PublisherId, TrustPolicy,
    VerifierRegistry,
};
use crate::foundation::ids::Digest;
use crate::foundation::report::Label;

/// Why a configured location cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum LocationError {
    /// The path is relative, so it would depend on the engine's working directory.
    NotAbsolute,
}

impl fmt::Display for LocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute => f.write_str("the trust-root location is not an absolute path"),
        }
    }
}

/// Where the owner's trust-root file is, as configured under the setting `setting`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustRootLocation {
    /// Nothing is configured: no key is trusted for any class.
    NotConfigured { setting: &'static str },
    /// The configured value cannot be used.
    Invalid {
        setting: &'static str,
        problem: LocationError,
    },
    /// The owner's trust-root file.
    File {
        setting: &'static str,
        path: PathBuf,
    },
}

impl TrustRootLocation {
    /// The location configured as `value` under `setting` (an environment variable or a
    /// settings key the engine chooses). Absent or empty is not configured; a relative
    /// path is invalid. Nothing is read here.
    pub fn from_setting(setting: &'static str, value: Option<&OsStr>) -> Self {
        match value.filter(|value| !value.is_empty()) {
            None => Self::NotConfigured { setting },
            Some(value) => {
                let path = PathBuf::from(value);
                if path.is_absolute() {
                    Self::File { setting, path }
                } else {
                    Self::Invalid {
                        setting,
                        problem: LocationError::NotAbsolute,
                    }
                }
            }
        }
    }
}

/// Why a trust-root file was not put in force. The roots in force, if any, stay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadRefusal {
    /// The file was unreadable or is not a valid trust-root file.
    File { error: TrustRootError },
    /// The file lists, unrevoked, key material that a file in force during this
    /// service's life revoked, or that the revocation floor holds from an earlier run.
    RevocationWithdrawn {
        key: RootKeyId,
        publisher: PublisherId,
        revoked_as: RootKeyId,
    },
    /// The revocation floor cannot be used, so nothing is put in force, or the new
    /// revocations the file carries could not be written to it, so the file is not.
    Floor { error: FloorError },
}

impl LoadRefusal {
    /// The stable tag of the refusal.
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
            Self::RevocationWithdrawn { .. } => "revocation_withdrawn",
            Self::Floor { .. } => "revocation_floor",
        }
    }
}

impl fmt::Display for LoadRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File { error } => write!(f, "{error}"),
            Self::RevocationWithdrawn {
                key,
                publisher,
                revoked_as,
            } => write!(
                f,
                "trust-root key {key} (publisher {publisher}) was revoked as {revoked_as}; \
                 neither a reload nor a restart withdraws a revocation. Lifting a mistaken \
                 one is the owner's deliberate act: remove the revocation floor file named in \
                 the trust-root status while the engine is stopped"
            ),
            Self::Floor { error } => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for LoadRefusal {}

impl Serialize for LoadRefusal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct View<'a> {
            refusal: &'static str,
            detail: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            key: Option<&'a RootKeyId>,
        }
        let key = match self {
            Self::File { .. } | Self::Floor { .. } => None,
            Self::RevocationWithdrawn { key, .. } => Some(key),
        };
        View {
            refusal: self.tag(),
            detail: self.to_string(),
            key,
        }
        .serialize(serializer)
    }
}

/// Why the service gives no verifier or policy for a class.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ClassRefusal {
    /// No trust-root file is in force: not configured, misconfigured, or never accepted.
    NoTrustRoots { class: ArtifactClass },
    /// The roots in force list no key that may sign this class.
    NoKeys { class: ArtifactClass },
    /// The catalog already has a responsible verifier for this class.
    AlreadyRegistered { class: ArtifactClass },
}

impl fmt::Display for ClassRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTrustRoots { class } => write!(
                f,
                "no trust-root file is in force, so nothing of class {class} is trusted"
            ),
            Self::NoKeys { class } => write!(
                f,
                "the trust roots in force list no key for {class}, so nothing of it is trusted"
            ),
            Self::AlreadyRegistered { class } => {
                write!(f, "the catalog already has a verifier for {class}")
            }
        }
    }
}

impl std::error::Error for ClassRefusal {}

/// The state of the trust roots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RootsState {
    /// No location is configured; nothing is trusted.
    NotConfigured {
        setting: &'static str,
        remedy: String,
    },
    /// The configured location cannot be used; nothing is trusted.
    InvalidLocation {
        setting: &'static str,
        problem: LocationError,
        remedy: String,
    },
    /// A location is configured, but no file from it was accepted; nothing is trusted.
    NotLoaded { location: String, remedy: String },
    /// The file accepted as `generation` (from 1) is in force.
    Loaded {
        location: String,
        generation: u64,
        keys: usize,
    },
}

/// The state of one key at the status's time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum KeyState {
    Valid,
    NotYetValid,
    Expired,
    /// Revoked: it vouches for nothing at any time.
    Revoked {
        reason: Label,
    },
}

/// One key of a class.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KeyStatus {
    pub id: RootKeyId,
    pub publisher: PublisherId,
    pub algorithm: KeyAlgorithm,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    /// The key this one rotates from.
    pub replaces: Option<RootKeyId>,
    /// The key that rotates from this one.
    pub replaced_by: Option<RootKeyId>,
    #[serde(flatten)]
    pub state: KeyState,
}

/// What the roots in force say about one class.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "trust", rename_all = "snake_case")]
pub enum ClassTrust {
    /// No trust-root file is in force.
    NoTrustRoots,
    /// The roots in force list no key for this class.
    NoKeys,
    /// The keys that may sign this class, in id order, and how many vouch now.
    Keys {
        usable_now: usize,
        verifier_registered: bool,
        keys: Vec<KeyStatus>,
    },
}

/// One class of the status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ClassStatus {
    pub class: ArtifactClass,
    pub trust: ClassTrust,
}

/// The service's status at `checked_at`, every class listed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TrustRootStatus {
    pub roots: RootsState,
    /// Why the latest load or reload was refused; cleared once a file is accepted.
    pub last_refusal: Option<LoadRefusal>,
    /// The revocation floor: its location, how many revocations it holds and its state,
    /// with the remedy when it cannot be used. Without a floor
    /// ([`TrustRootService::open`]) it counts the revocations held in memory.
    pub floor: FloorStatus,
    pub checked_at: DateTime<Utc>,
    pub classes: Vec<ClassStatus>,
}

/// What a reload did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reload", rename_all = "snake_case")]
pub enum ReloadOutcome {
    /// No location is configured; nothing was read and nothing is trusted.
    NotConfigured {
        setting: &'static str,
        remedy: String,
    },
    /// The configured location cannot be used; nothing was read.
    InvalidLocation {
        setting: &'static str,
        problem: LocationError,
        remedy: String,
    },
    /// The file is in force as `generation`. `changed` lists the classes whose policy
    /// changed, for [`TrustRootService::apply_policies`]; `needs_reopen` the classes
    /// [`TrustRootService::register`] refused for want of keys that have keys now: the
    /// catalog fixes its verifiers when it opens, so they get one when it is reopened.
    Applied {
        generation: u64,
        changed: Vec<ArtifactClass>,
        needs_reopen: Vec<ArtifactClass>,
    },
    /// The file was refused; the roots in force (`kept`, their generation) stay.
    Refused {
        refusal: LoadRefusal,
        kept: Option<u64>,
    },
}

/// What the engine offers to verify for one class: the statement its publishers sign
/// and the structure check its specialized importer supplies.
pub struct ClassVerification {
    pub class: ArtifactClass,
    pub binding: StatementBinding,
    pub structure: Box<dyn StructureValidator>,
}

impl fmt::Debug for ClassVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClassVerification")
            .field("class", &self.class)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

/// What [`TrustRootService::register`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Registration {
    pub registered: Vec<ArtifactClass>,
    pub refused: Vec<ClassRefusal>,
}

/// What setting one class's policy did in the catalog.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PolicyApplied {
    pub class: ArtifactClass,
    /// Objects the new policy no longer trusts: quarantined, never deleted.
    pub quarantined: Vec<ObjectId>,
    /// Objects quarantined only for withdrawn trust that the new policy trusts again.
    pub restored: Vec<ObjectId>,
}

/// The roots in force and the generation they were accepted as.
struct InForce {
    roots: SharedTrustRoots,
    generation: u64,
}

/// The engine's trust roots: the owner's file in force, its verifiers and policies per
/// artifact class, reloads and status. See the module documentation.
pub struct TrustRootService {
    location: TrustRootLocation,
    calendar: Arc<dyn TrustCalendar>,
    in_force: Option<InForce>,
    last_refusal: Option<LoadRefusal>,
    /// Every revoked key material of every file accepted, and every one the floor held at
    /// open, with the id it was revoked as.
    revoked: BTreeMap<PublisherId, RootKeyId>,
    /// The durable revocation floor, when the service keeps one.
    floor: Option<RevocationFloor>,
    /// Classes offered to [`Self::register`] and refused for want of keys.
    awaiting_keys: BTreeSet<ArtifactClass>,
    /// Classes [`Self::register`] gave a verifier.
    registered: BTreeSet<ArtifactClass>,
}

impl fmt::Debug for TrustRootService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustRootService")
            .field("location", &self.location)
            .field("generation", &self.generation())
            .field("last_refusal", &self.last_refusal)
            .field("registered", &self.registered)
            .finish_non_exhaustive()
    }
}

impl TrustRootService {
    /// The service for `location`, judging key windows by `calendar`, with no revocation
    /// floor: its revocations hold for its own life only, as before the floor existed,
    /// for callers and tests that pass none. A configured file is read now; a refusal is
    /// kept for [`Self::status`].
    pub fn open(location: TrustRootLocation, calendar: Arc<dyn TrustCalendar>) -> Self {
        Self::start(location, calendar, None)
    }

    /// The service for `location`, judging key windows by `calendar`, with the revocation
    /// floor `floor` ([`RevocationFloor::open`]): every key material the floor holds stays
    /// revoked across restarts, and every new revocation is written to it before the file
    /// that carries it is put in force. A floor that cannot be used trusts nothing. A
    /// configured file is read now; a refusal is kept for [`Self::status`].
    pub fn open_with_floor(
        location: TrustRootLocation,
        calendar: Arc<dyn TrustCalendar>,
        floor: RevocationFloor,
    ) -> Self {
        Self::start(location, calendar, Some(floor))
    }

    fn start(
        location: TrustRootLocation,
        calendar: Arc<dyn TrustCalendar>,
        floor: Option<RevocationFloor>,
    ) -> Self {
        let revoked = floor
            .iter()
            .flat_map(RevocationFloor::revocations)
            .map(|revocation| (revocation.publisher, revocation.revoked_as.clone()))
            .collect();
        let mut service = Self {
            location,
            calendar,
            in_force: None,
            last_refusal: None,
            revoked,
            floor,
            awaiting_keys: BTreeSet::new(),
            registered: BTreeSet::new(),
        };
        // The outcome is kept in the service's state and shown by its status.
        let _ = service.reload();
        service
    }

    /// The location the service reads.
    pub fn location(&self) -> &TrustRootLocation {
        &self.location
    }

    /// The revocation floor, when the service keeps one.
    pub fn floor(&self) -> Option<&RevocationFloor> {
        self.floor.as_ref()
    }

    /// The generation of the roots in force (from 1), if any.
    pub fn generation(&self) -> Option<u64> {
        self.in_force.as_ref().map(|held| held.generation)
    }

    /// The roots in force, shared with every verifier the service gave out, for consumers
    /// that read the trust roots themselves (the sandbox update roots, helper admission).
    pub fn shared(&self) -> Option<SharedTrustRoots> {
        self.in_force.as_ref().map(|held| held.roots.clone())
    }

    /// Reads the configured file again and puts it in force, or keeps the roots in force
    /// and reports why it was refused. With a floor, the file's new revocations are
    /// written to it first; a floor that cannot be used refuses every file.
    pub fn reload(&mut self) -> ReloadOutcome {
        let path = match &self.location {
            TrustRootLocation::NotConfigured { setting } => {
                return ReloadOutcome::NotConfigured {
                    setting,
                    remedy: not_configured_remedy(setting),
                }
            }
            TrustRootLocation::Invalid { setting, problem } => {
                return ReloadOutcome::InvalidLocation {
                    setting,
                    problem: *problem,
                    remedy: invalid_location_remedy(setting),
                }
            }
            TrustRootLocation::File { path, .. } => path.clone(),
        };
        let unusable = self
            .floor
            .as_ref()
            .and_then(RevocationFloor::problem)
            .cloned();
        let accepted = match unusable {
            Some(error) => Err(LoadRefusal::Floor { error }),
            None => TrustRoots::load(&path).map_err(|error| LoadRefusal::File { error }),
        };
        match accepted
            .and_then(|roots| self.check_revocations(&roots).map(|()| roots))
            .and_then(|roots| self.persist_revocations(&roots).map(|()| roots))
        {
            Ok(roots) => self.put_in_force(roots),
            Err(refusal) => {
                self.last_refusal = Some(refusal.clone());
                ReloadOutcome::Refused {
                    refusal,
                    kept: self.generation(),
                }
            }
        }
    }

    /// Refuses `roots` if they list unrevoked key material a file in force revoked.
    fn check_revocations(&self, roots: &TrustRoots) -> Result<(), LoadRefusal> {
        for key in roots.keys().filter(|key| !key.is_revoked()) {
            let publisher = key.publisher_id();
            if let Some(revoked_as) = self.revoked.get(&publisher) {
                return Err(LoadRefusal::RevocationWithdrawn {
                    key: key.id().clone(),
                    publisher,
                    revoked_as: revoked_as.clone(),
                });
            }
        }
        Ok(())
    }

    /// Writes to the floor, if the service keeps one, every revocation of `roots` whose
    /// key material is not revoked yet, before `roots` are put in force.
    fn persist_revocations(&mut self, roots: &TrustRoots) -> Result<(), LoadRefusal> {
        let Some(floor) = &mut self.floor else {
            return Ok(());
        };
        let first_seen = self.calendar.now();
        let found = roots
            .keys()
            .filter(|key| !self.revoked.contains_key(&key.publisher_id()))
            .filter_map(|key| {
                key.revocation().map(|revocation| FloorRevocation {
                    publisher: key.publisher_id(),
                    revoked_as: key.id().clone(),
                    reason: revocation.reason.clone(),
                    first_seen,
                })
            })
            .collect();
        floor
            .record(found)
            .map(|_| ())
            .map_err(|error| LoadRefusal::Floor { error })
    }

    fn put_in_force(&mut self, roots: TrustRoots) -> ReloadOutcome {
        let changed: Vec<ArtifactClass> = ArtifactClass::ALL
            .into_iter()
            .filter(|class| match &self.in_force {
                Some(held) => held.roots.current().policy_for(*class) != roots.policy_for(*class),
                None => has_keys(&roots, *class),
            })
            .collect();
        let needs_reopen = self
            .awaiting_keys
            .iter()
            .copied()
            .filter(|class| has_keys(&roots, *class))
            .collect();
        for key in roots.keys().filter(|key| key.is_revoked()) {
            self.revoked
                .entry(key.publisher_id())
                .or_insert_with(|| key.id().clone());
        }
        let generation = match &mut self.in_force {
            Some(held) => {
                held.roots.replace(roots);
                held.generation = held.generation.saturating_add(1);
                held.generation
            }
            None => {
                self.in_force = Some(InForce {
                    roots: SharedTrustRoots::new(roots),
                    generation: 1,
                });
                1
            }
        };
        self.last_refusal = None;
        ReloadOutcome::Applied {
            generation,
            changed,
            needs_reopen,
        }
    }

    /// The roots in force if `class` has keys there, or why not.
    fn roots_for(
        &self,
        class: ArtifactClass,
    ) -> Result<(SharedTrustRoots, Arc<TrustRoots>), ClassRefusal> {
        let held = self
            .in_force
            .as_ref()
            .ok_or(ClassRefusal::NoTrustRoots { class })?;
        let roots = held.roots.current();
        if has_keys(&roots, class) {
            Ok((held.roots.clone(), roots))
        } else {
            Err(ClassRefusal::NoKeys { class })
        }
    }

    /// The catalog trust policy of `class` from the roots in force: its non-revoked
    /// keys' publishers.
    pub fn policy(&self, class: ArtifactClass) -> Result<TrustPolicy, ClassRefusal> {
        self.roots_for(class)
            .map(|(_, roots)| roots.policy_for(class))
    }

    /// The responsible catalog verifier of `class`, over the roots in force (it follows
    /// every later reload) and the service's calendar.
    pub fn verifier(
        &self,
        class: ArtifactClass,
        binding: StatementBinding,
        structure: Box<dyn StructureValidator>,
    ) -> Result<SignedArtifactVerifier, ClassRefusal> {
        let (shared, _) = self.roots_for(class)?;
        Ok(SignedArtifactVerifier::new(
            class,
            binding,
            shared,
            Arc::clone(&self.calendar),
            structure,
        ))
    }

    /// Registers, for every offered class that has keys, its verifier in `registry` and
    /// its policy in `config`, through the catalog's own registration; a class without
    /// keys, or with a verifier already, is refused and gets neither, so the catalog
    /// refuses its imports. Call before `Catalog::open`.
    pub fn register(
        &mut self,
        offered: Vec<ClassVerification>,
        registry: &mut VerifierRegistry,
        mut config: CatalogConfig,
    ) -> (CatalogConfig, Registration) {
        let mut registration = Registration::default();
        for ClassVerification {
            class,
            binding,
            structure,
        } in offered
        {
            let built = self
                .verifier(class, binding, structure)
                .and_then(|verifier| {
                    let policy = self.policy(class)?;
                    registry.register(Box::new(verifier)).map_err(|duplicate| {
                        ClassRefusal::AlreadyRegistered {
                            class: duplicate.class,
                        }
                    })?;
                    Ok(policy)
                });
            match built {
                Ok(policy) => {
                    config = config.with_trust(class, policy);
                    self.awaiting_keys.remove(&class);
                    self.registered.insert(class);
                    registration.registered.push(class);
                }
                Err(refusal) => {
                    if !matches!(refusal, ClassRefusal::AlreadyRegistered { .. }) {
                        self.awaiting_keys.insert(class);
                    }
                    registration.refused.push(refusal);
                }
            }
        }
        (config, registration)
    }

    /// Sets the policy of every class this service registered in `catalog` from the
    /// roots in force, as after a reload. The catalog re-checks every object of each
    /// class: one a revoked or removed key admitted is quarantined, never deleted.
    pub fn apply_policies(&self, catalog: &mut Catalog) -> Vec<PolicyApplied> {
        let Some(held) = &self.in_force else {
            return Vec::new();
        };
        let roots = held.roots.current();
        self.registered
            .iter()
            .map(|class| {
                let revision = catalog.set_trust_policy(*class, roots.policy_for(*class));
                PolicyApplied {
                    class: *class,
                    quarantined: revision.quarantined,
                    restored: revision.restored,
                }
            })
            .collect()
    }

    /// Verifies `signature` as `publisher`'s over `statement` about an artifact of
    /// `class`, under the roots in force at the calendar's time, and records the outcome
    /// as a CORE-08 signed component, a refusal included.
    pub fn identify(
        &self,
        class: ArtifactClass,
        publisher: &PublisherId,
        statement: Digest,
        signature: &[u8],
    ) -> SignedComponent {
        let at = self.calendar.now();
        match &self.in_force {
            Some(held) => SignedComponent::check(
                &held.roots.current(),
                class,
                publisher,
                statement,
                signature,
                at,
            ),
            None => SignedComponent::unchecked(
                class,
                *publisher,
                statement,
                at,
                ComponentVerification::NoTrustRoots {},
            ),
        }
    }

    /// [`Self::identify`] for catalog content: the statement is the one `binding` names
    /// for `content` as `publisher`'s artifact of its class.
    pub fn identify_content(
        &self,
        binding: StatementBinding,
        content: &ContentDescriptor,
        publisher: &PublisherId,
        attestation: &[u8],
    ) -> SignedComponent {
        let statement = binding.statement(publisher, content.class, content);
        self.identify(content.class, publisher, statement, attestation)
    }

    /// The status at the calendar's time: the roots' state, the latest refusal, and
    /// every class with its keys.
    pub fn status(&self) -> TrustRootStatus {
        let checked_at = self.calendar.now();
        let roots = match (&self.location, &self.in_force) {
            (TrustRootLocation::NotConfigured { setting }, _) => RootsState::NotConfigured {
                setting,
                remedy: not_configured_remedy(setting),
            },
            (TrustRootLocation::Invalid { setting, problem }, _) => RootsState::InvalidLocation {
                setting,
                problem: *problem,
                remedy: invalid_location_remedy(setting),
            },
            (TrustRootLocation::File { path, .. }, None) => RootsState::NotLoaded {
                location: path.display().to_string(),
                remedy: match self
                    .floor
                    .as_ref()
                    .filter(|floor| floor.problem().is_some())
                {
                    Some(floor) => floor.remedy(),
                    None => format!(
                        "No trust-root file from this location was accepted, so nothing is \
                         trusted; see last_refusal. Place a valid trust-root file (format \
                         {TRUST_ROOTS_FORMAT}) there and reload."
                    ),
                },
            },
            (TrustRootLocation::File { path, .. }, Some(held)) => RootsState::Loaded {
                location: path.display().to_string(),
                generation: held.generation,
                keys: held.roots.current().keys().count(),
            },
        };
        let current = self.in_force.as_ref().map(|held| held.roots.current());
        let classes = ArtifactClass::ALL
            .into_iter()
            .map(|class| ClassStatus {
                class,
                trust: match &current {
                    None => ClassTrust::NoTrustRoots,
                    Some(roots) => self.class_trust(roots, class, checked_at),
                },
            })
            .collect();
        let floor = match &self.floor {
            Some(floor) => floor.status(),
            None => FloorStatus {
                location: None,
                revocations: self.revoked.len(),
                state: FloorState::NotKept,
            },
        };
        TrustRootStatus {
            roots,
            last_refusal: self.last_refusal.clone(),
            floor,
            checked_at,
            classes,
        }
    }

    fn class_trust(
        &self,
        roots: &TrustRoots,
        class: ArtifactClass,
        at: DateTime<Utc>,
    ) -> ClassTrust {
        let successors: BTreeMap<&RootKeyId, &RootKeyId> = roots
            .keys()
            .filter_map(|key| key.replaces().map(|replaced| (replaced, key.id())))
            .collect();
        let keys: Vec<KeyStatus> = roots
            .keys()
            .filter(|key| key.classes().contains(&class))
            .map(|key| KeyStatus {
                id: key.id().clone(),
                publisher: key.publisher_id(),
                algorithm: key.algorithm(),
                valid_from: key.valid_from(),
                valid_until: key.valid_until(),
                replaces: key.replaces().cloned(),
                replaced_by: successors.get(key.id()).map(|id| (*id).clone()),
                state: match key.check(class, at) {
                    Ok(()) => KeyState::Valid,
                    Err(KeyRefusal::Revoked { reason, .. }) => KeyState::Revoked { reason },
                    Err(KeyRefusal::NotYetValid { .. }) => KeyState::NotYetValid,
                    Err(_) => KeyState::Expired,
                },
            })
            .collect();
        if keys.is_empty() {
            return ClassTrust::NoKeys;
        }
        ClassTrust::Keys {
            usable_now: keys
                .iter()
                .filter(|key| key.state == KeyState::Valid)
                .count(),
            verifier_registered: self.registered.contains(&class),
            keys,
        }
    }
}

/// Whether the roots list a key that may sign `class`, revoked or not.
pub(super) fn has_keys(roots: &TrustRoots, class: ArtifactClass) -> bool {
    roots.keys().any(|key| key.classes().contains(&class))
}

fn not_configured_remedy(setting: &str) -> String {
    format!(
        "No trust-root file is configured and no key is built in, so no signed artifact of \
         any class is trusted. Set {setting} to the absolute path of the owner's trust-root \
         file (format {TRUST_ROOTS_FORMAT}), then reload."
    )
}

fn invalid_location_remedy(setting: &str) -> String {
    format!(
        "{setting} must be the absolute path of the owner's trust-root file (format \
         {TRUST_ROOTS_FORMAT}); nothing is trusted until it is, then reload."
    )
}
