//! The catalog service: open with recovery, per-class trust registration, garbage
//! collection, trust application after a reload, and status (S02; S2 CORE-02; GPU-W03).
//! See the module documentation of `catalog_service`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, Catalog, CatalogConfig, CatalogLimits, CatalogSummary,
    ContentDescriptor, FormatRefusal, GcRefusal, GcReport, IntegrityFailure, ObjectBytes, ObjectId,
    OpenFailure, OpenReport, PublisherId, Scope, StorageFailure, TrustPolicy, VerifierRegistry,
    VerifierRejection, LOCK_FILE,
};
use crate::foundation::ids::Clock;
use crate::foundation::signing::{
    ClassRefusal, ClassVerification, PolicyApplied, StructureValidator, TrustCalendar,
    TrustRootService,
};

/// Holds the opened catalog and locks it for each use. The service reaches the catalog
/// only through its holder, so a specialized importer that must own the catalog, as the
/// model sidecar adapter does, can hold it and share it with the service.
pub trait CatalogHolder: Send + Sync {
    /// The catalog, locked until the guard drops.
    fn catalog(&self) -> MutexGuard<'_, Catalog>;
}

impl CatalogHolder for Mutex<Catalog> {
    /// The catalog changes its state only in complete steps, so a lock poisoned by a
    /// panicking holder still guards a consistent catalog and is read through.
    fn catalog(&self) -> MutexGuard<'_, Catalog> {
        self.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What the engine configures for its catalog. Nothing is admitted that is not
/// configured: a scope without a quota stores nothing, and a class is trusted only through
/// the trust roots or, if listed in `user_selected`, for the tenants' own originals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogServiceConfig {
    pub limits: CatalogLimits,
    /// How long garbage stays after it becomes unreachable and unleased (CORE-02).
    pub gc_grace: Duration,
    /// Each scope's explicit space budget.
    pub quotas: BTreeMap<Scope, u64>,
    /// Classes whose policy accepts originals a tenant selects for its own scope
    /// (`TrustClaim::UserSelected`), such as the files of a model folder the owner chose.
    pub user_selected: BTreeSet<ArtifactClass>,
}

impl CatalogServiceConfig {
    /// Default limits, no quota and no user-selected class.
    pub fn new(gc_grace: Duration) -> Self {
        Self {
            limits: CatalogLimits::default(),
            gc_grace,
            quotas: BTreeMap::new(),
            user_selected: BTreeSet::new(),
        }
    }

    /// Replaces the limits.
    pub fn with_limits(mut self, limits: CatalogLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Gives `scope` an explicit space budget.
    pub fn with_quota(mut self, scope: Scope, quota_bytes: u64) -> Self {
        self.quotas.insert(scope, quota_bytes);
        self
    }

    /// Lets `class` accept the tenants' own originals into their own scopes. It never
    /// trusts a publisher: that still needs a key of the trust roots.
    pub fn accept_user_selected(mut self, class: ArtifactClass) -> Self {
        self.user_selected.insert(class);
        self
    }
}

/// Where a local class's publisher policy comes from: a function of the trust roots in
/// force, read before the catalog opens and again after every reload
/// ([`CatalogService::apply_trust_roots`]).
pub type PolicySource = Box<dyn Fn(&TrustRootService) -> TrustPolicy + Send + Sync>;

/// What the engine offers to verify for one class.
pub enum OfferedClass {
    /// A class whose publishers sign with keys of the trust roots, with the statement
    /// they sign and its specialized importer's structure check.
    Signed(ClassVerification),
    /// A class whose specialized importer brings its own responsible verifier, which
    /// authenticates no publisher, such as the model sidecar's.
    Local(Box<dyn ArtifactVerifier>),
    /// A class whose specialized importer brings its own verifier, which authenticates
    /// publishers its own way (such as V10's OCI verifier), with the source of its
    /// publisher policy. The policy is in the catalog's configuration before it opens, so
    /// recovery judges the class's objects under it instead of quarantining them for want
    /// of one.
    LocalWithPolicy {
        verifier: Box<dyn ArtifactVerifier>,
        policy: PolicySource,
    },
}

impl OfferedClass {
    /// The class offered.
    pub fn class(&self) -> ArtifactClass {
        match self {
            Self::Signed(verification) => verification.class,
            Self::Local(verifier) | Self::LocalWithPolicy { verifier, .. } => verifier.class(),
        }
    }
}

impl fmt::Debug for OfferedClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signed(verification) => f.debug_tuple("Signed").field(verification).finish(),
            Self::Local(verifier) => f.debug_tuple("Local").field(&verifier.class()).finish(),
            Self::LocalWithPolicy { verifier, .. } => f
                .debug_tuple("LocalWithPolicy")
                .field(&verifier.class())
                .finish(),
        }
    }
}

/// Which verifier a class got when the catalog opened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verifier", rename_all = "snake_case")]
pub enum ClassVerifier {
    /// The shared signed verifier over the trust roots in force, with the class's
    /// publisher policy from them (`TrustRootService::register`).
    Signed,
    /// No key of the trust roots may sign the class (`publishers` says why), so no
    /// publisher is trusted; the class accepts only the tenants' own originals, checked by
    /// its structure check.
    UserSelectedOnly { publishers: ClassRefusal },
    /// The specialized importer's own verifier. It authenticates no publisher, or, for a
    /// class offered with a policy source, publishers its own way under a policy read
    /// from the trust roots (`policy` in [`ClassAdmission`]).
    Local,
    /// No verifier: every publication of the class is refused with the catalog's
    /// `TrustRefusal::NoVerifier`, for this reason.
    Refused { refusal: ClassRefusal },
    /// The engine offered no structure check for the class, so it has no verifier and
    /// every publication of it is refused with `TrustRefusal::NoVerifier`.
    NotOffered,
}

/// One class as the catalog admits it now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ClassAdmission {
    pub class: ArtifactClass,
    #[serde(flatten)]
    pub verifier: ClassVerifier,
    /// A trust policy is configured; without one the catalog trusts nothing of the class.
    pub policy: bool,
    /// The policy accepts the tenants' own originals into their own scopes.
    pub accepts_user_selected: bool,
}

/// Why the catalog was not opened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum OpenRefusal {
    /// The root is relative, so it would depend on the engine's working directory.
    NotAbsolute { root: String },
    /// Another Yougori engine has the catalog in this root open: it holds the root's
    /// [`LOCK_FILE`]. Nothing under the root was read, created or removed.
    InUse { root: String },
    /// The root could not be created or read; nothing was changed beyond that step.
    Storage { failure: StorageFailure },
}

impl fmt::Display for OpenRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute { root } => {
                write!(f, "the catalog root {root} is not an absolute path")
            }
            Self::InUse { root } => write!(
                f,
                "the catalog root {root} is in use by another Yougori engine, which holds its \
                 {LOCK_FILE}; this engine left it untouched"
            ),
            Self::Storage { failure } => failure.fmt(f),
        }
    }
}

impl std::error::Error for OpenRefusal {}

/// A quarantined object found on open, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuarantinedObject {
    pub object: ObjectId,
    pub reason: IntegrityFailure,
}

/// What the layout migration did on open.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MigrationSummary {
    pub from_format: u32,
    pub to_format: u32,
    /// Interrupted imports re-keyed to the current layout; each resumes its verified data.
    pub rekeyed: usize,
    pub upgraded: usize,
    /// Interrupted imports that cannot resume; collected after the grace period.
    pub unresumable: usize,
}

/// What opening the catalog recovered (the catalog's recovery contract; GPU-W03
/// "interrupted-import recovery").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecoveryReport {
    pub opened_at: DateTime<Utc>,
    /// Objects published and healthy.
    pub published: usize,
    /// Objects whose record, index, data length or trust failed the open's checks: kept,
    /// unreadable and reported; a verified, trusted import of the same content replaces
    /// one.
    pub quarantined: Vec<QuarantinedObject>,
    /// Objects committed by an interrupted publication and never published: never
    /// readable; a retried import validates and publishes one, otherwise the collector
    /// removes it after the grace period.
    pub unpublished: Vec<ObjectId>,
    /// Staging directories of interrupted imports: a retried import re-verifies and
    /// reuses their extents; otherwise the collector removes them after the grace period.
    pub interrupted_imports: usize,
    /// Records and roots that could not be read: kept untouched.
    pub unreadable: Vec<StorageFailure>,
    /// Temporary files of interrupted atomic writes, removed: they were never published.
    pub temporaries_removed: usize,
    /// Records in a newer or unknown format: kept untouched, never collected.
    pub refused: Vec<FormatRefusal>,
    pub migration: MigrationSummary,
}

impl RecoveryReport {
    fn new(report: OpenReport, opened_at: DateTime<Utc>) -> Self {
        Self {
            opened_at,
            published: report.published,
            quarantined: report
                .quarantined
                .into_iter()
                .map(|(object, reason)| QuarantinedObject { object, reason })
                .collect(),
            unpublished: report.unpublished,
            interrupted_imports: report.staging,
            unreadable: report.unreadable,
            temporaries_removed: report.temporaries_removed,
            refused: report.refused,
            migration: MigrationSummary {
                from_format: report.migration.from_format,
                to_format: report.migration.to_format,
                rekeyed: report.migration.rekeyed.len(),
                upgraded: report.migration.upgraded,
                unresumable: report.migration.unresumable.len(),
            },
        }
    }
}

/// What one garbage collection did, or why it was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum GcOutcome {
    Collected {
        /// Prepared representations removed: unreachable, unleased, healthy and past the
        /// grace period.
        removed: Vec<ObjectId>,
        removed_bytes: u64,
        /// Committed objects never published, removed after the grace period.
        removed_unpublished: Vec<ObjectId>,
        /// Abandoned staging directories removed after the grace period.
        removed_staging: usize,
        /// Unreachable objects kept because a live lease holds them.
        kept_leased: Vec<ObjectId>,
        /// Unreachable originals kept: only source-file deletion removes one.
        kept_originals: usize,
        /// Unreachable quarantined objects kept for inspection.
        kept_quarantined: usize,
        /// Unreachable objects still within the grace period.
        kept_in_grace: usize,
    },
    /// Nothing was collected.
    Refused { detail: String, refusal: GcRefused },
}

/// Why a collection was refused or stopped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum GcRefused {
    /// Some roots could not be read, so reachability is unknown.
    UnreadableRoots {
        failures: Vec<StorageFailure>,
    },
    Storage {
        failure: StorageFailure,
    },
}

impl GcOutcome {
    fn new(result: Result<GcReport, GcRefusal>) -> Self {
        match result {
            Ok(report) => Self::Collected {
                removed: report.removed,
                removed_bytes: report.removed_bytes,
                removed_unpublished: report.removed_unpublished,
                removed_staging: report.removed_staging,
                kept_leased: report.kept_leased,
                kept_originals: report.kept_originals.len(),
                kept_quarantined: report.kept_quarantined.len(),
                kept_in_grace: report.kept_in_grace.len(),
            },
            Err(refusal) => Self::Refused {
                detail: refusal.to_string(),
                refusal: match refusal {
                    GcRefusal::UnreadableRoots { failures } => {
                        GcRefused::UnreadableRoots { failures }
                    }
                    GcRefusal::Storage { failure } => GcRefused::Storage { failure },
                },
            },
        }
    }
}

/// One garbage collection and when it ran.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GcRecord {
    pub at: DateTime<Utc>,
    #[serde(flatten)]
    pub outcome: GcOutcome,
}

/// What setting the policies from the trust roots in force did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TrustApplied {
    pub at: DateTime<Utc>,
    /// The generation of the roots in force, if any.
    pub generation: Option<u64>,
    /// Each class whose policy was set, local classes with a policy source included:
    /// objects quarantined (never deleted) and restored.
    pub classes: Vec<PolicyApplied>,
    /// Classes that have keys now but no signed verifier, because the catalog fixes its
    /// verifiers when it opens: they verify publishers once the catalog is reopened.
    pub needs_reopen: Vec<ArtifactClass>,
}

/// The service's status: its classes, what the catalog holds, and its latest recovery,
/// collection and trust application.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CatalogServiceStatus {
    pub root: String,
    pub checked_at: DateTime<Utc>,
    /// Every artifact class, in class order.
    pub classes: Vec<ClassAdmission>,
    /// Offers refused because the class was already offered.
    pub refused_offers: Vec<ClassRefusal>,
    pub catalog: CatalogSummary,
    pub recovery: RecoveryReport,
    pub last_gc: Option<GcRecord>,
    pub last_trust: Option<TrustApplied>,
}

/// The responsible verifier of a class no trust-root key may sign, configured to accept
/// the tenants' own originals: it authenticates no publisher and runs the structure check
/// the class's importer offered.
struct OwnOriginals {
    class: ArtifactClass,
    structure: Box<dyn StructureValidator>,
}

impl ArtifactVerifier for OwnOriginals {
    fn class(&self) -> ArtifactClass {
        self.class
    }

    fn authenticate(
        &self,
        _content: &ContentDescriptor,
        _publisher: &PublisherId,
        _attestation: &[u8],
    ) -> Result<(), VerifierRejection> {
        Err(VerifierRejection::AttestationInvalid)
    }

    fn validate(
        &self,
        content: &ContentDescriptor,
        bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        self.structure.validate(content, bytes)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The engine's catalog service. See the module documentation.
pub struct CatalogService {
    root: PathBuf,
    holder: Arc<dyn CatalogHolder>,
    user_selected: BTreeSet<ArtifactClass>,
    classes: BTreeMap<ArtifactClass, ClassVerifier>,
    /// The policy sources of the local classes registered with one.
    policy_sources: BTreeMap<ArtifactClass, PolicySource>,
    refused_offers: Vec<ClassRefusal>,
    calendar: Arc<dyn TrustCalendar>,
    recovery: RecoveryReport,
    last_gc: Mutex<Option<GcRecord>>,
    last_trust: Mutex<Option<TrustApplied>>,
}

impl fmt::Debug for CatalogService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CatalogService")
            .field("root", &self.root)
            .field("classes", &self.classes)
            .finish_non_exhaustive()
    }
}

/// One registered offer: the configuration with its policy, the verifier it got, and the
/// policy source to read again after a reload, if it brought one.
type Registered = (CatalogConfig, ClassVerifier, Option<PolicySource>);

/// The policy `source` reads from `trust`, plus the tenants' own originals when the class
/// accepts them.
fn sourced_policy(
    source: &PolicySource,
    trust: &TrustRootService,
    accepts_own: bool,
) -> TrustPolicy {
    let policy = source(trust);
    if accepts_own {
        policy.accept_user_selected()
    } else {
        policy
    }
}

/// Registers one offer in `registry` and `config`, through `trust` for signed classes and
/// for the policy of a local class offered with a source.
fn register_offer(
    offer: OfferedClass,
    user_selected: &BTreeSet<ArtifactClass>,
    trust: &mut TrustRootService,
    registry: &mut VerifierRegistry,
    config: CatalogConfig,
) -> Registered {
    let class = offer.class();
    let accepts_own = user_selected.contains(&class);
    let duplicate = |_| ClassVerifier::Refused {
        refusal: ClassRefusal::AlreadyRegistered { class },
    };
    match offer {
        OfferedClass::Local(verifier) => match registry.register(verifier) {
            Ok(()) if accepts_own => (
                config.with_trust(class, TrustPolicy::new().accept_user_selected()),
                ClassVerifier::Local,
                None,
            ),
            Ok(()) => (config, ClassVerifier::Local, None),
            Err(error) => (config, duplicate(error), None),
        },
        OfferedClass::LocalWithPolicy { verifier, policy } => match registry.register(verifier) {
            Ok(()) => (
                config.with_trust(class, sourced_policy(&policy, trust, accepts_own)),
                ClassVerifier::Local,
                Some(policy),
            ),
            Err(error) => (config, duplicate(error), None),
        },
        OfferedClass::Signed(verification) => match trust.policy(class) {
            Err(publishers) if accepts_own => {
                let own = OwnOriginals {
                    class,
                    structure: verification.structure,
                };
                match registry.register(Box::new(own)) {
                    Ok(()) => (
                        config.with_trust(class, TrustPolicy::new().accept_user_selected()),
                        ClassVerifier::UserSelectedOnly { publishers },
                        None,
                    ),
                    Err(error) => (config, duplicate(error), None),
                }
            }
            // With keys through the trust roots' own registration; without, the trust
            // service records the refusal, so a reload that adds keys reports the class.
            _ => {
                let (config, registration) = trust.register(vec![verification], registry, config);
                match registration.refused.into_iter().next() {
                    Some(refusal) => (config, ClassVerifier::Refused { refusal }, None),
                    None if accepts_own => {
                        let policy = config.trust.get(&class).cloned().unwrap_or_default();
                        (
                            config.with_trust(class, policy.accept_user_selected()),
                            ClassVerifier::Signed,
                            None,
                        )
                    }
                    None => (config, ClassVerifier::Signed, None),
                }
            }
        },
    }
}

impl CatalogService {
    /// Opens or creates the catalog in `root` with `config`, after registering every
    /// offered class (see [`ClassVerifier`]), and hands the opened catalog to `hold`. The
    /// catalog's open recovers what an interrupted run left ([`RecoveryReport`]). Returns
    /// the service and the holder, for callers that drive a specialized importer through
    /// it.
    pub fn open<H, F>(
        root: &Path,
        config: CatalogServiceConfig,
        offered: Vec<OfferedClass>,
        trust: &mut TrustRootService,
        clock: Arc<dyn Clock>,
        calendar: Arc<dyn TrustCalendar>,
        hold: F,
    ) -> Result<(Self, Arc<H>), OpenRefusal>
    where
        H: CatalogHolder + 'static,
        F: FnOnce(Catalog) -> H,
    {
        if !root.is_absolute() {
            return Err(OpenRefusal::NotAbsolute {
                root: root.display().to_string(),
            });
        }
        let mut catalog_config = config.quotas.iter().fold(
            CatalogConfig::new(config.gc_grace).with_limits(config.limits),
            |catalog_config, (scope, quota_bytes)| {
                catalog_config.with_quota(scope.clone(), *quota_bytes)
            },
        );
        let mut registry = VerifierRegistry::new();
        let mut classes = BTreeMap::new();
        let mut policy_sources = BTreeMap::new();
        let mut refused_offers = Vec::new();
        for offer in offered {
            let class = offer.class();
            if classes.contains_key(&class) {
                refused_offers.push(ClassRefusal::AlreadyRegistered { class });
                continue;
            }
            let (next, verifier, source) = register_offer(
                offer,
                &config.user_selected,
                trust,
                &mut registry,
                catalog_config,
            );
            catalog_config = next;
            classes.insert(class, verifier);
            if let Some(source) = source {
                policy_sources.insert(class, source);
            }
        }
        for class in ArtifactClass::ALL {
            classes.entry(class).or_insert(ClassVerifier::NotOffered);
        }
        let (catalog, report) = Catalog::open(root, catalog_config, registry, clock).map_err(
            |failure| match failure {
                OpenFailure::InUse { root } => OpenRefusal::InUse {
                    root: root.display().to_string(),
                },
                OpenFailure::Storage(failure) => OpenRefusal::Storage { failure },
            },
        )?;
        let holder = Arc::new(hold(catalog));
        let shared: Arc<dyn CatalogHolder> = holder.clone();
        let service = Self {
            root: root.to_path_buf(),
            holder: shared,
            user_selected: config.user_selected,
            classes,
            policy_sources,
            refused_offers,
            recovery: RecoveryReport::new(report, calendar.now()),
            calendar,
            last_gc: Mutex::new(None),
            last_trust: Mutex::new(None),
        };
        Ok((service, holder))
    }

    /// The catalog root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The catalog, locked until the guard drops, for roots, reads and deletions.
    pub fn catalog(&self) -> MutexGuard<'_, Catalog> {
        self.holder.catalog()
    }

    /// What opening the catalog recovered.
    pub fn recovery(&self) -> &RecoveryReport {
        &self.recovery
    }

    /// The verifier each class got when the catalog opened.
    pub fn verifier(&self, class: ArtifactClass) -> &ClassVerifier {
        self.classes
            .get(&class)
            .unwrap_or(&ClassVerifier::NotOffered)
    }

    /// Runs the catalog's lease-aware garbage collection once and keeps the record for
    /// the status. It never removes an object under a live lease, a quarantined object
    /// or a user's original, and touches nothing outside the root.
    pub fn collect_garbage(&self) -> GcRecord {
        let outcome = GcOutcome::new(self.catalog().collect_garbage());
        let record = GcRecord {
            at: self.calendar.now(),
            outcome,
        };
        *lock(&self.last_gc) = Some(record.clone());
        record
    }

    /// Sets the policy of every class with a signed or user-selection verifier from the
    /// roots in force in `trust`, as after a reload: the class's publishers (none when it
    /// has no keys now), plus the tenants' own originals when the class accepts them. A
    /// local class offered with a policy source gets what its source reads from `trust`
    /// now, plus the tenants' own originals when it accepts them. The catalog re-checks
    /// every object of each class: one a revoked or removed key admitted is quarantined and
    /// its leases revoked, never deleted.
    ///
    /// `TrustRootService::apply_policies` sets the roots' policy alone; for a class that
    /// accepts the tenants' own originals that would withdraw their trust and revoke their
    /// leases, so the service sets the same publishers with the configured acceptance.
    pub fn apply_trust_roots(&self, trust: &TrustRootService) -> TrustApplied {
        let mut classes = Vec::new();
        let mut needs_reopen = Vec::new();
        {
            let mut catalog = self.catalog();
            for (class, verifier) in &self.classes {
                if let Some(source) = self.policy_sources.get(class) {
                    let accepts_own = self.user_selected.contains(class);
                    let policy = sourced_policy(source, trust, accepts_own);
                    let revision = catalog.set_trust_policy(*class, policy);
                    classes.push(PolicyApplied {
                        class: *class,
                        quarantined: revision.quarantined,
                        restored: revision.restored,
                    });
                    continue;
                }
                let keyed = trust.policy(*class);
                match verifier {
                    ClassVerifier::Signed | ClassVerifier::UserSelectedOnly { .. } => {
                        if matches!(verifier, ClassVerifier::UserSelectedOnly { .. })
                            && keyed.is_ok()
                        {
                            needs_reopen.push(*class);
                        }
                        let mut policy = keyed.unwrap_or_default();
                        if self.user_selected.contains(class) {
                            policy = policy.accept_user_selected();
                        }
                        let revision = catalog.set_trust_policy(*class, policy);
                        classes.push(PolicyApplied {
                            class: *class,
                            quarantined: revision.quarantined,
                            restored: revision.restored,
                        });
                    }
                    ClassVerifier::Refused {
                        refusal: ClassRefusal::NoKeys { .. } | ClassRefusal::NoTrustRoots { .. },
                    } if keyed.is_ok() => needs_reopen.push(*class),
                    _ => {}
                }
            }
        }
        let applied = TrustApplied {
            at: self.calendar.now(),
            generation: trust.generation(),
            classes,
            needs_reopen,
        };
        *lock(&self.last_trust) = Some(applied.clone());
        applied
    }

    /// The status now: every class with its verifier and policy, what the catalog holds
    /// per scope, class and state, and the latest recovery, collection and trust
    /// application.
    pub fn status(&self) -> CatalogServiceStatus {
        let (classes, summary) = {
            let catalog = self.catalog();
            let policies = &catalog.config().trust;
            let classes = self
                .classes
                .iter()
                .map(|(class, verifier)| ClassAdmission {
                    class: *class,
                    verifier: verifier.clone(),
                    policy: policies.contains_key(class),
                    accepts_user_selected: policies
                        .get(class)
                        .is_some_and(TrustPolicy::accepts_user_selected),
                })
                .collect();
            (classes, catalog.summary())
        };
        CatalogServiceStatus {
            root: self.root.display().to_string(),
            checked_at: self.calendar.now(),
            classes,
            refused_offers: self.refused_offers.clone(),
            catalog: summary,
            recovery: self.recovery.clone(),
            last_gc: lock(&self.last_gc).clone(),
            last_trust: lock(&self.last_trust).clone(),
        }
    }
}
