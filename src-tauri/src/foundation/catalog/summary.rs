//! A host-side summary of the catalog for the engine's operator (S02 in
//! docs/combined-plan-leftover-tasks.md, "adopt the catalog on actual import paths"; S2
//! CORE-02 quotas, leases and garbage collection; GPU-W03).
//!
//! [`Catalog::summary`] counts what the catalog holds now: per scope, the published and
//! quarantined objects of each artifact class with their bytes and how many are users'
//! originals, the scope's quota charge, its leased objects and imports in flight; and, for
//! the whole catalog, live leases and grants, roots, records it could not read, and the
//! committed-but-unpublished objects and interrupted staging still on disk. It reads
//! nothing from disk and changes nothing.
//!
//! It is the host's view, like [`Catalog::failures`]: it names scopes, but carries no
//! private metadata, source identity or label of any object (INT-05). Show a tenant only
//! its own [`ScopeSummary`].

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::identity::{ArtifactClass, Scope};
use super::state::{Catalog, QuotaUsage};

/// A number of objects and their bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ObjectTally {
    pub objects: u64,
    pub bytes: u64,
}

impl ObjectTally {
    fn add(&mut self, bytes: u64) {
        self.objects = self.objects.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

/// One artifact class's objects in one scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ClassSummary {
    pub class: ArtifactClass,
    /// Published and readable now.
    pub published: ObjectTally,
    /// Quarantined: failed validation, or the current policy no longer accepts the trust
    /// they were published under. Kept and unreadable; nothing deletes them automatically.
    pub quarantined: ObjectTally,
    /// Of the published and quarantined objects, the users' originals, which garbage
    /// collection and cache eviction never remove (line 552).
    pub originals: ObjectTally,
}

/// A scope's storage charge against its budget (CORE-02 quotas).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct QuotaCharge {
    /// `None` when the scope has no explicit budget, so it stores nothing new.
    pub limit_bytes: Option<u64>,
    pub published_bytes: u64,
    pub reserved_bytes: u64,
    pub unpublished_bytes: u64,
    pub charged_bytes: u64,
    /// The charge exceeds the budget, as after the budget was lowered: every import of
    /// the scope is refused until space is freed; nothing is evicted to make room.
    pub over_budget: bool,
}

impl From<QuotaUsage> for QuotaCharge {
    fn from(usage: QuotaUsage) -> Self {
        let charged_bytes = usage.charged_bytes();
        Self {
            limit_bytes: usage.limit_bytes,
            published_bytes: usage.published_bytes,
            reserved_bytes: usage.reserved_bytes,
            unpublished_bytes: usage.unpublished_bytes,
            charged_bytes,
            over_budget: usage.limit_bytes.is_some_and(|limit| charged_bytes > limit),
        }
    }
}

/// One scope: its quota charge, its objects per class, its leased objects and its
/// imports in flight.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScopeSummary {
    pub scope: Scope,
    pub quota: QuotaCharge,
    /// Classes with at least one published or quarantined object, in class order.
    pub classes: Vec<ClassSummary>,
    /// The scope's objects under at least one live lease, whoever holds it.
    pub leased_objects: u64,
    pub imports_in_flight: u64,
}

/// What the catalog holds now, for its operator. See the module documentation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CatalogSummary {
    /// Every scope with a budget, an object, an import in flight or unpublished data, in
    /// scope order.
    pub scopes: Vec<ScopeSummary>,
    pub live_leases: u64,
    pub live_grants: u64,
    pub roots: u64,
    /// Roots that could not be read: garbage collection is refused while any exist.
    pub unreadable_roots: u64,
    /// Publication records that could not be read or are in a newer format: kept and
    /// never collected.
    pub unreadable_records: u64,
    /// Committed objects never published, as after an interrupted publication: resumed
    /// by a retried import, otherwise collected after the grace period.
    pub unpublished: ObjectTally,
    /// Staging of interrupted or cancelled imports no import is using: re-verified when
    /// resumed, otherwise collected after the grace period.
    pub staging: ObjectTally,
    /// Of that staging, directories a newer build wrote: kept, never collected.
    pub retained_staging: u64,
    /// Failure provenance records held, and those dropped because the log was full.
    pub failures: u64,
    pub dropped_failures: u64,
}

fn count(items: usize) -> u64 {
    u64::try_from(items).unwrap_or(u64::MAX)
}

impl Catalog {
    /// What the catalog holds now, counted per scope, class and state. Reads nothing
    /// from disk and changes nothing; see the module documentation.
    pub fn summary(&self) -> CatalogSummary {
        let now = self.now();
        let leased = self.leased_objects(now);
        let mut classes: BTreeMap<(Scope, ArtifactClass), ClassSummary> = BTreeMap::new();
        let mut leased_in: BTreeMap<Scope, u64> = BTreeMap::new();
        for (object, entry) in &self.entries {
            let scope = entry.scope().clone();
            let index = entry.index();
            let tally = classes
                .entry((scope.clone(), index.class))
                .or_insert(ClassSummary {
                    class: index.class,
                    published: ObjectTally::default(),
                    quarantined: ObjectTally::default(),
                    originals: ObjectTally::default(),
                });
            let length_bytes = index.length_bytes();
            if self.is_usable(entry) {
                tally.published.add(length_bytes);
            } else {
                tally.quarantined.add(length_bytes);
            }
            if index.role.is_original() {
                tally.originals.add(length_bytes);
            }
            if leased.contains(object) {
                let held = leased_in.entry(scope).or_default();
                *held = held.saturating_add(1);
            }
        }
        let mut in_flight: BTreeMap<Scope, u64> = BTreeMap::new();
        for flight in self.flights.values().filter(|flight| flight.is_pending()) {
            let pending = in_flight.entry(flight.request.scope.clone()).or_default();
            *pending = pending.saturating_add(1);
        }
        let mut unpublished = ObjectTally::default();
        let mut unpublished_scopes = BTreeSet::new();
        for waiting in self.unpublished.values() {
            unpublished.add(waiting.length_bytes);
            unpublished_scopes.extend(waiting.scope.clone());
        }
        let mut staging = ObjectTally::default();
        for remnant in self.remnants.values() {
            staging.add(remnant.length_bytes);
            unpublished_scopes.extend(remnant.scope.clone());
        }
        let scopes: BTreeSet<Scope> = classes
            .keys()
            .map(|(scope, _)| scope.clone())
            .chain(self.config.quota_bytes.keys().cloned())
            .chain(in_flight.keys().cloned())
            .chain(unpublished_scopes)
            .collect();
        let scopes = scopes
            .into_iter()
            .map(|scope| ScopeSummary {
                quota: QuotaCharge::from(self.quota_usage(&scope)),
                classes: classes
                    .iter()
                    .filter(|((owner, _), _)| *owner == scope)
                    .map(|(_, summary)| *summary)
                    .collect(),
                leased_objects: leased_in.get(&scope).copied().unwrap_or(0),
                imports_in_flight: in_flight.get(&scope).copied().unwrap_or(0),
                scope,
            })
            .collect();
        CatalogSummary {
            scopes,
            live_leases: count(
                self.leases
                    .values()
                    .filter(|lease| lease.cell.is_live(now))
                    .count(),
            ),
            live_grants: count(
                self.grants
                    .values()
                    .filter(|grant| now < grant.expires_at)
                    .count(),
            ),
            roots: count(self.roots.len()),
            unreadable_roots: count(self.unreadable_roots.len()),
            unreadable_records: count(self.unclassified.len()),
            unpublished,
            staging,
            retained_staging: count(
                self.remnants
                    .values()
                    .filter(|remnant| remnant.retained)
                    .count(),
            ),
            failures: count(self.failures.records().count()),
            dropped_failures: self.failures.dropped(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::Duration;

    use super::super::fakes::{FakeSource, FakeVerifier, StopAt};
    use super::super::{
        ArtifactClass, Catalog, CatalogConfig, ImportManifest, ImportRequest, ImportSource,
        ImportStage, ImportStart, ImportStatus, ObjectMetadata, ObjectRole, Scope, TrustClaim,
        TrustPolicy, Uninterrupted, VerifierRegistry,
    };
    use super::*;
    use crate::foundation::ids::{ExecutionId, ManualClock, MonotonicTime, OperationId, TenantId};

    fn tenant(name: &str) -> Scope {
        Scope::tenant(TenantId::new(name).unwrap())
    }

    fn request(scope: &Scope, bytes: &[u8]) -> ImportRequest {
        ImportRequest {
            operation: OperationId::new("op-summary").unwrap(),
            execution: ExecutionId::new("exe-summary").unwrap(),
            scope: scope.clone(),
            class: ArtifactClass::ModelWeights,
            role: ObjectRole::Original,
            manifest: ImportManifest::describe(bytes, std::num::NonZeroU64::new(4).unwrap()),
            trust: TrustClaim::UserSelected,
            depends_on: BTreeSet::new(),
            metadata: ObjectMetadata::new(),
        }
    }

    #[test]
    fn the_summary_counts_objects_per_scope_class_and_state_with_charges_and_leases() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (tenant("a"), tenant("b"));
        let config = CatalogConfig::new(Duration::from_secs(60))
            .with_quota(a.clone(), 1 << 20)
            .with_quota(b.clone(), 4)
            .with_trust(
                ArtifactClass::ModelWeights,
                TrustPolicy::new().accept_user_selected(),
            );
        let mut verifiers = VerifierRegistry::new();
        verifiers
            .register(Box::new(FakeVerifier::new(ArtifactClass::ModelWeights)))
            .unwrap();
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1)));
        let (mut catalog, _) = Catalog::open(dir.path(), config, verifiers, clock).unwrap();
        assert_eq!(
            catalog.summary().scopes.len(),
            2,
            "budgeted scopes are listed"
        );

        let weights = b"twelve bytes";
        let source = || FakeSource::new("weights", weights);
        let ImportStart::Started(ticket) = catalog
            .begin_import(request(&a, weights), source().identity())
            .unwrap()
        else {
            panic!("not started");
        };
        let status = catalog
            .drive_import(&ticket, &mut source(), &mut Uninterrupted)
            .unwrap();
        let ImportStatus::Published { object, .. } = status else {
            panic!("{status:?}");
        };
        // A second import of the same tenant stops before publication.
        let other = b"another file";
        let ImportStart::Started(pending) = catalog
            .begin_import(
                request(&a, other),
                FakeSource::new("other", other).identity(),
            )
            .unwrap()
        else {
            panic!("not started");
        };
        catalog
            .drive_import(
                &pending,
                &mut FakeSource::new("other", other),
                &mut StopAt::stage(ImportStage::CatalogPublication),
            )
            .unwrap();
        let execution = ExecutionId::new("exe-reader").unwrap();
        catalog
            .acquire_lease(&a, &execution, object, Duration::from_secs(5))
            .unwrap();

        let summary = catalog.summary();
        let scope_a = &summary.scopes[0];
        assert_eq!(scope_a.scope, a);
        assert_eq!(
            scope_a.classes,
            vec![ClassSummary {
                class: ArtifactClass::ModelWeights,
                published: ObjectTally {
                    objects: 1,
                    bytes: 12
                },
                quarantined: ObjectTally::default(),
                originals: ObjectTally {
                    objects: 1,
                    bytes: 12
                },
            }]
        );
        assert_eq!(scope_a.leased_objects, 1);
        assert_eq!(scope_a.imports_in_flight, 1);
        assert_eq!(scope_a.quota.published_bytes, 12);
        assert_eq!(
            scope_a.quota.unpublished_bytes, 12,
            "the committed copy is charged"
        );
        assert!(!scope_a.quota.over_budget);
        assert_eq!(summary.live_leases, 1);
        assert_eq!(
            summary.unpublished,
            ObjectTally {
                objects: 1,
                bytes: 12
            }
        );
        let scope_b = &summary.scopes[1];
        assert_eq!((scope_b.scope.clone(), scope_b.classes.len()), (b, 0));
        assert_eq!(scope_b.quota.limit_bytes, Some(4));

        // The summary serializes for the operator's status.
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["scopes"][0]["classes"][0]["class"], "model_weights");
        assert_eq!(json["scopes"][0]["scope"]["scope"], "tenant");
    }
}
