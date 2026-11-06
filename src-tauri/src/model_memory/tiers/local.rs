//! Local storage (table line 542): original and prepared immutable artifacts, under
//! quotas, in an existing user-selected pool (Appendix A.2 line 1492: one WSL
//! distribution and VHDX per storage pool).
//!
//! The objects live in a pool's CORE-02 catalog (T05). Only its importer writes them, and
//! consumers read through its read-only handles (line 546), so this tier never writes:
//! it records an object only once that catalog shows it published, with the role the
//! catalog recorded. A pool is used only if the user selected it and it is present now;
//! Yougori never creates or picks another. Before an import writes anything, its bytes
//! are reserved in the CORE-03 ledger, whose storage budgets are the quotas: a tenant's
//! object is charged to that tenant, and one of Yougori's own host scope (a guest image,
//! a runtime update) to the [`HostBudgetHolder`] the host's supervisor configured at
//! construction, never to a tenant. Without one, host-scope imports are refused. An
//! object already stored is not reserved again (GPU-W03: repeated imports do not
//! multiply disk usage).
//!
//! Bytes leave only through the catalog's distinct operations (line 552), each its own
//! method here: cache eviction of planned derived representations, local model deletion
//! (which removes a root and no bytes), source-file deletion on the user's explicit
//! request, and garbage collection of what is no longer reachable. Their storage is given
//! back to the ledger when the catalog reports the bytes removed. No budget path reaches
//! source-file deletion, and the catalog refuses to evict an original.
//!
//! The catalog, not this tier's records, says what exists now: another holder of the
//! catalog may evict, collect or quarantine an object. A stored copy is offered, or stands
//! in for a dropped GPU copy (§1.1 line 307), only while the catalog shows it published
//! and healthy in its scope and its pool is present.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::charge::{release, reserve_and_create, Charged, LedgerCharge, Released};
use super::object::{Consumer, ObjectCopy, ObjectRef};
use super::representations::{DerivedKind, PlannedEviction};
use super::source::{OfferRefusal, SourceOffer, SourcePath, TierRefusal};
use super::Tier;
use crate::foundation::catalog::{
    CacheEviction, Catalog, DeleteRefusal, EvictionRefusal, GcRefusal, GcReport,
    LocalModelDeletion, ObjectId, ObjectRole, ObjectStatus, RootName, Scope, SourceFileDeletion,
    SourceFileTarget,
};
use crate::foundation::ids::{Clock, ExecutionId, TenantId};
use crate::foundation::ledger::{Amounts, CostPurpose, Ledger, LedgerError, ReservationId};
use crate::model_memory::math::{InputError, SourceId, MAX_NAME_LEN};
use crate::model_memory::residency::eviction::{
    Content, CopyTier, ReconstructibleCopy, Verification,
};

/// A storage pool's name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PoolId(String);

impl PoolId {
    /// Accepts 1–128 characters without control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, InputError> {
        let value = value.into();
        if value.is_empty() {
            return Err(InputError::Empty { field: "PoolId" });
        }
        if value.chars().count() > MAX_NAME_LEN || value.chars().any(char::is_control) {
            return Err(InputError::OutOfRange { field: "PoolId" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PoolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether the user selected a pool for Yougori's storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolSelection {
    UserSelected,
    NotSelected,
}

/// Whether a pool is there now, such as a drive that may be unplugged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolPresence {
    Present,
    Missing,
}

/// A storage pool as the user configured it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoragePool {
    pub id: PoolId,
    pub selection: PoolSelection,
    pub presence: PoolPresence,
}

/// The ledger budget the host's supervisor set aside for Yougori's own artifacts, the
/// catalog's host scope (guest images and runtime updates; table line 542, quotas). The
/// CORE-03 ledger charges every reservation to a [`TenantId`] budget, so the supervisor
/// names one for the host and sets its storage quota with `set_tenant_budget`, the way a
/// tenant's is set. The holder is not a tenant: the tier refuses an import for a tenant
/// scope of that name, so no tenant spends the host's budget and the host spends no
/// tenant's (the P02 integration item: an owner for host storage quota).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostBudgetHolder(TenantId);

impl HostBudgetHolder {
    /// The ledger budget named `holder`.
    pub fn new(holder: TenantId) -> Self {
        Self(holder)
    }

    /// The ledger budget the host's artifacts are charged to.
    pub fn id(&self) -> &TenantId {
        &self.0
    }
}

impl fmt::Display for HostBudgetHolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the host's budget holder {}", self.0)
    }
}

/// Storage reserved for one import before it writes anything. Consumed by recording the
/// publication or by abandoning the import; a refused recording hands it back.
#[derive(Debug, PartialEq, Eq)]
pub struct StorageReservation {
    reservation: ReservationId,
    pool: PoolId,
    object: ObjectRef,
    bytes: u64,
}

impl StorageReservation {
    pub fn reservation(&self) -> ReservationId {
        self.reservation
    }

    pub fn pool(&self) -> &PoolId {
        &self.pool
    }

    pub fn object(&self) -> &ObjectRef {
        &self.object
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// What a removal through the tier did: the catalog's own report, and the storage
/// reservations given back for the bytes it removed. A created workload's amounts count
/// until the host observes the release, so each is usually pending until confirmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Removal<R> {
    pub catalog: R,
    pub released: Vec<Released>,
    /// Reservations the ledger refused to take back. The bytes are gone and the tier no
    /// longer records them, so these need reconciling with the ledger.
    pub unreleased: Vec<UnreleasedReservation>,
}

/// A storage reservation the ledger refused to take back after the catalog removed its
/// object's bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnreleasedReservation {
    pub object: ObjectId,
    pub reservation: ReservationId,
    pub bytes: u64,
    pub error: LedgerError,
}

/// Why local storage refused (table line 542).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalRefusal {
    UnknownPool {
        pool: PoolId,
    },
    DuplicatePool {
        pool: PoolId,
    },
    /// Yougori stores only in pools the user selected.
    PoolNotUserSelected {
        pool: PoolId,
    },
    PoolMissing {
        pool: PoolId,
    },
    ZeroBytes,
    /// Yougori's own host-scope artifacts are charged to the host's budget holder, and
    /// the tier was built without one.
    NoHostBudgetHolder {
        object: ObjectRef,
    },
    /// The tenant scope is named like the host's budget holder, which is not a tenant;
    /// charging it would let a tenant spend the host's budget.
    TenantIsHostBudgetHolder {
        object: ObjectRef,
        holder: HostBudgetHolder,
    },
    /// The ledger refused: the tenant's storage quota or the host's storage capacity
    /// (CORE-03).
    Ledger(LedgerError),
    /// The object is already stored; nothing is reserved again.
    AlreadyStored {
        object: ObjectRef,
        pool: PoolId,
    },
    /// The catalog does not show the reserved object published and healthy in its
    /// scope.
    NotPublished {
        object: ObjectRef,
        status: ObjectStatus,
    },
    /// The catalog published another length than was reserved.
    LengthMismatch {
        object: ObjectRef,
        reserved_bytes: u64,
        published_bytes: u64,
    },
    NotStored {
        object: ObjectRef,
    },
    /// The object is stored in another pool than the one named.
    InOtherPool {
        object: ObjectRef,
        pool: PoolId,
    },
    /// Cache eviction in local storage names only prepared representations (line 552).
    WrongEviction {
        tier: Tier,
        kind: DerivedKind,
    },
    /// One cache eviction removes objects of one scope.
    ScopesDiffer {
        first: Scope,
        other: Scope,
    },
    /// The catalog refused the cache eviction and removed nothing: an original, a leased
    /// object, a copy no longer reconstructible or a dependency.
    Eviction(EvictionRefusal),
    /// The catalog refused a deletion and removed nothing.
    Delete(DeleteRefusal),
    /// The catalog refused to collect.
    Collection(GcRefusal),
}

impl fmt::Display for LocalRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPool { pool } => write!(f, "pool {pool} is unknown"),
            Self::DuplicatePool { pool } => write!(f, "pool {pool} is already known"),
            Self::PoolNotUserSelected { pool } => write!(
                f,
                "pool {pool} was not selected by the user; Yougori stores only in selected pools"
            ),
            Self::PoolMissing { pool } => write!(f, "pool {pool} is not present"),
            Self::ZeroBytes => f.write_str("an object has at least one byte"),
            Self::NoHostBudgetHolder { object } => write!(
                f,
                "{object} is one of the host's own artifacts, and no host budget holder is \
                 configured to charge its storage quota to"
            ),
            Self::TenantIsHostBudgetHolder { object, holder } => write!(
                f,
                "{object} names {holder} as its tenant, which is not a tenant: a tenant \
                 cannot spend the host's budget"
            ),
            Self::Ledger(error) => error.fmt(f),
            Self::AlreadyStored { object, pool } => {
                write!(f, "{object} is already stored in pool {pool}")
            }
            Self::NotPublished { object, status } => write!(
                f,
                "the catalog does not show {object} published and healthy: {status:?}"
            ),
            Self::LengthMismatch {
                object,
                reserved_bytes,
                published_bytes,
            } => write!(
                f,
                "{reserved_bytes} bytes were reserved for {object}, but the catalog published \
                 {published_bytes}"
            ),
            Self::NotStored { object } => write!(f, "{object} is not stored"),
            Self::InOtherPool { object, pool } => {
                write!(f, "{object} is stored in pool {pool}")
            }
            Self::WrongEviction { tier, kind } => write!(
                f,
                "a {kind:?} eviction in {tier} is not a cache eviction of local storage"
            ),
            Self::ScopesDiffer { first, other } => write!(
                f,
                "one cache eviction removes objects of one scope, not of {first} and {other}"
            ),
            Self::Eviction(refusal) => refusal.fmt(f),
            Self::Delete(refusal) => refusal.fmt(f),
            Self::Collection(refusal) => refusal.fmt(f),
        }
    }
}

impl std::error::Error for LocalRefusal {}

impl From<LedgerError> for LocalRefusal {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}

/// A recording the tier refused, with the reservation handed back so the caller can
/// retry or abandon it.
#[derive(Debug, PartialEq, Eq)]
pub struct NotRecorded {
    pub refusal: LocalRefusal,
    pub reservation: StorageReservation,
}

impl fmt::Display for NotRecorded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.refusal.fmt(f)
    }
}

impl std::error::Error for NotRecorded {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stored {
    object: ObjectRef,
    pool: PoolId,
    role: ObjectRole,
    bytes: u64,
    reservation: ReservationId,
}

/// Why an object's storage can be charged to no budget.
enum Unchargeable {
    NoHostBudgetHolder,
    TenantIsHostBudgetHolder(HostBudgetHolder),
}

/// Local storage across the user's pools (table line 542).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalStorageTier {
    pools: BTreeMap<PoolId, StoragePool>,
    stored: BTreeMap<ObjectId, Stored>,
    importing: BTreeMap<ReservationId, ObjectId>,
    /// The budget host-scope artifacts are charged to; `None` refuses them.
    host_budget: Option<HostBudgetHolder>,
}

impl LocalStorageTier {
    /// A tier for tenants' objects only: without a host budget holder it refuses to store
    /// Yougori's own host-scope artifacts.
    pub fn new() -> Self {
        Self::default()
    }

    /// A tier that charges Yougori's own host-scope artifacts to `holder`'s ledger
    /// budget, the explicit configuration of the host's supervisor.
    pub fn with_host_budget_holder(holder: HostBudgetHolder) -> Self {
        Self {
            host_budget: Some(holder),
            ..Self::default()
        }
    }

    /// The budget host-scope artifacts are charged to; `None` refuses them.
    pub fn host_budget_holder(&self) -> Option<&HostBudgetHolder> {
        self.host_budget.as_ref()
    }

    /// Records a pool as the user configured it; the tier never creates one.
    pub fn add_pool(&mut self, pool: StoragePool) -> Result<(), LocalRefusal> {
        if self.pools.contains_key(&pool.id) {
            return Err(LocalRefusal::DuplicatePool { pool: pool.id });
        }
        self.pools.insert(pool.id.clone(), pool);
        Ok(())
    }

    /// Records whether a pool is present now.
    pub fn observe_pool(
        &mut self,
        pool: &PoolId,
        presence: PoolPresence,
    ) -> Result<(), LocalRefusal> {
        self.pools
            .get_mut(pool)
            .map(|known| known.presence = presence)
            .ok_or_else(|| LocalRefusal::UnknownPool { pool: pool.clone() })
    }

    /// Pools the user selected that are present now, in name order: the only pools an
    /// import may use.
    pub fn eligible_pools(&self) -> Vec<PoolId> {
        self.pools
            .keys()
            .filter(|pool| self.usable_pool(pool).is_ok())
            .cloned()
            .collect()
    }

    /// Bytes a tenant's stored objects occupy in a pool. The ledger's reservations, not
    /// this tally, are the quota. Host-scope objects are no tenant's and never count,
    /// not even under the name of the host's budget holder, which is not a tenant.
    pub fn used_bytes(&self, pool: &PoolId, tenant: &TenantId) -> u64 {
        self.stored
            .values()
            .filter(|stored| stored.pool == *pool && stored.object.tenant() == Some(tenant))
            .fold(0u64, |total, stored| total.saturating_add(stored.bytes))
    }

    /// Bytes Yougori's own host-scope objects occupy in a pool, charged to the host's
    /// budget holder and to no tenant.
    pub fn host_used_bytes(&self, pool: &PoolId) -> u64 {
        self.stored
            .values()
            .filter(|stored| stored.pool == *pool && stored.object.tenant().is_none())
            .fold(0u64, |total, stored| total.saturating_add(stored.bytes))
    }

    /// What a stored object is to its owner, as the catalog recorded it.
    pub fn role_of(&self, object: ObjectId) -> Option<&ObjectRole> {
        self.stored.get(&object).map(|stored| &stored.role)
    }

    /// The ledger reservation holding a stored object's bytes.
    pub fn reservation_of(&self, object: ObjectId) -> Option<ReservationId> {
        self.stored.get(&object).map(|stored| stored.reservation)
    }

    /// Reservations of imports not yet recorded or abandoned.
    pub fn importing(&self) -> Vec<ReservationId> {
        self.importing.keys().copied().collect()
    }

    /// Reserves storage for an import of `object` into `pool` before it writes anything
    /// (reserve before create): the pool must be selected and present, and the ledger
    /// charges the owning tenant's storage quota, or the host's budget holder's for one
    /// of Yougori's own host-scope artifacts. An object already stored is not reserved
    /// again.
    pub fn reserve_import<C: Clock>(
        &mut self,
        pool: &PoolId,
        object: ObjectRef,
        bytes: u64,
        importer: &ExecutionId,
        charge: &LedgerCharge,
        ledger: &mut Ledger<C>,
    ) -> Result<StorageReservation, LocalRefusal> {
        if bytes == 0 {
            return Err(LocalRefusal::ZeroBytes);
        }
        self.usable_pool(pool)?;
        if let Some(stored) = self.stored.get(&object.id()) {
            return Err(LocalRefusal::AlreadyStored {
                object,
                pool: stored.pool.clone(),
            });
        }
        let tenant = match self.charged_party(&object) {
            Ok(tenant) => tenant,
            Err(Unchargeable::NoHostBudgetHolder) => {
                return Err(LocalRefusal::NoHostBudgetHolder { object })
            }
            Err(Unchargeable::TenantIsHostBudgetHolder(holder)) => {
                return Err(LocalRefusal::TenantIsHostBudgetHolder { object, holder })
            }
        };
        let reservation = reserve_and_create(
            ledger,
            charge,
            Charged {
                tenant: &tenant,
                execution: importer,
                purpose: CostPurpose::Storage,
                parent: None,
            },
            Amounts::new().storage_quota_bytes(bytes),
        )?;
        self.importing.insert(reservation, object.id());
        Ok(StorageReservation {
            reservation,
            pool: pool.clone(),
            object,
            bytes,
        })
    }

    /// Records a reserved import once the pool's catalog shows it published and healthy
    /// in its scope with exactly the reserved length, keeping the role the catalog
    /// recorded (original or prepared). Only the catalog's importer wrote it.
    pub fn record_published(
        &mut self,
        reservation: StorageReservation,
        catalog: &Catalog,
    ) -> Result<(), NotRecorded> {
        let object = &reservation.object;
        let status = catalog.status(&object.scope, object.id());
        let published = if status == ObjectStatus::Published {
            catalog.private_metadata(&object.scope, object.id()).ok()
        } else {
            None
        };
        let Some(metadata) = published else {
            let refusal = LocalRefusal::NotPublished {
                object: object.clone(),
                status,
            };
            return Err(NotRecorded {
                refusal,
                reservation,
            });
        };
        if metadata.length_bytes != reservation.bytes {
            let refusal = LocalRefusal::LengthMismatch {
                object: object.clone(),
                reserved_bytes: reservation.bytes,
                published_bytes: metadata.length_bytes,
            };
            return Err(NotRecorded {
                refusal,
                reservation,
            });
        }
        self.importing.remove(&reservation.reservation);
        self.stored.insert(
            reservation.object.id(),
            Stored {
                object: reservation.object,
                pool: reservation.pool,
                role: metadata.role,
                bytes: reservation.bytes,
                reservation: reservation.reservation,
            },
        );
        Ok(())
    }

    /// Gives back the reservation of an import that failed, was cancelled or found the
    /// object already published. What it wrote counts until the host observes it gone.
    pub fn abandon<C: Clock>(
        &mut self,
        reservation: StorageReservation,
        ledger: &mut Ledger<C>,
    ) -> Result<Released, LocalRefusal> {
        self.importing.remove(&reservation.reservation);
        Ok(release(ledger, reservation.reservation, reservation.bytes)?)
    }

    /// Cache eviction (line 552): removes planned prepared representations of one scope
    /// from `pool` through its catalog and gives their storage back. The catalog refuses,
    /// removing nothing, if any of them is a user's original, leased, no longer
    /// reconstructible or needed by another object; a [`PlannedEviction`] names only a
    /// derived kind besides. Cache eviction never deletes an original to meet a budget.
    pub fn evict_cache<C: Clock>(
        &mut self,
        pool: &PoolId,
        catalog: &mut Catalog,
        evictions: &[PlannedEviction],
        ledger: &mut Ledger<C>,
    ) -> Result<Removal<CacheEviction>, LocalRefusal> {
        self.known_pool(pool)?;
        let Some(first) = evictions.first() else {
            return Ok(Removal {
                catalog: CacheEviction::default(),
                released: Vec::new(),
                unreleased: Vec::new(),
            });
        };
        let scope = first.object.scope.clone();
        let mut objects = Vec::with_capacity(evictions.len());
        for eviction in evictions {
            if eviction.tier != Tier::LocalStorage || eviction.kind == DerivedKind::HostCopy {
                return Err(LocalRefusal::WrongEviction {
                    tier: eviction.tier,
                    kind: eviction.kind,
                });
            }
            if eviction.object.scope != scope {
                return Err(LocalRefusal::ScopesDiffer {
                    first: scope,
                    other: eviction.object.scope.clone(),
                });
            }
            self.stored_in(pool, &eviction.object)?;
            objects.push(eviction.object.id());
        }
        let eviction = catalog
            .evict_cache(&scope, &objects)
            .map_err(LocalRefusal::Eviction)?;
        let (released, unreleased) = self.release_removed(pool, &eviction.evicted, ledger);
        Ok(Removal {
            catalog: eviction,
            released,
            unreleased,
        })
    }

    /// Local model deletion (line 552): removes the model's local-model root through the
    /// pool's catalog and nothing else. It deletes no bytes, so no storage comes back
    /// here; objects it leaves unreachable go through
    /// [`collect_garbage`](Self::collect_garbage) after the catalog's grace period, and
    /// originals a source-file root holds stay.
    pub fn delete_local_model(
        &self,
        pool: &PoolId,
        catalog: &mut Catalog,
        scope: &Scope,
        name: &RootName,
    ) -> Result<LocalModelDeletion, LocalRefusal> {
        self.known_pool(pool)?;
        catalog
            .delete_local_model(scope, name)
            .map_err(LocalRefusal::Delete)
    }

    /// Source-file deletion (line 552), on the user's explicit request only, the one
    /// action that deletes an original: through the pool's catalog it removes a
    /// source-file root and the originals it held, or one original no root holds, such as
    /// one a deleted local model left behind. The catalog refuses, removing nothing, while
    /// any of them is leased or still needed; their storage is given back. No budget path
    /// calls it.
    pub fn delete_source_file<C: Clock>(
        &mut self,
        pool: &PoolId,
        catalog: &mut Catalog,
        scope: &Scope,
        target: &SourceFileTarget,
        ledger: &mut Ledger<C>,
    ) -> Result<Removal<SourceFileDeletion>, LocalRefusal> {
        self.known_pool(pool)?;
        let deletion = catalog
            .delete_source_file(scope, target)
            .map_err(LocalRefusal::Delete)?;
        let (released, unreleased) = self.release_removed(pool, &deletion.deleted, ledger);
        Ok(Removal {
            catalog: deletion,
            released,
            unreleased,
        })
    }

    /// Garbage collection through the pool's catalog: prepared representations that are
    /// unreachable and unleased past its grace period, such as those a local model deletion
    /// left, are removed and their storage is given back. The catalog never collects an
    /// original; one left unreachable stays until a source-file deletion names it.
    pub fn collect_garbage<C: Clock>(
        &mut self,
        pool: &PoolId,
        catalog: &mut Catalog,
        ledger: &mut Ledger<C>,
    ) -> Result<Removal<GcReport>, LocalRefusal> {
        self.known_pool(pool)?;
        let report = catalog
            .collect_garbage()
            .map_err(LocalRefusal::Collection)?;
        let (released, unreleased) = self.release_removed(pool, &report.removed, ledger);
        Ok(Removal {
            catalog: report,
            released,
            unreleased,
        })
    }

    /// A stored copy of the object that can reconstruct a dropped GPU copy (T08
    /// `residency::eviction`, line 307): stored here, in a pool that is present, and shown
    /// by the pool's catalog as published and healthy in the object's own scope now, so
    /// verified and still there. An object the catalog evicted, collected or quarantined
    /// has no copy here, whatever this tier recorded.
    pub fn copy_of(&self, object: &ObjectRef, catalog: &Catalog) -> Option<ObjectCopy> {
        self.published(object, catalog).ok()?;
        Some(ObjectCopy {
            object: object.clone(),
            holder: None,
            copy: ReconstructibleCopy {
                tier: CopyTier::LocalStorage,
                verification: Verification::Verified {
                    content: Content::Immutable(object.content),
                },
            },
        })
    }

    /// Offers a stored object to `requester` as a source while its pool is selected and
    /// present and the pool's catalog shows it published and healthy. Whether the
    /// requester may read it is the catalog's scope rule, checked when sources are
    /// chosen.
    pub fn offer(
        &self,
        source: SourceId,
        object: &ObjectRef,
        requester: &Consumer,
        path: SourcePath,
        catalog: &Catalog,
    ) -> Result<SourceOffer, OfferRefusal> {
        let refuse =
            |refusal| OfferRefusal::new(&source, Tier::LocalStorage, TierRefusal::Local(refusal));
        let stored = self.stored.get(&object.id()).ok_or_else(|| {
            refuse(LocalRefusal::NotStored {
                object: object.clone(),
            })
        })?;
        self.usable_pool(&stored.pool).map_err(refuse)?;
        self.published(object, catalog).map_err(refuse)?;
        let covers_bytes = stored.bytes;
        Ok(SourceOffer::new(
            Tier::LocalStorage,
            source,
            object.clone(),
            requester,
            path,
            covers_bytes,
        ))
    }

    /// The stored object, if its pool is present and the catalog shows it published and
    /// healthy in its own scope now.
    fn published(&self, object: &ObjectRef, catalog: &Catalog) -> Result<&Stored, LocalRefusal> {
        let stored = self
            .stored
            .get(&object.id())
            .ok_or_else(|| LocalRefusal::NotStored {
                object: object.clone(),
            })?;
        if self.known_pool(&stored.pool)?.presence != PoolPresence::Present {
            return Err(LocalRefusal::PoolMissing {
                pool: stored.pool.clone(),
            });
        }
        let status = catalog.status(&object.scope, object.id());
        if status != ObjectStatus::Published {
            return Err(LocalRefusal::NotPublished {
                object: object.clone(),
                status,
            });
        }
        Ok(stored)
    }

    fn known_pool(&self, pool: &PoolId) -> Result<&StoragePool, LocalRefusal> {
        self.pools
            .get(pool)
            .ok_or_else(|| LocalRefusal::UnknownPool { pool: pool.clone() })
    }

    fn usable_pool(&self, pool: &PoolId) -> Result<&StoragePool, LocalRefusal> {
        let known = self.known_pool(pool)?;
        if known.selection != PoolSelection::UserSelected {
            return Err(LocalRefusal::PoolNotUserSelected { pool: pool.clone() });
        }
        if known.presence != PoolPresence::Present {
            return Err(LocalRefusal::PoolMissing { pool: pool.clone() });
        }
        Ok(known)
    }

    /// The stored object, which must be in `pool`.
    fn stored_in(&self, pool: &PoolId, object: &ObjectRef) -> Result<&Stored, LocalRefusal> {
        let stored = self
            .stored
            .get(&object.id())
            .ok_or_else(|| LocalRefusal::NotStored {
                object: object.clone(),
            })?;
        if stored.pool != *pool {
            return Err(LocalRefusal::InOtherPool {
                object: object.clone(),
                pool: stored.pool.clone(),
            });
        }
        Ok(stored)
    }

    /// The ledger budget an object's storage is charged to: its tenant's, or the host's
    /// budget holder for a host-scope object. A tenant scope named like the holder is
    /// charged nothing, so no tenant spends the host's budget.
    fn charged_party(&self, object: &ObjectRef) -> Result<TenantId, Unchargeable> {
        match (object.tenant(), &self.host_budget) {
            (Some(tenant), Some(holder)) if tenant == holder.id() => {
                Err(Unchargeable::TenantIsHostBudgetHolder(holder.clone()))
            }
            (Some(tenant), _) => Ok(tenant.clone()),
            (None, Some(holder)) => Ok(holder.id().clone()),
            (None, None) => Err(Unchargeable::NoHostBudgetHolder),
        }
    }

    /// Forgets the objects `pool`'s catalog removed, then gives their storage back. The
    /// bytes are already gone, so every entry is forgotten whatever the ledger answers, and
    /// a refused release is reported rather than ending the walk.
    fn release_removed<C: Clock>(
        &mut self,
        pool: &PoolId,
        objects: &[ObjectId],
        ledger: &mut Ledger<C>,
    ) -> (Vec<Released>, Vec<UnreleasedReservation>) {
        let mut released = Vec::new();
        let mut unreleased = Vec::new();
        for object in objects {
            if !self
                .stored
                .get(object)
                .is_some_and(|stored| stored.pool == *pool)
            {
                continue;
            }
            let Some(stored) = self.stored.remove(object) else {
                continue;
            };
            match release(ledger, stored.reservation, stored.bytes) {
                Ok(done) => released.push(done),
                Err(error) => unreleased.push(UnreleasedReservation {
                    object: *object,
                    reservation: stored.reservation,
                    bytes: stored.bytes,
                    error,
                }),
            }
        }
        (released, unreleased)
    }
}

#[cfg(test)]
mod tests;
