//! The engine's catalog service (S02 in docs/combined-plan-leftover-tasks.md, "adopt the
//! catalog on actual import paths"; docs/combined-gpu-memory-and-vm-sandbox-plan.md, S2
//! CORE-02: "atomic publication, quotas, leases, resumable verified data and garbage
//! collection ... retention of user originals"; GPU-W03: "Integrate CORE-02 publication,
//! interrupted-import recovery, quotas and lease-aware garbage collection"; the S08 note
//! "catalog wiring once the engine opens a catalog").
//!
//! [`CatalogService`] opens the one CORE-02 [`Catalog`](crate::foundation::catalog::Catalog)
//! the engine keeps, under a root directory its caller names, and composes what is already
//! built; it re-implements none of it:
//!
//! - **Recovery on open.** The catalog's own open is the recovery contract: temporaries of
//!   interrupted atomic writes are removed, staging layouts migrate, every publication
//!   record is checked and quarantined if it fails, committed-but-unpublished objects and
//!   interrupted staging are kept for a retried import to resume from verified data, or
//!   collected after the grace period. [`RecoveryReport`] records what this open found. All
//!   of it runs under the root's exclusive lock: a root another engine holds is refused
//!   ([`OpenRefusal::InUse`]) and left untouched.
//! - **Quotas.** Each configured scope gets its budget; a scope without one stores
//!   nothing, and an import over budget is refused with the catalog's typed
//!   `QuotaRefusal`. Nothing is evicted to make room.
//! - **Lease-aware garbage collection.** [`CatalogService::collect_garbage`] runs the
//!   catalog's collector, which never removes an object under a live lease, a quarantined
//!   object or a user's original, and touches nothing outside the root; the latest run is
//!   kept for the status.
//! - **Trust per artifact class.** Each class the caller offers is registered through the
//!   engine's [`TrustRootService`]: a class with keys gets the shared signed verifier and
//!   its publisher policy (`TrustRootService::register`); a class without keys keeps
//!   refusing every publication with a typed reason, unless the caller configured it to
//!   accept the tenants' own originals ([`CatalogServiceConfig::accept_user_selected`]),
//!   which never trusts a publisher. A class whose specialized importer brings its own
//!   verifier gets no policy, unless the caller offers it with a policy source
//!   ([`OfferedClass::LocalWithPolicy`]): its policy is then read from the roots before
//!   the catalog opens, so recovery judges its objects under it.
//!   [`CatalogService::apply_trust_roots`] sets every registered class's policy from the
//!   roots in force after a reload, those classes included.
//! - **Status.** [`CatalogService::status`] lists every class with its verifier and
//!   policy, the catalog's objects per scope, class and state with their bytes, quota
//!   charges and leases, the last recovery, the last collection and the last trust
//!   application.
//!
//! Pure and path based: the service reads no environment and no setting; the engine glue
//! (`catalog_service.rs` at the crate root) chooses the root, the quotas and the classes.

mod location;
mod service;

#[cfg(test)]
mod tests;

pub use location::{CatalogLocation, LocationProblem};
pub use service::{
    CatalogHolder, CatalogService, CatalogServiceConfig, CatalogServiceStatus, ClassAdmission,
    ClassVerifier, GcOutcome, GcRecord, MigrationSummary, OfferedClass, OpenRefusal, PolicySource,
    QuarantinedObject, RecoveryReport, TrustApplied,
};
