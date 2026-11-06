//! Recovery recipes (GPU §4.15, line 866): what can be reloaded or recomputed after
//! eviction, from which immutable source, and under which availability assumptions.
//!
//! - A reload names a CORE-02 catalog object ([`ObjectId`] binds scope, class and content)
//!   in a tier that guarantees availability, by residency's rule
//!   ([`ReconstructibleCopy::reconstructs`]: verified, pinned host RAM or local storage).
//! - A recipe never promises reconstruction from a peer that can disappear
//!   ([`RecipeRefusal::PeerCanDisappear`]) or from a prompt the service no longer holds
//!   ([`RecipeRefusal::PromptNotHeld`]).
//! - Indispensable reconstruction dependencies are held explicitly, each honoured for the
//!   plan's whole horizon and never assumed renewed: a reload by a CORE-02 read lease on
//!   its exact catalog object ([`ObjectHold`], checked through [`ObjectHoldAuthority`],
//!   which the [`Catalog`] implements), a recompute's prompt by a CORE-04 service lease
//!   (checked through [`HoldAuthority`], which the CORE-04 [`Coordinator`] implements).
//! - Written-back copies are the plan's own: residency's eviction rule decides when state
//!   must be written back, and the copy stays in the plan's host budget.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use crate::foundation::catalog::{
    ArtifactClass, Catalog, LeaseId as CatalogLeaseId, ObjectId, ReadRefusal, Scope,
};
use crate::foundation::coordination::{CapacityPort, Coordinator, LeaseKind, LeaseRefusal};
use crate::foundation::ids::{Clock, ContentKey, Digest, ExecutionId, LeaseId, MonotonicTime};
use crate::model_memory::identity::TokenPrefix;
use crate::model_memory::residency::eviction::{Content, CopyTier, ReconstructibleCopy};
use crate::model_memory::residency::retention::ObjectKind;

use super::declaration::{
    session_prefix_matches, CheckedWorkflow, Resource, ResourceKey, WorkflowDeclaration,
};

/// An immutable source in the CORE-02 catalog (line 866: "from which immutable source").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CatalogSource {
    pub object: ObjectId,
    pub scope: Scope,
    pub class: ArtifactClass,
    pub content: ContentKey,
    /// Where the copy lives and whether it was verified (§3.4).
    pub copy: ReconstructibleCopy,
}

/// Whether the service holds the exact prompt a recompute needs (line 866).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromptHolding {
    /// Held under a CORE-04 service lease.
    Held { prefix: TokenPrefix, lease: LeaseId },
    /// Not held; any recipe that relies on it is refused.
    NotHeld { prefix: TokenPrefix },
}

/// A CORE-02 read lease on the catalog object a reload depends on, with the reader scope
/// and execution it was acquired under (line 866: lease indispensable dependencies).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectHold {
    pub reader: Scope,
    pub execution: ExecutionId,
    pub lease: CatalogLeaseId,
}

/// How a resource can be materialized again (line 866).
#[derive(Clone, Debug, PartialEq)]
pub enum RecoveryRecipe {
    /// Reload immutable bytes from a catalog object, held by a catalog read lease on that
    /// exact object.
    Reload {
        source: CatalogSource,
        hold: ObjectHold,
    },
    /// Build a merged variant on the device from its resident base and adapter (§3.9,
    /// line 634). It is a materialization, never a reconstructible copy (line 307), so
    /// evicting the variant still writes it back or retains it.
    Derive {
        sources: Vec<ResourceKey>,
        compute_seconds: f64,
    },
    /// Recompute session KV from the exact prompt the service holds.
    Recompute {
        prompt: PromptHolding,
        compute_seconds: f64,
    },
    /// Rebuild from an authorized peer's copy. Always refused: a peer can disappear.
    Peer { peer: Digest },
}

impl RecoveryRecipe {
    /// The compute time of a derive or recompute; zero for transfers.
    pub fn compute_seconds(&self) -> f64 {
        match self {
            Self::Derive {
                compute_seconds, ..
            }
            | Self::Recompute {
                compute_seconds, ..
            } => *compute_seconds,
            Self::Reload { .. } | Self::Peer { .. } => 0.0,
        }
    }

    /// The CORE-04 lease this recipe depends on, with the kind it must be: a recompute's
    /// service lease on its prompt.
    pub fn hold(&self) -> Option<(LeaseId, LeaseKind)> {
        match self {
            Self::Recompute {
                prompt: PromptHolding::Held { lease, .. },
                ..
            } => Some((*lease, LeaseKind::Service)),
            _ => None,
        }
    }

    /// The catalog lease a reload depends on.
    pub fn object_hold(&self) -> Option<&ObjectHold> {
        match self {
            Self::Reload { hold, .. } => Some(hold),
            _ => None,
        }
    }
}

/// A catalog lease as the catalog honours it now: the object it reads and when it ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldObject {
    pub object: ObjectId,
    /// When the lease ends unless renewed; renewal is never assumed.
    pub expires_at: MonotonicTime,
}

/// The authority that honours holds on catalog objects (line 866). The CORE-02 catalog
/// implements it.
pub trait ObjectHoldAuthority {
    /// The object a held, live lease reads and when the lease ends; refused exactly as a
    /// read through the lease would be.
    fn object_hold(&self, hold: &ObjectHold) -> Result<HeldObject, ReadRefusal>;
}

impl ObjectHoldAuthority for Catalog {
    /// The object and expiry from [`Catalog::lease_object`], without opening a handle.
    fn object_hold(&self, hold: &ObjectHold) -> Result<HeldObject, ReadRefusal> {
        let (object, expires_at) = self.lease_object(&hold.reader, &hold.execution, hold.lease)?;
        Ok(HeldObject { object, expires_at })
    }
}

/// Writes a catalog refusal by its message; the refusal stays typed in Rust.
fn display<S: serde::Serializer>(refusal: &ReadRefusal, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(refusal)
}

/// A lease as its authority honours it now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldLease {
    pub kind: LeaseKind,
    pub parent: ExecutionId,
    /// When it ends unless renewed; renewal is never assumed.
    pub expires_at: MonotonicTime,
}

/// The authority that honours holds on reconstruction dependencies (line 866: pin or
/// explicitly lease indispensable dependencies). The CORE-04 coordinator implements it.
pub trait HoldAuthority {
    /// The lease if it is honoured now.
    fn hold(&self, lease: LeaseId) -> Result<HeldLease, LeaseRefusal>;
}

impl<C: Clock, P: CapacityPort> HoldAuthority for Coordinator<C, P> {
    fn hold(&self, lease: LeaseId) -> Result<HeldLease, LeaseRefusal> {
        let lease = self.check_lease(lease)?;
        Ok(HeldLease {
            kind: lease.kind(),
            parent: lease.parent().clone(),
            expires_at: lease.expires_at(),
        })
    }
}

/// Why a recipe was refused (line 866).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum RecipeRefusal {
    /// A peer can disappear, so it is never promised as a source.
    PeerCanDisappear {
        peer: Digest,
    },
    /// The prompt is not held by the service.
    PromptNotHeld,
    /// The held prompt is not this session's exact token state.
    PromptMismatch,
    /// The copy is unverified or in a tier that does not guarantee availability.
    SourceNotGuaranteed {
        tier: CopyTier,
    },
    /// The object id does not bind the declared scope, class and content.
    SourceIdentityMismatch,
    /// The source's content is not the resource's content.
    SourceContentMismatch,
    /// The source belongs to another scope; equal bytes are not permission (S3.3).
    SourceOutsideScope,
    WrongArtifactClass {
        class: ArtifactClass,
    },
    /// Reload and derive rebuild immutable state; recompute rebuilds session KV.
    WrongKind {
        kind: ObjectKind,
    },
    UnknownSource {
        source: String,
    },
    /// Derive sources are not exactly one base and one adapter on that base.
    InvalidSource {
        source: String,
    },
    /// Derive sources form a cycle.
    DeriveCycle,
    NotPositive {
        field: &'static str,
    },
    /// The lease is not honoured (expired, revoked, released, stale).
    HoldNotHonoured {
        lease: LeaseId,
        refusal: LeaseRefusal,
    },
    WrongLeaseKind {
        lease: LeaseId,
        expected: LeaseKind,
        found: LeaseKind,
    },
    /// The lease belongs to another parent execution.
    ForeignLease {
        lease: LeaseId,
    },
    /// The lease ends before the plan's horizon; renewal is never assumed.
    HoldEndsTooEarly {
        lease: LeaseId,
        expires_at: MonotonicTime,
        needed_until: MonotonicTime,
    },
    /// The catalog refuses the reload's lease as it would refuse a read: another reader's,
    /// unknown, expired, released or revoked, or the object is no longer readable.
    ObjectHoldNotHonoured {
        #[serde(serialize_with = "display")]
        refusal: ReadRefusal,
    },
    /// The catalog lease reads another object than the reload's source.
    ObjectHoldOnAnotherObject {
        held: ObjectId,
        source: ObjectId,
    },
    /// The catalog lease was acquired for another reader scope or execution than this
    /// workflow's.
    ForeignObjectHold,
    /// The catalog lease ends before the plan's horizon; renewal is never assumed.
    ObjectHoldEndsTooEarly {
        expires_at: MonotonicTime,
        needed_until: MonotonicTime,
    },
}

impl fmt::Display for RecipeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerCanDisappear { .. } => {
                f.write_str("a peer can disappear, so it is never a promised source")
            }
            Self::PromptNotHeld => f.write_str("the service does not hold the prompt"),
            Self::PromptMismatch => f.write_str("the held prompt is not the session's state"),
            Self::SourceNotGuaranteed { tier } => write!(
                f,
                "a copy in {tier:?} is unverified or not guaranteed to stay available"
            ),
            Self::HoldEndsTooEarly {
                expires_at,
                needed_until,
                ..
            } => write!(
                f,
                "the hold ends at {} ns but is needed until {} ns",
                expires_at.as_nanos(),
                needed_until.as_nanos()
            ),
            other => write!(f, "{other:?}"),
        }
    }
}

/// The structural checks of one recipe, made when a workflow is checked.
pub(crate) fn check_recipe_structure(
    resource: &Resource,
    recipe: &RecoveryRecipe,
    index: &BTreeMap<&ResourceKey, usize>,
    declaration: &WorkflowDeclaration,
) -> Result<(), RecipeRefusal> {
    let kind = resource.kind;
    match recipe {
        RecoveryRecipe::Peer { peer } => Err(RecipeRefusal::PeerCanDisappear { peer: *peer }),
        RecoveryRecipe::Reload { source, .. } => {
            if kind == ObjectKind::SessionKv {
                return Err(RecipeRefusal::WrongKind { kind });
            }
            if source.class != ArtifactClass::ModelWeights {
                return Err(RecipeRefusal::WrongArtifactClass {
                    class: source.class,
                });
            }
            if ObjectId::new(&source.scope, source.class, source.content) != source.object {
                return Err(RecipeRefusal::SourceIdentityMismatch);
            }
            if source.scope != Scope::tenant(declaration.tenant.clone()) {
                return Err(RecipeRefusal::SourceOutsideScope);
            }
            if resource.content != Some(source.content) {
                return Err(RecipeRefusal::SourceContentMismatch);
            }
            if !source
                .copy
                .reconstructs(&Content::Immutable(source.content))
            {
                return Err(RecipeRefusal::SourceNotGuaranteed {
                    tier: source.copy.tier,
                });
            }
            if let RecoveryRecipe::Reload { hold, .. } = recipe {
                if hold.reader != source.scope || hold.execution != declaration.execution {
                    return Err(RecipeRefusal::ForeignObjectHold);
                }
            }
            Ok(())
        }
        RecoveryRecipe::Derive {
            sources,
            compute_seconds,
        } => {
            if kind != ObjectKind::MergedVariant {
                return Err(RecipeRefusal::WrongKind { kind });
            }
            positive("derive compute seconds", *compute_seconds)?;
            let mut base = None;
            let mut adapter = None;
            let mut seen = BTreeSet::new();
            for source in sources {
                let at =
                    index
                        .get(source)
                        .copied()
                        .ok_or_else(|| RecipeRefusal::UnknownSource {
                            source: source.to_string(),
                        })?;
                let invalid = || RecipeRefusal::InvalidSource {
                    source: source.to_string(),
                };
                if !seen.insert(at) {
                    return Err(invalid());
                }
                match declaration.resources[at].identity.kind() {
                    ObjectKind::BaseWeights if base.is_none() => base = Some(source),
                    ObjectKind::Adapter if adapter.is_none() => adapter = Some(at),
                    _ => return Err(invalid()),
                }
            }
            let (Some(base), Some(adapter)) = (base, adapter) else {
                return Err(RecipeRefusal::NotPositive {
                    field: "derive sources: one base and one adapter",
                });
            };
            if declaration.resources[adapter].prerequisites != [base.clone()] {
                return Err(RecipeRefusal::InvalidSource {
                    source: declaration.resources[adapter].key.to_string(),
                });
            }
            if derives_from(declaration, index, &resource.key, sources) {
                return Err(RecipeRefusal::DeriveCycle);
            }
            Ok(())
        }
        RecoveryRecipe::Recompute {
            prompt,
            compute_seconds,
        } => {
            if kind != ObjectKind::SessionKv {
                return Err(RecipeRefusal::WrongKind { kind });
            }
            positive("recompute seconds", *compute_seconds)?;
            match prompt {
                PromptHolding::NotHeld { .. } => Err(RecipeRefusal::PromptNotHeld),
                PromptHolding::Held { prefix, .. } => {
                    if session_prefix_matches(&resource.identity, prefix) {
                        Ok(())
                    } else {
                        Err(RecipeRefusal::PromptMismatch)
                    }
                }
            }
        }
    }
}

/// Whether deriving `target` from `sources` closes a cycle through other derive recipes.
fn derives_from(
    declaration: &WorkflowDeclaration,
    index: &BTreeMap<&ResourceKey, usize>,
    target: &ResourceKey,
    sources: &[ResourceKey],
) -> bool {
    let mut stack: Vec<&ResourceKey> = sources.iter().collect();
    let mut seen = BTreeSet::new();
    while let Some(key) = stack.pop() {
        if key == target {
            return true;
        }
        if !seen.insert(key) {
            continue;
        }
        if let Some(at) = index.get(key) {
            for recipe in &declaration.resources[*at].recipes {
                if let RecoveryRecipe::Derive { sources, .. } = recipe {
                    stack.extend(sources.iter());
                }
            }
        }
    }
    false
}

fn positive(field: &'static str, value: f64) -> Result<(), RecipeRefusal> {
    if value.is_finite() && value > 0.0 {
        Ok(())
    } else {
        Err(RecipeRefusal::NotPositive { field })
    }
}

/// Checks one recipe's hold: honoured now, on the recipe's own dependency, of this
/// workflow's parent execution and lasting until `needed_until` without renewal.
pub(crate) fn check_hold(
    workflow: &CheckedWorkflow,
    recipe: &RecoveryRecipe,
    holds: &dyn HoldAuthority,
    objects: &dyn ObjectHoldAuthority,
    needed_until: MonotonicTime,
) -> Result<(), RecipeRefusal> {
    if let RecoveryRecipe::Reload { source, hold } = recipe {
        let held = objects
            .object_hold(hold)
            .map_err(|refusal| RecipeRefusal::ObjectHoldNotHonoured { refusal })?;
        if held.object != source.object {
            return Err(RecipeRefusal::ObjectHoldOnAnotherObject {
                held: held.object,
                source: source.object,
            });
        }
        if held.expires_at < needed_until {
            return Err(RecipeRefusal::ObjectHoldEndsTooEarly {
                expires_at: held.expires_at,
                needed_until,
            });
        }
        return Ok(());
    }
    let Some((lease, expected)) = recipe.hold() else {
        return Ok(());
    };
    let held = holds
        .hold(lease)
        .map_err(|refusal| RecipeRefusal::HoldNotHonoured { lease, refusal })?;
    if held.kind != expected {
        return Err(RecipeRefusal::WrongLeaseKind {
            lease,
            expected,
            found: held.kind,
        });
    }
    if held.parent != workflow.execution {
        return Err(RecipeRefusal::ForeignLease { lease });
    }
    if held.expires_at < needed_until {
        return Err(RecipeRefusal::HoldEndsTooEarly {
            lease,
            expires_at: held.expires_at,
            needed_until,
        });
    }
    Ok(())
}

/// Every recipe whose hold fails now, as (resource, recipe) pairs, with the first
/// refusal of each.
pub(crate) fn failing_holds(
    workflow: &CheckedWorkflow,
    holds: &dyn HoldAuthority,
    objects: &dyn ObjectHoldAuthority,
    needed_until: MonotonicTime,
) -> Vec<((usize, usize), RecipeRefusal)> {
    let mut failing = Vec::new();
    for (at, resource) in workflow.resources.iter().enumerate() {
        for (number, recipe) in resource.recipes.iter().enumerate() {
            if let Err(refusal) = check_hold(workflow, recipe, holds, objects, needed_until) {
                failing.push(((at, number), refusal));
            }
        }
    }
    failing
}
