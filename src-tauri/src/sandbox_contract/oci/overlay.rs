//! Read-only bases and per-sandbox overlays (§5.3 "each consuming VM gets independent
//! writable overlays ... shared mutable caches are not allowed by default"; VM-W33
//! "read-only bases and sandbox-owned overlays").
//!
//! An overlay descriptor binds one sandbox execution and boot generation to the read-only
//! catalog objects of one image (its layers and tree) and to a writable upper layer that
//! only that sandbox owns. Binding checks with the catalog that the sandbox may read every
//! base object (its own scope's, or another scope's under that owner's grant) and takes a
//! lease on each, so revocation and expiry reach the overlay. Overlays are never shared:
//! another sandbox, or the same sandbox after a reboot or restore, binds its own. A shared
//! writable cache is refused; Tier 0 has no switch that allows one. The importer's
//! execution cannot consume its own import, so the writable importer stays separate from
//! consumers.
//!
//! The descriptor is a plan for the runtime. The image tree is materialized inside the
//! VM, never on the host filesystem.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::foundation::catalog::{Catalog, LeaseId, ObjectId, ReadRefusal, Scope};
use crate::foundation::ids::{
    Clock, Digest, DigestBuilder, ExecutionId, MonotonicTime, SandboxBootGeneration,
};

/// Domain of [`OverlayId`].
const OVERLAY_DOMAIN: &str = "yougori/oci/overlay/v1";

/// The read-only bases of one imported image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageObjects {
    /// The scope that owns the objects.
    pub owner: Scope,
    /// The execution that imported them.
    pub importer: ExecutionId,
    pub tree: ObjectId,
    pub layers: Vec<ObjectId>,
}

/// What a sandbox may write to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WritableCache {
    /// An upper layer owned by this sandbox and generation only.
    PrivateToSandbox,
    /// A writable cache shared with other sandboxes: refused (§5.3).
    Shared { name: String },
}

/// A request to give one sandbox an overlay over an image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayRequest {
    /// The scope the sandbox reads as.
    pub reader: Scope,
    pub sandbox: ExecutionId,
    pub generation: SandboxBootGeneration,
    pub image: ImageObjects,
    pub writable: WritableCache,
    /// How long the leases on the base objects last.
    pub lease_duration: Duration,
}

/// An overlay's identity: the sandbox, its generation and the image tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct OverlayId(Digest);

impl OverlayId {
    fn new(sandbox: &ExecutionId, generation: SandboxBootGeneration, tree: ObjectId) -> Self {
        Self(
            DigestBuilder::new(OVERLAY_DOMAIN)
                .str(sandbox.as_str())
                .u64(generation.get())
                .digest(&tree.digest())
                .finish(),
        )
    }

    /// The underlying digest.
    pub fn digest(self) -> Digest {
        self.0
    }
}

/// Where the image tree becomes files: only inside the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Materialization {
    InsideGuestOnly,
}

/// The writable layer of one overlay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpperLayer {
    pub owner: ExecutionId,
    pub generation: SandboxBootGeneration,
    /// Always false: nothing else may write to or read from it.
    pub shared: bool,
}

/// One sandbox's overlay over read-only bases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayDescriptor {
    pub overlay: OverlayId,
    pub sandbox: ExecutionId,
    pub generation: SandboxBootGeneration,
    pub reader: Scope,
    pub base_owner: Scope,
    pub tree: ObjectId,
    pub layers: Vec<ObjectId>,
    /// One lease per base object, held by the sandbox.
    pub leases: Vec<(ObjectId, LeaseId)>,
    pub upper: UpperLayer,
    pub materialization: Materialization,
    pub bound_at: MonotonicTime,
}

/// Why an overlay was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OverlayRefusal {
    /// Shared mutable caches are not allowed (§5.3).
    SharedMutableCache,
    /// The importer's execution cannot consume its own import.
    ImporterIsConsumer,
    /// The sandbox may not read a base object: no grant, quarantined, or absent.
    NotReadable {
        object: ObjectId,
        refusal: ReadRefusal,
    },
    AlreadyBound {
        overlay: OverlayId,
    },
    UnknownOverlay,
    /// Another sandbox's overlay.
    OtherSandbox,
    /// The overlay was bound for an earlier or later boot generation.
    StaleGeneration {
        bound: SandboxBootGeneration,
        presented: SandboxBootGeneration,
    },
    TooManyOverlays {
        limit: usize,
    },
}

impl fmt::Display for OverlayRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SharedMutableCache => f.write_str("shared mutable caches are not allowed"),
            Self::ImporterIsConsumer => f.write_str("the importer cannot consume its own import"),
            Self::NotReadable { object, refusal } => write!(f, "{object}: {refusal}"),
            Self::AlreadyBound { .. } => {
                f.write_str("this sandbox generation already has the overlay")
            }
            Self::UnknownOverlay => f.write_str("no such overlay"),
            Self::OtherSandbox => f.write_str("the overlay belongs to another sandbox"),
            Self::StaleGeneration { bound, presented } => {
                write!(f, "bound for generation {bound}, presented {presented}")
            }
            Self::TooManyOverlays { limit } => write!(f, "at most {limit} overlays"),
        }
    }
}

impl std::error::Error for OverlayRefusal {}

/// The overlays bound so far, each to one sandbox and generation.
pub struct OverlayRegistry {
    clock: Arc<dyn Clock>,
    overlays: BTreeMap<OverlayId, OverlayDescriptor>,
    max_overlays: usize,
}

impl fmt::Debug for OverlayRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OverlayRegistry")
            .field("overlays", &self.overlays.len())
            .field("max_overlays", &self.max_overlays)
            .finish()
    }
}

impl OverlayRegistry {
    /// An empty registry that binds at most `max_overlays` overlays, stamping each with
    /// `clock`.
    pub fn new(clock: Arc<dyn Clock>, max_overlays: usize) -> Self {
        Self {
            clock,
            overlays: BTreeMap::new(),
            max_overlays,
        }
    }

    /// Binds a new overlay for `request.sandbox` at `request.generation`.
    pub fn bind(
        &mut self,
        catalog: &mut Catalog,
        request: OverlayRequest,
    ) -> Result<OverlayDescriptor, OverlayRefusal> {
        if let WritableCache::Shared { .. } = request.writable {
            return Err(OverlayRefusal::SharedMutableCache);
        }
        if request.sandbox == request.image.importer {
            return Err(OverlayRefusal::ImporterIsConsumer);
        }
        let overlay = OverlayId::new(&request.sandbox, request.generation, request.image.tree);
        if self.overlays.contains_key(&overlay) {
            return Err(OverlayRefusal::AlreadyBound { overlay });
        }
        if self.overlays.len() >= self.max_overlays {
            return Err(OverlayRefusal::TooManyOverlays {
                limit: self.max_overlays,
            });
        }
        let mut objects = vec![request.image.tree];
        objects.extend(request.image.layers.iter().copied());
        objects.sort();
        objects.dedup();
        let mut leases = Vec::with_capacity(objects.len());
        for object in objects {
            match catalog.acquire_lease(
                &request.reader,
                &request.sandbox,
                object,
                request.lease_duration,
            ) {
                Ok(lease) => leases.push((object, lease)),
                Err(refusal) => {
                    for (_, lease) in leases {
                        let _ = catalog.release_lease(&request.reader, &request.sandbox, lease);
                    }
                    return Err(OverlayRefusal::NotReadable { object, refusal });
                }
            }
        }
        let descriptor = OverlayDescriptor {
            overlay,
            sandbox: request.sandbox.clone(),
            generation: request.generation,
            reader: request.reader,
            base_owner: request.image.owner,
            tree: request.image.tree,
            layers: request.image.layers,
            leases,
            upper: UpperLayer {
                owner: request.sandbox,
                generation: request.generation,
                shared: false,
            },
            materialization: Materialization::InsideGuestOnly,
            bound_at: self.clock.now(),
        };
        self.overlays.insert(overlay, descriptor.clone());
        Ok(descriptor)
    }

    /// The overlay, for its own sandbox at its own generation only.
    pub fn attach(
        &self,
        overlay: OverlayId,
        sandbox: &ExecutionId,
        generation: SandboxBootGeneration,
    ) -> Result<&OverlayDescriptor, OverlayRefusal> {
        let descriptor = self
            .overlays
            .get(&overlay)
            .ok_or(OverlayRefusal::UnknownOverlay)?;
        if descriptor.sandbox != *sandbox {
            return Err(OverlayRefusal::OtherSandbox);
        }
        if descriptor.generation != generation {
            return Err(OverlayRefusal::StaleGeneration {
                bound: descriptor.generation,
                presented: generation,
            });
        }
        Ok(descriptor)
    }

    /// Releases the overlay and its leases; only its sandbox may.
    pub fn release(
        &mut self,
        catalog: &mut Catalog,
        overlay: OverlayId,
        sandbox: &ExecutionId,
    ) -> Result<(), OverlayRefusal> {
        let owned = self
            .overlays
            .get(&overlay)
            .ok_or(OverlayRefusal::UnknownOverlay)?
            .sandbox
            == *sandbox;
        if !owned {
            return Err(OverlayRefusal::OtherSandbox);
        }
        if let Some(descriptor) = self.overlays.remove(&overlay) {
            for (_, lease) in descriptor.leases {
                let _ = catalog.release_lease(&descriptor.reader, &descriptor.sandbox, lease);
            }
        }
        Ok(())
    }

    /// How many overlays are bound.
    pub fn len(&self) -> usize {
        self.overlays.len()
    }

    /// Whether no overlay is bound.
    pub fn is_empty(&self) -> bool {
        self.overlays.is_empty()
    }
}
