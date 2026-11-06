//! Adapters on an active model (G06 of docs/combined-plan-leftover-tasks.md; GPU-W10 of
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, line 1296: "Test adapter switching
//! and independently materialized merged variants", with its acceptance at line 1300: no
//! cross-tenant state reuse, and request shape changes cannot overrun reserved memory;
//! GPU §3.9, lines 793–797).
//!
//! [`ActiveAdapters`] keeps, for one serving activation, the unmerged adapters attached to
//! it, the merged variants of its base, the requests in flight on each and the KV each
//! produced. The compatibility, authorization and KV keys are P07's and T07's; this module
//! binds them to one activation, its reservation and its requests:
//!
//! - **Attach and switch.** An adapter is attached only after P07's compatibility check
//!   ([`check_compatibility`]) against the activation's base, for a caller holding a T07
//!   scoped grant to serve its artifact ([`GrantedUse::Serve`]), and while the coordination
//!   authority has not revoked the adapter's grant ([`adapter_grant_id`]). Its device
//!   memory is a CORE-03 reservation carved from the activation's own reservation as a
//!   child, within the limits the backend declares ([`BackendAdapterLimits`]: rank, count
//!   and bytes), as the KV pool grows ([`crate::model_memory::boundaries::KvSpec`]): an
//!   adapter larger than the limits is refused, one that fits once other adapters are
//!   released waits ([`AttachRefusal::AwaitingRelease`]), and a ledger refusal names the
//!   limiting resource. A session switches adapters through T07's [`AdaptedModel::apply`],
//!   one unmerged adapter at a time, and only onto an attached adapter.
//! - **Merged variants.** A merged variant ([`MergedVariant`]) has its own T07 identity and
//!   names every input: the canonical base and each merged adapter. A request is served
//!   from it only for a caller holding a grant to serve every input, and never while any
//!   input's grant is revoked.
//! - **KV keyed by adapter.** Each KV state is recorded under the [`Route`] that produced
//!   it: the base, one adapter or one merged variant. P07's reuse check
//!   ([`super::kv::check_kv_reuse`]) runs only for a request admitted on that same route,
//!   whose KV request names that route's model and adapter, so KV is never served under
//!   another adapter or variant.
//! - **Revocation.** The coordination authority revokes an adapter's grant on its own
//!   ([`Coordinator::revoke_grant`], or `revoke_grant_and_publish`), leaving the epoch and
//!   every other grant in force. Every attach and admission asks the authority first
//!   ([`GrantRevocations`]), so new requests are denied from its tombstone on, before its
//!   record arrives. The record ([`RevokedGrant`]) then detaches the adapter, invalidates
//!   every merged variant built from it and every KV state produced under either, and
//!   starts the drain: each request in flight on them is cancelled with its declared bound
//!   (INT-02; VM part §6.3 steps 2–3), stopping at its next cancellation boundary and by
//!   that bound at the latest, and the adapter's reservation is released through the
//!   ledger only once no such request remains and the runner reported the adapter
//!   unloaded (GPU §3.6 steps 6–7, lines 755–756). A plain detach drains the same way,
//!   except that its requests may finish within their bound. Revocation never waits for
//!   that cleanup (VM part §6.5). A request admitted with [`ActiveAdapters::admit_bound`]
//!   binds its coordinator lease to the grant of every adapter it is served with
//!   ([`LeaseGrants`]), so the revocation itself cancels it with its own declared bound.
//! - **Whole-authority revocation.** Revoking the activation's authority advances its
//!   authorization epoch (CORE-04; INT-02): from then on nothing is attached, admitted,
//!   switched or recorded here, every adapter is detached, every variant and every KV
//!   state is dropped, and every request drains by its bound
//!   ([`ActiveAdapters::apply_authority_revocation`]).
//! - **Limits and waits.** The backend's limits come from CORE-01 `AdapterLimits` evidence
//!   about the exact runtime ([`evidenced_adapter_limits`]), and an attachment that must
//!   wait for a slot or bytes keeps its place first in, first out
//!   ([`crate::model_memory::boundaries::WaitQueue`]).
//! - **Variant memory.** A merged variant materialized on the activation holds its device
//!   memory as a CORE-03 child of the activation's reservation, released through the
//!   ledger only once it is retired or invalidated and no request uses it
//!   ([`ActiveAdapters::materialize_variant`]).
//!
//! The calls a runner makes are listed on [`ActiveAdapters`]. Pure, synchronous code: time
//! is passed in from the shared clock, and the ledger is reached only through the host.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::foundation::coordination::{CapacityPort, Coordinator, RevokedGrant};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, Digest, DigestBuilder, ExecutionId, GpuDeviceKey, GrantId, LeaseId,
    MonotonicTime, OperationId, TenantId, TrustScope,
};
use crate::foundation::ledger::{
    Admission, Amounts, CostPurpose, Ledger, LedgerError, Provenance, ReleaseOutcome, Requester,
    ReservationId, ReservationRequest,
};
use crate::model_memory::boundaries::{
    CapacityRefusal, HostLedger, WaitDemand, WaitLimits, WaitQueue, WaitTurn,
};
use crate::model_memory::identity::{
    check_grant, AdaptedModel, AdapterChange, AdapterIdentity, AdapterRecipe, ArtifactIdentity,
    ExecutionIdentity, ExecutionSpec, GrantNeed, GrantRefusal, GrantedUse, LogicalModelIdentity,
    LogicalModelSpec, RevocationPort, ScopeEnforcement, ScopedGrant,
};

use super::adapter::{check_compatibility, AdapterLimits, AdapterReference, LayerTable};
use super::kv::{self, kv_state_key, KvRequest, KvReuseGrant, PublicPrefixSharing, StoredKv};

mod authority;
mod binding;
mod limits;
mod refusals;
mod variants;

pub use authority::AuthorityRevocationEffects;
pub use binding::LeaseGrants;
pub use limits::{evidenced_adapter_limits, AdapterLimitsRefusal, EvidencedAdapterLimits};
pub use refusals::{
    AdapterKvRefusal, AttachRefusal, DetachRefusal, KvRecordRefusal, ReleaseRefusal,
    RequestRefusal, RouteRefusal, SwitchRefusal, VariantRefusal,
};
pub use variants::{VariantReceipt, VariantReleaseRefusal, VariantView};

/// Domain of [`adapter_grant_id`].
pub const ADAPTER_GRANT_DOMAIN: &str = "yougori/model-memory/adapters/serve-adapter-grant/v1";

/// The grant to serve one adapter under an authority, as the coordination authority names
/// it: the host revokes exactly this identity under the activation's parent execution
/// ([`Coordinator::revoke_grant`]) to withdraw the adapter there and nothing else.
pub fn adapter_grant_id(adapter: &AdapterIdentity) -> GrantId {
    GrantId::from_digest(
        DigestBuilder::new(ADAPTER_GRANT_DOMAIN)
            .digest(adapter.digest())
            .finish(),
    )
}

/// Whether the coordination authority revoked one grant under an execution's authority
/// (CORE-04 per-grant revocation). This is the authoritative check of VM part §6.3: every
/// attach and admission asks it, so a revocation denies new requests from its tombstone
/// on, whether or not its record has reached [`ActiveAdapters::apply_revocation`].
pub trait GrantRevocations {
    /// True once `grant` was revoked under `execution`; it is never honoured there again.
    fn is_revoked(&self, execution: &ExecutionId, grant: GrantId) -> bool;

    /// True once `epoch` of `execution`'s authority is no longer in force: the authority
    /// was revoked, which advances its authorization epoch, or `execution` is unknown
    /// (CORE-04; INT-02). Nothing bound to that epoch is honoured again.
    fn authority_revoked(&self, execution: &ExecutionId, epoch: AuthorizationEpoch) -> bool;
}

impl<C: Clock, P: CapacityPort> GrantRevocations for Coordinator<C, P> {
    fn is_revoked(&self, execution: &ExecutionId, grant: GrantId) -> bool {
        self.grant_revoked(execution, grant)
    }

    fn authority_revoked(&self, execution: &ExecutionId, epoch: AuthorizationEpoch) -> bool {
        let current = match self.sandbox(execution) {
            Some(sandbox) => Some(sandbox.generations().authorization),
            None => self
                .labelled_runtime(execution)
                .map(|runtime| runtime.epoch()),
        };
        current != Some(epoch)
    }
}

/// What attaching and releasing adapters reach on the host: the coordination authority's
/// per-grant revocations and the CORE-03 ledger behind its capacity port. A
/// [`Coordinator`] over a [`HostLedger`] is one.
pub trait AdapterHost: GrantRevocations {
    /// The ledger's clock.
    type Clock: Clock;

    /// Runs `write` on the ledger.
    fn write_ledger<R>(&mut self, write: impl FnOnce(&mut Ledger<Self::Clock>) -> R) -> R;
}

impl<C: Clock, P: HostLedger<C>> AdapterHost for Coordinator<C, P> {
    type Clock = C;

    fn write_ledger<R>(&mut self, write: impl FnOnce(&mut Ledger<C>) -> R) -> R {
        self.capacity_mut().write_ledger(write)
    }
}

/// What the pinned backend accepts for unmerged adapters on one activation: CORE-01
/// `AdapterLimits` evidence about the exact runtime ([`evidenced_adapter_limits`], with
/// [`ActiveAdapters::with_evidenced_limits`]). Declared limits ([`ActiveAdapters::new`])
/// serve fixtures and backends adopted before that evidence exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendAdapterLimits {
    /// The engine's rank limit, which P07's compatibility check applies.
    pub rank: AdapterLimits,
    /// The most adapters resident at once, such as the slots of its batched adapter
    /// kernels.
    pub max_resident: u32,
    /// The most device bytes the resident adapters may hold together.
    pub max_bytes: u64,
}

/// The serving activation adapters attach to (GPU §3.6, §3.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveBase {
    /// The base's logical identity, which every adapter must have been made for.
    pub logical: LogicalModelIdentity,
    /// The base as executed: the model of every KV state computed on this activation
    /// without a merged variant.
    pub execution: ExecutionIdentity,
    /// The base's adaptable layers.
    pub layers: LayerTable,
    /// The parent execution the activation serves under, whose grants the coordination
    /// authority revokes.
    pub authority: ExecutionId,
    /// The authorization epoch of that authority the activation was published under;
    /// once it is revoked nothing here is honoured again.
    pub epoch: AuthorizationEpoch,
    /// Where requests are served; every scoped grant is checked for this trust scope.
    pub trust_scope: TrustScope,
    /// The CORE-03 reservation of the activation's own GPU memory, open and in use;
    /// adapters are carved from it.
    pub reservation: ReservationId,
    /// The device the activation runs on.
    pub device: GpuDeviceKey,
}

/// An artifact and the tenant that owns it: what a caller needs a scoped grant for
/// (S3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedArtifact {
    pub owner: TenantId,
    pub artifact: ArtifactIdentity,
}

/// An adapter to attach.
#[derive(Clone, Debug, PartialEq)]
pub struct AdapterAttachment {
    pub reference: AdapterReference,
    /// The adapter's artifact and its owner.
    pub artifact: OwnedArtifact,
    /// The device bytes the adapter holds once loaded, as the runner adapter computes them
    /// for its backend.
    pub bytes: u64,
}

/// Who a request or an attachment is for, and the scoped grants they present (S3.3).
/// Every grant is checked against the catalog again at each use.
#[derive(Clone, Copy, Debug)]
pub struct Caller<'a> {
    pub tenant: &'a TenantId,
    pub grants: &'a [ScopedGrant],
}

/// Which weights and adapter a request is served with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Route {
    /// The activation's base, with no adapter.
    Base,
    /// The base with one attached, unmerged adapter.
    Adapter(AdapterIdentity),
    /// A merged variant of the base, by its execution identity.
    Merged(ExecutionIdentity),
}

/// What a caller needs a grant to serve: the base or one adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Input {
    Base,
    Adapter(AdapterIdentity),
}

/// A merged variant of the active base, with every input it was materialized from
/// (GPU §3.9 line 795; §1.1, line 308).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergedVariant {
    /// The variant's logical model: the base's spec with its adapters merged, as T07's
    /// `LogicalModelSpec::with_merged` makes it.
    pub logical: LogicalModelSpec,
    /// The variant as executed; it must execute `logical`.
    pub execution: ExecutionSpec,
    /// The canonical base's artifact and owner.
    pub base: OwnedArtifact,
    /// Each merged adapter's artifact and owner, one for every adapter in the recipe.
    pub adapters: BTreeMap<AdapterIdentity, OwnedArtifact>,
}

/// Why an adapter was detached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetachCause {
    /// The runner detached it, as to free its slot for a switch.
    Detached,
    /// The coordination authority revoked its grant.
    Revoked { grant: GrantId },
    /// The coordination authority revoked the activation's whole authority at `epoch`.
    AuthorityRevoked { epoch: AuthorizationEpoch },
}

/// One attached adapter as the registry holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachmentView {
    pub bytes: u64,
    /// Its CORE-03 reservation, a child of the activation's.
    pub reservation: ReservationId,
    /// `None` while it serves new requests.
    pub detached: Option<DetachCause>,
    /// Requests still in flight on it.
    pub in_flight: usize,
}

/// What attaching produced: the adapter's reservation. Load the adapter into the backend
/// when `newly_attached`; otherwise it is resident already.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachReceipt {
    pub adapter: AdapterIdentity,
    pub reservation: ReservationId,
    pub bytes: u64,
    pub newly_attached: bool,
}

/// A request admitted on one route. Made only by [`ActiveAdapters::admit`]; KV is recorded
/// and reused only under it.
#[derive(Debug, PartialEq, Eq)]
pub struct AdapterUse {
    lease: LeaseId,
    route: Route,
    model: ExecutionIdentity,
    adapter: Option<AdapterIdentity>,
}

impl AdapterUse {
    /// The execution lease the request holds.
    pub fn lease(&self) -> LeaseId {
        self.lease
    }

    pub fn route(&self) -> Route {
        self.route
    }

    /// The model as executed: the base, or the merged variant.
    pub fn model(&self) -> ExecutionIdentity {
        self.model
    }

    /// The unmerged adapter, if any.
    pub fn adapter(&self) -> Option<AdapterIdentity> {
        self.adapter
    }
}

/// How a request in flight stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestStanding {
    Serving,
    /// Its route was detached or revoked: it must stop by `bound_at`. Under a revoked
    /// grant it stops at its next cancellation boundary (VM part §6.3 step 2); after a
    /// plain detach it may finish within the bound.
    Draining {
        bound_at: MonotonicTime,
        revoked: Option<GrantId>,
    },
    /// The activation's whole authority was revoked at `epoch`: the request stops at its
    /// next cancellation boundary, and by `bound_at` at the latest (INT-02).
    AuthorityRevoked {
        bound_at: MonotonicTime,
        epoch: AuthorizationEpoch,
    },
}

/// A request in flight on a detached adapter or an invalidated variant, and the bound by
/// which it must stop (INT-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrainingRequest {
    pub lease: LeaseId,
    pub route: Route,
    pub bound_at: MonotonicTime,
    /// The revoked grant that cancelled it; `None` after a plain detach, a retirement or a
    /// revocation of the whole authority.
    pub revoked: Option<GrantId>,
}

/// Requests that must stop, and adapters and variants ready to unload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Drain {
    /// Requests in flight on a detached adapter or an invalidated variant, each with the
    /// bound by which it must stop.
    pub draining: Vec<DrainingRequest>,
    /// Detached adapters nothing uses any more: unload each from the backend, then call
    /// [`ActiveAdapters::release_unloaded`].
    pub unload: Vec<AdapterIdentity>,
    /// Retired or invalidated variants holding memory here that nothing uses any more:
    /// unload each, then call [`ActiveAdapters::release_variant`].
    pub unload_variants: Vec<ExecutionIdentity>,
}

/// What applying one grant revocation did. The revocation is in force either way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationEffects {
    pub grant: GrantId,
    /// Adapters detached for new requests.
    pub detached: Vec<AdapterIdentity>,
    /// Merged variants built from a revoked adapter, now refused to everyone: retire their
    /// activations.
    pub variants: Vec<ExecutionIdentity>,
    /// KV states produced under a detached adapter or an invalidated variant, by
    /// [`kv_state_key`]: drop them.
    pub kv: Vec<Digest>,
    pub drain: Drain,
}

/// Requests that passed their drain bound, and adapters that became ready to unload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Overdue {
    /// Requests whose bound passed: the runner must have stopped them, and their
    /// records end.
    pub ended: Vec<DrainingRequest>,
    pub unload: Vec<AdapterIdentity>,
    pub unload_variants: Vec<ExecutionIdentity>,
}

/// What P07's KV reuse check reads besides the KV and the request.
#[derive(Clone, Copy)]
pub struct KvReuseContext<'a> {
    pub sharing: &'a PublicPrefixSharing,
    /// The coordination authority's revocations of whole authorities (T09).
    pub revocations: &'a dyn RevocationPort,
    pub enforcement: &'a ScopeEnforcement,
    pub now: MonotonicTime,
}

#[derive(Clone, Debug, PartialEq)]
struct Attached {
    artifact: OwnedArtifact,
    bytes: u64,
    reservation: ReservationId,
    detached: Option<DetachCause>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Variant {
    base: OwnedArtifact,
    adapters: BTreeMap<AdapterIdentity, OwnedArtifact>,
    invalidated: Option<GrantId>,
    /// Its CORE-03 child of the activation's reservation and its bytes, when it was
    /// materialized here.
    memory: Option<(ReservationId, u64)>,
    /// Retired by the runner: it serves no new request.
    retired: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InFlight {
    route: Route,
    bound: Option<MonotonicTime>,
    revoked: Option<GrantId>,
    /// Cancelled by a revocation of the whole authority.
    authority: bool,
}

/// The adapters, merged variants, requests and KV of one serving activation (G06,
/// GPU-W10).
///
/// What a runner calls, in order:
///
/// 1. When the activation is published, [`ActiveAdapters::new`] with the activation's own
///    GPU reservation (the coordinator's GPU holding of the generation), the limits its
///    adapter declares for the backend, and the drain bound of its leases
///    (`LeaseTerms::cancel_within`).
/// 2. To load an adapter, [`ActiveAdapters::attach`]; on a new attachment, load it into
///    the backend. To free a slot, [`ActiveAdapters::detach`].
/// 3. To record a merged variant once it is materialized,
///    [`ActiveAdapters::record_variant`].
/// 4. For each request, after the governor leased it, [`ActiveAdapters::admit`] on its
///    route; at every cancellation boundary, [`ActiveAdapters::check_request`]; for KV it
///    produced, [`ActiveAdapters::record_kv`]; before reusing stored KV,
///    [`ActiveAdapters::check_kv_reuse`]; when it ends, [`ActiveAdapters::finish`]. A
///    session changes its adapter with [`ActiveAdapters::switch_session`].
/// 5. On every [`RevokedGrant`] the coordinator issues for the activation's authority,
///    [`ActiveAdapters::apply_revocation`]: stop each draining request by its bound, drop
///    the KV and retire the variants it lists. Periodically, [`ActiveAdapters::end_overdue`].
/// 6. For each adapter in a [`Drain::unload`], unload it from the backend, then
///    [`ActiveAdapters::release_unloaded`] with the runner's own report.
#[derive(Debug)]
pub struct ActiveAdapters {
    base: ActiveBase,
    limits: BackendAdapterLimits,
    drain_bound: Duration,
    attached: BTreeMap<AdapterIdentity, Attached>,
    variants: BTreeMap<ExecutionIdentity, Variant>,
    requests: BTreeMap<LeaseId, InFlight>,
    kv: BTreeMap<Digest, Route>,
    /// The grants revoked under the activation's authority, from their records.
    revoked: BTreeSet<GrantId>,
    /// Until when the limits' CORE-01 evidence may be relied on for new attachments;
    /// `None` for declared limits.
    limits_until: Option<MonotonicTime>,
    /// Attachments waiting for a slot or bytes, first in line first.
    attach_waits: WaitQueue<AdapterIdentity>,
    /// The epoch of the activation's authority whose revocation was applied here.
    authority_revoked: Option<AuthorizationEpoch>,
}

impl ActiveAdapters {
    /// No adapter attached to `base` yet, with `limits` as declared for the backend.
    /// `drain_bound` is how long a request in flight on a detached adapter may still run
    /// when its own cancellation names no bound. A runtime with CORE-01 evidence of its
    /// limits uses [`ActiveAdapters::with_evidenced_limits`].
    pub fn new(base: ActiveBase, limits: BackendAdapterLimits, drain_bound: Duration) -> Self {
        Self {
            base,
            limits,
            drain_bound,
            attached: BTreeMap::new(),
            variants: BTreeMap::new(),
            requests: BTreeMap::new(),
            kv: BTreeMap::new(),
            revoked: BTreeSet::new(),
            limits_until: None,
            attach_waits: WaitQueue::new(WaitLimits::DEFAULT),
            authority_revoked: None,
        }
    }

    pub fn base(&self) -> &ActiveBase {
        &self.base
    }

    pub fn limits(&self) -> BackendAdapterLimits {
        self.limits
    }

    /// How many adapters hold memory: attached, draining or awaiting release.
    pub fn resident_count(&self) -> usize {
        self.attached.len()
    }

    /// The device bytes the resident adapters hold.
    pub fn resident_bytes(&self) -> u64 {
        self.attached
            .values()
            .fold(0u64, |total, attached| total.saturating_add(attached.bytes))
    }

    /// One attached adapter, if it holds memory.
    pub fn attachment(&self, adapter: &AdapterIdentity) -> Option<AttachmentView> {
        let attached = self.attached.get(adapter)?;
        Some(AttachmentView {
            bytes: attached.bytes,
            reservation: attached.reservation,
            detached: attached.detached,
            in_flight: self.leases_on(Route::Adapter(*adapter)).len(),
        })
    }

    /// The grant that invalidated a recorded merged variant: `Some(None)` while it is
    /// valid, `None` if it was never recorded.
    pub fn variant_invalidated_by(&self, variant: &ExecutionIdentity) -> Option<Option<GrantId>> {
        self.variants.get(variant).map(|entry| entry.invalidated)
    }

    /// The route a recorded KV state was produced under.
    pub fn kv_route(&self, key: &Digest) -> Option<Route> {
        self.kv.get(key).copied()
    }

    /// Attaches an adapter for `caller`, or confirms it is attached (GPU §3.9 line 793).
    ///
    /// In order: the activation's authority must stand and the adapter's grant must not be
    /// revoked under it (asked of `host`); the caller must hold a grant to serve the
    /// adapter's artifact in the activation's trust scope at `now`; an adapter already
    /// attached is returned as it is, unless it is being detached; otherwise P07's
    /// compatibility check against the base, then the backend's limits, current at `now`
    /// when they came from evidence, then its turn among the attachments waiting first in,
    /// first out, then a CORE-03 child of the activation's reservation for its bytes, in
    /// use at once. A refusal reserves nothing; one that waits keeps its place.
    pub fn attach<H: AdapterHost>(
        &mut self,
        host: &mut H,
        attachment: AdapterAttachment,
        caller: &Caller<'_>,
        operation: &OperationId,
        now: MonotonicTime,
    ) -> Result<AttachReceipt, AttachRefusal> {
        let adapter = attachment.reference.adapter;
        self.authority_stands(&*host)
            .map_err(|epoch| AttachRefusal::AuthorityRevoked { epoch })?;
        let grant = adapter_grant_id(&adapter);
        if self.grant_revoked(grant, &*host) {
            return Err(AttachRefusal::Revoked { grant });
        }
        if let Some(attached) = self.attached.get(&adapter) {
            authorize(caller, &attached.artifact, &self.base.trust_scope, now)
                .map_err(AttachRefusal::Unauthorized)?;
            return match attached.detached {
                None => Ok(AttachReceipt {
                    adapter,
                    reservation: attached.reservation,
                    bytes: attached.bytes,
                    newly_attached: false,
                }),
                Some(DetachCause::Revoked { grant }) => Err(AttachRefusal::Revoked { grant }),
                Some(DetachCause::AuthorityRevoked { epoch }) => {
                    Err(AttachRefusal::AuthorityRevoked { epoch })
                }
                Some(DetachCause::Detached) => Err(AttachRefusal::StillDetaching { adapter }),
            };
        }
        authorize(caller, &attachment.artifact, &self.base.trust_scope, now)
            .map_err(AttachRefusal::Unauthorized)?;
        check_compatibility(
            &self.base.logical,
            &self.base.layers,
            &attachment.reference,
            &self.limits.rank,
        )
        .map_err(AttachRefusal::Incompatible)?;
        self.limits_current(now)?;
        self.fits(adapter, attachment.bytes, now)?;
        let (parent, device, bytes) = (self.base.reservation, self.base.device, attachment.bytes);
        let carved = host.write_ledger(|ledger| carve(ledger, parent, device, operation, bytes));
        self.attach_waits.leave(&adapter);
        let reservation = carved?;
        self.attached.insert(
            adapter,
            Attached {
                artifact: attachment.artifact,
                bytes,
                reservation,
                detached: None,
            },
        );
        Ok(AttachReceipt {
            adapter,
            reservation,
            bytes,
            newly_attached: true,
        })
    }

    /// Detaches an adapter for new requests, as to free its slot for a switch. Requests in
    /// flight on it may run until `now` plus the drain bound; once none remains, it is
    /// listed to unload.
    pub fn detach(
        &mut self,
        adapter: AdapterIdentity,
        now: MonotonicTime,
    ) -> Result<Drain, DetachRefusal> {
        let attached = self
            .attached
            .get_mut(&adapter)
            .ok_or(DetachRefusal::NotAttached { adapter })?;
        if let Some(cause) = attached.detached {
            return Err(DetachRefusal::AlreadyDetached { adapter, cause });
        }
        attached.detached = Some(DetachCause::Detached);
        let bound = now.saturating_add(self.drain_bound);
        let draining = self.bound_requests(Route::Adapter(adapter), None, |_| bound);
        let unload = if self.unloadable(&adapter) {
            vec![adapter]
        } else {
            Vec::new()
        };
        Ok(Drain {
            draining,
            unload,
            unload_variants: Vec::new(),
        })
    }

    /// Switches a session on this activation's base to the unmerged adapter `to`, or to
    /// none, through T07's rules: one unmerged adapter at a time, detached before another
    /// is attached. The target must be attached, serving and not revoked. The session's KV
    /// stays keyed by the adapter that produced it, so none of it is served after the
    /// switch.
    pub fn switch_session(
        &self,
        session: &AdaptedModel,
        to: Option<AdapterIdentity>,
        grants: &dyn GrantRevocations,
    ) -> Result<AdaptedModel, SwitchRefusal> {
        if session.logical.identity() != self.base.logical {
            return Err(SwitchRefusal::OtherBase);
        }
        self.authority_stands(grants)
            .map_err(|epoch| SwitchRefusal::Route(RouteRefusal::AuthorityRevoked { epoch }))?;
        if let Some(adapter) = to {
            self.serving_adapter(adapter, grants)
                .map_err(SwitchRefusal::Route)?;
        }
        let detached = match session.unmerged {
            Some(_) => session
                .apply(&AdapterChange::DetachUnmerged)
                .map_err(SwitchRefusal::Lora)?,
            None => session.clone(),
        };
        match to {
            Some(adapter) => detached
                .apply(&AdapterChange::AttachUnmerged(adapter))
                .map_err(SwitchRefusal::Lora),
            None => Ok(detached),
        }
    }

    /// Records a merged variant of the base once it is materialized, with every input it
    /// was made from (GPU §3.9 line 795). The variant must merge at least one adapter into
    /// exactly this activation's base, execute its own logical identity, name an input for
    /// each merged adapter and no other, and no input's grant may be revoked. Recording
    /// one already recorded keeps the first record.
    pub fn record_variant(
        &mut self,
        variant: MergedVariant,
        grants: &dyn GrantRevocations,
    ) -> Result<ExecutionIdentity, VariantRefusal> {
        self.authority_stands(grants)
            .map_err(|epoch| VariantRefusal::AuthorityRevoked { epoch })?;
        let AdapterRecipe::Merged(merged) = &variant.logical.adapters else {
            return Err(VariantRefusal::NotMerged);
        };
        let base = LogicalModelSpec {
            adapters: AdapterRecipe::None,
            ..variant.logical.clone()
        }
        .identity();
        if base != self.base.logical {
            return Err(VariantRefusal::OtherBase { base });
        }
        let execution = variant
            .execution
            .identity()
            .map_err(VariantRefusal::Execution)?;
        if variant.execution.logical != variant.logical.identity() {
            return Err(VariantRefusal::ExecutesAnotherModel);
        }
        let recipe: BTreeSet<AdapterIdentity> = merged
            .adapters()
            .iter()
            .map(|entry| entry.adapter)
            .collect();
        if let Some(adapter) = recipe
            .iter()
            .find(|adapter| !variant.adapters.contains_key(adapter))
        {
            return Err(VariantRefusal::MissingInput { adapter: *adapter });
        }
        if let Some(adapter) = variant
            .adapters
            .keys()
            .find(|adapter| !recipe.contains(adapter))
        {
            return Err(VariantRefusal::UnknownInput { adapter: *adapter });
        }
        for adapter in &recipe {
            let grant = adapter_grant_id(adapter);
            if self.grant_revoked(grant, grants) {
                return Err(VariantRefusal::InputRevoked {
                    adapter: *adapter,
                    grant,
                });
            }
        }
        self.variants.entry(execution).or_insert(Variant {
            base: variant.base,
            adapters: variant.adapters,
            invalidated: None,
            memory: None,
            retired: false,
        });
        Ok(execution)
    }

    /// Admits one request, under its execution `lease`, on `route` for `caller` at `now`.
    ///
    /// The base needs nothing beyond the activation's own admission. An adapter must be
    /// attached and serving, its grant not revoked (asked of `grants`), and the caller must
    /// hold a grant to serve its artifact. A merged variant must be recorded and valid, no
    /// input's grant revoked, and the caller must hold a grant to serve every input: the
    /// base and each merged adapter.
    pub fn admit(
        &mut self,
        lease: LeaseId,
        route: Route,
        caller: &Caller<'_>,
        grants: &dyn GrantRevocations,
        now: MonotonicTime,
    ) -> Result<AdapterUse, RouteRefusal> {
        if self.requests.contains_key(&lease) {
            return Err(RouteRefusal::LeaseInUse { lease });
        }
        self.authority_stands(grants)
            .map_err(|epoch| RouteRefusal::AuthorityRevoked { epoch })?;
        let scope = &self.base.trust_scope;
        let (model, adapter) = match route {
            Route::Base => (self.base.execution, None),
            Route::Adapter(adapter) => {
                let attached = self.serving_adapter(adapter, grants)?;
                authorize(caller, &attached.artifact, scope, now).map_err(|refusal| {
                    RouteRefusal::Unauthorized {
                        input: Input::Adapter(adapter),
                        refusal,
                    }
                })?;
                (self.base.execution, Some(adapter))
            }
            Route::Merged(variant) => {
                let entry = self.serving_variant(variant, grants)?;
                if entry.retired {
                    return Err(RouteRefusal::VariantRetired { variant });
                }
                authorize(caller, &entry.base, scope, now).map_err(|refusal| {
                    RouteRefusal::Unauthorized {
                        input: Input::Base,
                        refusal,
                    }
                })?;
                for (adapter, artifact) in &entry.adapters {
                    authorize(caller, artifact, scope, now).map_err(|refusal| {
                        RouteRefusal::Unauthorized {
                            input: Input::Adapter(*adapter),
                            refusal,
                        }
                    })?;
                }
                (variant, None)
            }
        };
        self.requests.insert(
            lease,
            InFlight {
                route,
                bound: None,
                revoked: None,
                authority: false,
            },
        );
        Ok(AdapterUse {
            lease,
            route,
            model,
            adapter,
        })
    }

    /// How the request holding `lease` stands at `now`. A draining request may run until
    /// its bound and no longer (INT-02); the runner asks at each cancellation boundary.
    pub fn check_request(
        &self,
        lease: LeaseId,
        now: MonotonicTime,
    ) -> Result<RequestStanding, RequestRefusal> {
        let request = self
            .requests
            .get(&lease)
            .ok_or(RequestRefusal::UnknownRequest { lease })?;
        match request.bound {
            None => Ok(RequestStanding::Serving),
            Some(bound_at) if now >= bound_at => {
                Err(RequestRefusal::DrainBoundPassed { lease, bound_at })
            }
            Some(bound_at) if request.authority => Ok(RequestStanding::AuthorityRevoked {
                bound_at,
                epoch: self.base.epoch,
            }),
            Some(bound_at) => Ok(RequestStanding::Draining {
                bound_at,
                revoked: request.revoked,
            }),
        }
    }

    /// The request holding `lease` ended. Returns the adapter that became ready to unload,
    /// if it was the last request on a detached adapter; a variant that became ready is
    /// listed by [`ActiveAdapters::unloadable_variants`].
    pub fn finish(&mut self, lease: LeaseId) -> Option<AdapterIdentity> {
        let request = self.requests.remove(&lease)?;
        match request.route {
            Route::Adapter(adapter) if self.unloadable(&adapter) => Some(adapter),
            _ => None,
        }
    }

    /// Ends every request whose drain bound passed by `now`: the runner must have stopped
    /// it. Returns them, with the adapters and variants that became ready to unload.
    pub fn end_overdue(&mut self, now: MonotonicTime) -> Overdue {
        let mut ended = Vec::new();
        self.requests.retain(|lease, request| match request.bound {
            Some(bound_at) if now >= bound_at => {
                ended.push(DrainingRequest {
                    lease: *lease,
                    route: request.route,
                    bound_at,
                    revoked: request.revoked,
                });
                false
            }
            _ => true,
        });
        let candidates: BTreeSet<AdapterIdentity> = ended
            .iter()
            .filter_map(|request| match request.route {
                Route::Adapter(adapter) => Some(adapter),
                _ => None,
            })
            .collect();
        let unload = candidates
            .into_iter()
            .filter(|adapter| self.unloadable(adapter))
            .collect();
        let variants: BTreeSet<ExecutionIdentity> = ended
            .iter()
            .filter_map(|request| match request.route {
                Route::Merged(variant) => Some(variant),
                _ => None,
            })
            .collect();
        let unload_variants = variants
            .into_iter()
            .filter(|variant| self.variant_unloadable(variant))
            .collect();
        Overdue {
            ended,
            unload,
            unload_variants,
        }
    }

    /// Releases a detached adapter's reservation through the ledger once the runner
    /// unloaded it, as `source` observed: its own report suffices for a child reservation
    /// (CORE-03). Refused while the adapter is attached or any request may still use it,
    /// so memory is never released under a request (GPU §3.6 step 7). A ledger refusal
    /// keeps the adapter counted; call again with an authoritative source.
    pub fn release_unloaded<H: AdapterHost>(
        &mut self,
        host: &mut H,
        adapter: AdapterIdentity,
        source: SourceClass,
    ) -> Result<ReleaseOutcome, ReleaseRefusal> {
        let attached = self
            .attached
            .get(&adapter)
            .ok_or(ReleaseRefusal::NotAttached { adapter })?;
        if attached.detached.is_none() {
            return Err(ReleaseRefusal::StillAttached { adapter });
        }
        let leases = self.leases_on(Route::Adapter(adapter));
        if !leases.is_empty() {
            return Err(ReleaseRefusal::StillInUse { adapter, leases });
        }
        let reservation = attached.reservation;
        let outcome = host
            .write_ledger(|ledger| match ledger.cancel(reservation) {
                Ok(ReleaseOutcome::Pending) => ledger.confirm_release(reservation, source),
                other => other,
            })
            .map_err(ReleaseRefusal::Ledger)?;
        self.attached.remove(&adapter);
        Ok(outcome)
    }

    /// Applies the coordination authority's revocation of one grant (CORE-04 per-grant
    /// revocation; VM part §6.3). A grant under another authority changes nothing.
    ///
    /// The adapter the grant names is detached for new requests; every merged variant with
    /// it as an input is invalidated; every KV state produced under either is dropped from
    /// the record. Each request in flight on them is cancelled with its declared bound: the
    /// bound the coordinator recorded for its lease, else the revocation time plus the
    /// drain bound. Applying the same revocation again changes nothing.
    pub fn apply_revocation(&mut self, revoked: &RevokedGrant) -> RevocationEffects {
        let grant = revoked.grant;
        let mut effects = RevocationEffects {
            grant,
            detached: Vec::new(),
            variants: Vec::new(),
            kv: Vec::new(),
            drain: Drain::default(),
        };
        if revoked.execution != self.base.authority {
            return effects;
        }
        self.revoked.insert(grant);
        let fallback = revoked.at.saturating_add(self.drain_bound);
        let bound_for = |lease: LeaseId| {
            revoked
                .cancellations
                .iter()
                .find(|cancellation| cancellation.lease == lease)
                .map_or(fallback, |cancellation| cancellation.bound_at)
        };
        let mut routes = BTreeSet::new();
        for (adapter, attached) in &mut self.attached {
            let named = adapter_grant_id(adapter) == grant;
            let revoked_already = matches!(
                attached.detached,
                Some(DetachCause::Revoked { .. } | DetachCause::AuthorityRevoked { .. })
            );
            if named && !revoked_already {
                attached.detached = Some(DetachCause::Revoked { grant });
                effects.detached.push(*adapter);
                routes.insert(Route::Adapter(*adapter));
            }
        }
        for (variant, entry) in &mut self.variants {
            let built_from = entry
                .adapters
                .keys()
                .any(|adapter| adapter_grant_id(adapter) == grant);
            if built_from && entry.invalidated.is_none() {
                entry.invalidated = Some(grant);
                effects.variants.push(*variant);
                routes.insert(Route::Merged(*variant));
            }
        }
        for route in &routes {
            let draining = self.bound_requests(*route, Some(grant), bound_for);
            effects.drain.draining.extend(draining);
        }
        self.kv.retain(|key, route| {
            let produced_under_revoked = routes.contains(route);
            if produced_under_revoked {
                effects.kv.push(*key);
            }
            !produced_under_revoked
        });
        effects.drain.unload = effects
            .detached
            .iter()
            .filter(|adapter| self.unloadable(adapter))
            .copied()
            .collect();
        effects.drain.unload_variants = effects
            .variants
            .iter()
            .filter(|variant| self.variant_unloadable(variant))
            .copied()
            .collect();
        effects
    }

    /// Records a KV state the request under `under` produced, at `now`, keyed by
    /// [`kv_state_key`]. The state must have been computed by the route's model with its
    /// adapter, the request must still be allowed to run, and its route must still stand.
    pub fn record_kv(
        &mut self,
        stored: &StoredKv,
        under: &AdapterUse,
        grants: &dyn GrantRevocations,
        now: MonotonicTime,
    ) -> Result<Digest, KvRecordRefusal> {
        self.check_use(under, now)
            .map_err(KvRecordRefusal::Request)?;
        self.route_stands(under.route, grants)
            .map_err(KvRecordRefusal::Route)?;
        if stored.spec.scope.model != under.model || stored.spec.scope.adapter != under.adapter {
            return Err(KvRecordRefusal::NotProducedOnRoute);
        }
        let key = kv_state_key(stored);
        self.kv.insert(key, under.route);
        Ok(key)
    }

    /// Checks that the request under `under` may reuse `stored` (GPU §3.9 line 797). The
    /// request must still be allowed to run and its route must still stand; its KV request
    /// must name the route's model and adapter; the stored state must be recorded under
    /// that same route; then P07's check ([`kv::check_kv_reuse`]) decides, with T07's trust
    /// scope, tenant scope, public-prefix sharing, revocations and scope enforcement.
    pub fn check_kv_reuse(
        &self,
        stored: &StoredKv,
        request: &KvRequest,
        under: &AdapterUse,
        grants: &dyn GrantRevocations,
        context: &KvReuseContext<'_>,
    ) -> Result<KvReuseGrant, AdapterKvRefusal> {
        self.check_use(under, context.now)
            .map_err(AdapterKvRefusal::Request)?;
        self.route_stands(under.route, grants)
            .map_err(AdapterKvRefusal::Route)?;
        if request.spec.scope.model != under.model || request.spec.scope.adapter != under.adapter {
            return Err(AdapterKvRefusal::RequestNotOnItsRoute);
        }
        let produced = *self
            .kv
            .get(&kv_state_key(stored))
            .ok_or(AdapterKvRefusal::NotRecorded)?;
        if produced != under.route {
            return Err(AdapterKvRefusal::ProducedUnderAnother {
                produced,
                serving: under.route,
            });
        }
        kv::check_kv_reuse(
            stored,
            request,
            context.sharing,
            context.revocations,
            context.enforcement,
            context.now,
        )
        .map_err(AdapterKvRefusal::Reuse)
    }

    /// The runner dropped a KV state; returns the route it was recorded under.
    pub fn drop_kv(&mut self, key: &Digest) -> Option<Route> {
        self.kv.remove(key)
    }

    /// Whether `grant` was revoked under the activation's authority: by a record applied
    /// here, or by the coordination authority now.
    fn grant_revoked(&self, grant: GrantId, grants: &dyn GrantRevocations) -> bool {
        self.revoked.contains(&grant) || grants.is_revoked(&self.base.authority, grant)
    }

    /// The attached adapter, if it serves new requests.
    fn serving_adapter(
        &self,
        adapter: AdapterIdentity,
        grants: &dyn GrantRevocations,
    ) -> Result<&Attached, RouteRefusal> {
        self.authority_stands(grants)
            .map_err(|epoch| RouteRefusal::AuthorityRevoked { epoch })?;
        let grant = adapter_grant_id(&adapter);
        if self.grant_revoked(grant, grants) {
            return Err(RouteRefusal::Revoked { grant });
        }
        let attached = self
            .attached
            .get(&adapter)
            .ok_or(RouteRefusal::NotAttached { adapter })?;
        match attached.detached {
            None => Ok(attached),
            Some(DetachCause::Detached) => Err(RouteRefusal::Detaching { adapter }),
            Some(DetachCause::Revoked { grant }) => Err(RouteRefusal::Revoked { grant }),
            Some(DetachCause::AuthorityRevoked { epoch }) => {
                Err(RouteRefusal::AuthorityRevoked { epoch })
            }
        }
    }

    /// The recorded variant, if it is valid and none of its inputs' grants is revoked.
    fn serving_variant(
        &self,
        variant: ExecutionIdentity,
        grants: &dyn GrantRevocations,
    ) -> Result<&Variant, RouteRefusal> {
        self.authority_stands(grants)
            .map_err(|epoch| RouteRefusal::AuthorityRevoked { epoch })?;
        let entry = self
            .variants
            .get(&variant)
            .ok_or(RouteRefusal::UnknownVariant { variant })?;
        if let Some(grant) = entry.invalidated {
            return Err(RouteRefusal::VariantInvalidated { variant, grant });
        }
        if let Some(grant) = entry
            .adapters
            .keys()
            .map(adapter_grant_id)
            .find(|grant| self.grant_revoked(*grant, grants))
        {
            return Err(RouteRefusal::VariantInvalidated { variant, grant });
        }
        Ok(entry)
    }

    /// Whether KV may still be recorded or reused on `route`, while the activation's
    /// authority stands: the base always; an adapter while attached and not revoked, even
    /// while it drains after a detach; a variant while valid, even while it drains after it
    /// was retired.
    fn route_stands(
        &self,
        route: Route,
        grants: &dyn GrantRevocations,
    ) -> Result<(), RouteRefusal> {
        self.authority_stands(grants)
            .map_err(|epoch| RouteRefusal::AuthorityRevoked { epoch })?;
        match route {
            Route::Base => Ok(()),
            Route::Adapter(adapter) => {
                let grant = adapter_grant_id(&adapter);
                if self.grant_revoked(grant, grants) {
                    return Err(RouteRefusal::Revoked { grant });
                }
                match self
                    .attached
                    .get(&adapter)
                    .map(|attached| attached.detached)
                {
                    None => Err(RouteRefusal::NotAttached { adapter }),
                    Some(Some(DetachCause::Revoked { grant })) => {
                        Err(RouteRefusal::Revoked { grant })
                    }
                    Some(_) => Ok(()),
                }
            }
            Route::Merged(variant) => self.serving_variant(variant, grants).map(|_| ()),
        }
    }

    /// The request `under` is in flight on its own route and may still run at `now`.
    fn check_use(&self, under: &AdapterUse, now: MonotonicTime) -> Result<(), RequestRefusal> {
        let on_route = self
            .requests
            .get(&under.lease)
            .is_some_and(|request| request.route == under.route);
        if !on_route {
            return Err(RequestRefusal::UnknownRequest { lease: under.lease });
        }
        self.check_request(under.lease, now).map(|_| ())
    }

    /// Gives every request in flight on `route` the bound `bound_for` names for its lease,
    /// or keeps an earlier one, and the revoked grant that cancelled it, if any; returns
    /// them.
    fn bound_requests(
        &mut self,
        route: Route,
        revoked: Option<GrantId>,
        bound_for: impl Fn(LeaseId) -> MonotonicTime,
    ) -> Vec<DrainingRequest> {
        let mut draining = Vec::new();
        for (lease, request) in &mut self.requests {
            if request.route != route {
                continue;
            }
            let bound_at = request
                .bound
                .map_or(bound_for(*lease), |bound| bound.min(bound_for(*lease)));
            request.bound = Some(bound_at);
            request.revoked = request.revoked.or(revoked);
            draining.push(DrainingRequest {
                lease: *lease,
                route,
                bound_at,
                revoked: request.revoked,
            });
        }
        draining
    }

    /// The leases in flight on `route`.
    fn leases_on(&self, route: Route) -> Vec<LeaseId> {
        self.requests
            .iter()
            .filter(|(_, request)| request.route == route)
            .map(|(lease, _)| *lease)
            .collect()
    }

    /// Whether `adapter` is detached and no request is in flight on it.
    fn unloadable(&self, adapter: &AdapterIdentity) -> bool {
        self.attached
            .get(adapter)
            .is_some_and(|attached| attached.detached.is_some())
            && self.leases_on(Route::Adapter(*adapter)).is_empty()
    }

    /// Refuses `bytes` beyond the backend's limits, and makes `adapter` wait, first in,
    /// first out, while the resident adapters, or the attachments waiting ahead of it,
    /// leave too few slots or bytes for it.
    fn fits(
        &mut self,
        adapter: AdapterIdentity,
        bytes: u64,
        now: MonotonicTime,
    ) -> Result<(), AttachRefusal> {
        let BackendAdapterLimits {
            max_resident,
            max_bytes,
            ..
        } = self.limits;
        if bytes == 0 || max_resident == 0 || bytes > max_bytes {
            self.attach_waits.leave(&adapter);
            return Err(if bytes == 0 {
                AttachRefusal::NoBytes
            } else {
                AttachRefusal::ExceedsLimits {
                    requested_bytes: bytes,
                    max_bytes,
                    max_resident,
                }
            });
        }
        let resident = u32::try_from(self.attached.len()).unwrap_or(u32::MAX);
        let free_slots = max_resident.saturating_sub(resident);
        let free_bytes = max_bytes.saturating_sub(self.resident_bytes());
        let free = WaitDemand {
            bytes: free_bytes,
            slots: free_slots,
        };
        let demand = WaitDemand { bytes, slots: 1 };
        match self.attach_waits.turn(&adapter, demand, free, now) {
            WaitTurn::Admit => Ok(()),
            WaitTurn::Wait {
                fits_now: false, ..
            } => Err(AttachRefusal::AwaitingRelease {
                requested_bytes: bytes,
                free_bytes,
                free_slots,
            }),
            WaitTurn::Wait { ahead, .. } => Err(AttachRefusal::QueuedBehind {
                requested_bytes: bytes,
                free_bytes,
                free_slots,
                ahead: u32::try_from(ahead).unwrap_or(u32::MAX),
            }),
            WaitTurn::Full { waiting } => Err(AttachRefusal::WaitQueueFull {
                waiting: u32::try_from(waiting).unwrap_or(u32::MAX),
            }),
        }
    }
}

/// Checks that `caller` holds a grant to serve `input` in `scope` at `now`, among the
/// grants it presents for that artifact; the first refusal is kept, and no grant at all is
/// [`GrantRefusal::Missing`].
fn authorize(
    caller: &Caller<'_>,
    input: &OwnedArtifact,
    scope: &TrustScope,
    now: MonotonicTime,
) -> Result<MonotonicTime, GrantRefusal> {
    let need = GrantNeed {
        owner: &input.owner,
        grantee: caller.tenant,
        artifact: &input.artifact,
        scope,
        granted_use: GrantedUse::Serve,
    };
    let mut refusal = None;
    for grant in caller
        .grants
        .iter()
        .filter(|grant| grant.artifact == input.artifact)
    {
        match check_grant(Some(grant), &need, now) {
            Ok(valid_until) => return Ok(valid_until),
            Err(refused) => {
                refusal.get_or_insert(refused);
            }
        }
    }
    Err(refusal.unwrap_or(GrantRefusal::Missing))
}

/// Carves `bytes` of `device`'s VRAM from `parent`, the activation's own reservation, as a
/// child in use at once: the backend loads the adapter now. The child takes the parent's
/// execution, tenant and priority (CORE-03). A refusal leaves nothing carved.
fn carve<C: Clock>(
    ledger: &mut Ledger<C>,
    parent: ReservationId,
    device: GpuDeviceKey,
    operation: &OperationId,
    bytes: u64,
) -> Result<ReservationId, AttachRefusal> {
    let record = ledger
        .reservation(parent)
        .ok_or(AttachRefusal::NoReservation)?;
    let provenance = Provenance {
        requester: Requester::ModelPlacement,
        execution: record.provenance().execution.clone(),
        operation: operation.clone(),
        tenant: record.provenance().tenant.clone(),
        purpose: CostPurpose::Compute,
        retry_number: 0,
    };
    let request = ReservationRequest::new(
        provenance,
        record.priority(),
        Amounts::new().vram_bytes(device, bytes),
    )
    .within(parent);
    match ledger.reserve(request) {
        Ok(Admission::Granted(reservation)) => match ledger.begin_create(reservation) {
            Ok(()) => Ok(reservation),
            Err(_) => {
                let _cancelled = ledger.cancel(reservation);
                Err(AttachRefusal::NoReservation)
            }
        },
        Ok(Admission::Queued {
            ticket,
            waiting_for,
            ..
        }) => {
            let _withdrawn = ledger.cancel_queued(ticket);
            Err(AttachRefusal::Ledger {
                refusal: CapacityRefusal::from_ledger(&waiting_for),
            })
        }
        Err(LedgerError::Capacity(error)) => Err(AttachRefusal::Ledger {
            refusal: CapacityRefusal::from_ledger(&error),
        }),
        Err(_) => Err(AttachRefusal::NoReservation),
    }
}

#[cfg(test)]
mod tests;
