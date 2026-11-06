//! Shared prerequisites reserved once (GPU-W06, "dependency-aware marginal value with
//! shared bases counted once"; GPU §1.1 line 304 and §2.7: shared prerequisites charged
//! once; CORE-03 reservations before creation).
//!
//! A prerequisite several preparations need, such as one base model under two adapters,
//! is one CORE-03 reservation for all of them. The first holder files it; later holders
//! join it; each holder leaves when its preparation finishes or is cancelled, and the
//! reservation is cancelled only when the last holder leaves. Cancelling returns a grant
//! whose workload was never created at once; a created one counts until a host observes
//! its release (CORE-03), which this module never confirms itself.
//!
//! The reservation is filed by the model placement governor
//! ([`Requester::ModelPlacement`]) under the governor's own execution, not under one
//! holder's: revoking one workflow ([`Ledger::cancel_execution`]) must not take a base
//! the other holders still use. Each holder's own authority is still followed: when a
//! holder's lease ends, its preparation ends and leaves. A prerequisite is shared only
//! within one tenant, whose budget it is charged to; tenants never share one (S3.3).
//!
//! Waiting requests are followed without draining the ledger's events, which belong to
//! its one history owner: a ticket that left the queue was granted exactly when an open
//! reservation carries it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use crate::foundation::ids::{
    Clock, Digest, DigestBuilder, ExecutionId, IdError, OperationId, TenantId,
};
use crate::foundation::ledger::{
    Admission, Amounts, CostPurpose, Ledger, LedgerError, Priority, Provenance, QueueTicket,
    ReleaseOutcome, Requester, ReservationId, ReservationRequest, ReservationState, ResourceUnit,
};

/// Digest domain of the operation a shared prerequisite's reservation is filed under.
pub const PREREQUISITE_OPERATION_DOMAIN: &str =
    "yougori/model-memory/readiness/adoption/prerequisite/v1";

/// A prerequisite by the identity of its state, such as the digest of a transitions
/// `StateIdentity` for a base model. Equal keys are the same state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrerequisiteKey(Digest);

impl PrerequisiteKey {
    /// The prerequisite whose state has `identity`.
    pub const fn new(identity: Digest) -> Self {
        Self(identity)
    }

    /// The identity of its state.
    pub const fn digest(self) -> Digest {
        self.0
    }
}

impl fmt::Display for PrerequisiteKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.0.to_hex();
        write!(f, "prerequisite {}", hex.get(..12).unwrap_or(&hex))
    }
}

/// One prerequisite a preparation needs and what holding it reserves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrerequisiteDemand {
    pub key: PrerequisiteKey,
    pub demand: Amounts,
}

/// Where a reservation request stands in the ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Holding {
    /// Waiting in the bounded queue at this priority.
    Queued {
        ticket: QueueTicket,
        priority: Priority,
    },
    Granted {
        reservation: ReservationId,
    },
}

impl Holding {
    /// The granted reservation; `None` while waiting.
    pub fn reservation(self) -> Option<ReservationId> {
        match self {
            Self::Granted { reservation } => Some(reservation),
            Self::Queued { .. } => None,
        }
    }
}

/// What releasing one holding did in the ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerRelease {
    /// A waiting request was withdrawn before it was granted.
    Withdrawn {
        ticket: QueueTicket,
    },
    /// The request had already left the queue without a grant.
    NotQueued {
        ticket: QueueTicket,
    },
    /// Cancelled before its workload was created: the amounts are back now.
    Returned {
        reservation: ReservationId,
        amounts: Amounts,
    },
    /// Its workload exists, so the amounts count until a host observes the release.
    AwaitingObservedRelease {
        reservation: ReservationId,
    },
    AlreadyClosed {
        reservation: ReservationId,
    },
    /// Other preparations still hold this shared prerequisite.
    StillShared {
        key: PrerequisiteKey,
        holders: usize,
    },
    /// The prerequisite was already dropped: its request was refused or its
    /// reservation closed, so there is nothing left to release.
    PrerequisiteGone {
        key: PrerequisiteKey,
    },
    /// The ledger refused the cancellation.
    Failed {
        error: LedgerError,
    },
}

/// What promoting a holding to foreground did (GPU §2.9: promotion to demand reuses the
/// same work).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromotionEffect {
    /// Re-filed as foreground and granted at once; the background request was withdrawn.
    RefiledGranted { reservation: ReservationId },
    /// Re-filed as foreground and waiting; under the ledger's foreground-first fairness
    /// it is served before every background request. The background request was
    /// withdrawn.
    RefiledQueued { ticket: QueueTicket },
    /// Already granted: the work it reserved now serves the request. The ledger has no
    /// in-place priority change, so the record keeps the background priority it was
    /// granted with.
    AlreadyGranted { reservation: ReservationId },
    /// Already waiting as foreground.
    AlreadyForeground { ticket: QueueTicket },
    /// The foreground request was refused, so the background request keeps waiting.
    KeptBackground { error: LedgerError },
    /// Nothing is reserved for it.
    NothingHeld,
}

/// Why a shared prerequisite could not be acquired, released or used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SharedRefusal {
    EmptyDemand {
        key: PrerequisiteKey,
    },
    /// The same prerequisite was declared with another demand.
    DemandMismatch {
        key: PrerequisiteKey,
    },
    AlreadyHolding {
        key: PrerequisiteKey,
        holder: OperationId,
    },
    NotHeld {
        key: PrerequisiteKey,
    },
    NotAHolder {
        key: PrerequisiteKey,
        holder: OperationId,
    },
    /// The reservation is still waiting in the queue.
    NotGranted {
        key: PrerequisiteKey,
    },
    Capacity {
        key: PrerequisiteKey,
        error: LedgerError,
    },
    Id(IdError),
}

impl fmt::Display for SharedRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDemand { key } => write!(f, "{key} reserves nothing"),
            Self::DemandMismatch { key } => {
                write!(f, "{key} is already held with another demand")
            }
            Self::AlreadyHolding { key, holder } => write!(f, "{holder} already holds {key}"),
            Self::NotHeld { key } => write!(f, "{key} is not held"),
            Self::NotAHolder { key, holder } => write!(f, "{holder} does not hold {key}"),
            Self::NotGranted { key } => write!(f, "{key} is still waiting for capacity"),
            Self::Capacity { key, error } => write!(f, "{key} was refused: {error}"),
            Self::Id(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SharedRefusal {}

/// What acquiring a prerequisite did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acquired {
    /// The first holder filed the reservation.
    Reserved { holding: Holding },
    /// The prerequisite was already reserved or waiting; the holder joined it.
    Joined { holding: Holding, holders: usize },
}

impl Acquired {
    /// Where the prerequisite's reservation stands.
    pub fn holding(self) -> Holding {
        match self {
            Self::Reserved { holding } | Self::Joined { holding, .. } => holding,
        }
    }
}

/// Something that happened to a shared prerequisite in the ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SharedEvent {
    /// Its waiting request was granted.
    Granted {
        tenant: TenantId,
        key: PrerequisiteKey,
        reservation: ReservationId,
    },
    /// Its request left the queue without a grant, or its reservation was closed or set
    /// releasing by someone else (reclaimed unused, or cancelled). The entry is gone and
    /// every holder listed has lost it.
    Lost {
        tenant: TenantId,
        key: PrerequisiteKey,
        holders: BTreeSet<OperationId>,
        holding: Holding,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    operation: OperationId,
    demand: Amounts,
    holders: BTreeSet<OperationId>,
    /// Holders whose preparation now serves a request.
    foreground: BTreeSet<OperationId>,
    holding: Holding,
}

/// The bytes among `amounts`: every amount counted in bytes, host and device alike.
pub(crate) fn bytes_of(amounts: &Amounts) -> u64 {
    amounts
        .iter()
        .filter(|(resource, _)| resource.unit() == ResourceUnit::Bytes)
        .fold(0u64, |total, (_, amount)| total.saturating_add(amount))
}

/// The CORE-03 provenance of a governor reservation.
pub(crate) fn provenance(
    execution: &ExecutionId,
    operation: &OperationId,
    tenant: &TenantId,
) -> Provenance {
    Provenance {
        requester: Requester::ModelPlacement,
        execution: execution.clone(),
        operation: operation.clone(),
        tenant: tenant.clone(),
        purpose: CostPurpose::Compute,
        retry_number: 0,
    }
}

/// Files `demand` at `priority`, waiting at most `wait` (never, when zero).
pub(crate) fn file<C: Clock>(
    ledger: &mut Ledger<C>,
    provenance: Provenance,
    priority: Priority,
    demand: &Amounts,
    wait: Duration,
) -> Result<Holding, LedgerError> {
    let request = ReservationRequest::new(provenance, priority, demand.clone());
    let request = if wait.is_zero() {
        request
    } else {
        request.wait_up_to(wait)
    };
    Ok(match ledger.reserve(request)? {
        Admission::Granted(reservation) => Holding::Granted { reservation },
        Admission::Queued { ticket, .. } => Holding::Queued { ticket, priority },
    })
}

/// The open reservation the queue granted to `ticket`, if it was granted.
fn granted_from<C: Clock>(ledger: &Ledger<C>, ticket: QueueTicket) -> Option<ReservationId> {
    ledger
        .open_reservations()
        .find(|record| record.ticket() == Some(ticket))
        .map(|record| record.id())
}

/// Follows a holding: a ticket that left the queue becomes its grant, and `None` means
/// the request or reservation is lost: refused, withdrawn, reclaimed, closed, or set
/// releasing by someone else (a holding is released only after it stops being followed).
pub(crate) fn follow<C: Clock>(ledger: &Ledger<C>, holding: Holding) -> Option<Holding> {
    match holding {
        Holding::Queued { ticket, .. } if ledger.queue_position(ticket).is_none() => {
            granted_from(ledger, ticket).map(|reservation| Holding::Granted { reservation })
        }
        Holding::Granted { reservation }
            if ledger
                .reservation(reservation)
                .is_none_or(|record| record.state() == ReservationState::Releasing) =>
        {
            None
        }
        other => Some(other),
    }
}

/// Withdraws or cancels a holding. A ticket granted since it was last followed is
/// cancelled as the reservation it became, so nothing is left behind.
pub(crate) fn release_holding<C: Clock>(ledger: &mut Ledger<C>, holding: Holding) -> LedgerRelease {
    let cancel = |ledger: &mut Ledger<C>, reservation| match ledger.cancel(reservation) {
        Ok(ReleaseOutcome::Released { amounts }) => LedgerRelease::Returned {
            reservation,
            amounts,
        },
        Ok(ReleaseOutcome::Pending) => LedgerRelease::AwaitingObservedRelease { reservation },
        Ok(ReleaseOutcome::AlreadyClosed) => LedgerRelease::AlreadyClosed { reservation },
        Err(error) => LedgerRelease::Failed { error },
    };
    match holding {
        Holding::Queued { ticket, .. } => match ledger.cancel_queued(ticket) {
            Ok(true) => LedgerRelease::Withdrawn { ticket },
            Ok(false) => match granted_from(ledger, ticket) {
                Some(reservation) => cancel(ledger, reservation),
                None => LedgerRelease::NotQueued { ticket },
            },
            Err(error) => LedgerRelease::Failed { error },
        },
        Holding::Granted { reservation } => cancel(ledger, reservation),
    }
}

/// Re-files a background request as foreground (GPU §2.9 promotion; the ledger's
/// foreground-first fairness then serves it before background work). The foreground
/// request is filed before the background one is withdrawn, so the work never stands
/// without a request; if the background one was granted meanwhile, it is kept and the
/// new one withdrawn.
pub(crate) fn promote_holding<C: Clock>(
    ledger: &mut Ledger<C>,
    provenance: Provenance,
    demand: &Amounts,
    holding: &mut Holding,
    wait: Duration,
) -> PromotionEffect {
    let old = match *holding {
        Holding::Granted { reservation } => return PromotionEffect::AlreadyGranted { reservation },
        Holding::Queued {
            ticket,
            priority: Priority::Foreground,
        } => return PromotionEffect::AlreadyForeground { ticket },
        Holding::Queued {
            ticket,
            priority: Priority::Background,
        } => ticket,
    };
    let new = match file(ledger, provenance, Priority::Foreground, demand, wait) {
        Ok(new) => new,
        Err(error) => return PromotionEffect::KeptBackground { error },
    };
    if matches!(ledger.cancel_queued(old), Ok(false)) {
        if let Some(reservation) = granted_from(ledger, old) {
            release_holding(ledger, new);
            *holding = Holding::Granted { reservation };
            return PromotionEffect::AlreadyGranted { reservation };
        }
    }
    *holding = new;
    match new {
        Holding::Granted { reservation } => PromotionEffect::RefiledGranted { reservation },
        Holding::Queued { ticket, .. } => PromotionEffect::RefiledQueued { ticket },
    }
}

/// Every shared prerequisite the governor holds, per tenant (see the module
/// documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedPrerequisites {
    execution: ExecutionId,
    entries: BTreeMap<(TenantId, PrerequisiteKey), Entry>,
}

impl SharedPrerequisites {
    /// Nothing held; reservations are filed under the governor's `execution`.
    pub fn new(execution: ExecutionId) -> Self {
        Self {
            execution,
            entries: BTreeMap::new(),
        }
    }

    /// How many preparations hold the prerequisite; zero when it is not held.
    pub fn holders(&self, tenant: &TenantId, key: PrerequisiteKey) -> usize {
        self.entries
            .get(&(tenant.clone(), key))
            .map_or(0, |entry| entry.holders.len())
    }

    /// Whether the prerequisite is held or waited for.
    pub fn holds(&self, tenant: &TenantId, key: PrerequisiteKey) -> bool {
        self.entries.contains_key(&(tenant.clone(), key))
    }

    /// Where its reservation stands.
    pub fn holding(&self, tenant: &TenantId, key: PrerequisiteKey) -> Option<Holding> {
        self.entries
            .get(&(tenant.clone(), key))
            .map(|entry| entry.holding)
    }

    /// Bytes reserved or waited for by prerequisites no request uses yet, each counted
    /// once however many preparations share it.
    pub fn speculative_bytes(&self) -> u64 {
        self.entries
            .values()
            .filter(|entry| entry.foreground.is_empty())
            .fold(0u64, |total, entry| {
                total.saturating_add(bytes_of(&entry.demand))
            })
    }

    /// The bytes [`Self::speculative_bytes`] counts for one prerequisite: its demand while
    /// no request uses it, zero once one does, and `None` when it is not held.
    pub fn speculative_bytes_of(&self, tenant: &TenantId, key: PrerequisiteKey) -> Option<u64> {
        self.entries.get(&(tenant.clone(), key)).map(|entry| {
            if entry.foreground.is_empty() {
                bytes_of(&entry.demand)
            } else {
                0
            }
        })
    }

    /// Adds `holder` to the prerequisite: files its reservation when no one holds it yet
    /// (waiting at most `wait`), and joins it otherwise.
    pub fn acquire<C: Clock>(
        &mut self,
        ledger: &mut Ledger<C>,
        tenant: &TenantId,
        prerequisite: &PrerequisiteDemand,
        holder: &OperationId,
        wait: Duration,
    ) -> Result<Acquired, SharedRefusal> {
        let key = prerequisite.key;
        if prerequisite.demand.is_empty() {
            return Err(SharedRefusal::EmptyDemand { key });
        }
        if let Some(entry) = self.entries.get_mut(&(tenant.clone(), key)) {
            if entry.demand != prerequisite.demand {
                return Err(SharedRefusal::DemandMismatch { key });
            }
            if !entry.holders.insert(holder.clone()) {
                return Err(SharedRefusal::AlreadyHolding {
                    key,
                    holder: holder.clone(),
                });
            }
            return Ok(Acquired::Joined {
                holding: entry.holding,
                holders: entry.holders.len(),
            });
        }
        let digest = DigestBuilder::new(PREREQUISITE_OPERATION_DOMAIN)
            .str(tenant.as_str())
            .digest(&key.digest())
            .finish()
            .to_hex();
        let operation = OperationId::new(format!("prereq-{}", digest.get(..40).unwrap_or(&digest)))
            .map_err(SharedRefusal::Id)?;
        let holding = file(
            ledger,
            provenance(&self.execution, &operation, tenant),
            Priority::Background,
            &prerequisite.demand,
            wait,
        )
        .map_err(|error| SharedRefusal::Capacity { key, error })?;
        self.entries.insert(
            (tenant.clone(), key),
            Entry {
                operation,
                demand: prerequisite.demand.clone(),
                holders: BTreeSet::from([holder.clone()]),
                foreground: BTreeSet::new(),
                holding,
            },
        );
        Ok(Acquired::Reserved { holding })
    }

    /// Removes `holder`. The reservation is withdrawn or cancelled only when it was the
    /// last holder.
    pub fn release<C: Clock>(
        &mut self,
        ledger: &mut Ledger<C>,
        tenant: &TenantId,
        key: PrerequisiteKey,
        holder: &OperationId,
    ) -> Result<LedgerRelease, SharedRefusal> {
        let slot = (tenant.clone(), key);
        let entry = self
            .entries
            .get_mut(&slot)
            .ok_or(SharedRefusal::NotHeld { key })?;
        if !entry.holders.remove(holder) {
            return Err(SharedRefusal::NotAHolder {
                key,
                holder: holder.clone(),
            });
        }
        entry.foreground.remove(holder);
        if !entry.holders.is_empty() {
            return Ok(LedgerRelease::StillShared {
                key,
                holders: entry.holders.len(),
            });
        }
        let holding = entry.holding;
        self.entries.remove(&slot);
        Ok(release_holding(ledger, holding))
    }

    /// Marks `holder` as serving a request and re-files a waiting background reservation
    /// as foreground, waiting at most `wait`.
    pub fn promote<C: Clock>(
        &mut self,
        ledger: &mut Ledger<C>,
        tenant: &TenantId,
        key: PrerequisiteKey,
        holder: &OperationId,
        wait: Duration,
    ) -> Result<PromotionEffect, SharedRefusal> {
        let execution = self.execution.clone();
        let entry = self
            .entries
            .get_mut(&(tenant.clone(), key))
            .ok_or(SharedRefusal::NotHeld { key })?;
        if !entry.holders.contains(holder) {
            return Err(SharedRefusal::NotAHolder {
                key,
                holder: holder.clone(),
            });
        }
        entry.foreground.insert(holder.clone());
        let provenance = provenance(&execution, &entry.operation, tenant);
        Ok(promote_holding(
            ledger,
            provenance,
            &entry.demand,
            &mut entry.holding,
            wait,
        ))
    }

    /// Marks the prerequisite's workload as being created (CORE-03 reserve before
    /// create); idempotent, so every holder may call it before its own work.
    pub fn begin_create<C: Clock>(
        &mut self,
        ledger: &mut Ledger<C>,
        tenant: &TenantId,
        key: PrerequisiteKey,
    ) -> Result<ReservationId, SharedRefusal> {
        let entry = self
            .entries
            .get(&(tenant.clone(), key))
            .ok_or(SharedRefusal::NotHeld { key })?;
        let reservation = entry
            .holding
            .reservation()
            .ok_or(SharedRefusal::NotGranted { key })?;
        ledger
            .begin_create(reservation)
            .map_err(|error| SharedRefusal::Capacity { key, error })?;
        Ok(reservation)
    }

    /// Follows every waiting request and reservation in the ledger: grants are taken up,
    /// and a prerequisite whose request or reservation is gone is dropped with its
    /// holders listed (GPU-W06 stale-state reconciliation).
    pub fn poll<C: Clock>(&mut self, ledger: &Ledger<C>) -> Vec<SharedEvent> {
        let mut events = Vec::new();
        let mut lost = Vec::new();
        for ((tenant, key), entry) in &mut self.entries {
            match follow(ledger, entry.holding) {
                Some(Holding::Granted { reservation }) if entry.holding.reservation().is_none() => {
                    entry.holding = Holding::Granted { reservation };
                    events.push(SharedEvent::Granted {
                        tenant: tenant.clone(),
                        key: *key,
                        reservation,
                    });
                }
                Some(_) => {}
                None => lost.push((tenant.clone(), *key)),
            }
        }
        for slot in lost {
            if let Some(entry) = self.entries.remove(&slot) {
                events.push(SharedEvent::Lost {
                    tenant: slot.0,
                    key: slot.1,
                    holders: entry.holders,
                    holding: entry.holding,
                });
            }
        }
        events
    }
}
