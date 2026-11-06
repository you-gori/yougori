//! Shared physical extents (S03; GPU part §2.7 line 608: "Count physical shared weights
//! once, but each process's contexts, KV and scratch separately"; §3.7 line 775: physical
//! allocations are owned apart from mappings and the last reference is closed
//! deliberately; GPU-W02 line 1182: shared physical allocations).
//!
//! One physical extent several holders use, such as weights one runtime's processes map
//! or a dedicated allocation exported to importers, is one reservation, filed once under
//! its [`ExtentKey`]; a second request for the same key joins it instead of reserving
//! again, so capacity counts it once. Each holder is one of its own open reservations,
//! such as the process's reservation for its contexts and KV, which never includes the
//! extent's amounts. Holders share an extent only within one tenant (S3.2's authorized
//! trust scope).
//!
//! The extent is released only when its last holder leaves: by [`Ledger::leave_extent`],
//! or because the holder's own reservation closed or began releasing, as when its
//! execution is cancelled. Until then a direct cancellation is refused, and cancelling a
//! whole execution leaves the extent to its other holders. Releasing follows the ledger's
//! rules: an extent never created returns at once, and one in use counts until a source
//! with authority observes its release. An extent closed with its parent, or released by
//! the lifecycle that owns it, ends for every holder.
//!
//! Cost (BENCH-08) is attributed per holder without double counting: over each interval
//! the extent's amount times the time is split evenly among the holders present, any
//! indivisible remainder going to the lowest reservation numbers, and the release that
//! follows the last holder to the holders present before it. The holders' shares add up
//! exactly to the extent record's own integral
//! ([`ReservationRecord::held_amount_nanoseconds`](crate::foundation::ledger::ReservationRecord::held_amount_nanoseconds)).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::ownership::OwnershipError;
use super::{Admission, Ledger, ReleaseOutcome};
use crate::foundation::ids::{Clock, Digest, MonotonicTime, TenantId};
use crate::foundation::ledger::{
    AmountChange, Amounts, ChangeCause, LedgerError, Provenance, QueuePolicy, ReservationId,
    ReservationRequest, ReservationState, ResourceKey,
};

/// How many records of closed shared extents the ledger keeps until they are taken; older
/// ones are dropped first and counted.
pub const MAX_EXTENT_RECORDS: usize = 1_024;

/// One physical extent, by the digest of its identity, such as a device and the dedicated
/// allocation that holds an artifact batch. Equal keys are the same physical memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExtentKey(Digest);

impl ExtentKey {
    /// The extent whose identity has `digest`.
    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    /// The digest of its identity.
    pub const fn digest(self) -> Digest {
        self.0
    }
}

impl fmt::Display for ExtentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.0.to_hex();
        write!(f, "shared extent {}", hex.get(..12).unwrap_or(&hex))
    }
}

/// What sharing an extent did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareAdmission {
    /// The first holder's request reserved the extent.
    Reserved { reservation: ReservationId },
    /// The extent was already reserved; the holder joined it.
    Joined {
        reservation: ReservationId,
        holders: usize,
    },
}

impl ShareAdmission {
    /// The extent's reservation.
    pub fn reservation(self) -> ReservationId {
        match self {
            Self::Reserved { reservation } | Self::Joined { reservation, .. } => reservation,
        }
    }
}

/// What a holder leaving did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareRelease {
    /// Other holders remain.
    StillShared { holders: usize },
    /// The last holder left before the extent was created: its amounts are back.
    Released { amounts: Amounts },
    /// The last holder left; the extent exists, so it counts until its release is
    /// observed.
    Pending,
    /// The extent was already closed.
    AlreadyClosed,
}

/// Why a holder stopped holding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderExit {
    /// It left.
    Left,
    /// Its own reservation closed or began releasing.
    HolderGone,
    /// The extent closed or began releasing under it: with its parent, or released by the
    /// lifecycle that owns it.
    ExtentGone,
}

/// When and why a holder stopped holding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Departure {
    pub at: MonotonicTime,
    pub exit: HolderExit,
}

/// One holder's time with an extent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolderSpan {
    /// The holder's own reservation.
    pub holder: ReservationId,
    /// Its provenance, for cost attribution.
    pub provenance: Provenance,
    pub joined_at: MonotonicTime,
    /// `None` while it holds the extent.
    pub left: Option<Departure>,
}

/// One holder's share of an extent's cost, in the resource's unit times nanoseconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolderCost {
    pub holder: ReservationId,
    pub provenance: Provenance,
    pub resource: ResourceKey,
    pub amount_nanoseconds: u128,
}

/// A shared extent as the ledger keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedExtent {
    key: ExtentKey,
    reservation: ReservationId,
    tenant: TenantId,
    demand: Amounts,
    spans: Vec<HolderSpan>,
    /// The extent record's amounts over time, as last seen, for attribution after the
    /// record left the ledger.
    history: Vec<AmountChange>,
}

impl SharedExtent {
    pub fn key(&self) -> ExtentKey {
        self.key
    }

    /// The extent's reservation.
    pub fn reservation(&self) -> ReservationId {
        self.reservation
    }

    /// The tenant whose holders share it.
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The amounts it was reserved with.
    pub fn demand(&self) -> &Amounts {
        &self.demand
    }

    /// Every holder it had, in the order they joined.
    pub fn spans(&self) -> &[HolderSpan] {
        &self.spans
    }

    /// The holders that have not left, in the order they joined.
    pub fn holders(&self) -> impl Iterator<Item = &HolderSpan> {
        self.spans.iter().filter(|span| span.left.is_none())
    }
}

/// The record of a shared extent that closed, with each holder's cost. The ledger's
/// [`LedgerHistory`](crate::foundation::ledger::LedgerHistory) takes and exports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedExtentRecord {
    pub key: ExtentKey,
    pub reservation: ReservationId,
    pub spans: Vec<HolderSpan>,
    pub closed_at: MonotonicTime,
    /// Each holder's share of the extent's cost, by holder and then resource.
    pub costs: Vec<HolderCost>,
}

/// Why a shared extent refused a holder or a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareRefusal {
    /// Holders share an extent only within one tenant.
    TenantMismatch {
        holder: ReservationId,
    },
    /// A holder is an open reservation that is not releasing.
    HolderNotOpen {
        holder: ReservationId,
    },
    AlreadyHolding {
        holder: ReservationId,
    },
    NotAHolder {
        holder: ReservationId,
    },
    /// The key is shared with another demand: it names other physical memory.
    DemandMismatch,
    /// A holder is never the extent or carved from it.
    HolderInsideExtent {
        holder: ReservationId,
    },
    /// No open extent has this key.
    NotShared,
    /// The extent is releasing; nobody new joins it.
    Releasing,
    /// The extent's request was not granted at once; an extent never waits in the queue.
    NotGranted,
}

impl fmt::Display for ShareRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TenantMismatch { holder } => {
                write!(
                    f,
                    "{holder} is another tenant's; tenants never share an extent"
                )
            }
            Self::HolderNotOpen { holder } => {
                write!(f, "{holder} is closed or releasing and holds nothing new")
            }
            Self::AlreadyHolding { holder } => write!(f, "{holder} already holds it"),
            Self::NotAHolder { holder } => write!(f, "{holder} does not hold it"),
            Self::DemandMismatch => f.write_str("it is already shared with another demand"),
            Self::HolderInsideExtent { holder } => {
                write!(f, "{holder} is the extent or is carved from it")
            }
            Self::NotShared => f.write_str("no open extent has this key"),
            Self::Releasing => f.write_str("it is releasing; nobody new joins it"),
            Self::NotGranted => f.write_str("its request was not granted at once"),
        }
    }
}

/// The shared extents of one ledger.
#[derive(Debug, Default)]
pub(super) struct Shares {
    by_key: BTreeMap<ExtentKey, SharedExtent>,
    by_reservation: BTreeMap<ReservationId, ExtentKey>,
    closed: Vec<SharedExtentRecord>,
    dropped: u64,
}

fn refused(key: ExtentKey, refusal: ShareRefusal) -> LedgerError {
    LedgerError::Ownership(OwnershipError::Share { key, refusal })
}

impl<C: Clock> Ledger<C> {
    /// Shares the extent `key` names with `holder`: joins it when it is open, and
    /// otherwise reserves it with `request` and makes `holder` its first holder. The
    /// request never waits; a joining request must name the extent's tenant and demand.
    pub fn share_extent(
        &mut self,
        key: ExtentKey,
        request: ReservationRequest,
        holder: ReservationId,
    ) -> Result<ShareAdmission, LedgerError> {
        if let Some(extent) = self.ownership.shares.by_key.get(&key) {
            if extent.demand != request.demand {
                return Err(refused(key, ShareRefusal::DemandMismatch));
            }
            if extent.tenant != request.provenance.tenant {
                return Err(refused(key, ShareRefusal::TenantMismatch { holder }));
            }
            let reservation = extent.reservation;
            let holders = self.join_extent(key, holder)?;
            return Ok(ShareAdmission::Joined {
                reservation,
                holders,
            });
        }
        let tenant = request.provenance.tenant.clone();
        self.check_holder(key, &tenant, holder, None)?;
        let request = ReservationRequest {
            queue: QueuePolicy::NoWait,
            ..request
        };
        let demand = request.demand.clone();
        let reservation = match self.reserve(request)? {
            Admission::Granted(reservation) => reservation,
            Admission::Queued { ticket, .. } => {
                self.cancel_queued(ticket)?;
                return Err(refused(key, ShareRefusal::NotGranted));
            }
        };
        if let Err(error) = self.check_holder(key, &tenant, holder, Some(reservation)) {
            self.cancel(reservation)?;
            return Err(error);
        }
        let (Some(extent), Some(holding)) = (self.open.get(&reservation), self.open.get(&holder))
        else {
            return Err(LedgerError::Closed { reservation });
        };
        let span = HolderSpan {
            holder,
            provenance: holding.provenance.clone(),
            joined_at: extent.granted_at,
            left: None,
        };
        let history = extent.history.clone();
        let shares = &mut self.ownership.shares;
        shares.by_reservation.insert(reservation, key);
        shares.by_key.insert(
            key,
            SharedExtent {
                key,
                reservation,
                tenant,
                demand,
                spans: vec![span],
                history,
            },
        );
        Ok(ShareAdmission::Reserved { reservation })
    }

    /// Adds `holder` to the open extent `key` and returns how many hold it now.
    pub fn join_extent(
        &mut self,
        key: ExtentKey,
        holder: ReservationId,
    ) -> Result<usize, LedgerError> {
        self.run(|ledger, now| {
            let Some(extent) = ledger.ownership.shares.by_key.get(&key) else {
                return Err(refused(key, ShareRefusal::NotShared));
            };
            let reservation = extent.reservation;
            let tenant = extent.tenant.clone();
            match ledger.open.get(&reservation).map(|record| record.state) {
                Some(ReservationState::Granted | ReservationState::InUse) => {}
                _ => return Err(refused(key, ShareRefusal::Releasing)),
            }
            ledger.check_holder(key, &tenant, holder, Some(reservation))?;
            let Some(provenance) = ledger
                .open
                .get(&holder)
                .map(|record| record.provenance.clone())
            else {
                return Err(refused(key, ShareRefusal::HolderNotOpen { holder }));
            };
            let Some(extent) = ledger.ownership.shares.by_key.get_mut(&key) else {
                return Err(refused(key, ShareRefusal::NotShared));
            };
            extent.spans.push(HolderSpan {
                holder,
                provenance,
                joined_at: now,
                left: None,
            });
            Ok(ledger.live_holders(key))
        })
    }

    /// Removes `holder` from the extent `key`. When it was the last holder, the extent is
    /// released: at once if never created, and otherwise counted until its release is
    /// observed.
    pub fn leave_extent(
        &mut self,
        key: ExtentKey,
        holder: ReservationId,
    ) -> Result<ShareRelease, LedgerError> {
        self.run(|ledger, now| {
            let Some(extent) = ledger.ownership.shares.by_key.get_mut(&key) else {
                return Err(refused(key, ShareRefusal::NotShared));
            };
            let reservation = extent.reservation;
            let Some(span) = extent
                .spans
                .iter_mut()
                .find(|span| span.holder == holder && span.left.is_none())
            else {
                return Err(refused(key, ShareRefusal::NotAHolder { holder }));
            };
            span.left = Some(Departure {
                at: now,
                exit: HolderExit::Left,
            });
            let holders = ledger.live_holders(key);
            if holders > 0 {
                return Ok(ShareRelease::StillShared { holders });
            }
            Ok(match ledger.cancel_at(reservation, now)? {
                ReleaseOutcome::Released { amounts } => ShareRelease::Released { amounts },
                ReleaseOutcome::Pending => ShareRelease::Pending,
                ReleaseOutcome::AlreadyClosed => ShareRelease::AlreadyClosed,
            })
        })
    }

    /// The shared extent `key` names, while its reservation is open.
    pub fn shared_extent(&self, key: ExtentKey) -> Option<&SharedExtent> {
        self.ownership.shares.by_key.get(&key)
    }

    /// The shared extent an open reservation is.
    pub fn extent_of(&self, reservation: ReservationId) -> Option<&SharedExtent> {
        let key = self.ownership.shares.by_reservation.get(&reservation)?;
        self.ownership.shares.by_key.get(key)
    }

    /// Each holder's share of the extent's cost up to `until` (see the module
    /// documentation); `None` when no open extent has the key.
    pub fn extent_costs(&self, key: ExtentKey, until: MonotonicTime) -> Option<Vec<HolderCost>> {
        let extent = self.ownership.shares.by_key.get(&key)?;
        let history = self
            .open
            .get(&extent.reservation)
            .map_or(extent.history.as_slice(), |record| {
                record.history.as_slice()
            });
        Some(holder_costs(&extent.spans, history, until))
    }

    /// Records of shared extents that closed and were not yet taken, oldest first; at
    /// most [`MAX_EXTENT_RECORDS`].
    pub fn extent_records(&self) -> &[SharedExtentRecord] {
        &self.ownership.shares.closed
    }

    /// Hands the records of closed shared extents over, for cost attribution (BENCH-08).
    pub fn take_extent_records(&mut self) -> Vec<SharedExtentRecord> {
        std::mem::take(&mut self.ownership.shares.closed)
    }

    /// How many records of closed shared extents were dropped untaken.
    pub fn extent_records_dropped(&self) -> u64 {
        self.ownership.shares.dropped
    }

    /// The extent `reservation` is and how many live holders hold it, when any do.
    pub(super) fn held_extent(&self, reservation: ReservationId) -> Option<(ExtentKey, usize)> {
        let key = *self.ownership.shares.by_reservation.get(&reservation)?;
        let holders = self.live_holders(key);
        (holders > 0).then_some((key, holders))
    }

    /// Ends the extent `reservation` is for every holder, before it is released whatever
    /// its holders: the lifecycle that owns it ended.
    pub(super) fn unshare(&mut self, reservation: ReservationId, now: MonotonicTime) {
        let Some(key) = self
            .ownership
            .shares
            .by_reservation
            .get(&reservation)
            .copied()
        else {
            return;
        };
        if let Some(extent) = self.ownership.shares.by_key.get_mut(&key) {
            depart(&mut extent.spans, |_| true, now, HolderExit::ExtentGone);
        }
    }

    /// Ends holdings whose holder or extent is gone, releases extents whose last holder
    /// went, and records the extents that closed.
    pub(super) fn settle_shares(&mut self, now: MonotonicTime) {
        let keys: Vec<ExtentKey> = self.ownership.shares.by_key.keys().copied().collect();
        for key in keys {
            let Some(extent) = self.ownership.shares.by_key.get(&key) else {
                continue;
            };
            let reservation = extent.reservation;
            let Some(state) = self.open.get(&reservation).map(|record| record.state) else {
                self.close_extent(key, now);
                continue;
            };
            let gone: BTreeSet<ReservationId> = extent
                .spans
                .iter()
                .filter(|span| span.left.is_none() && !self.holds(span.holder))
                .map(|span| span.holder)
                .collect();
            let history = self
                .open
                .get(&reservation)
                .filter(|record| record.history.len() != extent.history.len())
                .map(|record| record.history.clone());
            let Some(extent) = self.ownership.shares.by_key.get_mut(&key) else {
                continue;
            };
            if let Some(history) = history {
                extent.history = history;
            }
            depart(
                &mut extent.spans,
                |holder| gone.contains(&holder),
                now,
                HolderExit::HolderGone,
            );
            if state == ReservationState::Releasing {
                depart(&mut extent.spans, |_| true, now, HolderExit::ExtentGone);
                continue;
            }
            if self.live_holders(key) == 0 {
                if let Ok(ReleaseOutcome::Released { .. }) = self.cancel_at(reservation, now) {
                    self.close_extent(key, now);
                }
            }
        }
    }

    /// Whether `holder` is an open reservation that is not releasing.
    fn holds(&self, holder: ReservationId) -> bool {
        self.open
            .get(&holder)
            .is_some_and(|record| record.state != ReservationState::Releasing)
    }

    fn live_holders(&self, key: ExtentKey) -> usize {
        self.ownership.shares.by_key.get(&key).map_or(0, |extent| {
            extent
                .holders()
                .filter(|span| self.holds(span.holder))
                .count()
        })
    }

    /// Checks that `holder` may hold the extent `key` of `tenant`, whose reservation is
    /// `extent` once it exists.
    fn check_holder(
        &self,
        key: ExtentKey,
        tenant: &TenantId,
        holder: ReservationId,
        extent: Option<ReservationId>,
    ) -> Result<(), LedgerError> {
        let Some(record) = self.open.get(&holder) else {
            self.open_record(holder)?;
            return Err(refused(key, ShareRefusal::HolderNotOpen { holder }));
        };
        if record.state == ReservationState::Releasing {
            return Err(refused(key, ShareRefusal::HolderNotOpen { holder }));
        }
        if record.provenance.tenant != *tenant {
            return Err(refused(key, ShareRefusal::TenantMismatch { holder }));
        }
        if let Some(extent) = extent {
            let mut cursor = Some(holder);
            while let Some(id) = cursor {
                if id == extent {
                    return Err(refused(key, ShareRefusal::HolderInsideExtent { holder }));
                }
                cursor = self.open.get(&id).and_then(|record| record.parent);
            }
        }
        let holding = self
            .ownership
            .shares
            .by_key
            .get(&key)
            .is_some_and(|extent| extent.holders().any(|span| span.holder == holder));
        if holding {
            return Err(refused(key, ShareRefusal::AlreadyHolding { holder }));
        }
        Ok(())
    }

    /// Records a closed extent with each holder's cost and forgets it.
    fn close_extent(&mut self, key: ExtentKey, now: MonotonicTime) {
        let shares = &mut self.ownership.shares;
        let Some(mut extent) = shares.by_key.remove(&key) else {
            return;
        };
        shares.by_reservation.remove(&extent.reservation);
        let closed = self
            .closed
            .iter()
            .rev()
            .find(|record| record.id == extent.reservation);
        let (history, closed_at) = match closed {
            Some(record) => (record.history.clone(), record.closed_at.unwrap_or(now)),
            None => {
                let mut history = std::mem::take(&mut extent.history);
                history.push(AmountChange {
                    at: now,
                    amounts: Amounts::new(),
                    cause: ChangeCause::Closed,
                });
                (history, now)
            }
        };
        depart(
            &mut extent.spans,
            |_| true,
            closed_at,
            HolderExit::ExtentGone,
        );
        let costs = holder_costs(&extent.spans, &history, closed_at);
        let shares = &mut self.ownership.shares;
        shares.closed.push(SharedExtentRecord {
            key,
            reservation: extent.reservation,
            spans: extent.spans,
            closed_at,
            costs,
        });
        let excess = shares.closed.len().saturating_sub(MAX_EXTENT_RECORDS);
        if excess > 0 {
            shares.closed.drain(..excess);
            shares.dropped = shares
                .dropped
                .saturating_add(u64::try_from(excess).unwrap_or(u64::MAX));
        }
    }
}

/// Ends, at `at` and for `exit`, every holding whose holder `which` selects.
fn depart(
    spans: &mut [HolderSpan],
    which: impl Fn(ReservationId) -> bool,
    at: MonotonicTime,
    exit: HolderExit,
) {
    for span in spans
        .iter_mut()
        .filter(|span| span.left.is_none() && which(span.holder))
    {
        span.left = Some(Departure { at, exit });
    }
}

/// Splits the integral of `history` up to `until` among the holders `spans` describe (see
/// the module documentation).
fn holder_costs(
    spans: &[HolderSpan],
    history: &[AmountChange],
    until: MonotonicTime,
) -> Vec<HolderCost> {
    let Some(first) = history.first().map(|change| change.at) else {
        return Vec::new();
    };
    let mut points: BTreeSet<MonotonicTime> = history.iter().map(|change| change.at).collect();
    for span in spans {
        points.insert(span.joined_at);
        if let Some(left) = span.left {
            points.insert(left.at);
        }
    }
    points.insert(until);
    let points: Vec<MonotonicTime> = points
        .into_iter()
        .filter(|point| *point >= first && *point <= until)
        .collect();
    let mut totals: BTreeMap<(ReservationId, ResourceKey), u128> = BTreeMap::new();
    let mut last_present: Vec<ReservationId> = Vec::new();
    for window in points.windows(2) {
        let (start, end) = match window {
            [start, end] => (*start, *end),
            _ => continue,
        };
        let present: Vec<ReservationId> = spans
            .iter()
            .filter(|span| span.joined_at <= start && span.left.is_none_or(|left| left.at > start))
            .map(|span| span.holder)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let payers = if present.is_empty() {
            &last_present
        } else {
            last_present = present;
            &last_present
        };
        let Some(holders) = u128::try_from(payers.len()).ok().filter(|count| *count > 0) else {
            continue;
        };
        let Some(amounts) = history
            .iter()
            .take_while(|change| change.at <= start)
            .last()
            .map(|change| &change.amounts)
        else {
            continue;
        };
        let span = end.saturating_duration_since(start).as_nanos();
        for (resource, amount) in amounts.iter() {
            let cost = u128::from(amount).saturating_mul(span);
            let (each, remainder) = (cost / holders, cost % holders);
            for (index, holder) in payers.iter().enumerate() {
                let extra = u128::from(u128::try_from(index).is_ok_and(|index| index < remainder));
                let total = totals.entry((*holder, resource)).or_insert(0);
                *total = total.saturating_add(each.saturating_add(extra));
            }
        }
    }
    totals
        .into_iter()
        .filter_map(|((holder, resource), amount_nanoseconds)| {
            let provenance = spans
                .iter()
                .find(|span| span.holder == holder)?
                .provenance
                .clone();
            Some(HolderCost {
                holder,
                provenance,
                resource,
                amount_nanoseconds,
            })
        })
        .collect()
}
