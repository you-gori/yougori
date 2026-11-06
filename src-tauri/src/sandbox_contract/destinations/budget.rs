//! Name, connection, byte and effect budgets per route (VM §4.2 step 7; VM-W03: budget
//! scope explicit), and the sandbox's release channels (VM §2.5).
//!
//! Every budget is reserved centrally before use, so concurrent requests cannot each
//! spend the same remainder (VM §2.5; VM-P32). The release account keeps
//!
//! ```text
//! counted_bytes_out <= sum(channel_budget) + documented_reserved_in_flight_allowance
//! ```
//!
//! and charges the VM-D12 general release budget of CORE-05 for everything it counts.
//! This bounds counted bytes only, not all information leakage (line 1817).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::transfer::GeneralReleaseBudget;

use super::policy::RouteId;

/// The limits of one route grant. Their scope is that route for the life of the sandbox:
/// usage is kept per route id and a new policy epoch does not reset it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteBudgets {
    /// DNS queries the broker may send for this route (the name budget).
    pub dns_queries: u64,
    /// Connections the broker may open.
    pub connections: u64,
    /// Bytes the broker may send.
    pub bytes_out: u64,
    /// Bytes the broker may receive.
    pub bytes_in: u64,
    /// External effects (operations that change state elsewhere).
    pub effects: u64,
}

/// One kind of route budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetKind {
    DnsQueries,
    Connections,
    BytesOut,
    BytesIn,
    Effects,
}

impl BudgetKind {
    /// Every budget kind of a route.
    pub const ALL: [Self; 5] = [
        Self::DnsQueries,
        Self::Connections,
        Self::BytesOut,
        Self::BytesIn,
        Self::Effects,
    ];

    const fn index(self) -> usize {
        match self {
            Self::DnsQueries => 0,
            Self::Connections => 1,
            Self::BytesOut => 2,
            Self::BytesIn => 3,
            Self::Effects => 4,
        }
    }
}

impl RouteBudgets {
    /// The limit of one kind.
    pub const fn limit(&self, kind: BudgetKind) -> u64 {
        match kind {
            BudgetKind::DnsQueries => self.dns_queries,
            BudgetKind::Connections => self.connections,
            BudgetKind::BytesOut => self.bytes_out,
            BudgetKind::BytesIn => self.bytes_in,
            BudgetKind::Effects => self.effects,
        }
    }
}

/// Where a budget applies (VM-W03: budget scope explicit).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BudgetScope {
    /// One route grant, for the life of the sandbox.
    Route(RouteId),
    /// One release channel of the sandbox.
    ReleaseChannel(ReleaseChannel),
    /// The sandbox's VM-D12 general release budget.
    GeneralRelease,
}

impl fmt::Display for BudgetScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Route(route) => write!(f, "route {route}"),
            Self::ReleaseChannel(channel) => write!(f, "release channel {channel:?}"),
            Self::GeneralRelease => f.write_str("the general release budget"),
        }
    }
}

/// A budget would be exceeded; nothing was charged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetExhausted {
    pub scope: BudgetScope,
    pub kind: Option<BudgetKind>,
    pub limit: u64,
    pub used: u64,
    pub reserved: u64,
    pub requested: u64,
}

impl fmt::Display for BudgetExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}: {} more would exceed the limit of {} ({} used, {} reserved)",
            self.scope,
            self.kind
                .map(|kind| format!(" {kind:?}"))
                .unwrap_or_default(),
            self.requested,
            self.limit,
            self.used,
            self.reserved
        )
    }
}

impl std::error::Error for BudgetExhausted {}

/// Usage of one route.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RouteUsage {
    used: [u64; 5],
    reserved: [u64; 5],
}

impl RouteUsage {
    pub const fn used(&self, kind: BudgetKind) -> u64 {
        self.used[kind.index()]
    }

    pub const fn reserved(&self, kind: BudgetKind) -> u64 {
        self.reserved[kind.index()]
    }
}

/// A held route-budget reservation. It must be committed or cancelled through the
/// [`BudgetBook`] that issued it.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct BudgetReservation {
    route: RouteId,
    kind: BudgetKind,
    amount: u64,
    id: u64,
}

impl BudgetReservation {
    pub fn route(&self) -> &RouteId {
        &self.route
    }

    pub const fn kind(&self) -> BudgetKind {
        self.kind
    }

    pub const fn amount(&self) -> u64 {
        self.amount
    }
}

/// Why a reservation could not be settled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettleError {
    /// The reservation is not open in this book.
    Unknown,
    /// More was used than reserved; the excess is refused, not silently counted.
    ExceedsReservation { reserved: u64, actual: u64 },
}

impl fmt::Display for SettleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("the reservation is not open"),
            Self::ExceedsReservation { reserved, actual } => {
                write!(f, "{actual} used exceeds the {reserved} reserved")
            }
        }
    }
}

impl std::error::Error for SettleError {}

/// The central book of route usage (VM §4.2 step 7).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BudgetBook {
    routes: BTreeMap<RouteId, RouteUsage>,
    open: BTreeMap<u64, (RouteId, BudgetKind, u64)>,
    next_id: u64,
}

impl BudgetBook {
    /// An empty book: nothing used or reserved.
    pub fn new() -> Self {
        Self::default()
    }

    /// Usage of `route` so far.
    pub fn usage(&self, route: &RouteId) -> RouteUsage {
        self.routes.get(route).copied().unwrap_or_default()
    }

    /// Reserves `amount` of `kind` for `route` against `limits`, or refuses without
    /// reserving.
    pub fn reserve(
        &mut self,
        route: &RouteId,
        limits: &RouteBudgets,
        kind: BudgetKind,
        amount: u64,
    ) -> Result<BudgetReservation, BudgetExhausted> {
        let usage = self.routes.entry(route.clone()).or_default();
        let index = kind.index();
        let limit = limits.limit(kind);
        let committed = usage.used[index].saturating_add(usage.reserved[index]);
        if committed
            .checked_add(amount)
            .is_none_or(|total| total > limit)
        {
            return Err(BudgetExhausted {
                scope: BudgetScope::Route(route.clone()),
                kind: Some(kind),
                limit,
                used: usage.used[index],
                reserved: usage.reserved[index],
                requested: amount,
            });
        }
        usage.reserved[index] = usage.reserved[index].saturating_add(amount);
        self.next_id = self.next_id.wrapping_add(1);
        self.open
            .insert(self.next_id, (route.clone(), kind, amount));
        Ok(BudgetReservation {
            route: route.clone(),
            kind,
            amount,
            id: self.next_id,
        })
    }

    /// Settles a reservation with the amount actually used; the rest returns to the
    /// budget. More than was reserved is refused, but the reservation is still closed and
    /// charged with what was used, so an overrun is counted and never left reserved.
    pub fn commit(
        &mut self,
        reservation: BudgetReservation,
        actual: u64,
    ) -> Result<(), SettleError> {
        self.settle(&reservation, actual)?;
        if actual > reservation.amount {
            return Err(SettleError::ExceedsReservation {
                reserved: reservation.amount,
                actual,
            });
        }
        Ok(())
    }

    /// Returns a reservation unused.
    pub fn cancel(&mut self, reservation: BudgetReservation) -> Result<(), SettleError> {
        self.settle(&reservation, 0)
    }

    /// Reserves and commits in one step.
    pub fn charge(
        &mut self,
        route: &RouteId,
        limits: &RouteBudgets,
        kind: BudgetKind,
        amount: u64,
    ) -> Result<(), BudgetExhausted> {
        let reservation = self.reserve(route, limits, kind, amount)?;
        self.open.remove(&reservation.id);
        let index = kind.index();
        let usage = self.routes.entry(route.clone()).or_default();
        usage.reserved[index] = usage.reserved[index].saturating_sub(amount);
        usage.used[index] = usage.used[index].saturating_add(amount);
        Ok(())
    }

    fn settle(&mut self, reservation: &BudgetReservation, actual: u64) -> Result<(), SettleError> {
        match self.open.get(&reservation.id) {
            Some((route, kind, amount))
                if *route == reservation.route
                    && *kind == reservation.kind
                    && *amount == reservation.amount => {}
            _ => return Err(SettleError::Unknown),
        }
        self.open.remove(&reservation.id);
        let index = reservation.kind.index();
        let usage = self.routes.entry(reservation.route.clone()).or_default();
        usage.reserved[index] = usage.reserved[index].saturating_sub(reservation.amount);
        usage.used[index] = usage.used[index].saturating_add(actual);
        Ok(())
    }
}

/// A permitted release channel (VM §2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    ProviderRequest,
    TransportStream,
    DnsQuery,
    PublishedServiceResponse,
    File,
    TerminalOutput,
    Log,
    BrowserPreview,
    /// A user-approved transfer. It carries its own CORE-05 envelope budget and never
    /// draws on this account (S3.7).
    UserApprovedTransfer,
}

/// The destination or trust class a channel releases to (VM §2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseTrustClass {
    /// An external provider or service.
    External,
    /// A resolver operated outside the trust domain.
    Resolver,
    /// The audience of a published service.
    PublishedAudience,
    /// The local user's own views (terminal, logs, previews, files).
    LocalUser,
}

/// One channel's budget and trust class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelPolicy {
    pub budget_bytes: u64,
    pub trust_class: ReleaseTrustClass,
}

/// The in-flight allowance: bytes that may leave beyond a reservation because their exact
/// size is not known until sent (framing, retransmission), with the reason documented.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InFlightAllowance {
    pub bytes: u64,
    pub documented_reason: String,
}

/// Why the release account refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseError {
    /// The channel has no policy, so it may release nothing.
    ChannelNotPermitted {
        channel: ReleaseChannel,
    },
    /// The channel is budgeted elsewhere (a CORE-05 transfer envelope).
    OwnBudgetChannel {
        channel: ReleaseChannel,
    },
    Exhausted(BudgetExhausted),
    /// The allowance has no documented reason.
    UndocumentedAllowance,
    /// Bytes beyond the reservation exceeded the documented allowance. They were counted
    /// (they already left), and the account refuses everything from now on.
    AllowanceExceeded {
        excess_bytes: u64,
        allowance_bytes: u64,
    },
    /// The account was closed by an earlier overrun.
    Closed,
    UnknownReservation,
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChannelNotPermitted { channel } => {
                write!(f, "release channel {channel:?} has no policy")
            }
            Self::OwnBudgetChannel { channel } => write!(
                f,
                "release channel {channel:?} uses its own transfer budget, not this account"
            ),
            Self::Exhausted(exhausted) => fmt::Display::fmt(exhausted, f),
            Self::UndocumentedAllowance => {
                f.write_str("the in-flight allowance must document its reason")
            }
            Self::AllowanceExceeded {
                excess_bytes,
                allowance_bytes,
            } => write!(
                f,
                "{excess_bytes} bytes beyond reservations exceed the {allowance_bytes}-byte \
                 in-flight allowance; releases are stopped"
            ),
            Self::Closed => f.write_str("releases are stopped after an allowance overrun"),
            Self::UnknownReservation => f.write_str("the release reservation is not open"),
        }
    }
}

impl std::error::Error for ReleaseError {}

/// A held release reservation.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct ReleaseReservation {
    channel: ReleaseChannel,
    bytes: u64,
    id: u64,
}

impl ReleaseReservation {
    pub const fn channel(&self) -> ReleaseChannel {
        self.channel
    }

    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ChannelState {
    used: u64,
    reserved: u64,
}

/// The sandbox's release account (VM §2.5): per-channel budgets with central reservation,
/// a documented in-flight allowance, and the VM-D12 general release budget of CORE-05
/// charged for every counted byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseAccount {
    policies: BTreeMap<ReleaseChannel, ChannelPolicy>,
    state: BTreeMap<ReleaseChannel, ChannelState>,
    general: GeneralReleaseBudget,
    general_reserved: u64,
    allowance: InFlightAllowance,
    allowance_used: u64,
    open: BTreeMap<u64, (ReleaseChannel, u64)>,
    next_id: u64,
    closed: bool,
}

impl ReleaseAccount {
    /// An account over `policies`, charging `general`. A user-approved transfer channel
    /// is refused (it has its own budget), as is an allowance without a reason.
    pub fn new(
        policies: BTreeMap<ReleaseChannel, ChannelPolicy>,
        general: GeneralReleaseBudget,
        allowance: InFlightAllowance,
    ) -> Result<Self, ReleaseError> {
        if policies.contains_key(&ReleaseChannel::UserApprovedTransfer) {
            return Err(ReleaseError::OwnBudgetChannel {
                channel: ReleaseChannel::UserApprovedTransfer,
            });
        }
        if allowance.documented_reason.trim().is_empty() {
            return Err(ReleaseError::UndocumentedAllowance);
        }
        Ok(Self {
            policies,
            state: BTreeMap::new(),
            general,
            general_reserved: 0,
            allowance,
            allowance_used: 0,
            open: BTreeMap::new(),
            next_id: 0,
            closed: false,
        })
    }

    /// Bytes counted as released so far, allowance overruns included.
    pub fn counted_bytes_out(&self) -> u64 {
        self.state
            .values()
            .map(|state| state.used)
            .sum::<u64>()
            .saturating_add(self.allowance_used)
    }

    /// The right-hand side of the VM §2.5 bound: the sum of channel budgets plus the
    /// documented in-flight allowance.
    pub fn bound_bytes(&self) -> u64 {
        self.policies
            .values()
            .map(|policy| policy.budget_bytes)
            .fold(0u64, u64::saturating_add)
            .saturating_add(self.allowance.bytes)
    }

    /// Bytes used on one channel.
    pub fn used_bytes(&self, channel: ReleaseChannel) -> u64 {
        self.state.get(&channel).map_or(0, |state| state.used)
    }

    pub fn general(&self) -> &GeneralReleaseBudget {
        &self.general
    }

    pub const fn allowance_used_bytes(&self) -> u64 {
        self.allowance_used
    }

    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Reserves `bytes` on `channel` against both its budget and the general budget.
    pub fn reserve(
        &mut self,
        channel: ReleaseChannel,
        bytes: u64,
    ) -> Result<ReleaseReservation, ReleaseError> {
        if self.closed {
            return Err(ReleaseError::Closed);
        }
        if channel == ReleaseChannel::UserApprovedTransfer {
            return Err(ReleaseError::OwnBudgetChannel { channel });
        }
        let policy = *self
            .policies
            .get(&channel)
            .ok_or(ReleaseError::ChannelNotPermitted { channel })?;
        let state = self.state.entry(channel).or_default();
        let held = state.used.saturating_add(state.reserved);
        if held
            .checked_add(bytes)
            .is_none_or(|total| total > policy.budget_bytes)
        {
            return Err(ReleaseError::Exhausted(BudgetExhausted {
                scope: BudgetScope::ReleaseChannel(channel),
                kind: None,
                limit: policy.budget_bytes,
                used: state.used,
                reserved: state.reserved,
                requested: bytes,
            }));
        }
        let general_free = self
            .general
            .remaining_bytes()
            .saturating_sub(self.general_reserved);
        if bytes > general_free {
            return Err(ReleaseError::Exhausted(BudgetExhausted {
                scope: BudgetScope::GeneralRelease,
                kind: None,
                limit: self.general.limit_bytes(),
                used: self.general.released_bytes(),
                reserved: self.general_reserved,
                requested: bytes,
            }));
        }
        state.reserved = state.reserved.saturating_add(bytes);
        self.general_reserved = self.general_reserved.saturating_add(bytes);
        self.next_id = self.next_id.wrapping_add(1);
        self.open.insert(self.next_id, (channel, bytes));
        Ok(ReleaseReservation {
            channel,
            bytes,
            id: self.next_id,
        })
    }

    /// Settles a reservation with the bytes that actually left. Bytes beyond the
    /// reservation draw on the in-flight allowance; beyond that they are still counted,
    /// the account closes and the overrun is reported.
    pub fn commit(
        &mut self,
        reservation: ReleaseReservation,
        actual_bytes: u64,
    ) -> Result<(), ReleaseError> {
        if self.open.remove(&reservation.id) != Some((reservation.channel, reservation.bytes)) {
            return Err(ReleaseError::UnknownReservation);
        }
        let within = actual_bytes.min(reservation.bytes);
        let excess = actual_bytes - within;
        self.general_reserved = self.general_reserved.saturating_sub(reservation.bytes);
        // The reservation already proved the general budget can take `within`, and only
        // this account charges it.
        if let Err(exceeded) = self.general.charge(within) {
            return Err(ReleaseError::Exhausted(BudgetExhausted {
                scope: BudgetScope::GeneralRelease,
                kind: None,
                limit: exceeded.limit_bytes,
                used: exceeded.released_bytes,
                reserved: self.general_reserved,
                requested: exceeded.requested_bytes,
            }));
        }
        let state = self.state.entry(reservation.channel).or_default();
        state.reserved = state.reserved.saturating_sub(reservation.bytes);
        state.used = state.used.saturating_add(within);
        if excess > 0 {
            self.allowance_used = self.allowance_used.saturating_add(excess);
            if self.allowance_used > self.allowance.bytes {
                self.closed = true;
                return Err(ReleaseError::AllowanceExceeded {
                    excess_bytes: self.allowance_used,
                    allowance_bytes: self.allowance.bytes,
                });
            }
        }
        Ok(())
    }

    /// Returns a reservation unused.
    pub fn cancel(&mut self, reservation: ReleaseReservation) -> Result<(), ReleaseError> {
        if self.open.remove(&reservation.id) != Some((reservation.channel, reservation.bytes)) {
            return Err(ReleaseError::UnknownReservation);
        }
        let state = self.state.entry(reservation.channel).or_default();
        state.reserved = state.reserved.saturating_sub(reservation.bytes);
        self.general_reserved = self.general_reserved.saturating_sub(reservation.bytes);
        Ok(())
    }

    /// Reserves and commits exactly `bytes` in one step.
    pub fn charge(&mut self, channel: ReleaseChannel, bytes: u64) -> Result<(), ReleaseError> {
        let reservation = self.reserve(channel, bytes)?;
        self.commit(reservation, bytes)
    }
}
