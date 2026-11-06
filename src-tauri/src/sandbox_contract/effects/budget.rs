//! Release channels and wire-byte budgets (VM part §2.5 lines 1806–1817; VM-P32, VM-P33;
//! VM-D12).
//!
//! Every permitted release channel is declared with a destination trust class, an
//! accounting policy and a budget. A [`ReleaseLedger`] holds all reservations centrally,
//! so concurrent requests can never spend the same remaining budget, and it keeps
//!
//! ```text
//! counted_bytes_out <= sum(channel_budget) + documented_reserved_in_flight_allowance
//! ```
//!
//! (§2.5 lines 1812–1813). Headers, URLs, names and framing count wherever they leave the
//! trust domain: a [`WireMeasure`] has a field for each, and no accounting policy leaves
//! any of them out. Bytes are charged before they leave. A charge larger than its
//! reservation draws the excess from the documented in-flight allowance, and when that
//! is used up the charge is refused and the bytes must not be sent.
//!
//! This bounds bytes, not all information leakage: timing, correlations, packet
//! behaviour and shared hardware are not captured by a byte count (§2.5 line 1817).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::canonical::entries;
use crate::foundation::ids::Digest;
use crate::foundation::transfer::VM_D12_GENERAL_RELEASE_BUDGET_BYTES;

/// VM-D12's starting general release budget, 8 MiB, the value the transfer module also
/// holds (`transfer::VM_D12_GENERAL_RELEASE_BUDGET_BYTES`); adjusted from measurement per
/// VM part §12.4.
pub const DEFAULT_GENERAL_RELEASE_BUDGET_BYTES: u64 = VM_D12_GENERAL_RELEASE_BUDGET_BYTES;

/// A permitted release channel (§2.5 line 1808).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannelKind {
    ProviderRequest,
    TransportStream,
    DnsQuery,
    PublishedServiceResponse,
    File,
    TerminalOutput,
    Log,
    BrowserPreview,
    UserApprovedTransfer,
}

impl ReleaseChannelKind {
    /// Every channel §2.5 line 1808 names.
    pub const ALL: [Self; 9] = [
        Self::ProviderRequest,
        Self::TransportStream,
        Self::DnsQuery,
        Self::PublishedServiceResponse,
        Self::File,
        Self::TerminalOutput,
        Self::Log,
        Self::BrowserPreview,
        Self::UserApprovedTransfer,
    ];

    pub const fn tag(self) -> &'static str {
        match self {
            Self::ProviderRequest => "provider_request",
            Self::TransportStream => "transport_stream",
            Self::DnsQuery => "dns_query",
            Self::PublishedServiceResponse => "published_service_response",
            Self::File => "file",
            Self::TerminalOutput => "terminal_output",
            Self::Log => "log",
            Self::BrowserPreview => "browser_preview",
            Self::UserApprovedTransfer => "user_approved_transfer",
        }
    }
}

/// The trust class of a release destination (§2.5 line 1808).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    /// The user, through the host's own interface: terminal, preview, approval dialogs.
    HostUser,
    /// Host storage outside the sandbox: promoted files, logs.
    HostStorage,
    /// An external provider reached only through a registered route and an executor.
    RegisteredProvider,
    /// The public network: published services, transport streams.
    PublicNetwork,
    /// A DNS resolver.
    DnsResolver,
    /// An enrolled Yougori peer host.
    PeerHost,
}

impl TrustClass {
    pub const ALL: [Self; 6] = [
        Self::HostUser,
        Self::HostStorage,
        Self::RegisteredProvider,
        Self::PublicNetwork,
        Self::DnsResolver,
        Self::PeerHost,
    ];

    pub const fn tag(self) -> &'static str {
        match self {
            Self::HostUser => "host_user",
            Self::HostStorage => "host_storage",
            Self::RegisteredProvider => "registered_provider",
            Self::PublicNetwork => "public_network",
            Self::DnsResolver => "dns_resolver",
            Self::PeerHost => "peer_host",
        }
    }
}

/// The bytes of one release as they leave the trust domain (§2.5 line 1815). Every part
/// counts; there is no field for bytes that do not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireMeasure {
    pub body_bytes: u64,
    pub header_bytes: u64,
    pub url_bytes: u64,
    /// Names that leave the domain: DNS labels, TLS server names, file names.
    pub name_bytes: u64,
    pub framing_bytes: u64,
}

impl WireMeasure {
    /// The sum of every part, saturating so an overflow can only over-count.
    pub fn total_bytes(&self) -> u64 {
        self.body_bytes
            .saturating_add(self.header_bytes)
            .saturating_add(self.url_bytes)
            .saturating_add(self.name_bytes)
            .saturating_add(self.framing_bytes)
    }

    /// A release that is all body, for channels that carry no protocol framing of their
    /// own, such as terminal output.
    pub const fn body(body_bytes: u64) -> Self {
        Self {
            body_bytes,
            header_bytes: 0,
            url_bytes: 0,
            name_bytes: 0,
            framing_bytes: 0,
        }
    }
}

strict_tagged_enum! {
    /// How a channel counts one release (§2.5 line 1808: an accounting policy per
    /// channel). Both count every part of the [`WireMeasure`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum AccountingPolicy (tag = "accounting", wire = AccountingPolicyWire, wire_name = "AccountingPolicyWire") {
        /// Every byte that leaves.
        WireBytes,
        /// Every byte that leaves, and at least `floor_bytes` per message, for channels
        /// whose smallest message leaks more than its measured size, such as DNS.
        WireBytesWithMessageFloor { floor_bytes: u64 },
    }
}

impl AccountingPolicy {
    /// The bytes one release counts.
    pub fn counted_bytes(&self, measure: &WireMeasure) -> u64 {
        match self {
            Self::WireBytes => measure.total_bytes(),
            Self::WireBytesWithMessageFloor { floor_bytes } => {
                measure.total_bytes().max(*floor_bytes)
            }
        }
    }
}

strict_tagged_enum! {
    /// What a channel may count in total.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum ChannelBudget (tag = "budget", wire = ChannelBudgetWire, wire_name = "ChannelBudgetWire") {
        /// Counted against the sandbox's general release budget as well (VM-D12).
        General { budget_bytes: u64 },
        /// An explicitly approved transfer with its own budget, which never raises the
        /// general budget; `approval` names the approval record.
        Approved { budget_bytes: u64, approval: Digest },
    }
}

impl ChannelBudget {
    pub const fn budget_bytes(&self) -> u64 {
        match self {
            Self::General { budget_bytes } | Self::Approved { budget_bytes, .. } => *budget_bytes,
        }
    }

    pub const fn is_general(&self) -> bool {
        matches!(self, Self::General { .. })
    }
}

/// A channel and its destination trust class; one declaration each.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelKey {
    pub kind: ReleaseChannelKind,
    pub trust: TrustClass,
}

/// One declared release channel (§2.5 line 1808).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelDeclaration {
    pub key: ChannelKey,
    pub accounting: AccountingPolicy,
    pub budget: ChannelBudget,
}

/// Longest accepted allowance rationale.
pub const MAX_RATIONALE_BYTES: usize = 512;

/// The documented reserved in-flight allowance of §2.5 line 1813: bytes a charge may
/// count beyond its own reservation, such as framing a conservative estimate missed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InFlightAllowance {
    allowance_bytes: u64,
    rationale: String,
}

impl InFlightAllowance {
    /// No overrun at all; a charge must fit its reservation.
    pub fn none() -> Self {
        Self {
            allowance_bytes: 0,
            rationale: "no in-flight overrun is permitted".to_owned(),
        }
    }

    /// An allowance, refused unless it is documented by a rationale.
    pub fn documented(allowance_bytes: u64, rationale: &str) -> Result<Self, PolicyError> {
        let rationale = rationale.trim();
        if rationale.is_empty() {
            return Err(PolicyError::UndocumentedAllowance);
        }
        if rationale.len() > MAX_RATIONALE_BYTES {
            return Err(PolicyError::RationaleTooLong {
                max_bytes: MAX_RATIONALE_BYTES,
            });
        }
        Ok(Self {
            allowance_bytes,
            rationale: rationale.to_owned(),
        })
    }

    pub const fn allowance_bytes(&self) -> u64 {
        self.allowance_bytes
    }

    pub fn rationale(&self) -> &str {
        &self.rationale
    }
}

/// Why a release policy was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    DuplicateChannel {
        key: ChannelKey,
    },
    UndocumentedAllowance,
    RationaleTooLong {
        max_bytes: usize,
    },
    /// The budgets and allowance do not fit in 64 bits.
    CeilingOverflow,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateChannel { key } => write!(
                f,
                "the {} channel to {} is declared twice",
                key.kind.tag(),
                key.trust.tag()
            ),
            Self::UndocumentedAllowance => {
                f.write_str("an in-flight allowance needs a documented rationale")
            }
            Self::RationaleTooLong { max_bytes } => {
                write!(
                    f,
                    "the allowance rationale is longer than {max_bytes} bytes"
                )
            }
            Self::CeilingOverflow => f.write_str("the release budgets overflow 64 bits"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// The declared release channels of one sandbox, its general budget and its allowance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePolicy {
    #[serde(with = "entries")]
    channels: BTreeMap<ChannelKey, ChannelDeclaration>,
    general_budget_bytes: u64,
    allowance: InFlightAllowance,
}

impl ReleasePolicy {
    /// A policy with `general_budget_bytes` over every general channel together.
    pub fn new(
        general_budget_bytes: u64,
        channels: Vec<ChannelDeclaration>,
        allowance: InFlightAllowance,
    ) -> Result<Self, PolicyError> {
        let mut declared = BTreeMap::new();
        for channel in channels {
            if declared.insert(channel.key, channel).is_some() {
                return Err(PolicyError::DuplicateChannel { key: channel.key });
            }
        }
        let policy = Self {
            channels: declared,
            general_budget_bytes,
            allowance,
        };
        policy
            .checked_ceiling()
            .ok_or(PolicyError::CeilingOverflow)?;
        Ok(policy)
    }

    /// [`ReleasePolicy::new`] with VM-D12's 8 MiB general budget.
    pub fn vm_d12(
        channels: Vec<ChannelDeclaration>,
        allowance: InFlightAllowance,
    ) -> Result<Self, PolicyError> {
        Self::new(DEFAULT_GENERAL_RELEASE_BUDGET_BYTES, channels, allowance)
    }

    pub fn channel(&self, key: &ChannelKey) -> Option<&ChannelDeclaration> {
        self.channels.get(key)
    }

    pub fn channels(&self) -> impl Iterator<Item = &ChannelDeclaration> {
        self.channels.values()
    }

    pub const fn general_budget_bytes(&self) -> u64 {
        self.general_budget_bytes
    }

    pub fn allowance(&self) -> &InFlightAllowance {
        &self.allowance
    }

    /// `sum(channel_budget) + documented_reserved_in_flight_allowance`.
    pub fn ceiling_bytes(&self) -> u64 {
        self.checked_ceiling().unwrap_or(u64::MAX)
    }

    fn checked_ceiling(&self) -> Option<u64> {
        self.channels
            .values()
            .try_fold(self.allowance.allowance_bytes, |sum, channel| {
                sum.checked_add(channel.budget.budget_bytes())
            })
    }
}

/// Names one reservation in a [`ReleaseLedger`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReservationToken(u64);

impl ReservationToken {
    pub(super) const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A granted release reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseReservation {
    pub token: ReservationToken,
    pub channel: ChannelKey,
    pub reserved_bytes: u64,
}

/// What one charge counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseCharge {
    pub counted_bytes: u64,
    pub from_reservation_bytes: u64,
    pub from_allowance_bytes: u64,
}

/// Where one channel stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelUsage {
    /// Reserved and not yet charged.
    pub reserved_bytes: u64,
    /// Charged within the channel's budget.
    pub counted_bytes: u64,
    /// Charged beyond reservations, from the in-flight allowance.
    pub allowance_bytes: u64,
}

/// Why a release was refused; nothing was counted and the bytes must not leave.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRefusal {
    pub channel: Option<ChannelKey>,
    pub reason: ReleaseRefusalReason,
}

strict_tagged_enum! {
    /// The reason in a [`ReleaseRefusal`].
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ReleaseRefusalReason (tag = "reason", wire = ReleaseRefusalReasonWire, wire_name = "ReleaseRefusalReasonWire") {
        /// The channel is not declared, so it releases nothing (VM-P33).
        UndeclaredChannel,
        EmptyReservation,
        ChannelBudgetExhausted { requested_bytes: u64, available_bytes: u64 },
        GeneralBudgetExhausted { requested_bytes: u64, available_bytes: u64 },
        AllowanceExhausted { overrun_bytes: u64, available_bytes: u64 },
        UnknownReservation { token: ReservationToken },
        TokensExhausted,
    }
}

impl fmt::Display for ReleaseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(channel) = &self.channel {
            write!(
                f,
                "{} channel to {}: ",
                channel.kind.tag(),
                channel.trust.tag()
            )?;
        }
        match &self.reason {
            ReleaseRefusalReason::UndeclaredChannel => {
                f.write_str("the channel is not declared, so it releases nothing")
            }
            ReleaseRefusalReason::EmptyReservation => f.write_str("a reservation needs bytes"),
            ReleaseRefusalReason::ChannelBudgetExhausted {
                requested_bytes,
                available_bytes,
            } => write!(
                f,
                "{requested_bytes} bytes requested, {available_bytes} left in the channel budget"
            ),
            ReleaseRefusalReason::GeneralBudgetExhausted {
                requested_bytes,
                available_bytes,
            } => write!(
                f,
                "{requested_bytes} bytes requested, {available_bytes} left in the general \
                 release budget"
            ),
            ReleaseRefusalReason::AllowanceExhausted {
                overrun_bytes,
                available_bytes,
            } => write!(
                f,
                "{overrun_bytes} bytes beyond the reservation, {available_bytes} left in the \
                 in-flight allowance; the bytes must not be sent"
            ),
            ReleaseRefusalReason::UnknownReservation { token } => {
                write!(f, "reservation {} is not held", token.get())
            }
            ReleaseRefusalReason::TokensExhausted => f.write_str("no reservation tokens are left"),
        }
    }
}

impl std::error::Error for ReleaseRefusal {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeldRelease {
    channel: ChannelKey,
    reserved_bytes: u64,
    charged_bytes: u64,
}

impl HeldRelease {
    fn unspent_bytes(&self) -> u64 {
        self.reserved_bytes.saturating_sub(self.charged_bytes)
    }
}

/// The central release ledger of one sandbox (§2.5 line 1815).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseLedger {
    policy: ReleasePolicy,
    #[serde(with = "entries")]
    usage: BTreeMap<ChannelKey, ChannelUsage>,
    held: BTreeMap<ReservationToken, HeldRelease>,
    allowance_used_bytes: u64,
    next_token: u64,
}

impl ReleaseLedger {
    pub fn new(policy: ReleasePolicy) -> Self {
        let usage = policy
            .channels
            .keys()
            .map(|key| (*key, ChannelUsage::default()))
            .collect();
        Self {
            policy,
            usage,
            held: BTreeMap::new(),
            allowance_used_bytes: 0,
            next_token: 1,
        }
    }

    pub fn policy(&self) -> &ReleasePolicy {
        &self.policy
    }

    /// Reserves `bytes` on `channel`, within the channel's budget and, for a general
    /// channel, within the general budget; partial grants are never made.
    pub fn reserve(
        &mut self,
        channel: ChannelKey,
        bytes: u64,
    ) -> Result<ReleaseReservation, ReleaseRefusal> {
        let refuse = |reason| ReleaseRefusal {
            channel: Some(channel),
            reason,
        };
        let declaration = *self
            .policy
            .channel(&channel)
            .ok_or_else(|| refuse(ReleaseRefusalReason::UndeclaredChannel))?;
        if bytes == 0 {
            return Err(refuse(ReleaseRefusalReason::EmptyReservation));
        }
        let usage = self.usage.get(&channel).copied().unwrap_or_default();
        let committed = usage.reserved_bytes.saturating_add(usage.counted_bytes);
        let available = declaration.budget.budget_bytes().saturating_sub(committed);
        if bytes > available {
            return Err(refuse(ReleaseRefusalReason::ChannelBudgetExhausted {
                requested_bytes: bytes,
                available_bytes: available,
            }));
        }
        if declaration.budget.is_general() {
            let general_available = self
                .policy
                .general_budget_bytes
                .saturating_sub(self.general_committed_bytes());
            if bytes > general_available {
                return Err(refuse(ReleaseRefusalReason::GeneralBudgetExhausted {
                    requested_bytes: bytes,
                    available_bytes: general_available,
                }));
            }
        }
        let token = ReservationToken(self.next_token);
        self.next_token = self
            .next_token
            .checked_add(1)
            .ok_or_else(|| refuse(ReleaseRefusalReason::TokensExhausted))?;
        self.held.insert(
            token,
            HeldRelease {
                channel,
                reserved_bytes: bytes,
                charged_bytes: 0,
            },
        );
        let entry = self.usage.entry(channel).or_default();
        entry.reserved_bytes = entry.reserved_bytes.saturating_add(bytes);
        Ok(ReleaseReservation {
            token,
            channel,
            reserved_bytes: bytes,
        })
    }

    /// Charges one release before its bytes leave. The excess over what is left of the
    /// reservation comes from the in-flight allowance; if that cannot cover it, nothing is
    /// counted and the release is refused.
    pub fn charge(
        &mut self,
        token: ReservationToken,
        measure: &WireMeasure,
    ) -> Result<ReleaseCharge, ReleaseRefusal> {
        let held = *self.held.get(&token).ok_or(ReleaseRefusal {
            channel: None,
            reason: ReleaseRefusalReason::UnknownReservation { token },
        })?;
        let accounting = self
            .policy
            .channel(&held.channel)
            .map(|declaration| declaration.accounting)
            .ok_or(ReleaseRefusal {
                channel: Some(held.channel),
                reason: ReleaseRefusalReason::UndeclaredChannel,
            })?;
        let counted = accounting.counted_bytes(measure);
        let from_reservation = counted.min(held.unspent_bytes());
        let overrun = counted - from_reservation;
        let allowance_left = self.allowance_left_bytes();
        if overrun > allowance_left {
            return Err(ReleaseRefusal {
                channel: Some(held.channel),
                reason: ReleaseRefusalReason::AllowanceExhausted {
                    overrun_bytes: overrun,
                    available_bytes: allowance_left,
                },
            });
        }
        if let Some(entry) = self.held.get_mut(&token) {
            entry.charged_bytes = entry.charged_bytes.saturating_add(from_reservation);
        }
        let usage = self.usage.entry(held.channel).or_default();
        usage.reserved_bytes = usage.reserved_bytes.saturating_sub(from_reservation);
        usage.counted_bytes = usage.counted_bytes.saturating_add(from_reservation);
        usage.allowance_bytes = usage.allowance_bytes.saturating_add(overrun);
        self.allowance_used_bytes = self.allowance_used_bytes.saturating_add(overrun);
        Ok(ReleaseCharge {
            counted_bytes: counted,
            from_reservation_bytes: from_reservation,
            from_allowance_bytes: overrun,
        })
    }

    /// Ends a reservation and returns its unspent bytes to the channel.
    pub fn release(&mut self, token: ReservationToken) -> Result<u64, ReleaseRefusal> {
        let held = self.held.remove(&token).ok_or(ReleaseRefusal {
            channel: None,
            reason: ReleaseRefusalReason::UnknownReservation { token },
        })?;
        let unspent = held.unspent_bytes();
        let usage = self.usage.entry(held.channel).or_default();
        usage.reserved_bytes = usage.reserved_bytes.saturating_sub(unspent);
        Ok(unspent)
    }

    /// Every byte counted as released, within budgets and from the allowance.
    pub fn counted_bytes_out(&self) -> u64 {
        self.usage
            .values()
            .fold(self.allowance_used_bytes, |sum, usage| {
                sum.saturating_add(usage.counted_bytes)
            })
    }

    /// `sum(channel_budget) + documented_reserved_in_flight_allowance`.
    pub fn ceiling_bytes(&self) -> u64 {
        self.policy.ceiling_bytes()
    }

    pub fn usage(&self, channel: &ChannelKey) -> Option<ChannelUsage> {
        self.usage.get(channel).copied()
    }

    /// Bytes reserved and not yet charged, over every channel.
    pub fn outstanding_reserved_bytes(&self) -> u64 {
        self.usage
            .values()
            .fold(0u64, |sum, usage| sum.saturating_add(usage.reserved_bytes))
    }

    pub fn allowance_left_bytes(&self) -> u64 {
        self.policy
            .allowance
            .allowance_bytes
            .saturating_sub(self.allowance_used_bytes)
    }

    pub fn held_reservations(&self) -> usize {
        self.held.len()
    }

    /// Reserved plus counted over the general channels.
    pub fn general_committed_bytes(&self) -> u64 {
        self.usage
            .iter()
            .filter(|(key, _)| {
                self.policy
                    .channel(key)
                    .is_some_and(|declaration| declaration.budget.is_general())
            })
            .fold(0u64, |sum, (_, usage)| {
                sum.saturating_add(usage.reserved_bytes)
                    .saturating_add(usage.counted_bytes)
            })
    }

    /// A compact identity of the mutable state, for the §12.3 model search.
    pub(super) fn fingerprint(&self) -> Vec<u64> {
        let mut state = vec![self.allowance_used_bytes, self.next_token];
        for usage in self.usage.values() {
            state.extend([
                usage.reserved_bytes,
                usage.counted_bytes,
                usage.allowance_bytes,
            ]);
        }
        for (token, held) in &self.held {
            let channel = self
                .policy
                .channels
                .keys()
                .position(|key| *key == held.channel)
                .map_or(u64::MAX, |index| index as u64);
            state.extend([token.0, channel, held.reserved_bytes, held.charged_bytes]);
        }
        state
    }

    /// The first broken ledger invariant, if any: the §2.5 ceiling, each channel's
    /// budget, the general budget, the allowance, and agreement between reservations and
    /// channel totals.
    pub fn invariant_violation(&self) -> Option<String> {
        if self.counted_bytes_out() > self.ceiling_bytes() {
            return Some(format!(
                "counted {} bytes out above the ceiling of {}",
                self.counted_bytes_out(),
                self.ceiling_bytes()
            ));
        }
        for (key, usage) in &self.usage {
            let budget = self
                .policy
                .channel(key)
                .map_or(0, |declaration| declaration.budget.budget_bytes());
            if usage.reserved_bytes.saturating_add(usage.counted_bytes) > budget {
                return Some(format!("the {} channel exceeds its budget", key.kind.tag()));
            }
            let held: u64 = self
                .held
                .values()
                .filter(|held| held.channel == *key)
                .fold(0u64, |sum, held| sum.saturating_add(held.unspent_bytes()));
            if held != usage.reserved_bytes {
                return Some(format!(
                    "the {} channel's reservations disagree with its total",
                    key.kind.tag()
                ));
            }
        }
        if self.general_committed_bytes() > self.policy.general_budget_bytes {
            return Some("the general channels exceed the general budget".to_owned());
        }
        if self.allowance_used_bytes > self.policy.allowance.allowance_bytes {
            return Some("the in-flight allowance is overdrawn".to_owned());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    pub(crate) fn key(kind: ReleaseChannelKind, trust: TrustClass) -> ChannelKey {
        ChannelKey { kind, trust }
    }

    fn general(
        kind: ReleaseChannelKind,
        trust: TrustClass,
        budget_bytes: u64,
    ) -> ChannelDeclaration {
        ChannelDeclaration {
            key: key(kind, trust),
            accounting: AccountingPolicy::WireBytes,
            budget: ChannelBudget::General { budget_bytes },
        }
    }

    #[test]
    fn the_vm_d12_general_budget_is_8_mib() {
        assert_eq!(DEFAULT_GENERAL_RELEASE_BUDGET_BYTES, 8 * 1024 * 1024);
        assert_eq!(DEFAULT_GENERAL_RELEASE_BUDGET_BYTES, 8_388_608);
        let policy = ReleasePolicy::vm_d12(
            vec![general(
                ReleaseChannelKind::Log,
                TrustClass::HostStorage,
                16 * 1024 * 1024,
            )],
            InFlightAllowance::none(),
        )
        .unwrap();
        assert_eq!(policy.general_budget_bytes(), 8_388_608);
        let mut ledger = ReleaseLedger::new(policy);
        let log = key(ReleaseChannelKind::Log, TrustClass::HostStorage);
        // The channel would allow 16 MiB, but the general budget caps it at 8 MiB.
        let refused = ledger.reserve(log, 8_388_609).unwrap_err();
        assert_eq!(
            refused.reason,
            ReleaseRefusalReason::GeneralBudgetExhausted {
                requested_bytes: 8_388_609,
                available_bytes: 8_388_608
            }
        );
        ledger.reserve(log, 8_388_608).unwrap();
        assert!(ledger.reserve(log, 1).is_err());
    }

    #[test]
    fn the_ceiling_formula_holds_on_worked_numbers() {
        // Budgets 1000 + 300 + 64 and a documented 100-byte allowance: ceiling 1464.
        let policy = ReleasePolicy::new(
            1_500,
            vec![
                general(
                    ReleaseChannelKind::ProviderRequest,
                    TrustClass::RegisteredProvider,
                    1_000,
                ),
                general(ReleaseChannelKind::Log, TrustClass::HostStorage, 300),
                ChannelDeclaration {
                    key: key(ReleaseChannelKind::DnsQuery, TrustClass::DnsResolver),
                    accounting: AccountingPolicy::WireBytesWithMessageFloor { floor_bytes: 32 },
                    budget: ChannelBudget::General { budget_bytes: 64 },
                },
            ],
            InFlightAllowance::documented(100, "TLS record framing beyond the estimate").unwrap(),
        )
        .unwrap();
        assert_eq!(policy.ceiling_bytes(), 1_464);
        let mut ledger = ReleaseLedger::new(policy);
        let provider = key(
            ReleaseChannelKind::ProviderRequest,
            TrustClass::RegisteredProvider,
        );
        let reservation = ledger.reserve(provider, 1_000).unwrap();
        // 900 body + 80 headers + 40 URL + 20 name + 30 framing = 1070: 1000 from the
        // reservation and 70 from the allowance.
        let charge = ledger
            .charge(
                reservation.token,
                &WireMeasure {
                    body_bytes: 900,
                    header_bytes: 80,
                    url_bytes: 40,
                    name_bytes: 20,
                    framing_bytes: 30,
                },
            )
            .unwrap();
        assert_eq!(
            charge,
            ReleaseCharge {
                counted_bytes: 1_070,
                from_reservation_bytes: 1_000,
                from_allowance_bytes: 70
            }
        );
        assert_eq!(ledger.allowance_left_bytes(), 30);
        // A DNS query of 10 bytes counts its 32-byte floor.
        let dns = key(ReleaseChannelKind::DnsQuery, TrustClass::DnsResolver);
        let query = ledger.reserve(dns, 32).unwrap();
        assert_eq!(
            ledger
                .charge(
                    query.token,
                    &WireMeasure {
                        name_bytes: 10,
                        ..WireMeasure::default()
                    }
                )
                .unwrap()
                .counted_bytes,
            32
        );
        // 31 more overrun bytes than the allowance holds: refused, nothing counted.
        let before = ledger.counted_bytes_out();
        let log = ledger
            .reserve(key(ReleaseChannelKind::Log, TrustClass::HostStorage), 10)
            .unwrap();
        let refused = ledger
            .charge(log.token, &WireMeasure::body(41))
            .unwrap_err();
        assert_eq!(
            refused.reason,
            ReleaseRefusalReason::AllowanceExhausted {
                overrun_bytes: 31,
                available_bytes: 30
            }
        );
        assert_eq!(ledger.counted_bytes_out(), before);
        ledger.charge(log.token, &WireMeasure::body(40)).unwrap();
        assert_eq!(ledger.counted_bytes_out(), 1_070 + 32 + 40);
        assert_eq!(ledger.allowance_left_bytes(), 0);
        assert!(ledger.counted_bytes_out() <= ledger.ceiling_bytes());
        assert_eq!(ledger.invariant_violation(), None);
    }

    #[test]
    fn unused_reservations_return_and_unknown_tokens_are_refused() {
        let policy = ReleasePolicy::new(
            100,
            vec![general(
                ReleaseChannelKind::TerminalOutput,
                TrustClass::HostUser,
                100,
            )],
            InFlightAllowance::none(),
        )
        .unwrap();
        let mut ledger = ReleaseLedger::new(policy);
        let terminal = key(ReleaseChannelKind::TerminalOutput, TrustClass::HostUser);
        let first = ledger.reserve(terminal, 60).unwrap();
        assert!(ledger.reserve(terminal, 41).is_err());
        ledger.charge(first.token, &WireMeasure::body(25)).unwrap();
        assert_eq!(ledger.release(first.token), Ok(35));
        assert_eq!(
            ledger.usage(&terminal),
            Some(ChannelUsage {
                reserved_bytes: 0,
                counted_bytes: 25,
                allowance_bytes: 0
            })
        );
        ledger.reserve(terminal, 75).unwrap();
        assert!(ledger.reserve(terminal, 1).is_err());
        assert_eq!(
            ledger.release(first.token).unwrap_err().reason,
            ReleaseRefusalReason::UnknownReservation { token: first.token }
        );
        assert_eq!(
            ledger.reserve(terminal, 0).unwrap_err().reason,
            ReleaseRefusalReason::EmptyReservation
        );
    }

    #[test]
    fn policies_refuse_duplicates_undocumented_allowances_and_overflow() {
        let log = general(ReleaseChannelKind::Log, TrustClass::HostStorage, 1);
        assert_eq!(
            ReleasePolicy::new(1, vec![log, log], InFlightAllowance::none()),
            Err(PolicyError::DuplicateChannel { key: log.key })
        );
        assert_eq!(
            InFlightAllowance::documented(10, "  "),
            Err(PolicyError::UndocumentedAllowance)
        );
        assert!(InFlightAllowance::documented(10, &"x".repeat(513)).is_err());
        assert_eq!(
            ReleasePolicy::new(
                1,
                vec![
                    general(ReleaseChannelKind::Log, TrustClass::HostStorage, u64::MAX),
                    general(ReleaseChannelKind::File, TrustClass::HostStorage, 1),
                ],
                InFlightAllowance::none()
            ),
            Err(PolicyError::CeilingOverflow)
        );
    }

    #[test]
    fn approved_transfers_never_raise_the_general_budget() {
        let approval = digest("yougori/test/approval/v1", &[b"bulk"]);
        let policy = ReleasePolicy::new(
            10,
            vec![
                general(ReleaseChannelKind::Log, TrustClass::HostStorage, 10),
                ChannelDeclaration {
                    key: key(
                        ReleaseChannelKind::UserApprovedTransfer,
                        TrustClass::PublicNetwork,
                    ),
                    accounting: AccountingPolicy::WireBytes,
                    budget: ChannelBudget::Approved {
                        budget_bytes: 1_000,
                        approval,
                    },
                },
            ],
            InFlightAllowance::none(),
        )
        .unwrap();
        let mut ledger = ReleaseLedger::new(policy);
        ledger
            .reserve(
                key(
                    ReleaseChannelKind::UserApprovedTransfer,
                    TrustClass::PublicNetwork,
                ),
                1_000,
            )
            .unwrap();
        ledger
            .reserve(key(ReleaseChannelKind::Log, TrustClass::HostStorage), 10)
            .unwrap();
        assert_eq!(ledger.general_committed_bytes(), 10);
        assert_eq!(ledger.ceiling_bytes(), 1_010);
    }

    #[test]
    fn the_ledger_round_trips_and_refuses_unknown_fields() {
        let policy = ReleasePolicy::vm_d12(
            vec![general(
                ReleaseChannelKind::File,
                TrustClass::HostStorage,
                5,
            )],
            InFlightAllowance::none(),
        )
        .unwrap();
        let mut ledger = ReleaseLedger::new(policy);
        ledger
            .reserve(key(ReleaseChannelKind::File, TrustClass::HostStorage), 3)
            .unwrap();
        let json = serde_json::to_value(&ledger).unwrap();
        assert_eq!(
            serde_json::from_value::<ReleaseLedger>(json.clone()).unwrap(),
            ledger
        );
        let mut extra = json;
        extra["shadow_budget"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ReleaseLedger>(extra).is_err());
        assert!(serde_json::from_value::<AccountingPolicy>(
            serde_json::json!({"accounting": "wire_bytes", "skip_headers": true})
        )
        .is_err());
    }
}
