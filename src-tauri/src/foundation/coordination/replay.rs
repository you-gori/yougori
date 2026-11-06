//! Replay protection for authority-bearing messages (S2 CORE-04; VM part §6.3: "Nonces and
//! generation numbers are scoped by host/issuer and sandbox identity. Persist replay
//! protection across restarts."; VM-W29: nonces, lease verification and replay
//! protection; VM-P13: replayed and stale-generation capabilities fail without an external
//! effect; docs/combined-plan-remaining-only.md §8, S04 / M13 / M17).
//!
//! An issuer numbers the authority-bearing messages of one scope 1, 2, 3, …: grants,
//! renewals, effect requests and acknowledgments. The scope is a [`ScopedEpoch`], so a
//! number is never used twice: another host, issuer, run, sandbox or epoch is another
//! scope, and a run of the coordination authority is handed out only once persisted. The
//! receiver keeps a [`ReplayState`]:
//!
//! - Per scope, a sliding window of at most [`MAX_WINDOW`] numbers below the highest one
//!   accepted. A number is accepted once; a number again is refused, and so is one below
//!   the window, which may have been accepted already (fail closed). Memory is bounded by
//!   the window and by [`ReplayConfig::max_scopes`].
//! - Persisted as limits, not values, as lease ids are: no number above the limit of the
//!   latest confirmed [`ReplayRecord`] is accepted, so a receiver that restarts from its
//!   record ([`ReplayState::restore`]) refuses every number at or below the recorded limit,
//!   and a number accepted before the crash is never accepted again. A newer number waits
//!   for the next record ([`ReplayRefusal::LimitNotPersisted`]).
//! - Retired scopes fold into one floor per issuer and execution: accepting a number in a
//!   later run or epoch retires every earlier scope of that line, and the coordinator's
//!   epoch advance or an execution's retirement can retire them explicitly
//!   ([`ReplayState::retire_below`], [`ReplayState::retire_line`]). A retired scope's window
//!   goes, and every number in it is refused from then on: compaction never makes a number
//!   acceptable again.
//! - A revocation is idempotent and always delivered: replayed, below the window, in a
//!   retired scope or with no limit persisted, it is never refused, so replay protection
//!   never stands between a revocation and its enforcement (VM part §6.4).
//!
//! Nothing here reads a clock, so a clock that goes back or a skewed peer cannot reopen a
//! window.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::scope::{AuthorityIssuer, ScopedEpoch};
use crate::foundation::ids::{AuthorizationEpoch, ExecutionId, Incarnation};

/// The widest replay window: the bits of one `u128`.
pub const MAX_WINDOW: u32 = 128;

/// A message's number within its scope; numbers start at 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Nonce(u64);

impl Nonce {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// How a receiver keeps replay state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayConfig {
    /// How many numbers below the highest accepted one are still accepted out of order;
    /// at most [`MAX_WINDOW`].
    pub window: u32,
    /// How far above the highest accepted number a record sets each scope's limit, so a
    /// steady stream needs a record only every `persist_margin` messages.
    pub persist_margin: u64,
    /// Scopes with a window at most; a message in a further scope is refused.
    pub max_scopes: usize,
}

impl ReplayConfig {
    /// Refuses a window of zero or above [`MAX_WINDOW`], a zero margin and room for no
    /// scope.
    pub fn validate(&self) -> Result<(), ReplayConfigError> {
        if self.window == 0 || self.window > MAX_WINDOW {
            return Err(ReplayConfigError::WindowOutOfRange {
                window: self.window,
                max: MAX_WINDOW,
            });
        }
        if self.persist_margin == 0 {
            return Err(ReplayConfigError::ZeroMargin);
        }
        if self.max_scopes == 0 {
            return Err(ReplayConfigError::ZeroScopes);
        }
        Ok(())
    }
}

/// Why a replay configuration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ReplayConfigError {
    WindowOutOfRange { window: u32, max: u32 },
    ZeroMargin,
    ZeroScopes,
}

crate::foundation::strict_serde::strict_tag!(ReplayConfigError, "problem");

impl fmt::Display for ReplayConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WindowOutOfRange { window, max } => {
                write!(f, "a replay window of {window} is not within 1 to {max}")
            }
            Self::ZeroMargin => f.write_str("the persist margin must be above zero"),
            Self::ZeroScopes => f.write_str("the replay state must hold at least one scope"),
        }
    }
}

impl std::error::Error for ReplayConfigError {}

/// What an authority-bearing message carries (VM part §4.6, §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageClass {
    /// A grant of authority or a capability.
    Grant,
    /// A lease or capability renewal.
    Renewal,
    /// A request for an external effect.
    Effect,
    /// An enforcement point's acknowledgment, such as channels closed; a replayed one must
    /// never acknowledge a later revocation.
    Acknowledgment,
    /// A revocation: idempotent, so it is delivered whatever its number.
    Revocation,
}

impl MessageClass {
    /// Whether delivering the message twice has the effect of delivering it once.
    pub const fn is_idempotent(self) -> bool {
        matches!(self, Self::Revocation)
    }
}

/// How a message was let through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    /// Its number was accepted, once.
    Accepted,
    /// A revocation, delivered without a replay check.
    Idempotent,
}

/// The scopes of one issuer and execution that are retired: every message in them is
/// refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "floor", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum ScopeFloor {
    /// Every scope of an earlier run, or of an earlier epoch in this run.
    Below {
        incarnation: Incarnation,
        authorization: AuthorizationEpoch,
    },
    /// Every scope: the execution was retired.
    Retired,
}

crate::foundation::strict_serde::strict_tag!(ScopeFloor, "floor");

impl ScopeFloor {
    /// Whether `scope` is retired under this floor.
    pub fn refuses(&self, scope: &ScopedEpoch) -> bool {
        match self {
            Self::Below {
                incarnation,
                authorization,
            } => scope.position() < (*incarnation, *authorization),
            Self::Retired => true,
        }
    }

    /// The higher of the two floors.
    fn raised(self, other: Self) -> Self {
        match (self, other) {
            (Self::Retired, _) | (_, Self::Retired) => Self::Retired,
            (
                Self::Below {
                    incarnation,
                    authorization,
                },
                Self::Below {
                    incarnation: other_incarnation,
                    authorization: other_authorization,
                },
            ) => {
                let (incarnation, authorization) =
                    (incarnation, authorization).max((other_incarnation, other_authorization));
                Self::Below {
                    incarnation,
                    authorization,
                }
            }
        }
    }
}

/// Why a message was refused (VM-P13: no external effect). The refusal names no scope: the
/// receiver refused the scope it was handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ReplayRefusal {
    /// Numbers start at 1.
    ZeroNonce,
    /// The number was already accepted in its scope.
    Replayed { nonce: Nonce },
    /// The number is below what the window still tracks, or at or below the limit a
    /// restart restored; it may have been accepted, so it is refused.
    BelowWindow { nonce: Nonce, lowest: u64 },
    /// The scope was retired: an earlier run or epoch, or a retired execution.
    ScopeRetired { floor: ScopeFloor },
    /// The number is above the limit of the latest confirmed record; it is accepted once a
    /// record covering it is confirmed ([`ReplayState::confirm_persisted`]).
    LimitNotPersisted { nonce: Nonce, limit: u64 },
    /// No room for another scope.
    TooManyScopes { max: usize },
}

crate::foundation::strict_serde::strict_tag!(ReplayRefusal, "refusal");

impl fmt::Display for ReplayRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroNonce => f.write_str("message numbers start at 1"),
            Self::Replayed { nonce } => {
                write!(f, "message {} was already accepted in its scope", nonce.get())
            }
            Self::BelowWindow { nonce, lowest } => write!(
                f,
                "message {} is below the lowest number its scope still accepts, {lowest}",
                nonce.get()
            ),
            Self::ScopeRetired { .. } => {
                f.write_str("the scope is retired; none of its messages is accepted")
            }
            Self::LimitNotPersisted { nonce, limit } => write!(
                f,
                "message {} is above the persisted limit {limit}; it is accepted once a record                  covering it is persisted",
                nonce.get()
            ),
            Self::TooManyScopes { max } => {
                write!(f, "the replay state already holds its {max} scopes")
            }
        }
    }
}

impl std::error::Error for ReplayRefusal {}

/// One scope's window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Window {
    /// The highest number accepted; 0 when none was.
    highest: u64,
    /// Bit `i` is set when `highest - i` was accepted.
    seen: u128,
    /// Every number at or below it is refused: the limit a restart restored.
    floor: u64,
    /// No number above it is accepted: the limit of the latest confirmed record.
    limit: u64,
    /// The limit the next record asks for, raised by a number refused above the limit.
    wanted: u64,
}

/// One scope's limit in a [`ReplayRecord`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeLimit {
    pub scope: ScopedEpoch,
    pub limit: u64,
}

/// One issuer's and execution's floor in a [`ReplayRecord`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineFloor {
    pub issuer: AuthorityIssuer,
    pub execution: ExecutionId,
    pub floor: ScopeFloor,
}

/// What a receiver persists of its replay state: each scope's limit and each line's floor
/// (VM part §6.3: persist replay protection across restarts). Store it durably, then pass
/// it to [`ReplayState::confirm_persisted`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRecord {
    limits: Vec<ScopeLimit>,
    floors: Vec<LineFloor>,
}

impl ReplayRecord {
    /// Each scope's limit, in scope order.
    pub fn limits(&self) -> &[ScopeLimit] {
        &self.limits
    }

    /// Each line's floor, in line order.
    pub fn floors(&self) -> &[LineFloor] {
        &self.floors
    }

    /// Whether the record holds nothing.
    pub fn is_empty(&self) -> bool {
        self.limits.is_empty() && self.floors.is_empty()
    }

    /// The limit recorded for `scope`.
    pub fn limit(&self, scope: &ScopedEpoch) -> Option<u64> {
        self.limits
            .iter()
            .find(|entry| &entry.scope == scope)
            .map(|entry| entry.limit)
    }

    /// The floor recorded for `issuer` and `execution`.
    pub fn floor(&self, issuer: AuthorityIssuer, execution: &ExecutionId) -> Option<ScopeFloor> {
        self.floors
            .iter()
            .find(|entry| entry.issuer == issuer && &entry.execution == execution)
            .map(|entry| entry.floor)
    }

    /// The two records merged: each scope's higher limit and each line's higher floor,
    /// without the scopes the floors retire. Merging never lowers anything, so a record
    /// restored from an older copy and merged with a newer one is the newer one's.
    pub fn merge(&self, other: &Self) -> Self {
        let mut floors: BTreeMap<(AuthorityIssuer, ExecutionId), ScopeFloor> = BTreeMap::new();
        for entry in self.floors.iter().chain(&other.floors) {
            floors
                .entry((entry.issuer, entry.execution.clone()))
                .and_modify(|floor| *floor = floor.raised(entry.floor))
                .or_insert(entry.floor);
        }
        let mut limits: BTreeMap<ScopedEpoch, u64> = BTreeMap::new();
        for entry in self.limits.iter().chain(&other.limits) {
            let retired = floors
                .get(&(entry.scope.issuer, entry.scope.execution.clone()))
                .is_some_and(|floor| floor.refuses(&entry.scope));
            if retired {
                continue;
            }
            limits
                .entry(entry.scope.clone())
                .and_modify(|limit| *limit = (*limit).max(entry.limit))
                .or_insert(entry.limit);
        }
        Self::from_maps(limits, floors)
    }

    fn from_maps(
        limits: BTreeMap<ScopedEpoch, u64>,
        floors: BTreeMap<(AuthorityIssuer, ExecutionId), ScopeFloor>,
    ) -> Self {
        Self {
            limits: limits
                .into_iter()
                .map(|(scope, limit)| ScopeLimit { scope, limit })
                .collect(),
            floors: floors
                .into_iter()
                .map(|((issuer, execution), floor)| LineFloor {
                    issuer,
                    execution,
                    floor,
                })
                .collect(),
        }
    }
}

/// A receiver's replay state for authority-bearing messages (VM part §6.3; VM-W29).
#[derive(Clone, Debug)]
pub struct ReplayState {
    config: ReplayConfig,
    windows: BTreeMap<ScopedEpoch, Window>,
    floors: BTreeMap<(AuthorityIssuer, ExecutionId), ScopeFloor>,
}

impl ReplayState {
    /// A receiver with no earlier run: it accepts nothing until its first record is
    /// confirmed.
    pub fn new(config: ReplayConfig) -> Result<Self, ReplayConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            windows: BTreeMap::new(),
            floors: BTreeMap::new(),
        })
    }

    /// A receiver restarted from `record`, its latest confirmed record: in every recorded
    /// scope, each number at or below the recorded limit is refused, so nothing accepted
    /// before the restart is accepted again, and the floors stand.
    pub fn restore(config: ReplayConfig, record: &ReplayRecord) -> Result<Self, ReplayConfigError> {
        let mut state = Self::new(config)?;
        for entry in &record.floors {
            state
                .floors
                .entry((entry.issuer, entry.execution.clone()))
                .and_modify(|floor| *floor = floor.raised(entry.floor))
                .or_insert(entry.floor);
        }
        for entry in &record.limits {
            if state.retired(&entry.scope).is_some() {
                continue;
            }
            let window = state.windows.entry(entry.scope.clone()).or_default();
            window.floor = window.floor.max(entry.limit);
            window.limit = window.limit.max(entry.limit);
            window.wanted = window.wanted.max(entry.limit);
        }
        Ok(state)
    }

    /// The configuration.
    pub fn config(&self) -> ReplayConfig {
        self.config
    }

    /// Scopes with a window now.
    pub fn scopes(&self) -> usize {
        self.windows.len()
    }

    /// The floor of `issuer` and `execution`, if any of their scopes is retired.
    pub fn floor(&self, issuer: AuthorityIssuer, execution: &ExecutionId) -> Option<ScopeFloor> {
        self.floors.get(&(issuer, execution.clone())).copied()
    }

    /// Lets one message of `class`, numbered `nonce` in `scope`, through at most once. A
    /// revocation always passes ([`Delivery::Idempotent`]). Accepting a number in a later
    /// run or epoch than every earlier scope of its issuer and execution retires those.
    pub fn accept(
        &mut self,
        scope: &ScopedEpoch,
        nonce: Nonce,
        class: MessageClass,
    ) -> Result<Delivery, ReplayRefusal> {
        if class.is_idempotent() {
            return Ok(Delivery::Idempotent);
        }
        let number = nonce.get();
        if number == 0 {
            return Err(ReplayRefusal::ZeroNonce);
        }
        if let Some(floor) = self.retired(scope) {
            return Err(ReplayRefusal::ScopeRetired { floor });
        }
        if !self.windows.contains_key(scope) && self.windows.len() >= self.config.max_scopes {
            return Err(ReplayRefusal::TooManyScopes {
                max: self.config.max_scopes,
            });
        }
        let width = u64::from(self.config.window);
        let margin = self.config.persist_margin;
        let window = self.windows.entry(scope.clone()).or_default();
        if number <= window.floor {
            return Err(ReplayRefusal::BelowWindow {
                nonce,
                lowest: window.floor.saturating_add(1),
            });
        }
        if window.highest > 0 && number.saturating_add(width) <= window.highest {
            return Err(ReplayRefusal::BelowWindow {
                nonce,
                lowest: window.highest.saturating_sub(width).saturating_add(1),
            });
        }
        if number <= window.highest {
            let bit = u32::try_from(window.highest - number)
                .ok()
                .and_then(|offset| 1u128.checked_shl(offset))
                .unwrap_or(0);
            if bit == 0 || window.seen & bit != 0 {
                return Err(ReplayRefusal::Replayed { nonce });
            }
            window.seen |= bit;
            return Ok(Delivery::Accepted);
        }
        if number > window.limit {
            window.wanted = window.wanted.max(number.saturating_add(margin));
            return Err(ReplayRefusal::LimitNotPersisted {
                nonce,
                limit: window.limit,
            });
        }
        let shift = number - window.highest;
        window.seen = u32::try_from(shift)
            .ok()
            .and_then(|shift| window.seen.checked_shl(shift))
            .unwrap_or(0)
            | 1;
        window.highest = number;
        self.retire_below(scope);
        Ok(Delivery::Accepted)
    }

    /// Retires every scope of `current`'s issuer and execution in an earlier run, or in an
    /// earlier epoch of `current`'s run, such as when the coordinator advances the epoch:
    /// their windows go and their messages are refused from now on. Returns how many
    /// windows went.
    pub fn retire_below(&mut self, current: &ScopedEpoch) -> usize {
        let (incarnation, authorization) = current.position();
        self.raise_floor(
            current.issuer,
            &current.execution,
            ScopeFloor::Below {
                incarnation,
                authorization,
            },
        )
    }

    /// Retires every scope of `issuer` and `execution`, such as when the execution is
    /// retired ([`Coordinator::retire`](super::Coordinator::retire)). Returns how many
    /// windows went.
    pub fn retire_line(&mut self, issuer: AuthorityIssuer, execution: &ExecutionId) -> usize {
        self.raise_floor(issuer, execution, ScopeFloor::Retired)
    }

    fn raise_floor(
        &mut self,
        issuer: AuthorityIssuer,
        execution: &ExecutionId,
        floor: ScopeFloor,
    ) -> usize {
        let raised = self
            .floors
            .get(&(issuer, execution.clone()))
            .map_or(floor, |current| current.raised(floor));
        self.floors.insert((issuer, execution.clone()), raised);
        let before = self.windows.len();
        self.windows.retain(|scope, _| {
            !(scope.issuer == issuer && &scope.execution == execution && raised.refuses(scope))
        });
        before - self.windows.len()
    }

    /// The floor that retires `scope`, if one does.
    fn retired(&self, scope: &ScopedEpoch) -> Option<ScopeFloor> {
        self.floors
            .get(&(scope.issuer, scope.execution.clone()))
            .copied()
            .filter(|floor| floor.refuses(scope))
    }

    /// What to persist now: each scope's limit, `persist_margin` above its highest number
    /// or higher, and each line's floor. Store it durably, then confirm it.
    pub fn persist(&self) -> ReplayRecord {
        let margin = self.config.persist_margin;
        let limits = self
            .windows
            .iter()
            .map(|(scope, window)| {
                let limit = window
                    .limit
                    .max(window.wanted)
                    .max(window.highest.saturating_add(margin));
                (scope.clone(), limit)
            })
            .collect();
        ReplayRecord::from_maps(limits, self.floors.clone())
    }

    /// `record`, from [`ReplayState::persist`], is stored durably: each scope may accept
    /// numbers up to its recorded limit.
    pub fn confirm_persisted(&mut self, record: &ReplayRecord) {
        for entry in &record.limits {
            if let Some(window) = self.windows.get_mut(&entry.scope) {
                window.limit = window.limit.max(entry.limit);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::coordination::scope::{HostId, IssuerId};

    fn config() -> ReplayConfig {
        ReplayConfig {
            window: 4,
            persist_margin: 10,
            max_scopes: 3,
        }
    }

    fn issuer(host: &str) -> AuthorityIssuer {
        AuthorityIssuer {
            host: HostId::named(host),
            issuer: IssuerId::named("coordinator"),
        }
    }

    fn scope(host: &str, run: u64, of: &str, epoch: u64) -> ScopedEpoch {
        ScopedEpoch {
            issuer: issuer(host),
            incarnation: Incarnation::new(run),
            execution: ExecutionId::new(of).unwrap(),
            authorization: AuthorizationEpoch::new(epoch),
        }
    }

    /// A state whose `scope` may accept numbers up to its first record's limit.
    fn ready(scope: &ScopedEpoch) -> ReplayState {
        let mut state = ReplayState::new(config()).unwrap();
        assert!(matches!(
            state.accept(scope, Nonce::new(1), MessageClass::Grant),
            Err(ReplayRefusal::LimitNotPersisted { limit: 0, .. })
        ));
        let record = state.persist();
        state.confirm_persisted(&record);
        state
    }

    #[test]
    fn configurations_are_checked() {
        assert_eq!(config().validate(), Ok(()));
        for (window, error) in [
            (
                0,
                ReplayConfigError::WindowOutOfRange {
                    window: 0,
                    max: MAX_WINDOW,
                },
            ),
            (
                129,
                ReplayConfigError::WindowOutOfRange {
                    window: 129,
                    max: MAX_WINDOW,
                },
            ),
        ] {
            let mut bad = config();
            bad.window = window;
            assert_eq!(bad.validate(), Err(error));
        }
        let mut bad = config();
        bad.persist_margin = 0;
        assert_eq!(bad.validate(), Err(ReplayConfigError::ZeroMargin));
        bad = config();
        bad.max_scopes = 0;
        assert!(ReplayState::new(bad).is_err());
    }

    #[test]
    fn a_number_is_accepted_once_within_its_window() {
        let one = scope("host-a", 1, "exe-1", 1);
        let mut state = ready(&one);
        for number in [1, 3, 2, 6] {
            assert_eq!(
                state.accept(&one, Nonce::new(number), MessageClass::Renewal),
                Ok(Delivery::Accepted)
            );
        }
        assert_eq!(
            state.accept(&one, Nonce::new(3), MessageClass::Effect),
            Err(ReplayRefusal::Replayed {
                nonce: Nonce::new(3)
            })
        );
        // 6 is the highest; the window of four keeps 3 to 6, so 2 is refused, and 4 and
        // 5 are still accepted out of order.
        assert_eq!(
            state.accept(&one, Nonce::new(2), MessageClass::Effect),
            Err(ReplayRefusal::BelowWindow {
                nonce: Nonce::new(2),
                lowest: 3
            })
        );
        assert_eq!(
            state.accept(&one, Nonce::new(5), MessageClass::Effect),
            Ok(Delivery::Accepted)
        );
        assert_eq!(
            state.accept(&one, Nonce::new(0), MessageClass::Effect),
            Err(ReplayRefusal::ZeroNonce)
        );
        // A jump past the whole window forgets the bits but not the window.
        assert_eq!(
            state.accept(&one, Nonce::new(10), MessageClass::Grant),
            Ok(Delivery::Accepted)
        );
        assert!(matches!(
            state.accept(&one, Nonce::new(6), MessageClass::Grant),
            Err(ReplayRefusal::BelowWindow { lowest: 7, .. })
        ));
        // The first record let numbers up to 11 through; above it, a number waits for the
        // next record.
        assert_eq!(
            state.accept(&one, Nonce::new(11), MessageClass::Grant),
            Ok(Delivery::Accepted)
        );
        assert_eq!(
            state.accept(&one, Nonce::new(12), MessageClass::Grant),
            Err(ReplayRefusal::LimitNotPersisted {
                nonce: Nonce::new(12),
                limit: 11
            })
        );
        let record = state.persist();
        assert_eq!(record.limit(&one), Some(22));
        state.confirm_persisted(&record);
        assert_eq!(
            state.accept(&one, Nonce::new(12), MessageClass::Grant),
            Ok(Delivery::Accepted)
        );
    }

    #[test]
    fn scopes_differ_by_host_issuer_run_execution_and_epoch() {
        let one = scope("host-a", 1, "exe-1", 1);
        let others = [
            scope("host-b", 1, "exe-1", 1),
            scope("host-a", 1, "exe-2", 1),
        ];
        let mut state = ready(&one);
        state
            .accept(&one, Nonce::new(1), MessageClass::Grant)
            .unwrap();
        for other in &others {
            // Another scope has its own numbers, and its own persisted limit.
            assert!(matches!(
                state.accept(other, Nonce::new(1), MessageClass::Grant),
                Err(ReplayRefusal::LimitNotPersisted { .. })
            ));
        }
        let record = state.persist();
        state.confirm_persisted(&record);
        for other in &others {
            assert_eq!(
                state.accept(other, Nonce::new(1), MessageClass::Grant),
                Ok(Delivery::Accepted)
            );
        }
        // Room for three scopes: a fourth is refused.
        assert_eq!(
            state.accept(
                &scope("host-c", 1, "exe-1", 1),
                Nonce::new(1),
                MessageClass::Grant
            ),
            Err(ReplayRefusal::TooManyScopes { max: 3 })
        );
    }

    #[test]
    fn a_later_epoch_or_run_retires_the_earlier_scopes_of_its_line() {
        let first = scope("host-a", 1, "exe-1", 1);
        let second = scope("host-a", 1, "exe-1", 2);
        let next_run = scope("host-a", 2, "exe-1", 1);
        let mut state = ready(&first);
        state
            .accept(&first, Nonce::new(1), MessageClass::Grant)
            .unwrap();
        let _ = state.accept(&second, Nonce::new(1), MessageClass::Grant);
        let record = state.persist();
        state.confirm_persisted(&record);
        assert_eq!(state.scopes(), 2);
        state
            .accept(&second, Nonce::new(1), MessageClass::Grant)
            .unwrap();
        // The first epoch's window went with its acceptance of the second epoch.
        assert_eq!(state.scopes(), 1);
        assert!(matches!(
            state.accept(&first, Nonce::new(2), MessageClass::Grant),
            Err(ReplayRefusal::ScopeRetired { .. })
        ));
        assert_eq!(
            state.retire_below(&next_run),
            1,
            "the second epoch of run 1 goes"
        );
        assert!(matches!(
            state.accept(&second, Nonce::new(2), MessageClass::Grant),
            Err(ReplayRefusal::ScopeRetired { .. })
        ));
        // A revocation in a retired scope is still delivered.
        assert_eq!(
            state.accept(&first, Nonce::new(1), MessageClass::Revocation),
            Ok(Delivery::Idempotent)
        );
        state.retire_line(issuer("host-a"), &first.execution);
        assert_eq!(
            state.floor(issuer("host-a"), &first.execution),
            Some(ScopeFloor::Retired)
        );
        assert!(matches!(
            state.accept(
                &scope("host-a", 9, "exe-1", 9),
                Nonce::new(1),
                MessageClass::Grant
            ),
            Err(ReplayRefusal::ScopeRetired {
                floor: ScopeFloor::Retired,
                ..
            })
        ));
    }

    #[test]
    fn a_restart_refuses_everything_up_to_the_persisted_limit() {
        let one = scope("host-a", 1, "exe-1", 1);
        let mut state = ready(&one);
        for number in 1..=4 {
            state
                .accept(&one, Nonce::new(number), MessageClass::Effect)
                .unwrap();
        }
        let record = state.persist();
        state.confirm_persisted(&record);
        // Accepted after the record was stored, then lost with the crash.
        state
            .accept(&one, Nonce::new(9), MessageClass::Effect)
            .unwrap();
        let json = serde_json::to_string(&record).unwrap();
        let stored: ReplayRecord = serde_json::from_str(&json).unwrap();
        let mut restarted = ReplayState::restore(config(), &stored).unwrap();
        for number in [4, 9, 14] {
            assert!(matches!(
                restarted.accept(&one, Nonce::new(number), MessageClass::Effect),
                Err(ReplayRefusal::BelowWindow { lowest: 15, .. })
            ));
        }
        assert!(matches!(
            restarted.accept(&one, Nonce::new(15), MessageClass::Effect),
            Err(ReplayRefusal::LimitNotPersisted { limit: 14, .. })
        ));
        let again = restarted.persist();
        restarted.confirm_persisted(&again);
        assert_eq!(
            restarted.accept(&one, Nonce::new(15), MessageClass::Effect),
            Ok(Delivery::Accepted)
        );
        let mut extra = serde_json::to_value(&stored).unwrap();
        extra["cursor"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ReplayRecord>(extra).is_err());
    }

    #[test]
    fn merging_records_never_lowers_a_limit_or_a_floor() {
        let first = scope("host-a", 1, "exe-1", 1);
        let second = scope("host-a", 1, "exe-1", 2);
        let mut state = ready(&first);
        let older = state.persist();
        state
            .accept(&first, Nonce::new(1), MessageClass::Grant)
            .unwrap();
        let _ = state.accept(&second, Nonce::new(30), MessageClass::Grant);
        state.retire_below(&second);
        let newer = state.persist();
        assert_eq!(older.limit(&first), Some(11));
        let merged = older.merge(&newer);
        assert_eq!(merged, newer.merge(&older));
        assert_eq!(merged.limit(&first), None, "the floor retires it");
        assert_eq!(merged.limit(&second), Some(40));
        assert_eq!(
            merged.floor(issuer("host-a"), &first.execution),
            Some(ScopeFloor::Below {
                incarnation: Incarnation::new(1),
                authorization: AuthorizationEpoch::new(2)
            })
        );
        assert!(ReplayRecord::default().is_empty());
        assert_eq!(merged.merge(&ReplayRecord::default()), merged);
    }
}
