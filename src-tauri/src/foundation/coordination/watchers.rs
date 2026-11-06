//! Watchers: enforcement points that cache the coordinator's authority state (S2 CORE-04;
//! VM part §6.3: "An eventually delivered filesystem notification is not an instantaneous
//! global revocation mechanism. Use an authoritative check or short-lived leases with
//! explicit maximum staleness"; VM-W29: stale watchers; VM-W26: PID reuse;
//! docs/combined-plan-remaining-only.md §8, S04 / M13 / M17: "a ... stale watcher ... cannot
//! revive authorization").
//!
//! An enforcement point that does not ask the coordinator on every decision keeps an
//! [`AuthorityView`]: the scoped epoch in force, the [`AuthorityRevision`] of the
//! execution's authority, and how long the view may be used. A view goes stale with every
//! revocation, grant revocation, policy change, boot or recovery of its execution, and
//! expires at its declared staleness bound on the coordinator's clock session. A stale
//! watcher cannot revive authorization: [`Coordinator::check_view`] refuses a view that is
//! not current, from another run or clock session, expired, or checked while the clock
//! reads earlier than it already did, so a view held through a partition or a restart is
//! never taken up again.
//!
//! The [`WatcherRegistry`] records who caches what: each watcher's holder, the views issued
//! to it and the latest one it acknowledged enforcing. It is the evidence tombstone
//! compaction needs that no watcher can still present revoked authority
//! ([`Coordinator::retire`](super::Coordinator::retire)): a watcher has acknowledged the
//! current revision, has ended, or let its last view lapse on the same clock session with
//! the allowed skew. A watcher in a local process is named by its host identity, PID and
//! creation time ([`ProcessIdentity`]): a process that took the PID later is never taken
//! for it, and the host's observation that the PID no longer names it ends it. A watcher in
//! the engine ends with the engine's run. A remote watcher ends only by its own
//! acknowledgment or a lapse the coordinator measured itself; across a restart it stays
//! pending until it acknowledges again.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::capacity::CapacityPort;
use super::coordinator::Coordinator;
use super::scope::{AuthorityIssuer, HostId, ScopeRefusal, ScopedEpoch};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, Digest, ExecutionId, Incarnation, MonotonicTime,
    PolicyEpoch, SandboxBootGeneration,
};
use crate::foundation::process::{IdentityCheck, ProcessIdentity};

/// How far an execution's authority has changed: every change that takes authority away
/// raises it. Ordered by the authorization epoch, then the boot generation, the policy
/// epoch and the count of revoked grants, so a revocation, a new boot, a recovery, a policy
/// change and a grant revocation each give a later revision. A model activation never
/// changes it (S3.1). Compared only within one run of the coordination authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRevision {
    pub authorization: AuthorizationEpoch,
    pub boot: SandboxBootGeneration,
    pub policy: PolicyEpoch,
    /// Grants revoked under the execution (tombstones).
    pub revoked_grants: u64,
}

impl fmt::Display for AuthorityRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "authorization epoch {}, boot generation {}, policy epoch {}, {} revoked grant(s)",
            self.authorization, self.boot, self.policy, self.revoked_grants
        )
    }
}

/// What a watcher may cache of one execution's authority, and until when (VM part §6.3:
/// explicit maximum staleness). Only a [`WatcherRegistry`] obtains one from the coordinator;
/// it reads back strictly so a watcher in another process can present it again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityView {
    epoch: ScopedEpoch,
    revision: AuthorityRevision,
    clock: ClockSession,
    issued_at: MonotonicTime,
    fresh_until: MonotonicTime,
}

impl AuthorityView {
    /// The scoped epoch in force when the view was issued.
    pub fn epoch(&self) -> &ScopedEpoch {
        &self.epoch
    }

    /// The execution's revision when the view was issued.
    pub fn revision(&self) -> AuthorityRevision {
        self.revision
    }

    /// The clock session `issued_at` and `fresh_until` are points on.
    pub fn clock(&self) -> ClockSession {
        self.clock
    }

    pub fn issued_at(&self) -> MonotonicTime {
        self.issued_at
    }

    /// The view is not used from then on.
    pub fn fresh_until(&self) -> MonotonicTime {
        self.fresh_until
    }

    /// Where the view stands among the views of its execution: its run, then its
    /// revision.
    pub fn position(&self) -> (Incarnation, AuthorityRevision) {
        (self.epoch.incarnation, self.revision)
    }
}

/// Why a view is not honoured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ViewRefusal {
    /// Its scoped epoch is not the one in force: another host, issuer or run, a stale
    /// epoch, or a retired execution.
    Scope { refusal: ScopeRefusal },
    /// It was issued on another clock session, such as before a restart.
    OtherClock,
    /// The execution's authority changed since it was issued.
    Stale {
        presented: AuthorityRevision,
        current: AuthorityRevision,
    },
    /// Its staleness bound has passed.
    Expired { fresh_until: MonotonicTime },
    /// The clock reads earlier than a reading the coordinator already took; until it
    /// passes that again, no view is issued or honoured (VM part §6.2).
    ClockWentBack {
        now: MonotonicTime,
        high_water: MonotonicTime,
    },
}

crate::foundation::strict_serde::strict_tag!(ViewRefusal, "reason");

impl fmt::Display for ViewRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scope { refusal } => write!(f, "{refusal}"),
            Self::OtherClock => f.write_str("the view was issued on another clock session"),
            Self::Stale { presented, current } => write!(
                f,
                "the view shows {presented}, but the execution is at {current}"
            ),
            Self::Expired { fresh_until } => {
                write!(f, "the view expired at {} ns", fresh_until.as_nanos())
            }
            Self::ClockWentBack { now, high_water } => write!(
                f,
                "the clock reads {} ns, earlier than the {} ns it already read",
                now.as_nanos(),
                high_water.as_nanos()
            ),
        }
    }
}

impl std::error::Error for ViewRefusal {}

impl From<ScopeRefusal> for ViewRefusal {
    fn from(refusal: ScopeRefusal) -> Self {
        Self::Scope { refusal }
    }
}

impl<C: Clock, P: CapacityPort> Coordinator<C, P> {
    /// The clock now, or, while it reads earlier than a reading already taken on this
    /// clock session, the reading and that high-water mark: views, lapses and lease
    /// expiries are judged only on a clock that has not gone back (VM part §6.2).
    pub(super) fn forward_now(&self) -> Result<MonotonicTime, (MonotonicTime, MonotonicTime)> {
        let now = self.now();
        let high_water = self.clock_high_water();
        if now < high_water {
            Err((now, high_water))
        } else {
            Ok(now)
        }
    }

    /// [`Coordinator::forward_now`] for a view.
    fn view_time(&self) -> Result<MonotonicTime, ViewRefusal> {
        self.forward_now()
            .map_err(|(now, high_water)| ViewRefusal::ClockWentBack { now, high_water })
    }

    /// The revision of `execution`'s authority now ([`AuthorityRevision`]); a retired or
    /// unknown execution has none.
    pub fn authority_revision(
        &self,
        execution: &ExecutionId,
    ) -> Result<AuthorityRevision, ScopeRefusal> {
        let authorization = self.epoch_in_force(execution)?;
        let revoked_grants = self
            .grant_tombstones
            .get(execution)
            .map_or(0, |grants| u64::try_from(grants.len()).unwrap_or(u64::MAX));
        let (boot, policy) = self.sandboxes.get(execution).map_or(
            (SandboxBootGeneration::FIRST, PolicyEpoch::FIRST),
            |sandbox| {
                let generations = sandbox.generations();
                (generations.boot, generations.policy)
            },
        );
        Ok(AuthorityRevision {
            authorization,
            boot,
            policy,
            revoked_grants,
        })
    }

    /// A view of `execution`'s authority now, usable for `max_staleness` on this clock
    /// session. Issued through [`WatcherRegistry::view`], which records it.
    fn issue_view(
        &self,
        issuer: AuthorityIssuer,
        execution: &ExecutionId,
        max_staleness: Duration,
    ) -> Result<AuthorityView, ViewRefusal> {
        let epoch = self.scoped_epoch(issuer, execution)?;
        let revision = self.authority_revision(execution)?;
        let now = self.view_time()?;
        Ok(AuthorityView {
            epoch,
            revision,
            clock: self.session,
            issued_at: now,
            fresh_until: now.saturating_add(max_staleness),
        })
    }

    /// Whether `view`, presented by a watcher, may still be used now: its scoped epoch is
    /// the one in force in this run, it shows the execution's current revision, it was
    /// issued on this clock session and its staleness bound has not passed. A watcher that
    /// kept a view through a partition, a revocation or a restart gets it refused, so a
    /// stale watcher never revives authorization.
    pub fn check_view(
        &self,
        issuer: AuthorityIssuer,
        view: &AuthorityView,
    ) -> Result<(), ViewRefusal> {
        self.check_scoped_epoch(issuer, &view.epoch)?;
        if view.clock != self.session {
            return Err(ViewRefusal::OtherClock);
        }
        let now = self.view_time()?;
        let current = self.authority_revision(&view.epoch.execution)?;
        if view.revision != current {
            return Err(ViewRefusal::Stale {
                presented: view.revision,
                current,
            });
        }
        if now >= view.fresh_until {
            return Err(ViewRefusal::Expired {
                fresh_until: view.fresh_until,
            });
        }
        Ok(())
    }
}

/// A watcher, by a digest its registration names it with.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WatcherId(Digest);

impl WatcherId {
    /// The digest domain of [`WatcherId::named`].
    pub const DOMAIN: &'static str = "yougori/coordination/watcher/v1";

    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    /// The watcher named by text, such as an enforcement point's configured name.
    pub fn named(name: &str) -> Self {
        Self(digest(Self::DOMAIN, &[name.as_bytes()]))
    }

    pub const fn digest(self) -> Digest {
        self.0
    }
}

impl fmt::Debug for WatcherId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WatcherId({})", self.0)
    }
}

impl fmt::Display for WatcherId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Where a watcher's cache lives (VM part §6.4: stable process handles, never a PID
/// alone).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "holder", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum WatcherHolder {
    /// Inside the engine; the cache ends with the engine's run.
    Engine,
    /// A local process, by its PID and creation time.
    Process { identity: ProcessIdentity },
    /// An enforcement point on another host, which this host cannot observe.
    Remote { host: HostId },
}

crate::foundation::strict_serde::strict_tag!(WatcherHolder, "holder");

/// One watcher as it registered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatcherRegistration {
    pub watcher: WatcherId,
    pub execution: ExecutionId,
    pub holder: WatcherHolder,
    /// How long it uses a view: every view issued to it is fresh for this long.
    pub max_staleness: Duration,
}

/// How a watcher ended; an ended watcher holds no cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "ended", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum WatcherEnd {
    /// It deregistered.
    Deregistered,
    /// The host observed that no process holds its PID any more.
    ProcessGone { identity: ProcessIdentity },
    /// The host observed another process holding its PID: it ended, and the other
    /// process is never taken for it.
    ProcessReused { identity: ProcessIdentity },
    /// It lived in the engine, which restarted into run `incarnation`.
    EngineRestarted { incarnation: Incarnation },
}

crate::foundation::strict_serde::strict_tag!(WatcherEnd, "ended");

/// One watcher's record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatcherRecord {
    registration: WatcherRegistration,
    /// The latest view issued to it.
    issued: AuthorityView,
    /// The latest view it acknowledged enforcing.
    acknowledged: Option<AuthorityView>,
    ended: Option<WatcherEnd>,
}

impl WatcherRecord {
    pub fn registration(&self) -> &WatcherRegistration {
        &self.registration
    }

    /// The latest view issued to the watcher.
    pub fn issued(&self) -> &AuthorityView {
        &self.issued
    }

    /// The latest view the watcher acknowledged enforcing.
    pub fn acknowledged(&self) -> Option<&AuthorityView> {
        self.acknowledged.as_ref()
    }

    /// How it ended, if it did.
    pub fn ended(&self) -> Option<WatcherEnd> {
        self.ended
    }
}

/// Where a watcher stands against an execution's current revision, as tombstone
/// compaction reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "standing", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum WatcherStanding {
    /// It acknowledged the current revision, or a later one, in this run.
    Current { acknowledged: AuthorityRevision },
    /// It ended, holding nothing.
    Ended { end: WatcherEnd },
    /// Its last view's bound and the allowed skew have passed on this clock session.
    Lapsed { fresh_until: MonotonicTime },
    /// It may still hold a view from before the current revision.
    Pending {
        acknowledged: Option<(Incarnation, AuthorityRevision)>,
    },
}

crate::foundation::strict_serde::strict_tag!(WatcherStanding, "standing");

impl WatcherStanding {
    /// Whether the watcher can no longer present authority older than the current
    /// revision.
    pub fn is_clear(&self) -> bool {
        !matches!(self, Self::Pending { .. })
    }
}

/// Why the registry refused a call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum WatcherRefusal {
    Duplicate {
        watcher: WatcherId,
    },
    Unknown {
        watcher: WatcherId,
    },
    /// The caller is not the holder that registered: such as another process holding the
    /// registered process's PID now.
    HolderMismatch {
        watcher: WatcherId,
    },
    /// The view is of another execution than the watcher registered for.
    ExecutionMismatch {
        watcher: WatcherId,
        registered: ExecutionId,
        presented: ExecutionId,
    },
    /// The view is older than one the watcher already acknowledged: a watcher's
    /// acknowledgment never moves back.
    Backwards {
        watcher: WatcherId,
        acknowledged: (Incarnation, AuthorityRevision),
        presented: (Incarnation, AuthorityRevision),
    },
    Ended {
        watcher: WatcherId,
        end: WatcherEnd,
    },
    /// The watcher is not a local process, so no process observation applies to it.
    NotAProcess {
        watcher: WatcherId,
    },
    /// The coordinator issued no view.
    View {
        refusal: ViewRefusal,
    },
}

crate::foundation::strict_serde::strict_tag!(WatcherRefusal, "reason");

impl fmt::Display for WatcherRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate { watcher } => write!(f, "watcher {watcher} is already registered"),
            Self::Unknown { watcher } => write!(f, "watcher {watcher} is not registered"),
            Self::HolderMismatch { watcher } => {
                write!(
                    f,
                    "the caller is not the holder watcher {watcher} registered as"
                )
            }
            Self::ExecutionMismatch {
                watcher,
                registered,
                presented,
            } => write!(f, "watcher {watcher} watches {registered}, not {presented}"),
            Self::Backwards { watcher, .. } => {
                write!(f, "watcher {watcher} already acknowledged a later view")
            }
            Self::Ended { watcher, .. } => write!(f, "watcher {watcher} has ended"),
            Self::NotAProcess { watcher } => {
                write!(f, "watcher {watcher} is not a local process")
            }
            Self::View { refusal } => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for WatcherRefusal {}

impl From<ViewRefusal> for WatcherRefusal {
    fn from(refusal: ViewRefusal) -> Self {
        Self::View { refusal }
    }
}

/// Every watcher of the coordinator's authority, with the views issued to it and the ones
/// it acknowledged (VM part §6.3). Persist it with the coordinator's state: a registration
/// the registry forgot would let compaction pass a watcher it never heard of.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatcherRegistry {
    watchers: BTreeMap<WatcherId, WatcherRecord>,
}

impl WatcherRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// The watcher's record.
    pub fn watcher(&self, watcher: WatcherId) -> Option<&WatcherRecord> {
        self.watchers.get(&watcher)
    }

    /// Every watcher of `execution`.
    pub fn watchers_of<'a>(
        &'a self,
        execution: &'a ExecutionId,
    ) -> impl Iterator<Item = (WatcherId, &'a WatcherRecord)> + 'a {
        self.watchers
            .iter()
            .filter(move |(_, record)| &record.registration.execution == execution)
            .map(|(watcher, record)| (*watcher, record))
    }

    /// Registers a watcher and issues its first view of the execution's authority from
    /// `coordinator`.
    pub fn register<C: Clock, P: CapacityPort>(
        &mut self,
        coordinator: &Coordinator<C, P>,
        issuer: AuthorityIssuer,
        registration: WatcherRegistration,
    ) -> Result<AuthorityView, WatcherRefusal> {
        let watcher = registration.watcher;
        if self.watchers.contains_key(&watcher) {
            return Err(WatcherRefusal::Duplicate { watcher });
        }
        let view =
            coordinator.issue_view(issuer, &registration.execution, registration.max_staleness)?;
        self.watchers.insert(
            watcher,
            WatcherRecord {
                registration,
                issued: view.clone(),
                acknowledged: None,
                ended: None,
            },
        );
        Ok(view)
    }

    /// A fresh view for `watcher`, called by `holder`; the registry records it as the
    /// latest issued to the watcher, which is what a lapse is measured from.
    pub fn view<C: Clock, P: CapacityPort>(
        &mut self,
        coordinator: &Coordinator<C, P>,
        issuer: AuthorityIssuer,
        watcher: WatcherId,
        holder: &WatcherHolder,
    ) -> Result<AuthorityView, WatcherRefusal> {
        let record = self.live_record(watcher, holder)?;
        let view = coordinator.issue_view(
            issuer,
            &record.registration.execution,
            record.registration.max_staleness,
        )?;
        record.issued = view.clone();
        Ok(view)
    }

    /// `watcher`, called by `holder`, enforces `view` now. Refused for another holder, such
    /// as a process holding the registered process's PID later, for a view of another
    /// execution, and for a view older than one it already acknowledged.
    pub fn acknowledge(
        &mut self,
        watcher: WatcherId,
        holder: &WatcherHolder,
        view: AuthorityView,
    ) -> Result<(), WatcherRefusal> {
        let record = self.live_record(watcher, holder)?;
        if view.epoch.execution != record.registration.execution {
            return Err(WatcherRefusal::ExecutionMismatch {
                watcher,
                registered: record.registration.execution.clone(),
                presented: view.epoch.execution.clone(),
            });
        }
        if let Some(acknowledged) = &record.acknowledged {
            if view.position() < acknowledged.position() {
                return Err(WatcherRefusal::Backwards {
                    watcher,
                    acknowledged: acknowledged.position(),
                    presented: view.position(),
                });
            }
        }
        record.acknowledged = Some(view);
        Ok(())
    }

    /// `watcher`, called by `holder`, stops caching.
    pub fn deregister(
        &mut self,
        watcher: WatcherId,
        holder: &WatcherHolder,
    ) -> Result<(), WatcherRefusal> {
        let record = self.live_record(watcher, holder)?;
        record.ended = Some(WatcherEnd::Deregistered);
        Ok(())
    }

    /// What the host observed at the PID of a watcher in a local process
    /// ([`ProcessIdentity::check`]): a PID that names no process, or another process,
    /// ends it; one that still names it changes nothing. Returns how it ended, if it did.
    pub fn observe_process(
        &mut self,
        watcher: WatcherId,
        check: IdentityCheck,
    ) -> Result<Option<WatcherEnd>, WatcherRefusal> {
        let record = self
            .watchers
            .get_mut(&watcher)
            .ok_or(WatcherRefusal::Unknown { watcher })?;
        let WatcherHolder::Process { identity } = record.registration.holder else {
            return Err(WatcherRefusal::NotAProcess { watcher });
        };
        if let Some(end) = record.ended {
            return Ok(Some(end));
        }
        record.ended = match check {
            IdentityCheck::Same => None,
            IdentityCheck::Gone => Some(WatcherEnd::ProcessGone { identity }),
            IdentityCheck::Reused => Some(WatcherEnd::ProcessReused { identity }),
        };
        Ok(record.ended)
    }

    /// The engine restarted into run `incarnation`: every watcher inside it whose views
    /// are from an earlier run ended with it. Returns those.
    pub fn engine_restarted(&mut self, incarnation: Incarnation) -> Vec<WatcherId> {
        let mut ended = Vec::new();
        for (watcher, record) in &mut self.watchers {
            if record.registration.holder == WatcherHolder::Engine
                && record.ended.is_none()
                && record.issued.epoch.incarnation < incarnation
            {
                record.ended = Some(WatcherEnd::EngineRestarted { incarnation });
                ended.push(*watcher);
            }
        }
        ended
    }

    /// Forgets every watcher of `execution`, once its retirement made every view of it
    /// unusable. Returns how many went.
    pub fn forget(&mut self, execution: &ExecutionId) -> usize {
        let before = self.watchers.len();
        self.watchers
            .retain(|_, record| &record.registration.execution != execution);
        before - self.watchers.len()
    }

    /// Where `record` stands against `current`, the scoped epoch and revision in force,
    /// read at `now` on `clock`, with `skew` allowed for clocks the watcher uses. `now` is
    /// `None` when the coordinator's clock reads earlier than it already did; then no
    /// lapse is measured.
    pub fn standing(
        record: &WatcherRecord,
        current: (&ScopedEpoch, AuthorityRevision),
        clock: ClockSession,
        now: Option<MonotonicTime>,
        skew: Duration,
    ) -> WatcherStanding {
        if let Some(end) = record.ended {
            return WatcherStanding::Ended { end };
        }
        let (epoch, revision) = current;
        if let Some(acknowledged) = &record.acknowledged {
            if acknowledged.epoch.incarnation == epoch.incarnation
                && acknowledged.revision >= revision
            {
                return WatcherStanding::Current {
                    acknowledged: acknowledged.revision,
                };
            }
        }
        let lapsed_at = record.issued.fresh_until.saturating_add(skew);
        if record.issued.clock == clock && now.is_some_and(|now| now >= lapsed_at) {
            return WatcherStanding::Lapsed {
                fresh_until: record.issued.fresh_until,
            };
        }
        WatcherStanding::Pending {
            acknowledged: record.acknowledged.as_ref().map(AuthorityView::position),
        }
    }

    /// The record of a watcher that has not ended, called by its registered holder.
    fn live_record(
        &mut self,
        watcher: WatcherId,
        holder: &WatcherHolder,
    ) -> Result<&mut WatcherRecord, WatcherRefusal> {
        let record = self
            .watchers
            .get_mut(&watcher)
            .ok_or(WatcherRefusal::Unknown { watcher })?;
        if &record.registration.holder != holder {
            return Err(WatcherRefusal::HolderMismatch { watcher });
        }
        if let Some(end) = record.ended {
            return Err(WatcherRefusal::Ended { watcher, end });
        }
        Ok(record)
    }
}
