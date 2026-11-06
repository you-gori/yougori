//! §12.3 models 2 and 4 as exhaustive small-state checks (VM part lines 2654–2665).
//!
//! Both checks run this module's own code, not a separate specification: model 2 drives
//! a real [`EffectRecord`] and model 4 a real [`ReleaseLedger`] and
//! [`AuthorizationBook`]. A breadth-first search applies every event in every reachable
//! state up to the stated bounds and checks the invariants after each step; a violation
//! comes back as a [`Counterexample`] with its event trace.
//!
//! Model 2 (effect state machine) assumes one effect, one abstract provider whose truth
//! (committed or not) reconciliation reads, a policy epoch that can move at any time,
//! and crashes at any point after dispatch. States are identified by phase, attempt,
//! provider commits, whether the current attempt reached the provider and whether the
//! policy epoch moved since authorization; histories that differ only in earlier
//! attempts are merged. It shows: authorization and reservation precede every dispatch;
//! the identity and description never change and an attempt's capability (with its
//! epochs) is fixed from authorization to outcome; a failed effect never committed; an
//! uncertain outcome is never retried blindly, so the provider commits at most once.
//!
//! Model 4 (budget reservation) assumes concurrent operations that each reserve, charge
//! twice and release in any interleaving, on two channels with a general budget and a
//! documented in-flight allowance, plus concurrent effect and spend holds under one
//! delegation. It shows the §2.5 ceiling, every channel and general budget, the
//! allowance and the delegation budget hold in every state, and that every unused
//! reservation returns.
//!
//! A proof of the model does not prove the operating system, the hypervisor, external
//! providers or hardware (§12.3 line 2665).

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::time::Duration;

use super::budget::{
    AccountingPolicy, ChannelBudget, ChannelDeclaration, ChannelKey, InFlightAllowance,
    ReleaseChannelKind, ReleaseLedger, ReleasePolicy, ReleaseReservation, ReservationToken,
    TrustClass, WireMeasure,
};
use super::canonical::Parameters;
use super::capability::{
    AuthorizationBasis, CapabilityKey, ExecutorIdentity, ExecutorName, Nonce, OperationCapability,
    PolicyVersion, SealedCapability,
};
use super::contract::DeliveryGuarantee;
use super::delegation::{
    AuthorizationBook, DelegationBudget, DelegationId, DelegationScope, StandingDelegation,
};
use super::description::{
    AccountRef, CostCeiling, Deadline, Destination, EffectDescription, EffectFields, Idempotency,
    IdempotencyKey, IdempotencyRequirement, IssuerId, OperationKey, OperationName, ProviderId,
    ResourceRef, RouteRef, SandboxRef,
};
use super::state::{
    EffectFailure, EffectPhase, EffectRecord, HeldReservation, Observation, ProviderResult,
    Reconciliation, ReconciliationSource, Settlement, UnknownCause,
};
use crate::foundation::coordination::SandboxGenerations;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{digest, ExecutionId, MonotonicTime, PolicyEpoch, TenantId};

/// Bounds of the model 2 search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectModelBounds {
    /// Longest event sequence explored.
    pub max_depth: usize,
    /// Most authorizations of the one effect.
    pub max_attempts: u32,
    /// Fault injection: reconciliation reports "not committed" whatever the provider's
    /// truth, as a controller that retries blindly would. The search must then find a
    /// "failed" effect the provider had committed, the state a blind retry commits again
    /// from.
    pub blind_retry: bool,
}

/// Bounds of the model 4 search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetModelBounds {
    /// Concurrent operations.
    pub operations: usize,
    /// Largest reservation an operation asks for, in bytes.
    pub max_reserve_bytes: u64,
    /// Largest single charge, in bytes.
    pub max_charge_bytes: u64,
}

/// What a search explored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelReport {
    pub states: usize,
    pub transitions: usize,
    pub deepest: usize,
    pub assumptions: &'static [&'static str],
}

/// A trace that breaks an invariant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counterexample {
    pub trace: Vec<String>,
    pub violation: String,
}

const EFFECT_ASSUMPTIONS: &[&str] = &[
    "one effect and one abstract provider whose truth reconciliation reads",
    "the policy epoch may move at any step; crashes may happen at any step after dispatch",
    "states are merged by phase, attempt, commits, reach and epoch flags",
    "fakes only: no real provider, clock or storage",
];

const BUDGET_ASSUMPTIONS: &[&str] = &[
    "operations reserve, charge twice and release in every interleaving",
    "two general channels (4 and 3 bytes), a 6-byte general budget, a 1-byte allowance",
    "a delegation of 2 effects and 5 spend units shared by every operation",
    "the ledger is the single central authority; no other path releases bytes",
];

fn setup_error(detail: impl ToString) -> Counterexample {
    Counterexample {
        trace: Vec::new(),
        violation: format!("model setup failed: {}", detail.to_string()),
    }
}

fn model_session() -> ClockSession {
    ClockSession::from_uuid(uuid::Uuid::from_u128(0x5eed))
}

fn model_sandbox() -> Result<SandboxRef, Counterexample> {
    Ok(SandboxRef {
        issuer: IssuerId::new(digest("yougori/model/issuer/v1", &[b"host"])),
        execution: ExecutionId::new("exe-model").map_err(setup_error)?,
    })
}

fn model_description() -> Result<EffectDescription, Counterexample> {
    let fields = EffectFields {
        principal: TenantId::new("tenant-model").map_err(setup_error)?,
        sandbox: model_sandbox()?,
        operation: OperationKey {
            provider: ProviderId::new("provider").map_err(setup_error)?,
            operation: OperationName::new("create_item").map_err(setup_error)?,
            contract_version: 1,
        },
        resource: ResourceRef {
            account: AccountRef::new(digest("yougori/model/account/v1", &[b"a"])),
            object: digest("yougori/model/object/v1", &[b"o"]),
        },
        destination: Destination {
            route: RouteRef::new(digest("yougori/model/route/v1", &[b"r"])),
            trust: TrustClass::RegisteredProvider,
        },
        parameters: Parameters::new(),
        payload: None,
        attachments: BTreeMap::new(),
        preconditions: BTreeSet::new(),
        max_cost: CostCeiling {
            max_spend_microunits: 1,
            max_volume_units: 1,
        },
        max_wire_bytes_out: 64,
        deadline: Deadline {
            clock: model_session(),
            at: MonotonicTime::from_nanos(u64::MAX),
        },
        idempotency: Idempotency {
            key: IdempotencyKey::new(digest("yougori/model/idempotency/v1", &[b"k"])),
            requirement: IdempotencyRequirement::ProviderKey,
        },
    };
    EffectDescription::new(fields).map_err(setup_error)
}

fn model_capability(
    key: &CapabilityKey,
    description: &EffectDescription,
    attempt: u32,
    policy: u64,
) -> Result<SealedCapability, Counterexample> {
    Ok(key.seal(OperationCapability {
        effect: description.id(),
        principal: description.principal().clone(),
        sandbox: description.sandbox().clone(),
        generations: SandboxGenerations {
            policy: PolicyEpoch::new(policy),
            ..SandboxGenerations::FIRST
        },
        policy_version: PolicyVersion::new(digest("yougori/model/policy/v1", &[b"p"])),
        executor: ExecutorIdentity {
            name: ExecutorName::new("executor").map_err(setup_error)?,
            build: digest("yougori/model/build/v1", &[b"b"]),
        },
        lease: crate::foundation::ids::LeaseId::FIRST,
        operation: description.operation().clone(),
        resource: description.resource(),
        destination: description.destination(),
        payload: description.payload(),
        attachments: description.attachments_digest(),
        max_cost: description.max_cost(),
        clock: model_session(),
        expires_at: MonotonicTime::from_nanos(u64::MAX),
        nonce: Nonce::new(u64::from(attempt)),
        idempotency: description.idempotency(),
        attempt,
        basis: AuthorizationBasis::Delegation {
            delegation: DelegationId::new(digest("yougori/model/delegation/v1", &[b"d"])),
        },
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EffectEvent {
    Validate,
    Authorize,
    Reserve,
    ChangePolicy,
    Dispatch,
    Commit,
    Reject,
    ReplyLost,
    RequestLost,
    CrashAfterCommit,
    CrashBeforeCommit,
    Reconcile,
    Retry,
    Cancel,
}

const EFFECT_EVENTS: [EffectEvent; 14] = [
    EffectEvent::Validate,
    EffectEvent::Authorize,
    EffectEvent::Reserve,
    EffectEvent::ChangePolicy,
    EffectEvent::Dispatch,
    EffectEvent::Commit,
    EffectEvent::Reject,
    EffectEvent::ReplyLost,
    EffectEvent::RequestLost,
    EffectEvent::CrashAfterCommit,
    EffectEvent::CrashBeforeCommit,
    EffectEvent::Reconcile,
    EffectEvent::Retry,
    EffectEvent::Cancel,
];

#[derive(Clone)]
struct EffectWorld {
    record: EffectRecord,
    /// Times the provider committed the effect.
    commits: u32,
    /// Whether the current attempt's request reached the provider and committed.
    attempt_committed: bool,
    /// The current policy epoch.
    policy: u64,
    /// Whether the policy epoch moved since the current attempt was authorized.
    stale: bool,
    trace: Vec<String>,
}

impl EffectWorld {
    fn key(&self) -> (EffectPhase, u32, u32, bool, bool) {
        (
            self.record.phase(),
            self.record.attempt(),
            self.commits,
            self.attempt_committed,
            self.stale,
        )
    }
}

fn held() -> HeldReservation {
    HeldReservation {
        release: ReleaseReservation {
            token: ReservationToken::new(1),
            channel: ChannelKey {
                kind: ReleaseChannelKind::ProviderRequest,
                trust: TrustClass::RegisteredProvider,
            },
            reserved_bytes: 64,
        },
        spend_microunits: 1,
    }
}

fn result() -> ProviderResult {
    ProviderResult {
        result: digest("yougori/model/result/v1", &[b"ok"]),
        spend_microunits: 1,
        volume_units: 1,
    }
}

fn apply_effect(
    world: &mut EffectWorld,
    event: EffectEvent,
    key: &CapabilityKey,
    bounds: &EffectModelBounds,
) -> Result<bool, Counterexample> {
    let at = MonotonicTime::from_nanos(u64::try_from(world.trace.len()).unwrap_or(u64::MAX));
    let record = &mut world.record;
    let changed = match event {
        EffectEvent::Validate => record
            .validate(Ok(DeliveryGuarantee::ExactlyOnceByProviderKey), at)
            .is_ok(),
        EffectEvent::Authorize => {
            if record.attempt() >= bounds.max_attempts {
                false
            } else {
                let attempt = record.attempt().saturating_add(1);
                let sealed = model_capability(key, record.description(), attempt, world.policy)?;
                let authorized = record.authorize(sealed, at).is_ok();
                if authorized {
                    world.attempt_committed = false;
                    world.stale = false;
                }
                authorized
            }
        }
        EffectEvent::Reserve => record.reserve(held(), at).is_ok(),
        EffectEvent::ChangePolicy => {
            world.policy = world.policy.saturating_add(1);
            world.stale = record.state().capability().is_some();
            true
        }
        EffectEvent::Dispatch => {
            let bound = record
                .state()
                .capability()
                .map(|sealed| sealed.capability().generations.policy);
            let gate = match bound {
                Some(bound) if bound.get() != world.policy => {
                    Err(EffectFailure::PolicyEpochChanged {
                        bound,
                        current: PolicyEpoch::new(world.policy),
                    })
                }
                _ => Ok(()),
            };
            record.dispatch(gate, at).is_ok()
        }
        EffectEvent::Commit | EffectEvent::ReplyLost | EffectEvent::CrashAfterCommit
            if record.phase() == EffectPhase::Dispatched =>
        {
            world.commits = world.commits.saturating_add(1);
            world.attempt_committed = true;
            match event {
                EffectEvent::Commit => record.settle(Settlement::Committed(result()), at).is_ok(),
                EffectEvent::ReplyLost => record
                    .settle(Settlement::Unknown(UnknownCause::ResponseLost), at)
                    .is_ok(),
                _ => record.recover_after_crash(at),
            }
        }
        EffectEvent::Reject => record
            .settle(
                Settlement::NotCommitted(EffectFailure::ProviderRejected {
                    code: "rejected".to_owned(),
                }),
                at,
            )
            .is_ok(),
        EffectEvent::RequestLost => record
            .settle(Settlement::Unknown(UnknownCause::ResponseLost), at)
            .is_ok(),
        EffectEvent::CrashBeforeCommit => record.recover_after_crash(at),
        EffectEvent::Reconcile => {
            let observation = if world.attempt_committed && !bounds.blind_retry {
                Observation::Committed { result: result() }
            } else {
                Observation::NotCommitted
            };
            record
                .reconcile(
                    Reconciliation {
                        observation,
                        source: ReconciliationSource::ProviderLookup,
                    },
                    at,
                )
                .is_ok()
        }
        EffectEvent::Retry => record.retry(at).is_ok(),
        EffectEvent::Cancel => record.fail(EffectFailure::Cancelled, at).is_ok(),
        EffectEvent::Commit | EffectEvent::ReplyLost | EffectEvent::CrashAfterCommit => false,
    };
    Ok(changed)
}

fn effect_violation(
    world: &EffectWorld,
    before: &EffectWorld,
    initial: &EffectDescription,
) -> Option<String> {
    let record = &world.record;
    if let Some(violation) = record.history_violation() {
        return Some(violation);
    }
    if record.id() != initial.id() || record.description() != initial {
        return Some("the identity or the description changed".to_owned());
    }
    if world.commits > 1 {
        return Some(format!(
            "the provider committed {} times: an uncertain outcome was retried blindly",
            world.commits
        ));
    }
    if before.record.phase() == EffectPhase::Confirmed && record.phase() != EffectPhase::Confirmed {
        return Some("a confirmed effect changed".to_owned());
    }
    if record.phase() == EffectPhase::Failed && world.commits > 0 {
        return Some("a failed effect had committed".to_owned());
    }
    let holds = matches!(
        record.phase(),
        EffectPhase::Reserved | EffectPhase::Dispatched | EffectPhase::OutcomeUnknown
    );
    if record.state().held().is_some() != holds {
        return Some("the held reservation disagrees with the phase".to_owned());
    }
    if record.phase() == EffectPhase::Dispatched
        && before.record.phase() != EffectPhase::Reserved
        && before.record.phase() != EffectPhase::Dispatched
    {
        return Some("a dispatch did not come from a reservation".to_owned());
    }
    None
}

/// §12.3 model 2: every reachable state of one effect within `bounds`.
pub fn check_effect_model(bounds: EffectModelBounds) -> Result<ModelReport, Counterexample> {
    let key = CapabilityKey::new(&[0x5e; 32]).map_err(setup_error)?;
    let description = model_description()?;
    let start = EffectWorld {
        record: EffectRecord::propose(description.clone()),
        commits: 0,
        attempt_committed: false,
        policy: 1,
        stale: false,
        trace: Vec::new(),
    };
    let mut seen = HashSet::from([start.key()]);
    let mut queue = VecDeque::from([start]);
    let mut transitions = 0;
    let mut deepest = 0;
    while let Some(world) = queue.pop_front() {
        deepest = deepest.max(world.trace.len());
        if world.trace.len() >= bounds.max_depth {
            continue;
        }
        for event in EFFECT_EVENTS {
            let mut next = world.clone();
            let changed = apply_effect(&mut next, event, &key, &bounds)?;
            if !changed {
                if next.record != world.record {
                    let mut trace = world.trace.clone();
                    trace.push(format!("{event:?}"));
                    return Err(Counterexample {
                        trace,
                        violation: "a refused event changed the record".to_owned(),
                    });
                }
                continue;
            }
            transitions += 1;
            next.trace.push(format!("{event:?}"));
            if let Some(violation) = effect_violation(&next, &world, &description) {
                return Err(Counterexample {
                    trace: next.trace,
                    violation,
                });
            }
            if seen.insert(next.key()) {
                queue.push_back(next);
            }
        }
    }
    Ok(ModelReport {
        states: seen.len(),
        transitions,
        deepest,
        assumptions: EFFECT_ASSUMPTIONS,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Program {
    Start,
    Reserved {
        token: ReservationToken,
        charges: u8,
    },
    Released,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Hold {
    None,
    Reserved { spend: u64 },
    InFlight { spend: u64 },
    Done,
}

#[derive(Clone)]
struct BudgetWorld {
    ledger: ReleaseLedger,
    book: AuthorizationBook,
    programs: Vec<Program>,
    holds: Vec<Hold>,
}

impl BudgetWorld {
    fn key(&self) -> (Vec<u64>, Vec<u64>, Vec<Program>, Vec<Hold>) {
        (
            self.ledger.fingerprint(),
            self.book.fingerprint(),
            self.programs.clone(),
            self.holds.clone(),
        )
    }
}

fn channel(index: usize) -> ChannelKey {
    ChannelKey {
        kind: if index == 0 {
            ReleaseChannelKind::ProviderRequest
        } else {
            ReleaseChannelKind::Log
        },
        trust: if index == 0 {
            TrustClass::RegisteredProvider
        } else {
            TrustClass::HostStorage
        },
    }
}

fn effect_id(index: usize) -> super::description::EffectId {
    super::description::EffectId::new(digest(
        "yougori/model/effect/v1",
        &[&u64::try_from(index).unwrap_or(u64::MAX).to_be_bytes()],
    ))
}

fn budget_start(bounds: &BudgetModelBounds) -> Result<(BudgetWorld, DelegationId), Counterexample> {
    let declaration = |index: usize, budget_bytes: u64| ChannelDeclaration {
        key: channel(index),
        accounting: AccountingPolicy::WireBytes,
        budget: ChannelBudget::General { budget_bytes },
    };
    let policy = ReleasePolicy::new(
        6,
        vec![declaration(0, 4), declaration(1, 3)],
        InFlightAllowance::documented(1, "one framing byte a conservative estimate may miss")
            .map_err(setup_error)?,
    )
    .map_err(setup_error)?;
    let mut book = AuthorizationBook::new();
    let sandbox = model_sandbox()?;
    let delegation = book.grant(StandingDelegation {
        scope: DelegationScope {
            principal: TenantId::new("tenant-model").map_err(setup_error)?,
            sandbox,
            executor: ExecutorName::new("executor").map_err(setup_error)?,
            operations: BTreeSet::new(),
            routes: BTreeSet::new(),
            accounts: BTreeSet::new(),
            max_cost_per_effect: CostCeiling::default(),
            max_wire_bytes_per_effect: 0,
        },
        budget: DelegationBudget {
            max_effects: 2,
            max_spend_microunits: 5,
        },
        policy: PolicyEpoch::FIRST,
        expires: Deadline {
            clock: model_session(),
            at: MonotonicTime::ZERO.saturating_add(Duration::from_secs(1)),
        },
    });
    Ok((
        BudgetWorld {
            ledger: ReleaseLedger::new(policy),
            book,
            programs: vec![Program::Start; bounds.operations],
            holds: vec![Hold::None; bounds.operations],
        },
        delegation,
    ))
}

fn budget_violation(world: &BudgetWorld, delegation: &DelegationId) -> Option<String> {
    if let Some(violation) = world.ledger.invariant_violation() {
        return Some(violation);
    }
    if world.ledger.counted_bytes_out() > world.ledger.ceiling_bytes() {
        return Some("counted bytes above the §2.5 ceiling".to_owned());
    }
    if let Some((reserved, used, reserved_spend, used_spend)) =
        world.book.delegation_usage(delegation)
    {
        if reserved.saturating_add(used) > 2 {
            return Some("more effects than the delegation allows".to_owned());
        }
        if reserved_spend.saturating_add(used_spend) > 5 {
            return Some("more spend than the delegation allows".to_owned());
        }
    }
    let finished = world
        .programs
        .iter()
        .all(|program| *program == Program::Released)
        && world
            .holds
            .iter()
            .all(|hold| matches!(hold, Hold::None | Hold::Done));
    if finished {
        if world.ledger.outstanding_reserved_bytes() != 0 || world.ledger.held_reservations() != 0 {
            return Some("an unused byte reservation did not return".to_owned());
        }
        if world.book.outstanding_effects() != 0 {
            return Some("an unused effect reservation did not return".to_owned());
        }
    }
    None
}

/// Every move one operation can make next.
fn budget_moves(world: &BudgetWorld, index: usize, bounds: &BudgetModelBounds) -> Vec<String> {
    let mut moves = Vec::new();
    let (Some(program), Some(hold)) = (world.programs.get(index), world.holds.get(index)) else {
        return moves;
    };
    match *program {
        Program::Start => {
            for channel_index in 0..2 {
                for bytes in 1..=bounds.max_reserve_bytes {
                    moves.push(format!("reserve:{channel_index}:{bytes}"));
                }
            }
            moves.push("skip".to_owned());
        }
        Program::Reserved { charges, .. } => {
            if charges < 2 {
                for bytes in 0..=bounds.max_charge_bytes {
                    moves.push(format!("charge:{bytes}"));
                }
            }
            moves.push("release".to_owned());
        }
        Program::Released => {}
    }
    match *hold {
        Hold::None => {
            for spend in 1..=3 {
                moves.push(format!("hold:{spend}"));
            }
        }
        Hold::Reserved { .. } => {
            moves.push("consume".to_owned());
            moves.push("unhold".to_owned());
        }
        Hold::InFlight { spend } => {
            moves.push("settle:fail".to_owned());
            for actual in 0..=spend {
                moves.push(format!("settle:commit:{actual}"));
            }
        }
        Hold::Done => {}
    }
    moves
}

fn apply_budget(
    world: &mut BudgetWorld,
    index: usize,
    action: &str,
    delegation: &DelegationId,
) -> bool {
    let parts: Vec<&str> = action.split(':').collect();
    let number = |position: usize| {
        parts
            .get(position)
            .and_then(|text| text.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let effect = effect_id(index);
    let basis = AuthorizationBasis::Delegation {
        delegation: *delegation,
    };
    let (Some(&program), Some(&hold)) = (world.programs.get(index), world.holds.get(index)) else {
        return false;
    };
    let set_program = |world: &mut BudgetWorld, value| {
        if let Some(slot) = world.programs.get_mut(index) {
            *slot = value;
        }
    };
    let set_hold = |world: &mut BudgetWorld, value| {
        if let Some(slot) = world.holds.get_mut(index) {
            *slot = value;
        }
    };
    match parts.first().copied() {
        Some("reserve") => {
            let channel_index = usize::try_from(number(1)).unwrap_or(0);
            match world.ledger.reserve(channel(channel_index), number(2)) {
                Ok(reservation) => {
                    set_program(
                        world,
                        Program::Reserved {
                            token: reservation.token,
                            charges: 0,
                        },
                    );
                    true
                }
                Err(_) => false,
            }
        }
        Some("skip") => {
            set_program(world, Program::Released);
            true
        }
        Some("charge") => {
            let Program::Reserved { token, charges } = program else {
                return false;
            };
            let bytes = number(1);
            // Split across body and framing so both parts are counted.
            let measure = WireMeasure {
                body_bytes: bytes / 2,
                framing_bytes: bytes - bytes / 2,
                ..WireMeasure::default()
            };
            match world.ledger.charge(token, &measure) {
                Ok(_) => {
                    set_program(
                        world,
                        Program::Reserved {
                            token,
                            charges: charges.saturating_add(1),
                        },
                    );
                    true
                }
                Err(_) => false,
            }
        }
        Some("release") => {
            let Program::Reserved { token, .. } = program else {
                return false;
            };
            let released = world.ledger.release(token).is_ok();
            set_program(world, Program::Released);
            released
        }
        Some("hold") => match world.book.reserve(basis, effect, number(1)) {
            Ok(_) => {
                set_hold(world, Hold::Reserved { spend: number(1) });
                true
            }
            Err(_) => false,
        },
        Some("consume") => {
            let Hold::Reserved { spend } = hold else {
                return false;
            };
            let consumed = world.book.consume(&effect).is_ok();
            if consumed {
                set_hold(world, Hold::InFlight { spend });
            }
            consumed
        }
        Some("unhold") => {
            let released = world.book.release(&effect).is_ok();
            if released {
                set_hold(world, Hold::Done);
            }
            released
        }
        Some("settle") => {
            let committed = parts.get(1) == Some(&"commit");
            let settled = world.book.settle(&effect, committed, number(2)).is_ok();
            if settled {
                set_hold(world, Hold::Done);
            }
            settled
        }
        _ => false,
    }
}

/// §12.3 model 4: every interleaving of `bounds.operations` concurrent operations, once
/// over byte reservations on the release channels and once over effect and spend holds
/// under one delegation (the two share no state).
pub fn check_budget_model(bounds: BudgetModelBounds) -> Result<ModelReport, Counterexample> {
    let (start, delegation) = budget_start(&bounds)?;
    let mut bytes = start.clone();
    bytes.holds = vec![Hold::Done; bounds.operations];
    let mut effects = start;
    effects.programs = vec![Program::Released; bounds.operations];
    let first = search_budget(bytes, &bounds, &delegation)?;
    let second = search_budget(effects, &bounds, &delegation)?;
    Ok(ModelReport {
        states: first.states + second.states,
        transitions: first.transitions + second.transitions,
        deepest: first.deepest.max(second.deepest),
        assumptions: BUDGET_ASSUMPTIONS,
    })
}

fn search_budget(
    start: BudgetWorld,
    bounds: &BudgetModelBounds,
    delegation: &DelegationId,
) -> Result<ModelReport, Counterexample> {
    // Each new state keeps only its parent step, so traces are rebuilt on demand.
    let mut steps: Vec<(usize, String)> = Vec::new();
    let trace = |steps: &[(usize, String)], mut at: usize, last: String| {
        let mut trace = vec![last];
        while let Some((parent, label)) = steps.get(at) {
            trace.push(label.clone());
            at = *parent;
        }
        trace.reverse();
        trace
    };
    let mut seen = HashSet::from([start.key()]);
    let mut queue = VecDeque::from([(start, usize::MAX, 0usize)]);
    let mut transitions = 0;
    let mut deepest = 0;
    while let Some((world, step, depth)) = queue.pop_front() {
        deepest = deepest.max(depth);
        for index in 0..world.programs.len() {
            for action in budget_moves(&world, index, bounds) {
                let mut next = world.clone();
                if !apply_budget(&mut next, index, &action, delegation) {
                    continue;
                }
                transitions += 1;
                let label = format!("op{index} {action}");
                if let Some(violation) = budget_violation(&next, delegation) {
                    return Err(Counterexample {
                        trace: trace(&steps, step, label),
                        violation,
                    });
                }
                if seen.insert(next.key()) {
                    steps.push((step, label));
                    queue.push_back((next, steps.len() - 1, depth + 1));
                }
            }
        }
    }
    Ok(ModelReport {
        states: seen.len(),
        transitions,
        deepest,
        assumptions: BUDGET_ASSUMPTIONS,
    })
}
