//! Test fakes for the effects module: a scripted authority, an in-memory audit store and
//! spool behind the real CORE-06 journal, an in-memory effect store, a scripted provider
//! and a content store. Nothing here touches a process, network or file.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::budget::{
    AccountingPolicy, ChannelBudget, ChannelDeclaration, ChannelKey, InFlightAllowance,
    ReleaseChannelKind, ReleaseLedger, ReleasePolicy, TrustClass,
};
use super::canonical::{CanonicalValue, ParamName, Parameters};
use super::capability::{
    AuthorizationBasis, CapabilityKey, ExecutorIdentity, ExecutorName, PolicyVersion,
};
use super::contract::{
    ContractRegistry, ListOrder, OperationContract, ParamKind, ParamSpec, PayloadRule, RouteSpec,
    ScalarKind,
};
use super::controller::{
    AuthorityPort, AuthorizationRequest, ControllerConfig, DispatchOutcome, EffectController,
    EffectError, EffectStore, JournalAudit, LeaseView, PersistedEffects, SandboxStanding,
    StoreFailure,
};
use super::delegation::{DelegationBudget, DelegationId, DelegationScope, StandingDelegation};
use super::description::{
    AccountRef, AttachmentName, CostCeiling, Deadline, Destination, EffectDescription,
    EffectFields, EffectId, Idempotency, IdempotencyKey, IdempotencyRequirement, IssuerId,
    OperationKey, OperationName, PayloadRef, ProviderId, ResourceRef, RouteRef, SandboxRef,
};
use super::executor::{
    ExecutorRefusal, NarrowExecutor, OutboundRequest, PayloadStore, ProviderLookup, ProviderPort,
    ProviderReply, RequestContent,
};
use super::secrets::{CredentialHandle, ExternalCredential};
use crate::foundation::coordination::{CancelCause, LeaseRefusal, SandboxGenerations};
use crate::foundation::events::{
    AuditConfig, AuditFailurePolicy, AuditJournal, AuditRecord, AuditSpool, AuditStore,
    EmissionLimit, JournalId, ProducerId, RedactionPolicy, StoreRefusal,
};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{
    digest, AuthorizationEpoch, ContentKey, ExecutionId, LeaseId, ManualClock, MonotonicTime,
    TenantId,
};
use crate::foundation::transfer::CredentialRef;

pub const SECOND: Duration = Duration::from_secs(1);
pub const HOUR: Duration = Duration::from_secs(3_600);
pub const SESSION: ClockSession = ClockSession::from_uuid(uuid::Uuid::from_u128(0xe1));
pub const START: MonotonicTime = MonotonicTime::from_nanos(1_000_000_000);
pub const PAYLOAD: &[u8] = b"diff --git a/parser.rs b/parser.rs\n+fixed\n";
pub const ATTACHMENT: &[u8] = b"diagram bytes";

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn issuer() -> IssuerId {
    IssuerId::new(digest("yougori/test/issuer/v1", &[b"host-1"]))
}

pub fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

pub fn sandbox() -> SandboxRef {
    SandboxRef {
        issuer: issuer(),
        execution: execution("exe-a"),
    }
}

pub fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

pub fn param(name: &str) -> ParamName {
    ParamName::new(name).unwrap()
}

pub fn route(name: &str) -> RouteRef {
    RouteRef::new(digest("yougori/test/route/v1", &[name.as_bytes()]))
}

pub fn account(name: &str) -> AccountRef {
    AccountRef::new(digest("yougori/test/account/v1", &[name.as_bytes()]))
}

pub fn operation(name: &str) -> OperationKey {
    OperationKey {
        provider: ProviderId::new("forge").unwrap(),
        operation: OperationName::new(name).unwrap(),
        contract_version: 1,
    }
}

pub fn payload(bytes: &[u8]) -> PayloadRef {
    PayloadRef {
        content: ContentKey::of(bytes),
        length_bytes: bytes.len() as u64,
    }
}

pub fn executor_identity() -> ExecutorIdentity {
    ExecutorIdentity {
        name: ExecutorName::new("forge-change-requests").unwrap(),
        build: digest("yougori/test/executor-build/v1", &[b"1.0.0"]),
    }
}

pub fn key() -> CapabilityKey {
    CapabilityKey::new(&[0x42; 32]).unwrap()
}

pub fn policy_version() -> PolicyVersion {
    PolicyVersion::new(digest("yougori/test/policy/v1", &[b"resolved"]))
}

pub fn credential() -> CredentialHandle {
    CredentialHandle::new(
        CredentialRef::from_digest(digest("yougori/test/vault/v1", &[b"forge-token"])),
        ExternalCredential::LongLivedProvider,
    )
}

/// The `forge/open_change_request` contract the tests use.
pub fn contract() -> OperationContract {
    let text = |max_bytes| ParamSpec {
        kind: ParamKind::Scalar {
            kind: ScalarKind::Text { max_bytes },
        },
        required: true,
    };
    OperationContract {
        operation: operation("open_change_request"),
        parameters: BTreeMap::from([
            (param("title"), text(200)),
            (
                param("draft"),
                ParamSpec {
                    kind: ParamKind::Scalar {
                        kind: ScalarKind::Bool,
                    },
                    required: false,
                },
            ),
            (
                param("labels"),
                ParamSpec {
                    kind: ParamKind::List {
                        item: ScalarKind::Text { max_bytes: 32 },
                        max_items: 4,
                        order: ListOrder::Unordered,
                    },
                    required: false,
                },
            ),
            (
                param("commits"),
                ParamSpec {
                    kind: ParamKind::List {
                        item: ScalarKind::Digest,
                        max_items: 4,
                        order: ListOrder::Ordered,
                    },
                    required: false,
                },
            ),
            (
                param("priority"),
                ParamSpec {
                    kind: ParamKind::Scalar {
                        kind: ScalarKind::Integer { min: 0, max: 5 },
                    },
                    required: false,
                },
            ),
        ]),
        routes: BTreeMap::from([(
            route("forge"),
            RouteSpec {
                trust: TrustClass::RegisteredProvider,
                name_bytes: 15,
            },
        )]),
        payload: PayloadRule::Optional,
        attachments: BTreeSet::from([AttachmentName::new("diagram").unwrap()]),
        provider_key: true,
        checkable_preconditions: true,
        response_fields: BTreeSet::from([param("number"), param("url")]),
        header_bytes: 200,
        framing_bytes: 50,
        max_cost: CostCeiling {
            max_spend_microunits: 1_000_000,
            max_volume_units: 10,
        },
    }
}

/// Fields that fit [`contract`].
pub fn fields() -> EffectFields {
    EffectFields {
        principal: tenant(),
        sandbox: sandbox(),
        operation: operation("open_change_request"),
        resource: ResourceRef {
            account: account("org-a"),
            object: digest("yougori/test/object/v1", &[b"repo-a"]),
        },
        destination: Destination {
            route: route("forge"),
            trust: TrustClass::RegisteredProvider,
        },
        parameters: Parameters::new()
            .with(
                param("title"),
                CanonicalValue::Text("Fix the parser".into()),
            )
            .with(param("draft"), CanonicalValue::Bool(false)),
        payload: Some(payload(PAYLOAD)),
        attachments: BTreeMap::new(),
        preconditions: BTreeSet::new(),
        max_cost: CostCeiling {
            max_spend_microunits: 1_000,
            max_volume_units: 1,
        },
        max_wire_bytes_out: 4_096,
        deadline: Deadline {
            clock: SESSION,
            at: START.saturating_add(HOUR),
        },
        idempotency: Idempotency {
            key: IdempotencyKey::new(digest("yougori/test/idempotency/v1", &[b"1"])),
            requirement: IdempotencyRequirement::ProviderKey,
        },
    }
}

pub fn description() -> EffectDescription {
    EffectDescription::new(fields()).unwrap()
}

/// Fields with another idempotency key, so they describe a second effect.
pub fn fields_numbered(n: u8) -> EffectFields {
    let mut fields = fields();
    fields.idempotency.key = IdempotencyKey::new(digest("yougori/test/idempotency/v1", &[&[n]]));
    fields
}

/// The release policy: VM-D12's 8 MiB general budget over every channel of §2.5.
pub fn release_policy(provider_budget_bytes: u64) -> ReleasePolicy {
    let declaration = |kind, trust, budget_bytes| ChannelDeclaration {
        key: ChannelKey { kind, trust },
        accounting: AccountingPolicy::WireBytes,
        budget: ChannelBudget::General { budget_bytes },
    };
    ReleasePolicy::vm_d12(
        vec![
            declaration(
                ReleaseChannelKind::ProviderRequest,
                TrustClass::RegisteredProvider,
                provider_budget_bytes,
            ),
            declaration(
                ReleaseChannelKind::TransportStream,
                TrustClass::PublicNetwork,
                1_000,
            ),
            ChannelDeclaration {
                key: ChannelKey {
                    kind: ReleaseChannelKind::DnsQuery,
                    trust: TrustClass::DnsResolver,
                },
                accounting: AccountingPolicy::WireBytesWithMessageFloor { floor_bytes: 64 },
                budget: ChannelBudget::General {
                    budget_bytes: 1_000,
                },
            },
            declaration(
                ReleaseChannelKind::PublishedServiceResponse,
                TrustClass::PublicNetwork,
                1_000,
            ),
            declaration(ReleaseChannelKind::File, TrustClass::HostStorage, 1_000),
            declaration(
                ReleaseChannelKind::TerminalOutput,
                TrustClass::HostUser,
                1_000,
            ),
            declaration(ReleaseChannelKind::Log, TrustClass::HostStorage, 1_000),
            declaration(
                ReleaseChannelKind::BrowserPreview,
                TrustClass::HostUser,
                1_000,
            ),
            ChannelDeclaration {
                key: ChannelKey {
                    kind: ReleaseChannelKind::UserApprovedTransfer,
                    trust: TrustClass::PublicNetwork,
                },
                accounting: AccountingPolicy::WireBytes,
                budget: ChannelBudget::Approved {
                    budget_bytes: 1_000,
                    approval: digest("yougori/test/approval/v1", &[b"bulk"]),
                },
            },
        ],
        InFlightAllowance::none(),
    )
    .unwrap()
}

/// A scripted CORE-04 authority: per-sandbox standing and per-lease answers.
#[derive(Default)]
pub struct AuthorityState {
    pub standing: BTreeMap<ExecutionId, SandboxStanding>,
    pub leases: BTreeMap<LeaseId, Result<LeaseView, LeaseRefusal>>,
    pub next_lease: u64,
}

#[derive(Clone, Default)]
pub struct SharedAuthority(pub Arc<Mutex<AuthorityState>>);

impl SharedAuthority {
    fn generations(&self, execution: &ExecutionId) -> SandboxGenerations {
        match lock(&self.0).standing.get(execution) {
            Some(SandboxStanding::Authorized { generations, .. })
            | Some(SandboxStanding::NoAuthority { generations }) => *generations,
            _ => SandboxGenerations::FIRST,
        }
    }

    /// Grants authority under the sandbox's current generations until `expires_at`.
    pub fn grant(&self, execution: &ExecutionId, expires_at: MonotonicTime) {
        let generations = self.generations(execution);
        lock(&self.0).standing.insert(
            execution.clone(),
            SandboxStanding::Authorized {
                generations,
                clock: SESSION,
                authority_expires_at: expires_at,
            },
        );
    }

    /// Issues a lease under the current generations.
    pub fn issue_lease(&self, execution: &ExecutionId, expires_at: MonotonicTime) -> LeaseId {
        let generations = self.generations(execution);
        let mut state = lock(&self.0);
        state.next_lease += 1;
        let lease = LeaseId::new(state.next_lease);
        state.leases.insert(
            lease,
            Ok(LeaseView {
                lease,
                parent: execution.clone(),
                generations,
                clock: SESSION,
                expires_at,
            }),
        );
        lease
    }

    fn change(
        &self,
        execution: &ExecutionId,
        cause: CancelCause,
        step: impl Fn(&mut SandboxGenerations),
    ) {
        let mut state = lock(&self.0);
        let Some(standing) = state.standing.get_mut(execution) else {
            return;
        };
        match standing {
            SandboxStanding::Authorized { generations, .. }
            | SandboxStanding::NoAuthority { generations } => step(generations),
            SandboxStanding::NotRunning => {}
        }
        for answer in state.leases.values_mut() {
            if matches!(answer, Ok(view) if &view.parent == execution) {
                *answer = Err(LeaseRefusal::Cancelled { cause });
            }
        }
    }

    /// A policy change: only the policy epoch moves, and old leases are cancelled.
    pub fn raise_policy(&self, execution: &ExecutionId) {
        self.change(execution, CancelCause::PolicyChange, |generations| {
            generations.policy = generations.policy.next().unwrap();
        });
    }

    /// A new boot: boot generation and authorization epoch move.
    pub fn reboot(&self, execution: &ExecutionId) {
        self.change(execution, CancelCause::NewBoot, |generations| {
            generations.boot = generations.boot.next().unwrap();
            generations.authorization = generations.authorization.next().unwrap();
        });
    }

    /// A coordinator revocation: the epoch moves and no authority is held.
    pub fn revoke(&self, execution: &ExecutionId) -> AuthorizationEpoch {
        self.change(execution, CancelCause::Revocation, |generations| {
            generations.authorization = generations.authorization.next().unwrap();
        });
        let generations = self.generations(execution);
        lock(&self.0).standing.insert(
            execution.clone(),
            SandboxStanding::NoAuthority { generations },
        );
        generations.authorization
    }
}

impl AuthorityPort for SharedAuthority {
    fn standing(&self, sandbox: &ExecutionId) -> SandboxStanding {
        lock(&self.0)
            .standing
            .get(sandbox)
            .copied()
            .unwrap_or(SandboxStanding::NotRunning)
    }

    fn lease(&self, lease: LeaseId) -> Result<LeaseView, LeaseRefusal> {
        lock(&self.0)
            .leases
            .get(&lease)
            .cloned()
            .unwrap_or(Err(LeaseRefusal::UnknownLease { lease }))
    }
}

/// Audit storage in memory; `refuse` makes it refuse every write.
#[derive(Clone, Default)]
pub struct MemoryAuditStore {
    pub records: Arc<Mutex<Vec<AuditRecord>>>,
    pub refuse: Arc<Mutex<bool>>,
}

impl AuditStore for MemoryAuditStore {
    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        if *lock(&self.refuse) {
            return Err(StoreRefusal::Full);
        }
        let mut records = lock(&self.records);
        if !records.iter().any(|stored| stored == record) {
            records.push(record.clone());
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemorySpool(VecDeque<AuditRecord>);

impl AuditSpool for MemorySpool {
    fn push(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        self.0.push_back(record.clone());
        Ok(())
    }

    fn front(&self) -> Result<Option<AuditRecord>, StoreRefusal> {
        Ok(self.0.front().cloned())
    }

    fn pop_front(&mut self) -> Result<(), StoreRefusal> {
        self.0.pop_front();
        Ok(())
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn records(&self) -> Result<Vec<AuditRecord>, StoreRefusal> {
        Ok(self.0.iter().cloned().collect())
    }
}

pub type TestAudit = JournalAudit<MemoryAuditStore, MemorySpool, Arc<ManualClock>>;

/// The real CORE-06 journal over memory; high-impact operations need durable records.
pub fn audit(clock: Arc<ManualClock>, store: MemoryAuditStore) -> TestAudit {
    let (journal, authority) = AuditJournal::open(
        JournalId::new("effects").unwrap(),
        ProducerId::new("effect-controller").unwrap(),
        store,
        MemorySpool::default(),
        clock,
        AuditConfig {
            spool_records: 4,
            revocation_reserve_records: 2,
            failure_policy: AuditFailurePolicy::DenyHighImpact,
            guest_observations: EmissionLimit::new(10, SECOND).unwrap(),
            redaction: RedactionPolicy::metadata_only(),
        },
    )
    .unwrap();
    JournalAudit::new(journal, authority)
}

/// Every persisted state, newest last; `refuse` makes it refuse.
#[derive(Clone, Default)]
pub struct MemoryStore {
    pub snapshots: Arc<Mutex<Vec<PersistedEffects>>>,
    pub refuse: Arc<Mutex<bool>>,
}

impl MemoryStore {
    pub fn latest(&self) -> PersistedEffects {
        lock(&self.snapshots).last().cloned().unwrap()
    }

    pub fn snapshot(&self, index: usize) -> PersistedEffects {
        lock(&self.snapshots)[index].clone()
    }

    pub fn count(&self) -> usize {
        lock(&self.snapshots).len()
    }
}

impl EffectStore for MemoryStore {
    fn persist(&mut self, state: &PersistedEffects) -> Result<(), StoreFailure> {
        if *lock(&self.refuse) {
            return Err(StoreFailure {
                detail: "disk full".to_owned(),
            });
        }
        // Persisting goes through the serialized form, as a durable store would.
        let json = serde_json::to_string(state).map_err(|error| StoreFailure {
            detail: error.to_string(),
        })?;
        let restored: PersistedEffects =
            serde_json::from_str(&json).map_err(|error| StoreFailure {
                detail: error.to_string(),
            })?;
        lock(&self.snapshots).push(restored);
        Ok(())
    }
}

/// What the scripted provider does with the next submissions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderMode {
    Commit,
    /// Commits, then the reply is lost.
    CommitLoseReply,
    /// The request never arrives.
    LoseRequest,
    Reject,
    Redirect(RouteRef),
    Partial,
    /// The port refuses before sending, as an executor-side refusal.
    RefuseInPort,
}

pub struct ProviderState {
    pub mode: ProviderMode,
    pub calls: u32,
    /// Commits per idempotency key, or per resource when no key was sent.
    pub commits: BTreeMap<String, u32>,
    pub requests: Vec<OutboundRequest>,
    pub credentials: Vec<CredentialRef>,
    /// The clock reading passed with each submission and each lookup.
    pub times: Vec<MonotonicTime>,
    pub lookups: Vec<MonotonicTime>,
}

#[derive(Clone)]
pub struct SharedProvider(pub Arc<Mutex<ProviderState>>);

impl SharedProvider {
    pub fn new(mode: ProviderMode) -> Self {
        Self(Arc::new(Mutex::new(ProviderState {
            mode,
            calls: 0,
            commits: BTreeMap::new(),
            requests: Vec::new(),
            credentials: Vec::new(),
            times: Vec::new(),
            lookups: Vec::new(),
        })))
    }

    pub fn set_mode(&self, mode: ProviderMode) {
        lock(&self.0).mode = mode;
    }

    pub fn calls(&self) -> u32 {
        lock(&self.0).calls
    }

    pub fn total_commits(&self) -> u32 {
        lock(&self.0).commits.values().sum()
    }

    pub fn last_request(&self) -> Option<OutboundRequest> {
        lock(&self.0).requests.last().cloned()
    }
}

fn commit_key(request: &OutboundRequest) -> String {
    match request.idempotency_key {
        Some(key) => format!("key:{key}"),
        None => format!("resource:{}", request.resource.object),
    }
}

fn response() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("number".to_owned(), "42".to_owned()),
        ("url".to_owned(), "https://forge.example/42".to_owned()),
        // A reflected credential and an undeclared field the executor must drop.
        (
            "authorization".to_owned(),
            "Bearer reflected-secret".to_owned(),
        ),
        ("debug".to_owned(), "internal".to_owned()),
    ])
}

impl ProviderPort for SharedProvider {
    fn submit(
        &mut self,
        request: &OutboundRequest,
        content: &RequestContent,
        credential: CredentialRef,
        now: MonotonicTime,
    ) -> ProviderReply {
        if let Err(refusal) = content.check(request) {
            return ProviderReply::Refused { refusal };
        }
        let mut state = lock(&self.0);
        state.times.push(now);
        state.calls += 1;
        state.requests.push(request.clone());
        state.credentials.push(credential);
        let key = commit_key(request);
        let deduplicated = request.idempotency_key.is_some() && state.commits.contains_key(&key);
        let commit = |state: &mut ProviderState| {
            if !deduplicated {
                *state.commits.entry(key.clone()).or_default() += 1;
            }
        };
        match state.mode.clone() {
            ProviderMode::Commit => {
                commit(&mut state);
                ProviderReply::Committed {
                    response: response(),
                    spend_microunits: 400,
                    volume_units: 1,
                }
            }
            ProviderMode::CommitLoseReply => {
                commit(&mut state);
                ProviderReply::NoResponse
            }
            ProviderMode::LoseRequest => ProviderReply::NoResponse,
            ProviderMode::RefuseInPort => ProviderReply::Refused {
                refusal: ExecutorRefusal::NotSent {
                    detail: "transport_unavailable".to_owned(),
                },
            },
            ProviderMode::Reject => ProviderReply::Rejected {
                code: "validation_failed".to_owned(),
            },
            ProviderMode::Redirect(route) => ProviderReply::Redirect { route },
            ProviderMode::Partial => {
                commit(&mut state);
                ProviderReply::PartialSuccess {
                    response: response(),
                    spend_microunits: 200,
                    volume_units: 1,
                }
            }
        }
    }

    fn lookup(
        &mut self,
        request: &OutboundRequest,
        content: &RequestContent,
        _credential: CredentialRef,
        now: MonotonicTime,
    ) -> ProviderLookup {
        if content.check(request).is_err() {
            return ProviderLookup::Unknown;
        }
        let mut state = lock(&self.0);
        state.lookups.push(now);
        if state.commits.contains_key(&commit_key(request)) {
            ProviderLookup::Committed {
                response: response(),
                spend_microunits: 400,
                volume_units: 1,
            }
        } else {
            ProviderLookup::NotCommitted
        }
    }
}

/// The host content store; `overwrite` models a file changed in place after review.
#[derive(Clone, Default)]
pub struct MemoryPayloads(pub Arc<Mutex<BTreeMap<ContentKey, Vec<u8>>>>);

impl MemoryPayloads {
    pub fn with(bytes: &[&[u8]]) -> Self {
        let store = Self::default();
        for bytes in bytes {
            lock(&store.0).insert(ContentKey::of(bytes), bytes.to_vec());
        }
        store
    }

    pub fn overwrite(&self, key: ContentKey, bytes: &[u8]) {
        lock(&self.0).insert(key, bytes.to_vec());
    }
}

impl PayloadStore for MemoryPayloads {
    fn bytes(&self, content: &ContentKey) -> Option<Vec<u8>> {
        lock(&self.0).get(content).cloned()
    }
}

pub type TestExecutor = NarrowExecutor<SharedProvider, MemoryPayloads>;
pub type TestController =
    EffectController<Arc<ManualClock>, SharedAuthority, TestAudit, MemoryStore>;

pub fn config() -> ControllerConfig {
    ControllerConfig {
        issuer: issuer(),
        session: SESSION,
        capability_lifetime: 60 * SECOND,
        allowed_clock_uncertainty: 2 * SECOND,
    }
}

/// A controller, its fakes and a standing delegation over the forge contract.
pub struct World {
    pub clock: Arc<ManualClock>,
    pub authority: SharedAuthority,
    pub audit_store: MemoryAuditStore,
    pub store: MemoryStore,
    pub provider: SharedProvider,
    pub payloads: MemoryPayloads,
    pub controller: TestController,
    pub executor: TestExecutor,
    pub lease: LeaseId,
    pub delegation: DelegationId,
}

pub fn delegation_scope() -> DelegationScope {
    DelegationScope {
        principal: tenant(),
        sandbox: sandbox(),
        executor: executor_identity().name,
        operations: BTreeSet::from([operation("open_change_request")]),
        routes: BTreeSet::from([route("forge")]),
        accounts: BTreeSet::from([account("org-a")]),
        max_cost_per_effect: CostCeiling {
            max_spend_microunits: 10_000,
            max_volume_units: 5,
        },
        max_wire_bytes_per_effect: 8_192,
    }
}

pub fn delegation(max_effects: u64) -> StandingDelegation {
    StandingDelegation {
        scope: delegation_scope(),
        budget: DelegationBudget {
            max_effects,
            max_spend_microunits: 100_000,
        },
        policy: crate::foundation::ids::PolicyEpoch::FIRST,
        expires: Deadline {
            clock: SESSION,
            at: START.saturating_add(10 * HOUR),
        },
    }
}

impl World {
    pub fn new() -> Self {
        Self::with(ProviderMode::Commit, 64 * 1024, 10)
    }

    pub fn with(mode: ProviderMode, provider_budget_bytes: u64, max_effects: u64) -> Self {
        let clock = Arc::new(ManualClock::new(START));
        let authority = SharedAuthority::default();
        authority.grant(&execution("exe-a"), START.saturating_add(10 * HOUR));
        let lease = authority.issue_lease(&execution("exe-a"), START.saturating_add(10 * HOUR));
        let audit_store = MemoryAuditStore::default();
        let store = MemoryStore::default();
        let provider = SharedProvider::new(mode);
        let payloads = MemoryPayloads::with(&[PAYLOAD, ATTACHMENT]);
        let mut controller = EffectController::new(
            config(),
            clock.clone(),
            key(),
            authority.clone(),
            audit(clock.clone(), audit_store.clone()),
            store.clone(),
            ContractRegistry::new().with(contract()),
            ReleaseLedger::new(release_policy(provider_budget_bytes)),
        )
        .unwrap();
        let delegation = controller
            .grant_delegation(delegation(max_effects))
            .unwrap();
        let executor = NarrowExecutor::new(
            executor_identity(),
            contract(),
            key(),
            SESSION,
            provider.clone(),
            payloads.clone(),
        );
        Self {
            clock,
            authority,
            audit_store,
            store,
            provider,
            payloads,
            controller,
            executor,
            lease,
            delegation,
        }
    }

    pub fn request(&self) -> AuthorizationRequest {
        AuthorizationRequest {
            basis: AuthorizationBasis::Delegation {
                delegation: self.delegation,
            },
            executor: executor_identity(),
            lease: self.lease,
            policy_version: policy_version(),
        }
    }

    /// Proposes, validates, authorizes and reserves.
    pub fn prepare(&mut self, description: EffectDescription) -> Result<EffectId, EffectError> {
        let id = self.controller.propose(description)?;
        self.controller.validate(&id)?;
        let request = self.request();
        self.controller.authorize(&id, request)?;
        self.controller.reserve(&id)?;
        Ok(id)
    }

    pub fn dispatch(&mut self, id: &EffectId) -> Result<DispatchOutcome, EffectError> {
        self.controller
            .dispatch(id, &mut self.executor, credential())
    }

    /// The whole pipeline for one description.
    pub fn run(&mut self, description: EffectDescription) -> (EffectId, DispatchOutcome) {
        let id = self.prepare(description).unwrap();
        let outcome = self.dispatch(&id).unwrap();
        (id, outcome)
    }

    pub fn audit_records(&self) -> Vec<AuditRecord> {
        lock(&self.audit_store.records).clone()
    }
}
