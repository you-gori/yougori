//! Test fakes for the provider module: a scripted CORE-04 authority, the real CORE-06
//! journal over memory, an in-memory effect store read back through the records port, a
//! fake vault holding a fixture credential, a scripted transport and a content store.
//! Nothing here touches a process, network or file. The fixture credential is fake.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::operation::{
    BatchSpec, BodyEncoding, CostModel, DestinationBinding, GraphQlKind, GraphQlOperation,
    MeteredParam, OperationCatalog, OperationDraft, OperationFamily, OperationIntent,
    ProviderOperation,
};
use super::records::EffectRecordsPort;
use super::response::{CostReport, FieldSchema, ResponsePolicy, ResponseProfile, ResponseSchema};
use super::scan::{find_encoded, KnownSecrets, ScanEncoding};
use super::spend::{SharedSpendLedger, SpendLedger};
use super::vault::{
    AuthenticatedRequest, CredentialVault, GrantTable, LookupResult, SecretValue, TransportResult,
    UpstreamReply, UpstreamTransport, VaultFacts, VaultGrant, VaultRefusal, VaultScope,
};
use super::{executor::ExecutorParts, executor::ProviderExecutor, request::UpstreamRequest};
use crate::foundation::coordination::{CancelCause, LeaseRefusal, SandboxGenerations};
use crate::foundation::events::{
    AuditConfig, AuditFailurePolicy, AuditJournal, AuditRecord, AuditSpool, AuditStore,
    EmissionLimit, JournalId, ProducerId, RedactionPolicy, StoreRefusal,
};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{
    digest, AuthorizationEpoch, ContentKey, Digest, ExecutionId, LeaseId, ManualClock,
    MonotonicTime, PolicyEpoch, TenantId,
};
use crate::foundation::transfer::CredentialRef;
use crate::sandbox_contract::destinations::{
    Authority, DestinationPort, EffectClass, HttpMethod, OperationName as RouteOperationName,
    OperationRoute, OperationSpec, OperationTls, PathTemplate, RedirectPolicy, RouteKind,
};
use crate::sandbox_contract::effects::{
    AccountRef, AccountingPolicy, AuthorityPort, AuthorizationBasis, AuthorizationRequest,
    BudgetHold, CapabilityKey, ChannelBudget, ChannelDeclaration, ChannelKey, ControllerConfig,
    CostCeiling, Deadline, DelegationBudget, DelegationId, DelegationScope, Destination,
    DispatchOutcome, EffectController, EffectDescription, EffectError, EffectFields, EffectId,
    EffectRecord, EffectStore, ExecutorIdentity, ExecutorName, ExposureProfile, Idempotency,
    IdempotencyKey, IdempotencyRequirement, InFlightAllowance, IssuerId, JournalAudit, LeaseView,
    OperationContract, OperationKey, OperationName, ParamKind, ParamName, ParamSpec, Parameters,
    PayloadRef, PayloadRule, PayloadStore, PersistedEffects, PolicyVersion, ProviderId,
    ReleaseChannelKind, ReleaseLedger, ReleasePolicy, ResourceRef, RouteRef, RouteSpec, SandboxRef,
    SandboxStanding, ScalarKind, ScopeViolation, SecretClass, StandingDelegation, StoreFailure,
    TrustClass,
};

pub const SECOND: Duration = Duration::from_secs(1);
pub const HOUR: Duration = Duration::from_secs(3_600);
pub const SESSION: ClockSession = ClockSession::from_uuid(uuid::Uuid::from_u128(0x07));
pub const START: MonotonicTime = MonotonicTime::from_nanos(1_000_000_000);

/// The fixture credential the fake vault holds. It is not a real credential.
pub const VAULT_SECRET: &[u8] = b"sk-live-FIXTURE-vault-0123456789abcdef";
/// A second known fixture secret the vault does not hold, planted in fake responses.
pub const PLANTED_SECRET: &[u8] = b"ghp_FIXTURE_planted_secret_42424242";

pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn at(since_start: Duration) -> MonotonicTime {
    START.saturating_add(since_start)
}

pub fn bearer() -> Vec<u8> {
    [b"Bearer ".as_slice(), VAULT_SECRET].concat()
}

/// Whether `text` holds a fixture secret in any scanned encoding.
pub fn leaks(text: &[u8]) -> bool {
    [VAULT_SECRET, PLANTED_SECRET, bearer().as_slice()]
        .iter()
        .any(|secret| find_encoded(text, secret).is_some())
}

pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn issuer() -> IssuerId {
    IssuerId::new(digest("yougori/test/issuer/v1", &[b"host-a"]))
}

pub fn execution() -> ExecutionId {
    ExecutionId::new("exe-a").unwrap()
}

pub fn sandbox() -> SandboxRef {
    SandboxRef {
        issuer: issuer(),
        execution: execution(),
    }
}

pub fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

pub fn param(name: &str) -> ParamName {
    ParamName::new(name).unwrap()
}

pub fn account(name: &str) -> AccountRef {
    AccountRef::new(digest("yougori/test/account/v1", &[name.as_bytes()]))
}

pub fn op_key(name: &str) -> OperationKey {
    OperationKey {
        provider: ProviderId::new("forge").unwrap(),
        operation: OperationName::new(name).unwrap(),
        contract_version: 1,
    }
}

pub fn executor_identity() -> ExecutorIdentity {
    ExecutorIdentity {
        name: ExecutorName::new("forge-executor").unwrap(),
        build: digest("yougori/test/executor-build/v1", &[b"1"]),
    }
}

pub fn key() -> CapabilityKey {
    CapabilityKey::new(&[7u8; 32]).unwrap()
}

pub fn policy_version() -> PolicyVersion {
    PolicyVersion::new(digest("yougori/test/policy/v1", &[b"p1"]))
}

pub fn credential_ref() -> CredentialRef {
    CredentialRef::from_digest(digest("yougori/test/vault/v1", &[b"forge-key"]))
}

pub fn port() -> DestinationPort {
    DestinationPort::new(443).unwrap()
}

pub fn forge_authority() -> Authority {
    Authority::parse("api.forge.example", port()).unwrap()
}

pub fn raw_authority() -> Authority {
    Authority::parse("raw.forge.example", port()).unwrap()
}

pub fn forge_route_ref() -> RouteRef {
    DestinationBinding::route_ref_for(&forge_authority())
}

pub fn raw_route_ref() -> RouteRef {
    DestinationBinding::route_ref_for(&raw_authority())
}

pub fn text(max_bytes: u32) -> ParamKind {
    ParamKind::Scalar {
        kind: ScalarKind::Text { max_bytes },
    }
}

pub fn integer(min: i64, max: i64) -> ParamKind {
    ParamKind::Scalar {
        kind: ScalarKind::Integer { min, max },
    }
}

pub fn spec(
    name: &str,
    method: HttpMethod,
    path: &str,
    query: &[&str],
    effect: EffectClass,
) -> OperationSpec {
    OperationSpec {
        name: RouteOperationName::new(name).unwrap(),
        method,
        path: PathTemplate::parse(path).unwrap(),
        query_keys: query.iter().map(|key| (*key).to_owned()).collect(),
        effect,
    }
}

pub fn forge_specs() -> Vec<OperationSpec> {
    use EffectClass::{External, ReadOnly};
    use HttpMethod::{Get, Post, Put};
    vec![
        spec(
            "open_pull_request",
            Post,
            "/repos/{owner}/{repo}/pulls",
            &[],
            External,
        ),
        spec("generate_summary", Post, "/v1/summaries", &[], ReadOnly),
        spec(
            "trigger_build",
            Get,
            "/repos/{owner}/{repo}/dispatch",
            &["ref", "note"],
            External,
        ),
        spec("upload_object", Put, "/objects/{name}", &["mode"], External),
        spec("star_repository", Post, "/graphql", &[], External),
        spec(
            "add_label",
            Post,
            "/repos/{owner}/{repo}/labels",
            &[],
            External,
        ),
        spec("apply_labels", Post, "/batch", &[], External),
    ]
}

pub fn forge_route() -> RouteKind {
    RouteKind::Operation(
        OperationRoute::new(
            OperationTls::ConstructedByExecutor,
            Some(credential_ref()),
            forge_specs(),
            RedirectPolicy::Disabled,
            false,
        )
        .unwrap(),
    )
}

pub fn raw_route() -> RouteKind {
    RouteKind::Operation(
        OperationRoute::new(
            OperationTls::TerminatedAtExecutor,
            Some(credential_ref()),
            vec![spec(
                "raw_call",
                HttpMethod::Post,
                "/raw",
                &[],
                EffectClass::External,
            )],
            RedirectPolicy::Disabled,
            false,
        )
        .unwrap(),
    )
}

pub fn binding(
    authority: Authority,
    route: RouteKind,
    spec: &str,
    path: &[&str],
) -> DestinationBinding {
    DestinationBinding {
        authority,
        route,
        spec: RouteOperationName::new(spec).unwrap(),
        path_params: path.iter().map(|name| param(name)).collect(),
    }
}

pub struct ContractParts<'a> {
    pub name: &'a str,
    pub params: Vec<(&'a str, ParamKind, bool)>,
    pub payload: PayloadRule,
    pub response: Vec<(&'a str, ScalarKind, bool)>,
    pub provider_key: bool,
    pub max_cost: CostCeiling,
    pub route: RouteRef,
}

pub fn contract(parts: &ContractParts<'_>) -> OperationContract {
    OperationContract {
        operation: op_key(parts.name),
        parameters: parts
            .params
            .iter()
            .map(|(name, kind, required)| {
                (
                    param(name),
                    ParamSpec {
                        kind: *kind,
                        required: *required,
                    },
                )
            })
            .collect(),
        routes: BTreeMap::from([(
            parts.route,
            RouteSpec {
                trust: TrustClass::RegisteredProvider,
                name_bytes: 64,
            },
        )]),
        payload: parts.payload,
        attachments: BTreeSet::new(),
        provider_key: parts.provider_key,
        checkable_preconditions: true,
        response_fields: parts
            .response
            .iter()
            .map(|(name, _, _)| param(name))
            .collect(),
        header_bytes: 512,
        framing_bytes: 64,
        max_cost: parts.max_cost,
    }
}

pub fn typed(response: &[(&str, ScalarKind, bool)], cost_report: CostReport) -> ResponsePolicy {
    ResponsePolicy {
        profile: ResponseProfile::Typed {
            schema: ResponseSchema {
                fields: response
                    .iter()
                    .map(|(name, kind, required)| {
                        (
                            param(name),
                            FieldSchema {
                                kind: *kind,
                                required: *required,
                            },
                        )
                    })
                    .collect(),
                max_body_bytes: 16 * 1024,
            },
        },
        cost_report,
    }
}

pub fn credentials() -> BTreeSet<SecretClass> {
    BTreeSet::from([
        SecretClass::LongLivedProviderCredential,
        SecretClass::ShortLivedCapability,
    ])
}

pub fn fixed(fixed_microunits: u64) -> CostModel {
    CostModel {
        fixed_microunits,
        microunits_per_request_byte: 0,
        metered: None,
    }
}

pub const GRAPHQL_DOCUMENT: &str =
    "mutation AddStar($id: ID!) { addStar(input: {starrableId: $id}) { clientMutationId } }";

pub struct OpParts<'a> {
    pub contract: ContractParts<'a>,
    pub family: OperationFamily,
    pub intent: OperationIntent,
    pub spec: &'a str,
    pub path: &'a [&'a str],
    pub encoding: BodyEncoding,
    pub cost: CostModel,
    pub cost_report: CostReport,
}

pub fn draft(parts: OpParts<'_>) -> OperationDraft {
    let (authority, route) = if parts.family.is_passthrough() {
        (raw_authority(), raw_route())
    } else {
        (forge_authority(), forge_route())
    };
    let response = if parts.family.is_passthrough() {
        ResponsePolicy {
            profile: ResponseProfile::CredentialedPassthrough {
                max_body_bytes: 4096,
            },
            cost_report: parts.cost_report.clone(),
        }
    } else {
        typed(&parts.contract.response, parts.cost_report.clone())
    };
    OperationDraft {
        contract: contract(&parts.contract),
        family: parts.family,
        intent: parts.intent,
        binding: binding(authority, route, parts.spec, parts.path),
        encoding: parts.encoding,
        cost: parts.cost,
        response,
        credentials: credentials(),
    }
}

fn ceiling(max_spend_microunits: u64, max_volume_units: u64) -> CostCeiling {
    CostCeiling {
        max_spend_microunits,
        max_volume_units,
    }
}

pub fn open_pull_request_parts() -> OpParts<'static> {
    OpParts {
        contract: ContractParts {
            name: "open_pull_request",
            params: vec![
                ("owner", text(64), true),
                ("repo", text(64), true),
                ("title", text(256), true),
                ("head", text(128), true),
                ("base", text(128), true),
            ],
            payload: PayloadRule::Forbidden,
            response: vec![
                (
                    "number",
                    ScalarKind::Integer {
                        min: 1,
                        max: i64::MAX,
                    },
                    true,
                ),
                ("html_url", ScalarKind::Text { max_bytes: 512 }, true),
            ],
            provider_key: true,
            max_cost: ceiling(10_000, 5),
            route: forge_route_ref(),
        },
        family: OperationFamily::RepositoryWrite,
        intent: OperationIntent::SideEffecting,
        spec: "open_pull_request",
        path: &["owner", "repo"],
        encoding: BodyEncoding::JsonParameters,
        cost: fixed(1_000),
        cost_report: CostReport::NotReported,
    }
}

pub fn generate_summary_parts() -> OpParts<'static> {
    OpParts {
        contract: ContractParts {
            name: "generate_summary",
            params: vec![
                ("prompt", text(4096), true),
                ("max_output_tokens", integer(0, 4096), false),
                (
                    "tags",
                    ParamKind::List {
                        item: ScalarKind::Text { max_bytes: 32 },
                        max_items: 8,
                        order: crate::sandbox_contract::effects::ListOrder::Unordered,
                    },
                    false,
                ),
            ],
            payload: PayloadRule::Forbidden,
            response: vec![
                ("output_text", ScalarKind::Text { max_bytes: 8192 }, true),
                ("finish_reason", ScalarKind::Text { max_bytes: 32 }, true),
            ],
            provider_key: false,
            max_cost: ceiling(1_000_000, 10_000),
            route: forge_route_ref(),
        },
        family: OperationFamily::Inference,
        intent: OperationIntent::ReadOnly,
        spec: "generate_summary",
        path: &[],
        encoding: BodyEncoding::JsonParameters,
        cost: CostModel {
            fixed_microunits: 100,
            microunits_per_request_byte: 2,
            metered: Some(MeteredParam {
                param: param("max_output_tokens"),
                microunits_per_unit: 30,
            }),
        },
        cost_report: CostReport::Header {
            name: "x-cost-microunits".to_owned(),
        },
    }
}

pub fn trigger_build_parts() -> OpParts<'static> {
    OpParts {
        contract: ContractParts {
            name: "trigger_build",
            params: vec![
                ("owner", text(64), true),
                ("repo", text(64), true),
                ("ref", text(64), true),
                ("note", text(4096), false),
            ],
            payload: PayloadRule::Forbidden,
            response: vec![(
                "run_id",
                ScalarKind::Integer {
                    min: 0,
                    max: i64::MAX,
                },
                true,
            )],
            provider_key: true,
            max_cost: ceiling(10_000, 5),
            route: forge_route_ref(),
        },
        family: OperationFamily::RepositoryWrite,
        intent: OperationIntent::SideEffecting,
        spec: "trigger_build",
        path: &["owner", "repo"],
        encoding: BodyEncoding::Query,
        cost: fixed(500),
        cost_report: CostReport::NotReported,
    }
}

pub fn upload_object_parts() -> OpParts<'static> {
    OpParts {
        contract: ContractParts {
            name: "upload_object",
            params: vec![("name", text(128), true), ("mode", text(16), false)],
            payload: PayloadRule::Required,
            response: vec![("etag", ScalarKind::Digest, true)],
            provider_key: true,
            max_cost: ceiling(u64::MAX / 4, 5),
            route: forge_route_ref(),
        },
        family: OperationFamily::ObjectUpload,
        intent: OperationIntent::SideEffecting,
        spec: "upload_object",
        path: &["name"],
        encoding: BodyEncoding::RawPayload,
        cost: CostModel {
            fixed_microunits: 0,
            microunits_per_request_byte: 1,
            metered: None,
        },
        cost_report: CostReport::NotReported,
    }
}

pub fn star_repository_parts() -> OpParts<'static> {
    OpParts {
        contract: ContractParts {
            name: "star_repository",
            params: vec![("id", text(64), true)],
            payload: PayloadRule::Forbidden,
            response: vec![(
                "client_mutation_id",
                ScalarKind::Text { max_bytes: 64 },
                false,
            )],
            provider_key: true,
            max_cost: ceiling(10_000, 5),
            route: forge_route_ref(),
        },
        family: OperationFamily::GraphQl(
            GraphQlOperation::new(GRAPHQL_DOCUMENT, "AddStar", GraphQlKind::Mutation).unwrap(),
        ),
        intent: OperationIntent::SideEffecting,
        spec: "star_repository",
        path: &[],
        encoding: BodyEncoding::GraphQlEnvelope,
        cost: fixed(50),
        cost_report: CostReport::NotReported,
    }
}

pub fn add_label_parts() -> OpParts<'static> {
    OpParts {
        contract: ContractParts {
            name: "add_label",
            params: vec![
                ("owner", text(64), true),
                ("repo", text(64), true),
                ("label", text(64), true),
            ],
            payload: PayloadRule::Forbidden,
            response: vec![("ok", ScalarKind::Bool, true)],
            provider_key: true,
            max_cost: ceiling(10_000, 5),
            route: forge_route_ref(),
        },
        family: OperationFamily::RepositoryWrite,
        intent: OperationIntent::SideEffecting,
        spec: "add_label",
        path: &["owner", "repo"],
        encoding: BodyEncoding::JsonParameters,
        cost: fixed(200),
        cost_report: CostReport::NotReported,
    }
}

pub fn apply_labels_parts() -> OpParts<'static> {
    OpParts {
        contract: ContractParts {
            name: "apply_labels",
            params: vec![],
            payload: PayloadRule::Required,
            response: vec![("applied", ScalarKind::Integer { min: 0, max: 1_000 }, true)],
            provider_key: true,
            max_cost: ceiling(100_000, 50),
            route: forge_route_ref(),
        },
        family: OperationFamily::Batch(BatchSpec {
            members: BTreeSet::from([op_key("add_label")]),
            max_members: 3,
        }),
        intent: OperationIntent::SideEffecting,
        spec: "apply_labels",
        path: &[],
        encoding: BodyEncoding::BatchDocument,
        cost: fixed(10),
        cost_report: CostReport::NotReported,
    }
}

pub fn raw_call_parts() -> OpParts<'static> {
    OpParts {
        contract: ContractParts {
            name: "raw_call",
            params: vec![("body_text", text(4096), true)],
            payload: PayloadRule::Forbidden,
            response: vec![("body", ScalarKind::Text { max_bytes: 4096 }, true)],
            provider_key: false,
            max_cost: ceiling(10_000, 5),
            route: raw_route_ref(),
        },
        family: OperationFamily::CredentialedPassthrough,
        intent: OperationIntent::SideEffecting,
        spec: "raw_call",
        path: &[],
        encoding: BodyEncoding::JsonParameters,
        cost: fixed(10),
        cost_report: CostReport::NotReported,
    }
}

pub fn catalog() -> OperationCatalog {
    let mut catalog = OperationCatalog::new();
    for parts in [
        open_pull_request_parts(),
        generate_summary_parts(),
        trigger_build_parts(),
        upload_object_parts(),
        star_repository_parts(),
        add_label_parts(),
        apply_labels_parts(),
        raw_call_parts(),
    ] {
        catalog
            .insert(ProviderOperation::new(draft(parts)).unwrap())
            .unwrap();
    }
    catalog
}

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

/// A scripted CORE-04 authority.
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

    /// A coordinator revocation: the epoch moves, leases are cancelled and no authority
    /// is held.
    pub fn revoke(&self, execution: &ExecutionId) -> AuthorizationEpoch {
        let mut state = lock(&self.0);
        let mut epoch = AuthorizationEpoch::FIRST;
        if let Some(standing) = state.standing.get_mut(execution) {
            let generations = match standing {
                SandboxStanding::Authorized { generations, .. }
                | SandboxStanding::NoAuthority { generations } => {
                    generations.authorization = generations.authorization.next().unwrap();
                    *generations
                }
                SandboxStanding::NotRunning => SandboxGenerations::FIRST,
            };
            epoch = generations.authorization;
            *standing = SandboxStanding::NoAuthority { generations };
        }
        for answer in state.leases.values_mut() {
            if matches!(answer, Ok(view) if &view.parent == execution) {
                *answer = Err(LeaseRefusal::Cancelled {
                    cause: CancelCause::Revocation,
                });
            }
        }
        epoch
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

#[derive(Clone, Default)]
pub struct MemoryAuditStore {
    pub records: Arc<Mutex<Vec<AuditRecord>>>,
}

impl AuditStore for MemoryAuditStore {
    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
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

pub fn audit(clock: Arc<ManualClock>, store: MemoryAuditStore) -> TestAudit {
    let (journal, authority) = AuditJournal::open(
        JournalId::new("provider-effects").unwrap(),
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

/// Every persisted state, newest last, through the serialized form.
#[derive(Clone, Default)]
pub struct MemoryStore {
    pub snapshots: Arc<Mutex<Vec<PersistedEffects>>>,
    pub json: Arc<Mutex<Vec<String>>>,
}

impl MemoryStore {
    pub fn latest(&self) -> Option<PersistedEffects> {
        lock(&self.snapshots).last().cloned()
    }
}

impl EffectStore for MemoryStore {
    fn persist(&mut self, state: &PersistedEffects) -> Result<(), StoreFailure> {
        let json = serde_json::to_string(state).map_err(|error| StoreFailure {
            detail: error.to_string(),
        })?;
        let restored: PersistedEffects =
            serde_json::from_str(&json).map_err(|error| StoreFailure {
                detail: error.to_string(),
            })?;
        lock(&self.snapshots).push(restored);
        lock(&self.json).push(json);
        Ok(())
    }
}

/// The records port over the durable store, as an independent executor reads it: the
/// latest persisted state, read back through its serialized form.
pub struct StoreRecords(pub MemoryStore);

impl EffectRecordsPort for StoreRecords {
    fn record(&self, effect: &EffectId) -> Option<EffectRecord> {
        EffectRecordsPort::record(&self.0.latest()?, effect)
    }

    fn hold(&self, effect: &EffectId) -> Option<BudgetHold> {
        EffectRecordsPort::hold(&self.0.latest()?, effect)
    }

    fn check_basis(
        &self,
        basis: &AuthorizationBasis,
        description: &EffectDescription,
        executor: &ExecutorIdentity,
        policy: PolicyEpoch,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Result<(), ScopeViolation> {
        self.0
            .latest()
            .ok_or(ScopeViolation::UnknownBasis)?
            .check_basis(basis, description, executor, policy, now, session)
    }
}

/// The fake vault: a grant table and the fixture credential.
pub struct VaultState {
    pub grants: GrantTable,
    pub secrets: BTreeMap<CredentialRef, Vec<u8>>,
    pub sends: u32,
    pub lookups: u32,
}

#[derive(Clone)]
pub struct FakeVault(pub Arc<Mutex<VaultState>>);

impl std::fmt::Debug for FakeVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeVault(..)")
    }
}

impl FakeVault {
    pub fn new(grant: VaultGrant) -> Self {
        let mut grants = GrantTable::new();
        let credential = grant.credential;
        grants.grant(grant).unwrap();
        Self(Arc::new(Mutex::new(VaultState {
            grants,
            secrets: BTreeMap::from([(credential, VAULT_SECRET.to_vec())]),
            sends: 0,
            lookups: 0,
        })))
    }

    pub fn sends(&self) -> u32 {
        lock(&self.0).sends
    }

    fn authorization(
        &self,
        scope: &VaultScope,
        now: MonotonicTime,
    ) -> Result<(SecretClass, SecretValue), VaultRefusal> {
        let state = lock(&self.0);
        let class = state.grants.permits(scope, now, SESSION)?;
        let secret = state
            .secrets
            .get(&scope.credential)
            .ok_or(VaultRefusal::UnknownCredential)?;
        Ok((
            class,
            SecretValue::new([b"Bearer ".as_slice(), secret].concat()),
        ))
    }
}

impl CredentialVault for FakeVault {
    fn facts(&self, scope: &VaultScope, now: MonotonicTime) -> Result<VaultFacts, VaultRefusal> {
        let (class, value) = self.authorization(scope, now)?;
        Ok(VaultFacts {
            class,
            authorization_header_bytes: value.len_bytes(),
        })
    }

    fn send(
        &mut self,
        scope: &VaultScope,
        request: &UpstreamRequest,
        transport: &mut dyn UpstreamTransport,
        now: MonotonicTime,
    ) -> Result<TransportResult, VaultRefusal> {
        let (_, value) = self.authorization(scope, now)?;
        lock(&self.0).sends += 1;
        Ok(transport.exchange(&AuthenticatedRequest::new(request, &value)))
    }

    fn lookup(
        &mut self,
        scope: &VaultScope,
        request: &UpstreamRequest,
        transport: &mut dyn UpstreamTransport,
        now: MonotonicTime,
    ) -> Result<LookupResult, VaultRefusal> {
        let (_, value) = self.authorization(scope, now)?;
        lock(&self.0).lookups += 1;
        Ok(transport.lookup(&AuthenticatedRequest::new(request, &value)))
    }

    fn reflects_secret(&self, scope: &VaultScope, bytes: &[u8]) -> Option<ScanEncoding> {
        let state = lock(&self.0);
        let secret = state.secrets.get(&scope.credential)?;
        find_encoded(bytes, secret)
            .or_else(|| find_encoded(bytes, &[b"Bearer ".as_slice(), secret].concat()))
    }
}

/// What the scripted transport answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplyMode {
    Fixed(UpstreamReply),
    /// Reflects the authorization value in a response header.
    EchoAuthorizationHeader,
    /// Reflects the authorization value inside a schema field of the body.
    EchoAuthorizationBody,
    /// Reflects it base64-encoded in the body.
    EchoAuthorizationBase64,
    Lost,
    NotSent,
}

pub struct TransportState {
    pub mode: ReplyMode,
    pub lookup: LookupResult,
    /// Every request that reached the wire, with the authorization the vault attached.
    pub sent: Vec<(UpstreamRequest, Vec<u8>)>,
}

#[derive(Clone)]
pub struct FakeTransport(pub Arc<Mutex<TransportState>>);

impl FakeTransport {
    pub fn new(mode: ReplyMode) -> Self {
        Self(Arc::new(Mutex::new(TransportState {
            mode,
            lookup: LookupResult::Unknown,
            sent: Vec::new(),
        })))
    }

    pub fn set(&self, mode: ReplyMode) {
        lock(&self.0).mode = mode;
    }

    pub fn set_lookup(&self, lookup: LookupResult) {
        lock(&self.0).lookup = lookup;
    }

    pub fn sent(&self) -> Vec<(UpstreamRequest, Vec<u8>)> {
        lock(&self.0).sent.clone()
    }
}

pub fn reply(status: u16, headers: &[(&str, &str)], body: &str) -> UpstreamReply {
    UpstreamReply {
        status,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        body: body.as_bytes().to_vec(),
    }
}

impl UpstreamTransport for FakeTransport {
    fn exchange(&mut self, request: &AuthenticatedRequest<'_>) -> TransportResult {
        let mut state = lock(&self.0);
        let authorization = request.authorization_for_transport().to_vec();
        let echoed = String::from_utf8_lossy(&authorization).into_owned();
        let answer = match &state.mode {
            ReplyMode::NotSent => return TransportResult::NotSent,
            ReplyMode::Lost => None,
            ReplyMode::Fixed(reply) => Some(reply.clone()),
            ReplyMode::EchoAuthorizationHeader => Some(reply(
                200,
                &[("x-echo", echoed.as_str())],
                r#"{"output_text":"ok","finish_reason":"stop"}"#,
            )),
            ReplyMode::EchoAuthorizationBody => Some(reply(
                200,
                &[],
                &format!(r#"{{"output_text":"{echoed}","finish_reason":"stop"}}"#),
            )),
            ReplyMode::EchoAuthorizationBase64 => Some(reply(
                200,
                &[],
                &format!(
                    r#"{{"output_text":"{}","finish_reason":"stop"}}"#,
                    base64(&authorization)
                ),
            )),
        };
        state.sent.push((request.request().clone(), authorization));
        match answer {
            Some(answer) => TransportResult::Reply(answer),
            None => TransportResult::Lost,
        }
    }

    fn lookup(&mut self, _request: &AuthenticatedRequest<'_>) -> LookupResult {
        lock(&self.0).lookup.clone()
    }
}

#[derive(Clone, Default)]
pub struct MemoryPayloads(pub Arc<Mutex<BTreeMap<ContentKey, Vec<u8>>>>);

impl MemoryPayloads {
    pub fn put(&self, bytes: &[u8]) -> PayloadRef {
        let content = ContentKey::of(bytes);
        lock(&self.0).insert(content, bytes.to_vec());
        PayloadRef {
            content,
            length_bytes: bytes.len() as u64,
        }
    }

    pub fn overwrite(&self, content: ContentKey, bytes: &[u8]) {
        lock(&self.0).insert(content, bytes.to_vec());
    }
}

impl PayloadStore for MemoryPayloads {
    fn bytes(&self, content: &ContentKey) -> Option<Vec<u8>> {
        lock(&self.0).get(content).cloned()
    }
}

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

pub fn every_operation() -> BTreeSet<OperationKey> {
    [
        "open_pull_request",
        "generate_summary",
        "trigger_build",
        "upload_object",
        "star_repository",
        "add_label",
        "apply_labels",
        "raw_call",
    ]
    .iter()
    .map(|name| op_key(name))
    .collect()
}

pub fn vault_grant() -> VaultGrant {
    VaultGrant {
        credential: credential_ref(),
        class: SecretClass::LongLivedProviderCredential,
        executor: executor_identity().name,
        operations: every_operation(),
        routes: BTreeSet::from([forge_route_ref(), raw_route_ref()]),
        accounts: BTreeSet::from([account("org-a")]),
        clock: SESSION,
        expires_at: at(100 * HOUR),
    }
}

pub fn delegation() -> StandingDelegation {
    StandingDelegation {
        scope: DelegationScope {
            principal: tenant(),
            sandbox: sandbox(),
            executor: executor_identity().name,
            operations: every_operation(),
            routes: BTreeSet::from([forge_route_ref(), raw_route_ref()]),
            accounts: BTreeSet::from([account("org-a")]),
            max_cost_per_effect: CostCeiling {
                max_spend_microunits: u64::MAX / 4,
                max_volume_units: 100_000,
            },
            max_wire_bytes_per_effect: 128 * 1024 * 1024,
        },
        budget: DelegationBudget {
            max_effects: 1_000,
            max_spend_microunits: u64::MAX / 2,
        },
        policy: PolicyEpoch::FIRST,
        expires: Deadline {
            clock: SESSION,
            at: at(10 * HOUR),
        },
    }
}

/// A controller, its fakes, the provider catalog and a standing delegation.
pub struct World {
    pub clock: Arc<ManualClock>,
    pub authority: SharedAuthority,
    pub audit_store: MemoryAuditStore,
    pub store: MemoryStore,
    pub catalog: OperationCatalog,
    pub controller: TestController,
    pub vault: FakeVault,
    pub transport: FakeTransport,
    pub payloads: MemoryPayloads,
    pub spend: SharedSpendLedger,
    pub lease: LeaseId,
    pub delegation: DelegationId,
    next_key: u8,
}

pub const ACCOUNT_BUDGET_MICROUNITS: u64 = 5_000_000;

impl World {
    pub fn new() -> Self {
        Self::build(1024 * 1024, ACCOUNT_BUDGET_MICROUNITS)
    }

    pub fn build(provider_budget_bytes: u64, account_budget_microunits: u64) -> Self {
        let clock = Arc::new(ManualClock::new(START));
        let authority = SharedAuthority::default();
        authority.grant(&execution(), at(10 * HOUR));
        let lease = authority.issue_lease(&execution(), at(10 * HOUR));
        let audit_store = MemoryAuditStore::default();
        let store = MemoryStore::default();
        let catalog = catalog();
        let mut controller = EffectController::new(
            config(),
            clock.clone(),
            key(),
            authority.clone(),
            audit(clock.clone(), audit_store.clone()),
            store.clone(),
            catalog.contracts(),
            ReleaseLedger::new(release_policy(provider_budget_bytes)),
        )
        .unwrap();
        let delegation = controller.grant_delegation(delegation()).unwrap();
        let mut ledger = SpendLedger::new();
        ledger
            .open_account(account("org-a"), account_budget_microunits)
            .unwrap();
        Self {
            clock,
            authority,
            audit_store,
            store,
            catalog,
            controller,
            vault: FakeVault::new(vault_grant()),
            transport: FakeTransport::new(ReplyMode::Fixed(reply(
                200,
                &[("x-cost-microunits", "250")],
                r#"{"output_text":"a summary","finish_reason":"stop","debug":"internal"}"#,
            ))),
            payloads: MemoryPayloads::default(),
            spend: SharedSpendLedger::new(ledger),
            lease,
            delegation,
            next_key: 0,
        }
    }

    pub fn known() -> KnownSecrets {
        KnownSecrets::new()
            .with_fixture(VAULT_SECRET)
            .unwrap()
            .with_fixture(PLANTED_SECRET)
            .unwrap()
    }

    pub fn parts(
        &self,
        profile: ExposureProfile,
        passthrough: Option<Digest>,
    ) -> ExecutorParts<MemoryPayloads> {
        ExecutorParts {
            identity: executor_identity(),
            key: key(),
            session: SESSION,
            profile,
            passthrough_authorization: passthrough,
            vault: Box::new(self.vault.clone()),
            transport: Box::new(self.transport.clone()),
            payloads: self.payloads.clone(),
            records: Box::new(StoreRecords(self.store.clone())),
            authority: Box::new(self.authority.clone()),
            spend: self.spend.clone(),
            known: Self::known(),
        }
    }

    pub fn executor(&self, name: &str) -> ProviderExecutor<MemoryPayloads> {
        ProviderExecutor::new(
            &self.catalog,
            &op_key(name),
            self.parts(ExposureProfile::Strict, None),
        )
        .unwrap()
    }

    pub fn credential(&self) -> crate::sandbox_contract::effects::CredentialHandle {
        crate::sandbox_contract::effects::CredentialHandle::new(
            credential_ref(),
            crate::sandbox_contract::effects::ExternalCredential::LongLivedProvider,
        )
    }

    /// The fields of an effect for `name` with `parameters` and an optional payload,
    /// approved up to the contract's ceiling.
    pub fn fields(
        &mut self,
        name: &str,
        parameters: Parameters,
        payload: Option<&[u8]>,
    ) -> EffectFields {
        self.next_key = self.next_key.wrapping_add(1);
        let operation = self.catalog.get(&op_key(name)).unwrap();
        let contract = operation.contract();
        let payload = payload.map(|bytes| self.payloads.put(bytes));
        EffectFields {
            principal: tenant(),
            sandbox: sandbox(),
            operation: op_key(name),
            resource: ResourceRef {
                account: account("org-a"),
                object: digest("yougori/test/object/v1", &[name.as_bytes()]),
            },
            destination: Destination {
                route: operation.route_ref(),
                trust: TrustClass::RegisteredProvider,
            },
            parameters,
            payload,
            attachments: BTreeMap::new(),
            preconditions: BTreeSet::new(),
            max_cost: contract.max_cost,
            max_wire_bytes_out: 16 * 1024,
            deadline: Deadline {
                clock: SESSION,
                at: at(HOUR),
            },
            idempotency: Idempotency {
                key: IdempotencyKey::new(digest(
                    "yougori/test/idempotency/v1",
                    &[&[self.next_key]],
                )),
                requirement: if contract.provider_key {
                    IdempotencyRequirement::ProviderKey
                } else {
                    IdempotencyRequirement::NoExactlyOnce
                },
            },
        }
    }

    pub fn describe(
        &mut self,
        name: &str,
        parameters: Parameters,
        payload: Option<&[u8]>,
    ) -> EffectDescription {
        EffectDescription::new(self.fields(name, parameters, payload)).unwrap()
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

    /// Proposes, validates, authorizes and reserves, without the spend reservation.
    pub fn prepare_without_spend(
        &mut self,
        description: EffectDescription,
    ) -> Result<EffectId, EffectError> {
        let id = self.controller.propose(description)?;
        self.controller.validate(&id)?;
        let request = self.request();
        self.controller.authorize(&id, request)?;
        self.controller.reserve(&id)?;
        Ok(id)
    }

    /// The whole preparation, with the conservative spend reservation.
    pub fn prepare(&mut self, description: EffectDescription) -> EffectId {
        let payload = description
            .payload()
            .and_then(|reference| self.payloads.bytes(&reference.content));
        let cost = self
            .catalog
            .check_request(&description, payload.as_deref())
            .unwrap();
        let account = description.resource().account;
        let id = self.prepare_without_spend(description).unwrap();
        self.spend
            .with(|ledger| ledger.reserve(id, account, cost.max_spend_microunits))
            .unwrap();
        id
    }

    pub fn dispatch(
        &mut self,
        id: &EffectId,
        executor: &mut ProviderExecutor<MemoryPayloads>,
    ) -> DispatchOutcome {
        let credential = self.credential();
        self.controller.dispatch(id, executor, credential).unwrap()
    }

    pub fn audit_records(&self) -> Vec<AuditRecord> {
        lock(&self.audit_store.records).clone()
    }
}

pub fn summary_parameters(prompt: &str) -> Parameters {
    Parameters::new()
        .with(
            param("prompt"),
            crate::sandbox_contract::effects::CanonicalValue::Text(prompt.to_owned()),
        )
        .with(
            param("max_output_tokens"),
            crate::sandbox_contract::effects::CanonicalValue::Integer(1_000),
        )
}

pub fn text_value(value: &str) -> crate::sandbox_contract::effects::CanonicalValue {
    crate::sandbox_contract::effects::CanonicalValue::Text(value.to_owned())
}

pub fn pull_request_parameters(title: &str) -> Parameters {
    Parameters::new()
        .with(param("owner"), text_value("acme"))
        .with(param("repo"), text_value("widgets"))
        .with(param("title"), text_value(title))
        .with(param("head"), text_value("fix-parser"))
        .with(param("base"), text_value("main"))
}
