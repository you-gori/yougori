//! Contract tests for V07: operation families, the executor's independent checks, the
//! response policy, conservative spend and the claims (VM-W12, VM-W28; VM-P12,
//! VM-P30–VM-P33, VM-P40). Tier 0: every provider, vault and transport here is a fake,
//! so these tests prove the contract only.

use std::collections::{BTreeMap, BTreeSet};

use super::fakes::*;
use super::*;
use crate::foundation::ids::{digest, Clock, ContentKey, TenantId};
use crate::foundation::transfer::{CredentialRef, GeneralReleaseBudget};
use crate::sandbox_contract::destinations::{
    DecisionRef, HazardHandling, HttpMethod, OperationName as RouteOperationName, OperationRoute,
    OperationTls, PassThroughHazard, RedirectPolicy, RouteKind, TransportRoute,
};
use crate::sandbox_contract::effects::{
    CanonicalValue, ContractRefusal, CostCeiling, CredentialHandle, DeliveryGuarantee,
    EffectDescription, EffectError, EffectExecutor, EffectFailure, EffectFields, EffectPhase,
    ExecutorOutcome, ExecutorRefusal, ExposureProfile, ExternalCredential, IdempotencyKey,
    OperationName, Parameters, Precondition, RawParameters, RawValue, ResourceRef, ScalarKind,
    SecretClass, ShortLivedTerms, StateRefusal, TypedOperation,
};

fn raw_text(value: &str) -> RawValue {
    RawValue::Text(value.to_owned())
}

fn pull_request_reply() -> UpstreamReply {
    reply(
        201,
        &[],
        r#"{"number":7,"html_url":"https://forge.example/acme/widgets/pull/7"}"#,
    )
}

fn sealed(
    world: &World,
    id: &crate::sandbox_contract::effects::EffectId,
) -> crate::sandbox_contract::effects::SealedCapability {
    world
        .controller
        .record(id)
        .unwrap()
        .state()
        .capability()
        .unwrap()
        .clone()
}

fn spend_hold(world: &World, id: &crate::sandbox_contract::effects::EffectId) -> Option<SpendHold> {
    world.spend.snapshot().unwrap().hold(id).copied()
}

fn account_state(world: &World) -> SpendAccount {
    *world
        .spend
        .snapshot()
        .unwrap()
        .account(&account("org-a"))
        .unwrap()
}

fn label_member(label: &str) -> RawBatchMember {
    RawBatchMember {
        operation: Some(op_key("add_label")),
        parameters: RawParameters::new()
            .with("owner", raw_text("acme"))
            .with("repo", raw_text("widgets"))
            .with("label", raw_text(label)),
    }
}

fn batch_spec(catalog: &OperationCatalog) -> BatchSpec {
    match catalog.get(&op_key("apply_labels")).unwrap().family() {
        OperationFamily::Batch(spec) => spec.clone(),
        _ => unreachable!("apply_labels is a batch"),
    }
}

// --- Operation families as typed contracts (§4.6 line 2024) ---

#[test]
fn a_get_with_side_effects_and_a_post_that_only_reads_are_both_expressible() {
    let catalog = catalog();
    let trigger = catalog.get(&op_key("trigger_build")).unwrap();
    assert_eq!(trigger.method(), Some(HttpMethod::Get));
    assert_eq!(trigger.intent(), OperationIntent::SideEffecting);
    assert!(trigger.intent().changes_provider_state());
    let summary = catalog.get(&op_key("generate_summary")).unwrap();
    assert_eq!(summary.method(), Some(HttpMethod::Post));
    assert_eq!(summary.intent(), OperationIntent::ReadOnly);
    assert_eq!(summary.family(), &OperationFamily::Inference);
    // Intent is declared and must agree with the V02 route's effect class; the method
    // never decides it.
    let mut parts = trigger_build_parts();
    parts.intent = OperationIntent::ReadOnly;
    assert_eq!(
        ProviderOperation::new(draft(parts)),
        Err(OperationRefusal::IntentDisagreesWithRoute {
            intent: OperationIntent::ReadOnly
        })
    );
    let mut parts = generate_summary_parts();
    parts.intent = OperationIntent::SideEffecting;
    assert_eq!(
        ProviderOperation::new(draft(parts)),
        Err(OperationRefusal::IntentDisagreesWithRoute {
            intent: OperationIntent::SideEffecting
        })
    );
    // A bare HTTP verb never names an operation (effects' rule, reused).
    assert!(OperationName::new("POST").is_err());
    assert!(OperationName::new("get").is_err());
}

#[test]
fn bindings_that_do_not_fit_one_v02_operation_route_are_refused() {
    let refuse = |change: &dyn Fn(&mut OperationDraft)| {
        let mut d = draft(open_pull_request_parts());
        change(&mut d);
        ProviderOperation::new(d).unwrap_err()
    };
    let transport = TransportRoute::new(
        PassThroughHazard::ALL
            .iter()
            .map(|hazard| {
                let handling = if *hazard == PassThroughHazard::InTunnelProtocolChange {
                    HazardHandling::BroaderTransportGrant(DecisionRef::new(digest(
                        "yougori/test/decision/v1",
                        &[b"t"],
                    )))
                } else {
                    HazardHandling::Refuse
                };
                (*hazard, handling)
            })
            .collect(),
    )
    .unwrap();
    assert_eq!(
        refuse(&|d| d.binding.route = RouteKind::Transport(transport.clone())),
        OperationRefusal::TransportRouteCannotBind
    );
    assert_eq!(
        refuse(&|d| d.binding.spec = RouteOperationName::new("missing").unwrap()),
        OperationRefusal::SpecNotOnRoute {
            spec: RouteOperationName::new("missing").unwrap()
        }
    );
    let route = |tls, credential, redirects| {
        RouteKind::Operation(
            OperationRoute::new(tls, credential, forge_specs(), redirects, false).unwrap(),
        )
    };
    assert_eq!(
        refuse(&|d| d.binding.route = route(
            OperationTls::ConstructedByExecutor,
            Some(credential_ref()),
            RedirectPolicy::Reauthorize
        )),
        OperationRefusal::RedirectsMustBeDisabled
    );
    assert_eq!(
        refuse(&|d| d.binding.route = route(
            OperationTls::TerminatedAtExecutor,
            Some(credential_ref()),
            RedirectPolicy::Disabled
        )),
        OperationRefusal::TlsModeMismatch
    );
    assert_eq!(
        refuse(&|d| d.binding.route = route(
            OperationTls::ConstructedByExecutor,
            None,
            RedirectPolicy::Disabled
        )),
        OperationRefusal::RouteNotCredentialed
    );
    assert_eq!(
        refuse(&|d| {
            let spec = *d.contract.routes.values().next().unwrap();
            d.contract.routes.insert(raw_route_ref(), spec);
        }),
        OperationRefusal::ContractRouteMismatch
    );
    // "api.forge.example" takes 19 bytes in DNS: 4 + 6 + 8 + 1.
    assert_eq!(
        refuse(&|d| {
            for spec in d.contract.routes.values_mut() {
                spec.name_bytes = 4;
            }
        }),
        OperationRefusal::NameBytesUndercounted {
            declared_bytes: 4,
            required_bytes: 19
        }
    );
    assert_eq!(
        refuse(&|d| d.binding.path_params.clear()),
        OperationRefusal::PathParameterMismatch
    );
    assert_eq!(
        refuse(&|d| {
            d.contract
                .attachments
                .insert(crate::sandbox_contract::effects::AttachmentName::new("diagram").unwrap());
        }),
        OperationRefusal::AttachmentsUnsupported
    );
    assert_eq!(
        refuse(&|d| {
            d.contract.response_fields.insert(param("extra"));
        }),
        OperationRefusal::ResponseFieldsMismatch
    );
    assert_eq!(
        refuse(&|d| {
            d.response.profile = ResponseProfile::CredentialedPassthrough { max_body_bytes: 10 }
        }),
        OperationRefusal::ProfileMismatch
    );
    assert_eq!(
        refuse(&|d| d.credentials.clear()),
        OperationRefusal::NoCredentialClasses
    );
    assert_eq!(
        refuse(&|d| {
            d.credentials.insert(SecretClass::SandboxLocalSecret);
        }),
        OperationRefusal::CredentialClassNotExternal {
            class: SecretClass::SandboxLocalSecret
        }
    );
    assert_eq!(
        refuse(&|d| {
            d.cost.metered = Some(MeteredParam {
                param: param("title"),
                microunits_per_unit: 1,
            })
        }),
        OperationRefusal::Cost {
            refusal: CostRefusal::MeteredParamUnbounded {
                name: param("title")
            }
        }
    );
    assert_eq!(
        refuse(&|d| {
            d.cost.metered = Some(MeteredParam {
                param: param("nope"),
                microunits_per_unit: 1,
            })
        }),
        OperationRefusal::Cost {
            refusal: CostRefusal::MeteredParamUndeclared {
                name: param("nope")
            }
        }
    );
    // A GET cannot carry a body, and every query parameter must be on the route.
    let mut d = draft(trigger_build_parts());
    d.encoding = BodyEncoding::JsonParameters;
    assert_eq!(
        ProviderOperation::new(d),
        Err(OperationRefusal::EncodingMismatch {
            encoding: BodyEncoding::JsonParameters
        })
    );
    let mut d = draft(trigger_build_parts());
    d.contract.parameters.insert(
        param("branch"),
        crate::sandbox_contract::effects::ParamSpec {
            kind: text(10),
            required: false,
        },
    );
    assert_eq!(
        ProviderOperation::new(d),
        Err(OperationRefusal::QueryKeyNotOnRoute {
            name: param("branch")
        })
    );
    let mut d = draft(trigger_build_parts());
    d.binding.path_params = vec![param("owner"), param("note")];
    assert_eq!(
        ProviderOperation::new(d),
        Err(OperationRefusal::PathParameterNotRequiredText {
            name: param("note")
        })
    );
}

#[test]
fn a_graphql_document_with_more_than_one_operation_is_refused() {
    let two = format!("{GRAPHQL_DOCUMENT} query Leak {{ viewer {{ token }} }}");
    assert_eq!(
        GraphQlOperation::new(&two, "AddStar", GraphQlKind::Mutation),
        Err(GraphQlRefusal::NotExactlyOneOperation { operations: 2 })
    );
    let catalog = catalog();
    let star = catalog.get(&op_key("star_repository")).unwrap();
    assert_eq!(
        star.check_graphql_document(GRAPHQL_DOCUMENT, Some("AddStar")),
        Ok(())
    );
    assert_eq!(
        star.check_graphql_document(&two, Some("AddStar")),
        Err(OperationRefusal::GraphQl {
            refusal: GraphQlRefusal::NotExactlyOneOperation { operations: 2 }
        })
    );
    let other = GRAPHQL_DOCUMENT.replace("AddStar", "RemoveStar");
    assert_eq!(
        star.check_graphql_document(&other, None),
        Err(OperationRefusal::GraphQl {
            refusal: GraphQlRefusal::OperationMismatch
        })
    );
    assert_eq!(
        star.check_graphql_document(GRAPHQL_DOCUMENT, Some("RemoveStar")),
        Err(OperationRefusal::GraphQl {
            refusal: GraphQlRefusal::OperationMismatch
        })
    );
    // The registered bytes, exactly: a reformatted document is refused, not normalized.
    let reformatted = GRAPHQL_DOCUMENT.replace("{ addStar", "{\n  addStar");
    assert_eq!(
        star.check_graphql_document(&reformatted, Some("AddStar")),
        Err(OperationRefusal::GraphQl {
            refusal: GraphQlRefusal::DocumentMismatch
        })
    );
    assert_eq!(
        catalog
            .get(&op_key("generate_summary"))
            .unwrap()
            .check_graphql_document(GRAPHQL_DOCUMENT, None),
        Err(OperationRefusal::FamilyMismatch)
    );
    // A query registered as side-effecting, or a mutation as read-only, does not fit.
    let mut parts = star_repository_parts();
    parts.family = OperationFamily::GraphQl(
        GraphQlOperation::new(
            "query Viewer { viewer { login } }",
            "Viewer",
            GraphQlKind::Query,
        )
        .unwrap(),
    );
    assert_eq!(
        ProviderOperation::new(draft(parts)),
        Err(OperationRefusal::FamilyMismatch)
    );
}

#[test]
fn a_batch_with_an_untyped_member_is_refused() {
    let catalog = catalog();
    let spec = batch_spec(&catalog);
    let members = catalog.members_of(&op_key("apply_labels")).unwrap();
    let typed = |list: Vec<RawBatchMember>| {
        BatchDocument::from_raw(&RawBatch { members: list }, &spec, &members)
    };
    let document = typed(vec![label_member("bug"), label_member("p1")]).unwrap();
    assert_eq!(document.members().len(), 2);
    let mut untyped = label_member("bug");
    untyped.operation = None;
    assert_eq!(
        typed(vec![label_member("bug"), untyped]),
        Err(BatchRefusal::UntypedMember { index: 1 })
    );
    let mut foreign = label_member("bug");
    foreign.operation = Some(op_key("open_pull_request"));
    assert_eq!(
        typed(vec![foreign]),
        Err(BatchRefusal::MemberNotInBatch { index: 0 })
    );
    let mut extra = label_member("bug");
    extra.parameters = extra.parameters.with("color", raw_text("red"));
    assert_eq!(
        typed(vec![extra]),
        Err(BatchRefusal::MemberInvalid {
            index: 0,
            refusal: ContractRefusal::UnknownParameter {
                name: "color".to_owned()
            }
        })
    );
    assert_eq!(typed(vec![]), Err(BatchRefusal::Empty));
    assert_eq!(
        typed(vec![
            label_member("a"),
            label_member("b"),
            label_member("c"),
            label_member("d")
        ]),
        Err(BatchRefusal::TooManyMembers { max_members: 3 })
    );
    // The canonical bytes read back; anything else is refused.
    let bytes = document.canonical_bytes().unwrap();
    assert_eq!(
        BatchDocument::parse(&bytes, &spec, &members).unwrap(),
        document
    );
    let pretty = serde_json::to_vec_pretty(&document.members()).unwrap();
    assert_eq!(
        BatchDocument::parse(&pretty, &spec, &members),
        Err(BatchRefusal::NotCanonical)
    );
    // Member order is part of the payload, so of the effect identity.
    let reordered = typed(vec![label_member("p1"), label_member("bug")])
        .unwrap()
        .canonical_bytes()
        .unwrap();
    assert_ne!(ContentKey::of(&reordered), ContentKey::of(&bytes));
    // The catalog refuses a batch of batches, unknown members, and a read-only batch
    // with a side-effecting member.
    let mut nested = apply_labels_parts();
    nested.contract.name = "apply_more";
    nested.family = OperationFamily::Batch(BatchSpec {
        members: BTreeSet::from([op_key("apply_labels")]),
        max_members: 2,
    });
    let mut copy = catalog.clone();
    assert_eq!(
        copy.insert(ProviderOperation::new(draft(nested)).unwrap()),
        Err(OperationRefusal::BatchMemberNotTyped {
            member: op_key("apply_labels")
        })
    );
    let mut ghost = apply_labels_parts();
    ghost.contract.name = "apply_ghosts";
    ghost.family = OperationFamily::Batch(BatchSpec {
        members: BTreeSet::from([op_key("ghost")]),
        max_members: 2,
    });
    assert_eq!(
        copy.insert(ProviderOperation::new(draft(ghost)).unwrap()),
        Err(OperationRefusal::BatchMemberUnknown {
            member: op_key("ghost")
        })
    );
    let mut weak = apply_labels_parts();
    weak.contract.name = "read_batch";
    weak.intent = OperationIntent::ReadOnly;
    weak.spec = "generate_summary";
    assert_eq!(
        copy.insert(ProviderOperation::new(draft(weak)).unwrap()),
        Err(OperationRefusal::BatchIntentTooWeak)
    );
    assert_eq!(
        copy.insert(catalog.get(&op_key("add_label")).unwrap().clone()),
        Err(OperationRefusal::DuplicateOperation {
            operation: op_key("add_label")
        })
    );
}

#[test]
fn canonical_equivalents_bind_to_one_effect_and_any_change_to_another() {
    let catalog = catalog();
    let summary = catalog.get(&op_key("generate_summary")).unwrap();
    let a = RawParameters::new()
        .with("prompt", raw_text("hi"))
        .with("tags", RawValue::List(vec![raw_text("b"), raw_text("a")]))
        .with("max_output_tokens", RawValue::Integer(10));
    let b = RawParameters::from_json(r#"{"max_output_tokens":10,"tags":["a","b"],"prompt":"hi"}"#)
        .unwrap();
    let pa = summary.normalize_parameters(&a).unwrap();
    let pb = summary.normalize_parameters(&b).unwrap();
    assert_eq!(pa, pb);
    let mut world = World::new();
    let fields = world.fields("generate_summary", pa.clone(), None);
    let first = EffectDescription::new(fields.clone()).unwrap();
    let second = EffectDescription::new(EffectFields {
        parameters: pb,
        ..fields.clone()
    })
    .unwrap();
    assert_eq!(first.id(), second.id());
    let changed = summary
        .normalize_parameters(&a.clone().with("prompt", raw_text("hi!")))
        .unwrap();
    let third = EffectDescription::new(EffectFields {
        parameters: changed,
        ..fields
    })
    .unwrap();
    assert_ne!(first.id(), third.id());
    assert_eq!(
        summary.normalize_parameters(
            &a.with("tags", RawValue::List(vec![raw_text("a"), raw_text("a")]))
        ),
        Err(OperationRefusal::Contract {
            refusal: ContractRefusal::DuplicateItem {
                name: param("tags")
            }
        })
    );
}

#[test]
fn the_cost_model_is_conservative_with_worked_numbers() {
    let catalog = catalog();
    let summary = catalog.get(&op_key("generate_summary")).unwrap();
    let parameters = summary_parameters("hello");
    // {"max_output_tokens":{"integer":1000},"prompt":{"text":"hello"}} is 64 bytes.
    let request_bytes = ProviderOperation::request_bytes(&parameters, 0);
    assert_eq!(request_bytes, 64);
    // 100 fixed + 2 × 64 bytes + 30 × 1000 tokens = 30 228.
    let cost = summary
        .cost()
        .max_cost(summary.contract(), &parameters, request_bytes)
        .unwrap();
    assert_eq!(
        cost,
        CostCeiling {
            max_spend_microunits: 30_228,
            max_volume_units: 1_000
        }
    );
    // Without the metered parameter the declared maximum, 4096, is assumed:
    // {"prompt":{"text":"hello"}} is 27 bytes; 100 + 54 + 122 880 = 123 034.
    let bare = Parameters::new().with(param("prompt"), text_value("hello"));
    let bytes = ProviderOperation::request_bytes(&bare, 0);
    assert_eq!(bytes, 27);
    assert_eq!(
        summary
            .cost()
            .max_cost(summary.contract(), &bare, bytes)
            .unwrap()
            .max_spend_microunits,
        123_034
    );
    // A non-metered call counts one unit of volume.
    let pull = catalog.get(&op_key("open_pull_request")).unwrap();
    assert_eq!(
        pull.cost()
            .max_cost(pull.contract(), &pull_request_parameters("t"), 0)
            .unwrap(),
        CostCeiling {
            max_spend_microunits: 1_000,
            max_volume_units: 1
        }
    );
    let overflowing = CostModel {
        fixed_microunits: u64::MAX,
        microunits_per_request_byte: 1,
        metered: None,
    };
    assert_eq!(
        overflowing.max_cost(summary.contract(), &bare, 1),
        Err(CostRefusal::Overflow)
    );
    let negative = parameters
        .clone()
        .with(param("max_output_tokens"), CanonicalValue::Integer(-1));
    assert_eq!(
        summary.cost().max_cost(summary.contract(), &negative, 1),
        Err(CostRefusal::NegativeUnits {
            name: param("max_output_tokens")
        })
    );
    // The approved maximum must cover the model's maximum.
    let mut world = World::new();
    let mut fields = world.fields("generate_summary", parameters, None);
    fields.max_cost = CostCeiling {
        max_spend_microunits: 30_000,
        max_volume_units: 1_000,
    };
    let description = EffectDescription::new(fields).unwrap();
    assert_eq!(
        catalog.check_request(&description, None),
        Err(OperationRefusal::CostAboveDescription {
            model: CostCeiling {
                max_spend_microunits: 30_228,
                max_volume_units: 1_000
            },
            described: CostCeiling {
                max_spend_microunits: 30_000,
                max_volume_units: 1_000
            }
        })
    );
}

// --- The executor (§4.5 line 2004; VM-W12) ---

#[test]
fn a_typed_operation_commits_and_returns_only_the_permitted_representation() {
    let mut world = World::new();
    let mut executor = world.executor("generate_summary");
    let description = world.describe(
        "generate_summary",
        summary_parameters("summarize the diff"),
        None,
    );
    let reserved = world
        .catalog
        .check_request(&description, None)
        .unwrap()
        .max_spend_microunits;
    let id = world.prepare(description.clone());
    let outcome = world.dispatch(&id, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::Confirmed);
    let response = outcome.response.clone().unwrap();
    assert_eq!(response.get("output_text"), Some("a summary"));
    assert_eq!(response.get("finish_reason"), Some("stop"));
    assert_eq!(response.get("debug"), None);
    assert_eq!(response.len(), 2);
    let receipt = outcome.receipt.unwrap();
    assert_eq!(receipt.provider_result.spend_microunits, 250);
    let execution = executor.last_execution().unwrap().clone();
    assert_eq!(
        execution.outcome,
        ExecutionOutcome::Committed {
            representation: receipt.provider_result.result,
            reported_spend_microunits: Some(250)
        }
    );
    // Settled to the provider-reported cost; the rest of the reservation returned.
    let spend = execution.spend.unwrap();
    assert_eq!(spend.charged_microunits, 250);
    assert_eq!(spend.returned_microunits, reserved - 250);
    let account = account_state(&world);
    assert_eq!(
        (account.spent_microunits, account.reserved_microunits),
        (250, 0)
    );
    // The vault attached the credential on the way to the transport; the request the
    // executor built never held it.
    let sent = world.transport.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].1, bearer());
    assert!(!sent[0].0.headers.contains_key("authorization"));
    assert!(!leaks(format!("{:?}", sent[0].0).as_bytes()));
    assert!(execution.sent_bytes.unwrap() <= outcome.sent.unwrap().total_bytes());
}

#[test]
fn the_executor_builds_the_upstream_request_from_the_description_alone() {
    let mut world = World::new();
    world.transport.set(ReplyMode::Fixed(pull_request_reply()));
    let mut executor = world.executor("open_pull_request");
    let description = world.describe(
        "open_pull_request",
        pull_request_parameters("Fix parser"),
        None,
    );
    let id = world.prepare(description.clone());
    let outcome = world.dispatch(&id, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::Confirmed);
    assert_eq!(outcome.response.unwrap().get("number"), Some("7"));
    let (request, _) = world.transport.sent().remove(0);
    assert_eq!(request.method, HttpMethod::Post);
    assert_eq!(request.target, "/repos/acme/widgets/pulls");
    assert_eq!(
        String::from_utf8(request.body.clone()).unwrap(),
        r#"{"base":"main","head":"fix-parser","title":"Fix parser"}"#
    );
    assert_eq!(
        request.headers.get("idempotency-key"),
        Some(&description.idempotency().key.digest().to_hex())
    );
    assert_eq!(
        request,
        executor
            .upstream_request(&description, credential_ref(), world.clock.now())
            .unwrap()
    );
    // A GET with side effects carries its parameters in the query and no body.
    let build = world.describe(
        "trigger_build",
        Parameters::new()
            .with(param("owner"), text_value("acme"))
            .with(param("repo"), text_value("widgets"))
            .with(param("ref"), text_value("main"))
            .with(param("note"), text_value("fix it")),
        None,
    );
    let request = world
        .executor("trigger_build")
        .upstream_request(&build, credential_ref(), world.clock.now())
        .unwrap();
    assert_eq!(request.method, HttpMethod::Get);
    assert_eq!(
        request.target,
        "/repos/acme/widgets/dispatch?note=fix%20it&ref=main"
    );
    assert!(request.body.is_empty());
    assert!(!request.headers.contains_key("content-type"));
    // A path value that is not one plain segment is refused.
    let traversal = world.describe(
        "trigger_build",
        Parameters::new()
            .with(param("owner"), text_value(".."))
            .with(param("repo"), text_value("widgets"))
            .with(param("ref"), text_value("main")),
        None,
    );
    assert_eq!(
        world.executor("trigger_build").upstream_request(
            &traversal,
            credential_ref(),
            world.clock.now()
        ),
        Err(ProviderRefusal::Build {
            refusal: RequestRefusal::PathParameterInvalid {
                name: param("owner")
            }
        })
    );
}

fn run_with(
    mode: ReplyMode,
) -> (
    World,
    ProviderExecutor<MemoryPayloads>,
    crate::sandbox_contract::effects::EffectId,
    crate::sandbox_contract::effects::DispatchOutcome,
) {
    let mut world = World::new();
    world.transport.set(mode);
    let mut executor = world.executor("generate_summary");
    let description = world.describe("generate_summary", summary_parameters("hello"), None);
    let id = world.prepare(description);
    let outcome = world.dispatch(&id, &mut executor);
    (world, executor, id, outcome)
}

#[test]
fn responses_reflecting_a_credential_or_fixture_secret_are_refused_and_redacted() {
    let ok_body = r#"{"output_text":"ok","finish_reason":"stop"}"#;
    let planted = String::from_utf8(PLANTED_SECRET.to_vec()).unwrap();
    let modes = vec![
        ReplyMode::EchoAuthorizationHeader,
        ReplyMode::EchoAuthorizationBody,
        ReplyMode::EchoAuthorizationBase64,
        ReplyMode::Fixed(reply(
            200,
            &[],
            &format!(r#"{{"output_text":"token {planted}","finish_reason":"stop"}}"#),
        )),
        // A reflection outside the schema fields is refused too: the whole body is scanned.
        ReplyMode::Fixed(reply(
            200,
            &[],
            &format!(r#"{{"output_text":"ok","finish_reason":"stop","echo":"{planted}"}}"#),
        )),
        ReplyMode::Fixed(reply(200, &[("Authorization", "x")], ok_body)),
        ReplyMode::Fixed(reply(403, &[("x-debug", planted.as_str())], "{}")),
    ];
    for mode in modes {
        let (world, executor, id, outcome) = run_with(mode.clone());
        assert_eq!(outcome.phase, EffectPhase::OutcomeUnknown, "{mode:?}");
        assert!(outcome.response.is_none());
        let execution = executor.last_execution().unwrap().clone();
        let ExecutionOutcome::Unknown {
            reason:
                UnknownReason::ResponseRefused {
                    refusal: ResponseRefusal::Leak { report },
                },
        } = &execution.outcome
        else {
            panic!("{mode:?}: {:?}", execution.outcome);
        };
        assert!(!report.is_clean());
        // The untrusted response leaves the outcome unknown and fully spent.
        assert_eq!(
            spend_hold(&world, &id).unwrap().state,
            SpendHoldState::Unknown
        );
        for text in [
            serde_json::to_string(&execution).unwrap(),
            format!("{execution:?}"),
            execution.to_string(),
            format!("{outcome:?}"),
        ] {
            assert!(!leaks(text.as_bytes()), "{mode:?}: {text}");
        }
    }
}

#[test]
fn fixture_credentials_never_appear_in_guest_visible_parts_or_records() {
    // VM-P12. The scan below covers the encodings in SCAN_COVERAGE only; it cannot see
    // copies outside these values, and no guest launch exists at Tier 0.
    assert!(SCAN_COVERAGE.contains("does not detect"));
    let (world, executor, _, committed) = run_with(ReplyMode::EchoAuthorizationBody);
    let mut texts = vec![
        format!("{committed:?}"),
        serde_json::to_string(executor.last_execution().unwrap()).unwrap(),
        format!("{:?}", executor.last_execution()),
        serde_json::to_string(&world.credential()).unwrap(),
        format!("{:?}", world.credential()),
        format!("{:?}", World::known()),
        format!("{:?}", world.vault),
        format!("{:?}", SecretValue::new(bearer())),
        format!("{:?}", world.audit_records()),
        format!("{:?}", world.controller.uncertain_outcomes()),
    ];
    texts.extend(lock(&world.store.json).iter().cloned());
    let (_, _, _, fine) = run_with(ReplyMode::Fixed(reply(
        200,
        &[],
        r#"{"output_text":"a summary","finish_reason":"stop"}"#,
    )));
    texts.push(format!("{fine:?}"));
    texts.push(serde_json::to_string(&fine.response).unwrap());
    // A refusal's Display and its serialized form.
    let refusal = ProviderRefusal::RequestCarriesSecret {
        finding: LeakFinding {
            location: LeakLocation::RequestBody,
            source: LeakSource::VaultCredential,
            encoding: ScanEncoding::Verbatim,
        },
    };
    texts.push(refusal.to_string());
    texts.push(serde_json::to_string(&refusal).unwrap());
    for text in texts {
        assert!(!leaks(text.as_bytes()), "{text}");
    }
    // The transport did receive it: the scan would have caught it had it leaked.
    assert!(world
        .transport
        .sent()
        .iter()
        .all(|(_, authorization)| leaks(authorization)));
}

#[test]
fn a_request_that_would_carry_a_secret_is_refused_before_sending() {
    let mut world = World::new();
    let mut executor = world.executor("generate_summary");
    let prompt = format!(
        "post this: {}",
        String::from_utf8(VAULT_SECRET.to_vec()).unwrap()
    );
    let description = world.describe("generate_summary", summary_parameters(&prompt), None);
    let id = world.prepare(description);
    let outcome = world.dispatch(&id, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::Failed);
    assert!(world.transport.sent().is_empty());
    assert!(matches!(
        executor.last_execution().unwrap().outcome,
        ExecutionOutcome::Refused {
            refusal: ProviderRefusal::RequestCarriesSecret { .. }
        }
    ));
}

#[test]
fn a_modified_effect_field_after_approval_fails() {
    let mut world = World::new();
    world.transport.set(ReplyMode::Fixed(pull_request_reply()));
    let mut executor = world.executor("open_pull_request");
    let description = world.describe(
        "open_pull_request",
        pull_request_parameters("Fix parser"),
        None,
    );
    let id = world.prepare(description.clone());
    let capability = sealed(&world, &id);
    let fields = description.fields().clone();
    let mutations: Vec<(&str, EffectFields)> = vec![
        (
            "parameters",
            EffectFields {
                parameters: pull_request_parameters("Delete everything"),
                ..fields.clone()
            },
        ),
        (
            "object",
            EffectFields {
                resource: ResourceRef {
                    object: digest("yougori/test/object/v1", &[b"other"]),
                    ..fields.resource
                },
                ..fields.clone()
            },
        ),
        (
            "account",
            EffectFields {
                resource: ResourceRef {
                    account: account("org-b"),
                    ..fields.resource
                },
                ..fields.clone()
            },
        ),
        (
            "max cost",
            EffectFields {
                max_cost: CostCeiling {
                    max_spend_microunits: 9_999,
                    max_volume_units: 5,
                },
                ..fields.clone()
            },
        ),
        (
            "wire bytes",
            EffectFields {
                max_wire_bytes_out: fields.max_wire_bytes_out + 1,
                ..fields.clone()
            },
        ),
        (
            "idempotency",
            EffectFields {
                idempotency: crate::sandbox_contract::effects::Idempotency {
                    key: IdempotencyKey::new(digest("yougori/test/idempotency/v1", &[b"x"])),
                    ..fields.idempotency
                },
                ..fields.clone()
            },
        ),
        (
            "preconditions",
            EffectFields {
                preconditions: BTreeSet::from([Precondition::Absent]),
                ..fields.clone()
            },
        ),
        (
            "principal",
            EffectFields {
                principal: TenantId::new("tenant-b").unwrap(),
                ..fields.clone()
            },
        ),
    ];
    for (field, mutated) in mutations {
        let mutated = EffectDescription::new(mutated).unwrap();
        assert_ne!(mutated.id(), description.id(), "{field}");
        let report = executor.execute(
            TypedOperation {
                description: &mutated,
                capability: &capability,
                credential: world.credential(),
            },
            world.clock.now(),
        );
        assert_eq!(report.sent, None, "{field}");
        assert!(
            matches!(
                executor.last_execution().unwrap().outcome,
                ExecutionOutcome::Refused { .. }
            ),
            "{field}"
        );
    }
    // A capability changed after sealing is not the one the record holds.
    let mut json = serde_json::to_value(&capability).unwrap();
    json["capability"]["max_cost"]["max_spend_microunits"] = serde_json::json!(1);
    let forged = serde_json::from_value(json).unwrap();
    let report = executor.execute(
        TypedOperation {
            description: &description,
            capability: &forged,
            credential: world.credential(),
        },
        world.clock.now(),
    );
    assert_eq!(report.sent, None);
    assert_eq!(
        executor.last_execution().unwrap().outcome,
        ExecutionOutcome::Refused {
            refusal: ProviderRefusal::RecordMismatch
        }
    );
    assert!(world.transport.sent().is_empty());
    // The approved effect itself still proceeds, exactly once.
    let outcome = world.dispatch(&id, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::Confirmed);
    assert_eq!(world.transport.sent().len(), 1);
}

#[test]
fn concurrent_overspend_fails() {
    // Each call may cost 30 228 microunits; the account holds 50 000.
    let mut world = World::build(1024 * 1024, 50_000);
    let first = world.describe("generate_summary", summary_parameters("hello"), None);
    let second = world.describe("generate_summary", summary_parameters("hello"), None);
    let cost = world
        .catalog
        .check_request(&first, None)
        .unwrap()
        .max_spend_microunits;
    assert_eq!(cost, 30_228);
    let a = world.prepare_without_spend(first).unwrap();
    let b = world.prepare_without_spend(second).unwrap();
    // Both reserve at once; only one fits in the remaining budget.
    let handles: Vec<_> = [a, b]
        .into_iter()
        .map(|id| {
            let spend = world.spend.clone();
            std::thread::spawn(move || {
                spend.with(|ledger| ledger.reserve(id, account("org-a"), cost))
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results.iter().any(|result| matches!(
        result,
        Err(SpendRefusal::Exhausted {
            requested_microunits: 30_228,
            available_microunits: 19_772
        })
    )));
    let (winner, loser) = if spend_hold(&world, &a).is_some() {
        (a, b)
    } else {
        (b, a)
    };
    // The one without a reservation is refused before anything is sent.
    let mut executor = world.executor("generate_summary");
    let outcome = world.dispatch(&loser, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::Failed);
    assert!(world.transport.sent().is_empty());
    assert_eq!(
        executor.last_execution().unwrap().outcome,
        ExecutionOutcome::Refused {
            refusal: ProviderRefusal::Spend {
                refusal: SpendRefusal::NotHeld
            }
        }
    );
    assert_eq!(
        outcome.failure,
        Some(EffectFailure::Executor {
            refusal: ExecutorRefusal::NotSent {
                detail: "spend:not_held".to_owned()
            }
        })
    );
    let outcome = world.dispatch(&winner, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::Confirmed);
    assert_eq!(world.spend.snapshot().unwrap().invariant_violation(), None);
}

#[test]
fn partial_success_and_lost_responses_end_outcome_unknown() {
    // VM-P31: a lost response.
    let (mut world, mut executor, id, outcome) = run_with(ReplyMode::Lost);
    assert_eq!(outcome.phase, EffectPhase::OutcomeUnknown);
    assert_eq!(
        executor.last_execution().unwrap().outcome,
        ExecutionOutcome::Unknown {
            reason: UnknownReason::ResponseLost
        }
    );
    let held = spend_hold(&world, &id).unwrap();
    assert_eq!(held.state, SpendHoldState::Unknown);
    assert_eq!(
        account_state(&world).unknown_microunits,
        held.reserved_microunits
    );
    // No retry, and no promise of exactly-once delivery.
    assert_eq!(
        world.controller.retry(&id),
        Err(EffectError::State(StateRefusal::NeedsReconciliation))
    );
    let reports = world.controller.uncertain_outcomes();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].delivery, DeliveryGuarantee::NoExactlyOnce);
    assert!(reports[0]
        .message()
        .contains("the provider cannot deduplicate a retry"));
    // Reconciliation through the provider settles both the effect and the spend.
    world.transport.set_lookup(LookupResult::Committed(reply(
        200,
        &[("x-cost-microunits", "300")],
        r#"{"output_text":"late","finish_reason":"stop"}"#,
    )));
    let credential = world.credential();
    let reconciled = world
        .controller
        .reconcile(&id, &mut executor, credential)
        .unwrap();
    assert_eq!(reconciled.phase, EffectPhase::Confirmed);
    assert_eq!(spend_hold(&world, &id), None);
    let account = account_state(&world);
    assert_eq!(
        (account.spent_microunits, account.unknown_microunits),
        (300, 0)
    );

    // Partial success, then reconciled as not committed: the spend returns.
    let (mut world, mut executor, id, outcome) = run_with(ReplyMode::Fixed(reply(
        207,
        &[("x-cost-microunits", "5")],
        "{}",
    )));
    assert_eq!(outcome.phase, EffectPhase::OutcomeUnknown);
    assert_eq!(
        executor.last_execution().unwrap().outcome,
        ExecutionOutcome::Unknown {
            reason: UnknownReason::PartialSuccess
        }
    );
    world.transport.set_lookup(LookupResult::NotCommitted);
    let credential = world.credential();
    let reconciled = world
        .controller
        .reconcile(&id, &mut executor, credential)
        .unwrap();
    assert_eq!(reconciled.phase, EffectPhase::Failed);
    let account = account_state(&world);
    assert_eq!(
        (account.spent_microunits, account.unknown_microunits),
        (0, 0)
    );

    // A server error leaves the outcome unknown as well.
    let (_, executor, _, outcome) = run_with(ReplyMode::Fixed(reply(500, &[], "oops")));
    assert_eq!(outcome.phase, EffectPhase::OutcomeUnknown);
    assert_eq!(
        executor.last_execution().unwrap().outcome,
        ExecutionOutcome::Unknown {
            reason: UnknownReason::ResponseRefused {
                refusal: ResponseRefusal::ServerError { status: 500 }
            }
        }
    );
    // A response that fails its schema leaves it unknown, never "helpfully" accepted.
    let (_, executor, _, outcome) = run_with(ReplyMode::Fixed(reply(
        200,
        &[],
        r#"{"output_text":"no reason given"}"#,
    )));
    assert_eq!(outcome.phase, EffectPhase::OutcomeUnknown);
    assert_eq!(
        executor.last_execution().unwrap().outcome,
        ExecutionOutcome::Unknown {
            reason: UnknownReason::ResponseRefused {
                refusal: ResponseRefusal::MissingField {
                    name: param("finish_reason")
                }
            }
        }
    );
}

#[test]
fn expiry_and_revocation_during_buffering_refuse() {
    // The capability expires while the request waits: the controller refuses at the
    // dispatch boundary, and the executor refuses on its own when called directly.
    let mut world = World::new();
    let mut executor = world.executor("generate_summary");
    let description = world.describe("generate_summary", summary_parameters("a"), None);
    let id = world.prepare(description.clone());
    let direct = world.describe("generate_summary", summary_parameters("b"), None);
    let direct_id = world.prepare(direct.clone());
    world.clock.advance(61 * SECOND);
    let outcome = world.dispatch(&id, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::Failed);
    assert!(matches!(
        outcome.failure,
        Some(EffectFailure::Capability { .. })
    ));
    // The host returns the unused reservation (VM-P32: recovers safely).
    assert!(world.spend.with(|ledger| ledger.release(&id)).is_ok());
    let report = executor.execute(
        TypedOperation {
            description: &direct,
            capability: &sealed(&world, &direct_id),
            credential: world.credential(),
        },
        world.clock.now(),
    );
    assert!(matches!(
        report.outcome,
        ExecutorOutcome::Refused(ExecutorRefusal::Capability { .. })
    ));
    assert_eq!(report.sent, None);
    // Refused before the reservation was consumed: it waits for the host to return it.
    assert_eq!(
        spend_hold(&world, &direct_id).unwrap().state,
        SpendHoldState::Reserved
    );
    assert!(world.transport.sent().is_empty());

    // A revocation while buffered (VM-P40).
    let mut world = World::new();
    let mut executor = world.executor("generate_summary");
    let description = world.describe("generate_summary", summary_parameters("a"), None);
    let id = world.prepare(description.clone());
    world.authority.revoke(&execution());
    let report = executor.execute(
        TypedOperation {
            description: &description,
            capability: &sealed(&world, &id),
            credential: world.credential(),
        },
        world.clock.now(),
    );
    assert_eq!(report.sent, None);
    assert_eq!(
        executor.last_execution().unwrap().outcome,
        ExecutionOutcome::Refused {
            refusal: ProviderRefusal::NoAuthority
        }
    );
    let outcome = world.dispatch(&id, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::Failed);
    assert!(world.transport.sent().is_empty());

    // The delegation is revoked while buffered.
    let mut world = World::new();
    let mut executor = world.executor("generate_summary");
    let description = world.describe("generate_summary", summary_parameters("a"), None);
    let id = world.prepare(description.clone());
    let delegation = world.delegation;
    world.controller.revoke_delegation(&delegation).unwrap();
    let report = executor.execute(
        TypedOperation {
            description: &description,
            capability: &sealed(&world, &id),
            credential: world.credential(),
        },
        world.clock.now(),
    );
    assert_eq!(report.sent, None);
    assert_eq!(
        executor.last_execution().unwrap().outcome,
        ExecutionOutcome::Refused {
            refusal: ProviderRefusal::Delegation {
                violation: crate::sandbox_contract::effects::ScopeViolation::Revoked
            }
        }
    );

    // The vault grant is revoked while buffered.
    let mut world = World::new();
    let mut executor = world.executor("generate_summary");
    let description = world.describe("generate_summary", summary_parameters("a"), None);
    let id = world.prepare(description);
    lock(&world.vault.0)
        .grants
        .revoke(credential_ref(), world.clock.now());
    let outcome = world.dispatch(&id, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::Failed);
    assert_eq!(
        outcome.failure,
        Some(EffectFailure::Executor {
            refusal: ExecutorRefusal::NotSent {
                detail: "vault:revoked".to_owned()
            }
        })
    );
    assert_eq!(outcome.sent, None);
    assert_eq!(world.vault.sends(), 0);
    assert!(world.transport.sent().is_empty());

    // A short-lived credential expires while buffered.
    let mut world = World::new();
    let mut grant = vault_grant();
    grant.class = SecretClass::ShortLivedCapability;
    world.vault = FakeVault::new(grant);
    let mut executor = world.executor("generate_summary");
    let description = world.describe("generate_summary", summary_parameters("a"), None);
    let id = world.prepare(description);
    let handle = CredentialHandle::for_class(
        credential_ref(),
        SecretClass::ShortLivedCapability,
        ExternalCredential::ShortLived {
            terms: ShortLivedTerms {
                scope: digest("yougori/test/scope/v1", &[b"summaries"]),
                audience: forge_route_ref(),
                clock: SESSION,
                expires_at: at(30 * SECOND),
                delegated_budget: CostCeiling {
                    max_spend_microunits: 1_000_000,
                    max_volume_units: 10_000,
                },
            },
        },
    )
    .unwrap();
    world.clock.advance(31 * SECOND);
    let outcome = world
        .controller
        .dispatch(&id, &mut executor, handle)
        .unwrap();
    assert_eq!(outcome.phase, EffectPhase::Failed);
    assert!(matches!(
        outcome.failure,
        Some(EffectFailure::Executor {
            refusal: ExecutorRefusal::Credential { .. }
        })
    ));
    assert!(world.transport.sent().is_empty());
    assert_eq!(
        spend_hold(&world, &id).unwrap().state,
        SpendHoldState::Reserved
    );
}

#[test]
fn redirects_are_never_followed_and_a_failed_request_is_never_broadened() {
    let (world, executor, id, outcome) = run_with(ReplyMode::Fixed(reply(
        302,
        &[("location", "https://elsewhere.example/steal")],
        "",
    )));
    assert_eq!(outcome.phase, EffectPhase::Failed);
    assert!(matches!(
        outcome.failure,
        Some(EffectFailure::RedirectRefused { .. })
    ));
    assert_eq!(world.transport.sent().len(), 1);
    assert!(matches!(
        executor.last_execution().unwrap().outcome,
        ExecutionOutcome::RedirectRefused { .. }
    ));
    assert_eq!(spend_hold(&world, &id), None);
    assert_eq!(account_state(&world).spent_microunits, 0);

    // A rejection fails the effect; the retry sends exactly the approved request again.
    let (mut world, mut executor, id, outcome) = run_with(ReplyMode::Fixed(reply(
        403,
        &[("x-cost-microunits", "3")],
        "{}",
    )));
    assert_eq!(outcome.phase, EffectPhase::Failed);
    assert_eq!(
        outcome.failure,
        Some(EffectFailure::ProviderRejected {
            code: "http_403".to_owned()
        })
    );
    assert_eq!(account_state(&world).spent_microunits, 3);
    world.controller.retry(&id).unwrap();
    world.controller.validate(&id).unwrap();
    let request = world.request();
    world.controller.authorize(&id, request).unwrap();
    world.controller.reserve(&id).unwrap();
    let description = world.controller.record(&id).unwrap().description().clone();
    let cost = world.catalog.check_request(&description, None).unwrap();
    world
        .spend
        .with(|ledger| ledger.reserve(id, account("org-a"), cost.max_spend_microunits))
        .unwrap();
    world.transport.set(ReplyMode::Fixed(reply(
        200,
        &[],
        r#"{"output_text":"ok","finish_reason":"stop"}"#,
    )));
    let outcome = world.dispatch(&id, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::Confirmed);
    let sent = world.transport.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].0, sent[1].0);
    assert_eq!(executor.last_execution().unwrap().attempt, 2);
}

#[test]
fn executor_scope_cannot_widen() {
    let mut world = World::new();
    let mut summary = world.executor("generate_summary");
    let description = world.describe(
        "open_pull_request",
        pull_request_parameters("Fix parser"),
        None,
    );
    let id = world.prepare(description.clone());
    // An executor for one operation refuses another's effect.
    let report = summary.execute(
        TypedOperation {
            description: &description,
            capability: &sealed(&world, &id),
            credential: world.credential(),
        },
        world.clock.now(),
    );
    assert_eq!(
        report.outcome,
        ExecutorOutcome::Refused(ExecutorRefusal::Contract {
            refusal: ContractRefusal::OperationMismatch
        })
    );
    // A credential other than the route's, or of a class the operation does not
    // accept, is refused before the vault is asked.
    let mut pull = world.executor("open_pull_request");
    let other = CredentialHandle::new(
        CredentialRef::from_digest(digest("yougori/test/vault/v1", &[b"other-key"])),
        ExternalCredential::LongLivedProvider,
    );
    let report = pull.execute(
        TypedOperation {
            description: &description,
            capability: &sealed(&world, &id),
            credential: other,
        },
        world.clock.now(),
    );
    assert_eq!(report.sent, None);
    assert_eq!(
        pull.last_execution().unwrap().outcome,
        ExecutionOutcome::Refused {
            refusal: ProviderRefusal::CredentialNotRouteCredential
        }
    );
    let signed_url = CredentialHandle::new(
        credential_ref(),
        ExternalCredential::SignedDownloadUrl {
            audience: forge_route_ref(),
            clock: SESSION,
            expires_at: at(HOUR),
        },
    );
    pull.execute(
        TypedOperation {
            description: &description,
            capability: &sealed(&world, &id),
            credential: signed_url,
        },
        world.clock.now(),
    );
    assert_eq!(
        pull.last_execution().unwrap().outcome,
        ExecutionOutcome::Refused {
            refusal: ProviderRefusal::CredentialClassUnsupported {
                class: SecretClass::SignedDownloadUrl
            }
        }
    );
    // The vault grant can be narrowed, never widened; a narrowed grant refuses.
    let mut narrower = vault_grant();
    narrower.operations.remove(&op_key("open_pull_request"));
    lock(&world.vault.0).grants.grant(narrower.clone()).unwrap();
    let mut wider = narrower;
    wider.operations.insert(op_key("open_pull_request"));
    assert!(matches!(
        lock(&world.vault.0).grants.grant(wider),
        Err(VaultRefusal::WouldWiden { .. })
    ));
    let outcome = world.dispatch(&id, &mut pull);
    assert_eq!(outcome.phase, EffectPhase::Failed);
    assert_eq!(
        pull.last_execution().unwrap().outcome,
        ExecutionOutcome::Refused {
            refusal: ProviderRefusal::Vault {
                refusal: VaultRefusal::OperationNotGranted
            }
        }
    );
    assert!(world.transport.sent().is_empty());
}

#[test]
fn a_concurrent_duplicate_dispatch_is_refused() {
    let mut world = World::new();
    let mut executor = world.executor("generate_summary");
    let description = world.describe("generate_summary", summary_parameters("a"), None);
    let id = world.prepare(description.clone());
    let capability = sealed(&world, &id);
    let operation = TypedOperation {
        description: &description,
        capability: &capability,
        credential: world.credential(),
    };
    let first = executor.execute(operation, world.clock.now());
    assert!(matches!(first.outcome, ExecutorOutcome::Committed { .. }));
    let second = executor.execute(operation, world.clock.now());
    assert_eq!(second.sent, None);
    assert_eq!(
        executor.last_execution().unwrap().outcome,
        ExecutionOutcome::Refused {
            refusal: ProviderRefusal::Spend {
                refusal: SpendRefusal::NotHeld
            }
        }
    );
    // A second executor holding the same records cannot dispatch it either.
    let mut twin = world.executor("generate_summary");
    twin.execute(operation, world.clock.now());
    assert!(matches!(
        twin.last_execution().unwrap().outcome,
        ExecutionOutcome::Refused { .. }
    ));
    assert_eq!(world.transport.sent().len(), 1);
}

#[test]
fn every_wire_byte_counts_and_a_request_beyond_its_reservation_is_refused() {
    // VM-P33: the URL and headers count, not only the body. A note of 1 500 spaces is
    // 1 500 body bytes in the effects estimate but 4 500 bytes once percent-encoded in
    // the query.
    let mut world = World::new();
    let mut executor = world.executor("trigger_build");
    let description = world.describe(
        "trigger_build",
        Parameters::new()
            .with(param("owner"), text_value("acme"))
            .with(param("repo"), text_value("widgets"))
            .with(param("ref"), text_value("main"))
            .with(param("note"), text_value(&" ".repeat(1_500))),
        None,
    );
    let id = world.prepare(description);
    let outcome = world.dispatch(&id, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::Failed);
    assert!(matches!(
        outcome.failure,
        Some(EffectFailure::Executor {
            refusal: ExecutorRefusal::WireBytesAboveCeiling { .. }
        })
    ));
    assert!(world.transport.sent().is_empty());
    assert_eq!(world.controller.release_ledger().counted_bytes_out(), 0);
}

#[test]
fn money_spend_is_kept_apart_from_release_and_transfer_budgets() {
    // Line 57 and §2.5: provider money, wire bytes and transfer bytes are separate.
    let (world, _, _, outcome) = run_with(ReplyMode::Fixed(reply(
        200,
        &[("x-cost-microunits", "250")],
        r#"{"output_text":"ok","finish_reason":"stop"}"#,
    )));
    assert_eq!(outcome.phase, EffectPhase::Confirmed);
    let ledger = world.controller.release_ledger();
    assert_eq!(
        ledger.counted_bytes_out(),
        outcome.sent.unwrap().total_bytes()
    );
    assert_eq!(account_state(&world).spent_microunits, 250);
    assert_eq!(
        ledger.policy().general_budget_bytes(),
        GeneralReleaseBudget::vm_d12_default().limit_bytes()
    );
    assert_eq!(
        GeneralReleaseBudget::vm_d12_default().limit_bytes(),
        8 * 1024 * 1024
    );
    // Reserving money moves no byte counter.
    let before = (
        ledger.counted_bytes_out(),
        ledger.outstanding_reserved_bytes(),
    );
    let effect = crate::sandbox_contract::effects::EffectId::new(digest(
        "yougori/test/effect/v1",
        &[b"money"],
    ));
    world
        .spend
        .with(|spend| spend.reserve(effect, account("org-a"), 1_000_000))
        .unwrap();
    let ledger = world.controller.release_ledger();
    assert_eq!(
        (
            ledger.counted_bytes_out(),
            ledger.outstanding_reserved_bytes()
        ),
        before
    );
    // A 2 MiB upload fits the money budget (1 microunit per byte) but not the 1 MiB
    // provider-request byte budget: the two are refused independently.
    let mut world = World::new();
    let payload = vec![b'x'; 2 * 1024 * 1024];
    let mut fields = world.fields(
        "upload_object",
        Parameters::new().with(param("name"), text_value("weights.bin")),
        Some(&payload),
    );
    fields.max_wire_bytes_out = 3 * 1024 * 1024;
    let description = EffectDescription::new(fields).unwrap();
    let cost = world
        .catalog
        .check_request(&description, Some(&payload))
        .unwrap();
    assert!(cost.max_spend_microunits < ACCOUNT_BUDGET_MICROUNITS);
    assert!(matches!(
        world.prepare_without_spend(description),
        Err(EffectError::Refused {
            failure: EffectFailure::Release { .. }
        })
    ));
    // And money can run out while bytes remain.
    let mut world = World::build(1024 * 1024, 100);
    let description = world.describe("generate_summary", summary_parameters("a"), None);
    let id = world.prepare_without_spend(description).unwrap();
    assert!(matches!(
        world
            .spend
            .with(|spend| spend.reserve(id, account("org-a"), 30_228)),
        Err(SpendRefusal::Exhausted { .. })
    ));
}

#[test]
fn a_credentialed_passthrough_is_weaker_and_never_zero_exposure() {
    let world = World::new();
    let raw = world.catalog.get(&op_key("raw_call")).unwrap();
    assert_eq!(raw.claim(), CredentialClaim::WeakerPassthrough);
    assert_eq!(
        raw.claim().zero_exposure_label(),
        Err(ClaimRefusal::PassthroughIsNeverZeroExposure)
    );
    assert!(!raw.claim().allowed_in(ExposureProfile::Strict));
    let typed = world.catalog.get(&op_key("generate_summary")).unwrap();
    assert_eq!(typed.claim(), CredentialClaim::NotDeliveredToGuest);
    assert!(typed.claim().zero_exposure_label().is_ok());
    assert_eq!(
        ProviderExecutor::new(
            &world.catalog,
            &op_key("raw_call"),
            world.parts(ExposureProfile::Strict, None)
        )
        .err(),
        Some(OperationRefusal::PassthroughRefusedInStrictProfile)
    );
    assert_eq!(
        ProviderExecutor::new(
            &world.catalog,
            &op_key("raw_call"),
            world.parts(ExposureProfile::Standard, None)
        )
        .err(),
        Some(OperationRefusal::PassthroughNeedsSeparateAuthorization)
    );
    let mut world = World::new();
    let mut executor = ProviderExecutor::new(
        &world.catalog,
        &op_key("raw_call"),
        world.parts(
            ExposureProfile::Standard,
            Some(digest("yougori/test/decision/v1", &[b"weaker profile"])),
        ),
    )
    .unwrap();
    assert_eq!(executor.claim(), CredentialClaim::WeakerPassthrough);
    world
        .transport
        .set(ReplyMode::Fixed(reply(200, &[], "raw provider text")));
    let description = world.describe(
        "raw_call",
        Parameters::new().with(param("body_text"), text_value("hello")),
        None,
    );
    let id = world.prepare(description);
    let outcome = world.dispatch(&id, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::Confirmed);
    assert_eq!(
        outcome.response.unwrap().get(PASSTHROUGH_BODY_FIELD),
        Some("raw provider text")
    );
    // The scan still applies to the weaker profile.
    world.transport.set(ReplyMode::EchoAuthorizationBody);
    let description = world.describe(
        "raw_call",
        Parameters::new().with(param("body_text"), text_value("again")),
        None,
    );
    let id = world.prepare(description);
    let outcome = world.dispatch(&id, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::OutcomeUnknown);
    assert!(outcome.response.is_none());
}

#[test]
fn batches_and_graphql_execute_as_typed_operations() {
    let mut world = World::new();
    let spec = batch_spec(&world.catalog);
    let members = world.catalog.members_of(&op_key("apply_labels")).unwrap();
    let bytes = BatchDocument::from_raw(
        &RawBatch {
            members: vec![label_member("bug"), label_member("p1")],
        },
        &spec,
        &members,
    )
    .unwrap()
    .canonical_bytes()
    .unwrap();
    let description = world.describe("apply_labels", Parameters::new(), Some(&bytes));
    // 10 for the batch and 200 for each typed member; one unit of volume each.
    assert_eq!(
        world.catalog.check_request(&description, Some(&bytes)),
        Ok(CostCeiling {
            max_spend_microunits: 410,
            max_volume_units: 3
        })
    );
    let mut executor = world.executor("apply_labels");
    world
        .transport
        .set(ReplyMode::Fixed(reply(200, &[], r#"{"applied":2}"#)));
    let id = world.prepare(description.clone());
    let outcome = world.dispatch(&id, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::Confirmed);
    let (request, _) = world.transport.sent().remove(0);
    assert_eq!(request.target, "/batch");
    assert_eq!(request.body, bytes);
    // Bytes swapped in the store after approval are refused before sending.
    let second = world.describe("apply_labels", Parameters::new(), Some(&bytes[..]));
    let second_id = world.prepare(second.clone());
    let swapped = BatchDocument::from_raw(
        &RawBatch {
            members: vec![label_member("wontfix")],
        },
        &spec,
        &members,
    )
    .unwrap()
    .canonical_bytes()
    .unwrap();
    world
        .payloads
        .overwrite(second.payload().unwrap().content, &swapped);
    let outcome = world.dispatch(&second_id, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::Failed);
    assert_eq!(world.transport.sent().len(), 1);

    // GraphQL: the registered document, the variables from the parameters.
    let mut world = World::new();
    let mut executor = world.executor("star_repository");
    world.transport.set(ReplyMode::Fixed(reply(
        200,
        &[],
        r#"{"client_mutation_id":"m1"}"#,
    )));
    let description = world.describe(
        "star_repository",
        Parameters::new().with(param("id"), text_value("R_1")),
        None,
    );
    let id = world.prepare(description);
    let outcome = world.dispatch(&id, &mut executor);
    assert_eq!(outcome.phase, EffectPhase::Confirmed);
    let (request, _) = world.transport.sent().remove(0);
    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "operationName": "AddStar",
            "query": GRAPHQL_DOCUMENT,
            "variables": {"id": "R_1"}
        })
    );
}

#[test]
fn records_round_trip_strictly() {
    let (_, executor, _, _) = run_with(ReplyMode::EchoAuthorizationHeader);
    let execution = executor.last_execution().unwrap().clone();
    let json = serde_json::to_string(&execution).unwrap();
    assert_eq!(
        serde_json::from_str::<ProviderExecution>(&json).unwrap(),
        execution
    );
    for text in [
        r#"{"outcome":"not_sent","extra":1}"#,
        r#"{"outcome":"precondition_failed","x":true}"#,
    ] {
        assert!(serde_json::from_str::<ExecutionOutcome>(text).is_err());
    }
    assert!(serde_json::from_str::<ProviderRefusal>(r#"{"reason":"no_record","x":1}"#).is_err());
    assert!(serde_json::from_str::<CredentialClaim>(
        r#"{"claim":"weaker_passthrough","zero_exposure":true}"#
    )
    .is_err());
    let policy: ResponsePolicy = serde_json::from_str(
        r#"{"profile":{"profile":"credentialed_passthrough","max_body_bytes":5},"cost_report":{"report":"not_reported"}}"#,
    )
    .unwrap();
    assert_eq!(policy.cost_report, CostReport::NotReported);
    assert!(serde_json::from_str::<CostReport>(r#"{"report":"not_reported","name":"x"}"#).is_err());
    // Map keys of the verdict's schema are declared names.
    let schema = ResponseSchema {
        fields: BTreeMap::from([(
            param("ok"),
            FieldSchema {
                kind: ScalarKind::Bool,
                required: true,
            },
        )]),
        max_body_bytes: 10,
    };
    let json = serde_json::to_string(&schema).unwrap();
    assert_eq!(
        serde_json::from_str::<ResponseSchema>(&json).unwrap(),
        schema
    );
}

#[test]
fn a_request_that_never_left_fails_and_returns_everything() {
    let (world, executor, id, outcome) = run_with(ReplyMode::NotSent);
    assert_eq!(outcome.phase, EffectPhase::Failed);
    assert_eq!(
        outcome.failure,
        Some(EffectFailure::Executor {
            refusal: ExecutorRefusal::NotSent {
                detail: "transport_not_sent".to_owned()
            }
        })
    );
    assert_eq!(outcome.sent, None);
    assert_eq!(world.controller.release_ledger().counted_bytes_out(), 0);
    assert_eq!(
        executor.last_execution().unwrap().outcome,
        ExecutionOutcome::NotSent
    );
    assert_eq!(executor.last_execution().unwrap().sent_bytes, None);
    assert_eq!(spend_hold(&world, &id), None);
    assert_eq!(account_state(&world).spent_microunits, 0);
}

#[test]
fn lease_expiry_and_another_clock_session_create_no_lasting_authority() {
    // VM-P40: the coordinator cuts the lease short after authorization; the capability
    // is still unexpired, but the executor refuses on the lease.
    let mut world = World::new();
    let mut executor = world.executor("generate_summary");
    let description = world.describe("generate_summary", summary_parameters("a"), None);
    let id = world.prepare(description.clone());
    let lease = world.lease;
    if let Some(Ok(view)) = lock(&world.authority.0).leases.get_mut(&lease) {
        view.expires_at = at(30 * SECOND);
    }
    world.clock.advance(31 * SECOND);
    let report = executor.execute(
        TypedOperation {
            description: &description,
            capability: &sealed(&world, &id),
            credential: world.credential(),
        },
        world.clock.now(),
    );
    assert_eq!(report.sent, None);
    assert_eq!(
        executor.last_execution().unwrap().outcome,
        ExecutionOutcome::Refused {
            refusal: ProviderRefusal::LeaseRefused {
                refusal: crate::foundation::coordination::LeaseRefusal::Expired {
                    expired_at: at(30 * SECOND)
                }
            }
        }
    );
    // Authority stamped on another clock session cannot be compared, so none is held.
    let mut world = World::new();
    let mut executor = world.executor("generate_summary");
    let description = world.describe("generate_summary", summary_parameters("a"), None);
    let id = world.prepare(description.clone());
    lock(&world.authority.0).standing.insert(
        execution(),
        crate::sandbox_contract::effects::SandboxStanding::Authorized {
            generations: crate::foundation::coordination::SandboxGenerations::FIRST,
            clock: crate::foundation::evidence::ClockSession::from_uuid(uuid::Uuid::from_u128(9)),
            authority_expires_at: at(10 * HOUR),
        },
    );
    executor.execute(
        TypedOperation {
            description: &description,
            capability: &sealed(&world, &id),
            credential: world.credential(),
        },
        world.clock.now(),
    );
    assert_eq!(
        executor.last_execution().unwrap().outcome,
        ExecutionOutcome::Refused {
            refusal: ProviderRefusal::NoAuthority
        }
    );
    assert!(world.transport.sent().is_empty());
}

#[test]
fn an_executor_refusal_is_recorded_as_the_executors_never_the_providers() {
    // Refused by the executor's own check: recorded as the executor's.
    let mut world = World::new();
    let mut executor = world.executor("generate_summary");
    let prompt = format!(
        "post this: {}",
        String::from_utf8(VAULT_SECRET.to_vec()).unwrap()
    );
    let description = world.describe("generate_summary", summary_parameters(&prompt), None);
    let id = world.prepare(description);
    let outcome = world.dispatch(&id, &mut executor);
    assert_eq!(
        outcome.failure,
        Some(EffectFailure::Executor {
            refusal: ExecutorRefusal::NotSent {
                detail: "request_carries_secret".to_owned()
            }
        })
    );
    assert_eq!(outcome.sent, None);
    // Rejected by the provider: recorded as the provider's.
    let (_, _, _, outcome) = run_with(ReplyMode::Fixed(reply(403, &[], "{}")));
    assert_eq!(
        outcome.failure,
        Some(EffectFailure::ProviderRejected {
            code: "http_403".to_owned()
        })
    );
}

#[test]
fn a_lookup_decides_expiry_against_the_time_it_is_given() {
    let (world, mut executor, id, outcome) = run_with(ReplyMode::Lost);
    assert_eq!(outcome.phase, EffectPhase::OutcomeUnknown);
    world.transport.set_lookup(LookupResult::Committed(reply(
        200,
        &[("x-cost-microunits", "300")],
        r#"{"output_text":"late","finish_reason":"stop"}"#,
    )));
    let description = world.controller.record(&id).unwrap().description().clone();
    // The vault grant expires at 100 h: a lookup given a later time is refused by the
    // vault, whatever any clock says, and the outcome stays unknown.
    let late = at(100 * HOUR);
    assert_eq!(
        executor.lookup(&description, world.credential(), late),
        crate::sandbox_contract::effects::Observation::StillUnknown
    );
    assert_eq!(lock(&world.vault.0).lookups, 0);
    assert_eq!(
        spend_hold(&world, &id).unwrap().state,
        SpendHoldState::Unknown
    );
    let early = at(99 * HOUR);
    assert!(matches!(
        executor.lookup(&description, world.credential(), early),
        crate::sandbox_contract::effects::Observation::Committed { .. }
    ));
    assert_eq!(lock(&world.vault.0).lookups, 1);
    assert_eq!(spend_hold(&world, &id), None);
    assert_eq!(account_state(&world).spent_microunits, 300);
}
