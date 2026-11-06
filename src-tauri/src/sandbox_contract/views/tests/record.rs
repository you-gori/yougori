//! The stored view: what it binds, strict reading, its domain-separated digest, flipped
//! fields, re-sealed forgeries caught by the launch record and the contract, and the
//! builder's refusals.

use serde_json::{json, Value};

use super::*;
use crate::foundation::ids::digest;
use crate::sandbox::backend::{FactSource, Scripted};
use crate::sandbox_contract::declarations::PolicyPreview;
use crate::sandbox_contract::destinations::NetworkMode;

fn facts_json(json: &mut Value) -> &mut Vec<Value> {
    json["body"]["facts"].as_array_mut().unwrap()
}

#[test]
fn a_view_binds_its_launch_record_contract_and_sandbox() {
    let fixture = launch();
    let view = fixture.view();
    let record = &fixture.record;
    let body = view.body();
    assert_eq!(view.launch_record(), record.identity());
    assert_eq!(body.launch_record, record.identity());
    assert_eq!(body.contract.digest, record.contract());
    assert_eq!(
        body.contract.digest,
        fixture.evaluation.resolved().identity().digest()
    );
    assert_eq!(body.execution, record.sandbox().execution);
    assert_eq!(body.tenant, record.sandbox().tenant);
    assert_eq!(body.generations, record.sandbox().generations);
    assert_eq!(body.vm, record.vm());
    assert_eq!(body.restored_from, None);
    assert_eq!(body.configuration, config("a"));
    assert_eq!(body.clock, record.clock());
    assert_eq!(body.recorded_at, record.recorded_at());
    assert_eq!(body.max_age, MINUTE);
    assert_eq!(body.view_version, ViewVersion::CURRENT);
    // Launch-record facts come first, then the contract's and the declaration's.
    let split = body
        .facts
        .iter()
        .position(|fact| !fact.from_launch_record())
        .unwrap();
    assert!(body.facts[split..]
        .iter()
        .all(|fact| !fact.from_launch_record()));
    assert_eq!(view.check_against(record), Ok(()));
    assert_eq!(view.check_contract(fixture.evaluation.resolved()), Ok(()));
}

#[test]
fn the_view_round_trips_through_json_byte_for_byte() {
    let view = launch().view();
    let text = view.to_json().unwrap();
    let read = SandboxView::from_json(&text).unwrap();
    assert_eq!(read, view);
    assert_eq!(read.digest(), view.digest());
    assert_eq!(read.to_json().unwrap(), text);
    // serde's own path checks the same things.
    let through_serde: SandboxView = serde_json::from_str(&text).unwrap();
    assert_eq!(through_serde, view);
    let mut edited: Value = serde_json::from_str(&text).unwrap();
    edited["body"]["max_age"]["secs"] = json!(3_600);
    assert!(serde_json::from_value::<SandboxView>(edited).is_err());
}

#[test]
fn the_digest_is_domain_separated_over_the_whole_body() {
    let view = launch().view();
    let bytes = serde_json::to_vec(view.body()).unwrap();
    assert_eq!(view.digest(), digest(VIEW_DOMAIN, &[&bytes]));
    assert_ne!(
        view.digest(),
        digest(crate::sandbox::backend::LAUNCH_RECORD_DOMAIN, &[&bytes])
    );
    assert_ne!(view.digest(), view.launch_record());
    // Two launches of the same contract have different views.
    let other = launch_with(
        Setup {
            execution: "exe-2",
            ..Setup::default()
        },
        |_| {},
    )
    .view();
    assert_ne!(other.digest(), view.digest());
    assert_eq!(other.body().contract, view.body().contract);
}

#[test]
fn reading_refuses_unknown_fields_at_every_level() {
    let view = launch().view();
    let accelerator = index_of(&view, is_accelerator);
    let edits: Vec<Box<dyn Fn(&mut Value)>> = vec![
        Box::new(|json| json["signature"] = json!("ok")),
        Box::new(|json| json["body"]["score"] = json!(10)),
        Box::new(move |json| facts_json(json)[accelerator]["trust"] = json!("high")),
        Box::new(move |json| facts_json(json)[accelerator]["value"]["requested"] = json!(true)),
        Box::new(move |json| facts_json(json)[accelerator]["basis"]["verified"] = json!(true)),
        Box::new(move |json| {
            facts_json(json)[accelerator]["basis"]["stamp"]["current"] = json!(true)
        }),
        Box::new(|json| json["body"]["contract"]["issuer"] = json!("x")),
    ];
    for (index, edit) in edits.iter().enumerate() {
        let refusal = read_after(&view, |json| edit(json)).unwrap_err();
        assert!(
            matches!(refusal, ViewRefusal::Malformed { .. }),
            "edit {index}: {refusal:?}"
        );
    }
}

#[test]
fn reading_refuses_another_version_or_notice() {
    let view = launch().view();
    let refusal = read_after(&view, |json| json["body"]["view_version"] = json!(2)).unwrap_err();
    assert!(
        matches!(&refusal, ViewRefusal::Malformed { detail } if detail.contains("view version 2")),
        "{refusal:?}"
    );
    let refusal = read_after(&view, |json| {
        json["body"]["notice"] = json!("This view certifies the sandbox as secure.")
    })
    .unwrap_err();
    assert!(
        matches!(&refusal, ViewRefusal::Malformed { detail } if detail.contains("fixed text")),
        "{refusal:?}"
    );
    let refusal = read_after(&view, |json| {
        json["body"]["contract"]["meaning"] = json!("proves enforcement")
    })
    .unwrap_err();
    assert!(matches!(refusal, ViewRefusal::Malformed { .. }));
    assert!(matches!(
        SandboxView::from_json("not json"),
        Err(ViewRefusal::Malformed { .. })
    ));
}

#[test]
fn flipping_any_one_field_is_detected() {
    let view = launch().view();
    let accelerator = index_of(&view, is_accelerator);
    let access = index_of(&view, |fact| matches!(fact.value, FactValue::Access { .. }));
    let hypervisor = index_of(&view, |fact| {
        matches!(fact.value, FactValue::HypervisorAvailable { .. })
    });
    let other_digest = digest("yougori/test/views/other/v1", &[b"x"]).to_hex();
    let edits: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
        (
            "accelerator value",
            Box::new(move |json| {
                facts_json(json)[accelerator]["value"]["accelerator"]["hardware"]["hypervisor"] =
                    json!("whpx")
            }),
        ),
        (
            "observation time",
            Box::new(move |json| {
                facts_json(json)[accelerator]["basis"]["stamp"]["observed_at"] =
                    json!(999_999_999_999u64)
            }),
        ),
        (
            "freshness bound",
            Box::new(move |json| {
                facts_json(json)[accelerator]["basis"]["stamp"]["fresh_for"]["secs"] = json!(86_400)
            }),
        ),
        (
            "basis kind",
            Box::new(move |json| {
                facts_json(json)[accelerator]["basis"]["basis"] = json!("host_verified")
            }),
        ),
        (
            "evidence freshness",
            Box::new(move |json| {
                facts_json(json)[hypervisor]["basis"]["stamp"]["fresh_until"] = json!(u64::MAX)
            }),
        ),
        (
            "launch record",
            Box::new({
                let other = other_digest.clone();
                move |json| json["body"]["launch_record"] = json!(other)
            }),
        ),
        (
            "configuration",
            Box::new({
                let other = other_digest.clone();
                move |json| json["body"]["configuration"] = json!(other)
            }),
        ),
        (
            "contract line",
            Box::new(move |json| {
                facts_json(json)[access]["value"]["access"]["private_data"] = json!(false)
            }),
        ),
        (
            "freshness requirement",
            Box::new(|json| json["body"]["max_age"]["secs"] = json!(86_400)),
        ),
        (
            "a fact removed",
            Box::new(move |json| {
                facts_json(json).remove(access);
            }),
        ),
    ];
    for (name, edit) in &edits {
        let refusal = read_after(&view, |json| edit(json)).unwrap_err();
        let stored = match refusal {
            ViewRefusal::DigestMismatch { stored, .. } => stored,
            other => panic!("{name}: {other:?}"),
        };
        assert_eq!(stored, view.digest(), "{name}");
    }
    // The digest itself.
    let refusal = read_after(&view, |json| json["digest"] = json!(other_digest)).unwrap_err();
    assert!(
        matches!(refusal, ViewRefusal::DigestMismatch { computed, .. } if computed == view.digest())
    );
    assert!(refusal.to_string().contains("changed after it was sealed"));
}

#[test]
fn a_basis_that_does_not_fit_is_refused_even_when_resealed() {
    let view = launch().view();
    let access = index_of(&view, |fact| matches!(fact.value, FactValue::Access { .. }));
    let accelerator = index_of(&view, is_accelerator);
    let stamp = serde_json::to_value(&view.facts()[accelerator].basis).unwrap();
    // A contract line dressed as a host observation.
    let forged = resealed(&view, |body| body["facts"][access]["basis"] = stamp.clone());
    assert_eq!(
        SandboxView::from_json(&forged.to_json().unwrap()),
        Err(ViewRefusal::BasisDoesNotFit { index: access })
    );
    // An accelerator dressed as a contract statement.
    let forged = resealed(&view, |body| {
        body["facts"][accelerator]["basis"] = json!({"basis": "asserted", "by": "contract"})
    });
    assert_eq!(
        SandboxView::from_json(&forged.to_json().unwrap()),
        Err(ViewRefusal::BasisDoesNotFit { index: accelerator })
    );
}

#[test]
fn checking_against_another_launch_record_is_refused() {
    let fixture = launch();
    let view = fixture.view();
    let other = launch_with(
        Setup {
            execution: "exe-2",
            ..Setup::default()
        },
        |_| {},
    );
    let refusal = view.check_against(&other.record).unwrap_err();
    assert_eq!(
        refusal,
        ViewRefusal::OtherLaunchRecord {
            view: fixture.record.identity(),
            record: other.record.identity(),
        }
    );
    assert!(refusal.to_string().contains("not launch record"));
}

#[test]
fn a_resealed_forgery_is_caught_by_its_launch_record() {
    let fixture = launch_with(Setup::default(), |script| {
        script.guest.accelerator = Some(kvm());
    });
    let view = fixture.view();
    let record = &fixture.record;
    assert_eq!(view.check_against(record), Ok(()));
    let guest = index_of(&view, |fact| is_accelerator(fact) && is_guest(fact));
    let host = index_of(&view, |fact| is_accelerator(fact) && !is_guest(fact));
    let host_stamp = serde_json::to_value(&view.facts()[host].basis).unwrap();
    let cases: Vec<(&str, RecordPart, Box<dyn Fn(&mut Value)>)> = vec![
        (
            "a guest assertion relabelled as a host observation",
            RecordPart::Facts,
            Box::new(move |body| body["facts"][guest]["basis"] = host_stamp.clone()),
        ),
        (
            "an observation moved later to look fresh",
            RecordPart::Facts,
            Box::new(move |body| {
                body["facts"][host]["basis"]["stamp"]["observed_at"] = json!(10_000_000_000_000u64)
            }),
        ),
        (
            "an observation relabelled as corroborated",
            RecordPart::Facts,
            Box::new(move |body| body["facts"][host]["basis"]["basis"] = json!("host_verified")),
        ),
        (
            "a host fact dropped",
            RecordPart::Facts,
            Box::new(move |body| {
                body["facts"].as_array_mut().unwrap().remove(host);
            }),
        ),
        (
            "a looser freshness bound",
            RecordPart::MaxAge,
            Box::new(|body| body["max_age"]["secs"] = json!(86_400)),
        ),
        (
            "another configuration",
            RecordPart::Configuration,
            Box::new(|body| body["configuration"] = json!(config("b"))),
        ),
        (
            "another tenant",
            RecordPart::Sandbox,
            Box::new(|body| body["tenant"] = json!("tenant-2")),
        ),
        (
            "another contract",
            RecordPart::Contract,
            Box::new(|body| {
                body["contract"]["digest"] = json!(digest("yougori/test/views/c/v1", &[b"c"]))
            }),
        ),
    ];
    for (name, part, edit) in &cases {
        let forged = resealed(&view, |body| edit(body));
        // The forgery has a correct digest and fitting bases, so it reads back...
        let read = SandboxView::from_json(&forged.to_json().unwrap())
            .unwrap_or_else(|refusal| panic!("{name}: {refusal}"));
        // ...but it is not what the launch record yields.
        assert_eq!(
            read.check_against(record),
            Err(ViewRefusal::DiffersFromRecord { part: *part }),
            "{name}"
        );
    }
}

#[test]
fn checking_against_the_contract_catches_edited_lines() {
    let fixture = launch();
    let view = fixture.view();
    let contract = fixture.evaluation.resolved();
    let access = index_of(&view, |fact| matches!(fact.value, FactValue::Access { .. }));
    let requested = index_of(&view, |fact| {
        matches!(fact.value, FactValue::Requested { .. })
    });
    let forged = resealed(&view, |body| {
        body["facts"].as_array_mut().unwrap().remove(access);
    });
    assert_eq!(forged.check_against(&fixture.record), Ok(()));
    assert_eq!(
        forged.check_contract(contract),
        Err(ViewRefusal::DiffersFromContract)
    );
    // A withheld capability moved into the permitted lines.
    let moved = resealed(&view, |body| {
        let tuple = body["facts"][requested]["value"]["tuple"].clone();
        body["facts"][access]["value"]["access"]["tuple"] = tuple;
    });
    assert_eq!(
        moved.check_contract(contract),
        Err(ViewRefusal::DiffersFromContract)
    );
    let other = launch_with(
        Setup {
            declaration: offline_tool(),
            ceiling: vec![read_inputs(), write_outputs()],
            granted: vec![read_inputs(), write_outputs()],
            ..Setup::default()
        },
        |_| {},
    );
    assert!(matches!(
        view.check_contract(other.evaluation.resolved()),
        Err(ViewRefusal::OtherContract { .. })
    ));
}

#[test]
fn build_refuses_a_contract_the_record_does_not_name() {
    let fixture = launch();
    let other = launch_with(
        Setup {
            declaration: offline_tool(),
            ceiling: vec![read_inputs(), write_outputs()],
            granted: vec![read_inputs(), write_outputs()],
            ..Setup::default()
        },
        |_| {},
    );
    let error = SandboxView::build(&ViewInputs {
        contract: other.evaluation.resolved(),
        preview: &other.preview,
        ..fixture.inputs(None)
    })
    .unwrap_err();
    assert_eq!(
        error,
        ViewError::ContractMismatch {
            record: fixture.record.contract(),
            contract: other.evaluation.resolved().identity(),
        }
    );
    assert!(error.to_string().contains("not the contract"));
}

#[test]
fn build_refuses_a_preview_of_another_contract_or_with_other_lines() {
    let fixture = launch();
    let other = launch_with(
        Setup {
            declaration: offline_tool(),
            ceiling: vec![read_inputs(), write_outputs()],
            granted: vec![read_inputs(), write_outputs()],
            ..Setup::default()
        },
        |_| {},
    );
    assert!(matches!(
        SandboxView::build(&ViewInputs {
            preview: &other.preview,
            ..fixture.inputs(None)
        }),
        Err(ViewError::PreviewForAnotherContract { .. })
    ));
    let edits: Vec<Box<dyn Fn(&mut PolicyPreview)>> = vec![
        Box::new(|preview| {
            preview.reads.clear();
        }),
        Box::new(|preview| {
            let line = preview.reads[0].clone();
            preview.writes.push(line);
        }),
        Box::new(|preview| {
            preview.removed.clear();
        }),
        Box::new(|preview| {
            let line = preview.releases[0].clone();
            preview.devices.push(line);
        }),
    ];
    for edit in &edits {
        let mut preview = fixture.preview.clone();
        edit(&mut preview);
        assert_eq!(
            SandboxView::build(&ViewInputs {
                preview: &preview,
                ..fixture.inputs(Some(NetworkMode::DeclaredTransport))
            }),
            Err(ViewError::PreviewDoesNotMatchContract)
        );
    }
}

#[test]
fn the_stored_view_holds_no_labels() {
    let fixture = launch_with(Setup::default(), |script| {
        script.accelerator = Scripted::Verified {
            value: kvm(),
            control: control(),
        };
    });
    assert_eq!(fixture.record.accelerator().source(), FactSource::Verified);
    let view = fixture.view();
    let json: Value = serde_json::from_str(&view.to_json().unwrap()).unwrap();
    let mut keys = BTreeSet::new();
    fn walk(value: &Value, keys: &mut BTreeSet<String>) {
        match value {
            Value::Object(fields) => {
                for (key, inner) in fields {
                    keys.insert(key.clone());
                    walk(inner, keys);
                }
            }
            Value::Array(items) => items.iter().for_each(|inner| walk(inner, keys)),
            _ => {}
        }
    }
    walk(&json, &mut keys);
    for key in ["label", "verified", "observed", "why"] {
        assert!(!keys.contains(key), "stored key {key}");
    }
    // The corroborated accelerator is stored as a basis with its stamp, not as a verdict.
    let accelerator = index_of(&view, is_accelerator);
    assert!(matches!(
        view.facts()[accelerator].basis,
        FactBasis::HostVerified { .. }
    ));
}
