//! The compatibility rule: the current version strictly, a newer version refused to act
//! on and downgraded explicitly to show, version 1 read by its own reader and upgraded,
//! older and unversioned documents refused, every pinned fixture of every version
//! readable, and stored evidence rechecked when shown again.

use serde_json::{json, Value};

use super::*;
use crate::foundation::product::fixtures::GOLDEN_FIXTURES;
use crate::foundation::product::{
    read_view, ContractReadError, ContractVersion, ProductView, Read, ReadPurpose, Remedy,
    OLDEST_READABLE_VERSION, PRODUCT_CONTRACT_VERSION,
};

/// The current version's fixture `name`.
fn fixture(name: &str) -> &'static str {
    GOLDEN_FIXTURES
        .iter()
        .find(|fixture| fixture.name == name && fixture.version == PRODUCT_CONTRACT_VERSION)
        .unwrap()
        .json
}

fn with(json: &str, change: impl FnOnce(&mut Value)) -> String {
    let mut value: Value = serde_json::from_str(json).unwrap();
    change(&mut value);
    value.to_string()
}

#[test]
fn every_pinned_fixture_of_every_readable_version_stays_readable() {
    for version in OLDEST_READABLE_VERSION..=PRODUCT_CONTRACT_VERSION {
        assert!(
            GOLDEN_FIXTURES
                .iter()
                .any(|fixture| fixture.version == version),
            "version {version} has no golden fixture"
        );
    }
    for fixture in GOLDEN_FIXTURES {
        let read = read_view(fixture.json, ReadPurpose::Act).unwrap();
        match read {
            Read::Current(_) => assert_eq!(fixture.version, PRODUCT_CONTRACT_VERSION),
            Read::Upgraded { from, .. } => assert_eq!(from, fixture.version),
            Read::Downgraded(_) => panic!("{} was downgraded", fixture.name),
        }
        assert!(read.document().is_some());
    }
}

#[test]
fn a_newer_version_is_refused_to_act_on_and_downgraded_explicitly_to_show() {
    let newer = PRODUCT_CONTRACT_VERSION + 1;
    let json = with(fixture("vm_sandbox_ready"), |value| {
        value["contract_version"] = json!(newer);
        value["isolation_score"] = json!(10);
    });
    assert_eq!(
        read_view(&json, ReadPurpose::Act).unwrap_err(),
        ContractReadError::Newer { found: newer }
    );
    let Read::Downgraded(notice) = read_view(&json, ReadPurpose::Display).unwrap() else {
        panic!("a newer document is shown only as a notice");
    };
    assert_eq!(notice.found, newer);
    assert_eq!(notice.supported, PRODUCT_CONTRACT_VERSION);
    assert_eq!(notice.refusal.code.as_str(), "newer_contract_version");
    assert_eq!(notice.refusal.remedy(), &Remedy::UpdateYougori);
    assert!(Read::<ProductView>::Downgraded(notice).document().is_none());
}

#[test]
fn older_unversioned_and_invalid_documents_are_refused_with_codes() {
    let older = with(fixture("labelled_runtime_refused"), |value| {
        value["contract_version"] = json!(0);
    });
    let error = read_view(&older, ReadPurpose::Display).unwrap_err();
    assert_eq!(error, ContractReadError::Unsupported { found: 0 });
    assert_eq!(
        error.refusal().code.as_str(),
        "unsupported_contract_version"
    );

    let missing = with(fixture("labelled_runtime_refused"), |value| {
        value.as_object_mut().unwrap().remove("contract_version");
    });
    let error = read_view(&missing, ReadPurpose::Display).unwrap_err();
    assert_eq!(error, ContractReadError::VersionMissing);
    assert_eq!(error.refusal().code.as_str(), "contract_version_missing");

    let text = with(fixture("labelled_runtime_refused"), |value| {
        value["contract_version"] = json!("1");
    });
    assert!(matches!(
        read_view(&text, ReadPurpose::Act),
        Err(ContractReadError::Invalid { .. })
    ));

    let unknown = with(fixture("labelled_runtime_refused"), |value| {
        value["certified"] = json!(true);
    });
    let Err(ContractReadError::Invalid { message }) = read_view(&unknown, ReadPurpose::Act) else {
        panic!("an unknown field is refused");
    };
    assert!(message.contains("unknown field"), "{message}");
    assert_eq!(
        ContractReadError::Invalid { message }
            .refusal()
            .code
            .as_str(),
        "invalid_product_document"
    );

    let newer = json!(PRODUCT_CONTRACT_VERSION + 1);
    assert!(serde_json::from_value::<ContractVersion>(newer).is_err());
    assert!(serde_json::from_value::<ContractVersion>(json!(OLDEST_READABLE_VERSION)).is_err());
    assert_eq!(
        serde_json::to_value(ContractVersion::CURRENT).unwrap(),
        json!(PRODUCT_CONTRACT_VERSION)
    );
}

#[test]
fn a_stored_document_shown_again_later_never_presents_stale_evidence_as_current() {
    let Read::Current(stored) = read_view(fixture("vm_sandbox_ready"), ReadPurpose::Act).unwrap()
    else {
        panic!("current");
    };
    let verified = |view: &ProductView| {
        view.evidence()
            .into_iter()
            .filter(|evidence| evidence.is_verified() || evidence.is_observed())
            .count()
    };
    assert!(verified(&stored) >= 3);

    let probes = Probes::new(SourceClass::HostProbe);
    let restarted = stored.as_of(probes.now(), config());
    assert_eq!(verified(&restarted), 0);
    assert!(restarted
        .execution
        .as_ref()
        .unwrap()
        .actual()
        .value()
        .is_none());
    assert!(restarted.check().is_ok());
    assert!(read_view(&restarted.to_json().unwrap(), ReadPurpose::Act).is_ok());

    let asserted_before = stored
        .evidence()
        .into_iter()
        .filter(|evidence| evidence.is_asserted())
        .count();
    let asserted_after = restarted
        .evidence()
        .into_iter()
        .filter(|evidence| evidence.is_asserted())
        .count();
    assert_eq!(asserted_before, asserted_after);

    probes.advance(Duration::from_secs(2));
    let mut same_session = stored.clone();
    same_session.shown_at.clock = probes.now().session();
    let reconfigured = same_session.as_of(probes.now(), other_config());
    assert_eq!(verified(&reconfigured), 0);
    assert_eq!(
        verified(&same_session.as_of(probes.now(), config())),
        verified(&stored)
    );

    let forged = with(fixture("vm_sandbox_ready"), |value| {
        value["shown_at"]["at"] = json!(u64::MAX);
    });
    let Err(ContractReadError::Invalid { message }) = read_view(&forged, ReadPurpose::Act) else {
        panic!("evidence not current when shown is refused");
    };
    assert!(
        message.contains("not current when the document was shown"),
        "{message}"
    );
}

#[test]
fn version_1_is_read_by_its_own_reader_and_upgraded_to_its_version_2_fixture() {
    let version_1: Vec<_> = GOLDEN_FIXTURES
        .iter()
        .filter(|fixture| fixture.version == 1)
        .collect();
    assert_eq!(version_1.len(), 4);
    for old in version_1 {
        let Read::Upgraded { from, document } = read_view(old.json, ReadPurpose::Act).unwrap()
        else {
            panic!("{} is upgraded", old.name);
        };
        assert_eq!(from, 1);
        assert_eq!(document.contract_version, ContractVersion::CURRENT);
        assert!(document.endpoint.is_none() && document.grants.is_none());
        let pinned = fixture(old.name);
        assert_eq!(document.to_json_pretty().unwrap() + "\n", pinned);
        let Read::Current(current) = read_view(pinned, ReadPurpose::Act).unwrap() else {
            panic!("current");
        };
        assert_eq!(current, document);
    }

    // A document naming version 1 holds exactly version 1's fields, read strictly.
    let v1 = |name: &str| {
        GOLDEN_FIXTURES
            .iter()
            .find(|fixture| fixture.name == name && fixture.version == 1)
            .unwrap()
            .json
    };
    for part in ["endpoint", "grants"] {
        let json = with(v1("model_preparing"), |value| {
            value[part] = json!({});
        });
        let Err(ContractReadError::Invalid { message }) = read_view(&json, ReadPurpose::Display)
        else {
            panic!("version 1 had no {part}");
        };
        assert!(message.contains("unknown field"), "{message}");
    }
    let relabelled = with(fixture("agent_endpoint_declared"), |value| {
        value["contract_version"] = json!(1);
    });
    assert!(matches!(
        read_view(&relabelled, ReadPurpose::Act),
        Err(ContractReadError::Invalid { .. })
    ));
    let forged = with(v1("vm_sandbox_ready"), |value| {
        value["shown_at"]["at"] = json!(u64::MAX);
    });
    let Err(ContractReadError::Invalid { message }) = read_view(&forged, ReadPurpose::Act) else {
        panic!("version 1 is checked as the current version is");
    };
    assert!(message.contains("not current"), "{message}");
}
