//! Declared agent endpoint capabilities on their own: support stands only on the host's
//! own conformance run and is never shown as verified, a runner's declaration stays an
//! assertion, an untested, stale or reconfigured feature is unavailable and never leaves
//! its dialect advertised, and a stored endpoint is advertised again only on current
//! evidence. The conversions from the serving protocol are tested in `product_views`.

use serde_json::{json, Value};

use super::*;
use crate::foundation::evidence::{Backend, BackendRelease, ConfigurationFingerprint};
use crate::foundation::product::{
    read_view, AgentEndpoint, Asserter, CellShown, ConformanceShown, DialectShown, EndpointAspect,
    EndpointDialect, EndpointError, EndpointFeature, Evidence, FeatureSupport, Observer,
    ProductView, Read, ReadPurpose, ShownAt, ShownText, UnsupportedReason, ViewSubject,
    ViewSubjectKind,
};
use crate::foundation::report::Label;

const CC: EndpointDialect = EndpointDialect::OpenAiChatCompletions;
const RS: EndpointDialect = EndpointDialect::OpenAiResponses;

fn launch() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("launch", "coder-flags")]).unwrap()
}

fn other_launch() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("launch", "other-flags")]).unwrap()
}

fn label(text: &str) -> Label {
    Label::new(text).unwrap()
}

/// A run of `dialect` the host's harness recorded at `at`, with 20 cases and the given
/// failures.
fn run(dialect: EndpointDialect, at: MonotonicTime, failed: &[&str]) -> ConformanceShown {
    ConformanceShown {
        run: digest(
            "yougori/test/product/conformance-run/v1",
            &[dialect.label().as_bytes()],
        ),
        configuration: launch(),
        observed_at: at,
        cases: 20,
        failed: failed.iter().map(|case| label(case)).collect(),
    }
}

/// Every feature supported by 3 cases, except where `except` says otherwise; a feature the
/// dialect does not define is shown as such.
fn cells(
    dialect: EndpointDialect,
    except: &[(EndpointFeature, CellShown)],
) -> impl Fn(EndpointFeature) -> CellShown + '_ {
    move |feature| {
        if let Some((_, cell)) = except.iter().find(|(named, _)| *named == feature) {
            return cell.clone();
        }
        if feature.in_dialect(dialect) {
            CellShown::Supported { cases: 3 }
        } else {
            CellShown::Unsupported {
                reason: UnsupportedReason::NotInDialect,
            }
        }
    }
}

fn declared_parallel() -> (EndpointFeature, CellShown) {
    (
        EndpointFeature::ParallelCalls,
        CellShown::Unsupported {
            reason: UnsupportedReason::DeclaredByRunner {
                explanation: ShownText::new("this runner emits one call per turn"),
            },
        },
    )
}

fn evidence_of(shown: &DialectShown, feature: EndpointFeature) -> &Evidence {
    shown.feature(feature).unwrap().support().evidence()
}

fn feature_index(feature: EndpointFeature) -> usize {
    EndpointFeature::ALL
        .iter()
        .position(|named| *named == feature)
        .unwrap()
}

/// `shown` as JSON, changed by `change`, read back.
fn tampered(shown: &DialectShown, change: impl FnOnce(&mut Value)) -> String {
    let mut json = serde_json::to_value(shown).unwrap();
    change(&mut json);
    refused::<DialectShown>(json)
}

#[test]
fn support_stands_only_on_the_hosts_own_run_and_a_declaration_stays_an_assertion() {
    let probes = Probes::new(SourceClass::HostProbe);
    let at = probes.now().at();
    let declared = [declared_parallel()];
    let shown = DialectShown::published(
        CC,
        run(CC, at, &[]),
        cells(CC, &declared),
        launch(),
        probes.now(),
        HOUR,
    )
    .unwrap();
    assert!(shown.is_advertised());
    assert_eq!(shown.label(), "OpenAI Chat Completions");
    for line in shown.features() {
        assert!(!line.support().evidence().is_verified(), "{line}");
    }
    assert!(matches!(
        evidence_of(&shown, EndpointFeature::ToolSchema),
        Evidence::Observed {
            by: Observer::Host,
            ..
        }
    ));
    for feature in [
        EndpointFeature::ParallelCalls,
        EndpointFeature::TokenCounting,
    ] {
        assert!(matches!(
            evidence_of(&shown, feature),
            Evidence::Asserted {
                by: Asserter::Declaration,
                ..
            }
        ));
        assert!(!shown.feature(feature).unwrap().is_supported());
    }
    let tools: Vec<EndpointFeature> = shown
        .aspect(EndpointAspect::ToolCalling)
        .map(|line| line.feature())
        .collect();
    assert_eq!(
        tools,
        [
            EndpointFeature::ToolSchema,
            EndpointFeature::ToolChoice,
            EndpointFeature::ParallelCalls
        ]
    );
    let streaming: Vec<EndpointFeature> = shown
        .aspect(EndpointAspect::Streaming)
        .map(|line| line.feature())
        .collect();
    assert_eq!(
        streaming,
        [
            EndpointFeature::StreamingDeltas,
            EndpointFeature::Cancellation
        ]
    );
    assert_eq!(round_trip(&shown), shown);

    // Support is never verified, asserted or another run's; a declaration is never
    // observed; the dialect's own definition is never contradicted.
    let schema = feature_index(EndpointFeature::ToolSchema);
    let error = tampered(&shown, |json| {
        json["features"][schema]["support"]["evidence"] = json!({
            "state": "verified", "by": {"kind": "controlled_check"},
            "observed_at": at, "fresh_until": at.as_nanos() + 10
        });
    });
    assert!(error.contains("wrong evidence"), "{error}");
    let error = tampered(&shown, |json| {
        json["features"][schema]["support"]["evidence"] =
            json!({"state": "asserted", "by": "guest"});
    });
    assert!(error.contains("wrong evidence"), "{error}");
    let error = tampered(&shown, |json| {
        json["features"][schema]["support"]["value"]["cases"] = json!(21);
    });
    assert!(error.contains("does not hold"), "{error}");
    let error = tampered(&shown, |json| {
        json["features"][schema]["support"]["evidence"]["observed_at"] = json!(0);
    });
    assert!(error.contains("does not hold"), "{error}");
    let parallel = feature_index(EndpointFeature::ParallelCalls);
    let error = tampered(&shown, |json| {
        json["features"][parallel]["support"]["evidence"] = json!({
            "state": "observed", "by": "host", "observed_at": at,
            "fresh_until": at.as_nanos() + 10
        });
    });
    assert!(error.contains("wrong evidence"), "{error}");
    let tokens = feature_index(EndpointFeature::TokenCounting);
    let error = tampered(&shown, |json| {
        json["features"][tokens]["support"] = json!({
            "value": {"support": "supported", "cases": 2},
            "evidence": {"state": "observed", "by": "host", "observed_at": at,
                         "fresh_until": at.as_nanos() + 10}
        });
    });
    assert!(error.contains("does not define"), "{error}");
    let error = tampered(&shown, |json| {
        json["features"][schema]["support"]["value"] =
            json!({"support": "unsupported", "reason": {"reason": "not_in_dialect"}});
        json["features"][schema]["support"]["evidence"] =
            json!({"state": "asserted", "by": "declaration"});
    });
    assert!(error.contains("defines"), "{error}");

    // The words, the order, the advertisement and the fields are the contract's own.
    let error = tampered(&shown, |json| json["advertised"] = json!(false));
    assert!(error.contains("advertised exactly when"), "{error}");
    let error = tampered(&shown, |json| json["label"] = json!("OpenAI-compatible"));
    assert!(error.contains("is shown as"), "{error}");
    let error = tampered(&shown, |json| {
        json["features"][schema]["aspect"] = json!("exchange");
    });
    assert!(error.contains("is shown as"), "{error}");
    let error = tampered(&shown, |json| {
        json["features"].as_array_mut().unwrap().swap(0, 1);
    });
    assert!(error.contains("every feature once"), "{error}");
    let error = tampered(&shown, |json| json["certified"] = json!(true));
    assert!(error.contains("unknown field"), "{error}");
    let error = tampered(&shown, |json| {
        json["conformance"]["failed"] = json!(["cc-a", "cc-a"]);
    });
    assert!(error.contains("each failed case once"), "{error}");
    let error = tampered(&shown, |json| {
        json.as_object_mut().unwrap().remove("conformance");
    });
    assert!(error.contains("does not hold"), "{error}");
}

#[test]
fn a_failed_case_is_observed_and_must_be_one_the_run_failed() {
    let probes = Probes::new(SourceClass::HostProbe);
    let at = probes.now().at();
    let failed = [(
        EndpointFeature::FinishReason,
        CellShown::Unsupported {
            reason: UnsupportedReason::ConformanceFailed {
                case: label("cc-finish-length"),
                mismatch: ShownText::new("finish reason stop, expected length"),
            },
        },
    )];
    let shown = DialectShown::published(
        CC,
        run(CC, at, &["cc-finish-length"]),
        cells(CC, &failed),
        launch(),
        probes.now(),
        HOUR,
    )
    .unwrap();
    let finish = shown.feature(EndpointFeature::FinishReason).unwrap();
    assert!(finish.support().evidence().is_observed());
    assert!(
        finish.to_string().contains("cc-finish-length failed"),
        "{finish}"
    );
    assert!(
        !shown.is_advertised(),
        "every exchange needs a supported finish reason"
    );
    assert_eq!(
        DialectShown::published(
            CC,
            run(CC, at, &[]),
            cells(CC, &failed),
            launch(),
            probes.now(),
            HOUR
        ),
        Err(EndpointError::NotFromRun {
            dialect: CC,
            feature: EndpointFeature::FinishReason
        })
    );
    assert_eq!(
        DialectShown::published(
            CC,
            ConformanceShown {
                cases: 0,
                ..run(CC, at, &[])
            },
            cells(CC, &[]),
            launch(),
            probes.now(),
            HOUR
        ),
        Err(EndpointError::RunCounts { dialect: CC })
    );
}

#[test]
fn an_untested_reconfigured_or_stale_feature_is_unavailable_and_never_advertised() {
    let probes = Probes::new(SourceClass::HostProbe);
    let at = probes.now().at();

    // Responses never ran a token count: untested, so not advertised, the rest supported.
    let untested = [(EndpointFeature::TokenCounting, CellShown::Untested)];
    let responses = DialectShown::published(
        RS,
        run(RS, at, &[]),
        cells(RS, &untested),
        launch(),
        probes.now(),
        HOUR,
    )
    .unwrap();
    assert!(!responses.is_advertised());
    let refusal = evidence_of(&responses, EndpointFeature::TokenCounting)
        .refusal()
        .unwrap();
    assert_eq!(refusal.code.as_str(), "evidence_missing");
    assert_eq!(refusal.remedy_text().as_str(), "run the check");
    assert!(responses
        .feature(EndpointFeature::RequestFields)
        .unwrap()
        .is_supported());

    // Observed under another launch configuration: nothing the dialect defines is shown.
    let reconfigured = DialectShown::published(
        CC,
        run(CC, at, &[]),
        cells(CC, &[declared_parallel()]),
        other_launch(),
        probes.now(),
        HOUR,
    )
    .unwrap();
    assert!(!reconfigured.is_advertised());
    for line in reconfigured.features() {
        if line.feature().in_dialect(CC) {
            let refusal = line.support().evidence().refusal().unwrap();
            assert_eq!(refusal.code.as_str(), "evidence_configuration_changed");
            assert!(line.support().value().is_none());
        } else {
            assert!(line.support().evidence().is_asserted());
        }
    }

    // A run past its freshness, or dated after now, is stale.
    probes.advance(HOUR + HOUR);
    let stale = DialectShown::published(
        CC,
        run(CC, at, &[]),
        cells(CC, &[]),
        launch(),
        probes.now(),
        HOUR,
    )
    .unwrap();
    assert!(!stale.is_advertised());
    assert_eq!(
        evidence_of(&stale, EndpointFeature::RequestFields)
            .refusal()
            .unwrap()
            .code
            .as_str(),
        "evidence_stale"
    );
    let future = DialectShown::published(
        CC,
        run(CC, probes.now().at().saturating_add(HOUR), &[]),
        cells(CC, &[]),
        launch(),
        probes.now(),
        HOUR,
    )
    .unwrap();
    assert!(!future.is_advertised());

    // No row at all: every feature the dialect defines is missing.
    let unpublished = DialectShown::unpublished(EndpointDialect::AnthropicMessages);
    assert!(!unpublished.is_advertised());
    assert!(unpublished.conformance().is_none());
    assert!(unpublished.features().iter().all(|line| line
        .support()
        .evidence()
        .refusal()
        .unwrap()
        .code
        .as_str()
        == "evidence_missing"));
    assert_eq!(round_trip(&unpublished), unpublished);
    let unpublished_cc = DialectShown::unpublished(CC);
    assert!(unpublished_cc
        .feature(EndpointFeature::TokenCounting)
        .unwrap()
        .support()
        .evidence()
        .is_asserted());
}

/// An endpoint of the test model on the shared-kernel GPU runtime: Chat Completions
/// advertised, Responses with token counting untested, Messages unpublished.
fn endpoint(probes: &Probes) -> AgentEndpoint {
    let at = probes.now().at();
    let untested = [(EndpointFeature::TokenCounting, CellShown::Untested)];
    AgentEndpoint::new(
        digest("yougori/test/product/model/v1", &[b"coder-7b"]),
        BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        ExecutionCategory::SharedKernelGpuRuntime,
        vec![
            DialectShown::published(
                CC,
                run(CC, at, &[]),
                cells(CC, &[declared_parallel()]),
                launch(),
                probes.now(),
                HOUR,
            )
            .unwrap(),
            DialectShown::published(
                RS,
                run(RS, at, &[]),
                cells(RS, &untested),
                launch(),
                probes.now(),
                HOUR,
            )
            .unwrap(),
            DialectShown::unpublished(EndpointDialect::AnthropicMessages),
        ],
    )
    .unwrap()
}

#[test]
fn an_endpoint_lists_every_dialect_once_on_its_runners_own_label() {
    let probes = Probes::new(SourceClass::HostProbe);
    let shown = endpoint(&probes);
    assert_eq!(shown.advertised(), [CC]);
    assert!(!shown.runner().category.is_sandbox());
    assert_eq!(
        shown.runner().category.label(),
        "GPU runtime (shared kernel), not a sandbox"
    );
    assert_eq!(round_trip(&shown), shown);

    let mut reordered = serde_json::to_value(&shown).unwrap();
    reordered["dialects"].as_array_mut().unwrap().swap(0, 2);
    assert!(refused::<AgentEndpoint>(reordered).contains("every dialect once"));
    let mut as_vm = serde_json::to_value(&shown).unwrap();
    as_vm["runner"]["category"] =
        json!({"category": "shared_kernel_gpu_runtime", "label": "VM sandbox", "sandbox": true});
    assert!(refused::<AgentEndpoint>(as_vm).contains("never with another label"));
    assert_eq!(
        AgentEndpoint::new(
            shown.model(),
            shown.runner().release.clone(),
            ExecutionCategory::SharedKernelGpuRuntime,
            shown.dialects()[..2].to_vec(),
        ),
        Err(EndpointError::DialectOrder)
    );
}

#[test]
fn a_stored_endpoint_shown_again_is_advertised_only_on_current_evidence() {
    let probes = Probes::new(SourceClass::HostProbe);
    let mut view = ProductView::new(
        ViewSubject::new(ViewSubjectKind::Model, "coder-7b").unwrap(),
        ShownAt::of(probes.now(), config()),
    );
    view.endpoint = Some(endpoint(&probes));
    let json = view.to_json().unwrap();
    let Read::Current(stored) = read_view(&json, ReadPurpose::Act).unwrap() else {
        panic!("current");
    };
    assert_eq!(stored, view);
    let observed = |view: &ProductView| {
        view.evidence()
            .into_iter()
            .filter(|evidence| evidence.is_observed())
            .count()
    };
    assert!(observed(&stored) >= 18);

    // Within freshness on the same clock and configuration: unchanged.
    probes.advance(Duration::from_secs(60));
    let later = stored.as_of(probes.now(), config());
    assert_eq!(later.endpoint.as_ref().unwrap().advertised(), [CC]);

    // Past freshness, under another configuration, or on another clock: nothing observed
    // stays, so no dialect stays advertised, and declarations stay assertions.
    probes.advance(HOUR);
    let asserted = |view: &ProductView| {
        view.evidence()
            .into_iter()
            .filter(|evidence| evidence.is_asserted())
            .count()
    };
    for shown in [
        stored.as_of(probes.now(), config()),
        later.as_of(probes.now(), config()),
        stored.as_of(Probes::new(SourceClass::HostProbe).now(), config()),
    ] {
        assert_eq!(observed(&shown), 0);
        assert!(shown.endpoint.as_ref().unwrap().advertised().is_empty());
        assert_eq!(asserted(&shown), asserted(&stored));
        assert!(shown.check().is_ok());
        assert!(read_view(&shown.to_json().unwrap(), ReadPurpose::Act).is_ok());
    }
    let reconfigured = stored.as_of(probes.now(), other_config());
    assert_eq!(observed(&reconfigured), 0);

    // A document showing an observation past its freshness as current is refused.
    let mut forged: Value = serde_json::from_str(&json).unwrap();
    forged["shown_at"]["at"] = json!(u64::MAX);
    assert!(read_view(&forged.to_string(), ReadPurpose::Act).is_err());
}

#[test]
fn the_contracts_features_and_dialects_keep_their_order_and_words() {
    assert_eq!(EndpointFeature::ALL.len(), 11);
    assert_eq!(
        EndpointFeature::EVERY_EXCHANGE,
        [
            EndpointFeature::RequestFields,
            EndpointFeature::FinishReason,
            EndpointFeature::Errors
        ]
    );
    for dialect in EndpointDialect::ALL {
        let tag = serde_json::to_value(dialect).unwrap();
        assert_eq!(
            serde_json::from_value::<EndpointDialect>(tag).unwrap(),
            dialect
        );
        for feature in EndpointFeature::ALL {
            assert_eq!(
                feature.in_dialect(dialect),
                !(dialect == CC && feature == EndpointFeature::TokenCounting)
            );
        }
    }
    let supported = FeatureSupport::Supported { cases: 1 };
    let error = refused::<FeatureSupport>(json!({"support": "supported", "cases": 1, "x": 1}));
    assert!(error.contains("unknown field"), "{error}");
    assert_eq!(round_trip(&supported), supported);
    let not_defined = refused::<UnsupportedReason>(json!({"reason": "not_in_dialect", "why": "x"}));
    assert!(not_defined.contains("unknown field"), "{not_defined}");
}
