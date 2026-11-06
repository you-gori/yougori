//! The declared agent endpoint from the serving protocol's own rows and runs: dialects and
//! features map one to one, support and failed cases stand on the host's own live run, a
//! runner's declaration stays an assertion, an untested or reconfigured feature never
//! leaves a dialect advertised, a row is shown only with its own run for its own model and
//! runner, and the golden fixture is what the conversion produces. The host's harness
//! sends the protocol's own cases to a stand-in runner that answers as each case recorded,
//! as the serving protocol's tests do; nothing here contacts a runner.

use std::time::Duration;

use serde_json::Value;

use crate::foundation::evidence::{
    Backend, BackendRelease, ClockSession, ConfigurationFingerprint, SourceClass,
};
use crate::foundation::ids::{digest, Digest, ExecutionCategory};
use crate::foundation::product::fixtures::GOLDEN_FIXTURES;
use crate::foundation::product::test_support::{config, Probes, HOUR};
use crate::foundation::product::{
    read_view, Asserter, CellShown, EndpointDialect, EndpointFeature, Evidence, FeatureSupport,
    Observer, ProductView, Read, ReadPurpose, ShownAt, UnsupportedReason, ViewSubject,
    ViewSubjectKind,
};
use crate::product_views::from_serving::{agent_endpoint, EndpointSourceError, PublishedRow};
use crate::serving_protocol::{
    load_cases, AssemblyLimits, CapabilityRow, CapabilityTable, CellStatus, ConformanceCase,
    ConformanceRun, Dialect, Feature, LiveHarness, RecordedFrame, RecordedResponse, RunnerRef,
    ToolExecutor, UnsupportedFeature, ValidatedToolCall,
};

const CC: Dialect = Dialect::OpenAiChatCompletions;
const RS: Dialect = Dialect::OpenAiResponses;

const LIMITS: AssemblyLimits = AssemblyLimits {
    max_tool_calls: 16,
    max_argument_bytes: 4096,
    max_text_bytes: 4096,
};

fn model() -> Digest {
    digest("yougori/test/product/model/v1", &[b"coder-7b"])
}

fn runner() -> RunnerRef {
    RunnerRef {
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        category: ExecutionCategory::SharedKernelGpuRuntime,
    }
}

fn launch() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("launch", "coder-flags")]).unwrap()
}

/// Runs no tool call.
struct Nothing;

impl ToolExecutor for Nothing {
    fn execute(&mut self, _: &ValidatedToolCall) {}
}

/// The stand-in runner's answer to `case`: the response the case recorded, as the raw
/// event text the host captures from the wire.
fn served(case: &ConformanceCase) -> RecordedResponse {
    RecordedResponse {
        frames: case
            .response
            .frames
            .iter()
            .map(|frame| RecordedFrame {
                event: frame.event.clone(),
                data: None,
                data_text: Some(frame.to_sse().unwrap().data),
            })
            .collect(),
        ..case.response.clone()
    }
}

/// The host's harness against the stand-in runner for every case of `dialect`, on the
/// registry's clock. `wrong` names a case answered with another case's response.
fn live_run(dialect: Dialect, probes: &Probes, wrong: Option<(&str, &str)>) -> ConformanceRun {
    let cases = load_cases(dialect).unwrap();
    let find = |id: &str| cases.iter().find(|case| case.case.as_str() == id).unwrap();
    let mut harness = LiveHarness::new(dialect, model(), runner(), launch(), LIMITS);
    for case in &cases {
        let answer = match wrong {
            Some((id, with)) if case.case.as_str() == id => served(find(with)),
            _ => served(case),
        };
        harness.observe(case, &answer, &mut Nothing).unwrap();
    }
    harness.finish(&*probes.clock).unwrap()
}

fn declared_parallel() -> [(Feature, String); 1] {
    [(
        Feature::ParallelCalls,
        "this runner emits one call per turn".to_owned(),
    )]
}

#[test]
fn dialects_and_features_map_one_to_one_with_the_serving_protocols() {
    let dialects: Vec<EndpointDialect> = Dialect::ALL
        .into_iter()
        .map(EndpointDialect::from)
        .collect();
    assert_eq!(dialects, EndpointDialect::ALL);
    for dialect in Dialect::ALL {
        let shown = EndpointDialect::from(dialect);
        assert_eq!(Dialect::from(shown), dialect);
        assert_eq!(shown.label(), dialect.to_string());
        assert_eq!(
            serde_json::to_value(shown).unwrap(),
            serde_json::to_value(dialect).unwrap()
        );
        for feature in Feature::ALL {
            assert_eq!(
                EndpointFeature::from(feature).in_dialect(shown),
                feature.in_dialect(dialect)
            );
        }
    }
    let features: Vec<EndpointFeature> = Feature::ALL
        .into_iter()
        .map(EndpointFeature::from)
        .collect();
    assert_eq!(features, EndpointFeature::ALL);
    let every: Vec<EndpointFeature> = Feature::EVERY_EXCHANGE
        .into_iter()
        .map(EndpointFeature::from)
        .collect();
    assert_eq!(every, EndpointFeature::EVERY_EXCHANGE);
    for feature in Feature::ALL {
        assert_eq!(Feature::from(EndpointFeature::from(feature)), feature);
        assert_eq!(
            serde_json::to_value(EndpointFeature::from(feature)).unwrap(),
            serde_json::to_value(feature).unwrap()
        );
    }
}

#[test]
fn the_endpoint_declares_what_the_rows_say_on_the_hosts_own_runs() {
    let probes = Probes::new(SourceClass::HostProbe);
    let cc_run = live_run(CC, &probes, None);
    let rs_run = live_run(RS, &probes, None);
    let cc = CapabilityRow::from_run(model(), runner(), CC, &cc_run, &declared_parallel()).unwrap();
    let rs = CapabilityRow::from_run(model(), runner(), RS, &rs_run, &[]).unwrap();
    let mut table = CapabilityTable::new();
    table.publish(cc.clone());
    table.publish(rs.clone());
    let rows = [
        PublishedRow {
            row: &cc,
            run: &cc_run,
        },
        PublishedRow {
            row: &rs,
            run: &rs_run,
        },
    ];
    let endpoint = agent_endpoint(model(), &runner(), &rows, launch(), probes.now(), HOUR).unwrap();

    // Advertised exactly as the serving protocol advertises.
    let advertised: Vec<EndpointDialect> = table
        .advertised_dialects(model(), &runner(), launch())
        .into_iter()
        .map(EndpointDialect::from)
        .collect();
    assert_eq!(endpoint.advertised(), advertised);
    assert_eq!(advertised, [EndpointDialect::OpenAiChatCompletions]);
    assert!(!endpoint.runner().category.is_sandbox());

    // Each feature stands on what its cell says.
    for (row, run) in [(&cc, &cc_run), (&rs, &rs_run)] {
        let shown = endpoint
            .dialect(EndpointDialect::from(row.key().dialect))
            .unwrap();
        let conformance = shown.conformance().unwrap();
        assert_eq!(conformance.run, run.identity());
        assert_eq!(conformance.observed_at, run.observed_at());
        assert_eq!(
            conformance.cases,
            u64::try_from(run.verdicts().len()).unwrap()
        );
        for feature in Feature::ALL {
            let line = shown.feature(EndpointFeature::from(feature)).unwrap();
            let evidence = line.support().evidence();
            match row.cell(feature) {
                CellStatus::Supported { evidence: cell } => {
                    assert_eq!(
                        line.support().value(),
                        Some(&FeatureSupport::Supported {
                            cases: u64::try_from(cell.cases.len()).unwrap()
                        })
                    );
                    assert!(matches!(
                        evidence,
                        Evidence::Observed { by: Observer::Host, observed_at, .. }
                            if *observed_at == run.observed_at()
                    ));
                }
                CellStatus::Unsupported {
                    reason:
                        UnsupportedFeature::DeclaredByRunner { .. } | UnsupportedFeature::NotInDialect,
                } => assert!(matches!(
                    evidence,
                    Evidence::Asserted {
                        by: Asserter::Declaration,
                        ..
                    }
                )),
                CellStatus::Unsupported { .. } => panic!("no case failed"),
                CellStatus::Untested => {
                    assert_eq!(
                        evidence.refusal().unwrap().code.as_str(),
                        "evidence_missing"
                    );
                }
            }
            assert!(!evidence.is_verified());
        }
    }
    let messages = endpoint
        .dialect(EndpointDialect::AnthropicMessages)
        .unwrap();
    assert!(messages.conformance().is_none());
    assert!(!messages.is_advertised());

    // Under another launch configuration nothing is advertised, as the protocol refuses.
    let other = ConfigurationFingerprint::from_settings([("launch", "other-flags")]).unwrap();
    let reconfigured =
        agent_endpoint(model(), &runner(), &rows, other, probes.now(), HOUR).unwrap();
    assert!(reconfigured.advertised().is_empty());
    assert!(table
        .advertised_dialects(model(), &runner(), other)
        .is_empty());
}

#[test]
fn a_failed_case_is_shown_as_the_hosts_observation_of_it() {
    let probes = Probes::new(SourceClass::HostProbe);
    let parallel = load_cases(CC)
        .unwrap()
        .into_iter()
        .find(|case| case.case.as_str() == "cc-parallel-two-tools")
        .unwrap();
    let other = load_cases(CC)
        .unwrap()
        .into_iter()
        .find(|case| case.case != parallel.case && case.expect.tool_calls.is_empty())
        .unwrap();
    let run = live_run(
        CC,
        &probes,
        Some((parallel.case.as_str(), other.case.as_str())),
    );
    let row = CapabilityRow::from_run(model(), runner(), CC, &run, &[]).unwrap();
    let endpoint = agent_endpoint(
        model(),
        &runner(),
        &[PublishedRow {
            row: &row,
            run: &run,
        }],
        launch(),
        probes.now(),
        HOUR,
    )
    .unwrap();
    let shown = endpoint
        .dialect(EndpointDialect::OpenAiChatCompletions)
        .unwrap();
    assert_eq!(
        shown.conformance().unwrap().failed,
        std::slice::from_ref(&parallel.case)
    );
    let mut failed = 0;
    for feature in Feature::ALL {
        if let CellStatus::Unsupported {
            reason: UnsupportedFeature::ConformanceFailed { case, .. },
        } = row.cell(feature)
        {
            failed += 1;
            let line = shown.feature(EndpointFeature::from(feature)).unwrap();
            assert!(line.support().evidence().is_observed());
            assert!(matches!(
                line.support().value(),
                Some(FeatureSupport::Unsupported {
                    reason: UnsupportedReason::ConformanceFailed { case: shown_case, .. }
                }) if shown_case == case
            ));
        }
    }
    assert!(failed > 0);
    assert_eq!(
        shown.is_advertised(),
        row.advertisement().is_ok(),
        "advertised exactly as the protocol advertises"
    );
    let cell = CellShown::from(row.cell(Feature::ParallelCalls));
    assert!(matches!(cell, CellShown::Unsupported { .. }));
}

#[test]
fn a_row_is_shown_only_with_its_own_run_for_its_own_model_and_runner() {
    let probes = Probes::new(SourceClass::HostProbe);
    let cc_run = live_run(CC, &probes, None);
    let rs_run = live_run(RS, &probes, None);
    let cc = CapabilityRow::from_run(model(), runner(), CC, &cc_run, &[]).unwrap();
    probes.advance(Duration::from_secs(1));
    let later = live_run(CC, &probes, None);
    let now = probes.now();
    let endpoint = |rows: &[PublishedRow<'_>]| {
        agent_endpoint(model(), &runner(), rows, launch(), now, HOUR).map(|_| ())
    };
    let dialect = EndpointDialect::OpenAiChatCompletions;
    assert_eq!(
        endpoint(&[PublishedRow {
            row: &cc,
            run: &rs_run
        }]),
        Err(EndpointSourceError::NotTheRowsRun { dialect })
    );
    assert_eq!(
        endpoint(&[PublishedRow {
            row: &cc,
            run: &later
        }]),
        Err(EndpointSourceError::NotTheRowsRun { dialect })
    );
    let both = PublishedRow {
        row: &cc,
        run: &cc_run,
    };
    assert_eq!(
        endpoint(&[both, both]),
        Err(EndpointSourceError::DuplicateDialect { dialect })
    );
    let other_runner = RunnerRef {
        release: BackendRelease::new(Backend::Vllm, "0.32.0").unwrap(),
        category: ExecutionCategory::SharedKernelGpuRuntime,
    };
    assert_eq!(
        agent_endpoint(model(), &other_runner, &[both], launch(), now, HOUR).map(|_| ()),
        Err(EndpointSourceError::OtherSubject { dialect })
    );
    assert_eq!(endpoint(&[both]), Ok(()));
}

/// The endpoint fixture: the test model on the shared-kernel GPU runtime, Chat
/// Completions advertised with parallel calls declared unsupported, Responses not
/// advertised for want of a token-counting case, and no Messages row.
fn agent_endpoint_declared() -> ProductView {
    let probes = Probes::new(SourceClass::HostProbe);
    let cc_run = live_run(CC, &probes, None);
    let rs_run = live_run(RS, &probes, None);
    let cc = CapabilityRow::from_run(model(), runner(), CC, &cc_run, &declared_parallel()).unwrap();
    let rs = CapabilityRow::from_run(model(), runner(), RS, &rs_run, &[]).unwrap();
    probes.advance(Duration::from_secs(1));
    let now = probes.now();
    let mut view = ProductView::new(
        ViewSubject::new(ViewSubjectKind::Model, "coder-7b").unwrap(),
        ShownAt::of(now, config()),
    );
    view.endpoint = Some(
        agent_endpoint(
            model(),
            &runner(),
            &[
                PublishedRow {
                    row: &cc,
                    run: &cc_run,
                },
                PublishedRow {
                    row: &rs,
                    run: &rs_run,
                },
            ],
            launch(),
            now,
            HOUR,
        )
        .unwrap(),
    );
    view.shown_at.clock = ClockSession::from_uuid(uuid::Uuid::from_u128(
        0x0123_4567_89ab_4cde_8f01_2345_6789_abcd,
    ));
    view
}

#[test]
fn the_endpoint_fixture_is_what_the_conversion_produces() {
    let fixture = GOLDEN_FIXTURES
        .iter()
        .find(|fixture| fixture.name == "agent_endpoint_declared")
        .unwrap();
    assert_eq!(fixture.version, 2);
    let built = agent_endpoint_declared();
    let expected: Value = serde_json::from_str(fixture.json).unwrap();
    assert_eq!(serde_json::to_value(&built).unwrap(), expected);
    assert_eq!(built.to_json_pretty().unwrap() + "\n", fixture.json);
    match read_view(fixture.json, ReadPurpose::Act).unwrap() {
        Read::Current(read) => assert_eq!(read, built),
        other => panic!("read as {other:?}"),
    }
}
