//! FAST-01 on a fake runner (S13 line 241): the corpus served as fresh-prefill tests and
//! as deliberate warm-prefix tests, kept in separate ledgers. Every fresh attempt
//! discloses its cold-test nonce, every request is checked against its fixture first,
//! and each ledger reports every attempt with untrimmed tails and the best run only as a
//! diagnostic.

use super::corpus::{Corpus, FreshPrefillSuite, RenderedRequest};
use super::load::RunnerFactory;
use super::rng::SeededRng;
use super::runner::{RequestPlan, RetryPolicy, Script, UserScript};
use super::BenchError;
use crate::foundation::ids::Clock;
use crate::foundation::report::{
    ArrivalMode, AttemptLedger, BenchId, IntervalKind, Label, LatencySummary, LoadDescription,
    NoncePlacement, PercentileMethod, PrefillMode, RunRecord,
};

/// The variant of fresh-prefill attempts.
pub const FRESH_VARIANT: &str = "fast01-fresh-prefill";
/// The variant of the request that first reads the shared prefix.
pub const PRIMING_VARIANT: &str = "fast01-warm-priming";
/// The variant of deliberate warm-prefix attempts.
pub const WARM_VARIANT: &str = "fast01-warm-prefix";

/// What a FAST-01 run sends.
#[derive(Clone, Debug, PartialEq)]
pub struct Fast01Spec {
    pub model: Label,
    pub placement: NoncePlacement,
    /// How many times each fresh fixture is sent, each time with a new nonce.
    pub repetitions: u32,
    pub max_output_tokens: u32,
}

/// The FAST-01 ledgers, kept apart, with their first-token summaries.
#[derive(Clone, Debug, PartialEq)]
pub struct Fast01Report {
    pub fresh: AttemptLedger,
    pub priming: AttemptLedger,
    pub warm: AttemptLedger,
    pub fresh_time_to_first_token: LatencySummary,
    pub warm_time_to_first_token: LatencySummary,
}

/// Refuses a ledger that holds a successful attempt of the other prefill mode
/// (FAST-01: "fresh-prefill and deliberate warm-prefix tests are separate").
pub fn check_prefill(ledger: &AttemptLedger, mode: PrefillMode) -> Result<(), BenchError> {
    let mixed = ledger
        .records()
        .iter()
        .filter(|record| record.is_success())
        .any(|record| record.state.value().map(|state| state.prefill) != Some(mode));
    if mixed {
        Err(BenchError::MixedPrefillModes)
    } else {
        Ok(())
    }
}

fn plan(spec: &Fast01Spec, variant: &Label, request: RenderedRequest) -> RequestPlan {
    RequestPlan {
        variant: variant.clone(),
        model: spec.model.clone(),
        request,
        max_output_tokens: spec.max_output_tokens,
        deadline_nanos: u64::MAX / 4,
        timeout_nanos: u64::MAX / 4,
        gap_before_nanos: 0,
        switch_from_previous: false,
        burst: 0,
        check_response: false,
    }
}

fn ledger_of(records: &[RunRecord], variant: &Label) -> Result<AttemptLedger, BenchError> {
    Ok(AttemptLedger::from_records(
        records
            .iter()
            .filter(|record| &record.attempt.variant == variant)
            .cloned(),
    )?)
}

/// Serves the fresh-prefill suite, then the priming request, then the warm-prefix
/// suite, on one fake runner, and splits the attempts into their three ledgers.
pub fn run_fast01(
    factory: &RunnerFactory,
    corpus: &Corpus,
    spec: &Fast01Spec,
) -> Result<Fast01Report, BenchError> {
    let (mut runner, _start) = factory.started(30_000, &spec.model, BenchId::Bench01)?;
    let mut rng = SeededRng::new(runner.seed()).fork();
    let fresh = FreshPrefillSuite::new(corpus, &mut rng, spec.placement, spec.repetitions)?;
    for (request, fixture) in fresh
        .requests()
        .iter()
        .zip(corpus.fixtures().iter().cycle())
    {
        request.check_against(fixture)?;
    }
    let warm = corpus.warm_prefix_suite()?;
    let priming = warm.priming()?;
    priming.check_against(warm.priming_fixture())?;
    let warm_requests = warm.requests()?;
    for (request, question) in warm_requests.iter().zip(warm.questions()) {
        request.check_against(question)?;
    }
    let (fresh_variant, priming_variant, warm_variant) = (
        Label::new(FRESH_VARIANT)?,
        Label::new(PRIMING_VARIANT)?,
        Label::new(WARM_VARIANT)?,
    );
    let mut requests: Vec<RequestPlan> = fresh
        .requests()
        .iter()
        .map(|request| plan(spec, &fresh_variant, request.clone()))
        .collect();
    requests.push(plan(spec, &priming_variant, priming));
    requests.extend(
        warm_requests
            .into_iter()
            .map(|request| plan(spec, &warm_variant, request)),
    );
    let script = Script {
        bench: BenchId::Bench01,
        load: LoadDescription {
            concurrent_requests: 1,
            arrival: ArrivalMode::Sequential,
        },
        users: vec![UserScript {
            start_at: runner.clock().now(),
            requests,
            retry: RetryPolicy::NONE,
        }],
        recycle_after_switches: None,
    };
    let outcome = runner.serve(&script)?;
    let fresh = ledger_of(&outcome.records, &fresh_variant)?;
    let priming = ledger_of(&outcome.records, &priming_variant)?;
    let warm = ledger_of(&outcome.records, &warm_variant)?;
    check_prefill(&fresh, PrefillMode::Fresh)?;
    check_prefill(&warm, PrefillMode::WarmPrefix)?;
    let method = PercentileMethod::NearestRank;
    Ok(Fast01Report {
        fresh_time_to_first_token: LatencySummary::from_ledger(
            &fresh,
            IntervalKind::TimeToFirstToken,
            method,
        )?,
        warm_time_to_first_token: LatencySummary::from_ledger(
            &warm,
            IntervalKind::TimeToFirstToken,
            method,
        )?,
        fresh,
        priming,
        warm,
    })
}
