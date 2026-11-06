//! The economic report of S8: the narrow accelerator-only estimate and the total cost per
//! successful agent task, from time-stamped measured prices, with input, output and
//! cached tokens counted separately (S7 "Cost and capacity", BENCH-08).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::error::ReportError;
use super::ledger::AttemptLedger;
use super::measured::{Measured, NonNegative, NotMeasuredReason};
use super::stats::{Quotient, SuccessRate, UndefinedReason};
use super::text::{Label, PublicUrl};

/// What a price is per.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriceUnit {
    GpuHour,
    VmHour,
    KilowattHour,
    MillionInputTokens,
    MillionCachedInputTokens,
    MillionOutputTokens,
    GibMonth,
    GibTransferred,
}

strict_tagged_enum! {
/// Where a price came from. S8: "Use current measured cost inputs at analysis time; an
/// illustrative rental quote from the paper is not a default Yougori price", so there is
/// no variant for an illustrative or third-party quote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PriceProvenance (tag = "kind", wire = PriceProvenanceWire, wire_name = "PriceProvenanceWire") {
    /// The provider's metered bill for the observed usage.
    MeteredBilling,
    /// A provider's published price list, read at `observed_at`.
    ProviderPriceList { url: PublicUrl },
    /// The owner's declared rate for their own hardware or electricity.
    OwnerDeclaredRate,
}
}

/// A time-stamped price with its source (S7 "Time-stamp actual prices"; S8 "price
/// source/time").
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceQuote {
    pub usd_per_unit: NonNegative,
    pub unit: PriceUnit,
    pub source: Label,
    pub provenance: PriceProvenance,
    /// Calendar time the price was observed; supplied by the caller, never read here.
    pub observed_at: DateTime<Utc>,
}

/// The analysis time and the oldest price it accepts as current (S8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceWindow {
    pub analysis_at: DateTime<Utc>,
    pub max_age_seconds: u64,
}

impl PriceWindow {
    /// Refuses a quote observed after the analysis or older than the declared age.
    pub fn check(&self, quote: &PriceQuote) -> Result<(), ReportError> {
        if quote.observed_at > self.analysis_at {
            return Err(ReportError::PriceFromFuture);
        }
        let age_seconds = (self.analysis_at - quote.observed_at).num_seconds();
        if age_seconds > i64::try_from(self.max_age_seconds).unwrap_or(i64::MAX) {
            return Err(ReportError::StalePrice);
        }
        Ok(())
    }

    fn check_unit(&self, quote: &PriceQuote, allowed: &[PriceUnit]) -> Result<(), ReportError> {
        self.check(quote)?;
        if allowed.contains(&quote.unit) {
            Ok(())
        } else {
            Err(ReportError::WrongPriceUnit)
        }
    }
}

/// Always [`EstimateScope::AcceleratorOnlyNarrowEstimate`]: the first S8 equation "is a
/// narrow accelerator estimate at a stated workload and interactivity level".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EstimateScope {
    AcceleratorOnlyNarrowEstimate,
}

/// The workload and interactivity level the narrow estimate is stated at.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatedWorkload {
    pub concurrency: u32,
    pub input_tokens_per_request: u64,
    pub output_tokens_per_request: u64,
    pub per_user_output_tokens_per_second: NonNegative,
}

/// S8 equation 1, labelled as a narrow estimate.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AcceleratorOnlyEstimate {
    pub scope: EstimateScope,
    pub gpu_price: PriceQuote,
    pub measured_output_tokens_per_second: NonNegative,
    pub workload: StatedWorkload,
    pub usd_per_million_output_tokens: Quotient,
}

/// S8 equation 1:
/// `measured_GPU_cost_per_hour / (measured_output_tokens_per_second * 3600) * 1,000,000`.
/// Zero throughput gives "undefined", not infinity.
pub fn accelerator_only_cost_per_million_output_tokens(
    gpu_price: PriceQuote,
    measured_output_tokens_per_second: NonNegative,
    workload: StatedWorkload,
    prices: &PriceWindow,
) -> Result<AcceleratorOnlyEstimate, ReportError> {
    prices.check_unit(&gpu_price, &[PriceUnit::GpuHour])?;
    let usd_per_million_output_tokens = Quotient::divide(
        gpu_price.usd_per_unit.get() * 1_000_000.0,
        measured_output_tokens_per_second.get() * 3600.0,
        UndefinedReason::ZeroThroughput,
    );
    Ok(AcceleratorOnlyEstimate {
        scope: EstimateScope::AcceleratorOnlyNarrowEstimate,
        gpu_price,
        measured_output_tokens_per_second,
        workload,
        usd_per_million_output_tokens,
    })
}

/// A quantity at a quoted price.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PricedQuantity {
    pub quantity: NonNegative,
    pub quote: PriceQuote,
}

/// The cost components of S7 and S8: compute, storage, transfer, retry, idle and replica
/// time, VM resources and interruptions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostComponent {
    Compute,
    Storage,
    Transfer,
    Retry,
    Idle,
    Replica,
    VmResources,
    Interruption,
}

impl CostComponent {
    /// Every component equation 2 sums.
    pub const ALL: [Self; 8] = [
        Self::Compute,
        Self::Storage,
        Self::Transfer,
        Self::Retry,
        Self::Idle,
        Self::Replica,
        Self::VmResources,
        Self::Interruption,
    ];

    const fn units(self) -> &'static [PriceUnit] {
        match self {
            Self::Compute => &[
                PriceUnit::GpuHour,
                PriceUnit::VmHour,
                PriceUnit::KilowattHour,
            ],
            Self::Storage => &[PriceUnit::GibMonth],
            Self::Transfer => &[PriceUnit::GibTransferred],
            Self::Retry | Self::Idle | Self::Replica | Self::Interruption => {
                &[PriceUnit::GpuHour, PriceUnit::VmHour]
            }
            Self::VmResources => &[PriceUnit::VmHour],
        }
    }
}

/// Every component, each measured or explicitly not measured. "Not applicable" counts as
/// zero; any other unmeasured component leaves the total undefined rather than
/// understated.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCostComponents {
    pub compute: Measured<Vec<PricedQuantity>>,
    pub storage: Measured<Vec<PricedQuantity>>,
    pub transfer: Measured<Vec<PricedQuantity>>,
    pub retry: Measured<Vec<PricedQuantity>>,
    pub idle: Measured<Vec<PricedQuantity>>,
    pub replica: Measured<Vec<PricedQuantity>>,
    pub vm_resources: Measured<Vec<PricedQuantity>>,
    pub interruption: Measured<Vec<PricedQuantity>>,
}

impl TaskCostComponents {
    pub fn get(&self, component: CostComponent) -> &Measured<Vec<PricedQuantity>> {
        match component {
            CostComponent::Compute => &self.compute,
            CostComponent::Storage => &self.storage,
            CostComponent::Transfer => &self.transfer,
            CostComponent::Retry => &self.retry,
            CostComponent::Idle => &self.idle,
            CostComponent::Replica => &self.replica,
            CostComponent::VmResources => &self.vm_resources,
            CostComponent::Interruption => &self.interruption,
        }
    }
}

/// The inputs of S8 equation 2 over a declared observation window.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCostInputs {
    pub observation_window_start: DateTime<Utc>,
    pub observation_window_seconds: u64,
    pub components: TaskCostComponents,
}

/// S8 equation 2 with its inputs and denominators.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TaskCostReport {
    pub observation_window_start: DateTime<Utc>,
    pub observation_window_seconds: u64,
    pub component_costs_usd: BTreeMap<CostComponent, Measured<f64>>,
    pub total_cost_usd: Quotient,
    pub initial_attempts: u64,
    pub completed_valid_tasks: u64,
    pub usd_per_completed_valid_task: Quotient,
}

/// `total_usd / completed_valid_tasks`; undefined, not infinite, at zero tasks.
pub fn cost_per_completed_task(total_usd: NonNegative, completed_valid_tasks: u64) -> Quotient {
    Quotient::divide(
        total_usd.get(),
        completed_valid_tasks as f64,
        UndefinedReason::NoCompletedValidTasks,
    )
}

/// S8 equation 2:
/// `all_assigned_compute_storage_transfer_retry_idle_cost / completed_valid_tasks`.
/// The numerator includes unsuccessful attempts and fixed idle and replica costs over the
/// declared window; the denominator counts each validly completed task once, from the
/// raw attempts in `ledger`.
pub fn total_cost_per_successful_agent_task(
    inputs: &TaskCostInputs,
    ledger: &AttemptLedger,
    prices: &PriceWindow,
) -> Result<TaskCostReport, ReportError> {
    if inputs.observation_window_seconds == 0 {
        return Err(ReportError::EmptyObservationWindow);
    }
    let mut component_costs_usd = BTreeMap::new();
    let mut total = Some(0.0f64);
    for component in CostComponent::ALL {
        let cost = match inputs.components.get(component) {
            Measured::Measured { value } => {
                let mut sum = 0.0;
                for priced in value {
                    prices.check_unit(&priced.quote, component.units())?;
                    sum += priced.quantity.get() * priced.quote.usd_per_unit.get();
                }
                Measured::measured(sum)
            }
            Measured::NotMeasured { reason } => Measured::not_measured(*reason),
        };
        total = match (&cost, total) {
            (Measured::Measured { value }, Some(total)) => Some(total + value),
            (
                Measured::NotMeasured {
                    reason: NotMeasuredReason::NotApplicable,
                },
                total,
            ) => total,
            _ => None,
        };
        component_costs_usd.insert(component, cost);
    }
    let completed_valid_tasks = ledger.completed_valid_tasks();
    let (total_cost_usd, usd_per_completed_valid_task) = match total {
        Some(total) => (
            Quotient::Defined { value: total },
            cost_per_completed_task(NonNegative::new(total)?, completed_valid_tasks),
        ),
        None => {
            let undefined = Quotient::Undefined {
                reason: UndefinedReason::ComponentNotMeasured,
            };
            (undefined, undefined)
        }
    };
    Ok(TaskCostReport {
        observation_window_start: inputs.observation_window_start,
        observation_window_seconds: inputs.observation_window_seconds,
        component_costs_usd,
        total_cost_usd,
        initial_attempts: ledger.initial_attempts().count() as u64,
        completed_valid_tasks,
        usd_per_completed_valid_task,
    })
}

/// Tokens counted separately by class (S8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub output_tokens: u64,
}

/// One quote per token class; each must be priced per million tokens of its own class.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenPrices {
    pub input: PriceQuote,
    pub cached_input: PriceQuote,
    pub output: PriceQuote,
}

/// The cost of each token class, kept separate (S8), and their total.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct TokenCostBreakdown {
    pub input_usd: f64,
    pub cached_input_usd: f64,
    pub output_usd: f64,
    pub total_usd: f64,
}

/// Prices input, cached input and output tokens separately (S7, S8).
pub fn token_cost(
    usage: &TokenUsage,
    prices: &TokenPrices,
    window: &PriceWindow,
) -> Result<TokenCostBreakdown, ReportError> {
    window.check_unit(&prices.input, &[PriceUnit::MillionInputTokens])?;
    window.check_unit(&prices.cached_input, &[PriceUnit::MillionCachedInputTokens])?;
    window.check_unit(&prices.output, &[PriceUnit::MillionOutputTokens])?;
    let per_million =
        |tokens: u64, quote: &PriceQuote| tokens as f64 / 1_000_000.0 * quote.usd_per_unit.get();
    let input_usd = per_million(usage.input_tokens, &prices.input);
    let cached_input_usd = per_million(usage.cached_input_tokens, &prices.cached_input);
    let output_usd = per_million(usage.output_tokens, &prices.output);
    Ok(TokenCostBreakdown {
        input_usd,
        cached_input_usd,
        output_usd,
        total_usd: input_usd + cached_input_usd + output_usd,
    })
}

/// BENCH-08 total cost per million output tokens; undefined with no output tokens.
pub fn total_cost_per_million_output_tokens(
    total_usd: NonNegative,
    output_tokens: u64,
) -> Quotient {
    Quotient::divide(
        total_usd.get() * 1_000_000.0,
        output_tokens as f64,
        UndefinedReason::NoOutputTokens,
    )
}

/// S7 tokens per GPU-hour; undefined with no GPU time.
pub fn tokens_per_gpu_hour(tokens: u64, gpu_seconds: NonNegative) -> Quotient {
    Quotient::divide(
        tokens as f64 * 3600.0,
        gpu_seconds.get(),
        UndefinedReason::NoGpuTime,
    )
}

/// One point of a measured concurrency curve (S7 per-user speed at the measured
/// concurrency).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConcurrencyPoint {
    pub concurrency: u32,
    pub per_user_output_tokens_per_second: NonNegative,
    pub aggregate_output_tokens_per_second: NonNegative,
}

/// The evidence an economic comparison needs (S8: "No margin or economic advantage is
/// assumed before the measured task success and concurrency curves are available").
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EconomicEvidence {
    pub usd_per_completed_valid_task: Quotient,
    pub task_success: SuccessRate,
    pub concurrency_curve: Vec<ConcurrencyPoint>,
}

/// Cost per completed task of two sides that both have the required evidence (S8).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EconomicComparison {
    pub candidate_usd_per_task: f64,
    pub baseline_usd_per_task: f64,
    /// (baseline − candidate) / baseline.
    pub relative_saving: Quotient,
}

/// Compares cost per completed task only when both sides have a measured concurrency
/// curve and a defined cost per task.
pub fn economic_advantage(
    candidate: &EconomicEvidence,
    baseline: &EconomicEvidence,
) -> Result<EconomicComparison, ReportError> {
    if candidate.concurrency_curve.is_empty() || baseline.concurrency_curve.is_empty() {
        return Err(ReportError::MissingConcurrencyCurve);
    }
    let (Some(candidate_usd_per_task), Some(baseline_usd_per_task)) = (
        candidate.usd_per_completed_valid_task.value(),
        baseline.usd_per_completed_valid_task.value(),
    ) else {
        return Err(ReportError::CostUndefined);
    };
    Ok(EconomicComparison {
        candidate_usd_per_task,
        baseline_usd_per_task,
        relative_saving: Quotient::divide(
            baseline_usd_per_task - candidate_usd_per_task,
            baseline_usd_per_task,
            UndefinedReason::ZeroBaseline,
        ),
    })
}

/// What a lifecycle cost is counted in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleUnit {
    Usd,
    GpuSeconds,
    Joules,
}

/// §2.1 lifecycle cost: "Preparation + retention + requests + reclamation over a stated
/// horizon".
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCost {
    pub horizon_seconds: u64,
    pub unit: LifecycleUnit,
    pub preparation: Measured<NonNegative>,
    pub retention: Measured<NonNegative>,
    pub requests: Measured<NonNegative>,
    pub reclamation: Measured<NonNegative>,
}

impl LifecycleCost {
    /// The sum of the four parts; undefined when one is unmeasured for any reason other
    /// than "not applicable", and refused without a stated horizon.
    pub fn total(&self) -> Result<Quotient, ReportError> {
        if self.horizon_seconds == 0 {
            return Err(ReportError::EmptyObservationWindow);
        }
        let mut total = 0.0;
        for part in [
            &self.preparation,
            &self.retention,
            &self.requests,
            &self.reclamation,
        ] {
            match part {
                Measured::Measured { value } => total += value.get(),
                Measured::NotMeasured {
                    reason: NotMeasuredReason::NotApplicable,
                } => {}
                Measured::NotMeasured { .. } => {
                    return Ok(Quotient::Undefined {
                        reason: UndefinedReason::ComponentNotMeasured,
                    })
                }
            }
        }
        Ok(Quotient::Defined { value: total })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::report::fixtures::{failed, label, op, serving_record};
    use crate::foundation::report::record::{AttemptRole, FailureKind};
    use chrono::TimeZone;

    fn at(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 27, hour, 0, 0)
            .single()
            .unwrap()
    }

    fn quote(usd: f64, unit: PriceUnit) -> PriceQuote {
        PriceQuote {
            usd_per_unit: NonNegative::new(usd).unwrap(),
            unit,
            source: label("provider-x-on-demand"),
            provenance: PriceProvenance::MeteredBilling,
            observed_at: at(9),
        }
    }

    fn window() -> PriceWindow {
        PriceWindow {
            analysis_at: at(12),
            max_age_seconds: 24 * 3600,
        }
    }

    fn workload() -> StatedWorkload {
        StatedWorkload {
            concurrency: 8,
            input_tokens_per_request: 2048,
            output_tokens_per_request: 512,
            per_user_output_tokens_per_second: NonNegative::new(62.5).unwrap(),
        }
    }

    #[test]
    fn accelerator_only_worked_example() {
        // $2.00 per GPU-hour at 500 output tokens/s: 2 / (500 × 3600) × 10^6 = $1.111…
        let estimate = accelerator_only_cost_per_million_output_tokens(
            quote(2.0, PriceUnit::GpuHour),
            NonNegative::new(500.0).unwrap(),
            workload(),
            &window(),
        )
        .unwrap();
        let value = estimate.usd_per_million_output_tokens.value().unwrap();
        assert!((value - 10.0 / 9.0).abs() < 1e-12);
        assert_eq!(estimate.scope, EstimateScope::AcceleratorOnlyNarrowEstimate);
        let json = serde_json::to_value(&estimate).unwrap();
        assert_eq!(json["scope"], "accelerator_only_narrow_estimate");

        let stalled = accelerator_only_cost_per_million_output_tokens(
            quote(2.0, PriceUnit::GpuHour),
            NonNegative::ZERO,
            workload(),
            &window(),
        )
        .unwrap();
        assert_eq!(
            stalled.usd_per_million_output_tokens,
            Quotient::Undefined {
                reason: UndefinedReason::ZeroThroughput
            }
        );
        assert_eq!(
            accelerator_only_cost_per_million_output_tokens(
                quote(2.0, PriceUnit::VmHour),
                NonNegative::new(500.0).unwrap(),
                workload(),
                &window(),
            ),
            Err(ReportError::WrongPriceUnit)
        );
    }

    #[test]
    fn prices_are_time_stamped_and_current() {
        let mut future = quote(2.0, PriceUnit::GpuHour);
        future.observed_at = at(13);
        assert_eq!(window().check(&future), Err(ReportError::PriceFromFuture));
        let mut stale = quote(2.0, PriceUnit::GpuHour);
        stale.observed_at = Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).single().unwrap();
        assert_eq!(window().check(&stale), Err(ReportError::StalePrice));
        // An illustrative quote from a paper has no provenance to be recorded under.
        assert!(
            serde_json::from_str::<PriceProvenance>(r#"{"kind":"illustrative_quote"}"#).is_err()
        );
        assert!(
            serde_json::from_str::<PriceProvenance>(r#"{"kind":"third_party_claim"}"#).is_err()
        );
    }

    fn priced(quantity: f64, usd: f64, unit: PriceUnit) -> Measured<Vec<PricedQuantity>> {
        Measured::measured(vec![PricedQuantity {
            quantity: NonNegative::new(quantity).unwrap(),
            quote: quote(usd, unit),
        }])
    }

    fn inputs() -> TaskCostInputs {
        TaskCostInputs {
            observation_window_start: at(0),
            observation_window_seconds: 6 * 3600,
            components: TaskCostComponents {
                compute: priced(10.0, 2.0, PriceUnit::GpuHour),
                storage: priced(50.0, 0.02, PriceUnit::GibMonth),
                transfer: priced(10.0, 0.1, PriceUnit::GibTransferred),
                retry: priced(1.0, 2.0, PriceUnit::GpuHour),
                idle: priced(2.0, 2.0, PriceUnit::GpuHour),
                replica: priced(1.0, 2.0, PriceUnit::GpuHour),
                vm_resources: Measured::not_measured(NotMeasuredReason::NotApplicable),
                interruption: Measured::not_measured(NotMeasuredReason::NotApplicable),
            },
        }
    }

    fn tasks() -> AttemptLedger {
        let mut rejected = serving_record("op-3", 100);
        rejected.outcome = failed(FailureKind::Rejected);
        rejected.events.truncate(1);
        let mut retry = serving_record("op-3r1", 100);
        retry.attempt.role = AttemptRole::Retry {
            first_attempt: op("op-3"),
            retry_number: 1,
        };
        AttemptLedger::from_records(vec![
            serving_record("op-1", 100),
            serving_record("op-2", 100),
            rejected,
            retry,
        ])
        .unwrap()
    }

    #[test]
    fn total_cost_per_task_worked_example() {
        // 20 + 1 + 1 + 2 + 4 + 2 = $30 over 3 completed tasks (one after a retry).
        let report = total_cost_per_successful_agent_task(&inputs(), &tasks(), &window()).unwrap();
        let total = report.total_cost_usd.value().unwrap();
        assert!((total - 30.0).abs() < 1e-9);
        assert_eq!(report.completed_valid_tasks, 3);
        assert_eq!(report.initial_attempts, 3);
        let per_task = report.usd_per_completed_valid_task.value().unwrap();
        assert!((per_task - 10.0).abs() < 1e-9);
        assert_eq!(
            report.component_costs_usd[&CostComponent::VmResources],
            Measured::not_measured(NotMeasuredReason::NotApplicable)
        );
    }

    #[test]
    fn zero_completed_tasks_is_undefined_not_infinite() {
        assert_eq!(
            cost_per_completed_task(NonNegative::new(30.0).unwrap(), 0),
            Quotient::Undefined {
                reason: UndefinedReason::NoCompletedValidTasks
            }
        );
        let mut failure = serving_record("op-1", 100);
        failure.outcome = failed(FailureKind::Timeout);
        failure.events.truncate(1);
        let ledger = AttemptLedger::from_records(vec![failure]).unwrap();
        let report = total_cost_per_successful_agent_task(&inputs(), &ledger, &window()).unwrap();
        assert_eq!(
            report.usd_per_completed_valid_task,
            Quotient::Undefined {
                reason: UndefinedReason::NoCompletedValidTasks
            }
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("inf") && !json.contains("null"));
    }

    #[test]
    fn an_unmeasured_component_leaves_the_total_undefined() {
        let mut partial = inputs();
        partial.components.transfer = Measured::not_measured(NotMeasuredReason::NotRecorded);
        let report = total_cost_per_successful_agent_task(&partial, &tasks(), &window()).unwrap();
        assert_eq!(
            report.total_cost_usd,
            Quotient::Undefined {
                reason: UndefinedReason::ComponentNotMeasured
            }
        );
        let mut wrong = inputs();
        wrong.components.storage = priced(50.0, 0.02, PriceUnit::GpuHour);
        assert_eq!(
            total_cost_per_successful_agent_task(&wrong, &tasks(), &window()),
            Err(ReportError::WrongPriceUnit)
        );
        let mut empty = inputs();
        empty.observation_window_seconds = 0;
        assert_eq!(
            total_cost_per_successful_agent_task(&empty, &tasks(), &window()),
            Err(ReportError::EmptyObservationWindow)
        );
    }

    #[test]
    fn token_classes_are_priced_separately() {
        let prices = TokenPrices {
            input: quote(3.0, PriceUnit::MillionInputTokens),
            cached_input: quote(0.3, PriceUnit::MillionCachedInputTokens),
            output: quote(15.0, PriceUnit::MillionOutputTokens),
        };
        let usage = TokenUsage {
            input_tokens: 1_000_000,
            cached_input_tokens: 500_000,
            output_tokens: 200_000,
        };
        let cost = token_cost(&usage, &prices, &window()).unwrap();
        assert!((cost.input_usd - 3.0).abs() < 1e-12);
        assert!((cost.cached_input_usd - 0.15).abs() < 1e-12);
        assert!((cost.output_usd - 3.0).abs() < 1e-12);
        assert!((cost.total_usd - 6.15).abs() < 1e-12);
        let swapped = TokenPrices {
            input: prices.output.clone(),
            output: prices.input.clone(),
            ..prices
        };
        assert_eq!(
            token_cost(&usage, &swapped, &window()),
            Err(ReportError::WrongPriceUnit)
        );
        assert_eq!(
            total_cost_per_million_output_tokens(NonNegative::new(30.0).unwrap(), 0),
            Quotient::Undefined {
                reason: UndefinedReason::NoOutputTokens
            }
        );
        assert_eq!(
            total_cost_per_million_output_tokens(NonNegative::new(3.0).unwrap(), 1_000_000),
            Quotient::Defined { value: 3.0 }
        );
        assert_eq!(
            tokens_per_gpu_hour(1_800_000, NonNegative::new(3600.0).unwrap()),
            Quotient::Defined { value: 1_800_000.0 }
        );
        assert_eq!(
            tokens_per_gpu_hour(10, NonNegative::ZERO),
            Quotient::Undefined {
                reason: UndefinedReason::NoGpuTime
            }
        );
    }

    #[test]
    fn no_economic_advantage_without_curves_and_task_success() {
        let point = ConcurrencyPoint {
            concurrency: 8,
            per_user_output_tokens_per_second: NonNegative::new(40.0).unwrap(),
            aggregate_output_tokens_per_second: NonNegative::new(320.0).unwrap(),
        };
        let evidence = |usd: f64, curve: Vec<ConcurrencyPoint>| EconomicEvidence {
            usd_per_completed_valid_task: Quotient::Defined { value: usd },
            task_success: SuccessRate::new(9, 10).unwrap(),
            concurrency_curve: curve,
        };
        assert_eq!(
            economic_advantage(&evidence(8.0, vec![]), &evidence(10.0, vec![point.clone()])),
            Err(ReportError::MissingConcurrencyCurve)
        );
        let undefined = EconomicEvidence {
            usd_per_completed_valid_task: Quotient::Undefined {
                reason: UndefinedReason::NoCompletedValidTasks,
            },
            ..evidence(0.0, vec![point.clone()])
        };
        assert_eq!(
            economic_advantage(&undefined, &evidence(10.0, vec![point.clone()])),
            Err(ReportError::CostUndefined)
        );
        let comparison = economic_advantage(
            &evidence(8.0, vec![point.clone()]),
            &evidence(10.0, vec![point]),
        )
        .unwrap();
        assert_eq!(comparison.relative_saving.value(), Some(0.2));
    }

    #[test]
    fn lifecycle_cost_sums_four_parts_over_a_stated_horizon() {
        let part = |value: f64| Measured::measured(NonNegative::new(value).unwrap());
        let mut cost = LifecycleCost {
            horizon_seconds: 86_400,
            unit: LifecycleUnit::GpuSeconds,
            preparation: part(120.0),
            retention: part(600.0),
            requests: part(3_000.0),
            reclamation: Measured::not_measured(NotMeasuredReason::NotApplicable),
        };
        assert_eq!(cost.total().unwrap(), Quotient::Defined { value: 3_720.0 });
        cost.retention = Measured::not_measured(NotMeasuredReason::InstrumentUnavailable);
        assert_eq!(
            cost.total().unwrap(),
            Quotient::Undefined {
                reason: UndefinedReason::ComponentNotMeasured
            }
        );
        cost.horizon_seconds = 0;
        assert_eq!(cost.total(), Err(ReportError::EmptyObservationWindow));
    }
}
