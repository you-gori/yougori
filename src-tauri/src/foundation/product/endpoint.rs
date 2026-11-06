//! Declared agent endpoint capabilities (S2 CORE-07 "declared agent endpoint
//! capabilities"; GPU-W11: "Declare supported agent endpoint dialects and model/tool
//! combinations through CORE-07"; S7 line 126: "Declare each actually supported API
//! dialect and model/tool combination ... No generic proxy can promise complete semantic
//! conversion"; S9 line 165; S12 G2: "endpoint dialect, tool/stream behavior").
//!
//! The serving protocol's capability rows say, per model, runner and dialect, whether each
//! feature is supported with conformance evidence, unsupported with a reason, or untested;
//! a dialect is advertised only when no feature is untested and the features every
//! exchange uses are supported, under the configuration the evidence was observed with.
//! An [`AgentEndpoint`] is the contract's own shape of those rows for one model on one
//! runner: every dialect once, in [`EndpointDialect::ALL`] order, each with the
//! conformance run its row was built from and every feature once, each with its
//! [`EndpointAspect`] (every exchange, tool calling or streaming). The runner is shown
//! with its execution category's own label, so a labelled model runtime is never shown as
//! a sandbox. The engine's `product_views` module converts the serving protocol's rows and
//! runs into it.
//!
//! Each feature is a [`Fact`] with one evidence state, decided here from the row's cell
//! ([`DialectShown::published`]): support and a failed conformance case are observed by
//! the host, whose own harness sent the requests and judged the runner's answers, current
//! only while the run is fresh and only under the runner configuration it observed; a
//! runner's declaration that a feature is unsupported, and a feature the dialect does not
//! define, are assertions; an untested feature, and every feature of a row observed under
//! another configuration, are unavailable with a reason and a remedy. Support never stands
//! on an assertion and is never shown as verified: a conformance run is the host's
//! observation of one runner's answers, not a CORE-01 probe. Whether a dialect is
//! advertised is never stored on its own: it is recomputed from its features when a
//! document is read and when it is shown again ([`AgentEndpoint::as_of`]), so a stale or
//! untested feature never leaves a dialect advertised.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};

use super::evidence::{Asserter, Evidence, Fact, FactError, Observer};
use super::execution::CategoryShown;
use super::refusal::{EvidenceCode, Refusal, RefusalCode, Remedy};
use super::text::ShownText;
use super::view::ShownAt;
use crate::foundation::evidence::{
    BackendRelease, ClockReading, ConfigurationFingerprint, Remedy as EvidenceRemedy, SourceClass,
};
use crate::foundation::ids::{Digest, ExecutionCategory, MonotonicTime};
use crate::foundation::report::Label;

/// An agent-facing API dialect (S7 line 126), named as the serving protocol names it.
/// Each is shown on its own evidence; one is never derived from another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EndpointDialect {
    /// OpenAI Chat Completions.
    #[serde(rename = "openai_chat_completions")]
    OpenAiChatCompletions,
    /// OpenAI Responses.
    #[serde(rename = "openai_responses")]
    OpenAiResponses,
    /// Anthropic Messages.
    #[serde(rename = "anthropic_messages")]
    AnthropicMessages,
}

impl EndpointDialect {
    /// Every dialect, in the order an endpoint lists them.
    pub const ALL: [Self; 3] = [
        Self::OpenAiChatCompletions,
        Self::OpenAiResponses,
        Self::AnthropicMessages,
    ];

    /// The words a person reads, the same in the desktop and the CLI.
    pub const fn label(self) -> &'static str {
        match self {
            Self::OpenAiChatCompletions => "OpenAI Chat Completions",
            Self::OpenAiResponses => "OpenAI Responses",
            Self::AnthropicMessages => "Anthropic Messages",
        }
    }
}

impl fmt::Display for EndpointDialect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// What part of an agent's use of the endpoint a feature belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointAspect {
    /// Requests, context, finish reasons, usage and errors.
    Exchange,
    /// Tool schemas, tool choice and several calls in one turn.
    ToolCalling,
    /// Streamed deltas and cancellation.
    Streaming,
}

/// One feature of a dialect's capability row (S9 line 165), named as the serving protocol
/// names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointFeature {
    RequestFields,
    SystemContextPreservation,
    ToolSchema,
    ToolChoice,
    StreamingDeltas,
    ParallelCalls,
    FinishReason,
    Usage,
    TokenCounting,
    Errors,
    Cancellation,
}

impl EndpointFeature {
    /// Every feature, in row order.
    pub const ALL: [Self; 11] = [
        Self::RequestFields,
        Self::SystemContextPreservation,
        Self::ToolSchema,
        Self::ToolChoice,
        Self::StreamingDeltas,
        Self::ParallelCalls,
        Self::FinishReason,
        Self::Usage,
        Self::TokenCounting,
        Self::Errors,
        Self::Cancellation,
    ];

    /// The features every exchange uses: a dialect is advertised only when all of them
    /// are supported.
    pub const EVERY_EXCHANGE: [Self; 3] = [Self::RequestFields, Self::FinishReason, Self::Errors];

    /// Whether `dialect` defines the feature at all: Chat Completions has no token
    /// counting endpoint.
    pub const fn in_dialect(self, dialect: EndpointDialect) -> bool {
        !matches!(
            (self, dialect),
            (Self::TokenCounting, EndpointDialect::OpenAiChatCompletions)
        )
    }

    /// The aspect the feature belongs to.
    pub const fn aspect(self) -> EndpointAspect {
        match self {
            Self::ToolSchema | Self::ToolChoice | Self::ParallelCalls => {
                EndpointAspect::ToolCalling
            }
            Self::StreamingDeltas | Self::Cancellation => EndpointAspect::Streaming,
            Self::RequestFields
            | Self::SystemContextPreservation
            | Self::FinishReason
            | Self::Usage
            | Self::TokenCounting
            | Self::Errors => EndpointAspect::Exchange,
        }
    }

    /// The words a person reads, the same in the desktop and the CLI.
    pub const fn label(self) -> &'static str {
        match self {
            Self::RequestFields => "request fields accepted and honoured",
            Self::SystemContextPreservation => "system instructions and earlier turns kept",
            Self::ToolSchema => "tool calls checked against their declared schemas",
            Self::ToolChoice => "an explicit tool choice honoured",
            Self::StreamingDeltas => "streamed output in the dialect's event order",
            Self::ParallelCalls => "several tool calls in one turn",
            Self::FinishReason => "a finish reason the dialect defines, matching the content",
            Self::Usage => "token usage reported",
            Self::TokenCounting => "the dialect's token counting endpoint",
            Self::Errors => "failures in the dialect's error shapes",
            Self::Cancellation => "a cancelled request stops without running a pending tool call",
        }
    }
}

strict_product_enum! {
    /// Why a feature is unsupported; an unsupported feature always says why.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum UnsupportedReason tag "reason" {
        /// The dialect does not define it.
        NotInDialect,
        /// A conformance case exercising it failed in the row's run.
        ConformanceFailed { case: Label, mismatch: ShownText },
        /// The runner's adapter declares it unsupported.
        DeclaredByRunner { explanation: ShownText },
    }
}

impl fmt::Display for UnsupportedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInDialect => f.write_str("the dialect does not define it"),
            Self::ConformanceFailed { case, mismatch } => {
                write!(f, "conformance case {} failed: {mismatch}", case.as_str())
            }
            Self::DeclaredByRunner { explanation } => {
                write!(f, "the runner does not support it: {explanation}")
            }
        }
    }
}

strict_product_enum! {
    /// A feature's value: supported, citing how many passing conformance cases of the
    /// dialect's run exercised it, or unsupported with why.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum FeatureSupport tag "support" {
        Supported { cases: u64 },
        Unsupported { reason: UnsupportedReason },
    }
}

/// A row's cell for one feature in the contract's words, as a conversion reads it from
/// the serving protocol; [`DialectShown::published`] decides the evidence it stands on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CellShown {
    /// Every case of the run that exercised it passed; `cases` of them did.
    Supported {
        cases: u64,
    },
    Unsupported {
        reason: UnsupportedReason,
    },
    /// No case of the run exercised it.
    Untested,
}

/// The conformance run a dialect's row was built from: the host's own harness against
/// the row's model and runner, under the runner configuration it observed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceShown {
    /// The run's identity, which the row's supported cells cite.
    pub run: Digest,
    /// The runner launch configuration the run observed.
    pub configuration: ConfigurationFingerprint,
    /// When the run was recorded, on the evidence clock.
    pub observed_at: MonotonicTime,
    /// How many cases the run judged.
    pub cases: u64,
    /// The cases that failed, each once.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<Label>,
}

/// One feature as shown: its aspect, its words and its value on its one evidence state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FeatureLine {
    feature: EndpointFeature,
    aspect: EndpointAspect,
    label: &'static str,
    support: Fact<FeatureSupport>,
}

impl FeatureLine {
    fn new(feature: EndpointFeature, support: Fact<FeatureSupport>) -> Self {
        Self {
            feature,
            aspect: feature.aspect(),
            label: feature.label(),
            support,
        }
    }

    pub fn feature(&self) -> EndpointFeature {
        self.feature
    }

    pub fn aspect(&self) -> EndpointAspect {
        self.aspect
    }

    /// The words a person reads.
    pub fn label(&self) -> &'static str {
        self.label
    }

    /// The value and its evidence; no value while unavailable.
    pub fn support(&self) -> &Fact<FeatureSupport> {
        &self.support
    }

    /// Whether the feature is supported on current evidence.
    pub fn is_supported(&self) -> bool {
        matches!(self.support.value(), Some(FeatureSupport::Supported { .. }))
    }

    /// The value stands on the evidence its kind allows (see the module notes), a feature
    /// the dialect does not define is shown exactly as such, and a conformance value
    /// matches the dialect's run.
    fn check(
        &self,
        dialect: EndpointDialect,
        run: Option<&ConformanceShown>,
    ) -> Result<(), EndpointError> {
        let feature = self.feature;
        let wrong = EndpointError::WrongEvidence { dialect, feature };
        let not_from_run = EndpointError::NotFromRun { dialect, feature };
        let undefined = EndpointError::NotInDialect { dialect, feature };
        let Some(value) = self.support.value() else {
            // Unavailable: why is in the refusal; a feature the dialect does not define is
            // never unavailable.
            return if feature.in_dialect(dialect) {
                Ok(())
            } else {
                Err(undefined)
            };
        };
        let evidence = self.support.evidence();
        let shown_undefined = matches!(
            value,
            FeatureSupport::Unsupported {
                reason: UnsupportedReason::NotInDialect
            }
        );
        if shown_undefined == feature.in_dialect(dialect) {
            return Err(undefined);
        }
        match value {
            FeatureSupport::Unsupported {
                reason: UnsupportedReason::NotInDialect,
            } => declared(evidence).then_some(()).ok_or(wrong),
            FeatureSupport::Unsupported {
                reason: UnsupportedReason::DeclaredByRunner { .. },
            } => {
                if !declared(evidence) {
                    return Err(wrong);
                }
                run.map(|_| ()).ok_or(not_from_run)
            }
            FeatureSupport::Supported { cases } => {
                let at = host_observed(evidence).ok_or(wrong)?;
                let run = run.ok_or(not_from_run)?;
                if *cases == 0 || *cases > run.cases || at != run.observed_at {
                    return Err(not_from_run);
                }
                Ok(())
            }
            FeatureSupport::Unsupported {
                reason: UnsupportedReason::ConformanceFailed { case, .. },
            } => {
                let at = host_observed(evidence).ok_or(wrong)?;
                let run = run.ok_or(not_from_run)?;
                if !run.failed.contains(case) || at != run.observed_at {
                    return Err(not_from_run);
                }
                Ok(())
            }
        }
    }
}

/// When the host observed `evidence`, if the host observed it.
fn host_observed(evidence: &Evidence) -> Option<MonotonicTime> {
    match evidence {
        Evidence::Observed {
            by: Observer::Host,
            observed_at,
            ..
        } => Some(*observed_at),
        _ => None,
    }
}

/// Whether `evidence` is a declaration's assertion.
fn declared(evidence: &Evidence) -> bool {
    matches!(
        evidence,
        Evidence::Asserted {
            by: Asserter::Declaration,
            ..
        }
    )
}

impl fmt::Display for FeatureLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.support.value() {
            Some(FeatureSupport::Supported { cases }) => write!(
                f,
                "{}: supported, {cases} passing conformance case(s); {}",
                self.label,
                self.support.evidence()
            ),
            Some(FeatureSupport::Unsupported { reason }) => write!(
                f,
                "{}: unsupported, {reason}; {}",
                self.label,
                self.support.evidence()
            ),
            None => write!(f, "{}: {}", self.label, self.support.evidence()),
        }
    }
}

impl<'de> Deserialize<'de> for FeatureLine {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            feature: EndpointFeature,
            aspect: EndpointAspect,
            label: String,
            support: Fact<FeatureSupport>,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.aspect != wire.feature.aspect() || wire.label != wire.feature.label() {
            return Err(serde::de::Error::custom(format!(
                "the feature {:?} is shown as \"{}\" under {:?}",
                wire.feature,
                wire.feature.label(),
                wire.feature.aspect()
            )));
        }
        Ok(Self::new(wire.feature, wire.support))
    }
}

/// One dialect as shown: whether it is advertised now, the run its row was built from and
/// every feature once, in [`EndpointFeature::ALL`] order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DialectShown {
    dialect: EndpointDialect,
    label: &'static str,
    /// Recomputed from the features: none unavailable, and every exchange's features
    /// supported.
    advertised: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    conformance: Option<ConformanceShown>,
    features: Vec<FeatureLine>,
}

impl DialectShown {
    /// A dialect with no published row for the model and runner: every feature the
    /// dialect defines is unavailable until the host's harness tests it, and one it does
    /// not define is shown as such. It is not advertised.
    pub fn unpublished(dialect: EndpointDialect) -> Self {
        let missing = Refusal::new(
            RefusalCode::Evidence {
                code: EvidenceCode::Missing,
            },
            &format!(
                "no {dialect} conformance run of this model on this runner was published, so \
                 nothing about the dialect is known"
            ),
            Remedy::Evidence {
                step: EvidenceRemedy::RunCheck,
            },
        );
        let features = EndpointFeature::ALL
            .into_iter()
            .map(|feature| {
                let support = if feature.in_dialect(dialect) {
                    Fact::unavailable(missing.clone())
                } else {
                    not_in_dialect()
                };
                FeatureLine::new(feature, support)
            })
            .collect();
        Self::with_features(dialect, None, features)
    }

    /// A dialect's published row: `run` is the conformance run it was built from and
    /// `cell` gives each feature's cell. Support and a failed case are observed by the
    /// host at the run's time and current for `fresh_for` after it, judged at `now`, a
    /// reading of the same evidence clock the run's time was read from; a runner's
    /// declaration and a feature the dialect does not define are assertions; an untested
    /// feature is unavailable. When the run observed another runner configuration than
    /// `current`, every feature the dialect defines is unavailable, as the serving
    /// protocol refuses the row. Refused when a cell contradicts the dialect or the run.
    pub fn published(
        dialect: EndpointDialect,
        run: ConformanceShown,
        cell: impl Fn(EndpointFeature) -> CellShown,
        current: ConfigurationFingerprint,
        now: ClockReading,
        fresh_for: Duration,
    ) -> Result<Self, EndpointError> {
        let changed = run.configuration != current;
        // The host's observation, judged at `now` by the contract's own freshness rule:
        // shown again at the reading it was made at, under the same configuration, it is
        // unavailable only when dated after `now` or past its bound.
        let observed = Evidence::observed_by(
            SourceClass::HostProbe,
            run.observed_at,
            run.observed_at.saturating_add(fresh_for),
        )
        .as_of(&ShownAt::of(now, current), now, current);
        let mut features = Vec::with_capacity(EndpointFeature::ALL.len());
        for feature in EndpointFeature::ALL {
            let fact = |value, evidence: &Evidence| {
                Fact::new(value, evidence.clone())
                    .map_err(|_: FactError| EndpointError::WrongEvidence { dialect, feature })
            };
            let support = match cell(feature) {
                CellShown::Unsupported {
                    reason: UnsupportedReason::NotInDialect,
                } => not_in_dialect(),
                _ if changed && feature.in_dialect(dialect) => {
                    Fact::unavailable(configuration_changed(dialect))
                }
                CellShown::Untested => Fact::unavailable(untested(dialect, feature)),
                CellShown::Unsupported {
                    reason: reason @ UnsupportedReason::DeclaredByRunner { .. },
                } => Fact::asserted(
                    FeatureSupport::Unsupported { reason },
                    Asserter::Declaration,
                    None,
                ),
                CellShown::Supported { cases } => match &observed {
                    Evidence::Unavailable { refusal } => Fact::unavailable(refusal.clone()),
                    evidence => fact(FeatureSupport::Supported { cases }, evidence)?,
                },
                CellShown::Unsupported {
                    reason: reason @ UnsupportedReason::ConformanceFailed { .. },
                } => match &observed {
                    Evidence::Unavailable { refusal } => Fact::unavailable(refusal.clone()),
                    evidence => fact(FeatureSupport::Unsupported { reason }, evidence)?,
                },
            };
            features.push(FeatureLine::new(feature, support));
        }
        let shown = Self::with_features(dialect, Some(run), features);
        shown.check()?;
        Ok(shown)
    }

    fn with_features(
        dialect: EndpointDialect,
        conformance: Option<ConformanceShown>,
        features: Vec<FeatureLine>,
    ) -> Self {
        Self {
            dialect,
            label: dialect.label(),
            advertised: advertisable(&features),
            conformance,
            features,
        }
    }

    pub fn dialect(&self) -> EndpointDialect {
        self.dialect
    }

    /// The words a person reads.
    pub fn label(&self) -> &'static str {
        self.label
    }

    /// Whether the endpoint is advertised in this dialect: no feature is unavailable and
    /// every exchange's features are supported, on current evidence.
    pub fn is_advertised(&self) -> bool {
        self.advertised
    }

    /// The conformance run its row was built from; `None` when no row was published.
    pub fn conformance(&self) -> Option<&ConformanceShown> {
        self.conformance.as_ref()
    }

    /// Every feature, in [`EndpointFeature::ALL`] order.
    pub fn features(&self) -> &[FeatureLine] {
        &self.features
    }

    /// The line of `feature`.
    pub fn feature(&self, feature: EndpointFeature) -> Option<&FeatureLine> {
        self.features.iter().find(|line| line.feature == feature)
    }

    /// The lines of one aspect, such as tool calling or streaming, in order.
    pub fn aspect(&self, aspect: EndpointAspect) -> impl Iterator<Item = &FeatureLine> {
        self.features
            .iter()
            .filter(move |line| line.aspect == aspect)
    }

    /// Every feature in order once, each consistent with the dialect and the run, the
    /// run's counts consistent, and `advertised` what the features give.
    pub fn check(&self) -> Result<(), EndpointError> {
        let dialect = self.dialect;
        let order: Vec<EndpointFeature> = self.features.iter().map(|line| line.feature).collect();
        if order != EndpointFeature::ALL {
            return Err(EndpointError::FeatureOrder { dialect });
        }
        if let Some(run) = &self.conformance {
            let mut failed: Vec<&Label> = run.failed.iter().collect();
            failed.sort();
            failed.dedup();
            let failures = u64::try_from(run.failed.len()).unwrap_or(u64::MAX);
            if run.cases == 0 || failures > run.cases || failed.len() != run.failed.len() {
                return Err(EndpointError::RunCounts { dialect });
            }
        }
        for line in &self.features {
            line.check(dialect, self.conformance.as_ref())?;
        }
        if self.advertised != advertisable(&self.features) {
            return Err(EndpointError::Advertised { dialect });
        }
        Ok(())
    }

    /// The dialect when shown again ([`Fact::as_of`]), advertised again only as its
    /// features now allow.
    fn as_of(
        &self,
        shown: &ShownAt,
        now: ClockReading,
        configuration: ConfigurationFingerprint,
    ) -> Self {
        let features = self
            .features
            .iter()
            .map(|line| {
                FeatureLine::new(line.feature, line.support.as_of(shown, now, configuration))
            })
            .collect();
        Self::with_features(self.dialect, self.conformance.clone(), features)
    }
}

impl<'de> Deserialize<'de> for DialectShown {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            dialect: EndpointDialect,
            label: String,
            advertised: bool,
            #[serde(default)]
            conformance: Option<ConformanceShown>,
            features: Vec<FeatureLine>,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.label != wire.dialect.label() {
            return Err(serde::de::Error::custom(format!(
                "the dialect {:?} is shown as \"{}\"",
                wire.dialect,
                wire.dialect.label()
            )));
        }
        let shown = Self {
            dialect: wire.dialect,
            label: wire.dialect.label(),
            advertised: wire.advertised,
            conformance: wire.conformance,
            features: wire.features,
        };
        shown.check().map_err(serde::de::Error::custom)?;
        Ok(shown)
    }
}

/// Whether features advertise their dialect: none unavailable, and every exchange's
/// features supported.
fn advertisable(features: &[FeatureLine]) -> bool {
    features
        .iter()
        .all(|line| !line.support.evidence().is_unavailable())
        && EndpointFeature::EVERY_EXCHANGE.into_iter().all(|feature| {
            features
                .iter()
                .any(|line| line.feature == feature && line.is_supported())
        })
}

/// A feature the dialect does not define, as the protocol's definition asserts it.
fn not_in_dialect() -> Fact<FeatureSupport> {
    Fact::asserted(
        FeatureSupport::Unsupported {
            reason: UnsupportedReason::NotInDialect,
        },
        Asserter::Declaration,
        None,
    )
}

fn untested(dialect: EndpointDialect, feature: EndpointFeature) -> Refusal {
    Refusal::new(
        RefusalCode::Evidence {
            code: EvidenceCode::Missing,
        },
        &format!(
            "no {dialect} conformance case exercised \"{}\" on this runner, so it is untested",
            feature.label()
        ),
        Remedy::Evidence {
            step: EvidenceRemedy::RunCheck,
        },
    )
}

fn configuration_changed(dialect: EndpointDialect) -> Refusal {
    Refusal::new(
        RefusalCode::Evidence {
            code: EvidenceCode::ConfigurationChanged,
        },
        &format!(
            "the {dialect} conformance run observed the runner under another launch \
             configuration, so it no longer describes this runner"
        ),
        Remedy::Evidence {
            step: EvidenceRemedy::RecheckCurrentConfiguration,
        },
    )
}

/// The runner an endpoint is served by: its backend release and its execution category
/// with its own label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRunner {
    pub release: BackendRelease,
    pub category: CategoryShown,
}

/// What one model's agent endpoint on one runner declares, per dialect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AgentEndpoint {
    /// The model's identity digest.
    model: Digest,
    runner: EndpointRunner,
    /// Every dialect once, in [`EndpointDialect::ALL`] order.
    dialects: Vec<DialectShown>,
}

impl AgentEndpoint {
    /// `model` served by `release` in `category`, with every dialect once in
    /// [`EndpointDialect::ALL`] order.
    pub fn new(
        model: Digest,
        release: BackendRelease,
        category: ExecutionCategory,
        dialects: Vec<DialectShown>,
    ) -> Result<Self, EndpointError> {
        let endpoint = Self {
            model,
            runner: EndpointRunner {
                release,
                category: CategoryShown::from(category),
            },
            dialects,
        };
        endpoint.check()?;
        Ok(endpoint)
    }

    pub fn model(&self) -> Digest {
        self.model
    }

    pub fn runner(&self) -> &EndpointRunner {
        &self.runner
    }

    pub fn dialects(&self) -> &[DialectShown] {
        &self.dialects
    }

    /// The dialect `dialect`.
    pub fn dialect(&self, dialect: EndpointDialect) -> Option<&DialectShown> {
        self.dialects.iter().find(|shown| shown.dialect == dialect)
    }

    /// The dialects advertised now, in order.
    pub fn advertised(&self) -> Vec<EndpointDialect> {
        self.dialects
            .iter()
            .filter(|shown| shown.advertised)
            .map(|shown| shown.dialect)
            .collect()
    }

    /// Every feature's evidence, in order.
    pub fn evidence(&self) -> impl Iterator<Item = &Evidence> {
        self.dialects
            .iter()
            .flat_map(|shown| shown.features.iter())
            .map(|line| line.support.evidence())
    }

    /// Every dialect once, in order, each consistent ([`DialectShown::check`]).
    pub fn check(&self) -> Result<(), EndpointError> {
        let order: Vec<EndpointDialect> = self.dialects.iter().map(|shown| shown.dialect).collect();
        if order != EndpointDialect::ALL {
            return Err(EndpointError::DialectOrder);
        }
        self.dialects.iter().try_for_each(DialectShown::check)
    }

    /// The endpoint shown again at `now` under `configuration` ([`Fact::as_of`]): a
    /// feature whose observation is no longer current is unavailable, and a dialect is
    /// advertised only as its features now allow. Assertions are unchanged.
    pub fn as_of(
        &self,
        shown: &ShownAt,
        now: ClockReading,
        configuration: ConfigurationFingerprint,
    ) -> Self {
        Self {
            model: self.model,
            runner: self.runner.clone(),
            dialects: self
                .dialects
                .iter()
                .map(|dialect| dialect.as_of(shown, now, configuration))
                .collect(),
        }
    }
}

impl<'de> Deserialize<'de> for AgentEndpoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            model: Digest,
            runner: EndpointRunner,
            dialects: Vec<DialectShown>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let endpoint = Self {
            model: wire.model,
            runner: wire.runner,
            dialects: wire.dialects,
        };
        endpoint.check().map_err(serde::de::Error::custom)?;
        Ok(endpoint)
    }
}

/// Why an agent endpoint is inconsistent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointError {
    /// The dialects are not every dialect once, in order.
    DialectOrder,
    /// A dialect's features are not every feature once, in order.
    FeatureOrder { dialect: EndpointDialect },
    /// A feature the dialect does not define is shown as anything else, or one it defines
    /// as undefined.
    NotInDialect {
        dialect: EndpointDialect,
        feature: EndpointFeature,
    },
    /// A value stands on another evidence state than its kind allows: support and a
    /// failed case on the host's observation, a declaration on an assertion.
    WrongEvidence {
        dialect: EndpointDialect,
        feature: EndpointFeature,
    },
    /// A conformance value without the run it came from, or not matching it.
    NotFromRun {
        dialect: EndpointDialect,
        feature: EndpointFeature,
    },
    /// The run judged no case, or lists more or repeated failures.
    RunCounts { dialect: EndpointDialect },
    /// The dialect's advertisement is not what its features give.
    Advertised { dialect: EndpointDialect },
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DialectOrder => f.write_str("an endpoint lists every dialect once, in order"),
            Self::FeatureOrder { dialect } => {
                write!(f, "{dialect} lists every feature once, in order")
            }
            Self::NotInDialect { dialect, feature } => write!(
                f,
                "{dialect} {} \"{}\", and it is shown exactly as such",
                if feature.in_dialect(*dialect) {
                    "defines"
                } else {
                    "does not define"
                },
                feature.label()
            ),
            Self::WrongEvidence { dialect, feature } => write!(
                f,
                "\"{}\" in {dialect} stands on the wrong evidence: support and a failed case \
                 are observed by the host's own conformance run, never asserted or verified, \
                 and a runner's declaration is an assertion",
                feature.label()
            ),
            Self::NotFromRun { dialect, feature } => write!(
                f,
                "\"{}\" in {dialect} cites a conformance result its dialect's run does not hold",
                feature.label()
            ),
            Self::RunCounts { dialect } => write!(
                f,
                "the {dialect} conformance run judges at least one case, and lists each failed \
                 case once"
            ),
            Self::Advertised { dialect } => write!(
                f,
                "{dialect} is advertised exactly when no feature is unavailable and every \
                 exchange's features are supported"
            ),
        }
    }
}

impl std::error::Error for EndpointError {}
