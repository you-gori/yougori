//! The product document (S2 CORE-07: "UI and CLI resolve the same state").
//!
//! A [`ProductView`] is what the engine API returns about one setup, sandbox, model or
//! operation and what the CLI and desktop both read: the execution category requested and
//! the actual backend, requested CORE-01 capabilities with their evidence, a launched
//! sandbox's facts, model readiness and residency, a model's declared agent endpoint,
//! permissions, the CORE-04 grants an execution holds, progress, refusals and the
//! migration of an old setup. Every part is optional except what names the document, and
//! every part is built by its own conversion.
//!
//! A document is shown at one [`ShownAt`]: a reading of the shared evidence clock and the
//! configuration in force. Every verified or observed state in it was current then
//! ([`ProductView::check`]), and [`ProductView::as_of`] recomputes the states for a later
//! reading, so a stored or forwarded document never presents stale evidence as current.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::endpoint::AgentEndpoint;
use super::evidence::Evidence;
use super::execution::{CapabilityCheck, Execution};
use super::grants::ExecutionGrants;
use super::migration::MigrationShown;
use super::model::ModelStatus;
use super::permissions::PermissionLine;
use super::progress::ProgressShown;
use super::refusal::Refusal;
use super::sandbox_evidence::SandboxEvidence;
use super::version::ContractVersion;
use crate::foundation::evidence::{ClockReading, ClockSession, ConfigurationFingerprint};
use crate::foundation::ids::{validate_identifier, IdError, MonotonicTime};

/// What a document is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewSubjectKind {
    Setup,
    Sandbox,
    Model,
    Operation,
}

/// The setup, sandbox, model or operation a document is about, by its identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ViewSubject {
    kind: ViewSubjectKind,
    id: String,
}

impl ViewSubject {
    /// Accepts the ids.rs identifier grammar.
    pub fn new(kind: ViewSubjectKind, id: &str) -> Result<Self, IdError> {
        validate_identifier(id)?;
        Ok(Self {
            kind,
            id: id.to_owned(),
        })
    }

    pub fn kind(&self) -> ViewSubjectKind {
        self.kind
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

impl<'de> Deserialize<'de> for ViewSubject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            kind: ViewSubjectKind,
            id: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.kind, &wire.id).map_err(serde::de::Error::custom)
    }
}

/// When a document was shown: a reading of the shared evidence clock, and the host
/// configuration in force then.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShownAt {
    pub clock: ClockSession,
    pub at: MonotonicTime,
    pub configuration: ConfigurationFingerprint,
}

impl ShownAt {
    /// Shown at `now` under `configuration`.
    pub fn of(now: ClockReading, configuration: ConfigurationFingerprint) -> Self {
        Self {
            clock: now.session(),
            at: now.at(),
            configuration,
        }
    }
}

/// The product document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProductView {
    pub contract_version: ContractVersion,
    pub subject: ViewSubject,
    pub shown_at: ShownAt,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<Execution>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<CapabilityCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelStatus>,
    /// What the model's agent endpoint declares, per dialect (contract version 2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<AgentEndpoint>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<PermissionLine>,
    /// The CORE-04 grants of the execution's authority (contract version 2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grants: Option<ExecutionGrants>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub progress: Vec<ProgressShown>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refusals: Vec<Refusal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migration: Option<MigrationShown>,
}

impl ProductView {
    /// An empty document of the current contract version about `subject`, shown at
    /// `shown_at`.
    pub fn new(subject: ViewSubject, shown_at: ShownAt) -> Self {
        Self {
            contract_version: ContractVersion::CURRENT,
            subject,
            shown_at,
            execution: None,
            capabilities: Vec::new(),
            sandbox: None,
            model: None,
            endpoint: None,
            permissions: Vec::new(),
            grants: None,
            progress: Vec::new(),
            refusals: Vec::new(),
            migration: None,
        }
    }

    /// Every evidence state in the document, wherever it is shown.
    pub fn evidence(&self) -> Vec<&Evidence> {
        let mut states = Vec::new();
        if let Some(execution) = &self.execution {
            states.push(execution.actual().evidence());
        }
        states.extend(self.capabilities.iter().map(CapabilityCheck::evidence));
        if let Some(sandbox) = &self.sandbox {
            states.extend(sandbox.lines().map(|line| line.evidence()));
        }
        if let Some(endpoint) = &self.endpoint {
            states.extend(endpoint.evidence());
        }
        states
    }

    /// Every verified or observed state was current when the document was shown, and every
    /// part is consistent on its own.
    pub fn check(&self) -> Result<(), ViewError> {
        if let Some(execution) = &self.execution {
            execution
                .check()
                .map_err(|error| ViewError::Inconsistent(error.to_string()))?;
        }
        for capability in &self.capabilities {
            capability
                .check()
                .map_err(|error| ViewError::Inconsistent(error.to_string()))?;
        }
        if let Some(migration) = &self.migration {
            migration
                .check()
                .map_err(|error| ViewError::Inconsistent(error.to_string()))?;
        }
        if let Some(sandbox) = &self.sandbox {
            for line in sandbox.lines() {
                line.check()
                    .map_err(|error| ViewError::Inconsistent(error.to_string()))?;
            }
        }
        for permission in &self.permissions {
            permission
                .check()
                .map_err(|error| ViewError::Inconsistent(error.to_string()))?;
        }
        if let Some(endpoint) = &self.endpoint {
            endpoint
                .check()
                .map_err(|error| ViewError::Inconsistent(error.to_string()))?;
        }
        if let Some(grants) = &self.grants {
            grants
                .check(&self.shown_at)
                .map_err(|error| ViewError::Inconsistent(error.to_string()))?;
        }
        let at = self.shown_at.at;
        for evidence in self.evidence() {
            match evidence {
                Evidence::Verified {
                    observed_at,
                    fresh_until,
                    ..
                }
                | Evidence::Observed {
                    observed_at,
                    fresh_until,
                    ..
                } if at < *observed_at || at > *fresh_until => {
                    return Err(ViewError::NotCurrentWhenShown {
                        state: evidence.name(),
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// The document shown again at `now` under `configuration`: every verified or observed
    /// state that is no longer current, on another clock session or under another
    /// configuration becomes unavailable with its reason and remedy ([`Evidence::as_of`]),
    /// a dialect is advertised only as its features then allow, and a grant is held only
    /// while its authority then stands in force. Assertions, readiness, revocations,
    /// progress, refusals and migration are unchanged.
    pub fn as_of(&self, now: ClockReading, configuration: ConfigurationFingerprint) -> Self {
        let shown = &self.shown_at;
        let mut view = self.clone();
        view.shown_at = ShownAt::of(now, configuration);
        view.execution = self.execution.as_ref().map(|execution| {
            execution.with_actual(execution.actual().as_of(shown, now, configuration))
        });
        view.capabilities = self
            .capabilities
            .iter()
            .map(|check| check.with_evidence(check.evidence().as_of(shown, now, configuration)))
            .collect();
        view.sandbox = self.sandbox.as_ref().map(|sandbox| {
            sandbox.with_sections(
                sandbox
                    .sections()
                    .iter()
                    .map(|section| {
                        section.with_lines(
                            section
                                .lines()
                                .iter()
                                .map(|line| {
                                    line.with_evidence(line.evidence().as_of(
                                        shown,
                                        now,
                                        configuration,
                                    ))
                                })
                                .collect(),
                        )
                    })
                    .collect(),
            )
        });
        view.endpoint = self
            .endpoint
            .as_ref()
            .map(|endpoint| endpoint.as_of(shown, now, configuration));
        view.grants = self.grants.as_ref().map(|grants| grants.as_of(now));
        view
    }

    /// The document as JSON, refused when it is inconsistent.
    pub fn to_json(&self) -> Result<String, ViewError> {
        self.check()?;
        serde_json::to_string(self).map_err(|error| ViewError::Json(error.to_string()))
    }

    /// The document as indented JSON, as the golden fixtures are written.
    pub fn to_json_pretty(&self) -> Result<String, ViewError> {
        self.check()?;
        serde_json::to_string_pretty(self).map_err(|error| ViewError::Json(error.to_string()))
    }
}

impl<'de> Deserialize<'de> for ProductView {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            contract_version: ContractVersion,
            subject: ViewSubject,
            shown_at: ShownAt,
            #[serde(default)]
            execution: Option<Execution>,
            #[serde(default)]
            capabilities: Vec<CapabilityCheck>,
            #[serde(default)]
            sandbox: Option<SandboxEvidence>,
            #[serde(default)]
            model: Option<ModelStatus>,
            #[serde(default)]
            endpoint: Option<AgentEndpoint>,
            #[serde(default)]
            permissions: Vec<PermissionLine>,
            #[serde(default)]
            grants: Option<ExecutionGrants>,
            #[serde(default)]
            progress: Vec<ProgressShown>,
            #[serde(default)]
            refusals: Vec<Refusal>,
            #[serde(default)]
            migration: Option<MigrationShown>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let view = Self {
            contract_version: wire.contract_version,
            subject: wire.subject,
            shown_at: wire.shown_at,
            execution: wire.execution,
            capabilities: wire.capabilities,
            sandbox: wire.sandbox,
            model: wire.model,
            endpoint: wire.endpoint,
            permissions: wire.permissions,
            grants: wire.grants,
            progress: wire.progress,
            refusals: wire.refusals,
            migration: wire.migration,
        };
        view.check().map_err(serde::de::Error::custom)?;
        Ok(view)
    }
}

/// Why a document is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViewError {
    /// A part is inconsistent.
    Inconsistent(String),
    /// A verified or observed state was not current when the document was shown.
    NotCurrentWhenShown { state: &'static str },
    /// The document could not be written as JSON.
    Json(String),
}

impl fmt::Display for ViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inconsistent(problem) => write!(f, "the document is inconsistent: {problem}"),
            Self::NotCurrentWhenShown { state } => write!(
                f,
                "a {state} state was not current when the document was shown"
            ),
            Self::Json(problem) => write!(f, "the document could not be written: {problem}"),
        }
    }
}

impl std::error::Error for ViewError {}
