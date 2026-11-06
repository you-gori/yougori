//! What each running runner started with (GPU-W11; G08: a running runner keeps the exact
//! helper version it started with, and an upgrade or rollback applies only to new
//! runners).
//!
//! [`RunnerPins::start`] records, once per runner instance, the [`RunnerHelpers`] it was
//! selected; nothing replaces them while it runs. A runner gets other versions only by
//! stopping and starting again, which is a new selection. The rollout never reads or
//! writes these records; [`RunnerPins::running_on`] and
//! [`RunnerPins::running_on_object`] tell the host which runners still use a version that
//! failed or whose bundle was quarantined, so it can decide to restart them.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::identity::{HelperPin, HelperPinId};
use super::manifest::HelperId;
use super::rollout::{RunnerHelpers, ServingHelper};
use crate::foundation::catalog::ObjectId;
use crate::foundation::evidence::BackendRelease;
use crate::foundation::ids::{validate_identifier, IdError};

/// One runner instance, such as a model environment's id: the shared identifier rule.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RunnerInstance(String);

impl RunnerInstance {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RunnerInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RunnerInstance({})", self.0)
    }
}

impl fmt::Display for RunnerInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RunnerInstance {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// What one running runner started with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RunnerStart {
    pub runner: RunnerInstance,
    pub release: BackendRelease,
    pub helpers: BTreeMap<HelperId, RunnerHelpers>,
}

impl RunnerStart {
    /// Every pinned version the runner loaded, serving or shadow.
    fn pins(&self) -> impl Iterator<Item = &HelperPin> {
        self.helpers.values().flat_map(|helpers| {
            let serving = match &helpers.serve {
                ServingHelper::Bundle { pin } => Some(pin),
                ServingHelper::SourceInjection => None,
            };
            serving.into_iter().chain(helpers.shadow.as_ref())
        })
    }
}

/// Why a runner's helpers were not recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinningRefusal {
    /// The runner is running: it keeps what it started with until it stops.
    AlreadyRunning { runner: RunnerInstance },
    /// A selection was made for another runner release.
    WrongRunner {
        helper: HelperId,
        expected: BackendRelease,
        found: BackendRelease,
    },
    /// Two selections for one helper.
    DuplicateHelper { helper: HelperId },
}

impl fmt::Display for PinningRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning { runner } => write!(
                f,
                "runner {runner} is running and keeps its helper versions until it stops"
            ),
            Self::WrongRunner {
                helper,
                expected,
                found,
            } => write!(
                f,
                "helper {helper} was selected for {found}, not this runner's {expected}"
            ),
            Self::DuplicateHelper { helper } => {
                write!(f, "helper {helper} was selected twice")
            }
        }
    }
}

impl std::error::Error for PinningRefusal {}

/// The helper versions of every running runner.
#[derive(Clone, Debug, Default)]
pub struct RunnerPins {
    running: BTreeMap<RunnerInstance, RunnerStart>,
}

impl RunnerPins {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records what `runner` on `release` starts with. A running runner is refused: its
    /// versions change only by stopping and starting again.
    pub fn start(
        &mut self,
        runner: RunnerInstance,
        release: BackendRelease,
        selected: Vec<RunnerHelpers>,
    ) -> Result<&RunnerStart, PinningRefusal> {
        if self.running.contains_key(&runner) {
            return Err(PinningRefusal::AlreadyRunning { runner });
        }
        let mut helpers = BTreeMap::new();
        for selection in selected {
            if selection.runner != release {
                return Err(PinningRefusal::WrongRunner {
                    helper: selection.helper,
                    expected: release,
                    found: selection.runner,
                });
            }
            let helper = selection.helper.clone();
            if helpers.insert(helper.clone(), selection).is_some() {
                return Err(PinningRefusal::DuplicateHelper { helper });
            }
        }
        let start = RunnerStart {
            runner: runner.clone(),
            release,
            helpers,
        };
        Ok(self.running.entry(runner).or_insert(start))
    }

    /// What `runner` started with, while it runs.
    pub fn get(&self, runner: &RunnerInstance) -> Option<&RunnerStart> {
        self.running.get(runner)
    }

    /// What serves `helper` in `runner`.
    pub fn serving(&self, runner: &RunnerInstance, helper: &HelperId) -> Option<&ServingHelper> {
        self.running
            .get(runner)
            .and_then(|start| start.helpers.get(helper))
            .map(|helpers| &helpers.serve)
    }

    /// Every running runner with what it started with, in instance order.
    pub fn running(&self) -> impl Iterator<Item = &RunnerStart> {
        self.running.values()
    }

    /// Forgets a stopped runner and returns what it ran with.
    pub fn stop(&mut self, runner: &RunnerInstance) -> Option<RunnerStart> {
        self.running.remove(runner)
    }

    /// Runners that loaded `pin`, serving or in shadow.
    pub fn running_on(&self, pin: HelperPinId) -> Vec<RunnerInstance> {
        self.running
            .values()
            .filter(|start| start.pins().any(|loaded| loaded.id() == pin))
            .map(|start| start.runner.clone())
            .collect()
    }

    /// Runners that loaded a version held in `object`, as after the catalog quarantined
    /// it.
    pub fn running_on_object(&self, object: ObjectId) -> Vec<RunnerInstance> {
        self.running
            .values()
            .filter(|start| start.pins().any(|loaded| loaded.object == object))
            .map(|start| start.runner.clone())
            .collect()
    }
}
